
"""
4.1 - permit lifecycle: `CONSUMED` describes AUTHORITY, not epistemic quality.

    ISSUED          authority exists, no execution attempt yet
    CLAIMED         authority spent, attempt exists, outcome NOT yet resolved
    CONSUMED        the attempt is resolved; authority permanently dead
    REVOKED/EXPIRED authority died before a successful claim

Both a machine-proven terminal outcome and an operator settlement RESOLVE an attempt, so both consume
the permit. What differs is `terminal_evidence`: True for machine proof, False for a human decision.
`CLAIMED + resolved` is therefore a lifecycle lie, and the one surviving exception - a crash between
"evidence durable" and "permit consumed" - is a visible, completable obligation rather than a state.
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.continuity import AttemptOutcome, complete_pending_consumption, reconstruct
from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
from ciph.kernel.permit_store import PermitStoreError
from ciph.runtime import CiphRuntime
from permit_test_support import enqueue_permit_bearing_job
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability


class TestGate41PermitLifecycle(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-41-lifecycle-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.runtime = CiphRuntime(db_path=self.db)
        self.cap = SimpleComputeCapability(name='lifecycle.compute')
        self.runtime.register_capability(self.cap)

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def enqueue(self, cap=None, params=None, attempts=3):
        cap = cap or self.cap
        return enqueue_permit_bearing_job(
            self.runtime, capability=cap.manifest.name, params=params or {'value': 1},
            max_retries=attempts)

    def execute(self, job_id, worker='lifecycle_worker'):
        job = self.runtime.queue.lease_next_job(worker, 30, target_job_id=job_id)
        return self.runtime.worker_daemon._execute_leased_job(job, worker) if job else None

    def permit_store(self):
        return build_durable_permit_consumer_dependencies(
            self.db, trust_registry=self.runtime.trust_registry).permit_store

    def state_of(self, permit_id):
        return self.permit_store().state_of(permit_id)

    def event_count(self):
        with sqlite3.connect(self.db) as conn:
            return conn.execute("SELECT COUNT(*) FROM ciph_event_store").fetchone()[0]

    def action(self, state):
        return state.actions[0]

    # ------------------------------------------------------------------ machine-proven resolution
    def test_a_machine_proven_success_consumes_the_permit(self):
        fixture = self.enqueue()
        receipt = self.execute(fixture.job_id)
        self.assertEqual(receipt.exit_code, 0)

        self.assertEqual(self.state_of(fixture.permit_id), 'CONSUMED')
        row = self.permit_store().get_permit_row(fixture.permit_id)
        self.assertTrue(row['consumed_at'])

        state = self.action(reconstruct(self.db))
        self.assertEqual(state.permit_state, 'CONSUMED')
        self.assertEqual(state.attempt_outcome, AttemptOutcome.TERMINAL.value)
        self.assertTrue(state.terminal_evidence)
        self.assertFalse(state.consumption_pending)
        self.assertFalse(state.authorization_alive)
        self.assertIn(fixture.permit_id, reconstruct(self.db).dead_authority)

    def test_a_machine_proven_terminal_failure_consumes_the_permit(self):
        """A resolved FAILURE is resolved too: `CLAIMED` must not survive a terminal disposition."""
        fixture = self.enqueue()
        self.permit_store().claim(fixture.permit_id, 'w')
        row = self.permit_store().get_permit_row(fixture.permit_id)
        # The exact attempt's evidence says the effect is CONFIRMED, which the classifier reads as
        # TERMINAL, not as retryable-unknown.
        self.runtime.event_store.append_event('ExecutionReceiptStoredEvent', 'agg', {
            'provenance': {'manifest_hash': self.cap.manifest.compute_manifest_hash()},
            'governed_authorization': {
                'execution_attempt_id': row['execution_attempt_id'],
                'execution_permit_id': fixture.permit_id,
                'execution_permit_digest': fixture.permit.permit_digest(),
                'authorization_generation': 0,
                'effect_certainty': 'EFFECT_CONFIRMED',
            },
        })
        result = self.runtime.retry_disposition(
            job_id=fixture.job_id, expected_permit_id=fixture.permit_id)
        self.assertEqual(result.outcome, 'TERMINAL')

        self.assertEqual(self.state_of(fixture.permit_id), 'CONSUMED')
        state = self.action(reconstruct(self.db))
        self.assertEqual(state.permit_state, 'CONSUMED')
        self.assertEqual(state.attempt_outcome, AttemptOutcome.TERMINAL.value)

    def test_an_unresolved_attempt_stays_claimed(self):
        fixture = self.enqueue()
        self.permit_store().claim(fixture.permit_id, 'w')
        result = self.runtime.retry_disposition(
            job_id=fixture.job_id, expected_permit_id=fixture.permit_id)
        self.assertEqual(result.outcome, 'RECONCILIATION_REQUIRED')

        self.assertEqual(self.state_of(fixture.permit_id), 'CLAIMED',
                         "reconciliation means the outcome is unknown, so the permit stays claimed")
        state = self.action(reconstruct(self.db))
        self.assertEqual(state.attempt_outcome, AttemptOutcome.UNRESOLVED.value)
        self.assertFalse(state.consumption_pending)
        self.assertIn(state.execution_attempt_id, reconstruct(self.db).unresolved_attempts)

    # ------------------------------------------------------------------ operator resolution
    def test_an_operator_settlement_consumes_the_permit_without_claiming_proof(self):
        cap = SimpleComputeCapability(name='lifecycle.failing', should_fail=True)
        self.runtime.register_capability(cap)
        fixture = self.enqueue(cap=cap, attempts=1)
        self.execute(fixture.job_id)                     # claims, fails, reconciles
        self.assertEqual(self.runtime.queue.get_job(fixture.job_id)['status'],
                         'RECONCILIATION_REQUIRED')

        settled = self.runtime.reconcile_job(
            fixture.job_id, 'FAILED',
            'operator reviewed the unresolved effect and settled the attempt',
        )
        self.assertTrue(settled)
        self.assertEqual(self.state_of(fixture.permit_id), 'CONSUMED',
                         "a human resolution resolves the attempt and retires its authority")

        state = self.action(reconstruct(self.db))
        self.assertEqual(state.permit_state, 'CONSUMED')
        self.assertEqual(state.attempt_outcome, AttemptOutcome.RESOLVED_BY_OPERATOR.value)
        self.assertFalse(state.terminal_evidence,
                         "an operator decision is a resolution, not machine proof")
        self.assertFalse(state.consumption_pending)

    # ------------------------------------------------------------------ the crash window
    def test_the_crash_window_is_visible_and_completable(self):
        fixture = self.enqueue()
        store = self.permit_store()
        claim = store.claim(fixture.permit_id, 'w')
        self.runtime.event_store.append_event('ExecutionReceiptStoredEvent', 'agg', {
            'provenance': {'manifest_hash': self.cap.manifest.compute_manifest_hash()},
            'governed_authorization': {
                'execution_attempt_id': claim.execution_attempt_id,
                'execution_permit_id': fixture.permit_id,
                'execution_permit_digest': fixture.permit.permit_digest(),
                'authorization_generation': 0,
                'effect_certainty': 'EFFECT_CONFIRMED',
            },
        })
        # This is the crash: the receipt is durable, the consume never happened.
        self.assertEqual(self.state_of(fixture.permit_id), 'CLAIMED')

        pending = reconstruct(self.db)
        action = self.action(pending)
        self.assertEqual(action.attempt_outcome, AttemptOutcome.TERMINAL.value,
                         "the resolution is proven; only the lifecycle is unfinished")
        self.assertTrue(action.consumption_pending)
        self.assertIn(fixture.permit_id, pending.completion_obligations)
        self.assertNotIn(fixture.permit_id, pending.dead_authority)
        self.assertNotIn(action.execution_attempt_id, pending.unresolved_attempts,
                         "a resolved attempt is never reported as unresolved")

        events_before = self.event_count()
        completed = complete_pending_consumption(self.db)
        self.assertEqual(completed, (fixture.permit_id,))

        after = reconstruct(self.db)
        self.assertEqual(self.action(after).permit_state, 'CONSUMED')
        self.assertFalse(self.action(after).consumption_pending)
        self.assertEqual(after.completion_obligations, ())
        self.assertIn(fixture.permit_id, after.dead_authority)
        self.assertEqual(self.event_count(), events_before,
                         "completion creates no fact; it only closes a durable transition")
        self.assertEqual(complete_pending_consumption(self.db), (),
                         "completion is idempotent")

    # ------------------------------------------------------------------ dead means dead
    def test_a_consumed_permit_can_never_be_claimed_again(self):
        fixture = self.enqueue()
        self.execute(fixture.job_id)
        with self.assertRaises(PermitStoreError):
            self.permit_store().claim(fixture.permit_id, 'worker_after_restart')


if __name__ == '__main__':
    unittest.main()
