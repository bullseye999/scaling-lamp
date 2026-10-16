
"""
4.1 Gate Zero - deterministic cold-start reconstruction.

The question is not "does Ciph remember?" It is:

    If Ciph dies right now and starts from nothing but its durable evidence,
    can it say what it was doing, what actually happened, what remains unresolved
    and what authority is still valid - without inventing state?

Every specimen below is written against that question. Where a law is stated in
`ciph.kernel.continuity`, there is a test here that could falsify it.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ciph.contracts.enums import ReplaySemantics
from ciph.kernel.continuity import (
    INTEGRITY_JOB_PERMIT_ABSENT_FROM_STORE,
    INTEGRITY_RUNNABLE_JOB_WITH_SPENT_PERMIT,
    AttemptOutcome,
    reconstruct,
)
from ciph.kernel.execution_authority import SignedExecutionPermit
from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
from ciph.runtime import CiphRuntime
from permit_test_support import enqueue_permit_bearing_job
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability


class TestGate41ColdStartReconstruction(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-41-gate-zero-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.runtime = CiphRuntime(db_path=self.db)
        self.cap = SimpleComputeCapability(name='continuity.compute')
        self.runtime.register_capability(self.cap)

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def idempotent_cap(self, name='continuity.compute_idem', **kwargs):
        class Idempotent(SimpleComputeCapability):
            @property
            def manifest(self):
                return replace(super().manifest, replay_semantics=ReplaySemantics.IDEMPOTENT)
        cap = Idempotent(name, **kwargs)
        self.runtime.register_capability(cap)
        return cap

    def enqueue(self, cap=None, params=None, attempts=3):
        cap = cap or self.cap
        return enqueue_permit_bearing_job(
            self.runtime, capability=cap.manifest.name, params=params or {'value': 1},
            max_retries=attempts)

    def execute(self, job_id, worker='continuity_worker'):
        job = self.runtime.queue.lease_next_job(worker, 30, target_job_id=job_id)
        return self.runtime.worker_daemon._execute_leased_job(job, worker) if job else None

    def permit_store(self):
        return build_durable_permit_consumer_dependencies(
            self.db, trust_registry=self.runtime.trust_registry).permit_store

    def restart(self):
        """A completely fresh runtime over the same durable stores - the restart, in one line."""
        self.runtime.shutdown()
        self.runtime = CiphRuntime(db_path=self.db)
        return self.runtime

    def action(self, state, capability_name='continuity.compute'):
        return [a for a in state.actions if a.capability == capability_name][0]

    def store_sizes(self):
        conn = sqlite3.connect(self.db)
        try:
            return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    for t in ('ciph_ipc_jobs', 'execution_permits', 'ciph_event_store')}
        finally:
            conn.close()

    # ------------------------------------------------------------------ law 1: reads only
    def test_reconstruction_creates_no_new_facts(self):
        fixture = self.enqueue()
        self.execute(fixture.job_id)
        before = self.store_sizes()

        state = reconstruct(self.db)

        self.assertEqual(self.store_sizes(), before,
                         "reconstruction is a read; it may not write a single row")
        self.assertEqual(dict(state.source_counts)['ciph_ipc_jobs'], before['ciph_ipc_jobs'])
        self.assertTrue(state.source_fingerprint)

    # ------------------------------------------------------------------ law 2: canonical only
    def test_reconstruction_takes_no_projection_or_checkpoint(self):
        """A cache cannot become authority: nothing may be substituted for the canonical stores.

        `conn` is present deliberately and is not an exception to the law: a caller's connection is a
        STRICTER view of the same canonical stores (it lets a decision read and act inside one
        transaction), never an alternative source of truth.
        """
        import inspect
        signature = inspect.signature(reconstruct)
        self.assertEqual(set(signature.parameters) - {"db_path", "now", "read_only", "conn"}, set(),
                         "an unexpected parameter could let a projection stand in for truth")
        for forbidden in ("cache", "checkpoint", "projection", "snapshot", "state", "events",
                          "hint", "state_dict", "canonical_state"):
            self.assertNotIn(forbidden, signature.parameters)

    # ------------------------------------------------------------------ law 4 + the first specimen
    def test_a_claimed_attempt_killed_before_terminal_evidence_stays_unresolved(self):
        fixture = self.enqueue()
        store = self.permit_store()
        claim = store.claim(fixture.permit_id, 'worker_that_died')   # authority spent, then crash
        attempt_id = claim.execution_attempt_id

        state = reconstruct(self.db)
        action = self.action(state)

        self.assertEqual(action.logical_action_id, fixture.permit.payload.logical_action_id)
        self.assertEqual(int(action.latest_generation), 0)
        self.assertEqual(action.permit_id, fixture.permit_id)
        self.assertEqual(action.permit_state, 'CLAIMED')
        self.assertEqual(action.execution_attempt_id, attempt_id)
        self.assertEqual(action.attempt_outcome, AttemptOutcome.UNRESOLVED.value)
        self.assertFalse(action.terminal_evidence)
        self.assertIn(attempt_id, state.unresolved_attempts)
        self.assertIn(fixture.job_id, state.reconciliation_obligations)

        # Restart: same logical action, same permit, SAME attempt identity, still unresolved.
        self.restart()
        after = reconstruct(self.db)
        self.assertEqual(after.canonical_digest(), state.canonical_digest(),
                         "a restart changed what the evidence says")

        # ...and nothing was invented to rescue it.
        self.assertEqual(len(after.actions), 1)
        self.assertEqual(after.actions[0].execution_attempt_id, attempt_id)
        self.assertEqual(after.actions[0].job_status, 'QUEUED',
                         "the restart must not have terminated the job either")
        with sqlite3.connect(self.db) as conn:
            permits = conn.execute("SELECT COUNT(*) FROM execution_permits").fetchone()[0]
            generations = conn.execute(
                "SELECT MAX(authorization_generation) FROM execution_permits").fetchone()[0]
        self.assertEqual(permits, 1, "no fresh permit may appear just because work is unfinished")
        self.assertEqual(int(generations or 0), 0, "no generation may advance on restart")
        # A second attempt is impossible: the spent permit cannot be claimed again.
        from ciph.kernel.permit_store import PermitStoreError
        with self.assertRaises(PermitStoreError):
            store.claim(fixture.permit_id, 'worker_after_restart')

    def test_an_unresolved_attempt_never_becomes_success_or_failure(self):
        fixture = self.enqueue()
        self.permit_store().claim(fixture.permit_id, 'worker_that_died')
        before = reconstruct(self.db)
        self.restart()
        for _ in range(3):
            after = reconstruct(self.db)
            self.assertEqual(after.canonical_digest(), before.canonical_digest())
            self.assertEqual(after.actions[0].attempt_outcome, AttemptOutcome.UNRESOLVED.value)

    # ------------------------------------------------------------------ law 5 + second specimen
    def test_a_terminal_action_stays_terminal_across_restart(self):
        fixture = self.enqueue()
        receipt = self.execute(fixture.job_id)
        self.assertEqual(receipt.exit_code, 0)

        state = reconstruct(self.db)
        action = self.action(state)
        self.assertEqual(action.attempt_outcome, AttemptOutcome.TERMINAL.value)
        self.assertTrue(action.terminal_evidence)
        self.assertEqual(action.job_status, 'SUCCEEDED')
        self.assertFalse(action.authorization_alive)
        self.assertNotIn(action.permit_id, state.remaining_authorized_work)

        self.restart()
        after = reconstruct(self.db)
        self.assertEqual(after.canonical_digest(), state.canonical_digest())
        self.assertEqual(after.actions[0].attempt_outcome, AttemptOutcome.TERMINAL.value)
        # No redispatch: the job is terminal and the authority is dead - CONSUMED, not CLAIMED.
        self.assertEqual(after.actions[0].job_status, 'SUCCEEDED')
        self.assertEqual(after.actions[0].permit_state, 'CONSUMED')
        self.assertIn(after.actions[0].permit_id, after.dead_authority)
        self.assertFalse(after.actions[0].consumption_pending)
        self.assertIsNone(self.runtime.queue.lease_next_job('worker_after_restart', 30))

    # ------------------------------------------------------------------ third specimen
    def test_an_issued_unclaimed_permit_is_neither_spent_nor_regenerated(self):
        fixture = self.enqueue()
        before = reconstruct(self.db)
        action = self.action(before)
        self.assertEqual(action.attempt_outcome, AttemptOutcome.NOT_ATTEMPTED.value)
        self.assertTrue(action.authorization_alive,
                        "an unclaimed permit is still valid authority after a restart")

        self.restart()
        after = reconstruct(self.db)
        self.assertEqual(after.canonical_digest(), before.canonical_digest())

        # It was not spent by the restart: the claim still succeeds exactly once.
        claim = self.permit_store().claim(fixture.permit_id, 'worker_after_restart')
        self.assertTrue(claim.execution_attempt_id)
        # ...and no replacement was minted.
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM execution_permits").fetchone()[0], 1)

    # ------------------------------------------------------------------ law 5: dead stays dead
    def test_consumed_authority_stays_dead_after_restart(self):
        fixture = self.enqueue()
        store = self.permit_store()
        store.claim(fixture.permit_id, 'w')
        store.consume(fixture.permit_id, 'w')

        state = reconstruct(self.db)
        action = self.action(state)
        self.assertEqual(action.permit_state, 'CONSUMED')
        self.assertFalse(action.authorization_alive)
        self.assertIn(action.permit_id, state.dead_authority)
        self.restart()
        after = reconstruct(self.db)
        self.assertEqual(after.canonical_digest(), state.canonical_digest())
        self.assertEqual(after.actions[0].permit_state, 'CONSUMED')

    # ------------------------------------------------------------------ law 6: no minting
    def test_restart_cannot_mint_authority_for_unfinished_work(self):
        cap = self.idempotent_cap(should_fail=True)
        fixture = self.enqueue(cap=cap)
        self.execute(fixture.job_id)     # fails; the governed disposition retries it
        retried = self.carried_permit_generation(fixture.job_id)
        self.assertEqual(retried, 1, "precondition: the action advanced one generation")

        before_sizes = self.store_sizes()
        self.restart()
        for _ in range(3):
            state = reconstruct(self.db)
        self.assertEqual(self.store_sizes(), before_sizes,
                         "restart may not mint, revoke, consume or move anything")
        self.assertEqual(dict(state.source_counts)['execution_permits'], before_sizes['execution_permits'])

    def carried_permit_generation(self, job_id):
        raw = self.runtime.queue.get_job(job_id)['execution_permit']
        permit = SignedExecutionPermit.from_dict(json.loads(raw) if isinstance(raw, str) else raw)
        return int(permit.payload.authorization_generation or 0)

    # ------------------------------------------------------------------ law 7: determinism
    def test_replaying_the_same_history_reconstructs_the_same_state(self):
        fixture = self.enqueue()
        self.execute(fixture.job_id)
        moment = 1_800_000_000.0

        first = reconstruct(self.db, now=moment)
        second = reconstruct(self.db, now=moment)
        self.assertEqual(first.canonical_digest(), second.canonical_digest())
        self.restart()
        third = reconstruct(self.db, now=moment)
        self.assertEqual(third.canonical_digest(), first.canonical_digest(),
                         "a fresh process over the same history must agree exactly")

        # Cross-process, not just cross-instance.
        code = (
            "import json,sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
            "from ciph.kernel.continuity import reconstruct;"
            "print(reconstruct(%r, now=%r).canonical_digest())"
            % (str(Path(__file__).resolve().parents[1]), self.db, moment)
        )
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), first.canonical_digest())

    def test_the_clock_is_an_explicit_input(self):
        """Expiry is a function of the clock, so a different clock is a different (honest) state."""
        fixture = self.enqueue()
        early = reconstruct(self.db, now=1_000_000_000.0)
        late = reconstruct(self.db, now=4_000_000_000.0)
        self.assertEqual(self.action(early).permit_state, 'ISSUED')
        self.assertEqual(self.action(late).permit_state, 'EXPIRED')
        self.assertNotEqual(early.canonical_digest(), late.canonical_digest())

    # ------------------------------------------------------------------ law 8: no guesses
    def test_missing_evidence_yields_unresolved_not_success(self):
        fixture = self.enqueue()
        self.permit_store().claim(fixture.permit_id, 'w')
        # Delete every trace of terminal evidence for this job, as a corrupted store would.
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM ciph_event_store WHERE event_type = 'ExecutionReceiptStoredEvent'")
        state = reconstruct(self.db)
        self.assertEqual(self.action(state).attempt_outcome, AttemptOutcome.UNRESOLVED.value)
        self.assertFalse(self.action(state).terminal_evidence)

    def test_contradictory_attempt_evidence_is_unknown_not_a_match(self):
        fixture = self.enqueue()
        self.permit_store().claim(fixture.permit_id, 'w')
        # A receipt that names this permit but a DIFFERENT attempt: an integrity conflict, not proof.
        self.runtime.event_store.append_event('ExecutionReceiptStoredEvent', 'agg', {
            'provenance': {'manifest_hash': self.cap.manifest.compute_manifest_hash()},
            'governed_authorization': {
                'execution_attempt_id': 'attempt_somebody_else',
                'execution_permit_id': fixture.permit_id,
                'execution_permit_digest': fixture.permit.permit_digest(),
                'authorization_generation': 0,
            },
        })
        state = reconstruct(self.db)
        self.assertEqual(self.action(state).attempt_outcome, AttemptOutcome.UNKNOWN.value)
        self.assertFalse(self.action(state).terminal_evidence)
        self.assertIn(fixture.job_id, state.reconciliation_obligations)

    def test_a_job_naming_a_permit_the_store_no_longer_holds_is_an_integrity_flag(self):
        fixture = self.enqueue()
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM execution_permits WHERE permit_id = ?", (fixture.permit_id,))
        state = reconstruct(self.db)
        self.assertTrue(any(INTEGRITY_JOB_PERMIT_ABSENT_FROM_STORE in f
                            for f in state.integrity_flags), state.integrity_flags)
        self.assertNotEqual(self.action(state).attempt_outcome, AttemptOutcome.TERMINAL.value)

    # ------------------------------------------------------------------ law 3: replanning
    def test_a_logical_action_survives_replanning(self):
        """Plan identity is not action identity: the action key comes from the permit."""
        fixture = self.enqueue()
        self.execute(fixture.job_id)
        before = reconstruct(self.db)

        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE ciph_ipc_jobs SET plan_id = ?, step_id = ? WHERE job_id = ?",
                         ('plan_v2_after_replan', 'step_v2', fixture.job_id))
        after = reconstruct(self.db)

        self.assertEqual([a.logical_action_id for a in after.actions],
                         [a.logical_action_id for a in before.actions])
        self.assertEqual(after.actions[0].logical_action_id,
                         fixture.permit.payload.logical_action_id)
        self.assertEqual(after.canonical_digest(), before.canonical_digest(),
                         "replanning is not a continuity fact")

    # ------------------------------------------------------------------ runnable work
    def test_remaining_authorized_work_names_only_runnable_jobs(self):
        runnable = self.enqueue()
        gone = self.enqueue()
        self.permit_store().claim(gone.permit_id, 'w_that_died')

        state = reconstruct(self.db)
        self.assertIn(runnable.job_id, state.remaining_authorized_work)
        self.assertNotIn(gone.job_id, state.remaining_authorized_work)
        # And the impossible state is NAMED: a leaseable job whose authority is already spent.
        self.assertTrue(any(f.startswith(f"{INTEGRITY_RUNNABLE_JOB_WITH_SPENT_PERMIT}:{gone.job_id}")
                            for f in state.integrity_flags), state.integrity_flags)


if __name__ == '__main__':
    unittest.main()
