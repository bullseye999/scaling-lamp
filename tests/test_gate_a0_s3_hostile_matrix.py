
"""
Gate A0 / S3 - hostile, crash and replay matrix for the sealed authority model.

These specimens are not about a new concept. They are the adversarial cases the S3 constitution is
supposed to make *unrepresentable*, each asserted against the canonical artifacts rather than
against a returned status:

    a success receipt that cannot name its attempt
    evidence that leaks between authorization generations
    a carried permit that was tampered with in the row
    a caller stating a retry verdict
    a pre-claim transport refusal that quietly creates authority
"""

import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ciph.contracts.enums import ReplaySemantics
from ciph.kernel.execution_authority import SignedExecutionPermit
from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
from ciph.memory.event_store import AttemptEvidenceOutcome, governed_authorization_block
from ciph.runtime import CiphRuntime
from ciph.workers.receipts import OutcomeCategory
from permit_test_support import enqueue_permit_bearing_job
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability


class TestS3HostileMatrix(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-s3-hostile-')
        self.db = str(Path(self.temp.name) / 'jobs.db')
        self.runtime = CiphRuntime(db_path=self.db)
        self.cap = SimpleComputeCapability(name='review.compute')
        self.runtime.register_capability(self.cap)

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def idempotent_cap(self, name='review.compute_idempotent', **kwargs):
        class IdempotentCompute(SimpleComputeCapability):
            @property
            def manifest(self):
                return replace(super().manifest, replay_semantics=ReplaySemantics.IDEMPOTENT)
        cap = IdempotentCompute(name, **kwargs)
        self.runtime.register_capability(cap)
        return cap

    def enqueue(self, cap=None, params=None, attempts=3):
        cap = cap or self.cap
        return enqueue_permit_bearing_job(
            self.runtime, capability=cap.manifest.name, params=params or {'value': 1},
            max_retries=attempts,
        )

    def execute(self, job_id, worker='hostile_worker'):
        job = self.runtime.queue.lease_next_job(worker, 30, target_job_id=job_id)
        return self.runtime.worker_daemon._execute_leased_job(job, worker) if job else None

    def carried_permit(self, job_id):
        raw = self.runtime.queue.get_job(job_id)['execution_permit']
        return SignedExecutionPermit.from_dict(json.loads(raw) if isinstance(raw, str) else raw)

    def permit_store(self):
        return build_durable_permit_consumer_dependencies(
            self.db, trust_registry=self.runtime.trust_registry
        ).permit_store

    def generation_count(self):
        with sqlite3.connect(self.db) as conn:
            return conn.execute(
                'SELECT COUNT(*) FROM execution_permits WHERE authorization_generation > 0'
            ).fetchone()[0]

    # ------------------------------------------------------------------ 1. attempt identity
    def test_a_successful_receipt_names_the_exact_attempt(self):
        """A success receipt must be attributable to one canonical claim, not to "the job"."""
        fixture = self.enqueue()
        receipt = self.execute(fixture.job_id)
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.outcome, OutcomeCategory.SUCCESS)

        block = (receipt.provenance or {})['governed_authorization']
        row = self.permit_store().get_permit_row(fixture.permit_id)
        self.assertEqual(block['execution_attempt_id'], row['execution_attempt_id'])
        self.assertEqual(block['execution_permit_id'], fixture.permit_id)
        self.assertEqual(block['execution_permit_digest'], fixture.permit.permit_digest())
        self.assertEqual(int(block['authorization_generation']), 0)
        self.assertEqual(block['logical_action_id'], fixture.permit.payload.logical_action_id)

        # And the canonical reader finds exactly that attempt's evidence.
        evidence = self.runtime.event_store.get_attempt_evidence(
            execution_attempt_id=row['execution_attempt_id'],
            permit_id=fixture.permit_id,
            permit_digest=fixture.permit.permit_digest(),
            authorization_generation=0,
        )
        self.assertIs(evidence.outcome, AttemptEvidenceOutcome.ATTRIBUTABLE)
        self.assertEqual(len(evidence.events), 1)

    # ------------------------------------------------------------------ 2. generation isolation
    def test_attempt_evidence_is_isolated_between_authorization_generations(self):
        """A0's evidence must never be reachable through A1's identity, or the reverse."""
        cap = self.idempotent_cap(should_fail=True)
        fixture = self.enqueue(cap=cap, attempts=3)
        permit0 = fixture.permit
        first = self.execute(fixture.job_id)
        self.assertNotEqual(first.exit_code, 0)

        permit1 = self.carried_permit(fixture.job_id)
        self.assertEqual(int(permit1.payload.authorization_generation or 0), 1)
        cap.should_fail = False
        second = self.execute(fixture.job_id)
        self.assertEqual(second.exit_code, 0)

        store = self.permit_store()
        row0 = store.get_permit_row(permit0.payload.permit_id)
        row1 = store.get_permit_row(permit1.payload.permit_id)
        self.assertNotEqual(row0['execution_attempt_id'], row1['execution_attempt_id'])

        evidence0 = self.runtime.event_store.get_attempt_evidence(
            execution_attempt_id=row0['execution_attempt_id'], permit_id=permit0.payload.permit_id,
            permit_digest=permit0.permit_digest(), authorization_generation=0,
        )
        evidence1 = self.runtime.event_store.get_attempt_evidence(
            execution_attempt_id=row1['execution_attempt_id'], permit_id=permit1.payload.permit_id,
            permit_digest=permit1.permit_digest(), authorization_generation=1,
        )
        self.assertIs(evidence0.outcome, AttemptEvidenceOutcome.ATTRIBUTABLE)
        self.assertIs(evidence1.outcome, AttemptEvidenceOutcome.ATTRIBUTABLE)

        def attempt_ids(evidence):
            # Read the block the ONE canonical way: a receipt carries it inside `provenance`.
            return {governed_authorization_block(e).get('execution_attempt_id')
                    for e in evidence.events}

        self.assertEqual(attempt_ids(evidence0), {row0['execution_attempt_id']})
        self.assertEqual(attempt_ids(evidence1), {row1['execution_attempt_id']})

        # A generation-1 identity must not be satisfied by generation-0 evidence with a lie about
        # the generation: that is an integrity conflict, never a match.
        mismatched = self.runtime.event_store.get_attempt_evidence(
            execution_attempt_id=row0['execution_attempt_id'], permit_id=permit0.payload.permit_id,
            permit_digest=permit0.permit_digest(), authorization_generation=1,
        )
        self.assertIs(mismatched.outcome, AttemptEvidenceOutcome.INTEGRITY_CONFLICT)

    # ------------------------------------------------------------------ 3. tampered carriage
    def test_a_tampered_carried_permit_is_refused_before_the_body_runs(self):
        fixture = self.enqueue()
        with sqlite3.connect(self.db) as conn:
            row = conn.execute('SELECT execution_permit FROM ciph_ipc_jobs WHERE job_id = ?;',
                               (fixture.job_id,)).fetchone()[0]
        tampered = json.loads(row)
        tampered['signature'] = '00' * max(1, len(tampered['signature']) // 2)
        with sqlite3.connect(self.db) as conn:
            conn.execute('UPDATE ciph_ipc_jobs SET execution_permit = ? WHERE job_id = ?;',
                         (json.dumps(tampered), fixture.job_id))

        receipt = self.execute(fixture.job_id)
        self.assertNotEqual(receipt.exit_code, 0)
        self.assertEqual(self.cap.execution_count, 0)
        self.assertEqual(self.generation_count(), 0)

    def test_a_pre_claim_transport_refusal_creates_no_authority(self):
        """A dead transport session refuses the delivery; it must not mint, spend or advance."""
        fixture = self.enqueue()
        with sqlite3.connect(self.db) as conn:
            token = json.loads(conn.execute(
                'SELECT execution_token FROM ciph_ipc_jobs WHERE job_id = ?;',
                (fixture.job_id,)).fetchone()[0])
        token['signature'] = '00' * max(1, len(token['signature']) // 2)
        with sqlite3.connect(self.db) as conn:
            conn.execute('UPDATE ciph_ipc_jobs SET execution_token = ? WHERE job_id = ?;',
                         (json.dumps(token), fixture.job_id))

        receipt = self.execute(fixture.job_id)
        self.assertNotEqual(receipt.exit_code, 0)
        self.assertEqual(self.cap.execution_count, 0)
        # The permit was never spent and no successor generation exists.
        self.assertEqual(self.permit_store().state_of(fixture.permit_id), 'ISSUED')
        self.assertEqual(self.generation_count(), 0)

    # ------------------------------------------------------------------ 3b. no retroactive policy
    def test_a_replay_declaration_cannot_be_widened_retroactively(self):
        """The exact attack the manifest identity cannot catch.

        `ReplaySemantics` is outside the frozen V1 manifest hash, so flipping UNSAFE -> IDEMPOTENT
        leaves the identity untouched. If retry safety were read from the CURRENT declaration, the
        attempt that ran under UNSAFE would retroactively acquire retry authority. It must not: the
        permit bound UNSAFE at issuance, so no proof can exist.
        """
        cap = SimpleComputeCapability(name='review.compute_widen', should_fail=True)
        self.runtime.register_capability(cap)
        fixture = self.enqueue(cap=cap, attempts=3)
        permit0 = self.carried_permit(fixture.job_id)

        receipt = self.execute(fixture.job_id)
        self.assertNotEqual(receipt.exit_code, 0)
        self.assertEqual(self.runtime.queue.get_job(fixture.job_id)['status'],
                         'RECONCILIATION_REQUIRED')
        self.assertEqual(self.generation_count(), 0)

        widened = self.idempotent_cap(name='review.compute_widen', should_fail=True)
        self.assertEqual(widened.manifest.compute_manifest_hash(),
                         cap.manifest.compute_manifest_hash(),
                         "the identity must be unchanged, or this specimen proves nothing")

        result = self.runtime.retry_disposition(
            job_id=fixture.job_id, expected_permit_id=permit0.payload.permit_id)

        self.assertEqual(result.outcome, 'RECONCILIATION_REQUIRED')
        self.assertIsNone(result.permit_id)
        self.assertEqual(self.generation_count(), 0,
                         "an edited declaration may not reach backwards in time")

    def test_a_replay_declaration_narrowed_after_issuance_also_refuses(self):
        """The inverse direction: mutable current policy may never keep authority alive."""
        cap = self.idempotent_cap(should_fail=True, name='review.compute_narrow')
        fixture = self.enqueue(cap=cap, attempts=3)

        first = self.execute(fixture.job_id)
        self.assertNotEqual(first.exit_code, 0)
        self.assertEqual(self.runtime.queue.get_job(fixture.job_id)['status'], 'RETRYING')
        permit1 = self.carried_permit(fixture.job_id)
        self.assertEqual(int(permit1.payload.authorization_generation or 0), 1)

        # Narrow the declaration: the capability now declares UNSAFE, identity unchanged.
        narrowed = SimpleComputeCapability(name='review.compute_narrow', should_fail=True)
        self.runtime.register_capability(narrowed)

        second = self.execute(fixture.job_id)
        self.assertNotEqual(second.exit_code, 0)
        self.assertEqual(self.runtime.queue.get_job(fixture.job_id)['status'],
                         'RECONCILIATION_REQUIRED')
        self.assertEqual(self.generation_count(), 1, "no N+2 after the policy narrowed")

    # ------------------------------------------------------------------ 4. no caller verdict
    def test_no_caller_can_state_a_retry_verdict(self):
        fixture = self.enqueue()
        with self.assertRaises(TypeError):
            self.runtime.retry_disposition(
                job_id=fixture.job_id, expected_permit_id=fixture.permit_id, retry_safe=True,
            )
        with self.assertRaises(TypeError):
            self.runtime.retry_disposition(
                job_id=fixture.job_id, expected_permit_id=fixture.permit_id, attempts_remaining=3,
            )


if __name__ == "__main__":
    unittest.main()
