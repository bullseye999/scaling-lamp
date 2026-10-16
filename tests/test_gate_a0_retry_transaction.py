
"""
Gate A0 - the atomic retry transition.

One BEGIN IMMEDIATE over job state, permit state and the exact attempt's evidence. These specimens
prove the two impossibility properties, not merely the returned status.

RETRY SAFETY IS DERIVED HERE, NOT ACCEPTED. The transition no longer takes a caller verdict: it
resolves the capability manifest centrally and requires the exact attempt's evidence to attest that
same manifest identity before a declared replay guarantee counts as proof. `retry_safe` survives only
as an internal parameter of the classifier primitives.
"""

import json
import sqlite3
import tempfile
import unittest

from ciph.contracts.enums import (
    AuthorizationTier,
    NetworkPolicy,
    ReplaySemantics,
    ReversibilityClass,
    RiskTier,
)
from ciph.kernel.execution_authority import SignedExecutionPermit
from ciph.kernel.permit_composition import build_durable_permit_dependencies
from ciph.kernel.permit_store import ExecutionPermitStore
from ciph.kernel.policy_engine import CapabilityManifest, replay_policy_digest
from ciph.kernel.retry_transaction import apply_retry_transition
from ciph.memory.event_store import EventStore
from ciph.workers.ipc_queue import IPCJobQueue


def _manifest(semantics):
    return CapabilityManifest(
        name="cap.read", description="retry-transaction specimen",
        risk_tier=RiskTier.NONE, network_policy=NetworkPolicy.OFFLINE_ONLY,
        reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO,
        replay_semantics=semantics,
    )


class _RetryTransactionHarness(unittest.TestCase):
    """Shared plumbing: one job, one permit, one canonical store."""

    PERMIT_CAPABILITY = "cap.read"

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_rtxn_")
        self.db = f"{self._dir}/vault.db"
        self.queue = IPCJobQueue(self.db)
        self.store = ExecutionPermitStore(self.db)
        self.events = EventStore(self.db)
        self.deps = build_durable_permit_dependencies(self.db)
        self.safe_manifest = _manifest(ReplaySemantics.IDEMPOTENT)
        self.unsafe_manifest = _manifest(ReplaySemantics.UNSAFE)

    def _resolver(self, manifest):
        return lambda capability_id: manifest if capability_id == self.PERMIT_CAPABILITY else None

    def _attest(self, permit, certainty="EFFECT_UNKNOWN", manifest_hash=None, attempt_id=None,
                replay_policy_digest_value="__BOUND__"):
        """Write the exact attempt's evidence, attesting manifest identity AND policy binding."""
        row = self.store.get_permit_row(permit.payload.permit_id)
        attested_binding = (permit.payload.replay_policy_digest
                            if replay_policy_digest_value == "__BOUND__"
                            else replay_policy_digest_value)
        self.events.append_event("ExecutionReceiptStoredEvent", "agg", {
            "provenance": {
                "manifest_hash": (manifest_hash if manifest_hash is not None
                                  else self.safe_manifest.compute_manifest_hash()),
                "replay_policy_digest": attested_binding,
            },
            "governed_authorization": {
                "execution_attempt_id": attempt_id or row["execution_attempt_id"],
                "execution_permit_id": permit.payload.permit_id,
                "execution_permit_digest": permit.permit_digest(),
                "authorization_generation": int(permit.payload.authorization_generation or 0),
                "effect_certainty": certainty,
            },
        })


class AtomicRetryTransitionTests(_RetryTransactionHarness):

    def _enqueue(self, job_id="JOB-R1", max_retries=3, manifest=None):
        from ciph.kernel.execution_gateway import ExecutionRequest
        request = ExecutionRequest(
            capability=self.PERMIT_CAPABILITY, params={"k": "v"}, target=None,
            logical_action_id=job_id, route="test",
            replay_policy_digest=replay_policy_digest(manifest or self.safe_manifest),
        )
        permit = self.deps.gateway.issue_permit(request)
        self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint, job_id=job_id,
        )
        self.queue.enqueue_job(
            capability=self.PERMIT_CAPABILITY, params={"k": "v"}, job_id=job_id,
            idempotency_key=job_id, max_retries=max_retries, execution_permit=permit,
        )
        return permit

    def _go(self, permit, **kw):
        kw.setdefault("manifest_resolver", self._resolver(self.safe_manifest))
        return apply_retry_transition(
            db_path=self.db, queue=self.queue, permit_store=self.store, event_store=self.events,
            dependencies=self.deps, job_id=kw.pop("job_id", "JOB-R1"),
            expected_permit_id=permit.payload.permit_id, **kw
        )

    def _carried(self, job_id="JOB-R1"):
        return self.queue.get_job_for_retry(job_id)["execution_permit"]

    def _generation_gt_zero(self):
        with sqlite3.connect(self.db) as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM execution_permits WHERE authorization_generation > 0;"
            ).fetchone()[0]

    def test_the_caller_can_no_longer_state_a_retry_verdict(self):
        """The parameter is gone: a verdict cannot be smuggled in from any call site."""
        permit = self._enqueue()
        with self.assertRaises(TypeError):
            apply_retry_transition(
                db_path=self.db, queue=self.queue, permit_store=self.store, event_store=self.events,
                dependencies=self.deps, job_id="JOB-R1",
                expected_permit_id=permit.payload.permit_id, 
                retry_safe=True,
            )

    def test_unspent_authority_redelivers_the_same_permit(self):
        permit = self._enqueue()
        # Lost lease before any claim: the permit is still ISSUED.
        result = self._go(permit, )

        self.assertTrue(result.applied)
        self.assertEqual(result.outcome, "REDELIVER_SAME_GENERATION")
        self.assertEqual(result.permit_id, permit.payload.permit_id)
        self.assertEqual(result.generation, 0)
        self.assertIsNotNone(self._carried())

    def test_a_declared_safe_claimed_failure_installs_generation_one_atomically(self):
        permit = self._enqueue()
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_UNKNOWN")

        result = self._go(permit, )

        self.assertTrue(result.applied)
        self.assertEqual(result.outcome, "NEXT_GENERATION")
        self.assertEqual(result.generation, 1)
        self.assertEqual(result.safety_source, "CAPABILITY_REPLAY_DECLARATION")
        self.assertIsNotNone(self.store.get_permit_row(result.permit_id), "N+1 must be registered")
        carried = SignedExecutionPermit.from_dict(json.loads(self._carried()))
        self.assertEqual(carried.payload.logical_action_id, permit.payload.logical_action_id)
        self.assertEqual(carried.payload.permit_id, result.permit_id)
        self.assertEqual(self.queue.get_job_for_retry("JOB-R1")["status"], "RETRYING")

    def test_a_policy_widened_after_issuance_confers_no_retroactive_authority(self):
        """The declaration flipped UNSAFE -> IDEMPOTENT with the manifest identity untouched.

        That is exactly the widening the manifest identity cannot catch, because `ReplaySemantics`
        is outside the frozen V1 hash. The permit's ISSUANCE binding is what refuses it.
        """
        permit = self._enqueue(manifest=self.unsafe_manifest)
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_UNKNOWN")
        self.assertEqual(self.unsafe_manifest.compute_manifest_hash(),
                         self.safe_manifest.compute_manifest_hash(),
                         "the two declarations must share one identity or this proves nothing")

        result = self._go(permit)  # current declaration is IDEMPOTENT; the permit bound UNSAFE

        self.assertEqual(result.outcome, "RECONCILIATION_REQUIRED")
        self.assertEqual(self._generation_gt_zero(), 0)

    def test_a_policy_narrowed_after_issuance_also_refuses(self):
        """The inverse: mutable current policy may never be used to keep authority alive."""
        permit = self._enqueue(manifest=self.safe_manifest)
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_UNKNOWN")

        result = self._go(permit, manifest_resolver=self._resolver(self.unsafe_manifest))

        self.assertEqual(result.outcome, "RECONCILIATION_REQUIRED")
        self.assertEqual(self._generation_gt_zero(), 0)

    def test_evidence_that_attests_a_different_policy_binding_is_no_proof(self):
        permit = self._enqueue()
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_UNKNOWN", replay_policy_digest_value="0" * 64)

        result = self._go(permit)

        self.assertEqual(result.outcome, "RECONCILIATION_REQUIRED")
        self.assertEqual(self._generation_gt_zero(), 0)

    def test_without_a_capability_declaration_an_unknown_effect_reconciles(self):
        """The capability says nothing: no proof exists, so uncertainty is not retryable."""
        permit = self._enqueue(manifest=self.unsafe_manifest)
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_UNKNOWN")
        before = self._carried()

        result = self._go(permit, 
                          manifest_resolver=self._resolver(self.unsafe_manifest))

        self.assertTrue(result.applied)
        self.assertEqual(result.outcome, "RECONCILIATION_REQUIRED")
        self.assertEqual(self._carried(), before)
        self.assertEqual(self._generation_gt_zero(), 0)

    def test_a_declaration_cannot_be_borrowed_from_another_manifest(self):
        """Evidence attesting a DIFFERENT manifest identity yields no proof, not a weaker one."""
        permit = self._enqueue()
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_UNKNOWN", manifest_hash="0" * 64)

        result = self._go(permit, )

        self.assertEqual(result.outcome, "RECONCILIATION_REQUIRED")
        self.assertEqual(self._generation_gt_zero(), 0)

    def test_an_effect_confirmed_attempt_is_terminal_even_when_the_capability_declares_safety(self):
        permit = self._enqueue()
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_CONFIRMED")

        result = self._go(permit, )

        self.assertEqual(result.outcome, "TERMINAL")
        self.assertEqual(self.queue.get_job_for_retry("JOB-R1")["status"], "FAILED")
        self.assertEqual(self._generation_gt_zero(), 0)

    def test_an_exhausted_execution_budget_is_terminal(self):
        """max_retries is the total executed-attempt budget and is derived, never reported."""
        permit = self._enqueue(max_retries=1)
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_UNKNOWN")

        result = self._go(permit)

        self.assertTrue(result.applied, result.reason)
        self.assertEqual(result.outcome, "TERMINAL")
        self.assertEqual(self.queue.get_job_for_retry("JOB-R1")["status"], "FAILED")
        self.assertIsNone(self.queue.lease_next_job("w2", 30))
        self.assertEqual(self._generation_gt_zero(), 0)

    def test_a_claimed_attempt_with_no_attributable_evidence_reconciles(self):
        permit = self._enqueue()
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        before = self._carried()

        result = self._go(permit, )

        self.assertEqual(result.outcome, "RECONCILIATION_REQUIRED")
        # The job must NOT stay runnable while carrying a spent, unusable permit.
        status = self.queue.get_job_for_retry("JOB-R1")["status"]
        self.assertEqual(status, "RECONCILIATION_REQUIRED")
        self.assertNotIn(status, ("QUEUED", "RETRYING", "LEASED", "EXECUTING"))
        self.assertEqual(self._carried(), before, "no N+1 permit was installed")
        self.assertEqual(self._generation_gt_zero(), 0, "no next-generation permit may exist")

    def test_a_stale_report_after_the_job_moved_on_is_refused(self):
        permit = self._enqueue()
        result = self._go(permit, )  # moves to RETRYING, same permit
        self.assertTrue(result.applied)

        stale = apply_retry_transition(
            db_path=self.db, queue=self.queue, permit_store=self.store, event_store=self.events,
            dependencies=self.deps, job_id="JOB-R1",
            expected_permit_id="permit_long_gone", 
            manifest_resolver=self._resolver(self.safe_manifest),
        )
        self.assertFalse(stale.applied)
        self.assertEqual(stale.reason, "STALE_CORRELATION")

    def test_a_failure_after_registration_rolls_back_everything(self):
        permit = self._enqueue()
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        self._attest(permit, certainty="EFFECT_UNKNOWN")
        before = self._carried()
        original = self.queue.apply_retry_transition

        def _boom(**kwargs):
            if kwargs.get("conn") is not None:
                raise RuntimeError("injected failure after N+1 registration")
            return original(**kwargs)

        self.queue.apply_retry_transition = _boom
        try:
            with self.assertRaises(RuntimeError):
                self._go(permit, )
        finally:
            self.queue.apply_retry_transition = original

        self.assertEqual(self._generation_gt_zero(), 0, "the registered N+1 must be rolled back")
        self.assertEqual(self._carried(), before, "the job must be unchanged")
        self.assertEqual(self.queue.get_job_for_retry("JOB-R1")["status"], "QUEUED")


class NoRunnableSpentAuthorityTests(_RetryTransactionHarness):
    """The final state-machine property: no committed state has a runnable job + unusable permit."""

    def _enqueue_claimed(self, job_id="JOB-N1", max_retries=3, manifest=None):
        from ciph.kernel.execution_gateway import ExecutionRequest
        request = ExecutionRequest(
            capability=self.PERMIT_CAPABILITY, params={"k": "v"}, target=None,
            logical_action_id=job_id, route="test",
            replay_policy_digest=replay_policy_digest(manifest or self.safe_manifest),
        )
        permit = self.deps.gateway.issue_permit(request)
        self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint, job_id=job_id,
        )
        self.queue.enqueue_job(capability=self.PERMIT_CAPABILITY, params={"k": "v"}, job_id=job_id,
                              idempotency_key=job_id, max_retries=max_retries, execution_permit=permit)
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())
        return permit

    def test_no_attributable_evidence_leaves_the_job_non_runnable(self):
        permit = self._enqueue_claimed()
        result = apply_retry_transition(
            db_path=self.db, queue=self.queue, permit_store=self.store, event_store=self.events,
            dependencies=self.deps, job_id="JOB-N1",
            expected_permit_id=permit.payload.permit_id, 
            manifest_resolver=self._resolver(self.safe_manifest),
        )
        status = self.queue.get_job_for_retry("JOB-N1")["status"]
        self.assertEqual(result.outcome, "RECONCILIATION_REQUIRED")
        self.assertNotIn(status, ("QUEUED", "RETRYING", "LEASED", "EXECUTING"))
        # And it cannot be leased back out.
        self.assertIsNone(self.queue.lease_next_job("w2", 30))

    def test_an_integrity_conflict_also_leaves_the_job_non_runnable(self):
        permit = self._enqueue_claimed("JOB-N2")
        self.events.append_event("ExecutionReceiptStoredEvent", "agg", {
            "governed_authorization": {
                "execution_attempt_id": "A-nobody", "execution_permit_id": permit.payload.permit_id,
                "execution_permit_digest": "D-WRONG", "authorization_generation": 0,
            }
        })
        result = apply_retry_transition(
            db_path=self.db, queue=self.queue, permit_store=self.store, event_store=self.events,
            dependencies=self.deps, job_id="JOB-N2",
            expected_permit_id=permit.payload.permit_id, 
            manifest_resolver=self._resolver(self.safe_manifest),
        )
        self.assertEqual(result.outcome, "INTEGRITY_CONFLICT")
        self.assertNotIn(self.queue.get_job_for_retry("JOB-N2")["status"],
                         ("QUEUED", "RETRYING", "LEASED", "EXECUTING"))
        self.assertIsNone(self.queue.lease_next_job("w2", 30))


if __name__ == "__main__":
    unittest.main()
