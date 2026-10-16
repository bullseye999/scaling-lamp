
"""
Gate A0 - A' advancement law: who may advance the authorization generation, and on what evidence.

Representation alone would let a caller ask for (L, 37) and manufacture fresh authority. These
specimens pin the classification and the monotonic lineage.
"""

import tempfile
import unittest

from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitPayload, time_us
from ciph.kernel.permit_store import ExecutionPermitStore, PermitStoreError
from ciph.kernel.retry_authority import (
    RetryAuthorization,
    RetryNotAuthorized,
    RetryOutcome,
    authorize_next_generation,
    classify_retry,
)


class RetryClassificationTests(unittest.TestCase):

    def test_unspent_authority_is_redelivered_not_regenerated(self):
        self.assertEqual(
            classify_retry(permit_state="ISSUED"), RetryOutcome.REDELIVER_SAME_GENERATION
        )

    def test_a_claimed_attempt_with_unknown_effect_requires_reconciliation(self):
        """A failed call is not evidence that the effect failed."""
        self.assertEqual(
            classify_retry(permit_state="CLAIMED", effect_certainty="EFFECT_UNKNOWN", retry_safe=False,
                           attempts_remaining=5),
            RetryOutcome.RECONCILIATION_REQUIRED,
        )

    def test_a_claimed_attempt_with_no_recorded_certainty_also_reconciles(self):
        self.assertEqual(
            classify_retry(permit_state="CLAIMED", effect_certainty=None, retry_safe=False,
                           attempts_remaining=5),
            RetryOutcome.RECONCILIATION_REQUIRED,
        )

    def test_an_independent_retry_safety_proof_reaches_next_generation(self):
        """Reachability: without this precedence the claimed-retry branch would be dead."""
        self.assertEqual(
            classify_retry(permit_state="CLAIMED", effect_certainty="EFFECT_UNKNOWN", retry_safe=True,
                           attempts_remaining=3),
            RetryOutcome.NEXT_GENERATION,
        )

    def test_an_unsigned_retry_authorization_cannot_be_constructed(self):
        with self.assertRaises(ValueError) as caught:
            RetryAuthorization(logical_action_id="L", next_generation=1)
        self.assertIn("CANONICAL_CLASSIFIER", str(caught.exception))

    def test_the_canonical_path_refuses_to_authorize_when_the_classifier_says_no(self):
        with self.assertRaises(RetryNotAuthorized):
            authorize_next_generation(
                logical_action_id="L", previous_generation=0, permit_state="CLAIMED",
                effect_certainty="EFFECT_UNKNOWN", retry_safe=False, attempts_remaining=3,
            )

    def test_a_claimed_confirmed_effect_is_terminal(self):
        self.assertEqual(
            classify_retry(permit_state="CLAIMED", effect_certainty="EFFECT_CONFIRMED", retry_safe=True,
                           attempts_remaining=5),
            RetryOutcome.TERMINAL,
        )

    def test_a_retry_safe_claimed_failure_advances(self):
        self.assertEqual(
            classify_retry(permit_state="CLAIMED", effect_certainty="NO_EFFECT_CONFIRMED", retry_safe=True,
                           attempts_remaining=2),
            RetryOutcome.NEXT_GENERATION,
        )

    def test_an_exhausted_retry_budget_is_terminal(self):
        self.assertEqual(
            classify_retry(permit_state="CLAIMED", effect_certainty="NO_EFFECT_CONFIRMED", retry_safe=True,
                           attempts_remaining=0),
            RetryOutcome.TERMINAL,
        )


class MonotonicGenerationTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_gen_")
        self.db = f"{self._dir}/vault.db"
        self.store = ExecutionPermitStore(self.db)
        self.authority, _ = ExecutionAuthority.generate()

    def _permit(self, logical_action_id, fingerprint="A", generation=0):
        payload = ExecutionPermitPayload.build(
            capability_id="cap.read", request_digest="rd", action_fingerprint=fingerprint,
            issued_at_us=time_us(), ttl_seconds=600.0, logical_action_id=logical_action_id,
            authorization_generation=generation,
        )
        return self.authority.issue_permit(payload)

    def _register(self, permit, job_id=None, retry_authorization=None):
        return self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint,
            authorization_generation=permit.payload.authorization_generation,
            retry_authorization=retry_authorization,
            job_id=job_id,
        )

    def test_a_producer_cannot_simply_ask_for_generation_one(self):
        """Ordinary issuance is generation 0; generation 1 needs the canonical proof object."""
        self._register(self._permit("L-ASK", generation=0))
        with self.assertRaises(PermitStoreError) as caught:
            self._register(self._permit("L-ASK", generation=1))
        self.assertEqual(caught.exception.reason, "DENY_RETRY_NOT_AUTHORIZED")

    def test_a_generation_may_not_skip(self):
        """Even a canonically AUTHORIZED retry cannot leapfrog the lineage."""
        authorization = authorize_next_generation(
            logical_action_id="L-SKIP", previous_generation=1, permit_state="CLAIMED",
            effect_certainty="NO_EFFECT_CONFIRMED", retry_safe=True, attempts_remaining=1,
        )
        with self.assertRaises(PermitStoreError) as caught:
            self._register(
                self._permit("L-SKIP", generation=2), retry_authorization=authorization
            )
        self.assertEqual(caught.exception.reason, "DENY_GENERATION_SKIP")

    def test_a_retry_safe_failure_allows_generation_one_with_a_fresh_permit(self):
        first = self._permit("L-RETRY", generation=0)
        self._register(first)
        self.store.claim(first.payload.permit_id, "w1", digest=first.permit_digest())

        outcome = classify_retry(
            permit_state="CLAIMED", effect_certainty="NO_EFFECT_CONFIRMED",
            retry_safe=True, attempts_remaining=1,
        )
        self.assertEqual(outcome, RetryOutcome.NEXT_GENERATION)

        authorization = authorize_next_generation(
            logical_action_id="L-RETRY", previous_generation=0, permit_state="CLAIMED",
            effect_certainty="NO_EFFECT_CONFIRMED", retry_safe=True, attempts_remaining=1,
        )
        second = self._permit("L-RETRY", generation=1)
        self.assertTrue(self._register(second, retry_authorization=authorization).registered)
        self.assertEqual(second.payload.logical_action_id, first.payload.logical_action_id)
        self.assertNotEqual(second.payload.permit_id, first.payload.permit_id)
        self.assertEqual(second.payload.action_fingerprint, first.payload.action_fingerprint)

    def test_a_spent_permit_cannot_be_claimed_twice(self):
        """Each generation keeps one permit and one claim, however often it is delivered."""
        permit = self._permit("L-ONCE", generation=0)
        self._register(permit)
        self.store.claim(permit.payload.permit_id, "w1", digest=permit.permit_digest())

        with self.assertRaises(PermitStoreError):
            self.store.claim(permit.payload.permit_id, "w2", digest=permit.permit_digest())


class NonBroadeningRetryDerivationTests(unittest.TestCase):
    """A retry renews authority; it never turns "run this again" into "choose something else"."""

    def setUp(self):
        from ciph.kernel.execution_authority import ExecutionAuthority
        self.authority, _ = ExecutionAuthority.generate()

    def _permit(self, *, generation=0, target=None):
        from ciph.kernel.execution_authority import ExecutionPermitPayload, time_us
        payload = ExecutionPermitPayload.build(
            capability_id="cap.read", request_digest="rd", action_fingerprint="A",
            issued_at_us=time_us(), ttl_seconds=600.0, logical_action_id="L-DERIVE",
            authorization_generation=generation, target=target,
            mission_id="M-1", authorization_envelope_id="E-1",
        )
        return self.authority.issue_permit(payload)

    def test_identity_is_carried_from_the_permit_not_the_caller(self):
        from ciph.kernel.retry_authority import derive_retry_request
        permit = self._permit()

        request = derive_retry_request(permit, params={"k": "v"})

        self.assertEqual(request.capability, permit.payload.capability_id)
        self.assertEqual(request.logical_action_id, permit.payload.logical_action_id)
        self.assertEqual(request.action_fingerprint, permit.payload.action_fingerprint)
        self.assertEqual(request.mission_id, permit.payload.mission_id)
        self.assertEqual(request.authorization_envelope_id, permit.payload.authorization_envelope_id)
        self.assertEqual(request.authorization_generation, 1)

    def test_the_derivation_accepts_no_capability_or_envelope_arguments(self):
        """Structural: a caller cannot repoint the retry at another action."""
        import inspect
        from ciph.kernel.retry_authority import derive_retry_request
        parameters = set(inspect.signature(derive_retry_request).parameters)
        for forbidden in ("capability", "logical_action_id", "action_fingerprint",
                          "mission_id", "authorization_envelope_id", "authorization_epoch"):
            self.assertNotIn(forbidden, parameters)

    def test_a_widened_target_is_refused(self):
        from ciph.kernel.retry_authority import derive_retry_request
        permit = self._permit(target="repo-A")
        with self.assertRaises(ValueError) as caught:
            derive_retry_request(permit, params={"k": "v"}, target="repo-B")
        self.assertIn("TARGET_WIDENING", str(caught.exception))

    def test_the_horizon_may_only_shrink(self):
        from ciph.kernel.retry_authority import derive_retry_request
        permit = self._permit()
        original = permit.payload.expires_at_us / 1_000_000.0
        now = original - 30.0

        request = derive_retry_request(permit, params={"k": "v"}, now=now, claim_horizon_seconds=600.0)

        # Never beyond the original permit's horizon, even though 600s was requested.
        self.assertLessEqual(request.authorization_generation, 1)
        self.assertEqual(request.capability, permit.payload.capability_id)

    def test_an_exhausted_horizon_refuses_to_derive(self):
        from ciph.kernel.retry_authority import derive_retry_request
        permit = self._permit()
        expired = permit.payload.expires_at_us / 1_000_000.0 + 1.0
        with self.assertRaises(ValueError) as caught:
            derive_retry_request(permit, params={"k": "v"}, now=expired)
        self.assertIn("HORIZON_EXHAUSTED", str(caught.exception))


class SharedTransactionSeamTests(unittest.TestCase):
    """
    Atomic retry wiring needs the permit registration to enrol in the caller's transaction, or
    "classify -> register N+1 -> requeue" cannot be one atomic step.
    """

    def setUp(self):
        import tempfile
        from ciph.kernel.execution_authority import ExecutionAuthority
        self._dir = tempfile.mkdtemp(prefix="ciph_txn_")
        self.db = f"{self._dir}/vault.db"
        self.store = ExecutionPermitStore(self.db)
        self.authority, _ = ExecutionAuthority.generate()

    def _permit(self, logical_action_id):
        from ciph.kernel.execution_authority import ExecutionPermitPayload, time_us
        payload = ExecutionPermitPayload.build(
            capability_id="cap.read", request_digest="rd", action_fingerprint="A",
            issued_at_us=time_us(), ttl_seconds=600.0, logical_action_id=logical_action_id,
        )
        return self.authority.issue_permit(payload)

    def _register(self, permit, conn):
        return self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint,
            conn=conn,
        )

    def _conn(self):
        import sqlite3
        conn = sqlite3.connect(self.db, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def test_a_caller_rollback_removes_the_registration(self):
        permit = self._permit("L-TXN-ROLLBACK")
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self.assertTrue(self._register(permit, conn).registered)
            conn.execute("ROLLBACK")
        finally:
            conn.close()

        self.assertIsNone(
            self.store._blocking_permit_row("L-TXN-ROLLBACK"),
            "the store must not have committed inside the caller's transaction",
        )

    def test_a_caller_commit_persists_the_registration(self):
        permit = self._permit("L-TXN-COMMIT")
        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self.assertTrue(self._register(permit, conn).registered)
            conn.execute("COMMIT")
        finally:
            conn.close()

        row = self.store._blocking_permit_row("L-TXN-COMMIT")
        self.assertIsNotNone(row)
        self.assertEqual(row["permit_id"], permit.payload.permit_id)


if __name__ == "__main__":
    unittest.main()
