"""
Gate A0 closure test - Step 4: durable permit lifecycle.

Decision of record: EXECUTION PERMIT V1.

THE TWO PROPERTIES THAT MATTER
  single claimant   two workers racing for one permit: exactly one wins, enforced by the database
  derived expiry    a stalled expiry worker must never be able to extend authority

A consumed or claimed permit is NOT evidence that the capability succeeded. These tests never
assert that, because the store does not know it.
"""

import os
import tempfile
import threading
import time
import unittest

from ciph.kernel.permit_store import (
    DENY_ALREADY_CLAIMED,
    OUTCOME_INVALID_AT_TIME,
    OUTCOME_UNVERIFIABLE_HISTORY,
    OUTCOME_VALID_AT_TIME,
    DENY_ALREADY_CONSUMED,
    DENY_DIGEST_MISMATCH,
    DENY_EPOCH_MISMATCH,
    DENY_EXPIRED,
    DENY_NOT_CLAIMANT,
    DENY_REVOKED,
    DENY_UNKNOWN,
    STATE_CLAIMED,
    STATE_CONSUMED,
    STATE_EXPIRED,
    STATE_ISSUED,
    STATE_REVOKED,
    ExecutionPermitStore,
    PermitStoreError,
    permit_digest,
)


class _History:
    """
    Stands in for the evented authority history that does not exist yet.

    Its presence in these tests is deliberate: it is the shape the real authority_at(T)
    reconstruction must eventually provide, and the absence of that reconstruction is what
    makes the third verdict UNVERIFIABLE_HISTORY rather than a guess.
    """

    def __init__(self, **facts):
        self._facts = facts

    def authority_at(self, permit_id, moment):
        return type("External", (), self._facts)()


class PermitStoreTests(unittest.TestCase):

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(prefix="test_permits_", suffix=".db")
        os.close(handle)
        self.store = ExecutionPermitStore(db_path=self.db_path)
        self.digest = permit_digest(b"canonical-permit-body")

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except OSError:
                pass

    def _register(self, permit_id="permit_1", ttl=60.0, epoch=7, digest=None):
        now = time.time()
        self.store.register(
            permit_id=permit_id,
            digest=digest or self.digest,
            issued_at=now,
            expires_at=now + ttl,
            authorization_epoch=epoch,
        )
        return permit_id

    def test_registered_permit_starts_issued(self):
        self._register()
        self.assertEqual(self.store.state_of("permit_1"), STATE_ISSUED)

    def test_claim_transitions_to_claimed(self):
        self._register()
        claim = self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.assertEqual(claim.claimant, "worker-A")
        self.assertEqual(self.store.state_of("permit_1"), STATE_CLAIMED)

    def test_second_claimant_is_refused(self):
        """Single claimant, not merely single signature."""
        self._register()
        self.store.claim("permit_1", "worker-A", digest=self.digest)
        with self.assertRaises(PermitStoreError) as caught:
            self.store.claim("permit_1", "worker-B", digest=self.digest)
        self.assertEqual(caught.exception.reason, DENY_ALREADY_CLAIMED)

    def test_concurrent_claimants_exactly_one_wins(self):
        """
        The race that a read-then-execute would lose. Two connections, one permit: the database
        decides, not timing luck.
        """
        self._register()
        winners = []
        errors = []
        barrier = threading.Barrier(2)

        def attempt(claimant):
            store = ExecutionPermitStore(db_path=self.db_path)
            barrier.wait()
            try:
                store.claim("permit_1", claimant, digest=self.digest)
                winners.append(claimant)
            except PermitStoreError as error:
                errors.append(error.reason)

        threads = [threading.Thread(target=attempt, args=(name,))
                   for name in ("worker-A", "worker-B")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(len(winners), 1, f"winners={winners} errors={errors}")
        self.assertEqual(errors, [DENY_ALREADY_CLAIMED])
        self.assertEqual(self.store.state_of("permit_1"), STATE_CLAIMED)
        self.assertEqual(self.store.describe("permit_1")["claimed_by"], winners[0])

    def test_expiry_is_derived_not_trusted(self):
        """The stored state still says ISSUED. The clock says otherwise, so the clock wins."""
        now = time.time()
        self.store.register("permit_1", self.digest, now, now + 0.05)
        time.sleep(0.1)
        self.assertEqual(self.store.state_of("permit_1"), STATE_EXPIRED)
        with self.assertRaises(PermitStoreError) as caught:
            self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.assertEqual(caught.exception.reason, DENY_EXPIRED)
        self.assertEqual(self.store.describe("permit_1")["state"], STATE_ISSUED)

    def test_revoked_permit_cannot_be_claimed(self):
        self._register()
        self.assertTrue(self.store.revoke("permit_1", reason="OPERATOR_REVOKED"))
        with self.assertRaises(PermitStoreError) as caught:
            self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.assertEqual(caught.exception.reason, DENY_REVOKED)

    def test_surgical_revocation_leaves_other_permits_alone(self):
        """Epoch invalidation is broad; explicit revocation is surgical. Both mechanisms exist."""
        self._register("permit_1")
        self._register("permit_2")
        self.store.revoke("permit_1")
        self.assertEqual(self.store.state_of("permit_1"), STATE_REVOKED)
        self.assertEqual(self.store.state_of("permit_2"), STATE_ISSUED)
        self.store.claim("permit_2", "worker-B", digest=self.digest)

    def test_digest_mismatch_is_refused(self):
        self._register()
        with self.assertRaises(PermitStoreError) as caught:
            self.store.claim("permit_1", "worker-A", digest=permit_digest(b"different-body"))
        self.assertEqual(caught.exception.reason, DENY_DIGEST_MISMATCH)

    def test_epoch_mismatch_invalidates_and_refuses(self):
        """Revocation by epoch: everything minted under a superseded grant dies at once."""
        self._register(epoch=7)
        with self.assertRaises(PermitStoreError) as caught:
            self.store.claim("permit_1", "worker-A", digest=self.digest,
                             current_authorization_epoch=8)
        self.assertEqual(caught.exception.reason, DENY_EPOCH_MISMATCH)
        self.assertEqual(self.store.state_of("permit_1"), STATE_REVOKED)

    def test_consume_requires_the_claimant(self):
        self._register()
        self.store.claim("permit_1", "worker-A", digest=self.digest)
        with self.assertRaises(PermitStoreError) as caught:
            self.store.consume("permit_1", "worker-B")
        self.assertEqual(caught.exception.reason, DENY_NOT_CLAIMANT)

    def test_consumed_permit_cannot_be_reused(self):
        self._register()
        self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.store.consume("permit_1", "worker-A")
        self.assertEqual(self.store.state_of("permit_1"), STATE_CONSUMED)
        with self.assertRaises(PermitStoreError) as caught:
            self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.assertEqual(caught.exception.reason, DENY_ALREADY_CONSUMED)

    def test_claimed_without_consume_is_visible_as_reconciliation_input(self):
        """
        Claim then die: the permit must never replay, and the orphaned CLAIMED row is the signal
        that the effect is unknown. The store reports the state; it does not guess the outcome.
        """
        self._register()
        store_after_crash = ExecutionPermitStore(db_path=self.db_path)
        store_after_crash.claim("permit_1", "worker-A", digest=self.digest)
        del store_after_crash

        reopened = ExecutionPermitStore(db_path=self.db_path)
        described = reopened.describe("permit_1")
        self.assertEqual(described["state"], STATE_CLAIMED)
        self.assertNotIn("outcome", described)
        with self.assertRaises(PermitStoreError):
            reopened.claim("permit_1", "worker-B", digest=self.digest)

    def test_claim_returns_a_durably_anchored_attempt_identity(self):
        """The worker cannot invent the attempt id; the transaction mints it."""
        self._register()
        claim = self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.assertTrue(claim.execution_attempt_id.startswith("attempt_"))
        self.assertEqual(claim.permit_id, "permit_1")
        self.assertEqual(claim.claimed_at, self.store.describe("permit_1")["claimed_at"])
        self.assertEqual(
            self.store.describe("permit_1")["execution_attempt_id"],
            claim.execution_attempt_id,
        )

    def test_claim_takes_no_attempt_parameter_from_the_caller(self):
        """If a caller could pass an attempt id, the anchor would be a claim about itself."""
        import inspect
        signature = inspect.signature(self.store.claim)
        self.assertNotIn("execution_attempt_id", signature.parameters)
        self.assertNotIn("attempt_id", signature.parameters)

    def test_attempt_identities_are_unique_per_claim(self):
        self._register("permit_1")
        self._register("permit_2")
        first = self.store.claim("permit_1", "worker-A", digest=self.digest)
        second = self.store.claim("permit_2", "worker-A", digest=self.digest)
        self.assertNotEqual(first.execution_attempt_id, second.execution_attempt_id)

    def test_attempt_identity_survives_consumption(self):
        """A receipt must be able to cite the attempt after the permit is spent."""
        self._register()
        claim = self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.store.consume("permit_1", "worker-A")
        described = self.store.describe("permit_1")
        self.assertEqual(described["state"], STATE_CONSUMED)
        self.assertEqual(described["execution_attempt_id"], claim.execution_attempt_id)

    def test_valid_at_before_issuance_is_conclusively_invalid(self):
        self._register()
        result = self.store.valid_at("permit_1", time.time() - 3600)
        self.assertEqual(result.outcome, OUTCOME_INVALID_AT_TIME)
        self.assertEqual(result.reason, "NOT_YET_ISSUED")
        self.assertTrue(result.is_conclusive)

    def test_valid_at_after_expiry_is_conclusively_invalid(self):
        self._register()
        result = self.store.valid_at("permit_1", time.time() + 3600)
        self.assertEqual(result.outcome, OUTCOME_INVALID_AT_TIME)
        self.assertEqual(result.reason, "EXPIRED_BEFORE_MOMENT")

    def test_valid_at_after_revocation_is_conclusively_invalid(self):
        self._register()
        now = time.time()
        self.store.revoke("permit_1", reason="OPERATOR_REVOKED", now=now)
        result = self.store.valid_at("permit_1", now + 1)
        self.assertEqual(result.outcome, OUTCOME_INVALID_AT_TIME)
        self.assertIn("OPERATOR_REVOKED", result.reason)

    def test_revocation_does_not_retroactively_invalidate_an_earlier_moment(self):
        """A 2026 execution must not become unauthorized because a grant expired in 2028."""
        self._register(ttl=600.0)
        issued_at = self.store.describe("permit_1")["issued_at"]
        revoked_at = time.time()
        self.store.revoke("permit_1", reason="OPERATOR_REVOKED", now=revoked_at)
        # Strictly between issuance and revocation: the moment of a legitimate execution.
        moment_of_execution = issued_at + (revoked_at - issued_at) / 2
        result = self.store.valid_at(
            "permit_1", moment_of_execution,
            authority_history=_History(
                authorization_grant_at_T=OUTCOME_VALID_AT_TIME,
                authorization_epoch_at_T=OUTCOME_VALID_AT_TIME,
                mission_envelope_at_T=OUTCOME_VALID_AT_TIME,
                epistemic_leases_at_T=OUTCOME_VALID_AT_TIME,
            ),
        )
        self.assertEqual(result.outcome, OUTCOME_VALID_AT_TIME)

    def test_valid_at_without_authority_history_is_unverifiable_not_invalid(self):
        """The third state exists precisely so this is not reported as a denial."""
        self._register()
        result = self.store.valid_at("permit_1", time.time())
        self.assertEqual(result.outcome, OUTCOME_UNVERIFIABLE_HISTORY)
        self.assertFalse(result.is_conclusive)
        self.assertIn("authorization_grant_at_T", result.unverifiable)
        self.assertIn("epistemic_leases_at_T", result.unverifiable)

    def test_valid_at_with_complete_authority_history_is_valid(self):
        self._register()
        result = self.store.valid_at(
            "permit_1", time.time(),
            authority_history=_History(
                authorization_grant_at_T=OUTCOME_VALID_AT_TIME,
                authorization_epoch_at_T=OUTCOME_VALID_AT_TIME,
                mission_envelope_at_T=OUTCOME_VALID_AT_TIME,
                epistemic_leases_at_T=OUTCOME_VALID_AT_TIME,
            ),
        )
        self.assertEqual(result.outcome, OUTCOME_VALID_AT_TIME)

    def test_valid_at_with_a_lapsed_grant_is_invalid_and_names_the_fact(self):
        self._register()
        result = self.store.valid_at(
            "permit_1", time.time(),
            authority_history=_History(
                authorization_grant_at_T=OUTCOME_VALID_AT_TIME,
                authorization_epoch_at_T=OUTCOME_VALID_AT_TIME,
                mission_envelope_at_T=OUTCOME_VALID_AT_TIME,
                epistemic_leases_at_T=OUTCOME_INVALID_AT_TIME,
            ),
        )
        self.assertEqual(result.outcome, OUTCOME_INVALID_AT_TIME)
        self.assertIn("epistemic_leases_at_T", result.reason)

    def test_valid_at_with_partial_authority_history_is_unverifiable(self):
        """Partial evidence is not evidence of validity."""
        self._register()
        result = self.store.valid_at(
            "permit_1", time.time(),
            authority_history=_History(
                authorization_grant_at_T=OUTCOME_VALID_AT_TIME,
            ),
        )
        self.assertEqual(result.outcome, OUTCOME_UNVERIFIABLE_HISTORY)
        self.assertIn("mission_envelope_at_T", result.unverifiable)

    def test_later_consumption_does_not_invalidate_the_moment_of_execution(self):
        """
        issued 12:00, claimed 12:01, executed 12:02, consumed 12:04.
        Querying 12:02 must not report invalid merely because the permit is spent now.
        Historical checks read timestamps, not current state.
        """
        self._register(ttl=600.0)
        issued_at = self.store.describe("permit_1")["issued_at"]
        claim = self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.store.consume("permit_1", "worker-A")
        consumed_at = self.store.describe("permit_1")["consumed_at"]

        moment_of_execution = claim.claimed_at
        self.assertLess(moment_of_execution, consumed_at)
        self.assertGreaterEqual(moment_of_execution, issued_at)

        result = self.store.valid_at(
            "permit_1", moment_of_execution,
            authority_history=_History(
                authorization_grant_at_T=OUTCOME_VALID_AT_TIME,
                authorization_epoch_at_T=OUTCOME_VALID_AT_TIME,
                mission_envelope_at_T=OUTCOME_VALID_AT_TIME,
                epistemic_leases_at_T=OUTCOME_VALID_AT_TIME,
            ),
        )
        self.assertEqual(result.outcome, OUTCOME_VALID_AT_TIME)

    def test_moment_after_consumption_is_invalid(self):
        self._register(ttl=600.0)
        self.store.claim("permit_1", "worker-A", digest=self.digest)
        self.store.consume("permit_1", "worker-A")
        consumed_at = self.store.describe("permit_1")["consumed_at"]
        result = self.store.valid_at("permit_1", consumed_at + 1)
        self.assertEqual(result.outcome, OUTCOME_INVALID_AT_TIME)
        self.assertEqual(result.reason, "ALREADY_CONSUMED")

    def test_claimed_permit_is_valid_for_its_own_attempt_only(self):
        """Claimed by A means valid for A and invalid for B, not simply invalid."""
        self._register(ttl=600.0)
        claim = self.store.claim("permit_1", "worker-A", digest=self.digest)
        history = _History(
            authorization_grant_at_T=OUTCOME_VALID_AT_TIME,
            authorization_epoch_at_T=OUTCOME_VALID_AT_TIME,
            mission_envelope_at_T=OUTCOME_VALID_AT_TIME,
            epistemic_leases_at_T=OUTCOME_VALID_AT_TIME,
        )
        own = self.store.valid_at(
            "permit_1", time.time(), authority_history=history,
            execution_attempt_id=claim.execution_attempt_id,
        )
        self.assertEqual(own.outcome, OUTCOME_VALID_AT_TIME)

        other = self.store.valid_at(
            "permit_1", time.time(), authority_history=history,
            execution_attempt_id="attempt_someone_else",
        )
        self.assertEqual(other.outcome, OUTCOME_INVALID_AT_TIME)
        self.assertEqual(other.reason, "CLAIMED_BY_ANOTHER_ATTEMPT")

    def test_valid_at_unknown_permit_is_unverifiable(self):
        result = self.store.valid_at("permit_missing", time.time())
        self.assertEqual(result.outcome, OUTCOME_UNVERIFIABLE_HISTORY)
        self.assertEqual(result.reason, "NO_PERMIT_RECORD")

    def test_unknown_permit_is_reported_not_invented(self):
        with self.assertRaises(PermitStoreError) as caught:
            self.store.state_of("permit_missing")
        self.assertEqual(caught.exception.reason, DENY_UNKNOWN)

    def test_re_registering_a_different_digest_is_refused(self):
        """A permit id may not be reused for different authority."""
        self._register()
        with self.assertRaises(PermitStoreError) as caught:
            self._register(digest=permit_digest(b"other-body"))
        self.assertEqual(caught.exception.reason, DENY_DIGEST_MISMATCH)


if __name__ == "__main__":
    unittest.main()
