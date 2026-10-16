"""
Gate A0 closure test - Step 5: governed receipt claims and authorization provenance.

Decisions of record: EXECUTION PERMIT V1, TARGET_IDENTITY_V1.

THE PROPERTY THAT MATTERS
A receipt must not be able to cite *a* valid permit instead of *its* permit, and lineage must be
derived from canonical state rather than copied from whatever the caller handed over.

AND THE HONEST LIMIT
Descent can be VALID while authorization history is UNVERIFIABLE, because the evented authority
history does not exist yet. That combination is asserted deliberately.
"""

import os
import tempfile
import time
import unittest

from ciph.kernel.authorization_provenance import (
    DESCENT_INVALID,
    DESCENT_NOT_APPLICABLE,
    DESCENT_UNVERIFIABLE,
    DESCENT_VALID,
    DENY_LEGACY_AFTER_CUTOVER,
    DENY_LEGACY_CARRIES_PERMIT_REFERENCE,
    DENY_MISSING_ATTEMPT_REFERENCE,
    DENY_MISSING_LANE,
    DENY_MISSING_PERMIT_DIGEST,
    DENY_MISSING_PERMIT_REFERENCE,
    DENY_UNKNOWN_ATTEMPT,
    PROVENANCE_LEGACY,
    PROVENANCE_PERMIT_V1,
    STATUS_INVALID,
    STATUS_UNVERIFIABLE,
    STATUS_VALID,
    AuthorizationProvenanceVerifier,
    ExecutionFacts,
    GovernedReceiptClaims,
    ReceiptContractError,
    create_governed_claims,
)
from ciph.kernel.execution_authority import (
    ExecutionAuthority,
    ExecutionPermitPayload,
    time_us,
)
from ciph.kernel.permit_store import ExecutionPermitStore


class _History:
    def authority_at(self, permit_id, moment):
        from ciph.kernel.permit_store import OUTCOME_VALID_AT_TIME
        return type("External", (), {
            "authorization_grant_at_T": OUTCOME_VALID_AT_TIME,
            "authorization_epoch_at_T": OUTCOME_VALID_AT_TIME,
            "mission_envelope_at_T": OUTCOME_VALID_AT_TIME,
            "epistemic_leases_at_T": OUTCOME_VALID_AT_TIME,
        })()


class ProvenanceTests(unittest.TestCase):

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(prefix="test_prov2_", suffix=".db")
        os.close(handle)
        self.store = ExecutionPermitStore(db_path=self.db_path)
        self.authority, _ = ExecutionAuthority.generate()

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except OSError:
                pass

    def _issued_claim(self, capability="capability.read", target="repo-A", ttl=600.0,
                      digest_override=None, claimed_by="worker-A"):
        payload = ExecutionPermitPayload.build(
            capability_id=capability, request_digest="rd", action_fingerprint="af",
            issued_at_us=time_us(), ttl_seconds=ttl, target=target,
            logical_action_id="LA-77",
        )
        permit = self.authority.issue_permit(payload)
        self.store.register(
            permit_id=permit.payload.permit_id,
            digest=digest_override or permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id="LA-77",
            action_fingerprint=permit.payload.action_fingerprint,
        )
        claim = self.store.claim(
            permit.payload.permit_id, claimed_by, digest=digest_override or permit.permit_digest()
        )
        return permit, claim

    def _facts(self, permit, claim, **overrides):
        base = dict(
            capability=permit.payload.capability_id,
            execution_started_at_us=time_us(),
            execution_finished_at_us=time_us() + 1_000_000,
            target_digest=permit.payload.target_digest,
            logical_action_id="LA-77",
            action_fingerprint="af",
            execution_identity="worker-A",
        )
        base.update(overrides)
        return ExecutionFacts(**base)

    def _verifier(self, with_history=True):
        return AuthorizationProvenanceVerifier(
            self.store, authority_history=_History() if with_history else None
        )

    # ------------------------------------------------------------ descent and history

    def test_descent_valid_while_authorization_history_is_unverifiable(self):
        permit, claim = self._issued_claim()
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        result = self._verifier(with_history=False).verify(claims, self._facts(permit, claim), permit)
        self.assertEqual(result.descent, DESCENT_VALID)
        self.assertEqual(result.authorization_history, "UNVERIFIABLE_HISTORY")
        self.assertEqual(result.status, STATUS_UNVERIFIABLE)
        self.assertIn("authorization_grant_at_T", result.missing_evidence)

    def test_full_provenance_is_valid(self):
        permit, claim = self._issued_claim()
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        result = self._verifier().verify(claims, self._facts(permit, claim), permit)
        self.assertEqual(result.status, STATUS_VALID)
        self.assertEqual(result.descent, DESCENT_VALID)

    def test_receipt_citing_a_different_digest_is_a_contradiction(self):
        permit, claim = self._issued_claim()
        claims = GovernedReceiptClaims(
            authorization_provenance=PROVENANCE_PERMIT_V1,
            execution_permit_id=permit.payload.permit_id,
            execution_permit_digest="00" * 32,
            execution_attempt_id=claim.execution_attempt_id,
        )
        result = self._verifier().verify(claims, self._facts(permit, claim), permit)
        self.assertEqual(result.status, STATUS_INVALID)
        self.assertIn("receipt_digest_mismatch", result.contradictions)

    def test_corrupted_store_digest_cannot_validate_a_receipt_on_its_own(self):
        """
        Three values must agree: recomputed from the envelope, stored, and receipt-claimed.
        The store's own digest field is not privileged evidence about the permit.
        """
        permit, claim = self._issued_claim(digest_override="ab" * 32)
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        result = self._verifier().verify(claims, self._facts(permit, claim), permit)
        self.assertEqual(result.status, STATUS_INVALID)
        self.assertIn("permit_store_digest_not_recomputable", result.contradictions)

    def test_receipt_citing_another_attempt_is_a_contradiction(self):
        permit, claim = self._issued_claim()
        claims = GovernedReceiptClaims(
            authorization_provenance=PROVENANCE_PERMIT_V1,
            execution_permit_id=permit.payload.permit_id,
            execution_permit_digest=permit.permit_digest(),
            execution_attempt_id="attempt_someone_else",
        )
        result = self._verifier().verify(claims, self._facts(permit, claim), permit)
        self.assertIn("attempt_identity_mismatch", result.contradictions)

    def test_capability_and_target_mismatch_are_caught(self):
        permit, claim = self._issued_claim()
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        facts = self._facts(permit, claim, capability="capability.delete_everything",
                            target_digest="ff" * 32)
        result = self._verifier().verify(claims, facts, permit)
        self.assertIn("capability_mismatch", result.contradictions)
        self.assertIn("target_identity_mismatch", result.contradictions)

    def test_execution_identity_must_be_the_claimant(self):
        permit, claim = self._issued_claim(claimed_by="worker-A")
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        facts = self._facts(permit, claim, execution_identity="worker-Z")
        result = self._verifier().verify(claims, facts, permit)
        self.assertIn("execution_identity_is_not_the_claimant", result.contradictions)

    def test_descent_is_unverifiable_without_the_signed_artifact(self):
        permit, claim = self._issued_claim()
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        result = self._verifier().verify(claims, self._facts(permit, claim))
        self.assertEqual(result.descent, DESCENT_UNVERIFIABLE)
        self.assertIn("permit_artifact", result.missing_evidence)

    def test_unknown_permit_is_unverifiable(self):
        permit, claim = self._issued_claim()
        claims = GovernedReceiptClaims(
            authorization_provenance=PROVENANCE_PERMIT_V1,
            execution_permit_id="permit_nonexistent",
            execution_permit_digest=permit.permit_digest(),
            execution_attempt_id=claim.execution_attempt_id,
        )
        result = self._verifier().verify(claims, self._facts(permit, claim))
        self.assertEqual(result.descent, DESCENT_UNVERIFIABLE)
        self.assertEqual(result.status, STATUS_UNVERIFIABLE)

    def test_impossible_chronologies_are_contradictions(self):
        permit, claim = self._issued_claim()
        claims = create_governed_claims(self.store, claim.execution_attempt_id)

        now = time_us()
        backwards = self._facts(permit, claim, execution_started_at_us=now + 1_000_000,
                                execution_finished_at_us=now)
        result = self._verifier().verify(claims, backwards, permit)
        self.assertIn("receipt_finished_before_started", result.contradictions)

        before_claim = self._facts(
            permit, claim,
            execution_started_at_us=int((claim.claimed_at - 60) * 1_000_000),
            execution_finished_at_us=int((claim.claimed_at - 59) * 1_000_000),
        )
        result = self._verifier().verify(claims, before_claim, permit)
        self.assertIn("execution_started_before_claim", result.contradictions)

    # ---------------------------------------------------- construction barriers

    def test_governed_lane_requires_its_references(self):
        for kwargs, reason in (
            (dict(execution_permit_id="", execution_permit_digest="d", execution_attempt_id="a"),
             DENY_MISSING_PERMIT_REFERENCE),
            (dict(execution_permit_id="p", execution_permit_digest="", execution_attempt_id="a"),
             DENY_MISSING_PERMIT_DIGEST),
            (dict(execution_permit_id="p", execution_permit_digest="d", execution_attempt_id=""),
             DENY_MISSING_ATTEMPT_REFERENCE),
        ):
            with self.subTest(reason=reason):
                with self.assertRaises(ReceiptContractError) as caught:
                    GovernedReceiptClaims(
                        authorization_provenance=PROVENANCE_PERMIT_V1, **kwargs
                    ).validate_construction()
                self.assertEqual(caught.exception.reason, reason)

    def test_missing_lane_is_refused(self):
        with self.assertRaises(ReceiptContractError) as caught:
            GovernedReceiptClaims(authorization_provenance="").validate_construction()
        self.assertEqual(caught.exception.reason, DENY_MISSING_LANE)

    def test_legacy_lane_forbids_permit_references(self):
        """A pre-permit receipt cannot cite a permit it never had."""
        with self.assertRaises(ReceiptContractError) as caught:
            GovernedReceiptClaims(
                authorization_provenance=PROVENANCE_LEGACY,
                execution_permit_id="p",
            ).validate_construction()
        self.assertEqual(caught.exception.reason, DENY_LEGACY_CARRIES_PERMIT_REFERENCE)

    def test_legacy_lane_cannot_be_created_after_the_cutover_epoch(self):
        with self.assertRaises(ReceiptContractError) as caught:
            GovernedReceiptClaims(
                authorization_provenance=PROVENANCE_LEGACY
            ).validate_construction(cutover_epoch=5, receipt_epoch=6)
        self.assertEqual(caught.exception.reason, DENY_LEGACY_AFTER_CUTOVER)

    def test_legacy_lane_verifies_as_not_applicable(self):
        result = self._verifier().verify(
            GovernedReceiptClaims(authorization_provenance=PROVENANCE_LEGACY),
            ExecutionFacts(capability="c", execution_started_at_us=1, execution_finished_at_us=2),
        )
        self.assertEqual(result.descent, DESCENT_NOT_APPLICABLE)
        self.assertEqual(result.status, STATUS_UNVERIFIABLE)

    # ------------------------------------------------------------ lineage derivation

    def test_lineage_is_derived_from_durable_state_not_from_the_caller(self):
        permit, claim = self._issued_claim()
        derived = create_governed_claims(self.store, claim.execution_attempt_id)
        record = self.store.find_by_attempt(claim.execution_attempt_id)
        self.assertEqual(derived.execution_permit_id, record["permit_id"])
        self.assertEqual(derived.execution_permit_digest, record["permit_digest"])
        self.assertEqual(derived.execution_attempt_id, record["execution_attempt_id"])
        self.assertEqual(derived.authorization_provenance, PROVENANCE_PERMIT_V1)

    def test_lineage_derivation_refuses_an_attempt_the_store_never_wrote(self):
        """A fabricated object cannot be laundered into lineage; only a durable row can."""
        with self.assertRaises(ReceiptContractError) as caught:
            create_governed_claims(self.store, "attempt_fabricated")
        self.assertEqual(caught.exception.reason, DENY_UNKNOWN_ATTEMPT)


if __name__ == "__main__":
    unittest.main()
