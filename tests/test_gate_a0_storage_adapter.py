"""
Gate A0 closure test - real-storage adapter.

The adapter starts from the shape the vault actually stores: a canonical signed receipt payload,
its denormalized projection columns and descriptive metadata. It may translate evidence; it may
not invent authority semantics. These specimens are deliberately hostile about which of those
three sources tries to decide the answer.
"""

import unittest

from ciph.contracts.enums import EffectCertainty, NetworkPolicy, OutcomeCategory
from ciph.kernel.crypto_identity import Ed25519KeyManager
from ciph.kernel.manifest_credit import (
    CreditQuery,
    CreditSubject,
    IncidentAxis,
    IncidentScope,
    ReceiptIntegrity,
    assessment_from_complete_partition_scan,
    compute_current_credit,
    compute_subject_credit,
)
from ciph.kernel.manifest_identity import ManifestBinding, ManifestIdentity
from ciph.kernel.performance_metric import (
    EXECUTION_SUCCESS_V1,
    LEGACY_EXECUTION_OUTCOME_V1,
    ExclusionReason,
)
from ciph.kernel.storage_adapter import (
    ReceiptVerificationResult,
    StoredReceiptRecord,
    adapt_stored_receipt,
)
from ciph.workers.receipts import ExecutionReceipt

H2 = ManifestIdentity(2, "H2")

VERSIONED_H2 = {"manifest_identity": {"hash_version": 2, "manifest_hash": "H2"}}
# Two authoritative identity representations at once is corruption, not a precedence question.
CONFLICTING_IDENTITIES = {
    "governed": {"manifest_identity": {"hash_version": 2, "manifest_hash": "H2"}},
    "manifest_identity": {"hash_version": 2, "manifest_hash": "H1"},
}


class _Manifest:
    """Stands in for a resolved manifest that can state its identity."""

    def __init__(self, identity):
        self._identity = identity

    def identity(self):
        return self._identity


def _verifier(public_key, snapshot_ref="test-snapshot"):
    def verify(receipt):
        if receipt.verify_signature(public_key):
            return ReceiptVerificationResult.verified("VALID", trust_snapshot_ref=snapshot_ref)
        return ReceiptVerificationResult.invalid(
            "SIGNATURE_MISMATCH", trust_snapshot_ref=snapshot_ref
        )

    return verify


def _signed(receipt):
    private_key, public_key = Ed25519KeyManager.generate_keypair()
    return receipt.sign(private_key, worker_key_id="worker-A"), _verifier(public_key)


def _fields(outcome, exit_code, provenance, capability="cap.X", receipt_id="rcpt_x"):
    results = {"ok": outcome is OutcomeCategory.SUCCESS}
    return dict(
        receipt_id=receipt_id,
        job_id="JOB-ADP",
        capability=capability,
        target="t",
        started_at=1_700_000_000.0,
        completed_at=1_700_000_001.0,
        input_hash="ih",
        output_hash=ExecutionReceipt.hash_payload(results),
        exit_code=exit_code,
        outcome=outcome,
        results=results,
        side_effects=[],
        idempotency_key="idem",
        attempt_number=1,
        requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
        actual_transport_used="NONE",
        worker_id="worker-A",
        provenance=provenance,
    )


def _current(outcome, certainty, provenance, exit_code=0):
    return ExecutionReceipt.issue(
        effect_certainty=certainty, **_fields(outcome, exit_code, provenance)
    )


def _historical(outcome, provenance, exit_code=0):
    return ExecutionReceipt(schema_version="4.1", **_fields(outcome, exit_code, provenance))


def _subject():
    return CreditSubject.from_manifest("cap.X", _Manifest(H2))


def _query(subject):
    return CreditQuery(subject=subject, metric_ref=EXECUTION_SUCCESS_V1, snapshot_ref="S1")


def _complete(subject):
    return assessment_from_complete_partition_scan(
        subject=subject,
        metric_ref=EXECUTION_SUCCESS_V1,
        snapshot_ref="S1",
        source_ref="adapter_fixture",
        source_digest="adapter-fixture-digest",
    )


class AdapterSpecimenTests(unittest.TestCase):

    def test_signed_unknown_effect_is_a_semantic_exclusion_despite_metadata_success(self):
        """Metadata may say anything. The authenticated field decides."""
        signed, verify = _signed(
            _current(OutcomeCategory.SUCCESS, EffectCertainty.EFFECT_UNKNOWN, VERSIONED_H2)
        )
        stored = StoredReceiptRecord(
            receipt=signed.to_dict(), metadata={"status": "completed successfully"}
        )
        adapted = adapt_stored_receipt(stored, verify)

        observation = adapted.record.performance
        self.assertIsNotNone(observation)
        self.assertEqual(observation.metric_ref, EXECUTION_SUCCESS_V1)
        self.assertIsNone(observation.score)
        self.assertEqual(observation.exclusion_reason, ExclusionReason.EFFECT_UNKNOWN)

        result = compute_current_credit(H2, [adapted.record])
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.semantic_excluded_count, 1)

    def test_projection_says_success_but_the_signed_failure_scores_zero_and_does_not_block(self):
        signed, verify = _signed(
            _current(OutcomeCategory.EXECUTION_ERROR, EffectCertainty.EFFECT_CONFIRMED,
                     VERSIONED_H2, exit_code=1)
        )
        stored = StoredReceiptRecord(
            receipt=signed.to_dict(),
            projection={
                "capability": "cap.X",
                "receipt_id": signed.receipt_id,
                "output_hash": signed.output_hash,
                "outcome": "SUCCESS",   # the denormalized cache is stale/wrong
                "exit_code": 0,
            },
            metadata={"status": "successful"},
        )
        adapted = adapt_stored_receipt(stored, verify)

        self.assertEqual(adapted.record.performance.score, 0.0)
        self.assertEqual(adapted.record.performance.metric_ref, EXECUTION_SUCCESS_V1)
        reasons = {i.reason for i in adapted.projection_incidents}
        self.assertIn("DENORMALIZED_OUTCOME_MISMATCH", reasons)
        self.assertIn("DENORMALIZED_EXIT_CODE_MISMATCH", reasons)
        for incident in adapted.projection_incidents:
            self.assertEqual(incident.axis, IncidentAxis.PROJECTION)

        subject = _subject()
        result = compute_subject_credit(
            _query(subject), [adapted.record],
            retrieval_assessment=_complete(subject),
            projection_incidents=adapted.projection_incidents,
        )
        self.assertEqual(result.integrity_incidents, ())
        self.assertTrue(result.authority_usable)
        self.assertEqual(len(result.projection_incidents), 2)

    def test_historical_receipt_adapts_to_the_legacy_metric_and_is_never_strict_credit(self):
        signed, verify = _signed(_historical(OutcomeCategory.SUCCESS, VERSIONED_H2))
        adapted = adapt_stored_receipt(StoredReceiptRecord(receipt=signed.to_dict()), verify)

        observation = adapted.record.performance
        self.assertEqual(observation.metric_ref, LEGACY_EXECUTION_OUTCOME_V1)
        self.assertEqual(observation.score, 1.0)

        result = compute_current_credit(H2, [adapted.record], metric_ref=EXECUTION_SUCCESS_V1)
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.different_metric_excluded_count, 1)

    def test_missing_certainty_under_the_current_schema_is_unverifiable_with_no_legacy_fallback(self):
        signed, verify = _signed(
            _current(OutcomeCategory.SUCCESS, EffectCertainty.EFFECT_CONFIRMED, VERSIONED_H2)
        )
        body = signed.to_dict()
        body.pop("effect_certainty", None)

        adapted = adapt_stored_receipt(StoredReceiptRecord(receipt=body), verify)
        self.assertEqual(adapted.record.receipt_integrity, ReceiptIntegrity.UNVERIFIABLE)
        self.assertIsNone(adapted.record.performance)
        self.assertTrue(any("UNRECONSTITUTABLE_RECEIPT" in n for n in adapted.notes))
        # No silent downgrade into history: an unreadable 4.2 claim is not a 4.1 receipt.
        self.assertNotEqual(adapted.record.binding.binding, ManifestBinding.LEGACY_UNVERSIONED)

        result = compute_subject_credit(_query(_subject()), [adapted.record])
        self.assertFalse(result.authority_usable)
        incident = result.integrity_incidents[0]
        self.assertEqual(incident.scope, IncidentScope.LEDGER_GLOBAL)
        # Governance reason and diagnostic cause are two levels, not one.
        self.assertEqual(incident.reason, "RECEIPT_INTEGRITY_UNVERIFIABLE")
        self.assertEqual(incident.cause, "MISSING_EFFECT_CERTAINTY_FOR_SCHEMA")

    def test_corrupt_identity_preserves_a_verified_performance_fact_but_blocks_authority(self):
        signed, verify = _signed(
            _current(OutcomeCategory.SUCCESS, EffectCertainty.EFFECT_CONFIRMED, CONFLICTING_IDENTITIES)
        )
        adapted = adapt_stored_receipt(StoredReceiptRecord(receipt=signed.to_dict()), verify)

        self.assertEqual(adapted.record.receipt_integrity, ReceiptIntegrity.VERIFIED)
        self.assertEqual(adapted.record.binding.binding, ManifestBinding.CORRUPT)
        self.assertEqual(adapted.record.performance.score, 1.0)          # the fact is preserved
        self.assertEqual(adapted.record.capability_attribution.capability_id, "cap.X")

        result = compute_subject_credit(_query(_subject()), [adapted.record])
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertFalse(result.authority_usable)
        incident = result.integrity_incidents[0]
        self.assertEqual(incident.scope, IncidentScope.CAPABILITY)
        self.assertEqual(incident.capability, "cap.X")

    def test_an_unverifiable_verifier_fails_closed_without_claiming_contradiction(self):
        receipt = _current(OutcomeCategory.SUCCESS, EffectCertainty.EFFECT_CONFIRMED, VERSIONED_H2)

        def unavailable(_receipt):
            return ReceiptVerificationResult.unverifiable(
                "KEY_HISTORY_UNAVAILABLE", trust_snapshot_ref="snapshot-without-key"
            )

        adapted = adapt_stored_receipt(StoredReceiptRecord(receipt=receipt.to_dict()), unavailable)
        self.assertEqual(adapted.record.receipt_integrity, ReceiptIntegrity.UNVERIFIABLE)
        self.assertIsNone(adapted.record.performance)
        self.assertIsNone(adapted.record.capability_attribution)

    def test_an_invalid_signature_yields_no_attribution_and_no_performance(self):
        signed, _ = _signed(
            _current(OutcomeCategory.SUCCESS, EffectCertainty.EFFECT_CONFIRMED, VERSIONED_H2)
        )
        _, other_public = Ed25519KeyManager.generate_keypair()

        adapted = adapt_stored_receipt(
            StoredReceiptRecord(receipt=signed.to_dict()), _verifier(other_public)
        )
        self.assertEqual(adapted.record.receipt_integrity, ReceiptIntegrity.INVALID)
        self.assertEqual(adapted.record.integrity_cause, "SIGNATURE_MISMATCH")
        self.assertIsNone(adapted.record.performance)
        self.assertIsNone(adapted.record.capability_attribution)

        result = compute_subject_credit(_query(_subject()), [adapted.record])
        self.assertEqual(result.integrity_incidents[0].reason, "RECEIPT_INTEGRITY_FAILURE")
        self.assertEqual(result.integrity_incidents[0].cause, "SIGNATURE_MISMATCH")

    def test_a_verified_receipt_remembers_the_trust_context_it_was_verified_under(self):
        """A bare boolean would hide which key history admitted the evidence."""
        private_key, public_key = Ed25519KeyManager.generate_keypair()
        signed = _current(
            OutcomeCategory.SUCCESS, EffectCertainty.EFFECT_CONFIRMED, VERSIONED_H2
        ).sign(private_key, worker_key_id="worker-A")
        adapted = adapt_stored_receipt(
            StoredReceiptRecord(receipt=signed.to_dict()),
            _verifier(public_key, snapshot_ref="ledger-snapshot-42"),
        )
        self.assertEqual(adapted.verification.integrity, ReceiptIntegrity.VERIFIED)
        self.assertEqual(adapted.verification.trust_snapshot_ref, "ledger-snapshot-42")
        self.assertIsNone(adapted.record.integrity_cause)


if __name__ == "__main__":
    unittest.main()
