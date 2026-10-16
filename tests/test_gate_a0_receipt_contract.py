"""
Gate A0 closure test - Step A: governed provenance in the real ExecutionReceipt.

Decision of record: EXECUTION PERMIT V1.

TWO THINGS MUST BOTH HOLD
  legacy receipts keep byte-identical signature payloads, so nothing already signed changes meaning
  governed provenance is inside the signature, so it cannot be edited without breaking authenticity

And `None` from `governed_claims()` means *legacy*, explicitly. It never means "governed, but the
fields went missing" - a governed receipt is signed over its provenance block.
"""

import unittest

from ciph.contracts.enums import NetworkPolicy, OutcomeCategory
from ciph.kernel.authorization_provenance import (
    DENY_LEGACY_CARRIES_PERMIT_REFERENCE,
    PROVENANCE_LEGACY,
    PROVENANCE_PERMIT_V1,
    GovernedReceiptClaims,
    ReceiptContractError,
)
from ciph.workers.receipts import ExecutionReceipt


def _receipt(**overrides):
    base = dict(
        receipt_id="rcpt_1",
        job_id="JOB-1",
        capability="capability.read",
        target="repo-A",
        started_at=1_700_000_000.0,
        completed_at=1_700_000_001.0,
        input_hash="ih",
        output_hash=ExecutionReceipt.hash_payload({"ok": True}),
        exit_code=0,
        outcome=OutcomeCategory.SUCCESS,
        results={"ok": True},
        side_effects=[],
        idempotency_key="idem-1",
        attempt_number=1,
        requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
        actual_transport_used="NONE",
        worker_id="worker-A",
    )
    base.update(overrides)
    return ExecutionReceipt(**base)


class ReceiptGovernedProvenanceTests(unittest.TestCase):

    def test_legacy_receipt_reports_explicitly_legacy(self):
        receipt = _receipt()
        self.assertFalse(receipt.has_governed_provenance())
        self.assertIsNone(receipt.governed_claims())

    def test_legacy_signature_payload_is_unchanged(self):
        """Legacy receipts must keep signing exactly as they did before this contract existed."""
        plain = _receipt()
        explicit_empty = _receipt(provenance={})
        self.assertEqual(
            plain.compute_signature_payload(), explicit_empty.compute_signature_payload()
        )
        self.assertNotIn("governed_authorization", plain.compute_signature_payload())

    def test_governed_claims_round_trip(self):
        claims = GovernedReceiptClaims(
            authorization_provenance=PROVENANCE_PERMIT_V1,
            execution_permit_id="permit_1",
            execution_permit_digest="d" * 64,
            execution_attempt_id="attempt_1",
            authorization_epoch=7,
        )
        receipt = _receipt().attach_governed_claims(claims)
        self.assertTrue(receipt.has_governed_provenance())
        recovered = receipt.governed_claims()
        self.assertEqual(recovered.execution_permit_id, "permit_1")
        self.assertEqual(recovered.execution_attempt_id, "attempt_1")
        self.assertEqual(recovered.authorization_epoch, 7)
        self.assertEqual(recovered.authorization_provenance, PROVENANCE_PERMIT_V1)

    def test_governed_provenance_is_bound_into_the_signature(self):
        """
        Editing the lineage must break the signature, or provenance would be decorative.
        """
        claims = GovernedReceiptClaims(
            authorization_provenance=PROVENANCE_PERMIT_V1,
            execution_permit_id="permit_1",
            execution_permit_digest="d" * 64,
            execution_attempt_id="attempt_1",
        )
        governed = _receipt().attach_governed_claims(claims)
        self.assertNotEqual(
            _receipt().compute_signature_payload(),
            governed.compute_signature_payload(),
        )

        tampered = _receipt(provenance={
            ExecutionReceipt.GOVERNED_PROVENANCE_KEY: {
                "authorization_provenance": PROVENANCE_PERMIT_V1,
                "execution_permit_id": "permit_2",
                "execution_permit_digest": "d" * 64,
                "execution_attempt_id": "attempt_1",
                "authorization_epoch": None,
            }
        })
        self.assertNotEqual(
            governed.compute_signature_payload(),
            tampered.compute_signature_payload(),
        )

    def test_attaching_impossible_claims_is_refused(self):
        with self.assertRaises(ReceiptContractError) as caught:
            _receipt().attach_governed_claims(
                GovernedReceiptClaims(
                    authorization_provenance=PROVENANCE_LEGACY,
                    execution_permit_id="permit_1",
                )
            )
        self.assertEqual(caught.exception.reason, DENY_LEGACY_CARRIES_PERMIT_REFERENCE)

    def test_execution_facts_convert_seconds_to_integer_microseconds(self):
        facts = _receipt().execution_facts()
        self.assertEqual(facts.capability, "capability.read")
        self.assertEqual(facts.execution_started_at_us, 1_700_000_000_000_000)
        self.assertEqual(facts.execution_finished_at_us, 1_700_000_001_000_000)
        self.assertIsInstance(facts.execution_started_at_us, int)
        self.assertEqual(facts.execution_identity, "worker-A")

    def test_governed_receipt_survives_signing_and_verification(self):
        from ciph.kernel.crypto_identity import Ed25519KeyManager
        private_key, public_key = Ed25519KeyManager.generate_keypair()
        claims = GovernedReceiptClaims(
            authorization_provenance=PROVENANCE_PERMIT_V1,
            execution_permit_id="permit_1",
            execution_permit_digest="d" * 64,
            execution_attempt_id="attempt_1",
        )
        signed = _receipt().attach_governed_claims(claims).sign(private_key, worker_key_id="worker-A")
        self.assertTrue(signed.has_governed_provenance())
        self.assertTrue(signed.verify_signature(public_key))  # first param is the verification key
        self.assertEqual(signed.governed_claims().execution_attempt_id, "attempt_1")


if __name__ == "__main__":
    unittest.main()
