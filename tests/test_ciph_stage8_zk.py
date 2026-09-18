"""
test_ciph_stage8_zk.py - Verification for Stage 8 Zero-Knowledge Epistemic Proofs.
"""

import time
import unittest
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory
from ciph.kernel.policy_engine import NetworkPolicy
from ciph.zk.zk_engine import ZKReceiptVerifier, ZKEvidenceProof


def _make_receipt(receipt_id: str, job_id: str, capability: str, results: dict) -> ExecutionReceipt:
    now = time.time()
    return ExecutionReceipt(
        receipt_id=receipt_id,
        job_id=job_id,
        capability=capability,
        target="target.test",
        started_at=now - 1.0,
        completed_at=now,
        input_hash="hash_input",
        output_hash="hash_output",
        exit_code=0,
        outcome=OutcomeCategory.SUCCESS,
        results=results,
        side_effects=[],
        idempotency_key=f"idemp_{job_id}",
        attempt_number=1,
        requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
        actual_transport_used="LOCAL_SOCKET"
    )


class TestCiphStage8ZK(unittest.TestCase):

    def test_zk_proof_generation_and_verification(self):
        """Verify ZK proof validly verifies receipt statement without disclosing private witness."""
        receipt = _make_receipt(
            receipt_id="RCPT-ZK-01",
            job_id="JOB-01",
            capability="cybersecurity.bounty_scan",
            results={"vulnerable_subdomains": ["api.target.com"], "criticality": 9.8}
        )

        private_witness = {
            "api_key": "SECRET_HUNTER_KEY_NEVER_DISCLOSE",
            "proxy_ip": "10.0.0.1",
            "internal_token": "AUTH_XYZ"
        }

        # Generate proof
        proof = ZKReceiptVerifier.generate_proof(receipt, private_witness)

        self.assertIsNotNone(proof)
        self.assertEqual(proof.capability, "cybersecurity.bounty_scan")

        # Verifier checks proof with statement hash, without witness
        is_valid = ZKReceiptVerifier.verify_proof(proof, expected_statement_hash=proof.statement_hash)
        self.assertTrue(is_valid)

    def test_zk_tampered_statement_rejected(self):
        """Tampered statement hash or corrupted challenge fails verification."""
        receipt = _make_receipt(
            receipt_id="RCPT-ZK-02",
            job_id="JOB-02",
            capability="pentest.cvss_calculate",
            results={"score": 10.0}
        )
        proof = ZKReceiptVerifier.generate_proof(receipt, {"secret_param": "val"})

        # Tamper statement hash
        self.assertFalse(ZKReceiptVerifier.verify_proof(proof, expected_statement_hash="tampered_statement_hash"))

        # Tamper challenge
        proof.challenge = "tampered_challenge"
        self.assertFalse(proof.verify())


if __name__ == "__main__":
    unittest.main()
