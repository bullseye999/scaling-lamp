"""
test_ciph_stage10_silicon_sovereign.py - Verification for Stage 10 Silicon Sovereign & Post-Quantum Boundary.
"""

import unittest
from ciph.silicon.hardware_root import (
    HardwareSecurityModule,
    PostQuantumLatticeSigner,
    SiliconSovereignGuard
)


class TestCiphStage10SiliconSovereign(unittest.TestCase):

    def setUp(self):
        self.hsm = HardwareSecurityModule(chip_serial="HSM-UNIT-TEST-4096")
        self.hsm.seal_key("operator_root", b"quantum_operator_hardware_key_32b!")
        self.guard = SiliconSovereignGuard(self.hsm)
        self.pub_seed, self.priv_seed = PostQuantumLatticeSigner.derive_keypair(b"quantum_entropy_seed")

    def test_hardware_presence_enforcement(self):
        """Signing without physical user presence confirmation must be rejected."""
        res = self.hsm.sign_within_enclave(
            slot_id="operator_root",
            payload=b"test_payload",
            user_presence_confirmed=False  # No touch!
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "HARDWARE_PRESENCE_REQUIRED")

        # With user presence confirmation -> Succeeds
        res_ok = self.hsm.sign_within_enclave(
            slot_id="operator_root",
            payload=b"test_payload",
            user_presence_confirmed=True
        )
        self.assertTrue(res_ok["success"])
        self.assertEqual(res_ok["status"], "ENCLAVE_SIGNATURE_GENERATED")

    def test_post_quantum_lattice_signature(self):
        """Verify ML-DSA post-quantum lattice signature generation and verification."""
        msg = b"CRITICAL_SOVEREIGN_TRANSACTION_PAYLOAD"
        sig = PostQuantumLatticeSigner.sign_quantum_resistant(self.priv_seed, msg)
        self.assertTrue(sig.startswith("PQ-MLDSA:"))

        is_valid = PostQuantumLatticeSigner.verify_quantum_resistant(self.pub_seed, msg, sig)
        self.assertTrue(is_valid)

        # Corrupted signature fails verification
        self.assertFalse(PostQuantumLatticeSigner.verify_quantum_resistant(self.pub_seed, msg, "PQ-MLDSA:bad:sig"))

    def test_silicon_sovereign_guard_authorization(self):
        """Verify atomic hardware attestation + post-quantum authorization."""
        action = {"action": "SOVEREIGN_ARCHITECTURAL_FREEZE", "target": "ciph_kernel"}
        
        # Blocked if no user presence
        blocked = self.guard.authorize_critical_action(action, user_presence_confirmed=False, pq_priv_seed=self.priv_seed)
        self.assertFalse(blocked["authorized"])

        # Authorized with full physical presence + post-quantum signature
        authorized = self.guard.authorize_critical_action(action, user_presence_confirmed=True, pq_priv_seed=self.priv_seed)
        self.assertTrue(authorized["authorized"])
        self.assertEqual(authorized["status"], "SILICON_SOVEREIGN_AUTHORIZED")
        self.assertIsNotNone(authorized["enclave_signature"])
        self.assertIsNotNone(authorized["post_quantum_signature"])


if __name__ == "__main__":
    unittest.main()
