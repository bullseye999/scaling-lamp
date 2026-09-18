"""
test_gate0_trust_registry.py - Gate Zero Milestone 0.1 Verification Suite
Tests Ed25519 asymmetric trust chain, TrustRegistry lifecycle (active, retired, revoked),
pinned root operator key, expanded 14-field ExecutionToken, and OperatorConsentGrant.
"""

import time
import unittest
from ciph.kernel.crypto_identity import (
    Ed25519KeyManager,
    TrustRegistry,
    KeyRole,
    KeyStatus,
    OperatorConsentGrant,
    ExecutionToken
)


class TestGate0TrustRegistry(unittest.TestCase):

    def setUp(self):
        self.registry = TrustRegistry(db_path=":memory:")
        self.op_priv, self.op_pub = Ed25519KeyManager.generate_keypair()
        self.kern_priv, self.kern_pub = Ed25519KeyManager.generate_keypair()
        self.wrk_priv, self.wrk_pub = Ed25519KeyManager.generate_keypair()

    def test_ed25519_key_generation_and_signing(self):
        """Basic Ed25519 generation, signing, and tamper detection."""
        msg = b"hello ciph constitutional execution"
        sig = Ed25519KeyManager.sign(self.op_priv, msg)
        self.assertTrue(Ed25519KeyManager.verify(self.op_pub, msg, sig))

        # Tampered message
        tampered = b"hello ciph unconstitutional execution"
        self.assertFalse(Ed25519KeyManager.verify(self.op_pub, tampered, sig))

        # Wrong key
        self.assertFalse(Ed25519KeyManager.verify(self.kern_pub, msg, sig))

    def test_trust_registry_lifecycle_and_historical_validity(self):
        """
        Key lifecycle: ACTIVE -> RETIRED preserves historical validity for receipts
        signed prior to retirement, while rejecting new signatures.
        """
        key_id = "worker_node_01"
        self.registry.register_key(key_id, KeyRole.WORKER, self.wrk_pub.hex())

        # Historical message signed at t1
        t1 = 1000.0
        msg1 = b"operation_receipt_t1"
        sig1 = Ed25519KeyManager.sign(self.wrk_priv, msg1)
        valid, reason = self.registry.verify_signature_at_time(key_id, msg1, sig1, signed_at=t1)
        self.assertTrue(valid)
        self.assertEqual(reason, "VALID")

        # Retire key at t2 = 2000.0
        t2 = 2000.0
        self.registry.retire_key(key_id, retirement_timestamp=t2)
        rec = self.registry.get_key(key_id)
        self.assertEqual(rec["status"], KeyStatus.RETIRED.value)
        self.assertEqual(rec["valid_until"], t2)

        # Verification of t1 signature still passes!
        valid, reason = self.registry.verify_signature_at_time(key_id, msg1, sig1, signed_at=t1)
        self.assertTrue(valid)
        self.assertEqual(reason, "VALID")

        # Signature purportedly made at t3 > t2 must be rejected!
        t3 = 2500.0
        msg3 = b"operation_receipt_t3_after_retirement"
        sig3 = Ed25519KeyManager.sign(self.wrk_priv, msg3)
        valid, reason = self.registry.verify_signature_at_time(key_id, msg3, sig3, signed_at=t3)
        self.assertFalse(valid)
        self.assertIn("SIGNED_AFTER_RETIREMENT", reason)

    def test_trust_registry_compromise_revocation(self):
        """
        Compromise revocation: immediately invalidates all signatures (past and present).
        """
        key_id = "worker_rogue"
        self.registry.register_key(key_id, KeyRole.WORKER, self.wrk_pub.hex())

        t1 = 1000.0
        msg = b"compromised_worker_evidence"
        sig = Ed25519KeyManager.sign(self.wrk_priv, msg)

        # Before revocation: valid
        valid, _ = self.registry.verify_signature_at_time(key_id, msg, sig, signed_at=t1)
        self.assertTrue(valid)

        # Revoke key for private key compromise
        self.registry.revoke_key(key_id, reason="Worker node disk exfiltrated")
        rec = self.registry.get_key(key_id)
        self.assertEqual(rec["status"], KeyStatus.REVOKED.value)

        # After revocation: past signature is now rejected as compromised!
        valid, reason = self.registry.verify_signature_at_time(key_id, msg, sig, signed_at=t1)
        self.assertFalse(valid)
        self.assertIn("KEY_REVOKED", reason)

    def test_pinned_operator_root_authorization(self):
        """Registry with pinned root operator requires operator signature to register new keys."""
        pinned_registry = TrustRegistry(db_path=":memory:", pinned_operator_pub_hex=self.op_pub.hex())

        # Unsigned registration attempt fails
        unauthorized = pinned_registry.register_key(
            "kernel_01", KeyRole.KERNEL, self.kern_pub.hex()
        )
        self.assertFalse(unauthorized)

        # Authorized registration with operator signature succeeds
        payload = f"REGISTER_KEY:kernel_01:{KeyRole.KERNEL.value}:{self.kern_pub.hex()}:None".encode("utf-8")
        op_sig = Ed25519KeyManager.sign(self.op_priv, payload)

        authorized = pinned_registry.register_key(
            "kernel_01", KeyRole.KERNEL, self.kern_pub.hex(), operator_signature=op_sig
        )
        self.assertTrue(authorized)

    def test_operator_consent_grant_signing_and_verification(self):
        """Operator consent grant signed by K_operator_priv and verified."""
        self.registry.register_key("operator_root", KeyRole.OPERATOR, self.op_pub.hex())

        grant = OperatorConsentGrant(
            grant_id="grant_bounty_01",
            plan_hash="plan_hash_abc",
            step_id="step_recon",
            capability="bounty.active_probe",
            parameters_hash="param_hash_xyz",
            scope_grant_id="scope_target_corp",
            max_budget={"max_usd": 50.0},
            issued_at=time.time(),
            expires_at=time.time() + 300,
            operator_key_id="operator_root"
        )
        signed_grant = grant.sign(self.op_priv)
        self.assertTrue(len(signed_grant.signature) > 0)

        # Verification against trust registry succeeds
        valid, reason = signed_grant.verify(self.registry)
        self.assertTrue(valid, f"Verification failed: {reason}")
        self.assertEqual(reason, "VALID")

        # Expired grant fails
        expired_grant = OperatorConsentGrant(
            grant_id="grant_expired",
            plan_hash="plan_hash_abc",
            step_id="step_recon",
            capability="bounty.active_probe",
            parameters_hash="param_hash_xyz",
            scope_grant_id="scope_target_corp",
            issued_at=time.time() - 200,
            expires_at=time.time() - 100,
            operator_key_id="operator_root"
        ).sign(self.op_priv)
        valid, reason = expired_grant.verify(self.registry)
        self.assertFalse(valid)
        self.assertEqual(reason, "GRANT_EXPIRED")

    def test_execution_token_14_fields_binding_and_tamper_rejection(self):
        """
        ExecutionToken signed by K_kernel_priv covers all 14 mandatory fields.
        Tampering with any single field must invalidate verification.
        """
        self.registry.register_key("kernel_primary", KeyRole.KERNEL, self.kern_pub.hex())

        token = ExecutionToken(
            token_id="tok_01h8x",
            nonce="nonce_98124a",
            plan_hash="plan_hash_omega",
            step_id="step_01",
            capability="memory.store",
            manifest_hash="man_hash_1122",
            manifest_version="1.0.0",
            parameters_hash="params_hash_3344",
            scope_grant_id="scope_local",
            authorization_grant_id="grant_bounty_01",
            execution_lane="LANE_2_MUTATION",
            authorized_worker_class="WORKER_LOCAL",
            issued_at=time.time(),
            expires_at=time.time() + 120,
            max_attempts=3,
            kernel_key_id="kernel_primary"
        )
        signed_token = token.sign(self.kern_priv)
        self.assertTrue(len(signed_token.signature) > 0)

        # Verify correct context
        valid, reason = signed_token.verify(
            self.registry,
            expected_plan_hash="plan_hash_omega",
            expected_step_id="step_01",
            expected_capability="memory.store",
            expected_params_hash="params_hash_3344",
            expected_manifest_hash="man_hash_1122",
            worker_class="WORKER_LOCAL"
        )
        self.assertTrue(valid, f"Verification failed: {reason}")
        self.assertEqual(reason, "VALID")

        # Tampering with plan_hash
        valid, reason = signed_token.verify(
            self.registry,
            expected_plan_hash="plan_hash_FORGED",
            expected_step_id="step_01",
            expected_capability="memory.store"
        )
        self.assertFalse(valid)
        self.assertIn("PLAN_HASH_MISMATCH", reason)

        # Tampering with capability
        valid, reason = signed_token.verify(
            self.registry,
            expected_plan_hash="plan_hash_omega",
            expected_step_id="step_01",
            expected_capability="bounty.exploit"
        )
        self.assertFalse(valid)
        self.assertIn("CAPABILITY_MISMATCH", reason)

        # Tampering with worker class
        valid, reason = signed_token.verify(
            self.registry,
            expected_plan_hash="plan_hash_omega",
            expected_step_id="step_01",
            expected_capability="memory.store",
            worker_class="ROGUE_WORKER_CLASS"
        )
        self.assertFalse(valid)
        self.assertIn("WORKER_CLASS_UNAUTHORIZED", reason)


if __name__ == "__main__":
    unittest.main()
