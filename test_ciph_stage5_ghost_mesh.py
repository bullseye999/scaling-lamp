"""
test_ciph_stage5_ghost_mesh.py - Verification for Stage 5 Distributed Ghost Mesh & Tor P2P Federation.
"""

import os
import unittest
from nacl.signing import SigningKey

from ciph.runtime import CiphRuntime
from ciph.kernel.crypto_identity import TrustRegistry, KeyStatus, Ed25519KeyManager
from ciph.federation.ghost_mesh import GhostMeshNode, MeshHandshake, MeshTaskEnvelope
from ciph.planner.schemas import IntentProposal


class TestCiphStage5GhostMesh(unittest.TestCase):
    TEST_DB_A = "test_stage5_mesh_a.db"
    TEST_DB_B = "test_stage5_mesh_b.db"

    def setUp(self):
        for db in (self.TEST_DB_A, self.TEST_DB_B):
            if os.path.exists(db):
                os.remove(db)
        self.auth_key = b"mesh_auth_secret_key_stage5_32b!"
        self.runtime_a = CiphRuntime(db_path=self.TEST_DB_A, auth_secret_key=self.auth_key)
        self.runtime_b = CiphRuntime(db_path=self.TEST_DB_B, auth_secret_key=self.auth_key)

        self.trust_a = TrustRegistry(self.TEST_DB_A)
        self.trust_b = TrustRegistry(self.TEST_DB_B)

        self.node_a = GhostMeshNode(
            "node_alpha",
            self.trust_a,
            operator_signing_key=self.runtime_a.operator_priv_bytes,
        )
        self.node_b = GhostMeshNode(
            "node_bravo",
            self.trust_b,
            operator_signing_key=self.runtime_b.operator_priv_bytes,
        )

        # Cross-register peer nodes
        self.node_a.add_trusted_peer("node_bravo", self.node_b.public_key_hex)
        self.node_b.add_trusted_peer("node_alpha", self.node_a.public_key_hex)

    def tearDown(self):
        self.runtime_a.shutdown()
        self.runtime_b.shutdown()
        for db in (self.TEST_DB_A, self.TEST_DB_B):
            if os.path.exists(db):
                try:
                    os.remove(db)
                except Exception:
                    pass

    def test_mutual_handshake_authentication(self):
        """Verify Node A handshake is validated by Node B using Ed25519 signature."""
        handshake = self.node_a.initiate_handshake("node_bravo")
        self.assertTrue(self.node_b.verify_incoming_handshake(handshake))

        # Tampered handshake must be rejected
        handshake.challenge_nonce = "tampered_nonce_injection"
        self.assertFalse(self.node_b.verify_incoming_handshake(handshake))

    def test_revoked_peer_fails_handshake(self):
        """Revoked node key in TrustRegistry must fail-closed."""
        reason = "compromised_node"
        payload = f"REVOKE_KEY:key_node_alpha:{reason}".encode("utf-8")
        signature = Ed25519KeyManager.sign(self.runtime_b.operator_priv_bytes, payload)
        self.assertTrue(
            self.trust_b.revoke_key(
                "key_node_alpha",
                reason=reason,
                operator_signature=signature,
            )
        )
        handshake = self.node_a.initiate_handshake("node_bravo")
        self.assertFalse(self.node_b.verify_incoming_handshake(handshake))

    def test_remote_mesh_task_execution(self):
        """Dispatch remote IntentProposal envelope from Node A, executed on Node B."""
        proposal = IntentProposal(
            proposal_id="PROP-MESH-01",
            objective="Remote CVSS Calculation via Mesh",
            proposed_capability="pentest.cvss_calculate",
            provided_parameters={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
        )
        envelope = self.node_a.create_task_envelope("node_bravo", proposal)

        # Node B executes envelope
        res = self.node_b.execute_remote_mesh_task(envelope, self.runtime_b)

        self.assertEqual(res["status"], "SUCCESS")
        receipt = res["receipt"]
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.capability, "pentest.cvss_calculate")
        self.assertEqual(receipt.results["base_score"], 10.0)
        self.assertEqual(res["responder_node_id"], "node_bravo")


if __name__ == "__main__":
    unittest.main()
