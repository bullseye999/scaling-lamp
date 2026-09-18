"""
test_gate0_barrier1_persistent_identity.py - Verification Suite for Gate Zero Barrier 1
Tests:
1. End-to-end persistent Ed25519 worker identity.
2. Receipt validity across process restarts (receipt_valid_before_restart and receipt_valid_after_restart).
3. Persistent worker and kernel keypairs in SQLite key vault / trust registry.
4. Cryptographic ingress verification rejecting forged non-empty signatures.
5. TrustRegistry verification against retirement and compromise revocation.
"""

import os
import time
import unittest
from ciph.runtime import CiphRuntime
from ciph.kernel.crypto_identity import (
    TrustRegistry,
    KeyRole,
    KeyStatus,
    Ed25519KeyManager,
)
from ciph.kernel.policy_engine import ScopeGrant, ScopeType
from ciph.planner.schemas import IntentProposal
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory


class TestGate0Barrier1PersistentIdentity(unittest.TestCase):
    DB_PATH = "test_barrier1_identity.db"

    def _cleanup(self):
        for ext in ("", "-wal", "-shm"):
            p = self.DB_PATH + ext
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def setUp(self):
        self._cleanup()

    def tearDown(self):
        self._cleanup()

    def test_persistent_ed25519_identity_across_process_restarts(self):
        """
        Assessor Finding 2 Remediation:
        Verify that receipts signed by a worker remain cryptographically valid
        across process restarts by loading persistent Ed25519 keypairs from SQLite trust registry / vault.
        """
        # Session 1: Process 1 executes task and signs receipt with persistent Ed25519 key
        runtime1 = CiphRuntime(db_path=self.DB_PATH)
        worker_key_p1 = runtime1.worker_secret_key
        kernel_key_p1 = runtime1.kernel_priv_bytes

        # Verify keys are 32-byte Ed25519 keys
        self.assertEqual(len(worker_key_p1), 32)
        self.assertEqual(len(kernel_key_p1), 32)

        proposal = IntentProposal(
            proposal_id="PROP-BARRIER1-01",
            objective="CVSS calculation test",
            proposed_capability="pentest.cvss_calculate",
            provided_parameters={
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "target": "vuln_assessment"
            }
        )
        scope = ScopeGrant(
            scope_id="scope_local_b1",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["vuln_assessment"]
        )

        res1 = runtime1.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(res1["status"], "SUCCESS")
        receipt1 = res1["receipt"]
        self.assertIsNotNone(receipt1)
        self.assertIsNotNone(receipt1.worker_signature)

        # Verification in Session 1
        valid_before, reason_before = receipt1.verify(runtime1.trust_registry)
        self.assertTrue(valid_before, f"Receipt verification failed before restart: {reason_before}")
        self.assertTrue(receipt1.verify_signature(secret_key=runtime1.worker_secret_key))

        # Shutdown Session 1
        runtime1.shutdown()
        del runtime1

        # Session 2: Process restarts using the exact same SQLite database
        runtime2 = CiphRuntime(db_path=self.DB_PATH)

        # 1. Verify that worker and kernel keypairs persisted across restarts
        self.assertEqual(runtime2.worker_secret_key, worker_key_p1, "Worker private key changed across process restart!")
        self.assertEqual(runtime2.kernel_priv_bytes, kernel_key_p1, "Kernel private key changed across process restart!")

        # 2. Verify that the receipt produced before restart is STILL VALID after restart!
        valid_after, reason_after = receipt1.verify(runtime2.trust_registry)
        self.assertTrue(valid_after, f"Receipt failed verification after restart: {reason_after}")

        # 3. Verify that verify_signature using the restored worker secret key also passes
        self.assertTrue(receipt1.verify_signature(secret_key=runtime2.worker_secret_key))

        runtime2.shutdown()

    def test_forged_nonempty_signature_rejected_by_trust_registry_and_queue(self):
        """
        Assessor Finding 1 & Barrier 3 Remediation:
        Queue ingress and receipt verification MUST reject forged, non-empty signatures.
        """
        runtime = CiphRuntime(db_path=self.DB_PATH)

        # Enqueue a job
        job_id = runtime.queue.enqueue_job(
            capability="tor.check_status",
            params={},
            plan_id="p_forged",
            step_id="s_forged",
            idempotency_key="idemp_forged_sig"
        )
        leased = runtime.queue.lease_next_job(worker_id="worker_forger", lease_ttl_seconds=30)
        self.assertIsNotNone(leased)

        # Forged receipt with non-empty fake signature string
        forged_receipt = {
            "receipt_id": "rcpt_forged_007",
            "job_id": job_id,
            "capability": "tor.check_status",
            "target": None,
            "started_at": 100.0,
            "completed_at": 100.5,
            "input_hash": ExecutionReceipt.hash_payload({}),
            "output_hash": ExecutionReceipt.hash_payload({"status": "FORGED_PWN"}),
            "exit_code": 0,
            "outcome": "SUCCESS",
            "results": {"status": "FORGED_PWN"},
            "side_effects": [],
            "idempotency_key": "idemp_forged_sig",
            "attempt_number": 1,
            "requested_network_policy": "OFFLINE_ONLY",
            "actual_transport_used": "LOCAL_SOCKET",
            "worker_id": "worker_forger",
            "worker_signature": "not-a-valid-signature-attacker-payload"
        }

        # Queue ingress must cryptographically reject this forged signature
        event_id = runtime.queue.complete_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="worker_forger",
            receipt_dict=forged_receipt
        )
        self.assertEqual(event_id, 0, "Queue accepted a forged non-empty signature!")

        # Receipt object direct verification must also reject
        rcpt_obj = ExecutionReceipt.from_dict(forged_receipt)
        valid, reason = rcpt_obj.verify(runtime.trust_registry)
        self.assertFalse(valid, "Receipt verification accepted a forged non-empty signature!")

        runtime.shutdown()

    def test_tampered_receipt_results_fail_verification(self):
        """Modifying results without matching output_hash causes verification to fail."""
        runtime = CiphRuntime(db_path=self.DB_PATH)
        proposal = IntentProposal(
            proposal_id="PROP-TAMPER-01",
            objective="CVSS calculation test",
            proposed_capability="pentest.cvss_calculate",
            provided_parameters={
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "target": "vuln_assessment"
            }
        )
        scope = ScopeGrant(
            scope_id="scope_tamper",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["vuln_assessment"]
        )
        res = runtime.execute_reference_loop(proposal, scope_grant=scope)
        receipt = res["receipt"]

        # Valid original
        self.assertTrue(receipt.verify(runtime.trust_registry)[0])

        # Tamper results payload
        tampered_dict = receipt.to_dict()
        tampered_dict["results"]["base_score"] = 0.0  # falsify score
        tampered_receipt = ExecutionReceipt.from_dict(tampered_dict)

        valid, reason = tampered_receipt.verify(runtime.trust_registry)
        self.assertFalse(valid)
        self.assertIn("OUTPUT_HASH_MISMATCH", reason)

        runtime.shutdown()

    def test_key_revocation_invalidates_receipts(self):
        """Revoking a worker's key immediately invalidates historical and future receipt verification."""
        runtime = CiphRuntime(db_path=self.DB_PATH)
        proposal = IntentProposal(
            proposal_id="PROP-REVOKE-01",
            objective="CVSS calculation test",
            proposed_capability="pentest.cvss_calculate",
            provided_parameters={
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "target": "vuln_assessment"
            }
        )
        scope = ScopeGrant(
            scope_id="scope_revoke",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["vuln_assessment"]
        )
        res = runtime.execute_reference_loop(proposal, scope_grant=scope)
        receipt = res["receipt"]

        # Before revocation: valid
        self.assertTrue(receipt.verify(runtime.trust_registry)[0])

        # Revoke worker key
        reason = "Worker node compromise simulated"
        payload = f"REVOKE_KEY:worker_primary:{reason}".encode("utf-8")
        operator_signature = Ed25519KeyManager.sign(runtime.operator_priv_bytes, payload)
        self.assertTrue(
            runtime.trust_registry.revoke_key(
                "worker_primary",
                reason=reason,
                operator_signature=operator_signature,
            )
        )

        # After revocation: rejected!
        valid, reason = receipt.verify(runtime.trust_registry)
        self.assertFalse(valid)
        self.assertIn("KEY_REVOKED", reason)

        runtime.shutdown()

    def test_retirement_lifecycle_preserves_historical_receipts(self):
        """Retiring a worker key preserves validity for prior receipts, but rejects future signatures."""
        runtime = CiphRuntime(db_path=self.DB_PATH)
        proposal = IntentProposal(
            proposal_id="PROP-RETIRE-01",
            objective="CVSS calculation test",
            proposed_capability="pentest.cvss_calculate",
            provided_parameters={
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "target": "vuln_assessment"
            }
        )
        scope = ScopeGrant(
            scope_id="scope_retire",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["vuln_assessment"]
        )
        res = runtime.execute_reference_loop(proposal, scope_grant=scope)
        receipt = res["receipt"]

        # 1. Historical receipt signed at t_done = receipt.completed_at
        t_done = receipt.completed_at
        self.assertTrue(receipt.verify(runtime.trust_registry)[0])

        # 2. Retire worker key at t_retire = t_done + 10.0
        t_retire = t_done + 10.0
        payload = f"RETIRE_KEY:worker_primary:{t_retire}".encode("utf-8")
        operator_signature = Ed25519KeyManager.sign(runtime.operator_priv_bytes, payload)
        self.assertTrue(
            runtime.trust_registry.retire_key(
                "worker_primary",
                retirement_timestamp=t_retire,
                operator_signature=operator_signature,
            )
        )

        # 3. Prior receipt remains VALID
        valid_hist, reason_hist = receipt.verify(runtime.trust_registry)
        self.assertTrue(valid_hist, f"Historical receipt rejected after retirement: {reason_hist}")

        # 4. A new signature created after t_retire MUST be rejected!
        post_receipt_dict = receipt.to_dict()
        post_receipt_dict["receipt_id"] = "rcpt_after_retire"
        post_receipt_dict["completed_at"] = t_retire + 50.0  # after retirement
        post_receipt = ExecutionReceipt.from_dict(post_receipt_dict).sign(
            runtime.worker_secret_key, worker_key_id="worker_primary"
        )
        valid_future, reason_future = post_receipt.verify(runtime.trust_registry)
        self.assertFalse(valid_future)
        self.assertIn("SIGNED_AFTER_RETIREMENT", reason_future)

        runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
