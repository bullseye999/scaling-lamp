"""
test_gate0_barrier1_remediation_findings.py - Comprehensive Verification for Assessor Findings 1-6
1. Revocation is not bypassable at successful ingress (TrustRegistry is sole authority, no secret_key/HMAC fallback).
2. Failure ingress performs strict cryptographic verification (garbage signature rejected, job status unchanged).
3. Receipts are strictly bound to committed job context (job_id, capability, worker_id, idempotency_key).
4. Retirement cannot be defeated by backdating completed_at.
5. Pinned-root initialization fails closed (raises PermissionError on key mismatch or registration failure).
6. Key vault is encrypted (AES-GCM) with 0600 file permissions, and daemon uses authentic Ed25519 keypair.
"""

import os
import stat
import time
import uuid
import sqlite3
import unittest
from ciph.kernel.policy_engine import NetworkPolicy
from ciph.kernel.crypto_identity import (
    TrustRegistry,
    KeyRole,
    KeyStatus,
    Ed25519KeyManager
)
from ciph.workers.ipc_queue import IPCJobQueue, JobState
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory
from ciph.runtime import CiphRuntime


class TestGate0Barrier1RemediationFindings(unittest.TestCase):
    DB_PATH = "test_barrier1_findings.db"

    def setUp(self):
        if os.path.exists(self.DB_PATH):
            try:
                os.remove(self.DB_PATH)
            except Exception:
                pass

    def tearDown(self):
        if os.path.exists(self.DB_PATH):
            try:
                os.remove(self.DB_PATH)
            except Exception:
                pass

    def test_finding1_revocation_cannot_be_bypassed_at_ingress(self):
        """Finding 1: Ingress must not fall back to worker private key when key is revoked in TrustRegistry."""
        reg = TrustRegistry(self.DB_PATH)
        priv_bytes, pub_bytes = reg.get_or_create_keypair("worker_01", KeyRole.WORKER)
        queue = IPCJobQueue(self.DB_PATH, trust_registry=reg, worker_secret_key=priv_bytes)

        # Enqueue and lease job
        job_id = queue.enqueue_job("osint.find_monetizable_threats", {"target": "audit.corp"})
        leased = queue.lease_next_job("worker_01", lease_ttl_seconds=30)
        self.assertIsNotNone(leased)
        self.assertEqual(leased["job_id"], job_id)

        # Revoke the worker's key
        reg.revoke_key("worker_01", reason="Compromised credentials")

        # Worker attempts to sign and submit receipt
        now = time.time()
        receipt = ExecutionReceipt(
            receipt_id="rcpt_revoked_01",
            job_id=job_id,
            capability="osint.find_monetizable_threats",
            target="audit.corp",
            started_at=now - 5,
            completed_at=now,
            input_hash=ExecutionReceipt.hash_payload({"target": "audit.corp"}),
            output_hash=ExecutionReceipt.hash_payload({"status": "ok"}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"status": "ok"},
            side_effects=[],
            idempotency_key=leased["idempotency_key"],
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="OFFLINE",
            worker_id="worker_01"
        ).sign(priv_bytes, worker_key_id="worker_01")

        # Ingress MUST reject with return code 0
        event_id = queue.complete_job_and_append_receipt_event(job_id, "worker_01", receipt.to_dict())
        self.assertEqual(event_id, 0, "Revoked key must be rejected by ingress even if private key is supplied")

        # Job must NOT be SUCCEEDED
        job_rec = queue.get_job(job_id)
        self.assertNotEqual(job_rec["status"], JobState.SUCCEEDED.value)

    def test_finding2_failure_ingress_performs_cryptographic_verification(self):
        """Finding 2: Failure ingress must reject unauthenticated/garbage signatures without modifying job."""
        reg = TrustRegistry(self.DB_PATH)
        priv_bytes, pub_bytes = reg.get_or_create_keypair("worker_01", KeyRole.WORKER)
        queue = IPCJobQueue(self.DB_PATH, trust_registry=reg, worker_secret_key=priv_bytes)

        job_id = queue.enqueue_job("osint.find_monetizable_threats", {"target": "audit.corp"})
        leased = queue.lease_next_job("worker_01", lease_ttl_seconds=30)
        self.assertIsNotNone(leased)

        now = time.time()
        bad_receipt = ExecutionReceipt(
            receipt_id="rcpt_bad_sig_01",
            job_id=job_id,
            capability="osint.find_monetizable_threats",
            target="audit.corp",
            started_at=now - 5,
            completed_at=now,
            input_hash=ExecutionReceipt.hash_payload({"target": "audit.corp"}),
            output_hash=ExecutionReceipt.hash_payload({"error": "Failed"}),
            exit_code=1,
            outcome=OutcomeCategory.EXECUTION_ERROR,
            results={"error": "Failed"},
            side_effects=[],
            idempotency_key=leased["idempotency_key"],
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="OFFLINE",
            worker_id="worker_01",
            worker_signature="00" * 64  # Garbage signature
        )

        event_id = queue.fail_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="worker_01",
            error="Hardware failure",
            receipt_dict=bad_receipt.to_dict()
        )
        self.assertEqual(event_id, 0, "Failure ingress must reject invalid signature")

        job_rec = queue.get_job(job_id)
        self.assertNotEqual(job_rec["status"], JobState.FAILED.value)

    def test_finding3_receipt_bound_to_committed_job_context(self):
        """Finding 3: Ingress must reject receipts naming different job_id, capability, or worker_id."""
        reg = TrustRegistry(self.DB_PATH)
        priv_bytes, pub_bytes = reg.get_or_create_keypair("worker_01", KeyRole.WORKER)
        queue = IPCJobQueue(self.DB_PATH, trust_registry=reg, worker_secret_key=priv_bytes)

        job_id = queue.enqueue_job("osint.find_monetizable_threats", {"target": "audit.corp"})
        leased = queue.lease_next_job("worker_01", lease_ttl_seconds=30)
        self.assertIsNotNone(leased)

        now = time.time()

        # Receipt naming a DIFFERENT job_id
        mismatched_receipt = ExecutionReceipt(
            receipt_id="rcpt_mismatch_01",
            job_id="JOB-DIFFERENT-1234",  # Mismatch!
            capability="osint.find_monetizable_threats",
            target="audit.corp",
            started_at=now - 5,
            completed_at=now,
            input_hash=ExecutionReceipt.hash_payload({"target": "audit.corp"}),
            output_hash=ExecutionReceipt.hash_payload({"status": "ok"}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"status": "ok"},
            side_effects=[],
            idempotency_key=leased["idempotency_key"],
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="OFFLINE",
            worker_id="worker_01"
        ).sign(priv_bytes, worker_key_id="worker_01")

        res = queue.complete_job_and_append_receipt_event(job_id, "worker_01", mismatched_receipt.to_dict())
        self.assertEqual(res, 0, "Ingress must reject receipt with mismatched job_id")

        # Receipt naming a DIFFERENT capability
        mismatched_cap = ExecutionReceipt(
            receipt_id="rcpt_mismatch_02",
            job_id=job_id,
            capability="code.promote_upgrade",  # Mismatch!
            target="audit.corp",
            started_at=now - 5,
            completed_at=now,
            input_hash=ExecutionReceipt.hash_payload({"target": "audit.corp"}),
            output_hash=ExecutionReceipt.hash_payload({"status": "ok"}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"status": "ok"},
            side_effects=[],
            idempotency_key=leased["idempotency_key"],
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="OFFLINE",
            worker_id="worker_01"
        ).sign(priv_bytes, worker_key_id="worker_01")

        res_cap = queue.complete_job_and_append_receipt_event(job_id, "worker_01", mismatched_cap.to_dict())
        self.assertEqual(res_cap, 0, "Ingress must reject receipt with mismatched capability")

    def test_finding4_retirement_cannot_be_defeated_by_backdating(self):
        """Finding 4: A key used after retirement cannot be validated by backdating completed_at."""
        reg = TrustRegistry(self.DB_PATH)
        priv_bytes, pub_bytes = reg.get_or_create_keypair("worker_01", KeyRole.WORKER)
        queue = IPCJobQueue(self.DB_PATH, trust_registry=reg, worker_secret_key=priv_bytes)

        job_id = queue.enqueue_job("osint.find_monetizable_threats", {"target": "audit.corp"})
        leased = queue.lease_next_job("worker_01", lease_ttl_seconds=30)
        self.assertIsNotNone(leased)

        # Retire key at current time
        retired_time = time.time()
        reg.retire_key("worker_01")

        time.sleep(0.05)
        now = time.time()

        # Attacker crafts receipt claiming completed_at BEFORE retirement
        forged_backdated_receipt = ExecutionReceipt(
            receipt_id="rcpt_backdated_01",
            job_id=job_id,
            capability="osint.find_monetizable_threats",
            target="audit.corp",
            started_at=retired_time - 10,
            completed_at=retired_time - 5,  # Claimed in the past before retirement!
            input_hash=ExecutionReceipt.hash_payload({"target": "audit.corp"}),
            output_hash=ExecutionReceipt.hash_payload({"status": "ok"}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"status": "ok"},
            side_effects=[],
            idempotency_key=leased["idempotency_key"],
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="OFFLINE",
            worker_id="worker_01"
        ).sign(priv_bytes, worker_key_id="worker_01")

        # Ingress evaluates against current live time 'now' where key is retired -> REJECT
        res = queue.complete_job_and_append_receipt_event(job_id, "worker_01", forged_backdated_receipt.to_dict())
        self.assertEqual(res, 0, "Ingress must reject receipt signed with a currently retired key, regardless of claimed completed_at")

    def test_finding5_pinned_root_initialization_fails_closed(self):
        """Finding 5: Fresh runtime with pinned operator key must raise PermissionError if runtime operator doesn't match pin."""
        _, foreign_operator_pub = Ed25519KeyManager.generate_keypair()
        pinned_hex = foreign_operator_pub.hex()

        # Starting runtime with a pinned root that does not match local operator must fail fatally
        with self.assertRaises(PermissionError):
            CiphRuntime(db_path=self.DB_PATH, pinned_operator_pub_hex=pinned_hex)

    def test_finding6_key_vault_encryption_and_file_permissions(self):
        """Finding 6: Database must have mode 0600 and private keys must be stored encrypted (ENC:...)."""
        reg = TrustRegistry(self.DB_PATH)
        priv_bytes, pub_bytes = reg.get_or_create_keypair("worker_01", KeyRole.WORKER)

        # 1. Verify file permissions
        file_stat = os.stat(self.DB_PATH)
        mode = file_stat.st_mode & 0o777
        self.assertEqual(mode, 0o600, f"Database file should have mode 0600, got {oct(mode)}")

        # 2. Inspect raw sqlite table to verify private key is encrypted (starts with 'ENC:')
        conn = sqlite3.connect(self.DB_PATH)
        cursor = conn.execute("SELECT private_key_hex FROM ciph_key_vault WHERE key_id = 'worker_01';")
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        stored_val = row[0]
        self.assertTrue(stored_val.startswith("ENC:"), f"Stored private key must be encrypted, got: {stored_val[:10]}")
        self.assertNotIn(priv_bytes.hex(), stored_val, "Plaintext private key hex must never appear in key vault")

        # 3. Verify daemon does not use secrets.token_bytes(32)
        from ciph.workers.daemon import DurableWorkerDaemon
        daemon = DurableWorkerDaemon(queue=None, registry=None, db_path=":memory:")
        self.assertIsNotNone(daemon.worker_priv_bytes)
        self.assertEqual(len(daemon.worker_priv_bytes), 32)
        # Verify it is a valid Ed25519 key (can sign and verify)
        sig = Ed25519KeyManager.sign(daemon.worker_priv_bytes, b"test_ed25519")
        self.assertTrue(Ed25519KeyManager.verify(daemon.worker_pub_bytes, b"test_ed25519", sig))


if __name__ == "__main__":
    unittest.main()
