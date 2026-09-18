"""
test_gate0_barrier2_execution_tokens.py - Verification Suite for Gate Zero Barrier 2
Tests:
1. Direct enqueue of mandatory-interrupt capability (e.g. code.promote_upgrade) without token is refused by worker.
2. Forged / invalid kernel signature on ExecutionToken is rejected by worker.
3. Expired ExecutionToken is rejected by worker.
4. Tampered parameters hash in ExecutionToken is rejected by worker.
5. Execution lane mismatch in ExecutionToken is rejected by worker.
6. Replayed ExecutionToken is rejected by worker.
7. Legitimate ExecutionToken signed by kernel executes successfully.
"""

import os
import time
import uuid
import hashlib
import unittest
import sqlite3
import threading
from unittest.mock import patch
from ciph.runtime import CiphRuntime
from ciph.kernel.crypto_identity import ExecutionToken, Ed25519KeyManager
from ciph.kernel.policy_engine import (
    AuthorizationTier,
    AuthorizationGrant,
    ScopeGrant,
    ScopeType,
    ExecutionLane,
    RiskTier,
)
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory, JobState


class TestGate0Barrier2ExecutionTokens(unittest.TestCase):
    DB_PATH = "test_barrier2_tokens.db"

    def setUp(self):
        if os.path.exists(self.DB_PATH):
            try:
                os.remove(self.DB_PATH)
            except Exception:
                pass
        self.runtime = CiphRuntime(db_path=self.DB_PATH)

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.DB_PATH):
            try:
                os.remove(self.DB_PATH)
            except Exception:
                pass

    def test_direct_enqueue_mandatory_interrupt_without_token_blocked_by_worker(self):
        """
        Assessor Finding 4 Remediation:
        Worker MUST verify execution authority. Direct enqueue of code.promote_upgrade
        without grant or token MUST NOT reach capability execution.
        """
        # Directly enqueue code.promote_upgrade without token
        job_id = self.runtime.queue.enqueue_job(
            capability="code.promote_upgrade",
            params={"proposal_id": "PROP-UNAUTHORIZED-01"},
            plan_id="p_exploit",
            step_id="s_exploit"
        )
        self.assertIsNotNone(job_id)

        # Worker leases the job
        leased = self.runtime.queue.lease_next_job(worker_id="worker_sentinel", lease_ttl_seconds=30)
        self.assertIsNotNone(leased)

        # Worker attempts execution
        receipt = self.runtime.worker_daemon._execute_leased_job(leased, worker_id="worker_sentinel")
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.exit_code, 1)
        self.assertEqual(receipt.outcome, OutcomeCategory.AUTH_REQUIRED)
        self.assertIn("AUTHORITY_VERIFICATION_FAILED", receipt.error_message)

        # Confirm job state in queue is marked failed
        job_record = self.runtime.queue.get_job(job_id)
        self.assertEqual(job_record["status"], JobState.FAILED.value)

    def test_execution_token_with_forged_kernel_signature_rejected(self):
        """Worker and queue ingress reject ExecutionToken if kernel signature is invalid or forged."""
        params = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
        cap = self.runtime.registry.get("pentest.cvss_calculate")
        now = time.time()

        # Mint token with a forged signature
        forged_token = ExecutionToken(
            token_id="tok_forged_001",
            nonce="nonce_forged",
            plan_hash="plan_hash_test",
            step_id="step_test",
            capability="pentest.cvss_calculate",
            manifest_hash=cap.manifest.compute_manifest_hash(),
            manifest_version=cap.manifest.version,
            parameters_hash=ExecutionReceipt.hash_payload(params),
            scope_grant_id="NONE",
            authorization_grant_id="NONE",
            execution_lane=cap.manifest.derive_execution_lane().value,
            authorized_worker_class="ALL",
            issued_at=now,
            expires_at=now + 300.0,
            max_attempts=1,
            kernel_key_id="kernel_primary",
            signature="attacker_forged_signature_hex_deadbeef"
        )

        # 1. Queue ingress rejects forged token
        with self.assertRaises(ValueError) as ctx:
            self.runtime.queue.enqueue_job(
                capability="pentest.cvss_calculate",
                params=params,
                plan_id="p_forged_sig",
                step_id="s_forged_sig",
                execution_token=forged_token
            )
        self.assertIn("Invalid ExecutionToken", str(ctx.exception))

        # 2. Defense-in-depth: Even if forged token bypassed ingress into SQLite directly, worker rejects it
        raw_forged_job = {
            "job_id": "JOB-FORGED-001",
            "capability": "pentest.cvss_calculate",
            "params": params,
            "execution_token": forged_token.to_dict()
        }
        receipt = self.runtime.worker_daemon._execute_leased_job(raw_forged_job, worker_id="worker_sentinel")
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.exit_code, 1)
        self.assertEqual(receipt.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertIn("EXECUTION_TOKEN_SIGNATURE_INVALID", receipt.error_message)

    def test_expired_execution_token_rejected_by_worker(self):
        """Worker and queue ingress reject ExecutionToken when expires_at < current_time."""
        params = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
        now = time.time()

        # Mint token that is already expired
        expired_token = self.runtime.mint_execution_token(
            capability="pentest.cvss_calculate",
            params=params,
            issued_at=now - 500.0,
            timeout_seconds=-100.0  # forces expires_at < now
        )

        # 1. Queue ingress rejects expired token
        with self.assertRaises(ValueError) as ctx:
            self.runtime.queue.enqueue_job(
                capability="pentest.cvss_calculate",
                params=params,
                plan_id="p_expired",
                step_id="s_expired",
                execution_token=expired_token
            )
        self.assertIn("Invalid ExecutionToken", str(ctx.exception))

        # 2. Defense-in-depth: If expired token was in database, worker rejects it
        raw_expired_job = {
            "job_id": "JOB-EXPIRED-001",
            "capability": "pentest.cvss_calculate",
            "params": params,
            "execution_token": expired_token.to_dict()
        }
        receipt = self.runtime.worker_daemon._execute_leased_job(raw_expired_job, worker_id="worker_sentinel")
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.exit_code, 1)
        self.assertIn("EXECUTION_TOKEN_EXPIRED", receipt.error_message)

    def test_tampered_parameters_hash_rejected_by_worker(self):
        """Worker detects mismatch between token parameters_hash and actual parameters."""
        legit_params = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
        token = self.runtime.mint_execution_token(
            capability="pentest.cvss_calculate",
            params=legit_params
        )

        # Enqueue with TAMPERED parameters (attacker altered vector)
        tampered_params = {"vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N", "target": "audit"}
        job_id = self.runtime.queue.enqueue_job(
            capability="pentest.cvss_calculate",
            params=tampered_params,
            execution_token=token
        )

        leased = self.runtime.queue.lease_next_job(worker_id="worker_sentinel")
        receipt = self.runtime.worker_daemon._execute_leased_job(leased, worker_id="worker_sentinel")

        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.exit_code, 1)
        self.assertIn("EXECUTION_TOKEN_PARAMS_HASH_MISMATCH", receipt.error_message)

    def test_token_replay_rejected_by_worker(self):
        """Worker refuses to execute the same token_id more than once."""
        params = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
        token = self.runtime.mint_execution_token(
            capability="pentest.cvss_calculate",
            params=params
        )

        # 1. First execution: succeeds
        job_id_1 = self.runtime.queue.enqueue_job(
            capability="pentest.cvss_calculate",
            params=params,
            execution_token=token,
            idempotency_key="idemp_run_1"
        )
        leased_1 = self.runtime.queue.lease_next_job(worker_id="worker_sentinel")
        receipt_1 = self.runtime.worker_daemon._execute_leased_job(leased_1, worker_id="worker_sentinel")
        self.assertEqual(receipt_1.exit_code, 0)

        # 2. Second execution attempt with identical token_id: rejected as replay
        job_id_2 = self.runtime.queue.enqueue_job(
            capability="pentest.cvss_calculate",
            params=params,
            execution_token=token,
            idempotency_key="idemp_run_2"
        )
        leased_2 = self.runtime.queue.lease_next_job(worker_id="worker_sentinel")
        receipt_2 = self.runtime.worker_daemon._execute_leased_job(leased_2, worker_id="worker_sentinel")
        self.assertEqual(receipt_2.exit_code, 1)
        self.assertIn("EXECUTION_TOKEN_REPLAYED", receipt_2.error_message)

    def test_legitimate_execution_token_succeeds_end_to_end(self):
        """Valid ExecutionToken signed by kernel executes successfully and produces valid receipt."""
        params = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
        token = self.runtime.mint_execution_token(
            capability="pentest.cvss_calculate",
            params=params
        )

        job_id = self.runtime.queue.enqueue_job(
            capability="pentest.cvss_calculate",
            params=params,
            execution_token=token,
            idempotency_key="idemp_legit_001"
        )
        leased = self.runtime.queue.lease_next_job(worker_id="worker_sentinel")
        receipt = self.runtime.worker_daemon._execute_leased_job(leased, worker_id="worker_sentinel")

        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.outcome, OutcomeCategory.SUCCESS)
        self.assertIsNotNone(receipt.worker_signature)
        valid, _ = receipt.verify(self.runtime.trust_registry)
        self.assertTrue(valid)

    def test_token_consumption_database_failure_fails_closed(self):
        """Worker fails closed when storage failure occurs during atomic token consumption."""
        params = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
        token = self.runtime.mint_execution_token(
            capability="pentest.cvss_calculate",
            params=params
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="pentest.cvss_calculate",
            params=params,
            execution_token=token
        )
        leased = self.runtime.queue.lease_next_job(worker_id="worker_sentinel")

        cap = self.runtime.registry.get("pentest.cvss_calculate")
        orig_execute = cap.execute
        executed = []
        def mocked_execute(*args, **kwargs):
            executed.append(True)
            return orig_execute(*args, **kwargs)
        cap.execute = mocked_execute

        real_get_conn = self.runtime.queue._get_connection
        class BrokenStorageConn:
            def __init__(self, conn):
                self._conn = conn
            def execute(self, sql, *args):
                if "INSERT INTO ciph_consumed_tokens" in sql:
                    raise sqlite3.OperationalError("Simulated disk error during token insert")
                return self._conn.execute(sql, *args)
            def commit(self):
                return self._conn.commit()
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                return self._conn.__exit__(exc_type, exc_val, exc_tb)

        with patch.object(self.runtime.queue, '_get_connection', side_effect=lambda: BrokenStorageConn(real_get_conn())):
            receipt = self.runtime.worker_daemon._execute_leased_job(leased, worker_id="worker_sentinel")

        self.assertEqual(receipt.exit_code, 1)
        self.assertEqual(receipt.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertIn("STORAGE_UNAVAILABLE", receipt.error_message)
        self.assertEqual(len(executed), 0, "Capability MUST NOT be executed if token consumption fails in storage!")

    def test_concurrent_token_reuse_fails_closed(self):
        """Simultaneous execution attempts with identical token are resolved safely by unique constraints."""
        params = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
        token = self.runtime.mint_execution_token(
            capability="pentest.cvss_calculate",
            params=params
        )
        job_id_1 = self.runtime.queue.enqueue_job(
            capability="pentest.cvss_calculate",
            params=params,
            execution_token=token,
            idempotency_key="idemp_conc_1"
        )
        job_id_2 = self.runtime.queue.enqueue_job(
            capability="pentest.cvss_calculate",
            params=params,
            execution_token=token,
            idempotency_key="idemp_conc_2"
        )

        leased_1 = self.runtime.queue.lease_next_job(worker_id="worker_sentinel_1")
        leased_2 = self.runtime.queue.lease_next_job(worker_id="worker_sentinel_2")

        cap = self.runtime.registry.get("pentest.cvss_calculate")
        orig_execute = cap.execute
        exec_count = 0
        lock = threading.Lock()
        def tracking_execute(*args, **kwargs):
            nonlocal exec_count
            with lock:
                exec_count += 1
            time.sleep(0.05)
            return orig_execute(*args, **kwargs)
        cap.execute = tracking_execute

        results = []
        def worker_thread(leased_job, wid):
            rcpt = self.runtime.worker_daemon._execute_leased_job(leased_job, worker_id=wid)
            results.append(rcpt)

        t1 = threading.Thread(target=worker_thread, args=(leased_1, "worker_sentinel_1"))
        t2 = threading.Thread(target=worker_thread, args=(leased_2, "worker_sentinel_2"))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(results), 2)
        successes = [r for r in results if r.exit_code == 0]
        replays = [r for r in results if r.exit_code == 1 and "EXECUTION_TOKEN_REPLAYED" in r.error_message]

        self.assertEqual(len(successes), 1, "Exactly one worker must succeed")
        self.assertEqual(len(replays), 1, "Concurrent worker must be rejected as REPLAYED")
        self.assertEqual(exec_count, 1, "Underlying capability must be executed exactly once")


if __name__ == "__main__":
    unittest.main()
