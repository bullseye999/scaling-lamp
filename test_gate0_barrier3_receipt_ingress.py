"""
test_gate0_barrier3_receipt_ingress.py - Verification Suite for Gate Zero Barrier 3
Tests:
1. Reject receipt with missing worker signature (returns 0, no event committed).
2. Reject receipt with forged/invalid signature (returns 0, no event committed).
3. Reject receipt when input_hash mismatches execution token parameters_hash (returns 0).
4. Accept legitimate signed receipt with matching execution token (returns event_id, commits event).
"""

import os
import time
import json
import sqlite3
import unittest
from unittest import mock
from ciph.runtime import CiphRuntime
from ciph.kernel.policy_engine import NetworkPolicy
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory, JobState


class TestGate0Barrier3ReceiptIngress(unittest.TestCase):
    DB_PATH = "test_barrier3_ingress.db"

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
        self.runtime = CiphRuntime(db_path=self.DB_PATH)

    def tearDown(self):
        self.runtime.shutdown()
        self._cleanup()

    def test_reject_receipt_with_missing_worker_signature(self):
        """complete_job_and_append_receipt_event rejects unauthenticated receipts without worker signature."""
        params = {"a": 10, "b": 20}
        token = self.runtime.mint_execution_token("math.multiply", params)
        job_id = self.runtime.queue.enqueue_job(
            capability="math.multiply",
            params=params,
            execution_token=token
        )
        leased = self.runtime.queue.lease_next_job(worker_id="w_ingress_01")
        self.assertIsNotNone(leased)

        raw_receipt_dict = {
            "receipt_id": "rcpt_unsigned_999",
            "job_id": job_id,
            "capability": "math.multiply",
            "started_at": time.time(),
            "completed_at": time.time(),
            "input_hash": ExecutionReceipt.hash_payload(params),
            "output_hash": ExecutionReceipt.hash_payload({"result": 200}),
            "exit_code": 0,
            "outcome": "SUCCESS",
            "results": {"result": 200},
            "side_effects": [],
            "idempotency_key": "idemp_test",
            "attempt_number": 1,
            "requested_network_policy": "OFFLINE_ONLY",
            "actual_transport_used": "LOCAL",
            "worker_id": "w_ingress_01",
            "worker_signature": ""  # MISSING
        }

        res = self.runtime.queue.complete_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="w_ingress_01",
            receipt_dict=raw_receipt_dict
        )
        self.assertEqual(res, 0)

        # Confirm job was NOT marked SUCCEEDED
        job = self.runtime.queue.get_job(job_id)
        self.assertNotEqual(job["status"], JobState.SUCCEEDED.value)

    def test_reject_receipt_with_forged_signature(self):
        """complete_job_and_append_receipt_event rejects non-empty forged signatures."""
        params = {"a": 10, "b": 20}
        token = self.runtime.mint_execution_token("math.multiply", params)
        job_id = self.runtime.queue.enqueue_job(
            capability="math.multiply",
            params=params,
            execution_token=token
        )
        leased = self.runtime.queue.lease_next_job(worker_id="w_ingress_02")

        receipt = ExecutionReceipt(
            receipt_id="rcpt_forged_999",
            job_id=job_id,
            capability="math.multiply",
            target=None,
            started_at=time.time(),
            completed_at=time.time(),
            input_hash=ExecutionReceipt.hash_payload(params),
            output_hash=ExecutionReceipt.hash_payload({"result": 200}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"result": 200},
            side_effects=[],
            idempotency_key="idemp_test",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="LOCAL",
            worker_id="w_ingress_02",
            worker_signature="deadbeef_attacker_forged_signature"
        )

        res = self.runtime.queue.complete_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="w_ingress_02",
            receipt_dict=receipt.to_dict()
        )
        self.assertEqual(res, 0)

        # Confirm job was NOT marked SUCCEEDED
        job = self.runtime.queue.get_job(job_id)
        self.assertNotEqual(job["status"], JobState.SUCCEEDED.value)

    def test_reject_receipt_when_input_hash_mismatches_token_parameters_hash(self):
        """complete_job_and_append_receipt_event rejects receipt whose input_hash does not match token parameters_hash."""
        legit_params = {"a": 10, "b": 20}
        token = self.runtime.mint_execution_token("math.multiply", legit_params)
        job_id = self.runtime.queue.enqueue_job(
            capability="math.multiply",
            params=legit_params,
            execution_token=token
        )
        leased = self.runtime.queue.lease_next_job(worker_id="w_ingress_03")

        # Worker signs receipt with TAMPERED input_hash
        tampered_params = {"a": 999, "b": 20}
        receipt = ExecutionReceipt(
            receipt_id="rcpt_tampered_input_999",
            job_id=job_id,
            capability="math.multiply",
            target=None,
            started_at=time.time(),
            completed_at=time.time(),
            input_hash=ExecutionReceipt.hash_payload(tampered_params),  # DOES NOT MATCH TOKEN
            output_hash=ExecutionReceipt.hash_payload({"result": 200}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"result": 200},
            side_effects=[],
            idempotency_key="idemp_test",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="LOCAL",
            worker_id="w_ingress_03",
        ).sign(self.runtime.worker_secret_key, worker_key_id=self.runtime.worker_key_id)

        res = self.runtime.queue.complete_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="w_ingress_03",
            receipt_dict=receipt.to_dict()
        )
        self.assertEqual(res, 0)

        # Confirm job was NOT marked SUCCEEDED
        job = self.runtime.queue.get_job(job_id)
        self.assertNotEqual(job["status"], JobState.SUCCEEDED.value)

    def test_accept_legitimate_receipt_matching_token_and_signature(self):
        """complete_job_and_append_receipt_event accepts valid signed receipt bound to token."""
        params = {"a": 10, "b": 20}
        token = self.runtime.mint_execution_token("math.multiply", params)
        job_id = self.runtime.queue.enqueue_job(
            capability="math.multiply",
            params=params,
            idempotency_key="idemp_test",
            execution_token=token
        )
        leased = self.runtime.queue.lease_next_job(worker_id="w_ingress_04")

        receipt = ExecutionReceipt(
            receipt_id="rcpt_legit_001",
            job_id=job_id,
            capability="math.multiply",
            target=None,
            started_at=time.time(),
            completed_at=time.time(),
            input_hash=ExecutionReceipt.hash_payload(params),
            output_hash=ExecutionReceipt.hash_payload({"result": 200}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"result": 200},
            side_effects=[],
            idempotency_key="idemp_test",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="LOCAL",
            worker_id="w_ingress_04",
        ).sign(self.runtime.worker_secret_key, worker_key_id=self.runtime.worker_key_id)

        event_id = self.runtime.queue.complete_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="w_ingress_04",
            receipt_dict=receipt.to_dict()
        )
        self.assertGreater(event_id, 0)

        # Confirm job was marked SUCCEEDED
        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.SUCCEEDED.value)
        self.assertEqual(job["receipt_id"], "rcpt_legit_001")


    def test_storage_fault_during_ingress_propagates_instead_of_silent_rejection(self):
        """A transient storage fault must fail loudly, not be swallowed into a bare 0."""
        params = {"a": 10, "b": 20}
        token = self.runtime.mint_execution_token("math.multiply", params)
        job_id = self.runtime.queue.enqueue_job(
            capability="math.multiply",
            params=params,
            idempotency_key="idemp_storage_fault",
            execution_token=token
        )
        self.runtime.queue.lease_next_job(worker_id="w_ingress_05")

        receipt = ExecutionReceipt(
            receipt_id="rcpt_storage_fault_001",
            job_id=job_id,
            capability="math.multiply",
            target=None,
            started_at=time.time(),
            completed_at=time.time(),
            input_hash=ExecutionReceipt.hash_payload(params),
            output_hash=ExecutionReceipt.hash_payload({"result": 200}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"result": 200},
            side_effects=[],
            idempotency_key="idemp_storage_fault",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="LOCAL",
            worker_id="w_ingress_05",
        ).sign(self.runtime.worker_secret_key, worker_key_id=self.runtime.worker_key_id)

        with mock.patch.object(
            self.runtime.trust_registry,
            "verify_signature_at_time",
            side_effect=sqlite3.OperationalError("database is locked"),
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.runtime.queue.complete_job_and_append_receipt_event(
                    job_id=job_id,
                    worker_id="w_ingress_05",
                    receipt_dict=receipt.to_dict()
                )

        job = self.runtime.queue.get_job(job_id)
        self.assertNotEqual(job["status"], JobState.SUCCEEDED.value)


if __name__ == "__main__":
    unittest.main()
