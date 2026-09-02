"""
test_ciph_workers.py - Unit tests for CIPH 4.0 IPC Job Queue & Durable Worker Daemon.
"""

import os
import unittest
import time
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.workers.daemon import DurableWorkerDaemon
from ciph.workers.receipts import JobState
from ciph.capabilities.registry import CapabilityRegistry
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier


class TestCiphWorkers(unittest.TestCase):
    TEST_DB = "test_ciph_workers.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.queue = IPCJobQueue(self.TEST_DB)
        self.registry = CapabilityRegistry()

    def tearDown(self):
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_ipc_queue_lifecycle(self):
        # 1. Enqueue
        job_id = self.queue.enqueue_job("test.compute", {"n": 5}, max_retries=1)
        job = self.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.QUEUED.value)

        # 2. Lease
        leased = self.queue.lease_next_job("worker-test-1", lease_ttl_seconds=10)
        self.assertIsNotNone(leased)
        self.assertEqual(leased["job_id"], job_id)
        self.assertEqual(self.queue.get_job(job_id)["status"], JobState.LEASED.value)

        # 3. Mark executing
        self.queue.mark_executing(job_id, "worker-test-1")
        self.assertEqual(self.queue.get_job(job_id)["status"], JobState.EXECUTING.value)

        # 4. Complete
        self.queue.complete_job(job_id, "worker-test-1", {"output": 25})
        job_final = self.queue.get_job(job_id)
        self.assertEqual(job_final["status"], JobState.SUCCEEDED.value)
        self.assertEqual(job_final["result"]["output"], 25)

    def test_durable_worker_daemon_execution(self):
        class SquareCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="math.square",
                    description="Square a number",
                    risk_tier=RiskTier.NONE,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                n = params.get("n", 0)
                return {"success": True, "square": n * n}

        self.registry.register(SquareCapability())
        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            num_workers=1,
            db_path=self.TEST_DB
        )
        daemon.start()

        try:
            # Enqueue job
            job_id = self.queue.enqueue_job("math.square", {"n": 9})

            # Poll for completion (max 3 seconds)
            completed = False
            for _ in range(30):
                j = self.queue.get_job(job_id)
                if j and j["status"] == JobState.SUCCEEDED.value:
                    self.assertEqual(j["result"]["square"], 81)
                    completed = True
                    break
                time.sleep(0.1)

            self.assertTrue(completed, "Worker daemon failed to process job within timeout")
        finally:
            daemon.stop()

    def test_crash_recovery_and_at_least_once_delivery(self):
        """Simulate worker process crash and verify watchdog recovers job without corruption."""
        # Enqueue job with 2 retries
        job_id = self.queue.enqueue_job("test.crash_recovery", {"param": 100}, max_retries=2)
        
        # Worker 1 leases job with 0.05s TTL, then crashes (does not complete or heartbeat)
        leased = self.queue.lease_next_job("crashed-worker-1", lease_ttl_seconds=0.05)
        self.assertIsNotNone(leased)
        self.assertEqual(leased["job_id"], job_id)
        self.assertEqual(leased["attempt_number"], 1)

        # Wait for lease to expire
        time.sleep(0.1)

        # Watchdog reclaims expired leases
        reclaimed = self.queue.reclaim_expired_leases()
        self.assertEqual(reclaimed, 1)

        reclaimed_job = self.queue.get_job(job_id)
        self.assertEqual(reclaimed_job["status"], JobState.RETRYING.value)
        self.assertIsNone(reclaimed_job["leased_to"])

        # Worker 2 successfully leases attempt 2 and completes the job
        leased2 = self.queue.lease_next_job("healthy-worker-2", lease_ttl_seconds=10)
        self.assertIsNotNone(leased2)
        self.assertEqual(leased2["job_id"], job_id)
        self.assertEqual(leased2["attempt_number"], 2)

        self.queue.complete_job(job_id, "healthy-worker-2", {"recovered": True})
        final_job = self.queue.get_job(job_id)
        self.assertEqual(final_job["status"], JobState.SUCCEEDED.value)
        self.assertEqual(final_job["attempt_number"], 2)

    def test_idempotency_key_deduplication(self):
        """Re-enqueueing with identical idempotency_key must return existing job and prevent duplicate execution."""
        idemp_token = "idemp_test_token_abc_123"

        # 1. First enqueue
        job_id_1 = self.queue.enqueue_job(
            capability="math.square",
            params={"n": 4},
            idempotency_key=idemp_token
        )

        # 2. Worker completes first job
        leased = self.queue.lease_next_job("worker_1", lease_ttl_seconds=30)
        self.assertIsNotNone(leased)
        self.queue.complete_job(job_id_1, "worker_1", {"square": 16}, receipt_id="rcpt_16")

        # 3. Duplicate enqueue attempt with same idempotency key
        job_id_2 = self.queue.enqueue_job(
            capability="math.square",
            params={"n": 4},
            idempotency_key=idemp_token
        )

        # Must return the existing job_id
        self.assertEqual(job_id_1, job_id_2)

        # Check by query helper
        job_lookup = self.queue.get_job_by_idempotency_key(idemp_token)
        self.assertIsNotNone(job_lookup)
        self.assertEqual(job_lookup["job_id"], job_id_1)
        self.assertEqual(job_lookup["status"], JobState.SUCCEEDED.value)
        self.assertEqual(job_lookup["receipt_id"], "rcpt_16")

    def test_drain_once_with_hmac_signing_and_event_store(self):
        """Verify synchronous single-step execution, HMAC signing, and EventStore commit."""
        from ciph.memory.event_store import EventStore

        class MultiplyCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="math.multiply",
                    description="Multiply",
                    risk_tier=RiskTier.NONE,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                return {"result": params.get("a", 0) * params.get("b", 0)}

        event_store = EventStore(self.TEST_DB)
        self.registry.register(MultiplyCapability())
        worker_key = b"test_worker_signing_key_secret_32b!"

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=event_store,
            db_path=self.TEST_DB,
            worker_secret_key=worker_key
        )

        # Enqueue job
        job_id = self.queue.enqueue_job("math.multiply", {"a": 7, "b": 8}, idempotency_key="idemp_mult_56")
        
        # Drain once
        receipt = daemon.drain_once(worker_id="worker_drain_01")
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.results["result"], 56)
        self.assertTrue(receipt.verify_signature(worker_key))

        # Check job in queue
        job = self.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.SUCCEEDED.value)
        self.assertEqual(job["receipt_id"], receipt.receipt_id)

        # Check EventStore
        events = event_store.get_events(aggregate_id=receipt.receipt_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["results"]["result"], 56)


if __name__ == "__main__":
    unittest.main()
