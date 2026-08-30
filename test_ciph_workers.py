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


if __name__ == "__main__":
    unittest.main()
