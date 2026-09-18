"""
test_gate0_crash_reconciliation.py - Gate Zero Crash Uncertainty & Governed Reconciliation Harness
Verifies the Constitutional Crash Rule:
- An in-flight executing job whose worker lease expires must NEVER blindly retry.
- It must transition to RECONCILIATION_REQUIRED.
- Governed operator reconciliation resolves the job with an explicit audit trail.
"""

import os
import time
import unittest
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.workers.receipts import JobState


class TestGate0CrashReconciliation(unittest.TestCase):
    TEST_DB = "test_gate0_crash_rec.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.queue = IPCJobQueue(db_path=self.TEST_DB)
        from ciph.kernel.crypto_identity import KeyRole
        self.operator_priv, self.operator_pub = self.queue.trust_registry.get_or_create_keypair("operator_root", KeyRole.OPERATOR)

    def tearDown(self):
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_leased_job_unexecuted_reclaims_to_retrying(self):
        """Worker dies before calling mark_executing -> Safely transitions to RETRYING."""
        job_id = self.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "k1"},
            plan_id="plan_unexecuted",
            step_id="step_1",
            max_retries=2
        )
        leased = self.queue.lease_next_job(worker_id="worker_alpha", lease_ttl_seconds=0.05)
        self.assertIsNotNone(leased)
        job_leased = self.queue.get_job(job_id)
        self.assertEqual(job_leased["status"], JobState.LEASED.value)

        # Allow lease to expire without calling mark_executing
        time.sleep(0.06)

        reclaimed = self.queue.reclaim_expired_leases()
        self.assertEqual(reclaimed, 1)

        job = self.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.RETRYING.value)
        self.assertIsNone(job["leased_to"])

    def test_executing_job_crashed_transitions_to_reconciliation_required(self):
        """Worker crashes mid-flight during EXECUTING -> Transitions to RECONCILIATION_REQUIRED (no blind retry)."""
        job_id = self.queue.enqueue_job(
            capability="cloud.provision",
            params={"target": "remote_vps_cluster"},
            plan_id="plan_crashed",
            step_id="step_mutating",
            max_retries=3
        )
        leased = self.queue.lease_next_job(worker_id="worker_doomed", lease_ttl_seconds=0.05)
        self.assertIsNotNone(leased)

        # Worker begins execution (external side effects may now be in flight)
        self.queue.mark_executing(job_id, worker_id="worker_doomed")
        job_in_flight = self.queue.get_job(job_id)
        self.assertEqual(job_in_flight["status"], JobState.EXECUTING.value)

        # Worker receives SIGKILL and disappears; lease expires
        time.sleep(0.06)

        reclaimed = self.queue.reclaim_expired_leases()
        self.assertEqual(reclaimed, 1)

        crashed_job = self.queue.get_job(job_id)
        self.assertEqual(crashed_job["status"], JobState.RECONCILIATION_REQUIRED.value)
        self.assertIn("reconciliation required", crashed_job["error"].lower())

        # Crucial Constitutional Invariant: A worker leasing the queue MUST NOT receive this job!
        next_lease = self.queue.lease_next_job(worker_id="worker_beta", lease_ttl_seconds=10)
        self.assertIsNone(next_lease)

    def test_reconciliation_resolution_by_operator(self):
        """Reconciliation required job is resolved explicitly via reconcile_job."""
        import json
        import hashlib
        from ciph.kernel.crypto_identity import Ed25519KeyManager

        job_id = self.queue.enqueue_job(
            capability="cloud.provision",
            params={"target": "remote_vps_cluster"},
            plan_id="plan_recon",
            step_id="step_recon"
        )
        self.queue.lease_next_job(worker_id="worker_doomed_2", lease_ttl_seconds=0.05)
        self.queue.mark_executing(job_id, worker_id="worker_doomed_2")
        time.sleep(0.06)
        self.queue.reclaim_expired_leases()

        job = self.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.RECONCILIATION_REQUIRED.value)

        # Operator investigates VPS cluster, confirms resource was created, and reconciles
        res_dict = {"cluster_id": "cluster-402", "confirmed_by": "operator_k"}
        res_digest = hashlib.sha256(json.dumps(res_dict, sort_keys=True).encode('utf-8')).hexdigest()
        notes = "Operator audited VPS via external probe: resource cluster-402 confirmed active."
        recon_msg = f"RECONCILE:{job_id}:{JobState.COMPLETED.value}:{res_digest}:{notes}".encode('utf-8')
        sig = Ed25519KeyManager.sign(self.operator_priv, recon_msg)

        success = self.queue.reconcile_job(
            job_id=job_id,
            target_state=JobState.COMPLETED,
            resolution_notes=notes,
            result=res_dict,
            operator_id="operator_root",
            operator_signature=sig
        )
        self.assertTrue(success)

        final_job = self.queue.get_job(job_id)
        self.assertEqual(final_job["status"], JobState.COMPLETED.value)
        self.assertEqual(final_job["result"]["cluster_id"], "cluster-402")
        self.assertIn("Operator audited", final_job["error"])


if __name__ == "__main__":
    unittest.main()
