"""
test_phase3_worker_daemons_and_crash_recovery.py - Verification Suite for Program 1, Phase 3.

Covers Robust Worker Daemons, Leases & Crash Recovery:
1. Multi-worker daemon pool with isolated concurrent execution contexts.
2. Worker pool supervisor auto-healing and dead-thread respawning.
3. Autonomous background watchdog lease reclamation (pre-execution RETRYING vs. in-flight RECONCILIATION_REQUIRED).
4. Deterministic idempotency keys (sha256(plan_id + ":" + step_id + ":" + params_hash)) and zero duplicate execution.
5. In-flight worker crash recovery with constitutional operator reconciliation and zero duplicate side effects.
6. At-least-once delivery with consecutive retry limits and terminal FAILED transition.
7. Atomic BEGIN IMMEDIATE single-transaction boundaries and lease loss protection (COMMIT_FAILED_LEASE_LOST).
8. Fail-closed non-zero exit code and unhandled Python exception handling with backtrace and signed receipts.
9. Heartbeat lease extension preserving long-running executions against concurrent watchdog runs.
10. Operational telemetry and graceful daemon drain/shutdown.
"""

import os
import time
import json
import uuid
import sqlite3
import hashlib
import threading
import unittest
from typing import Dict, Any, Optional

from ciph.workers.ipc_queue import IPCJobQueue
from ciph.workers.daemon import DurableWorkerDaemon
from ciph.workers.receipts import JobState, OutcomeCategory, ExecutionReceipt, compute_idempotency_key
from ciph.capabilities.registry import CapabilityRegistry
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import (
    CapabilityManifest,
    RiskTier,
    NetworkPolicy,
    ReversibilityClass,
    AuthorizationTier,
)
from ciph.memory.event_store import EventStore
from ciph.kernel.crypto_identity import TrustRegistry, KeyRole, Ed25519KeyManager


class SimpleComputeCapability(BaseCapability):
    def __init__(self, name: str = "math.compute", sleep_seconds: float = 0.0, should_fail: bool = False, fail_with_exception: bool = False):
        self._name = name
        self.sleep_seconds = sleep_seconds
        self.should_fail = should_fail
        self.fail_with_exception = fail_with_exception
        self.execution_count = 0
        self._lock = threading.Lock()

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name=self._name,
            description="Simple test compute capability",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
        )

    def run(self, params, context=None):
        with self._lock:
            self.execution_count += 1
        if self.sleep_seconds > 0:
            time.sleep(self.sleep_seconds)
        if self.fail_with_exception:
            raise RuntimeError(f"Simulated execution crash for {self._name}")
        if self.should_fail:
            return {"success": False, "error": "Execution deliberately returned failure exit"}
        val = params.get("value", 1)
        return {"success": True, "doubled": val * 2}


class TestPhase3WorkerDaemonsAndCrashRecovery(unittest.TestCase):
    """Rigorous Exit Gate Suite for Phase 3: Robust Worker Daemons, Leases & Crash Recovery."""

    def setUp(self):
        self.test_db = f"test_phase3_{uuid.uuid4().hex[:10]}.db"
        self.queue = IPCJobQueue(self.test_db)
        self.trust_registry = TrustRegistry(self.test_db)
        self.event_store = EventStore(self.test_db)
        self.registry = CapabilityRegistry()

        # Generate Worker and Operator identities
        self.worker_priv, self.worker_pub = self.trust_registry.get_or_create_keypair("worker_primary", KeyRole.WORKER)
        self.operator_priv, self.operator_pub = self.trust_registry.get_or_create_keypair("operator_root", KeyRole.OPERATOR)

    def tearDown(self):
        for f in [self.test_db, f"{self.test_db}-wal", f"{self.test_db}-shm"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    # =========================================================================
    # 1. Multi-Worker Daemon Pool Concurrency
    # =========================================================================

    def test_multi_worker_daemon_pool_concurrency(self):
        """Worker daemon pool with 4 concurrent workers processes 12 jobs in parallel with unique worker attributions."""
        cap = SimpleComputeCapability(name="test.concurrent", sleep_seconds=0.02)
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=4,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )

        job_ids = []
        for i in range(12):
            jid = self.queue.enqueue_job("test.concurrent", {"value": i})
            job_ids.append(jid)

        daemon.start()
        try:
            # Wait for all 12 jobs to complete (max 5.0 seconds)
            all_succeeded = False
            for _ in range(50):
                completed_count = 0
                for jid in job_ids:
                    j = self.queue.get_job(jid)
                    if j and j["status"] == JobState.SUCCEEDED.value:
                        completed_count += 1
                if completed_count == 12:
                    all_succeeded = True
                    break
                time.sleep(0.1)

            self.assertTrue(all_succeeded, "All 12 concurrent jobs must succeed")
            self.assertEqual(cap.execution_count, 12)

            # Verify that multiple workers participated
            worker_ids_seen = set()
            for jid in job_ids:
                j = self.queue.get_job(jid)
                self.assertIsNotNone(j["receipt_id"])
                events = self.event_store.get_events(aggregate_id=j["receipt_id"])
                self.assertEqual(len(events), 1)
                payload = events[0]["payload"]
                if isinstance(payload, str):
                    payload = json.loads(payload)
                worker_ids_seen.add(payload["worker_id"])

            self.assertGreaterEqual(len(worker_ids_seen), 2, "Jobs should be distributed across multiple worker threads")
        finally:
            daemon.stop(timeout=2.0)

    # =========================================================================
    # 2. Worker Pool Supervisor Auto-Healing
    # =========================================================================

    def test_worker_pool_supervisor_auto_heals_dead_threads(self):
        """Supervisor loop automatically detects dead worker threads and respawns replacements to maintain pool capacity."""
        cap = SimpleComputeCapability(name="test.supervisor")
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=3,
            supervised=True,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )
        daemon.start()

        try:
            self.assertEqual(daemon.active_workers_count(), 3)
            pool_status = daemon.get_pool_status()
            self.assertTrue(pool_status["supervised"])
            self.assertEqual(pool_status["target_num_workers"], 3)

            # Intentionally simulate death of 2 worker threads by terminating them
            with daemon._worker_lock:
                dead_thread_1 = daemon.workers[0]
                dead_thread_2 = daemon.workers[1]

            daemon.kill_worker(dead_thread_1)
            daemon.kill_worker(dead_thread_2)

            dead_thread_1.join(timeout=1.0)
            dead_thread_2.join(timeout=1.0)
            self.assertFalse(dead_thread_1.is_alive(), "Worker 1 must have terminated")
            self.assertFalse(dead_thread_2.is_alive(), "Worker 2 must have terminated")

            # Let supervisor detect deficit and replenish
            time.sleep(0.6)
            self.assertEqual(daemon.active_workers_count(), 3, "Supervisor must maintain exactly 3 live worker threads")

            # Verify queue processing works on the respawned worker threads
            jid = self.queue.enqueue_job("test.supervisor", {"value": 42})
            completed = False
            for _ in range(30):
                j = self.queue.get_job(jid)
                if j and j["status"] == JobState.SUCCEEDED.value:
                    completed = True
                    break
                time.sleep(0.1)
            self.assertTrue(completed, "Respawned workers must process queued jobs")
        finally:
            daemon.stop(timeout=2.0)

    # =========================================================================
    # 3. Autonomous Background Watchdog Lease Reclamation
    # =========================================================================

    def test_autonomous_watchdog_reclaims_pre_execution_lease_to_retrying(self):
        """Watchdog background thread automatically reclaims pre-execution expired leases to RETRYING."""
        cap = SimpleComputeCapability(name="test.watchdog")
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=1,
            enable_watchdog=True,
            watchdog_interval=0.1,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )

        job_id = self.queue.enqueue_job("test.watchdog", {"value": 10}, max_retries=2)

        # Worker A leases with very short TTL (0.05s) and dies before mark_executing
        leased = self.queue.lease_next_job("worker_doomed_pre", lease_ttl_seconds=0.05, target_job_id=job_id)
        self.assertIsNotNone(leased)
        self.assertEqual(leased["attempt_number"], 1)

        # Start daemon with autonomous watchdog
        daemon.start()
        try:
            # The watchdog should automatically reclaim to RETRYING, and the daemon worker should pick it up and complete it
            completed = False
            for _ in range(40):
                j = self.queue.get_job(job_id)
                if j and j["status"] == JobState.SUCCEEDED.value:
                    self.assertEqual(j["attempt_number"], 2)
                    completed = True
                    break
                time.sleep(0.1)

            self.assertTrue(completed, "Watchdog should reclaim job and healthy worker must complete attempt 2")
        finally:
            daemon.stop(timeout=2.0)

    # =========================================================================
    # 4. In-Flight Worker Crash & Constitutional Operator Reconciliation
    # =========================================================================

    def test_in_flight_worker_crash_requires_reconciliation_zero_duplicate_execution(self):
        """Worker crashing mid-flight moves to RECONCILIATION_REQUIRED; peer workers NEVER auto-retry."""
        cap = SimpleComputeCapability(name="test.inflight")
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=2,
            enable_watchdog=True,
            watchdog_interval=0.1,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )

        job_id = self.queue.enqueue_job("test.inflight", {"value": 77}, max_retries=3)

        # Worker leases and calls mark_executing
        leased = self.queue.lease_next_job("worker_crashed_mid", lease_ttl_seconds=0.05, target_job_id=job_id)
        self.assertIsNotNone(leased)
        self.queue.mark_executing(job_id, "worker_crashed_mid")

        # Worker dies mid-execution (SIGKILL simulation). Daemon starts with active watchdog
        daemon.start()
        try:
            # Watchdog must transition job to RECONCILIATION_REQUIRED
            reconcil_needed = False
            for _ in range(30):
                j = self.queue.get_job(job_id)
                if j and j["status"] == JobState.RECONCILIATION_REQUIRED.value:
                    reconcil_needed = True
                    break
                time.sleep(0.1)

            self.assertTrue(reconcil_needed, "In-flight crash must transition to RECONCILIATION_REQUIRED")

            # Let the daemon run for another 0.5s: active workers MUST NOT touch or retry the job
            time.sleep(0.5)
            j = self.queue.get_job(job_id)
            self.assertEqual(j["status"], JobState.RECONCILIATION_REQUIRED.value)
            self.assertEqual(cap.execution_count, 0, "No worker should re-execute an in-flight crashed job")

            # Operator resolves the crash via cryptographically signed reconciliation
            res_dict = {"recovered": True, "value": 154}
            res_digest = hashlib.sha256(json.dumps(res_dict, sort_keys=True).encode('utf-8')).hexdigest()
            notes = "Operator audited system: in-flight task confirmed completed safely."
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
            self.assertEqual(final_job["result"]["value"], 154)

            # Check EventStore recorded JobReconciledEvent
            events = self.event_store.get_events(aggregate_id=job_id)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "JobReconciledEvent")
        finally:
            daemon.stop(timeout=2.0)

    # =========================================================================
    # 5. Deterministic Idempotency Key De-duplication
    # =========================================================================

    def test_deterministic_idempotency_key_deduplication(self):
        """Concurrent enqueue with identical idempotency_key creates exactly 1 job and executes once."""
        cap = SimpleComputeCapability(name="test.idemp")
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=2,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )

        plan_id = "plan_test_idemp_99"
        step_id = "step_01"
        params = {"value": 50}
        params_hash = ExecutionReceipt.hash_payload(params)
        idemp_key = compute_idempotency_key(plan_id, step_id, params_hash)

        # Enqueue from 5 concurrent threads
        enqueued_ids = []
        lock = threading.Lock()

        def do_enqueue():
            jid = self.queue.enqueue_job(
                capability="test.idemp",
                params=params,
                idempotency_key=idemp_key,
                plan_id=plan_id,
                step_id=step_id
            )
            with lock:
                enqueued_ids.append(jid)

        threads = [threading.Thread(target=do_enqueue) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 5 threads must receive the exact same job ID
        self.assertEqual(len(enqueued_ids), 5)
        self.assertEqual(len(set(enqueued_ids)), 1, "Duplicate idempotency keys must resolve to the identical job_id")
        job_id = enqueued_ids[0]

        # Start daemon and process
        daemon.start()
        try:
            completed = False
            for _ in range(30):
                j = self.queue.get_job(job_id)
                if j and j["status"] == JobState.SUCCEEDED.value:
                    completed = True
                    break
                time.sleep(0.1)

            self.assertTrue(completed)
            self.assertEqual(cap.execution_count, 1, "Capability must only execute once for an idempotency key")

            # Lookup by idempotency key
            looked_up = self.queue.get_job_by_idempotency_key(idemp_key)
            self.assertIsNotNone(looked_up)
            self.assertEqual(looked_up["job_id"], job_id)
            self.assertEqual(looked_up["status"], JobState.SUCCEEDED.value)
        finally:
            daemon.stop(timeout=2.0)

    # =========================================================================
    # 6. Retry Limits and Terminal FAILED Transition
    # =========================================================================

    def test_retry_limits_and_terminal_failed_transition(self):
        """A capability returning failure retries up to max_retries and transitions to FAILED when exhausted."""
        cap = SimpleComputeCapability(name="test.failing", should_fail=True)
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=1,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )

        job_id = self.queue.enqueue_job("test.failing", {"value": 1}, max_retries=2)
        daemon.start()
        try:
            terminal = False
            for _ in range(40):
                j = self.queue.get_job(job_id)
                if j and j["status"] == JobState.FAILED.value:
                    terminal = True
                    self.assertEqual(j["attempt_number"], 2)
                    break
                time.sleep(0.1)

            self.assertTrue(terminal, "Job must transition to FAILED after max_retries is exhausted")
            self.assertEqual(cap.execution_count, 2)

            # Subsequent lease should find no work
            leased = self.queue.lease_next_job("worker_check", lease_ttl_seconds=10)
            self.assertIsNone(leased, "Failed jobs must not be leased")
        finally:
            daemon.stop(timeout=2.0)

    # =========================================================================
    # 7. Atomic BEGIN IMMEDIATE Boundaries & Lease Loss Protection
    # =========================================================================

    def test_atomic_begin_immediate_lease_loss_fails_closed(self):
        """Worker completing after lease has already expired returns COMMIT_FAILED_LEASE_LOST with zero state overwrite."""
        cap = SimpleComputeCapability(name="test.slow")
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=1,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )

        job_id = self.queue.enqueue_job("test.slow", {"value": 100})
        # Lease with very short TTL
        leased = self.queue.lease_next_job("worker_slow", lease_ttl_seconds=0.05, target_job_id=job_id)
        self.assertIsNotNone(leased)

        # Allow lease to expire
        time.sleep(0.08)

        # Worker attempts to commit completion on expired lease
        fake_receipt = ExecutionReceipt(
            receipt_id="rcpt_expired_01",
            job_id=job_id,
            capability="test.slow",
            target=None,
            started_at=time.time() - 0.1,
            completed_at=time.time(),
            input_hash=ExecutionReceipt.hash_payload({"value": 100}),
            output_hash=ExecutionReceipt.hash_payload({"success": True, "doubled": 200}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"success": True, "doubled": 200},
            side_effects=[],
            idempotency_key="",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="NONE",
            worker_id="worker_slow"
        ).sign(self.worker_priv, worker_key_id="worker_primary")

        commit_rowid = self.queue.complete_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="worker_slow",
            receipt_dict=fake_receipt.to_dict()
        )
        self.assertEqual(commit_rowid, 0, "Atomic commit must fail closed when lease is expired")

        # Confirm nothing was appended to EventStore
        events = self.event_store.get_events(aggregate_id="rcpt_expired_01")
        self.assertEqual(len(events), 0)

    # =========================================================================
    # 8. Fail-Closed Exception Handling with Backtrace and Signed Receipt
    # =========================================================================

    def test_fail_closed_exception_handling_with_backtrace_and_receipt(self):
        """An unhandled capability exception produces a signed EXECUTION_ERROR receipt with backtrace in EventStore."""
        cap = SimpleComputeCapability(name="test.crash_exc", fail_with_exception=True)
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=1,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )

        job_id = self.queue.enqueue_job("test.crash_exc", {"value": 5}, max_retries=1)
        receipt = daemon.drain_once(worker_id="worker_exc_01")

        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.exit_code, 1)
        self.assertEqual(receipt.outcome, OutcomeCategory.EXECUTION_ERROR)
        self.assertEqual(receipt.error_class, "RuntimeError")
        self.assertIn("Simulated execution crash", receipt.error_message)
        self.assertIsNotNone(receipt.backtrace)
        self.assertTrue(receipt.verify_signature(trust_registry=self.trust_registry))

        # Check EventStore recorded the failure
        events = self.event_store.get_events(aggregate_id=receipt.receipt_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "ExecutionReceiptStoredEvent")

    # =========================================================================
    # 9. Heartbeat Lease Extension for Long-Running Tasks
    # =========================================================================

    def test_heartbeat_lease_renewal_for_long_running_tasks(self):
        """Worker heartbeat extends lease beyond original TTL without watchdog reclamation."""
        cap = SimpleComputeCapability(name="test.long_running", sleep_seconds=0.4)
        self.registry.register(cap, code_origin="internal")

        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=1,
            enable_watchdog=True,
            watchdog_interval=0.05,
            heartbeat_interval=0.1,
            heartbeat_lease_extension=1,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )

        # Enqueue job
        job_id = self.queue.enqueue_job("test.long_running", {"value": 7})

        # Lease with 0.2s TTL (shorter than task duration 0.4s)
        leased = self.queue.lease_next_job("worker_hb_test", lease_ttl_seconds=0.2, target_job_id=job_id)
        self.assertIsNotNone(leased)

        watchdog_sweeps = []
        reclaim = self.queue.reclaim_expired_leases
        def counted_reclaim():
            watchdog_sweeps.append(time.monotonic())
            return reclaim()
        self.queue.reclaim_expired_leases = counted_reclaim

        # Start watchdog background thread to actively reclaim expired leases
        daemon._watchdog_stop = threading.Event()
        daemon._watchdog_thread = threading.Thread(
            target=daemon._watchdog_loop,
            name="CIPH-ActiveWatchdog",
            daemon=True
        )
        daemon.running = True
        daemon._watchdog_thread.start()

        try:
            # Execute via daemon which spawns heartbeat renewing every 0.1s
            receipt = daemon._execute_leased_job(leased, "worker_hb_test")
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt.exit_code, 0)
            self.assertEqual(receipt.results["doubled"], 14)
            self.assertGreaterEqual(len(watchdog_sweeps), 2)

            j = self.queue.get_job(job_id)
            self.assertEqual(j["status"], JobState.SUCCEEDED.value)
        finally:
            daemon.stop(timeout=2.0)

    # =========================================================================
    # 10. Operational Telemetry and Graceful Daemon Shutdown
    # =========================================================================

    def test_operational_telemetry_and_graceful_drain(self):
        """Daemon reports accurate pool telemetry and drains gracefully on stop."""
        daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            db_path=self.test_db,
            num_workers=2,
            enable_watchdog=True,
            supervised=True,
            worker_secret_key=self.worker_priv,
            trust_registry=self.trust_registry,
            strict_tokens=False
        )
        daemon.start()
        try:
            status = daemon.get_pool_status()
            self.assertTrue(status["running"])
            self.assertEqual(status["target_num_workers"], 2)
            self.assertEqual(status["active_workers_count"], 2)
            self.assertTrue(status["supervised"])
            self.assertTrue(status["watchdog_enabled"])
        finally:
            daemon.stop(timeout=2.0)
            self.assertFalse(daemon.running)
            self.assertEqual(daemon.active_workers_count(), 0)


if __name__ == "__main__":
    unittest.main()
