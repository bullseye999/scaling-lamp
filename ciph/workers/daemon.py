import time
import uuid
import threading
from typing import Optional, Dict, Any, List
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.capabilities.registry import CapabilityRegistry
from ciph.workers.receipts import JobState, ExecutionReceipt, OutcomeCategory
from ciph.kernel.policy_engine import NetworkPolicy
from ciph.memory.event_store import EventStore


class DurableWorkerDaemon:
    """
    Autonomous background worker daemon.
    Processes tasks independently of the CLI interface, producing immutable receipts in SQLite.
    Continuously renews worker leases via background heartbeats while tasks run.
    """

    def __init__(
        self,
        queue: Optional[IPCJobQueue] = None,
        registry: Optional[CapabilityRegistry] = None,
        event_store: Optional[EventStore] = None,
        vault=None,
        num_workers: int = 2,
        db_path: str = "ciph_vault.db",
        worker_secret_key: Optional[bytes] = None
    ):
        import secrets
        self.db_path = db_path
        self.queue = queue or IPCJobQueue(db_path)
        self.registry = registry or CapabilityRegistry()
        self.event_store = event_store or EventStore(db_path)
        self.vault = vault
        self.num_workers = num_workers
        self.worker_secret_key = worker_secret_key or secrets.token_bytes(32)
        self.running = False
        self.workers: List[threading.Thread] = []

    def start(self):
        """Start background worker threads."""
        self.running = True
        self.workers = []
        for i in range(self.num_workers):
            worker_id = f"worker-{i}-{uuid.uuid4().hex[:6]}"
            t = threading.Thread(target=self._worker_loop, args=(worker_id,), name=f"CIPH-Worker-{i}", daemon=True)
            t.start()
            self.workers.append(t)

    def stop(self, timeout: float = 3.0):
        """Gracefully signal all workers to drain, join, and stop."""
        self.running = False
        for t in self.workers:
            if t.is_alive():
                t.join(timeout=timeout)

    def _start_heartbeat(self, job_id: str, worker_id: str, stop_event: threading.Event):
        """Background heartbeat thread to renew lease every 10 seconds."""
        while not stop_event.is_set():
            stop_event.wait(timeout=10.0)
            if not stop_event.is_set():
                try:
                    self.queue.renew_lease(job_id, worker_id, lease_ttl_seconds=30)
                except Exception:
                    pass

    def drain_once(self, worker_id: str = "worker_sync_01") -> Optional[ExecutionReceipt]:
        """Process a single job synchronously (useful for test assertions and offline single-step loops)."""
        job = self.queue.lease_next_job(worker_id, lease_ttl_seconds=30)
        if not job:
            return None
        return self._execute_leased_job(job, worker_id)

    def _execute_leased_job(self, job: Dict[str, Any], worker_id: str) -> Optional[ExecutionReceipt]:
        """Execute a leased job with heartbeat, HMAC signing, queue completion, and EventStore logging."""
        job_id = job['job_id']
        capability_name = job['capability']
        params = job['params']
        idemp_key = job.get('idempotency_key', '')
        plan_id = job.get('plan_id')
        step_id = job.get('step_id')

        # 1. Mark as executing
        self.queue.mark_executing(job_id, worker_id)

        # 2. Start background heartbeat
        stop_heartbeat = threading.Event()
        hb_thread = threading.Thread(
            target=self._start_heartbeat,
            args=(job_id, worker_id, stop_heartbeat),
            name=f"HB-{job_id}",
            daemon=True
        )
        hb_thread.start()

        start_t = time.time()
        receipt = None
        try:
            cap = self.registry.get(capability_name)
            if not cap:
                err_msg = f"Capability '{capability_name}' not registered in worker."
                err_results = {"error": err_msg}
                err_receipt = ExecutionReceipt(
                    receipt_id=f"rcpt_fail_{uuid.uuid4().hex[:8]}",
                    job_id=job_id,
                    capability=capability_name,
                    target=params.get("target"),
                    started_at=start_t,
                    completed_at=time.time(),
                    input_hash=ExecutionReceipt.hash_payload(params),
                    output_hash=ExecutionReceipt.hash_payload(err_results),
                    exit_code=1,
                    outcome=OutcomeCategory.EXECUTION_ERROR,
                    results=err_results,
                    side_effects=[],
                    idempotency_key=idemp_key or "",
                    attempt_number=1,
                    requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
                    actual_transport_used="NONE_UNREGISTERED",
                    worker_id=worker_id,
                    error_message=err_msg
                ).sign(self.worker_secret_key)
                self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                return None

            raw_receipt = cap.execute(params, context={
                "job_id": job_id,
                "worker_id": worker_id,
                "idempotency_key": idemp_key,
                "plan_id": plan_id,
                "step_id": step_id
            })
            end_t = time.time()

            # Sign receipt
            receipt = raw_receipt.sign(self.worker_secret_key)

            # Atomic Single-Transaction Commit to Queue and EventStore
            if receipt.exit_code == 0:
                self.queue.complete_job_and_append_receipt_event(
                    job_id=job_id,
                    worker_id=worker_id,
                    receipt_dict=receipt.to_dict()
                )
            else:
                self.queue.fail_job_and_append_receipt_event(
                    job_id=job_id,
                    worker_id=worker_id,
                    error=receipt.error_message or "Execution returned non-zero exit code",
                    receipt_dict=receipt.to_dict()
                )

            # Record completion receipt to vault if attached
            if self.vault and hasattr(self.vault, 'store_completion_receipt'):
                try:
                    self.vault.store_completion_receipt(
                        job_id=job_id,
                        tool_name=capability_name,
                        target=receipt.target or "system",
                        results=receipt.results,
                        exit_code=receipt.exit_code
                    )
                except Exception:
                    pass

        except Exception as ex:
            err_receipt = ExecutionReceipt(
                receipt_id=f"rcpt_fail_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                capability=capability_name,
                target=params.get("target"),
                started_at=start_t,
                completed_at=time.time(),
                input_hash=ExecutionReceipt.hash_payload(params),
                output_hash=ExecutionReceipt.hash_payload({"error": str(ex)}),
                exit_code=1,
                outcome=OutcomeCategory.EXECUTION_ERROR,
                results={"error": str(ex)},
                side_effects=[],
                idempotency_key=idemp_key or "",
                attempt_number=1,
                requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
                actual_transport_used="EXCEPTION_FAILED",
                worker_id=worker_id,
                error_message=str(ex)
            ).sign(self.worker_secret_key)
            self.queue.fail_job_and_append_receipt_event(job_id, worker_id, str(ex), err_receipt.to_dict())
        finally:
            stop_heartbeat.set()

        return receipt

    def _worker_loop(self, worker_id: str):
        """Continuous execution loop with heartbeat renewal and canonical receipts."""
        while self.running:
            try:
                job = self.queue.lease_next_job(worker_id, lease_ttl_seconds=30)
                if not job:
                    time.sleep(0.5)
                    continue
                self._execute_leased_job(job, worker_id)
            except Exception:
                time.sleep(1.0)
