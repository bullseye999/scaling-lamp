"""
ciph.workers.daemon - Autonomous Durable Worker Daemon (CIPH 4.0).
Executes background tasks with periodic heartbeat lease renewals and canonical receipts.
"""

import time
import uuid
import threading
from typing import Optional, Dict, Any, List
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.capabilities.registry import CapabilityRegistry
from ciph.workers.receipts import JobState


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
        vault=None,
        num_workers: int = 2,
        db_path: str = "ciph_vault.db"
    ):
        self.queue = queue or IPCJobQueue(db_path)
        self.registry = registry or CapabilityRegistry()
        self.vault = vault
        self.num_workers = num_workers
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

    def _worker_loop(self, worker_id: str):
        """Continuous execution loop with heartbeat renewal and canonical receipts."""
        while self.running:
            try:
                # 1. Atomically lease next job
                job = self.queue.lease_next_job(worker_id, lease_ttl_seconds=30)
                if not job:
                    time.sleep(0.5)
                    continue

                job_id = job['job_id']
                capability_name = job['capability']
                params = job['params']

                # 2. Mark as executing
                self.queue.mark_executing(job_id, worker_id)

                # Record STARTED progress receipt in vault if attached
                if self.vault and hasattr(self.vault, 'store_progress_receipt'):
                    try:
                        self.vault.store_progress_receipt(
                            job_id=job_id,
                            tool_name=capability_name,
                            target=params.get("target", "system"),
                            phase="STARTED",
                            event=f"Leased by {worker_id}"
                        )
                    except Exception:
                        pass

                # 3. Start background heartbeat for long-running task
                stop_heartbeat = threading.Event()
                hb_thread = threading.Thread(
                    target=self._start_heartbeat,
                    args=(job_id, worker_id, stop_heartbeat),
                    name=f"HB-{job_id}",
                    daemon=True
                )
                hb_thread.start()

                try:
                    # 4. Execute via Capability Registry
                    cap = self.registry.get(capability_name)
                    if not cap:
                        self.queue.fail_job(job_id, worker_id, f"Capability '{capability_name}' not registered in worker.")
                        continue

                    receipt = cap.execute(params, context={"job_id": job_id, "worker_id": worker_id})
                    
                    if receipt.exit_code == 0:
                        self.queue.complete_job(job_id, worker_id, receipt.results)
                    else:
                        self.queue.fail_job(job_id, worker_id, receipt.error_message or "Execution returned non-zero exit code")

                    # Record completion receipt to vault
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
                    self.queue.fail_job(job_id, worker_id, str(ex))
                finally:
                    stop_heartbeat.set()

            except Exception:
                time.sleep(1.0)
