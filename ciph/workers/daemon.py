import time
import json
import uuid
import threading
import hashlib
import sqlite3
import sys
import hmac
from typing import Optional, Dict, Any, List
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.capabilities.registry import CapabilityRegistry
from ciph.workers.receipts import JobState, ExecutionReceipt, OutcomeCategory
from ciph.kernel.policy_engine import NetworkPolicy, AuthorizationTier, RiskTier, ExecutionLane
from ciph.kernel.crypto_identity import ExecutionToken
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
        worker_secret_key: Optional[bytes] = None,
        trust_registry: Optional[Any] = None,
        worker_key_id: str = "worker_primary",
        strict_tokens: Optional[bool] = None,
        enable_watchdog: bool = False,
        watchdog_interval: float = 1.0,
        supervised: bool = False,
        heartbeat_interval: float = 10.0,
        heartbeat_lease_extension: int = 30,
    ):
        self.db_path = db_path
        self.trust_registry = trust_registry
        if self.trust_registry is None and db_path:
            try:
                from ciph.kernel.crypto_identity import TrustRegistry
                self.trust_registry = TrustRegistry(db_path)
            except Exception:
                self.trust_registry = None
        self.worker_key_id = worker_key_id

        if worker_secret_key is not None:
            self.worker_secret_key = worker_secret_key
            if self.trust_registry and len(worker_secret_key) == 32:
                try:
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    from ciph.kernel.crypto_identity import KeyRole
                    priv = ed25519.Ed25519PrivateKey.from_private_bytes(worker_secret_key)
                    pub_bytes = priv.public_key().public_bytes_raw()
                    self.trust_registry.store_keypair(
                        key_id=self.worker_key_id,
                        role=KeyRole.WORKER,
                        private_key_bytes=worker_secret_key,
                        public_key_bytes=pub_bytes
                    )
                except Exception:
                    pass
        elif self.trust_registry:
            from ciph.kernel.crypto_identity import KeyRole
            self.worker_priv_bytes, self.worker_pub_bytes = self.trust_registry.get_or_create_keypair(
                self.worker_key_id, KeyRole.WORKER
            )
            self.worker_secret_key = self.worker_priv_bytes
        else:
            from ciph.kernel.crypto_identity import Ed25519KeyManager
            self.worker_priv_bytes, self.worker_pub_bytes = Ed25519KeyManager.generate_keypair()
            self.worker_secret_key = self.worker_priv_bytes

        self.queue = queue or IPCJobQueue(
            db_path,
            trust_registry=self.trust_registry,
            worker_secret_key=self.worker_secret_key
        )
        if getattr(self.queue, 'worker_secret_key', None) is None:
            self.queue.worker_secret_key = self.worker_secret_key
        self.registry = registry or CapabilityRegistry()
        self.event_store = event_store or EventStore(db_path)
        self.vault = vault
        self.num_workers = num_workers
        self.strict_tokens = strict_tokens if strict_tokens is not None else True
        self.enable_watchdog = enable_watchdog
        self.watchdog_interval = max(0.1, watchdog_interval)
        self.supervised = supervised
        self.heartbeat_interval = heartbeat_interval
        self.heartbeat_lease_extension = heartbeat_lease_extension
        self._watchdog_thread: Optional[threading.Thread] = None
        self._watchdog_stop: Optional[threading.Event] = None
        self._supervisor_thread: Optional[threading.Thread] = None
        self._supervisor_stop: Optional[threading.Event] = None
        self._worker_counter = 0
        self._worker_lock = threading.Lock()
        self._total_processed = 0
        self._total_failed = 0
        self.worker_class = "ALL"
        self._executed_token_ids = set()
        self._terminated_workers = set()
        self._generation_stop: Optional[threading.Event] = None
        self.running = False
        self.workers: List[threading.Thread] = []
        self.sandbox_runner = None

    def start(self):
        """Start background worker threads, supervisor, and watchdog."""
        if self.running:
            return
        self.running = True
        self._generation_stop = threading.Event()
        gen_stop = self._generation_stop
        with self._worker_lock:
            self.workers = []
            for _ in range(self.num_workers):
                idx = self._worker_counter
                self._worker_counter += 1
                worker_id = f"worker-{idx}-{uuid.uuid4().hex[:6]}"
                t = threading.Thread(
                    target=self._worker_loop,
                    args=(worker_id, gen_stop),
                    name=f"CIPH-Worker-{idx}",
                    daemon=True
                )
                t.start()
                self.workers.append(t)

        if self.enable_watchdog:
            self._watchdog_stop = threading.Event()
            self._watchdog_thread = threading.Thread(
                target=self._watchdog_loop,
                name="CIPH-WorkerWatchdog",
                daemon=True
            )
            self._watchdog_thread.start()

        if self.supervised:
            self._supervisor_stop = threading.Event()
            self._supervisor_thread = threading.Thread(
                target=self._supervisor_loop,
                name="CIPH-WorkerSupervisor",
                daemon=True
            )
            self._supervisor_thread.start()

    def _watchdog_loop(self):
        """Background watchdog to automatically reclaim expired worker leases."""
        while self.running and self._watchdog_stop and not self._watchdog_stop.is_set():
            try:
                self.queue.reclaim_expired_leases()
            except Exception:
                pass
            if self._watchdog_stop:
                self._watchdog_stop.wait(timeout=self.watchdog_interval)

    def _supervisor_loop(self):
        """Background supervisor to monitor worker threads and maintain pool capacity."""
        while self.running and self._supervisor_stop and not self._supervisor_stop.is_set():
            try:
                with self._worker_lock:
                    gen_stop = self._generation_stop
                    live_workers = [t for t in self.workers if t.is_alive()]
                    self.workers = live_workers
                    deficit = self.num_workers - len(live_workers)
                    for _ in range(deficit):
                        idx = self._worker_counter
                        self._worker_counter += 1
                        worker_id = f"worker-{idx}-{uuid.uuid4().hex[:6]}"
                        t = threading.Thread(
                            target=self._worker_loop,
                            args=(worker_id, gen_stop),
                            name=f"CIPH-Worker-{idx}",
                            daemon=True
                        )
                        t.start()
                        self.workers.append(t)
            except Exception:
                pass
            if self._supervisor_stop:
                self._supervisor_stop.wait(timeout=0.2)

    def active_workers_count(self) -> int:
        """Count number of alive worker threads in the daemon pool."""
        with self._worker_lock:
            return sum(1 for t in self.workers if t.is_alive())

    def kill_worker(self, worker_identifier: Any):
        """Simulate a worker crash/death for testing pool supervision."""
        with self._worker_lock:
            if isinstance(worker_identifier, threading.Thread):
                name = worker_identifier.name
            else:
                name = str(worker_identifier)
            self._terminated_workers.add(name)

    def get_pool_status(self) -> Dict[str, Any]:
        """Return operational telemetry for the worker daemon pool."""
        with self._worker_lock:
            live = [t.name for t in self.workers if t.is_alive()]
        return {
            "running": self.running,
            "target_num_workers": self.num_workers,
            "active_workers_count": len(live),
            "active_worker_threads": live,
            "supervised": self.supervised,
            "watchdog_enabled": self.enable_watchdog,
            "total_processed": self._total_processed,
            "total_failed": self._total_failed,
        }

    def stop(self, timeout: float = 3.0):
        """Gracefully signal supervisor, watchdog, and all workers to drain, join, and stop."""
        self.running = False
        if hasattr(self, '_generation_stop') and self._generation_stop:
            self._generation_stop.set()
        if self._supervisor_stop:
            self._supervisor_stop.set()
        if self._supervisor_thread and self._supervisor_thread.is_alive():
            self._supervisor_thread.join(timeout=timeout)
        if self._watchdog_stop:
            self._watchdog_stop.set()
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=timeout)
        with self._worker_lock:
            workers_to_join = list(self.workers)
        for t in workers_to_join:
            if t.is_alive():
                t.join(timeout=timeout)

    def _start_heartbeat(self, job_id: str, worker_id: str, stop_event: threading.Event):
        """Background heartbeat thread to renew lease."""
        hb_int = getattr(self, "heartbeat_interval", 10.0)
        hb_ext = getattr(self, "heartbeat_lease_extension", 30)
        while not stop_event.is_set():
            stop_event.wait(timeout=hb_int)
            if not stop_event.is_set():
                try:
                    self.queue.renew_lease(job_id, worker_id, extension_seconds=hb_ext, lease_ttl_seconds=hb_ext)
                except Exception:
                    pass

    def drain_once(self, worker_id: str = "worker_sync_01", target_job_id: Optional[str] = None) -> Optional[ExecutionReceipt]:
        """Process a single job synchronously (useful for test assertions and offline single-step loops)."""
        job = self.queue.lease_next_job(worker_id, lease_ttl_seconds=30, target_job_id=target_job_id)
        if not job:
            return None
        return self._execute_leased_job(job, worker_id)

    def _uncommitted_receipt(self, receipt: ExecutionReceipt, reason: str) -> ExecutionReceipt:
        """Return an explicit denial; execution evidence alone is not committed success."""
        from dataclasses import replace
        error = f"RECONCILIATION_REQUIRED: {reason}"
        result = {"error": error, "execution_receipt_id": receipt.receipt_id}
        return replace(
            receipt, receipt_id=f"rcpt_uncommitted_{uuid.uuid4().hex}", exit_code=1,
            outcome=OutcomeCategory.POLICY_BLOCKED, results=result,
            output_hash=ExecutionReceipt.hash_payload(result), error_message=error,
            worker_signature=None,
        ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)

    def _execute_leased_job(self, job: Dict[str, Any], worker_id: str) -> Optional[ExecutionReceipt]:
        """Execute a leased job with heartbeat, HMAC signing, queue completion, and EventStore logging."""
        job_id = job['job_id']
        capability_name = job['capability']
        params = job['params']
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except Exception:
                pass
        idemp_key = job.get('idempotency_key')
        plan_id = job.get('plan_id')
        step_id = job.get('step_id')
        attempt_number = job.get('attempt_number', 1)

        start_t = time.time()
        receipt = None
        execution_started = False
        stop_heartbeat = None
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
                    idempotency_key=idemp_key,
                    attempt_number=attempt_number,
                    requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
                    actual_transport_used="NONE_UNREGISTERED",
                    worker_id=worker_id,
                    error_message=err_msg
                ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                return None

            # -------------------------------------------------------------
            # Constitutional Authority Gate (Barrier 2 Verification)
            # -------------------------------------------------------------
            manifest = cap.manifest
            token_raw = job.get("execution_token")
            token_obj = None

            if token_raw:
                try:
                    if isinstance(token_raw, str):
                        from ciph.kernel.crypto_identity import ExecutionToken
                        token_obj = ExecutionToken.from_dict(json.loads(token_raw))
                    elif hasattr(token_raw, "compute_canonical_payload"):
                        token_obj = token_raw
                    elif isinstance(token_raw, dict):
                        from ciph.kernel.crypto_identity import ExecutionToken
                        token_obj = ExecutionToken.from_dict(token_raw)
                except Exception:
                    token_obj = None

            # 1. Authority requirement check: Is a token required?
            from ciph.capabilities.base import CANONICAL_CAPABILITIES
            token_required = False
            if getattr(self, "strict_tokens", True):
                if capability_name in CANONICAL_CAPABILITIES or self.registry.code_origin(capability_name) != "internal" or capability_name.startswith("external.observe.") or manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
                    token_required = True
                elif token_raw is not None:
                    token_required = True

            if token_required and not token_obj:
                err_msg = f"AUTHORITY_VERIFICATION_FAILED: Capability '{capability_name}' ({manifest.authorization.value}) requires valid signed ExecutionToken. None provided."
                err_receipt = ExecutionReceipt(
                    receipt_id=f"rcpt_auth_denied_{uuid.uuid4().hex[:8]}",
                    job_id=job_id,
                    capability=capability_name,
                    target=params.get("target"),
                    started_at=start_t,
                    completed_at=time.time(),
                    input_hash=ExecutionReceipt.hash_payload(params),
                    output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                    exit_code=1,
                    outcome=OutcomeCategory.AUTH_REQUIRED if manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT else OutcomeCategory.POLICY_BLOCKED,
                    results={"error": err_msg},
                    side_effects=[],
                    idempotency_key=idemp_key,
                    attempt_number=attempt_number,
                    requested_network_policy=manifest.network_policy,
                    actual_transport_used="NONE_AUTHORITY_DENIED",
                    worker_id=worker_id,
                    error_message=err_msg
                ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                return err_receipt

            # 2. If token is present, perform rigorous 14-field verification & replay defense
            if token_obj:
                now = time.time()
                computed_p_hash = ExecutionReceipt.hash_payload(params)

                # Field 1: Expiration
                if token_obj.expires_at > 0 and now > token_obj.expires_at:
                    err_msg = f"EXECUTION_TOKEN_EXPIRED: Token expired at {token_obj.expires_at}, current time {now}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_exp_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_TOKEN_EXPIRED",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 2: Issued at (reject future timestamps)
                if token_obj.issued_at > now + 5.0:
                    err_msg = f"EXECUTION_TOKEN_FUTURE_ISSUED: Token issued_at={token_obj.issued_at} > current time {now}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_future_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_FUTURE_ISSUED",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Check 3: Cryptographic Signature check against TrustRegistry
                if self.trust_registry:
                    is_valid_sig, sig_err = self.trust_registry.verify_signature_at_time(
                        token_obj.kernel_key_id,
                        token_obj.compute_canonical_payload(),
                        token_obj.signature,
                        token_obj.issued_at
                    )
                    if not is_valid_sig:
                        err_msg = f"EXECUTION_TOKEN_SIGNATURE_INVALID: {sig_err}."
                        err_receipt = ExecutionReceipt(
                            receipt_id=f"rcpt_tok_sig_err_{uuid.uuid4().hex[:8]}",
                            job_id=job_id,
                            capability=capability_name,
                            target=params.get("target"),
                            started_at=start_t,
                            completed_at=time.time(),
                            input_hash=computed_p_hash,
                            output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                            exit_code=1,
                            outcome=OutcomeCategory.POLICY_BLOCKED,
                            results={"error": err_msg},
                            side_effects=[],
                            idempotency_key=idemp_key,
                            attempt_number=attempt_number,
                            requested_network_policy=manifest.network_policy,
                            actual_transport_used="NONE_SIGNATURE_INVALID",
                            worker_id=worker_id,
                            error_message=err_msg
                        ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                        self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                        return err_receipt

                # Check 4: Persistent Replay Protection (ciph_consumed_tokens in SQLite)
                is_replayed = False
                try:
                    with self.queue._get_connection() as conn:
                        cur = conn.execute("SELECT token_id FROM ciph_consumed_tokens WHERE token_id = ? OR nonce = ?", (token_obj.token_id, token_obj.nonce))
                        if cur.fetchone() or token_obj.token_id in self._executed_token_ids:
                            is_replayed = True
                except Exception as dbe:
                    err_msg = f"STORAGE_UNAVAILABLE: Failed to query persistent token replay status from database: {dbe}"
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_storage_qry_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_STORAGE_FAILURE",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    try:
                        self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    except Exception:
                        pass
                    return err_receipt

                if is_replayed:
                    err_msg = f"EXECUTION_TOKEN_REPLAYED: Token ID '{token_obj.token_id}' or nonce was already executed."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_replay_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_TOKEN_REPLAY",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 5: Capability match
                if token_obj.capability != capability_name:
                    err_msg = f"EXECUTION_TOKEN_MISMATCH: Token capability '{token_obj.capability}' != requested '{capability_name}'."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_mismatch_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_TOKEN_MISMATCH",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 4: Parameters hash
                if token_obj.parameters_hash != computed_p_hash:
                    err_msg = f"EXECUTION_TOKEN_PARAMS_HASH_MISMATCH: expected {token_obj.parameters_hash}, got {computed_p_hash}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_param_err_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_PARAMS_MISMATCH",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 5: Execution lane
                expected_lane = manifest.derive_execution_lane().value
                if token_obj.execution_lane != expected_lane:
                    err_msg = f"EXECUTION_TOKEN_LANE_MISMATCH: expected {expected_lane}, got {token_obj.execution_lane}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_lane_err_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_LANE_MISMATCH",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 7: Step ID
                expected_step_id = job.get('step_id') or getattr(token_obj, 'step_id', None)
                if expected_step_id and token_obj.step_id != expected_step_id:
                    err_msg = f"EXECUTION_TOKEN_STEP_ID_MISMATCH: expected {expected_step_id}, got {token_obj.step_id}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_step_err_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_STEP_ID_MISMATCH",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 8: Plan hash
                plan_id = job.get('plan_id') or getattr(token_obj, 'plan_id', None) or "PLAN_STANDALONE"
                step_id = job.get('step_id') or getattr(token_obj, 'step_id', None) or "STEP_STANDALONE"
                expected_plan_hash = hashlib.sha256(f"{plan_id}:{step_id}".encode('utf-8')).hexdigest()[:16]
                is_valid_p_hash = (
                    token_obj.plan_hash == expected_plan_hash
                    or (len(token_obj.plan_hash) == 64 and job.get('plan_id') and job.get('plan_id') != 'PLAN_STANDALONE')
                    or (token_obj.authorization_grant_id and token_obj.authorization_grant_id != 'NONE')
                )
                if not is_valid_p_hash:
                    err_msg = f"EXECUTION_TOKEN_PLAN_HASH_MISMATCH: expected {expected_plan_hash}, got {token_obj.plan_hash}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_plan_err_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_PLAN_HASH_MISMATCH",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 8: Manifest hash
                expected_m_hash = manifest.compute_manifest_hash()
                if token_obj.manifest_hash != expected_m_hash:
                    err_msg = f"EXECUTION_TOKEN_MANIFEST_HASH_MISMATCH: expected {expected_m_hash}, got {token_obj.manifest_hash}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_mhash_err_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_MANIFEST_HASH_MISMATCH",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 9: Manifest version
                if token_obj.manifest_version != manifest.version:
                    err_msg = f"EXECUTION_TOKEN_MANIFEST_VERSION_MISMATCH: expected {manifest.version}, got {token_obj.manifest_version}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_mver_err_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_MANIFEST_VERSION_MISMATCH",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 10: Authorized worker class
                worker_cls = getattr(self, "worker_class", "DEFAULT")
                if token_obj.authorized_worker_class not in ("ALL", worker_cls, worker_id):
                    err_msg = f"EXECUTION_TOKEN_WORKER_CLASS_UNAUTHORIZED: Token authorized for '{token_obj.authorized_worker_class}', worker is '{worker_cls}'."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_wcls_err_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_WORKER_CLASS_UNAUTHORIZED",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 11: Max attempts
                if token_obj.max_attempts <= 0:
                    err_msg = f"EXECUTION_TOKEN_MAX_ATTEMPTS_INVALID: max_attempts={token_obj.max_attempts} <= 0."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_attempts_inv_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_number,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_MAX_ATTEMPTS_INVALID",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                attempt_num = attempt_number
                if attempt_num > token_obj.max_attempts:
                    err_msg = f"EXECUTION_TOKEN_ATTEMPTS_EXCEEDED: attempt {attempt_num} exceeds max_attempts {token_obj.max_attempts}."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_attempts_exc_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash,
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=attempt_num,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="NONE_ATTEMPTS_EXCEEDED",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    return err_receipt

                # Field 12: Mandatory Authorization Grant Check
                if manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
                    if not token_obj.authorization_grant_id or token_obj.authorization_grant_id in ("NONE", ""):
                        err_msg = f"EXECUTION_TOKEN_MISSING_GRANT: Capability '{capability_name}' requires AuthorizationGrant bound in token."
                        err_receipt = ExecutionReceipt(
                            receipt_id=f"rcpt_tok_no_grant_{uuid.uuid4().hex[:8]}",
                            job_id=job_id,
                            capability=capability_name,
                            target=params.get("target"),
                            started_at=start_t,
                            completed_at=time.time(),
                            input_hash=computed_p_hash,
                            output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                            exit_code=1,
                            outcome=OutcomeCategory.AUTH_REQUIRED,
                            results={"error": err_msg},
                            side_effects=[],
                            idempotency_key=idemp_key,
                            attempt_number=attempt_number,
                            requested_network_policy=manifest.network_policy,
                            actual_transport_used="NONE_GRANT_MISSING",
                            worker_id=worker_id,
                            error_message=err_msg
                        ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                        self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                        return err_receipt

                    # Verify grant against SQLite ciph_authorization_grants
                    grant_verified = False
                    try:
                        with self.queue._get_connection() as conn:
                            cur = conn.execute("SELECT * FROM ciph_authorization_grants WHERE grant_id = ?", (token_obj.authorization_grant_id,))
                            g_row = cur.fetchone()
                            if g_row:
                                if (g_row["capability"] == capability_name and
                                    g_row["params_hash"] == computed_p_hash and
                                    g_row["plan_hash"] == token_obj.plan_hash and
                                    g_row["step_id"] == token_obj.step_id and
                                    (g_row["expires_at"] == 0 or now <= g_row["expires_at"])):
                                    grant_verified = True
                    except Exception:
                        pass

                    if not grant_verified:
                        err_msg = f"EXECUTION_TOKEN_GRANT_UNVERIFIED: Authorization grant '{token_obj.authorization_grant_id}' is invalid, unverified, expired, or mismatched."
                        err_receipt = ExecutionReceipt(
                            receipt_id=f"rcpt_tok_bad_grant_{uuid.uuid4().hex[:8]}",
                            job_id=job_id,
                            capability=capability_name,
                            target=params.get("target"),
                            started_at=start_t,
                            completed_at=time.time(),
                            input_hash=computed_p_hash,
                            output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                            exit_code=1,
                            outcome=OutcomeCategory.AUTH_REQUIRED,
                            results={"error": err_msg},
                            side_effects=[],
                            idempotency_key=idemp_key,
                            attempt_number=attempt_number,
                            requested_network_policy=manifest.network_policy,
                            actual_transport_used="NONE_GRANT_UNVERIFIED",
                            worker_id=worker_id,
                            error_message=err_msg
                        ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                        self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                        return err_receipt

            # -------------------------------------------------------------
            # Barrier 3: Atomic Queue Lease Validation & Token Consumption
            # -------------------------------------------------------------
            token_id = token_obj.token_id if token_obj else None
            nonce = token_obj.nonce if token_obj else None
            tok_exp = token_obj.expires_at if token_obj else None

            try:
                success, err_reason = self.queue.mark_executing_and_consume_token(
                    job_id=job_id,
                    worker_id=worker_id,
                    token_id=token_id,
                    nonce=nonce,
                    token_expires_at=tok_exp
                )
            except Exception as ex:
                success, err_reason = False, f"STORAGE_FAILURE: {ex}"
            if not success:
                if err_reason == "TOKEN_EXPIRED":
                    now_ts = time.time()
                    err_msg = f"EXECUTION_TOKEN_EXPIRED: Token expired at {tok_exp}, current time {now_ts} immediately prior to consumption."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_exp_race_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=now_ts,
                        input_hash=computed_p_hash if 'computed_p_hash' in locals() else ExecutionReceipt.hash_payload(params),
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=job.get("attempt_number", 1),
                        requested_network_policy=manifest.network_policy if 'manifest' in locals() else NetworkPolicy.OFFLINE_ONLY,
                        actual_transport_used="NONE_TOKEN_EXPIRED_RACE",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    try:
                        self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    except Exception:
                        pass
                    return err_receipt
                elif err_reason == "TOKEN_REPLAYED":
                    err_msg = f"EXECUTION_TOKEN_REPLAYED: Token ID '{token_id}' or nonce was already consumed (uniqueness constraint violated)."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_replay_race_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash if 'computed_p_hash' in locals() else ExecutionReceipt.hash_payload(params),
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=job.get("attempt_number", 1),
                        requested_network_policy=manifest.network_policy if 'manifest' in locals() else NetworkPolicy.OFFLINE_ONLY,
                        actual_transport_used="NONE_TOKEN_REPLAY_RACE",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    try:
                        self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    except Exception:
                        pass
                    return err_receipt
                elif err_reason and str(err_reason).startswith("STORAGE_FAILURE"):
                    err_msg = f"STORAGE_UNAVAILABLE: Failed to atomically consume execution token: {err_reason}"
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_tok_storage_err_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target"),
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash if 'computed_p_hash' in locals() else ExecutionReceipt.hash_payload(params),
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=job.get("attempt_number", 1),
                        requested_network_policy=manifest.network_policy if 'manifest' in locals() else NetworkPolicy.OFFLINE_ONLY,
                        actual_transport_used="NONE_STORAGE_FAILURE",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    try:
                        self.queue.fail_job_and_append_receipt_event(job_id, worker_id, err_msg, err_receipt.to_dict())
                    except Exception:
                        pass
                    return err_receipt
                else:
                    err_msg = f"LEASE_LOST_BEFORE_EXECUTION: Worker '{worker_id}' failed to transition job '{job_id}' to EXECUTING (lease lost or expired)."
                    err_receipt = ExecutionReceipt(
                        receipt_id=f"rcpt_lease_lost_{uuid.uuid4().hex[:8]}",
                        job_id=job_id,
                        capability=capability_name,
                        target=params.get("target") if isinstance(params, dict) else None,
                        started_at=start_t,
                        completed_at=time.time(),
                        input_hash=computed_p_hash if 'computed_p_hash' in locals() else ExecutionReceipt.hash_payload(params),
                        output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                        exit_code=1,
                        outcome=OutcomeCategory.POLICY_BLOCKED,
                        results={"error": err_msg},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=job.get("attempt_number", 1),
                        requested_network_policy=manifest.network_policy if 'manifest' in locals() else NetworkPolicy.OFFLINE_ONLY,
                        actual_transport_used="NONE_LEASE_LOST",
                        worker_id=worker_id,
                        error_message=err_msg
                    ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                    return err_receipt

            token_hash = token_obj.token_hash() if token_obj else ""
            if token_obj:
                self._executed_token_ids.add(token_obj.token_id)
            exec_start_t = time.time()

            # Start background heartbeat now that execution is confirmed
            stop_heartbeat = threading.Event()
            hb_thread = threading.Thread(
                target=self._start_heartbeat,
                args=(job_id, worker_id, stop_heartbeat),
                name=f"HB-{job_id}",
                daemon=True
            )
            hb_thread.start()

            from ciph.kernel.sandbox import OfflineSandboxRunner, SandboxPolicy, SandboxTerminationReason
            from ciph.kernel.policy_engine import is_sandboxed_execution_required
            from ciph.contracts.enums import ScopeType

            scope_obj = None
            if token_obj and token_obj.scope_payload_json:
                from ciph.contracts.grants import ScopeGrant
                scope_obj = ScopeGrant.from_dict(json.loads(token_obj.scope_payload_json))
                if scope_obj.scope_id != token_obj.scope_grant_id or scope_obj.is_expired():
                    raise PermissionError("SIGNED_SCOPE_BINDING_INVALID")

            is_sandboxed = is_sandboxed_execution_required(
                capability_name=capability_name,
                manifest=manifest,
                cap_instance=cap,
                scope_grant=scope_obj if 'scope_obj' in locals() else None,
                execution_token=token_obj,
                code_origin=self.registry.code_origin(capability_name)
            )

            from ciph.capabilities.external_evidence import ExternalEvidenceCapability
            external_source = cap.source if type(cap) is ExternalEvidenceCapability else None
            from ciph.evolution.production import EvolutionRevisionCapability
            if type(cap) is EvolutionRevisionCapability:
                # Exact trusted adapter type: token/scope verification above remains
                # mandatory. Candidate code executes only in the OS sandbox.
                execution_started = True
                sbx_res = cap.execute_supervised(params, token_obj)
                if not sbx_res.execution_confirmed and sbx_res.termination_reason != SandboxTerminationReason.UNCERTAIN_CLEANUP:
                    stop_heartbeat.set()
                    denial_payload={"job_id":job_id,"worker_id":worker_id,"capability":capability_name,
                        "reason":"SANDBOX_UNAVAILABLE","error":sbx_res.stderr,"timestamp":time.time()}
                    from ciph.kernel.crypto_identity import Ed25519KeyManager
                    denial_payload['supervisor_signature']=Ed25519KeyManager.sign(self.worker_secret_key,json.dumps(denial_payload,sort_keys=True).encode())
                    self.queue.fail_job_containment_denied(job_id,worker_id,sbx_res.stderr,denial_payload)
                    return {"status":"SANDBOX_UNAVAILABLE","job_id":job_id,"error":sbx_res.stderr}
                if sbx_res.termination_reason == SandboxTerminationReason.UNCERTAIN_CLEANUP:
                    stop_heartbeat.set()
                    self.queue.mark_job_uncertain(job_id,worker_id,sbx_res.stderr)
                    return {"status":"RECONCILIATION_REQUIRED","job_id":job_id}
                end_t=time.time()
                result=sbx_res.data if sbx_res.data is not None else {"error":sbx_res.stderr}
                raw_receipt=ExecutionReceipt(receipt_id='rcpt_evolution_'+uuid.uuid4().hex,job_id=job_id,
                    capability=capability_name,target=params.get('target'),started_at=exec_start_t,completed_at=end_t,
                    input_hash=ExecutionReceipt.hash_payload(params),output_hash=ExecutionReceipt.hash_payload(result),
                    exit_code=sbx_res.exit_code if sbx_res.exit_code is not None else 1,
                    outcome=OutcomeCategory.SUCCESS if sbx_res.exit_code==0 else OutcomeCategory.EXECUTION_ERROR,
                    results=result,side_effects=[],idempotency_key=idemp_key,attempt_number=attempt_number,
                    requested_network_policy=manifest.network_policy,actual_transport_used='SANDBOX_OFFLINE',worker_id=worker_id,
                    error_message=sbx_res.stderr or None,
                    provenance={
                        "token_id": token_obj.token_id,
                        "execution_token_hash": token_obj.token_hash(),
                        "manifest_version": token_obj.manifest_version,
                        "manifest_hash": token_obj.manifest_hash,
                        "parameters_hash": token_obj.parameters_hash,
                        "plan_hash": token_obj.plan_hash,
                        "step_id": token_obj.step_id,
                        "reversibility": manifest.reversibility.value,
                        "evolution_canary_id": cap.canary_id,
                        "source_revision": cap.manager._load(cap.canary_id)['candidate_hash'],
                        "peak_memory_bytes": sbx_res.peak_memory_bytes,
                        "cpu_seconds": sbx_res.cpu_seconds
                    } if token_obj else {
                        "reversibility": manifest.reversibility.value,
                        "evolution_canary_id": cap.canary_id,
                        "source_revision": cap.manager._load(cap.canary_id)['candidate_hash'],
                        "peak_memory_bytes": sbx_res.peak_memory_bytes,
                        "cpu_seconds": sbx_res.cpu_seconds
                    }
                )
            elif is_sandboxed:
                if not hasattr(cap, "get_sandbox_command") or not callable(getattr(cap, "get_sandbox_command")):
                    stop_heartbeat.set()
                    denial_payload = {
                        "job_id": job_id,
                        "worker_id": worker_id,
                        "capability": capability_name,
                        "reason": "SANDBOX_ADAPTER_MISSING",
                        "error": f"Capability '{capability_name}' requires sandboxing but provides no get_sandbox_command adapter.",
                        "timestamp": time.time(),
                    }
                    if self.worker_secret_key:
                        denial_bytes = json.dumps(denial_payload, sort_keys=True).encode('utf-8')
                        try:
                            from ciph.kernel.crypto_identity import Ed25519KeyManager
                            denial_payload["supervisor_signature"] = Ed25519KeyManager.sign(self.worker_secret_key, denial_bytes)
                        except Exception:
                            denial_payload["supervisor_signature"] = hmac.new(self.worker_secret_key, denial_bytes, hashlib.sha256).hexdigest()

                    if hasattr(self.queue, "fail_job_containment_denied"):
                        self.queue.fail_job_containment_denied(
                            job_id=job_id,
                            worker_id=worker_id,
                            error=f"SANDBOX_UNAVAILABLE: SANDBOX_ADAPTER_MISSING: Capability '{capability_name}' provides no get_sandbox_command adapter.",
                            denial_payload=denial_payload
                        )
                    else:
                        if self.event_store:
                            self.event_store.append_event(
                                "SandboxDeniedEvent",
                                f"sandbox:denial:{job_id}",
                                denial_payload
                            )
                        self.queue.fail_job(
                            job_id=job_id,
                            worker_id=worker_id,
                            error=f"SANDBOX_UNAVAILABLE: SANDBOX_ADAPTER_MISSING: Capability '{capability_name}' provides no get_sandbox_command adapter."
                        )
                    return {
                        "status": "SANDBOX_UNAVAILABLE",
                        "job_id": job_id,
                        "error": f"Capability '{capability_name}' requires sandboxing but provides no get_sandbox_command adapter.",
                    }

                sbx_policy = SandboxPolicy(
                    network_policy=NetworkPolicy.OFFLINE_ONLY if external_source else manifest.network_policy,
                    max_wall_time_seconds=float(manifest.timeout_seconds),
                )
                from ciph.kernel.sandbox.runner import RootlessContainerRunner
                container_required = scope_obj and scope_obj.scope_type == ScopeType.CONTAINER_SANDBOX
                runner = RootlessContainerRunner() if container_required else (self.sandbox_runner or OfflineSandboxRunner())
                diag = runner.probe_containment(sbx_policy)
                if diag.overall == "UNAVAILABLE":
                    stop_heartbeat.set()
                    denial_payload = {
                        "job_id": job_id,
                        "worker_id": worker_id,
                        "capability": capability_name,
                        "reason": "SANDBOX_UNAVAILABLE",
                        "diagnostics": diag.to_dict(),
                        "timestamp": time.time(),
                    }
                    if self.worker_secret_key:
                        denial_bytes = json.dumps(denial_payload, sort_keys=True).encode('utf-8')
                        try:
                            from ciph.kernel.crypto_identity import Ed25519KeyManager
                            denial_payload["supervisor_signature"] = Ed25519KeyManager.sign(self.worker_secret_key, denial_bytes)
                        except Exception:
                            denial_payload["supervisor_signature"] = hmac.new(self.worker_secret_key, denial_bytes, hashlib.sha256).hexdigest()

                    if hasattr(self.queue, "fail_job_containment_denied"):
                        self.queue.fail_job_containment_denied(
                            job_id=job_id,
                            worker_id=worker_id,
                            error="SANDBOX_UNAVAILABLE: Containment criteria not met.",
                            denial_payload=denial_payload
                        )
                    else:
                        if self.event_store:
                            self.event_store.append_event(
                                "SandboxDeniedEvent",
                                f"sandbox:denial:{job_id}",
                                denial_payload
                            )
                        self.queue.fail_job(
                            job_id=job_id,
                            worker_id=worker_id,
                            error="SANDBOX_UNAVAILABLE: Containment criteria not met."
                        )
                    return {
                        "status": "SANDBOX_UNAVAILABLE",
                        "job_id": job_id,
                        "diagnostics": diag.to_dict(),
                        "error": "Containment unavailable; execution denied."
                    }

                sbx_cmd = cap.get_sandbox_command(params)
                child_payload = params
                broker_transport = "NONE"
                if external_source:
                    from ciph.kernel.sandbox.tor_broker import TorEvidenceBroker
                    execution_started = True
                    try:
                        expected_source_hash = hashlib.sha256(json.dumps(external_source.provenance(), sort_keys=True).encode()).hexdigest()
                        if not token_obj or token_obj.source_policy_hash != expected_source_hash:
                            raise PermissionError("EXTERNAL_SOURCE_CHANGED_AFTER_AUTHORIZATION")
                        broker = getattr(self, "evidence_broker", None) or TorEvidenceBroker()
                        observation = broker.fetch(external_source, target=params.get("target"), scope=scope_obj)
                        child_payload = {"success": True, "observation": observation}
                        broker_transport = "TOR_SOCKS5_REMOTE_DNS_PINNED"
                    except Exception as exc:
                        child_payload = {"success": False, "error": str(exc), "status": "EXTERNAL_COLLECTION_FAILED"}
                execution_started = True
                sbx_res = runner.execute_isolated(sbx_cmd, payload=child_payload, policy=sbx_policy)
                if external_source and (not sbx_res.execution_confirmed or sbx_res.data != child_payload):
                    stop_heartbeat.set()
                    self.queue.mark_job_uncertain(job_id, worker_id, "EXTERNAL_COLLECTION_RECONCILIATION_REQUIRED")
                    return {"status": "RECONCILIATION_REQUIRED", "job_id": job_id}

                end_t = time.time()

                if (sbx_res.termination_reason == SandboxTerminationReason.SANDBOX_UNAVAILABLE
                    or (not sbx_res.execution_confirmed and sbx_res.exit_code is None
                        and sbx_res.termination_reason != SandboxTerminationReason.UNCERTAIN_CLEANUP)):
                    stop_heartbeat.set()
                    denial_payload = {
                        "job_id": job_id,
                        "worker_id": worker_id,
                        "capability": capability_name,
                        "reason": "SANDBOX_UNAVAILABLE",
                        "error": sbx_res.stderr or "Sandbox launch refused",
                        "diagnostics": sbx_res.diagnostics.to_dict() if sbx_res.diagnostics else None,
                        "timestamp": time.time(),
                    }
                    if self.worker_secret_key:
                        denial_bytes = json.dumps(denial_payload, sort_keys=True).encode('utf-8')
                        try:
                            from ciph.kernel.crypto_identity import Ed25519KeyManager
                            denial_payload["supervisor_signature"] = Ed25519KeyManager.sign(self.worker_secret_key, denial_bytes)
                        except Exception:
                            denial_payload["supervisor_signature"] = hmac.new(self.worker_secret_key, denial_bytes, hashlib.sha256).hexdigest()

                    if hasattr(self.queue, "fail_job_containment_denied"):
                        self.queue.fail_job_containment_denied(
                            job_id=job_id,
                            worker_id=worker_id,
                            error=f"SANDBOX_UNAVAILABLE: {sbx_res.stderr or 'Execution refused'}",
                            denial_payload=denial_payload
                        )
                    else:
                        if self.event_store:
                            self.event_store.append_event(
                                "SandboxDeniedEvent",
                                f"sandbox:denial:{job_id}",
                                denial_payload
                            )
                        self.queue.fail_job(
                            job_id=job_id,
                            worker_id=worker_id,
                            error=f"SANDBOX_UNAVAILABLE: {sbx_res.stderr or 'Execution refused'}"
                        )
                    return {
                        "status": "SANDBOX_UNAVAILABLE",
                        "job_id": job_id,
                        "error": sbx_res.stderr or "Sandbox launch refused",
                    }

                if (sbx_res.termination_reason == SandboxTerminationReason.UNCERTAIN_CLEANUP
                    or (manifest.reversibility.value != "READ_ONLY" and sbx_res.termination_reason in
                        (SandboxTerminationReason.TIMEOUT, SandboxTerminationReason.OUTPUT_FLOOD))):
                    stop_heartbeat.set()
                    self.queue.mark_job_uncertain(job_id, worker_id, "UNCERTAIN_CLEANUP: Sandbox descendants could not be confirmed dead")
                    return {
                        "status": "RECONCILIATION_REQUIRED",
                        "job_id": job_id,
                        "error": "UNCERTAIN_CLEANUP: Sandbox descendants could not be confirmed dead",
                    }

                outcome_cat = OutcomeCategory.SUCCESS if sbx_res.exit_code == 0 else OutcomeCategory.EXECUTION_ERROR
                if sbx_res.termination_reason == SandboxTerminationReason.OUTPUT_FLOOD:
                    outcome_cat = OutcomeCategory.RESOURCE_EXHAUSTED
                elif sbx_res.termination_reason == SandboxTerminationReason.TIMEOUT:
                    outcome_cat = OutcomeCategory.TIMEOUT

                token_hash = token_obj.token_hash() if token_obj else ""
                raw_receipt = ExecutionReceipt(
                    receipt_id=f"rcpt_sbx_{uuid.uuid4().hex[:12]}",
                    job_id=job_id,
                    capability=capability_name,
                    target=params.get("target") if isinstance(params, dict) else None,
                    started_at=exec_start_t,
                    completed_at=end_t,
                    input_hash=computed_p_hash if 'computed_p_hash' in locals() else ExecutionReceipt.hash_payload(params),
                    output_hash=ExecutionReceipt.hash_payload(sbx_res.data or {"raw": sbx_res.stdout, "err": sbx_res.stderr}),
                    exit_code=sbx_res.exit_code if sbx_res.exit_code is not None else 1,
                    outcome=outcome_cat,
                    results=sbx_res.data or {"raw": sbx_res.stdout, "err": sbx_res.stderr},
                    side_effects=[],
                    idempotency_key=idemp_key,
                    attempt_number=attempt_number,
                    requested_network_policy=manifest.network_policy,
                    actual_transport_used=broker_transport if external_source else "SANDBOX_OFFLINE",
                    worker_id=worker_id,
                    error_message=sbx_res.stderr if (sbx_res.exit_code or 0) != 0 else None,
                    provenance={
                        "token_id": token_obj.token_id,
                        "execution_token_hash": token_hash,
                        "manifest_version": token_obj.manifest_version,
                        "manifest_hash": token_obj.manifest_hash,
                        "parameters_hash": token_obj.parameters_hash,
                        "plan_hash": token_obj.plan_hash,
                        "step_id": token_obj.step_id,
                        "reversibility": manifest.reversibility.value,
                        "sandbox_tier": runner.tier,
                        **({"external_source_policy": external_source.provenance()} if external_source else {})
                    } if token_obj else {}
                )
            else:
                from ciph.capabilities.base import WorkerExecutionContext
                token_hash = token_obj.token_hash() if token_obj else ""
                worker_ctx = WorkerExecutionContext.create(
                    job_id=job_id,
                    worker_id=worker_id,
                    capability=capability_name,
                    token_hash=token_hash,
                    worker_secret_key=self.worker_secret_key
                )
                execution_started = True
                exec_context = {
                    "job_id": job_id,
                    "worker_id": worker_id,
                    "worker_context": worker_ctx,
                    "worker_secret_key": self.worker_secret_key,
                    "trust_registry": self.trust_registry,
                    "idempotency_key": idemp_key,
                    "plan_id": plan_id,
                    "step_id": step_id,
                    "execution_token": token_obj,
                    "execution_token_hash": token_hash,
                    "attempt_number": attempt_number,
                    "provenance": {
                        "token_id": token_obj.token_id,
                        "execution_token_hash": token_hash,
                        "manifest_version": token_obj.manifest_version,
                        "manifest_hash": token_obj.manifest_hash,
                        "parameters_hash": token_obj.parameters_hash,
                        "plan_hash": token_obj.plan_hash,
                        "step_id": token_obj.step_id,
                        "reversibility": manifest.reversibility.value
                    } if token_obj else {"reversibility": manifest.reversibility.value}
                }
                raw_receipt = cap.execute(params, context=exec_context)
                end_t = time.time()

            # Ensure receipt worker_id and attempt_number match the executing lease holder
            if raw_receipt.worker_id != worker_id or raw_receipt.attempt_number != attempt_number:
                raw_d = raw_receipt.to_dict()
                raw_d["worker_id"] = worker_id
                raw_d["attempt_number"] = attempt_number
                raw_receipt = ExecutionReceipt.from_dict(raw_d)

            # Verify consistency of receipt provenance against validated execution token and manifest before signing
            if token_obj:
                r_prov = raw_receipt.provenance or {}
                exp_m_hash = manifest.compute_manifest_hash()
                if (r_prov.get("manifest_version") != manifest.version or
                    r_prov.get("manifest_version") != token_obj.manifest_version or
                    r_prov.get("manifest_hash") != exp_m_hash or
                    r_prov.get("manifest_hash") != token_obj.manifest_hash or
                    r_prov.get("execution_token_hash") != token_hash or
                    r_prov.get("token_id") != token_obj.token_id or
                    r_prov.get("parameters_hash") != token_obj.parameters_hash or
                    r_prov.get("plan_hash") != token_obj.plan_hash or
                    r_prov.get("step_id") != token_obj.step_id or
                    raw_receipt.capability != token_obj.capability or
                    raw_receipt.input_hash != token_obj.parameters_hash):
                    err_msg = "PROVENANCE_CONSISTENCY_VIOLATION: Receipt provenance does not match verified execution token and manifest."
                    raw_d = raw_receipt.to_dict()
                    raw_d["outcome"] = OutcomeCategory.POLICY_BLOCKED
                    raw_d["exit_code"] = 1
                    raw_d["error_message"] = err_msg
                    raw_d["results"] = {"error": err_msg}
                    raw_d["output_hash"] = ExecutionReceipt.hash_payload(raw_d["results"])
                    raw_receipt = ExecutionReceipt.from_dict(raw_d)

            # Sign receipt
            receipt = raw_receipt.sign(self.worker_secret_key, worker_key_id=self.worker_key_id)

            # Atomic Single-Transaction Commit to Queue and EventStore
            if receipt.exit_code == 0:
                try:
                    commit_rowid = self.queue.complete_job_and_append_receipt_event(
                        job_id=job_id,
                        worker_id=worker_id,
                        receipt_dict=receipt.to_dict()
                    )
                    if commit_rowid:
                        with self._worker_lock:
                            self._total_processed += 1
                    if not commit_rowid:
                        err_msg = f"COMMIT_FAILED_LEASE_LOST: Atomic completion commit failed for job '{job_id}' on worker '{worker_id}' (lease lost, reclaimed, or expired during execution)."
                        receipt = ExecutionReceipt(
                            receipt_id=f"rcpt_commit_lost_{uuid.uuid4().hex[:8]}",
                            job_id=job_id,
                            capability=capability_name,
                            target=receipt.target,
                            started_at=receipt.started_at,
                            completed_at=time.time(),
                            input_hash=receipt.input_hash,
                            output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                            exit_code=1,
                            outcome=OutcomeCategory.POLICY_BLOCKED,
                            results={"error": err_msg},
                            side_effects=receipt.side_effects,
                            idempotency_key=receipt.idempotency_key,
                            attempt_number=receipt.attempt_number,
                            requested_network_policy=receipt.requested_network_policy,
                            actual_transport_used="NONE_COMMIT_FAILED",
                            worker_id=worker_id,
                            error_message=err_msg
                        ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                except Exception as store_ex:
                    # Completion storage failed after execution succeeded!
                    # Do NOT treat as execution error and do NOT allow automatic blind re-execution.
                    # Preserve evidence and require reconciliation.
                    try:
                        self.queue.mark_reconciliation_required(
                            job_id=job_id,
                            worker_id=worker_id,
                            error=f"RECEIPT_STORE_FAILURE: {store_ex}",
                            receipt_dict=receipt.to_dict()
                        )
                    except Exception:
                        pass
                    return self._uncommitted_receipt(receipt, f"RECEIPT_STORE_FAILURE: {store_ex}")
            else:
                with self._worker_lock:
                    self._total_failed += 1
                if (receipt.side_effects or manifest.reversibility.value != "READ_ONLY"):
                    try:
                        self.queue.mark_reconciliation_required(job_id, worker_id, "EXECUTION_EFFECTS_UNCERTAIN", receipt.to_dict())
                    except Exception:
                        pass
                    return self._uncommitted_receipt(receipt, "EXECUTION_EFFECTS_UNCERTAIN")
                try:
                    fail_rowid = self.queue.fail_job_and_append_receipt_event(
                        job_id=job_id,
                        worker_id=worker_id,
                        error=receipt.error_message or "Execution returned non-zero exit code",
                        receipt_dict=receipt.to_dict()
                    )
                    if not fail_rowid:
                        err_msg = f"COMMIT_FAILED_LEASE_LOST: Atomic failure commit failed for job '{job_id}' on worker '{worker_id}' (lease lost, reclaimed, or expired during execution)."
                        receipt = ExecutionReceipt(
                            receipt_id=f"rcpt_commit_fail_lost_{uuid.uuid4().hex[:8]}",
                            job_id=job_id,
                            capability=capability_name,
                            target=receipt.target,
                            started_at=receipt.started_at,
                            completed_at=time.time(),
                            input_hash=receipt.input_hash,
                            output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                            exit_code=1,
                            outcome=OutcomeCategory.POLICY_BLOCKED,
                            results={"error": err_msg},
                            side_effects=receipt.side_effects,
                            idempotency_key=receipt.idempotency_key,
                            attempt_number=receipt.attempt_number,
                            requested_network_policy=receipt.requested_network_policy,
                            actual_transport_used="NONE_COMMIT_FAILED",
                            worker_id=worker_id,
                            error_message=err_msg
                        ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                except Exception as store_ex:
                    try:
                        self.queue.mark_reconciliation_required(
                            job_id=job_id,
                            worker_id=worker_id,
                            error=f"FAILURE_RECEIPT_STORE_FAILURE: {store_ex}",
                            receipt_dict=receipt.to_dict()
                        )
                    except Exception:
                        pass
                    return self._uncommitted_receipt(receipt, f"FAILURE_RECEIPT_STORE_FAILURE: {store_ex}")

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
            import traceback
            tb_str = traceback.format_exc()
            with self._worker_lock:
                self._total_failed += 1
            err_receipt = ExecutionReceipt(
                receipt_id=f"rcpt_fail_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                capability=capability_name,
                target=params.get("target") if isinstance(params, dict) else None,
                started_at=start_t,
                completed_at=time.time(),
                input_hash=ExecutionReceipt.hash_payload(params),
                output_hash=ExecutionReceipt.hash_payload({"error": str(ex)}),
                exit_code=1,
                outcome=OutcomeCategory.EXECUTION_ERROR,
                results={"error": str(ex)},
                side_effects=[],
                idempotency_key=idemp_key,
                attempt_number=attempt_number,
                requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
                actual_transport_used="EXCEPTION_FAILED",
                worker_id=worker_id,
                error_class=type(ex).__name__,
                backtrace=tb_str[:1024],
                error_message=str(ex)
            ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
            receipt = err_receipt
            if execution_started:
                try:
                    self.queue.mark_reconciliation_required(job_id, worker_id, str(ex), err_receipt.to_dict())
                except Exception:
                    pass
                return self._uncommitted_receipt(err_receipt, f"WORKER_EXCEPTION_AFTER_ACTIVATION: {ex}")
            try:
                self.queue.fail_job_and_append_receipt_event(job_id, worker_id, str(ex), err_receipt.to_dict())
            except Exception:
                pass
        finally:
            if stop_heartbeat:
                stop_heartbeat.set()

        return receipt

    def _worker_loop(self, worker_id: str, stop_event: Optional[threading.Event] = None):
        """Continuous execution loop with heartbeat renewal and canonical receipts."""
        current_thread_name = threading.current_thread().name
        while self.running and (stop_event is None or not stop_event.is_set()):
            if worker_id in self._terminated_workers or current_thread_name in self._terminated_workers:
                break
            try:
                job = self.queue.lease_next_job(worker_id, lease_ttl_seconds=30)
                if not job:
                    time.sleep(0.1)
                    continue
                self._execute_leased_job(job, worker_id)
            except Exception:
                time.sleep(0.5)
