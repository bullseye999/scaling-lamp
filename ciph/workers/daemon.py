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
from ciph.workers.receipts import JobState, ExecutionReceipt, OutcomeCategory, EffectCertainty
from ciph.kernel.execution_gateway import GovernedPreExecutionRefusal
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
        retry_disposition: Optional[Any] = None,
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
        # The ONE disposition engine for post-failure governed jobs, injected by the composition boundary.
        self.retry_disposition = retry_disposition
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

    def _resolve_job_canonical_scope(self, job):
        """
        Resolve the canonical ScopeGrant for this job EXACTLY ONCE (S3.4).

        The reference is the one the governed request/permit path binds - never the token's embedded
        copy and never descriptive queue metadata. Every execution-affecting decision consumes the
        returned object: sandbox requirement, runner selection, broker access and the execution
        request. Returns None when the job references no scope at all; raises a governed refusal when
        a referenced scope cannot be resolved, because guessing is not an option.
        """
        import json as _json

        from ciph.kernel.scope_grant_store import ScopeGrantStore

        raw = job["execution_permit"] if "execution_permit" in job.keys() else None
        if not raw:
            return None
        try:
            data = _json.loads(raw) if isinstance(raw, str) else raw
            from ciph.kernel.execution_authority import SignedExecutionPermit
            permit = SignedExecutionPermit.from_dict(data)
        except Exception:
            return None
        reference = permit.payload.scope_grant_id
        if not reference or reference == "NONE":
            return None
        resolved = ScopeGrantStore(self.queue.db_path).resolve(reference)
        if not resolved.resolvable:
            raise GovernedPreExecutionRefusal(
                f"SCOPE_REFERENCE_UNRESOLVED:{reference}:{resolved.outcome.value}"
            )
        return resolved.grant

    def _dispose_post_claim_failure(self, *, job_id, permit_id, attempt_number):
        """
        Hand a post-claim failure to the ONE disposition engine.

        The worker reports facts; the central transaction re-reads canonical queue state, permit
        state and exact-attempt evidence, and DERIVES both retry safety and the remaining
        execution-retry budget. Nothing here signs, bumps a generation, requeues, states an opinion
        about whether a retry is safe, or reports a budget - the worker has neither to give.
        """
        if self.retry_disposition is None:
            return None
        try:
            return self.retry_disposition(job_id=job_id, expected_permit_id=permit_id)
        except Exception:
            return None

    def _post_claim_provenance(self, slot):
        """
        The canonical provenance block for a post-claim handler, plus its integrity condition.

        Returns `(block, integrity_reason)`. It NEVER raises: a provenance corroboration failure
        happens while the daemon is already handling the execution condition that brought it here, and
        letting it propagate would replace "the body raised OriginalError" with "the handler raised
        ClaimProvenanceConflict" - losing the primary fact. Callers record both: the primary condition
        and, when present, the integrity reason, and fail closed into reconciliation.

        A missing binding is not an error: it means execution never reached the claim, and this
        post-claim machinery does not apply.
        """
        from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
        from ciph.kernel.retry_authority import (
            ClaimProvenanceConflict,
            ClaimProvenanceUnavailable,
            canonical_claim_provenance,
        )

        if slot is None or getattr(slot, "binding", None) is None:
            return None, None
        try:
            store = build_durable_permit_consumer_dependencies(
                self.queue.db_path, trust_registry=self.trust_registry
            ).permit_store
            return canonical_claim_provenance(slot, store), None
        except (ClaimProvenanceConflict, ClaimProvenanceUnavailable) as error:
            return None, type(error).__name__

    def _record_attempt_evidence(self, receipt):
        """
        Record a signed receipt as canonical attempt evidence, exactly once.

        Evidence, not authority: a signed receipt is immutable and is the exact-attempt fact the
        retry transition classifies. It MUST exist before the disposition reads it - recording it
        afterwards made every governed failure look like NO_ATTRIBUTABLE_EVIDENCE, so a claimed
        attempt could never be proven retry-safe. The receipt id guards against the double write that
        a fallback reconciliation path would otherwise produce.
        """
        try:
            if self.event_store is None or receipt is None:
                return
            receipt_id = getattr(receipt, "receipt_id", None)
            if not receipt_id:
                return
            if self.event_store.get_events(aggregate_id=receipt_id, limit=1):
                return
            self.event_store.append_event(
                "ExecutionReceiptStoredEvent", receipt_id, receipt.to_dict()
            )
        except Exception:
            pass

    def _execute_under_canonical_permit(self, *, cap, params, job, worker_id, exec_context):
        """
        Run the capability through the canonical guarded path.

        The daemon deserializes the exact permit the durable job carries; it does not interpret the
        token for authority. A missing or unreadable permit is a governed pre-execution refusal:
        execution never began, so no PermitClaim, no execution_attempt_id and no provenance are
        fabricated. Everything else - signature, expiry, revocation, consumption, capability
        mismatch - is decided by the canonical authorizer and the permit store inside
        `GuardedExecutor`, which owns the single claim transition.
        """
        import json as _json

        from ciph.kernel.execution_authority import SignedExecutionPermit
        from ciph.kernel.execution_gateway import ExecutionRequest, GuardedExecutor
        from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
        from ciph.kernel.scope_grant_store import ScopeGrantStore

        raw = job["execution_permit"] if "execution_permit" in job.keys() else None
        if not raw:
            raise GovernedPreExecutionRefusal("PERMIT_REQUIRED")
        try:
            data = _json.loads(raw) if isinstance(raw, str) else raw
            permit = SignedExecutionPermit.from_dict(data)
        except Exception as error:
            raise GovernedPreExecutionRefusal(f"PERMIT_MALFORMED:{type(error).__name__}")

        dependencies = build_durable_permit_consumer_dependencies(
            self.queue.db_path, trust_registry=self.trust_registry
        )

        scope = None
        reference = permit.payload.scope_grant_id
        if reference and reference != "NONE":
            resolved = ScopeGrantStore(self.queue.db_path).resolve(reference)
            if not resolved.resolvable:
                raise GovernedPreExecutionRefusal(
                    f"SCOPE_REFERENCE_UNRESOLVED:{reference}:{resolved.outcome.value}"
                )
            scope = resolved.grant

        request = ExecutionRequest(
            capability=cap.manifest.name,
            params=dict(params or {}),
            target=(params or {}).get("target"),
            scope_grant=scope,
            logical_action_id=permit.payload.logical_action_id,
            route="daemon.worker",
        )
        # The claim transition happens INSIDE GuardedExecutor: the attempt identity is born in the
        # authoritative transaction and nowhere else.
        # CLAIM-BOUND PROVENANCE. The builder runs only after the claim exists, so it can state
        # WHICH attempt produced this evidence - permit id, digest, authorization generation and the
        # real PermitClaim's execution_attempt_id. It reuses the existing governed-provenance block
        # rather than growing the signed receipt schema, and it merges the trajectory the daemon
        # already carries so nothing previously signed is dropped.
        def _bind_claim_to_provenance(claim):
            block = {
                "authorization_provenance": "PROVENANCE_PERMIT_V1",
                "execution_permit_id": permit.payload.permit_id,
                "execution_permit_digest": permit.permit_digest(),
                "execution_attempt_id": claim.execution_attempt_id,
                "authorization_generation": int(permit.payload.authorization_generation or 0),
                "logical_action_id": permit.payload.logical_action_id,
            }
            merged = dict(exec_context.get("provenance") or {})
            merged["governed_authorization"] = block
            # COPIED, not chosen: the binding the permit was signed over at issuance. The retry
            # decision requires the evidence to attest this exact value, so a worker cannot widen a
            # policy after the fact and a policy edit cannot reach backwards.
            merged["replay_policy_digest"] = permit.payload.replay_policy_digest
            return merged

        executor = GuardedExecutor(dependencies.authorizer, permit_store=dependencies.permit_store)
        result, _claim = executor.execute(
            request, cap, exec_context, permit=permit, claimant=worker_id,
            provenance_builder=_bind_claim_to_provenance,
        )
        return result

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
        # EXECUTION-LOCAL slot. It must never be daemon-instance state: this daemon runs several
        # worker threads, so a shared pointer would let job A's failure handler read job B's slot.
        # A frame-local variable is per-invocation by construction.
        from ciph.kernel.execution_gateway import ClaimBindingSlot
        claim_binding_slot = ClaimBindingSlot()
        try:
            cap = self.registry.get(capability_name)
            if not cap:
                err_msg = f"Capability '{capability_name}' not registered in worker."
                err_results = {"error": err_msg}
                err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                        err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                        err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                        err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                    err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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

            # S3.4: ONE canonical resolution. The token's embedded scope copy is no longer
            # consulted for any execution-affecting decision.
            canonical_scope = self._resolve_job_canonical_scope(job)

            is_sandboxed = is_sandboxed_execution_required(
                capability_name=capability_name,
                manifest=manifest,
                cap_instance=cap,
                scope_grant=canonical_scope,
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
                raw_receipt=ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, receipt_id='rcpt_evolution_'+uuid.uuid4().hex,job_id=job_id,
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
                container_required = canonical_scope and canonical_scope.scope_type == ScopeType.CONTAINER_SANDBOX
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
                        observation = broker.fetch(external_source, target=params.get("target"), scope=canonical_scope)
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
                raw_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                # The frame-local slot created above; single-assignment, validated before authorize.
                exec_context = {
                    "claim_binding_slot": claim_binding_slot,
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
                raw_receipt = self._execute_under_canonical_permit(
                    cap=cap, params=params, job=job, worker_id=worker_id,
                    exec_context=exec_context,
                )
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
                    # ONE ATOMIC COMPLETION. The terminal receipt, the job's terminal state and the
                    # permit's consumption are one proposition: a resolved attempt must not stay
                    # CLAIMED, because `CLAIMED` means "authority spent, outcome NOT yet resolved".
                    _binding = getattr(claim_binding_slot, "binding", None)
                    _consumer = None
                    if _binding is not None:
                        try:
                            from ciph.kernel.permit_composition import (
                                build_durable_permit_consumer_dependencies,
                            )
                            _consumer = build_durable_permit_consumer_dependencies(
                                self.queue.db_path, trust_registry=self.trust_registry
                            ).permit_store
                        except Exception:
                            # The execution SUCCEEDED and its receipt is authoritative; failing the
                            # completion because the consumer could not be built would turn a real
                            # effect into a reconciliation. Leave the permit CLAIMED and let Gate
                            # Zero report the outstanding completion instead.
                            _consumer = None

                    def _consume_resolved_attempt(conn):
                        if _consumer is None:
                            return
                        _consumer.consume(_binding.permit_id, worker_id, conn=conn)

                    commit_rowid = self.queue.complete_job_and_append_receipt_event(
                        job_id=job_id,
                        worker_id=worker_id,
                        receipt_dict=receipt.to_dict(),
                        within_transaction=_consume_resolved_attempt,
                    )
                    if commit_rowid:
                        with self._worker_lock:
                            self._total_processed += 1
                    if not commit_rowid:
                        err_msg = f"COMMIT_FAILED_LEASE_LOST: Atomic completion commit failed for job '{job_id}' on worker '{worker_id}' (lease lost, reclaimed, or expired during execution)."
                        receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                # ONE DISPOSITION ENGINE, non-exception path. A claimed failure is handed to the
                # canonical transition, which decides retry / reconcile / terminal. Without this the
                # legacy path refuses (correctly) and the row would sit in EXECUTING.
                # EVIDENCE BEFORE DISPOSITION. The failure receipt IS the canonical evidence the
                # retry transition classifies, so it must exist before the transition reads it.
                self._record_attempt_evidence(receipt)
                _binding = getattr(claim_binding_slot, "binding", None)
                _governed = bool(job.get("execution_permit"))
                _disposition = self._dispose_post_claim_failure(
                    job_id=job_id,
                    permit_id=(_binding.permit_id if _binding is not None else None),
                    attempt_number=attempt_number,
                )
                if _governed:
                    # A governed job's post-failure lifecycle belongs to the central transition
                    # ALONE. `applied` means it settled the row (retry / redeliver / reconcile /
                    # terminal); a refusal means the row already moved and this report is stale.
                    # Either way this path mutates nothing.
                    if _disposition is None:
                        # No disposition engine is wired. Fail closed into uncertainty instead of
                        # leaving a claimed job runnable - the worker may not choose a disposition.
                        try:
                            self.queue.mark_reconciliation_required(
                                job_id, worker_id, "RETRY_DISPOSITION_NOT_CONFIGURED", receipt.to_dict()
                            )
                        except Exception:
                            pass
                        return self._uncommitted_receipt(receipt, "RETRY_DISPOSITION_NOT_CONFIGURED")
                    return receipt
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
                        receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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

        except GovernedPreExecutionRefusal as refusal:
            # A known governance refusal is a REFUSED TRANSITION, not a failed execution.
            #
            # The claim transition - not activation and not lease acquisition - is the point after
            # which execution uncertainty becomes possible. Here no PermitClaim was created, no
            # execution_attempt_id exists and nothing ran, so there is nothing to reconcile.
            reason = getattr(refusal, "reason", type(refusal).__name__)
            err_msg = f"GOVERNED_REFUSAL: {reason}"
            refusal_receipt = ExecutionReceipt.issue(
                effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value,
                receipt_id=f"rcpt_refused_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                capability=capability_name,
                target=params.get("target") if isinstance(params, dict) else None,
                started_at=start_t,
                completed_at=time.time(),
                input_hash=ExecutionReceipt.hash_payload(params),
                output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                exit_code=1,
                outcome=OutcomeCategory.POLICY_BLOCKED,
                results={"error": err_msg, "reason": reason},
                side_effects=[],
                idempotency_key=idemp_key,
                attempt_number=attempt_number,
                requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
                actual_transport_used="NONE_GOVERNANCE_REFUSED",
                worker_id=worker_id,
                error_message=err_msg,
            ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
            try:
                self.queue.fail_job_and_append_receipt_event(
                    job_id, worker_id, err_msg, refusal_receipt.to_dict()
                )
            except Exception:
                pass
            return refusal_receipt
        except Exception as ex:
            import traceback
            tb_str = traceback.format_exc()
            with self._worker_lock:
                self._total_failed += 1
            err_receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, 
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
                # POST-CLAIM failure. Record the primary condition AND the claim attribution, using
                # the one canonical helper. If corroboration itself fails, the integrity reason is
                # attached alongside - never instead of - the execution condition, and the outcome is
                # reconciliation: execution uncertainty exists even when attribution cannot be
                # verified. Never POLICY_BLOCKED, never a retry generation.
                block, integrity_reason = self._post_claim_provenance(claim_binding_slot)
                extra = {"primary_condition": f"{type(ex).__name__}: {ex}"}
                if block is not None:
                    extra["governed_authorization"] = block
                if integrity_reason is not None:
                    extra["claim_provenance_integrity"] = integrity_reason
                try:
                    err_d = err_receipt.to_dict()
                    err_d["results"] = {**(err_d.get("results") or {}), **extra}
                    err_receipt = ExecutionReceipt.from_dict(err_d)
                except Exception:
                    pass
                # ONE DISPOSITION ENGINE. Hand the post-claim failure to the central transition,
                # which re-reads canonical state and decides. The worker only reports facts.
                # EVIDENCE BEFORE DISPOSITION (see the non-exception path): the signed failure
                # receipt is this exact attempt's canonical evidence and must exist before the
                # transition that classifies it runs.
                self._record_attempt_evidence(err_receipt)
                disposition = self._dispose_post_claim_failure(
                    job_id=job_id,
                    permit_id=(block or {}).get("execution_permit_id"),
                    attempt_number=attempt_number,
                )
                if not (disposition is not None and disposition.applied):
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
