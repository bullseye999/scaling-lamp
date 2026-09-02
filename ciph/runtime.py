import time
import uuid
import hashlib
from typing import Dict, Any, Optional, List
from ciph.capabilities.registry import CapabilityRegistry
from ciph.kernel.policy_engine import (
    ExecutionLane,
    CapabilityManifest,
    NetworkPolicy,
    AuthorizationTier,
    AuthorizationGrant,
    ScopeGrant,
)
from ciph.kernel.adversarial_gate import AdversarialRedTeamGate
from ciph.workers.receipts import (
    JobState,
    ExecutionReceipt,
    OutcomeCategory,
    compute_idempotency_key,
    generate_environment_fingerprint,
)
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.memory.event_store import EventStore
from ciph.memory.materialized_views import MaterializedWorldview
from ciph.memory.claim_leases import ClaimLeaseManager
from ciph.memory.active_forgetting import ActiveForgettingEngine
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.perception.observation import ReliabilityClass
from ciph.perception.bus import SensoryBus
from ciph.planner.skill_registry import SkillRegistry
from ciph.planner.schemas import (
    PlanStep,
    ExecutionDAG,
    IntentProposal,
    PlanValidationResult,
)
from ciph.planner.dag_planner import DAGExecutor
from ciph.operator.cadence_engine import CadenceManager
from ciph.operator.dialogue_formatter import DialogueFormatter
from ciph.perception.curiosity_daemon import CuriosityDaemon
from ciph.perception.curiosity_question import CuriosityQuestionDAG
from ciph.capabilities.commands import CommandRegistry
from ciph.capabilities.evolution import HotReloadEngine
from ciph.capabilities.capability_ledger import CapabilityLedger, MaintenanceLeaseManager
from ciph.capabilities.registry import (
    CapabilityRegistry,
    MemoryRetrieveCapability,
    MemoryStoreCapability,
    CvssCalculatorCapability,
    SportsPredictCapability,
    BountyScanCapability,
    OsintMonetizeCapability,
    CodeAuditCapability,
    TorStatusCapability,
)


class CiphRuntime:
    """
    Lightweight, decoupled Cognitive Runtime.
    Wires all core subsystems, enforces network & authorization policies,
    and runs Red Team falsification checks on high-consequence operations.
    """

    def __init__(
        self,
        vault=None,
        db_path: str = "ciph_vault.db",
        auth_secret_key: Optional[bytes] = None,
        worker_secret_key: Optional[bytes] = None
    ):
        import secrets
        self.vault = vault
        self.db_path = db_path
        self.auth_secret_key = auth_secret_key or secrets.token_bytes(32)
        self.worker_secret_key = worker_secret_key or secrets.token_bytes(32)
        
        # Subsystems
        self.registry = CapabilityRegistry()
        self.command_registry = CommandRegistry()
        self.queue = IPCJobQueue(db_path)
        self.event_store = EventStore(db_path)
        self.worldview = MaterializedWorldview(db_path)
        self.leases = ClaimLeaseManager(db_path)
        self.active_forgetting = ActiveForgettingEngine(
            worldview=self.worldview,
            leases=self.leases,
            event_store=self.event_store,
            db_path=db_path
        )
        self.sensory_bus = SensoryBus()
        self.question_dag = CuriosityQuestionDAG()
        self.skill_registry = SkillRegistry()
        self.dag_executor = DAGExecutor(self.registry)
        self.cadence_manager = CadenceManager()
        self.formatter = DialogueFormatter()
        self.red_team_gate = AdversarialRedTeamGate()
        self.curiosity_daemon = CuriosityDaemon()
        self.evolution_engine = HotReloadEngine(self.red_team_gate)
        self.capability_ledger = CapabilityLedger(self.event_store, self.registry, self.worker_secret_key)
        self.maintenance_manager = MaintenanceLeaseManager(db_path)

        self._register_default_adapters()

        self.started_at = time.time()
        self._is_running = True

    def run_curiosity_cycle(self) -> List[Dict[str, Any]]:
        """Run an autonomous inquiry cycle to discover and refresh epistemic gaps."""
        return self.curiosity_daemon.run_inquiry_cycle(self)

    def hot_reload_evolved_capability(
        self,
        code_source: str,
        class_name: str,
        auth_grant: Optional[AuthorizationGrant] = None,
        test_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Dynamically stage, audit, and hot-reload a candidate capability into the running kernel."""
        return self.evolution_engine.hot_reload_capability(
            code_source=code_source,
            class_name=class_name,
            runtime=self,
            auth_grant=auth_grant,
            test_params=test_params
        )

    def promote_evolved_skill(
        self,
        signature: str,
        auth_grant: AuthorizationGrant
    ) -> Dict[str, Any]:
        """Promote a procedural skill to ACTIVE using cryptographic operator grant."""
        return self.evolution_engine.promote_skill_with_operator_grant(
            signature=signature,
            skill_registry=self.skill_registry,
            auth_grant=auth_grant,
            auth_secret_key=self.auth_secret_key
        )

    def _register_default_adapters(self):
        """Auto-register standard core capabilities."""
        self.registry.register(MemoryRetrieveCapability(self.vault))
        self.registry.register(MemoryStoreCapability(self.vault))
        self.registry.register(CvssCalculatorCapability())
        self.registry.register(CodeAuditCapability())
        self.registry.register(TorStatusCapability())

    def register_capability(self, capability) -> None:
        """Register a capability into the runtime registry."""
        self.registry.register(capability)

    def get_manifests(self) -> List[CapabilityManifest]:
        """List all registered capability manifests."""
        return self.registry.list_manifests()

    def route_and_execute(
        self,
        capability_name: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> ExecutionReceipt:
        """
        Deterministically inspects capability manifest, checks policy,
        routes execution through the appropriate Execution Lane, and evaluates Red Team gate.
        """
        cap = self.registry.get(capability_name)
        if not cap:
            raise KeyError(f"Capability '{capability_name}' is not registered in runtime.")

        manifest = cap.manifest
        lane = manifest.derive_execution_lane()
        context = context or {}
        context["execution_lane"] = lane.value
        context["requested_network_policy"] = manifest.network_policy.value

        # 1. Enforce Network Policy (Fail-Closed)
        if manifest.network_policy == NetworkPolicy.NETWORK_DENIED:
            job_id = context.get("job_id", f"JOB-{uuid.uuid4().hex[:8].upper()}")
            return ExecutionReceipt(
                receipt_id=f"rcpt_blocked_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                capability=capability_name,
                target=params.get("target"),
                started_at=time.time(),
                completed_at=time.time(),
                input_hash=ExecutionReceipt.hash_payload(params),
                output_hash=ExecutionReceipt.hash_payload({"error": "Policy Denied"}),
                exit_code=1,
                outcome=OutcomeCategory.POLICY_BLOCKED,
                results={"error": f"Execution of '{capability_name}' blocked by NETWORK_DENIED policy."},
                side_effects=[],
                idempotency_key=context.get("idempotency_key", ""),
                attempt_number=1,
                requested_network_policy=manifest.network_policy,
                actual_transport_used="NONE_BLOCKED",
                error_message="Blocked by security policy."
            )

        # 2. Enforce Authorization Tiers & Strict Cryptographic Grant Binding
        from ciph.kernel.policy_engine import AuthorizationTier, AuthorizationGrant, ScopeGrant
        if manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
            auth_grant = context.get("auth_grant")
            scope_grant = context.get("scope_grant")
            params_hash = ExecutionReceipt.hash_payload(params)
            step_id = context.get("step_id", "STEP_SINGLE")
            plan_hash = context.get("plan_hash") or hashlib.sha256(f"single:{capability_name}:{params_hash}".encode()).hexdigest()
            now = time.time()
            
            is_grant_valid = (
                auth_grant is not None and 
                isinstance(auth_grant, AuthorizationGrant) and 
                auth_grant.verify_signature(self.auth_secret_key) and 
                auth_grant.is_valid_for(
                    plan_hash=plan_hash,
                    step_id=step_id,
                    capability=capability_name,
                    params_hash=params_hash,
                    current_time=now
                )
            )

            # Scope binding validation
            if is_grant_valid and auth_grant.scope_grant_id:
                if not scope_grant or auth_grant.scope_grant_id != scope_grant.scope_id:
                    is_grant_valid = False

            if not is_grant_valid:
                job_id = context.get("job_id", f"JOB-{uuid.uuid4().hex[:8].upper()}")
                return ExecutionReceipt(
                    receipt_id=f"rcpt_auth_blocked_{uuid.uuid4().hex[:8]}",
                    job_id=job_id,
                    capability=capability_name,
                    target=params.get("target"),
                    started_at=now,
                    completed_at=now,
                    input_hash=params_hash,
                    output_hash=ExecutionReceipt.hash_payload({"error": "Authorization Required"}),
                    exit_code=1,
                    outcome=OutcomeCategory.AUTH_REQUIRED,
                    results={"error": f"Execution of '{capability_name}' requires valid cryptographic AuthorizationGrant strictly bound to plan, step, capability, parameters, and scope ({manifest.authorization.value})."},
                    side_effects=[],
                    idempotency_key=context.get("idempotency_key", ""),
                    attempt_number=1,
                    requested_network_policy=manifest.network_policy,
                    actual_transport_used="NONE_UNAUTHORIZED",
                    error_message=f"Cryptographic AuthorizationGrant binding failed for ({manifest.authorization.value})."
                )

        # 3. Execute through capability wrapper
        receipt = cap.execute(params, context)

        # 3. Adversarial Red Team Gate for high-impact operations
        passed_gate, gate_reason = self.red_team_gate.evaluate_receipt(manifest, receipt, context)
        if not passed_gate:
            # Wrap receipt with gate failure
            receipt = ExecutionReceipt(
                receipt_id=receipt.receipt_id,
                job_id=receipt.job_id,
                capability=receipt.capability,
                target=receipt.target,
                started_at=receipt.started_at,
                completed_at=receipt.completed_at,
                input_hash=receipt.input_hash,
                output_hash=receipt.output_hash,
                exit_code=1,
                outcome=OutcomeCategory.EXECUTION_ERROR,
                results={"error": f"Adversarial Gate Veto: {gate_reason}", "raw_results": receipt.results},
                side_effects=receipt.side_effects,
                idempotency_key=receipt.idempotency_key,
                attempt_number=receipt.attempt_number,
                requested_network_policy=receipt.requested_network_policy,
                actual_transport_used=receipt.actual_transport_used,
                error_message=f"Adversarial Gate Veto: {gate_reason}",
                provenance=receipt.provenance
            )

        # 4. Record to Event Store & Vault
        self.event_store.append_event(
            event_type="ExecutionReceiptStoredEvent",
            aggregate_id=receipt.receipt_id,
            payload=receipt.to_dict()
        )

        if self.vault and hasattr(self.vault, 'store_completion_receipt'):
            try:
                self.vault.store_completion_receipt(
                    job_id=receipt.job_id,
                    tool_name=receipt.capability,
                    target=receipt.target or "system",
                    results=receipt.results,
                    exit_code=receipt.exit_code
                )
            except Exception:
                pass

        return receipt

    def execute_reference_loop(
        self,
        proposal: IntentProposal,
        scope_grant: Optional[ScopeGrant] = None,
        auth_grant: Optional[AuthorizationGrant] = None,
        worker_id: str = "worker_runtime_01"
    ) -> Dict[str, Any]:
        """
        Executes the Phase 2 Reference Loop:
        IntentProposal -> Validation -> PlanStep & DAG -> Scope/Auth Check ->
        IPCJobQueue -> Worker Execution -> HMAC Signed ExecutionReceipt ->
        EventStore -> MaterializedWorldview -> Grounded Response.
        """
        now = time.time()

        # Step 1: Validate Intent Proposal
        if not proposal.is_executable_proposal():
            return {
                "status": "INCOMPLETE_INTENT",
                "is_executable": False,
                "missing_parameters": proposal.missing_parameters,
                "receipt": None,
                "dialogue": f"Missing required parameters to execute {proposal.proposed_capability}: {', '.join(proposal.missing_parameters)}"
            }

        # Step 2: Capability Discovery & Verification
        cap = self.registry.get(proposal.proposed_capability)
        if not cap:
            return {
                "status": "UNKNOWN_CAPABILITY",
                "is_executable": False,
                "error": f"Capability '{proposal.proposed_capability}' not registered in runtime.",
                "receipt": None,
                "dialogue": f"Capability '{proposal.proposed_capability}' is unknown or unavailable."
            }

        manifest = cap.manifest
        target = proposal.provided_parameters.get("target")

        # Step 3: Scope Grant Verification
        if scope_grant:
            if scope_grant.is_expired(now):
                return {
                    "status": "SCOPE_EXPIRED",
                    "error": f"ScopeGrant '{scope_grant.scope_id}' has expired.",
                    "receipt": None,
                    "dialogue": "Operation aborted: Target scope authorization has expired."
                }
            if not scope_grant.is_target_permitted(target):
                receipt = ExecutionReceipt(
                    receipt_id=f"rcpt_scope_denied_{uuid.uuid4().hex[:8]}",
                    job_id=f"JOB-{uuid.uuid4().hex[:8].upper()}",
                    capability=proposal.proposed_capability,
                    target=target,
                    started_at=now,
                    completed_at=now,
                    input_hash=ExecutionReceipt.hash_payload(proposal.provided_parameters),
                    output_hash=ExecutionReceipt.hash_payload({"error": "Target outside ScopeGrant"}),
                    exit_code=1,
                    outcome=OutcomeCategory.POLICY_BLOCKED,
                    results={"error": f"Target '{target}' is not permitted by ScopeGrant '{scope_grant.scope_id}'."},
                    side_effects=[],
                    idempotency_key="",
                    attempt_number=1,
                    requested_network_policy=manifest.network_policy,
                    actual_transport_used="NONE_SCOPE_DENIED",
                    worker_id=worker_id,
                    error_message=f"Target outside permitted scope {scope_grant.allowed_targets}"
                )
                return {
                    "status": "POLICY_BLOCKED",
                    "receipt": receipt,
                    "dialogue": f"Policy blocked: Target '{target}' is outside permitted scope."
                }

        # Step 4: Compile PlanStep & ExecutionDAG
        deterministic_hash = hashlib.sha256(proposal.proposal_id.encode('utf-8')).hexdigest()[:8]
        step_id = f"step_{deterministic_hash}"
        plan_id = f"plan_{deterministic_hash}"
        plan_step = PlanStep(
            step_id=step_id,
            capability=proposal.proposed_capability,
            parameters=proposal.provided_parameters,
            reversibility=manifest.reversibility,
            timeout_seconds=manifest.timeout_seconds,
            authorization_tier=manifest.authorization,
            scope_grant_id=scope_grant.scope_id if scope_grant else None,
            authorization_grant_id=auth_grant.grant_id if auth_grant else None
        )
        dag = ExecutionDAG(
            plan_id=plan_id,
            objective=proposal.objective,
            steps=[plan_step]
        )
        plan_hash = dag.compute_plan_hash()
        params_hash = plan_step.compute_params_hash()
        idemp_key = compute_idempotency_key(dag.plan_id, step_id, params_hash)

        # Step 5: Check Operator Authorization Grant if required
        if manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
            if not auth_grant:
                return {
                    "status": "AUTHORIZATION_REQUIRED",
                    "plan_hash": plan_hash,
                    "params_hash": params_hash,
                    "step_id": step_id,
                    "capability": manifest.name,
                    "receipt": None,
                    "dialogue": f"Operator authorization required for high-risk action '{manifest.name}'. Plan Hash: {plan_hash[:12]}"
                }
            if not auth_grant.verify_signature(self.auth_secret_key):
                return {
                    "status": "INVALID_AUTHORIZATION_SIGNATURE",
                    "receipt": None,
                    "dialogue": "Security veto: AuthorizationGrant signature verification failed."
                }
            if scope_grant and auth_grant.scope_grant_id and auth_grant.scope_grant_id != scope_grant.scope_id:
                return {
                    "status": "AUTHORIZATION_MISMATCH",
                    "receipt": None,
                    "dialogue": f"Security veto: AuthorizationGrant requires scope '{auth_grant.scope_grant_id}', but active scope '{scope_grant.scope_id}' does not match."
                }
            if not auth_grant.is_valid_for(plan_hash, step_id, manifest.name, params_hash, now, scope_grant_id=scope_grant.scope_id if scope_grant else None):
                return {
                    "status": "AUTHORIZATION_MISMATCH",
                    "receipt": None,
                    "dialogue": "Security veto: AuthorizationGrant does not match the active plan, capability, parameters, or scope."
                }

        # Check idempotency replay before executing duplicate task
        existing_job = self.queue.get_job_by_idempotency_key(idemp_key)
        if existing_job and existing_job.get("status") == JobState.SUCCEEDED.value:
            events = self.event_store.get_events(aggregate_id=existing_job.get("receipt_id"))
            existing_receipt_dict = events[0]["payload"] if events else existing_job.get("result")
            if isinstance(existing_receipt_dict, str):
                existing_receipt_dict = json.loads(existing_receipt_dict)
            if isinstance(existing_receipt_dict, dict) and "receipt_id" in existing_receipt_dict:
                existing_receipt = ExecutionReceipt.from_dict(existing_receipt_dict)
            else:
                existing_receipt = ExecutionReceipt(
                    receipt_id=existing_job.get("receipt_id") or f"rcpt_idemp_{idemp_key[:8]}",
                    job_id=existing_job["job_id"],
                    capability=proposal.proposed_capability,
                    target=proposal.provided_parameters.get("target"),
                    started_at=existing_job.get("completed_at") or now,
                    completed_at=existing_job.get("completed_at") or now,
                    input_hash=params_hash,
                    output_hash=ExecutionReceipt.hash_payload(existing_job.get("result")),
                    exit_code=0,
                    outcome=OutcomeCategory.SUCCESS,
                    results=existing_job.get("result") or {},
                    side_effects=[],
                    idempotency_key=idemp_key,
                    attempt_number=1,
                    requested_network_policy=manifest.network_policy,
                    actual_transport_used="IDEMPOTENT_REPLAY"
                )
            dialogue = self.formatter.format_entry(
                register="FACT",
                content=f"Idempotent replay: '{manifest.name}' previously executed.",
                evidence_id=existing_receipt.receipt_id,
                assurance=0.99
            )
            return {
                "status": "SUCCESS",
                "receipt": existing_receipt,
                "event_id": events[0]["event_id"] if events else 0,
                "job_id": existing_job["job_id"],
                "dialogue": dialogue,
                "idempotent_replay": True
            }

        # Step 6: Persistent Queue Enqueue & Lease
        job_id = self.queue.enqueue_job(
            capability=proposal.proposed_capability,
            params=proposal.provided_parameters,
            plan_id=dag.plan_id,
            step_id=step_id,
            idempotency_key=idemp_key,
            max_retries=1
        )
        leased_job = self.queue.lease_next_job(worker_id=worker_id, lease_ttl_seconds=60)
        if leased_job is None or leased_job['job_id'] != job_id:
            # Another concurrent worker holds the execution lease for this idempotency key
            for _ in range(100):
                j = self.queue.get_job(job_id)
                if j and j['status'] == JobState.SUCCEEDED.value:
                    events = self.event_store.get_events(aggregate_id=j.get("receipt_id"))
                    existing_receipt_dict = events[0]["payload"] if events else j.get("result")
                    if isinstance(existing_receipt_dict, str):
                        existing_receipt_dict = json.loads(existing_receipt_dict)
                    existing_receipt = ExecutionReceipt.from_dict(existing_receipt_dict) if isinstance(existing_receipt_dict, dict) and "receipt_id" in existing_receipt_dict else ExecutionReceipt(
                        receipt_id=j.get("receipt_id") or f"rcpt_idemp_{idemp_key[:8]}",
                        job_id=job_id,
                        capability=proposal.proposed_capability,
                        target=proposal.provided_parameters.get("target"),
                        started_at=j.get("completed_at") or now,
                        completed_at=j.get("completed_at") or now,
                        input_hash=params_hash,
                        output_hash=ExecutionReceipt.hash_payload(j.get("result")),
                        exit_code=0,
                        outcome=OutcomeCategory.SUCCESS,
                        results=j.get("result") or {},
                        side_effects=[],
                        idempotency_key=idemp_key,
                        attempt_number=1,
                        requested_network_policy=manifest.network_policy,
                        actual_transport_used="IDEMPOTENT_REPLAY"
                    )
                    dialogue = self.formatter.format_entry(
                        register="FACT",
                        content=f"Idempotent replay: '{manifest.name}' previously executed.",
                        evidence_id=existing_receipt.receipt_id,
                        assurance=0.99
                    )
                    return {
                        "status": "SUCCESS",
                        "receipt": existing_receipt,
                        "event_id": events[0]["event_id"] if events else 0,
                        "job_id": job_id,
                        "dialogue": dialogue,
                        "idempotent_replay": True
                    }
                time.sleep(0.05)

            return {
                "status": "IN_PROGRESS_CONCURRENT",
                "job_id": job_id,
                "dialogue": "Concurrent execution in progress by another worker."
            }

        self.queue.mark_executing(job_id, worker_id)

        # Step 7: Execution & HMAC Signed Receipt
        start_t = time.time()
        raw_receipt = cap.execute(
            params=proposal.provided_parameters,
            context={
                "job_id": job_id,
                "plan_id": dag.plan_id,
                "step_id": step_id,
                "worker_id": worker_id,
                "idempotency_key": idemp_key
            }
        )
        end_t = time.time()

        # Build fully canonical signed ExecutionReceipt
        receipt = ExecutionReceipt(
            receipt_id=raw_receipt.receipt_id,
            job_id=job_id,
            capability=raw_receipt.capability,
            target=raw_receipt.target,
            started_at=start_t,
            completed_at=end_t,
            input_hash=params_hash,
            output_hash=raw_receipt.output_hash,
            exit_code=raw_receipt.exit_code,
            outcome=raw_receipt.outcome,
            results=raw_receipt.results,
            side_effects=raw_receipt.side_effects,
            idempotency_key=idemp_key,
            attempt_number=1,
            requested_network_policy=raw_receipt.requested_network_policy,
            actual_transport_used=raw_receipt.actual_transport_used,
            worker_id=worker_id,
            environment_fingerprint=generate_environment_fingerprint(),
            error_message=raw_receipt.error_message,
            provenance={
                "plan_id": dag.plan_id,
                "step_id": step_id,
                "plan_hash": plan_hash,
                "proposal_id": proposal.proposal_id
            }
        ).sign(self.worker_secret_key)

        # Steps 8 & 9: Atomic Cross-Store Commit (Queue + EventStore in single IMMEDIATE transaction)
        if receipt.exit_code == 0:
            event_id = self.queue.complete_job_and_append_receipt_event(job_id, worker_id, receipt.to_dict())
        else:
            event_id = self.queue.fail_job_and_append_receipt_event(
                job_id=job_id,
                worker_id=worker_id,
                error=receipt.error_message or "Non-zero exit code",
                receipt_dict=receipt.to_dict()
            )

        # Step 10: Materialized Worldview Projection
        if receipt.exit_code == 0:
            claim_id = f"CLM-{uuid.uuid4().hex[:8].upper()}"
            is_offline = manifest.network_policy in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.LOCAL_ONLY)
            rel = ReliabilityClass.AUTHORITATIVE_LOCAL if is_offline else ReliabilityClass.DIRECT_SENSOR
            
            node = TransmutationNode(
                claim_id=claim_id,
                subject=str(target or proposal.proposed_capability),
                predicate="execution_outcome",
                value=receipt.results,
                condition=f"proposal_id:{proposal.proposal_id}",
                state=EpistemicCategory.SUPPORTED,
                reliability=rel,
                assurance_score=0.90 if is_offline else 0.85,
                evidence_receipt_ids=[receipt.receipt_id],
                freshness_deadline=now + 86400  # 24 hour freshness default
            )
            self.worldview.upsert_claim(node)

        # Step 11: Grounded Dialogue Formatting
        dialogue = self.formatter.format_receipt_card(receipt)

        return {
            "status": "SUCCESS" if receipt.exit_code == 0 else "EXECUTION_ERROR",
            "receipt": receipt,
            "event_id": event_id,
            "job_id": job_id,
            "dialogue": dialogue
        }

    def execute_dag_plan(
        self,
        dag: ExecutionDAG,
        scope_grant: Optional[ScopeGrant] = None,
        auth_grants: Optional[Dict[str, AuthorizationGrant]] = None,
        target_backup_paths: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute a multi-step ExecutionDAG through the governed runtime.
        Validates topology, checks mandatory interrupt authorizations, commits events,
        and manages compensations / T0 rollbacks on failure.
        """
        auth_grants = auth_grants or {}

        # 1. Statically validate DAG
        val_res = self.dag_executor.validate_plan(dag)
        if not val_res.is_valid:
            return {
                "status": "VALIDATION_FAILED",
                "plan_id": dag.plan_id,
                "errors": val_res.errors,
                "success": False
            }

        # 2. Check authorization grants for high-consequence steps
        plan_hash = dag.compute_plan_hash()
        step_map = {s.step_id: s for s in dag.steps}
        now = time.time()
        for step_id in val_res.required_grants:
            grant = auth_grants.get(step_id)
            step_obj = step_map.get(step_id)
            params_hash = step_obj.compute_params_hash() if step_obj else ""
            if not grant or not isinstance(grant, AuthorizationGrant) or not grant.verify_signature(self.auth_secret_key):
                return {
                    "status": "AUTHORIZATION_REQUIRED",
                    "plan_id": dag.plan_id,
                    "step_id": step_id,
                    "errors": [f"Step '{step_id}' requires valid cryptographic AuthorizationGrant."],
                    "success": False
                }
            if step_obj and step_obj.scope_grant_id and grant.scope_grant_id:
                if grant.scope_grant_id != step_obj.scope_grant_id:
                    return {
                        "status": "AUTHORIZATION_MISMATCH",
                        "plan_id": dag.plan_id,
                        "step_id": step_id,
                        "errors": [f"AuthorizationGrant for step '{step_id}' requires scope '{grant.scope_grant_id}', but step scope does not match."],
                        "success": False
                    }
            if not grant.is_valid_for(
                plan_hash=plan_hash,
                step_id=step_id,
                capability=step_obj.capability,
                params_hash=params_hash,
                current_time=now,
                scope_grant_id=step_obj.scope_grant_id if (step_obj and step_obj.scope_grant_id) else None
            ):
                return {
                    "status": "AUTHORIZATION_MISMATCH",
                    "plan_id": dag.plan_id,
                    "step_id": step_id,
                    "errors": [f"AuthorizationGrant for step '{step_id}' does not match plan hash, capability, parameters, or scope."],
                    "success": False
                }

        # 3. Execute DAG with compensation handling
        dag_result = self.dag_executor.execute_dag(dag, target_backup_paths=target_backup_paths)

        # 4. Commit step receipts to EventStore and MaterializedWorldview
        for step_id, r_dict in dag_result.get("step_receipts", {}).items():
            ev_id = self.event_store.append_event(
                event_type="ExecutionReceiptStoredEvent",
                aggregate_id=r_dict["receipt_id"],
                payload=r_dict
            )
            if r_dict.get("exit_code") == 0:
                claim_node = TransmutationNode(
                    claim_id=f"CLM-{uuid.uuid4().hex[:8].upper()}",
                    subject=str(r_dict.get("target") or r_dict["capability"]),
                    predicate=f"step_{step_id}_outcome",
                    value=r_dict.get("results"),
                    state=EpistemicCategory.SUPPORTED,
                    reliability=ReliabilityClass.AUTHORITATIVE_LOCAL,
                    assurance_score=0.90,
                    evidence_receipt_ids=[r_dict["receipt_id"]]
                )
                self.worldview.upsert_claim(claim_node)

        return {
            "status": "SUCCESS" if dag_result["success"] else "EXECUTION_ERROR",
            "plan_id": dag.plan_id,
            "success": dag_result["success"],
            "executed_steps_count": dag_result["executed_steps_count"],
            "total_steps_count": dag_result["total_steps_count"],
            "error": dag_result.get("error"),
            "step_receipts": dag_result.get("step_receipts"),
            "rollback_snapshot_id": dag_result.get("rollback_snapshot_id")
        }

    def dispatch_slash_command(
        self,
        user_input: str,
        scope_grant: Optional[ScopeGrant] = None,
        auth_grant: Optional[AuthorizationGrant] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Declaratively parse and execute a slash command through the governed reference loop.
        Returns execution result or None if input does not match any registered command.
        """
        return self.command_registry.dispatch(
            user_input=user_input,
            runtime=self,
            scope_grant=scope_grant,
            auth_grant=auth_grant
        )

    def shutdown(self) -> None:
        """Graceful runtime shutdown."""
        self._is_running = False
