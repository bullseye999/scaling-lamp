from ciph.contracts.base import ContractValidationError
import time
import json
import uuid
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from ciph.capabilities.registry import CapabilityRegistry
from ciph.kernel.policy_engine import (
    ExecutionLane,
    CapabilityManifest,
    NetworkPolicy,
    AuthorizationTier,
    AuthorizationGrant,
    ScopeGrant,
)
from ciph.kernel.crypto_identity import (
    TrustRegistry,
    KeyRole,
    KeyStatus,
    Ed25519KeyManager,
    ExecutionToken,
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
from ciph.maintenance.exclusion import SharedExclusionCoordinator
from ciph.epistemic.closed_loop import EpistemicClosedLoopDaemon
from ciph.kernel.epistemic_projector import EpistemicProjector
from ciph.workers.receipts import EpistemicDecision
from ciph.workers.daemon import DurableWorkerDaemon
from ciph.capabilities.registry import (
    CapabilityRegistry,
    MemoryRetrieveCapability,
    MemoryStoreCapability,
    CvssCalculatorCapability,
    SportsPredictCapability,
    BountyScanCapability,
    BountySummaryCapability,
    OsintMonetizeCapability,
    DarknetStatusCapability,
    DarknetReportCapability,
    CodeAuditCapability,
    CodeListStagedCapability,
    CodePromoteUpgradeCapability,
    TorStatusCapability,
    WisdomConsultCapability,
    TradingPortfolioCapability,
    DeadmanStatusCapability,
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
        worker_secret_key: Optional[bytes] = None,
        trust_registry: Optional[TrustRegistry] = None,
        pinned_operator_pub_hex: Optional[str] = None
    ):
        if trust_registry is not None:
            from ciph.contracts.base import ContractValidationError
            raise ContractValidationError(
                "CALLER_CONTROLLED_AUTHORITY_REJECTED: Verification authority cannot be supplied or replaced by callers."
            )
        self.db_path = db_path
        if vault is not None:
            self.vault = vault
        else:
            try:
                from cipher_vault import CipherVault
                self.vault = CipherVault(self.db_path)
            except Exception:
                self.vault = None

        # Connect TrustRegistry
        self.trust_registry = TrustRegistry(
            db_path=self.db_path,
            pinned_operator_pub_hex=pinned_operator_pub_hex
        )

        # Persistent Ed25519 Identities
        self.operator_key_id = "operator_root"
        self.operator_priv_bytes, self.operator_pub_bytes = self.trust_registry.get_or_create_keypair(
            self.operator_key_id, KeyRole.OPERATOR
        )

        # Root every runtime registry before subordinate identities are admitted.
        # Legacy databases are pinned on first trusted startup.
        self.trust_registry.pin_operator_root(self.operator_pub_bytes.hex())

        if self.trust_registry.pinned_operator_pub_hex:
            if self.operator_pub_bytes.hex().lower() != self.trust_registry.pinned_operator_pub_hex.lower():
                raise PermissionError(
                    f"CRITICAL: Runtime operator public key '{self.operator_pub_bytes.hex()}' "
                    f"does not match pinned root operator key '{self.trust_registry.pinned_operator_pub_hex}'."
                )

        kernel_op_sig = None
        if self.trust_registry.pinned_operator_pub_hex:
            k_pair = self.trust_registry.get_keypair("kernel_primary")
            if not k_pair:
                k_priv, k_pub = Ed25519KeyManager.generate_keypair()
                payload = f"REGISTER_KEY:kernel_primary:KERNEL:{k_pub.hex()}:None".encode("utf-8")
                kernel_op_sig = Ed25519KeyManager.sign(self.operator_priv_bytes, payload)
                self.trust_registry.store_keypair(
                    "kernel_primary", KeyRole.KERNEL, k_priv, k_pub, operator_signature=kernel_op_sig
                )
        self.kernel_key_id = "kernel_primary"
        self.kernel_priv_bytes, self.kernel_pub_bytes = self.trust_registry.get_or_create_keypair(
            self.kernel_key_id, KeyRole.KERNEL, operator_signature=kernel_op_sig
        )

        worker_op_sig = None
        if self.trust_registry.pinned_operator_pub_hex:
            w_pair = self.trust_registry.get_keypair("worker_primary")
            if not w_pair:
                w_priv, w_pub = Ed25519KeyManager.generate_keypair()
                payload = f"REGISTER_KEY:worker_primary:WORKER:{w_pub.hex()}:None".encode("utf-8")
                worker_op_sig = Ed25519KeyManager.sign(self.operator_priv_bytes, payload)
                self.trust_registry.store_keypair(
                    "worker_primary", KeyRole.WORKER, w_priv, w_pub, operator_signature=worker_op_sig
                )
        self.worker_key_id = "worker_primary"
        self.worker_priv_bytes, self.worker_pub_bytes = self.trust_registry.get_or_create_keypair(
            self.worker_key_id, KeyRole.WORKER, operator_signature=worker_op_sig
        )
        if not self.trust_registry.get_key("worker_local"):
            wl_op_sig = None
            if self.trust_registry.pinned_operator_pub_hex:
                payload = f"REGISTER_KEY:worker_local:WORKER:{self.worker_pub_bytes.hex()}:None".encode("utf-8")
                wl_op_sig = Ed25519KeyManager.sign(self.operator_priv_bytes, payload)
            self.trust_registry.register_key("worker_local", KeyRole.WORKER, self.worker_pub_bytes.hex(), operator_signature=wl_op_sig)

        # Fatal check: verify all mandatory identities are registered in TrustRegistry
        for req_id in ["operator_root", "kernel_primary", "worker_primary"]:
            if not self.trust_registry.get_key(req_id):
                raise PermissionError(f"CRITICAL: Identity '{req_id}' is not registered in TrustRegistry. Cannot proceed.")

        # Persistent keys take precedence if not explicitly overridden
        self.auth_secret_key = auth_secret_key or self.kernel_priv_bytes
        self.worker_secret_key = worker_secret_key or self.worker_priv_bytes

        # Mirror persistent identities to vault if attached
        if self.vault and hasattr(self.vault, 'set_config'):
            try:
                self.vault.set_config('operator_key_id', self.operator_key_id)
                self.vault.set_config('kernel_key_id', self.kernel_key_id)
                self.vault.set_config('worker_key_id', self.worker_key_id)
                self.vault.set_config('worker_pub_hex', self.worker_pub_bytes.hex())
                self.vault.set_config('kernel_pub_hex', self.kernel_pub_bytes.hex())
            except Exception:
                pass

        # Subsystems
        self.registry = CapabilityRegistry()
        self.command_registry = CommandRegistry()
        self.queue = IPCJobQueue(
            db_path,
            trust_registry=self.trust_registry,
            worker_secret_key=self.worker_secret_key
        )
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
        self.worker_daemon = DurableWorkerDaemon(
            queue=self.queue,
            registry=self.registry,
            event_store=self.event_store,
            vault=self.vault,
            worker_secret_key=self.worker_secret_key,
            trust_registry=self.trust_registry,
            worker_key_id=self.worker_key_id,
            db_path=db_path,
            strict_tokens=True
        )
        self.dag_executor = DAGExecutor(
            self.registry,
            worker_secret_key=self.worker_secret_key,
            event_store=self.event_store,
            queue=self.queue,
            worker_daemon=self.worker_daemon,
            trust_registry=self.trust_registry
        )
        self.cadence_manager = CadenceManager()
        self.formatter = DialogueFormatter()
        self.red_team_gate = AdversarialRedTeamGate()
        self.curiosity_daemon = CuriosityDaemon()
        self.epistemic_daemon = EpistemicClosedLoopDaemon()
        self.evolution_engine = HotReloadEngine(self.red_team_gate)
        self.capability_ledger = CapabilityLedger(
            self.event_store,
            self.registry,
            self.worker_secret_key,
            trust_registry=self.trust_registry
        )
        self.maintenance_manager = SharedExclusionCoordinator(db_path, trust_registry=self.trust_registry)
        from ciph.maintenance.engine import IdleMaintenanceEngine
        self.idle_maintenance_engine = IdleMaintenanceEngine(
            db_path=db_path,
            trust_registry=self.trust_registry,
            registry=self.registry,
            operator_key_id=self.operator_key_id,
            operator_secret_key=self.operator_priv_bytes,
        )

        self._register_default_adapters()
        from ciph.capabilities.local_commands import register_local_capabilities
        register_local_capabilities(self)

        from ciph.contracts.epistemic import ClaimProjector
        self.claim_projector = ClaimProjector._for_runtime(
            self.trust_registry,
            self.operator_pub_bytes,
        )

        self.worldview._bind_runtime(self)
        self.question_dag = CuriosityQuestionDAG(self)

        self.started_at = time.time()
        self._is_running = True
        # Recover only already-authorized evolution sessions; startup never invents
        # a grant or begins a new investigation.
        with self.event_store._get_connection() as conn:
            has_evolution=conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ciph_phase8_canary_state'").fetchone()
        if has_evolution:
            self.evolution.recover()

    def close(self):
        """Shutdown this runtime instance."""
        self._is_running = False

    def mint_execution_token(
        self,
        capability: str,
        params: Dict[str, Any],
        plan_id: str = "PLAN_STANDALONE",
        step_id: str = "STEP_STANDALONE",
        scope_grant: Optional[ScopeGrant] = None,
        auth_grant: Optional[AuthorizationGrant] = None,
        timeout_seconds: Optional[float] = None,
        issued_at: Optional[float] = None,
        plan_hash: Optional[str] = None,
        max_attempts: int = 3,
        expires_at: Optional[float] = None
    ) -> ExecutionToken:
        """Mint and sign a 14-field ExecutionToken with the kernel's persistent Ed25519 private key."""
        now = issued_at if issued_at is not None else time.time()
        cap = self.registry.get(capability)
        manifest = cap.manifest if cap else None
        m_hash = manifest.compute_manifest_hash() if manifest else ""
        m_ver = manifest.version if manifest else "1.0.0"
        lane = manifest.derive_execution_lane().value if manifest else "LANE_1_READ_ONLY"
        t_sec = timeout_seconds if timeout_seconds is not None else (manifest.timeout_seconds if manifest else 30.0)

        resolved_plan_hash = plan_hash or (auth_grant.plan_hash if auth_grant and hasattr(auth_grant, 'plan_hash') else None) or hashlib.sha256(f"{plan_id}:{step_id}".encode('utf-8')).hexdigest()[:16]
        plan_hash = resolved_plan_hash
        params_hash = ExecutionReceipt.hash_payload(params)

        # 1. Mandatory Interrupt Check: Must have a genuine verified AuthorizationGrant
        if manifest and manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
            if not auth_grant:
                raise PermissionError(f"MANDATORY_INTERRUPT: Capability '{capability}' requires a valid AuthorizationGrant to mint an ExecutionToken.")

        # 2. If auth_grant is provided, strictly verify its type, signature, and bindings
        if auth_grant is not None:
            from ciph.kernel.policy_engine import AuthorizationGrant
            if not isinstance(auth_grant, AuthorizationGrant):
                raise PermissionError("INVALID_AUTHORIZATION_GRANT: auth_grant must be an instance of AuthorizationGrant.")
            if not auth_grant.verify_signature(self.auth_secret_key):
                raise PermissionError(f"INVALID_AUTHORIZATION_SIGNATURE: Signature verification failed for grant '{auth_grant.grant_id}'.")
            if not auth_grant.is_valid_for(
                plan_hash=plan_hash,
                step_id=step_id,
                capability=capability,
                params_hash=params_hash,
                current_time=now,
                scope_grant_id=scope_grant.scope_id if scope_grant else None
            ):
                raise PermissionError(f"AUTHORIZATION_GRANT_MISMATCH: Grant '{auth_grant.grant_id}' does not match plan/step/capability/params/scope bindings.")

            # Record verified grant in SQLite for durable worker verification
            try:
                with self.queue._get_connection() as conn:
                    conn.execute("""
                        INSERT INTO ciph_authorization_grants (
                            grant_id, plan_hash, step_id, capability, params_hash, scope_grant_id, signature, expires_at, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(grant_id) DO UPDATE SET
                            plan_hash=excluded.plan_hash,
                            step_id=excluded.step_id,
                            capability=excluded.capability,
                            params_hash=excluded.params_hash,
                            signature=excluded.signature;
                    """, (
                        auth_grant.grant_id, plan_hash, step_id, capability, params_hash,
                        scope_grant.scope_id if scope_grant else "NONE",
                        auth_grant.signature, auth_grant.expires_at, auth_grant.created_at
                    ))
                    conn.commit()
            except Exception:
                pass

        token_expiry = expires_at if expires_at is not None else now + t_sec + 300.0
        if scope_grant is not None and scope_grant.valid_until is not None:
            token_expiry = min(token_expiry, scope_grant.valid_until)
        if auth_grant is not None:
            token_expiry = min(token_expiry, auth_grant.expires_at)
        token = ExecutionToken(
            token_id=f"tok_{uuid.uuid4().hex[:12]}",
            nonce=uuid.uuid4().hex,
            plan_hash=plan_hash,
            step_id=step_id,
            capability=capability,
            manifest_hash=m_hash,
            manifest_version=m_ver,
            parameters_hash=params_hash,
            scope_grant_id=scope_grant.scope_id if scope_grant else "NONE",
            authorization_grant_id=auth_grant.grant_id if auth_grant else "NONE",
            execution_lane=lane,
            authorized_worker_class="ALL",
            issued_at=now,
            expires_at=token_expiry,
            max_attempts=max_attempts,
            kernel_key_id=self.kernel_key_id,
            scope_payload_json=json.dumps(scope_grant.to_dict(), sort_keys=True) if scope_grant else "",
            source_policy_hash=hashlib.sha256(json.dumps(cap.source.provenance(), sort_keys=True).encode()).hexdigest() if hasattr(cap, "source") and capability.startswith("external.observe.") else ""
        )
        return token.sign(self.kernel_priv_bytes)

    @property
    def evolution(self):
        """Lazy, governed Phase 8 workflow sharing this runtime's trust authority."""
        if not hasattr(self, '_evolution_coordinator'):
            from ciph.evolution.workflow import EvolutionCoordinator
            self._evolution_coordinator = EvolutionCoordinator(self)
        return self._evolution_coordinator

    def run_curiosity_cycle(self) -> List[Dict[str, Any]]:
        """Run an autonomous inquiry cycle to discover and refresh epistemic gaps."""
        return self.curiosity_daemon.run_inquiry_cycle(self)

    def resume_curiosity(self, reason: str):
        """Explicit trusted runtime/operator resume, retaining all spent quota."""
        self.question_dag.store.resume(reason)

    def run_epistemic_cycle(self, force_refresh_all: bool = False):
        """Run an autonomous closed-loop epistemic refresh cycle (Stage 4)."""
        return self.epistemic_daemon.run_closed_loop_cycle(self, force_refresh_all=force_refresh_all)

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
        memory_backend = self.vault if self.vault is not None else object()
        self.registry.register(MemoryRetrieveCapability(memory_backend), code_origin="internal")
        self.registry.register(MemoryStoreCapability(memory_backend), code_origin="internal")
        self.registry.register(CvssCalculatorCapability(), code_origin="internal")
        self.registry.register(CodeAuditCapability(), code_origin="internal")
        self.registry.register(TorStatusCapability(), code_origin="internal")

        # Domain 1: OSINT & Threat Intelligence
        try:
            from osint_miner import OSINTMiner
            self.registry.register(OsintMonetizeCapability(OSINTMiner(self.vault)), code_origin="internal")
        except Exception:
            self.registry.register(OsintMonetizeCapability(None), code_origin="internal")

        try:
            from darknet_monitor import DarknetMonitor
            dm = DarknetMonitor(self.vault)
            self.registry.register(DarknetStatusCapability(dm), code_origin="internal")
            self.registry.register(DarknetReportCapability(dm), code_origin="internal")
        except Exception:
            self.registry.register(DarknetStatusCapability(None), code_origin="internal")
            self.registry.register(DarknetReportCapability(None), code_origin="internal")

        # Domain 2: Scoped Bounty & Recon
        try:
            from bounty_hunter import BountyHunter
            bh = BountyHunter(vault=self.vault)
            self.registry.register(BountyScanCapability(bh), code_origin="internal")
            self.registry.register(BountySummaryCapability(bh), code_origin="internal")
        except Exception:
            self.registry.register(BountyScanCapability(None), code_origin="internal")
            self.registry.register(BountySummaryCapability(None), code_origin="internal")

        # Domain 3: Sports & Telemetry
        try:
            from sports_predictor import SportsPredictor
            sp = SportsPredictor(self.vault)
            self.registry.register(SportsPredictCapability(sp), code_origin="internal")
        except Exception:
            self.registry.register(SportsPredictCapability(None), code_origin="internal")

        # Domain 4: Code Evolution & Self-Modification (Strictly Last)
        try:
            from code_staging import CodeStagingManager
            csm = CodeStagingManager(self.vault)
            self.registry.register(CodeListStagedCapability(csm), code_origin="internal")
            self.registry.register(CodePromoteUpgradeCapability(csm), code_origin="internal")
        except Exception:
            self.registry.register(CodeListStagedCapability(None), code_origin="internal")
            self.registry.register(CodePromoteUpgradeCapability(None), code_origin="internal")

        # Stage 3: Auxiliary Domains (Wisdom, Trading, Resilience)
        try:
            from book_engine import BookEngine
            be = BookEngine(self.vault)
            self.registry.register(WisdomConsultCapability(be), code_origin="internal")
        except Exception:
            self.registry.register(WisdomConsultCapability(None), code_origin="internal")

        try:
            from trading_engine import TradingEngine
            te = TradingEngine(self.vault)
            self.registry.register(TradingPortfolioCapability(te), code_origin="internal")
        except Exception:
            self.registry.register(TradingPortfolioCapability(None), code_origin="internal")

        try:
            from dead_mans_switch import DeadMansSwitch
            dms = DeadMansSwitch(self.vault)
            self.registry.register(DeadmanStatusCapability(dms), code_origin="internal")
        except Exception:
            self.registry.register(DeadmanStatusCapability(None), code_origin="internal")

    def register_external_source(self, source):
        """Trusted operator configuration; untrusted observations cannot call this API."""
        from ciph.capabilities.external_evidence import ExternalEvidenceCapability
        capability = ExternalEvidenceCapability(source)
        self.register_capability(capability, code_origin="internal")
        return capability.manifest.name

    def _project_execution_evidence(self, receipt, manifest=None, predicate=None):
        if receipt.provenance.get("external_source_policy"):
            observation = self.worldview.ingest_observation(receipt.receipt_id)
            from ciph.contracts.enums import DecayProfile
            return self.claim_projector.project_from_observation(observation, decay_profile=DecayProfile(receipt.provenance["external_source_policy"]["decay_profile"]))
        if receipt.capability.startswith("operator."):
            from ciph.contracts.enums import DecayProfile
            return self.claim_projector.project_claim(receipt, manifest=manifest, predicate=predicate,
                decay_profile=DecayProfile.LIVE_NETWORK_STATE)
        return self.claim_projector.project_claim(receipt, manifest=manifest, predicate=predicate)

    def register_capability(self, capability, *, code_origin="internal") -> None:
        """Register a capability into the runtime registry."""
        self.registry.register(capability, code_origin=code_origin)

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
        scope_grant = context.get("scope_grant")
        auth_grant = context.get("auth_grant")
        if manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
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

        # 3. Worker-Only Execution via Durable IPC Queue (Gate Zero Invariant)
        job_id = context.get("job_id")
        idemp = context.get("idempotency_key") or f"idemp_{uuid.uuid4().hex}"
        plan_id = context.get("plan_id", "PLAN_STANDALONE")
        step_id = context.get("step_id", "STEP_STANDALONE")
        if not job_id:
            existing_job = self.queue.get_job_by_idempotency_key(idemp)
            if existing_job:
                job_id = existing_job["job_id"]
            else:
                token = self.mint_execution_token(
                    capability=capability_name,
                    params=params,
                    plan_id=plan_id,
                    step_id=step_id,
                    scope_grant=scope_grant,
                    auth_grant=auth_grant
                )
                job_id = self.queue.enqueue_job(
                    capability=capability_name,
                    params=params,
                    plan_id=plan_id,
                    step_id=step_id,
                    idempotency_key=idemp,
                    execution_token=token
                )
        known_job = self.queue.get_job(job_id)
        job_matches = (known_job and known_job["capability"] == capability_name
                       and ExecutionReceipt.hash_payload(known_job["params"]) == ExecutionReceipt.hash_payload(params))
        receipt = None
        if job_matches:
            if known_job["status"] in (JobState.SUCCEEDED.value, JobState.COMPLETED.value):
                proof = self._authenticated_terminal_replay(known_job, manifest, ExecutionReceipt.hash_payload(params), known_job["idempotency_key"])
                receipt = proof.get("receipt") if proof.get("status") == "SUCCESS" else None
            else:
                receipt = self.worker_daemon.drain_once(worker_id="worker_coordinator", target_job_id=job_id)
        if isinstance(receipt, dict):
            return receipt
        if not receipt:
            now_t = time.time()
            err_msg = f"NON_WORKER_EXECUTION_BLOCKED: Capability '{capability_name}' cannot be executed directly outside verified worker daemon."
            receipt = ExecutionReceipt(
                receipt_id=f"rcpt_noworker_{uuid.uuid4().hex[:8]}",
                job_id=job_id,
                capability=capability_name,
                target=params.get("target"),
                started_at=now_t,
                completed_at=now_t,
                input_hash=ExecutionReceipt.hash_payload(params),
                output_hash=ExecutionReceipt.hash_payload({"error": err_msg}),
                exit_code=1,
                outcome=OutcomeCategory.POLICY_BLOCKED,
                results={"error": err_msg},
                side_effects=[],
                idempotency_key=idemp,
                attempt_number=1,
                requested_network_policy=manifest.network_policy,
                actual_transport_used="NONE_NON_WORKER_BLOCKED",
                worker_id="worker_coordinator",
                error_message=err_msg
            ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)


        if receipt.exit_code == 0:
            try:
                job = self.queue.get_job(job_id)
                proof = self._authenticated_terminal_replay(job, manifest, ExecutionReceipt.hash_payload(params), job["idempotency_key"])
                if proof.get("status") != "SUCCESS" or proof.get("receipt") != receipt:
                    return self.worker_daemon._uncommitted_receipt(receipt, "EVIDENCE_MISSING")
            except Exception as ex:
                return self.worker_daemon._uncommitted_receipt(receipt, f"EVIDENCE_MISSING: {ex}")

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
            ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)

        # Preserve the unique queue-committed receipt; log a policy verdict separately.
        if not passed_gate:
            self.event_store.append_event("ExecutionPolicyEvaluatedEvent", receipt.receipt_id, receipt.to_dict())

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

    def _evidence_missing_replay(self, job_id: str, reason: str) -> Dict[str, Any]:
        """Return the single fail-closed contract for unauthenticated terminal state."""
        error = f"EVIDENCE_MISSING: Job '{job_id}' terminal evidence rejected: {reason}."
        return {
            "status": "EVIDENCE_MISSING",
            "reconciled": False,
            "receipt": None,
            "reconciliation_event": None,
            "claim": None,
            "event_id": None,
            "job_id": job_id,
            "error": error,
            "dialogue": f"Integrity error: {error}",
            "idempotent_replay": True,
        }

    def _authenticated_terminal_replay(
        self,
        job: Dict[str, Any],
        manifest: CapabilityManifest,
        params_hash: str,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        """Authenticate terminal evidence and bind it to the requested job context."""
        job_id = job.get("job_id")
        if job.get("status") not in (JobState.SUCCEEDED.value, JobState.COMPLETED.value):
            return self._evidence_missing_replay(job_id, "job is not successfully committed")
        chain_valid, corrupted_event_id = self.event_store.verify_integrity()
        if not chain_valid:
            return self._evidence_missing_replay(
                job_id, f"event chain integrity failed at event {corrupted_event_id}"
            )

        if job.get("receipt_id"):
            receipt_id = job.get("receipt_id")
            events = self.event_store.get_events(
                aggregate_id=receipt_id,
                event_type="ExecutionReceiptStoredEvent",
            )
            if len(events) != 1:
                return self._evidence_missing_replay(
                    job_id, f"expected one execution receipt event, found {len(events)}"
                )
            event = events[0]
            payload = event.get("payload")
            try:
                if isinstance(payload, str):
                    payload = json.loads(payload)
                receipt = ExecutionReceipt.from_dict(payload) if isinstance(payload, dict) else None
            except Exception as exc:
                return self._evidence_missing_replay(job_id, f"malformed execution receipt: {exc}")
            if receipt is None:
                return self._evidence_missing_replay(job_id, "malformed execution receipt")

            try:
                receipt_valid = receipt.verify_signature(
                    secret_key=self.worker_secret_key,
                    trust_registry=self.trust_registry,
                )
                receipt_reason = "INVALID_WORKER_RECEIPT_SIGNATURE"
            except Exception as exc:
                receipt_valid, receipt_reason = False, f"receipt verification error: {exc}"
            if not receipt_valid:
                return self._evidence_missing_replay(job_id, receipt_reason)

            params = job.get("params") or {}
            target_value = params.get("target") or params.get("domain") or params.get("symbol")
            expected_target = str(target_value) if target_value else None
            bindings_valid = all((
                event.get("aggregate_id") == receipt.receipt_id == receipt_id,
                receipt.job_id == job_id,
                receipt.capability == job.get("capability") == manifest.name,
                receipt.input_hash == params_hash,
                receipt.idempotency_key == idempotency_key == job.get("idempotency_key"),
                receipt.target == expected_target,
                receipt.requested_network_policy == manifest.network_policy,
                receipt.exit_code == 0,
                receipt.outcome == OutcomeCategory.SUCCESS,
                receipt.results == job.get("result"),
                receipt.worker_signature == job.get("worker_signature"),
                receipt.attempt_number == job.get("attempt_number"),
            ))
            if not bindings_valid:
                return self._evidence_missing_replay(job_id, "execution receipt context mismatch")

            try:
                created_at = float(job.get("created_at"))
                completed_at = float(job.get("completed_at"))
                event_time = float(event.get("timestamp"))
                if not (
                    created_at <= receipt.started_at <= receipt.completed_at <= event_time + 1e-6
                    and abs(completed_at - event_time) <= 1e-6
                ):
                    return self._evidence_missing_replay(job_id, "execution receipt timestamp mismatch")
            except (TypeError, ValueError):
                return self._evidence_missing_replay(job_id, "malformed execution receipt timestamps")

            dialogue = self.formatter.format_entry(
                register="FACT",
                content=f"Idempotent replay: '{manifest.name}' previously executed.",
                evidence_id=receipt.receipt_id,
                assurance=0.99,
            )
            return {
                "status": "SUCCESS",
                "receipt": receipt,
                "claim": None,
                "event_id": event.get("event_id"),
                "job_id": job_id,
                "dialogue": dialogue,
                "idempotent_replay": True,
            }

        events = self.event_store.get_events(
            aggregate_id=job_id,
            event_type="JobReconciledEvent",
        )
        if len(events) != 1:
            return self._evidence_missing_replay(
                job_id, f"expected one reconciliation event, found {len(events)}"
            )
        event = events[0]
        valid, reason = self.queue.verify_reconciliation_event(job, event)
        if not valid:
            return self._evidence_missing_replay(job_id, reason)

        payload = event["payload"]
        dialogue = self.formatter.format_entry(
            register="FACT",
            content=f"Idempotent replay: '{manifest.name}' was previously resolved via governed operator reconciliation.",
            evidence_id=job_id,
            assurance=1.0,
        )
        return {
            "status": "RECONCILED",
            "reconciled": True,
            "receipt": None,
            "reconciliation_event": event,
            "claim": None,
            "event_id": event.get("event_id"),
            "job_id": job_id,
            "result": payload["result"],
            "operator_id": payload["operator_id"],
            "resolution_notes": payload["resolution_notes"],
            "dialogue": dialogue,
            "idempotent_replay": True,
        }

    def execute_reference_loop(
        self,
        proposal: IntentProposal,
        scope_grant: Optional[ScopeGrant] = None,
        auth_grant: Optional[AuthorizationGrant] = None,
        worker_id: str = "worker_runtime_01",
        claim_predicate: Optional[str] = None
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
                denial = {"error": f"Target '{target}' is not permitted by ScopeGrant '{scope_grant.scope_id}'."}
                receipt = ExecutionReceipt(
                    receipt_id=f"rcpt_scope_denied_{uuid.uuid4().hex[:8]}",
                    job_id=f"JOB-{uuid.uuid4().hex[:8].upper()}",
                    capability=proposal.proposed_capability,
                    target=target,
                    started_at=now,
                    completed_at=now,
                    input_hash=ExecutionReceipt.hash_payload(proposal.provided_parameters),
                    output_hash=ExecutionReceipt.hash_payload(denial),
                    exit_code=1,
                    outcome=OutcomeCategory.POLICY_BLOCKED,
                    results=denial,
                    side_effects=[],
                    idempotency_key="",
                    attempt_number=1,
                    requested_network_policy=manifest.network_policy,
                    actual_transport_used="NONE_SCOPE_DENIED",
                    worker_id=worker_id,
                    error_message=f"Target outside permitted scope {scope_grant.allowed_targets}"
                ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)
                try:
                    event_id = self.event_store.append_event(
                        "CommandPolicyDenied", receipt.receipt_id, receipt.to_dict()
                    )
                except Exception:
                    return {"status": "STORAGE_FAILURE", "receipt": None, "claim": None,
                            "dialogue": "Command blocked; denial evidence could not be committed."}
                return {
                    "status": "POLICY_BLOCKED",
                    "receipt": receipt,
                    "event_id": event_id,
                    "dialogue": f"Policy blocked: Target '{target}' is outside permitted scope."
                }

        # Step 4: Compile PlanStep & ExecutionDAG
        proposal_digest = hashlib.sha256(proposal.proposal_id.encode('utf-8')).hexdigest()
        # Keep existing non-command replay IDs compatible; new command identities
        # use the complete digest rather than a collision-prone 32-bit namespace.
        deterministic_hash = proposal_digest if proposal.proposal_id.startswith("cmd_") else proposal_digest[:8]
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
            authorization_grant_id=None
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
        if existing_job and existing_job.get("status") in (JobState.SUCCEEDED.value, JobState.COMPLETED.value):
            return self._authenticated_terminal_replay(
                existing_job, manifest, params_hash, idemp_key
            )

        step = None
        if dag and hasattr(dag, "steps") and dag.steps:
            if isinstance(dag.steps, dict):
                step = dag.steps.get(step_id)
            else:
                for s in dag.steps:
                    if getattr(s, "step_id", None) == step_id:
                        step = s
                        break
        configured_retries = step.retry_policy.get("max_retries", 1) if (step and hasattr(step, "retry_policy") and isinstance(step.retry_policy, dict)) else 1
        job_max_retries = max(2, configured_retries + 1)

        # Step 6: Mint Governed ExecutionToken & Enqueue
        token = self.mint_execution_token(
            capability=proposal.proposed_capability,
            params=proposal.provided_parameters,
            plan_id=dag.plan_id,
            step_id=step_id,
            scope_grant=scope_grant,
            auth_grant=auth_grant,
            timeout_seconds=manifest.timeout_seconds,
            issued_at=now,
            plan_hash=plan_hash,
            max_attempts=job_max_retries
        )
        job_id = self.queue.enqueue_job(
            capability=proposal.proposed_capability,
            params=proposal.provided_parameters,
            plan_id=dag.plan_id,
            step_id=step_id,
            idempotency_key=idemp_key,
            max_retries=job_max_retries,
            execution_token=token
        )
        leased_job = self.queue.lease_next_job(worker_id=worker_id, lease_ttl_seconds=60, target_job_id=job_id)
        if leased_job is None or leased_job['job_id'] != job_id:
            # Another concurrent worker holds the execution lease for this idempotency key
            for _ in range(100):
                j = self.queue.get_job(job_id)
                if j and j['status'] in (JobState.SUCCEEDED.value, JobState.COMPLETED.value):
                    return self._authenticated_terminal_replay(
                        j, manifest, params_hash, idemp_key
                    )
                time.sleep(0.05)

            return {
                "status": "IN_PROGRESS_CONCURRENT",
                "job_id": job_id,
                "dialogue": "Concurrent execution in progress by another worker."
            }

        # Step 7: Worker-Only Execution via Durable IPC Queue (Gate Zero Invariant)
        receipt = self.worker_daemon._execute_leased_job(leased_job, worker_id)
        if not receipt:
            job_rec = self.queue.get_job(job_id)
            if job_rec and job_rec.get("status") in (JobState.SUCCEEDED.value, JobState.COMPLETED.value):
                return self._authenticated_terminal_replay(
                    job_rec, manifest, params_hash, idemp_key
                )
            else:
                receipt = ExecutionReceipt(
                    receipt_id=f"rcpt_fail_{uuid.uuid4().hex[:8]}",
                    job_id=job_id,
                    capability=proposal.proposed_capability,
                    target=target,
                    started_at=time.time(),
                    completed_at=time.time(),
                    input_hash=params_hash,
                    output_hash=ExecutionReceipt.hash_payload({"error": "Worker execution failed"}),
                    exit_code=1,
                    outcome=OutcomeCategory.EXECUTION_ERROR,
                    results={"error": "Worker daemon failed to process job"},
                    side_effects=[],
                    idempotency_key=idemp_key,
                    attempt_number=1,
                    requested_network_policy=manifest.network_policy,
                    actual_transport_used="NONE_FAILED",
                    worker_id=worker_id,
                    error_message="Worker daemon failed to process job"
                ).sign(self.worker_secret_key, worker_key_id=self.worker_key_id)

        # Publication has the same durable evidence gate as idempotent replay.
        if isinstance(receipt, dict):
            return receipt

        if receipt.exit_code == 0:
            try:
                completed_job = self.queue.get_job(job_id)
                proof = self._authenticated_terminal_replay(completed_job, manifest, params_hash, idemp_key)
                if proof.get("status") != "SUCCESS" or proof.get("receipt") != receipt:
                    return self._evidence_missing_replay(job_id, "uncommitted or mismatched execution evidence")
            except Exception as ex:
                return self._evidence_missing_replay(job_id, f"storage verification failed: {ex}")
        elif "RECONCILIATION_REQUIRED" in (receipt.error_message or ""):
            return {"status": "RECONCILIATION_REQUIRED", "receipt": receipt, "claim": None,
                    "event_id": None, "job_id": job_id, "error": receipt.error_message,
                    "dialogue": "Execution outcome requires reconciliation before it can be reported as verified."}

        # Retrieve committed event_id from EventStore strictly bound to this receipt
        events = self.event_store.get_events(aggregate_id=receipt.receipt_id)
        event_id = events[0]["event_id"] if events else None

        # Execution success and proposition admission are separate outcomes.
        canonical_claim = None
        if receipt.exit_code == 0:
            try:
                canonical_claim = self._project_execution_evidence(receipt, manifest=manifest, predicate=claim_predicate)
                self.worldview.admit_claim(canonical_claim)
            except ContractValidationError as exc:
                return {"status": "EPISTEMIC_ADMISSION_REJECTED", "receipt": receipt, "claim": None,
                        "event_id": event_id, "job_id": job_id, "error": str(exc),
                        "dialogue": "Execution completed, but its proposition failed evidence admission."}

        # Step 11: Grounded Dialogue Formatting
        dialogue = self.formatter.format_receipt_card(receipt)

        return {
            "status": "SUCCESS" if receipt.exit_code == 0 else "EXECUTION_ERROR",
            "receipt": receipt,
            "claim": canonical_claim,
            "event_id": event_id,
            "job_id": job_id,
            "dialogue": dialogue
        }

    def reconcile_job(
        self,
        job_id: str,
        target_state: Any,
        resolution_notes: str,
        result: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = None
    ) -> bool:
        """
        Governed operator reconciliation via CiphRuntime:
        Cryptographically signs the reconciliation intent using the runtime's operator key
        and atomically commits the transition and audit event to IPCJobQueue.
        """
        op_id = operator_id or self.operator_key_id
        state_val = target_state.value if hasattr(target_state, "value") else str(target_state)
        res_dict = result or {}
        res_str = json.dumps(res_dict, sort_keys=True)
        res_digest = hashlib.sha256(res_str.encode('utf-8')).hexdigest()
        recon_payload_msg = f"RECONCILE:{job_id}:{state_val}:{res_digest}:{resolution_notes.strip()}".encode('utf-8')

        op_sig = Ed25519KeyManager.sign(self.operator_priv_bytes, recon_payload_msg)
        return self.queue.reconcile_job(
            job_id=job_id,
            target_state=target_state,
            resolution_notes=resolution_notes,
            result=result,
            operator_id=op_id,
            operator_signature=op_sig
        )

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
        now = time.time()

        # Enforce ScopeGrant across all steps if provided
        if scope_grant:
            if scope_grant.is_expired(now):
                return {
                    "status": "SCOPE_EXPIRED",
                    "plan_id": dag.plan_id,
                    "errors": [f"ScopeGrant '{scope_grant.scope_id}' has expired."],
                    "success": False
                }
            for step in dag.steps:
                target = step.parameters.get("target")
                if target and not scope_grant.is_target_permitted(target):
                    return {
                        "status": "POLICY_BLOCKED",
                        "plan_id": dag.plan_id,
                        "step_id": step.step_id,
                        "errors": [f"Target '{target}' in step '{step.step_id}' outside permitted scope {scope_grant.allowed_targets}."],
                        "success": False
                    }

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
        dag_result = self.dag_executor.execute_dag(
            dag,
            target_backup_paths=target_backup_paths,
            auth_grants=auth_grants
        )

        # Each DAG receipt must already be atomically committed by the worker queue.
        admission_errors = []
        for step_id, r_dict in dag_result.get("step_receipts", {}).items():
            if r_dict.get("exit_code") == 0:
                try:
                    receipt = ExecutionReceipt.from_dict(r_dict)
                    claim = self._project_execution_evidence(receipt)
                    self.worldview.admit_claim(claim)
                except ContractValidationError as exc:
                    admission_errors.append({"step_id": step_id, "error": str(exc)})
        if admission_errors:
            dag_result["success"] = False
            dag_result["error"] = {"code": "EPISTEMIC_ADMISSION_REJECTED", "steps": admission_errors}

        return {
            "status": "SUCCESS" if dag_result["success"] else "EXECUTION_ERROR",
            "plan_id": dag.plan_id,
            "success": dag_result["success"],
            "executed_steps_count": dag_result["executed_steps_count"],
            "total_steps_count": dag_result["total_steps_count"],
            "error": dag_result.get("error"),
            "step_receipts": dag_result.get("step_receipts"),
            "compensation_receipts": dag_result.get("compensation_receipts", []),
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
        Returns an execution result, an explicit unavailable result, or None for non-command text.
        """
        return self.command_registry.dispatch(
            user_input=user_input,
            runtime=self,
            scope_grant=scope_grant,
            auth_grant=auth_grant
        )

    def run_idle_maintenance(
        self,
        bypass_idle_checks: bool = False,
        dependency_evidence_map: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes governed idle maintenance cycle via IdleMaintenanceEngine.
        Under exclusive operator lease, re-verifies event chain integrity, scavenges
        expired leases, runs safe PASSIVE WAL checkpoint & optimize, compiles empirical
        ledger cache, transitions stale claims, and performs static AST audit.
        """
        return self.idle_maintenance_engine.run_cycle(
            bypass_idle_checks=bypass_idle_checks,
            dependency_evidence_map=dependency_evidence_map
        )

    def check_and_run_maintenance_if_idle(
        self,
        dependency_evidence_map: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Evaluates durable quiescence criteria and runs a maintenance cycle if the system is idle."""
        idle, reason = self.idle_maintenance_engine.idle_detector.is_idle()
        if idle:
            return self.run_idle_maintenance(
                bypass_idle_checks=False,
                dependency_evidence_map=dependency_evidence_map
            )
        return None

    def get_cached_capability_ledger(self) -> Optional[Tuple[Dict[str, Any], Any]]:
        """Returns the in-memory compiled ledger cache populated by IdleMaintenanceEngine Task 4."""
        return self.idle_maintenance_engine.compiled_ledger_cache

    def _build_report_dict_from_profiles(self, profiles: Dict[str, Any], checkpoint: Any) -> Dict[str, Any]:
        """Converts in-memory empirical profiles and checkpoint into a report summary dictionary."""
        verified_active, untested, warning = [], [], []
        warning_status: Dict[str, str] = {}
        for p in profiles.values():
            status = str(getattr(p.health_status, "value", p.health_status))
            name = p.capability_name
            if status == "VERIFIED_ACTIVE":
                verified_active.append(name)
            elif status == "UNTESTED":
                untested.append(name)
            else:
                # Every status that is neither verified nor untested is surfaced as a warning.
                # A future enum addition lands here instead of vanishing from the briefing.
                warning.append(name)
                warning_status[name] = status

        historical_only = [n for n in warning if warning_status.get(n) == "HISTORICAL_ONLY"]
        degraded = [n for n in warning if warning_status.get(n) in ("DEGRADED", "OPERATIONAL_DEGRADED", "FAILING")]
        conflicted = [n for n in warning if warning_status.get(n) == "INTEGRITY_CONFLICT"]

        return {
            "checkpoint": {
                "verification_status": checkpoint.verification_status,
                "is_complete": checkpoint.is_complete,
                "total_events_scanned": checkpoint.total_events_scanned,
                "duplicate_replays_count": checkpoint.duplicate_replays_count,
                "conflicting_receipts_count": checkpoint.conflicting_receipts_count,
                "reconciled_jobs_count": checkpoint.reconciled_jobs_count,
                "unverifiable_receipts_count": checkpoint.unverifiable_receipts_count,
                "legacy_verified_receipts_count": getattr(checkpoint, "legacy_verified_receipts_count", 0),
                "scan_timestamp": checkpoint.scan_timestamp,
            },
            "summary": {
                "total_capabilities_tracked": len(profiles),
                "verified_active_count": len(verified_active),
                "untested_count": len(untested),
                "warning_count": len(warning),
                "historical_only_count": len(historical_only),
                "degraded_count": len(degraded),
                "conflicted_count": len(conflicted),
                "verified_active_capabilities": sorted(verified_active),
                "untested_capabilities": sorted(untested),
                "warning_capabilities": sorted(warning),
                "warning_status_by_name": warning_status,
                "historical_only_capabilities": sorted(historical_only),
                "degraded_capabilities": sorted(degraded),
                "conflicted_capabilities": sorted(conflicted),
            },
            "empirically_verified_capabilities": sorted(verified_active),
            "profiles": profiles
        }

    def generate_capability_briefing(self) -> str:
        """
        Generates an authoritative, epistemically tagged briefing of system capabilities.
        Uses cached ledger if available; on cold start, performs uncompromised full compilation.
        Discloses staleness if cache timestamp exceeds 3600 seconds.
        """
        cached = self.get_cached_capability_ledger()
        if cached is None:
            # Cold start: uncompromised full compilation with genesis verification
            from ciph.capabilities.capability_ledger import StaticDependencyInspector, generate_environment_fingerprint
            cur_env = generate_environment_fingerprint()
            now_t = time.time()
            dep_map = {}
            if self.registry and hasattr(self.registry, "list_manifests"):
                for manifest in self.registry.list_manifests():
                    declared = getattr(manifest, "declared_modules", ())
                    dep_map[manifest.name] = StaticDependencyInspector.check_declared_modules(
                        manifest.name, declared, cur_env, checked_at=now_t
                    )
            profiles, checkpoint = self.capability_ledger.compile_empirical_ledger(dependency_evidence_map=dep_map)
            self.idle_maintenance_engine.compiled_ledger_cache = (profiles, checkpoint)
            cached = (profiles, checkpoint)

        profiles, checkpoint = cached
        is_stale = (time.time() - checkpoint.scan_timestamp) > 3600.0
        report_dict = self._build_report_dict_from_profiles(profiles, checkpoint)
        return self.formatter.format_capability_briefing(report_dict, scan_timestamp=checkpoint.scan_timestamp, is_stale=is_stale)

    def generate_capability_card(self, capability_name: str) -> str:
        """Generates an authoritative Section 19 capability card for a single capability."""
        cached = self.get_cached_capability_ledger()
        if cached is None:
            self.generate_capability_briefing()
            cached = self.get_cached_capability_ledger()

        profiles, checkpoint = cached
        profile = profiles.get(capability_name)
        if profile is None:
            if self.registry and hasattr(self.registry, "get"):
                cap = self.registry.get(capability_name)
                if cap is None:
                    return f"[UNKNOWN] CAPABILITY PROFILE: {capability_name}\n  Capability: {capability_name}\n  Registered: no\n  Available now: no (UNREGISTERED)"

            return f"[UNKNOWN] CAPABILITY PROFILE: {capability_name}\n  Capability: {capability_name}\n  Registered: yes\n  Available now: no (UNTESTED - 0 verified executions)"

        m_hash = None
        try:
            cap = self.registry.get(capability_name) if self.registry else None
            manifest = getattr(cap, "manifest", None) if cap is not None else None
            if manifest is not None and hasattr(manifest, "compute_manifest_hash"):
                m_hash = manifest.compute_manifest_hash()
        except (AttributeError, TypeError, ValueError):
            m_hash = None

        return self.formatter.format_single_capability_card(profile, manifest_hash=m_hash)

    def answer_capability_query(self, query_text: Optional[str] = None) -> str:
        """
        Answers capability queries deterministically from the empirical capability ledger.
        Completely bypasses LLMs, preventing prompt laundering and epistemic hallucination.
        """
        if not query_text or not query_text.strip():
            return self.generate_capability_briefing()

        clean = query_text.strip()
        registered_names = set(self.registry.list_names()) if (self.registry and hasattr(self.registry, "list_names")) else (set(self.registry.list_capabilities()) if (self.registry and hasattr(self.registry, "list_capabilities")) else set())
        if clean in registered_names:
            return self.generate_capability_card(clean)

        tokens = clean.split()
        for tok in tokens:
            cleaned_tok = tok.strip(" ,;:\"'")
            if cleaned_tok in registered_names:
                return self.generate_capability_card(cleaned_tok)

        # If a specific single capability name was requested but not registered
        if len(tokens) == 1:
            return f"[UNKNOWN] Capability '{clean}' is not registered in the manifest."

        # Conversational inquiry fallback: return summary briefing if inquiry-related, else unknown notice
        conversational_triggers = ('what', 'list', 'show', 'ciph', 'capabilities', 'capability', 'toolbox', 'do', 'can', 'help')
        if any(trig in clean.lower() for trig in conversational_triggers):
            return self.generate_capability_briefing()

        return f"[UNKNOWN] Capability '{clean}' is not registered in the manifest."

    def shutdown(self) -> None:
        """Graceful runtime shutdown."""
        self.close()
        if hasattr(self, 'worker_daemon') and self.worker_daemon:
            try:
                self.worker_daemon.stop()
            except Exception:
                pass
