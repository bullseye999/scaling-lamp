"""
ciph.runtime - The Unified Cognitive Coordinator (CIPH 4.0).
Provides multi-lane execution dispatching, policy enforcement, Red Team gating, and subsystem wiring.
"""

import time
import uuid
from typing import Dict, Any, Optional, List
from ciph.capabilities.registry import CapabilityRegistry
from ciph.kernel.policy_engine import ExecutionLane, CapabilityManifest, NetworkPolicy
from ciph.kernel.adversarial_gate import AdversarialRedTeamGate
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory
from ciph.memory.event_store import EventStore
from ciph.memory.materialized_views import MaterializedWorldview
from ciph.memory.claim_leases import ClaimLeaseManager
from ciph.memory.active_forgetting import ActiveForgettingEngine
from ciph.perception.bus import SensoryBus
from ciph.planner.skill_registry import SkillRegistry
from ciph.planner.dag_planner import DAGExecutor
from ciph.operator.cadence_engine import CadenceManager
from ciph.operator.dialogue_formatter import DialogueFormatter


class CiphRuntime:
    """
    Lightweight, decoupled Cognitive Runtime.
    Wires all core subsystems, enforces network & authorization policies,
    and runs Red Team falsification checks on high-consequence operations.
    """

    def __init__(self, vault=None, db_path: str = "ciph_vault.db"):
        self.vault = vault
        self.db_path = db_path
        
        # Subsystems
        self.registry = CapabilityRegistry()
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
        self.skill_registry = SkillRegistry()
        self.dag_executor = DAGExecutor(self.registry)
        self.cadence_manager = CadenceManager()
        self.formatter = DialogueFormatter()
        self.red_team_gate = AdversarialRedTeamGate()

        self.started_at = time.time()
        self._is_running = True

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

        # 2. Enforce Authorization Tiers
        from ciph.kernel.policy_engine import AuthorizationTier
        if manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
            if not context.get("authorized") and not context.get("auto_authorize"):
                job_id = context.get("job_id", f"JOB-{uuid.uuid4().hex[:8].upper()}")
                return ExecutionReceipt(
                    receipt_id=f"rcpt_auth_blocked_{uuid.uuid4().hex[:8]}",
                    job_id=job_id,
                    capability=capability_name,
                    target=params.get("target"),
                    started_at=time.time(),
                    completed_at=time.time(),
                    input_hash=ExecutionReceipt.hash_payload(params),
                    output_hash=ExecutionReceipt.hash_payload({"error": "Authorization Required"}),
                    exit_code=1,
                    outcome=OutcomeCategory.POLICY_BLOCKED,
                    results={"error": f"Execution of '{capability_name}' requires explicit operator authorization ({manifest.authorization.value})."},
                    side_effects=[],
                    idempotency_key=context.get("idempotency_key", ""),
                    attempt_number=1,
                    requested_network_policy=manifest.network_policy,
                    actual_transport_used="NONE_UNAUTHORIZED",
                    error_message=f"Operator authorization required ({manifest.authorization.value})."
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

    def shutdown(self) -> None:
        """Graceful runtime shutdown."""
        self._is_running = False
