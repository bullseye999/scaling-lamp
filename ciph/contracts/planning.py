"""
ciph.contracts.planning - Canonical Contracts for IntentProposal, PlanStep, and ExecutionDAG.
Enforces DAG cycle detection, duplicate ID rejection, and deterministic topological plan hashing.
"""

import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import deque

from ciph.contracts.enums import ReversibilityClass, AuthorizationTier, SkillPromotionTier
from ciph.contracts.base import ContractValidationError, canonical_json, freeze_value


SUPPORTED_PLANNING_SCHEMA_VERSIONS = {"1.0"}


@dataclass(frozen=True)
class IntentProposal:
    """
    Formal representation of a user, agent, or event intention.
    Preserves existing fields: scope_reference, constraints, requested_outcome.
    """
    proposal_id: str
    objective: str
    proposed_capability: str
    provided_parameters: Dict[str, Any] = field(default_factory=dict)
    missing_parameters: List[str] = field(default_factory=list)
    scope_reference: Optional[str] = None
    scope_context: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    requested_outcome: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    schema_version: str = "1.0"

    def __post_init__(self):
        if self.schema_version not in SUPPORTED_PLANNING_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported IntentProposal schema_version: {self.schema_version}")
        object.__setattr__(self, "provided_parameters", freeze_value(self.provided_parameters or {}))
        object.__setattr__(self, "missing_parameters", tuple(self.missing_parameters or ()))
        object.__setattr__(self, "constraints", freeze_value(self.constraints or {}))
        # Sync scope_reference and scope_context for backward compatibility
        ref = self.scope_reference
        ctx = self.scope_context
        if ref and not ctx:
            object.__setattr__(self, "scope_context", ref)
        elif ctx and not ref:
            object.__setattr__(self, "scope_reference", ctx)

    def is_executable_proposal(self) -> bool:
        """Check if proposal has all mandatory parameters resolved and a target capability."""
        return len(self.missing_parameters) == 0 and bool(self.proposed_capability)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "proposal_id": self.proposal_id,
            "objective": self.objective,
            "proposed_capability": self.proposed_capability,
            "provided_parameters": dict(self.provided_parameters),
            "missing_parameters": list(self.missing_parameters),
            "scope_reference": self.scope_reference,
            "scope_context": self.scope_context,
            "constraints": dict(self.constraints),
            "requested_outcome": self.requested_outcome,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntentProposal":
        d = dict(data)
        ver = d.get("schema_version", "1.0")
        if ver not in SUPPORTED_PLANNING_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported IntentProposal schema_version: {ver}")
        return cls(
            proposal_id=d["proposal_id"],
            objective=d["objective"],
            proposed_capability=d["proposed_capability"],
            provided_parameters=d.get("provided_parameters", {}),
            missing_parameters=d.get("missing_parameters", []),
            scope_reference=d.get("scope_reference"),
            scope_context=d.get("scope_context"),
            constraints=d.get("constraints", {}),
            requested_outcome=d.get("requested_outcome"),
            created_at=d.get("created_at", time.time()),
            schema_version=ver
        )


@dataclass
class PlanValidationResult:
    plan_id: str
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    missing_parameters: List[str] = field(default_factory=list)
    required_grants: List[str] = field(default_factory=list)
    validated_at: float = field(default_factory=time.time)
    schema_version: str = "1.0"


@dataclass(frozen=True)
class PlanStep:
    """
    Atomic executable step within an ExecutionDAG.
    Preserves all compensation, retry, predicate, and authorization fields.
    """
    step_id: str
    capability: str
    parameters: Dict[str, Any]
    depends_on: List[str] = field(default_factory=list)
    reversibility: ReversibilityClass = ReversibilityClass.READ_ONLY
    compensation_action: Optional[str] = None          # Executable inverse capability
    compensation_params: Optional[Dict[str, Any]] = None
    success_condition: str = "exit_code == 0"         # Safe AST predicate string
    expected_receipt_type: str = "ExecutionReceipt"
    retry_policy: Dict[str, Any] = field(default_factory=lambda: {"max_retries": 1, "backoff": "linear"})
    idempotency_key: str = ""
    timeout_seconds: int = 30
    authorization_tier: AuthorizationTier = AuthorizationTier.AUTO
    scope_grant_id: Optional[str] = None
    authorization_grant_id: Optional[str] = None
    schema_version: str = "1.0"

    def __post_init__(self):
        if self.schema_version not in SUPPORTED_PLANNING_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported PlanStep schema_version: {self.schema_version}")
        if isinstance(self.reversibility, str):
            object.__setattr__(self, "reversibility", ReversibilityClass(self.reversibility))
        if isinstance(self.authorization_tier, str):
            object.__setattr__(self, "authorization_tier", AuthorizationTier(self.authorization_tier))
        object.__setattr__(self, "parameters", freeze_value(self.parameters or {}))
        object.__setattr__(self, "depends_on", tuple(self.depends_on or ()))
        if self.compensation_params is not None:
            object.__setattr__(self, "compensation_params", freeze_value(self.compensation_params))
        object.__setattr__(self, "retry_policy", freeze_value(self.retry_policy or {}))

    def compute_params_hash(self) -> str:
        """Deterministically hash parameters dictionary matching ExecutionReceipt.hash_payload."""
        from ciph.contracts.base import canonical_json
        return hashlib.sha256(canonical_json(self.parameters).encode("utf-8")).hexdigest()

    def compute_step_hash(self) -> str:
        """Compute canonical hash of step definition including dependencies, retry policy, and authorization."""
        step_payload = {
            "schema_version": self.schema_version,
            "step_id": self.step_id,
            "capability": self.capability,
            "params_hash": self.compute_params_hash(),
            "depends_on": sorted(self.depends_on),
            "reversibility": self.reversibility.value if hasattr(self.reversibility, "value") else str(self.reversibility),
            "compensation_action": self.compensation_action,
            "compensation_params": self.compensation_params,
            "success_condition": self.success_condition,
            "expected_receipt_type": self.expected_receipt_type,
            "retry_policy": self.retry_policy,
            "idempotency_key": self.idempotency_key,
            "timeout_seconds": self.timeout_seconds,
            "authorization_tier": self.authorization_tier.value if hasattr(self.authorization_tier, "value") else str(self.authorization_tier),
            "scope_grant_id": self.scope_grant_id,
            "authorization_grant_id": self.authorization_grant_id,
        }
        return hashlib.sha256(canonical_json(step_payload).encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["reversibility"] = self.reversibility.value if hasattr(self.reversibility, "value") else str(self.reversibility)
        d["authorization_tier"] = self.authorization_tier.value if hasattr(self.authorization_tier, "value") else str(self.authorization_tier)
        d["schema_version"] = self.schema_version
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlanStep":
        d = dict(data)
        ver = d.get("schema_version", "1.0")
        if ver not in SUPPORTED_PLANNING_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported PlanStep schema_version: {ver}")
        if "reversibility" in d and isinstance(d["reversibility"], str):
            d["reversibility"] = ReversibilityClass(d["reversibility"])
        if "authorization_tier" in d and isinstance(d["authorization_tier"], str):
            d["authorization_tier"] = AuthorizationTier(d["authorization_tier"])
        return cls(**d)


@dataclass(frozen=True)
class ExecutionDAG:
    """
    Validated acyclic execution graph.
    Enforces deterministic topological ordering, cycle rejection, and duplicate step ID rejection.
    """
    plan_id: str
    objective: str
    steps: List[PlanStep]
    rollback_snapshot_id: Optional[str] = None
    is_parameterized_template: bool = False
    template_signature: Optional[str] = None
    schema_version: str = "1.0"

    def __post_init__(self):
        if self.schema_version not in SUPPORTED_PLANNING_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported ExecutionDAG schema_version: {self.schema_version}")
        object.__setattr__(self, "steps", tuple(self.steps or ()))

    def validate(self) -> None:
        """Validate DAG: reject duplicate IDs, self-dependencies, missing dependencies, and cycles."""
        seen_ids: Set[str] = set()
        for step in self.steps:
            if step.step_id in seen_ids:
                raise ContractValidationError(f"Duplicate step_id detected in DAG: '{step.step_id}'")
            seen_ids.add(step.step_id)

        for step in self.steps:
            for dep in step.depends_on:
                if dep == step.step_id:
                    raise ContractValidationError(f"Self-dependency detected on step '{step.step_id}'")
                if dep not in seen_ids:
                    raise ContractValidationError(
                        f"Step '{step.step_id}' depends on non-existent step '{dep}'"
                    )

        # Topological sort with cycle detection (Kahn's algorithm)
        in_degree: Dict[str, int] = {s.step_id: 0 for s in self.steps}
        adj: Dict[str, List[str]] = {s.step_id: [] for s in self.steps}
        for step in self.steps:
            for dep in step.depends_on:
                adj[dep].append(step.step_id)
                in_degree[step.step_id] += 1

        queue = deque([sid for sid, deg in in_degree.items() if deg == 0])
        visited_count = 0
        while queue:
            curr = queue.popleft()
            visited_count += 1
            for nxt in adj[curr]:
                in_degree[nxt] -= 1
                if in_degree[nxt] == 0:
                    queue.append(nxt)

        if visited_count < len(self.steps):
            raise ContractValidationError(f"Cycle detected in ExecutionDAG '{self.plan_id}'")

    def get_topologically_sorted_steps(self) -> List[PlanStep]:
        """
        Return steps in deterministic topological order with stable step_id tie-breaking.
        """
        self.validate()
        step_map = {s.step_id: s for s in self.steps}
        in_degree: Dict[str, int] = {s.step_id: len(s.depends_on) for s in self.steps}
        adj: Dict[str, List[str]] = {s.step_id: [] for s in self.steps}
        for step in self.steps:
            for dep in step.depends_on:
                adj[dep].append(step.step_id)

        # Use sorted list for deterministic tie-breaking
        ready = sorted([sid for sid, deg in in_degree.items() if deg == 0])
        result = []
        while ready:
            curr_id = ready.pop(0)
            result.append(step_map[curr_id])
            for nxt in sorted(adj[curr_id]):
                in_degree[nxt] -= 1
                if in_degree[nxt] == 0:
                    ready.append(nxt)
                    ready.sort()  # Maintain stable tie-break
        return result

    def compute_plan_hash(self) -> str:
        """
        Compute canonical cryptographic hash of the compiled execution DAG.
        Uses deterministic topological ordering and complete canonical JSON.
        Binds all DAG execution parameters including rollback_snapshot_id and template metadata.
        """
        sorted_steps = self.get_topologically_sorted_steps()
        step_hashes = [f"{s.step_id}:{s.compute_step_hash()}" for s in sorted_steps]
        canonical_payload = {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "objective": self.objective,
            "step_hashes": step_hashes,
            "rollback_snapshot_id": self.rollback_snapshot_id,
            "is_parameterized_template": self.is_parameterized_template,
            "template_signature": self.template_signature,
        }
        return hashlib.sha256(canonical_json(canonical_payload).encode("utf-8")).hexdigest()

    def get_step(self, step_id: str) -> Optional[PlanStep]:
        for s in self.steps:
            if s.step_id == step_id:
                return s
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "objective": self.objective,
            "steps": [s.to_dict() for s in self.steps],
            "rollback_snapshot_id": self.rollback_snapshot_id,
            "is_parameterized_template": self.is_parameterized_template,
            "template_signature": self.template_signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionDAG":
        d = dict(data)
        ver = d.get("schema_version", "1.0")
        if ver not in SUPPORTED_PLANNING_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported ExecutionDAG schema_version: {ver}")
        steps = [PlanStep.from_dict(s) for s in d.get("steps", [])]
        return cls(
            plan_id=d["plan_id"],
            objective=d["objective"],
            steps=steps,
            rollback_snapshot_id=d.get("rollback_snapshot_id"),
            is_parameterized_template=d.get("is_parameterized_template", False),
            template_signature=d.get("template_signature"),
            schema_version=ver
        )


@dataclass
class SkillTemplate:
    template_id: str
    signature: str                                      # e.g., "cybersecurity.subdomain_takeover_audit"
    parameter_slots: List[str]                          # ["target_domain", "cloud_provider_list"]
    dag_nodes: List[PlanStep]
    precondition_hash: str = ""                         # Environment / target baseline hash
    confidence_decay_ttl: int = 604800                  # 7 days default TTL
    required_epistemic_state: Dict[str, Any] = field(default_factory=dict)
    promotion_tier: SkillPromotionTier = SkillPromotionTier.CANDIDATE
    flawless_runs_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    created_at: float = field(default_factory=time.time)
    author_agent: str = "ciph_planner_core"
    schema_version: str = "1.0"

    def is_expired(self, current_time: float) -> bool:
        return current_time > (self.created_at + self.confidence_decay_ttl)
