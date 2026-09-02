"""
ciph.planner.schemas - Canonical schemas for PlanStep, ExecutionDAG, SkillTemplate, and IntentProposal.
"""

import time
import json
import hashlib
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from ciph.kernel.policy_engine import ReversibilityClass, AuthorizationTier


class SkillPromotionTier(str, Enum):
    CANDIDATE = "CANDIDATE"  # Succeeded 1 time
    VALIDATED = "VALIDATED"  # Succeeded >= 3 times across varied parameters
    APPROVED  = "APPROVED"   # Signed off by operator
    ACTIVE    = "ACTIVE"     # Available for fast-path compilation
    REVOKED   = "REVOKED"    # Deprecated / environment drifted


@dataclass
class IntentProposal:
    proposal_id: str
    objective: str
    proposed_capability: str
    provided_parameters: Dict[str, Any] = field(default_factory=dict)
    missing_parameters: List[str] = field(default_factory=list)
    scope_reference: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    requested_outcome: Optional[str] = None
    created_at: float = field(default_factory=time.time)

    def is_executable_proposal(self) -> bool:
        """Check if proposal has all mandatory parameters resolved."""
        return len(self.missing_parameters) == 0 and bool(self.proposed_capability)


@dataclass
class PlanValidationResult:
    plan_id: str
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    missing_parameters: List[str] = field(default_factory=list)
    required_grants: List[str] = field(default_factory=list)
    validated_at: float = field(default_factory=time.time)


@dataclass
class PlanStep:
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

    def compute_params_hash(self) -> str:
        """Deterministically hash parameters dictionary."""
        try:
            canonical_str = json.dumps(self.parameters, sort_keys=True, default=str)
        except Exception:
            canonical_str = str(self.parameters)
        return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['reversibility'] = self.reversibility.value
        d['authorization_tier'] = self.authorization_tier.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlanStep":
        d = dict(data)
        if 'reversibility' in d and isinstance(d['reversibility'], str):
            d['reversibility'] = ReversibilityClass(d['reversibility'])
        if 'authorization_tier' in d and isinstance(d['authorization_tier'], str):
            d['authorization_tier'] = AuthorizationTier(d['authorization_tier'])
        return cls(**d)


@dataclass
class ExecutionDAG:
    plan_id: str
    objective: str
    steps: List[PlanStep]
    rollback_snapshot_id: Optional[str] = None
    is_parameterized_template: bool = False
    template_signature: Optional[str] = None

    def compute_plan_hash(self) -> str:
        """Compute canonical cryptographic hash of the compiled execution DAG."""
        step_fingerprints = []
        for s in sorted(self.steps, key=lambda x: x.step_id):
            step_fingerprints.append(f"{s.step_id}:{s.capability}:{s.compute_params_hash()}:{sorted(s.depends_on)}")
        raw = f"{self.plan_id}:{self.objective}:{';'.join(step_fingerprints)}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def get_step(self, step_id: str) -> Optional[PlanStep]:
        for s in self.steps:
            if s.step_id == step_id:
                return s
        return None


@dataclass
class SkillTemplate:
    template_id: str
    signature: str                                      # e.g., "cybersecurity.subdomain_takeover_audit"
    parameter_slots: List[str]                          # ["target_domain", "cloud_provider_list"]
    dag_nodes: List[PlanStep]
    precondition_hash: str                              # Environment / target baseline hash
    confidence_decay_ttl: int = 604800                  # 7 days default TTL
    required_epistemic_state: Dict[str, Any] = field(default_factory=dict)
    promotion_tier: SkillPromotionTier = SkillPromotionTier.CANDIDATE
    flawless_runs_count: int = 0
    created_at: float = 0.0

    def is_expired(self, current_time: float) -> bool:
        return current_time > (self.created_at + self.confidence_decay_ttl)
