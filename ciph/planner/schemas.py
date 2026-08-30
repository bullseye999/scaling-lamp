"""
ciph.planner.schemas - Canonical schemas for PlanStep, ExecutionDAG, and SkillTemplate.
"""

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
