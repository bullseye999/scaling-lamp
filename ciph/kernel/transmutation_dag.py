"""
ciph.kernel.transmutation_dag - Epistemic Categories, Belief Graph & Algorithmic Assurance.
"""

import time
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from ciph.perception.observation import ReliabilityClass


class EpistemicCategory(str, Enum):
    INTELLIGENCE_GAP = "INTELLIGENCE_GAP"  # Explicitly acknowledged unknown
    OBSERVED         = "OBSERVED"          # Point-in-time telemetry received
    INFERRED         = "INFERRED"          # Derived via deterministic model logic
    HYPOTHESIZED     = "HYPOTHESIZED"      # Formal testable premise
    SUPPORTED        = "SUPPORTED"         # Corroborated with verified receipts
    DISPUTED         = "DISPUTED"          # Quarantined pending secondary confirmation
    REFUTED          = "REFUTED"           # Negative result -> Sent to Tabu Graveyard
    STALE            = "STALE"             # Freshness deadline expired
    SUPERSEDED       = "SUPERSEDED"        # Overridden by newer valid event


RELIABILITY_BASE_WEIGHTS = {
    ReliabilityClass.AUTHORITATIVE_LOCAL: 0.95,
    ReliabilityClass.DIRECT_SENSOR: 0.85,
    ReliabilityClass.THIRD_PARTY_FEED: 0.70,
    ReliabilityClass.PASSIVE_RECON: 0.60,
    ReliabilityClass.UNVERIFIED_INCOMING: 0.40,
}


def calculate_assurance_score(
    reliability: ReliabilityClass,
    corroboration_count: int = 1,
    contradiction_count: int = 0,
    age_seconds: float = 0.0,
    ttl_seconds: Optional[float] = None
) -> float:
    """
    Deterministically computes epistemic assurance score (0.0 to 1.0)
    using objective telemetry metrics instead of LLM-hallucinated floats.
    """
    base = RELIABILITY_BASE_WEIGHTS.get(reliability, 0.50)
    
    # Bonus for independent corroborations (max +0.20)
    corroboration_bonus = min(0.20, (max(1, corroboration_count) - 1) * 0.05)
    
    # Severe penalty for active contradictions
    contradiction_penalty = contradiction_count * 0.30
    
    # Time decay
    decay = 0.0
    if ttl_seconds and ttl_seconds > 0:
        decay = min(0.40, (age_seconds / ttl_seconds) * 0.40)
        
    score = base + corroboration_bonus - contradiction_penalty - decay
    return max(0.0, min(1.0, round(score, 3)))


@dataclass
class TransmutationNode:
    claim_id: str                          # e.g., "CLM-90412"
    subject: str                           # Asset / Entity (e.g., "auth.server.com")
    predicate: str                         # Attribute / State (e.g., "cname_dangling")
    value: Any                             # Current value / payload
    condition: Optional[str] = None        # Scope context
    state: EpistemicCategory = EpistemicCategory.OBSERVED
    reliability: ReliabilityClass = ReliabilityClass.DIRECT_SENSOR
    assurance_score: float = 0.5
    evidence_receipt_ids: List[str] = field(default_factory=list)
    parent_claim_ids: List[str] = field(default_factory=list)
    superseded_by: Optional[str] = None
    freshness_deadline: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def is_stale(self, current_time: Optional[float] = None) -> bool:
        if self.freshness_deadline is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now > self.freshness_deadline

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['state'] = self.state.value
        d['reliability'] = self.reliability.value
        return d
