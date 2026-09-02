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


class TransmutationDAG:
    """
    Epistemic Transmutation DAG Engine.
    Enforces the Weakest-Link Principle: No derived inference can have
    greater assurance than its weakest supporting premise.
    """

    def __init__(self):
        self._nodes: Dict[str, TransmutationNode] = {}
        self._children: Dict[str, List[str]] = {}

    def add_node(self, node: TransmutationNode) -> None:
        """Add or update a node in the Transmutation DAG."""
        self._nodes[node.claim_id] = node
        for parent_id in node.parent_claim_ids:
            if parent_id not in self._children:
                self._children[parent_id] = []
            if node.claim_id not in self._children[parent_id]:
                self._children[parent_id].append(node.claim_id)

    def get_node(self, claim_id: str) -> Optional[TransmutationNode]:
        """Retrieve node by claim_id."""
        return self._nodes.get(claim_id)

    def derive_inference(
        self,
        derived_claim_id: str,
        subject: str,
        predicate: str,
        value: Any,
        parent_claim_ids: List[str],
        rule_name: str,
        condition: Optional[str] = None,
        freshness_deadline: Optional[float] = None
    ) -> TransmutationNode:
        """
        Derive an INFERRED belief from supporting premise nodes.
        Strictly applies the Weakest-Link Principle:
        assurance(C) <= min(assurance(P) for P in parents)
        """
        if not parent_claim_ids:
            raise ValueError("Inference must be grounded in at least one parent claim premise.")

        parent_nodes = []
        for pid in parent_claim_ids:
            pnode = self.get_node(pid)
            if not pnode:
                raise ValueError(f"Parent claim premise '{pid}' does not exist in the DAG.")
            parent_nodes.append(pnode)

        # Weakest-link assurance cap
        min_parent_assurance = min(p.assurance_score for p in parent_nodes)
        
        # Deduction confidence penalty (small 5% deduction discount)
        inferred_assurance = round(min_parent_assurance * 0.95, 3)

        # Inherit strictest reliability from parents
        reliability_order = [
            ReliabilityClass.UNVERIFIED_INCOMING,
            ReliabilityClass.PASSIVE_RECON,
            ReliabilityClass.THIRD_PARTY_FEED,
            ReliabilityClass.DIRECT_SENSOR,
            ReliabilityClass.AUTHORITATIVE_LOCAL
        ]
        min_rel = min(parent_nodes, key=lambda p: reliability_order.index(p.reliability)).reliability

        # Aggregate evidence receipts from all supporting parents
        inherited_evidence = []
        for p in parent_nodes:
            inherited_evidence.extend(p.evidence_receipt_ids)

        node = TransmutationNode(
            claim_id=derived_claim_id,
            subject=subject,
            predicate=predicate,
            value=value,
            condition=condition or f"rule:{rule_name}",
            state=EpistemicCategory.INFERRED,
            reliability=min_rel,
            assurance_score=inferred_assurance,
            evidence_receipt_ids=list(set(inherited_evidence)),
            parent_claim_ids=parent_claim_ids,
            freshness_deadline=freshness_deadline
        )
        self.add_node(node)
        return node

    def verify_weakest_link_invariants(self, claim_id: str) -> bool:
        """
        Formally verifies that a claim's assurance score is bounded by all its ancestors.
        Fails closed if any parent premise is missing or if assurance exceeds any parent.
        """
        node = self.get_node(claim_id)
        if not node:
            return False
        if not node.parent_claim_ids:
            return True

        for pid in node.parent_claim_ids:
            parent = self.get_node(pid)
            if not parent:
                return False  # Missing parent fails invariant verification
            if node.assurance_score > parent.assurance_score:
                return False
            # Recursively verify upstream
            if not self.verify_weakest_link_invariants(pid):
                return False
        return True

