"""
ciph.kernel.transmutation_dag - Epistemic Categories, Belief Graph & Algorithmic Assurance.
"""

import time
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from ciph.perception.observation import ReliabilityClass


from ciph.contracts.enums import (
    EpistemicCategory,
    EpistemicState,
    LifecycleState,
    DecayProfile,
    RELIABILITY_BASE_WEIGHTS,
)


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
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE
    decay_profile: DecayProfile = DecayProfile.SOFTWARE_BEHAVIOR
    valid_from: Optional[float] = None
    valid_until: Optional[float] = None
    predicate_class: Optional[str] = None
    normalized_context_hash: Optional[str] = None
    verifier_provenance: Optional[str] = None
    migration_status: str = "CANONICAL"
    invalidation_barrier: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def is_stale(self, current_time: Optional[float] = None) -> bool:
        if self.freshness_deadline is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now > self.freshness_deadline

    def is_fresh(self, current_time: Optional[float] = None) -> bool:
        if self.freshness_deadline is None:
            return True
        now = current_time if current_time is not None else time.time()
        return now <= self.freshness_deadline

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['state'] = self.state.value if hasattr(self.state, "value") else str(self.state)
        d['reliability'] = self.reliability.value if hasattr(self.reliability, "value") else str(self.reliability)
        d['lifecycle_state'] = self.lifecycle_state.value if hasattr(self.lifecycle_state, "value") else str(self.lifecycle_state)
        d['decay_profile'] = self.decay_profile.value if hasattr(self.decay_profile, "value") else str(self.decay_profile)
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
        import copy
        candidate = copy.deepcopy(node)
        graph = dict(self._nodes)
        graph[node.claim_id] = candidate
        children = {}
        visiting = set()
        depths = {}
        def depth(cid):
            if cid in visiting: raise ValueError("DEPENDENCY_CYCLE")
            if cid in depths: return depths[cid]
            if cid not in graph: raise ValueError("DANGLING_PARENT")
            visiting.add(cid)
            if len(visiting)>17: raise ValueError("GRAPH_DEPTH_EXCEEDED")
            result=max((depth(pid)+1 for pid in graph[cid].parent_claim_ids),default=0)
            visiting.remove(cid)
            if result>16: raise ValueError("GRAPH_DEPTH_EXCEEDED")
            depths[cid]=result
            return result
        for cid, entry in graph.items():
            depth(cid)
            for pid in entry.parent_claim_ids:
                children.setdefault(pid,[]).append(cid)
                if len(children[pid])>256: raise ValueError("GRAPH_WIDTH_EXCEEDED")
        for pid in candidate.parent_claim_ids:
            parent=graph[pid]
            if not parent.is_fresh() or parent.lifecycle_state != LifecycleState.ACTIVE or parent.state in (EpistemicState.DISPUTED,EpistemicState.REFUTED,EpistemicState.SUPERSEDED):
                raise ValueError("INACTIVE_PARENT")
            candidate.assurance_score=min(candidate.assurance_score,parent.assurance_score)
            if parent.freshness_deadline is not None:
                candidate.freshness_deadline=min(candidate.freshness_deadline,parent.freshness_deadline) if candidate.freshness_deadline is not None else parent.freshness_deadline
        self._nodes=graph
        self._children=children

    def get_node(self, claim_id: str) -> Optional[TransmutationNode]:
        """Retrieve node by claim_id."""
        import copy
        return copy.deepcopy(self._nodes.get(claim_id))

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
        return self.get_node(derived_claim_id)

    def verify_weakest_link_invariants(self, claim_id: str) -> bool:
        """Bound validation work across shared ancestors; incomplete checks reject."""
        pending = [claim_id]
        visited = set()
        while pending:
            cid = pending.pop()
            if cid in visited:
                continue
            if len(visited) >= 1024:
                return False
            visited.add(cid)
            node = self._nodes.get(cid)
            if node is None:
                return False
            for pid in node.parent_claim_ids:
                parent = self._nodes.get(pid)
                if parent is None or node.assurance_score > parent.assurance_score:
                    return False
                if not parent.is_fresh() or parent.lifecycle_state != LifecycleState.ACTIVE:
                    return False
                pending.append(pid)
        return True
