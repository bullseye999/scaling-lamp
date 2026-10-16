"""
ciph/kernel/autonomy_priority - 5.3: deterministic arbitration, never "the model felt task A mattered".

Factors are canonical facts, and the order is a total order with an explicit tiebreak, so a restart
produces the same answer and an operator override beats every computed factor.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import digest

AUTONOMY_PRIORITY_V1 = "AUTONOMY_PRIORITY_V1"

# Higher wins. Operator priority is unbounded in practice because nothing may outrank it.
OPERATOR_OVERRIDE = 1000.0
DEADLINE_URGENCY_WEIGHT = 10.0
RISK_WEIGHT = 2.0
EXTERNAL_EFFECT_PENALTY = 1.0
RESOURCE_COST_WEIGHT = 0.5

RISK_COST = {"NONE": 0.0, "LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0}


@dataclass(frozen=True)
class PriorityDecision:
    intent_id: str
    score: float
    reason_codes: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"intent_id": self.intent_id, "score": round(self.score, 12),
                "reason_codes": list(self.reason_codes)}


def arbitrate(db_path: str, *, intent_ids: Sequence[str], now: float,
              operator_priority_refs: Sequence[str] = ()) -> List[PriorityDecision]:
    """
    Rank intents deterministically.

    The only factor that is not computed is the OPERATOR one, and it is not a weight: an intent the
    operator named outranks every computed score, because urgency is not authority and taste is not
    priority.
    """
    from ciph.kernel.autonomous_work import get_work_intent
    overrides = {str(ref) for ref in operator_priority_refs}
    decisions: List[PriorityDecision] = []
    for intent_id in sorted(str(item) for item in intent_ids):
        intent = get_work_intent(db_path, intent_id)
        reasons: List[str] = []
        score = 0.0
        if intent.intent_id in overrides:
            score += OPERATOR_OVERRIDE
            reasons.append("OPERATOR_PRIORITY")
        if intent.latest_useful_time is not None:
            remaining = float(intent.latest_useful_time) - float(now)
            urgency = 1.0 / (1.0 + max(0.0, remaining) / 3600.0)
            score += DEADLINE_URGENCY_WEIGHT * urgency
            reasons.append("DEADLINE_URGENCY")
        score -= RISK_WEIGHT * RISK_COST.get(str(intent.risk_class).upper(), 4.0)
        reasons.append(f"RISK:{intent.risk_class}")
        if intent.external_effect:
            score -= EXTERNAL_EFFECT_PENALTY
            reasons.append("EXTERNAL_EFFECT")
        if intent.parent_mission_id is not None:
            reasons.append("MISSION_ATTACHED")
        decisions.append(PriorityDecision(intent_id=intent.intent_id, score=score,
                                         reason_codes=tuple(reasons)))
    return sorted(decisions, key=lambda decision: (-decision.score, decision.intent_id))


def arbitration_digest(decisions: Sequence[PriorityDecision]) -> str:
    return digest({"version": AUTONOMY_PRIORITY_V1,
                   "decisions": [decision.as_dict() for decision in decisions]})
