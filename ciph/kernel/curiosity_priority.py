"""
ciph.kernel.curiosity_priority - which uncertainty would actually be USEFUL to reduce?

4.4 Gate One. Novelty is not value, and uncertainty is not value either. The projection is a pure,
versioned, deterministic function of canonical inputs:

    score = decision_relevance
          + expected_information_gain
          + expected_prediction_improvement
          + expected_self_model_improvement
          - estimated_cost
          - estimated_risk
          - barren_investigation_penalty

There is deliberately no parameter for how interesting the model finds something: interest is not a
term in the function, so it cannot be smuggled in as one (law 6).

LAWS (each has a specimen in `test_gate_4_4_curiosity_priority.py`)

 1. Novelty alone gives no priority.
 2. High uncertainty alone gives no priority.
 3. Curiosity must have an expected epistemic benefit.
 4. Cost and risk are first-class.
 5. Mission relevance may raise priority; mission existence grants no investigation authority.
 6. Model fascination/interest is not a scoring input.
 7. A lower-cost uncertainty may outrank a theoretically richer one.
 8. The priority metric cannot itself modify evidence or world state.
 9. Score changes require canonical input changes.
10. Same uncertainty inputs -> same priority digest.
"""

from dataclasses import dataclass
import hashlib
import json
import time
from typing import Any, Dict, Optional, Tuple

from ciph.kernel.curiosity_learning import outcome_penalty
from ciph.kernel.missions import MISSION_ACTIVE, reconstruct_missions
from ciph.kernel.predictions import STATUS_EXPIRED_UNRESOLVED, STATUS_OPEN, prediction_history
from ciph.kernel.uncertainty_registry import (
    KIND_CALIBRATION_WEAKNESS,
    KIND_DYNAMICS_GAP,
    KIND_EPISTEMIC_CONTESTED,
    KIND_EPISTEMIC_UNRESOLVED,
    KIND_SELF_MODEL_UNKNOWN,
    KIND_WEAK_CAUSAL_HYPOTHESIS,
    KIND_WORLD_STALE,
    POSSIBLY_REDUCIBLE,
    REDUCIBILITY_UNKNOWN,
    REDUCIBLE,
    derive_uncertainties,
)

CURIOSITY_PRIORITY_V1 = "CURIOSITY_PRIORITY_V1"

# The FROZEN V1 weight tables. They are tables rather than learned weights on purpose: a curiosity
# score that could learn its own weights would be a second, unaccountable authority.
INFO_GAIN_BY_REDUCIBILITY = {
    REDUCIBLE: 1.0,
    POSSIBLY_REDUCIBLE: 0.5,
    REDUCIBILITY_UNKNOWN: 0.25,
    "IRREDUCIBLE": 0.0,
}

COST_BY_KIND = {
    KIND_EPISTEMIC_UNRESOLVED: 0.30,
    KIND_EPISTEMIC_CONTESTED: 0.30,
    KIND_WORLD_STALE: 0.10,
    KIND_WEAK_CAUSAL_HYPOTHESIS: 0.50,
    KIND_DYNAMICS_GAP: 0.40,
    KIND_SELF_MODEL_UNKNOWN: 0.70,
    KIND_CALIBRATION_WEAKNESS: 0.20,
}

RISK_BY_KIND = {
    KIND_EPISTEMIC_UNRESOLVED: 0.10,
    KIND_EPISTEMIC_CONTESTED: 0.30,
    KIND_WORLD_STALE: 0.10,
    KIND_WEAK_CAUSAL_HYPOTHESIS: 0.40,
    KIND_DYNAMICS_GAP: 0.20,
    KIND_SELF_MODEL_UNKNOWN: 0.60,
    KIND_CALIBRATION_WEAKNESS: 0.10,
}

# Two open predictions already represent a real decision stake; more add nothing to V1.
PREDICTION_IMPROVEMENT_SATURATION = 2

REASON_MISSION_RELEVANT = "MISSION_RELEVANT"
REASON_IRREDUCIBLE = "IRREDUCIBLE"
REASON_EXPENSIVE = "COST_ABOVE_MEDIAN"
REASON_RISKY = "RISK_ABOVE_MEDIAN"
REASON_BARREN_HISTORY = "BARREN_INVESTIGATION_HISTORY"
REASON_UNSCORABLE_PREDICTIONS = "UNSCORABLE_PREDICTIONS"


@dataclass(frozen=True)
class CuriosityPriority:
    uncertainty_id: str
    metric_id: str
    source_kind: str
    decision_relevance: float
    mission_relevance: float
    expected_information_gain: float
    expected_prediction_improvement: float
    expected_self_model_improvement: float
    estimated_cost: float
    estimated_risk: float
    barren_penalty: float
    score: float
    reason_codes: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"uncertainty_id": self.uncertainty_id, "metric_id": self.metric_id,
                "source_kind": self.source_kind,
                "decision_relevance": self.decision_relevance,
                "mission_relevance": self.mission_relevance,
                "expected_information_gain": self.expected_information_gain,
                "expected_prediction_improvement": self.expected_prediction_improvement,
                "expected_self_model_improvement": self.expected_self_model_improvement,
                "estimated_cost": self.estimated_cost, "estimated_risk": self.estimated_risk,
                "barren_penalty": self.barren_penalty, "score": self.score,
                "reason_codes": list(self.reason_codes)}

    def canonical_digest(self) -> str:
        return _digest(self.as_dict())


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _round(value: float) -> float:
    return round(float(value), 12)


def mission_relevance(db_path: str, subject: Optional[str], *, now: Optional[float] = None) -> float:
    """
    Derived from canonical mission state: an ACTIVE mission whose objective names the subject.

    Laws 1 and 5: this is the only way relevance enters, so a mission EXISTING does not make a
    question relevant, and a question being interesting does not make it relevant either.
    """
    if not subject:
        return 0.0
    token = str(subject).strip().lower()
    if not token:
        return 0.0
    continuity = reconstruct_missions(db_path, now=now)
    for mission in continuity.missions:
        if mission.status != MISSION_ACTIVE or not mission.objective:
            continue
        if token in str(mission.objective).lower():
            return 1.0
    return 0.0


def prediction_stake(db_path: str, uncertainty_source_ref: str) -> float:
    """
    How many OPEN or EXPIRED predictions bear on this uncertainty, saturated. A prediction that is
    already unresolvable is a real calibration stake, which is why it counts.
    """
    try:
        history = prediction_history(db_path, uncertainty_source_ref)
    except Exception:
        return 0.0
    stakes = sum(1 for record in history
                 if record.status in (STATUS_OPEN, STATUS_EXPIRED_UNRESOLVED))
    return _round(min(1.0, stakes / float(PREDICTION_IMPROVEMENT_SATURATION)))


def derive_priority(db_path: str, uncertainty_id: str, *, now: Optional[float] = None,
                    stale_after: Optional[float] = None) -> Optional[CuriosityPriority]:
    """Score ONE uncertainty. Returns None when the uncertainty no longer exists (it closed)."""
    moment = time.time() if now is None else float(now)
    record = None
    for candidate in derive_uncertainties(db_path, now=moment, stale_after=stale_after):
        if candidate.uncertainty_id == uncertainty_id:
            record = candidate
            break
    if record is None:
        return None

    relevance = mission_relevance(db_path, record.subject, now=moment)
    info_gain = _round(INFO_GAIN_BY_REDUCIBILITY.get(record.reducibility, 0.0))
    stakes = (prediction_stake(db_path, record.source_ref)
              if record.source_kind in (KIND_EPISTEMIC_UNRESOLVED, KIND_EPISTEMIC_CONTESTED)
              else 0.0)
    self_model = 1.0 if record.source_kind == KIND_SELF_MODEL_UNKNOWN else 0.0
    cost = _round(COST_BY_KIND.get(record.source_kind, 1.0))
    risk = _round(RISK_BY_KIND.get(record.source_kind, 1.0))
    penalty = _round(outcome_penalty(db_path, uncertainty_id))

    score = _round(relevance + info_gain + stakes + self_model - cost - risk - penalty)
    reasons = []
    if relevance > 0.0:
        reasons.append(REASON_MISSION_RELEVANT)
    if record.reducibility == "IRREDUCIBLE":
        reasons.append(REASON_IRREDUCIBLE)
    if cost > 0.30:
        reasons.append(REASON_EXPENSIVE)
    if risk > 0.30:
        reasons.append(REASON_RISKY)
    if penalty > 0.0:
        reasons.append(REASON_BARREN_HISTORY)
    if stakes > 0.0:
        reasons.append(REASON_UNSCORABLE_PREDICTIONS)

    return CuriosityPriority(
        uncertainty_id=uncertainty_id, metric_id=CURIOSITY_PRIORITY_V1,
        source_kind=record.source_kind, decision_relevance=_round(relevance),
        mission_relevance=_round(relevance), expected_information_gain=info_gain,
        expected_prediction_improvement=stakes,
        expected_self_model_improvement=_round(self_model), estimated_cost=cost,
        estimated_risk=risk, barren_penalty=penalty, score=score,
        reason_codes=tuple(reasons))


def prioritise(db_path: str, *, now: Optional[float] = None,
               stale_after: Optional[float] = None) -> Tuple[CuriosityPriority, ...]:
    """
    Every uncertainty, ranked. Higher score first, ties broken by id, so the order is deterministic.

    This RANKS attention. It authorises nothing: no score of any size can cause an execution (law 8).
    """
    moment = time.time() if now is None else float(now)
    scored = []
    for record in derive_uncertainties(db_path, now=moment, stale_after=stale_after):
        priority = derive_priority(db_path, record.uncertainty_id, now=moment,
                                   stale_after=stale_after)
        if priority is not None:
            scored.append(priority)
    return tuple(sorted(scored, key=lambda item: (-item.score, item.uncertainty_id)))


def priority_digest(db_path: str, *, now: Optional[float] = None,
                    stale_after: Optional[float] = None) -> str:
    """The deterministic identity of the ranking (law 10)."""
    return _digest([priority.as_dict()
                    for priority in prioritise(db_path, now=now, stale_after=stale_after)])
