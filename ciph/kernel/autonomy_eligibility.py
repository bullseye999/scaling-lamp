"""
ciph/kernel/autonomy_eligibility - 5.0 Gate Two (eligibility) and Gate Five (stop reasons).

    AUTONOMY_ELIGIBILITY_V1

A PURE FUNCTION over canonical state. The model may propose work; the kernel decides whether it is
eligible, and the decision names exactly one reason. There is no LLM discretion in this function, and
that is the point of it existing at all.
"""

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.autonomous_work import (
    STATUS_CANCELLED,
    STATUS_SATISFIED,
    get_work_intent,
    mission_basis,
    record_intent_decision,
    work_intent_status,
)
from ciph.kernel.autonomy_budgets import REASON_EXHAUSTED, budget_status
from ciph.kernel.autonomy_modes import (
    MODE_LIMITED,
    MODE_OFF,
    MODE_READ_ONLY,
    REASON_MODE_LIMITED,
    REASON_MODE_OFF,
    REASON_MODE_READ_ONLY,
    REASON_OPERATOR_HOLD,
    current_mode,
)
from ciph.kernel.crucible_types import CrucibleError, digest
from ciph.kernel.standing_authorization import (
    REASON_EXPIRED as REASON_STANDING_EXPIRED,
    REASON_RISK_CEILING,
    REASON_SCOPE_WIDENED,
    REASON_WORK_CLASS_NOT_PERMITTED,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    authorization_status,
    get_standing_authorization,
    standing_authorizations,
)

AUTONOMY_ELIGIBILITY_V1 = "AUTONOMY_ELIGIBILITY_V1"

OUTCOME_ELIGIBLE = "ELIGIBLE"
OUTCOME_NO_AUTHORITY = "BLOCKED_NO_AUTHORITY"
OUTCOME_STALE_BASIS = "BLOCKED_STALE_BASIS"
OUTCOME_RISK = "BLOCKED_RISK"
OUTCOME_RESOURCE = "BLOCKED_RESOURCE"
OUTCOME_CONFLICT = "BLOCKED_CONFLICT"
OUTCOME_OPERATOR_HOLD = "BLOCKED_OPERATOR_HOLD"
OUTCOME_SATISFIED = "SATISFIED"
OUTCOME_EXPIRED = "EXPIRED"
VALID_OUTCOMES = (OUTCOME_ELIGIBLE, OUTCOME_NO_AUTHORITY, OUTCOME_STALE_BASIS, OUTCOME_RISK,
                  OUTCOME_RESOURCE, OUTCOME_CONFLICT, OUTCOME_OPERATOR_HOLD, OUTCOME_SATISFIED,
                  OUTCOME_EXPIRED)

# Gate Five: an autonomous system needs explicit reasons to stop, including the one that matters most.
STOP_WORK_SATISFIED = "WORK_SATISFIED"
STOP_AUTHORITY_EXPIRED = "AUTHORITY_EXPIRED"
STOP_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
STOP_EPISTEMIC_BASIS_STALE = "EPISTEMIC_BASIS_STALE"
STOP_HIGHER_PRIORITY_WORK = "HIGHER_PRIORITY_WORK"
STOP_OPERATOR_INTERRUPT = "OPERATOR_INTERRUPT"
STOP_RISK_THRESHOLD = "RISK_THRESHOLD"
STOP_DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
STOP_NO_USEFUL_NEXT_ACTION = "NO_USEFUL_NEXT_ACTION"
STOP_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
VALID_STOP_REASONS = (STOP_WORK_SATISFIED, STOP_AUTHORITY_EXPIRED, STOP_BUDGET_EXHAUSTED,
                      STOP_EPISTEMIC_BASIS_STALE, STOP_HIGHER_PRIORITY_WORK, STOP_OPERATOR_INTERRUPT,
                      STOP_RISK_THRESHOLD, STOP_DEPENDENCY_UNAVAILABLE, STOP_NO_USEFUL_NEXT_ACTION,
                      STOP_RECOVERY_REQUIRED)

_STOP_BY_OUTCOME = {OUTCOME_SATISFIED: STOP_WORK_SATISFIED, OUTCOME_EXPIRED: STOP_AUTHORITY_EXPIRED,
                    OUTCOME_NO_AUTHORITY: STOP_AUTHORITY_EXPIRED,
                    OUTCOME_STALE_BASIS: STOP_EPISTEMIC_BASIS_STALE,
                    OUTCOME_RISK: STOP_RISK_THRESHOLD, OUTCOME_RESOURCE: STOP_BUDGET_EXHAUSTED,
                    OUTCOME_CONFLICT: STOP_HIGHER_PRIORITY_WORK,
                    OUTCOME_OPERATOR_HOLD: STOP_OPERATOR_INTERRUPT}


@dataclass(frozen=True)
class EligibilityDecision:
    intent_id: str
    outcome: str
    reason_codes: Tuple[str, ...]
    standing_auth_id: Optional[str]
    budget_ref: Optional[str]
    basis_digest: str
    stop_reason: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"intent_id": self.intent_id, "outcome": self.outcome,
                "reason_codes": list(self.reason_codes),
                "standing_auth_id": self.standing_auth_id, "budget_ref": self.budget_ref,
                "basis_digest": self.basis_digest, "stop_reason": self.stop_reason,
                "policy_version": AUTONOMY_ELIGIBILITY_V1}


def _authorization_for(db_path: str, intent: Any, *, now: Optional[float] = None
                       ) -> Optional[str]:
    """
    The grant this intent would run under: the first ACTIVE one that lists the work class, or failing
    that the first lapsed/revoked one that lists it.

    Returning the lapsed grant matters. "You were never granted this" and "your grant ran out" are
    different facts about the world, and only the second is repaired by governance rather than by a
    later clock reading. Collapsing both into BLOCKED_NO_AUTHORITY would erase the distinction the
    operator needs in order to know whether to re-grant or to investigate.
    """
    if intent.parent_mission_id is None:
        return None
    lapsed: List[str] = []
    for authorization in standing_authorizations(db_path, mission_id=intent.parent_mission_id):
        if str(intent.work_class) not in authorization.permitted_work_classes:
            continue
        if authorization_status(db_path, authorization.standing_auth_id, now=now) == STATUS_ACTIVE:
            return authorization.standing_auth_id
        lapsed.append(authorization.standing_auth_id)
    return lapsed[0] if lapsed else None


def _conflicting_work(db_path: str, intent: Any, *, now: float) -> Optional[str]:
    """Two intents for one mission may not both be runnable at once."""
    from ciph.kernel.autonomy_session import open_sessions
    if intent.parent_mission_id is None:
        return None
    for session in open_sessions(db_path):
        if session.mission_id == intent.parent_mission_id and session.session_id:
            return session.session_id
    return None


def evaluate_eligibility(db_path: str, *, intent_id: str, now: Optional[float] = None,
                         record: bool = True) -> EligibilityDecision:
    """
    THE eligibility function. One outcome, one reason, and no discretion.

    Ordering is deliberate: the operator's mode is checked before authority, because an operator hold is
    a statement about the world, not a competing preference.
    """
    moment = time.time() if now is None else float(now)
    intent = get_work_intent(db_path, intent_id)
    basis = mission_basis(db_path, intent.parent_mission_id)
    outcome: Optional[str] = None
    reasons: List[str] = []
    standing_auth_id: Optional[str] = None
    budget_ref: Optional[str] = None

    lifecycle = work_intent_status(db_path, intent_id, now=moment)
    if lifecycle == STATUS_SATISFIED:
        outcome, reasons = OUTCOME_SATISFIED, ["WORK_ALREADY_SATISFIED"]
    elif lifecycle == STATUS_CANCELLED:
        outcome, reasons = OUTCOME_SATISFIED, ["WORK_CANCELLED"]
    elif intent.latest_useful_time is not None and moment > float(intent.latest_useful_time):
        outcome, reasons = OUTCOME_EXPIRED, ["WORK_NO_LONGER_USEFUL"]

    mode = current_mode(db_path)
    if outcome is None:
        if mode in (MODE_OFF, "EMERGENCY_STOP", "QUIESCE"):
            outcome = OUTCOME_OPERATOR_HOLD
            reasons = [REASON_MODE_OFF if mode == MODE_OFF else REASON_OPERATOR_HOLD]
        elif mode == MODE_READ_ONLY and intent.external_effect:
            outcome, reasons = OUTCOME_OPERATOR_HOLD, [REASON_MODE_READ_ONLY]
        elif mode == MODE_LIMITED and str(intent.risk_class).upper() != "LOW":
            outcome, reasons = OUTCOME_RISK, [REASON_MODE_LIMITED]

    if outcome is None:
        standing_auth_id = _authorization_for(db_path, intent, now=moment)
        if standing_auth_id is None:
            outcome, reasons = OUTCOME_NO_AUTHORITY, ["NO_STANDING_AUTHORIZATION_FOR_WORK_CLASS"]
        else:
            status = authorization_status(db_path, standing_auth_id, now=moment)
            if status == STATUS_EXPIRED:
                # A lapsed grant is EXPIRED, not "unauthorized": the authority existed and the clock
                # ended it, which is a different repair than re-deciding whether it should exist.
                outcome, reasons = OUTCOME_EXPIRED, [REASON_STANDING_EXPIRED]
            elif status != STATUS_ACTIVE:
                outcome, reasons = OUTCOME_NO_AUTHORITY, [f"AUTHORIZATION_{status}"]
            else:
                authorization = get_standing_authorization(db_path, standing_auth_id)
                budget_ref = authorization.resource_budget_ref
                from ciph.kernel.standing_authorization import RISK_LEVELS, assert_work_permitted
                try:
                    assert_work_permitted(db_path, standing_auth_id=standing_auth_id,
                                          work_class=intent.work_class, risk_class=intent.risk_class,
                                          requested_scope=intent.requested_scope, now=moment)
                except CrucibleError as refused:
                    if refused.reason in (REASON_RISK_CEILING,):
                        outcome, reasons = OUTCOME_RISK, [refused.reason]
                    else:
                        outcome, reasons = OUTCOME_NO_AUTHORITY, [refused.reason]

    if outcome is None and budget_ref is not None:
        status = budget_status(db_path, budget_ref, now=moment)
        if status.remaining <= 0.0:
            outcome, reasons = OUTCOME_RESOURCE, [REASON_EXHAUSTED]

    if outcome is None:
        conflict = _conflicting_work(db_path, intent, now=moment)
        if conflict is not None:
            outcome, reasons = OUTCOME_CONFLICT, [f"SESSION_OPEN:{conflict}"]

    if outcome is None:
        if basis != intent.trigger_basis_digest:
            outcome, reasons = OUTCOME_STALE_BASIS, ["TRIGGER_BASIS_MOVED"]
        else:
            outcome, reasons = OUTCOME_ELIGIBLE, ["ELIGIBLE"]

    decision = EligibilityDecision(
        intent_id=intent_id, outcome=str(outcome), reason_codes=tuple(reasons),
        standing_auth_id=standing_auth_id, budget_ref=budget_ref, basis_digest=basis,
        stop_reason=_STOP_BY_OUTCOME.get(str(outcome)))
    if record:
        record_intent_decision(db_path, intent_id=intent_id, outcome=decision.outcome,
                               basis_digest=basis, now=moment)
    return decision


def eligibility_digest(db_path: str, *, now: Optional[float] = None) -> str:
    from ciph.kernel.autonomous_work import work_intent_history
    decisions = [evaluate_eligibility(db_path, intent_id=intent.intent_id, now=now, record=False)
                 for intent in work_intent_history(db_path)]
    return digest({"version": AUTONOMY_ELIGIBILITY_V1,
                   "decisions": [decision.as_dict() for decision in decisions]})
