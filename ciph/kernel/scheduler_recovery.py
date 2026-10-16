"""
ciph/kernel/scheduler_recovery - reconstruct what may run next.

4.1 Gate Three. The scheduler is deliberately stupid. It keeps no truth of its own and can only run
what canonical reconstruction says is eligible:

    reconstruct truth            (Gate Zero)
    -> reconstruct missions      (Gate One)
    -> current plan projection   (Gate Two)
    -> derive eligible actions
    -> resume

Eligibility is a function of canonical action state and authority, NEVER of "the old scheduler had a
timer for it". That inversion is the whole point: the failure mode this prevents is a resumed
scheduler asserting that work exists because it remembered scheduling it.

    TERMINAL                       -> never eligible
    UNRESOLVED / UNKNOWN           -> reconciliation, not dispatch
    RESOLVED_BY_OPERATOR           -> not eligible; trying again means a genuinely NEW action
    NOT_ATTEMPTED + live permit    -> ELIGIBLE (when a runnable carrier exists)
    NOT_ATTEMPTED + dead authority -> NEEDS_NEW_AUTHORITY; nothing is dispatched on its behalf
    live permit, no runnable job   -> NEEDS_NEW_CARRIER; the action is fine, its carrier is not
    omitted from the current plan  -> NOT_IN_CURRENT_PLAN; still authorized, just not scheduled

A plan can therefore *pause* work by omission, and cannot do anything stronger than that: omission
neither cancels nor revokes (Gate Two, law 19).
"""

from dataclasses import dataclass
from enum import Enum
import time
from typing import Callable, Dict, List, Optional, Tuple

from ciph.kernel.continuity import ActionContinuity
from ciph.kernel.missions import MissionState, reconstruct_missions

RUNNABLE_JOB_STATES = ("QUEUED", "RETRYING")


class Eligibility(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    TERMINAL = "TERMINAL"
    RESOLVED_BY_OPERATOR = "RESOLVED_BY_OPERATOR"
    NEEDS_NEW_AUTHORITY = "NEEDS_NEW_AUTHORITY"
    NEEDS_NEW_CARRIER = "NEEDS_NEW_CARRIER"
    NOT_IN_CURRENT_PLAN = "NOT_IN_CURRENT_PLAN"


@dataclass(frozen=True)
class ActionEligibility:
    logical_action_id: str
    mission_id: Optional[str]
    capability: Optional[str]
    job_id: Optional[str]
    job_status: Optional[str]
    permit_state: str
    attempt_outcome: str
    eligibility: str
    reason: str

    @property
    def dispatchable(self) -> bool:
        return self.eligibility == Eligibility.ELIGIBLE.value

    def as_dict(self) -> Dict[str, object]:
        return {
            "logical_action_id": self.logical_action_id,
            "mission_id": self.mission_id,
            "capability": self.capability,
            "job_id": self.job_id,
            "job_status": self.job_status,
            "permit_state": self.permit_state,
            "attempt_outcome": self.attempt_outcome,
            "eligibility": self.eligibility,
            "reason": self.reason,
        }


def _classify(action: ActionContinuity, *, in_current_plan: bool, has_current_plan: bool,
               consumption_pending: bool) -> Tuple[Eligibility, str]:
    """One action's eligibility, from canonical state only."""
    if action.attempt_outcome == "TERMINAL":
        return Eligibility.TERMINAL, "the attempt is resolved with machine evidence"
    if action.attempt_outcome in ("UNRESOLVED", "UNKNOWN"):
        return (Eligibility.RECONCILIATION_REQUIRED,
                "the attempt was spent and its outcome is unresolved; reconciliation, not dispatch")
    if action.attempt_outcome == "RESOLVED_BY_OPERATOR":
        return (Eligibility.RESOLVED_BY_OPERATOR,
                "a human resolved this attempt; retrying requires a new action, not this one")
    if consumption_pending:
        return (Eligibility.RECONCILIATION_REQUIRED,
                "the attempt is resolved but its permit is not yet consumed; complete it first")

    # From here the attempt is NOT_ATTEMPTED.
    if action.authorization_alive:
        if action.job_status in RUNNABLE_JOB_STATES:
            if has_current_plan and not in_current_plan:
                return (Eligibility.NOT_IN_CURRENT_PLAN,
                        "the current projection does not schedule this action; it is not cancelled")
            return Eligibility.ELIGIBLE, "authority is live and the job is runnable"
        return (Eligibility.NEEDS_NEW_CARRIER,
                f"authority is live but the job is {action.job_status or 'absent'}; it needs a carrier")
    return (Eligibility.NEEDS_NEW_AUTHORITY,
            f"authority is {action.permit_state}; running again needs new central authorisation")


def derive_eligibility(db_path: str, *, now: Optional[float] = None) -> Tuple[ActionEligibility, ...]:
    """Every mission action, classified. Read-only; decides nothing, dispatches nothing."""
    moment = time.time() if now is None else float(now)
    continuity = reconstruct_missions(db_path, now=moment)
    results: List[ActionEligibility] = []
    for mission in continuity.missions:
        scheduled = set(mission.plan_action_ids)
        has_current_plan = mission.current_plan_id is not None
        for action in mission.actions:
            eligibility, reason = _classify(
                action,
                in_current_plan=action.logical_action_id in scheduled,
                has_current_plan=has_current_plan,
                consumption_pending=action.consumption_pending,
            )
            results.append(ActionEligibility(
                logical_action_id=action.logical_action_id,
                mission_id=mission.mission_id,
                capability=action.capability,
                job_id=action.job_id,
                job_status=action.job_status,
                permit_state=action.permit_state,
                attempt_outcome=action.attempt_outcome,
                eligibility=eligibility.value,
                reason=reason,
            ))
        for action_id in mission.unauthorised_action_ids:
            results.append(ActionEligibility(
                logical_action_id=action_id,
                mission_id=mission.mission_id,
                capability=None,
                job_id=None,
                job_status=None,
                permit_state="NO_PERMIT",
                attempt_outcome="NOT_ATTEMPTED",
                eligibility=Eligibility.NEEDS_NEW_AUTHORITY.value,
                reason="planned work that has no canonical authority yet; planning grants nothing",
            ))
    return tuple(sorted(results, key=lambda e: (str(e.mission_id), e.logical_action_id)))


def recovered_dispatch_plan(db_path: str, *, now: Optional[float] = None) -> Tuple[ActionEligibility, ...]:
    """What a resumed scheduler may run right now: exactly the eligible actions, nothing else."""
    return tuple(e for e in derive_eligibility(db_path, now=now) if e.dispatchable)


def resume_eligible(db_path: str, *, dispatch: Callable[[ActionEligibility], bool],
                    now: Optional[float] = None) -> Tuple[str, ...]:
    """
    Hand each eligible action to `dispatch`, and return the job ids that were dispatched.

    The scheduler contributes no judgement: the set comes from `recovered_dispatch_plan`, and an
    action outside it is never offered to the dispatcher. `dispatch` returning False (a refusal, a
    lost lease) stops that one action and leaves the rest of the plan intact - recovery is not a
    transaction, it is a re-derivation.
    """
    dispatched: List[str] = []
    for action in recovered_dispatch_plan(db_path, now=now):
        if action.job_id is None:
            continue
        if dispatch(action):
            dispatched.append(action.job_id)
    return tuple(dispatched)
