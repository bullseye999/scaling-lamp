"""
ciph.kernel.governed_investigation - how curiosity finally causes something, through the ONE throat.

4.4 Gate Three.

    uncertainty -> priority -> proposal -> governance decision
        -> logical action (allocated by the canonical mission layer)
        -> permit (minted ONLY by the central authority)
        -> GuardedExecutor
        -> Observation

There is deliberately no second executor, no curiosity signer and no curiosity permit path. This
module contains no signing key, no `ExecutionAuthority`, and no `PermitStore.claim`; the ONE authority
step it performs is a call to the canonical producer entry point, `acquire_durable_permit`, exactly as
any other producer does.

LAWS (each has a specimen in `test_gate_4_4_governed_investigation.py`)

 1. All external investigation uses the existing execution authority system.
 2. Curiosity has no private signer.
 3. Curiosity has no PermitStore.claim path.
 4. Curiosity cannot bypass mission/authorization boundaries (an ACCEPTED proposal is required).
 5. Investigation results enter as Observation first, not as conclusions.
 6. Failed investigation != disproven hypothesis.
 7. No-result investigation fabricates no epistemic evidence.
 8. Investigation side effects obey normal effect-certainty/reconciliation rules.
 9. Curiosity retries obey the normal A' generation law.
10. Restart cannot duplicate an investigation already claimed or resolved.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from ciph.kernel.continuity import ContinuityState, reconstruct
from ciph.kernel.curiosity_proposal import (
    STATUS_ACCEPTED,
    get_proposal,
    proposal_status,
)
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.execution_gateway import ExecutionRequest
from ciph.kernel.missions import (
    PLAN_COVERAGE_PATCH,
    NewActionProposal,
    PlanProposal,
    apply_plan_proposal,
    open_mission,
    reconstruct_missions,
)
from ciph.kernel.permit_composition import acquire_durable_permit

ROUTE = "curiosity.investigation"
STEP_ID = "step_investigation"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_curiosity_investigation_actions (
        proposal_id TEXT PRIMARY KEY,
        mission_id TEXT NOT NULL,
        logical_action_id TEXT NOT NULL,
        capability TEXT NOT NULL,
        params_json TEXT,
        job_id TEXT NOT NULL,
        prepared_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_curiosity_investigation_authorizations (
        proposal_id TEXT NOT NULL,
        job_id TEXT NOT NULL,
        permit_id TEXT,
        authorized_at REAL,
        PRIMARY KEY (proposal_id, job_id)
    );
    """,
)


class GovernedInvestigationError(Exception):
    """A governed-investigation operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class PreparedInvestigation:
    proposal_id: str
    mission_id: str
    logical_action_id: str
    capability: str
    params: Mapping[str, Any]
    job_id: str

    def as_dict(self) -> Dict[str, Any]:
        return {"proposal_id": self.proposal_id, "mission_id": self.mission_id,
                "logical_action_id": self.logical_action_id, "capability": self.capability,
                "params": dict(self.params), "job_id": self.job_id}


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            pass
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _job_id_for(proposal_id: str) -> str:
    """
    A DETERMINISTIC job id per proposal (law 10).

    Because the id - and the idempotency key built from it - are stable, a restart that re-runs the
    authorization path lands on the SAME investigation rather than starting a second one.
    """
    return "CIJOB-" + hashlib.sha256(proposal_id.encode("utf-8")).hexdigest()[:12].upper()


def investigation_action(db_path: str, proposal_id: str) -> Optional[Dict[str, Any]]:
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute(
            "SELECT * FROM ciph_curiosity_investigation_actions WHERE proposal_id = ?;",
            (proposal_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    return dict(row) if row is not None else None


def prepare_investigation(db_path: str, *, proposal_id: str, capability: str,
                          params: Optional[Mapping[str, Any]] = None,
                          objective: Optional[str] = None, mission_id: Optional[str] = None,
                          now: Optional[float] = None) -> PreparedInvestigation:
    """
    Turn an ACCEPTED proposal into a mission plus a genuinely NEW logical action (laws 1-4).

    The identity comes from the canonical mission layer, never from the caller and never from the
    model, so a proposal cannot smuggle in a familiar-looking action id. This creates NO job and NO
    permit: `authorize_and_enqueue` is the only step that can do that.
    """
    moment = time.time() if now is None else float(now)
    status = proposal_status(db_path, proposal_id, now=moment)
    if status != STATUS_ACCEPTED:
        raise GovernedInvestigationError("PROPOSAL_NOT_ACCEPTED", f"{proposal_id}:{status}")
    existing = investigation_action(db_path, proposal_id)
    if existing is not None:
        return PreparedInvestigation(
            proposal_id=proposal_id, mission_id=str(existing["mission_id"]),
            logical_action_id=str(existing["logical_action_id"]),
            capability=str(existing["capability"]),
            params=json.loads(existing["params_json"] or "{}"), job_id=str(existing["job_id"]))

    proposal = get_proposal(db_path, proposal_id)
    mission = mission_id or open_mission(
        db_path, objective=objective or f"reduce uncertainty {proposal.uncertainty_id}", now=moment)
    state = reconstruct_missions(db_path, now=moment).state_of(mission)
    if state is None:
        raise GovernedInvestigationError("UNKNOWN_MISSION", mission)
    result = apply_plan_proposal(db_path, PlanProposal(
        mission_id=mission, basis_continuity_digest=state.canonical_digest(),
        objective=objective, coverage=PLAN_COVERAGE_PATCH,
        new_action_proposals=(NewActionProposal(capability=capability,
                                                parameters=dict(params or {}),
                                                label=f"curiosity:{proposal_id}"),),
        rationale=f"curiosity proposal {proposal_id}"), now=moment)
    logical_action_id = result["new_actions"][0][0]
    job_id = _job_id_for(proposal_id)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute(
            "INSERT INTO ciph_curiosity_investigation_actions (proposal_id, mission_id, "
            "logical_action_id, capability, params_json, job_id, prepared_at) VALUES (?,?,?,?,?,?,?);",
            (proposal_id, mission, logical_action_id, capability,
             json.dumps(dict(params or {})), job_id, moment),
        )
        conn.commit()
    finally:
        conn.close()
    return PreparedInvestigation(proposal_id=proposal_id, mission_id=mission,
                                 logical_action_id=logical_action_id, capability=capability,
                                 params=dict(params or {}), job_id=job_id)


def build_investigation_request(db_path: str, proposal_id: str, *,
                                now: Optional[float] = None) -> ExecutionRequest:
    """
    The canonical REQUEST for the investigation's logical action. Grants nothing: it is data.

    No scope grant is attached, which is also the honest minimum: curiosity asks for exactly one
    action, not a capability-wide or target-wide permission.
    """
    prepared = investigation_action(db_path, proposal_id)
    if prepared is None:
        raise GovernedInvestigationError("INVESTIGATION_NOT_PREPARED", proposal_id)
    params = json.loads(prepared["params_json"] or "{}")
    return ExecutionRequest(capability=str(prepared["capability"]), params=params,
                            target=params.get("target"), scope_grant=None,
                            logical_action_id=str(prepared["logical_action_id"]), route=ROUTE)


def authorize_and_enqueue(runtime, *, proposal_id: str,
                          now: Optional[float] = None) -> Dict[str, Any]:
    """
    THE ONLY authority step (laws 1-3, 8-10).

    It delegates to the canonical producer entry point for the permit and to the runtime's own queue
    and token mint. Nothing here signs a permit, mints an authority, or claims anything: a refusal by
    the central authority propagates and no job is enqueued.
    """
    moment = time.time() if now is None else float(now)
    prepared = investigation_action(runtime.db_path, proposal_id)
    if prepared is None:
        raise GovernedInvestigationError("INVESTIGATION_NOT_PREPARED", proposal_id)
    job_id = str(prepared["job_id"])
    request = build_investigation_request(runtime.db_path, proposal_id, now=moment)
    carriage = acquire_durable_permit(runtime.durable_permit_dependencies, request, job_id,
                                      claim_deadline=runtime.job_claim_deadline(now=moment),
                                      now=moment)
    if not carriage.accepted:
        raise GovernedInvestigationError("AUTHORITY_REFUSED", str(carriage.reason))
    plan_id = f"plan_curiosity_{prepared['logical_action_id']}"
    token = runtime.mint_execution_token(capability=request.capability, params=dict(request.params),
                                         plan_id=plan_id, step_id=STEP_ID)
    enqueued = runtime.queue.enqueue_job(
        capability=request.capability, params=dict(request.params), job_id=job_id,
        idempotency_key=job_id, plan_id=plan_id, step_id=STEP_ID, max_retries=1,
        execution_token=token, execution_permit=carriage.permit)
    permit_id = carriage.permit.payload.permit_id
    conn = _connect(runtime.db_path)
    try:
        init_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO ciph_curiosity_investigation_authorizations (proposal_id, "
            "job_id, permit_id, authorized_at) VALUES (?,?,?,?);",
            (proposal_id, str(enqueued), permit_id, moment),
        )
        conn.commit()
    finally:
        conn.close()
    return {"job_id": str(enqueued), "permit_id": permit_id,
            "logical_action_id": str(prepared["logical_action_id"]),
            "capability": request.capability}


def record_investigation_observation(db_path: str, *, source_ref: str, raw_text: str,
                                     observed_at: Optional[float] = None,
                                     now: Optional[float] = None) -> str:
    """
    What an investigation RETURNS: an Observation (law 5).

    Receiving a result does not make its contents true, so this writes an observation and never an
    evidence link. Whether the result bears on anything is a separate, epistemic decision taken by
    whoever has admissible evidence (law 7).
    """
    observation = record_observation(db_path, source_ref=source_ref, raw_text=raw_text,
                                     observed_at=observed_at, now=now)
    return str(observation["observation_id"])


def investigation_continuity(db_path: str, *, now: Optional[float] = None) -> ContinuityState:
    """The 4.1 truth about the investigation's attempt, reconstructed rather than remembered."""
    return reconstruct(db_path, now=now)


def investigation_digest(db_path: str) -> str:
    conn = _connect(db_path, read_only=True)
    try:
        actions = [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_curiosity_investigation_actions ORDER BY proposal_id;")]
        authorizations = [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_curiosity_investigation_authorizations "
            "ORDER BY proposal_id, job_id;")]
    except sqlite3.Error:
        actions, authorizations = [], []
    finally:
        conn.close()
    return _digest({"actions": actions, "authorizations": authorizations})
