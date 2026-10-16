"""
ciph/kernel/independent_expeditions - 10.9: durable investigations Ciph may choose to pursue.

    A system deciding that a question is worth investigating does not establish permission to investigate it.

WHAT AN EXPEDITION IS. A durable investigation managed through the EXISTING canonical owners: investigation
identity and proposals from 4.4 (`proposal_ref`), the uncertainty that motivated it from 4.4, authorization
from 5.x (`standing_authorization` + `autonomy_modes`), work from 6.x delegations, durable findings from 10.0,
relationships from 10.5, attention from 10.6 and anomalies from 10.8. This module owns the EXPEDITION - its
identity, lifecycle and checkpoints - and nothing else. It is not a second investigation database, a second
planner, a second curiosity priority, a work scheduler or a permit issuer.

SELECTING A QUESTION IS NOT AUTHORIZATION. `select_candidates` ranks questions using 4.4's OWN priority and
returns them marked `authorization_required: True` and `interestingness_is_not_authorization: True`. Nothing
here executes. `authorize_expedition` is where the real decision happens, and it is made by 5.x: the autonomy
MODE is consulted, the grant's STATUS is read, and `assert_work_permitted` decides the work class, the scope
and the risk ceiling. A refusal is recorded with the owner's exact reason and the expedition stays REFUSED.

AN EXPEDITION MAY NOT mint its own permit, expand its own authorization, renew an expired grant, change the
authority rules, scan an unapproved target, self-deploy, conceal resource use, or convert conversational
enthusiasm into standing execution authority.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

EXPEDITION_V1 = "EXPEDITION_V1"
EXPEDITION_LIFECYCLE_V1 = "EXPEDITION_LIFECYCLE_V1"
NOTIFICATION_CANDIDATE_V1 = "NOTIFICATION_CANDIDATE_V1"

PROPOSED = "PROPOSED"
ELIGIBLE = "ELIGIBLE"
ACTIVE = "ACTIVE"
PAUSED = "PAUSED"
INTERRUPTED = "INTERRUPTED"
COMPLETED = "COMPLETED"
INCONCLUSIVE = "INCONCLUSIVE"
FAILED = "FAILED"
REFUSED = "REFUSED"
EXPIRED = "EXPIRED"
AWAITING_OPERATOR = "AWAITING_OPERATOR"
LIFECYCLE = (PROPOSED, ELIGIBLE, ACTIVE, PAUSED, INTERRUPTED, COMPLETED, INCONCLUSIVE, FAILED, REFUSED,
             EXPIRED, AWAITING_OPERATOR)

# A transition table: a state may only move where the governing lifecycle actually permits it.
_ALLOWED_TRANSITIONS = {
    # Authorization IS the transition to work: a proposal that passes the owner's checks becomes ACTIVE.
    PROPOSED: (ELIGIBLE, ACTIVE, REFUSED, EXPIRED, AWAITING_OPERATOR),
    ELIGIBLE: (ACTIVE, REFUSED, EXPIRED, PAUSED, AWAITING_OPERATOR),
    ACTIVE: (PAUSED, INTERRUPTED, COMPLETED, INCONCLUSIVE, FAILED, EXPIRED, REFUSED),
    PAUSED: (ACTIVE, EXPIRED, INCONCLUSIVE, FAILED, REFUSED),
    INTERRUPTED: (ACTIVE, INCONCLUSIVE, FAILED, EXPIRED, REFUSED),
    AWAITING_OPERATOR: (ELIGIBLE, REFUSED, EXPIRED),
    REFUSED: (EXPIRED,),
    EXPIRED: (),
    COMPLETED: (),
    INCONCLUSIVE: (),
    FAILED: (),
}

REASON_NOT_AUTHORIZED = "NO_ACTIVE_STANDING_AUTHORIZATION"
REASON_UNKNOWN_EXPEDITION = "UNKNOWN_EXPEDITION"
REASON_INVALID_TRANSITION = "EXPEDITION_TRANSITION_NOT_PERMITTED"
REASON_NO_EXTERNAL_DELIVERY = "NO_EXTERNAL_NOTIFICATION_TRANSPORT_IS_WIRED"

CANDIDATE_UNCERTAINTY = "UNCERTAINTY"
CANDIDATE_ANOMALY = "HOMEOSTATIC_ANOMALY"
CANDIDATE_CONTRADICTION = "WORKER_CONTRADICTION"
CANDIDATE_ARCHITECTURAL = "ARCHITECTURAL_DISPUTE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_expeditions (
        expedition_id TEXT PRIMARY KEY,
        uncertainty_ref TEXT,
        proposal_ref TEXT,
        origin_question TEXT,
        domain TEXT,
        plan_ref TEXT,
        plan_version INTEGER NOT NULL,
        permitted_tools_json TEXT,
        resource_budget_ref TEXT,
        inference_budget INTEGER NOT NULL,
        tool_call_budget INTEGER NOT NULL,
        grant_ref TEXT,
        result_set_id TEXT,
        status TEXT NOT NULL,
        refusal_reason TEXT,
        created_at REAL NOT NULL,
        started_at REAL,
        ended_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_expedition_authorizations (
        decision_id TEXT PRIMARY KEY,
        expedition_id TEXT NOT NULL,
        grant_ref TEXT,
        work_class TEXT,
        risk_class TEXT,
        scope_json TEXT,
        authorized INTEGER NOT NULL,
        refusal_reason TEXT,
        detail_json TEXT,
        decided_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_expedition_checkpoints (
        checkpoint_id TEXT PRIMARY KEY,
        expedition_id TEXT NOT NULL,
        note TEXT,
        delegations_json TEXT,
        created_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_notification_candidates (
        candidate_id TEXT PRIMARY KEY,
        expedition_id TEXT NOT NULL,
        investigation_ref TEXT,
        finding_refs_json TEXT,
        confidence TEXT,
        uncertainty TEXT,
        relevance_reason TEXT,
        status TEXT NOT NULL,
        created_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
)


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            connection.row_factory = sqlite3.Row
            return connection
        except sqlite3.OperationalError:
            pass
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    return connection


def init_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        connection.execute(statement)


def _moment(now: Optional[float]) -> float:
    return time.time() if now is None else float(now)


def _rows(db_path: str, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def _write(db_path: str, query: str, params: Sequence[Any]) -> None:
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(query, tuple(params))
        connection.commit()
    finally:
        connection.close()


# ------------------------------------------------------------------ identity
def propose_expedition(db_path: str, *, uncertainty_ref: str, domain: str, origin_question: str,
                       plan_ref: Optional[str] = None, plan_version: int = 1,
                       permitted_tools: Sequence[str] = (), resource_budget_ref: Optional[str] = None,
                       inference_budget: int = 0, tool_call_budget: int = 0,
                       expires_at: Optional[float] = None, investigation_type: str = "EVIDENCE_GATHERING",
                       now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record a PROPOSED expedition bound to a 4.4 uncertainty and its canonical proposal.

    Proposing authorizes nothing: the expedition exists so the question has a durable identity, no more.
    """
    moment = _moment(now)
    proposal_ref = None
    try:
        from ciph.kernel.curiosity_proposal import propose_investigation
        proposal = propose_investigation(db_path, uncertainty_id=str(uncertainty_ref),
                                         investigation_type=investigation_type, now=moment)
        proposal_ref = proposal.proposal_id
    except Exception:
        proposal_ref = None  # a proposal is desirable, not required, for the expedition to exist
    expedition_id = "EXP-" + digest({"uncertainty": uncertainty_ref, "domain": domain,
                                     "question": origin_question, "at": moment})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_expeditions (expedition_id, uncertainty_ref, proposal_ref, "
                    "origin_question, domain, plan_ref, plan_version, permitted_tools_json, "
                    "resource_budget_ref, inference_budget, tool_call_budget, grant_ref, result_set_id, "
                    "status, refusal_reason, created_at, started_at, ended_at, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (expedition_id, str(uncertainty_ref), proposal_ref, str(origin_question), str(domain), plan_ref,
            int(plan_version), json.dumps(sorted(str(tool) for tool in permitted_tools)),
            resource_budget_ref, int(inference_budget), int(tool_call_budget), None, None, PROPOSED, None,
            moment, None, None, EXPEDITION_V1))
    return get_expedition(db_path, expedition_id)


def get_expedition(db_path: str, expedition_id: str) -> Dict[str, Any]:
    rows = _rows(db_path, "SELECT * FROM ciph_expeditions WHERE expedition_id = ?;", (str(expedition_id),))
    if not rows:
        raise CrucibleError(REASON_UNKNOWN_EXPEDITION, str(expedition_id))
    record = rows[0]
    record["permitted_tools"] = json.loads(record.pop("permitted_tools_json") or "[]")
    return record


def expeditions(db_path: str, *, status: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_expeditions"
    params: Sequence[Any] = ()
    if status is not None:
        query += " WHERE status = ?"
        params = (str(status),)
    query += " ORDER BY created_at, expedition_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["permitted_tools"] = json.loads(row.pop("permitted_tools_json") or "[]")
    return rows


def _transition(db_path: str, *, expedition_id: str, to_state: str, refusal_reason: Optional[str] = None,
                now: Optional[float] = None, **columns: Any) -> Dict[str, Any]:
    moment = _moment(now)
    record = get_expedition(db_path, expedition_id)
    current = str(record["status"])
    if to_state not in LIFECYCLE:
        raise CrucibleError("UNKNOWN_EXPEDITION_STATE", str(to_state))
    if to_state != current and to_state not in _ALLOWED_TRANSITIONS.get(current, ()):
        raise CrucibleError(REASON_INVALID_TRANSITION, f"{current}->{to_state}")
    assignments = ["status = ?", "refusal_reason = ?"]
    values: List[Any] = [str(to_state), refusal_reason]
    for column, value in columns.items():
        assignments.append(f"{column} = ?")
        values.append(value)
    if to_state == ACTIVE and record["started_at"] is None:
        assignments.append("started_at = ?")
        values.append(moment)
    if to_state in (COMPLETED, INCONCLUSIVE, FAILED, REFUSED, EXPIRED):
        assignments.append("ended_at = ?")
        values.append(moment)
    values.append(str(expedition_id))
    _write(db_path, f"UPDATE ciph_expeditions SET {', '.join(assignments)} WHERE expedition_id = ?;",
           tuple(values))
    return get_expedition(db_path, expedition_id)


# ------------------------------------------------------------------ the authorization boundary
def authorize_expedition(db_path: str, *, expedition_id: str, grant_ref: str, work_class: str,
                         risk_class: str = "LOW", requested_scope: Sequence[str] = (),
                         actor: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """
    THE boundary. Resolve the ACTUAL standing authorization through 5.x and record its decision.

    Order matters for the sentence it makes: the autonomy MODE is consulted first (it can only ever be more
    restrictive than the grant), then the grant's STATUS, then the owner's own scope/class/risk check.
    """
    moment = _moment(now)
    record = get_expedition(db_path, expedition_id)
    decision_id = "EXA-" + digest({"expedition": expedition_id, "grant": grant_ref, "at": moment})[:16].upper()
    authorized = False
    refusal_reason: Optional[str] = None
    detail: Dict[str, Any] = {"grant_ref": str(grant_ref), "work_class": str(work_class),
                              "risk_class": str(risk_class), "scope": sorted(str(s) for s in requested_scope)}
    try:
        from ciph.kernel.autonomy_modes import assert_mode_permits, current_mode
        detail["autonomy_mode"] = current_mode(db_path)
        assert_mode_permits(db_path, external_effect=True, risk_class=str(risk_class))
    except CrucibleError as blocked:
        refusal_reason = blocked.reason
        detail["blocked_by"] = "5.x autonomy mode"
    if refusal_reason is None:
        from ciph.kernel.standing_authorization import STATUS_ACTIVE, authorization_status
        status = authorization_status(db_path, str(grant_ref), now=moment)
        detail["authorization_status"] = status
        if status != STATUS_ACTIVE:
            refusal_reason = REASON_NOT_AUTHORIZED
        else:
            from ciph.kernel.standing_authorization import assert_work_permitted
            try:
                assert_work_permitted(db_path, standing_auth_id=str(grant_ref), work_class=str(work_class),
                                      risk_class=str(risk_class), requested_scope=list(requested_scope),
                                      now=moment)
                authorized = True
            except CrucibleError as refused:
                refusal_reason = refused.reason
                detail["owner_detail"] = refused.detail

    _write(db_path, "INSERT OR IGNORE INTO ciph_expedition_authorizations (decision_id, expedition_id, "
                    "grant_ref, work_class, risk_class, scope_json, authorized, refusal_reason, detail_json, "
                    "decided_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
           (decision_id, str(expedition_id), str(grant_ref), str(work_class), str(risk_class),
            json.dumps(sorted(str(s) for s in requested_scope)), 1 if authorized else 0, refusal_reason,
            json.dumps(detail, sort_keys=True, default=str), moment, EXPEDITION_LIFECYCLE_V1))
    if not authorized:
        _transition(db_path, expedition_id=expedition_id, to_state=REFUSED, refusal_reason=refusal_reason,
                    now=moment)
        return {"decision_id": decision_id, "authorized": False, "refusal_reason": refusal_reason,
                "detail": detail, "status": REFUSED, "executed": False,
                "expands_own_authorization": False, "policy_version": EXPEDITION_LIFECYCLE_V1}
    _transition(db_path, expedition_id=expedition_id, to_state=ACTIVE, refusal_reason=None, now=moment,
                grant_ref=str(grant_ref))
    return {"decision_id": decision_id, "authorized": True, "status": ACTIVE, "detail": detail,
            "executed": True, "policy_version": EXPEDITION_LIFECYCLE_V1}


def authorization_decisions(db_path: str, *, expedition_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_expedition_authorizations"
    params: Sequence[Any] = ()
    if expedition_id is not None:
        query += " WHERE expedition_id = ?"
        params = (str(expedition_id),)
    query += " ORDER BY decided_at, decision_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["authorized"] = bool(row["authorized"])
        row["scope"] = json.loads(row.pop("scope_json") or "[]")
        row["detail"] = json.loads(row.pop("detail_json") or "{}")
    return rows


def revalidate(db_path: str, *, expedition_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Re-check a long-running expedition against its grant. An expired or revoked permission stops the work -
    it is never silently continued, and the expedition never renews itself.
    """
    record = get_expedition(db_path, expedition_id)
    if not record.get("grant_ref"):
        return {"expedition_id": str(expedition_id), "valid": False, "reason": REASON_NOT_AUTHORIZED,
                "renews_itself": False}
    from ciph.kernel.standing_authorization import STATUS_ACTIVE, authorization_status
    status = authorization_status(db_path, str(record["grant_ref"]), now=_moment(now))
    if status != STATUS_ACTIVE:
        _transition(db_path, expedition_id=expedition_id, to_state=REFUSED, refusal_reason=REASON_NOT_AUTHORIZED,
                    now=now)
        return {"expedition_id": str(expedition_id), "valid": False, "authorization_status": status,
                "reason": REASON_NOT_AUTHORIZED, "renews_itself": False, "status": REFUSED}
    return {"expedition_id": str(expedition_id), "valid": True, "authorization_status": status,
            "renews_itself": False}


# ------------------------------------------------------------------ work, checkpoints, results
def dispatch(db_path: str, *, expedition_id: str, worker_id: str, task_identity: str,
             allowed_work_class: str, required_capabilities: Sequence[str] = (),
             now: Optional[float] = None) -> Dict[str, Any]:
    """Delegate through the EXISTING 6.x path - and only from an AUTHORIZED, ACTIVE expedition."""
    moment = _moment(now)
    record = get_expedition(db_path, expedition_id)
    if str(record["status"]) != ACTIVE:
        raise CrucibleError("EXPEDITION_NOT_ACTIVE", f"{expedition_id}:{record['status']}")
    from ciph.kernel.swarm_delegation import claim_delegation, propose_delegation
    delegation = propose_delegation(db_path, task_identity=str(task_identity),
                                    input_digest=f"IN-{task_identity}", basis_digest=f"BAS-{task_identity}",
                                    allowed_work_class=str(allowed_work_class),
                                    required_capabilities=list(required_capabilities), now=moment)
    from ciph.kernel.swarm_worker import worker_generation
    generation = worker_generation(db_path, str(worker_id)) or 1
    lease = claim_delegation(db_path, delegation.delegation_id, worker_id=str(worker_id),
                             worker_generation=generation, input_digest=delegation.input_digest,
                             lease_seconds=120.0, now=moment)
    return {"expedition_id": str(expedition_id), "delegation_id": delegation.delegation_id,
            "lease_id": lease.lease_id if hasattr(lease, "lease_id") else None,
            "worker_id": str(worker_id), "mints_a_permit": False,
            "policy_version": EXPEDITION_V1}


def checkpoint(db_path: str, *, expedition_id: str, note: str, delegations: Sequence[str] = (),
               now: Optional[float] = None) -> Dict[str, Any]:
    moment = _moment(now)
    get_expedition(db_path, expedition_id)
    checkpoint_id = "EXC-" + digest({"expedition": expedition_id, "note": note, "at": moment})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_expedition_checkpoints (checkpoint_id, expedition_id, note, "
                    "delegations_json, created_at, policy_version) VALUES (?,?,?,?,?,?);",
           (checkpoint_id, str(expedition_id), str(note), json.dumps(sorted(str(d) for d in delegations)),
            moment, EXPEDITION_V1))
    return {"checkpoint_id": checkpoint_id, "expedition_id": str(expedition_id), "note": str(note),
            "created_at": moment, "policy_version": EXPEDITION_V1}


def checkpoints(db_path: str, *, expedition_id: str) -> List[Dict[str, Any]]:
    rows = _rows(db_path, "SELECT * FROM ciph_expedition_checkpoints WHERE expedition_id = ? "
                          "ORDER BY created_at, checkpoint_id;", (str(expedition_id),))
    for row in rows:
        row["delegations"] = json.loads(row.pop("delegations_json") or "[]")
    return rows


def record_result(db_path: str, *, expedition_id: str, findings: Sequence[Dict[str, Any]],
                  note: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Commit durable findings through 10.0 and bind them to the expedition. Identity lives in 10.0; the
    expedition only REFERENCES it, so two expeditions with identical findings keep distinct identities.
    """
    moment = _moment(now)
    record = get_expedition(db_path, expedition_id)
    from ciph.kernel.referential_continuity import commit_result_set
    committed = commit_result_set(db_path, investigation_ref=f"EXPEDITION:{expedition_id}", findings=list(findings),
                                  note=note, now=moment)
    _write(db_path, "UPDATE ciph_expeditions SET result_set_id = ? WHERE expedition_id = ?;",
           (committed["result_set_id"], str(expedition_id)))
    return {"expedition_id": str(expedition_id), "result_set_id": committed["result_set_id"],
            "count": committed["count"], "revision": committed["revision"],
            "previous_result_set": record.get("result_set_id"), "policy_version": EXPEDITION_V1}


def lifecycle(db_path: str, *, expedition_id: str, to_state: str, refusal_reason: Optional[str] = None,
              now: Optional[float] = None) -> Dict[str, Any]:
    """Move the expedition through the EXISTING lifecycle states, refusing an impossible transition."""
    return _transition(db_path, expedition_id=expedition_id, to_state=to_state,
                       refusal_reason=refusal_reason, now=now)


def expire(db_path: str, *, expedition_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    return _transition(db_path, expedition_id=expedition_id, to_state=EXPIRED,
                       refusal_reason="the expedition window closed", now=now)


# ------------------------------------------------------------------ selection (interestingness != permission)
def select_candidates(db_path: str, *, limit: int = 10, now: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    Rank worthwhile QUESTIONS. It executes nothing and authorizes nothing.

    Ranking comes from 4.4's OWN curiosity priority (which itself "authorises nothing"), and the 10.8/10.5/10.4
    sources are appended with the same contract.
    """
    moment = _moment(now)
    candidates: List[Dict[str, Any]] = []
    try:
        from ciph.kernel.curiosity_priority import prioritise
        for priority in prioritise(db_path, now=moment):
            candidates.append({"kind": CANDIDATE_UNCERTAINTY, "ref": priority.uncertainty_id,
                               "score": getattr(priority, "score", None),
                               "reasons": list(getattr(priority, "reasons", ()) or ()),
                               "ranked_by": "4.4 curiosity priority"})
    except Exception:
        pass
    try:
        from ciph.kernel.operational_homeostasis import anomalies
        for anomaly in anomalies(db_path):
            candidates.append({"kind": CANDIDATE_ANOMALY, "ref": anomaly["anomaly_id"],
                               "score": None, "reasons": [anomaly["verdict"], anomaly["state"]],
                               "ranked_by": "10.8 homeostasis"})
    except Exception:
        pass
    try:
        from ciph.kernel.operational_awareness import contradictions
        for contradiction in contradictions(db_path, now=moment):
            candidates.append({"kind": CANDIDATE_CONTRADICTION, "ref": contradiction["subject_ref"],
                               "score": None, "reasons": [contradiction["kind"], contradiction["disposition"]],
                               "ranked_by": "10.5 operational awareness"})
    except Exception:
        pass
    for candidate in candidates:
        candidate["authorization_required"] = True
        candidate["interestingness_is_not_authorization"] = True
    return candidates[: int(limit)]


# ------------------------------------------------------------------ notification candidates
def create_notification_candidate(db_path: str, *, expedition_id: str, finding_refs: Sequence[str],
                                  confidence: str, uncertainty: str, relevance_reason: str,
                                  now: Optional[float] = None) -> Dict[str, Any]:
    """
    A durable, evidence-backed candidate for operator's attention. It is NOT a message: no transport is wired,
    and nothing here claims delivery.
    """
    moment = _moment(now)
    record = get_expedition(db_path, expedition_id)
    candidate_id = "NTC-" + digest({"expedition": expedition_id, "findings": sorted(map(str, finding_refs)),
                                    "at": moment})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_notification_candidates (candidate_id, expedition_id, "
                    "investigation_ref, finding_refs_json, confidence, uncertainty, relevance_reason, status, "
                    "created_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?);",
           (candidate_id, str(expedition_id), f"EXPEDITION:{expedition_id}",
            json.dumps(sorted(str(ref) for ref in finding_refs)), str(confidence), str(uncertainty),
            str(relevance_reason), "CANDIDATE", moment, NOTIFICATION_CANDIDATE_V1))
    return {"candidate_id": candidate_id, "expedition_id": str(expedition_id),
            "result_set_id": record.get("result_set_id"), "finding_refs": sorted(map(str, finding_refs)),
            "confidence": str(confidence), "uncertainty": str(uncertainty),
            "relevance_reason": str(relevance_reason), "status": "CANDIDATE",
            "external_delivery": False, "delivered": False, "policy_version": NOTIFICATION_CANDIDATE_V1}


def notification_candidates(db_path: str, *, expedition_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_notification_candidates"
    params: Sequence[Any] = ()
    if expedition_id is not None:
        query += " WHERE expedition_id = ?"
        params = (str(expedition_id),)
    query += " ORDER BY created_at, candidate_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["finding_refs"] = json.loads(row.pop("finding_refs_json") or "[]")
    return rows


def claim_external_delivery() -> Dict[str, Any]:
    """There is no real notification transport yet, and this refuses to pretend otherwise."""
    raise CrucibleError(REASON_NO_EXTERNAL_DELIVERY, "10.13 owns the Session adapter")


def expedition_digest(db_path: str) -> str:
    return digest({"expeditions": _rows(db_path, "SELECT expedition_id, status, grant_ref, result_set_id "
                                                  "FROM ciph_expeditions ORDER BY expedition_id;"),
                   "authorizations": _rows(db_path, "SELECT decision_id, expedition_id, authorized, "
                                                    "refusal_reason FROM ciph_expedition_authorizations "
                                                    "ORDER BY decision_id;"),
                   "checkpoints": _rows(db_path, "SELECT checkpoint_id, expedition_id FROM "
                                                 "ciph_expedition_checkpoints ORDER BY checkpoint_id;"),
                   "notifications": _rows(db_path, "SELECT candidate_id, status FROM "
                                                   "ciph_notification_candidates ORDER BY candidate_id;")})
