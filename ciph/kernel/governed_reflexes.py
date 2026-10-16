"""
ciph/kernel/governed_reflexes - 10.7: deterministic, versioned responses to CANONICAL state.

    A reflex applies a rule that ALREADY exists. It does not decide what should be true.

A reflex IS a predefined response to canonical state satisfying an explicitly versioned rule. It is NOT a
natural-language interpretation, a planner, a permit issuer, an emergency sovereign authority, an LLM
bypassing an authorization boundary, or a sensor executing commands.

    TRIGGERS MUST BE COMPUTABLE FROM CANONICAL STATE ALONE. If evaluating a trigger needs prose interpreted,
    the output is a hypothesis or an investigation request - not a reflex.

    ALL CONSEQUENTIAL ACTIONS GO THROUGH THE EXISTING AUTHORITY. This module never constructs, mints,
    broadens or impersonates a permit, and it does not own a second executor: where an owner already
    enforces something (6.x spawn governance, 5.x quiescence, 10.3 sensor status, 10.6 attention), the reflex
    ASKS that owner and records the owner's verdict. A reflex whose declared authority basis cannot be
    satisfied REFUSES and preserves the reason.

    DECISION IS NOT EFFECT. `ciph_reflex_decisions` records that a rule fired; `ciph_reflex_outcomes`
    records what the OWNER actually did. "REFLEX_TRIGGERED" never proves "PROTECTIVE_ACTION_EXECUTED", and a
    decision with no outcome is exactly what an interruption between the two looks like.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

GOVERNED_REFLEX_V1 = "GOVERNED_REFLEX_V1"
REFLEX_RULE_V1 = "REFLEX_RULE_V1"
REFLEX_DECISION_V1 = "REFLEX_DECISION_V1"
REFLEX_OUTCOME_V1 = "REFLEX_OUTCOME_V1"

RESOURCE_CEILING = "RESOURCE_CEILING"
WITNESS_MISSING = "WITNESS_MISSING"
QUIESCENCE_REQUEST = "QUIESCENCE_REQUEST"
INTEGRITY_DISPUTED = "INTEGRITY_DISPUTED"
AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
OBSERVATION_GAP = "OBSERVATION_GAP"
TRIGGER_KINDS = (RESOURCE_CEILING, WITNESS_MISSING, QUIESCENCE_REQUEST, INTEGRITY_DISPUTED,
                 AUTHORIZATION_EXPIRED, OBSERVATION_GAP)

TRIGGERED = "TRIGGERED"
NOT_TRIGGERED = "NOT_TRIGGERED"
REFUSED = "REFUSED"

ENFORCED_BY_OWNER = "ENFORCED_BY_OWNER"
NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"
REFUSED_BY_OWNER = "REFUSED_BY_OWNER"
FLAGGED_FOR_ATTENTION = "FLAGGED_FOR_ATTENTION"
MARKER_PRESERVED = "MARKER_PRESERVED"
REFUSAL_RECORDED = "REFUSAL_RECORDED"
NOT_MARKED = "NOT_MARKED"

REASON_NO_AUTHORITY = "NO_VALID_AUTHORIZATION_FOR_THIS_RESPONSE"
REASON_NOT_AN_OPERATOR = "THE_RESPONSE_OWNER_REQUIRES_AN_OPERATOR_ACTOR"
REASON_DUPLICATE = "IDEMPOTENT_REPLAY"
REASON_UNKNOWN_RULE = "UNKNOWN_REFLEX_RULE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_reflex_rules (
        rule_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        trigger_kind TEXT NOT NULL,
        trigger_params_json TEXT,
        evidence_source TEXT NOT NULL,
        subject_scope TEXT,
        freshness_ttl REAL NOT NULL,
        authority_basis TEXT NOT NULL,
        response_mechanism TEXT NOT NULL,
        response_target TEXT,
        response_actor TEXT,
        max_actions_per_window INTEGER NOT NULL,
        window_seconds REAL NOT NULL,
        retry_policy TEXT NOT NULL,
        failure_semantics TEXT NOT NULL,
        revocation_ref TEXT,
        contract_digest TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        registered_at REAL,
        PRIMARY KEY (rule_id, version)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_reflex_decisions (
        decision_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        rule_version INTEGER NOT NULL,
        subject_ref TEXT NOT NULL,
        trigger_satisfied INTEGER NOT NULL,
        trigger_evidence_json TEXT,
        evidence_ref TEXT,
        authority_basis TEXT,
        authority_ok INTEGER NOT NULL,
        decision TEXT NOT NULL,
        refusal_reason TEXT,
        decided_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_reflex_outcomes (
        outcome_id TEXT PRIMARY KEY,
        decision_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        response_mechanism TEXT NOT NULL,
        owner_ref TEXT,
        outcome TEXT NOT NULL,
        detail_json TEXT,
        recorded_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_reflex_actions (
        action_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        subject_ref TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        decision_id TEXT,
        executed_at REAL NOT NULL,
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


def _event(db_path: str, query: str, params: Sequence[Any]) -> None:
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(query, tuple(params))
        connection.commit()
    finally:
        connection.close()


# ------------------------------------------------------------------ the rule contract
def register_reflex(db_path: str, *, rule_id: str, trigger_kind: str, evidence_source: str,
                    authority_basis: str, response_mechanism: str, trigger_params: Optional[Dict[str, Any]] = None,
                    subject_scope: Optional[str] = None, freshness_ttl: float = 300.0,
                    response_target: Optional[str] = None, response_actor: Optional[str] = None,
                    max_actions_per_window: int = 1, window_seconds: float = 3600.0,
                    retry_policy: str = "NO_RETRY_AFTER_OUTCOME",
                    failure_semantics: str = "REFUSE_AND_PRESERVE_REASON",
                    revocation_ref: Optional[str] = None, version: int = 1,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    Declare every field a reflex must have, and refuse a silent contract change.

    Re-declaring the IDENTICAL contract is idempotent; changing it without a version bump is refused, because
    a silent rule change is a silent behaviour change.
    """
    if trigger_kind not in TRIGGER_KINDS:
        raise CrucibleError("UNKNOWN_TRIGGER_KIND", str(trigger_kind))
    moment = _moment(now)
    fields = {"trigger_kind": str(trigger_kind),
              "trigger_params": json.dumps(trigger_params or {}, sort_keys=True, default=str),
              "evidence_source": str(evidence_source), "subject_scope": subject_scope,
              "freshness_ttl": float(freshness_ttl), "authority_basis": str(authority_basis),
              "response_mechanism": str(response_mechanism), "response_target": response_target,
              "response_actor": response_actor, "max_actions_per_window": int(max_actions_per_window),
              "window_seconds": float(window_seconds), "retry_policy": str(retry_policy),
              "failure_semantics": str(failure_semantics), "revocation_ref": revocation_ref}
    contract_digest = digest(fields)
    key = str(rule_id).strip()
    existing = _rows(db_path, "SELECT contract_digest FROM ciph_reflex_rules WHERE rule_id = ? AND "
                              "version = ?;", (key, int(version)))
    if existing and str(existing[0]["contract_digest"]) != contract_digest:
        raise CrucibleError("REFLEX_CONTRACT_CHANGED_WITHOUT_A_VERSION", f"{key}:v{version}")
    _event(db_path, "INSERT OR IGNORE INTO ciph_reflex_rules (rule_id, version, trigger_kind, "
                    "trigger_params_json, evidence_source, subject_scope, freshness_ttl, authority_basis, "
                    "response_mechanism, response_target, response_actor, max_actions_per_window, "
                    "window_seconds, retry_policy, failure_semantics, revocation_ref, contract_digest, "
                    "policy_version, registered_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (key, int(version), fields["trigger_kind"], fields["trigger_params"], fields["evidence_source"],
            fields["subject_scope"], fields["freshness_ttl"], fields["authority_basis"],
            fields["response_mechanism"], fields["response_target"], fields["response_actor"],
            fields["max_actions_per_window"], fields["window_seconds"], fields["retry_policy"],
            fields["failure_semantics"], fields["revocation_ref"], contract_digest, REFLEX_RULE_V1,
            moment))
    return {"rule_id": key, "version": int(version), "contract_digest": contract_digest,
            "policy_version": REFLEX_RULE_V1, **{k: v for k, v in fields.items()
                                                 if k != "trigger_params"},
            "trigger_params": trigger_params or {}}


def reflex_rule(db_path: str, rule_id: str, version: Optional[int] = None) -> Dict[str, Any]:
    rows = _rows(db_path, "SELECT * FROM ciph_reflex_rules WHERE rule_id = ? AND version = ?;",
                 (str(rule_id), int(version))) if version is not None else \
        _rows(db_path, "SELECT * FROM ciph_reflex_rules WHERE rule_id = ? ORDER BY version DESC LIMIT 1;",
              (str(rule_id),))
    if not rows:
        raise CrucibleError(REASON_UNKNOWN_RULE, str(rule_id))
    rule = rows[0]
    rule["trigger_params"] = json.loads(rule.pop("trigger_params_json") or "{}")
    return rule


# ------------------------------------------------------------------ deterministic triggers
def evaluate(db_path: str, *, rule_id: str, subject_ref: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Evaluate the trigger FROM CANONICAL STATE ALONE. No prose, no model, no sensor label.

    `subject_ref` names the canonical subject (a sensor id, a component id, a grant id, a delegation id).
    """
    moment = _moment(now)
    rule = reflex_rule(db_path, rule_id)
    kind = rule["trigger_kind"]
    params = rule["trigger_params"]
    evidence: List[Dict[str, Any]] = []
    satisfied = False
    reason = "the canonical condition was not met"

    if kind in (RESOURCE_CEILING, QUIESCENCE_REQUEST):
        limit = int(params.get("limit", 3))
        window = float(params.get("window_seconds", 3600.0))
        from ciph.kernel.swarm_resources import spawn_events
        recent = [event for event in spawn_events(db_path)
                  if moment - float(event["recorded_at"]) <= window]
        satisfied = len(recent) >= limit
        evidence = [{"source": "6.x spawn events", "count": len(recent), "limit": limit,
                     "window_seconds": window}]
        reason = (f"{len(recent)} spawns in {window}s meets the {limit} ceiling" if satisfied
                  else f"{len(recent)} spawns in {window}s is below the {limit} ceiling")
    elif kind == WITNESS_MISSING:
        from ciph.kernel.sensory_fabric import sensor_status
        status = sensor_status(db_path, subject_ref, now=moment)
        satisfied = status["status"] not in ("LIVE", "REGISTERED")
        evidence = [{"source": "10.3 sensor status", **status}]
        reason = (f"sensor {subject_ref} has no fresh witness ({status['status']})" if satisfied
                  else f"sensor {subject_ref} has a fresh witness")
    elif kind == INTEGRITY_DISPUTED:
        from ciph.kernel.architectural_proprioception import DISPUTED, SOURCE, integrity_claim
        claim = integrity_claim(db_path, component_id=subject_ref, view=SOURCE, now=moment)
        satisfied = claim["status"] == DISPUTED
        evidence = [{"source": "10.4 integrity claim", **claim}]
        reason = "independent witnesses disagree" if satisfied else f"status is {claim['status']}"
    elif kind == AUTHORIZATION_EXPIRED:
        from ciph.kernel.standing_authorization import STATUS_ACTIVE, authorization_status
        status = authorization_status(db_path, subject_ref, now=moment)
        satisfied = status not in (STATUS_ACTIVE, "UNKNOWN")
        evidence = [{"source": "5.x standing authorization", "authorization_status": status}]
        reason = (f"authorization {subject_ref} is {status}" if satisfied
                  else f"authorization {subject_ref} is {status}")
    elif kind == OBSERVATION_GAP:
        from ciph.kernel.sensory_fabric import conflicts, gaps
        found = [dict(row) for row in gaps(db_path, sensor_id=subject_ref)]
        found += [dict(row) for row in conflicts(db_path, sensor_id=subject_ref)]
        satisfied = bool(found)
        evidence = [{"source": "10.3 gaps and conflicts", "count": len(found)}]
        reason = "an explicit gap or conflict marker exists" if satisfied else "no marker exists"

    return {"policy_version": REFLEX_DECISION_V1, "rule_id": rule_id, "rule_version": rule["version"],
            "subject_ref": str(subject_ref), "trigger_kind": kind, "satisfied": satisfied,
            "evidence": evidence, "reason": reason, "evaluated_at": moment,
            "computable_from_canonical_state": True, "used_the_model": False}


# ------------------------------------------------------------------ execution through OWNERS
def invoke(db_path: str, *, rule_id: str, subject_ref: str, authority_ref: Optional[str] = None,
           now: Optional[float] = None) -> Dict[str, Any]:
    """
    Decide (recorded), then ask the EXISTING owner to act (recorded separately), or refuse.

    The decision is written BEFORE the response, so an interruption between them is visible as a decision
    with no outcome rather than as a silent success.
    """
    moment = _moment(now)
    rule = reflex_rule(db_path, rule_id)
    result = evaluate(db_path, rule_id=rule_id, subject_ref=subject_ref, now=moment)
    decision_id = "RFD-" + digest({"rule": rule_id, "subject": subject_ref,
                                   "at": moment})[:16].upper()

    if not result["satisfied"]:
        _record_decision(db_path, decision_id=decision_id, rule=rule, subject_ref=subject_ref,
                         result=result, authority_ok=False, decision=NOT_TRIGGERED, refusal=None,
                         now=moment)
        return {"decision_id": decision_id, "decision": NOT_TRIGGERED, "outcome": None,
                "rule_id": rule_id, "trigger": result}

    # AUTHORITY. The declared basis must be satisfiable; a reflex never mints or impersonates one.
    authority_ok, refusal_reason, authority_detail = _check_authority(
        db_path, rule=rule, subject_ref=subject_ref, authority_ref=authority_ref, now=moment)
    if not authority_ok:
        _record_decision(db_path, decision_id=decision_id, rule=rule, subject_ref=subject_ref,
                         result=result, authority_ok=False, decision=REFUSED,
                         refusal=refusal_reason, now=moment)
        return {"decision_id": decision_id, "decision": REFUSED, "outcome": None, "rule_id": rule_id,
                "refusal_reason": refusal_reason, "authority_detail": authority_detail,
                "trigger": result, "effect_recorded": False}

    # IDEMPOTENCY. The same rule on the same subject inside the window is applied once.
    idempotency_key = f"{rule_id}:{subject_ref}:{int(moment // max(rule['window_seconds'], 1.0))}"
    if _rows(db_path, "SELECT 1 FROM ciph_reflex_actions WHERE idempotency_key = ?;", (idempotency_key,)):
        _record_decision(db_path, decision_id=decision_id, rule=rule, subject_ref=subject_ref,
                         result=result, authority_ok=True, decision=TRIGGERED,
                         refusal=REASON_DUPLICATE, now=moment)
        return {"decision_id": decision_id, "decision": TRIGGERED, "outcome": None, "rule_id": rule_id,
                "idempotent_replay": True, "refusal_reason": REASON_DUPLICATE, "trigger": result}

    _record_decision(db_path, decision_id=decision_id, rule=rule, subject_ref=subject_ref, result=result,
                     authority_ok=True, decision=TRIGGERED, refusal=None, now=moment)
    _event(db_path, "INSERT OR IGNORE INTO ciph_reflex_actions (action_id, rule_id, subject_ref, "
                    "idempotency_key, decision_id, executed_at, policy_version) VALUES (?,?,?,?,?,?,?);",
           ("RFA-" + digest({"key": idempotency_key})[:16].upper(), rule_id, subject_ref, idempotency_key,
            decision_id, moment, REFLEX_OUTCOME_V1))

    outcome = _ask_the_owner(db_path, rule=rule, subject_ref=subject_ref, authority_ref=authority_ref,
                             now=moment)
    outcome_id = "RFO-" + digest({"decision": decision_id})[:16].upper()
    _event(db_path, "INSERT OR IGNORE INTO ciph_reflex_outcomes (outcome_id, decision_id, rule_id, "
                    "response_mechanism, owner_ref, outcome, detail_json, recorded_at, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?);",
           (outcome_id, decision_id, rule_id, rule["response_mechanism"], outcome["owner_ref"],
            outcome["outcome"], json.dumps(outcome["detail"], sort_keys=True, default=str), moment,
            REFLEX_OUTCOME_V1))
    return {"decision_id": decision_id, "decision": TRIGGERED, "outcome_id": outcome_id,
            "rule_id": rule_id, "response_mechanism": rule["response_mechanism"],
            "owner_outcome": outcome["outcome"], "owner_ref": outcome["owner_ref"],
            "effect_recorded": True, "trigger": result, "detail": outcome["detail"]}


def _check_authority(db_path: str, *, rule: Dict[str, Any], subject_ref: str,
                     authority_ref: Optional[str], now: float) -> tuple:
    basis = str(rule["authority_basis"])
    if basis == "OPERATOR_ACTOR":
        actor = rule.get("response_actor") or ""
        if not str(actor).startswith("operator:"):
            return False, REASON_NOT_AN_OPERATOR, {"actor": actor, "owner": rule["response_mechanism"]}
        return True, None, {"actor": actor}
    if basis == "STANDING_AUTHORIZATION":
        reference = authority_ref or subject_ref
        from ciph.kernel.standing_authorization import STATUS_ACTIVE, authorization_status
        status = authorization_status(db_path, str(reference), now=now)
        if status != STATUS_ACTIVE:
            return False, REASON_NO_AUTHORITY, {"authorization_ref": str(reference), "status": status}
        return True, None, {"authorization_ref": str(reference), "status": status}
    if basis in ("EXISTING_OWNER_GUARD", "READ_ONLY_ASSERTION"):
        # The owner performs the enforcement; the reflex only asks. There is nothing to mint.
        return True, None, {"basis": basis, "owner": rule["response_mechanism"]}
    return False, REASON_NO_AUTHORITY, {"basis": basis}


def _ask_the_owner(db_path: str, *, rule: Dict[str, Any], subject_ref: str,
                   authority_ref: Optional[str], now: float) -> Dict[str, Any]:
    """
    ASK the existing owner. Its verdict is the effect; the reflex has none of its own.

    Every branch calls an owner that already exists. None of them mints, broadens or impersonates a permit.
    """
    kind = rule["trigger_kind"]
    params = rule["trigger_params"]
    if kind in (RESOURCE_CEILING, QUIESCENCE_REQUEST) and rule["response_mechanism"] == "SPAWN_GOVERNANCE":
        from ciph.kernel.swarm_resources import assert_spawn_allowed
        try:
            assert_spawn_allowed(db_path, limit=int(params.get("limit", 3)),
                                 window_seconds=float(params.get("window_seconds", 3600.0)),
                                 concurrency_limit=params.get("concurrency_limit"), now=now)
        except CrucibleError as refused:
            return {"owner_ref": "ciph/kernel/swarm_resources.py", "outcome": ENFORCED_BY_OWNER,
                    "detail": {"owner_refusal": refused.reason, "detail": refused.detail}}
        return {"owner_ref": "ciph/kernel/swarm_resources.py", "outcome": NO_ACTION_REQUIRED,
                "detail": {"note": "the owner's guard did not refuse"}}
    if kind == QUIESCENCE_REQUEST and rule["response_mechanism"] == "SWARM_QUIESCENCE":
        from ciph.kernel.swarm_quiescence import open_barrier
        try:
            barrier = open_barrier(db_path, actor=str(rule.get("response_actor") or ""),
                                   reason=rule.get("response_target") or "governed reflex", now=now)
        except CrucibleError as refused:
            return {"owner_ref": "ciph/kernel/swarm_quiescence.py", "outcome": REFUSED_BY_OWNER,
                    "detail": {"owner_refusal": refused.reason, "detail": refused.detail}}
        return {"owner_ref": "ciph/kernel/swarm_quiescence.py", "outcome": "BARRIER_OPENED_BY_OWNER",
                "detail": {"barrier_id": getattr(barrier, "barrier_id", None)}}
    if kind == WITNESS_MISSING:
        # 10.3 accepts STOPPED/FAILED/UNKNOWN for a deliberate mark; STALE is DERIVED from the freshness
        # TTL and must not be asserted. A missing witness is UNKNOWN - never "the subject failed".
        from ciph.kernel.sensory_fabric import UNKNOWN, mark_unavailable
        marked = mark_unavailable(db_path, sensor_id=subject_ref, reason="no fresh witness",
                                  status=UNKNOWN, now=now)
        return {"owner_ref": "ciph/kernel/sensory_fabric.py", "outcome": MARKER_PRESERVED,
                "detail": {"sensor_status": marked["status"], "subject_failed": marked["subject_failed"]}}
    if kind == INTEGRITY_DISPUTED:
        from ciph.kernel.selective_attention import submit
        queued = submit(db_path, subject_ref=f"integrity:{subject_ref}", sensor_kind="CHANGE",
                        evidence_ref=rule.get("response_target"), declared_severity=None, now=now)
        return {"owner_ref": "ciph/kernel/selective_attention.py", "outcome": FLAGGED_FOR_ATTENTION,
                "detail": {"attention_request": queued.get("request_id"),
                           "attention_category": queued.get("category")}}
    if kind == AUTHORIZATION_EXPIRED:
        from ciph.kernel.standing_authorization import authorization_status
        status = authorization_status(db_path, str(authority_ref or subject_ref), now=now)
        return {"owner_ref": "ciph/kernel/standing_authorization.py", "outcome": REFUSAL_RECORDED,
                "detail": {"authorization_status": status,
                           "note": "the expired grant is not resurrected and nothing is executed"}}
    if kind == OBSERVATION_GAP:
        from ciph.kernel.sensory_fabric import conflicts, gaps
        present = bool(gaps(db_path, sensor_id=subject_ref)) or \
            bool(conflicts(db_path, sensor_id=subject_ref))
        return {"owner_ref": "ciph/kernel/sensory_fabric.py",
                "outcome": MARKER_PRESERVED if present else NOT_MARKED,
                "detail": {"marker_present": present}}
    return {"owner_ref": None, "outcome": NO_ACTION_REQUIRED, "detail": {"note": "no response defined"}}


def _record_decision(db_path: str, *, decision_id: str, rule: Dict[str, Any], subject_ref: str,
                     result: Dict[str, Any], authority_ok: bool, decision: str,
                     refusal: Optional[str], now: float) -> None:
    evidence_ref = None
    for item in result["evidence"]:
        for candidate in ("arch_observation_id", "change_id", "event_id", "authorization_ref"):
            if item.get(candidate):
                evidence_ref = str(item[candidate])
                break
    _event(db_path, "INSERT OR IGNORE INTO ciph_reflex_decisions (decision_id, rule_id, rule_version, "
                    "subject_ref, trigger_satisfied, trigger_evidence_json, evidence_ref, authority_basis, "
                    "authority_ok, decision, refusal_reason, decided_at, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (decision_id, rule["rule_id"], int(rule["version"]), str(subject_ref),
            1 if result["satisfied"] else 0, json.dumps(result["evidence"], sort_keys=True, default=str),
            evidence_ref, rule["authority_basis"], 1 if authority_ok else 0, decision, refusal, now,
            REFLEX_DECISION_V1))


# ------------------------------------------------------------------ readers
def decisions(db_path: str, *, rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_reflex_decisions"
    params: Sequence[Any] = ()
    if rule_id is not None:
        query += " WHERE rule_id = ?"
        params = (str(rule_id),)
    query += " ORDER BY decided_at, decision_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["trigger_evidence"] = json.loads(row.pop("trigger_evidence_json") or "[]")
        row["trigger_satisfied"] = bool(row["trigger_satisfied"])
        row["authority_ok"] = bool(row["authority_ok"])
        row["is_an_effect"] = False
    return rows


def outcomes(db_path: str, *, rule_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_reflex_outcomes"
    params: Sequence[Any] = ()
    if rule_id is not None:
        query += " WHERE rule_id = ?"
        params = (str(rule_id),)
    query += " ORDER BY recorded_at, outcome_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["detail"] = json.loads(row.pop("detail_json") or "{}")
        row["is_an_effect"] = True
    return rows


def decisions_without_an_outcome(db_path: str) -> List[Dict[str, Any]]:
    """
    A TRIGGERED decision with no recorded outcome. This is what an interruption between deciding and
    recording looks like - it is reported, never silently repaired.
    """
    return _rows(db_path, "SELECT d.* FROM ciph_reflex_decisions d LEFT JOIN ciph_reflex_outcomes o "
                          "ON o.decision_id = d.decision_id WHERE d.decision = ? AND o.outcome_id IS NULL "
                          "ORDER BY d.decided_at;", (TRIGGERED,))


def reflex_digest(db_path: str) -> str:
    return digest({"rules": _rows(db_path, "SELECT rule_id, version, contract_digest FROM ciph_reflex_rules "
                                            "ORDER BY rule_id, version;"),
                   "decisions": _rows(db_path, "SELECT decision_id, rule_id, decision, refusal_reason "
                                               "FROM ciph_reflex_decisions ORDER BY decision_id;"),
                   "outcomes": _rows(db_path, "SELECT outcome_id, decision_id, outcome FROM "
                                              "ciph_reflex_outcomes ORDER BY outcome_id;")})
