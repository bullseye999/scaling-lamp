"""
ciph/kernel/autonomy_session - 5.0 Gates Three, Six, Nine (and 5.6/5.7/5.8 where they belong).

A daemon wake must be VISIBLE. A session answers: why did Ciph wake, what did it believe, what authority
did it hold, what did it attempt, what did it spend, and why did it stop.

Two laws from here carry the rest of 5.x:

    IDLENESS IS CONSTITUTIONAL. "Nothing worth doing right now" is a valid outcome, so autonomy does not
    degenerate into compulsive activity.

    AUTONOMY CANNOT PROMOTE. The continuous cycle may discover, hypothesise, generate and evaluate, and
    it stops at PROMOTION_READY for a human - because 4.5/R7 promotion is a separate, authorized act.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.autonomous_work import (
    STATUS_SATISFIED,
    TERMINAL_INTENT_STATUSES,
    get_work_intent,
    work_intent_status,
)
from ciph.kernel.autonomy_eligibility import (
    OUTCOME_ELIGIBLE,
    STOP_NO_USEFUL_NEXT_ACTION,
    STOP_OPERATOR_INTERRUPT,
    STOP_WORK_SATISFIED,
    VALID_STOP_REASONS,
    evaluate_eligibility,
)
from ciph.kernel.crucible_types import CrucibleError, digest

AUTONOMY_SESSION_V1 = "AUTONOMY_SESSION_V1"
AUTONOMY_IDLE_DECISION_V1 = "AUTONOMY_IDLE_DECISION_V1"
AUTONOMY_STATE_PROJECTION_V1 = "AUTONOMY_STATE_PROJECTION_V1"
AUTONOMY_CALIBRATION_V1 = "AUTONOMY_CALIBRATION_V1"

# 5.7 V1 ceiling: the broadest thing an autonomous cycle may reach on its own.
PROMOTION_READY = "PROMOTION_READY"

SESSION_OPEN = "OPEN"
SESSION_QUIESCING = "QUIESCING"
SESSION_CLOSED = "CLOSED"
SESSION_INTERRUPTED = "INTERRUPTED"
SESSION_FAILED = "FAILED"
VALID_SESSION_STATUSES = (SESSION_OPEN, SESSION_QUIESCING, SESSION_CLOSED, SESSION_INTERRUPTED,
                          SESSION_FAILED)

# 5.6: maintenance under standing authority. Updates are GOVERNED CHANGES, not maintenance.
MAINTENANCE_WORK_CLASSES: Tuple[str, ...] = ("MAINTENANCE_CHECK", "RUN_TEST_SUITE", "READ_REPOSITORY",
                                             "PRODUCE_REPORT", "RECOVERY_RECONCILE")
MAINTENANCE_EXCLUDES: Tuple[str, ...] = ("PRODUCTION_INSTALL", "META_PROMOTION", "KEY_ACCESS",
                                         "NETWORK_POST")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_sessions (
        session_id TEXT PRIMARY KEY,
        trigger_kind TEXT NOT NULL,
        trigger_ref TEXT,
        mission_id TEXT,
        standing_auth_id TEXT,
        basis_digest TEXT NOT NULL,
        status TEXT NOT NULL,
        opened_at REAL,
        closed_at REAL,
        stop_reason TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_session_work (
        work_item_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        intent_id TEXT NOT NULL,
        eligibility_outcome TEXT NOT NULL,
        job_id TEXT,
        attempt_ref TEXT,
        evidence_ref TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_idle_decisions (
        idle_id TEXT PRIMARY KEY,
        session_id TEXT,
        evaluated_work_count INTEGER NOT NULL,
        blocked_work_count INTEGER NOT NULL,
        eligible_work_count INTEGER NOT NULL,
        reason TEXT NOT NULL,
        next_review_at REAL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class AutonomySession:
    session_id: str
    trigger_kind: str
    trigger_ref: Optional[str]
    mission_id: Optional[str]
    standing_auth_id: Optional[str]
    basis_digest: str
    status: str
    stop_reason: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"session_id": self.session_id, "trigger_kind": self.trigger_kind,
                "trigger_ref": self.trigger_ref, "mission_id": self.mission_id,
                "standing_auth_id": self.standing_auth_id, "basis_digest": self.basis_digest,
                "status": self.status, "stop_reason": self.stop_reason}


@dataclass(frozen=True)
class IdleDecision:
    idle_id: str
    evaluated_work_count: int
    blocked_work_count: int
    eligible_work_count: int
    reason: str
    next_review_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"idle_id": self.idle_id, "evaluated_work_count": self.evaluated_work_count,
                "blocked_work_count": self.blocked_work_count,
                "eligible_work_count": self.eligible_work_count, "reason": self.reason,
                "next_review_at": self.next_review_at,
                "policy_version": AUTONOMY_IDLE_DECISION_V1}


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


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def open_session(db_path: str, *, trigger_kind: str, trigger_ref: Optional[str] = None,
                 mission_id: Optional[str] = None, standing_auth_id: Optional[str] = None,
                 basis_digest: Optional[str] = None,
                 now: Optional[float] = None) -> AutonomySession:
    """Open ONE durable session, so a wake is never invisible."""
    moment = time.time() if now is None else float(now)
    basis = basis_digest or digest({"trigger": str(trigger_kind), "ref": trigger_ref,
                                    "mission": mission_id})
    session_id = "AS-" + digest({"trigger": str(trigger_kind), "ref": trigger_ref,
                                 "mission": mission_id, "basis": basis,
                                 "opened_at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_sessions (session_id, trigger_kind, trigger_ref, "
            "mission_id, standing_auth_id, basis_digest, status, opened_at, closed_at, stop_reason) "
            "VALUES (?,?,?,?,?,?,?,?,?,?);",
            (session_id, str(trigger_kind), trigger_ref, mission_id, standing_auth_id, basis,
             SESSION_OPEN, moment, None, None))
        connection.commit()
    finally:
        connection.close()
    return get_session(db_path, session_id)


def record_session_work(db_path: str, *, session_id: str, intent_id: str,
                        eligibility_outcome: str, job_id: Optional[str] = None,
                        attempt_ref: Optional[str] = None, evidence_ref: Optional[str] = None,
                        now: Optional[float] = None) -> str:
    """Record what a session actually attempted, with the canonical refs that prove it."""
    get_session(db_path, session_id)
    moment = time.time() if now is None else float(now)
    work_item_id = "ASW-" + digest({"session": session_id, "intent": intent_id})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_session_work (work_item_id, session_id, intent_id, "
            "eligibility_outcome, job_id, attempt_ref, evidence_ref, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?);",
            (work_item_id, session_id, intent_id, str(eligibility_outcome), job_id, attempt_ref,
             evidence_ref, moment))
        if evidence_ref:
            # ONE logical work item, ONE row. Recording it again once its attempt resolved COMPLETES
            # the record instead of appending a second one - and the update only ever fills a gap, so
            # a resolution that has already been recorded is never overwritten by a later claim. This
            # is what makes "settle the boundary" decidable: an unresolved attempt can be resolved,
            # and a resolved one cannot be quietly re-opened.
            connection.execute(
                "UPDATE ciph_autonomy_session_work SET evidence_ref = ? "
                "WHERE work_item_id = ? AND evidence_ref IS NULL;", (str(evidence_ref), work_item_id))
        connection.commit()
    finally:
        connection.close()
    return work_item_id


def close_session(db_path: str, session_id: str, *, stop_reason: str,
                  status: str = SESSION_CLOSED, now: Optional[float] = None) -> AutonomySession:
    if stop_reason not in VALID_STOP_REASONS:
        raise CrucibleError("INVALID_STOP_REASON", str(stop_reason))
    if status not in VALID_SESSION_STATUSES:
        raise CrucibleError("INVALID_SESSION_STATUS", str(status))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_autonomy_sessions SET status = ?, stop_reason = ?, "
                           "closed_at = ? WHERE session_id = ?;", (status, stop_reason, moment,
                                                                   session_id))
        connection.commit()
    finally:
        connection.close()
    return get_session(db_path, session_id)


def close_with_idle(db_path: str, session_id: str, *, evaluated: int, blocked: int, eligible: int,
                    reason: str = STOP_NO_USEFUL_NEXT_ACTION, next_review_at: Optional[float] = None,
                    now: Optional[float] = None) -> IdleDecision:
    """
    GATE SIX: idleness is a constitutional outcome.

    A wake that finds nothing worth doing closes with NO_USEFUL_NEXT_ACTION. It does not invent an
    insight to justify its own existence.
    """
    moment = time.time() if now is None else float(now)
    idle_id = "IDL-" + digest({"session": session_id, "evaluated": int(evaluated),
                               "eligible": int(eligible), "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_idle_decisions (idle_id, session_id, "
            "evaluated_work_count, blocked_work_count, eligible_work_count, reason, "
            "next_review_at, recorded_at) VALUES (?,?,?,?,?,?,?,?);",
            (idle_id, session_id, int(evaluated), int(blocked), int(eligible), str(reason),
             next_review_at, moment))
        connection.commit()
    finally:
        connection.close()
    close_session(db_path, session_id, stop_reason=STOP_WORK_SATISFIED if eligible else
                  STOP_NO_USEFUL_NEXT_ACTION, now=moment)
    return IdleDecision(idle_id=idle_id, evaluated_work_count=int(evaluated),
                        blocked_work_count=int(blocked), eligible_work_count=int(eligible),
                        reason=str(reason), next_review_at=next_review_at)


def get_session(db_path: str, session_id: str) -> AutonomySession:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_autonomy_sessions WHERE session_id = ?;",
                                 (session_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_SESSION", session_id)
    row = dict(row)
    return AutonomySession(session_id=str(row["session_id"]),
                           trigger_kind=str(row["trigger_kind"]), trigger_ref=row["trigger_ref"],
                           mission_id=row["mission_id"], standing_auth_id=row["standing_auth_id"],
                           basis_digest=str(row["basis_digest"]), status=str(row["status"]),
                           stop_reason=row["stop_reason"])


def open_sessions(db_path: str) -> List[AutonomySession]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["session_id"]) for row in connection.execute(
            "SELECT session_id FROM ciph_autonomy_sessions WHERE status IN (?,?) "
            "ORDER BY opened_at, session_id;", (SESSION_OPEN, SESSION_QUIESCING))]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_session(db_path, session_id) for session_id in ids]


def session_history(db_path: str) -> List[AutonomySession]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["session_id"]) for row in connection.execute(
            "SELECT session_id FROM ciph_autonomy_sessions ORDER BY opened_at, session_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_session(db_path, session_id) for session_id in ids]


def session_work(db_path: str, session_id: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_autonomy_session_work WHERE session_id = ? ORDER BY rowid;",
            (session_id,))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def continuous_cycle(db_path: str, *, now: Optional[float] = None,
                     operator_priority_refs: Sequence[str] = ()) -> Dict[str, Any]:
    """
    5.7 — the loop, with its ceiling.

    Eligible work is returned for the caller to run through the normal 4.0 path. Improvement work stops
    at PROMOTION_READY: this function cannot promote, deploy or mint a permit, and a scanner asserts no
    autonomous module even names those calls.
    """
    from ciph.kernel.autonomous_work import due_for_reconsideration
    from ciph.kernel.autonomy_priority import arbitrate
    from ciph.kernel.autonomy_modes import assert_mode_permits
    moment = time.time() if now is None else float(now)
    due = due_for_reconsideration(db_path, now=moment)
    decisions = [evaluate_eligibility(db_path, intent_id=intent.intent_id, now=moment)
                 for intent in due]
    eligible = [decision for decision in decisions if decision.outcome == OUTCOME_ELIGIBLE]
    eligible_ids = [decision.intent_id for decision in eligible]
    ranked = arbitrate(db_path, intent_ids=eligible_ids, now=moment,
                       operator_priority_refs=operator_priority_refs)
    blocked = [decision for decision in decisions if decision.outcome != OUTCOME_ELIGIBLE]
    return {"evaluated": len(decisions), "eligible": eligible_ids, "blocked": len(blocked),
            "ranking": [decision.as_dict() for decision in ranked],
            "ceiling": PROMOTION_READY,
            "may_promote": False, "may_deploy": False,
            "idle": not eligible_ids}


def autonomy_state(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """
    GATE NINE: one projection that answers "why is Ciph doing this?" with the canonical chain, rather
    than "I decided it was useful".
    """
    from ciph.kernel.autonomous_work import work_intent_history
    from ciph.kernel.autonomy_modes import current_mode
    from ciph.kernel.standing_authorization import standing_authorizations
    moment = time.time() if now is None else float(now)
    chain = []
    for intent in work_intent_history(db_path):
        decision = evaluate_eligibility(db_path, intent_id=intent.intent_id, now=moment,
                                        record=False)
        chain.append({"intent_id": intent.intent_id, "origin_kind": intent.origin_kind,
                      "work_class": intent.work_class, "mission_id": intent.parent_mission_id,
                      "standing_auth_id": decision.standing_auth_id,
                      "eligibility": decision.outcome, "stop_reason": decision.stop_reason,
                      "budget_ref": decision.budget_ref})
    return {"mode": current_mode(db_path),
            "open_sessions": [session.session_id for session in open_sessions(db_path)],
            "standing_authorizations": [authorization.standing_auth_id
                                        for authorization in standing_authorizations(db_path)],
            "work_chain": chain, "idle": not any(item["eligibility"] == OUTCOME_ELIGIBLE
                                                 for item in chain)}


def autonomy_calibration(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """5.8: autonomy activity is not autonomy quality. Descriptive, with no scalar score."""
    from ciph.kernel.autonomy_eligibility import OUTCOME_ELIGIBLE as ELIGIBLE
    from ciph.kernel.autonomous_work import work_intent_history
    moment = time.time() if now is None else float(now)
    intents = work_intent_history(db_path)
    outcomes = [evaluate_eligibility(db_path, intent_id=intent.intent_id, now=moment, record=False)
                .outcome for intent in intents]
    sessions = session_history(db_path)
    connection = _connect(db_path, read_only=True)
    try:
        idle_count = int(connection.execute("SELECT COUNT(*) FROM ciph_autonomy_idle_decisions;")
                         .fetchone()[0])
    except sqlite3.Error:
        idle_count = 0
    finally:
        connection.close()
    return {"policy_version": AUTONOMY_CALIBRATION_V1, "intents": len(intents),
            "eligible": outcomes.count(ELIGIBLE),
            "blocked": len([outcome for outcome in outcomes if outcome != ELIGIBLE]),
            "stale_intents": len([intent for intent in intents
                                  if work_intent_status(db_path, intent.intent_id,
                                                        now=moment) not in
                                  TERMINAL_INTENT_STATUSES and
                                  work_intent_status(db_path, intent.intent_id,
                                                     now=moment) == STATUS_SATISFIED]),
            "sessions": len(sessions), "idle_decisions": idle_count,
            "interrupted_sessions": len([session for session in sessions
                                         if session.status == SESSION_INTERRUPTED]),
            "no_score": True}


def autonomy_session_digest(db_path: str) -> str:
    return digest({"version": AUTONOMY_SESSION_V1,
                   "sessions": [session.as_dict() for session in session_history(db_path)]})
