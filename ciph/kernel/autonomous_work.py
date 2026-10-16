"""
ciph/kernel/autonomous_work - 5.0 Gate Zero (work identity) and 5.2 (temporal governance).

    AutonomousWorkIntent != Job != Permit != Execution

Identity is NOT the wake-up. Two scheduler ticks for the same purpose are ONE logical work identity, so a
duplicate trigger cannot duplicate work - the same rule 4.1 applied to retries, applied to autonomy.

TEMPORAL LAW (5.2): a schedule says when something may be RECONSIDERED, not that it must execute. The
window survives; the decision does not.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

AUTONOMOUS_WORK_INTENT_V1 = "AUTONOMOUS_WORK_INTENT_V1"
AUTONOMY_STOP_REASON_V1 = "AUTONOMY_STOP_REASON_V1"

ORIGIN_MISSION_CONTINUATION = "MISSION_CONTINUATION"
ORIGIN_SCHEDULED_REVIEW = "SCHEDULED_REVIEW"
ORIGIN_CURIOSITY = "CURIOSITY"
ORIGIN_MAINTENANCE = "MAINTENANCE"
ORIGIN_IMPROVEMENT = "IMPROVEMENT"
ORIGIN_MONITORING = "MONITORING"
ORIGIN_RECOVERY = "RECOVERY"
VALID_ORIGIN_KINDS = (ORIGIN_MISSION_CONTINUATION, ORIGIN_SCHEDULED_REVIEW, ORIGIN_CURIOSITY,
                      ORIGIN_MAINTENANCE, ORIGIN_IMPROVEMENT, ORIGIN_MONITORING, ORIGIN_RECOVERY)

# work class -> (declared risk class, external effect). The CLASS decides its risk, not the caller: an
# intent cannot lower its own risk by asserting a friendlier label.
WORK_CLASSES: Dict[str, Tuple[str, bool]] = {
    "READ_REPOSITORY": ("LOW", False),
    "RUN_TEST_SUITE": ("LOW", False),
    "PRODUCE_REPORT": ("NONE", False),
    "INVESTIGATE_UNCERTAINTY": ("LOW", False),
    "GENERATE_CANDIDATE": ("LOW", False),
    "EVALUATE_CANDIDATE": ("LOW", False),
    "META_DISCOVERY": ("LOW", False),
    "MAINTENANCE_CHECK": ("LOW", False),
    "RECOVERY_RECONCILE": ("LOW", False),
    "NETWORK_POST": ("MEDIUM", True),
    "PRODUCTION_INSTALL": ("HIGH", True),
    "META_PROMOTION": ("HIGH", True),
    "KEY_ACCESS": ("CRITICAL", True),
}

STATUS_PROPOSED = "PROPOSED"
STATUS_ELIGIBLE = "ELIGIBLE"
STATUS_STALE = "STALE"
STATUS_BLOCKED = "BLOCKED"
STATUS_SATISFIED = "SATISFIED"
STATUS_CANCELLED = "CANCELLED"
TERMINAL_INTENT_STATUSES = (STATUS_SATISFIED, STATUS_CANCELLED)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_work_intents (
        intent_id TEXT PRIMARY KEY,
        origin_kind TEXT NOT NULL,
        work_class TEXT NOT NULL,
        parent_mission_id TEXT,
        subject_ref TEXT,
        triggering_evidence_refs_json TEXT,
        trigger_basis_digest TEXT NOT NULL,
        requested_scope_json TEXT,
        earliest_start REAL,
        latest_useful_time REAL,
        risk_class TEXT NOT NULL,
        external_effect INTEGER NOT NULL,
        terminal_status TEXT,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_intent_decisions (
        decision_id TEXT PRIMARY KEY,
        intent_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        basis_digest TEXT NOT NULL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class AutonomousWorkIntent:
    intent_id: str
    origin_kind: str
    work_class: str
    parent_mission_id: Optional[str]
    subject_ref: Optional[str]
    triggering_evidence_refs: Tuple[str, ...]
    trigger_basis_digest: str
    requested_scope: Tuple[str, ...]
    earliest_start: Optional[float]
    latest_useful_time: Optional[float]
    risk_class: str
    external_effect: bool
    terminal_status: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"intent_id": self.intent_id, "origin_kind": self.origin_kind,
                "work_class": self.work_class, "parent_mission_id": self.parent_mission_id,
                "subject_ref": self.subject_ref,
                "triggering_evidence_refs": list(self.triggering_evidence_refs),
                "trigger_basis_digest": self.trigger_basis_digest,
                "requested_scope": list(self.requested_scope),
                "earliest_start": self.earliest_start, "latest_useful_time": self.latest_useful_time,
                "risk_class": self.risk_class, "external_effect": self.external_effect,
                "terminal_status": self.terminal_status}


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


def mission_basis(db_path: str, mission_id: Optional[str]) -> str:
    """The canonical basis an autonomous intent is generated against. Reused by eligibility."""
    if mission_id is None:
        return digest({"mission": None})
    from ciph.kernel.missions import reconstruct_missions
    state = reconstruct_missions(db_path).state_of(str(mission_id))
    return digest({"mission": state.canonical_digest() if state is not None else None})


def propose_work_intent(db_path: str, *, origin_kind: str, work_class: str,
                        triggering_evidence_refs: Sequence[str],
                        parent_mission_id: Optional[str] = None, subject_ref: Optional[str] = None,
                        requested_scope: Sequence[str] = (),
                        earliest_start: Optional[float] = None,
                        latest_useful_time: Optional[float] = None,
                        now: Optional[float] = None) -> AutonomousWorkIntent:
    """
    Propose ONE autonomous work intent (Gate Zero).

    A wake-up is not identity: the same origin, class, mission, subject and triggering basis is the SAME
    logical work identity however many times a scheduler fires.
    """
    if str(origin_kind) not in VALID_ORIGIN_KINDS:
        raise CrucibleError("INVALID_WORK_ORIGIN", str(origin_kind))
    if str(work_class) not in WORK_CLASSES:
        raise CrucibleError("INVALID_WORK_CLASS", str(work_class))
    if not triggering_evidence_refs:
        # Autonomy is not allowed to wake up because it felt like it.
        raise CrucibleError("AUTONOMOUS_INTENT_REQUIRES_A_TRIGGER_BASIS", str(work_class))
    risk_class, external_effect = WORK_CLASSES[str(work_class)]
    moment = time.time() if now is None else float(now)
    basis = mission_basis(db_path, parent_mission_id)
    intent_id = "AWI-" + digest({"origin": str(origin_kind), "class": str(work_class),
                                 "mission": parent_mission_id, "subject": subject_ref,
                                 "basis": basis})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_work_intents (intent_id, origin_kind, work_class, "
            "parent_mission_id, subject_ref, triggering_evidence_refs_json, trigger_basis_digest, "
            "requested_scope_json, earliest_start, latest_useful_time, risk_class, external_effect, "
            "terminal_status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (intent_id, str(origin_kind), str(work_class), parent_mission_id, subject_ref,
             json.dumps(sorted(str(ref) for ref in triggering_evidence_refs)), basis,
             json.dumps(sorted(str(item) for item in requested_scope)), earliest_start,
             latest_useful_time, risk_class, 1 if external_effect else 0, None, moment))
        connection.commit()
    finally:
        connection.close()
    return get_work_intent(db_path, intent_id)


def record_intent_decision(db_path: str, *, intent_id: str, outcome: str, basis_digest: str,
                           now: Optional[float] = None) -> str:
    get_work_intent(db_path, intent_id)
    moment = time.time() if now is None else float(now)
    decision_id = "AWD-" + digest({"intent": intent_id, "outcome": outcome,
                                   "basis": basis_digest})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_intent_decisions (decision_id, intent_id, outcome, "
            "basis_digest, recorded_at) VALUES (?,?,?,?,?);",
            (decision_id, intent_id, str(outcome), str(basis_digest), moment))
        connection.commit()
    finally:
        connection.close()
    return decision_id


def _latest_decision(db_path: str, intent_id: str) -> Optional[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_autonomy_intent_decisions WHERE intent_id = ? "
                                 "ORDER BY rowid DESC LIMIT 1;", (intent_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return dict(row) if row is not None else None


def get_work_intent(db_path: str, intent_id: str) -> AutonomousWorkIntent:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_autonomy_work_intents WHERE intent_id = ?;",
                                 (intent_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_WORK_INTENT", intent_id)
    row = dict(row)
    return AutonomousWorkIntent(
        intent_id=str(row["intent_id"]), origin_kind=str(row["origin_kind"]),
        work_class=str(row["work_class"]), parent_mission_id=row["parent_mission_id"],
        subject_ref=row["subject_ref"],
        triggering_evidence_refs=tuple(json.loads(row["triggering_evidence_refs_json"] or "[]")),
        trigger_basis_digest=str(row["trigger_basis_digest"]),
        requested_scope=tuple(json.loads(row["requested_scope_json"] or "[]")),
        earliest_start=row["earliest_start"], latest_useful_time=row["latest_useful_time"],
        risk_class=str(row["risk_class"]), external_effect=bool(row["external_effect"]),
        terminal_status=row["terminal_status"])


def terminate_work_intent(db_path: str, intent_id: str, *, status: str,
                          now: Optional[float] = None) -> AutonomousWorkIntent:
    if status not in TERMINAL_INTENT_STATUSES:
        raise CrucibleError("INVALID_TERMINAL_STATUS", str(status))
    connection = _connect(db_path)
    try:
        init_schema(connection)
        cursor = connection.execute("UPDATE ciph_autonomy_work_intents SET terminal_status = ? "
                                    "WHERE intent_id = ?;", (status, intent_id))
        connection.commit()
        if cursor.rowcount == 0:
            raise CrucibleError("UNKNOWN_WORK_INTENT", intent_id)
    finally:
        connection.close()
    return get_work_intent(db_path, intent_id)


def work_intent_status(db_path: str, intent_id: str, *, now: Optional[float] = None) -> str:
    """
    The intent's effective status (Gate Zero lifecycle + the latest eligibility decision).

    A completed parent mission SATISFIES its stale schedule: the wake-up still happens, and it does
    nothing (hostile case 14).
    """
    moment = time.time() if now is None else float(now)
    intent = get_work_intent(db_path, intent_id)
    if intent.terminal_status in TERMINAL_INTENT_STATUSES:
        return str(intent.terminal_status)
    if intent.parent_mission_id is not None:
        # COMPLETED and ABANDONED are both terminal. An abandoned mission must not leave a wake-up
        # looking runnable: that is how "zombie" scheduled work appears, and it is the cheap way for a
        # cadence to outlive the reason it existed.
        from ciph.kernel.missions import (MISSION_ABANDONED, MISSION_COMPLETED,
                                          reconstruct_missions)
        state = reconstruct_missions(db_path).state_of(str(intent.parent_mission_id))
        if state is not None and state.status in (MISSION_COMPLETED, MISSION_ABANDONED):
            return STATUS_SATISFIED
    if intent.latest_useful_time is not None and moment > float(intent.latest_useful_time):
        return STATUS_STALE
    decision = _latest_decision(db_path, intent_id)
    if decision is not None and decision["basis_digest"] == mission_basis(db_path,
                                                                         intent.parent_mission_id):
        return str(decision["outcome"])
    if decision is not None:
        return STATUS_STALE
    return STATUS_PROPOSED


def due_for_reconsideration(db_path: str, *, now: Optional[float] = None
                            ) -> List[AutonomousWorkIntent]:
    """
    5.2: a schedule nominates work for RECONSIDERATION. It never nominates it for execution.
    """
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["intent_id"]) for row in connection.execute(
            "SELECT intent_id FROM ciph_autonomy_work_intents ORDER BY created_at, intent_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    due = []
    for intent_id in ids:
        intent = get_work_intent(db_path, intent_id)
        if intent.earliest_start is not None and moment < float(intent.earliest_start):
            continue
        if work_intent_status(db_path, intent_id, now=moment) in TERMINAL_INTENT_STATUSES:
            continue
        due.append(intent)
    return due


def work_intent_history(db_path: str) -> List[AutonomousWorkIntent]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["intent_id"]) for row in connection.execute(
            "SELECT intent_id FROM ciph_autonomy_work_intents ORDER BY created_at, intent_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_work_intent(db_path, intent_id) for intent_id in ids]


def autonomous_work_digest(db_path: str) -> str:
    return digest({"version": AUTONOMOUS_WORK_INTENT_V1,
                   "intents": [item.as_dict() for item in work_intent_history(db_path)]})
