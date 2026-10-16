"""
ciph/kernel/autonomy_schedule - 5.2: temporal governance.

    A schedule says when something may be RECONSIDERED. It never says that something must execute.

That sentence is the whole module. A trigger is a nomination, and every nomination is re-decided by the
pure eligibility function at the moment it fires, because the world that made the work worth doing may
have changed since the schedule was written.

Three temporal facts get first-class treatment:

    RECURRENCE  interval-bounded, with BACKOFF on repeated blocks so a permanently blocked wake stops
                retrying every tick.
    CERTAINTY   if the due moment is inside the clock's uncertainty band, the wake is NOT taken. A
                scheduler that cannot tell "now" from "just before now" must not act as if it can.
    IDENTITY    the next due moment is DERIVED from durable state, so a restart produces the same
                schedule rather than a fresh one.

Only an operator identity may REGISTER a schedule: a recurring obligation is authority over the future,
and a daemon that can write its own schedule can grant itself tomorrow's work.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ciph.kernel.crucible_types import CrucibleError, digest

AUTONOMY_SCHEDULE_V1 = "AUTONOMY_SCHEDULE_V1"
TEMPORAL_GOVERNANCE_V1 = "TEMPORAL_GOVERNANCE_V1"

REASON_SCHEDULE_REQUIRES_OPERATOR = "SCHEDULE_REQUIRES_AN_OPERATOR"
REASON_NOT_DUE = "SCHEDULE_NOT_DUE"
REASON_CLOCK_UNCERTAIN = "SCHEDULE_CLOCK_UNCERTAIN"
REASON_UNKNOWN_SCHEDULE = "UNKNOWN_SCHEDULE"
REASON_UNKNOWN_OUTCOME = "UNKNOWN_RECONSIDERATION_OUTCOME"

SCHEDULE_ACTIVE = "ACTIVE"
SCHEDULE_PAUSED = "PAUSED"
SCHEDULE_RETIRED = "RETIRED"

OUTCOME_NOMINATED = "NOMINATED"
OUTCOME_CLOCK_UNCERTAIN = "CLOCK_UNCERTAIN"
OUTCOME_BLOCKED = "BLOCKED"
VALID_RECONSIDERATION_OUTCOMES = (OUTCOME_NOMINATED, OUTCOME_CLOCK_UNCERTAIN, OUTCOME_BLOCKED)

MAX_BACKOFF_LEVEL = 6

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_schedules (
        schedule_id TEXT PRIMARY KEY,
        mission_id TEXT,
        origin_kind TEXT NOT NULL,
        work_class TEXT NOT NULL,
        interval_seconds REAL NOT NULL,
        max_interval_seconds REAL NOT NULL,
        clock_uncertainty_seconds REAL NOT NULL,
        next_reconsideration_at REAL,
        last_reconsideration_at REAL,
        backoff_level INTEGER NOT NULL,
        effective_interval_seconds REAL,
        status TEXT NOT NULL,
        registered_by TEXT NOT NULL,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_reconsiderations (
        reconsideration_id TEXT PRIMARY KEY,
        schedule_id TEXT NOT NULL,
        mission_id TEXT,
        work_class TEXT NOT NULL,
        outcome TEXT NOT NULL,
        intent_id TEXT,
        due_at REAL,
        considered_at REAL
    );
    """,
)


@dataclass(frozen=True)
class Schedule:
    schedule_id: str
    mission_id: Optional[str]
    origin_kind: str
    work_class: str
    interval_seconds: float
    max_interval_seconds: float
    clock_uncertainty_seconds: float
    next_reconsideration_at: Optional[float]
    last_reconsideration_at: Optional[float]
    backoff_level: int
    effective_interval_seconds: float
    status: str
    registered_by: str

    def as_dict(self) -> Dict[str, Any]:
        return {"schedule_id": self.schedule_id, "mission_id": self.mission_id,
                "origin_kind": self.origin_kind, "work_class": self.work_class,
                "interval_seconds": self.interval_seconds,
                "max_interval_seconds": self.max_interval_seconds,
                "clock_uncertainty_seconds": self.clock_uncertainty_seconds,
                "next_reconsideration_at": self.next_reconsideration_at,
                "last_reconsideration_at": self.last_reconsideration_at,
                "backoff_level": self.backoff_level,
                "effective_interval_seconds": self.effective_interval_seconds,
                "status": self.status, "registered_by": self.registered_by,
                "policy_version": AUTONOMY_SCHEDULE_V1}


@dataclass(frozen=True)
class Reconsideration:
    reconsideration_id: str
    schedule_id: str
    mission_id: Optional[str]
    work_class: str
    outcome: str
    intent_id: Optional[str]
    due_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"reconsideration_id": self.reconsideration_id, "schedule_id": self.schedule_id,
                "mission_id": self.mission_id, "work_class": self.work_class,
                "outcome": self.outcome, "intent_id": self.intent_id, "due_at": self.due_at,
                "policy_version": TEMPORAL_GOVERNANCE_V1}


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


# Additive columns, so a datastore written by an earlier build of this module still opens.
_ADDITIVE_COLUMNS = (("ciph_autonomy_schedules", "effective_interval_seconds", "REAL"),)


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)
    for table, column, kind in _ADDITIVE_COLUMNS:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind};")
        except sqlite3.Error:
            pass   # already present


def register_schedule(db_path: str, *, origin_kind: str, work_class: str, interval_seconds: float,
                      actor: str, mission_id: Optional[str] = None,
                      max_interval_seconds: Optional[float] = None,
                      clock_uncertainty_seconds: float = 0.0,
                      first_due_at: Optional[float] = None,
                      now: Optional[float] = None) -> Schedule:
    """
    Register one recurring reconsideration.

    `first_due_at` is explicit because the schedule must not become due merely because the process that
    wrote it happened to be running at that moment.
    """
    from ciph.kernel.autonomous_work import VALID_ORIGIN_KINDS, WORK_CLASSES
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_SCHEDULE_REQUIRES_OPERATOR, str(actor))
    if str(origin_kind) not in VALID_ORIGIN_KINDS:
        raise CrucibleError("INVALID_WORK_ORIGIN", str(origin_kind))
    if str(work_class) not in WORK_CLASSES:
        raise CrucibleError("INVALID_WORK_CLASS", str(work_class))
    interval = float(interval_seconds)
    if interval <= 0.0:
        raise CrucibleError("SCHEDULE_INTERVAL_MUST_BE_POSITIVE", str(interval_seconds))
    moment = time.time() if now is None else float(now)
    ceiling = float(max_interval_seconds) if max_interval_seconds is not None else interval * (
        2 ** MAX_BACKOFF_LEVEL)
    if ceiling < interval:
        raise CrucibleError("SCHEDULE_CEILING_BELOW_INTERVAL", f"{ceiling}<{interval}")
    due = float(first_due_at) if first_due_at is not None else moment + interval
    schedule_id = "SCH-" + digest({"mission": mission_id, "class": str(work_class),
                                   "origin": str(origin_kind), "interval": interval})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_schedules (schedule_id, mission_id, origin_kind, "
            "work_class, interval_seconds, max_interval_seconds, clock_uncertainty_seconds, "
            "next_reconsideration_at, last_reconsideration_at, backoff_level, "
            "effective_interval_seconds, status, registered_by, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (schedule_id, mission_id, str(origin_kind), str(work_class), interval, ceiling,
             float(clock_uncertainty_seconds), due, None, 0, interval, SCHEDULE_ACTIVE, str(actor),
             moment))
        connection.commit()
    finally:
        connection.close()
    return get_schedule(db_path, schedule_id)


def get_schedule(db_path: str, schedule_id: str) -> Schedule:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_autonomy_schedules WHERE schedule_id = ?;",
                                 (schedule_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_SCHEDULE, schedule_id)
    row = dict(row)
    return Schedule(schedule_id=str(row["schedule_id"]), mission_id=row["mission_id"],
                    origin_kind=str(row["origin_kind"]), work_class=str(row["work_class"]),
                    interval_seconds=float(row["interval_seconds"]),
                    max_interval_seconds=float(row["max_interval_seconds"]),
                    clock_uncertainty_seconds=float(row["clock_uncertainty_seconds"]),
                    next_reconsideration_at=row["next_reconsideration_at"],
                    last_reconsideration_at=row["last_reconsideration_at"],
                    backoff_level=int(row["backoff_level"]),
                    effective_interval_seconds=float(
                        row["effective_interval_seconds"] or row["interval_seconds"]),
                    status=str(row["status"]), registered_by=str(row["registered_by"]))


def schedules(db_path: str, *, status: Optional[str] = None) -> List[Schedule]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT schedule_id FROM ciph_autonomy_schedules"
    params: tuple = ()
    if status is not None:
        query += " WHERE status = ?"
        params = (str(status),)
    try:
        ids = [str(row["schedule_id"]) for row in connection.execute(
            query + " ORDER BY created_at, schedule_id;", params)]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_schedule(db_path, schedule_id) for schedule_id in ids]


def reconsideration_due(db_path: str, *, now: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    Which schedules are nominating work right now, and on what temporal footing.

    This function EXECUTES NOTHING and grants nothing. It reports; the eligibility function decides.
    """
    moment = time.time() if now is None else float(now)
    due: List[Dict[str, Any]] = []
    for schedule in schedules(db_path, status=SCHEDULE_ACTIVE):
        if schedule.next_reconsideration_at is None:
            continue
        due_at = float(schedule.next_reconsideration_at)
        if due_at > moment:
            continue
        # CERTAINTY is a comparison against the band the schedule DECLARED. With no declared
        # uncertainty the clock is trusted, so arriving exactly on time is an on-time arrival; an
        # `>` here would have made every punctual wake look doubtful, which is the kind of bug that
        # hides until a thirty-day cadence refuses to run.
        certain = (float(moment) - due_at) >= schedule.clock_uncertainty_seconds
        due.append({"schedule_id": schedule.schedule_id, "mission_id": schedule.mission_id,
                    "work_class": schedule.work_class, "due_at": due_at,
                    "certainty": "CERTAIN" if certain else "UNCERTAIN"})
    return due


def reconsider(db_path: str, schedule_id: str, *, now: Optional[float] = None) -> Reconsideration:
    """
    Take ONE reconsideration: nominate work, or refuse to act because the clock cannot be trusted.

    The nomination creates a Gate Zero work intent whose trigger basis IS the schedule, so a scheduled
    wake is still not allowed to wake up because it felt like it.

    TWO properties of the nomination are deliberate.

    Its IDENTITY carries the due moment, so "this morning's review" and "tomorrow morning's review" are
    different work while two ticks of the SAME morning are one - which is what makes the cadence
    repeatable and a retry harmless at the same time.

    Its USEFULNESS is bounded by one cadence period. Work identified now is worth doing until the next
    scheduled look; after that it is not "still pending", it is a stale nomination, and it lapses
    instead of being offered at every instant in between.
    """
    from ciph.kernel.autonomous_work import propose_work_intent
    moment = time.time() if now is None else float(now)
    schedule = get_schedule(db_path, schedule_id)
    if schedule.status != SCHEDULE_ACTIVE:
        raise CrucibleError("SCHEDULE_NOT_ACTIVE", f"{schedule_id}={schedule.status}")
    due_at = schedule.next_reconsideration_at
    if due_at is None or float(due_at) > moment:
        raise CrucibleError(REASON_NOT_DUE, f"{schedule_id}: due {due_at}, now {moment}")
    uncertainty = schedule.clock_uncertainty_seconds
    if uncertainty > 0.0 and (moment - float(due_at)) <= uncertainty:
        outcome, intent_id = OUTCOME_CLOCK_UNCERTAIN, None
    else:
        intent = propose_work_intent(db_path, origin_kind=schedule.origin_kind,
                                     work_class=schedule.work_class,
                                     triggering_evidence_refs=[f"SCHEDULE:{schedule.schedule_id}"],
                                     parent_mission_id=schedule.mission_id,
                                     subject_ref=f"cadence:{int(float(due_at))}",
                                     latest_useful_time=float(due_at) + schedule.interval_seconds,
                                     now=moment)
        outcome, intent_id = OUTCOME_NOMINATED, intent.intent_id
    reconsideration_id = "RCN-" + digest({"schedule": schedule_id,
                                          "due_at": float(due_at)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_reconsiderations (reconsideration_id, schedule_id, "
            "mission_id, work_class, outcome, intent_id, due_at, considered_at) VALUES (?,?,?,?,?,?,?,?);",
            (reconsideration_id, schedule_id, schedule.mission_id, schedule.work_class, outcome,
             intent_id, float(due_at), moment))
        connection.commit()
    finally:
        connection.close()
    return Reconsideration(reconsideration_id=reconsideration_id, schedule_id=schedule_id,
                           mission_id=schedule.mission_id, work_class=schedule.work_class,
                           outcome=outcome, intent_id=intent_id, due_at=float(due_at))


def advance_schedule(db_path: str, schedule_id: str, *, outcome: str,
                     now: Optional[float] = None) -> Schedule:
    """
    Move a schedule forward after it has been considered.

    Backoff is the only thing that changes its mind: a wake that keeps being BLOCKED gets further apart
    until it reaches the ceiling, so a permanently impossible obligation stops burning budget. A
    successful reconsideration resets it.
    """
    if str(outcome) not in VALID_RECONSIDERATION_OUTCOMES:
        raise CrucibleError(REASON_UNKNOWN_OUTCOME, str(outcome))
    moment = time.time() if now is None else float(now)
    schedule = get_schedule(db_path, schedule_id)
    level = 0 if outcome == OUTCOME_NOMINATED else min(MAX_BACKOFF_LEVEL,
                                                       schedule.backoff_level + 1)
    interval = min(schedule.max_interval_seconds, schedule.interval_seconds * (2 ** level))
    next_at = moment + interval
    connection = _connect(db_path)
    try:
        init_schema(connection)
        # The EFFECTIVE interval is stored, not just derived. "Why is the next look this far away?" is
        # an audit question, and the answer must be readable from the row rather than recomputed by
        # whoever is asking.
        connection.execute(
            "UPDATE ciph_autonomy_schedules SET next_reconsideration_at = ?, "
            "last_reconsideration_at = ?, backoff_level = ?, effective_interval_seconds = ? "
            "WHERE schedule_id = ?;",
            (next_at, moment, level, interval, schedule_id))
        connection.commit()
    finally:
        connection.close()
    return get_schedule(db_path, schedule_id)


def reconsideration_history(db_path: str,
                            schedule_id: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_autonomy_reconsiderations"
    params: tuple = ()
    if schedule_id is not None:
        query += " WHERE schedule_id = ?"
        params = (str(schedule_id),)
    try:
        return [dict(row) for row in connection.execute(
            query + " ORDER BY considered_at, reconsideration_id;", params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def schedule_digest(db_path: str) -> str:
    return digest({"version": AUTONOMY_SCHEDULE_V1,
                   "schedules": [schedule.as_dict() for schedule in schedules(db_path)],
                   "reconsiderations": reconsideration_history(db_path)})
