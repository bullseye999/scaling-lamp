"""
ciph/kernel/notification_pipeline - a durable outbox from a verified finding to a transport state.

    CREATED -> QUEUED -> TRANSPORT_ATTEMPTED -> ACCEPTED_BY_TRANSPORT -> CONFIRMED_DELIVERED
                                                                       -> CONFIRMED_READ

A transport may also return FAILED, RETRY_PENDING or (critically) UNKNOWN_OUTCOME. A timeout does NOT mean
the message arrived, and it does not mean it did not: the pipeline keeps the ambiguity instead of resolving
it in whichever direction is convenient. CONFIRMED_DELIVERED and CONFIRMED_READ are reachable ONLY with an
actual transport artifact (`evidence_ref`); a transport that merely returns 200 has accepted the message, not
proven that operator read it.

Content is composed from CANONICAL findings: every notification carries the durable finding references and
the count is CHECKED against them, so no model and no composer can state a discovery count the result set
does not support.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

NOTIFICATION_PIPELINE_V1 = "NOTIFICATION_PIPELINE_V1"
NOTIFICATION_V1 = "NOTIFICATION_V1"

CREATED = "CREATED"
QUEUED = "QUEUED"
TRANSPORT_ATTEMPTED = "TRANSPORT_ATTEMPTED"
ACCEPTED_BY_TRANSPORT = "ACCEPTED_BY_TRANSPORT"
CONFIRMED_DELIVERED = "CONFIRMED_DELIVERED"
CONFIRMED_READ = "CONFIRMED_READ"
FAILED = "FAILED"
RETRY_PENDING = "RETRY_PENDING"
UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
SUPPRESSED = "SUPPRESSED"
STATES = (CREATED, QUEUED, TRANSPORT_ATTEMPTED, ACCEPTED_BY_TRANSPORT, CONFIRMED_DELIVERED,
          CONFIRMED_READ, FAILED, RETRY_PENDING, UNKNOWN_OUTCOME, SUPPRESSED)

CRITICAL = "CRITICAL"
NORMAL = "NORMAL"

REASON_COUNT_MISMATCH = "COMPOSED_COUNT_DOES_NOT_MATCH_THE_DURABLE_FINDINGS"
REASON_UNRESOLVED_FINDING = "NOTIFICATION_CITES_A_FINDING_THAT_DOES_NOT_RESOLVE"
REASON_DELIVERY_NEEDS_EVIDENCE = "DELIVERY_CONFIRMATION_REQUIRES_TRANSPORT_EVIDENCE"
REASON_READ_NEEDS_EVIDENCE = "READ_CONFIRMATION_REQUIRES_TRANSPORT_EVIDENCE"
REASON_QUIET_HOURS = "OPERATOR_QUIET_HOURS"
REASON_RATE_LIMITED = "OPERATOR_RATE_LIMIT"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_notifications (
        notification_id TEXT PRIMARY KEY,
        candidate_id TEXT,
        expedition_id TEXT,
        finding_refs_json TEXT,
        subject TEXT,
        body TEXT,
        priority TEXT NOT NULL,
        state TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        transport_ref TEXT,
        last_transport_state TEXT,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_notification_attempts (
        attempt_id TEXT PRIMARY KEY,
        notification_id TEXT NOT NULL,
        transport TEXT,
        outcome TEXT,
        evidence_ref TEXT,
        detail_json TEXT,
        attempted_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_notification_preferences (
        key TEXT PRIMARY KEY,
        value TEXT,
        set_by TEXT,
        updated_at REAL
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


# ------------------------------------------------------------------ operator preferences
def set_preferences(db_path: str, *, actor: str, quiet_hours: Optional[Dict[str, float]] = None,
                    max_per_window: Optional[int] = None, window_seconds: Optional[float] = None,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """Operator-configurable notification behaviour. Only an operator identity may set it."""
    if not str(actor).startswith("operator:"):
        raise CrucibleError("NOTIFICATION_PREFERENCES_REQUIRE_AN_OPERATOR", str(actor))
    moment = _moment(now)
    entries = {"quiet_hours": quiet_hours, "max_per_window": max_per_window,
               "window_seconds": window_seconds}
    for key, value in entries.items():
        if value is None:
            continue
        _write(db_path, "INSERT OR REPLACE INTO ciph_notification_preferences (key, value, set_by, "
                        "updated_at) VALUES (?,?,?,?);",
               (key, json.dumps(value), str(actor), moment))
    return preferences(db_path)


def preferences(db_path: str) -> Dict[str, Any]:
    stored = {row["key"]: json.loads(row["value"]) for row in
              _rows(db_path, "SELECT key, value FROM ciph_notification_preferences;")}
    return {"quiet_hours": stored.get("quiet_hours"), "max_per_window": stored.get("max_per_window"),
            "window_seconds": stored.get("window_seconds"), "policy_version":
            NOTIFICATION_PIPELINE_V1}


def in_quiet_hours(db_path: str, *, now: Optional[float] = None) -> bool:
    window = preferences(db_path)["quiet_hours"]
    if not window:
        return False
    hour = time.localtime(_moment(now)).tm_hour + time.localtime(_moment(now)).tm_min / 60.0
    start, end = float(window.get("from", 22)), float(window.get("to", 7))
    return (hour >= start or hour < end) if start > end else (start <= hour < end)


# ------------------------------------------------------------------ composition and enqueue
def compose(db_path: str, *, candidate_id: str, subject: str, body: str, priority: str = NORMAL,
            now: Optional[float] = None) -> Dict[str, Any]:
    """
    Compose a notification from a 10.9 candidate. EVERY cited finding must RESOLVE in 10.0, and a stated
    count must MATCH the durable findings, so an unsupported discovery count is refused outright.
    """
    moment = _moment(now)
    from ciph.kernel.independent_expeditions import notification_candidates
    match = [row for row in notification_candidates(db_path) if row["candidate_id"] == str(candidate_id)]
    if not match:
        raise CrucibleError("UNKNOWN_NOTIFICATION_CANDIDATE", str(candidate_id))
    candidate = match[0]
    known = {row["finding_id"] for row in _rows(db_path, "SELECT finding_id FROM ciph_findings;")}
    unresolved = [ref for ref in candidate["finding_refs"] if ref not in known]
    if unresolved:
        raise CrucibleError(REASON_UNRESOLVED_FINDING, ",".join(unresolved))
    import re
    stated = re.findall(r"\b(\d+)\s+(?:findings|results|discoveries)\b", str(body))
    for number in stated:
        if int(number) != len(candidate["finding_refs"]):
            raise CrucibleError(REASON_COUNT_MISMATCH,
                               f"body says {number}, findings are {len(candidate['finding_refs'])}")
    notification_id = "NOT-" + digest({"candidate": candidate_id, "subject": subject,
                                       "at": moment})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_notifications (notification_id, candidate_id, "
                    "expedition_id, finding_refs_json, subject, body, priority, state, attempts, "
                    "transport_ref, last_transport_state, created_at, updated_at, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (notification_id, str(candidate_id), candidate["expedition_id"],
            json.dumps(candidate["finding_refs"]), str(subject), str(body), str(priority), CREATED, 0,
            None, None, moment, moment, NOTIFICATION_V1))
    return get_notification(db_path, notification_id)


def get_notification(db_path: str, notification_id: str) -> Dict[str, Any]:
    rows = _rows(db_path, "SELECT * FROM ciph_notifications WHERE notification_id = ?;",
                 (str(notification_id),))
    if not rows:
        raise CrucibleError("UNKNOWN_NOTIFICATION", str(notification_id))
    record = rows[0]
    record["finding_refs"] = json.loads(record.pop("finding_refs_json") or "[]")
    record["is_delivered"] = record["state"] == CONFIRMED_DELIVERED
    record["is_read"] = record["state"] == CONFIRMED_READ
    return record


def notifications(db_path: str, *, state: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT notification_id FROM ciph_notifications"
    params: Sequence[Any] = ()
    if state is not None:
        query += " WHERE state = ?"
        params = (str(state),)
    query += " ORDER BY created_at, notification_id;"
    return [get_notification(db_path, row["notification_id"]) for row in _rows(db_path, query, params)]


def enqueue(db_path: str, *, notification_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    return _set_state(db_path, notification_id=notification_id, state=QUEUED, now=now)


def _set_state(db_path: str, *, notification_id: str, state: str, now: Optional[float] = None,
               **columns: Any) -> Dict[str, Any]:
    moment = _moment(now)
    if state not in STATES:
        raise CrucibleError("UNKNOWN_NOTIFICATION_STATE", str(state))
    assignments = ["state = ?", "updated_at = ?"]
    values: List[Any] = [str(state), moment]
    for column, value in columns.items():
        assignments.append(f"{column} = ?")
        values.append(value)
    values.append(str(notification_id))
    _write(db_path, f"UPDATE ciph_notifications SET {', '.join(assignments)} WHERE notification_id = ?;",
           tuple(values))
    return get_notification(db_path, notification_id)


def suppress_stale(db_path: str, *, max_age_seconds: float, now: Optional[float] = None) -> List[str]:
    """A stale notification is SUPPRESSED rather than sent late as if it were fresh."""
    moment = _moment(now)
    stale = [row for row in notifications(db_path)
             if row["state"] in (CREATED, QUEUED, RETRY_PENDING, FAILED)
             and moment - float(row["created_at"]) > float(max_age_seconds)]
    for row in stale:
        _set_state(db_path, notification_id=row["notification_id"], state=SUPPRESSED, now=moment)
    return [row["notification_id"] for row in stale]


def _attempts_in_window(db_path: str, *, window_seconds: float, now: float) -> int:
    return len([row for row in _rows(db_path, "SELECT attempted_at FROM ciph_notification_attempts "
                                               "WHERE attempted_at >= ?;",
                                     (now - float(window_seconds),))])


def dispatch(db_path: str, *, adapter: Any, now: Optional[float] = None,
             max_batch: int = 5) -> Dict[str, Any]:
    """
    Submit QUEUED notifications through the TRANSPORT. Quiet hours and the operator's rate limit are honoured;
    CRITICAL is the only priority that may bypass quiet hours, and only when it carries findings.
    """
    moment = _moment(now)
    settings = preferences(db_path)
    results: List[Dict[str, Any]] = []
    quiet = in_quiet_hours(db_path, now=moment)
    window = float(settings["window_seconds"] or 3600.0)
    limit = settings["max_per_window"]
    sent = 0
    for record in notifications(db_path, state=QUEUED):
        if sent >= int(max_batch):
            break
        priority_critical = record["priority"] == CRITICAL and bool(record["finding_refs"])
        if quiet and not priority_critical:
            results.append({"notification_id": record["notification_id"], "state": QUEUED,
                            "suppressed_by": REASON_QUIET_HOURS})
            continue
        if limit is not None and _attempts_in_window(db_path, window_seconds=window, now=moment) >= int(limit):
            results.append({"notification_id": record["notification_id"], "state": QUEUED,
                            "suppressed_by": REASON_RATE_LIMITED})
            continue
        _set_state(db_path, notification_id=record["notification_id"], state=TRANSPORT_ATTEMPTED,
                   now=moment, attempts=int(record["attempts"]) + 1)
        outcome = adapter.submit(record)
        transport_state = str(outcome.get("status"))
        evidence = outcome.get("evidence_ref")
        if transport_state == "DELIVERED" and evidence:
            state = CONFIRMED_DELIVERED
        elif transport_state == "DELIVERED" and not evidence:
            state = ACCEPTED_BY_TRANSPORT  # a claim without an artifact is acceptance, not confirmation
            evidence = None
        elif transport_state == "ACCEPTED":
            state = ACCEPTED_BY_TRANSPORT
        elif transport_state == "TIMEOUT":
            state = UNKNOWN_OUTCOME
        elif transport_state == "FAILED":
            state = FAILED
        elif transport_state == "PENDING":
            state = RETRY_PENDING
        else:
            state = UNKNOWN_OUTCOME
        _write(db_path, "INSERT OR IGNORE INTO ciph_notification_attempts (attempt_id, notification_id, "
                        "transport, outcome, evidence_ref, detail_json, attempted_at, policy_version) "
                        "VALUES (?,?,?,?,?,?,?,?);",
               ("NAT-" + digest({"notification": record["notification_id"], "at": moment})[:16].upper(),
                record["notification_id"], adapter.channel_id, state, evidence,
                json.dumps(outcome, sort_keys=True, default=str), moment, NOTIFICATION_V1))
        _set_state(db_path, notification_id=record["notification_id"], state=state, now=moment,
                   transport_ref=adapter.channel_id, last_transport_state=transport_state)
        sent += 1
        results.append({"notification_id": record["notification_id"], "state": state,
                        "transport_state": transport_state})
    return {"policy_version": NOTIFICATION_PIPELINE_V1, "attempted": sent, "results": results,
            "quiet_hours_active": quiet}


def confirm_delivery(db_path: str, *, notification_id: str, evidence_ref: str,
                     now: Optional[float] = None) -> Dict[str, Any]:
    """CONFIRMED_DELIVERED requires a transport artifact. Without one this REFUSES."""
    if not str(evidence_ref or "").strip():
        raise CrucibleError(REASON_DELIVERY_NEEDS_EVIDENCE, str(notification_id))
    record = get_notification(db_path, notification_id)
    if record["state"] not in (ACCEPTED_BY_TRANSPORT, TRANSPORT_ATTEMPTED, UNKNOWN_OUTCOME):
        raise CrucibleError("DELIVERY_CONFIRMATION_IS_NOT_APPLICABLE", record["state"])
    return _set_state(db_path, notification_id=notification_id, state=CONFIRMED_DELIVERED, now=now,
                      last_transport_state=f"confirmed:{evidence_ref}")


def confirm_read(db_path: str, *, notification_id: str, evidence_ref: str,
                 now: Optional[float] = None) -> Dict[str, Any]:
    """CONFIRMED_READ requires actual evidence that operator read it. A send receipt is not a read receipt."""
    if not str(evidence_ref or "").strip():
        raise CrucibleError(REASON_READ_NEEDS_EVIDENCE, str(notification_id))
    record = get_notification(db_path, notification_id)
    if record["state"] != CONFIRMED_DELIVERED:
        raise CrucibleError("READ_CONFIRMATION_REQUIRES_A_CONFIRMED_DELIVERY", record["state"])
    return _set_state(db_path, notification_id=notification_id, state=CONFIRMED_READ, now=now,
                      last_transport_state=f"read:{evidence_ref}")


def attempts(db_path: str, *, notification_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_notification_attempts"
    params: Sequence[Any] = ()
    if notification_id is not None:
        query += " WHERE notification_id = ?"
        params = (str(notification_id),)
    query += " ORDER BY attempted_at, attempt_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["detail"] = json.loads(row.pop("detail_json") or "{}")
    return rows


def outbox_digest(db_path: str) -> str:
    return digest({"notifications": _rows(db_path, "SELECT notification_id, state, attempts, "
                                                   "last_transport_state FROM ciph_notifications "
                                                   "ORDER BY notification_id;"),
                   "attempts": _rows(db_path, "SELECT attempt_id, notification_id, outcome, evidence_ref "
                                              "FROM ciph_notification_attempts ORDER BY attempt_id;")})
