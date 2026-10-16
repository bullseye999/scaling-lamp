"""
ciph/kernel/selective_attention - 10.6: bounded allocation of REASONING, never of authority.

    Attention allocates inference, not authority.

THREE CATEGORIES, AND THEY ARE NOT PRIVILEGES.

    BACKGROUND  ordinary activity is retained without invoking the model at all.
    FOCUSED     significant observations are selected for deeper interpretation.
    CRITICAL    evidence-supported urgent developments preempt ordinary reasoning queues.

A sensor's KIND, a declared severity or a self-reported urgency CANNOT confer CRITICAL standing on their
own. CRITICAL requires an evidence reference that resolves and a corroborating factor (a verified
architectural integrity concern, a verified finding, or an operator priority). A worker shouting "CRITICAL"
gets its claim RECORDED and classified on the evidence, which is usually FOCUSED.

NO SINGLE ARBITRARY SCALAR. A decision records the input factors, the policy version, the category and a
REASON. When scheduling needs an order it uses (category, wait age, enqueue time, request id) with an
explicit tie-break rule, and the starvation ceiling promotes a long-waiting item rather than letting a burst
of high-priority events starve everything else forever.

THE MODEL IS NOT CALLED TO MAINTAIN THE QUEUE. Submission, classification, dedup, batching, expiry,
checkpointing, starvation detection and restart reconstruction are pure bookkeeping. `invoke` is the only
thing that consumes reasoning, it is metered by a bounded per-window budget, and when the model is
unavailable it returns MODEL_UNAVAILABLE and records NO outcome rather than inventing one.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SELECTIVE_ATTENTION_V1 = "SELECTIVE_ATTENTION_V1"
ATTENTION_POLICY_V1 = "ATTENTION_POLICY_V1"

BACKGROUND = "BACKGROUND"
FOCUSED = "FOCUSED"
CRITICAL = "CRITICAL"
ATTENTION_CATEGORIES = (BACKGROUND, FOCUSED, CRITICAL)
_CATEGORY_RANK = {CRITICAL: 0, FOCUSED: 1, BACKGROUND: 2}

PENDING = "PENDING"
INVOKED = "INVOKED"
DUPLICATE = "DUPLICATE"
EXPIRED = "EXPIRED"
CANCELLED = "CANCELLED"
BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
QUEUE_OVERFLOW = "QUEUE_OVERFLOW"
NOTHING_TO_DO = "NOTHING_TO_DO"

FOCUS_ACTIVE = "ACTIVE"
FOCUS_SUSPENDED = "SUSPENDED"
FOCUS_CLOSED = "CLOSED"

REASON_NO_EVIDENCE = "NO_EVIDENCE_REFERENCE"
REASON_SELF_DECLARED = "SELF_DECLARED_SEVERITY_IS_NOT_EVIDENCE"
REASON_UNRESOLVED_EVIDENCE = "EVIDENCE_REFERENCE_DOES_NOT_RESOLVE"
REASON_OPERATOR_PRIORITY = "OPERATOR_PRIORITY"
REASON_ACTIVE_GOAL = "RELEVANT_TO_AN_ACTIVE_GOAL"
REASON_ARCHITECTURAL_INTEGRITY = "VERIFIED_ARCHITECTURAL_INTEGRITY_CONCERN"
REASON_VERIFIED_FINDING = "VERIFIED_DURABLE_FINDING"
REASON_ROUTINE = "ROUTINE_ACTIVITY"
REASON_EVIDENCE_BACKED = "EVIDENCE_BACKED_OBSERVATION"

_SELECTION_TIE_BREAK = "category_rank, starvation_promoted, enqueued_at, request_id"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_attention_requests (
        request_id TEXT PRIMARY KEY,
        subject_ref TEXT NOT NULL,
        sensor_kind TEXT,
        declared_severity TEXT,
        category TEXT NOT NULL,
        factors_json TEXT,
        reason TEXT,
        evidence_ref TEXT,
        canonical_owner TEXT,
        dedup_key TEXT,
        enqueued_at REAL NOT NULL,
        expires_at REAL,
        status TEXT NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_attention_focus (
        focus_id TEXT PRIMARY KEY,
        request_id TEXT,
        subject_ref TEXT NOT NULL,
        category TEXT NOT NULL,
        context_ref TEXT,
        context_json TEXT,
        pending_questions_json TEXT,
        checkpoint_digest TEXT,
        opened_at REAL NOT NULL,
        closed_at REAL,
        status TEXT NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_attention_windows (
        window_id TEXT PRIMARY KEY,
        window_start REAL NOT NULL,
        window_end REAL NOT NULL,
        invocations INTEGER NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_attention_state (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_attention_events (
        record_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        detail_json TEXT,
        recorded_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
)


@dataclass(frozen=True)
class AttentionBudget:
    """The resource envelope. Every bound is explicit so a run is reproducible, not incidental."""
    max_invocations_per_window: int = 4
    window_seconds: float = 300.0
    max_active_focus: int = 2
    max_queue: int = 200
    max_batch: int = 5
    focus_ttl: float = 3600.0
    starvation_ceiling: float = 900.0
    max_consecutive_critical: int = 3


DEFAULT_BUDGET = AttentionBudget()


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


def _event(db_path: str, *, kind: str, detail: Dict[str, Any], now: float) -> str:
    record_id = "ATE-" + digest({"kind": kind, "detail": detail, "at": now})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_attention_events (record_id, kind, detail_json, "
                           "recorded_at, policy_version) VALUES (?,?,?,?,?);",
                           (record_id, str(kind), json.dumps(detail, sort_keys=True, default=str), now,
                            ATTENTION_POLICY_V1))
        connection.commit()
    finally:
        connection.close()
    return record_id


def _set_state(db_path: str, key: str, value: str, *, now: float) -> None:
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR REPLACE INTO ciph_attention_state (key, value, updated_at) "
                           "VALUES (?,?,?);", (str(key), str(value), now))
        connection.commit()
    finally:
        connection.close()


def _get_state(db_path: str, key: str, default: Optional[str] = None) -> Optional[str]:
    rows = _rows(db_path, "SELECT value FROM ciph_attention_state WHERE key = ?;", (str(key),))
    return default if not rows else rows[0]["value"]


# ------------------------------------------------------------------ evidence
def _evidence_resolves(db_path: str, evidence_ref: Optional[str]) -> bool:
    """An evidence reference counts only if a canonical owner can confirm it."""
    if not evidence_ref:
        return False
    reference = str(evidence_ref)
    if any(row["arch_observation_id"] == reference for row in
           _rows(db_path, "SELECT arch_observation_id FROM ciph_arch_observations;")):
        return True
    if any(row["change_id"] == reference for row in
           _rows(db_path, "SELECT change_id FROM ciph_arch_changes;")):
        return True
    if any(row["event_id"] == reference for row in
           _rows(db_path, "SELECT event_id FROM ciph_sensor_events;")):
        return True
    if any(row["record_id"] == reference for row in
           _rows(db_path, "SELECT record_id FROM ciph_self_executions;")):
        return True
    if any(row["result_set_id"] == reference for row in
           _rows(db_path, "SELECT result_set_id FROM ciph_result_sets;")):
        return True
    if any(row["finding_id"] == reference for row in
           _rows(db_path, "SELECT finding_id FROM ciph_findings;")):
        return True
    return False


def _architectural_integrity_concern(db_path: str, evidence_ref: Optional[str]) -> bool:
    """
    Is THE CITED EVIDENCE a verified architectural concern that outran authority?

    Evidence-linked on purpose: an unrelated integrity problem elsewhere in the database must not make this
    subject look critical, and an architectural change with UNKNOWN provenance is NOT such a concern - an
    absent authorization record is not a finding of wrongdoing.
    """
    if not evidence_ref:
        return False
    rows = _rows(db_path, "SELECT provenance FROM ciph_arch_changes WHERE change_id = ?;",
                 (str(evidence_ref),))
    return bool(rows) and str(rows[0]["provenance"]) in ("UNAUTHORIZED_MODIFICATION",
                                                         "AUTHORIZED_BUT_UNVERIFIED")


# ------------------------------------------------------------------ classification
def classify(db_path: str, *, subject_ref: str, sensor_kind: Optional[str] = None,
              declared_severity: Optional[str] = None, evidence_ref: Optional[str] = None,
              operator_priority: Optional[str] = None, related_to_active_goal: bool = False,
              time_sensitive: bool = False, novel: bool = False,
              uncertainty: Optional[str] = None, dependencies: Sequence[str] = (),
              now: Optional[float] = None) -> Dict[str, Any]:
    """
    Decide a CATEGORY from the evidence and the recorded factors - never from a self-declared label.

    Returns the factor set, the policy version and a REASON, so a later reader can audit the decision instead
    of trusting a number.
    """
    moment = _moment(now)
    resolved = _evidence_resolves(db_path, evidence_ref)
    integrity = _architectural_integrity_concern(db_path, evidence_ref)
    factors = {"sensor_kind": sensor_kind, "declared_severity": declared_severity,
               "has_evidence_reference": evidence_ref is not None,
               "evidence_reference_resolves": resolved, "operator_priority": operator_priority,
               "related_to_active_goal": bool(related_to_active_goal),
               "time_sensitive": bool(time_sensitive), "novel": bool(novel),
               "uncertainty": uncertainty, "dependencies": sorted(str(dep) for dep in dependencies),
               "verified_architectural_integrity_concern": integrity}

    if resolved and (operator_priority == "HIGH" or integrity):
        category, reason = CRITICAL, (REASON_OPERATOR_PRIORITY if operator_priority == "HIGH"
                                      else REASON_ARCHITECTURAL_INTEGRITY)
    elif resolved and related_to_active_goal:
        category, reason = CRITICAL, REASON_VERIFIED_FINDING
    elif evidence_ref is not None and not resolved:
        category, reason = FOCUSED, REASON_UNRESOLVED_EVIDENCE
    elif resolved:
        # Evidence that resolves, but without a corroborating factor strong enough for CRITICAL. It is a
        # meaningful observation, so it earns FOCUSED - never BACKGROUND, and never CRITICAL on its own.
        category, reason = FOCUSED, REASON_EVIDENCE_BACKED
    elif declared_severity in ("CRITICAL", "HIGH") or (sensor_kind == "ANOMALY"):
        # A self-declared alarm is NOT evidence. It is recorded and it earns FOCUSED, nothing more.
        category, reason = FOCUSED, REASON_SELF_DECLARED
    elif operator_priority in ("MEDIUM", "HIGH") or related_to_active_goal or time_sensitive:
        category, reason = FOCUSED, (REASON_OPERATOR_PRIORITY if operator_priority else REASON_ACTIVE_GOAL)
    else:
        category, reason = BACKGROUND, REASON_ROUTINE
    return {"category": category, "reason": reason, "factors": factors,
            "policy_version": ATTENTION_POLICY_V1, "decided_at": moment,
            "mints_authority": False}


# ------------------------------------------------------------------ submission and dedup
def submit(db_path: str, *, subject_ref: str, budget: AttentionBudget = DEFAULT_BUDGET,
           dedup_key: Optional[str] = None, ttl_seconds: Optional[float] = None,
           now: Optional[float] = None, **classification: Any) -> Dict[str, Any]:
    """Queue one attention request. Duplicates consume no budget; the queue bound refuses explicitly."""
    moment = _moment(now)
    canonical_owner = classification.pop("canonical_owner", None)
    decision = classify(db_path, subject_ref=subject_ref, now=moment, **classification)
    category, factors, reason = decision["category"], decision["factors"], decision["reason"]

    if dedup_key is not None:
        open_rows = _rows(db_path, "SELECT request_id FROM ciph_attention_requests WHERE dedup_key = ? "
                                   "AND status = ?;", (str(dedup_key), PENDING))
        if open_rows:
            _event(db_path, kind="DUPLICATE_SUPPRESSED",
                   detail={"dedup_key": dedup_key, "existing": open_rows[0]["request_id"]}, now=moment)
            return {"request_id": open_rows[0]["request_id"], "status": DUPLICATE, "queued": False,
                    "consumed_budget": False, "policy_version": ATTENTION_POLICY_V1}

    pending = _rows(db_path, "SELECT COUNT(*) AS n FROM ciph_attention_requests WHERE status = ?;",
                    (PENDING,))
    if pending and int(pending[0]["n"]) >= int(budget.max_queue):
        _set_state(db_path, "queue_overflow_count",
                   str(int(_get_state(db_path, "queue_overflow_count", "0") or 0) + 1), now=moment)
        _event(db_path, kind="QUEUE_OVERFLOW", detail={"subject_ref": subject_ref,
                                                       "category": category}, now=moment)
        return {"status": QUEUE_OVERFLOW, "queued": False, "loss_indicated": True,
                "category": category, "reason": reason, "policy_version": ATTENTION_POLICY_V1}

    request_id = "ATR-" + digest({"subject": str(subject_ref), "category": category, "at": moment,
                                  "reason": reason})[:16].upper()
    expires_at = None if ttl_seconds is None else moment + float(ttl_seconds)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_attention_requests (request_id, subject_ref, sensor_kind, "
            "declared_severity, category, factors_json, reason, evidence_ref, canonical_owner, dedup_key, "
            "enqueued_at, expires_at, status, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (request_id, str(subject_ref), factors["sensor_kind"], factors["declared_severity"], category,
             json.dumps(factors, sort_keys=True, default=str), reason,
             classification.get("evidence_ref"), canonical_owner,
             None if dedup_key is None else str(dedup_key), moment, expires_at, PENDING,
             ATTENTION_POLICY_V1))
        connection.commit()
    finally:
        connection.close()
    _event(db_path, kind="REQUEST_QUEUED",
           detail={"request_id": request_id, "category": category, "reason": reason,
                   "factors": factors}, now=moment)
    return {"request_id": request_id, "status": PENDING, "queued": True, "category": category,
            "reason": reason, "factors": factors, "policy_version": ATTENTION_POLICY_V1}


def requests(db_path: str, *, status: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_attention_requests"
    params: Tuple[Any, ...] = ()
    if status is not None:
        query += " WHERE status = ?"
        params = (str(status),)
    query += " ORDER BY enqueued_at, request_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["factors"] = json.loads(row.pop("factors_json") or "{}")
    return rows


def expire(db_path: str, *, now: Optional[float] = None) -> List[str]:
    """Obsolete attention requests are CANCELLED by expiry, not silently dropped."""
    moment = _moment(now)
    rows = _rows(db_path, "SELECT request_id FROM ciph_attention_requests WHERE status = ? AND "
                          "expires_at IS NOT NULL AND expires_at <= ?;", (PENDING, moment))
    connection = _connect(db_path)
    try:
        init_schema(connection)
        for row in rows:
            connection.execute("UPDATE ciph_attention_requests SET status = ? WHERE request_id = ?;",
                               (EXPIRED, row["request_id"]))
        connection.commit()
    finally:
        connection.close()
    for row in rows:
        _event(db_path, kind="REQUEST_EXPIRED", detail={"request_id": row["request_id"]}, now=moment)
    return [row["request_id"] for row in rows]


def cancel(db_path: str, *, request_id: str, reason: str, now: Optional[float] = None) -> Dict[str, Any]:
    moment = _moment(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_attention_requests SET status = ? WHERE request_id = ?;",
                           (CANCELLED, str(request_id)))
        connection.commit()
    finally:
        connection.close()
    _event(db_path, kind="REQUEST_CANCELLED", detail={"request_id": request_id, "reason": reason},
           now=moment)
    return {"request_id": str(request_id), "status": CANCELLED, "reason": str(reason)}


# ------------------------------------------------------------------ scheduling and the budget
def _window(db_path: str, *, budget: AttentionBudget, now: float) -> Dict[str, Any]:
    start = now - (now % float(budget.window_seconds))
    return {"window_id": f"WIN-{int(start)}", "window_start": start,
            "window_end": start + float(budget.window_seconds)}


def invocations_this_window(db_path: str, *, budget: AttentionBudget = DEFAULT_BUDGET,
                            now: Optional[float] = None) -> int:
    window = _window(db_path, budget=budget, now=_moment(now))
    rows = _rows(db_path, "SELECT invocations FROM ciph_attention_windows WHERE window_id = ?;",
                 (window["window_id"],))
    return 0 if not rows else int(rows[0]["invocations"])


def _record_invocation(db_path: str, *, budget: AttentionBudget, now: float) -> None:
    window = _window(db_path, budget=budget, now=now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT INTO ciph_attention_windows (window_id, window_start, window_end, invocations, "
            "policy_version) VALUES (?,?,?,?,?) ON CONFLICT(window_id) DO UPDATE SET "
            "invocations = invocations + 1;",
            (window["window_id"], window["window_start"], window["window_end"], 1, ATTENTION_POLICY_V1))
        connection.commit()
    finally:
        connection.close()


def _consecutive_critical(db_path: str) -> int:
    """How many CRITICAL invocations happened in a row, so a burst cannot starve everything else."""
    rows = _rows(db_path, "SELECT detail_json FROM ciph_attention_events WHERE kind = 'REQUEST_INVOKED' "
                          "ORDER BY recorded_at DESC, record_id DESC LIMIT 20;")
    streak = 0
    for row in rows:
        detail = json.loads(row["detail_json"] or "{}")
        categories = detail.get("categories") or ([detail["primary_category"]]
                                                  if detail.get("primary_category") else [])
        if categories[:1] == [CRITICAL]:
            streak += 1
        else:
            break
    return streak


def starved(db_path: str, *, budget: AttentionBudget = DEFAULT_BUDGET,
            now: Optional[float] = None) -> List[Dict[str, Any]]:
    moment = _moment(now)
    return [{"request_id": row["request_id"], "category": row["category"],
             "waited_seconds": moment - float(row["enqueued_at"])}
            for row in _rows(db_path, "SELECT * FROM ciph_attention_requests WHERE status = ? "
                                      "ORDER BY enqueued_at;", (PENDING,))
            if moment - float(row["enqueued_at"]) > float(budget.starvation_ceiling)]


def schedule(db_path: str, *, budget: AttentionBudget = DEFAULT_BUDGET, batch_size: int = 1,
             now: Optional[float] = None) -> Dict[str, Any]:
    """
    Choose what to reason about next. Deterministic, and it records WHY.

    CRITICAL preempts. Within a category the oldest request goes first, and a request that has waited past the
    starvation ceiling is PROMOTED - so a burst of high-priority events cannot starve everything else
    indefinitely. BACKGROUND work is never selected for invocation: it is retained without the model.
    """
    moment = _moment(now)
    expire(db_path, now=moment)
    pending = _rows(db_path, "SELECT * FROM ciph_attention_requests WHERE status = ? "
                             "ORDER BY enqueued_at, request_id;", (PENDING,))
    if not pending:
        return {"status": NOTHING_TO_DO, "selected": [], "policy_version": ATTENTION_POLICY_V1}

    long_waiting = [row for row in pending
                    if moment - float(row["enqueued_at"]) > float(budget.starvation_ceiling)]
    streak = _consecutive_critical(db_path)
    must_yield = streak >= int(budget.max_consecutive_critical)

    def rank(row: Dict[str, Any]) -> Tuple[int, int, float, str]:
        category = row["category"]
        effective = _CATEGORY_RANK.get(category, 9)
        promoted = 0 if row in long_waiting else 1
        if must_yield and category == CRITICAL:
            # A CRITICAL burst YIELDS: its effective rank drops to FOCUSED's and it loses the tie to the
            # older work. Otherwise a stream of alarms would starve every other task indefinitely.
            effective = _CATEGORY_RANK[FOCUSED]
            promoted = 2
        return (effective, promoted, float(row["enqueued_at"]), row["request_id"])

    invocable = [row for row in pending if row["category"] in (CRITICAL, FOCUSED)]
    if not invocable:
        return {"status": NOTHING_TO_DO, "selected": [], "background_only": True,
                "note": "routine activity is retained without invoking the model",
                "policy_version": ATTENTION_POLICY_V1}
    invocable.sort(key=rank)
    head = invocable[0]
    chosen = [head]
    if head["category"] == FOCUSED and int(batch_size) > 1:
        same = [row for row in invocable[1:] if row["category"] == FOCUSED]
        chosen = [head] + same[: int(batch_size) - 1]
    return {"status": "SELECTED", "selected": [row["request_id"] for row in chosen],
            "categories": [row["category"] for row in chosen],
            "tie_break_rule": _SELECTION_TIE_BREAK, "promoted_for_starvation":
            [row["request_id"] for row in chosen if row in long_waiting],
            "critical_streak": streak, "policy_version": ATTENTION_POLICY_V1}


def invoke(db_path: str, *, budget: AttentionBudget = DEFAULT_BUDGET, batch_size: int = 1,
           now: Optional[float] = None) -> Dict[str, Any]:
    """
    Spend ONE unit of the bounded reasoning budget. The only thing here that consumes inference.

    If the model is unavailable, or the window's budget is spent, the request stays PENDING and NO outcome is
    recorded: an unfunded decision is not a failed one, and it is certainly not an invented one.
    """
    moment = _moment(now)
    if str(_get_state(db_path, "model_available", "true")).lower() != "true":
        _event(db_path, kind="INVOCATION_REFUSED",
               detail={"reason": MODEL_UNAVAILABLE, "model_available": False}, now=moment)
        return {"status": MODEL_UNAVAILABLE, "outcome_recorded": False, "policy_version":
                ATTENTION_POLICY_V1,
                "note": "the queue is preserved; no reasoning outcome is invented"}
    if invocations_this_window(db_path, budget=budget, now=moment) >= int(budget.max_invocations_per_window):
        _event(db_path, kind="INVOCATION_REFUSED", detail={"reason": BUDGET_EXHAUSTED}, now=moment)
        return {"status": BUDGET_EXHAUSTED, "outcome_recorded": False,
                "policy_version": ATTENTION_POLICY_V1}
    plan = schedule(db_path, budget=budget, batch_size=batch_size, now=moment)
    if plan["status"] != "SELECTED":
        return plan

    connection = _connect(db_path)
    try:
        init_schema(connection)
        for request_id in plan["selected"]:
            connection.execute("UPDATE ciph_attention_requests SET status = ? WHERE request_id = ?;",
                               (INVOKED, request_id))
        connection.commit()
    finally:
        connection.close()
    _record_invocation(db_path, budget=budget, now=moment)
    focus_ids = []
    for request_id in plan["selected"]:
        record = _rows(db_path, "SELECT * FROM ciph_attention_requests WHERE request_id = ?;",
                       (request_id,))[0]
        focus_ids.append(open_focus(db_path, request_id=request_id, subject_ref=record["subject_ref"],
                                    category=record["category"],
                                    context_ref=record.get("evidence_ref"), budget=budget,
                                    now=moment)["focus_id"])
    _event(db_path, kind="REQUEST_INVOKED",
           detail={"requests": plan["selected"], "categories": plan["categories"],
                   "primary_category": (plan["categories"] or [None])[0],
                   "batch": len(plan["selected"]), "focus": focus_ids}, now=moment)
    return {"status": INVOKED, "outcome_recorded": True, "requests": plan["selected"],
            "categories": plan["categories"], "batch": len(plan["selected"]), "focus_ids": focus_ids,
            "invocations_this_window": invocations_this_window(db_path, budget=budget, now=moment),
            "tie_break_rule": plan["tie_break_rule"], "policy_version": ATTENTION_POLICY_V1}


# ------------------------------------------------------------------ focus contexts
def open_focus(db_path: str, *, request_id: Optional[str], subject_ref: str, category: str,
               context_ref: Optional[str] = None, pending_questions: Sequence[str] = (),
               budget: AttentionBudget = DEFAULT_BUDGET, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Open a focus context, SUSPENDING (never destroying) the oldest context if the bound is reached.

    A change of focus must not silently discard the previous investigation's context.
    """
    moment = _moment(now)
    active = _rows(db_path, "SELECT * FROM ciph_attention_focus WHERE status = ? ORDER BY opened_at;",
                   (FOCUS_ACTIVE,))
    if len(active) >= int(budget.max_active_focus):
        victim = active[0]
        checkpoint(db_path, focus_id=victim["focus_id"], context_ref=victim["context_ref"],
                   pending_questions=json.loads(victim["pending_questions_json"] or "[]"),
                   status=FOCUS_SUSPENDED, now=moment)
        _event(db_path, kind="FOCUS_SUSPENDED",
               detail={"focus_id": victim["focus_id"], "subject_ref": victim["subject_ref"],
                       "reason": "active-focus bound reached"}, now=moment)
    focus_id = "ATF-" + digest({"request": request_id, "subject": str(subject_ref), "at": moment,
                                "category": category})[:16].upper()
    questions = [str(item) for item in pending_questions]
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_attention_focus (focus_id, request_id, subject_ref, category, "
            "context_ref, context_json, pending_questions_json, checkpoint_digest, opened_at, closed_at, "
            "status, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
            (focus_id, request_id, str(subject_ref), str(category), context_ref, None,
             json.dumps(questions), None, moment, None, FOCUS_ACTIVE, ATTENTION_POLICY_V1))
        connection.commit()
    finally:
        connection.close()
    return {"focus_id": focus_id, "subject_ref": str(subject_ref), "category": str(category),
            "context_ref": context_ref, "status": FOCUS_ACTIVE, "pending_questions": questions}


def checkpoint(db_path: str, *, focus_id: str, context_ref: Optional[str], pending_questions: Sequence[str] = (),
               status: str = FOCUS_SUSPENDED, now: Optional[float] = None) -> Dict[str, Any]:
    """Persist a focus context so it survives a restart and a change of focus."""
    moment = _moment(now)
    questions = [str(item) for item in pending_questions]
    checkpoint_digest = digest({"focus": str(focus_id), "context": context_ref, "questions": questions})
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_attention_focus SET context_ref = ?, pending_questions_json = ?, "
                           "checkpoint_digest = ?, status = ?, closed_at = ? WHERE focus_id = ?;",
                           (context_ref, json.dumps(questions), checkpoint_digest, str(status),
                            moment if str(status) == FOCUS_CLOSED else None, str(focus_id)))
        connection.commit()
    finally:
        connection.close()
    return {"focus_id": str(focus_id), "context_ref": context_ref, "pending_questions": questions,
            "checkpoint_digest": checkpoint_digest, "status": str(status)}


def close_focus(db_path: str, *, focus_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    return checkpoint(db_path, focus_id=focus_id, context_ref=None, status=FOCUS_CLOSED, now=now)


def focus_contexts(db_path: str, *, status: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_attention_focus"
    params: Tuple[Any, ...] = ()
    if status is not None:
        query += " WHERE status = ?"
        params = (str(status),)
    query += " ORDER BY opened_at, focus_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["pending_questions"] = json.loads(row.pop("pending_questions_json") or "[]")
        row.pop("context_json", None)
    return rows


def restore(db_path: str, focus_id: str) -> Dict[str, Any]:
    """Bring a suspended context back WITHOUT re-deriving it: the checkpoint is returned as stored."""
    rows = _rows(db_path, "SELECT * FROM ciph_attention_focus WHERE focus_id = ?;", (str(focus_id),))
    if not rows:
        raise CrucibleError("UNKNOWN_FOCUS_CONTEXT", str(focus_id))
    record = dict(rows[0])
    record["pending_questions"] = json.loads(record.pop("pending_questions_json") or "[]")
    record.pop("context_json", None)
    record["preserved"] = True
    return record


# ------------------------------------------------------------------ model outage
def model_unavailable(db_path: str, *, reason: str, now: Optional[float] = None) -> Dict[str, Any]:
    moment = _moment(now)
    _set_state(db_path, "model_available", "false", now=moment)
    _set_state(db_path, "model_unavailable_reason", str(reason), now=moment)
    _event(db_path, kind="MODEL_UNAVAILABLE", detail={"reason": str(reason)}, now=moment)
    return {"model_available": False, "reason": str(reason), "outcome_recorded": False,
            "queue_preserved": True}


def model_available(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    moment = _moment(now)
    _set_state(db_path, "model_available", "true", now=moment)
    _event(db_path, kind="MODEL_AVAILABLE", detail={}, now=moment)
    return {"model_available": True, "queue_preserved": True,
            "pending": len(requests(db_path, status=PENDING))}


def history(db_path: str) -> List[Dict[str, Any]]:
    """The attention DECISIONS. These are not evidence and they do not claim any work completed."""
    rows = _rows(db_path, "SELECT * FROM ciph_attention_events ORDER BY recorded_at, record_id;")
    for row in rows:
        row["detail"] = json.loads(row.pop("detail_json") or "{}")
        row["is_evidence"] = False
    return rows


def attention_digest(db_path: str) -> str:
    """Durable decision state only - no wall-clock field can make two processes disagree."""
    return digest({"requests": requests(db_path), "focus": focus_contexts(db_path),
                   "events": history(db_path),
                   "windows": _rows(db_path, "SELECT * FROM ciph_attention_windows "
                                             "ORDER BY window_id;")})
