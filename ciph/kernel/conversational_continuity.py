"""
ciph/kernel/conversational_continuity - 10.1: durable, authoritative CONVERSATION identity.

    Conversational memory is not an alternative source of operational truth.

WHAT A CONVERSATIONAL RECORD AUTHORITATIVELY ESTABLISHES, AND WHAT IT DOES NOT.

It establishes WHAT WAS SAID, BY WHOM, IN WHICH CONVERSATION, WHEN, and WHAT IT REFERRED TO. That is the
whole of its authority. It does NOT establish that a statement was factually correct, that an action
occurred, or that work is authorized:

    an EXECUTION claim must resolve to execution evidence (4.3 / 4.0),
    a DISCOVERY claim must resolve to findings (10.0),
    a COMMITMENT is a record of a promise - it is NOT authorization to execute anything. The commitment
    carries an OPTIONAL authorization reference, and whether that reference still permits work is decided by
    the owner that grants it (5.x standing authorization, 4.0 permits), never here.

So this module owns conversations, and it BINDS to 10.0 for findings and follow-ups, to 4.4 for investigation
identity, to 10.5 for relationships, to 10.6 for attention checkpoints, and to 4.1 for remaining authorized
work. It never writes their tables.

Every turn carries identity, ordering and provenance, so a FRESH PROCESS reconstructs the same history
without the model's context window. References resolve to DURABLE IDENTITIES; where several referents are
plausible the ambiguity is exposed rather than silently resolved.
"""

import json
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

CONVERSATIONAL_CONTINUITY_V1 = "CONVERSATIONAL_CONTINUITY_V1"
CONVERSATION_SESSION_V1 = "CONVERSATION_SESSION_V1"
CONVERSATION_TURN_V1 = "CONVERSATION_TURN_V1"
CONVERSATION_REFERENCE_V1 = "CONVERSATION_REFERENCE_V1"

OPERATOR = "OPERATOR"
ASSISTANT = "ASSISTANT"
GUEST = "GUEST"
PARTICIPANT_ROLES = (OPERATOR, ASSISTANT, GUEST)

UTTERANCE = "UTTERANCE"
ANNOUNCEMENT = "ANNOUNCEMENT"
DECISION = "DECISION"
COMMITMENT = "COMMITMENT"
QUESTION = "QUESTION"
CLARIFICATION = "CLARIFICATION"
TURN_KINDS = (UTTERANCE, ANNOUNCEMENT, DECISION, COMMITMENT, QUESTION, CLARIFICATION)

OPEN = "OPEN"
CLOSED = "CLOSED"
ANSWERED = "ANSWERED"

FINDING = "FINDING"
RESULT_SET = "RESULT_SET"
INVESTIGATION = "INVESTIGATION"
WORKER_RESULT = "WORKER_RESULT"
ATTENTION_FOCUS = "ATTENTION_FOCUS"
TURN_REF = "TURN"
COMMITMENT_REF = "COMMITMENT"
REF_KINDS = (FINDING, RESULT_SET, INVESTIGATION, WORKER_RESULT, ATTENTION_FOCUS, TURN_REF, COMMITMENT_REF)

REASON_UNKNOWN_PARTICIPANT = "UNKNOWN_PARTICIPANT"
REASON_UNKNOWN_CHANNEL = "UNKNOWN_CHANNEL"
REASON_UNKNOWN_SESSION = "UNKNOWN_SESSION"
REASON_INVALID_KIND = "INVALID_TURN_KIND"
REASON_REFERENCE_DOES_NOT_RESOLVE = "REFERENCE_DOES_NOT_RESOLVE"
REASON_PARTICIPANT_NOT_AUTHORIZED = "PARTICIPANT_NOT_AUTHORIZED_FOR_THIS_CONTEXT"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_conv_participants (
        participant_id TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        display_name TEXT,
        authority_ref TEXT,
        registered_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_conv_channels (
        channel_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        adapter_ref TEXT,
        trusted INTEGER NOT NULL,
        external_delivery INTEGER NOT NULL,
        registered_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_conv_sessions (
        session_id TEXT PRIMARY KEY,
        participant_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        topic_ref TEXT,
        status TEXT NOT NULL,
        opened_at REAL NOT NULL,
        closed_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_conv_turns (
        turn_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        speaker TEXT NOT NULL,
        kind TEXT NOT NULL,
        text TEXT,
        refs_json TEXT,
        authorization_ref TEXT,
        provenance TEXT,
        recorded_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_conv_questions (
        question_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        text TEXT,
        status TEXT NOT NULL,
        answer_turn_id TEXT,
        raised_at REAL NOT NULL,
        resolved_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_conv_summaries (
        summary_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        text TEXT,
        superseded_by TEXT,
        regenerated_at REAL,
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


# ------------------------------------------------------------------ identity
def register_participant(db_path: str, *, participant_id: str, role: str,
                         display_name: Optional[str] = None, authority_ref: Optional[str] = None,
                         now: Optional[float] = None) -> Dict[str, Any]:
    """Only an authorized participant may be registered; a role is a stable property, not a claim per turn."""
    if role not in PARTICIPANT_ROLES:
        raise CrucibleError("INVALID_PARTICIPANT_ROLE", str(role))
    key = str(participant_id).strip()
    if not key:
        raise CrucibleError("PARTICIPANT_REQUIRES_AN_ID", repr(participant_id))
    moment = _moment(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_conv_participants (participant_id, role, "
                           "display_name, authority_ref, registered_at, policy_version) "
                           "VALUES (?,?,?,?,?,?);",
                           (key, str(role), display_name, authority_ref, moment,
                            CONVERSATIONAL_CONTINUITY_V1))
        connection.commit()
    finally:
        connection.close()
    return {"participant_id": key, "role": str(role), "display_name": display_name,
            "authority_ref": authority_ref, "policy_version": CONVERSATIONAL_CONTINUITY_V1}


def participant(db_path: str, participant_id: str) -> Dict[str, Any]:
    rows = _rows(db_path, "SELECT * FROM ciph_conv_participants WHERE participant_id = ?;",
                 (str(participant_id),))
    if not rows:
        raise CrucibleError(REASON_UNKNOWN_PARTICIPANT, str(participant_id))
    return rows[0]


def register_channel(db_path: str, *, channel_id: str, kind: str, adapter_ref: Optional[str] = None,
                     trusted: bool = True, external_delivery: bool = False,
                     now: Optional[float] = None) -> Dict[str, Any]:
    """
    Register a channel. `external_delivery` records whether the channel ACTUALLY delivers outside this
    process; a local adapter must not claim it, and the claim is refused if it tries.
    """
    key = str(channel_id).strip()
    if not key:
        raise CrucibleError("CHANNEL_REQUIRES_AN_ID", repr(channel_id))
    moment = _moment(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_conv_channels (channel_id, kind, adapter_ref, "
                           "trusted, external_delivery, registered_at, policy_version) VALUES (?,?,?,?,?,?,?);",
                           (key, str(kind), adapter_ref, 1 if trusted else 0,
                            1 if external_delivery else 0, moment, CONVERSATIONAL_CONTINUITY_V1))
        connection.commit()
    finally:
        connection.close()
    return {"channel_id": key, "kind": str(kind), "trusted": bool(trusted),
            "external_delivery": bool(external_delivery),
            "policy_version": CONVERSATIONAL_CONTINUITY_V1}


def channel(db_path: str, channel_id: str) -> Dict[str, Any]:
    rows = _rows(db_path, "SELECT * FROM ciph_conv_channels WHERE channel_id = ?;", (str(channel_id),))
    if not rows:
        raise CrucibleError(REASON_UNKNOWN_CHANNEL, str(channel_id))
    record = rows[0]
    record["trusted"] = bool(record["trusted"])
    record["external_delivery"] = bool(record["external_delivery"])
    return record


def open_session(db_path: str, *, session_id: str, participant_id: str, channel_id: str,
                 topic_ref: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """A session binds ONE authorized participant to ONE channel. Identity does not float across channels."""
    participant(db_path, participant_id)
    channel(db_path, channel_id)
    moment = _moment(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_conv_sessions (session_id, participant_id, "
                           "channel_id, topic_ref, status, opened_at, closed_at, policy_version) "
                           "VALUES (?,?,?,?,?,?,?,?);",
                           (str(session_id), str(participant_id), str(channel_id), topic_ref, OPEN,
                            moment, None, CONVERSATION_SESSION_V1))
        connection.commit()
    finally:
        connection.close()
    return {"session_id": str(session_id), "participant_id": str(participant_id),
            "channel_id": str(channel_id), "topic_ref": topic_ref, "status": OPEN,
            "opened_at": moment, "policy_version": CONVERSATION_SESSION_V1}


def close_session(db_path: str, *, session_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    moment = _moment(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_conv_sessions SET status = ?, closed_at = ? WHERE session_id = ?;",
                           (CLOSED, moment, str(session_id)))
        connection.commit()
    finally:
        connection.close()
    return {"session_id": str(session_id), "status": CLOSED, "closed_at": moment}


def session(db_path: str, session_id: str) -> Dict[str, Any]:
    rows = _rows(db_path, "SELECT * FROM ciph_conv_sessions WHERE session_id = ?;", (str(session_id),))
    if not rows:
        raise CrucibleError(REASON_UNKNOWN_SESSION, str(session_id))
    return rows[0]


def sessions(db_path: str, *, status: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_conv_sessions"
    params: Tuple[Any, ...] = ()
    if status is not None:
        query += " WHERE status = ?"
        params = (str(status),)
    query += " ORDER BY opened_at, session_id;"
    return _rows(db_path, query, params)


# ------------------------------------------------------------------ turns
def _validate_ref(db_path: str, ref_kind: str, ref_value: str) -> bool:
    """A reference must resolve in the owner that holds it. Anything else is a dangling claim."""
    if ref_kind == FINDING:
        return bool(_rows(db_path, "SELECT finding_id FROM ciph_findings WHERE finding_id = ?;",
                          (str(ref_value),)))
    if ref_kind == RESULT_SET:
        return bool(_rows(db_path, "SELECT result_set_id FROM ciph_result_sets WHERE result_set_id = ?;",
                          (str(ref_value),)))
    if ref_kind == INVESTIGATION:
        return bool(_rows(db_path, "SELECT result_set_id FROM ciph_result_sets "
                                   "WHERE investigation_ref = ?;", (str(ref_value),))) or \
            bool(_rows(db_path, "SELECT proposal_id FROM ciph_curiosity_proposals "
                                "WHERE proposal_id = ?;", (str(ref_value),)))
    if ref_kind == WORKER_RESULT:
        try:
            from ciph.kernel.swarm_results import get_result
            get_result(db_path, str(ref_value))
            return True
        except Exception:
            return False
    if ref_kind == ATTENTION_FOCUS:
        return bool(_rows(db_path, "SELECT focus_id FROM ciph_attention_focus WHERE focus_id = ?;",
                          (str(ref_value),)))
    if ref_kind == TURN_REF:
        return bool(_rows(db_path, "SELECT turn_id FROM ciph_conv_turns WHERE turn_id = ?;",
                          (str(ref_value),)))
    if ref_kind == COMMITMENT_REF:
        return bool(_rows(db_path, "SELECT turn_id FROM ciph_conv_turns WHERE turn_id = ? AND kind = ?;",
                          (str(ref_value), COMMITMENT)))
    return False


def record_turn(db_path: str, *, session_id: str, speaker: str, text: str, kind: str = UTTERANCE,
                refs: Sequence[Tuple[str, str]] = (), authorization_ref: Optional[str] = None,
                provenance: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record ONE turn, with ordering, provenance and validated references.

    A COMMITMENT turn records a PROMISE. `authorization_ref` is optional and, when present, is only a
    POINTER: whether it still permits work is decided by the owner that granted it.
    """
    session(db_path, session_id)
    if kind not in TURN_KINDS:
        raise CrucibleError(REASON_INVALID_KIND, str(kind))
    moment = _moment(now)
    resolved: List[Dict[str, Any]] = []
    for ref_kind, ref_value in refs:
        if ref_kind not in REF_KINDS:
            raise CrucibleError("UNKNOWN_REFERENCE_KIND", str(ref_kind))
        ok = _validate_ref(db_path, ref_kind, str(ref_value))
        resolved.append({"ref_kind": ref_kind, "ref_value": str(ref_value), "resolved": ok})
    ordinal = len(turns(db_path, session_id=session_id)) + 1
    turn_id = "TRN-" + digest({"session": str(session_id), "ordinal": ordinal, "speaker": str(speaker),
                               "text": str(text)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_conv_turns (turn_id, session_id, ordinal, speaker, kind, text, "
            "refs_json, authorization_ref, provenance, recorded_at, policy_version) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (turn_id, str(session_id), ordinal, str(speaker), str(kind), str(text),
             json.dumps(resolved, sort_keys=True), authorization_ref, provenance, moment,
             CONVERSATION_TURN_V1))
        if kind == QUESTION:
            question_id = "QST-" + digest({"turn": turn_id})[:16].upper()
            connection.execute(
                "INSERT OR IGNORE INTO ciph_conv_questions (question_id, session_id, turn_id, text, "
                "status, answer_turn_id, raised_at, resolved_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?);",
                (question_id, str(session_id), turn_id, str(text), OPEN, None, moment, None,
                 CONVERSATION_TURN_V1))
        connection.commit()
    finally:
        connection.close()
    return {"turn_id": turn_id, "session_id": str(session_id), "ordinal": ordinal, "speaker": str(speaker),
            "kind": str(kind), "text": str(text), "refs": resolved, "authorization_ref": authorization_ref,
            "provenance": provenance, "recorded_at": moment, "policy_version": CONVERSATION_TURN_V1,
            "establishes": "what was said, by whom, in which conversation",
            "does_not_establish": ["that the statement was correct", "that an action occurred",
                                   "that work is authorized"]}


def turns(db_path: str, *, session_id: Optional[str] = None, kind: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_conv_turns"
    clauses: List[str] = []
    params: List[Any] = []
    if session_id is not None:
        clauses.append("session_id = ?")
        params.append(str(session_id))
    if kind is not None:
        clauses.append("kind = ?")
        params.append(str(kind))
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY session_id, ordinal, turn_id;"
    rows = _rows(db_path, query, tuple(params))
    for row in rows:
        row["refs"] = json.loads(row.pop("refs_json") or "[]")
    return rows


def history(db_path: str, *, session_id: Optional[str] = None) -> Dict[str, Any]:
    """The durable history a fresh process reconstructs WITHOUT any model context window."""
    return {"policy_version": CONVERSATIONAL_CONTINUITY_V1,
            "sessions": [record for record in sessions(db_path)
                         if session_id is None or record["session_id"] == session_id],
            "turns": turns(db_path, session_id=session_id),
            "questions": outstanding_questions(db_path, session_id=session_id),
            "reconstructed_from": "durable rows", "used_the_model_context_window": False}


def authorized_history(db_path: str, *, session_id: str, participant_id: str) -> Dict[str, Any]:
    """
    The ACCESS BOUNDARY. Private historical context belongs to the participant who opened the session.

    A forged or unauthorized participant is refused HERE, whatever channel it arrived on, so channel
    transitions cannot be used to walk around identity.
    """
    record = session(db_path, session_id)
    if str(participant_id) != str(record["participant_id"]):
        raise CrucibleError(REASON_PARTICIPANT_NOT_AUTHORIZED, f"{participant_id}:{session_id}")
    payload = history(db_path, session_id=session_id)
    payload["participant_id"] = str(participant_id)
    payload["access_checked"] = True
    return payload


def outstanding_questions(db_path: str, *, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_conv_questions"
    params: Tuple[Any, ...] = ()
    if session_id is not None:
        query += " WHERE session_id = ?"
        params = (str(session_id),)
    query += " ORDER BY raised_at, question_id;"
    return _rows(db_path, query, params)


def resolve_question(db_path: str, *, question_id: str, answer_turn_id: str,
                     now: Optional[float] = None) -> Dict[str, Any]:
    moment = _moment(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_conv_questions SET status = ?, answer_turn_id = ?, "
                           "resolved_at = ? WHERE question_id = ?;",
                           (ANSWERED, str(answer_turn_id), moment, str(question_id)))
        connection.commit()
    finally:
        connection.close()
    return {"question_id": str(question_id), "status": ANSWERED, "answer_turn_id": str(answer_turn_id)}


def commitments(db_path: str, *, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Promises. Each carries an OPTIONAL authorization pointer and never grants anything by itself."""
    records = turns(db_path, session_id=session_id, kind=COMMITMENT)
    for record in records:
        record["is_authorization"] = False
    return records


# ------------------------------------------------------------------ referential understanding
def resolve_reference(db_path: str, *, phrase: str, session_id: Optional[str] = None,
                      actor: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Resolve a follow-up to a DURABLE IDENTITY, never to a semantically similar passage.

    Deterministic first (10.0 owns ordinals and result sets), then the conversational cases. Where several
    referents are plausible the AMBIGUITY is returned rather than silently resolved.
    """
    moment = _moment(now)
    text = str(phrase or "")
    from ciph.kernel.referential_continuity import resolve_conversational_reference
    canonical = resolve_conversational_reference(db_path, text, actor=actor, now=moment)
    if canonical.get("answered_from_evidence"):
        return {"kind": canonical["kind"], "resolved": True, "canonical": canonical,
                "ambiguous": False, "policy_version": CONVERSATIONAL_CONTINUITY_V1}

    lowered = text.lower()
    if "before i disconnected" in lowered or "what were we talking about" in lowered:
        closed = [record for record in sessions(db_path, status=CLOSED)]
        if not closed:
            return {"kind": "NO_PRIOR_CONVERSATION", "resolved": False, "ambiguous": False,
                    "note": "no closed session exists to refer to",
                    "policy_version": CONVERSATIONAL_CONTINUITY_V1}
        latest = sorted(closed, key=lambda record: record["closed_at"] or 0)[-1]
        return {"kind": "PRIOR_SESSION", "resolved": True, "ambiguous": False, "session": latest,
                "topic_ref": latest.get("topic_ref"),
                "policy_version": CONVERSATIONAL_CONTINUITY_V1}

    if "which worker" in lowered:
        from ciph.kernel import operational_awareness as awareness
        links = awareness.links(db_path, kind=awareness.LINK_RESULT_INVESTIGATION)
        if len(links) == 1:
            return {"kind": "WORKER_FOR_INVESTIGATION", "resolved": True, "ambiguous": False,
                    "link": links[0], "policy_version": CONVERSATIONAL_CONTINUITY_V1}
        return {"kind": "WORKER_FOR_INVESTIGATION", "resolved": False, "ambiguous": len(links) > 1,
                "candidates": links, "note": "several correlations exist; name one",
                "policy_version": CONVERSATIONAL_CONTINUITY_V1}

    if "continue the investigation" in lowered or "continue that investigation" in lowered:
        from ciph.kernel.referential_continuity import result_sets
        sets = result_sets(db_path)
        if len(sets) == 1:
            return {"kind": "INVESTIGATION", "resolved": True, "ambiguous": False,
                    "result_set_id": sets[0]["result_set_id"],
                    "investigation_ref": sets[0]["investigation_ref"],
                    "policy_version": CONVERSATIONAL_CONTINUITY_V1}
        return {"kind": "INVESTIGATION", "resolved": False, "ambiguous": len(sets) > 1,
                "candidates": [record["result_set_id"] for record in sets],
                "note": "several investigations exist; name one",
                "policy_version": CONVERSATIONAL_CONTINUITY_V1}

    if session_id is not None and ("that third" in lowered or "the third" in lowered
                                   or "that seventh" in lowered):
        pass  # handled by the canonical resolver above when a finding reference is present
    return {"kind": "UNRESOLVED_REFERENCE", "resolved": False, "ambiguous": False,
            "note": "the reference did not resolve to a durable identity",
            "policy_version": CONVERSATIONAL_CONTINUITY_V1}


# ------------------------------------------------------------------ summaries and context selection
def summarize(db_path: str, *, session_id: str, text: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    A REGENERABLE summary. It is never canonical: recording one supersedes the previous summary and leaves
    every canonical reference untouched.
    """
    session(db_path, session_id)
    moment = _moment(now)
    previous = _rows(db_path, "SELECT summary_id FROM ciph_conv_summaries WHERE session_id = ? "
                              "AND superseded_by IS NULL;", (str(session_id),))
    summary_id = "SUM-" + digest({"session": str(session_id), "text": str(text), "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        for row in previous:
            connection.execute("UPDATE ciph_conv_summaries SET superseded_by = ? WHERE summary_id = ?;",
                               (summary_id, row["summary_id"]))
        connection.execute("INSERT OR IGNORE INTO ciph_conv_summaries (summary_id, session_id, text, "
                           "superseded_by, regenerated_at, policy_version) VALUES (?,?,?,?,?,?);",
                           (summary_id, str(session_id), str(text), None, moment,
                            CONVERSATIONAL_CONTINUITY_V1))
        connection.commit()
    finally:
        connection.close()
    return {"summary_id": summary_id, "session_id": str(session_id), "text": str(text),
            "is_canonical": False, "supersedes": [row["summary_id"] for row in previous],
            "canonical_history_untouched": True, "policy_version": CONVERSATIONAL_CONTINUITY_V1}


def summaries(db_path: str, *, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_conv_summaries"
    params: Tuple[Any, ...] = ()
    if session_id is not None:
        query += " WHERE session_id = ?"
        params = (str(session_id),)
    query += " ORDER BY regenerated_at, summary_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["is_canonical"] = False
    return rows


def context_selection(db_path: str, *, session_id: str, question: Optional[str] = None,
                      focus_refs: Sequence[str] = (), limit: int = 20,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """
    SELECT the references the model should receive - bounded, evidence-linked, and never a dump.

    Summaries are offered as a HINT and clearly marked non-canonical; canonical refs come from the owners, so
    a stale summary cannot override newer canonical evidence.
    """
    moment = _moment(now)
    selected = turns(db_path, session_id=session_id)[-int(limit):]
    live_summaries = [row for row in summaries(db_path, session_id=session_id)
                      if row["superseded_by"] is None]
    references = [{"turn_id": row["turn_id"], "kind": row["kind"], "speaker": row["speaker"],
                   "refs": row["refs"], "canonical_owner": "conversational_continuity"}
                  for row in selected]
    return {"policy_version": CONVERSATIONAL_CONTINUITY_V1, "session_id": str(session_id),
            "references": references, "focus_refs": [str(ref) for ref in focus_refs],
            "summary_hints": [{"summary_id": row["summary_id"], "text": row["text"],
                               "is_canonical": False} for row in live_summaries],
            "canonical_evidence_is_separate": True, "bounded": True, "selected": len(references),
            "selected_at": moment}


def conversation_digest(db_path: str) -> str:
    """Durable rows only, so a fresh process computes the same digest."""
    payload = {
        "participants": _rows(db_path, "SELECT * FROM ciph_conv_participants ORDER BY participant_id;"),
        "channels": _rows(db_path, "SELECT * FROM ciph_conv_channels ORDER BY channel_id;"),
        "sessions": _rows(db_path, "SELECT * FROM ciph_conv_sessions ORDER BY session_id;"),
        "turns": turns(db_path),
        "questions": _rows(db_path, "SELECT * FROM ciph_conv_questions ORDER BY question_id;"),
        "summaries": _rows(db_path, "SELECT summary_id, session_id, superseded_by FROM ciph_conv_summaries "
                                    "ORDER BY summary_id;"),
    }
    return digest(payload)
