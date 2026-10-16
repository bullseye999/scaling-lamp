"""
ciph/kernel/personality_policy - 10.12: a VERSIONED personality policy, and nothing else.

    Personality may shape expression. It must never manufacture reality.

WHAT THIS OWNS: versioned CONVERSATIONAL PREFERENCES - a key, a value, a provenance, the evidence that
motivated it, the AUTHORITY CLASS it belongs to, a version, and a history that supports review, reversal and
rollback. It owns no facts, no findings, no commitments to act and no operational state. The expression
MECHANISMS stay where R14 put them (`personality_engine.py` shapes tone, `mood_engine.py` holds tone state);
this module decides WHICH declared preference applies and at what version.

SIX THINGS THAT MUST NOT BLEED INTO EACH OTHER (Part A):

    STABLE_COMMITMENT      e.g. "do not open every message with an honorific". Operator-only, durable.
    OPERATOR_PREFERENCE    an explicit preference operator stated. Operator-only.
    INTERACTION_FEEDBACK   something observed in one interaction. LOW authority: never permanent alone.
    DERIVED_TENDENCY       a pattern derived from repeated feedback. Requires repetition to activate.
    TEMPORARY_CONTEXT      session-scoped and EXPIRING; it cannot outlive its window.
    OPERATIONAL_EVIDENCE   not a preference at all. This module stores no facts, and a preference can never
                           change one.

A single ambiguous joke or an emotional reaction CANNOT rewrite the style: a low-authority signal is recorded
as PENDING and needs a second confirmation (or an operator) before it becomes ACTIVE.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

PERSONALITY_POLICY_V1 = "PERSONALITY_POLICY_V1"

STABLE_COMMITMENT = "STABLE_COMMITMENT"
OPERATOR_PREFERENCE = "OPERATOR_PREFERENCE"
INTERACTION_FEEDBACK = "INTERACTION_FEEDBACK"
DERIVED_TENDENCY = "DERIVED_TENDENCY"
TEMPORARY_CONTEXT = "TEMPORARY_CONTEXT"
POLICY_CLASSES = (STABLE_COMMITMENT, OPERATOR_PREFERENCE, INTERACTION_FEEDBACK, DERIVED_TENDENCY,
                  TEMPORARY_CONTEXT)

OPERATOR_ONLY = (STABLE_COMMITMENT, OPERATOR_PREFERENCE)
LOW_AUTHORITY = (INTERACTION_FEEDBACK, DERIVED_TENDENCY)

ACTIVE = "ACTIVE"
PENDING = "PENDING"
SUPERSEDED = "SUPERSEDED"
ROLLED_BACK = "ROLLED_BACK"
EXPIRED = "EXPIRED"

CASUAL = "CASUAL"
TECHNICAL = "TECHNICAL"
CRITICAL = "CRITICAL"
UNCERTAIN = "UNCERTAIN"
DISAGREEMENT = "DISAGREEMENT"
DISCOVERY = "DISCOVERY"
STYLES = (CASUAL, TECHNICAL, CRITICAL, UNCERTAIN, DISAGREEMENT, DISCOVERY)

REASON_NOT_AN_OPERATOR = "A_STABLE_COMMITMENT_OR_OPERATOR_PREFERENCE_REQUIRES_AN_OPERATOR"
REASON_NEEDS_REPETITION = "A_LOW_AUTHORITY_SIGNAL_NEEDS_A_SECOND_CONFIRMATION"
REASON_NEEDS_EXPIRY = "A_TEMPORARY_CONTEXT_MUST_EXPIRE"
OPERATIONAL_EVIDENCE_IS_NOT_A_PREFERENCE = True

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_personality_policies (
        policy_id TEXT PRIMARY KEY,
        key TEXT NOT NULL,
        version INTEGER NOT NULL,
        class TEXT NOT NULL,
        value_json TEXT,
        provenance TEXT,
        evidence_refs_json TEXT,
        authority TEXT NOT NULL,
        confirmations INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_by TEXT,
        created_at REAL NOT NULL,
        effective_at REAL,
        expires_at REAL,
        superseded_by TEXT,
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


def _materialize(record: Dict[str, Any]) -> Dict[str, Any]:
    record["value"] = json.loads(record.pop("value_json") or "null")
    record["evidence_refs"] = json.loads(record.pop("evidence_refs_json") or "[]")
    record["is_effective"] = record["status"] == ACTIVE
    record["expires_at"] = record.get("expires_at")
    return record


def propose_change(db_path: str, *, key: str, value: Any, policy_class: str, provenance: str,
                   evidence_refs: Sequence[str] = (), actor: Optional[str] = None,
                   confirmations: int = 1, expires_at: Optional[float] = None,
                   now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record a candidate preference change. Whether it becomes EFFECTIVE depends on its authority class.

    An operator change activates immediately. A LOW-authority observation stays PENDING until a second
    confirmation arrives - that is what stops one ambiguous interaction from rewriting Ciph's style.
    """
    if policy_class not in POLICY_CLASSES:
        raise CrucibleError("UNKNOWN_POLICY_CLASS", str(policy_class))
    is_operator = bool(actor) and str(actor).startswith("operator:")
    if policy_class in OPERATOR_ONLY and not is_operator:
        raise CrucibleError(REASON_NOT_AN_OPERATOR, str(actor))
    if policy_class == TEMPORARY_CONTEXT and expires_at is None:
        raise CrucibleError(REASON_NEEDS_EXPIRY, str(key))
    moment = _moment(now)
    previous = _rows(db_path, "SELECT version FROM ciph_personality_policies WHERE key = ? "
                              "ORDER BY version DESC LIMIT 1;", (str(key),))
    version = (int(previous[0]["version"]) + 1) if previous else 1
    authority = "OPERATOR" if policy_class in OPERATOR_ONLY else (
        "LOW" if policy_class in LOW_AUTHORITY else "SESSION")
    requires_repetition = policy_class in LOW_AUTHORITY
    effective = is_operator or (not requires_repetition)
    if requires_repetition:
        prior = _rows(db_path, "SELECT COUNT(*) AS n FROM ciph_personality_policies WHERE key = ? AND "
                               "class = ? AND status IN (?,?);",
                      (str(key), str(policy_class), PENDING, ACTIVE))
        confirmations = int(confirmations) + int(prior[0]["n"] if prior else 0)
        effective = confirmations >= 2
    status = ACTIVE if effective else PENDING
    policy_id = "PP-" + digest({"key": str(key), "version": version, "at": moment})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_personality_policies (policy_id, key, version, class, "
                    "value_json, provenance, evidence_refs_json, authority, confirmations, status, "
                    "created_by, created_at, effective_at, expires_at, superseded_by, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (policy_id, str(key), version, str(policy_class), json.dumps(value, sort_keys=True, default=str),
            str(provenance), json.dumps(sorted(str(ref) for ref in evidence_refs)), authority,
            int(confirmations), status, actor, moment, moment if effective else None, expires_at, None,
            PERSONALITY_POLICY_V1))
    if effective:
        superseded = _rows(db_path, "SELECT policy_id FROM ciph_personality_policies WHERE key = ? AND "
                                    "status = ? AND policy_id != ?;", (str(key), ACTIVE, policy_id))
        for row in superseded:
            _write(db_path, "UPDATE ciph_personality_policies SET status = ?, superseded_by = ? "
                            "WHERE policy_id = ?;", (SUPERSEDED, policy_id, row["policy_id"]))
    return {"policy_id": policy_id, "key": str(key), "version": version, "class": str(policy_class),
            "value": value, "status": status, "authority": authority,
            "requires_repetition": requires_repetition, "confirmations": int(confirmations),
            "effective": effective, "evidence_refs": sorted(str(ref) for ref in evidence_refs),
            "policy_version": PERSONALITY_POLICY_V1}


def activate(db_path: str, *, policy_id: str, actor: str, now: Optional[float] = None) -> Dict[str, Any]:
    """An operator promotes a PENDING candidate. A daemon may not promote its own habit."""
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_AN_OPERATOR, str(actor))
    moment = _moment(now)
    rows = _rows(db_path, "SELECT * FROM ciph_personality_policies WHERE policy_id = ?;", (str(policy_id),))
    if not rows:
        raise CrucibleError("UNKNOWN_POLICY", str(policy_id))
    record = rows[0]
    _write(db_path, "UPDATE ciph_personality_policies SET status = ?, effective_at = ? "
                    "WHERE policy_id = ?;", (ACTIVE, moment, str(policy_id)))
    superseded = _rows(db_path, "SELECT policy_id FROM ciph_personality_policies WHERE key = ? AND "
                                "status = ? AND policy_id != ?;",
                       (record["key"], ACTIVE, str(policy_id)))
    for row in superseded:
        _write(db_path, "UPDATE ciph_personality_policies SET status = ?, superseded_by = ? "
                        "WHERE policy_id = ?;", (SUPERSEDED, str(policy_id), row["policy_id"]))
    return {"policy_id": str(policy_id), "status": ACTIVE, "activated_by": str(actor),
            "superseded": [row["policy_id"] for row in superseded]}


def rollback(db_path: str, *, key: str, to_version: int, actor: str,
             now: Optional[float] = None) -> Dict[str, Any]:
    """
    Reinstate an earlier version as a NEW version - the history is append-only, never rewritten.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_AN_OPERATOR, str(actor))
    rows = _rows(db_path, "SELECT * FROM ciph_personality_policies WHERE key = ? AND version = ?;",
                 (str(key), int(to_version)))
    if not rows:
        raise CrucibleError("UNKNOWN_POLICY_VERSION", f"{key}:v{to_version}")
    target = rows[0]
    current = _rows(db_path, "SELECT policy_id FROM ciph_personality_policies WHERE key = ? AND status = ?;",
                    (str(key), ACTIVE))
    for row in current:
        _write(db_path, "UPDATE ciph_personality_policies SET status = ? WHERE policy_id = ?;",
               (ROLLED_BACK, row["policy_id"]))
    reinstated = propose_change(db_path, key=str(key), value=json.loads(target["value_json"] or "null"),
                                policy_class=str(target["class"]),
                                provenance=f"rollback to v{int(to_version)} by {actor}",
                                evidence_refs=json.loads(target["evidence_refs_json"] or "[]"),
                                actor=str(actor), now=now)
    reinstated["rolled_back_from"] = [row["policy_id"] for row in current]
    return reinstated


def current(db_path: str, *, policy_class: Optional[str] = None,
            now: Optional[float] = None) -> List[Dict[str, Any]]:
    """The EFFECTIVE preferences at this moment. An expired TEMPORARY_CONTEXT is not effective."""
    moment = _moment(now)
    rows = _rows(db_path, "SELECT * FROM ciph_personality_policies WHERE status = ? "
                          "ORDER BY key, version;", (ACTIVE,))
    records = [_materialize(row) for row in rows]
    for record in records:
        if record.get("expires_at") is not None and moment > float(record["expires_at"]):
            record["is_effective"] = False
    if policy_class is not None:
        records = [record for record in records if record["class"] == str(policy_class)]
    return records


def effective_values(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    for record in current(db_path, now=now):
        if record["is_effective"]:
            values[record["key"]] = record["value"]
    return values


def history(db_path: str, *, key: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_personality_policies"
    params: Sequence[Any] = ()
    if key is not None:
        query += " WHERE key = ?"
        params = (str(key),)
    query += " ORDER BY key, version;"
    return [_materialize(row) for row in _rows(db_path, query, params)]


def style_for(db_path: str, *, context: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Which presentation applies. An operator preference wins; otherwise the context decides.
    """
    values = effective_values(db_path, now=now)
    explicit = values.get("style.override")
    inferred = str(context).upper() if str(context).upper() in STYLES else CASUAL
    chosen = str(explicit) if explicit in STYLES else inferred
    return {"context": str(context), "style": chosen, "from_operator_override": explicit in STYLES,
            "available_styles": list(STYLES), "policy_version": PERSONALITY_POLICY_V1}


# ------------------------------------------------------------------ expression (fact-preserving)
_OPENERS = {CASUAL: "Sir, ", TECHNICAL: "", CRITICAL: "", UNCERTAIN: "", DISAGREEMENT: "",
            DISCOVERY: "Sir, "}
_HUMOUR_MARKERS = ("😂", "🤣", "😄", "🙂")
_NO_HUMOUR_STYLES = (CRITICAL, UNCERTAIN, DISAGREEMENT)


def render(db_path: str, *, text: str, style: Optional[str] = None, context: str = "casual",
           now: Optional[float] = None) -> Dict[str, Any]:
    """
    Apply the declared presentation to a sentence WITHOUT changing what it claims.

    The transform is deliberately shallow - an opener and the removal of humour markers in a serious style -
    so `facts_preserved` can prove it: every alphanumeric token from the source survives.
    """
    chosen = str(style) if style in STYLES else style_for(db_path, context=context, now=now)["style"]
    values = effective_values(db_path, now=now)
    honourific = bool(values.get("style.honourific", False))
    rendered = str(text)
    if chosen in _NO_HUMOUR_STYLES:
        for marker in _HUMOUR_MARKERS:
            rendered = rendered.replace(marker, "").strip()
    opener = _OPENERS.get(chosen, "")
    if chosen == CASUAL and honourific and not rendered.startswith("Sir"):
        rendered = f"Sir, {rendered[0].lower() + rendered[1:]}" if rendered else rendered
    elif opener and not rendered.startswith(opener.strip()):
        rendered = f"{opener}{rendered}" if opener else rendered
    if chosen == CASUAL and bool(values.get("style.emojis", False)) is False:
        pass
    return {"style": chosen, "text": rendered, "source_text": str(text),
            "facts_preserved": facts_preserved(str(text), rendered),
            "changes_factual_content": False, "policy_version": PERSONALITY_POLICY_V1}


def facts_preserved(before: str, after: str) -> bool:
    """Every alphanumeric token of the source must survive presentation."""
    import re
    tokens_before = re.findall(r"[a-z0-9]+", str(before).lower())
    tokens_after = re.findall(r"[a-z0-9]+", str(after).lower())
    return all(token in tokens_after for token in tokens_before)


def personality_digest(db_path: str) -> str:
    return digest({"policies": _rows(db_path, "SELECT policy_id, key, version, class, status, "
                                               "superseded_by FROM ciph_personality_policies "
                                               "ORDER BY policy_id;")})
