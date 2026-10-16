"""
ciph/kernel/autonomy_interrupts - 5.5: interrupts, intervention and safe quiescence.

An operator must be able to say STOP and have that mean something specific, in bounded time, without
the machinery pretending it is a suggestion. So the modes are given exact operational meanings here -
the mode module states the constitution, this module CARRIES IT OUT against the work that is actually
in flight:

    QUIESCE          settle the current atomic boundary: sessions stop opening new work, mint nothing,
                     and are closed by an explicit settle. In-flight attempts are NOT clobbered.
    EMERGENCY_STOP   the stronger act: stop the sessions AND withdraw the standing authority that would
                     let the next wake do anything.
    OFF              admit no new autonomous work and stop the live sessions. Authority is left on the
                     record because "off" is a statement about now, not a revocation of the grant.

Two properties are load-bearing:

    AN INTERRUPT IS AN EVENT, NEVER A REWRITE. Nothing here deletes history; a stopped session keeps its
    record, its stop reason, and everything it attempted.

    AN INTERRUPT NEEDS AN OPERATOR. The daemon cannot stop-work itself into a clean slate, and it
    certainly cannot un-stop itself - releasing a hold is an operator act in the mode module too.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

AUTONOMY_INTERRUPT_V1 = "AUTONOMY_INTERRUPT_V1"
INTERVENTION_V1 = "INTERVENTION_V1"

KIND_QUIESCE = "QUIESCE"
KIND_STOP_SESSIONS = "STOP_SESSIONS"
KIND_EMERGENCY_STOP = "EMERGENCY_STOP"
KIND_NO_ACTION = "NO_ACTION"

REASON_INTERVENTION_REQUIRES_OPERATOR = "INTERVENTION_REQUIRES_AN_OPERATOR"
REASON_DRAIN_REQUIRED = "INTERVENTION_DRAIN_REQUIRED"
REASON_UNKNOWN_INTERVENTION = "UNKNOWN_INTERVENTION"
REASON_NOTHING_TO_SETTLE = "NOTHING_TO_SETTLE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_interventions (
        intervention_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        actor TEXT NOT NULL,
        mode TEXT NOT NULL,
        sessions_quiesced_json TEXT,
        sessions_interrupted_json TEXT,
        authorizations_revoked_json TEXT,
        reason TEXT,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class Intervention:
    intervention_id: str
    kind: str
    actor: str
    mode: str
    sessions_quiesced: Tuple[str, ...]
    sessions_interrupted: Tuple[str, ...]
    authorizations_revoked: Tuple[str, ...]
    reason: Optional[str]
    changed: bool

    def as_dict(self) -> Dict[str, Any]:
        return {"intervention_id": self.intervention_id, "kind": self.kind, "actor": self.actor,
                "mode": self.mode, "sessions_quiesced": list(self.sessions_quiesced),
                "sessions_interrupted": list(self.sessions_interrupted),
                "authorizations_revoked": list(self.authorizations_revoked),
                "reason": self.reason, "policy_version": INTERVENTION_V1}


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


def _require_operator(actor: str) -> None:
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_INTERVENTION_REQUIRES_OPERATOR, str(actor))


def _kind_for_mode(mode: str) -> str:
    from ciph.kernel.autonomy_modes import (MODE_EMERGENCY_STOP, MODE_OFF, MODE_QUIESCE)
    if mode == MODE_EMERGENCY_STOP:
        return KIND_EMERGENCY_STOP
    if mode == MODE_QUIESCE:
        return KIND_QUIESCE
    if mode == MODE_OFF:
        return KIND_STOP_SESSIONS
    return KIND_NO_ACTION


def enforce_operator_mode(db_path: str, *, actor: str, reason: Optional[str] = None,
                          now: Optional[float] = None) -> Intervention:
    """
    Make the operator's current mode TRUE of the work in flight.

    Idempotent by construction: the same mode against the same live sessions produces the same
    intervention identity, so a daemon that retries the check does not create a second intervention or
    revoke the same grant twice.
    """
    from ciph.kernel.autonomy_modes import current_mode
    from ciph.kernel.autonomy_session import (SESSION_INTERRUPTED, SESSION_OPEN, SESSION_QUIESCING,
                                              close_session, open_sessions)
    _require_operator(actor)
    moment = time.time() if now is None else float(now)
    mode = current_mode(db_path)
    kind = _kind_for_mode(mode)
    if kind == KIND_NO_ACTION:
        # A mode that requires nothing is not an event. Recording it would fill the intervention
        # history with the absence of news, which is how a real intervention becomes hard to find.
        return Intervention(intervention_id="ITV-NOOP", kind=kind, actor=str(actor), mode=mode,
                            sessions_quiesced=(), sessions_interrupted=(),
                            authorizations_revoked=(), reason=reason, changed=False)
    live = [session for session in open_sessions(db_path) if session.status == SESSION_OPEN]
    quiesced: List[str] = []
    interrupted: List[str] = []
    revoked: List[str] = []
    if kind == KIND_QUIESCE:
        # Only a RUNNING session can be quiesced. A session that is already QUIESCING is the previous
        # call's work, and re-stopping it on every tick would make a retry look like a new event.
        for session in live:
            close_session(db_path, session.session_id, stop_reason="OPERATOR_INTERRUPT",
                          status=SESSION_QUIESCING, now=moment)
            quiesced.append(session.session_id)
    elif kind in (KIND_STOP_SESSIONS, KIND_EMERGENCY_STOP):
        for session in open_sessions(db_path):
            close_session(db_path, session.session_id, stop_reason="OPERATOR_INTERRUPT",
                          status=SESSION_INTERRUPTED, now=moment)
            interrupted.append(session.session_id)
        if kind == KIND_EMERGENCY_STOP:
            revoked = _revoke_active_authorizations(db_path, actor=actor, reason=reason or mode,
                                                   now=moment)
    # The session id list is part of the intervention's identity, so a retry that finds the same work
    # to stop maps onto the SAME record - and `changed` reports whether a new record was written,
    # not whether the caller intended one.
    record = _record_intervention(db_path, kind=kind, actor=actor, mode=mode,
                                  quiesced=quiesced, interrupted=interrupted, revoked=revoked,
                                  reason=reason, now=moment)
    return Intervention(intervention_id=record.intervention_id, kind=record.kind, actor=record.actor,
                        mode=record.mode, sessions_quiesced=record.sessions_quiesced,
                        sessions_interrupted=record.sessions_interrupted,
                        authorizations_revoked=record.authorizations_revoked, reason=record.reason,
                        changed=record.changed)


def _revoke_active_authorizations(db_path: str, *, actor: str, reason: str,
                                  now: float) -> List[str]:
    from ciph.kernel.standing_authorization import (STATUS_ACTIVE, authorization_status,
                                                    revoke_standing_authorization,
                                                    standing_authorizations)
    revoked: List[str] = []
    for authorization in standing_authorizations(db_path):
        if authorization.standing_auth_id in revoked:
            continue
        if authorization_status(db_path, authorization.standing_auth_id, now=now) == STATUS_ACTIVE:
            revoke_standing_authorization(db_path, authorization.standing_auth_id,
                                          reason=f"EMERGENCY_STOP:{reason}", actor=actor, now=now)
            revoked.append(authorization.standing_auth_id)
    return revoked


def _existing_intervention(db_path: str, *, kind: str, actor: str,
                           mode: str) -> Optional[Intervention]:
    """The record of this actor's response to this mode, if it already happened."""
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute(
            "SELECT * FROM ciph_autonomy_interventions WHERE kind = ? AND actor = ? AND mode = ? "
            "ORDER BY recorded_at, intervention_id LIMIT 1;", (kind, actor, mode)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        return None
    row = dict(row)
    return Intervention(intervention_id=str(row["intervention_id"]), kind=str(row["kind"]),
                        actor=str(row["actor"]), mode=str(row["mode"]),
                        sessions_quiesced=tuple(json.loads(row["sessions_quiesced_json"] or "[]")),
                        sessions_interrupted=tuple(json.loads(row["sessions_interrupted_json"]
                                                              or "[]")),
                        authorizations_revoked=tuple(json.loads(row["authorizations_revoked_json"]
                                                               or "[]")),
                        reason=row["reason"], changed=False)


def _record_intervention(db_path: str, *, kind: str, actor: str, mode: str,
                         quiesced: List[str], interrupted: List[str], revoked: List[str],
                         reason: Optional[str], now: float) -> Intervention:
    if not (quiesced or interrupted or revoked):
        # Nothing left to do: an idempotent re-check reports the intervention that already happened
        # rather than appending an empty echo of it to the record.
        existing = _existing_intervention(db_path, kind=kind, actor=actor, mode=mode)
        if existing is not None:
            return existing
    intervention_id = "ITV-" + digest({"kind": kind, "mode": mode, "actor": actor,
                                       "quiesced": sorted(quiesced),
                                       "interrupted": sorted(interrupted),
                                       "revoked": sorted(revoked)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        cursor = connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_interventions (intervention_id, kind, actor, mode, "
            "sessions_quiesced_json, sessions_interrupted_json, authorizations_revoked_json, reason, "
            "recorded_at) VALUES (?,?,?,?,?,?,?,?,?);",
            (intervention_id, kind, actor, mode, json.dumps(sorted(quiesced)),
             json.dumps(sorted(interrupted)), json.dumps(sorted(revoked)), reason, now))
        created = cursor.rowcount > 0
        connection.commit()
        row = connection.execute("SELECT * FROM ciph_autonomy_interventions WHERE intervention_id = ?;",
                                 (intervention_id,)).fetchone()
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_INTERVENTION, intervention_id)
    row = dict(row)
    return Intervention(intervention_id=str(row["intervention_id"]), kind=str(row["kind"]),
                        actor=str(row["actor"]), mode=str(row["mode"]),
                        sessions_quiesced=tuple(json.loads(row["sessions_quiesced_json"] or "[]")),
                        sessions_interrupted=tuple(json.loads(row["sessions_interrupted_json"]
                                                              or "[]")),
                        authorizations_revoked=tuple(json.loads(row["authorizations_revoked_json"]
                                                               or "[]")),
                        reason=row["reason"], changed=created)


def settle_session(db_path: str, session_id: str, *, actor: str,
                   now: Optional[float] = None) -> Dict[str, Any]:
    """
    Close a quiescing session once its atomic boundary is settled.

    Settling REFUSES while an attempt exists without evidence: an attempt whose outcome is unknown is
    the one thing that must not be closed over, because closing it would manufacture a resolution. The
    caller is told DRAIN_REQUIRED instead.
    """
    from ciph.kernel.autonomy_session import (SESSION_CLOSED, SESSION_QUIESCING, close_session,
                                              get_session, session_work)
    _require_operator(actor)
    moment = time.time() if now is None else float(now)
    session = get_session(db_path, session_id)
    if session.status not in (SESSION_QUIESCING,):
        if session.status == SESSION_CLOSED:
            raise CrucibleError(REASON_NOTHING_TO_SETTLE, session_id)
    unresolved = [item["attempt_ref"] for item in session_work(db_path, session_id)
                  if item.get("attempt_ref") and not item.get("evidence_ref")]
    if unresolved:
        raise CrucibleError(REASON_DRAIN_REQUIRED, ",".join(sorted(str(ref) for ref in unresolved)))
    closed = close_session(db_path, session_id, stop_reason="OPERATOR_INTERRUPT",
                           status=SESSION_CLOSED, now=moment)
    return {"session_id": closed.session_id, "status": closed.status,
            "stop_reason": closed.stop_reason, "settled_at": moment}


def interventions(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_autonomy_interventions ORDER BY recorded_at, intervention_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def intervention_digest(db_path: str) -> str:
    return digest({"version": AUTONOMY_INTERRUPT_V1, "interventions": interventions(db_path)})
