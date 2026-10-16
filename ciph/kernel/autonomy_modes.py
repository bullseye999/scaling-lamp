"""
ciph/kernel/autonomy_modes - 5.0 Gate Seven: operator supremacy.

The operator's control plane. A mode is append-only, and the effective mode is the MOST RESTRICTIVE
one any actor currently asserts, so a daemon cannot talk its way past an operator hold by lowering its
own setting.

    AUTONOMY_OFF      no new autonomous work intents admitted
    EMERGENCY_STOP    revoke eligible standing authority; no new autonomous execution
    QUIESCE           settle the current atomic boundary, mint no new permits, close sessions
    READ_ONLY         investigation allowed, no state-changing external action
    LIMITED           only LOW-risk classes below the risk ceiling
    NORMAL            the standing authorization still decides everything
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

AUTONOMY_MODE_V1 = "AUTONOMY_MODE_V1"

MODE_NORMAL = "AUTONOMY_NORMAL"
MODE_LIMITED = "AUTONOMY_LIMITED"
MODE_READ_ONLY = "AUTONOMY_READ_ONLY"
MODE_QUIESCE = "QUIESCE"
MODE_EMERGENCY_STOP = "EMERGENCY_STOP"
MODE_OFF = "AUTONOMY_OFF"

# Most restrictive first. The effective mode is the earliest entry that any actor asserts.
MODES_BY_RESTRICTIVENESS: Tuple[str, ...] = (MODE_OFF, MODE_EMERGENCY_STOP, MODE_QUIESCE,
                                             MODE_READ_ONLY, MODE_LIMITED, MODE_NORMAL)

REASON_OPERATOR_HOLD = "BLOCKED_OPERATOR_HOLD"
REASON_MODE_READ_ONLY = "BLOCKED_MODE_READ_ONLY"
REASON_MODE_LIMITED = "BLOCKED_MODE_LIMITED"
REASON_MODE_OFF = "BLOCKED_AUTONOMY_OFF"

THE_DAEMON_CANNOT_LOWER = "DAEMON_CANNOT_OVERRIDE_OPERATOR_MODE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_modes (
        mode_id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        mode TEXT NOT NULL,
        reason TEXT,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class ModeRecord:
    mode_id: str
    actor: str
    mode: str
    reason: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"mode_id": self.mode_id, "actor": self.actor, "mode": self.mode,
                "reason": self.reason}


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


def severity(mode: str) -> int:
    if mode not in MODES_BY_RESTRICTIVENESS:
        raise CrucibleError("UNKNOWN_AUTONOMY_MODE", str(mode))
    return MODES_BY_RESTRICTIVENESS.index(mode)


def more_restrictive(first: str, second: str) -> str:
    return first if severity(first) <= severity(second) else second


def set_mode(db_path: str, *, mode: str, actor: str, reason: Optional[str] = None,
             now: Optional[float] = None) -> ModeRecord:
    """Append a mode assertion. The effective mode is derived, not overwritten."""
    if mode not in MODES_BY_RESTRICTIVENESS:
        raise CrucibleError("UNKNOWN_AUTONOMY_MODE", str(mode))
    if not actor:
        raise CrucibleError("MODE_REQUIRES_AN_ACTOR", '')
    if not str(actor).startswith("operator:"):
        # RELAXATION IS AN OPERATOR ACT.
        #
        # A non-operator may assert a mode at least as restrictive as the one now in effect. A
        # self-hold is always allowed - that is how a daemon that finds something wrong stops
        # itself - but a non-operator may never assert a *less restrictive* mode than the effective
        # one. The dangerous artefact is not a silently relaxed hold (the effective mode is the most
        # restrictive assertion anyone holds, so the operator's own row survives). It is a daemon
        # *recording* "NORMAL" while the operator is holding, because the next reader of the mode
        # history then finds a plausible-looking claim that the hold was lifted.
        if severity(mode) > severity(current_mode(db_path)):
            raise CrucibleError(THE_DAEMON_CANNOT_LOWER, f"{actor} -> {mode}")
    moment = time.time() if now is None else float(now)
    mode_id = "MOD-" + digest({"actor": actor, "mode": mode, "reason": reason})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR REPLACE INTO ciph_autonomy_modes (mode_id, actor, mode, reason, recorded_at) "
            "VALUES (?,?,?,?,?);", (mode_id, str(actor), mode, reason, moment))
        connection.commit()
    finally:
        connection.close()
    return ModeRecord(mode_id=mode_id, actor=str(actor), mode=mode, reason=reason)


def current_mode(db_path: str) -> str:
    """The most restrictive mode any actor currently asserts."""
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT actor, mode FROM ciph_autonomy_modes ORDER BY rowid;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    latest: Dict[str, str] = {}
    for row in rows:
        latest[str(row["actor"])] = str(row["mode"])
    mode = MODE_NORMAL
    for asserted in latest.values():
        mode = more_restrictive(mode, asserted)
    return mode


def mode_history(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_autonomy_modes ORDER BY recorded_at, mode_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def assert_mode_permits(db_path: str, *, external_effect: bool, risk_class: str) -> None:
    """
    THE mode gate. Autonomy is refused, not degraded, when the operator says stop.
    """
    mode = current_mode(db_path)
    if mode == MODE_OFF:
        raise CrucibleError(REASON_MODE_OFF, mode)
    if mode == MODE_EMERGENCY_STOP:
        raise CrucibleError(REASON_OPERATOR_HOLD, mode)
    if mode == MODE_QUIESCE:
        raise CrucibleError(REASON_OPERATOR_HOLD, mode)
    if mode == MODE_READ_ONLY and external_effect:
        raise CrucibleError(REASON_MODE_READ_ONLY, mode)
    if mode == MODE_LIMITED and str(risk_class).upper() not in ("LOW",):
        raise CrucibleError(REASON_MODE_LIMITED, f"{mode}:{risk_class}")


def mode_digest(db_path: str) -> str:
    return digest({"version": AUTONOMY_MODE_V1, "mode": current_mode(db_path),
                   "history": [str(row["mode_id"]) for row in mode_history(db_path)]})
