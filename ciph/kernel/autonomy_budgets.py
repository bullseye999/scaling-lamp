"""
ciph/kernel/autonomy_budgets - 5.4: budgets constrain authority, and Ciph cannot raise its own.

    "I had one question, so I consumed the entire VPS for six hours" is the failure mode.

A budget is a WINDOW with a limit. Consumption inside the window is recorded; the window rolls over to
a fresh allowance; raising a limit requires an operator reference, so an autonomous cycle cannot decide
that its work is important enough to spend more.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

AUTONOMY_BUDGET_V1 = "AUTONOMY_BUDGET_V1"

RESOURCE_CPU = "CPU"
RESOURCE_WALL_CLOCK = "WALL_CLOCK"
RESOURCE_TOKENS = "API_TOKENS"
RESOURCE_MONEY = "MONEY"
RESOURCE_DISK = "DISK"
RESOURCE_NETWORK = "NETWORK"
RESOURCE_TOOL_CALLS = "TOOL_CALLS"
RESOURCE_RISK_EXPOSURE = "RISK_EXPOSURE"
VALID_RESOURCE_CLASSES = (RESOURCE_CPU, RESOURCE_WALL_CLOCK, RESOURCE_TOKENS, RESOURCE_MONEY,
                          RESOURCE_DISK, RESOURCE_NETWORK, RESOURCE_TOOL_CALLS, RESOURCE_RISK_EXPOSURE)

REASON_EXHAUSTED = "BLOCKED_RESOURCE"
REASON_INCREASE_REQUIRES_OPERATOR = "BUDGET_INCREASE_REQUIRES_AN_OPERATOR"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_budgets (
        budget_id TEXT PRIMARY KEY,
        resource_class TEXT NOT NULL,
        limit_value REAL NOT NULL,
        window_seconds REAL NOT NULL,
        window_started_at REAL NOT NULL,
        consumed REAL NOT NULL,
        granted_by TEXT NOT NULL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class BudgetStatus:
    budget_id: str
    resource_class: str
    limit: float
    consumed: float
    remaining: float
    window_expired: bool
    granted_by: str

    def as_dict(self) -> Dict[str, Any]:
        return {"budget_id": self.budget_id, "resource_class": self.resource_class,
                "limit": self.limit, "consumed": self.consumed, "remaining": self.remaining,
                "window_expired": self.window_expired, "granted_by": self.granted_by}


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


def _window_start(now: float, window_seconds: float) -> float:
    """Aligned windows, so a budget cannot be reset by restarting the process."""
    return float(int(now // window_seconds) * window_seconds)


def open_budget(db_path: str, *, resource_class: str, limit: float, window_seconds: float,
                granted_by: str, now: Optional[float] = None) -> str:
    if str(resource_class) not in VALID_RESOURCE_CLASSES:
        raise CrucibleError("UNKNOWN_RESOURCE_CLASS", str(resource_class))
    if float(limit) <= 0 or float(window_seconds) <= 0:
        raise CrucibleError("BUDGET_REQUIRES_POSITIVE_LIMIT", f"{limit}/{window_seconds}")
    moment = time.time() if now is None else float(now)
    budget_id = "BUD-" + digest({"class": resource_class, "window": float(window_seconds),
                                 "granted_by": granted_by})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_budgets (budget_id, resource_class, limit_value, "
            "window_seconds, window_started_at, consumed, granted_by, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?);",
            (budget_id, str(resource_class), float(limit), float(window_seconds),
             _window_start(moment, float(window_seconds)), 0.0, str(granted_by), moment))
        connection.commit()
    finally:
        connection.close()
    return budget_id


def budget_status(db_path: str, budget_id: str, *, now: Optional[float] = None) -> BudgetStatus:
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_autonomy_budgets WHERE budget_id = ?;",
                                 (budget_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_BUDGET", budget_id)
    row = dict(row)
    expired = _window_start(moment, float(row["window_seconds"])) != float(row["window_started_at"])
    consumed = 0.0 if expired else float(row["consumed"])
    return BudgetStatus(budget_id=str(row["budget_id"]), resource_class=str(row["resource_class"]),
                        limit=float(row["limit_value"]), consumed=consumed,
                        remaining=float(row["limit_value"]) - consumed, window_expired=expired,
                        granted_by=str(row["granted_by"]))


def consume_budget(db_path: str, budget_id: str, *, amount: float,
                   now: Optional[float] = None) -> BudgetStatus:
    """Refuses beyond the limit. A window that has rolled over resets to zero first."""
    if float(amount) < 0:
        raise CrucibleError("BUDGET_CONSUMPTION_MUST_BE_POSITIVE", str(amount))
    moment = time.time() if now is None else float(now)
    status = budget_status(db_path, budget_id, now=moment)
    if float(amount) > status.remaining:
        raise CrucibleError(REASON_EXHAUSTED,
                            f"{status.resource_class}:{amount}>{status.remaining}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        if status.window_expired:
            row = connection.execute("SELECT window_seconds FROM ciph_autonomy_budgets WHERE "
                                     "budget_id = ?;", (budget_id,)).fetchone()
            connection.execute("UPDATE ciph_autonomy_budgets SET window_started_at = ?, consumed = ? "
                               "WHERE budget_id = ?;",
                               (_window_start(moment, float(row["window_seconds"])), 0.0, budget_id))
        connection.execute("UPDATE ciph_autonomy_budgets SET consumed = consumed + ? "
                           "WHERE budget_id = ?;", (float(amount), budget_id))
        connection.commit()
    finally:
        connection.close()
    return budget_status(db_path, budget_id, now=moment)


def increase_budget(db_path: str, budget_id: str, *, new_limit: float, authority_ref: str,
                    now: Optional[float] = None) -> BudgetStatus:
    """
    Budget can constrain authority; increasing it is governance (5.4). An autonomous cycle cannot
    raise its own ceiling because the increase has to name a non-autonomous authority.
    """
    if not str(authority_ref or "").startswith("operator:"):
        raise CrucibleError(REASON_INCREASE_REQUIRES_OPERATOR, str(authority_ref))
    if float(new_limit) <= 0:
        raise CrucibleError("BUDGET_REQUIRES_POSITIVE_LIMIT", str(new_limit))
    connection = _connect(db_path)
    try:
        init_schema(connection)
        cursor = connection.execute("UPDATE ciph_autonomy_budgets SET limit_value = ? "
                                    "WHERE budget_id = ?;", (float(new_limit), budget_id))
        connection.commit()
        if cursor.rowcount == 0:
            raise CrucibleError("UNKNOWN_BUDGET", budget_id)
    finally:
        connection.close()
    return budget_status(db_path, budget_id, now=now)


def budget_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT budget_id, resource_class, limit_value, window_seconds, consumed, granted_by "
            "FROM ciph_autonomy_budgets ORDER BY budget_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return digest({"version": AUTONOMY_BUDGET_V1, "budgets": rows})
