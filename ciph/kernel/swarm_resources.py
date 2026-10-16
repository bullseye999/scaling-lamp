"""
ciph/kernel/swarm_resources - 6.9: swarm resource governance.

    Child budgets CONSERVE parent budget.

Subdivision is where a swarm quietly becomes a fork bomb with a philosophy degree: every worker feels
entitled to "a bit" of the session budget, and nobody adds up. So an allocation is a reservation drawn
against the parent's REMAINING allowance, consumption is bounded by the reservation, and unused
reservation is handed back. The invariant is arithmetic, not etiquette:

    consumption + outstanding reservations <= parent allowance

Spawning is rationed the same way. A worker generation announces itself through `record_spawn`, and
`assert_spawn_allowed` refuses when the rate or the concurrency ceiling is exceeded - so "scale out"
cannot become "spawn until the box dies".
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SWARM_BUDGET_ALLOCATION_V1 = "SWARM_BUDGET_ALLOCATION_V1"
SWARM_SPAWN_GOVERNANCE_V1 = "SWARM_SPAWN_GOVERNANCE_V1"

ALLOCATION_OPEN = "OPEN"
ALLOCATION_CLOSED = "CLOSED"

REASON_CHILD_EXCEEDS_PARENT = "CHILD_ALLOCATION_EXCEEDS_PARENT_BUDGET"
REASON_UNKNOWN_ALLOCATION = "UNKNOWN_SWARM_ALLOCATION"
REASON_ALLOCATION_EXHAUSTED = "SWARM_ALLOCATION_EXHAUSTED"
REASON_ALLOCATION_CLOSED = "SWARM_ALLOCATION_CLOSED"
REASON_SPAWN_RATE = "SWARM_SPAWN_RATE_EXCEEDED"
REASON_CONCURRENCY = "SWARM_CONCURRENCY_LIMIT_EXCEEDED"
REASON_NOT_OPERATOR = "SWARM_RESOURCE_CHANGE_REQUIRES_AN_OPERATOR"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_budget_allocations (
        allocation_id TEXT PRIMARY KEY,
        parent_budget_ref TEXT NOT NULL,
        worker_id TEXT,
        task_id TEXT,
        delegation_id TEXT,
        allocated REAL NOT NULL,
        consumed REAL NOT NULL,
        returned REAL NOT NULL,
        status TEXT NOT NULL,
        created_at REAL,
        closed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_spawn_events (
        spawn_id TEXT PRIMARY KEY,
        worker_id TEXT NOT NULL,
        instance_generation INTEGER NOT NULL,
        actor TEXT,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class Allocation:
    allocation_id: str
    parent_budget_ref: str
    worker_id: Optional[str]
    delegation_id: Optional[str]
    allocated: float
    consumed: float
    returned: float
    status: str

    @property
    def outstanding(self) -> float:
        return max(0.0, self.allocated - self.consumed - self.returned)

    def as_dict(self) -> Dict[str, Any]:
        return {"allocation_id": self.allocation_id, "parent_budget_ref": self.parent_budget_ref,
                "worker_id": self.worker_id, "delegation_id": self.delegation_id,
                "allocated": self.allocated, "consumed": self.consumed, "returned": self.returned,
                "outstanding": self.outstanding, "status": self.status,
                "policy_version": SWARM_BUDGET_ALLOCATION_V1}


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=15.0)
            connection.row_factory = sqlite3.Row
            return connection
        except sqlite3.OperationalError:
            pass
    connection = sqlite3.connect(db_path, timeout=15.0)
    connection.row_factory = sqlite3.Row
    return connection


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _row_to_allocation(row: Any) -> Allocation:
    row = dict(row)
    return Allocation(allocation_id=str(row["allocation_id"]),
                      parent_budget_ref=str(row["parent_budget_ref"]),
                      worker_id=row["worker_id"], delegation_id=row["delegation_id"],
                      allocated=float(row["allocated"]), consumed=float(row["consumed"]),
                      returned=float(row["returned"]), status=str(row["status"]))


def get_allocation(db_path: str, allocation_id: str) -> Allocation:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_swarm_budget_allocations "
                                 "WHERE allocation_id = ?;", (str(allocation_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_ALLOCATION, str(allocation_id))
    return _row_to_allocation(row)


def allocations(db_path: str, parent_budget_ref: Optional[str] = None,
                status: Optional[str] = None) -> List[Allocation]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_swarm_budget_allocations"
    clauses, params = [], []
    if parent_budget_ref is not None:
        clauses.append("parent_budget_ref = ?")
        params.append(str(parent_budget_ref))
    if status is not None:
        clauses.append("status = ?")
        params.append(str(status))
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    try:
        rows = [dict(row) for row in connection.execute(
            query + " ORDER BY created_at, allocation_id;", tuple(params))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [_row_to_allocation(row) for row in rows]


def outstanding_total(db_path: str, parent_budget_ref: str) -> float:
    return round(sum(item.outstanding for item in allocations(db_path, parent_budget_ref,
                                                             status=ALLOCATION_OPEN)), 9)


def parent_remaining(db_path: str, parent_budget_ref: str, *,
                     now: Optional[float] = None) -> float:
    """
    What the parent can still hand out: its own remaining allowance MINUS everything already reserved.

    Reserved-but-unspent is not available twice. That single subtraction is the whole defence against
    subdivision becoming budget multiplication.
    """
    from ciph.kernel.autonomy_budgets import budget_status
    status = budget_status(db_path, parent_budget_ref, now=now)
    return round(status.remaining - outstanding_total(db_path, parent_budget_ref), 9)


def allocate_child(db_path: str, parent_budget_ref: str, *, amount: float,
                   worker_id: Optional[str] = None, task_id: Optional[str] = None,
                   delegation_id: Optional[str] = None, now: Optional[float] = None) -> Allocation:
    moment = time.time() if now is None else float(now)
    available = parent_remaining(db_path, parent_budget_ref, now=moment)
    if float(amount) > available:
        raise CrucibleError(REASON_CHILD_EXCEEDS_PARENT,
                            f"{amount}>{available} for {parent_budget_ref}")
    allocation_id = "SBA-" + digest({"parent": parent_budget_ref, "worker": worker_id,
                                     "task": task_id, "delegation": delegation_id,
                                     "amount": float(amount), "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_swarm_budget_allocations (allocation_id, "
            "parent_budget_ref, worker_id, task_id, delegation_id, allocated, consumed, returned, "
            "status, created_at, closed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (allocation_id, str(parent_budget_ref), worker_id, task_id, delegation_id,
             float(amount), 0.0, 0.0, ALLOCATION_OPEN, moment, None))
        connection.commit()
    finally:
        connection.close()
    return get_allocation(db_path, allocation_id)


def consume_child(db_path: str, allocation_id: str, *, amount: float,
                  now: Optional[float] = None) -> Allocation:
    """Spend against a reservation. Spending beyond it is refused, not absorbed by the parent."""
    moment = time.time() if now is None else float(now)
    allocation = get_allocation(db_path, allocation_id)
    if allocation.status != ALLOCATION_OPEN:
        raise CrucibleError(REASON_ALLOCATION_CLOSED, allocation_id)
    if float(amount) > allocation.outstanding:
        raise CrucibleError(REASON_ALLOCATION_EXHAUSTED,
                            f"{amount}>{allocation.outstanding} for {allocation_id}")
    # The parent is drawn down HERE. The reservation stopped the same allowance being handed to two
    # children; this is the spending itself, and without it a swarm could consume a parent budget N
    # times over while every child stayed inside its own limit.
    from ciph.kernel.autonomy_budgets import consume_budget
    consume_budget(db_path, allocation.parent_budget_ref, amount=float(amount), now=moment)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_budget_allocations SET consumed = consumed + ? "
                           "WHERE allocation_id = ?;", (float(amount), str(allocation_id)))
        connection.commit()
    finally:
        connection.close()
    return get_allocation(db_path, allocation_id)


def return_unused(db_path: str, allocation_id: str, *, amount: float,
                  now: Optional[float] = None) -> Allocation:
    moment = time.time() if now is None else float(now)
    allocation = get_allocation(db_path, allocation_id)
    give_back = min(float(amount), allocation.outstanding)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_budget_allocations SET returned = returned + ? "
                           "WHERE allocation_id = ?;", (give_back, str(allocation_id)))
        connection.commit()
    finally:
        connection.close()
    return get_allocation(db_path, allocation_id)


def close_allocation(db_path: str, allocation_id: str, *, now: Optional[float] = None
                     ) -> Allocation:
    """Closing returns whatever was reserved and never spent. Nothing is silently written off."""
    moment = time.time() if now is None else float(now)
    allocation = get_allocation(db_path, allocation_id)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_budget_allocations SET returned = allocated - consumed, "
                           "status = ?, closed_at = ? WHERE allocation_id = ?;",
                           (ALLOCATION_CLOSED, moment, str(allocation_id)))
        connection.commit()
    finally:
        connection.close()
    return get_allocation(db_path, allocation_id)


# ---------------------------------------------------------------------------- spawn governance
def record_spawn(db_path: str, *, worker_id: str, instance_generation: int, actor: str,
                 now: Optional[float] = None) -> str:
    moment = time.time() if now is None else float(now)
    spawn_id = "SSP-" + digest({"worker": worker_id, "gen": int(instance_generation),
                                "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_swarm_spawn_events (spawn_id, worker_id, "
                           "instance_generation, actor, recorded_at) VALUES (?,?,?,?,?);",
                           (spawn_id, str(worker_id), int(instance_generation), str(actor), moment))
        connection.commit()
    finally:
        connection.close()
    return spawn_id


def spawn_events(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_spawn_events ORDER BY recorded_at, spawn_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def assert_spawn_allowed(db_path: str, *, limit: int, window_seconds: float,
                         concurrency_limit: Optional[int] = None,
                         now: Optional[float] = None) -> Dict[str, Any]:
    """
    Two ceilings before a new generation may exist: a RATE, and if given, a CONCURRENCY.

    The rate bounds a crash loop that respawns forever; the concurrency bound means "swarm mode" cannot
    become unbounded fan-out. Both are read from the durable record, so a supervisor that restarts
    cannot forget how many it already started.
    """
    from ciph.kernel.swarm_worker import members
    moment = time.time() if now is None else float(now)
    recent = [event for event in spawn_events(db_path)
              if moment - float(event["recorded_at"]) <= float(window_seconds)]
    if len(recent) >= int(limit):
        raise CrucibleError(REASON_SPAWN_RATE, f"{len(recent)}/{limit} in {window_seconds}s")
    live = members(db_path)
    if concurrency_limit is not None and len(live) >= int(concurrency_limit):
        raise CrucibleError(REASON_CONCURRENCY, f"{len(live)}/{concurrency_limit}")
    return {"policy_version": SWARM_SPAWN_GOVERNANCE_V1, "recent_spawns": len(recent),
            "live_workers": len(live), "limit": int(limit), "window_seconds": float(window_seconds),
            "concurrency_limit": concurrency_limit}


def resources_digest(db_path: str) -> str:
    return digest({"version": SWARM_BUDGET_ALLOCATION_V1,
                   "allocations": [item.as_dict() for item in allocations(db_path)],
                   "spawns": spawn_events(db_path)})
