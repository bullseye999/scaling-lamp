"""
ciph/kernel/swarm_delegation - 6.1 (governed delegation) and 6.2 (claims, leases, duplicate work).

    Delegation != a signed execution permit
    A lease grants POSSESSION OF COMPUTATION, not execution authority.

Ciph breaks work apart here. A delegation says: "this bounded internal computation, on exactly this
input, is worth doing". It cannot say "and you may change the world". If a worker performing the
delegation concludes that production should change, the delegation produces a PROPOSAL and the change
goes back through 4.0 - the action, the authority, the permit, the guarded executor - like any other
change Ciph makes.

Leases exist because workers crash. A lease is a time-boxed possession of one delegation by one worker
GENERATION, and everything about it is written down: who holds it, when it expires, which input it was
claimed against. The consequence is deliberate:

    computation may be at-least-once, authoritative effects stay exactly governed

Late work is therefore not lost and not silently current: it comes back classified, and only a CURRENT
result ever counts.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SWARM_DELEGATION_V1 = "SWARM_DELEGATION_V1"
SWARM_LEASE_V1 = "SWARM_LEASE_V1"

PROPOSED = "PROPOSED"
ELIGIBLE = "ELIGIBLE"
ASSIGNED = "ASSIGNED"
COMPLETED = "COMPLETED"
STALE = "STALE"
CANCELLED = "CANCELLED"
VALID_DELEGATION_STATUSES = (PROPOSED, ELIGIBLE, ASSIGNED, COMPLETED, STALE, CANCELLED)

LEASE_ACTIVE = "ACTIVE"
LEASE_RELEASED = "RELEASED"
LEASE_EXPIRED = "EXPIRED"
LEASE_INTERRUPTED = "INTERRUPTED"
VALID_LEASE_STATUSES = (LEASE_ACTIVE, LEASE_RELEASED, LEASE_EXPIRED, LEASE_INTERRUPTED)

REASON_GOVERNED_CHANGE = "SWARM_DELEGATION_CANNOT_CARRY_A_GOVERNED_CHANGE"
REASON_UNKNOWN_DELEGATION = "UNKNOWN_SWARM_DELEGATION"
REASON_UNKNOWN_LEASE = "UNKNOWN_SWARM_LEASE"
REASON_ALREADY_CLAIMED = "DELEGATION_ALREADY_CLAIMED"
REASON_NOT_ELIGIBLE = "DELEGATION_NOT_ELIGIBLE"
REASON_INPUT_MISMATCH = "DELEGATION_INPUT_MISMATCH"
REASON_STALE_GENERATION = "STALE_WORKER_GENERATION"
REASON_WORKER_NOT_READY = "WORKER_NOT_READY_FOR_WORK"
REASON_SWARM_FROZEN = "SWARM_IS_QUIESCING"
REASON_NOT_LEASE_HOLDER = "NOT_THE_LEASE_HOLDER"
REASON_LEASE_ALREADY_CLOSED = "LEASE_ALREADY_CLOSED"
REASON_WORK_CLASS_NOT_DELEGATED = "WORK_CLASS_NOT_DELEGATED_TO_THIS_WORKER"

# A delegation may carry bounded INTERNAL computation. These classes are not internal: they change the
# world, and the world is changed through 4.0's authority, never through a swarm assignment.
GOVERNED_CHANGE_CLASSES: Tuple[str, ...] = ("PRODUCTION_INSTALL", "META_PROMOTION", "KEY_ACCESS",
                                            "NETWORK_POST")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_delegations (
        delegation_id TEXT PRIMARY KEY,
        parent_work_id TEXT,
        parent_mission_id TEXT,
        autonomy_session_id TEXT,
        task_identity TEXT NOT NULL,
        task_generation INTEGER NOT NULL,
        input_digest TEXT NOT NULL,
        basis_digest TEXT NOT NULL,
        allowed_work_class TEXT NOT NULL,
        required_capabilities_json TEXT,
        resource_budget_ref TEXT,
        deadline REAL,
        status TEXT NOT NULL,
        created_at REAL,
        completed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_leases (
        lease_id TEXT PRIMARY KEY,
        delegation_id TEXT NOT NULL,
        worker_id TEXT NOT NULL,
        worker_generation INTEGER NOT NULL,
        claimed_at REAL,
        expires_at REAL,
        closed_at REAL,
        input_digest TEXT NOT NULL,
        status TEXT NOT NULL,
        note TEXT
    );
    """,
)


@dataclass(frozen=True)
class SwarmDelegation:
    delegation_id: str
    parent_work_id: Optional[str]
    parent_mission_id: Optional[str]
    autonomy_session_id: Optional[str]
    task_identity: str
    task_generation: int
    input_digest: str
    basis_digest: str
    allowed_work_class: str
    required_capabilities: Tuple[str, ...]
    resource_budget_ref: Optional[str]
    deadline: Optional[float]
    status: str

    def as_dict(self) -> Dict[str, Any]:
        return {"delegation_id": self.delegation_id, "parent_work_id": self.parent_work_id,
                "parent_mission_id": self.parent_mission_id,
                "autonomy_session_id": self.autonomy_session_id,
                "task_identity": self.task_identity, "task_generation": self.task_generation,
                "input_digest": self.input_digest, "basis_digest": self.basis_digest,
                "allowed_work_class": self.allowed_work_class,
                "required_capabilities": list(self.required_capabilities),
                "resource_budget_ref": self.resource_budget_ref, "deadline": self.deadline,
                "status": self.status, "policy_version": SWARM_DELEGATION_V1}


@dataclass(frozen=True)
class SwarmLease:
    lease_id: str
    delegation_id: str
    worker_id: str
    worker_generation: int
    claimed_at: float
    expires_at: float
    input_digest: str
    status: str

    def as_dict(self) -> Dict[str, Any]:
        return {"lease_id": self.lease_id, "delegation_id": self.delegation_id,
                "worker_id": self.worker_id, "worker_generation": self.worker_generation,
                "claimed_at": self.claimed_at, "expires_at": self.expires_at,
                "input_digest": self.input_digest, "status": self.status,
                "policy_version": SWARM_LEASE_V1}


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


def propose_delegation(db_path: str, *, task_identity: str, input_digest: str, basis_digest: str,
                       allowed_work_class: str, task_generation: int = 1, parent_work_id: Optional[str] = None,
                       parent_mission_id: Optional[str] = None,
                       autonomy_session_id: Optional[str] = None,
                       required_capabilities: Sequence[str] = (),
                       resource_budget_ref: Optional[str] = None, deadline: Optional[float] = None,
                       now: Optional[float] = None) -> SwarmDelegation:
    """
    Propose one bounded piece of delegated computation.

    The identity is derived from the task and ITS GENERATION, so re-proposing the same task at
    generation 1 is one delegation however many workers hear about it, while a genuine re-issue is a
    new generation rather than a mutation of the old one.
    """
    if str(allowed_work_class) in GOVERNED_CHANGE_CLASSES:
        raise CrucibleError(REASON_GOVERNED_CHANGE, str(allowed_work_class))
    moment = time.time() if now is None else float(now)
    delegation_id = "SD-" + digest({"task": str(task_identity), "gen": int(task_generation),
                                    "input": str(input_digest),
                                    "class": str(allowed_work_class)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_swarm_delegations (delegation_id, parent_work_id, "
            "parent_mission_id, autonomy_session_id, task_identity, task_generation, input_digest, "
            "basis_digest, allowed_work_class, required_capabilities_json, resource_budget_ref, "
            "deadline, status, created_at, completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (delegation_id, parent_work_id, parent_mission_id, autonomy_session_id,
             str(task_identity), int(task_generation), str(input_digest), str(basis_digest),
             str(allowed_work_class), json.dumps(sorted(str(item) for item in required_capabilities)),
             resource_budget_ref, deadline, ELIGIBLE, moment, None))
        connection.commit()
    finally:
        connection.close()
    return get_delegation(db_path, delegation_id)


def get_delegation(db_path: str, delegation_id: str) -> SwarmDelegation:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_swarm_delegations WHERE delegation_id = ?;",
                                 (str(delegation_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_DELEGATION, str(delegation_id))
    row = dict(row)
    return SwarmDelegation(
        delegation_id=str(row["delegation_id"]), parent_work_id=row["parent_work_id"],
        parent_mission_id=row["parent_mission_id"], autonomy_session_id=row["autonomy_session_id"],
        task_identity=str(row["task_identity"]), task_generation=int(row["task_generation"]),
        input_digest=str(row["input_digest"]), basis_digest=str(row["basis_digest"]),
        allowed_work_class=str(row["allowed_work_class"]),
        required_capabilities=tuple(json.loads(row["required_capabilities_json"] or "[]")),
        resource_budget_ref=row["resource_budget_ref"], deadline=row["deadline"],
        status=str(row["status"]))


def delegations(db_path: str, *, status: Optional[str] = None) -> List[SwarmDelegation]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT delegation_id FROM ciph_swarm_delegations"
    params: Tuple[Any, ...] = ()
    if status is not None:
        query += " WHERE status = ?"
        params = (str(status),)
    try:
        ids = [str(row["delegation_id"]) for row in connection.execute(
            query + " ORDER BY created_at, delegation_id;", params)]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_delegation(db_path, delegation_id) for delegation_id in ids]


def _lease_status(row: Any, *, now: float) -> str:
    status = str(row["status"])
    if status == LEASE_ACTIVE and row["expires_at"] is not None and now > float(row["expires_at"]):
        return LEASE_EXPIRED
    return status


def _lease_from_row(row: Any, *, now: float) -> SwarmLease:
    row = dict(row)
    return SwarmLease(lease_id=str(row["lease_id"]), delegation_id=str(row["delegation_id"]),
                      worker_id=str(row["worker_id"]),
                      worker_generation=int(row["worker_generation"]),
                      claimed_at=float(row["claimed_at"]), expires_at=float(row["expires_at"]),
                      input_digest=str(row["input_digest"]),
                      status=_lease_status(row, now=now))


def leases_for(db_path: str, delegation_id: str, *, now: Optional[float] = None
               ) -> List[SwarmLease]:
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_leases WHERE delegation_id = ? "
            "ORDER BY claimed_at, lease_id;", (str(delegation_id),))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [_lease_from_row(row, now=moment) for row in rows]


def current_lease(db_path: str, delegation_id: str, *, now: Optional[float] = None
                  ) -> Optional[SwarmLease]:
    """The ONE lease that currently possesses the delegation, if any."""
    for lease in leases_for(db_path, delegation_id, now=now):
        if lease.status == LEASE_ACTIVE:
            return lease
    return None


def claim_delegation(db_path: str, delegation_id: str, *, worker_id: str, worker_generation: int,
                     input_digest: str, lease_seconds: float = 60.0,
                     now: Optional[float] = None) -> SwarmLease:
    """
    Take possession of one delegation for a bounded time.

    Refusals, in the order they are checked, are the whole 6.2 argument: the swarm must be open (a
    freeze is a freeze), the worker must be CURRENT and active (an old generation may not work), the
    input must match (a worker may not quietly study a different question), and a live lease must not
    already exist (one current possessor, and an expired one is released rather than stolen silently).
    """
    from ciph.kernel.swarm_quiescence import swarm_is_frozen
    from ciph.kernel.swarm_worker import ACTIVE_STATUSES, get_worker, is_current_generation
    moment = time.time() if now is None else float(now)
    delegation = get_delegation(db_path, delegation_id)
    if delegation.status not in (ELIGIBLE, ASSIGNED):
        raise CrucibleError(REASON_NOT_ELIGIBLE, f"{delegation_id}:{delegation.status}")
    if swarm_is_frozen(db_path):
        raise CrucibleError(REASON_SWARM_FROZEN, str(delegation_id))
    if str(input_digest) != delegation.input_digest:
        raise CrucibleError(REASON_INPUT_MISMATCH, f"{delegation_id}:{input_digest[:12]}")
    if not is_current_generation(db_path, str(worker_id), int(worker_generation)):
        raise CrucibleError(REASON_STALE_GENERATION, f"{worker_id}:{worker_generation}")
    worker = get_worker(db_path, str(worker_id), int(worker_generation))
    if worker.status not in ACTIVE_STATUSES:
        raise CrucibleError(REASON_WORKER_NOT_READY, f"{worker_id}:{worker.status}")
    existing = current_lease(db_path, delegation_id, now=moment)
    if existing is not None:
        raise CrucibleError(REASON_ALREADY_CLAIMED,
                            f"{delegation_id}:held-by {existing.worker_id}")
    lease_id = "SL-" + digest({"delegation": delegation_id, "worker": str(worker_id),
                               "gen": int(worker_generation), "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        # THE RACE. Several workers claim at once, and a read-then-write across separate statements is
        # not a decision - it is a guess. The runtime torture found exactly that: three processes each
        # read "no active lease", each wrote one, and one delegation acquired three holders.
        #
        # So possession is decided INSIDE a write transaction: IMMEDIATE takes the write lock first, the
        # active-lease check is repeated under it, and a loser blocks (busy timeout) and then sees the
        # winner's lease rather than a stale empty read.
        connection.isolation_level = None
        connection.execute("BEGIN IMMEDIATE;")
        holder = connection.execute(
            "SELECT worker_id FROM ciph_swarm_leases WHERE delegation_id = ? AND status = ? "
            "AND expires_at IS NOT NULL AND expires_at >= ? ORDER BY claimed_at LIMIT 1;",
            (str(delegation_id), LEASE_ACTIVE, moment)).fetchone()
        if holder is not None:
            connection.execute("ROLLBACK;")
            raise CrucibleError(REASON_ALREADY_CLAIMED,
                                f"{delegation_id}:held-by {holder['worker_id']}")
        # Every expired lease is closed explicitly BEFORE the new one is written, so the history reads
        # as "W1 held it until T, then W2 took it" rather than as two simultaneous possessors.
        connection.execute("UPDATE ciph_swarm_leases SET status = ?, closed_at = ? "
                           "WHERE delegation_id = ? AND status = ? AND expires_at IS NOT NULL "
                           "AND expires_at < ?;",
                           (LEASE_EXPIRED, moment, str(delegation_id), LEASE_ACTIVE, moment))
        connection.execute(
            "INSERT INTO ciph_swarm_leases (lease_id, delegation_id, worker_id, worker_generation, "
            "claimed_at, expires_at, closed_at, input_digest, status, note) "
            "VALUES (?,?,?,?,?,?,?,?,?,?);",
            (lease_id, str(delegation_id), str(worker_id), int(worker_generation), moment,
             moment + float(lease_seconds), None, str(input_digest), LEASE_ACTIVE, None))
        connection.execute("UPDATE ciph_swarm_delegations SET status = ? WHERE delegation_id = ?;",
                           (ASSIGNED, str(delegation_id)))
        connection.execute("COMMIT;")
    except CrucibleError:
        raise
    except sqlite3.Error:
        try:
            connection.execute("ROLLBACK;")
        except sqlite3.Error:
            pass
        raise
    finally:
        connection.close()
    return get_lease(db_path, lease_id, now=moment)


def get_lease(db_path: str, lease_id: str, *, now: Optional[float] = None) -> SwarmLease:
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_swarm_leases WHERE lease_id = ?;",
                                 (str(lease_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_LEASE, str(lease_id))
    return _lease_from_row(row, now=moment)


def release_lease(db_path: str, lease_id: str, *, worker_id: str, worker_generation: int,
                  note: Optional[str] = None, status: str = LEASE_RELEASED,
                  actor: Optional[str] = None, now: Optional[float] = None) -> SwarmLease:
    """
    Give a delegation back, or have it taken away.

    Only the holder's own GENERATION may release it, unless the actor is the operator: a restarted
    worker is a different generation and must not tidy up after its predecessor as if it were it.
    """
    if status not in (LEASE_RELEASED, LEASE_INTERRUPTED):
        raise CrucibleError("INVALID_LEASE_CLOSE_STATUS", str(status))
    moment = time.time() if now is None else float(now)
    lease = get_lease(db_path, lease_id, now=moment)
    if lease.status != LEASE_ACTIVE:
        raise CrucibleError(REASON_LEASE_ALREADY_CLOSED, f"{lease_id}:{lease.status}")
    if not str(actor or "").startswith("operator:"):
        if lease.worker_id != str(worker_id) or lease.worker_generation != int(worker_generation):
            raise CrucibleError(REASON_NOT_LEASE_HOLDER,
                                f"{lease_id}:held-by {lease.worker_id}/{lease.worker_generation}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_leases SET status = ?, closed_at = ?, note = ? "
                           "WHERE lease_id = ?;", (status, moment, note, str(lease_id)))
        connection.commit()
    finally:
        connection.close()
    return get_lease(db_path, lease_id, now=moment)


def reclaim_expired_leases(db_path: str, *, now: Optional[float] = None) -> int:
    """
    Mark expired leases and return the delegations to the pool.

    Reclaiming a lease says NOTHING about the work the lost worker may have done: whatever it produced
    is classified when it arrives, not assumed at the moment possession is lost. A delegation whose
    worker died is available again; nothing is inferred about effects it may have had.
    """
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        expired = [str(row["delegation_id"]) for row in connection.execute(
            "SELECT DISTINCT delegation_id FROM ciph_swarm_leases WHERE status = ? "
            "AND expires_at IS NOT NULL AND expires_at < ?;", (LEASE_ACTIVE, moment))]
        cursor = connection.execute("UPDATE ciph_swarm_leases SET status = ?, closed_at = ? "
                                    "WHERE status = ? AND expires_at IS NOT NULL AND expires_at < ?;",
                                    (LEASE_EXPIRED, moment, LEASE_ACTIVE, moment))
        for delegation_id in expired:
            connection.execute("UPDATE ciph_swarm_delegations SET status = ? WHERE delegation_id = ? "
                               "AND status = ?;", (ELIGIBLE, delegation_id, ASSIGNED))
        connection.commit()
        return int(cursor.rowcount)
    finally:
        connection.close()


def interrupt_live_leases(db_path: str, *, actor: str, note: Optional[str] = None,
                          now: Optional[float] = None) -> List[str]:
    """
    Interrupt every lease that is currently live - the emergency-stop write, owned here.

    It lives in the lease module because the lease table has one writer, and because the meaning belongs
    here: an interrupted lease is INTERRUPTED, never COMPLETED. Nothing in this path writes a result,
    and nothing assumes the interrupted work had no effect - that is a question for reconciliation.
    """
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        live = [str(row["lease_id"]) for row in connection.execute(
            "SELECT lease_id FROM ciph_swarm_leases WHERE status = ? ORDER BY claimed_at, lease_id;",
            (LEASE_ACTIVE,))]
        for lease_id in live:
            connection.execute("UPDATE ciph_swarm_leases SET status = ?, closed_at = ?, note = ? "
                               "WHERE lease_id = ?;",
                               (LEASE_INTERRUPTED, moment, note or f"interrupted by {actor}",
                                lease_id))
        connection.commit()
    finally:
        connection.close()
    return sorted(live)


def complete_delegation(db_path: str, delegation_id: str, *, now: Optional[float] = None
                        ) -> SwarmDelegation:
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_delegations SET status = ?, completed_at = ? "
                           "WHERE delegation_id = ?;", (COMPLETED, moment, str(delegation_id)))
        connection.commit()
    finally:
        connection.close()
    return get_delegation(db_path, delegation_id)


def assert_scope_within_delegation(db_path: str, delegation_id: str, *,
                                   requested_work_class: str) -> None:
    """
    A worker may not widen what it was asked to do - not even to a "cheaper" class.

    Widening is refused here rather than policed later because the delegation is the ONLY statement of
    what the worker was asked to do, and a worker that can edit that statement can authorise itself.
    """
    delegation = get_delegation(db_path, delegation_id)
    if str(requested_work_class) != delegation.allowed_work_class:
        raise CrucibleError(REASON_WORK_CLASS_NOT_DELEGATED,
                            f"{delegation_id}:{requested_work_class}!={delegation.allowed_work_class}")


def delegation_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        leases = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_leases ORDER BY claimed_at, lease_id;")]
    except sqlite3.Error:
        leases = []
    finally:
        connection.close()
    return digest({"version": SWARM_DELEGATION_V1,
                   "delegations": [item.as_dict() for item in delegations(db_path)],
                   "leases": leases})
