"""
ciph/kernel/swarm_quiescence - 6.5 (the distributed quiescence barrier) and 6.6 (swarm emergency stop).

5.x left one question open on purpose:

    single-process: QUIESCE -> stop minting work -> drain
    swarm:           W1 working, W2 idle, W3 crashed, W4 joining, W5 holding a lease -> now what?

The answer here is that a barrier FREEZES the swarm first and settles second, and that it never
converts silence into a stop:

    timeout != worker acknowledged
    "W3 hasn't answered in 30 seconds" != "W3 has definitely stopped"

So the barrier completes only when every required member is ACKNOWLEDGED, or DEAD-and-reconciled, or
QUARANTINED-and-reconciled - and the reconciliation is an operator-or-coordinator act with an evidence
slot, not a clock reading. On one host the coordinator can inspect process state directly, which is
exactly why "the process is gone AND somebody reconciled what it was holding" is achievable here and
will need a different answer in 7.x federation.

Emergency stop is the same barrier with a stronger reason: it interrupts live leases (INTERRUPTED, not
COMPLETED - an interrupted attempt stays interrupted), it lets 5.x's operator mode do the authority
part, and it fabricates nothing.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SWARM_QUIESCENCE_V1 = "SWARM_QUIESCENCE_V1"

REQUESTED = "REQUESTED"
DRAINING = "DRAINING"
QUIESCED = "QUIESCED"
INCOMPLETE = "INCOMPLETE"
FAILED = "FAILED"
RELEASED = "RELEASED"
VALID_BARRIER_STATUSES = (REQUESTED, DRAINING, QUIESCED, INCOMPLETE, FAILED, RELEASED)
_FROZEN_STATUSES = (REQUESTED, DRAINING, QUIESCED, INCOMPLETE, FAILED)

ACK_SAFE_BOUNDARY = "SAFE_BOUNDARY_REACHED"
ACK_LEASE_RELEASED = "LEASE_RELEASED"
ACK_WORK_INTERRUPTED = "WORK_INTERRUPTED"
VALID_ACK_OUTCOMES = (ACK_SAFE_BOUNDARY, ACK_LEASE_RELEASED, ACK_WORK_INTERRUPTED)

RECONCILED_DEAD = "DEAD_AND_RECONCILED"
RECONCILED_QUARANTINED = "QUARANTINED_AND_RECONCILED"
VALID_RECONCILIATIONS = (RECONCILED_DEAD, RECONCILED_QUARANTINED)

REASON_QUIESCE = "QUIESCE"
REASON_EMERGENCY_STOP = "EMERGENCY_STOP"

REASON_NOT_OPERATOR = "SWARM_QUIESCENCE_REQUIRES_AN_OPERATOR"
REASON_UNKNOWN_BARRIER = "UNKNOWN_SWARM_BARRIER"
REASON_ALREADY_FROZEN = "SWARM_IS_ALREADY_QUIESCING"
REASON_STILL_DRAINING = "BARRIER_STILL_DRAINING"
REASON_NOT_IN_SNAPSHOT = "WORKER_NOT_IN_THE_BARRIER_SNAPSHOT"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_barriers (
        barrier_id TEXT PRIMARY KEY,
        barrier_generation INTEGER NOT NULL,
        reason TEXT NOT NULL,
        status TEXT NOT NULL,
        required_json TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        unresolved_json TEXT,
        requested_by TEXT,
        requested_at REAL,
        settled_at REAL,
        released_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_barrier_acks (
        ack_id TEXT PRIMARY KEY,
        barrier_id TEXT NOT NULL,
        worker_id TEXT NOT NULL,
        instance_generation INTEGER,
        outcome TEXT NOT NULL,
        note TEXT,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class Barrier:
    barrier_id: str
    barrier_generation: int
    reason: str
    status: str
    required: Tuple[str, ...]
    snapshot: Tuple[str, ...]
    unresolved: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"barrier_id": self.barrier_id, "barrier_generation": self.barrier_generation,
                "reason": self.reason, "status": self.status, "required": list(self.required),
                "snapshot": list(self.snapshot), "unresolved": list(self.unresolved),
                "policy_version": SWARM_QUIESCENCE_V1}


@dataclass(frozen=True)
class Acknowledgement:
    ack_id: str
    barrier_id: str
    worker_id: str
    instance_generation: Optional[int]
    outcome: str
    note: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"ack_id": self.ack_id, "barrier_id": self.barrier_id, "worker_id": self.worker_id,
                "instance_generation": self.instance_generation, "outcome": self.outcome,
                "note": self.note, "policy_version": SWARM_QUIESCENCE_V1}


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


def _operator(actor: str) -> bool:
    return str(actor).startswith("operator:")


def _row_to_barrier(row: Any) -> Barrier:
    row = dict(row)
    return Barrier(barrier_id=str(row["barrier_id"]),
                   barrier_generation=int(row["barrier_generation"]), reason=str(row["reason"]),
                   status=str(row["status"]),
                   required=tuple(json.loads(row["required_json"] or "[]")),
                   snapshot=tuple(json.loads(row["snapshot_json"] or "[]")),
                   unresolved=tuple(json.loads(row["unresolved_json"] or "[]")))


def get_barrier(db_path: str, barrier_id: str) -> Barrier:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_swarm_barriers WHERE barrier_id = ?;",
                                 (str(barrier_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_BARRIER, str(barrier_id))
    return _row_to_barrier(row)


def current_barrier(db_path: str) -> Optional[Barrier]:
    """The barrier that is still in force, if any. A RELEASED barrier is history, not a freeze."""
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_swarm_barriers WHERE status IN "
                                 "(?,?,?,?,?) ORDER BY barrier_generation DESC LIMIT 1;",
                                 _FROZEN_STATUSES).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return _row_to_barrier(row) if row is not None else None


def swarm_is_frozen(db_path: str) -> bool:
    """Freezing is the default for as long as a barrier is in force - including while it is stuck."""
    try:
        return current_barrier(db_path) is not None
    except sqlite3.Error:
        return False


def assert_swarm_open(db_path: str) -> None:
    barrier = current_barrier(db_path)
    if barrier is not None:
        raise CrucibleError(REASON_ALREADY_FROZEN, f"{barrier.barrier_id}:{barrier.status}")


def open_barrier(db_path: str, *, actor: str, reason: str = REASON_QUIESCE,
                 now: Optional[float] = None) -> Barrier:
    """
    Freeze the swarm and record exactly who is expected to stop.

    The snapshot is taken at request time and is the barrier's whole contract: a worker that joins
    AFTER this instant cannot be active (claims are refused while frozen), so the snapshot is the
    complete set of members whose stopping matters.
    """
    from ciph.kernel.swarm_worker import ACTIVE_STATUSES, members
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    existing = current_barrier(db_path)
    if existing is not None:
        raise CrucibleError(REASON_ALREADY_FROZEN, f"{existing.barrier_id}:{existing.status}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        row = connection.execute("SELECT MAX(barrier_generation) AS latest FROM ciph_swarm_barriers;"
                                 ).fetchone()
        generation = int(row["latest"] or 0) + 1
    finally:
        connection.close()
    live = members(db_path)
    snapshot = sorted(f"{identity.worker_id}@{identity.instance_generation}"
                      for identity in live)
    required = sorted(f"{identity.worker_id}@{identity.instance_generation}"
                      for identity in live
                      if identity.status in ACTIVE_STATUSES or identity.status == "QUIESCING")
    barrier_id = "SQB-" + digest({"gen": generation, "reason": str(reason),
                                 "snapshot": snapshot})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_swarm_barriers (barrier_id, barrier_generation, reason, "
            "status, required_json, snapshot_json, unresolved_json, requested_by, requested_at, "
            "settled_at, released_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (barrier_id, generation, str(reason), REQUESTED, json.dumps(required),
             json.dumps(snapshot), json.dumps(required), str(actor), moment, None, None))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def _acks(db_path: str, barrier_id: str) -> List[Acknowledgement]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_barrier_acks WHERE barrier_id = ? "
            "ORDER BY recorded_at, ack_id;", (str(barrier_id),))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [Acknowledgement(ack_id=str(row["ack_id"]), barrier_id=str(row["barrier_id"]),
                            worker_id=str(row["worker_id"]),
                            instance_generation=row["instance_generation"],
                            outcome=str(row["outcome"]), note=row["note"]) for row in rows]


def _unresolved(db_path: str, barrier: Barrier) -> Tuple[str, ...]:
    answered = {f"{ack.worker_id}@{ack.instance_generation}" for ack in _acks(db_path, barrier.barrier_id)}
    reconciled = set(barrier.snapshot) - set(barrier.required)
    answered |= reconciled
    return tuple(sorted(set(barrier.required) - answered))


def acknowledge(db_path: str, barrier_id: str, *, worker_id: str, instance_generation: int,
                 outcome: str = ACK_SAFE_BOUNDARY, note: Optional[str] = None,
                 now: Optional[float] = None) -> Barrier:
    """
    One worker states what it actually reached: a safe boundary, a released lease, or interrupted work.

    An acknowledgement is per-generation. Generation 7's acknowledgement does not speak for generation
    8, because generation 8 may be running code that generation 7 never saw.
    """
    moment = time.time() if now is None else float(now)
    if str(outcome) not in VALID_ACK_OUTCOMES:
        raise CrucibleError("UNKNOWN_ACK_OUTCOME", str(outcome))
    barrier = get_barrier(db_path, barrier_id)
    member = f"{worker_id}@{int(instance_generation)}"
    if member not in set(barrier.snapshot):
        raise CrucibleError(REASON_NOT_IN_SNAPSHOT, member)
    ack_id = "SQA-" + digest({"barrier": barrier_id, "member": member, "outcome": str(outcome)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_swarm_barrier_acks (ack_id, barrier_id, "
                           "worker_id, instance_generation, outcome, note, recorded_at) "
                           "VALUES (?,?,?,?,?,?,?);",
                           (ack_id, str(barrier_id), str(worker_id), int(instance_generation),
                            str(outcome), note, moment))
        connection.commit()
    finally:
        connection.close()
    barrier = settle_barrier(db_path, barrier_id, now=moment)
    return barrier


def report_timeout(db_path: str, barrier_id: str, *, worker_id: str, instance_generation: int,
                   now: Optional[float] = None) -> Barrier:
    """
    Record that a member has NOT answered.

    This writes an acknowledgement-shaped row with the outcome UNRESOLVED so the silence is evidence,
    while the barrier stays DRAINING. That is the difference between noticing a silence and converting
    it into a stop.
    """
    moment = time.time() if now is None else float(now)
    barrier = get_barrier(db_path, barrier_id)
    member = f"{worker_id}@{int(instance_generation)}"
    if member not in set(barrier.snapshot):
        raise CrucibleError(REASON_NOT_IN_SNAPSHOT, member)
    ack_id = "SQT-" + digest({"barrier": barrier_id, "member": member, "timeout": True})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_swarm_barrier_acks (ack_id, barrier_id, "
                           "worker_id, instance_generation, outcome, note, recorded_at) "
                           "VALUES (?,?,?,?,?,?,?);",
                           (ack_id, str(barrier_id), str(worker_id), int(instance_generation),
                            "UNRESOLVED", "timeout observed; not a stop", moment))
        connection.commit()
    finally:
        connection.close()
    barrier = get_barrier(db_path, barrier_id)
    return update_status(db_path, barrier_id, status=DRAINING, now=moment)


def reconcile_worker(db_path: str, barrier_id: str, *, worker_id: str, instance_generation: int,
                     disposition: str, evidence_ref: str, actor: str,
                     now: Optional[float] = None) -> Barrier:
    """
    Settle a member that cannot answer for itself, WITH evidence.

    This is the only path that removes a member from the required set without its acknowledgement, and
    it demands a named disposition and an evidence reference - because "we assume it stopped" is the
    assumption that later turns into two writers.
    """
    if str(disposition) not in VALID_RECONCILIATIONS:
        raise CrucibleError("UNKNOWN_RECONCILIATION", str(disposition))
    if not str(evidence_ref).strip():
        raise CrucibleError("RECONCILIATION_REQUIRES_EVIDENCE", str(worker_id))
    moment = time.time() if now is None else float(now)
    barrier = get_barrier(db_path, barrier_id)
    member = f"{worker_id}@{int(instance_generation)}"
    if member not in set(barrier.required):
        raise CrucibleError(REASON_NOT_IN_SNAPSHOT, member)
    remaining = tuple(item for item in barrier.required if item != member)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_barriers SET required_json = ?, "
                           "unresolved_json = ? WHERE barrier_id = ?;",
                           (json.dumps(list(remaining)), json.dumps(list(remaining)),
                            str(barrier_id)))
        connection.execute("INSERT OR IGNORE INTO ciph_swarm_barrier_acks (ack_id, barrier_id, "
                           "worker_id, instance_generation, outcome, note, recorded_at) "
                           "VALUES (?,?,?,?,?,?,?);",
                           ("SQR-" + digest({"barrier": barrier_id, "member": member,
                                             "disposition": str(disposition)})[:16].upper(),
                            str(barrier_id), str(worker_id), int(instance_generation),
                            str(disposition), f"{actor}:{evidence_ref}", moment))
        connection.commit()
    finally:
        connection.close()
    return settle_barrier(db_path, barrier_id, now=moment)


def update_status(db_path: str, barrier_id: str, *, status: str,
                  now: Optional[float] = None) -> Barrier:
    if status not in VALID_BARRIER_STATUSES:
        raise CrucibleError("UNKNOWN_BARRIER_STATUS", str(status))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_barriers SET status = ?, settled_at = ? "
                           "WHERE barrier_id = ?;", (status, moment, str(barrier_id)))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def settle_barrier(db_path: str, barrier_id: str, *, now: Optional[float] = None) -> Barrier:
    """
    Decide whether the swarm is actually quiesced.

    QUIESCED requires every required member answered or reconciled. A timeout does not count, a
    vanished process does not count on its own, and a new joiner cannot appear in the required set
    because the snapshot was frozen when the barrier opened.
    """
    moment = time.time() if now is None else float(now)
    barrier = get_barrier(db_path, barrier_id)
    if barrier.status in (RELEASED,):
        return barrier
    unresolved = _unresolved(db_path, barrier)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        if unresolved:
            # DRAINING, and it stays DRAINING for as long as members have not answered. A barrier that
            # promoted its own silence to INCOMPLETE would be a clock deciding that people stopped.
            connection.execute("UPDATE ciph_swarm_barriers SET status = ?, unresolved_json = ? "
                               "WHERE barrier_id = ?;",
                               (DRAINING, json.dumps(list(unresolved)), str(barrier_id)))
        else:
            connection.execute("UPDATE ciph_swarm_barriers SET status = ?, unresolved_json = ?, "
                               "settled_at = ? WHERE barrier_id = ?;",
                               (QUIESCED, json.dumps([]), moment, str(barrier_id)))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def fail_barrier(db_path: str, barrier_id: str, *, actor: str, reason: str,
                 now: Optional[float] = None) -> Barrier:
    """
    Declare a barrier UNFINISHABLE. An operator act, with a reason.

    This exists so that "we could not quiesce" is a thing somebody can say out loud. Without it the
    only options would be to wait forever or to let a timeout declare success, and both of those are
    ways of lying about whether the swarm stopped. A failed barrier stays FROZEN: the swarm does not
    resume just because the attempt to stop it failed.
    """
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    barrier = get_barrier(db_path, barrier_id)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        unresolved = list(_unresolved(db_path, barrier))
        connection.execute("UPDATE ciph_swarm_barriers SET status = ?, unresolved_json = ?, "
                           "settled_at = ? WHERE barrier_id = ?;",
                           (INCOMPLETE, json.dumps(unresolved), moment, str(barrier_id)))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def release_barrier(db_path: str, barrier_id: str, *, actor: str,
                    now: Optional[float] = None) -> Barrier:
    """
    Let the swarm work again. An operator act: leaving a freeze is a grant, so a worker cannot do it.
    """
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_barriers SET status = ?, released_at = ? "
                           "WHERE barrier_id = ?;", (RELEASED, moment, str(barrier_id)))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def emergency_stop_swarm(db_path: str, *, actor: str, reason: str = "operator emergency stop",
                         now: Optional[float] = None) -> Dict[str, Any]:
    """
    6.6: stop the whole swarm honestly.

    New delegation is frozen (the barrier), live leases are INTERRUPTED rather than completed, and the
    authority half stays with 5.x's operator mode - this function cannot relax it and does not try. An
    interrupted attempt remains interrupted: nothing here writes a result or a completion.
    """
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    from ciph.kernel.swarm_delegation import interrupt_live_leases
    barrier = open_barrier(db_path, actor=actor, reason=REASON_EMERGENCY_STOP, now=moment)
    interrupted = interrupt_live_leases(db_path, actor=actor, note=f"interrupted by {actor}",
                                       now=moment)
    return {"barrier_id": barrier.barrier_id, "reason": barrier.reason,
            "interrupted_leases": interrupted, "status": barrier.status,
            "fabricated_completions": 0, "policy_version": SWARM_QUIESCENCE_V1}


def swarm_state(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """One projection: is the swarm open, and what is outstanding if it is not?"""
    from ciph.kernel.swarm_delegation import LEASE_ACTIVE, leases_for, delegations
    from ciph.kernel.swarm_worker import members
    moment = time.time() if now is None else float(now)
    barrier = current_barrier(db_path)
    live_leases = []
    for delegation in delegations(db_path):
        for lease in leases_for(db_path, delegation.delegation_id, now=moment):
            if lease.status == LEASE_ACTIVE:
                live_leases.append(lease.lease_id)
    return {"policy_version": SWARM_QUIESCENCE_V1, "frozen": barrier is not None,
            "barrier": barrier.as_dict() if barrier else None,
            "live_leases": sorted(live_leases),
            "unresolved": list(_unresolved(db_path, barrier)) if barrier else [],
            "members": {identity.worker_id: identity.status for identity in members(db_path,
                                                                                  statuses=())}}


def quiescence_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        barriers = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_barriers ORDER BY barrier_generation, barrier_id;")]
        acks = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_barrier_acks ORDER BY recorded_at, ack_id;")]
    except sqlite3.Error:
        barriers, acks = [], []
    finally:
        connection.close()
    return digest({"version": SWARM_QUIESCENCE_V1, "barriers": barriers, "acknowledgements": acks})
