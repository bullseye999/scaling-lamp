"""
ciph/kernel/federation_quiescence - 7.6: distributed quiescence.

    6.x could demand DEAD + reconciled, because the host could inspect its own processes.
    7.x cannot. Across hosts, UNREACHABLE is not DEAD, and timeout is not an acknowledgement.

So the federation barrier separates four ways a node can be accounted for, and only three of them
resolve anything:

    ACKNOWLEDGED_QUIESCENT   the node said it stopped, and what it reached
    REVOKED_FROM_AUTHORITY   its authority was withdrawn by a governed act, so it cannot act even if it
                             is still running
    RECONCILED               what it left behind was settled with evidence
    UNREACHABLE              nothing is known. This RESOLVES NOTHING.

That last line is the phase. A federation cannot report itself quiescent because a machine stopped
answering the phone - it either gets an answer, revokes, reconciles, or stays incomplete and frozen.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

FEDERATION_QUIESCENCE_V1 = "FEDERATION_QUIESCENCE_V1"

REQUESTED = "REQUESTED"
DRAINING = "DRAINING"
QUIESCENT = "QUIESCENT"
INCOMPLETE = "INCOMPLETE"
RELEASED = "RELEASED"
FAILED = "FAILED"
VALID_STATUSES = (REQUESTED, DRAINING, QUIESCENT, INCOMPLETE, RELEASED, FAILED)
_FROZEN = (REQUESTED, DRAINING, QUIESCENT, INCOMPLETE, FAILED)

ACKNOWLEDGED_QUIESCENT = "ACKNOWLEDGED_QUIESCENT"
REVOKED_FROM_AUTHORITY = "REVOKED_FROM_AUTHORITY"
RECONCILED = "RECONCILED"
OBSERVED_UNREACHABLE = "UNREACHABLE"
VALID_OUTCOMES = (ACKNOWLEDGED_QUIESCENT, REVOKED_FROM_AUTHORITY, RECONCILED, OBSERVED_UNREACHABLE)
_RESOLVING = (ACKNOWLEDGED_QUIESCENT, REVOKED_FROM_AUTHORITY, RECONCILED)

REASON_NOT_OPERATOR = "FEDERATION_QUIESCENCE_REQUIRES_AN_OPERATOR"
REASON_UNKNOWN_BARRIER = "UNKNOWN_FEDERATION_BARRIER"
REASON_ALREADY_FROZEN = "FEDERATION_ALREADY_QUIESCING"
REASON_NOT_IN_SNAPSHOT = "NODE_NOT_IN_THE_FEDERATION_SNAPSHOT"
REASON_INCOMPLETE = "FEDERATION_QUIESCENCE_INCOMPLETE"

REASON_QUIESCE = "QUIESCE"
REASON_EMERGENCY_STOP = "EMERGENCY_STOP"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_barriers (
        barrier_id TEXT PRIMARY KEY,
        barrier_generation INTEGER NOT NULL,
        reason TEXT NOT NULL,
        status TEXT NOT NULL,
        required_json TEXT NOT NULL,
        acks_json TEXT,
        unresolved_json TEXT,
        requested_by TEXT,
        requested_at REAL,
        settled_at REAL,
        released_at REAL
    );
    """,
)


@dataclass(frozen=True)
class FederationBarrier:
    barrier_id: str
    barrier_generation: int
    reason: str
    status: str
    required: Tuple[str, ...]
    acks: Dict[str, str]
    unresolved: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"barrier_id": self.barrier_id, "barrier_generation": self.barrier_generation,
                "reason": self.reason, "status": self.status, "required": list(self.required),
                "acks": dict(self.acks), "unresolved": list(self.unresolved),
                "policy_version": FEDERATION_QUIESCENCE_V1}


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


def _from_row(row: Any) -> FederationBarrier:
    row = dict(row)
    return FederationBarrier(barrier_id=str(row["barrier_id"]),
                             barrier_generation=int(row["barrier_generation"]),
                             reason=str(row["reason"]), status=str(row["status"]),
                             required=tuple(json.loads(row["required_json"] or "[]")),
                             acks=dict(json.loads(row["acks_json"] or "{}")),
                             unresolved=tuple(json.loads(row["unresolved_json"] or "[]")))


def get_barrier(db_path: str, barrier_id: str) -> FederationBarrier:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_federation_barriers WHERE barrier_id = ?;",
                                 (str(barrier_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_BARRIER, str(barrier_id))
    return _from_row(row)


def current_barrier(db_path: str) -> Optional[FederationBarrier]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_federation_barriers WHERE status IN "
                                 "(?,?,?,?,?) ORDER BY barrier_generation DESC LIMIT 1;",
                                 _FROZEN).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return _from_row(row) if row is not None else None


def federation_is_frozen(db_path: str) -> bool:
    try:
        return current_barrier(db_path) is not None
    except sqlite3.Error:
        return False


def open_barrier(db_path: str, *, actor: str, reason: str = REASON_QUIESCE,
                 snapshot: Optional[Sequence[str]] = None,
                 now: Optional[float] = None) -> FederationBarrier:
    """
    Freeze the federation and record exactly who must answer.

    The snapshot is the contract. Nodes that join afterwards cannot become active while the barrier is
    in force, so they cannot slip in behind it, and a node that is already unreachable is still IN the
    snapshot - because its silence is precisely what the barrier must account for.
    """
    from ciph.kernel.federation_node import ACTIVE_MEMBERSHIP, is_current_generation, nodes
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    existing = current_barrier(db_path)
    if existing is not None:
        raise CrucibleError(REASON_ALREADY_FROZEN, f"{existing.barrier_id}:{existing.status}")
    if snapshot is None:
        # The snapshot names a GENERATION, so it is worth being explicit that only the CURRENT
        # generation of a node can be in it: a barrier against a superseded runtime would be a barrier
        # against a process that no longer speaks for the node.
        members = [f"{node.node_id}@{node.node_generation}"
                   for node in nodes(db_path, memberships=ACTIVE_MEMBERSHIP)
                   if is_current_generation(db_path, node.node_id, node.node_generation)]
    else:
        members = sorted(str(item) for item in snapshot)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        row = connection.execute("SELECT MAX(barrier_generation) AS latest "
                                 "FROM ciph_federation_barriers;").fetchone()
        generation = int(row["latest"] or 0) + 1
        barrier_id = "FQB-" + digest({"generation": generation, "reason": str(reason),
                                      "members": sorted(members)})[:16].upper()
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_barriers (barrier_id, barrier_generation, reason, "
            "status, required_json, acks_json, unresolved_json, requested_by, requested_at, "
            "settled_at, released_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (barrier_id, generation, str(reason), REQUESTED, json.dumps(sorted(members)),
             json.dumps({}), json.dumps(sorted(members)), str(actor), moment, None, None))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def _settle(db_path: str, barrier_id: str, *, now: float) -> FederationBarrier:
    barrier = get_barrier(db_path, barrier_id)
    if barrier.status == RELEASED:
        return barrier
    unresolved = sorted(member for member in barrier.required
                        if barrier.acks.get(member) not in _RESOLVING)
    status = QUIESCENT if not unresolved else (INCOMPLETE if barrier.status == INCOMPLETE
                                               else DRAINING)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_barriers SET status = ?, unresolved_json = ?, "
                           "settled_at = ? WHERE barrier_id = ?;",
                           (status, json.dumps(unresolved),
                            now if status == QUIESCENT else None, str(barrier_id)))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def acknowledge(db_path: str, barrier_id: str, *, node_id: str, generation: int,
                outcome: str = ACKNOWLEDGED_QUIESCENT, note: Optional[str] = None,
                actor: Optional[str] = None, now: Optional[float] = None) -> FederationBarrier:
    """
    Record how one node was accounted for. UNREACHABLE may be recorded here too - it just does not
    resolve anything, which is the distinction the whole phase turns on.
    """
    if str(outcome) not in VALID_OUTCOMES:
        raise CrucibleError("UNKNOWN_FEDERATION_ACK_OUTCOME", str(outcome))
    if outcome in (REVOKED_FROM_AUTHORITY, RECONCILED) and not _operator(actor or ""):
        raise CrucibleError(REASON_NOT_OPERATOR, f"{outcome} requires an operator")
    moment = time.time() if now is None else float(now)
    barrier = get_barrier(db_path, barrier_id)
    member = f"{node_id}@{int(generation)}"
    if member not in set(barrier.required):
        raise CrucibleError(REASON_NOT_IN_SNAPSHOT, member)
    acks = dict(barrier.acks)
    acks[member] = str(outcome)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_barriers SET acks_json = ? WHERE barrier_id = ?;",
                           (json.dumps(acks, sort_keys=True), str(barrier_id)))
        connection.commit()
    finally:
        connection.close()
    return _settle(db_path, barrier_id, now=moment)


def observe_unreachable(db_path: str, barrier_id: str, *, node_id: str, generation: int,
                        observed_by: str, now: Optional[float] = None) -> FederationBarrier:
    """
    Record that a node did not answer. It is evidence about the LINK, and it resolves nothing.

    This is the function that would be tempting to write as "the node is gone". It is not.
    """
    return acknowledge(db_path, barrier_id, node_id=node_id, generation=generation,
                       outcome=OBSERVED_UNREACHABLE,
                       note=f"not reached from {observed_by}", now=now)


def mark_incomplete(db_path: str, barrier_id: str, *, actor: str, reason: str,
                    now: Optional[float] = None) -> FederationBarrier:
    """Say out loud that the federation could not be brought to rest. It stays FROZEN."""
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    barrier = get_barrier(db_path, barrier_id)
    unresolved = sorted(member for member in barrier.required
                        if barrier.acks.get(member) not in _RESOLVING)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_barriers SET status = ?, unresolved_json = ?, "
                           "settled_at = ? WHERE barrier_id = ?;",
                           (INCOMPLETE, json.dumps(unresolved), moment, str(barrier_id)))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def release_barrier(db_path: str, barrier_id: str, *, actor: str,
                    now: Optional[float] = None) -> FederationBarrier:
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_barriers SET status = ?, released_at = ? "
                           "WHERE barrier_id = ?;", (RELEASED, moment, str(barrier_id)))
        connection.commit()
    finally:
        connection.close()
    return get_barrier(db_path, barrier_id)


def emergency_stop(db_path: str, *, actor: str, reason: str = "operator emergency stop",
                   now: Optional[float] = None) -> Dict[str, Any]:
    """
    Freeze the federation and withdraw distributed authority - without inventing any acknowledgements.

    Domains go FROZEN (a governed status change, not a transfer), every live domain's owner therefore
    cannot transition anything, and the barrier records that nothing has answered yet. An interrupted
    transition stays interrupted.
    """
    from ciph.kernel.federation_authority import (DOMAIN_FROZEN, domains, set_domain_status)
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    barrier = open_barrier(db_path, actor=actor, reason=REASON_EMERGENCY_STOP, now=moment)
    frozen = []
    for domain in domains(db_path):
        if domain.status != DOMAIN_FROZEN:
            set_domain_status(db_path, domain.domain_id, status=DOMAIN_FROZEN, actor=actor,
                              now=moment)
            frozen.append(domain.domain_id)
    return {"barrier_id": barrier.barrier_id, "status": barrier.status, "domains_frozen": frozen,
            "acknowledgements_fabricated": 0, "transitions_interrupted_stay_interrupted": True,
            "policy_version": FEDERATION_QUIESCENCE_V1}


def barrier_state(db_path: str) -> Dict[str, Any]:
    barrier = current_barrier(db_path)
    return {"frozen": barrier is not None,
            "barrier": barrier.as_dict() if barrier else None,
            "unresolved": list(barrier.unresolved) if barrier else []}


def quiescence_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_federation_barriers ORDER BY barrier_generation, barrier_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return digest({"version": FEDERATION_QUIESCENCE_V1, "barriers": rows})
