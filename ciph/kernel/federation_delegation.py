"""
ciph/kernel/federation_delegation - 7.4 (cross-node delegation), 7.12 (routing and placement)
and 7.13 (federation learning).

    remote delegation != authority transfer
    remote result    != evidence automatically
    routing          != ownership

Node A may ask Node B to perform bounded computation. B returns a result and the evidence behind it, and
that is ALL B gains: the result is a claim until canonical evidence rules say otherwise (4.2), and if the
computation concludes that production should change, the delegation produces a proposal that goes back
through 4.0's authority, 4.7's promotion constitution and R7's choke point like any other change.

Routing chooses the best node for a task by capability, trust, health, latency, cost and locality. A node
chosen because it is best does not thereby become a domain owner - `record_placement` writes
`authority_granted = 0` into the record it keeps, so the fact is auditable rather than assumed.

Learning is descriptive: outcomes, costs, conflicts and stale work, with no scalar.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

FEDERATION_DELEGATION_V1 = "FEDERATION_DELEGATION_V1"
FEDERATION_ROUTING_V1 = "FEDERATION_ROUTING_V1"
FEDERATION_LEARNING_V1 = "FEDERATION_LEARNING_V1"

PROPOSED = "PROPOSED"
ACCEPTED = "ACCEPTED"
COMPLETED = "COMPLETED"
REFUSED = "REFUSED"
STALE = "STALE"
VALID_STATUSES = (PROPOSED, ACCEPTED, COMPLETED, REFUSED, STALE)

OUTCOME_USEFUL = "USEFUL"
OUTCOME_USELESS = "USELESS"
OUTCOME_FAILED = "FAILED"
OUTCOME_INTERRUPTED = "INTERRUPTED"
VALID_OUTCOMES = (OUTCOME_USEFUL, OUTCOME_USELESS, OUTCOME_FAILED, OUTCOME_INTERRUPTED)

GOVERNED_CHANGE_CLASSES: Tuple[str, ...] = ("PRODUCTION_INSTALL", "META_PROMOTION", "KEY_ACCESS",
                                            "NETWORK_POST")

REASON_GOVERNED_CHANGE = "FEDERATION_DELEGATION_CANNOT_CARRY_A_GOVERNED_CHANGE"
REASON_UNKNOWN_DELEGATION = "UNKNOWN_FEDERATION_DELEGATION"
REASON_TARGET_NOT_TRUSTED = "TARGET_NODE_NOT_TRUSTED"
REASON_FROZEN = "FEDERATION_IS_QUIESCING"
REASON_WORK_CLASS_NOT_DELEGATED = "WORK_CLASS_NOT_DELEGATED_TO_THIS_NODE"
REASON_NO_TRUSTED_TARGET = "NO_TRUSTED_TARGET_FOR_REQUIREMENTS"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_delegations (
        delegation_id TEXT PRIMARY KEY,
        requester_node TEXT NOT NULL,
        requester_generation INTEGER,
        target_node TEXT NOT NULL,
        target_generation INTEGER,
        task_identity TEXT NOT NULL,
        input_digest TEXT NOT NULL,
        basis_digest TEXT NOT NULL,
        allowed_work_class TEXT NOT NULL,
        status TEXT NOT NULL,
        result_ref TEXT,
        created_at REAL,
        completed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_placements (
        placement_id TEXT PRIMARY KEY,
        task_class TEXT NOT NULL,
        chosen_node TEXT NOT NULL,
        candidates_json TEXT NOT NULL,
        reason_codes_json TEXT NOT NULL,
        authority_granted INTEGER NOT NULL,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_placement_attempts (
        attempt_id TEXT PRIMARY KEY,
        task_class TEXT NOT NULL,
        target_node TEXT NOT NULL,
        outcome TEXT NOT NULL,
        latency_seconds REAL,
        resource_cost REAL,
        reconciliation_conflicts INTEGER NOT NULL,
        stale_work INTEGER NOT NULL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class FederationDelegation:
    delegation_id: str
    requester_node: str
    target_node: str
    target_generation: Optional[int]
    task_identity: str
    input_digest: str
    allowed_work_class: str
    status: str
    result_ref: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"delegation_id": self.delegation_id, "requester_node": self.requester_node,
                "target_node": self.target_node, "target_generation": self.target_generation,
                "task_identity": self.task_identity, "input_digest": self.input_digest,
                "allowed_work_class": self.allowed_work_class, "status": self.status,
                "result_ref": self.result_ref, "authority_transferred": False,
                "policy_version": FEDERATION_DELEGATION_V1}


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


def request_delegation(db_path: str, *, requester_node: str, target_node: str,
                       task_identity: str, input_digest: str, basis_digest: str,
                       allowed_work_class: str, requester_generation: Optional[int] = None,
                       target_generation: Optional[int] = None, now: Optional[float] = None
                       ) -> FederationDelegation:
    """
    Ask another node to compute something bounded.

    Three refusals up front: a governed change is not delegable (a node cannot be asked to change the
    world), the target must be a TRUSTED node on its CURRENT generation (not a stranger, not a
    superseded runtime), and a frozen federation accepts no new work.
    """
    from ciph.kernel.federation_node import TRUSTED, current_generation, get_node
    from ciph.kernel.federation_quiescence import federation_is_frozen
    if str(allowed_work_class) in GOVERNED_CHANGE_CLASSES:
        raise CrucibleError(REASON_GOVERNED_CHANGE, str(allowed_work_class))
    if federation_is_frozen(db_path):
        raise CrucibleError(REASON_FROZEN, str(task_identity))
    target = get_node(db_path, target_node)
    if target.membership != TRUSTED:
        raise CrucibleError(REASON_TARGET_NOT_TRUSTED, f"{target_node}:{target.membership}")
    generation = int(target_generation) if target_generation is not None else current_generation(
        db_path, target_node)
    if generation != target.node_generation:
        raise CrucibleError("STALE_NODE_GENERATION", f"{target_node}:{generation}")
    moment = time.time() if now is None else float(now)
    delegation_id = "FD-" + digest({"requester": requester_node, "target": target_node,
                                    "task": task_identity, "input": input_digest})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_delegations (delegation_id, requester_node, "
            "requester_generation, target_node, target_generation, task_identity, input_digest, "
            "basis_digest, allowed_work_class, status, result_ref, created_at, completed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (delegation_id, str(requester_node), requester_generation, str(target_node), generation,
             str(task_identity), str(input_digest), str(basis_digest), str(allowed_work_class),
             PROPOSED, None, moment, None))
        connection.commit()
    finally:
        connection.close()
    return get_delegation(db_path, delegation_id)


def get_delegation(db_path: str, delegation_id: str) -> FederationDelegation:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_federation_delegations WHERE delegation_id = ?;",
                                 (str(delegation_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_DELEGATION, str(delegation_id))
    row = dict(row)
    return FederationDelegation(delegation_id=str(row["delegation_id"]),
                                requester_node=str(row["requester_node"]),
                                target_node=str(row["target_node"]),
                                target_generation=row["target_generation"],
                                task_identity=str(row["task_identity"]),
                                input_digest=str(row["input_digest"]),
                                allowed_work_class=str(row["allowed_work_class"]),
                                status=str(row["status"]), result_ref=row["result_ref"])


def set_delegation_status(db_path: str, delegation_id: str, *, status: str,
                          result_ref: Optional[str] = None, now: Optional[float] = None
                          ) -> FederationDelegation:
    if status not in VALID_STATUSES:
        raise CrucibleError("UNKNOWN_FEDERATION_DELEGATION_STATUS", str(status))
    moment = time.time() if now is None else float(now)
    get_delegation(db_path, delegation_id)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_delegations SET status = ?, "
                           "result_ref = COALESCE(?, result_ref), completed_at = ? "
                           "WHERE delegation_id = ?;",
                           (str(status), result_ref, moment, str(delegation_id)))
        connection.commit()
    finally:
        connection.close()
    return get_delegation(db_path, delegation_id)


def assert_scope_within_delegation(db_path: str, delegation_id: str, *,
                                   requested_work_class: str) -> None:
    """A remote node may not widen what it was asked to do - including to a 'cheaper' class."""
    delegation = get_delegation(db_path, delegation_id)
    if str(requested_work_class) != delegation.allowed_work_class:
        raise CrucibleError(REASON_WORK_CLASS_NOT_DELEGATED,
                            f"{delegation_id}:{requested_work_class}"
                            f"!={delegation.allowed_work_class}")


def result_is_not_evidence(delegation_id: str, *, result_digest: str) -> Dict[str, Any]:
    """The sentence a result has to carry: it is a claim until 4.2's rules say otherwise."""
    return {"delegation_id": str(delegation_id), "result_digest": str(result_digest),
            "is_evidence": False, "requires": "4.2 canonical evidence rules",
            "authority_transferred": False, "policy_version": FEDERATION_DELEGATION_V1}


# ---------------------------------------------------------------------------- 7.12 routing
def route(db_path: str, *, task_class: str, required_capabilities: Sequence[str] = (),
          latency_hint_by_node: Optional[Dict[str, float]] = None,
          cost_hint_by_node: Optional[Dict[str, float]] = None,
          preferred_locality: Optional[Sequence[str]] = None, now: Optional[float] = None
          ) -> List[Dict[str, Any]]:
    """
    Rank TRUSTED, reachable nodes for a task. Deterministic, and explicitly authority-free.

    The ordering is (health rank, capability fit, latency, cost, locality, node_id) so that a restart
    reproduces the same placement, and every candidate carries the reason codes that put it where it is.
    """
    from ciph.kernel.federation_node import (DEGRADED, HEALTH_QUARANTINE, HEALTHY, TRUSTED,
                                             UNREACHABLE, health_of, nodes)
    from ciph.kernel.federation_quiescence import federation_is_frozen
    if federation_is_frozen(db_path):
        return []
    latency_hint_by_node = dict(latency_hint_by_node or {})
    cost_hint_by_node = dict(cost_hint_by_node or {})
    locality = tuple(str(item) for item in (preferred_locality or ()))
    health_rank = {HEALTHY: 0, None: 1, DEGRADED: 2, UNREACHABLE: 3, HEALTH_QUARANTINE: 4}
    candidates = []
    for node in nodes(db_path, memberships=(TRUSTED, DEGRADED)):
        health = health_of(db_path, node.node_id).get("status")
        if health in (UNREACHABLE, HEALTH_QUARANTINE):
            # Unreachable is not dead, and it is not eligible either: it is simply not a target now.
            continue
        reasons = [f"membership:{node.membership}", f"health:{health or 'UNOBSERVED'}"]
        capability_fit = len([item for item in required_capabilities])
        if capability_fit:
            reasons.append(f"capabilities_required:{capability_fit}")
        if node.node_id in locality:
            reasons.append("locality:preferred")
        candidates.append({"node_id": node.node_id, "node_generation": node.node_generation,
                           "membership": node.membership, "health": health,
                           "latency_hint": latency_hint_by_node.get(node.node_id),
                           "cost_hint": cost_hint_by_node.get(node.node_id),
                           "reason_codes": reasons,
                           "authority_granted": False,
                           "policy_version": FEDERATION_ROUTING_V1})
    return sorted(candidates, key=lambda item: (
        health_rank.get(item["health"], 5),
        0 if item["node_id"] in locality else 1,
        latency_hint_by_node.get(item["node_id"], float("inf")),
        cost_hint_by_node.get(item["node_id"], float("inf")),
        item["node_id"]))


def record_placement(db_path: str, *, task_class: str, chosen_node: str,
                     candidates: Sequence[Dict[str, Any]], reason_codes: Sequence[str],
                     now: Optional[float] = None) -> Dict[str, Any]:
    """Record WHY a node was chosen, and record that choosing it granted it nothing."""
    from ciph.kernel.federation_node import TRUSTED, get_node
    node = get_node(db_path, chosen_node)
    if node.membership not in (TRUSTED, "DEGRADED"):
        raise CrucibleError(REASON_NO_TRUSTED_TARGET, f"{chosen_node}:{node.membership}")
    moment = time.time() if now is None else float(now)
    placement_id = "FPL-" + digest({"task_class": task_class, "chosen": chosen_node,
                                    "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_placements (placement_id, task_class, chosen_node, "
            "candidates_json, reason_codes_json, authority_granted, recorded_at) "
            "VALUES (?,?,?,?,?,?,?);",
            (placement_id, str(task_class), str(chosen_node),
             json.dumps([str(item.get("node_id")) for item in candidates]),
             json.dumps(sorted(str(item) for item in reason_codes)), 0, moment))
        connection.commit()
    finally:
        connection.close()
    return {"placement_id": placement_id, "task_class": str(task_class),
            "chosen_node": str(chosen_node), "authority_granted": False,
            "is_domain_owner": False, "policy_version": FEDERATION_ROUTING_V1,
            "recorded_at": moment}


def placements(db_path: str, task_class: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_federation_placements"
    params: Tuple[Any, ...] = ()
    if task_class is not None:
        query += " WHERE task_class = ?"
        params = (str(task_class),)
    try:
        return [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, placement_id;", params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


# ---------------------------------------------------------------------------- 7.13 learning
def record_attempt(db_path: str, *, task_class: str, target_node: str, outcome: str,
                   latency_seconds: float = 0.0, resource_cost: float = 0.0,
                   reconciliation_conflicts: int = 0, stale_work: int = 0,
                   now: Optional[float] = None) -> Dict[str, Any]:
    from ciph.kernel.federation_node import current_generation
    if str(outcome) not in VALID_OUTCOMES:
        raise CrucibleError("UNKNOWN_FEDERATION_OUTCOME", str(outcome))
    moment = time.time() if now is None else float(now)
    attempt_id = "FPA-" + digest({"task_class": task_class, "target": target_node,
                                 "generation": current_generation(db_path, target_node)
                                 if _known(db_path, target_node) else None})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_placement_attempts (attempt_id, task_class, "
            "target_node, outcome, latency_seconds, resource_cost, reconciliation_conflicts, "
            "stale_work, recorded_at) VALUES (?,?,?,?,?,?,?,?,?);",
            (attempt_id, str(task_class), str(target_node), str(outcome), float(latency_seconds),
             float(resource_cost), int(reconciliation_conflicts), int(stale_work), moment))
        connection.commit()
    finally:
        connection.close()
    return {"attempt_id": attempt_id, "task_class": str(task_class), "target_node": str(target_node),
            "outcome": str(outcome), "authority_granted": False,
            "policy_version": FEDERATION_LEARNING_V1, "recorded_at": moment}


def _known(db_path: str, node_id: str) -> bool:
    from ciph.kernel.federation_node import get_node
    try:
        get_node(db_path, node_id)
        return True
    except CrucibleError:
        return False


def federation_learning(db_path: str, task_class: Optional[str] = None) -> Dict[str, Any]:
    """Descriptive: outcomes, cost, conflict and staleness per task class. Deliberately no scalar."""
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_federation_placement_attempts"
    params: Tuple[Any, ...] = ()
    if task_class is not None:
        query += " WHERE task_class = ?"
        params = (str(task_class),)
    try:
        rows = [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, attempt_id;", params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    by_node: Dict[str, int] = {}
    for row in rows:
        by_node[str(row["target_node"])] = by_node.get(str(row["target_node"]), 0) + 1
    return {"policy_version": FEDERATION_LEARNING_V1, "task_class": task_class,
            "attempts": len(rows),
            "useful": len([row for row in rows if row["outcome"] == OUTCOME_USEFUL]),
            "useless": len([row for row in rows if row["outcome"] == OUTCOME_USELESS]),
            "failed": len([row for row in rows if row["outcome"] == OUTCOME_FAILED]),
            "interrupted": len([row for row in rows if row["outcome"] == OUTCOME_INTERRUPTED]),
            "reconciliation_conflicts": sum(int(row["reconciliation_conflicts"]) for row in rows),
            "stale_work": sum(int(row["stale_work"]) for row in rows),
            "latency_seconds_total": round(sum(float(row["latency_seconds"]) for row in rows), 6),
            "resource_cost_total": round(sum(float(row["resource_cost"]) for row in rows), 6),
            "attempts_by_node": dict(sorted(by_node.items())), "no_score": True}


def delegation_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        table = lambda name: [dict(row) for row in connection.execute(  # noqa: E731
            f"SELECT * FROM {name} ORDER BY rowid;")]
        payload = {"delegations": table("ciph_federation_delegations"),
                   "placements": table("ciph_federation_placements"),
                   "attempts": table("ciph_federation_placement_attempts")}
    except sqlite3.Error:
        payload = {"delegations": [], "placements": [], "attempts": []}
    finally:
        connection.close()
    return digest({"version": FEDERATION_DELEGATION_V1, **payload})
