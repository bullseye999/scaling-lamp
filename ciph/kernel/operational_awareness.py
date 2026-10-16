"""
ciph/kernel/operational_awareness - 10.5: one READ-ONLY operational relationship projection.

    Ciph should be able to see what its limbs are doing without inventing a second version of the truth.

WHAT THIS OWNS: a projection. It reads the actual owners - 10.3 observations, 10.4 architectural views,
10.0 durable findings, 4.2 evidence, 4.3 self-model, 4.4 curiosity, 5.x sessions, 6.x worker/delegation/
result state and 7.x federation identity/authority - and relates them. The ONE thing it writes is a
RELATIONSHIP edge (`ciph_operational_links`), because "this worker result is relevant to that investigation"
is a relationship that must survive a restart and belongs to no single owner.

WHAT IT REFUSES TO DO:

    A worker report is an OBSERVATION until its evidence is established. The projection reports the 6.x
    classification verbatim; it never promotes a result into a fact.

    A disconnected node is NOT continuously active because it once sent heartbeats. Its state comes from the
    LAST WITNESSED ACTIVITY, and past the freshness window it is STALE, never CURRENT.

    An observed worker completion must RESOLVE to its canonical result record, or the correlation is refused.

    A correlation mints no authority, creates no finding and grants no scope.
"""

import json
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

OPERATIONAL_AWARENESS_V1 = "OPERATIONAL_AWARENESS_V1"
OPERATIONAL_LINK_V1 = "OPERATIONAL_LINK_V1"

CURRENT = "CURRENT"
STALE = "STALE"
UNKNOWN = "UNKNOWN"

LINK_RESULT_INVESTIGATION = "RESULT_INVESTIGATION"
LINK_FINDING_EVIDENCE = "FINDING_EVIDENCE"
LINK_WORKER_DEPENDENCY = "WORKER_DEPENDENCY"
LINK_KINDS = (LINK_RESULT_INVESTIGATION, LINK_FINDING_EVIDENCE, LINK_WORKER_DEPENDENCY)

DEFAULT_FRESHNESS_TTL = 300.0

REASON_UNKNOWN_LINK_KIND = "UNKNOWN_LINK_KIND"
REASON_RESULT_DOES_NOT_RESOLVE = "WORKER_RESULT_DOES_NOT_RESOLVE"
REASON_RESULT_SET_DOES_NOT_RESOLVE = "RESULT_SET_DOES_NOT_RESOLVE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_operational_links (
        link_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        subject_ref TEXT NOT NULL,
        object_ref TEXT NOT NULL,
        evidence_ref TEXT,
        note TEXT,
        recorded_at REAL,
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


# ------------------------------------------------------------------ the one relationship store
def correlate(db_path: str, *, kind: str, subject_ref: str, object_ref: str,
              evidence_ref: Optional[str] = None, note: Optional[str] = None,
              now: Optional[float] = None) -> Dict[str, Any]:
    """
    Preserve a relationship between two canonical refs. Append-only and idempotent.

    The refs are VALIDATED against their owners where the owner can confirm them, so an "observed completion"
    cannot be correlated unless it resolves to a real canonical record.
    """
    if kind not in LINK_KINDS:
        raise CrucibleError(REASON_UNKNOWN_LINK_KIND, str(kind))
    subject, obj = str(subject_ref), str(object_ref)
    if kind == LINK_RESULT_INVESTIGATION:
        _require_worker_result(db_path, subject)
        _require_result_set(db_path, obj)
    moment = _moment(now)
    link_id = "OPL-" + digest({"kind": kind, "subject": subject, "object": obj})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_operational_links (link_id, kind, subject_ref, object_ref, "
            "evidence_ref, note, recorded_at, policy_version) VALUES (?,?,?,?,?,?,?,?);",
            (link_id, kind, subject, obj, evidence_ref, note, moment, OPERATIONAL_LINK_V1))
        connection.commit()
    finally:
        connection.close()
    return {"link_id": link_id, "kind": kind, "subject_ref": subject, "object_ref": obj,
            "evidence_ref": evidence_ref, "note": note, "mints_authority": False,
            "creates_a_finding": False, "policy_version": OPERATIONAL_LINK_V1}


def _require_worker_result(db_path: str, result_id: str) -> Any:
    from ciph.kernel.swarm_results import get_result
    try:
        return get_result(db_path, result_id)
    except CrucibleError:
        raise CrucibleError(REASON_RESULT_DOES_NOT_RESOLVE, result_id)


def _require_result_set(db_path: str, result_set_id: str) -> Any:
    from ciph.kernel.referential_continuity import result_sets
    for record in result_sets(db_path):
        if record["result_set_id"] == result_set_id:
            return record
    raise CrucibleError(REASON_RESULT_SET_DOES_NOT_RESOLVE, result_set_id)


def links(db_path: str, *, kind: Optional[str] = None, subject_ref: Optional[str] = None,
          object_ref: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_operational_links"
    clauses, params = [], []
    if kind is not None:
        clauses.append("kind = ?")
        params.append(str(kind))
    if subject_ref is not None:
        clauses.append("subject_ref = ?")
        params.append(str(subject_ref))
    if object_ref is not None:
        clauses.append("object_ref = ?")
        params.append(str(object_ref))
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY recorded_at, link_id;"
    return _rows(db_path, query, tuple(params))


# ------------------------------------------------------------------ last witnessed activity
def _last_witnessed(db_path: str, ref: str) -> Optional[float]:
    rows = _rows(db_path, "SELECT MAX(observed_at) AS latest FROM ciph_sensor_events "
                          "WHERE evidence_ref = ?;", (str(ref),))
    return None if not rows or rows[0]["latest"] is None else float(rows[0]["latest"])


def subject_state(db_path: str, *, ref: str, owner_ref: Optional[str] = None,
                  freshness_ttl: float = DEFAULT_FRESHNESS_TTL,
                  now: Optional[float] = None) -> Dict[str, Any]:
    """
    The state of an operational subject from its LAST WITNESSED activity.

    Historical heartbeats cannot keep a disconnected subject CURRENT: only a fresh witness can. A subject
    with no witness at all is UNKNOWN, and STALE is not a claim that the subject failed.
    """
    moment = _moment(now)
    witnessed = _last_witnessed(db_path, ref)
    if witnessed is None and owner_ref is not None:
        witnessed = _owner_timestamp(db_path, owner_ref)
    if witnessed is None:
        state = UNKNOWN
    elif moment - witnessed > float(freshness_ttl):
        state = STALE
    else:
        state = CURRENT
    return {"ref": str(ref), "state": state, "last_witnessed_at": witnessed,
            "age_seconds": None if witnessed is None else moment - witnessed,
            "freshness_ttl": float(freshness_ttl), "is_a_verdict_about_the_subject": False,
            "policy_version": OPERATIONAL_AWARENESS_V1}


def _owner_timestamp(db_path: str, owner_ref: str) -> Optional[float]:
    kind, _, identifier = str(owner_ref).partition(":")
    if kind == "worker":
        rows = _rows(db_path, "SELECT MAX(attested_at) AS latest FROM ciph_swarm_workers "
                              "WHERE worker_id = ?;", (identifier,))
    elif kind == "node":
        rows = _rows(db_path, "SELECT MAX(attested_at) AS latest FROM ciph_federation_nodes "
                              "WHERE node_id = ?;", (identifier,))
    else:
        return None
    return None if not rows or rows[0]["latest"] is None else float(rows[0]["latest"])


# ------------------------------------------------------------------ contradictions
def contradictions(db_path: str, *, now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Every place the evidence does not agree, reported as UNRESOLVED rather than resolved by preference."""
    found: List[Dict[str, Any]] = []

    # (a) sensor equivocation - the same sequence slot carried two different payloads
    for conflict in _rows(db_path, "SELECT * FROM ciph_sensor_conflicts ORDER BY recorded_at;"):
        found.append({"kind": "SENSOR_EQUIVOCATION", "subject_ref": conflict["sensor_id"],
                      "detail": {"sequence": conflict["sequence"],
                                 "first": conflict["first_payload_digest"],
                                 "conflicting": conflict["conflicting_payload_digest"]},
                      "disposition": "UNRESOLVED"})

    # (b) an architectural integrity claim that independent witnesses disagree about
    try:
        from ciph.kernel.architectural_proprioception import (DISPUTED, SOURCE, components,
                                                              integrity_claim)
        for record in components(db_path):
            claim = integrity_claim(db_path, component_id=record["component_id"], view=SOURCE, now=now)
            if claim["status"] == DISPUTED:
                found.append({"kind": "ARCHITECTURAL_DISPUTE", "subject_ref": record["component_id"],
                              "detail": claim, "disposition": "UNRESOLVED"})
    except Exception:  # pragma: no cover - a missing owner is not a contradiction
        pass

    # (c) retained worker arrivals for one delegation that do not agree. The owner has already CLASSIFIED
    # them (CONFLICTING / DUPLICATE / LATE); the projection surfaces the disagreement rather than hiding it
    # behind whichever arrival happened to arrive first.
    try:
        from ciph.kernel.swarm_delegation import delegations
        from ciph.kernel.swarm_results import results_for
        for delegation in delegations(db_path):
            results = results_for(db_path, delegation.delegation_id)
            digests = {result.output_digest for result in results}
            if len(digests) > 1:
                found.append({"kind": "WORKER_DISAGREEMENT",
                              "subject_ref": delegation.delegation_id,
                              "detail": {"output_digests": sorted(digests),
                                         "results": [{"result_id": result.result_id,
                                                      "worker_id": result.worker_id,
                                                      "result_status": result.result_status}
                                                     for result in results]},
                              "disposition": "UNRESOLVED"})
    except Exception:  # pragma: no cover
        pass
    return found


# ------------------------------------------------------------------ the projection
def build_projection(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """One coherent, read-only operational view. Every entry carries the ref of the owner it came from."""
    moment = _moment(now)
    projection: Dict[str, Any] = {"policy_version": OPERATIONAL_AWARENESS_V1, "built_at": moment,
                                  "read_only": True, "mints_authority": False}

    # investigations and their durable findings (10.0)
    try:
        from ciph.kernel.referential_continuity import result_sets
        projection["investigations"] = [
            {"result_set_id": record["result_set_id"], "investigation_ref": record["investigation_ref"],
             "revision": record["current_revision"], "owner": "referential_continuity",
             "correlated_links": [link["link_id"] for link in
                                  links(db_path, object_ref=record["result_set_id"])]}
            for record in result_sets(db_path)]
    except Exception:  # pragma: no cover
        projection["investigations"] = []

    # tasks, delegations and produced results (6.x)
    try:
        from ciph.kernel.swarm_delegation import delegations
        from ciph.kernel.swarm_results import results_for
        projection["tasks"] = [
            {"delegation_id": delegation.delegation_id, "task_identity": delegation.task_identity,
             "status": delegation.status, "allowed_work_class": delegation.allowed_work_class,
             "worker_results": [{"result_id": result.result_id, "worker_id": result.worker_id,
                                 "worker_generation": result.worker_generation,
                                 "output_digest": result.output_digest,
                                 "standing": result.has_standing,
                                 "is_evidence": False} for result
                                in results_for(db_path, delegation.delegation_id)]}
            for delegation in delegations(db_path)]
    except Exception:  # pragma: no cover
        projection["tasks"] = []

    # architectural dependencies (10.4)
    try:
        from ciph.kernel.architectural_proprioception import changes, components
        projection["architectural_dependencies"] = [
            {"component_id": record["component_id"], "dependencies": record["dependencies"],
             "owner": "architectural_proprioception"} for record in components(db_path)]
        projection["architectural_changes"] = [
            {"change_id": change["change_id"], "component_id": change["component_id"],
             "provenance": change["provenance"], "view": change["view"]} for change in changes(db_path)]
    except Exception:  # pragma: no cover
        projection["architectural_dependencies"] = []

    # generations (6.x/7.x) and their last witnessed activity
    try:
        from ciph.kernel.swarm_worker import (BUSY, DEAD, DRAINED, JOINING, QUARANTINED, QUIESCING,
                                              READY, members)
        all_statuses = (JOINING, READY, BUSY, QUIESCING, DRAINED, QUARANTINED, DEAD)
        projection["worker_generations"] = [
            {"worker_id": worker.worker_id, "generation": worker.instance_generation,
             "status": worker.status,
             "state": subject_state(db_path, ref=f"worker:{worker.worker_id}:{worker.instance_generation}",
                                    owner_ref=f"worker:{worker.worker_id}", now=moment)}
            for worker in members(db_path, statuses=all_statuses)]
    except Exception:  # pragma: no cover
        projection["worker_generations"] = []
    try:
        from ciph.kernel.federation_node import nodes
        projection["node_generations"] = [
            {"node_id": node.node_id, "generation": node.node_generation, "membership": node.membership,
             "state": subject_state(db_path, ref=f"node:{node.node_id}:{node.node_generation}",
                                    owner_ref=f"node:{node.node_id}", now=moment)}
            for node in nodes(db_path)]
    except Exception:  # pragma: no cover
        projection["node_generations"] = []

    # authorized work scopes (7.x authority domains) and autonomy session state (5.x)
    try:
        from ciph.kernel.federation_authority import domains
        projection["authorized_scopes"] = [
            {"domain_id": domain.domain_id, "scope": domain.scope, "owner_node_id": domain.owner_node_id,
             "status": domain.status, "owner": "federation_authority"} for domain in domains(db_path)]
    except Exception:  # pragma: no cover
        projection["authorized_scopes"] = []
    try:
        from ciph.kernel.autonomy_session import autonomy_state
        projection["autonomy"] = autonomy_state(db_path, now=moment)
    except Exception:  # pragma: no cover
        projection["autonomy"] = {}

    projection["links"] = links(db_path)
    projection["contradictions"] = contradictions(db_path, now=moment)
    return projection


def _durable_summary(db_path: str) -> Dict[str, Any]:
    """Only durable rows. No wall-clock field may enter the digest, or two processes would disagree."""
    return {
        "links": links(db_path),
        "investigations": _rows(db_path, "SELECT result_set_id, investigation_ref, current_revision "
                                         "FROM ciph_result_sets ORDER BY result_set_id;"),
        "delegations": _rows(db_path, "SELECT delegation_id, task_identity, task_generation, status "
                                      "FROM ciph_swarm_delegations ORDER BY delegation_id;"),
        "results": _rows(db_path, "SELECT result_id, delegation_id, worker_id, worker_generation, "
                                  "output_digest, result_status FROM ciph_swarm_results "
                                  "ORDER BY result_id;"),
        "components": _rows(db_path, "SELECT component_id, kind, dependencies_json FROM ciph_arch_components "
                                     "ORDER BY component_id;"),
        "changes": _rows(db_path, "SELECT change_id, component_id, provenance FROM ciph_arch_changes "
                                  "ORDER BY change_id;"),
        "workers": _rows(db_path, "SELECT worker_id, instance_generation, status FROM ciph_swarm_workers "
                                  "ORDER BY worker_id, instance_generation;"),
        "nodes": _rows(db_path, "SELECT node_id, node_generation, membership FROM ciph_federation_nodes "
                                "ORDER BY node_id, node_generation;"),
    }


def awareness_digest(db_path: str) -> str:
    return digest(_durable_summary(db_path))
