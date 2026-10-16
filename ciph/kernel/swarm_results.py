"""
ciph/kernel/swarm_results - 6.3 (result provenance) and 6.4 (aggregation).

    Worker output is a CLAIM until canonical evidence rules establish otherwise.
    Consensus can be information. Consensus is not evidence by itself.

Five agents agreeing is not five pieces of evidence. If four of them read the same wire story and the
fifth quotes the fourth, that is ONE source with a lot of confidence, and the 4.2 source-dependence
machinery already knows how to say so - so this module records source refs and counts the INDEPENDENT
ones rather than the loud ones.

Two kinds of disagreement are kept apart, because the remedies differ:

    DETERMINISTIC work that diverges is an INTEGRITY problem. Same input, same algorithm, different
    answer means something is broken - machine, code, or environment - and a majority vote is exactly
    the wrong response.

    REASONING work that diverges is DISAGREEMENT. It is information about difficulty, and the honest
    disposition is to preserve it rather than to let the larger camp win.

Nothing here returns "true".
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SWARM_RESULT_V1 = "SWARM_RESULT_V1"
SWARM_AGGREGATION_V1 = "SWARM_AGGREGATION_V1"

CURRENT = "CURRENT"
LATE = "LATE"
STALE_BASIS = "STALE_BASIS"
DUPLICATE = "DUPLICATE"
CONFLICTING = "CONFLICTING"
REJECTED = "REJECTED"
VALID_RESULT_STATUSES = (CURRENT, LATE, STALE_BASIS, DUPLICATE, CONFLICTING, REJECTED)
WITH_STANDING = (CURRENT,)

CONSISTENT = "CONSISTENT"
DISAGREEMENT = "DISAGREEMENT"
PARTIAL = "PARTIAL"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"
VALID_DISPOSITIONS = (CONSISTENT, DISAGREEMENT, PARTIAL, INSUFFICIENT_EVIDENCE, INTEGRITY_CONFLICT)

DECIDED_BY_REPRODUCIBILITY = "REPRODUCIBILITY"
DECIDED_BY_DISAGREEMENT = "DISAGREEMENT"
DECIDED_BY_EVIDENCE = "EVIDENCE"
DECIDED_BY_INTEGRITY = "INTEGRITY"
DECIDED_BY_ABSENCE = "ABSENCE"

REASON_UNKNOWN_RESULT = "UNKNOWN_SWARM_RESULT"
REASON_NOT_THE_LEASE_HOLDER = "RESULT_NOT_FROM_THE_LEASE_HOLDER"
REASON_UNKNOWN_INTEGRITY = "DETERMINISTIC_DIVERGENCE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_results (
        result_id TEXT PRIMARY KEY,
        delegation_id TEXT NOT NULL,
        worker_id TEXT NOT NULL,
        worker_generation INTEGER NOT NULL,
        input_digest TEXT NOT NULL,
        basis_digest TEXT NOT NULL,
        output_digest TEXT NOT NULL,
        evidence_refs_json TEXT,
        model_identity TEXT,
        source_dependency_refs_json TEXT,
        result_status TEXT NOT NULL,
        completed_at REAL,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_aggregations (
        aggregation_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        result_refs_json TEXT NOT NULL,
        method TEXT NOT NULL,
        disagreement_refs_json TEXT,
        evidence_basis_json TEXT,
        disposition TEXT NOT NULL,
        decided_by TEXT NOT NULL,
        deterministic INTEGER NOT NULL,
        independent_sources INTEGER NOT NULL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class WorkerResult:
    result_id: str
    delegation_id: str
    worker_id: str
    worker_generation: int
    input_digest: str
    basis_digest: str
    output_digest: str
    evidence_refs: Tuple[str, ...]
    model_identity: Optional[str]
    source_dependency_refs: Tuple[str, ...]
    result_status: str

    @property
    def has_standing(self) -> bool:
        return self.result_status in WITH_STANDING

    def as_dict(self) -> Dict[str, Any]:
        return {"result_id": self.result_id, "delegation_id": self.delegation_id,
                "worker_id": self.worker_id, "worker_generation": self.worker_generation,
                "input_digest": self.input_digest, "basis_digest": self.basis_digest,
                "output_digest": self.output_digest, "evidence_refs": list(self.evidence_refs),
                "model_identity": self.model_identity,
                "source_dependency_refs": list(self.source_dependency_refs),
                "result_status": self.result_status, "is_evidence": False,
                "policy_version": SWARM_RESULT_V1}


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


def _classify(db_path: str, *, delegation: Any, worker_id: str, worker_generation: int,
              basis_digest: str, output_digest: str) -> str:
    """
    What this arrival IS, decided by canonical facts and not by who sent it.

    Order matters: a result from a superseded generation is LATE whatever else it is, because a
    restarted worker's output belongs to the runtime that produced it.
    """
    from ciph.kernel.swarm_delegation import LEASE_ACTIVE, leases_for
    from ciph.kernel.swarm_worker import is_current_generation
    # A superseded runtime is LATE whatever else is true: generation 1's answer belongs to generation
    # 1, and generation 2 is a different worker wearing the same role name.
    if not is_current_generation(db_path, worker_id, worker_generation):
        return LATE
    mine = [lease for lease in leases_for(db_path, delegation.delegation_id)
            if lease.worker_id == str(worker_id)
            and lease.worker_generation == int(worker_generation)]
    if not mine:
        return REJECTED
    if mine[-1].status != LEASE_ACTIVE:
        # Possession was lost - expired, released or interrupted. The arrival is kept because it is
        # evidence that the work happened, and it carries no standing because somebody else owns the
        # question now. CONFLICTING is reserved for the worker who CURRENTLY holds it.
        return LATE
    if str(basis_digest) != delegation.basis_digest:
        return STALE_BASIS
    current = current_result(db_path, delegation.delegation_id)
    if current is not None:
        return DUPLICATE if current.output_digest == str(output_digest) else CONFLICTING
    return CURRENT


def submit_result(db_path: str, *, delegation_id: str, worker_id: str, worker_generation: int,
                  output_digest: str, basis_digest: str, evidence_refs: Sequence[str] = (),
                  model_identity: Optional[str] = None,
                  source_dependency_refs: Sequence[str] = (),
                  now: Optional[float] = None) -> WorkerResult:
    """
    Record one worker's arrival, CLASSIFIED.

    A late or stale arrival is kept, because deleting it would erase the fact that the work happened;
    it simply carries no standing, and the ledger says why.
    """
    from ciph.kernel.swarm_delegation import get_delegation
    moment = time.time() if now is None else float(now)
    delegation = get_delegation(db_path, delegation_id)
    status = _classify(db_path, delegation=delegation, worker_id=str(worker_id),
                       worker_generation=int(worker_generation), basis_digest=basis_digest,
                       output_digest=output_digest)
    refs = sorted(str(ref) for ref in evidence_refs)
    sources = sorted(str(ref) for ref in source_dependency_refs)
    result_id = "SR-" + digest({"delegation": delegation_id, "worker": str(worker_id),
                                "gen": int(worker_generation), "output": str(output_digest),
                                "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_swarm_results (result_id, delegation_id, worker_id, "
            "worker_generation, input_digest, basis_digest, output_digest, evidence_refs_json, "
            "model_identity, source_dependency_refs_json, result_status, completed_at, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (result_id, str(delegation_id), str(worker_id), int(worker_generation),
             delegation.input_digest, str(basis_digest), str(output_digest), json.dumps(refs),
             model_identity, json.dumps(sources), status, moment, moment))
        connection.commit()
    finally:
        connection.close()
    return get_result(db_path, result_id)


def get_result(db_path: str, result_id: str) -> WorkerResult:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_swarm_results WHERE result_id = ?;",
                                 (str(result_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_RESULT, str(result_id))
    row = dict(row)
    return WorkerResult(result_id=str(row["result_id"]), delegation_id=str(row["delegation_id"]),
                        worker_id=str(row["worker_id"]),
                        worker_generation=int(row["worker_generation"]),
                        input_digest=str(row["input_digest"]), basis_digest=str(row["basis_digest"]),
                        output_digest=str(row["output_digest"]),
                        evidence_refs=tuple(json.loads(row["evidence_refs_json"] or "[]")),
                        model_identity=row["model_identity"],
                        source_dependency_refs=tuple(json.loads(
                            row["source_dependency_refs_json"] or "[]")),
                        result_status=str(row["result_status"]))


def results_for(db_path: str, delegation_id: str) -> List[WorkerResult]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["result_id"]) for row in connection.execute(
            "SELECT result_id FROM ciph_swarm_results WHERE delegation_id = ? "
            "ORDER BY recorded_at, result_id;", (str(delegation_id),))]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_result(db_path, result_id) for result_id in ids]


def current_result(db_path: str, delegation_id: str) -> Optional[WorkerResult]:
    for result in results_for(db_path, delegation_id):
        if result.has_standing:
            return result
    return None


def result_claims_evidence() -> Dict[str, Any]:
    """A result is a claim. This function exists so that fact has somewhere to live."""
    return {"is_evidence": False, "requires": "4.2 canonical evidence rules",
            "policy_version": SWARM_RESULT_V1}


# ---------------------------------------------------------------------------- 6.4 aggregation
def independent_sources(results: Sequence[WorkerResult]) -> Tuple[str, ...]:
    """
    The DISTINCT external sources behind a set of results.

    Four workers citing one wire story contribute one source. The point of counting here rather than
    counting workers is that worker count is a fact about the swarm and source count is a fact about
    the world.
    """
    seen = set()
    for result in results:
        for ref in result.source_dependency_refs:
            seen.add(str(ref))
    return tuple(sorted(seen))


def aggregate(db_path: str, *, task_id: str, result_refs: Sequence[str], method: str,
              deterministic: bool, canonical_evidence_refs: Sequence[str] = (),
              now: Optional[float] = None) -> Dict[str, Any]:
    """
    Turn several arrivals into ONE disposition - never into a verdict about the world.

    Deterministic divergence is an integrity conflict. Non-deterministic divergence is disagreement.
    Agreement is reported as agreement, with `decided_by` naming what actually decided: evidence when
    canonical evidence exists, otherwise reproducibility, disagreement or absence. Consensus decides
    nothing on its own, and the record says so in a field a reader cannot miss.
    """
    moment = time.time() if now is None else float(now)
    results = [get_result(db_path, ref) for ref in result_refs]
    considered = [result for result in results if result.has_standing]
    outputs = {result.output_digest for result in considered}
    evidence = sorted(str(ref) for ref in canonical_evidence_refs)
    independent = independent_sources(considered)
    disagreement_refs: List[str] = []

    if deterministic:
        if len(outputs) > 1:
            disposition, decided_by = INTEGRITY_CONFLICT, DECIDED_BY_INTEGRITY
            disagreement_refs = sorted(result.result_id for result in considered)
        elif considered:
            disposition, decided_by = CONSISTENT, DECIDED_BY_REPRODUCIBILITY
        else:
            disposition, decided_by = INSUFFICIENT_EVIDENCE, DECIDED_BY_ABSENCE
    elif len(outputs) > 1:
        disposition, decided_by = DISAGREEMENT, DECIDED_BY_DISAGREEMENT
        disagreement_refs = sorted(result.result_id for result in considered)
    elif evidence and considered:
        disposition, decided_by = CONSISTENT, DECIDED_BY_EVIDENCE
    elif considered:
        disposition, decided_by = PARTIAL, DECIDED_BY_ABSENCE
    else:
        disposition, decided_by = INSUFFICIENT_EVIDENCE, DECIDED_BY_ABSENCE

    aggregation_id = "SA-" + digest({"task": str(task_id), "results": sorted(str(r) for r in
                                                                            result_refs),
                                     "method": str(method)})[:16].upper()
    record = {"aggregation_id": aggregation_id, "task_id": str(task_id),
              "result_refs": sorted(str(ref) for ref in result_refs), "method": str(method),
              "disposition": disposition, "decided_by": decided_by,
              "disagreement_refs": disagreement_refs,
              "evidence_basis": evidence, "independent_sources": list(independent),
              "deterministic": bool(deterministic), "consensus_is_evidence": False,
              "policy_version": SWARM_AGGREGATION_V1}
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_swarm_aggregations (aggregation_id, task_id, "
            "result_refs_json, method, disagreement_refs_json, evidence_basis_json, disposition, "
            "decided_by, deterministic, independent_sources, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (aggregation_id, str(task_id), json.dumps(record["result_refs"]), str(method),
             json.dumps(disagreement_refs), json.dumps(evidence), disposition, decided_by,
             1 if deterministic else 0, len(independent), moment))
        connection.commit()
    finally:
        connection.close()
    return record


def aggregations(db_path: str, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_swarm_aggregations"
    params: Tuple[Any, ...] = ()
    if task_id is not None:
        query += " WHERE task_id = ?"
        params = (str(task_id),)
    try:
        rows = [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, aggregation_id;", params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    for row in rows:
        row["result_refs"] = json.loads(row.pop("result_refs_json") or "[]")
        row["disagreement_refs"] = json.loads(row.pop("disagreement_refs_json") or "[]")
        row["evidence_basis"] = json.loads(row.pop("evidence_basis_json") or "[]")
        row["consensus_is_evidence"] = False
    return rows


def results_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        results = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_results ORDER BY recorded_at, result_id;")]
    except sqlite3.Error:
        results = []
    finally:
        connection.close()
    return digest({"version": SWARM_RESULT_V1, "results": results,
                   "aggregations": aggregations(db_path)})
