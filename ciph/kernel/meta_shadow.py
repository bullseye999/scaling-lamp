"""
ciph/kernel/meta_shadow - 4.7 Gate Three: the durable shadow lifecycle.

The identity is ALWAYS a 4.5 `CC-*` candidate. There is no second meta namespace, and a shadow record
never becomes an authority by existing: registering G2 does not make G2 the generator, and a restart
must never infer it.

    REGISTERED -> EVALUATING -> EVALUATED (ELIGIBLE) | INVALID

ELIGIBLE requires an independent meta verdict of DOMINATES with zero constitutional misses. Anything
else stays evidence, not standing.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_candidates import get_candidate
from ciph.kernel.crucible_metrics import STATUS_DOMINATES
from ciph.kernel.crucible_types import CrucibleError, digest
from ciph.kernel.meta_hypotheses import get_meta_hypothesis

META_SHADOW_V1 = "META_SHADOW_V1"

STATUS_REGISTERED = "REGISTERED"
STATUS_EVALUATING = "EVALUATING"
STATUS_EVALUATED = "EVALUATED"
STATUS_INVALID = "INVALID"
STATUS_ELIGIBLE = "ELIGIBLE"
VALID_SHADOW_STATUSES = (STATUS_REGISTERED, STATUS_EVALUATING, STATUS_EVALUATED, STATUS_INVALID,
                         STATUS_ELIGIBLE)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_shadow_records (
        shadow_id TEXT PRIMARY KEY,
        hypothesis_id TEXT NOT NULL,
        crucible_candidate_id TEXT NOT NULL,
        target_component TEXT NOT NULL,
        target_ring TEXT NOT NULL,
        authoritative_baseline TEXT NOT NULL,
        protocol_id TEXT,
        corpus_version TEXT,
        status TEXT NOT NULL,
        meta_result_ref TEXT,
        meta_status TEXT,
        constitutional_misses INTEGER,
        registered_at REAL,
        updated_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetaShadowRecord:
    shadow_id: str
    hypothesis_id: str
    crucible_candidate_id: str
    target_component: str
    target_ring: str
    authoritative_baseline: str
    protocol_id: Optional[str]
    corpus_version: Optional[str]
    status: str
    meta_result_ref: Optional[str]
    meta_status: Optional[str]
    constitutional_misses: Optional[int]

    def as_dict(self) -> Dict[str, Any]:
        return {"shadow_id": self.shadow_id, "hypothesis_id": self.hypothesis_id,
                "crucible_candidate_id": self.crucible_candidate_id,
                "target_component": self.target_component, "target_ring": self.target_ring,
                "authoritative_baseline": self.authoritative_baseline,
                "protocol_id": self.protocol_id, "corpus_version": self.corpus_version,
                "status": self.status, "meta_result_ref": self.meta_result_ref,
                "meta_status": self.meta_status,
                "constitutional_misses": self.constitutional_misses}

    @property
    def eligible(self) -> bool:
        return self.status == STATUS_ELIGIBLE


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


def register_shadow(db_path: str, *, hypothesis_id: str, crucible_candidate_id: str,
                    target_component: str, target_ring: str, authoritative_baseline: str,
                    protocol_id: Optional[str] = None, corpus_version: Optional[str] = None,
                    now: Optional[float] = None) -> MetaShadowRecord:
    """
    Register a shadow candidate (law 1). 4.5 owns the identity: a `CC-*` that does not exist in the
    Crucible registry is refused here rather than invented.
    """
    hypothesis = get_meta_hypothesis(db_path, hypothesis_id)
    get_candidate(db_path, crucible_candidate_id)
    if str(authoritative_baseline) != hypothesis.baseline_component_identity:
        raise CrucibleError("SHADOW_BASELINE_MISMATCH",
                            f"{authoritative_baseline} != {hypothesis.baseline_component_identity}")
    moment = time.time() if now is None else float(now)
    shadow_id = "MSH-" + digest({"hypothesis": hypothesis_id,
                                 "candidate": crucible_candidate_id,
                                 "target": target_component})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_shadow_records (shadow_id, hypothesis_id, "
            "crucible_candidate_id, target_component, target_ring, authoritative_baseline, "
            "protocol_id, corpus_version, status, meta_result_ref, meta_status, "
            "constitutional_misses, registered_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (shadow_id, hypothesis_id, crucible_candidate_id, target_component, target_ring,
             str(authoritative_baseline), protocol_id, corpus_version, STATUS_REGISTERED, None, None,
             None, moment, moment))
        connection.commit()
    finally:
        connection.close()
    return get_shadow(db_path, shadow_id)


def _update(db_path: str, shadow_id: str, *, status: str, protocol_id: Optional[str] = None,
            corpus_version: Optional[str] = None, meta_result_ref: Optional[str] = None,
            meta_status: Optional[str] = None, misses: Optional[int] = None,
            now: Optional[float] = None) -> MetaShadowRecord:
    moment = time.time() if now is None else float(now)
    record = get_shadow(db_path, shadow_id)
    if record.status in (STATUS_ELIGIBLE, STATUS_INVALID):
        raise CrucibleError("SHADOW_ALREADY_CLOSED", f"{shadow_id}:{record.status}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "UPDATE ciph_meta_shadow_records SET status = ?, protocol_id = COALESCE(?, protocol_id), "
            "corpus_version = COALESCE(?, corpus_version), meta_result_ref = COALESCE(?, "
            "meta_result_ref), meta_status = COALESCE(?, meta_status), "
            "constitutional_misses = COALESCE(?, constitutional_misses), updated_at = ? "
            "WHERE shadow_id = ?;",
            (status, protocol_id, corpus_version, meta_result_ref, meta_status, misses, moment,
             shadow_id))
        connection.commit()
    finally:
        connection.close()
    return get_shadow(db_path, shadow_id)


def begin_shadow_evaluation(db_path: str, shadow_id: str, *, protocol_id: str, corpus_version: str,
                            now: Optional[float] = None) -> MetaShadowRecord:
    return _update(db_path, shadow_id, status=STATUS_EVALUATING, protocol_id=protocol_id,
                   corpus_version=corpus_version, now=now)


def complete_shadow_evaluation(db_path: str, shadow_id: str, *, meta_result_ref: str,
                               meta_status: str, constitutional_misses: int,
                               now: Optional[float] = None) -> MetaShadowRecord:
    """
    Close the shadow evaluation (law 2, 3).

    ELIGIBLE is reserved for an independent DOMINATES with no constitutional miss. A candidate that
    missed a hard invariant is INVALID however well it scored elsewhere - the meta path has no power to
    make that tradeable.
    """
    if int(constitutional_misses) > 0:
        status = STATUS_INVALID
    elif meta_status == STATUS_DOMINATES:
        status = STATUS_ELIGIBLE
    else:
        status = STATUS_EVALUATED
    return _update(db_path, shadow_id, status=status, meta_result_ref=meta_result_ref,
                   meta_status=str(meta_status), misses=int(constitutional_misses), now=now)


def invalidate_shadow(db_path: str, shadow_id: str, *, reason: str,
                      now: Optional[float] = None) -> MetaShadowRecord:
    return _update(db_path, shadow_id, status=STATUS_INVALID, meta_status=str(reason), now=now)


def get_shadow(db_path: str, shadow_id: str) -> MetaShadowRecord:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_shadow_records WHERE shadow_id = ?;",
                                 (shadow_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_SHADOW", shadow_id)
    return _row_to_shadow(dict(row))


def _row_to_shadow(row: Dict[str, Any]) -> MetaShadowRecord:
    return MetaShadowRecord(
        shadow_id=str(row["shadow_id"]), hypothesis_id=str(row["hypothesis_id"]),
        crucible_candidate_id=str(row["crucible_candidate_id"]),
        target_component=str(row["target_component"]), target_ring=str(row["target_ring"]),
        authoritative_baseline=str(row["authoritative_baseline"]), protocol_id=row["protocol_id"],
        corpus_version=row["corpus_version"], status=str(row["status"]),
        meta_result_ref=row["meta_result_ref"], meta_status=row["meta_status"],
        constitutional_misses=row["constitutional_misses"])


def shadow_records(db_path: str, *, hypothesis_id: Optional[str] = None,
                   target_component: Optional[str] = None) -> List[MetaShadowRecord]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT shadow_id FROM ciph_meta_shadow_records"
    clauses, params = [], []
    if hypothesis_id is not None:
        clauses.append("hypothesis_id = ?")
        params.append(hypothesis_id)
    if target_component is not None:
        clauses.append("target_component = ?")
        params.append(target_component)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    try:
        ids = [str(row["shadow_id"]) for row in connection.execute(
            query + " ORDER BY registered_at, shadow_id;", tuple(params))]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_shadow(db_path, shadow_id) for shadow_id in ids]


def shadow_digest(db_path: str) -> str:
    return digest({"version": META_SHADOW_V1,
                   "shadows": [item.as_dict() for item in shadow_records(db_path)]})
