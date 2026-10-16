"""
ciph/kernel/evolution_adapters - R6 Gates B, C and F: the legacy lifecycle, placed under law.

The old machinery keeps working. What these adapters remove is its ability to answer constitutional
questions:

    Gate B  a legacy candidate enters through `register_candidate`; the CC-* identity is the ONLY
            identity, and legacy hashes become bound artifact fields
    Gate C  a legacy evaluation grant becomes a Crucible TrialRun; the legacy benchmark result can
            never say APPROVED, because no such result exists in the constitutional vocabulary
    Gate F  canary measurements feed the Crucible's regression verdict, and a rollback moves the
            canonical pointer BEFORE any mechanism restores bytes

Every function here delegates the decision and only performs the translation.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.crucible_candidates import (
    CrucibleCandidate,
    candidate_history,
    get_candidate,
    register_candidate,
    verify_candidate_identity,
)
from ciph.kernel.crucible_metrics import PerformanceVector
from ciph.kernel.crucible_monitoring import PostPromotionAssessment, assess_post_promotion
from ciph.kernel.crucible_promotion import RollbackRecord, rollback
from ciph.kernel.crucible_protocols import assert_protocol_integrity
from ciph.kernel.crucible_trials import (
    ROLE_BASELINE,
    ROLE_CANDIDATE,
    TrialRun,
    complete_trial,
    start_trial,
)
from ciph.kernel.crucible_types import CrucibleError, VALID_KINDS, digest

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_legacy_bindings (
        candidate_id TEXT NOT NULL,
        candidate_hash TEXT NOT NULL,
        base_file_hash TEXT NOT NULL,
        source TEXT,
        class_name TEXT,
        artifact_path TEXT,
        legacy_grant_ref TEXT,
        bound_at REAL,
        PRIMARY KEY (candidate_id, candidate_hash, base_file_hash)
    );
    """,
)


@dataclass(frozen=True)
class LegacyBinding:
    candidate_id: str
    candidate_hash: str
    base_file_hash: str
    source: Optional[str]
    class_name: Optional[str]
    artifact_path: Optional[str]
    legacy_grant_ref: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"candidate_id": self.candidate_id, "candidate_hash": self.candidate_hash,
                "base_file_hash": self.base_file_hash, "source": self.source,
                "class_name": self.class_name, "artifact_path": self.artifact_path,
                "legacy_grant_ref": self.legacy_grant_ref}


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


# ---------------------------------------------------------------------------- Gate B
def adopt_legacy_candidate(db_path: str, *, candidate_hash: str, base_file_hash: str,
                           source: Optional[str] = None, class_name: Optional[str] = None,
                           artifact_path: Optional[str] = None,
                           kind: str = "CAPABILITY_IMPLEMENTATION",
                           manifest_identity: Optional[str] = None,
                           legacy_grant_ref: Optional[str] = None,
                           created_by: Optional[str] = None,
                           now: Optional[float] = None) -> CrucibleCandidate:
    """
    Bring ONE legacy candidate under the constitutional identity owner (Gate B).

    The legacy `candidate_hash` becomes the artifact digest and the `base_file_hash` plus provenance
    become the configuration digest, so the exact thing that will be evaluated keeps one identity.
    Every later stage carries `candidate_id`; nothing re-identifies it.
    """
    if kind not in VALID_KINDS:
        raise CrucibleError("INVALID_CANDIDATE_KIND", str(kind))
    if not candidate_hash or not base_file_hash:
        raise CrucibleError("LEGACY_CANDIDATE_REQUIRES_HASHES",
                            f"{candidate_hash!r}/{base_file_hash!r}")
    moment = time.time() if now is None else float(now)
    configuration_digest = digest({"base_file_hash": base_file_hash, "source": source,
                                   "class_name": class_name, "artifact_path": artifact_path})
    candidate = register_candidate(
        db_path, kind=kind, artifact_digest=str(candidate_hash),
        configuration_digest=configuration_digest, manifest_identity=manifest_identity,
        declared_objective=f"legacy:{class_name or source or 'candidate'}",
        created_by=created_by, now=moment)

    existing = legacy_binding_for(db_path, candidate_hash=str(candidate_hash),
                                  base_file_hash=str(base_file_hash))
    if existing is not None and existing.candidate_id != candidate.candidate_id:
        raise CrucibleError("LEGACY_BINDING_ALREADY_ADOPTED",
                            f"{candidate_hash[:12]} is already {existing.candidate_id}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_crucible_legacy_bindings (candidate_id, candidate_hash, "
            "base_file_hash, source, class_name, artifact_path, legacy_grant_ref, bound_at) "
            "VALUES (?,?,?,?,?,?,?,?);",
            (candidate.candidate_id, str(candidate_hash), str(base_file_hash), source, class_name,
             artifact_path, legacy_grant_ref, moment))
        connection.commit()
    finally:
        connection.close()
    return candidate


def legacy_binding_for(db_path: str, *, candidate_hash: str,
                       base_file_hash: str) -> Optional[LegacyBinding]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute(
            "SELECT * FROM ciph_crucible_legacy_bindings WHERE candidate_hash = ? AND "
            "base_file_hash = ?;", (str(candidate_hash), str(base_file_hash))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        return None
    row = dict(row)
    return LegacyBinding(candidate_id=str(row["candidate_id"]),
                         candidate_hash=str(row["candidate_hash"]),
                         base_file_hash=str(row["base_file_hash"]), source=row["source"],
                         class_name=row["class_name"], artifact_path=row["artifact_path"],
                         legacy_grant_ref=row["legacy_grant_ref"])


def legacy_bindings(db_path: str) -> List[LegacyBinding]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in connection.execute(
            "SELECT * FROM ciph_crucible_legacy_bindings ORDER BY candidate_id, candidate_hash;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [LegacyBinding(**{key: row[key] for key in
                             ("candidate_id", "candidate_hash", "base_file_hash", "source",
                              "class_name", "artifact_path", "legacy_grant_ref")}) for row in rows]


# ---------------------------------------------------------------------------- Gate C
def bind_legacy_evaluation(db_path: str, *, candidate_id: str, protocol_id: str, role: str,
                           grant_ref: str, class_name: Optional[str] = None,
                           measurement_refs: Sequence[str] = (), seed: Optional[str] = None,
                           environment_identity: Optional[str] = None,
                           dataset_digest: Optional[str] = None,
                           now: Optional[float] = None) -> TrialRun:
    """
    Turn a legacy evaluation attempt into a Crucible trial (Gate C).

    The legacy grant is carried as a reference, not as a verdict. There is deliberately no function
    that converts a legacy benchmark report into a comparison status: that judgement belongs to
    `crucible_metrics`, and only the protocol-frozen evidence reaches it.
    """
    if role not in (ROLE_BASELINE, ROLE_CANDIDATE):
        raise CrucibleError("INVALID_TRIAL_ROLE", str(role))
    assert_protocol_integrity(db_path, protocol_id)
    get_candidate(db_path, candidate_id)          # identity must exist before evaluation
    return start_trial(db_path, protocol_id=protocol_id, subject_id=candidate_id, role=role,
                       environment_identity=environment_identity, dataset_digest=dataset_digest,
                       seed=seed or grant_ref, now=now)


def record_legacy_measurement(db_path: str, *, trial_id: str, observations: Mapping[str, Any],
                              class_name: Optional[str] = None,
                              now: Optional[float] = None) -> TrialRun:
    """Close a trial with measurements. The numbers are the mechanism's; the verdict is not."""
    return complete_trial(db_path, trial_id, observations=observations, now=now)


# ---------------------------------------------------------------------------- Gate F
def record_canary_measurement(db_path: str, *, promotion_id: str, candidate_id: str,
                              protocol_id: str, expected: PerformanceVector,
                              observed: PerformanceVector,
                              now: Optional[float] = None) -> PostPromotionAssessment:
    """Feed canary measurements to the constitutional regression verdict (Gate F)."""
    return assess_post_promotion(db_path, promotion_id=promotion_id, candidate_id=candidate_id,
                                 protocol_id=protocol_id, expected=expected, observed=observed,
                                 now=now)


def governed_rollback(db_path: str, *, role: str, promotion_id: str, assessment_id: str,
                      reason_codes: Sequence[str], restore: Any = None,
                      now: Optional[float] = None) -> RollbackRecord:
    """
    Roll back the CANONICAL decision first, then (optionally) let a mechanism restore bytes.

    The order is the law: `canary_manager.rollback_production` and its peers are mechanisms, and a
    mechanism that changed the active candidate by itself would be a second owner of promotion state.
    """
    record = rollback(db_path, role=role, evidence_refs=[assessment_id], reason_codes=reason_codes,
                      now=now)
    if restore is not None:
        restore(candidate_id=record.restored_candidate_id, promotion_id=promotion_id)
    return record


def adapter_digest(db_path: str) -> str:
    return digest({"bindings": [binding.as_dict() for binding in legacy_bindings(db_path)]})
