"""
ciph/kernel/crucible_candidates - 4.5 Gate Zero: what exactly is being evaluated?

A candidate is an immutable identity: the EXACT artifact and configuration that will be measured. Its
identity is derived from that payload by a frozen function, so editing the bytes or the configuration
does not "update" a candidate - it creates a different one.

LAWS
 1. Candidate identity is immutable.
 2. Editing candidate bytes or configuration creates a NEW candidate.
 3. Identity includes the exact artifact and configuration actually evaluated.
 4. Parent lineage is historical, not authority.
 5. Declarations have ZERO evaluation weight (nothing in the Crucible reads them as evidence).
 6. A candidate cannot promote itself.
 7. A candidate cannot modify its own evaluation history.
 8. "Newest" does not mean "better".
 9. Installed does not mean eligible.
10. Same artifact/configuration -> same candidate identity.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import (
    CRUCIBLE_CANDIDATE_ID_V1,
    CrucibleError,
    VALID_KINDS,
    digest,
)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_candidates (
        candidate_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        identity_payload_json TEXT NOT NULL,
        artifact_digest TEXT NOT NULL,
        configuration_digest TEXT NOT NULL,
        manifest_identity TEXT,
        parent_candidate_id TEXT,
        baseline_candidate_id TEXT,
        environment_requirements_json TEXT,
        created_by TEXT,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_candidate_declarations (
        declaration_id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL,
        declared_objective TEXT,
        declared_changes_json TEXT,
        declared_by TEXT,
        declared_at REAL
    );
    """,
)


@dataclass(frozen=True)
class CrucibleCandidate:
    candidate_id: str
    kind: str
    artifact_digest: str
    configuration_digest: str
    manifest_identity: Optional[str]
    parent_candidate_id: Optional[str]
    baseline_candidate_id: Optional[str]
    environment_requirements: Tuple[str, ...]
    declared_objective: Optional[str]
    declared_changes: Tuple[str, ...]
    created_by: Optional[str]
    created_at: Optional[float]
    identity_version: str = CRUCIBLE_CANDIDATE_ID_V1

    def as_dict(self) -> Dict[str, Any]:
        return {"candidate_id": self.candidate_id, "kind": self.kind,
                "artifact_digest": self.artifact_digest,
                "configuration_digest": self.configuration_digest,
                "manifest_identity": self.manifest_identity,
                "parent_candidate_id": self.parent_candidate_id,
                "baseline_candidate_id": self.baseline_candidate_id,
                "environment_requirements": list(self.environment_requirements),
                "declared_objective": self.declared_objective,
                "declared_changes": list(self.declared_changes),
                "created_by": self.created_by, "identity_version": self.identity_version}

    def canonical_digest(self) -> str:
        return digest(self.as_dict())


def candidate_identity_payload(*, kind: str, artifact_digest: str, configuration_digest: str,
                              manifest_identity: Optional[str] = None,
                              environment_requirements: Sequence[str] = (),
                              parent_candidate_id: Optional[str] = None,
                              baseline_candidate_id: Optional[str] = None) -> Dict[str, Any]:
    """
    THE frozen identity payload (law 3).

    Declarations, authorship and timestamps are deliberately absent: a description changing must not
    silently redefine which candidate was evaluated (law 5), while a byte or configuration change must
    (law 2).
    """
    return {"identity_version": CRUCIBLE_CANDIDATE_ID_V1, "kind": kind,
            "artifact_digest": artifact_digest, "configuration_digest": configuration_digest,
            "manifest_identity": manifest_identity,
            "environment_requirements": sorted(str(item) for item in environment_requirements),
            "parent_candidate_id": parent_candidate_id,
            "baseline_candidate_id": baseline_candidate_id}


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


def register_candidate(db_path: str, *, kind: str, artifact_digest: str,
                       configuration_digest: str, manifest_identity: Optional[str] = None,
                       environment_requirements: Sequence[str] = (),
                       parent_candidate_id: Optional[str] = None,
                       baseline_candidate_id: Optional[str] = None,
                       declared_objective: Optional[str] = None,
                       declared_changes: Sequence[str] = (), created_by: Optional[str] = None,
                       now: Optional[float] = None) -> CrucibleCandidate:
    """
    Register ONE candidate. Idempotent by identity payload, so re-registering the same artifact and
    configuration is the same candidate rather than a second chance to win.
    """
    if kind not in VALID_KINDS:
        raise CrucibleError("INVALID_CANDIDATE_KIND", str(kind))
    if not artifact_digest or not configuration_digest:
        raise CrucibleError("CANDIDATE_REQUIRES_ARTIFACT_AND_CONFIGURATION",
                            f"{artifact_digest!r}/{configuration_digest!r}")
    moment = time.time() if now is None else float(now)
    payload = candidate_identity_payload(
        kind=kind, artifact_digest=str(artifact_digest),
        configuration_digest=str(configuration_digest), manifest_identity=manifest_identity,
        environment_requirements=environment_requirements, parent_candidate_id=parent_candidate_id,
        baseline_candidate_id=baseline_candidate_id)
    candidate_id = "CC-" + digest(payload)[:16].upper()
    requirements = sorted(str(item) for item in environment_requirements)
    changes = sorted(str(item) for item in declared_changes)

    connection = _connect(db_path)
    try:
        init_schema(connection)
        existing = connection.execute("SELECT * FROM ciph_crucible_candidates WHERE candidate_id = ?;",
                                      (candidate_id,)).fetchone()
        if existing is None:
            connection.execute(
                "INSERT INTO ciph_crucible_candidates (candidate_id, kind, identity_payload_json, "
                "artifact_digest, configuration_digest, manifest_identity, parent_candidate_id, "
                "baseline_candidate_id, environment_requirements_json, created_by, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
                (candidate_id, kind, str(payload), str(artifact_digest), str(configuration_digest),
                 manifest_identity, parent_candidate_id, baseline_candidate_id,
                 str(requirements), created_by, moment))
        if declared_objective is not None or changes:
            declaration_id = "CDECL-" + digest({"candidate": candidate_id,
                                                "objective": declared_objective,
                                                "changes": changes,
                                                "by": created_by})[:16].upper()
            connection.execute(
                "INSERT OR IGNORE INTO ciph_crucible_candidate_declarations (declaration_id, "
                "candidate_id, declared_objective, declared_changes_json, declared_by, declared_at) "
                "VALUES (?,?,?,?,?,?);",
                (declaration_id, candidate_id, declared_objective, str(changes), created_by, moment))
        connection.commit()
    finally:
        connection.close()
    return get_candidate(db_path, candidate_id)


def _candidate_from_row(row: Mapping[str, Any],
                        declarations: Sequence[Mapping[str, Any]] = ()) -> CrucibleCandidate:
    latest = declarations[-1] if declarations else None
    return CrucibleCandidate(
        candidate_id=str(row["candidate_id"]), kind=str(row["kind"]),
        artifact_digest=str(row["artifact_digest"]),
        configuration_digest=str(row["configuration_digest"]),
        manifest_identity=row["manifest_identity"], parent_candidate_id=row["parent_candidate_id"],
        baseline_candidate_id=row["baseline_candidate_id"],
        environment_requirements=tuple(_load(row["environment_requirements_json"])),
        declared_objective=(latest or {}).get("declared_objective"),
        declared_changes=tuple(_load((latest or {}).get("declared_changes_json"))),
        created_by=row["created_by"], created_at=row["created_at"])


def _load(value: Any) -> List[str]:
    import json as _json
    if not value:
        return []
    try:
        return list(_json.loads(value))
    except Exception:
        return []


def get_candidate(db_path: str, candidate_id: str) -> CrucibleCandidate:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_crucible_candidates WHERE candidate_id = ?;",
                                 (candidate_id,)).fetchone()
        declarations = [dict(r) for r in connection.execute(
            "SELECT * FROM ciph_crucible_candidate_declarations WHERE candidate_id = ? "
            "ORDER BY declared_at, declaration_id;", (candidate_id,))]
    except sqlite3.Error:
        row, declarations = None, []
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_CANDIDATE", candidate_id)
    return _candidate_from_row(dict(row), declarations)


def verify_candidate_identity(db_path: str, candidate_id: str, *, artifact_digest: str,
                              configuration_digest: str,
                              manifest_identity: Optional[str] = None) -> str:
    """
    Law 2, as a guard: the candidate being evaluated must still be the candidate that was registered.

    A candidate whose bytes or configuration moved is refused rather than silently re-evaluated under
    the old identity - "the thing I tested" and "the thing I have" have to be the same thing.
    """
    candidate = get_candidate(db_path, candidate_id)
    if str(artifact_digest) != candidate.artifact_digest or str(
            configuration_digest) != candidate.configuration_digest or (
            manifest_identity is not None and manifest_identity != candidate.manifest_identity):
        raise CrucibleError("CANDIDATE_IDENTITY_MISMATCH",
                            f"{candidate_id}: registered {candidate.artifact_digest[:12]}/"
                            f"{candidate.configuration_digest[:12]}")
    return candidate_id


def candidate_history(db_path: str) -> List[CrucibleCandidate]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in connection.execute(
            "SELECT * FROM ciph_crucible_candidates ORDER BY created_at, candidate_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [_candidate_from_row(row) for row in rows]


def candidate_digest(db_path: str) -> str:
    return digest([candidate.as_dict() for candidate in candidate_history(db_path)])
