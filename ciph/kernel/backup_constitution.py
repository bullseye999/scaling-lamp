"""
ciph/kernel/backup_constitution - 8.3: which backup is legitimate, complete, and restorable.

    backup created  !=  backup verified  !=  backup restorable  !=  backup AUTHORIZED

Four different things, and collapsing them is how a "backup strategy" becomes a story people tell. A
backup is a BOUNDED, INTEGRITY-PROVEN, CONSISTENCY-BOUNDED set of state - and even a perfect one carries
no authority: restoring requires a separate authorization, and activating requires more than that.

Consistency is the part that is usually skipped. A snapshot that carries missions from one moment,
permits from another, evidence from a third and the active pointer from a fourth is not a backup of Ciph;
it is four unrelated facts wearing one filename. So a set binds ONE boundary, declared explicitly, and a
verification that ignores the boundary is not a verification.

R12's finding is answered by construction here: an approved set REFUSES root material as ordinary content
and REFUSES the legacy default passphrase, rather than documenting that it should.
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest
from ciph.kernel.recovery_manifest import assert_manifest_integrity, get_manifest

BACKUP_SET_V1 = "BACKUP_SET_V1"
BACKUP_CONSISTENCY_V1 = "BACKUP_CONSISTENCY_V1"

CREATED = "CREATED"
VERIFIED = "VERIFIED"
CORRUPTED = "CORRUPTED"
INCOMPLETE = "INCOMPLETE"
STALE = "STALE"
SUPERSEDED = "SUPERSEDED"
VALID_STATUSES = (CREATED, VERIFIED, CORRUPTED, INCOMPLETE, STALE, SUPERSEDED)

APPROVED = "APPROVED"
INSECURE_HISTORICAL = "INSECURE_HISTORICAL"
UNKNOWN_PROTECTION = "UNKNOWN_PROTECTION"

MINIMUM_PASSPHRASE_LENGTH = 24
LEGACY_DEFAULT_PASSPHRASE = "ciph_backup_passphrase"
PASSPHRASE_ENV_VAR = "CIPH_BACKUP_PASSPHRASE"
ROOT_MATERIAL_NAMES = ("ciph.key", "quantum.key", "root_secret", "kernel_priv_bytes",
                       "recovery_root", "node_priv")

REASON_INSECURE = "INSECURE_BACKUP_CONFIGURATION"
REASON_ROOT_MEMBER = "ROOT_MATERIAL_IS_NOT_ORDINARY_BACKUP_CONTENT"
REASON_NOT_OPERATOR = "BACKUP_AUTHORIZATION_REQUIRES_AN_OPERATOR"
REASON_NOT_VERIFIED = "BACKUP_IS_NOT_VERIFIED"
REASON_BOUNDARY = "BACKUP_REQUIRES_AN_EXPLICIT_CONSISTENCY_BOUNDARY"
REASON_UNKNOWN_BACKUP = "UNKNOWN_BACKUP_SET"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_backup_sets (
        backup_id TEXT PRIMARY KEY,
        source_identity TEXT NOT NULL,
        manifest_id TEXT NOT NULL,
        created_at REAL,
        state_digest TEXT NOT NULL,
        artifact_digest TEXT NOT NULL,
        schema_digest TEXT NOT NULL,
        included_json TEXT NOT NULL,
        excluded_json TEXT NOT NULL,
        encryption_identity TEXT NOT NULL,
        integrity_proof TEXT NOT NULL,
        consistency_boundary TEXT NOT NULL,
        status TEXT NOT NULL,
        verified_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_backup_authorizations (
        authorization_id TEXT PRIMARY KEY,
        backup_id TEXT NOT NULL,
        actor TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        authorized_at REAL
    );
    """,
)


@dataclass(frozen=True)
class BackupSet:
    backup_id: str
    source_identity: str
    manifest_id: str
    state_digest: str
    artifact_digest: str
    schema_digest: str
    included: Tuple[str, ...]
    excluded: Tuple[str, ...]
    encryption_identity: str
    consistency_boundary: str
    status: str

    def as_dict(self) -> Dict[str, Any]:
        return {"backup_id": self.backup_id, "source_identity": self.source_identity,
                "manifest_id": self.manifest_id, "state_digest": self.state_digest,
                "artifact_digest": self.artifact_digest, "schema_digest": self.schema_digest,
                "included": list(self.included), "excluded": list(self.excluded),
                "encryption_identity": self.encryption_identity,
                "consistency_boundary": self.consistency_boundary, "status": self.status,
                "policy_version": BACKUP_SET_V1}


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


def _from_row(row: Any) -> BackupSet:
    row = dict(row)
    return BackupSet(backup_id=str(row["backup_id"]), source_identity=str(row["source_identity"]),
                     manifest_id=str(row["manifest_id"]), state_digest=str(row["state_digest"]),
                     artifact_digest=str(row["artifact_digest"]),
                     schema_digest=str(row["schema_digest"]),
                     included=tuple(json.loads(row["included_json"] or "[]")),
                     excluded=tuple(json.loads(row["excluded_json"] or "[]")),
                     encryption_identity=str(row["encryption_identity"]),
                     consistency_boundary=str(row["consistency_boundary"]),
                     status=str(row["status"]))


def assert_backup_configuration(*, passphrase: Optional[str], included: Sequence[str]) -> None:
    """
    THE R12 REFUSAL, as a function so both the governed creator and any future caller hit the same wall.

    Three refusals, in order of how quietly they would otherwise go wrong: a missing or legacy-default
    passphrase (a default is a format, not encryption), a passphrase too short to be one, and root or
    recovery material named as ordinary content.
    """
    if not passphrase or str(passphrase).strip() == "" or str(passphrase) == LEGACY_DEFAULT_PASSPHRASE:
        raise CrucibleError(REASON_INSECURE,
                            "an explicit passphrase is required; the historical default is refused and "
                            "is never a fallback")
    if len(str(passphrase)) < MINIMUM_PASSPHRASE_LENGTH:
        raise CrucibleError(REASON_INSECURE,
                            f"passphrase below {MINIMUM_PASSPHRASE_LENGTH} characters")
    lowered = " ".join(str(item).lower() for item in included)
    for name in ROOT_MATERIAL_NAMES:
        if name in lowered:
            raise CrucibleError(REASON_ROOT_MEMBER,
                                f"{name} may not travel as ordinary backup content")


def create_approved_backup(db_path: str, *, source_identity: str, manifest_id: str,
                           state_digest: str, artifact_digest: str, schema_digest: str,
                           included: Sequence[str], excluded: Sequence[str] = (),
                           encryption_identity: str, consistency_boundary: str,
                           passphrase: Optional[str] = None, now: Optional[float] = None) -> BackupSet:
    """
    Create a governed backup set: verified configuration, integrity proof, ONE declared boundary.

    Status is CREATED - not VERIFIED. A creator that marked its own output verified would be grading its
    own homework, and the difference between created and verified is exactly the difference between a
    file existing and a restore having been proven possible.
    """
    if passphrase is None:
        passphrase = os.environ.get(PASSPHRASE_ENV_VAR)
    assert_backup_configuration(passphrase=passphrase, included=included)
    if not str(consistency_boundary).strip():
        raise CrucibleError(REASON_BOUNDARY, str(manifest_id))
    assert_manifest_integrity(db_path, manifest_id)
    moment = time.time() if now is None else float(now)
    integrity_proof = digest({"manifest_id": str(manifest_id), "state": str(state_digest),
                              "artifact": str(artifact_digest), "schema": str(schema_digest),
                              "included": sorted(str(item) for item in included),
                              "excluded": sorted(str(item) for item in excluded),
                              "boundary": str(consistency_boundary),
                              "encryption_identity": str(encryption_identity)})
    backup_id = "BS-" + integrity_proof[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_backup_sets (backup_id, source_identity, manifest_id, "
            "created_at, state_digest, artifact_digest, schema_digest, included_json, excluded_json, "
            "encryption_identity, integrity_proof, consistency_boundary, status, verified_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (backup_id, str(source_identity), str(manifest_id), moment, str(state_digest),
             str(artifact_digest), str(schema_digest),
             json.dumps(sorted(str(item) for item in included)),
             json.dumps(sorted(str(item) for item in excluded)), str(encryption_identity),
             integrity_proof, str(consistency_boundary), CREATED, None))
        connection.commit()
    finally:
        connection.close()
    return get_backup(db_path, backup_id)


def get_backup(db_path: str, backup_id: str) -> BackupSet:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_backup_sets WHERE backup_id = ?;",
                                 (str(backup_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_BACKUP, str(backup_id))
    return _from_row(row)


def verify_backup(db_path: str, backup_id: str, *, observed_state_digest: str,
                  observed_artifact_digest: str, present_families: Optional[Sequence[str]] = None,
                  observed_artifacts: Optional[Dict[str, str]] = None,
                  now: Optional[float] = None) -> Dict[str, Any]:
    """
    Independently verify a set: digests against the manifest, and completeness against the boundary.

    Corruption is checked BEFORE completeness: a set whose bytes do not hash to what the manifest
    recorded is not "missing a family", it is not that backup at all.
    """
    from ciph.kernel.recovery_manifest import verify_manifest
    moment = time.time() if now is None else float(now)
    backup = get_backup(db_path, backup_id)
    if str(observed_state_digest) != backup.state_digest \
            or str(observed_artifact_digest) != backup.artifact_digest:
        _set_status(db_path, backup_id, CORRUPTED, moment)
        return {"backup_id": backup_id, "status": CORRUPTED, "verified": False,
                "reason": "observed digests do not match the recorded set"}
    # The manifest's per-artifact digests are checked against the CALLER's observations, not against
    # the set's own record: a backup that graded its own artifacts would prove nothing.
    completeness = verify_manifest(db_path, backup.manifest_id,
                                   present_families=present_families or (),
                                   observed_artifacts=observed_artifacts or {})
    if completeness["status"] != "COMPLETE":
        _set_status(db_path, backup_id, INCOMPLETE, moment)
        return {"backup_id": backup_id, "status": INCOMPLETE, "verified": False,
                "missing_families": completeness["missing_families"],
                "missing_artifacts": completeness["missing_artifacts"]}
    _set_status(db_path, backup_id, VERIFIED, moment)
    return {"backup_id": backup_id, "status": VERIFIED, "verified": True,
            "consistency_boundary": backup.consistency_boundary,
            "included": list(backup.included), "excluded": list(backup.excluded)}


def _set_status(db_path: str, backup_id: str, status: str, moment: float) -> None:
    if status not in VALID_STATUSES:
        raise CrucibleError("UNKNOWN_BACKUP_STATUS", str(status))
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_backup_sets SET status = ?, verified_at = ? "
                           "WHERE backup_id = ?;", (status, moment, str(backup_id)))
        connection.commit()
    finally:
        connection.close()


def authorize_for_recovery(db_path: str, backup_id: str, *, actor: str, evidence_ref: str,
                           now: Optional[float] = None) -> Dict[str, Any]:
    """
    Authorize a VERIFIED backup for RESTORE - which is not authorization to activate anything.

    The distinction is the whole phase in one function: a verified backup is evidence that a restore is
    possible; a recovery authorization is a person saying "use this one"; neither is production
    authority, which is granted only by the recovery ceremony in `recovery_state.py`.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    backup = get_backup(db_path, backup_id)
    if backup.status != VERIFIED:
        raise CrucibleError(REASON_NOT_VERIFIED, f"{backup_id}:{backup.status}")
    if not str(evidence_ref).strip():
        raise CrucibleError(REASON_NOT_VERIFIED, "authorization requires evidence")
    moment = time.time() if now is None else float(now)
    authorization_id = "BA-" + digest({"backup": backup_id, "actor": actor,
                                       "evidence": evidence_ref})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_backup_authorizations (authorization_id, "
                           "backup_id, actor, evidence_ref, authorized_at) VALUES (?,?,?,?,?);",
                           (authorization_id, str(backup_id), str(actor), str(evidence_ref), moment))
        connection.commit()
    finally:
        connection.close()
    return {"authorization_id": authorization_id, "backup_id": str(backup_id),
            "authorized_for_recovery": True, "authorized_for_activation": False,
            "policy_version": BACKUP_SET_V1, "authorized_at": moment}


def recovery_authorization(db_path: str, backup_id: str) -> Optional[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_backup_authorizations WHERE backup_id = ? "
                                 "ORDER BY authorized_at LIMIT 1;", (str(backup_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return dict(row) if row is not None else None


def cannot_activate_itself(db_path: str, backup_id: str) -> Dict[str, Any]:
    """
    THE INVARIANT, executable: a backup set is not a path to production, only a path to a candidate.

    This function exists so the refusal has a name that a scanner and a specimen can both point at.
    """
    backup = get_backup(db_path, backup_id)
    return {"backup_id": backup.backup_id, "status": backup.status,
            "activation_authority": "none",
            "requires": "the governed recovery ceremony (recovery_state.activate)",
            "activated": False, "policy_version": BACKUP_SET_V1}


def classify_historical_backup(*, contains_root_material: bool, used_default_passphrase: bool,
                               integrity_proof: bool, consistency_boundary_declared: bool
                               ) -> Dict[str, Any]:
    """
    Classify an EXISTING archive by what actually protects it - never by what it was meant to be.

    A historical archive is not silently promoted to approved. If it packed the root, or leaned on the
    default passphrase, that is recorded as INSECURE_HISTORICAL and it stays that way - the finding is not
    erased by improving today's code path.
    """
    if contains_root_material or used_default_passphrase:
        return {"classification": INSECURE_HISTORICAL,
                "contains_root_material": bool(contains_root_material),
                "used_default_passphrase": bool(used_default_passphrase),
                "approved_for_restore": False,
                "note": "kept for inspection and forensics; not designated constitutionally approved"}
    if not integrity_proof or not consistency_boundary_declared:
        return {"classification": UNKNOWN_PROTECTION, "approved_for_restore": False,
                "note": "no integrity proof or no declared consistency boundary"}
    return {"classification": APPROVED, "approved_for_restore": True,
            "note": "integrity-proven with a declared boundary; still requires recovery authorization"}


def backup_sets(db_path: str) -> List[BackupSet]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["backup_id"]) for row in connection.execute(
            "SELECT backup_id FROM ciph_backup_sets ORDER BY created_at, backup_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_backup(db_path, backup_id) for backup_id in ids]


def backup_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        authorizations = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_backup_authorizations ORDER BY authorized_at, authorization_id;")]
    except sqlite3.Error:
        authorizations = []
    finally:
        connection.close()
    return digest({"version": BACKUP_SET_V1,
                   "sets": [item.as_dict() for item in backup_sets(db_path)],
                   "authorizations": authorizations})
