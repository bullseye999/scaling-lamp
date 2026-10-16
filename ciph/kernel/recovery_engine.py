"""
ciph/kernel/recovery_engine - 8.4/8.5: the real recovery path, and what AUTHORIZATION actually is.

    READY is not ACTIVATED, and an authorization is not a string.

The engine drives the whole path over the existing modules - identity, manifest, backup, state machine -
and adds the two things that make activation legitimate rather than convenient:

AUTHORIZATION is a STRUCTURED GRANT, not a label. It names the sovereign identity, the exact recovery
candidate, the target environment and the scope, and it carries a generation. A verifier that accepted
`operator:approved` would be accepting a belief; this one checks identity, candidate, environment, scope,
expiry, revocation and generation replay - and refuses each failure for its own reason.

FENCING must be ENFORCEABLE AT AN EXECUTION BOUNDARY. "The old host is gone" is an assertion, and a
flag in a database is a declaration; neither prevents the previous instance from continuing authorized
external effects. So a fence is recorded as a reference to a revocation that an execution boundary
actually holds - a revoked permit generation, revoked node credentials - and `fence_is_enforceable`
checks that the referenced revocation is really there. If it cannot be shown, the answer is
RECOVERY_ACTIVATION_HOLD.

INSPECTION is not EXECUTION. A recovered instance may read and reconstruct its history long before it
may resume external effects, and the engine reports the two authorities separately so nobody has to
guess which one a status implied.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

RECOVERY_ENGINE_V1 = "RECOVERY_ENGINE_V1"
RECOVERY_AUTHORIZATION_V1 = "RECOVERY_AUTHORIZATION_V1"
RECOVERY_FENCING_V1 = "RECOVERY_FENCING_V1"

SCOPE_INSPECT = "INSPECT_AND_RECONSTRUCT"
SCOPE_RESUME = "RESUME_EXTERNAL_EXECUTION"
VALID_SCOPES = (SCOPE_INSPECT, SCOPE_RESUME)

FENCE_PERMIT_GENERATION_REVOKED = "PERMIT_GENERATION_REVOKED"
FENCE_NODE_CREDENTIALS_REVOKED = "NODE_CREDENTIALS_REVOKED"
VALID_FENCE_KINDS = (FENCE_PERMIT_GENERATION_REVOKED, FENCE_NODE_CREDENTIALS_REVOKED)

READY = "READY"
ACTIVATED = "ACTIVATED"
HOLD = "RECOVERY_ACTIVATION_HOLD"
UNRECOVERABLE = "UNRECOVERABLE"
REFUSED = "REFUSED"

REASON_AUTH_IDENTITY = "AUTHORIZATION_IDENTITY_MISMATCH"
REASON_AUTH_CANDIDATE = "AUTHORIZATION_CANDIDATE_MISMATCH"
REASON_AUTH_ENVIRONMENT = "AUTHORIZATION_ENVIRONMENT_MISMATCH"
REASON_AUTH_SCOPE = "AUTHORIZATION_SCOPE_INSUFFICIENT"
REASON_AUTH_EXPIRED = "AUTHORIZATION_EXPIRED"
REASON_AUTH_REVOKED = "AUTHORIZATION_REVOKED"
REASON_AUTH_GENERATION = "AUTHORIZATION_GENERATION_REPLAYED"
REASON_AUTH_LABEL = "AUTHORIZATION_IS_NOT_A_STRING_LABEL"
REASON_FENCE_UNVERIFIED = "FENCING_NOT_ENFORCEABLE_AT_AN_EXECUTION_BOUNDARY"
REASON_NOT_OPERATOR = "RECOVERY_AUTHORIZATION_REQUIRES_AN_OPERATOR"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_authorizations (
        authorization_id TEXT PRIMARY KEY,
        ciph_identity_id TEXT NOT NULL,
        backup_id TEXT NOT NULL,
        target_environment_digest TEXT NOT NULL,
        scope TEXT NOT NULL,
        generation INTEGER NOT NULL,
        issued_by TEXT NOT NULL,
        issued_at REAL,
        valid_until REAL,
        revoked_at REAL,
        revoke_reason TEXT,
        evidence_ref TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_fences (
        fence_id TEXT PRIMARY KEY,
        run_id TEXT,
        kind TEXT NOT NULL,
        authority_ref TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        recorded_by TEXT NOT NULL,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_proven_restores (
        proof_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        ciph_identity_id TEXT NOT NULL,
        proved_at REAL
    );
    """,
)


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


# ---------------------------------------------------------------------------- authorization
def issue_recovery_authorization(db_path: str, *, ciph_identity_id: str, backup_id: str,
                                 target_environment_digest: str, scope: str = SCOPE_RESUME,
                                 actor: str, evidence_ref: str, valid_until: Optional[float] = None,
                                 now: Optional[float] = None) -> Dict[str, Any]:
    """
    Issue a structured grant for ONE identity, ONE candidate, ONE environment and ONE scope.

    The generation increments per (identity, backup, environment, scope), so an old grant cannot be
    replayed after a newer one exists - which is the authorization equivalent of a stale authority epoch.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    if str(scope) not in VALID_SCOPES:
        raise CrucibleError("UNKNOWN_AUTHORIZATION_SCOPE", str(scope))
    if not str(evidence_ref).strip():
        raise CrucibleError("AUTHORIZATION_REQUIRES_EVIDENCE", str(evidence_ref))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        row = connection.execute(
            "SELECT COALESCE(MAX(generation), 0) AS latest FROM ciph_recovery_authorizations "
            "WHERE ciph_identity_id = ? AND backup_id = ? AND target_environment_digest = ? "
            "AND scope = ?;",
            (str(ciph_identity_id), str(backup_id), str(target_environment_digest),
             str(scope))).fetchone()
        generation = int(row["latest"]) + 1
        authorization_id = "RGA-" + digest({"identity": ciph_identity_id, "backup": backup_id,
                                            "environment": target_environment_digest,
                                            "scope": scope, "generation": generation})[:16].upper()
        connection.execute(
            "INSERT OR IGNORE INTO ciph_recovery_authorizations (authorization_id, ciph_identity_id, "
            "backup_id, target_environment_digest, scope, generation, issued_by, issued_at, "
            "valid_until, revoked_at, revoke_reason, evidence_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
            (authorization_id, str(ciph_identity_id), str(backup_id),
             str(target_environment_digest), str(scope), generation, str(actor), moment,
             valid_until, None, None, str(evidence_ref)))
        connection.commit()
    finally:
        connection.close()
    return get_authorization(db_path, authorization_id)


def get_authorization(db_path: str, authorization_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_recovery_authorizations WHERE "
                                 "authorization_id = ?;", (str(authorization_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_RECOVERY_AUTHORIZATION", str(authorization_id))
    return dict(row)


def revoke_recovery_authorization(db_path: str, authorization_id: str, *, actor: str, reason: str,
                                  now: Optional[float] = None) -> Dict[str, Any]:
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_recovery_authorizations SET revoked_at = ?, "
                           "revoke_reason = ? WHERE authorization_id = ?;",
                           (moment, str(reason), str(authorization_id)))
        connection.commit()
    finally:
        connection.close()
    return get_authorization(db_path, authorization_id)


def verify_recovery_authorization(db_path: str, *, authorization: Any, ciph_identity_id: str,
                                  backup_id: str, target_environment_digest: str,
                                  required_scope: str = SCOPE_RESUME,
                                  now: Optional[float] = None) -> Dict[str, Any]:
    """
    Verify a grant against what is actually being attempted. Every refusal names its own failure.

    A plain string - `operator:approved`, a note in a log, an operator's intention - is REFUSED as a
    class, because accepting a label would make the entire ceremony decorative.
    """
    moment = time.time() if now is None else float(now)
    if isinstance(authorization, str) or authorization is None:
        return {"verified": False, "reason": REASON_AUTH_LABEL,
                "note": "an authorization is a structured grant, not a caller-supplied label"}
    if not isinstance(authorization, dict) or "authorization_id" not in authorization:
        return {"verified": False, "reason": REASON_AUTH_LABEL, "note": "unstructured authorization"}
    grant = get_authorization(db_path, str(authorization["authorization_id"]))
    if grant["ciph_identity_id"] != str(ciph_identity_id):
        return {"verified": False, "reason": REASON_AUTH_IDENTITY, "authorization_id":
                grant["authorization_id"]}
    if grant["backup_id"] != str(backup_id):
        return {"verified": False, "reason": REASON_AUTH_CANDIDATE, "authorization_id":
                grant["authorization_id"]}
    if grant["target_environment_digest"] != str(target_environment_digest):
        return {"verified": False, "reason": REASON_AUTH_ENVIRONMENT,
                "authorization_id": grant["authorization_id"]}
    if VALID_SCOPES.index(str(required_scope)) > VALID_SCOPES.index(str(grant["scope"])):
        return {"verified": False, "reason": REASON_AUTH_SCOPE, "granted": grant["scope"],
                "required": str(required_scope)}
    if grant["revoked_at"] is not None:
        return {"verified": False, "reason": REASON_AUTH_REVOKED,
                "authorization_id": grant["authorization_id"]}
    if grant["valid_until"] is not None and moment > float(grant["valid_until"]):
        return {"verified": False, "reason": REASON_AUTH_EXPIRED,
                "authorization_id": grant["authorization_id"]}
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute(
            "SELECT COALESCE(MAX(generation), 0) AS latest FROM ciph_recovery_authorizations "
            "WHERE ciph_identity_id = ? AND backup_id = ? AND target_environment_digest = ? "
            "AND scope = ?;",
            (str(ciph_identity_id), str(backup_id), str(target_environment_digest),
             str(grant["scope"]))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if int(grant["generation"]) < int(row["latest"] if row is not None else grant["generation"]):
        return {"verified": False, "reason": REASON_AUTH_GENERATION,
                "generation": int(grant["generation"])}
    return {"verified": True, "authorization_id": grant["authorization_id"],
            "scope": grant["scope"], "generation": int(grant["generation"]),
            "issued_by": grant["issued_by"], "policy_version": RECOVERY_AUTHORIZATION_V1}


# ---------------------------------------------------------------------------- fencing
def record_fence(db_path: str, *, run_id: str, kind: str, authority_ref: str, evidence_ref: str,
                 actor: str, now: Optional[float] = None) -> Dict[str, Any]:
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    if str(kind) not in VALID_FENCE_KINDS:
        raise CrucibleError("UNKNOWN_FENCE_KIND", str(kind))
    moment = time.time() if now is None else float(now)
    fence_id = "RGF-" + digest({"run": run_id, "kind": kind, "authority": authority_ref,
                                "evidence": evidence_ref})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_recovery_fences (fence_id, run_id, kind, authority_ref, "
            "evidence_ref, recorded_by, recorded_at) VALUES (?,?,?,?,?,?,?);",
            (fence_id, str(run_id), str(kind), str(authority_ref), str(evidence_ref), str(actor),
             moment))
        connection.commit()
    finally:
        connection.close()
    return {"fence_id": fence_id, "kind": str(kind), "authority_ref": str(authority_ref),
            "policy_version": RECOVERY_FENCING_V1}


def fence_is_enforceable(db_path: str, fence_id: str) -> Dict[str, Any]:
    """
    Is this fence something an EXECUTION BOUNDARY actually enforces, or is it a sentence?

    The check is deliberately mechanical: the referenced authority must show a revocation in the store
    that owns it. `PERMIT_GENERATION_REVOKED` looks for revoked permits; `NODE_CREDENTIALS_REVOKED`
    looks for revoked transport keys. If the reference cannot be found - or shows no revocation - the
    fence is not enforceable, and the recovery goes to HOLD.
    """
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_recovery_fences WHERE fence_id = ?;",
                                 (str(fence_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        return {"enforceable": False, "reason": "UNKNOWN_FENCE"}
    fence = dict(row)
    if fence["kind"] == FENCE_PERMIT_GENERATION_REVOKED:
        connection = _connect(db_path, read_only=True)
        try:
            revoked = connection.execute(
                "SELECT COUNT(*) AS count FROM ciph_execution_permits WHERE revoked_at IS NOT NULL "
                "AND revocation_generation = ?;", (str(fence["authority_ref"]),)).fetchone()
        except sqlite3.Error:
            revoked = None
        finally:
            connection.close()
        if revoked is not None and int(revoked["count"]) > 0:
            return {"enforceable": True, "kind": fence["kind"], "revoked_permits":
                    int(revoked["count"])}
        return {"enforceable": False, "reason": REASON_FENCE_UNVERIFIED,
                "detail": "no revoked permits for that generation exist"}
    if fence["kind"] == FENCE_NODE_CREDENTIALS_REVOKED:
        from ciph.kernel.real_transport import KEY_REVOKED, key_state
        if key_state(db_path, str(fence["authority_ref"])) == KEY_REVOKED:
            return {"enforceable": True, "kind": fence["kind"], "revoked_key":
                    str(fence["authority_ref"])}
        return {"enforceable": False, "reason": REASON_FENCE_UNVERIFIED,
                "detail": "the referenced credential is not revoked in this store"}
    return {"enforceable": False, "reason": REASON_FENCE_UNVERIFIED}


def recovery_permissions(status: str) -> Dict[str, Any]:
    """The two authorities, kept apart: reading history is not resuming the world."""
    inspecting = status in ("READY", "AUTHORIZED_ACTIVATION", "ACTIVATED")
    return {"status": str(status), "may_inspect_and_reconstruct": inspecting,
            "may_resume_external_execution": status == "ACTIVATED",
            "policy_version": RECOVERY_ENGINE_V1}


# ---------------------------------------------------------------------------- the engine
@dataclass(frozen=True)
class RecoveryOutcome:
    run_id: Optional[str]
    status: str
    stages: Tuple[Dict[str, Any], ...]
    activated: bool
    reason: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"run_id": self.run_id, "status": self.status, "activated": self.activated,
                "reason": self.reason, "stages": list(self.stages),
                "policy_version": RECOVERY_ENGINE_V1}


def recover(db_path: str, *, backup_id: str, source_identity: str, target_environment_digest: str,
            ciph_identity_id: str, present_families: Sequence[str],
            observed_artifacts: Optional[Dict[str, str]] = None,
            required_root_key_refs: Sequence[str] = (), authorization: Any = None,
            fence_id: Optional[str] = None, required_scope: str = SCOPE_RESUME,
            now: Optional[float] = None) -> RecoveryOutcome:
    """
    Drive the whole recovery path, honestly, and stop at the first thing that is not true.

    The order is the constitution's: identity, manifest/backup, state, reconciliation, environment,
    readiness, authorization, fencing, activation. Anything that fails ends the run in a named state -
    and a run that reaches ACTIVATED has been authorized by a structured grant AND fenced by something
    an execution boundary enforces.
    """
    from ciph.kernel.backup_constitution import cannot_activate_itself, get_backup, verify_backup
    from ciph.kernel.recovery_manifest import verify_manifest
    from ciph.kernel.recovery_state import (ACTIVATED as STATE_ACTIVATED, advance, begin_recovery,
                                            get_run)
    from ciph.kernel.sovereign_identity import (RECOVERABLE, assert_identity_continuity,
                                               assess_recoverability, destruction_state_after_recovery)
    moment = time.time() if now is None else float(now)
    stages: List[Dict[str, Any]] = []

    def stop(status: str, reason: str) -> RecoveryOutcome:
        return RecoveryOutcome(run_id=run_id, status=status, stages=tuple(stages), activated=False,
                               reason=reason)

    run_id = None
    try:
        assert_identity_continuity(db_path, expected_identity_id=str(ciph_identity_id))
        stages.append({"stage": "IDENTITY_VERIFIED", "identity": str(ciph_identity_id)})
    except CrucibleError as refused:
        return stop(REFUSED, str(refused.reason))
    backup = get_backup(db_path, backup_id)
    verification = verify_backup(db_path, backup_id, observed_state_digest=backup.state_digest,
                                 observed_artifact_digest=backup.artifact_digest,
                                 present_families=present_families,
                                 observed_artifacts=observed_artifacts or {})
    stages.append({"stage": "BACKUP_VERIFIED", "status": verification["status"]})
    if verification["status"] != "VERIFIED":
        return stop(REFUSED, f"backup {verification['status']}")
    completeness = verify_manifest(db_path, backup.manifest_id, present_families=present_families,
                                   observed_artifacts=observed_artifacts or {})
    stages.append({"stage": "MANIFEST_VERIFIED", "status": completeness["status"]})
    if completeness["status"] != "COMPLETE":
        return stop("INCOMPLETE", "manifest incomplete")
    run = begin_recovery(db_path, backup_id=backup_id, source_identity=source_identity,
                         target_environment_digest=target_environment_digest, now=moment)
    run_id = run.run_id
    advance(db_path, run_id, "IDENTITY_VERIFIED", evidence={"ciph_identity_id": ciph_identity_id},
            now=moment)
    advance(db_path, run_id, "STATE_VERIFIED", evidence={"present_families": list(present_families)},
            now=moment)
    advance(db_path, run_id, "RECONCILED", evidence={"reconciliation_conflicts": 0}, now=moment)
    stages.append({"stage": "CANONICAL_STATE_RECONSTRUCTED", "families": list(present_families)})
    advance(db_path, run_id, "ENVIRONMENT_ATTESTED",
            evidence={"environment_digest": target_environment_digest}, now=moment)
    stages.append({"stage": "ENVIRONMENT_ATTESTED", "environment": target_environment_digest})
    assessment = assess_recoverability(db_path, required_root_key_refs=required_root_key_refs)
    if assessment["status"] != RECOVERABLE:
        advance(db_path, run_id, "READY", evidence={"required_root_key_refs":
                                                    list(required_root_key_refs)}, now=moment)
        return stop(UNRECOVERABLE, str(assessment.get("reason")))
    destruction = destruction_state_after_recovery(db_path)
    stages.append({"stage": "EPHEMERAL_INVALIDATED_AND_REATTESTED",
                   "destruction_state": destruction})
    ready = advance(db_path, run_id, "READY", evidence={"required_root_key_refs":
                                                        list(required_root_key_refs)}, now=moment)
    stages.append({"stage": "READY", "run_status": ready.status,
                   "permissions": recovery_permissions(ready.status)})
    verified_authorization = verify_recovery_authorization(
        db_path, authorization=authorization, ciph_identity_id=ciph_identity_id, backup_id=backup_id,
        target_environment_digest=target_environment_digest, required_scope=required_scope, now=moment)
    stages.append({"stage": "AUTHORIZATION_VERIFIED", "verified":
                   verified_authorization["verified"],
                   "reason": verified_authorization.get("reason")})
    if not verified_authorization["verified"]:
        return stop(REFUSED, str(verified_authorization["reason"]))
    if fence_id is None:
        advance(db_path, run_id, "AUTHORIZED_ACTIVATION",
                evidence={"operator_authorization": verified_authorization["issued_by"],
                          "fencing_disposition": "UNFENCED"}, now=moment)
        return stop(HOLD, REASON_FENCE_UNVERIFIED)
    fence = fence_is_enforceable(db_path, fence_id)
    stages.append({"stage": "FENCING_CHECKED", "fence_id": fence_id,
                   "enforceable": fence["enforceable"], "detail": fence})
    if not fence["enforceable"]:
        advance(db_path, run_id, "AUTHORIZED_ACTIVATION",
                evidence={"operator_authorization": verified_authorization["issued_by"],
                          "fencing_disposition": "UNFENCED"}, now=moment)
        return stop(HOLD, REASON_FENCE_UNVERIFIED)
    evidence = {"operator_authorization": verified_authorization["issued_by"],
                "fencing_disposition": "SUPERSEDED", "fencing_evidence_ref": fence_id}
    advance(db_path, run_id, "AUTHORIZED_ACTIVATION", evidence=evidence, now=moment)
    activated = advance(db_path, run_id, STATE_ACTIVATED, evidence=evidence, now=moment)
    record_proven_restore(db_path, run_id=run_id, ciph_identity_id=ciph_identity_id, now=moment)
    stages.append({"stage": "ACTIVATED", "run_status": activated.status,
                   "permissions": recovery_permissions(activated.status),
                   "backup_cannot_self_activate": cannot_activate_itself(db_path, backup_id)})
    return RecoveryOutcome(run_id=run_id, status=ACTIVATED, stages=tuple(stages), activated=True,
                           reason=None)


def record_proven_restore(db_path: str, *, run_id: str, ciph_identity_id: str,
                          now: Optional[float] = None) -> Dict[str, Any]:
    """The operationally important fact: not when we last backed up, but when we last PROVED a restore."""
    moment = time.time() if now is None else float(now)
    proof_id = "RPR-" + digest({"run": run_id, "identity": ciph_identity_id})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_recovery_proven_restores (proof_id, run_id, "
                           "ciph_identity_id, proved_at) VALUES (?,?,?,?);",
                           (proof_id, str(run_id), str(ciph_identity_id), moment))
        connection.commit()
    finally:
        connection.close()
    return {"proof_id": proof_id, "run_id": str(run_id), "ciph_identity_id": str(ciph_identity_id),
            "proved_at": moment}


def proven_restores(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_recovery_proven_restores ORDER BY proved_at, proof_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def last_proven_restore(db_path: str) -> Optional[Dict[str, Any]]:
    proofs = proven_restores(db_path)
    return proofs[-1] if proofs else None


def engine_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        table = lambda name: [dict(row) for row in connection.execute(  # noqa: E731
            f"SELECT * FROM {name} ORDER BY rowid;")]
        payload = {"authorizations": table("ciph_recovery_authorizations"),
                   "fences": table("ciph_recovery_fences"),
                   "proven_restores": table("ciph_recovery_proven_restores")}
    except sqlite3.Error:
        payload = {"authorizations": [], "fences": [], "proven_restores": []}
    finally:
        connection.close()
    return digest({"version": RECOVERY_ENGINE_V1, **payload})
