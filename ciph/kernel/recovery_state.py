"""
ciph/kernel/recovery_state - 8.4 (the lifecycle), 8.5 (clone versus restore).

    RESTORE is a claim of continuation. CLONE is a copy with no standing. Bytes are the same.

Recovery is a governed STATE TRANSITION, not a file copy that happens to leave a working directory. Each
step has a precondition that a restored pile of bytes cannot satisfy by existing:

    RESTORE_STARTED -> IDENTITY_VERIFIED -> STATE_VERIFIED -> RECONCILED -> ENVIRONMENT_ATTESTED
    -> READY -> AUTHORIZED_ACTIVATION -> ACTIVATED

and each step can fail honestly into INCOMPLETE, INTEGRITY_CONFLICT, KEY_UNAVAILABLE, STALE_AUTHORITY,
RECOVERY_ACTIVATION_HOLD, UNRECOVERABLE or REFUSED.

Two rules carry the phase.

FENCING. A restored copy may not activate while the previous instance could still hold valid authority,
unless that authority is conclusively FENCED or SUPERSEDED. "The old machine is probably dead" is not
enough - that sentence is how two authoritative Ciphers are born. If fencing cannot be shown, the run
enters RECOVERY_ACTIVATION_HOLD and stays there.

CLONE. A clone is registered, carries NO standing by construction, and there is no path from clone to
production at all: not through bytes, not through source code, not through historical permits, not
through old operator grants, not through old federation credentials. A clone exists to be examined.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

RECOVERY_STATE_V1 = "RECOVERY_STATE_V1"
RECOVERY_ACTIVATION_V1 = "RECOVERY_ACTIVATION_V1"

RESTORE_STARTED = "RESTORE_STARTED"
IDENTITY_VERIFIED = "IDENTITY_VERIFIED"
STATE_VERIFIED = "STATE_VERIFIED"
RECONCILED = "RECONCILED"
ENVIRONMENT_ATTESTED = "ENVIRONMENT_ATTESTED"
READY = "READY"
AUTHORIZED_ACTIVATION = "AUTHORIZED_ACTIVATION"
ACTIVATED = "ACTIVATED"
INCOMPLETE = "INCOMPLETE"
INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"
KEY_UNAVAILABLE = "KEY_UNAVAILABLE"
STALE_AUTHORITY = "STALE_AUTHORITY"
RECOVERY_ACTIVATION_HOLD = "RECOVERY_ACTIVATION_HOLD"
UNRECOVERABLE = "UNRECOVERABLE"
REFUSED = "REFUSED"

LIFECYCLE: Tuple[str, ...] = (RESTORE_STARTED, IDENTITY_VERIFIED, STATE_VERIFIED, RECONCILED,
                              ENVIRONMENT_ATTESTED, READY, AUTHORIZED_ACTIVATION, ACTIVATED)
FAILURE_STATES: Tuple[str, ...] = (INCOMPLETE, INTEGRITY_CONFLICT, KEY_UNAVAILABLE, STALE_AUTHORITY,
                                   RECOVERY_ACTIVATION_HOLD, UNRECOVERABLE, REFUSED)
VALID_STATES = LIFECYCLE + FAILURE_STATES

FENCED = "FENCED"
SUPERSEDED = "SUPERSEDED"
UNFENCED = "UNFENCED"

CLONE_STANDING_NONE = "NONE"

REASON_NOT_OPERATOR = "RECOVERY_ACTIVATION_REQUIRES_AN_OPERATOR"
REASON_ILLEGAL = "ILLEGAL_RECOVERY_TRANSITION"
REASON_UNKNOWN_RUN = "UNKNOWN_RECOVERY_RUN"
REASON_UNKNOWN_CLONE = "UNKNOWN_CLONE"
REASON_IDENTITY = "RECOVERY_IDENTITY_MISMATCH"
REASON_UNFENCED = "PRIOR_AUTHORITY_NOT_FENCED"
REASON_ROOT_MISSING = "RECOVERY_KEY_UNAVAILABLE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_runs (
        run_id TEXT PRIMARY KEY,
        backup_id TEXT NOT NULL,
        source_identity TEXT NOT NULL,
        target_environment_digest TEXT,
        status TEXT NOT NULL,
        history_json TEXT,
        detail TEXT,
        started_at REAL,
        updated_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_activations (
        activation_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        ciph_identity_id TEXT NOT NULL,
        previous_active_generation INTEGER,
        new_active_generation INTEGER NOT NULL,
        operator_authorization TEXT NOT NULL,
        fencing_disposition TEXT NOT NULL,
        fencing_evidence_ref TEXT,
        activated_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_clones (
        clone_id TEXT PRIMARY KEY,
        source_identity TEXT NOT NULL,
        purpose TEXT,
        standing TEXT NOT NULL,
        registered_at REAL
    );
    """,
)


@dataclass(frozen=True)
class RecoveryRun:
    run_id: str
    backup_id: str
    source_identity: str
    target_environment_digest: Optional[str]
    status: str
    history: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"run_id": self.run_id, "backup_id": self.backup_id,
                "source_identity": self.source_identity,
                "target_environment_digest": self.target_environment_digest, "status": self.status,
                "history": list(self.history), "policy_version": RECOVERY_STATE_V1}


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


def _from_row(row: Any) -> RecoveryRun:
    row = dict(row)
    return RecoveryRun(run_id=str(row["run_id"]), backup_id=str(row["backup_id"]),
                       source_identity=str(row["source_identity"]),
                       target_environment_digest=row["target_environment_digest"],
                       status=str(row["status"]),
                       history=tuple(json.loads(row["history_json"] or "[]")))


def begin_recovery(db_path: str, *, backup_id: str, source_identity: str,
                   target_environment_digest: Optional[str] = None,
                   now: Optional[float] = None) -> RecoveryRun:
    from ciph.kernel.backup_constitution import recovery_authorization
    moment = time.time() if now is None else float(now)
    authorization = recovery_authorization(db_path, backup_id)
    if authorization is None:
        raise CrucibleError("BACKUP_NOT_AUTHORIZED_FOR_RECOVERY", str(backup_id))
    # Each ATTEMPT is its own run: a recovery that failed or was held is history, not a slot to be
    # reused. (A deterministic id keyed on the moment alone silently continued a held run, which the
    # Chunk-B suite caught immediately.)
    connection = _connect(db_path, read_only=True)
    try:
        init_schema(connection)
        attempt = int(connection.execute(
            "SELECT COUNT(*) AS count FROM ciph_recovery_runs WHERE backup_id = ?;",
            (str(backup_id),)).fetchone()["count"]) + 1
    except sqlite3.Error:
        attempt = 1
    finally:
        connection.close()
    run_id = "RR-" + digest({"backup": backup_id, "source": source_identity,
                             "attempt": attempt})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_recovery_runs (run_id, backup_id, source_identity, "
            "target_environment_digest, status, history_json, detail, started_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?);",
            (run_id, str(backup_id), str(source_identity), target_environment_digest,
             RESTORE_STARTED, json.dumps([RESTORE_STARTED]), None, moment, moment))
        connection.commit()
    finally:
        connection.close()
    return get_run(db_path, run_id)


def get_run(db_path: str, run_id: str) -> RecoveryRun:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_recovery_runs WHERE run_id = ?;",
                                 (str(run_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_RUN, str(run_id))
    return _from_row(row)


def advance(db_path: str, run_id: str, to_state: str, *, evidence: Optional[Dict[str, Any]] = None,
            now: Optional[float] = None) -> RecoveryRun:
    """
    Move one step, with that step's precondition actually checked.

    Every precondition here is something a pile of restored bytes cannot assert on its own: a matching
    identity, a complete manifest, zero reconciliation conflicts, an attested environment, available root
    material, and - for activation - a FENCED or SUPERSEDED predecessor.
    """
    from ciph.kernel.backup_constitution import get_backup
    from ciph.kernel.recovery_manifest import verify_manifest
    from ciph.kernel.sovereign_identity import (RECOVERABLE, assert_identity_continuity,
                                                assess_recoverability, destruction_state_after_recovery)
    evidence = dict(evidence or {})
    moment = time.time() if now is None else float(now)
    run = get_run(db_path, run_id)
    if to_state not in VALID_STATES:
        raise CrucibleError("UNKNOWN_RECOVERY_STATE", str(to_state))
    # A HOLD is a PAUSE, not an ending: the honest resumption is to supply the missing fence and
    # proceed to AUTHORIZED_ACTIVATION. Every other failure state is terminal for THIS run - trying again
    # means a new run, which is the difference between resuming and rewriting.
    resuming = (run.status == RECOVERY_ACTIVATION_HOLD and to_state == AUTHORIZED_ACTIVATION)
    if run.status in FAILURE_STATES and to_state not in FAILURE_STATES and not resuming:
        raise CrucibleError(REASON_ILLEGAL, f"{run.status}->{to_state}")
    if to_state in LIFECYCLE and not resuming:
        expected = LIFECYCLE[LIFECYCLE.index(run.status) + 1] if run.status in LIFECYCLE else None
        if to_state != expected:
            raise CrucibleError(REASON_ILLEGAL, f"{run.status}->{to_state}")
    if to_state == IDENTITY_VERIFIED:
        identity_id = evidence.get("ciph_identity_id")
        if identity_id is None:
            raise CrucibleError(REASON_IDENTITY, "identity reference required")
        assert_identity_continuity(db_path, expected_identity_id=str(identity_id))
    elif to_state == STATE_VERIFIED:
        backup = get_backup(db_path, run.backup_id)
        completeness = verify_manifest(db_path, backup.manifest_id,
                                      present_families=evidence.get("present_families") or ())
        if completeness["status"] != "COMPLETE":
            return fail_run(db_path, run_id, INCOMPLETE,
                           detail=f"manifest {completeness['status']}", now=moment)
    elif to_state == RECONCILED:
        conflicts = int(evidence.get("reconciliation_conflicts", 0))
        if conflicts:
            return fail_run(db_path, run_id, INTEGRITY_CONFLICT,
                            detail=f"{conflicts} unresolved conflicts", now=moment)
    elif to_state == ENVIRONMENT_ATTESTED:
        if evidence.get("environment_digest") != run.target_environment_digest:
            return fail_run(db_path, run_id, REFUSED,
                            detail="environment attestation does not match the target", now=moment)
    elif to_state == READY:
        assessment = assess_recoverability(db_path, required_root_key_refs=evidence.get(
            "required_root_key_refs") or ())
        if assessment["status"] == "UNRECOVERABLE":
            return fail_run(db_path, run_id, UNRECOVERABLE, detail=assessment.get("reason"),
                            now=moment)
        if assessment["status"] != RECOVERABLE:
            return fail_run(db_path, run_id, KEY_UNAVAILABLE, detail=assessment.get("reason"),
                            now=moment)
        policy = destruction_state_after_recovery(db_path)
        evidence["destruction_state"] = policy
    elif to_state == AUTHORIZED_ACTIVATION:
        authorization = evidence.get("operator_authorization")
        if not authorization or not str(authorization).startswith("operator:"):
            raise CrucibleError(REASON_NOT_OPERATOR, str(authorization))
        disposition = str(evidence.get("fencing_disposition") or UNFENCED)
        if disposition not in (FENCED, SUPERSEDED) or not str(
                evidence.get("fencing_evidence_ref") or "").strip():
            return fail_run(db_path, run_id, RECOVERY_ACTIVATION_HOLD,
                            detail="prior authority is not fenced or superseded", now=moment)
    elif to_state == ACTIVATED:
        previous = activation_history(db_path)
        new_generation = (max([int(item["new_active_generation"]) for item in previous], default=0)) + 1
        activation_id = "RA-" + digest({"run": run_id, "generation": new_generation})[:16].upper()
        connection = _connect(db_path)
        try:
            init_schema(connection)
            connection.execute(
                "INSERT OR IGNORE INTO ciph_recovery_activations (activation_id, run_id, "
                "ciph_identity_id, previous_active_generation, new_active_generation, "
                "operator_authorization, fencing_disposition, fencing_evidence_ref, activated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?);",
                (activation_id, run_id, run.source_identity,
                 previous[-1]["new_active_generation"] if previous else None, new_generation,
                 str(evidence.get("operator_authorization")),
                 str(evidence.get("fencing_disposition")),
                 str(evidence.get("fencing_evidence_ref")), moment))
            connection.commit()
        finally:
            connection.close()
    history = list(run.history) + [to_state]
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_recovery_runs SET status = ?, history_json = ?, "
                           "detail = ?, updated_at = ? WHERE run_id = ?;",
                           (to_state, json.dumps(history),
                            json.dumps(evidence, default=str)[:2000], moment, str(run_id)))
        connection.commit()
    finally:
        connection.close()
    return get_run(db_path, run_id)


def fail_run(db_path: str, run_id: str, status: str, *, detail: Optional[str] = None,
             now: Optional[float] = None) -> RecoveryRun:
    if status not in FAILURE_STATES:
        raise CrucibleError("UNKNOWN_RECOVERY_FAILURE_STATE", str(status))
    moment = time.time() if now is None else float(now)
    run = get_run(db_path, run_id)
    history = list(run.history) + [status]
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_recovery_runs SET status = ?, history_json = ?, detail = ?, "
                           "updated_at = ? WHERE run_id = ?;",
                           (status, json.dumps(history), detail, moment, str(run_id)))
        connection.commit()
    finally:
        connection.close()
    return get_run(db_path, run_id)


def assess_fencing(*, prior_instance_fenced: bool, superseding_evidence_ref: Optional[str] = None,
                   assertion_only: bool = False) -> Dict[str, Any]:
    """
    Decide whether a restored copy may proceed past the authority question.

    An ASSERTION that the old instance is dead is not evidence, and it is exactly the reasoning that
    produces two authoritative Ciphers, so it lands in HOLD rather than in ACTIVATED.
    """
    if prior_instance_fenced:
        return {"disposition": FENCED, "may_activate": True}
    if superseding_evidence_ref and str(superseding_evidence_ref).strip():
        return {"disposition": SUPERSEDED, "may_activate": True,
                "evidence_ref": str(superseding_evidence_ref)}
    return {"disposition": UNFENCED, "may_activate": False, "required_state": RECOVERY_ACTIVATION_HOLD,
            "assertion_only": bool(assertion_only),
            "note": "a belief that the previous instance is gone is not a fence"}


def activation_history(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_recovery_activations ORDER BY activated_at, activation_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def recovery_runs(db_path: str) -> List[RecoveryRun]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["run_id"]) for row in connection.execute(
            "SELECT run_id FROM ciph_recovery_runs ORDER BY started_at, run_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_run(db_path, run_id) for run_id in ids]


# ---------------------------------------------------------------------------- clone versus restore
def register_clone(db_path: str, *, source_identity: str, purpose: str,
                   now: Optional[float] = None) -> Dict[str, Any]:
    """
    Register a copy that exists to be LOOKED AT. Its standing is NONE and there is no code path that
    raises it: not identical bytes, not identical source, not historical permits, not old operator
    grants, not old federation credentials.
    """
    moment = time.time() if now is None else float(now)
    clone_id = "CL-" + digest({"source": source_identity, "purpose": purpose,
                               "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_recovery_clones (clone_id, source_identity, "
                           "purpose, standing, registered_at) VALUES (?,?,?,?,?);",
                           (clone_id, str(source_identity), str(purpose), CLONE_STANDING_NONE,
                            moment))
        connection.commit()
    finally:
        connection.close()
    return clone_record(db_path, clone_id)


def clone_record(db_path: str, clone_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_recovery_clones WHERE clone_id = ?;",
                                 (str(clone_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_CLONE, str(clone_id))
    row = dict(row)
    return {"clone_id": str(row["clone_id"]), "source_identity": str(row["source_identity"]),
            "purpose": row["purpose"], "standing": str(row["standing"]),
            "production_authority": "none", "registered_at": row["registered_at"],
            "policy_version": RECOVERY_ACTIVATION_V1}


def assert_no_standing(db_path: str, clone_id: str) -> Dict[str, Any]:
    """The refusal a clone meets when anything asks it to act: it has no standing, by construction."""
    record = clone_record(db_path, clone_id)
    return {"clone_id": record["clone_id"], "standing": record["standing"],
            "may_activate": False, "reason": "a clone is a copy, not a continuation",
            "requires": "a separate RESTORE run with its own authorization and fencing"}


def clone_registry(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_recovery_clones ORDER BY registered_at, clone_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def recovery_digest(db_path: str) -> str:
    return digest({"version": RECOVERY_STATE_V1,
                   "runs": [item.as_dict() for item in recovery_runs(db_path)],
                   "activations": activation_history(db_path),
                   "clones": clone_registry(db_path)})
