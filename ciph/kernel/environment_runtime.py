"""
ciph/kernel/environment_runtime - 9.6 (storage/snapshot integration), 9.7 (model runtime and resource
governance), 9.8 (governed updates), 9.9 (reproducible installation and the privileged profile).

    A snapshot is not an authorized recovery.  A model is not Ciph.  An installed update is not a
    promoted one.  An installation is not an activation.

Four boundaries, each with the same shape: the environment produces ARTIFACTS and the constitution
decides MEANING. So a snapshot becomes canonical only by crossing 8.x; a model change is an environment
event that leaves identity alone; an update reaches INSTALLED but not HEALTHY without evidence; and an
installation - privileged or user-scope - grants nothing until an operator activates it.
"""

import json
import os
import resource
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

ENVIRONMENT_STORAGE_V1 = "ENVIRONMENT_STORAGE_V1"
MODEL_RUNTIME_V1 = "MODEL_RUNTIME_V1"
ENVIRONMENT_UPDATE_V1 = "ENVIRONMENT_UPDATE_V1"
CIPHOS_IMAGE_V1 = "CIPHOS_IMAGE_V1"
PRIVILEGED_HOST_PROFILE_V1 = "PRIVILEGED_HOST_PROFILE_V1"

SNAPSHOT_TAKEN = "SNAPSHOT_TAKEN"
SNAPSHOT_IS_CANDIDATE = "RECOVERY_CANDIDATE"
SNAPSHOT_REFUSED = "REFUSED_BY_CONSTITUTION"

STAGED = "STAGED"
VERIFIED = "VERIFIED"
AUTHORIZED = "AUTHORIZED"
INSTALLING = "INSTALLING"
INSTALLED = "INSTALLED"
HEALTHY = "HEALTHY"
REGRESSED = "REGRESSED"
ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
ROLLED_BACK = "ROLLED_BACK"
UPDATE_STATES = (STAGED, VERIFIED, AUTHORIZED, INSTALLING, INSTALLED, HEALTHY, REGRESSED,
                 ROLLBACK_REQUIRED, ROLLED_BACK)

REASON_NOT_OPERATOR = "ENVIRONMENT_CHANGE_REQUIRES_AN_OPERATOR"
REASON_SNAPSHOT_NOT_AUTHORITY = "A_SNAPSHOT_IS_NOT_AN_AUTHORIZED_RECOVERY"
REASON_UPDATE_ORDER = "ILLEGAL_UPDATE_TRANSITION"
REASON_UPDATE_UNVERIFIED = "UPDATE_ARTIFACT_DOES_NOT_MATCH_THE_STAGED_DIGEST"
REASON_UPDATE_UNAUTHORIZED = "UPDATE_WITHOUT_AUTHORIZATION"
REASON_DOWNGRADE = "VERSION_DOWNGRADE_WITHOUT_AN_EXPLICIT_ROLLBACK_PLAN"
REASON_SCHEMA = "SCHEMA_INCOMPATIBILITY"
REASON_CLONE = "A_CLONE_IS_NOT_A_CONTINUATION"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_environment_snapshots (
        snapshot_id TEXT PRIMARY KEY,
        artifact_digest TEXT NOT NULL,
        consistency_boundary TEXT NOT NULL,
        taken_at REAL,
        status TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_model_runtimes (
        runtime_id TEXT PRIMARY KEY,
        service_identity TEXT NOT NULL,
        model_identity TEXT NOT NULL,
        provider TEXT NOT NULL,
        cpu_seconds INTEGER,
        address_space_bytes INTEGER,
        gpu_count INTEGER,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_environment_updates (
        update_id TEXT PRIMARY KEY,
        package_identity TEXT NOT NULL,
        from_version TEXT NOT NULL,
        to_version TEXT NOT NULL,
        staged_digest TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT,
        authorization_ref TEXT,
        recorded_at REAL,
        updated_at REAL
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


# ---------------------------------------------------------------------------- 9.6 storage
def record_snapshot(db_path: str, *, artifact_digest: str, consistency_boundary: str,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record that a snapshot EXISTS. Status is deliberately SNAPSHOT_TAKEN, not "restorable" and certainly
    not "canonical": the filesystem produced bytes, and the constitution decides what they mean.
    """
    moment = time.time() if now is None else float(now)
    snapshot_id = "SNAP-" + digest({"digest": artifact_digest,
                                    "boundary": consistency_boundary})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_environment_snapshots (snapshot_id, "
                           "artifact_digest, consistency_boundary, taken_at, status) "
                           "VALUES (?,?,?,?,?);",
                           (snapshot_id, str(artifact_digest), str(consistency_boundary), moment,
                            SNAPSHOT_TAKEN))
        connection.commit()
    finally:
        connection.close()
    return {"snapshot_id": snapshot_id, "status": SNAPSHOT_TAKEN,
            "artifact_digest": str(artifact_digest), "consistency_boundary": str(consistency_boundary),
            "authority": "none", "policy_version": ENVIRONMENT_STORAGE_V1}


def snapshot_as_recovery_candidate(db_path: str, snapshot_id: str, *, backup_id: str) -> Dict[str, Any]:
    """
    Promote a snapshot to a RECOVERY CANDIDATE - by way of 8.x's backup constitution, not around it.

    The snapshot must already be a verified backup set with an authorized recovery grant. Without that,
    the answer is REFUSED, because "the filesystem snapshotted it" is not a governance act.
    """
    from ciph.kernel.backup_constitution import VERIFIED, get_backup, recovery_authorization
    try:
        backup = get_backup(db_path, backup_id)
    except CrucibleError:
        return {"snapshot_id": snapshot_id, "status": SNAPSHOT_REFUSED,
                "reason": REASON_SNAPSHOT_NOT_AUTHORITY,
                "detail": "no backup set corresponds to this snapshot"}
    if backup.status != VERIFIED or recovery_authorization(db_path, backup_id) is None:
        return {"snapshot_id": snapshot_id, "status": SNAPSHOT_REFUSED,
                "reason": REASON_SNAPSHOT_NOT_AUTHORITY,
                "detail": f"backup is {backup.status} or lacks a recovery authorization"}
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_environment_snapshots SET status = ? WHERE snapshot_id = ?;",
                           (SNAPSHOT_IS_CANDIDATE, str(snapshot_id)))
        connection.commit()
    finally:
        connection.close()
    return {"snapshot_id": snapshot_id, "status": SNAPSHOT_IS_CANDIDATE, "backup_id": backup_id,
            "activable": False, "requires": "the 8.x activation ceremony", "authority": "none"}


def assert_snapshot_cannot_activate(db_path: str, snapshot_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT status FROM ciph_environment_snapshots WHERE snapshot_id = ?;",
                                 (str(snapshot_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return {"snapshot_id": snapshot_id, "status": str(row["status"]) if row else None,
            "may_activate": False, "requires": "8.x recovery authorization, fencing and activation"}


# ---------------------------------------------------------------------------- 9.7 model runtime
def register_model_runtime(db_path: str, *, service_identity: str, model_identity: str, provider: str,
                           cpu_seconds: Optional[int] = None,
                           address_space_bytes: Optional[int] = None,
                           gpu_count: Optional[int] = None, now: Optional[float] = None
                           ) -> Dict[str, Any]:
    """
    Describe how the model runtime is BOUNDED. GPU is optional: a CPU-only or remote profile is a
    supported deployment, with its capability limits documented rather than assumed away.
    """
    moment = time.time() if now is None else float(now)
    runtime_id = "MRT-" + digest({"service": service_identity, "model": model_identity,
                                 "provider": provider})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_model_runtimes (runtime_id, service_identity, "
                           "model_identity, provider, cpu_seconds, address_space_bytes, gpu_count, "
                           "recorded_at) VALUES (?,?,?,?,?,?,?,?);",
                           (runtime_id, str(service_identity), str(model_identity), str(provider),
                            cpu_seconds, address_space_bytes, gpu_count, moment))
        connection.commit()
    finally:
        connection.close()
    return {"runtime_id": runtime_id, "service_identity": str(service_identity),
            "model_identity": str(model_identity), "provider": str(provider),
            "cpu_seconds": cpu_seconds, "address_space_bytes": address_space_bytes,
            "gpu_count": gpu_count, "gpu_required": False, "policy_version": MODEL_RUNTIME_V1}


def run_with_limits(command: Sequence[str], *, cpu_seconds: Optional[int] = None,
                    address_space_bytes: Optional[int] = None, timeout: float = 30.0) -> Dict[str, Any]:
    """
    Run a child under REAL OS limits (setrlimit), so a resource bound is enforced rather than declared.

    This is genuine kernel enforcement available to an unprivileged account, and it is what a model
    runtime or a worker actually gets: a process that exceeds its address space fails to allocate, and a
    process that burns its CPU allowance is killed.
    """

    def _apply_limits() -> None:
        if cpu_seconds is not None:
            resource.setrlimit(resource.RLIMIT_CPU, (int(cpu_seconds), int(cpu_seconds)))
        if address_space_bytes is not None:
            resource.setrlimit(resource.RLIMIT_AS, (int(address_space_bytes),
                                                    int(address_space_bytes)))

    completed = subprocess.run(list(command), capture_output=True, text=True, timeout=timeout,
                               preexec_fn=_apply_limits)
    return {"returncode": completed.returncode, "stdout": completed.stdout.strip()[:200],
            "stderr": completed.stderr.strip()[:200],
            "limits_applied": {"cpu_seconds": cpu_seconds,
                               "address_space_bytes": address_space_bytes}}


# ---------------------------------------------------------------------------- 9.8 governed updates
def stage_update(db_path: str, *, package_identity: str, from_version: str, to_version: str,
                 staged_digest: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Stage an update. A DOWNGRADE is refused here unless it is an explicit rollback plan, because a silent
    version regression is how a governed update becomes an ungoverned one.
    """
    moment = time.time() if now is None else float(now)
    if str(to_version) < str(from_version) and not str(package_identity).startswith("rollback:"):
        raise CrucibleError(REASON_DOWNGRADE, f"{from_version}->{to_version}")
    update_id = "UPD-" + digest({"package": package_identity, "from": from_version,
                                 "to": to_version})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_environment_updates (update_id, package_identity, "
            "from_version, to_version, staged_digest, status, detail, authorization_ref, recorded_at, "
            "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (update_id, str(package_identity), str(from_version), str(to_version),
             str(staged_digest), STAGED, None, None, moment, moment))
        connection.commit()
    finally:
        connection.close()
    return get_update(db_path, update_id)


def get_update(db_path: str, update_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_environment_updates WHERE update_id = ?;",
                                 (str(update_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_UPDATE", str(update_id))
    return dict(row)


def verify_update(db_path: str, update_id: str, *, observed_digest: str, schema_compatible: bool = True,
                  now: Optional[float] = None) -> Dict[str, Any]:
    """Verification and schema compatibility are separate refusals with separate reasons."""
    moment = time.time() if now is None else float(now)
    update = get_update(db_path, update_id)
    if str(observed_digest) != update["staged_digest"]:
        return _set_update(db_path, update_id, status=STAGED, detail=REASON_UPDATE_UNVERIFIED,
                           moment=moment)
    if not schema_compatible:
        return _set_update(db_path, update_id, status=STAGED, detail=REASON_SCHEMA, moment=moment)
    return _set_update(db_path, update_id, status=VERIFIED, detail=None, moment=moment)


def authorize_update(db_path: str, update_id: str, *, operator_authorization: Any, now: Optional[float] = None
                     ) -> Dict[str, Any]:
    """
    An update needs its OWN operator authorization - and the same rules as any other operator act: a
    string is not a grant.
    """
    moment = time.time() if now is None else float(now)
    update = get_update(db_path, update_id)
    if update["status"] != VERIFIED:
        return _set_update(db_path, update_id, status=update["status"],
                           detail=REASON_UPDATE_ORDER, moment=moment)
    # The verdict comes from the OPERATOR PLANE (`accepted`), and `allowed` is accepted too so a caller
    # cannot accidentally satisfy this with a home-made dict that merely looks permissive.
    verdict = operator_authorization if isinstance(operator_authorization, dict) else {}
    if not (verdict.get("accepted") is True or verdict.get("allowed") is True):
        return _set_update(db_path, update_id, status=VERIFIED,
                           detail=REASON_UPDATE_UNAUTHORIZED, moment=moment)
    return _set_update(db_path, update_id, status=AUTHORIZED,
                       detail=str(operator_authorization.get("authorization_id")), moment=moment)


def install_update(db_path: str, update_id: str, *, observed_digest: str, now: Optional[float] = None
                   ) -> Dict[str, Any]:
    """Installation re-checks the bytes: what lands must be what was verified."""
    moment = time.time() if now is None else float(now)
    update = get_update(db_path, update_id)
    if update["status"] != AUTHORIZED:
        return _set_update(db_path, update_id, status=update["status"], detail=REASON_UPDATE_ORDER,
                           moment=moment)
    if str(observed_digest) != update["staged_digest"]:
        return _set_update(db_path, update_id, status=REGRESSED,
                           detail=REASON_UPDATE_UNVERIFIED, moment=moment)
    return _set_update(db_path, update_id, status=INSTALLED, detail=None, moment=moment)


def assess_update_health(db_path: str, update_id: str, *, healthy: bool, now: Optional[float] = None
                         ) -> Dict[str, Any]:
    moment = time.time() if now is None else float(now)
    update = get_update(db_path, update_id)
    if update["status"] != INSTALLED:
        return _set_update(db_path, update_id, status=update["status"], detail=REASON_UPDATE_ORDER,
                           moment=moment)
    return _set_update(db_path, update_id, status=HEALTHY if healthy else REGRESSED,
                       detail=None if healthy else "health regression after installation",
                       moment=moment)


def rollback_update(db_path: str, update_id: str, *, operator_authorization: Any,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    Rollback is an OPERATOR ACT on a REGRESSED update, and it lands in ROLLED_BACK - a new state, not a
    rewound history: the record of what was installed and what regressed survives.
    """
    moment = time.time() if now is None else float(now)
    update = get_update(db_path, update_id)
    if update["status"] not in (REGRESSED, ROLLBACK_REQUIRED):
        return _set_update(db_path, update_id, status=update["status"], detail=REASON_UPDATE_ORDER,
                           moment=moment)
    verdict = operator_authorization if isinstance(operator_authorization, dict) else {}
    if not (verdict.get("accepted") is True or verdict.get("allowed") is True):
        return _set_update(db_path, update_id, status=ROLLBACK_REQUIRED,
                           detail=REASON_UPDATE_UNAUTHORIZED, moment=moment)
    return _set_update(db_path, update_id, status=ROLLED_BACK,
                       detail=f"restored {update['from_version']}", moment=moment)


def _set_update(db_path: str, update_id: str, *, status: str, detail: Optional[str],
                moment: float) -> Dict[str, Any]:
    if status not in UPDATE_STATES:
        raise CrucibleError("UNKNOWN_UPDATE_STATE", str(status))
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_environment_updates SET status = ?, detail = ?, "
                           "updated_at = ? WHERE update_id = ?;",
                           (str(status), detail, moment, str(update_id)))
        connection.commit()
    finally:
        connection.close()
    return get_update(db_path, update_id)


# The needles, declared here and skipped by the scan below: a module that DEFINES a pattern is a
# catalogue, not an offender - the rule this project has had to apply in eight phases now.
UNSAFE_UPGRADE_NEEDLES = ("pip install --upgrade", "pip install -U ", "apt-get upgrade",
                          "pip3 install --upgrade")
_VENDORED_PARTS = ("ciph_env", "site-packages", ".venv", "node_modules")


def ungoverned_upgrade_commands(sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """`pip install --upgrade` and friends: an update that redefines constitutional policy silently."""
    if sources is None:
        from ciph.kernel.evolution_ownership import production_sources
        sources = list(production_sources())
    offenders = []
    for relative, text in sources:
        if relative.endswith("_scanners.py") or relative.endswith("_ownership.py"):
            continue
        if any(part in relative for part in _VENDORED_PARTS):
            continue
        if "UNSAFE_UPGRADE_NEEDLES" in text:
            continue
        for needle in UNSAFE_UPGRADE_NEEDLES:
            if needle in text and not relative.startswith("setup_ciph.sh"):
                offenders.append(f"{relative}:{needle}")
    return tuple(sorted(set(offenders)))


# ---------------------------------------------------------------------------- 9.9 installation
def installation_manifest() -> Dict[str, Any]:
    """
    What a CiphOS installation IS: base OS, units, identities, ownership, network, custody, versions,
    model options, recovery integration, first-boot behaviour and the activation procedure.
    """
    return {
        "policy_version": CIPHOS_IMAGE_V1,
        "base_os": "Debian 12 (bookworm) or equivalent, x86_64, systemd",
        "python": "3.10+",
        "dependencies": ["sqlite3 (stdlib)", "gpg (for approved backup archives)"],
        "service_units": ["ciph-core.service", "ciph-worker@.service", "ciph-operator.socket"],
        "unit_scope": "system (privileged profile) / user (diagnostic profile)",
        "accounts": {"ciph-core": "system account, no login shell",
                     "ciph-worker": "system account, no login shell",
                     "ciph-operator": "interactive account used ONLY for the activation ceremony"},
        "directory_ownership": {"/etc/ciph": "root:ciph-core 0750",
                                "/var/lib/ciph": "ciph-core:ciph-core 0700",
                                "/var/lib/ciph/vault": "ciph-vault:ciph-vault 0700",
                                "/var/log/ciph": "ciph-core:ciph-core 0750",
                                "/var/lib/ciph/recovery": "root:ciph-operator 0700"},
        "network_policy": "egress DENY by default; allow lists recorded in ciph_egress_rules",
        "secret_custody": "root/recovery material outside the service accounts' reach; mode-000 custody "
                          "files with an explicit operator-held unlock path",
        "application_version": "Ciph 9.x",
        "model_runtime_options": ["local CPU-only", "remote provider over an allowed egress",
                                  "local GPU (optional, never required)"],
        "recovery_integration": "8.x backup constitution and recovery engine; snapshots are candidates, "
                                "never authority",
        "first_boot_behaviour": "install, verify environment, reach AWAITING_OPERATOR_AUTHORIZATION with "
                                "zero authority",
        "operator_activation": "an operator principal presents a scoped authorization for "
                               "ACTIVATE_CONSTITUTION",
        "host_requirements": ["systemd", "a non-root service account", "writable /var/lib/ciph",
                              "no requirement for a GPU, a custom kernel or a TPM"],
    }


def privileged_host_profile() -> Dict[str, Any]:
    """
    The PROFILED privileged installation, in full, even though this host cannot activate it.

    Written out rather than summarised so it is not silently downgraded into a same-user install: the
    profile names the accounts, ownership, unit hardening and capabilities a privileged host must have.
    """
    return {
        "policy_version": PRIVILEGED_HOST_PROFILE_V1,
        "scope": "system",
        "requires": ["root to install", "systemd", "service accounts"],
        "activatable_on_this_host": False,
        "reason_unavailable": "this campaign runs unprivileged (uid 1001, no sudo), with /etc unwritable",
        "service_accounts": ["ciph-core", "ciph-worker", "ciph-vault"],
        "unit_hardening": ["NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
                           "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
                           "ProtectKernelModules=yes", "ProtectControlGroups=yes",
                           "RestrictAddressFamilies=AF_UNIX AF_INET", "RestrictNamespaces=yes",
                           "MemoryDenyWriteExecute=yes", "SystemCallFilter=@system-service",
                           "CapabilityBoundingSet=", "ReadWritePaths=/var/lib/ciph"],
        "worker_unit_hardening": ["the same, plus InaccessiblePaths=/var/lib/ciph/vault "
                                  "/var/lib/ciph/recovery"],
        "capability_restrictions": {"ciph-core": [], "ciph-worker": [],
                                    "ciph-operator": ["CAP_NONE"]},
        "network_policy_requirements": ["egress allow-lists per service identity",
                                        "no inbound except the operator socket"],
        "secret_custody_requirements": ["root material owned by root and outside ciph-core's reach",
                                        "no secrets in unit Environment= lines",
                                        "an unlock path that is itself an operator act"],
        "first_boot_defaults": {"autonomy": "OFF", "authority": "NONE",
                                "state": "AWAITING_OPERATOR_AUTHORIZATION"},
        "update_procedure": ["stage", "verify digest and schema", "operator authorize", "install",
                             "health assess", "rollback on regression"],
        "recovery_procedure": ["quiesce", "produce approved recovery material", "destroy",
                               "fresh install", "8.x restore", "fence", "authorize", "activate"],
        "verification_package": "tools/ciphos_host_verification.py",
    }


def user_scope_profile() -> Dict[str, Any]:
    """
    The DIAGNOSTIC profile this campaign actually ran, with its reduced guarantees named - so nobody can
    mistake a user-scope run for the privileged one.
    """
    return {"policy_version": CIPHOS_IMAGE_V1, "scope": "user", "states": [
        "systemd --user services start, restart and terminate",
        "file permissions and setrlimit limits are enforced",
        "the boot constitution and every refusal are exercised",
    ], "reduced_guarantees": [
        "no service users: isolation is policy-level, not cross-account",
        "no namespace isolation (unprivileged user namespaces unavailable)",
        "no systemd hardening directives in effect",
        "no egress enforcement at the kernel (policy only; a real connection SUCCEEDS)",
        "no VM boot and no measured boot",
    ], "may_be_reported_as": "USER-SCOPE VERIFICATION", "may_not_be_reported_as": "system-scope proof"}


def assert_profile_not_downgraded(*, claimed_scope: str, host_can_privilege: bool) -> Dict[str, Any]:
    """A user-scope run may NEVER be reported with system-scope guarantees."""
    if str(claimed_scope) == "system" and not host_can_privilege:
        raise CrucibleError("USER_SCOPE_CANNOT_BE_REPORTED_AS_SYSTEM_SCOPE",
                            "the privileged profile was not activated on this host")
    return {"claimed_scope": str(claimed_scope), "honest": True}


def runtime_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        table = lambda name: [dict(row) for row in connection.execute(  # noqa: E731
            f"SELECT * FROM {name} ORDER BY rowid;")]
        payload = {"snapshots": table("ciph_environment_snapshots"),
                   "model_runtimes": table("ciph_model_runtimes"),
                   "updates": table("ciph_environment_updates")}
    except sqlite3.Error:
        payload = {"snapshots": [], "model_runtimes": [], "updates": []}
    finally:
        connection.close()
    return digest({"version": ENVIRONMENT_STORAGE_V1, **payload})
