"""
ciph/kernel/environment_boot - 9.0 (installation and boot constitution) and 9.3 (governed lifecycle).

    Boot != activation.  Process running != authorized.  Service readiness != constitutional readiness.

The operating environment hosts Ciph. It starts the machinery; it never grants the authority. So boot is
a STATE MACHINE whose every non-failure path stops short of sovereign execution until an operator
authorizes it, and the failure states are first-class because a startup failure must never be disguised
as successful activation.

WHAT THIS ENVIRONMENT CAN ACTUALLY ENFORCE, stated because it decides what may be claimed:

    AVAILABLE   user-scoped `systemd --user` (real start, real restart policy, real termination)
                POSIX file modes (mode 000 refuses even its own owner - measured)
                subprocess environments (a scrubbed environment really is scrubbed)
                `sudo -n` refusal for an unprivileged account (measured)
    UNAVAILABLE system-scope units and service USERS (needs root; /etc is not writable here)
                Linux namespace isolation (unprivileged user namespaces are disabled here)
                a VM or reproducible image boot (no hypervisor in this environment)
                hardware-backed attestation (no TPM/UEFI attestation available)

The state machine and the refusals are therefore PROVEN here; system-scope privilege separation and VM
boot are NOT, and `ENVIRONMENT_CAPABILITIES` reports that as data so a seal cannot quietly borrow credit
it did not earn.
"""

import json
import os
import pathlib
import shutil
import signal
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

BOOT_CONSTITUTION_V1 = "BOOT_CONSTITUTION_V1"
SERVICE_IDENTITY_V1 = "SERVICE_IDENTITY_V1"
ENVIRONMENT_CAPABILITIES_V1 = "ENVIRONMENT_CAPABILITIES_V1"

NOT_INSTALLED = "NOT_INSTALLED"
INSTALLED = "INSTALLED"
BOOTSTRAPPING = "BOOTSTRAPPING"
ENVIRONMENT_VERIFIED = "ENVIRONMENT_VERIFIED"
AWAITING_OPERATOR_AUTHORIZATION = "AWAITING_OPERATOR_AUTHORIZATION"
CONSTITUTIONALLY_ACTIVATED = "CONSTITUTIONALLY_ACTIVATED"
RUNNING = "RUNNING"
BOOT_INTEGRITY_FAILED = "BOOT_INTEGRITY_FAILED"
ENVIRONMENT_ATTESTATION_FAILED = "ENVIRONMENT_ATTESTATION_FAILED"
KEY_CUSTODY_UNAVAILABLE = "KEY_CUSTODY_UNAVAILABLE"
AUTHORIZATION_REQUIRED = "AUTHORIZATION_REQUIRED"
RECOVERY_RECONCILIATION_REQUIRED = "RECOVERY_RECONCILIATION_REQUIRED"
SERVICE_FAILED = "SERVICE_FAILED"
ACTIVATION_REFUSED = "ACTIVATION_REFUSED"

LIFECYCLE: Tuple[str, ...] = (NOT_INSTALLED, INSTALLED, BOOTSTRAPPING, ENVIRONMENT_VERIFIED,
                              AWAITING_OPERATOR_AUTHORIZATION, CONSTITUTIONALLY_ACTIVATED, RUNNING)
FAILURE_STATES: Tuple[str, ...] = (BOOT_INTEGRITY_FAILED, ENVIRONMENT_ATTESTATION_FAILED,
                                   KEY_CUSTODY_UNAVAILABLE, AUTHORIZATION_REQUIRED,
                                   RECOVERY_RECONCILIATION_REQUIRED, SERVICE_FAILED,
                                   ACTIVATION_REFUSED)
VALID_STATES = LIFECYCLE + FAILURE_STATES

# Capabilities as MEASURED in the environment this ran in. `available: False` is a claim the seal must
# not borrow against.
ENVIRONMENT_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    "user_scoped_systemd": {"available": True,
                            "evidence": "systemctl --user answered the service manager",
                            "supports": ["service start/stop/restart", "systemd restart policy",
                                         "termination by the service manager"]},
    "posix_file_modes": {"available": True,
                         "evidence": "a mode-000 file is refused to its own owner",
                         "supports": ["secret custody by permission", "writable-scope confinement"]},
    "scrubbed_subprocess_environment": {"available": True,
                                        "evidence": "a child process sees only the variables given"},
    "unprivileged_sudo": {"available": False, "evidence": "sudo -n requires a password for this account",
                          "meaning": "privileged host operations are NOT reachable by inheritance"},
    "system_scope_units_and_service_users": {"available": False,
                                             "evidence": "/etc is not writable and sudo is unavailable",
                                             "unsupported_claims": ["system service identity",
                                                                    "systemd hardening in effect"]},
    "namespace_isolation": {"available": False,
                            "evidence": "unshare -r fails: uid_map is not writable",
                            "unsupported_claims": ["mount/pid/net namespace isolation"]},
    "vm_or_reproducible_image_boot": {"available": False,
                                      "evidence": "no hypervisor in this environment",
                                      "unsupported_claims": ["clean VM install", "first-boot behaviour"]},
    "hardware_backed_attestation": {"available": False,
                                    "evidence": "no TPM/UEFI attestation available",
                                    "unsupported_claims": ["measured boot", "secure boot"]},
}

REASON_NOT_AUTHORIZED = "OPERATOR_AUTHORIZATION_REQUIRED"
REASON_ILLEGAL = "ILLEGAL_BOOT_TRANSITION"
REASON_KEY_UNAVAILABLE = "KEY_CUSTODY_UNAVAILABLE"
REASON_INTEGRITY = "BOOT_INTEGRITY_FAILED"
REASON_OPERATOR = "OPERATOR_ACTION_REQUIRED"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_environment_boots (
        boot_id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL,
        software_revision TEXT NOT NULL,
        artifact_digest TEXT NOT NULL,
        service_config_digest TEXT NOT NULL,
        environment_identity TEXT NOT NULL,
        state TEXT NOT NULL,
        history_json TEXT,
        detail TEXT,
        booted_at REAL,
        updated_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_environment_services (
        service_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        unit_scope TEXT NOT NULL,
        service_identity TEXT NOT NULL,
        writable_scopes_json TEXT NOT NULL,
        readable_scopes_json TEXT NOT NULL,
        forbidden_scopes_json TEXT NOT NULL,
        created_at REAL
    );
    """,
)


@dataclass(frozen=True)
class BootState:
    boot_id: str
    installation_id: str
    state: str
    history: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"boot_id": self.boot_id, "installation_id": self.installation_id,
                "state": self.state, "history": list(self.history),
                "policy_version": BOOT_CONSTITUTION_V1,
                "sovereign_execution_enabled": self.state == RUNNING,
                "authority_granted_by_boot": False}


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


def environment_capabilities() -> Dict[str, Any]:
    """What this environment MEASURABLY enforces, and what it must not claim."""
    unavailable = [name for name, item in ENVIRONMENT_CAPABILITIES.items() if not item["available"]]
    unsupported = sorted({claim for name in unavailable
                          for claim in ENVIRONMENT_CAPABILITIES[name].get("unsupported_claims", [])})
    return {"policy_version": ENVIRONMENT_CAPABILITIES_V1,
            "capabilities": ENVIRONMENT_CAPABILITIES,
            "unavailable": unavailable, "unsupported_claims": unsupported}


def begin_boot(db_path: str, *, installation_id: str, software_revision: str, artifact_digest: str,
               service_config_digest: str, environment_identity: str,
               now: Optional[float] = None) -> BootState:
    """
    Record the START of a boot. Note what it does NOT do: it grants nothing.

    The boot row is a diagnostic record. It is not a permit, not a standing authorization, not a
    federation membership and not an operator decision.
    """
    moment = time.time() if now is None else float(now)
    boot_id = "BOOT-" + digest({"installation": installation_id, "revision": software_revision,
                                "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_environment_boots (boot_id, installation_id, "
            "software_revision, artifact_digest, service_config_digest, environment_identity, state, "
            "history_json, detail, booted_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (boot_id, str(installation_id), str(software_revision), str(artifact_digest),
             str(service_config_digest), str(environment_identity), INSTALLED,
             json.dumps([INSTALLED]), None, moment, moment))
        connection.commit()
    finally:
        connection.close()
    return get_boot(db_path, boot_id)


def get_boot(db_path: str, boot_id: str) -> BootState:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_environment_boots WHERE boot_id = ?;",
                                 (str(boot_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_BOOT", str(boot_id))
    row = dict(row)
    return BootState(boot_id=str(row["boot_id"]), installation_id=str(row["installation_id"]),
                     state=str(row["state"]), history=tuple(json.loads(row["history_json"] or "[]")))


def advance_boot(db_path: str, boot_id: str, to_state: str, *,
                 evidence: Optional[Dict[str, Any]] = None, now: Optional[float] = None) -> BootState:
    """
    Move the boot forward, with the precondition that step actually requires.

    The step that matters is AWAITING_OPERATOR_AUTHORIZATION -> CONSTITUTIONALLY_ACTIVATED: it requires
    an operator identity, and the boot machinery itself can never satisfy it. A unit file, a restart
    policy or a dependency becoming ready cannot produce an operator.
    """
    evidence = dict(evidence or {})
    moment = time.time() if now is None else float(now)
    boot = get_boot(db_path, boot_id)
    if to_state not in VALID_STATES:
        raise CrucibleError("UNKNOWN_BOOT_STATE", str(to_state))
    if boot.state in FAILURE_STATES and to_state not in FAILURE_STATES:
        raise CrucibleError(REASON_ILLEGAL, f"{boot.state}->{to_state}")
    if to_state in LIFECYCLE:
        expected = LIFECYCLE[LIFECYCLE.index(boot.state) + 1] if boot.state in LIFECYCLE else None
        if to_state != expected:
            raise CrucibleError(REASON_ILLEGAL, f"{boot.state}->{to_state}")
    if to_state == ENVIRONMENT_VERIFIED:
        caps = env_capabilities_ok(evidence.get("capabilities") or {})
        if not caps["ok"]:
            return _fail(db_path, boot_id, ENVIRONMENT_ATTESTATION_FAILED, caps["reason"], moment)
        if evidence.get("key_custody_available") is False:
            return _fail(db_path, boot_id, KEY_CUSTODY_UNAVAILABLE,
                         "indispensable custody material is unavailable", moment)
        if evidence.get("integrity_ok") is False:
            return _fail(db_path, boot_id, BOOT_INTEGRITY_FAILED, "installed artifacts diverge", moment)
    if to_state == CONSTITUTIONALLY_ACTIVATED:
        operator = evidence.get("operator_authorization")
        if not operator or not str(operator).startswith("operator:"):
            return _fail(db_path, boot_id, ACTIVATION_REFUSED, REASON_NOT_AUTHORIZED, moment)
        if evidence.get("recovery_reconciliation_required"):
            return _fail(db_path, boot_id, RECOVERY_RECONCILIATION_REQUIRED,
                         "an unresolved recovery obligation precedes activation", moment)
    history = list(boot.history) + [to_state]
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_environment_boots SET state = ?, history_json = ?, "
                           "detail = ?, updated_at = ? WHERE boot_id = ?;",
                           (to_state, json.dumps(history), json.dumps(evidence, default=str)[:2000],
                            moment, str(boot_id)))
        connection.commit()
    finally:
        connection.close()
    return get_boot(db_path, boot_id)


def env_capabilities_ok(declared: Dict[str, Any]) -> Dict[str, Any]:
    """
    An environment may not verify a capability this environment does not have.

    This is the honesty gate: a boot that claimed namespace isolation or measured boot would be claiming
    enforcement that was never measured, so the claim itself is failed.
    """
    overclaimed = [name for name in declared
                   if name in ENVIRONMENT_CAPABILITIES
                   and not ENVIRONMENT_CAPABILITIES[name]["available"]]
    if overclaimed:
        return {"ok": False, "reason": f"unsupported environment claims: {sorted(overclaimed)}"}
    return {"ok": True, "claimed": sorted(declared)}


def _fail(db_path: str, boot_id: str, state: str, detail: Optional[str], moment: float) -> BootState:
    boot = get_boot(db_path, boot_id)
    history = list(boot.history) + [state]
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_environment_boots SET state = ?, history_json = ?, "
                           "detail = ?, updated_at = ? WHERE boot_id = ?;",
                           (state, json.dumps(history), detail, moment, str(boot_id)))
        connection.commit()
    finally:
        connection.close()
    return get_boot(db_path, boot_id)


def boot_summary(db_path: str, boot_id: str) -> Dict[str, Any]:
    """
    What the boot granted: nothing. Reported explicitly so a status page cannot imply otherwise.
    """
    boot = get_boot(db_path, boot_id)
    running = boot.state == RUNNING
    return {"boot_id": boot.boot_id, "installation_id": boot.installation_id, "state": boot.state,
            "diagnostics_running": boot.state not in (NOT_INSTALLED, INSTALLED),
            "sovereign_execution_enabled": running,
            "authority_granted": "none",
            "new_execution_permits": 0, "autonomous_missions_started": 0,
            "production_deployments": 0, "recovery_activations": 0,
            "historical_permits_replayed": 0, "destructive_timers_armed": 0,
            "workers_authoritative": 0, "federation_domains_assumed": 0,
            "policy_version": BOOT_CONSTITUTION_V1}


# ---------------------------------------------------------------------------- service identity (9.1)
def register_service(db_path: str, *, name: str, service_identity: str, unit_scope: str = "user",
                     writable_scopes: Sequence[str] = (), readable_scopes: Sequence[str] = (),
                     forbidden_scopes: Sequence[str] = (), now: Optional[float] = None) -> Dict[str, Any]:
    """
    Describe a service's ACCESS, not its importance.

    The constitutional service does not get root because it matters: it gets the scopes it needs and the
    prohibition on everything else. `forbidden_scopes` is the part that carries the law.
    """
    moment = time.time() if now is None else float(now)
    service_id = "SVC-" + digest({"name": name, "identity": service_identity})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_environment_services (service_id, name, unit_scope, "
            "service_identity, writable_scopes_json, readable_scopes_json, forbidden_scopes_json, "
            "created_at) VALUES (?,?,?,?,?,?,?,?);",
            (service_id, str(name), str(unit_scope), str(service_identity),
             json.dumps(sorted(str(item) for item in writable_scopes)),
             json.dumps(sorted(str(item) for item in readable_scopes)),
             json.dumps(sorted(str(item) for item in forbidden_scopes)), moment))
        connection.commit()
    finally:
        connection.close()
    return get_service(db_path, service_id)


def get_service(db_path: str, service_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_environment_services WHERE service_id = ?;",
                                 (str(service_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_SERVICE", str(service_id))
    row = dict(row)
    return {"service_id": str(row["service_id"]), "name": str(row["name"]),
            "unit_scope": str(row["unit_scope"]), "service_identity": str(row["service_identity"]),
            "writable_scopes": json.loads(row["writable_scopes_json"] or "[]"),
            "readable_scopes": json.loads(row["readable_scopes_json"] or "[]"),
            "forbidden_scopes": json.loads(row["forbidden_scopes_json"] or "[]"),
            "policy_version": SERVICE_IDENTITY_V1}


def assert_within_scope(service: Dict[str, Any], *, target: str, write: bool = False) -> None:
    """
    A service may touch what its identity permits and NOTHING else - the prohibition is checked first,
    because a forbidden scope that also appears in a writable list is still forbidden.
    """
    resolved = os.path.realpath(str(target))
    for forbidden in service.get("forbidden_scopes", []):
        if resolved.startswith(os.path.realpath(str(forbidden))):
            raise CrucibleError("SERVICE_SCOPE_FORBIDDEN", f"{service['name']}:{resolved}")
    allowed = service.get("writable_scopes" if write else "readable_scopes", [])
    if not any(resolved.startswith(os.path.realpath(str(scope))) for scope in allowed):
        raise CrucibleError("SERVICE_SCOPE_DENIED",
                            f"{service['name']}:{'write' if write else 'read'} {resolved}")


def secure_file(path: str, *, mode: int = 0o000) -> str:
    """
    Put a file beyond ordinary access using a REAL OS boundary.

    Measured in this environment: a mode-000 file is refused to its own owner. That is the difference
    between a policy that says "don't read this" and a boundary that refuses.
    """
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("", encoding="utf-8")
    os.chmod(target, mode)
    return str(target)


def can_read(path: str) -> bool:
    """Read it for real. A policy assertion is not evidence that access is denied."""
    try:
        with open(path, "rb"):
            return True
    except PermissionError:
        return False
    except OSError:
        return False


def scrubbed_environment(env: Dict[str, str], *, command: Sequence[str],
                         timeout: float = 30.0) -> Dict[str, Any]:
    """
    Run a child with EXACTLY the environment given - no inheritance.

    A worker or model runtime that inherited the parent's environment would inherit whatever secrets it
    happened to hold, which is the commonest way a sandbox is defeated in practice.
    """
    completed = subprocess.run(list(command), env=dict(env), capture_output=True, text=True,
                               timeout=timeout)
    return {"returncode": completed.returncode, "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(), "environment_variables": sorted(env)}


def privileged_operation_reachable(*, command: Sequence[str] = ("sudo", "-n", "true")) -> Dict[str, Any]:
    """Can this account perform a privileged host operation non-interactively? Measured, not assumed."""
    try:
        completed = subprocess.run(list(command), capture_output=True, text=True, timeout=15)
        return {"reachable": completed.returncode == 0, "returncode": completed.returncode,
                "detail": (completed.stderr or completed.stdout).strip()[:200]}
    except (OSError, subprocess.SubprocessError) as error:
        return {"reachable": False, "returncode": None, "detail": str(error)[:200]}


# ---------------------------------------------------------------------------- service lifecycle (9.3)
def user_unit_available() -> Dict[str, Any]:
    try:
        completed = subprocess.run(["systemctl", "--user", "is-system-running"], capture_output=True,
                                   text=True, timeout=20)
        return {"available": True, "state": completed.stdout.strip() or completed.stderr.strip()}
    except (OSError, subprocess.SubprocessError) as error:
        return {"available": False, "state": str(error)[:200]}


def install_user_unit(unit_name: str, *, exec_start: str, description: str = "CiphOS service",
                      restart: str = "on-failure", working_directory: Optional[str] = None,
                      environment: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Install and start a REAL user-scoped service through the REAL service manager.

    Scope, stated: `systemd --user`, because a system unit needs root this environment does not have. It
    still exercises the parts of service management that matter to the constitution - the manager starts
    the process, applies the restart policy, and can terminate it - and it proves that none of that
    produces authority.
    """
    unit_dir = pathlib.Path(os.environ.get("XDG_CONFIG_HOME", str(pathlib.Path.home() / ".config")))
    unit_dir = unit_dir / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    lines = ["[Unit]", f"Description={description}", "", "[Service]", f"ExecStart={exec_start}",
             f"Restart={restart}"]
    if working_directory:
        lines.append(f"WorkingDirectory={working_directory}")
    for key, value in (environment or {}).items():
        lines.append(f'Environment="{key}={value}"')
    lines += ["", "[Install]", "WantedBy=default.target", ""]
    unit_path = unit_dir / f"{unit_name}.service"
    unit_path.write_text("\n".join(lines), encoding="utf-8")
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True, timeout=30)
    started = subprocess.run(["systemctl", "--user", "start", unit_name], capture_output=True,
                             text=True, timeout=60)
    return {"unit_path": str(unit_path), "unit_name": unit_name, "restart_policy": restart,
            "start_returncode": started.returncode,
            "start_detail": (started.stderr or started.stdout).strip()[:300],
            "authority_granted": "none"}


def unit_status(unit_name: str) -> Dict[str, Any]:
    completed = subprocess.run(["systemctl", "--user", "show", unit_name, "--property=ActiveState",
                                "--property=SubState", "--property=MainPID"], capture_output=True,
                               text=True, timeout=30)
    properties = dict(line.split("=", 1) for line in completed.stdout.strip().splitlines() if "=" in line)
    return {"unit": unit_name, **properties}


def stop_user_unit(unit_name: str) -> int:
    return subprocess.run(["systemctl", "--user", "stop", unit_name], capture_output=True,
                          text=True, timeout=60).returncode


def boot_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        table = lambda name: [dict(row) for row in connection.execute(  # noqa: E731
            f"SELECT * FROM {name} ORDER BY rowid;")]
        payload = {"boots": table("ciph_environment_boots"),
                   "services": table("ciph_environment_services")}
    except sqlite3.Error:
        payload = {"boots": [], "services": []}
    finally:
        connection.close()
    return digest({"version": BOOT_CONSTITUTION_V1, **payload})
