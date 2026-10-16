"""
ciph/kernel/environment_operator - 9.4 (operator control plane) and 9.5 (egress and stale-host effects).

    Authentication alone does not authorize arbitrary actions.
    A service cannot grant itself operator authority.

9.4 makes the operator a REAL thing: an authenticated principal whose authorization is
OPERATION-SPECIFIC, SCOPE-BOUND, CURRENT and REVOCABLE. The refusals are the substance - wrong credential,
expired, replayed generation, wrong generation, wrong Ciph identity, wrong environment, revoked, or a
worker asking for activation.

9.5 carries R13's isolated-stale-host finding into enforcement. Two kinds of effect, two honest answers:

    EXTERNALLY GOVERNED   the resource refuses stale authority - enforceable HERE, at the policy layer,
                          and enforceable for real wherever the resource checks (the 8.x execution
                          boundary does; a foreign API only if it checks).
    PURELY LOCAL          an unreachable host keeps physical control. Bounded by OS permissions where the
                          host can enforce them, and otherwise documented as residual physical control -
                          NEVER reported as constitutional success.

The ambient environment is not a credential: a copied session token, a hardcoded string, a settable env
variable and a successful process start are each tested as REFUSED.
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

OPERATOR_CONTROL_PLANE_V1 = "OPERATOR_CONTROL_PLANE_V1"
EGRESS_POLICY_V1 = "EGRESS_POLICY_V1"
ISOLATED_HOST_BOUNDARY_V1 = "ISOLATED_HOST_EFFECT_BOUNDARY_V1"

OPERATION_ACTIVATE = "ACTIVATE_CONSTITUTION"
OPERATION_SET_AUTONOMY = "SET_AUTONOMY_MODE"
OPERATION_QUIESCE = "QUIESCE"
OPERATION_RESUME = "RESUME"
OPERATION_EMERGENCY_STOP = "EMERGENCY_STOP"
OPERATION_APPROVE_RECOVERY = "APPROVE_RECOVERY"
OPERATION_APPROVE_UPDATE = "APPROVE_UPDATE"
VALID_OPERATIONS = (OPERATION_ACTIVATE, OPERATION_SET_AUTONOMY, OPERATION_QUIESCE, OPERATION_RESUME,
                    OPERATION_EMERGENCY_STOP, OPERATION_APPROVE_RECOVERY, OPERATION_APPROVE_UPDATE)

REASON_UNKNOWN_PRINCIPAL = "OPERATOR_PRINCIPAL_UNKNOWN"
REASON_NOT_OPERATOR = "OPERATOR_ACTION_REQUIRES_AN_OPERATOR"
REASON_WRONG_OPERATION = "AUTHORIZATION_IS_FOR_A_DIFFERENT_OPERATION"
REASON_WRONG_IDENTITY = "AUTHORIZATION_IS_FOR_A_DIFFERENT_CIPH"
REASON_WRONG_ENVIRONMENT = "AUTHORIZATION_IS_FOR_A_DIFFERENT_ENVIRONMENT"
REASON_WRONG_GENERATION = "AUTHORIZATION_IS_FOR_A_DIFFERENT_GENERATION"
REASON_EXPIRED = "AUTHORIZATION_EXPIRED"
REASON_REVOKED = "AUTHORIZATION_REVOKED"
REASON_REPLAYED = "AUTHORIZATION_GENERATION_REPLAYED"
REASON_AMBIENT_NOT_CREDENTIAL = "AMBIENT_ENVIRONMENT_IS_NOT_A_CREDENTIAL"
REASON_SERVICE_CANNOT_SELF_AUTHORIZE = "A_SERVICE_CANNOT_GRANT_ITSELF_OPERATOR_AUTHORITY"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_operator_principals (
        principal_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        credential_ref TEXT NOT NULL,
        principal_kind TEXT NOT NULL,
        created_at REAL,
        revoked_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_operator_authorizations (
        authorization_id TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        ciph_identity_id TEXT NOT NULL,
        environment_identity TEXT NOT NULL,
        generation INTEGER NOT NULL,
        issued_at REAL,
        valid_until REAL,
        revoked_at REAL,
        revoke_reason TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_operator_actions (
        action_id TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        outcome TEXT NOT NULL,
        reason TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_egress_rules (
        rule_id TEXT PRIMARY KEY,
        service_identity TEXT NOT NULL,
        destination_kind TEXT NOT NULL,
        destination TEXT NOT NULL,
        disposition TEXT NOT NULL,
        recorded_at REAL
    );
    """,
)

EGRESS_ALLOW = "ALLOW"
EGRESS_DENY = "DENY"
_DESTINATION_KINDS = ("host", "port", "unix_socket", "model_provider")

# The ambient-environment attack surface, each refused as a CREDENTIAL of its own class.
_AMBIENT_FORGERIES = ("CIPH_OPERATOR=1", "OPERATOR_AUTHORIZED", "AUTOSTART_AUTHORIZED",
                      "CIPH_SUDO_OPERATOR", "SKIP_OPERATOR_CHECK")


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


# ---------------------------------------------------------------------------- 9.4 principals
def register_principal(db_path: str, *, principal_id: str, display_name: str, credential_ref: str,
                       principal_kind: str = "human_operator", actor: str,
                       now: Optional[float] = None) -> Dict[str, Any]:
    """
    Register an operator PRINCIPAL. Only an operator identity may create one: a service that could
    register its own principal would be granting itself operator authority through a side door.
    """
    if not str(actor).startswith("operator:"):
        # A REFUSED attempt is audited BEFORE it is refused: "something tried to make itself an operator"
        # is exactly the event an operator needs to see, and a refusal that leaves no trace is a refusal
        # nobody can investigate.
        _record_action(db_path, principal_id=str(actor), operation="REGISTER_PRINCIPAL",
                       outcome="REFUSED", reason=REASON_SERVICE_CANNOT_SELF_AUTHORIZE,
                       moment=time.time() if now is None else float(now))
        raise CrucibleError(REASON_SERVICE_CANNOT_SELF_AUTHORIZE, str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_operator_principals (principal_id, display_name, "
            "credential_ref, principal_kind, created_at, revoked_at) VALUES (?,?,?,?,?,?);",
            (str(principal_id), str(display_name), str(credential_ref), str(principal_kind), moment,
             None))
        connection.commit()
    finally:
        connection.close()
    return get_principal(db_path, principal_id)


def get_principal(db_path: str, principal_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_operator_principals WHERE principal_id = ?;",
                                 (str(principal_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_PRINCIPAL, str(principal_id))
    return dict(row)


def authorize_operation(db_path: str, *, principal_id: str, operation: str, ciph_identity_id: str,
                        environment_identity: str, actor: str,
                        valid_until: Optional[float] = None,
                        now: Optional[float] = None) -> Dict[str, Any]:
    """
    Issue a scoped authorization for ONE operation, ONE Ciph identity and ONE environment.

    The generation increments per (principal, operation, identity, environment), so re-issuing the same
    authorization makes the previous one a REPLAY - a stale grant cannot be re-used by re-presenting it.
    """
    if str(operation) not in VALID_OPERATIONS:
        raise CrucibleError("UNKNOWN_OPERATOR_OPERATION", str(operation))
    if not str(actor).startswith("operator:"):
        _record_action(db_path, principal_id=str(actor), operation=str(operation), outcome="REFUSED",
                       reason=REASON_SERVICE_CANNOT_SELF_AUTHORIZE,
                       moment=time.time() if now is None else float(now))
        raise CrucibleError(REASON_SERVICE_CANNOT_SELF_AUTHORIZE, str(actor))
    get_principal(db_path, principal_id)
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        row = connection.execute(
            "SELECT COALESCE(MAX(generation), 0) AS latest FROM ciph_operator_authorizations "
            "WHERE principal_id = ? AND operation = ? AND ciph_identity_id = ? "
            "AND environment_identity = ?;",
            (str(principal_id), str(operation), str(ciph_identity_id),
             str(environment_identity))).fetchone()
        generation = int(row["latest"]) + 1
        authorization_id = "OA-" + digest({"principal": principal_id, "operation": operation,
                                           "identity": ciph_identity_id,
                                           "environment": environment_identity,
                                           "generation": generation})[:16].upper()
        connection.execute(
            "INSERT OR IGNORE INTO ciph_operator_authorizations (authorization_id, principal_id, "
            "operation, ciph_identity_id, environment_identity, generation, issued_at, valid_until, "
            "revoked_at, revoke_reason) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (authorization_id, str(principal_id), str(operation), str(ciph_identity_id),
             str(environment_identity), generation, moment, valid_until, None, None))
        connection.commit()
    finally:
        connection.close()
    return get_authorization(db_path, authorization_id)


def get_authorization(db_path: str, authorization_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_operator_authorizations WHERE "
                                 "authorization_id = ?;", (str(authorization_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_OPERATOR_AUTHORIZATION", str(authorization_id))
    return dict(row)


def revoke_authorization(db_path: str, authorization_id: str, *, actor: str, reason: str,
                         now: Optional[float] = None) -> Dict[str, Any]:
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_SERVICE_CANNOT_SELF_AUTHORIZE, str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_operator_authorizations SET revoked_at = ?, revoke_reason = ? "
                           "WHERE authorization_id = ?;", (moment, str(reason),
                                                           str(authorization_id)))
        connection.commit()
    finally:
        connection.close()
    return get_authorization(db_path, authorization_id)


def present_operator_authorization(db_path: str, *, authorization: Any, operation: str,
                                   ciph_identity_id: str, environment_identity: str,
                                   generation: Optional[int] = None,
                                   now: Optional[float] = None) -> Dict[str, Any]:
    """
    Verify what the operator is PRESENTING. Every refusal names its own failure, and an ambient string
    (`CIPH_OPERATOR=1`, a copied token, a started service) is refused as a class.
    """
    moment = time.time() if now is None else float(now)
    if isinstance(authorization, str) or authorization is None:
        reason = (REASON_AMBIENT_NOT_CREDENTIAL
                  if isinstance(authorization, str) and
                  any(token.split("=")[0] in str(authorization) for token in _AMBIENT_FORGERIES)
                  else REASON_AMBIENT_NOT_CREDENTIAL)
        _record_action(db_path, principal_id="unknown", operation=operation, outcome="REFUSED",
                       reason=reason, moment=moment)
        return {"accepted": False, "reason": reason,
                "note": "an operator authorization is a scoped grant, not a label or a variable"}
    if not isinstance(authorization, dict) or "authorization_id" not in authorization:
        return {"accepted": False, "reason": REASON_AMBIENT_NOT_CREDENTIAL}
    grant = get_authorization(db_path, str(authorization["authorization_id"]))
    principal = get_principal(db_path, grant["principal_id"])
    checks = [
        (str(grant["operation"]) != str(operation), REASON_WRONG_OPERATION),
        (str(grant["ciph_identity_id"]) != str(ciph_identity_id), REASON_WRONG_IDENTITY),
        (str(grant["environment_identity"]) != str(environment_identity), REASON_WRONG_ENVIRONMENT),
        (principal.get("revoked_at") is not None, REASON_REVOKED),
        (grant["revoked_at"] is not None, REASON_REVOKED),
        (grant["valid_until"] is not None and moment > float(grant["valid_until"]), REASON_EXPIRED),
    ]
    if generation is not None and int(generation) != int(grant["generation"]):
        checks.append((True, REASON_WRONG_GENERATION))
    for failed, reason in checks:
        if failed:
            _record_action(db_path, principal_id=grant["principal_id"], operation=operation,
                           outcome="REFUSED", reason=reason, moment=moment)
            return {"accepted": False, "reason": reason, "authorization_id": grant["authorization_id"]}
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute(
            "SELECT COALESCE(MAX(generation), 0) AS latest FROM ciph_operator_authorizations "
            "WHERE principal_id = ? AND operation = ? AND ciph_identity_id = ? "
            "AND environment_identity = ?;",
            (grant["principal_id"], grant["operation"], grant["ciph_identity_id"],
             grant["environment_identity"])).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if int(grant["generation"]) < int(row["latest"] if row is not None else grant["generation"]):
        _record_action(db_path, principal_id=grant["principal_id"], operation=operation,
                       outcome="REFUSED", reason=REASON_REPLAYED, moment=moment)
        return {"accepted": False, "reason": REASON_REPLAYED,
                "authorization_id": grant["authorization_id"]}
    _record_action(db_path, principal_id=grant["principal_id"], operation=operation,
                   outcome="ACCEPTED", reason=None, moment=moment)
    return {"accepted": True, "authorization_id": grant["authorization_id"],
            "principal_id": grant["principal_id"], "operation": grant["operation"],
            "generation": int(grant["generation"]), "policy_version": OPERATOR_CONTROL_PLANE_V1}


def _record_action(db_path: str, *, principal_id: str, operation: str, outcome: str,
                   reason: Optional[str], moment: float) -> str:
    action_id = "OAZ-" + digest({"principal": principal_id, "operation": operation,
                                 "outcome": outcome, "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_operator_actions (action_id, principal_id, "
                           "operation, outcome, reason, recorded_at) VALUES (?,?,?,?,?,?);",
                           (action_id, str(principal_id), str(operation), str(outcome), reason,
                            moment))
        connection.commit()
    finally:
        connection.close()
    return action_id


def operator_actions(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_operator_actions ORDER BY recorded_at, action_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def ambient_environment_is_not_a_credential() -> Dict[str, Any]:
    """The forgeries that must never be accepted, listed so a test can present every one."""
    return {"policy_version": OPERATOR_CONTROL_PLANE_V1, "ambient_tokens": list(_AMBIENT_FORGERIES),
            "accepted_as_credentials": False,
            "note": "a settable variable, a copied token and a successful process start are each "
                    "ambient conditions, not authorization"}


# ---------------------------------------------------------------------------- 9.5 egress
def record_egress_rule(db_path: str, *, service_identity: str, destination_kind: str,
                       destination: str, disposition: str, actor: str,
                       now: Optional[float] = None) -> Dict[str, Any]:
    """Egress is DENY by default: a rule is needed to allow, and DENY always wins when both match."""
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_SERVICE_CANNOT_SELF_AUTHORIZE, str(actor))
    if str(destination_kind) not in _DESTINATION_KINDS:
        raise CrucibleError("UNKNOWN_DESTINATION_KIND", str(destination_kind))
    if str(disposition) not in (EGRESS_ALLOW, EGRESS_DENY):
        raise CrucibleError("UNKNOWN_EGRESS_DISPOSITION", str(disposition))
    moment = time.time() if now is None else float(now)
    rule_id = "EG-" + digest({"service": service_identity, "kind": destination_kind,
                              "destination": destination, "disposition": disposition})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_egress_rules (rule_id, service_identity, "
                           "destination_kind, destination, disposition, recorded_at) "
                           "VALUES (?,?,?,?,?,?);",
                           (rule_id, str(service_identity), str(destination_kind),
                            str(destination), str(disposition), moment))
        connection.commit()
    finally:
        connection.close()
    return {"rule_id": rule_id, "service_identity": str(service_identity),
            "destination": str(destination), "disposition": str(disposition),
            "policy_version": EGRESS_POLICY_V1}


def egress_decision(db_path: str, *, service_identity: str, destination_kind: str,
                    destination: str) -> Dict[str, Any]:
    """
    DENY unless an explicit ALLOW matches, and a matching DENY overrides an ALLOW.

    Scope note: this is a POLICY decision, and it is enforceable for real only where something consults
    it (a fetch helper, a transport, a proxy). Claiming it as kernel-level enforcement would be the exact
    "configuration declaration as runtime proof" this program forbids.
    """
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_egress_rules WHERE service_identity = ? AND destination_kind = ?;",
            (str(service_identity), str(destination_kind)))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    matching = [row for row in rows if str(row["destination"]) == str(destination)]
    if any(row["disposition"] == EGRESS_DENY for row in matching):
        return {"allowed": False, "reason": "EXPLICIT_DENY", "enforcement": "policy-layer"}
    if any(row["disposition"] == EGRESS_ALLOW for row in matching):
        return {"allowed": True, "reason": "EXPLICIT_ALLOW", "enforcement": "policy-layer"}
    return {"allowed": False, "reason": "DEFAULT_DENY", "enforcement": "policy-layer"}


def real_egress_attempt(host: str, port: int, *, timeout: float = 3.0) -> Dict[str, Any]:
    """
    A REAL socket attempt, so a refusal can be observed rather than asserted.

    In this environment there is no kernel firewall, so a connection that SUCCEEDS succeeds: the honest
    report is that the policy said deny and the OS did not enforce it, which is exactly the gap the
    privileged-host package exists to close.
    """
    import socket
    try:
        with socket.create_connection((str(host), int(port)), timeout=timeout):
            return {"connected": True, "host": host, "port": int(port),
                    "os_enforced": False,
                    "note": "connected: the OS did not enforce the policy, so policy != enforcement here"}
    except OSError as error:
        return {"connected": False, "host": host, "port": int(port), "error": str(error)[:160],
                "os_enforced": None}


def stale_host_effect_disposition(*, effect_kind: str, externally_governed: bool,
                                  os_permission_enforced: bool) -> Dict[str, Any]:
    """
    What actually happens when an isolated superseded host attempts an effect.

    Three outcomes, and only two of them are success:
      * externally governed + the resource refuses -> REFUSED_BY_RESOURCE (governable, and proven at the
        8.x execution boundary)
      * local + the OS denies -> REFUSED_BY_OS (enforceable where the host enforces permissions)
      * local + the host still holds what it needs -> RESIDUAL_PHYSICAL_CONTROL: reported as a limitation,
        never as constitutional success
    """
    if externally_governed:
        return {"disposition": "REFUSED_BY_RESOURCE", "constitutional_success": True,
                "requires": "the resource checks current authorization or a revoked credential"}
    if os_permission_enforced:
        return {"disposition": "REFUSED_BY_OS", "constitutional_success": True,
                "requires": "the host enforces file/scope permissions on the effect"}
    return {"disposition": "RESIDUAL_PHYSICAL_CONTROL", "constitutional_success": False,
            "note": "an unreachable host that still holds the means can keep producing local effects; "
                    "this is a stated limitation, not a proven guarantee",
            "policy_version": ISOLATED_HOST_BOUNDARY_V1}


def operator_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        table = lambda name: [dict(row) for row in connection.execute(  # noqa: E731
            f"SELECT * FROM {name} ORDER BY rowid;")]
        payload = {"principals": table("ciph_operator_principals"),
                   "authorizations": table("ciph_operator_authorizations"),
                   "actions": table("ciph_operator_actions"),
                   "egress": table("ciph_egress_rules")}
    except sqlite3.Error:
        payload = {"principals": [], "authorizations": [], "actions": [], "egress": []}
    finally:
        connection.close()
    return digest({"version": OPERATOR_CONTROL_PLANE_V1, **payload})
