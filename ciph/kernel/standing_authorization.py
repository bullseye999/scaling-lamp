"""
ciph/kernel/standing_authorization - 5.0 Gate One: bounded persistent authority.

A mission may grant some STANDING authority, but only explicitly and only within a declared envelope.
The law that matters most:

    continuity grants persistence, not permission

and the second: a live daemon cannot mint its own standing authorization. Only an operator identity may
grant one, which is how "autonomy creating StandingAuthorization = 0" stops being a convention.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

STANDING_AUTHORIZATION_V1 = "STANDING_AUTHORIZATION_V1"

STATUS_ACTIVE = "ACTIVE"
STATUS_EXPIRED = "EXPIRED"
STATUS_REVOKED = "REVOKED"
STATUS_NOT_YET_VALID = "NOT_YET_VALID"

REASON_NOT_OPERATOR = "STANDING_AUTHORIZATION_REQUIRES_AN_OPERATOR"
REASON_WORK_CLASS_NOT_PERMITTED = "WORK_CLASS_NOT_PERMITTED"
REASON_SCOPE_WIDENED = "AUTONOMOUS_INTENT_WOULD_WIDEN_SCOPE"
REASON_RISK_CEILING = "RISK_ABOVE_STANDING_CEILING"
REASON_EXPIRED = "STANDING_AUTHORIZATION_EXPIRED"
REASON_REVOKED = "STANDING_AUTHORIZATION_REVOKED"

RISK_LEVELS = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_standing_authorizations (
        standing_auth_id TEXT PRIMARY KEY,
        mission_id TEXT NOT NULL,
        permitted_work_classes_json TEXT NOT NULL,
        scope_constraints_json TEXT,
        risk_ceiling TEXT NOT NULL,
        resource_budget_ref TEXT,
        valid_from REAL,
        valid_until REAL,
        revocation_conditions_json TEXT,
        authorization_generation INTEGER NOT NULL,
        granted_by TEXT NOT NULL,
        revoked_at REAL,
        revoke_reason TEXT,
        created_at REAL
    );
    """,
)


@dataclass(frozen=True)
class StandingAuthorization:
    standing_auth_id: str
    mission_id: str
    permitted_work_classes: Tuple[str, ...]
    scope_constraints: Tuple[str, ...]
    risk_ceiling: str
    resource_budget_ref: Optional[str]
    valid_from: Optional[float]
    valid_until: Optional[float]
    authorization_generation: int
    granted_by: str

    def as_dict(self) -> Dict[str, Any]:
        return {"standing_auth_id": self.standing_auth_id, "mission_id": self.mission_id,
                "permitted_work_classes": list(self.permitted_work_classes),
                "scope_constraints": list(self.scope_constraints),
                "risk_ceiling": self.risk_ceiling,
                "resource_budget_ref": self.resource_budget_ref,
                "valid_from": self.valid_from, "valid_until": self.valid_until,
                "authorization_generation": self.authorization_generation,
                "granted_by": self.granted_by}


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


def create_standing_authorization(db_path: str, *, mission_id: str,
                                  permitted_work_classes: Sequence[str], granted_by: str,
                                  risk_ceiling: str = "LOW", scope_constraints: Sequence[str] = (),
                                  resource_budget_ref: Optional[str] = None,
                                  valid_from: Optional[float] = None,
                                  valid_until: Optional[float] = None,
                                  revocation_conditions: Sequence[str] = (),
                                  authorization_generation: int = 0,
                                  now: Optional[float] = None) -> StandingAuthorization:
    """Only an operator identity may grant standing authority (the daemon-cannot-mint law)."""
    if not str(granted_by).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(granted_by))
    if not permitted_work_classes:
        raise CrucibleError("STANDING_AUTHORIZATION_REQUIRES_WORK_CLASSES", mission_id)
    ceiling = str(risk_ceiling).upper()
    if ceiling not in RISK_LEVELS:
        raise CrucibleError("UNKNOWN_RISK_CEILING", ceiling)
    moment = time.time() if now is None else float(now)
    auth_id = "SA-" + digest({"mission": mission_id, "classes": sorted(permitted_work_classes),
                              "ceiling": ceiling, "gen": authorization_generation,
                              "granted_by": granted_by})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_standing_authorizations (standing_auth_id, mission_id, "
            "permitted_work_classes_json, scope_constraints_json, risk_ceiling, resource_budget_ref, "
            "valid_from, valid_until, revocation_conditions_json, authorization_generation, "
            "granted_by, revoked_at, revoke_reason, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (auth_id, mission_id, json.dumps(sorted(str(item) for item in permitted_work_classes)),
             json.dumps(sorted(str(item) for item in scope_constraints)), ceiling, resource_budget_ref,
             valid_from, valid_until, json.dumps(sorted(str(item) for item in revocation_conditions)),
             int(authorization_generation), str(granted_by), None, None, moment))
        connection.commit()
    finally:
        connection.close()
    return get_standing_authorization(db_path, auth_id)


def revoke_standing_authorization(db_path: str, standing_auth_id: str, *, reason: str,
                                  actor: str, now: Optional[float] = None) -> bool:
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        cursor = connection.execute(
            "UPDATE ciph_standing_authorizations SET revoked_at = ?, revoke_reason = ? "
            "WHERE standing_auth_id = ? AND revoked_at IS NULL;", (moment, reason, standing_auth_id))
        connection.commit()
        return cursor.rowcount > 0
    finally:
        connection.close()


def get_standing_authorization(db_path: str, standing_auth_id: str) -> StandingAuthorization:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_standing_authorizations WHERE "
                                 "standing_auth_id = ?;", (standing_auth_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_STANDING_AUTHORIZATION", standing_auth_id)
    row = dict(row)
    return StandingAuthorization(
        standing_auth_id=str(row["standing_auth_id"]), mission_id=str(row["mission_id"]),
        permitted_work_classes=tuple(json.loads(row["permitted_work_classes_json"] or "[]")),
        scope_constraints=tuple(json.loads(row["scope_constraints_json"] or "[]")),
        risk_ceiling=str(row["risk_ceiling"]), resource_budget_ref=row["resource_budget_ref"],
        valid_from=row["valid_from"], valid_until=row["valid_until"],
        authorization_generation=int(row["authorization_generation"]),
        granted_by=str(row["granted_by"]))


def standing_authorizations(db_path: str, *, mission_id: Optional[str] = None
                            ) -> List[StandingAuthorization]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT standing_auth_id FROM ciph_standing_authorizations"
    params: Tuple[Any, ...] = ()
    if mission_id is not None:
        query += " WHERE mission_id = ?"
        params = (mission_id,)
    try:
        ids = [str(row["standing_auth_id"]) for row in connection.execute(
            query + " ORDER BY created_at, standing_auth_id;", params)]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_standing_authorization(db_path, auth_id) for auth_id in ids]


def authorization_status(db_path: str, standing_auth_id: str, *,
                         now: Optional[float] = None) -> str:
    """Revocation first, then the time window: an expired grant is dead, not dormant."""
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT revoked_at, valid_from, valid_until FROM "
                                 "ciph_standing_authorizations WHERE standing_auth_id = ?;",
                                 (standing_auth_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        return "UNKNOWN"
    if row["revoked_at"] is not None:
        return STATUS_REVOKED
    if row["valid_until"] is not None and moment > float(row["valid_until"]):
        return STATUS_EXPIRED
    if row["valid_from"] is not None and moment < float(row["valid_from"]):
        return STATUS_NOT_YET_VALID
    return STATUS_ACTIVE


def assert_work_permitted(db_path: str, *, standing_auth_id: str, work_class: str, risk_class: str,
                          requested_scope: Sequence[str] = (), now: Optional[float] = None) -> None:
    """The three ways autonomy over-reaches: unlisted class, widened scope, risk above the ceiling."""
    status = authorization_status(db_path, standing_auth_id, now=now)
    if status != STATUS_ACTIVE:
        raise CrucibleError(REASON_REVOKED if status == STATUS_REVOKED else REASON_EXPIRED, status)
    authorization = get_standing_authorization(db_path, standing_auth_id)
    if str(work_class) not in authorization.permitted_work_classes:
        raise CrucibleError(REASON_WORK_CLASS_NOT_PERMITTED, str(work_class))
    allowed = set(authorization.scope_constraints)
    if allowed:
        for scope in requested_scope:
            if str(scope) not in allowed:
                raise CrucibleError(REASON_SCOPE_WIDENED, str(scope))
    elif requested_scope:
        # A grant with NO declared scope permits no scope-taking work at all.
        raise CrucibleError(REASON_SCOPE_WIDENED, ','.join(str(item) for item in requested_scope))
    if RISK_LEVELS.index(str(risk_class).upper()) > RISK_LEVELS.index(authorization.risk_ceiling):
        raise CrucibleError(REASON_RISK_CEILING, f"{risk_class}>{authorization.risk_ceiling}")


def standing_digest(db_path: str) -> str:
    return digest({"version": STANDING_AUTHORIZATION_V1,
                   "authorizations": [item.as_dict() for item in standing_authorizations(db_path)]})
