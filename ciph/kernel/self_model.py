"""
ciph.kernel.self_model - what Ciph knows about ITSELF, from evidence rather than self-description.

4.3 Gate Three. The self model is a PROJECTION over canonical records: what exists, what is usable,
what is permitted, and what has actually been proven by governed execution. It is never a summary of
what the model says about itself.

CENTRAL LAW
    code presence != capability != permission != execution != successful effect.

    Each rung is a separate, independently recorded fact, so a capability can be INSTALLED and still
    not be available, available and still not authorized, authorized and still unverified. The
    strongest claim Ciph may make is the HIGHEST RUNG WHOSE WHOLE LADDER HOLDS:

        UNKNOWN      nothing canonical is known about this capability
        INSTALLED    code exists somewhere, and that is all
        AVAILABLE    the code exists in THIS environment
        AUTHORIZED   permission exists for this environment and manifest
        VERIFIED     a governed execution under this environment and manifest succeeded

LAWS (each has a specimen in `test_gate_4_3_self_model.py`)

 1. Module installed != capability verified.
 2. Capability verified != currently available.
 3. Available != authorized.
 4. Authorized != executed.
 5. Execution attempt != successful effect (only a recorded success verifies).
 6. Self-reported model text is NOT self-model evidence.
 7. Performance comes from governed execution evidence, never self-assessment.
 8. Environment AND manifest identity matter: evidence under one proves nothing about another.
 9. Limitations are first-class.
10. UNKNOWN is a valid and honest answer.
11. Self-model history is append-only.
12. Restart reconstructs an identical self state from canonical evidence.

Access to the wider system's permission and execution stores is deliberately NOT wired in here: this
gate projects over its own canonical records, so the separation is provable, and a later bridge can
feed it from governed execution evidence without changing these laws.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.manifest_identity import ManifestIdentity

LEVEL_UNKNOWN = "UNKNOWN"
LEVEL_INSTALLED = "INSTALLED"
LEVEL_AVAILABLE = "AVAILABLE"
LEVEL_AUTHORIZED = "AUTHORIZED"
LEVEL_VERIFIED = "VERIFIED"
CLAIM_LADDER = (LEVEL_UNKNOWN, LEVEL_INSTALLED, LEVEL_AVAILABLE, LEVEL_AUTHORIZED, LEVEL_VERIFIED)

REASON_NO_INSTALLATION = "NO_INSTALLATION"
REASON_NOT_AVAILABLE_IN_ENVIRONMENT = "NOT_AVAILABLE_IN_ENVIRONMENT"
REASON_NOT_AUTHORIZED = "NOT_AUTHORIZED"
REASON_NOT_EMPIRICALLY_VERIFIED = "NOT_EMPIRICALLY_VERIFIED"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_self_installations (
        record_id TEXT PRIMARY KEY,
        capability_id TEXT NOT NULL,
        module_ref TEXT,
        environment_ref TEXT,
        manifest_identity TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_self_authorizations (
        record_id TEXT PRIMARY KEY,
        capability_id TEXT NOT NULL,
        environment_ref TEXT,
        manifest_identity TEXT,
        scope_ref TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_self_executions (
        record_id TEXT PRIMARY KEY,
        capability_id TEXT NOT NULL,
        environment_ref TEXT,
        manifest_identity TEXT,
        succeeded INTEGER NOT NULL,
        attempt_ref TEXT,
        receipt_ref TEXT,
        recorded_at REAL
    );
    """,
)


class SelfModelError(Exception):
    """A self-model operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class SelfModelProjection:
    """What Ciph may honestly say about ONE capability, right now, in ONE environment and manifest."""

    capability_id: str
    claim_level: str
    installed: bool
    available: bool
    authorized: bool
    empirically_verified: bool
    reason_codes: Tuple[str, ...]
    environment_ref: Optional[str]
    manifest_identity: Optional[str]
    performance_ref: Optional[str]
    limitations: Tuple[str, ...]
    uncertainty: Tuple[str, ...]
    evidence_basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"capability_id": self.capability_id, "claim_level": self.claim_level,
                "installed": self.installed, "available": self.available,
                "authorized": self.authorized, "empirically_verified": self.empirically_verified,
                "reason_codes": list(self.reason_codes), "environment_ref": self.environment_ref,
                "manifest_identity": self.manifest_identity, "performance_ref": self.performance_ref,
                "limitations": list(self.limitations), "uncertainty": list(self.uncertainty),
                "evidence_basis_digest": self.evidence_basis_digest}

    def canonical_digest(self) -> str:
        return _digest(self.as_dict())


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            pass
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _manifest_key(manifest_identity: Any) -> Optional[str]:
    """Normalize a manifest identity to its canonical string. A real ManifestIdentity is preferred."""
    if manifest_identity is None:
        return None
    if isinstance(manifest_identity, ManifestIdentity):
        return str(manifest_identity)
    text = str(manifest_identity).strip()
    return text or None


def _capability_key(capability_id: Any) -> str:
    text = str(capability_id).strip()
    if not text:
        raise SelfModelError("CAPABILITY_REQUIRES_AN_ID", repr(capability_id))
    return text


def _record_id(prefix: str, payload: Mapping[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return prefix + hashlib.sha256(body.encode("utf-8")).hexdigest()[:12].upper()


def _insert_if_new(db_path: str, table: str, columns: Sequence[str],
                   values: Mapping[str, Any]) -> str:
    record_id = str(values["record_id"])
    conn = _connect(db_path)
    try:
        init_schema(conn)
        existing = conn.execute(f"SELECT 1 FROM {table} WHERE record_id = ?;", (record_id,)).fetchone()
        if existing is None:
            placeholders = ",".join("?" for _ in columns)
            conn.execute(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders});",
                         tuple(values[column] for column in columns))
            conn.commit()
    finally:
        conn.close()
    return record_id


def record_installation(db_path: str, *, capability_id: str, module_ref: Optional[str] = None,
                        environment_ref: Optional[str] = None, manifest_identity: Any = None,
                        now: Optional[float] = None) -> str:
    """Record that CODE for a capability exists. This is the weakest rung and says nothing more."""
    moment = time.time() if now is None else float(now)
    key = _capability_key(capability_id)
    env = None if environment_ref is None else str(environment_ref)
    manifest = _manifest_key(manifest_identity)
    record_id = _record_id("SIN-", {"capability": key, "module": module_ref, "env": env,
                                    "manifest": manifest})
    return _insert_if_new(db_path, "ciph_self_installations",
                          ("record_id", "capability_id", "module_ref", "environment_ref",
                           "manifest_identity", "recorded_at"),
                          {"record_id": record_id, "capability_id": key, "module_ref": module_ref,
                           "environment_ref": env, "manifest_identity": manifest,
                           "recorded_at": moment})


def record_authorization(db_path: str, *, capability_id: str, environment_ref: Optional[str] = None,
                         manifest_identity: Any = None, scope_ref: Optional[str] = None,
                         now: Optional[float] = None) -> str:
    """Record that permission for a capability exists. Permission is separate from existence."""
    moment = time.time() if now is None else float(now)
    key = _capability_key(capability_id)
    env = None if environment_ref is None else str(environment_ref)
    manifest = _manifest_key(manifest_identity)
    record_id = _record_id("SAU-", {"capability": key, "env": env, "manifest": manifest,
                                    "scope": scope_ref})
    return _insert_if_new(db_path, "ciph_self_authorizations",
                          ("record_id", "capability_id", "environment_ref", "manifest_identity",
                           "scope_ref", "recorded_at"),
                          {"record_id": record_id, "capability_id": key, "environment_ref": env,
                           "manifest_identity": manifest, "scope_ref": scope_ref,
                           "recorded_at": moment})


def record_execution_evidence(db_path: str, *, capability_id: str, succeeded: bool,
                              attempt_ref: Optional[str] = None, receipt_ref: Optional[str] = None,
                              environment_ref: Optional[str] = None, manifest_identity: Any = None,
                              now: Optional[float] = None) -> str:
    """
    Record the outcome of ONE governed execution (law 5).

    `succeeded` is an OUTCOME the governed machinery established, not a model's claim. A failed
    attempt records a LIMITATION: it is evidence about the world, and it never verifies anything.
    """
    moment = time.time() if now is None else float(now)
    key = _capability_key(capability_id)
    env = None if environment_ref is None else str(environment_ref)
    manifest = _manifest_key(manifest_identity)
    record_id = _record_id("SEX-", {"capability": key, "env": env, "manifest": manifest,
                                    "succeeded": bool(succeeded), "attempt": attempt_ref,
                                    "receipt": receipt_ref})
    return _insert_if_new(db_path, "ciph_self_executions",
                          ("record_id", "capability_id", "environment_ref", "manifest_identity",
                           "succeeded", "attempt_ref", "receipt_ref", "recorded_at"),
                          {"record_id": record_id, "capability_id": key, "environment_ref": env,
                           "manifest_identity": manifest, "succeeded": 1 if succeeded else 0,
                           "attempt_ref": attempt_ref, "receipt_ref": receipt_ref,
                           "recorded_at": moment})


def _rows(db_path: str, table: str, capability_id: str) -> List[Dict[str, Any]]:
    conn = _connect(db_path, read_only=True)
    try:
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM {table} WHERE capability_id = ? ORDER BY record_id;", (capability_id,))]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def _env_matches(row: Mapping[str, Any], queried_env: Optional[str]) -> bool:
    if queried_env is None:
        return True
    return row["environment_ref"] == queried_env


def _manifest_matches(row: Mapping[str, Any], queried_manifest: Optional[str]) -> bool:
    if queried_manifest is None:
        return True
    return row["manifest_identity"] == queried_manifest


def _ladder_level(*, installed: bool, available: bool, authorized: bool,
                  verified: bool) -> Tuple[str, Tuple[str, ...]]:
    """
    THE claim function. Frozen: the level is the highest rung whose ENTIRE supporting ladder holds,
    with the first missing rung named as the reason. It can never skip a rung.
    """
    if not installed:
        return LEVEL_UNKNOWN, (REASON_NO_INSTALLATION,)
    if not available:
        return LEVEL_INSTALLED, (REASON_NOT_AVAILABLE_IN_ENVIRONMENT,)
    if not authorized:
        return LEVEL_AVAILABLE, (REASON_NOT_AUTHORIZED,)
    if not verified:
        return LEVEL_AUTHORIZED, (REASON_NOT_EMPIRICALLY_VERIFIED,)
    return LEVEL_VERIFIED, ()


def project_capability(db_path: str, *, capability_id: str, environment_ref: Optional[str] = None,
                       manifest_identity: Any = None,
                       now: Optional[float] = None) -> SelfModelProjection:
    """
    Derive what Ciph may say about ONE capability in ONE environment and manifest (laws 1-8, 10).

    Nothing is asserted from prose: a capability that was never recorded is UNKNOWN, and a capability
    whose code exists but was never governed-executed is only INSTALLED or AVAILABLE.
    """
    key = _capability_key(capability_id)
    env = None if environment_ref is None else str(environment_ref)
    manifest = _manifest_key(manifest_identity)

    installations = _rows(db_path, "ciph_self_installations", key)
    authorized_rows = [row for row in _rows(db_path, "ciph_self_authorizations", key)
                       if _env_matches(row, env) and _manifest_matches(row, manifest)]
    execution_rows = [row for row in _rows(db_path, "ciph_self_executions", key)
                      if _env_matches(row, env) and _manifest_matches(row, manifest)]

    installed = bool(installations)
    available = any(_env_matches(row, env) for row in installations) if env is not None else installed
    authorized = bool(authorized_rows)
    successes = [row for row in execution_rows if int(row["succeeded"]) == 1]
    failures = [row for row in execution_rows if int(row["succeeded"]) == 0]
    verified = bool(successes)

    level, reasons = _ladder_level(installed=installed, available=available, authorized=authorized,
                                   verified=verified)
    performance_ref = (_digest([{"attempt": row["attempt_ref"], "receipt": row["receipt_ref"],
                                 "succeeded": int(row["succeeded"])} for row in execution_rows])
                       if execution_rows else None)
    limitations = tuple(f"{key}:attempt:{row['attempt_ref']}:failed" for row in failures)
    evidence_basis = _digest({"installations": [row["record_id"] for row in installations],
                              "authorizations": [row["record_id"] for row in authorized_rows],
                              "executions": [row["record_id"] for row in execution_rows],
                              "env": env, "manifest": manifest})
    return SelfModelProjection(
        capability_id=key, claim_level=level, installed=installed, available=available,
        authorized=authorized, empirically_verified=verified, reason_codes=tuple(reasons),
        environment_ref=env, manifest_identity=manifest, performance_ref=performance_ref,
        limitations=limitations, uncertainty=tuple(reasons), evidence_basis_digest=evidence_basis)


def assert_empirically_verified(db_path: str, capability_id: str, *,
                                environment_ref: Optional[str] = None,
                                manifest_identity: Any = None, now: Optional[float] = None) -> str:
    """
    Refuse the sentence "I can do this" unless governed execution proved it here (laws 1 and 5).

    The guard returns the level; a caller that wanted to advertise a capability has to hold the
    evidence, not the intention.
    """
    projection = project_capability(db_path, capability_id=capability_id,
                                    environment_ref=environment_ref,
                                    manifest_identity=manifest_identity, now=now)
    if projection.claim_level != LEVEL_VERIFIED:
        raise SelfModelError("CAPABILITY_NOT_VERIFIED",
                             f"{capability_id}:{projection.claim_level}")
    return projection.claim_level


def known_capabilities(db_path: str) -> Tuple[str, ...]:
    conn = _connect(db_path, read_only=True)
    try:
        found = set()
        for table in ("ciph_self_installations", "ciph_self_authorizations", "ciph_self_executions"):
            try:
                found.update(str(r[0]) for r in conn.execute(
                    f"SELECT DISTINCT capability_id FROM {table};"))
            except sqlite3.Error:
                continue
        return tuple(sorted(found))
    finally:
        conn.close()


def self_model_digest(db_path: str, *, environment_ref: Optional[str] = None,
                      manifest_identity: Any = None, now: Optional[float] = None) -> str:
    """The deterministic identity of the self model (law 12)."""
    payload = [project_capability(db_path, capability_id=capability_id,
                                  environment_ref=environment_ref,
                                  manifest_identity=manifest_identity, now=now).as_dict()
               for capability_id in known_capabilities(db_path)]
    return _digest(payload)
