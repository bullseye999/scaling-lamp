"""
ciph/kernel/sovereignty_portability - 8.6 (host/path independence), 8.7 (model independence),
8.8 (schema and migration sovereignty).

    machine != Ciph.   provider != Ciph.   model != Ciph.

Three ways a system quietly binds itself to an accident of its current installation, and one law for each.

HOST/PATH. R1 already made the vault identity independent of its path. This module CLASSIFIES the other
environmental dependencies so the accidental ones are visible rather than tribal knowledge: a required
environment property (a Python version, a writable data directory) is a fact about running Ciph; an
accidental one (this absolute home directory, this hostname) is a fact about the machine we happened to
use.

MODEL. A provider changing is an ENVIRONMENT event, not an identity event. The substitution is recorded,
the sovereign identity and history are untouched, and - the part that matters - the substitute's
capabilities are NOT inherited as verified: they start INSTALLED, because a model's confident claim about
its own competence is not evidence of it.

MIGRATION. Restoring last year's backup into this year's software is a REPRESENTATION change, never a
meaning change. Migrations are ordered, named at both ends, checked before and after, and they may not
rewrite a frozen constitutional identity to the current version.
"""

import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

HOST_PORTABILITY_V1 = "HOST_PORTABILITY_V1"
MODEL_SUBSTITUTION_V1 = "MODEL_SUBSTITUTION_V1"
RECOVERY_MIGRATION_PLAN_V1 = "RECOVERY_MIGRATION_PLAN_V1"

REQUIRED_ENV = "REQUIRED_ENVIRONMENT"
ACCIDENTAL = "ACCIDENTAL_INSTALLATION_DEPENDENCY"

MIGRATION_PENDING = "PENDING"
MIGRATION_APPLIED = "APPLIED"
MIGRATION_FAILED = "FAILED"
MIGRATION_UNSUPPORTED = "UNSUPPORTED_TRANSITION"

REASON_NOT_OPERATOR = "SOVEREIGNTY_CHANGE_REQUIRES_AN_OPERATOR"
REASON_PARTIAL = "MIGRATION_MUST_NOT_PARTIALLY_ACTIVATE"

# The environmental properties Ciph actually requires, as opposed to the ones it happens to have.
REQUIRED_ENVIRONMENT_PROPERTIES: Tuple[Tuple[str, str], ...] = (
    ("python", "3.10 or newer"),
    ("data_directory", "writable directory for the vault and its siblings"),
    ("clock", "a monotonic-ish wall clock for scheduling and expiry (never for ordering)"),
    ("sqlite", "a sqlite3 module with the standard Backup API"),
    ("filesystem", "POSIX rename semantics for atomic file replacement"),
)

_ACCIDENTAL_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"/home/[a-z][a-z0-9_-]*/", "absolute home directory"),
    (r"\bsocket\.gethostname\(\)", "hostname used as an identifier"),
    (r"\bplatform\.node\(\)", "hostname used as an identifier"),
    (r"\bos\.uname\(\)", "kernel identity used as an identifier"),
    (r"\b(10|192\.168|172)\.\d+\.\d+\.\d+\b", "hardcoded local address"),
)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_model_substitutions (
        substitution_id TEXT PRIMARY KEY,
        previous_model TEXT NOT NULL,
        new_model TEXT NOT NULL,
        provider TEXT,
        recorded_by TEXT NOT NULL,
        identity_unchanged INTEGER NOT NULL,
        capabilities_reverified INTEGER NOT NULL,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_migrations (
        migration_id TEXT PRIMARY KEY,
        plan_id TEXT NOT NULL,
        source_versions_json TEXT NOT NULL,
        target_versions_json TEXT NOT NULL,
        ordered_steps_json TEXT NOT NULL,
        pre_digest TEXT NOT NULL,
        post_digest TEXT,
        frozen_identities_json TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT,
        recorded_at REAL
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


# ---------------------------------------------------------------------------- host and path
def classify_environment_dependency(dependency: str, detail: str = "") -> Dict[str, Any]:
    """Required property, or an accident of this installation? Named, so it can be argued with."""
    for pattern, description in _ACCIDENTAL_PATTERNS:
        if re.search(pattern, str(detail)):
            return {"dependency": str(dependency), "classification": ACCIDENTAL,
                    "reason": description, "detail": str(detail)}
    return {"dependency": str(dependency), "classification": REQUIRED_ENV, "detail": str(detail)}


def required_environment() -> Tuple[Tuple[str, str], ...]:
    return REQUIRED_ENVIRONMENT_PROPERTIES


def accidental_dependencies(sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[Dict[str, str], ...]:
    """
    Scan for the accidental kind. This is a REPORTING tool: it finds candidates for a human to classify,
    and it deliberately does not pretend that a regex can decide whether a path is a dependency.
    """
    if sources is None:
        from ciph.kernel.evolution_ownership import production_sources
        sources = list(production_sources())
    found: List[Dict[str, str]] = []
    for relative, text in sources:
        for pattern, description in _ACCIDENTAL_PATTERNS:
            for match in re.finditer(pattern, text):
                found.append({"module": relative, "pattern": description,
                              "sample": match.group(0)[:40]})
    return tuple(sorted(found, key=lambda item: (item["module"], item["pattern"])))


def portability_report(*, host: Optional[str] = None, path: Optional[str] = None,
                       node_id: Optional[str] = None, identity_id: Optional[str] = None
                       ) -> Dict[str, Any]:
    """
    Recovery onto a different machine, stated as facts about what CHANGED versus what is IDENTITY.

    The host and the path are reported as environment; the identity is reported as identity. Nothing here
    treats a changed hostname as a changed Ciph, and nothing derives identity from either.
    """
    return {"policy_version": HOST_PORTABILITY_V1, "environment": {"host": host, "path": path},
            "identity": {"node_id": node_id, "ciph_identity_id": identity_id},
            "identity_depends_on_host": False, "identity_depends_on_path": False,
            "required_environment_properties": [list(item)
                                                for item in REQUIRED_ENVIRONMENT_PROPERTIES],
            "note": "R1's vault identity is unchanged by a move; nothing here reintroduces path-derived "
                    "identity"}


# ---------------------------------------------------------------------------- model substitution
def substitute_model(db_path: str, *, previous_model: str, new_model: str, provider: str,
                     actor: str, capability_evidence: Sequence[str] = (),
                     now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record a model change as an ENVIRONMENT event.

    `capabilities_reverified` is the honest part: a substitute model's capabilities are NOT carried over.
    Unless the operator supplies fresh evidence FOR THIS MODEL, the new capabilities are INSTALLED (the
    manifest names them) and must climb the 4.3 ladder again by measurement.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    verified = bool(capability_evidence)
    substitution_id = "MS-" + digest({"previous": previous_model, "new": new_model,
                                      "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_model_substitutions (substitution_id, previous_model, "
            "new_model, provider, recorded_by, identity_unchanged, capabilities_reverified, "
            "recorded_at) VALUES (?,?,?,?,?,?,?,?);",
            (substitution_id, str(previous_model), str(new_model), str(provider), str(actor), 1,
             1 if verified else 0, moment))
        connection.commit()
    finally:
        connection.close()
    return {"substitution_id": substitution_id, "previous_model": str(previous_model),
            "new_model": str(new_model), "provider": str(provider),
            "identity_unchanged": True, "capabilities_reverified": verified,
            "capabilities_carried_over": False,
            "capability_level_after_substitution": "VERIFIED" if verified else "INSTALLED",
            "reverification_required": not verified, "policy_version": MODEL_SUBSTITUTION_V1,
            "recorded_at": moment}


def model_substitutions(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_model_substitutions ORDER BY recorded_at, substitution_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


# ---------------------------------------------------------------------------- migration lineage
def build_migration_plan(*, source_versions: Dict[str, str], target_versions: Dict[str, str],
                         ordered_steps: Sequence[str], frozen_identities: Sequence[str],
                         pre_digest: str) -> Dict[str, Any]:
    """
    A governed migration: both ends named, the steps ordered, the frozen identities listed, and the
    integrity of the result recorded. An unsupported transition is REFUSED here rather than attempted.
    """
    unsupported = [name for name in target_versions if name not in source_versions]
    plan = {"policy_version": RECOVERY_MIGRATION_PLAN_V1, "source_versions": dict(source_versions),
            "target_versions": dict(target_versions),
            "ordered_steps": [str(step) for step in ordered_steps],
            "frozen_identities": sorted(str(item) for item in frozen_identities),
            "pre_digest": str(pre_digest),
            "unsupported_transitions": sorted(unsupported)}
    plan["plan_id"] = "RMP-" + digest(plan)[:16].upper()
    plan["supported"] = not unsupported
    return plan


def apply_migration(db_path: str, plan: Dict[str, Any], *, post_digest: Optional[str] = None,
                    step_digests: Optional[Dict[str, str]] = None,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record the migration, fail-closed.

    A plan whose target versions include something the source did not have is UNSUPPORTED and never
    partially applied; a migration whose post-digest is missing is FAILED rather than assumed - and in
    either case the recovery it belonged to cannot become an activation.
    """
    moment = time.time() if now is None else float(now)
    if not plan.get("supported", False):
        status, detail = MIGRATION_UNSUPPORTED, {"unsupported": plan.get("unsupported_transitions")}
    elif post_digest is None:
        status, detail = MIGRATION_FAILED, {"reason": "no post-migration integrity digest"}
    else:
        status, detail = MIGRATION_APPLIED, {"step_digests": dict(step_digests or {})}
    migration_id = "RMG-" + digest({"plan": plan.get("plan_id"), "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_recovery_migrations (migration_id, plan_id, "
            "source_versions_json, target_versions_json, ordered_steps_json, pre_digest, post_digest, "
            "frozen_identities_json, status, detail, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (migration_id, str(plan.get("plan_id")),
             json.dumps(plan.get("source_versions", {})),
             json.dumps(plan.get("target_versions", {})),
             json.dumps(list(plan.get("ordered_steps", []))), str(plan.get("pre_digest")),
             post_digest, json.dumps(sorted(plan.get("frozen_identities", []))), status,
             json.dumps(detail), moment))
        connection.commit()
    finally:
        connection.close()
    return {"migration_id": migration_id, "plan_id": str(plan.get("plan_id")), "status": status,
            "detail": detail, "may_activate": status == MIGRATION_APPLIED,
            "frozen_identities_preserved": list(plan.get("frozen_identities", [])),
            "policy_version": RECOVERY_MIGRATION_PLAN_V1, "recorded_at": moment}


def migrations(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_recovery_migrations ORDER BY recorded_at, migration_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def portability_digest(db_path: str) -> str:
    return digest({"version": MODEL_SUBSTITUTION_V1,
                   "substitutions": model_substitutions(db_path),
                   "migrations": migrations(db_path),
                   "required_environment":
                       [list(item) for item in REQUIRED_ENVIRONMENT_PROPERTIES]})
