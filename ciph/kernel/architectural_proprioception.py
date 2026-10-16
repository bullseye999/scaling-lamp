"""
ciph/kernel/architectural_proprioception - 10.4: evidence-grounded observation of Ciph's own anatomy.

    A Ciph that inspects its own architecture must FIRST be unable to lie to itself about it.

FOUR VIEWS, NEVER COLLAPSED.  The single most tempting error in self-observation is to collapse "the file
on disk" and "the code actually running" into "my implementation". They are different facts:

    SOURCE     what source files and declared components/dependencies are present in the observed tree
    INSTALLED  what artifact bytes and configuration are present in the selected installed environment
    LOADED     what implementation a running process actually loaded, WHERE A LOAD-TIME WITNESS EXISTS
    EXECUTED   what operations have attributable, authoritative execution evidence

Rehashing a changed file on disk does NOT establish that a running process loaded the changed version, so
the LOADED view is a LOAD-TIME WITNESS - a digest captured when a process actually imported the code.
Without such a witness the answer is UNRESOLVED, never "probably the source". `witness_loaded` therefore
REQUIRES a captured digest; it will not silently digest the file for you, because that is the exact
substitution this view exists to prevent.

SELF-OBSERVATION TRUST BOUNDARY (the central law).  Ciph cannot certify its own architectural integrity
solely through evidence produced by the same observer it is evaluating. `integrity_claim` refuses a
self-certification and reports DISPUTED when independent witnesses disagree. An ownership census is POLICY
- a versioned reference - not a cryptographic root of trust: the code that computes it can be modified by
the same privileged attacker it is meant to catch, and that limitation is STATED here rather than hidden.
No hardware-backed attestation is claimed while CiphOS 9.x certification remains on HOLD.

EVIDENCE BEFORE ASSERTION.  Every observation optionally carries a durable 4.2 observation reference; this
module owns RELATIONSHIPS and PROJECTIONS over canonical evidence, not facts, and it mints no authority:
an observation of a change never authorizes installing, promoting, restarting or modifying anything.
"""

import hashlib
import json
import os
import pathlib
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

ARCHITECTURAL_PROPRIOCEPTION_V1 = "ARCHITECTURAL_PROPRIOCEPTION_V1"
ARCH_COMPONENT_V1 = "ARCH_COMPONENT_V1"
ARCH_VIEW_V1 = "ARCH_VIEW_V1"
ARCH_CHANGE_V1 = "ARCH_CHANGE_V1"

SOURCE = "SOURCE"
INSTALLED = "INSTALLED"
LOADED = "LOADED"
EXECUTED = "EXECUTED"
ARCHITECTURAL_VIEWS = (SOURCE, INSTALLED, LOADED, EXECUTED)

OBSERVED = "OBSERVED"
UNRESOLVED = "UNRESOLVED"

MATCH = "MATCH"
MISMATCH = "MISMATCH"
UNKNOWN = "UNKNOWN"

# Change provenance. An authorized deployment record is evidence of an INTENDED action; it becomes
# AUTHORIZED_DEPLOYMENT only once the actually-installed bytes are independently corroborated.
AUTHORIZED_DEPLOYMENT = "AUTHORIZED_DEPLOYMENT"
AUTHORIZED_BUT_UNVERIFIED = "AUTHORIZED_BUT_UNVERIFIED"
# The earlier name is retained as an ALIAS of the same value so existing readers keep working; the meaning
# is now precise - authorized, but the installed bytes were not independently corroborated.
AUTHORIZED_DEPLOYMENT_MISMATCH = AUTHORIZED_BUT_UNVERIFIED
UNKNOWN_PROVENANCE = "UNKNOWN_PROVENANCE"
UNAUTHORIZED_MODIFICATION = "UNAUTHORIZED_MODIFICATION"
OBSERVATION_GAP = "OBSERVATION_GAP"

# Integrity claim dispositions.
SELF_CERTIFICATION_REFUSED = "SELF_CERTIFICATION_REFUSED"
CORROBORATED = "CORROBORATED"
DISPUTED = "DISPUTED"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

FRESH = "FRESH"
STALE = "STALE"

REASON_LOAD_WITNESS_REQUIRES_A_CAPTURED_DIGEST = "LOAD_WITNESS_REQUIRES_A_CAPTURED_DIGEST"
REASON_EXECUTION_EVIDENCE_NOT_CANONICAL = "EXECUTION_EVIDENCE_NOT_CANONICAL"
REASON_PROTECTED_ARTIFACT = "PROTECTED_ARTIFACT_CANNOT_BE_OBSERVED"
REASON_UNKNOWN_COMPONENT = "UNKNOWN_COMPONENT"

# A component is observed by DIGEST. Anything whose CONTENT is a secret or a sealed held-out set is never
# read into the projection, so introspection cannot become an exfiltration path.
_PROTECTED_SUFFIXES = (".key", ".salt", ".pem", ".db", ".db-wal", ".db-shm", ".env", ".sqlite", ".sqlite3")
_PROTECTED_TOKENS = ("vault", "secret", "credential", "private_key", "rootkey", "heldout", "held_out",
                     "meta_corpus", "sealed_eval", "evaluation_answers")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_arch_components (
        component_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        path TEXT,
        dependencies_json TEXT,
        ownership_ref TEXT,
        policy_version TEXT NOT NULL,
        registered_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_arch_observations (
        arch_observation_id TEXT PRIMARY KEY,
        component_id TEXT NOT NULL,
        view TEXT NOT NULL,
        digest TEXT,
        runtime_generation TEXT,
        observer_ref TEXT NOT NULL,
        independent INTEGER NOT NULL,
        detail_json TEXT,
        evidence_ref TEXT,
        observed_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_arch_changes (
        change_id TEXT PRIMARY KEY,
        component_id TEXT NOT NULL,
        view TEXT NOT NULL,
        previous_digest TEXT,
        current_digest TEXT,
        provenance TEXT NOT NULL,
        authorization_ref TEXT,
        verified_installed_digest TEXT,
        uncertainty TEXT,
        evidence_json TEXT,
        affected_json TEXT,
        invented_history INTEGER NOT NULL,
        recorded_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
)


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


def init_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        connection.execute(statement)


def _row_id(prefix: str, payload: Dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return prefix + hashlib.sha256(body.encode("utf-8")).hexdigest()[:12].upper()


def _moment(now: Optional[float]) -> float:
    return time.time() if now is None else float(now)


# ------------------------------------------------------------------ digests and the secret guard
def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_time_digest(path: Any) -> str:
    """Digest a file AS THE LOADING PROCESS SEES IT. Call this at import/first-use time, not later."""
    return digest_bytes(pathlib.Path(path).read_bytes())


def is_protected_artifact(path: Any) -> bool:
    """True when an artifact's CONTENT must never be read into a projection (keys, vaults, held-out set)."""
    text = str(path).lower()
    if text.endswith(_PROTECTED_SUFFIXES):
        return True
    name = pathlib.Path(text).name
    return any(token in name for token in _PROTECTED_TOKENS)


def _guard_artifact(path: Any) -> str:
    if is_protected_artifact(path):
        raise CrucibleError(REASON_PROTECTED_ARTIFACT, str(path))
    return str(path)


def _digest_artifact(path: Any) -> str:
    return digest_bytes(pathlib.Path(_guard_artifact(path)).read_bytes())


# ------------------------------------------------------------------ components
def register_component(db_path: str, *, component_id: str, kind: str = "module",
                       path: Optional[str] = None, dependencies: Sequence[str] = (),
                       ownership_ref: Optional[str] = None, now: Optional[float] = None) -> str:
    """Declare a component and its dependencies. Declaring a component asserts nothing about it."""
    key = str(component_id).strip()
    if not key:
        raise CrucibleError("COMPONENT_REQUIRES_AN_ID", repr(component_id))
    moment = _moment(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_arch_components (component_id, kind, path, dependencies_json, "
            "ownership_ref, policy_version, registered_at) VALUES (?,?,?,?,?,?,?);",
            (key, str(kind), path, json.dumps(sorted(str(dep) for dep in dependencies)),
             ownership_ref, ARCH_COMPONENT_V1, moment))
        connection.commit()
    finally:
        connection.close()
    return key


def components(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_arch_components ORDER BY component_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    for row in rows:
        row["dependencies"] = json.loads(row.pop("dependencies_json") or "[]")
    return rows


def _require_component(db_path: str, component_id: str) -> Dict[str, Any]:
    for record in components(db_path):
        if record["component_id"] == str(component_id):
            return record
    raise CrucibleError(REASON_UNKNOWN_COMPONENT, str(component_id))


# ------------------------------------------------------------------ recording observations
def _record_observation(db_path: str, *, component_id: str, view: str, artifact_digest: Optional[str],
                        runtime_generation: Optional[str], observer_ref: str, independent: bool,
                        detail: Optional[Dict[str, Any]] = None, evidence_ref: Optional[str] = None,
                        now: Optional[float] = None) -> Dict[str, Any]:
    if view not in ARCHITECTURAL_VIEWS:
        raise CrucibleError("INVALID_ARCHITECTURAL_VIEW", str(view))
    moment = _moment(now)
    observation_id = _row_id("AO-", {"component": component_id, "view": view, "digest": artifact_digest,
                                     "generation": runtime_generation, "observer": observer_ref,
                                     "at": moment})
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_arch_observations (arch_observation_id, component_id, view, "
            "digest, runtime_generation, observer_ref, independent, detail_json, evidence_ref, "
            "observed_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (observation_id, str(component_id), view, artifact_digest,
             None if runtime_generation is None else str(runtime_generation), str(observer_ref),
             1 if independent else 0, json.dumps(detail or {}, sort_keys=True), evidence_ref, moment,
             ARCH_VIEW_V1))
        connection.commit()
    finally:
        connection.close()
    return {"arch_observation_id": observation_id, "component_id": str(component_id), "view": view,
            "digest": artifact_digest, "runtime_generation": runtime_generation,
            "observer_ref": observer_ref, "independent": bool(independent), "evidence_ref": evidence_ref,
            "observed_at": moment, "policy_version": ARCH_VIEW_V1}


def observe_source(db_path: str, *, component_id: str, path: Optional[str] = None,
                   source_ref: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """Digest what is ON DISK in the source tree, and say only that."""
    record = _require_component(db_path, component_id)
    target = path or record.get("path")
    if not target:
        raise CrucibleError("SOURCE_OBSERVATION_REQUIRES_A_PATH", str(component_id))
    artifact_digest = _digest_artifact(target)
    return _record_observation(db_path, component_id=component_id, view=SOURCE,
                               artifact_digest=artifact_digest, runtime_generation=None,
                               observer_ref="local-source-observer", independent=False,
                               detail={"path": str(target)}, evidence_ref=source_ref, now=now)


def observe_installed(db_path: str, *, component_id: str, artifact_path: str,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """Digest the artifact bytes present in the INSTALLED environment. Says nothing about execution."""
    _require_component(db_path, component_id)
    artifact_digest = _digest_artifact(artifact_path)
    return _record_observation(db_path, component_id=component_id, view=INSTALLED,
                               artifact_digest=artifact_digest, runtime_generation=None,
                               observer_ref="local-installed-observer", independent=False,
                               detail={"artifact_path": str(artifact_path)}, now=now)


def witness_loaded(db_path: str, *, component_id: str, digest: str, runtime_generation: str,
                   module_ref: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record what a RUNNING process actually loaded.

    `digest` must be captured AT LOAD (see `load_time_digest`). Refusing to digest the file here is the
    whole point: a later re-hash of a file that changed on disk would corrupt this view into "the source".
    """
    _require_component(db_path, component_id)
    if not str(digest or "").strip():
        raise CrucibleError(REASON_LOAD_WITNESS_REQUIRES_A_CAPTURED_DIGEST, str(component_id))
    return _record_observation(db_path, component_id=component_id, view=LOADED,
                               artifact_digest=str(digest), runtime_generation=str(runtime_generation),
                               observer_ref="load-time-witness", independent=False,
                               detail={"module_ref": module_ref, "captured_at_load": True}, now=now)


def observe_executed(db_path: str, *, component_id: str, execution_ref: str,
                     runtime_generation: Optional[str] = None, now: Optional[float] = None
                     ) -> Dict[str, Any]:
    """
    Record that an operation ACTUALLY EXECUTED, from canonical execution evidence only.

    A model's sentence is not execution evidence. `execution_ref` must resolve in the 4.3 empirical
    execution record; a "model output" reference is refused.
    """
    _require_component(db_path, component_id)
    ref = str(execution_ref or "").strip()
    if ref not in _canonical_execution_refs(db_path):
        raise CrucibleError(REASON_EXECUTION_EVIDENCE_NOT_CANONICAL, ref)
    return _record_observation(db_path, component_id=component_id, view=EXECUTED,
                               artifact_digest=None, runtime_generation=runtime_generation,
                               observer_ref="canonical-execution-evidence", independent=False,
                               detail={"execution_ref": ref}, evidence_ref=ref, now=now)


def _canonical_execution_refs(db_path: str) -> Dict[str, Dict[str, Any]]:
    """The canonical execution evidence owner is the 4.3 empirical execution record."""
    connection = _connect(db_path, read_only=True)
    try:
        return {str(row["record_id"]): dict(row) for row in connection.execute(
            "SELECT * FROM ciph_self_executions;")}
    except sqlite3.Error:
        return {}
    finally:
        connection.close()


def witness_observation(db_path: str, *, component_id: str, view: str, digest: str,
                        observer_ref: str, independent: bool = True,
                        runtime_generation: Optional[str] = None, now: Optional[float] = None
                        ) -> Dict[str, Any]:
    """Record an observation made by ANOTHER observer. Pairwise witnesses are what the trust boundary uses."""
    _require_component(db_path, component_id)
    return _record_observation(db_path, component_id=component_id, view=view, artifact_digest=str(digest),
                               runtime_generation=runtime_generation, observer_ref=str(observer_ref),
                               independent=bool(independent), now=now)


def observations(db_path: str, *, component_id: Optional[str] = None,
                 view: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_arch_observations"
    clauses, params = [], []
    if component_id is not None:
        clauses.append("component_id = ?")
        params.append(str(component_id))
    if view is not None:
        clauses.append("view = ?")
        params.append(str(view))
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY observed_at, arch_observation_id;"
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    for row in rows:
        row["independent"] = bool(row["independent"])
        row["detail"] = json.loads(row.pop("detail_json") or "{}")
    return rows


def latest_view(db_path: str, component_id: str, view: str) -> Dict[str, Any]:
    for row in reversed(observations(db_path, component_id=component_id, view=view)):
        return row
    return {"component_id": str(component_id), "view": view, "status": UNRESOLVED,
            "digest": None, "policy_version": ARCH_VIEW_V1}


# ------------------------------------------------------------------ the four-view projection
def _relation(left: Optional[str], right: Optional[str]) -> str:
    if left is None or right is None:
        return UNKNOWN
    return MATCH if left == right else MISMATCH


def project_component(db_path: str, component_id: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """
    The FOUR views, kept distinct. There is deliberately no single "current implementation digest" here:
    collapsing the views is the error the module exists to prevent.
    """
    record = _require_component(db_path, component_id)
    views = {view: latest_view(db_path, component_id, view) for view in ARCHITECTURAL_VIEWS}
    source = views[SOURCE].get("digest")
    installed = views[INSTALLED].get("digest")
    loaded = views[LOADED].get("digest")
    return {
        "component_id": record["component_id"], "kind": record["kind"], "path": record.get("path"),
        "dependencies": record.get("dependencies", []),
        "views": views,
        "distinctions": {
            "source_vs_installed": _relation(source, installed),
            "installed_vs_loaded": _relation(installed, loaded),
            "source_vs_loaded": _relation(source, loaded),
            "loaded_is_resolved": views[LOADED].get("status") != UNRESOLVED,
            "executed_is_resolved": views[EXECUTED].get("status") != UNRESOLVED,
        },
        "collapsed": False,
        "authority": "OBSERVATION_ONLY",
        "policy_version": ARCHITECTURAL_PROPRIOCEPTION_V1,
    }


def architectural_projection(db_path: str, *, component: Optional[str] = None,
                             now: Optional[float] = None) -> Dict[str, Any]:
    if component is not None:
        return project_component(db_path, component, now=now)
    return {"policy_version": ARCHITECTURAL_PROPRIOCEPTION_V1, "collapsed": False,
            "components": {record["component_id"]: project_component(db_path, record["component_id"],
                                                                     now=now)
                           for record in components(db_path)}}


# ------------------------------------------------------------------ change witnessing
def correlate_deployment(db_path: str, deployment_id: str) -> Dict[str, Any]:
    """
    Read the R7 deployment owner's record for correlation. The record is evidence of an INTENDED action;
    it is not by itself proof of what is installed.
    """
    from ciph.kernel.evolution_deployment import get_deployment
    try:
        record = get_deployment(db_path, deployment_id)
    except CrucibleError:
        return {"found": False, "deployment_id": str(deployment_id)}
    return {"found": True, "deployment_id": record.deployment_id, "role": record.role,
            "candidate_id": record.candidate_id, "artifact_digest": record.artifact_digest,
            "installed_artifact_digest": record.installed_artifact_digest, "status": record.status,
            "authorization_ref": record.authorization_ref}


def witness_change(db_path: str, *, component_id: str, view: str, previous_digest: Optional[str],
                   current_digest: Optional[str], authorization_ref: Optional[str] = None,
                   verified_installed_digest: Optional[str] = None, evidence: Sequence[str] = (),
                   affected: Sequence[str] = (), uncertainty: Optional[str] = None,
                   now: Optional[float] = None) -> Dict[str, Any]:
    """
    Witness a change to a component in ONE view, and classify its provenance HONESTLY.

    THREE DISTINCT ANSWERS, because conflating them invents an actor.

        UNKNOWN_PROVENANCE           no authorization record could be correlated. That is an absence of
                                     knowledge, NOT a claim that the change was unauthorized.
        UNAUTHORIZED_MODIFICATION    an authorization record EXISTS and was refused or failed, yet the
                                     bytes changed - positive evidence that the change outran authority.
        AUTHORIZED_BUT_UNVERIFIED    a VERIFIED deployment authorized the change, but the installed bytes
                                     were not independently corroborated against it.
        AUTHORIZED_DEPLOYMENT        a VERIFIED deployment authorized it AND the installed bytes match.

    The absence of a correlated record is never evidence of an unauthorized actor.
    """
    _require_component(db_path, component_id)
    moment = _moment(now)
    correlation = correlate_deployment(db_path, authorization_ref) if authorization_ref else {"found": False}
    if not authorization_ref or not correlation.get("found"):
        # NO CORRELATED AUTHORIZATION RECORD. This is an absence of knowledge: the observer does not know
        # who changed the bytes, and it will not manufacture an unauthorized actor out of that absence.
        provenance = UNKNOWN_PROVENANCE
        uncertainty = uncertainty or ("no authorization record was correlated; provenance is unknown, "
                                      "which is not a claim that the change was unauthorized")
    elif str(correlation.get("status")) != "VERIFIED":
        # An authorization record EXISTS and was refused or failed, yet the bytes changed.
        provenance = UNAUTHORIZED_MODIFICATION
        uncertainty = uncertainty or (f"authorization record is {correlation.get('status')}, not VERIFIED")
    elif verified_installed_digest is None or verified_installed_digest != current_digest:
        provenance = AUTHORIZED_BUT_UNVERIFIED
        uncertainty = uncertainty or "installed bytes do not match the independently observed artifact"
    else:
        provenance = AUTHORIZED_DEPLOYMENT
    change_id = _row_id("ACH-", {"component": component_id, "view": view, "previous": previous_digest,
                                 "current": current_digest, "provenance": provenance,
                                 "authorization": authorization_ref})
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_arch_changes (change_id, component_id, view, previous_digest, "
            "current_digest, provenance, authorization_ref, verified_installed_digest, uncertainty, "
            "evidence_json, affected_json, invented_history, recorded_at, policy_version) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (change_id, str(component_id), str(view), previous_digest, current_digest, provenance,
             authorization_ref, verified_installed_digest, uncertainty,
             json.dumps(sorted(str(item) for item in evidence)), json.dumps(sorted(str(item) for item in affected)),
             0, moment, ARCH_CHANGE_V1))
        connection.commit()
    finally:
        connection.close()
    return {"change_id": change_id, "component_id": str(component_id), "view": str(view),
            "previous_digest": previous_digest, "current_digest": current_digest,
            "provenance": provenance, "authorized": provenance == AUTHORIZED_DEPLOYMENT,
            "authorization_ref": authorization_ref, "verified_installed_digest": verified_installed_digest,
            "uncertainty": uncertainty, "affected": sorted(str(item) for item in affected),
            "evidence": sorted(str(item) for item in evidence), "invented_history": False,
            "recorded_at": moment, "policy_version": ARCH_CHANGE_V1}


def record_observation_gap(db_path: str, *, component_id: str, missing_from: float, missing_to: float,
                           reason: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    An interval in which NO observer was watching is a GAP. The history is not filled in: no digests are
    invented and `invented_history` stays False, because an offline observer cannot know what happened.
    """
    _require_component(db_path, component_id)
    moment = _moment(now)
    change_id = _row_id("ACH-", {"component": component_id, "view": SOURCE, "gap": [missing_from, missing_to],
                                 "reason": reason})
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_arch_changes (change_id, component_id, view, previous_digest, "
            "current_digest, provenance, authorization_ref, verified_installed_digest, uncertainty, "
            "evidence_json, affected_json, invented_history, recorded_at, policy_version) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (change_id, str(component_id), SOURCE, None, None, OBSERVATION_GAP, None, None, str(reason),
             json.dumps([]), json.dumps([]), 0, moment, ARCH_CHANGE_V1))
        connection.commit()
    finally:
        connection.close()
    return {"change_id": change_id, "component_id": str(component_id), "view": SOURCE,
            "provenance": OBSERVATION_GAP, "authorized": False, "missing_from": float(missing_from),
            "missing_to": float(missing_to), "reason": str(reason), "invented_history": False,
            "policy_version": ARCH_CHANGE_V1}


def changes(db_path: str, *, component_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_arch_changes"
    params: Tuple[Any, ...] = ()
    if component_id is not None:
        query += " WHERE component_id = ?"
        params = (str(component_id),)
    query += " ORDER BY recorded_at, change_id;"
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(query, params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    for row in rows:
        row["evidence"] = json.loads(row.pop("evidence_json") or "[]")
        row["affected"] = json.loads(row.pop("affected_json") or "[]")
        row["invented_history"] = bool(row["invented_history"])
    return rows


# ------------------------------------------------------------------ self-observation trust boundary
def policy_reference() -> Dict[str, Any]:
    """
    The ownership censuses, as a VERSIONED POLICY REFERENCE.

    This is explicitly NOT a cryptographic root of trust: the code computing these digests lives in the
    same trust domain as everything else, so an attacker who can modify the observer can also modify its
    policy. The reference says which policy the observations were compared against - no more.
    """
    reference: Dict[str, Any] = {}
    try:
        from ciph.kernel.referential_ownership import ownership_digest as referential_digest
        reference["R14_referential"] = referential_digest()
    except Exception as exc:  # pragma: no cover - a missing census is itself reported
        reference["R14_referential"] = f"unavailable:{type(exc).__name__}"
    try:
        from ciph.kernel.environment_ownership import ownership_digest as environment_digest
        reference["R13_environment"] = environment_digest()
    except Exception as exc:  # pragma: no cover
        reference["R13_environment"] = f"unavailable:{type(exc).__name__}"
    return {"policy_version": ARCHITECTURAL_PROPRIOCEPTION_V1, "censuses": reference,
            "is_cryptographic_root_of_trust": False,
            "shared_compromise_limitation": "observer and policy share one trust domain; a privileged "
                                            "attacker able to modify the observer can modify this policy",
            "hardware_attestation_claimed": False,
            "note": "CiphOS 9.x host certification is on HOLD, so no TPM/UEFI/measured-boot guarantee "
                    "is asserted here"}


def integrity_claim(db_path: str, *, component_id: str, view: str = SOURCE,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    Decide what Ciph may claim about a component's integrity - and REFUSE the claim it cannot make.

    Evidence produced by the local observer alone cannot certify the component the observer is part of.
    Independent witnesses that agree produce CORROBORATED; independent witnesses that disagree produce
    DISPUTED and nothing is chosen between them.
    """
    _require_component(db_path, component_id)
    rows = observations(db_path, component_id=component_id, view=view)
    if not rows:
        return {"component_id": str(component_id), "view": str(view), "status": INSUFFICIENT_EVIDENCE,
                "digests": [], "policy_version": ARCHITECTURAL_PROPRIOCEPTION_V1}
    self_digests = {row["digest"] for row in rows if not row["independent"]}
    independent = {row["observer_ref"]: row["digest"] for row in rows if row["independent"]}
    independent_digests = set(independent.values())

    if not independent:
        return {"component_id": str(component_id), "view": str(view),
                "status": SELF_CERTIFICATION_REFUSED, "self_digests": sorted(self_digests),
                "witnesses": 0, "policy_version": ARCHITECTURAL_PROPRIOCEPTION_V1,
                "reason": "a component cannot certify itself solely through the observer's own evidence"}
    if len(independent_digests) > 1:
        return {"component_id": str(component_id), "view": str(view), "status": DISPUTED,
                "witnesses": len(independent), "observed": sorted(independent_digests),
                "policy_version": ARCHITECTURAL_PROPRIOCEPTION_V1,
                "reason": "independent witnesses disagree; no winner is chosen"}
    agreed = next(iter(independent_digests))
    status = CORROBORATED
    if self_digests and agreed not in self_digests:
        status = DISPUTED
    return {"component_id": str(component_id), "view": str(view), "status": status,
            "witnesses": len(independent), "observed": sorted(independent_digests),
            "agrees_with_local": (not self_digests) or agreed in self_digests,
            "policy_version": ARCHITECTURAL_PROPRIOCEPTION_V1}


def classify_freshness(observed_at: Optional[float], *, now: Optional[float], ttl: float) -> str:
    """An old observation is STALE, not current; a missing observation is UNKNOWN, not fresh."""
    if observed_at is None:
        return UNKNOWN
    moment = _moment(now)
    return FRESH if (moment - float(observed_at)) <= float(ttl) else STALE


def record_model_architectural_claim(db_path: str, *, model_ref: str, output_text: str,
                                     component_id: Optional[str] = None,
                                     now: Optional[float] = None) -> Dict[str, Any]:
    """A model's sentence about the architecture is MODEL OUTPUT (4.2), and can never be execution evidence."""
    from ciph.kernel.epistemic_ledger import record_model_output
    record = record_model_output(db_path, model_ref=str(model_ref), output_text=str(output_text),
                                 now=now)
    return {"model_output": record, "canonical_execution": False, "is_architectural_evidence": False,
            "component_id": component_id,
            "note": "a model assertion is recorded as model output and cannot become EXECUTED evidence"}


# ------------------------------------------------------------------ explanation over the evidence
def explain(db_path: str, *, component: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Answer the self-model questions FROM EVIDENCE. The reasoning model explains this; it does not invent it.
    """
    scoped = [component] if component is not None else [record["component_id"] for record in components(db_path)]
    projections = {name: project_component(db_path, name, now=now) for name in scoped}
    observed_changes = [change for change in changes(db_path) if component is None or change["component_id"] in scoped]
    return {
        "policy_version": ARCHITECTURAL_PROPRIOCEPTION_V1,
        "components_with_evidence": sorted(name for name, projection in projections.items()
                                           if any(view.get("status", OBSERVED) != UNRESOLVED
                                                  for view in projection["views"].values())),
        "running_implementation": {name: projection["views"][LOADED] for name, projection
                                   in projections.items()
                                   if projection["views"][LOADED].get("status", OBSERVED) != UNRESOLVED},
        "changed_on_disk": [change for change in observed_changes if change["view"] == SOURCE
                            and change["provenance"] != OBSERVATION_GAP],
        "installed_but_not_loaded": [name for name, projection in projections.items()
                                     if projection["distinctions"]["installed_vs_loaded"] == MISMATCH],
        "operations_that_executed": {name: projection["views"][EXECUTED] for name, projection
                                     in projections.items()
                                     if projection["views"][EXECUTED].get("status", OBSERVED) != UNRESOLVED},
        "authorized_changes": [change["change_id"] for change in observed_changes
                               if change["provenance"] == AUTHORIZED_DEPLOYMENT],
        "dependent_components_of_changes": sorted({dependent for change in observed_changes
                                                   for dependent in change["affected"]}),
        "uncertain": {
            "unresolved_views": {name: [view for view, record in projection["views"].items()
                                        if record.get("status", OBSERVED) == UNRESOLVED]
                                 for name, projection in projections.items()},
            "observation_gaps": [change["change_id"] for change in observed_changes
                                 if change["provenance"] == OBSERVATION_GAP],
            "unauthorized_or_unknown": [change["change_id"] for change in observed_changes
                                        if change["provenance"] in (UNAUTHORIZED_MODIFICATION,
                                                                    UNKNOWN_PROVENANCE,
                                                                    AUTHORIZED_BUT_UNVERIFIED)],
        },
        "policy_reference": policy_reference(),
    }


def architectural_digest(db_path: str) -> str:
    payload = {
        "components": components(db_path),
        "projection": architectural_projection(db_path),
        "changes": changes(db_path),
    }
    return digest(payload)
