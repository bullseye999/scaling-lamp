"""
ciph/kernel/recovery_manifest - 8.2: the canonical answer to "what does Ciph need to exist?".

    Recovery is a governed state transition, not `cp backup.db live.db`.

A manifest is not a file list. It is a CLASSIFICATION of every durable family into what may be done with
it during recovery, because the same bytes are legitimate, rebuildable, forbidden, or dangerous depending
on what they are:

    MUST_RESTORE           canonical history. Lose it and the continuation claim is a lie.
    MAY_REBUILD           derived projections. Cheaper and SAFER to regenerate than to trust.
    MUST_NOT_COPY         host-specific runtime residue (pids, sockets, leases). Copying it is how a
                          restored machine inherits a dead machine's claims.
    MUST_REATTEST         identity material that must be re-measured on new hardware before it means
                          anything.
    SPECIAL_CUSTODY       root and recovery secrets. Not ordinary members of anything.
    RECONCILE_BEFORE_USE  in-flight authority. Usable after reconciliation, never before.

The manifest is integrity-BOUND: its canonical fields, versions, inclusion/exclusion decisions and
referenced artifact digests all fold into one digest, so "we changed a recovery requirement" cannot look
like "nothing changed".
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

RECOVERY_MANIFEST_V1 = "RECOVERY_MANIFEST_V1"

MUST_RESTORE = "MUST_RESTORE"
MAY_REBUILD = "MAY_REBUILD"
MUST_NOT_COPY = "MUST_NOT_COPY"
MUST_REATTEST = "MUST_REATTEST"
SPECIAL_CUSTODY = "SPECIAL_CUSTODY"
RECONCILE_BEFORE_USE = "RECONCILE_BEFORE_USE"
VALID_DISPOSITIONS = (MUST_RESTORE, MAY_REBUILD, MUST_NOT_COPY, MUST_REATTEST, SPECIAL_CUSTODY,
                      RECONCILE_BEFORE_USE)

COMPLETE = "COMPLETE"
INCOMPLETE = "INCOMPLETE"
MANIFEST_TAMPERED = "MANIFEST_TAMPERED"

REASON_UNKNOWN_MANIFEST = "UNKNOWN_RECOVERY_MANIFEST"
REASON_NOT_OPERATOR = "MANIFEST_REQUIRES_AN_OPERATOR"


@dataclass(frozen=True)
class FamilyRequirement:
    family: str
    disposition: str
    carrier: str
    note: str

    def as_dict(self) -> Dict[str, Any]:
        return {"family": self.family, "disposition": self.disposition, "carrier": self.carrier,
                "note": self.note, "policy_version": RECOVERY_MANIFEST_V1}


# THE CLASSIFICATION. Every durable family this project holds, and what recovery may do with it.
FAMILY_REQUIREMENTS: Tuple[FamilyRequirement, ...] = (
    FamilyRequirement("missions", MUST_RESTORE, "ciph_missions",
                      "mission identity and status are the spine of continuity"),
    FamilyRequirement("mission_plans", MUST_RESTORE, "ciph_mission_plans", "plan history is canonical"),
    FamilyRequirement("execution_evidence", MUST_RESTORE, "ciph_attempts/ciph_event_store",
                      "evidence is what makes history true rather than remembered"),
    FamilyRequirement("permits", RECONCILE_BEFORE_USE, "ciph_execution_permits",
                      "a restored permit is not a live permit; reconcile before it means anything"),
    FamilyRequirement("epistemic_ledger", MUST_RESTORE, "ciph_observations",
                      "the canonical observation ledger"),
    FamilyRequirement("epistemic_projections", MAY_REBUILD, "ciph_epistemic_projection",
                      "beliefs are derived; rebuild rather than trust"),
    FamilyRequirement("world_self_model", MUST_RESTORE, "ciph_world_*, ciph_self_model",
                      "canonical model state"),
    FamilyRequirement("worldview_cache", MAY_REBUILD, "ciph_mv_observations",
                      "materialized views are a cache over observations"),
    FamilyRequirement("curiosity_history", MUST_RESTORE, "ciph_uncertainty_*",
                      "what Ciph wondered and learned"),
    FamilyRequirement("crucible_history", MUST_RESTORE, "ciph_crucible_*",
                      "candidates, trials, verdicts and promotions"),
    FamilyRequirement("active_candidate_pointer", MUST_RESTORE, "ciph_crucible_active",
                      "the pointer is the constitution's answer to what is active"),
    FamilyRequirement("improvement_meta_history", MUST_RESTORE, "ciph_meta_*",
                      "meta-evolution history and epochs"),
    FamilyRequirement("evolution_epochs", MUST_RESTORE, "ciph_evolution_epochs",
                      "epoch lineage is constitutional"),
    FamilyRequirement("autonomy_sessions", MUST_RESTORE, "ciph_autonomy_sessions",
                      "continuous operation history"),
    FamilyRequirement("standing_authorizations", MUST_RESTORE, "ciph_standing_authorizations",
                      "bounded authority grants, with their revocation history"),
    FamilyRequirement("autonomy_runtime", RECONCILE_BEFORE_USE, "ciph_autonomy_work_intents",
                      "in-flight intents reconcile rather than resume"),
    FamilyRequirement("swarm_worker_history", MUST_RESTORE, "ciph_swarm_membership",
                      "worker generations are history; a restored PID is not"),
    FamilyRequirement("swarm_runtime", MUST_NOT_COPY, "ciph_swarm_leases",
                      "a restored lease would claim work on a machine that never did it"),
    FamilyRequirement("federation_membership", MUST_RESTORE, "ciph_federation_membership",
                      "who is a member is federation law"),
    FamilyRequirement("federation_authority", MUST_RESTORE, "ciph_federation_authority_domains",
                      "domain ownership and epochs"),
    FamilyRequirement("federation_transport_runtime", MUST_NOT_COPY, "ciph_transport_sessions",
                      "socket sessions are dead the moment the host is"),
    FamilyRequirement("vault_identity", SPECIAL_CUSTODY, "ciph_vault.db header + ciph.key",
                      "the vault identity is committed to the sovereign identity; the key is not a "
                      "backup member"),
    FamilyRequirement("node_keys", SPECIAL_CUSTODY, "node key material",
                      "node credentials travel by their own governed procedure, never inside an "
                      "ordinary archive"),
    FamilyRequirement("root_custody", SPECIAL_CUSTODY, "operator-held recovery root",
                      "offline by design; absence of it is UNRECOVERABLE, not an invitation to "
                      "invent one"),
    FamilyRequirement("pid_and_runtime_state", MUST_NOT_COPY, "*.pid, sockets, locks",
                      "host residue"),
    FamilyRequirement("deadman_configuration", RECONCILE_BEFORE_USE, "ciph_destruction_policy",
                      "destruction state is reportable but never auto-armed"),
    FamilyRequirement("model_configuration", MUST_REATTEST, "provider/model settings",
                      "a model configuration is an environment fact, re-measured after move"),
    FamilyRequirement("caches", MAY_REBUILD, "scratch caches", "disposable by construction"),
)

_BY_FAMILY = {item.family: item for item in FAMILY_REQUIREMENTS}

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_manifests (
        manifest_id TEXT PRIMARY KEY,
        ciph_identity_id TEXT NOT NULL,
        constitutional_versions_json TEXT NOT NULL,
        required_state_families_json TEXT NOT NULL,
        required_secret_refs_json TEXT NOT NULL,
        required_artifact_digests_json TEXT NOT NULL,
        schema_versions_json TEXT NOT NULL,
        software_revision TEXT,
        environment_requirements_json TEXT,
        model_requirements_json TEXT,
        created_from_canonical_state_digest TEXT NOT NULL,
        recovery_policy_version TEXT NOT NULL,
        manifest_digest TEXT NOT NULL,
        created_at REAL
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


def requirements(family: Optional[str] = None) -> Any:
    if family is None:
        return tuple(item.as_dict() for item in FAMILY_REQUIREMENTS)
    item = _BY_FAMILY.get(str(family))
    if item is None:
        raise CrucibleError("UNCLASSIFIED_RECOVERY_FAMILY", str(family))
    return item.as_dict()


def families_with(disposition: str) -> Tuple[str, ...]:
    if disposition not in VALID_DISPOSITIONS:
        raise CrucibleError("UNKNOWN_RECOVERY_DISPOSITION", str(disposition))
    return tuple(item.family for item in FAMILY_REQUIREMENTS if item.disposition == disposition)


def _canonical_payload(*, ciph_identity_id: str, constitutional_versions: Sequence[str],
                       required_state_families: Sequence[str], required_secret_refs: Sequence[str],
                       required_artifact_digests: Dict[str, str], schema_versions: Dict[str, str],
                       software_revision: str, environment_requirements: Sequence[str],
                       model_requirements: Sequence[str],
                       created_from_canonical_state_digest: str,
                       recovery_policy_version: str) -> Dict[str, Any]:
    return {"ciph_identity_id": str(ciph_identity_id),
            "constitutional_versions": sorted(str(item) for item in constitutional_versions),
            "required_state_families": sorted(str(item) for item in required_state_families),
            "required_secret_refs": sorted(str(item) for item in required_secret_refs),
            "required_artifact_digests": {str(k): str(v)
                                          for k, v in sorted(required_artifact_digests.items())},
            "schema_versions": {str(k): str(v) for k, v in sorted(schema_versions.items())},
            "software_revision": str(software_revision),
            "environment_requirements": sorted(str(item) for item in environment_requirements),
            "model_requirements": sorted(str(item) for item in model_requirements),
            "created_from_canonical_state_digest": str(created_from_canonical_state_digest),
            "recovery_policy_version": str(recovery_policy_version),
            "policy_version": RECOVERY_MANIFEST_V1}


def build_manifest(db_path: str, *, ciph_identity_id: str, constitutional_versions: Sequence[str],
                   required_state_families: Sequence[str], required_secret_refs: Sequence[str] = (),
                   required_artifact_digests: Optional[Dict[str, str]] = None,
                   schema_versions: Optional[Dict[str, str]] = None, software_revision: str = "dev",
                   environment_requirements: Sequence[str] = (),
                   model_requirements: Sequence[str] = (),
                   created_from_canonical_state_digest: str,
                   recovery_policy_version: str = RECOVERY_MANIFEST_V1, now: Optional[float] = None
                   ) -> Dict[str, Any]:
    """
    Freeze what a restore of this identity requires. Every family named must be CLASSIFIED.

    An unclassified family fails upward here: a manifest cannot quietly include something nobody decided
    the rules for.
    """
    for family in required_state_families:
        requirements(family)
    moment = time.time() if now is None else float(now)
    payload = _canonical_payload(
        ciph_identity_id=ciph_identity_id, constitutional_versions=constitutional_versions,
        required_state_families=required_state_families, required_secret_refs=required_secret_refs,
        required_artifact_digests=dict(required_artifact_digests or {}),
        schema_versions=dict(schema_versions or {}), software_revision=software_revision,
        environment_requirements=environment_requirements, model_requirements=model_requirements,
        created_from_canonical_state_digest=created_from_canonical_state_digest,
        recovery_policy_version=recovery_policy_version)
    manifest_digest = digest(payload)
    manifest_id = "RM-" + manifest_digest[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_recovery_manifests (manifest_id, ciph_identity_id, "
            "constitutional_versions_json, required_state_families_json, required_secret_refs_json, "
            "required_artifact_digests_json, schema_versions_json, software_revision, "
            "environment_requirements_json, model_requirements_json, "
            "created_from_canonical_state_digest, recovery_policy_version, manifest_digest, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (manifest_id, str(ciph_identity_id),
             json.dumps(payload["constitutional_versions"]),
             json.dumps(payload["required_state_families"]),
             json.dumps(payload["required_secret_refs"]),
             json.dumps(payload["required_artifact_digests"]),
             json.dumps(payload["schema_versions"]), str(software_revision),
             json.dumps(payload["environment_requirements"]),
             json.dumps(payload["model_requirements"]),
             str(created_from_canonical_state_digest), str(recovery_policy_version),
             manifest_digest, moment))
        connection.commit()
    finally:
        connection.close()
    return get_manifest(db_path, manifest_id)


def get_manifest(db_path: str, manifest_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_recovery_manifests WHERE manifest_id = ?;",
                                 (str(manifest_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_MANIFEST, str(manifest_id))
    row = dict(row)
    return {"manifest_id": str(row["manifest_id"]), "ciph_identity_id": str(row["ciph_identity_id"]),
            "constitutional_versions": json.loads(row["constitutional_versions_json"] or "[]"),
            "required_state_families": json.loads(row["required_state_families_json"] or "[]"),
            "required_secret_refs": json.loads(row["required_secret_refs_json"] or "[]"),
            "required_artifact_digests": json.loads(row["required_artifact_digests_json"] or "{}"),
            "schema_versions": json.loads(row["schema_versions_json"] or "{}"),
            "software_revision": row["software_revision"],
            "environment_requirements": json.loads(row["environment_requirements_json"] or "[]"),
            "model_requirements": json.loads(row["model_requirements_json"] or "[]"),
            "created_from_canonical_state_digest": str(row["created_from_canonical_state_digest"]),
            "recovery_policy_version": str(row["recovery_policy_version"]),
            "manifest_digest": str(row["manifest_digest"]), "created_at": row["created_at"]}


def recompute_digest(manifest: Dict[str, Any]) -> str:
    return digest(_canonical_payload(
        ciph_identity_id=manifest["ciph_identity_id"],
        constitutional_versions=manifest["constitutional_versions"],
        required_state_families=manifest["required_state_families"],
        required_secret_refs=manifest["required_secret_refs"],
        required_artifact_digests=manifest["required_artifact_digests"],
        schema_versions=manifest["schema_versions"], software_revision=manifest["software_revision"],
        environment_requirements=manifest["environment_requirements"],
        model_requirements=manifest["model_requirements"],
        created_from_canonical_state_digest=manifest["created_from_canonical_state_digest"],
        recovery_policy_version=manifest["recovery_policy_version"]))


def assert_manifest_integrity(db_path: str, manifest_id: str) -> Dict[str, Any]:
    """
    A stored manifest whose fields no longer hash to its own digest has been TAMPERED WITH.

    This is why a changed recovery requirement cannot pass as no change: the requirement IS the digest.
    """
    manifest = get_manifest(db_path, manifest_id)
    if recompute_digest(manifest) != manifest["manifest_digest"]:
        raise CrucibleError(MANIFEST_TAMPERED, str(manifest_id))
    return manifest


def verify_manifest(db_path: str, manifest_id: str, *, present_families: Sequence[str] = (),
                    observed_artifacts: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    try:
        manifest = assert_manifest_integrity(db_path, manifest_id)
    except CrucibleError:
        return {"manifest_id": str(manifest_id), "status": MANIFEST_TAMPERED,
                "missing_families": [], "missing_artifacts": []}
    present = {str(item) for item in present_families}
    missing_families = tuple(sorted(set(manifest["required_state_families"]) - present))
    observed = dict(observed_artifacts or {})
    # ABSENCE OF AN OBSERVATION IS NOT A MISMATCH. A caller that supplies no artifact digests has not
    # checked them, and saying "missing" would be inventing a failure; saying "complete" while hiding
    # that nothing was checked would be worse. So it is reported, explicitly, as unchecked.
    missing_artifacts = tuple(sorted(
        name for name, expected in manifest["required_artifact_digests"].items()
        if name in observed and observed[name] != expected))
    status = COMPLETE if not missing_families and not missing_artifacts else INCOMPLETE
    return {"manifest_id": manifest["manifest_id"], "status": status,
            "missing_families": list(missing_families), "missing_artifacts": list(missing_artifacts),
            "artifacts_checked": bool(observed),
            "required_state_families": list(manifest["required_state_families"])}


def manifest_history(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT manifest_id, ciph_identity_id, manifest_digest, created_at "
            "FROM ciph_recovery_manifests ORDER BY created_at, manifest_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def manifest_digest(db_path: str) -> str:
    return digest({"version": RECOVERY_MANIFEST_V1,
                   "requirements": [item.as_dict() for item in FAMILY_REQUIREMENTS],
                   "manifests": manifest_history(db_path)})
