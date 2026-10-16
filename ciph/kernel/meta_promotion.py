"""
ciph/kernel/meta_promotion - 4.7 Gate Five: dual control, and the epoch transition it authorizes.

Ordinary promotion needs a Crucible standing and governance. Meta promotion needs more, and for 4.7 V1
it needs all of:

    shadow period complete (ELIGIBLE)
    + meta-protocol standing DOMINATES
    + ordinary Crucible standing DOMINATES
    + hard invariants clean
    + explicit external authorization

THE ORDERING IS THE LAW. Authority is never inferred from the filesystem, and the epoch is never
created before the bytes are:

    MetaPromotionRecord -> R7 governed deployment -> exact bytes verified -> new EvolutionEpoch

A deployment that fails creates no epoch. Bytes that land but an epoch transition that fails is an
explicit integrity state - META_DEPLOYMENT_RECONCILIATION_REQUIRED - not a silent success.

Rollback follows the same shape as everywhere else in this constitution: the canonical decision lands
FIRST (a new epoch that inherits the restored configuration), and only then may a mechanism restore
bytes.
"""

import json
import pathlib
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_metrics import STATUS_DOMINATES
from ciph.kernel.crucible_promotion import promote
from ciph.kernel.crucible_types import CrucibleError, digest
from ciph.kernel.evolution_deployment import deployment_history, deploy
from ciph.kernel.evolution_epochs import (
    current_epoch,
    get_epoch,
    rollback_epoch,
    rollback_history,
    transition_epoch,
)
from ciph.kernel.meta_shadow import STATUS_ELIGIBLE, get_shadow
from ciph.kernel.meta_targets import RING_CONSTITUTIONAL_ROOT

META_PROMOTION_V1 = "META_PROMOTION_V1"
META_DEPLOYMENT_RECONCILIATION_REQUIRED = "META_DEPLOYMENT_RECONCILIATION_REQUIRED"

REASON_SHADOW_NOT_ELIGIBLE = "SHADOW_NOT_ELIGIBLE"
REASON_META_STANDING = "META_STANDING_NOT_DOMINATES"
REASON_ORDINARY_STANDING = "ORDINARY_STANDING_NOT_DOMINATES"
REASON_AUTHORIZATION = "EXTERNAL_AUTHORIZATION_REQUIRED"
REASON_ALREADY_PROMOTED = "META_COMPONENT_ALREADY_PROMOTED"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_promotions (
        meta_promotion_id TEXT PRIMARY KEY,
        meta_candidate_id TEXT NOT NULL,
        shadow_id TEXT NOT NULL,
        target_component TEXT NOT NULL,
        target_role TEXT NOT NULL,
        old_component_identity TEXT,
        new_component_identity TEXT NOT NULL,
        old_epoch_id TEXT,
        new_epoch_id TEXT,
        meta_protocol_result_ref TEXT,
        ordinary_crucible_ref TEXT,
        external_authorization_ref TEXT NOT NULL,
        deployment_id TEXT,
        installed_artifact_digest TEXT,
        promoted_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetaPromotionRecord:
    meta_promotion_id: str
    meta_candidate_id: str
    shadow_id: str
    target_component: str
    target_role: str
    old_component_identity: Optional[str]
    new_component_identity: str
    old_epoch_id: Optional[str]
    new_epoch_id: str
    meta_protocol_result_ref: Optional[str]
    ordinary_crucible_ref: Optional[str]
    external_authorization_ref: str
    deployment_id: Optional[str]
    installed_artifact_digest: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"meta_promotion_id": self.meta_promotion_id,
                "meta_candidate_id": self.meta_candidate_id, "shadow_id": self.shadow_id,
                "target_component": self.target_component, "target_role": self.target_role,
                "old_component_identity": self.old_component_identity,
                "new_component_identity": self.new_component_identity,
                "old_epoch_id": self.old_epoch_id, "new_epoch_id": self.new_epoch_id,
                "meta_protocol_result_ref": self.meta_protocol_result_ref,
                "ordinary_crucible_ref": self.ordinary_crucible_ref,
                "external_authorization_ref": self.external_authorization_ref,
                "deployment_id": self.deployment_id,
                "installed_artifact_digest": self.installed_artifact_digest}


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


def byte_installer(target_path: str, *, installer_ref: str = "real-file-writer") -> Callable[..., str]:
    """
    The real mechanism for the meta path: write the authorized bytes and return their digest.

    It is a plain function so tests exercise real files, and production wiring can substitute the
    legacy activation machinery without changing the ordering this module enforces.
    """
    def installer(*, promotion_id: str, candidate_id: str, artifact_digest: str) -> str:
        path = pathlib.Path(target_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = getattr(installer, "artifact_bytes", None)
        if payload is None:
            raise CrucibleError("INSTALLER_REQUIRES_BYTES", target_path)
        path.write_bytes(payload)
        return digest(path.read_bytes())
    installer.installer_ref = installer_ref  # type: ignore[attr-defined]
    return installer


def meta_promotion_requirements(db_path: str, *, shadow_id: str, ordinary_standing: str,
                                authority_ref: Optional[str],
                                constitutional_violations: int = 0) -> Tuple[str, ...]:
    problems: List[str] = []
    try:
        shadow = get_shadow(db_path, shadow_id)
    except CrucibleError:
        return (REASON_SHADOW_NOT_ELIGIBLE,)
    if shadow.status != STATUS_ELIGIBLE:
        problems.append(f"{REASON_SHADOW_NOT_ELIGIBLE}:{shadow.status}")
    if shadow.meta_status != STATUS_DOMINATES:
        problems.append(f"{REASON_META_STANDING}:{shadow.meta_status}")
    if int(shadow.constitutional_misses or 0) > 0 or int(constitutional_violations) > 0:
        problems.append("HARD_INVARIANTS_NOT_CLEAN")
    if ordinary_standing != STATUS_DOMINATES:
        problems.append(f"{REASON_ORDINARY_STANDING}:{ordinary_standing}")
    if not authority_ref:
        problems.append(REASON_AUTHORIZATION)
    return tuple(problems)


def meta_promote(db_path: str, *, shadow_id: str, target_role: str, target_component: str,
                 artifact_bytes: bytes, configuration_digest: str, ordinary_protocol_id: str,
                 ordinary_standing: str, authority_ref: str, installer: Callable[..., str],
                 meta_protocol_result_ref: Optional[str] = None,
                 ordinary_crucible_ref: Optional[str] = None,
                 now: Optional[float] = None) -> MetaPromotionRecord:
    """
    Perform ONE governed meta promotion.

    There is deliberately no path here that installs without a promotion, and no path that opens a new
    epoch before the bytes are verified.
    """
    problems = meta_promotion_requirements(db_path, shadow_id=shadow_id,
                                           ordinary_standing=ordinary_standing,
                                           authority_ref=authority_ref)
    if problems:
        raise CrucibleError("META_PROMOTION_REFUSED", ",".join(problems))
    shadow = get_shadow(db_path, shadow_id)
    if shadow.target_ring == RING_CONSTITUTIONAL_ROOT:
        # Defence in depth: registration already refuses Ring 0, and so does the promotion boundary.
        raise CrucibleError("META_RING_0_FORBIDDEN", shadow.target_component)
    if shadow.target_component != target_component:
        raise CrucibleError("META_PROMOTION_TARGET_MISMATCH", target_component)
    existing = [record for record in meta_promotion_history(db_path)
                if record.shadow_id == shadow_id]
    if existing:
        raise CrucibleError(REASON_ALREADY_PROMOTED, shadow_id)

    moment = time.time() if now is None else float(now)
    artifact_digest = digest(artifact_bytes)
    setattr(installer, "artifact_bytes", artifact_bytes)
    previous_epoch = current_epoch(db_path)
    old_identity = previous_epoch.generator_identity if previous_epoch else shadow.authoritative_baseline

    # 1. the ordinary Crucible promotion record - the constitutional reason deployment may occur
    promotion = promote(db_path, role=target_role, candidate_id=shadow.crucible_candidate_id,
                        protocol_id=ordinary_protocol_id, comparison_status=STATUS_DOMINATES,
                        evaluation_refs=[ref for ref in (meta_protocol_result_ref,
                                                         ordinary_crucible_ref) if ref],
                        authorization_ref=authority_ref, now=moment)
    # 2. install through the R7 governed boundary
    deployment = deploy(db_path, promotion_id=promotion.promotion_id, role=target_role,
                        candidate_id=shadow.crucible_candidate_id, artifact_digest=artifact_digest,
                        configuration_digest=configuration_digest, installer=installer,
                        authorization_ref=authority_ref,
                        installer_ref=getattr(installer, "installer_ref", None), now=moment)
    # 3. only now may authority move
    try:
        epoch = transition_epoch(db_path, generator_identity=shadow.crucible_candidate_id,
                                 authority_ref=authority_ref, now=moment)
    except Exception as error:
        raise CrucibleError(META_DEPLOYMENT_RECONCILIATION_REQUIRED,
                            f"installed {artifact_digest[:12]} but no epoch: {error}")

    meta_promotion_id = "MPR-" + digest({"shadow": shadow_id, "candidate": shadow.crucible_candidate_id,
                                         "epoch": epoch.epoch_id,
                                         "auth": authority_ref})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_promotions (meta_promotion_id, meta_candidate_id, "
            "shadow_id, target_component, target_role, old_component_identity, "
            "new_component_identity, old_epoch_id, new_epoch_id, meta_protocol_result_ref, "
            "ordinary_crucible_ref, external_authorization_ref, deployment_id, "
            "installed_artifact_digest, promoted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (meta_promotion_id, shadow.crucible_candidate_id, shadow_id, target_component,
             target_role, old_identity, shadow.crucible_candidate_id,
             previous_epoch.epoch_id if previous_epoch else None, epoch.epoch_id,
             meta_protocol_result_ref, ordinary_crucible_ref, authority_ref,
             deployment.deployment_id, deployment.installed_artifact_digest, moment))
        connection.commit()
    finally:
        connection.close()
    return get_meta_promotion(db_path, meta_promotion_id)


def meta_rollback(db_path: str, *, bad_epoch: str, restore_from_epoch: str, target_component: str,
                  artifact_bytes: bytes, evidence_refs: Sequence[str], authority_ref: str,
                  installer: Callable[..., str], promoted_from: Optional[str] = None,
                  ordinary_role: str = "",
                  now: Optional[float] = None) -> Dict[str, Any]:
    """
    Governed meta rollback (law: restoration is a NEW epoch, never time travel).

    Canonical first, mechanism second - the same ordering as every other rollback in this system.
    """
    moment = time.time() if now is None else float(now)
    restoring = get_epoch(db_path, restore_from_epoch)
    new_epoch_id = rollback_epoch(db_path, bad_epoch=bad_epoch, restored_epoch=restore_from_epoch,
                                  restored_component=restoring.generator_identity,
                                  evidence_refs=evidence_refs, authority_ref=authority_ref,
                                  now=moment)
    setattr(installer, "artifact_bytes", artifact_bytes)
    installed = installer(promotion_id=f"rollback:{bad_epoch}", candidate_id=restoring.generator_identity,
                          artifact_digest=digest(artifact_bytes))
    verified = installed == digest(artifact_bytes)
    return {"new_epoch_id": new_epoch_id, "restored_identity": restoring.generator_identity,
            "rollback_of": bad_epoch, "installed_digest": installed, "verified": verified,
            "component": target_component, "promoted_from": promoted_from, "ordinary_role": ordinary_role}


def get_meta_promotion(db_path: str, meta_promotion_id: str) -> MetaPromotionRecord:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_promotions WHERE meta_promotion_id = ?;",
                                 (meta_promotion_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_META_PROMOTION", meta_promotion_id)
    row = dict(row)
    return MetaPromotionRecord(**{key: row[key] for key in (
        "meta_promotion_id", "meta_candidate_id", "shadow_id", "target_component", "target_role",
        "old_component_identity", "new_component_identity", "old_epoch_id", "new_epoch_id",
        "meta_protocol_result_ref", "ordinary_crucible_ref", "external_authorization_ref",
        "deployment_id", "installed_artifact_digest")})


def meta_promotion_history(db_path: str) -> List[MetaPromotionRecord]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["meta_promotion_id"]) for row in connection.execute(
            "SELECT meta_promotion_id FROM ciph_meta_promotions ORDER BY promoted_at, "
            "meta_promotion_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_meta_promotion(db_path, meta_promotion_id) for meta_promotion_id in ids]


def meta_promotion_digest(db_path: str) -> str:
    return digest({"version": META_PROMOTION_V1,
                   "promotions": [record.as_dict() for record in meta_promotion_history(db_path)],
                   "rollbacks": [str(row["rollback_id"]) for row in rollback_history(db_path)],
                   "deployments": [record.deployment_id for record in deployment_history(db_path)]})
