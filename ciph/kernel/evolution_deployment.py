"""
ciph/kernel/evolution_deployment - R6 Gates D and E.

Gate D: ONE governed deployment boundary. The old lifecycle has real mechanisms - staging, canaries,
physical file activation, capability re-registration - and R6 keeps them. What it takes away is their
authority to decide that a deployment may happen at all.

Gate E: ONE canonical answer to "which candidate is active?". The filesystem is CORROBORATION, never
the answer. A restart that finds the canonical pointer and the installed artifact disagree does not
silently pick one - it reports a conflict.

Law, in both directions:

    no PromotionRecord          -> NO DEPLOYMENT, whatever grant is presented
    filesystem changed          -> NOT a promotion

The installer is injected on purpose. This module is mechanism-agnostic: it does not know how bytes
reach the filesystem, and the mechanism cannot know whether it is allowed to run until this module has
said yes.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from ciph.kernel.crucible_candidates import get_candidate
from ciph.kernel.crucible_promotion import active_candidate, get_promotion
from ciph.kernel.crucible_types import CRUCIBLE_DEPLOYMENT_V1, CrucibleError, digest

STATUS_VERIFIED = "VERIFIED"
STATUS_FAILED = "FAILED"

CONSISTENT = "CONSISTENT"
DEPLOYMENT_INTEGRITY_CONFLICT = "DEPLOYMENT_INTEGRITY_CONFLICT"

REASON_NO_PROMOTION = "NO_PROMOTION_RECORD"
REASON_PROMOTION_MISMATCH = "PROMOTION_DOES_NOT_NAME_THIS_DEPLOYMENT"
REASON_CANDIDATE_IDENTITY_MISMATCH = "CANDIDATE_IDENTITY_MISMATCH"
REASON_ACTIVE_POINTER_MOVED = "ACTIVE_POINTER_NOT_THIS_CANDIDATE"
REASON_AUTHORIZATION_REQUIRED = "AUTHORIZATION_REQUIRED"
REASON_INSTALLER_REQUIRED = "INSTALLER_REQUIRED"
REASON_INSTALLED_MISMATCH = "INSTALLED_ARTIFACT_MISMATCH"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_deployments (
        deployment_id TEXT PRIMARY KEY,
        promotion_id TEXT NOT NULL,
        role TEXT NOT NULL,
        candidate_id TEXT NOT NULL,
        artifact_digest TEXT NOT NULL,
        configuration_digest TEXT,
        installer_ref TEXT,
        authorization_ref TEXT,
        installed_artifact_digest TEXT,
        status TEXT NOT NULL,
        deployed_at REAL
    );
    """,
)


@dataclass(frozen=True)
class DeploymentRecord:
    deployment_id: str
    promotion_id: str
    role: str
    candidate_id: str
    artifact_digest: str
    configuration_digest: Optional[str]
    installer_ref: Optional[str]
    authorization_ref: Optional[str]
    installed_artifact_digest: Optional[str]
    status: str
    deployed_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"deployment_id": self.deployment_id, "promotion_id": self.promotion_id,
                "role": self.role, "candidate_id": self.candidate_id,
                "artifact_digest": self.artifact_digest,
                "configuration_digest": self.configuration_digest,
                "installer_ref": self.installer_ref,
                "authorization_ref": self.authorization_ref,
                "installed_artifact_digest": self.installed_artifact_digest,
                "status": self.status}


def activation_role(target_capability: str) -> str:
    """
    THE canonical role name for a capability's active candidate.

    The legacy lifecycle knows capabilities by name and the Crucible knows roles. One deterministic
    convention connects them, so "which candidate is active for math.compute" has exactly one answer.
    """
    return f"capability:{target_capability}"


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


def deployment_preconditions(db_path: str, *, promotion_id: str, role: str, candidate_id: str,
                             artifact_digest: str, configuration_digest: Optional[str],
                             authorization_ref: Optional[str],
                             installer: Optional[Callable[..., str]]) -> Tuple[str, ...]:
    """
    Every reason a deployment would be refused, computed from canonical state.

    The order matters for the sentence it makes: a promotion is checked FIRST, so a perfectly valid
    legacy deployment grant presented with no PromotionRecord is refused on the constitutional
    question rather than on any mechanical one.
    """
    problems: List[str] = []
    try:
        promotion = get_promotion(db_path, promotion_id)
    except CrucibleError:
        return (REASON_NO_PROMOTION,)
    if promotion.role != role or promotion.candidate_id != candidate_id:
        problems.append(REASON_PROMOTION_MISMATCH)
    try:
        candidate = get_candidate(db_path, candidate_id)
    except CrucibleError:
        problems.append(REASON_CANDIDATE_IDENTITY_MISMATCH)
        return tuple(problems)
    if candidate.artifact_digest != artifact_digest or (
            configuration_digest is not None and candidate.configuration_digest != configuration_digest):
        problems.append(REASON_CANDIDATE_IDENTITY_MISMATCH)
    if active_candidate(db_path, role) != candidate_id:
        problems.append(REASON_ACTIVE_POINTER_MOVED)
    if not authorization_ref:
        problems.append(REASON_AUTHORIZATION_REQUIRED)
    if installer is None:
        problems.append(REASON_INSTALLER_REQUIRED)
    return tuple(problems)


def deploy(db_path: str, *, promotion_id: str, role: str, candidate_id: str,
           artifact_digest: str, installer: Callable[..., str],
           authorization_ref: str, configuration_digest: Optional[str] = None,
           installer_ref: Optional[str] = None, now: Optional[float] = None) -> DeploymentRecord:
    """
    Perform ONE governed deployment: verify, then install, then verify what was installed.

    The installer is the MECHANISM (staging, canary activation, file swap, capability
    re-registration). It is called only after every canonical check has passed, and its return value
    is verified against the artifact that was authorized.
    """
    moment = time.time() if now is None else float(now)
    problems = deployment_preconditions(
        db_path, promotion_id=promotion_id, role=role, candidate_id=candidate_id,
        artifact_digest=artifact_digest, configuration_digest=configuration_digest,
        authorization_ref=authorization_ref, installer=installer)
    if problems:
        raise CrucibleError("DEPLOYMENT_REFUSED", ",".join(problems))

    installed = installer(promotion_id=promotion_id, candidate_id=candidate_id,
                          artifact_digest=artifact_digest)
    if installed != artifact_digest:
        raise CrucibleError(REASON_INSTALLED_MISMATCH,
                            f"installer installed {installed!r}, authorized {artifact_digest!r}")

    deployment_id = "CDP-" + digest({"promotion": promotion_id, "role": role,
                                     "candidate": candidate_id, "artifact": artifact_digest,
                                     "installer": installer_ref or getattr(installer, "__name__", "?"),
                                     "authorization": authorization_ref})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_crucible_deployments (deployment_id, promotion_id, role, "
            "candidate_id, artifact_digest, configuration_digest, installer_ref, authorization_ref, "
            "installed_artifact_digest, status, deployed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (deployment_id, promotion_id, role, candidate_id, artifact_digest, configuration_digest,
             installer_ref or getattr(installer, "__name__", None), authorization_ref, installed,
             STATUS_VERIFIED, moment))
        connection.commit()
    finally:
        connection.close()
    return get_deployment(db_path, deployment_id)


def get_deployment(db_path: str, deployment_id: str) -> DeploymentRecord:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_crucible_deployments WHERE deployment_id = ?;",
                                 (deployment_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_DEPLOYMENT", deployment_id)
    return DeploymentRecord(
        deployment_id=str(row["deployment_id"]), promotion_id=str(row["promotion_id"]),
        role=str(row["role"]), candidate_id=str(row["candidate_id"]),
        artifact_digest=str(row["artifact_digest"]), configuration_digest=row["configuration_digest"],
        installer_ref=row["installer_ref"], authorization_ref=row["authorization_ref"],
        installed_artifact_digest=row["installed_artifact_digest"], status=str(row["status"]),
        deployed_at=row["deployed_at"])


def deployment_history(db_path: str, role: Optional[str] = None) -> List[DeploymentRecord]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_crucible_deployments"
    params: Tuple[Any, ...] = ()
    if role is not None:
        query += " WHERE role = ?"
        params = (role,)
    try:
        rows = [str(row["deployment_id"]) for row in connection.execute(
            query + " ORDER BY deployed_at, deployment_id;", params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [get_deployment(db_path, deployment_id) for deployment_id in rows]


def canonical_active_candidate(db_path: str, role: str) -> Optional[str]:
    """
    THE answer to "which candidate is active?" (Gate E).

    Callers must not ask the filesystem this question. The installed artifact is corroboration for the
    canonical pointer, never a substitute for it.
    """
    return active_candidate(db_path, role)


def verify_active_consistency(db_path: str, *, role: str,
                              observed_artifact_digest: Optional[str]) -> str:
    """
    Corroborate the canonical pointer against whatever is installed.

    A disagreement is reported as DEPLOYMENT_INTEGRITY_CONFLICT. Nothing here chooses a winner: an
    infrastructure that silently prefers one source of truth over another is how a filesystem edit
    becomes an unnoticed promotion.
    """
    active = canonical_active_candidate(db_path, role)
    canonical_artifact = None
    if active is not None:
        try:
            canonical_artifact = get_candidate(db_path, active).artifact_digest
        except CrucibleError:
            canonical_artifact = None
    if canonical_artifact == observed_artifact_digest:
        return CONSISTENT
    return DEPLOYMENT_INTEGRITY_CONFLICT


def deployment_digest(db_path: str) -> str:
    return digest({"version": CRUCIBLE_DEPLOYMENT_V1,
                   "deployments": [record.as_dict() for record in deployment_history(db_path)]})
