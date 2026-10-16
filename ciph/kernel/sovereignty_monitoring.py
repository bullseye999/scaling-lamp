"""
ciph/kernel/sovereignty_monitoring - 8.10: can Ciph still recover? by EVIDENCE.

    LAST_PROVEN_RESTORE, not LAST_BACKUP.

Backups you have never restored are Schroedinger's backups: simultaneously fine and useless until
somebody opens one. So the operationally important fact is when a restore was last PROVEN, reported
separately from when a backup was last taken.

Everything here is a MEASUREMENT. There is no sovereignty score, because a score would be an opinion
that hides exactly the facts a human needs: which family is missing, which key is not in custody, which
migration is unsupported, which conflict is unresolved.
"""

import sqlite3
import time
from typing import Any, Dict, List, Optional

from ciph.kernel.crucible_types import digest

SOVEREIGNTY_HEALTH_V1 = "SOVEREIGNTY_HEALTH_V1"

HEALTHY = "HEALTHY"
ATTENTION = "ATTENTION_REQUIRED"
UNPROVEN = "RESTORE_UNPROVEN"
DEGRADED = "DEGRADED"
UNRECOVERABLE = "UNRECOVERABLE"


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


def _scalar(db_path: str, query: str, default: Any = 0) -> Any:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute(query).fetchone()
        return row[0] if row is not None and row[0] is not None else default
    except sqlite3.Error:
        return default
    finally:
        connection.close()


def sovereignty_health(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """
    One projection, assembled from what the store can prove - and honest about what it cannot.
    """
    from ciph.kernel.backup_constitution import VERIFIED, backup_sets
    from ciph.kernel.recovery_engine import last_proven_restore, proven_restores
    from ciph.kernel.recovery_manifest import verify_manifest
    from ciph.kernel.recovery_state import recovery_runs
    from ciph.kernel.sovereign_identity import (RECOVERABLE, assess_recoverability, destruction_policy,
                                                identity)
    from ciph.kernel.sovereignty_portability import migrations, model_substitutions
    moment = time.time() if now is None else float(now)

    verified_sets = [item for item in backup_sets(db_path) if item.status == VERIFIED]
    latest = verified_sets[-1] if verified_sets else None
    proof = last_proven_restore(db_path)
    manifest_status = None
    if latest is not None:
        manifest_status = verify_manifest(db_path, latest.manifest_id,
                                          present_families=[])["status"]
    try:
        identity_id = identity(db_path).ciph_identity_id
    except Exception:
        identity_id = None
    try:
        recoverability = assess_recoverability(db_path)
    except Exception:
        recoverability = {"status": UNRECOVERABLE, "reason": "no sovereign identity"}
    runs = recovery_runs(db_path)
    conflicts = [run.run_id for run in runs if run.status == "INTEGRITY_CONFLICT"]
    held = [run.run_id for run in runs if run.status == "RECOVERY_ACTIVATION_HOLD"]
    unrecoverable_runs = [run.run_id for run in runs if run.status == UNRECOVERABLE]
    migration_risks = [{"migration_id": item["migration_id"], "status": item["status"]}
                       for item in migrations(db_path)
                       if item["status"] != "APPLIED"]
    model_dependencies = [{"new_model": item["new_model"], "provider": item["provider"],
                           "reverification_required": not bool(item["capabilities_reverified"])}
                          for item in model_substitutions(db_path)]

    if not identity_id or recoverability.get("status") == UNRECOVERABLE:
        status = UNRECOVERABLE
    elif latest is None:
        status = DEGRADED
    elif proof is None:
        status = UNPROVEN
    elif conflicts or migration_risks or held or unrecoverable_runs:
        status = ATTENTION
    else:
        status = HEALTHY

    return {
        "policy_version": SOVEREIGNTY_HEALTH_V1,
        "ciph_identity_id": identity_id,
        "latest_verified_backup": {"backup_id": latest.backup_id,
                                   "created_at": latest.consistency_boundary} if latest else None,
        "verified_backup_count": len(verified_sets),
        "last_proven_restore": proof,
        "proven_restore_count": len(proven_restores(db_path)),
        "manifest_completeness": manifest_status,
        "root_custody_status": recoverability.get("status"),
        "root_custody_missing": recoverability.get("missing_root_key_refs", []),
        "destruction_policy": destruction_policy(db_path),
        "integrity_conflicts": conflicts,
        "recovery_holds": held,
        "unrecoverable_runs": unrecoverable_runs,
        "migration_risks": migration_risks,
        "model_dependencies": model_dependencies,
        "status": status,
        "no_score": True,
        "note": "LAST_PROVEN_RESTORE is the operationally important fact; a verified backup that has "
                "never been restored is unproven",
        "evaluated_at": moment,
    }


def health_digest(db_path: str) -> str:
    """
    The projection minus its volatile parts.

    `evaluated_at` is a reading, not a fact about Ciph, and folding it into the digest would make the
    same constitutional state hash differently every time somebody looked - which is exactly the
    wall-clock contamination this program keeps refusing.
    """
    health = dict(sovereignty_health(db_path))
    health.pop("evaluated_at", None)
    return digest(health)
