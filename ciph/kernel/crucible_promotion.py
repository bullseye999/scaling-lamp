"""
ciph/kernel/crucible_promotion - 4.5 Gate Four: when may a candidate replace the baseline?

Evaluation and promotion are separate acts. A comparison that says DOMINATES changes nothing by itself;
promotion is a governed, explicit pointer move, and it creates NO execution authority.

LAWS
 1. Promotion requires a complete, integral, DOMINATES comparison.
 2. Promotion requires governance/operator authorization.
 3. Promotion is an append-only pointer move, never an edit of the baseline.
 4. Promotion does not create execution authority.
 5. A candidate cannot promote itself.
 6. Promotion is reversible (Gate Five).
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_candidates import get_candidate
from ciph.kernel.crucible_metrics import STATUS_DOMINATES
from ciph.kernel.crucible_protocols import assert_protocol_integrity, get_protocol
from ciph.kernel.crucible_types import CRUCIBLE_PROMOTION_V1, CrucibleError, digest

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_promotions (
        promotion_id TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        candidate_id TEXT NOT NULL,
        replaced_candidate_id TEXT,
        protocol_id TEXT NOT NULL,
        comparison_status TEXT NOT NULL,
        evaluation_refs_json TEXT,
        authorization_ref TEXT NOT NULL,
        promoted_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_active (
        role TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL,
        promotion_id TEXT,
        updated_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_rollbacks (
        rollback_id TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        candidate_id TEXT NOT NULL,
        restored_candidate_id TEXT NOT NULL,
        promotion_id TEXT,
        evidence_refs_json TEXT,
        reason_codes_json TEXT,
        rolled_back_at REAL
    );
    """,
)


@dataclass(frozen=True)
class PromotionRecord:
    promotion_id: str
    role: str
    candidate_id: str
    replaced_candidate_id: Optional[str]
    protocol_id: str
    comparison_status: str
    evaluation_refs: Tuple[str, ...]
    authorization_ref: str
    promoted_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"promotion_id": self.promotion_id, "role": self.role,
                "candidate_id": self.candidate_id,
                "replaced_candidate_id": self.replaced_candidate_id,
                "protocol_id": self.protocol_id, "comparison_status": self.comparison_status,
                "evaluation_refs": list(self.evaluation_refs),
                "authorization_ref": self.authorization_ref}


@dataclass(frozen=True)
class RollbackRecord:
    rollback_id: str
    role: str
    candidate_id: str
    restored_candidate_id: str
    promotion_id: Optional[str]
    evidence_refs: Tuple[str, ...]
    reason_codes: Tuple[str, ...]
    rolled_back_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"rollback_id": self.rollback_id, "role": self.role,
                "candidate_id": self.candidate_id,
                "restored_candidate_id": self.restored_candidate_id,
                "promotion_id": self.promotion_id, "evidence_refs": list(self.evidence_refs),
                "reason_codes": list(self.reason_codes)}


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


def promotion_requirements(db_path: str, *, protocol_id: str, candidate_id: str,
                           comparison_status: str, evaluation_refs: Sequence[str],
                           authorization_ref: Optional[str]) -> Tuple[str, ...]:
    """Every reason a promotion would be refused, computed from canonical state. Empty means eligible."""
    problems: List[str] = []
    if comparison_status != STATUS_DOMINATES:
        problems.append(f"COMPARISON_NOT_DOMINATES:{comparison_status}")
    if not authorization_ref:
        problems.append("AUTHORIZATION_REQUIRED")
    if not evaluation_refs:
        problems.append("EVALUATION_EVIDENCE_REQUIRED")
    try:
        assert_protocol_integrity(db_path, protocol_id)
        protocol = get_protocol(db_path, protocol_id)
        if len(evaluation_refs) < protocol.minimum_evidence:
            problems.append(f"MINIMUM_EVIDENCE_NOT_MET:"
                            f"{len(evaluation_refs)}<{protocol.minimum_evidence}")
    except CrucibleError as error:
        problems.append(f"PROTOCOL_UNUSABLE:{error.reason}")
    try:
        get_candidate(db_path, candidate_id)
    except CrucibleError:
        problems.append(f"UNKNOWN_CANDIDATE:{candidate_id}")
    return tuple(problems)


def promote(db_path: str, *, role: str, candidate_id: str, protocol_id: str,
            comparison_status: str, evaluation_refs: Sequence[str], authorization_ref: str,
            replaced_candidate_id: Optional[str] = None,
            now: Optional[float] = None) -> PromotionRecord:
    """
    Move the active pointer to a candidate - an append-only governed transition (laws 1-3).

    Nothing here mints authority: the module has no permit, signer or executor surface at all. A
    promoted planner may PROPOSE plans; running them still requires mission -> action -> permit.
    """
    moment = time.time() if now is None else float(now)
    problems = promotion_requirements(db_path, protocol_id=protocol_id, candidate_id=candidate_id,
                                      comparison_status=comparison_status,
                                      evaluation_refs=evaluation_refs,
                                      authorization_ref=authorization_ref)
    if problems:
        raise CrucibleError("PROMOTION_REFUSED", ",".join(problems))

    connection = _connect(db_path)
    try:
        init_schema(connection)
        current = connection.execute("SELECT * FROM ciph_crucible_active WHERE role = ?;",
                                     (role,)).fetchone()
        replaced = replaced_candidate_id or (current["candidate_id"] if current else None)
        promotion_id = "CPR-" + digest({"role": role, "candidate": candidate_id,
                                        "protocol": protocol_id,
                                        "refs": sorted(str(r) for r in evaluation_refs),
                                        "auth": authorization_ref})[:16].upper()
        connection.execute(
            "INSERT OR IGNORE INTO ciph_crucible_promotions (promotion_id, role, candidate_id, "
            "replaced_candidate_id, protocol_id, comparison_status, evaluation_refs_json, "
            "authorization_ref, promoted_at) VALUES (?,?,?,?,?,?,?,?,?);",
            (promotion_id, role, candidate_id, replaced, protocol_id, comparison_status,
             str(sorted(str(r) for r in evaluation_refs)), authorization_ref, moment))
        connection.execute(
            "INSERT OR REPLACE INTO ciph_crucible_active (role, candidate_id, promotion_id, "
            "updated_at) VALUES (?,?,?,?);",
            (role, candidate_id, promotion_id, moment))
        connection.commit()
    finally:
        connection.close()
    return get_promotion(db_path, promotion_id)


def rollback(db_path: str, *, role: str, evidence_refs: Sequence[str],
             reason_codes: Sequence[str], now: Optional[float] = None) -> RollbackRecord:
    """
    Restore the previous candidate as a POINTER move (law 6). The failed candidate, its benchmark
    victory and its production failure all remain exactly as they were recorded.
    """
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        active = connection.execute("SELECT * FROM ciph_crucible_active WHERE role = ?;",
                                    (role,)).fetchone()
        if active is None:
            raise CrucibleError("NO_ACTIVE_CANDIDATE", role)
        promotion = connection.execute("SELECT * FROM ciph_crucible_promotions WHERE promotion_id = ?;",
                                       (active["promotion_id"],)).fetchone()
        restored = promotion["replaced_candidate_id"] if promotion else None
        if not restored:
            raise CrucibleError("NO_PREVIOUS_CANDIDATE_TO_RESTORE", role)
        rollback_id = "CRB-" + digest({"role": role, "from": active["candidate_id"],
                                       "to": restored,
                                       "reasons": sorted(str(item) for item in reason_codes),
                                       "evidence": sorted(str(item) for item in evidence_refs)}
                                      )[:16].upper()
        connection.execute(
            "INSERT OR IGNORE INTO ciph_crucible_rollbacks (rollback_id, role, candidate_id, "
            "restored_candidate_id, promotion_id, evidence_refs_json, reason_codes_json, "
            "rolled_back_at) VALUES (?,?,?,?,?,?,?,?);",
            (rollback_id, role, str(active["candidate_id"]), restored, str(active["promotion_id"]),
             str(sorted(str(r) for r in evidence_refs)),
             str(sorted(str(item) for item in reason_codes)), moment))
        connection.execute(
            "INSERT OR REPLACE INTO ciph_crucible_active (role, candidate_id, promotion_id, "
            "updated_at) VALUES (?,?,?,?);",
            (role, restored, None, moment))
        connection.commit()
    finally:
        connection.close()
    return get_rollback(db_path, rollback_id)


def get_promotion(db_path: str, promotion_id: str) -> PromotionRecord:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_crucible_promotions WHERE promotion_id = ?;",
                                 (promotion_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_PROMOTION", promotion_id)
    return _promotion_from_row(dict(row))


def _promotion_from_row(row: Dict[str, Any]) -> PromotionRecord:
    return PromotionRecord(
        promotion_id=str(row["promotion_id"]), role=str(row["role"]),
        candidate_id=str(row["candidate_id"]), replaced_candidate_id=row["replaced_candidate_id"],
        protocol_id=str(row["protocol_id"]), comparison_status=str(row["comparison_status"]),
        evaluation_refs=tuple(_literal(row["evaluation_refs_json"])),
        authorization_ref=str(row["authorization_ref"]), promoted_at=row["promoted_at"])


def get_rollback(db_path: str, rollback_id: str) -> RollbackRecord:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_crucible_rollbacks WHERE rollback_id = ?;",
                                 (rollback_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_ROLLBACK", rollback_id)
    return RollbackRecord(
        rollback_id=str(row["rollback_id"]), role=str(row["role"]),
        candidate_id=str(row["candidate_id"]),
        restored_candidate_id=str(row["restored_candidate_id"]),
        promotion_id=row["promotion_id"], evidence_refs=tuple(_literal(row["evidence_refs_json"])),
        reason_codes=tuple(_literal(row["reason_codes_json"])),
        rolled_back_at=row["rolled_back_at"])


def _literal(value: Any) -> List[str]:
    import ast as _ast
    if not value:
        return []
    try:
        return [str(item) for item in _ast.literal_eval(str(value))]
    except Exception:
        return []


def active_candidate(db_path: str, role: str) -> Optional[str]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT candidate_id FROM ciph_crucible_active WHERE role = ?;",
                                 (role,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return str(row["candidate_id"]) if row is not None else None


def promotion_history(db_path: str, role: Optional[str] = None) -> List[PromotionRecord]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_crucible_promotions"
    params: Tuple[Any, ...] = ()
    if role is not None:
        query += " WHERE role = ?"
        params = (role,)
    try:
        rows = [dict(r) for r in connection.execute(query + " ORDER BY promoted_at, promotion_id;",
                                                    params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [_promotion_from_row(row) for row in rows]


def rollback_history(db_path: str) -> List[RollbackRecord]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in connection.execute(
            "SELECT * FROM ciph_crucible_rollbacks ORDER BY rolled_back_at, rollback_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [RollbackRecord(
        rollback_id=str(r["rollback_id"]), role=str(r["role"]), candidate_id=str(r["candidate_id"]),
        restored_candidate_id=str(r["restored_candidate_id"]), promotion_id=r["promotion_id"],
        evidence_refs=tuple(_literal(r["evidence_refs_json"])),
        reason_codes=tuple(_literal(r["reason_codes_json"])), rolled_back_at=r["rolled_back_at"])
        for r in rows]


def promotion_digest(db_path: str) -> str:
    return digest({"promotions": [item.as_dict() for item in promotion_history(db_path)],
                   "rollbacks": [item.as_dict() for item in rollback_history(db_path)],
                   "version": CRUCIBLE_PROMOTION_V1})
