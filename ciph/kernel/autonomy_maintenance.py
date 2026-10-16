"""
ciph/kernel/autonomy_maintenance - 5.6 (self-maintenance) and 5.7 (the ceiling of the loop).

MAINTENANCE is work Ciph may do to itself under standing authority: verify the database, check the
backups, run the test suite, read the repository, produce a report. Maintenance is NOT a licence to
change the world. An update is a GOVERNED CHANGE and crosses the same boundary as everything else, so
the governed classes are refused BY NAME here rather than left to a caller's judgement.

THE CEILING (5.7). The continuous loop may discover, hypothesise, generate and evaluate. It stops at
PROMOTION_READY, and a promotion-ready NOTICE IS NOT AUTHORITY: it names the candidate and the evidence,
states out loud that an operator decision is required, and carries flags that say it cannot promote or
deploy. Nothing inside this namespace can turn the notice into a promotion.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

AUTONOMY_MAINTENANCE_V1 = "AUTONOMY_MAINTENANCE_V1"
PROMOTION_READY_V1 = "PROMOTION_READY_V1"

REASON_GOVERNED_CHANGE_IS_NOT_MAINTENANCE = "GOVERNED_CHANGE_IS_NOT_MAINTENANCE"
REASON_HANDOFF_REQUIRES_A_CANDIDATE = "PROMOTION_READY_REQUIRES_A_CANDIDATE"
REASON_HANDOFF_REQUIRES_EVIDENCE = "PROMOTION_READY_REQUIRES_EVIDENCE"
REASON_CLASS_CANNOT_REACH_THE_CEILING = "WORK_CLASS_CANNOT_REACH_PROMOTION_READY"
REASON_CURIOSITY_REQUIRES_OPEN_QUESTION = "CURIOSITY_REQUIRES_AN_OPEN_QUESTION"
REASON_CURIOSITY_QUESTION_RESOLVED = "CURIOSITY_QUESTION_ALREADY_RESOLVED"

# What maintenance may do. Every entry is read-only with respect to the outside world.
MAINTENANCE_CHECKS: Tuple[Tuple[str, str], ...] = (
    ("MAINTENANCE_CHECK", "verify datastore integrity and schema ownership"),
    ("RUN_TEST_SUITE", "run the canonical suite and record the measurement"),
    ("READ_REPOSITORY", "inspect tracked sources and scanners"),
    ("PRODUCE_REPORT", "write a report for the operator"),
    ("RECOVERY_RECONCILE", "reconcile interrupted work from canonical state"),
)

# Never maintenance. These are governed changes dressed as housekeeping, and the catalogue exists so
# that refusing one is a lookup rather than an argument.
GOVERNED_CHANGES: Tuple[str, ...] = ("PRODUCTION_INSTALL", "META_PROMOTION", "KEY_ACCESS",
                                     "NETWORK_POST")

# The classes whose work can legitimately END in an operator handoff notice.
CEILING_WORK_CLASSES: Tuple[str, ...] = ("GENERATE_CANDIDATE", "EVALUATE_CANDIDATE",
                                         "META_DISCOVERY", "INVESTIGATE_UNCERTAINTY")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_autonomy_promotion_ready (
        handoff_id TEXT PRIMARY KEY,
        work_class TEXT NOT NULL,
        candidate_ref TEXT NOT NULL,
        evidence_refs_json TEXT NOT NULL,
        requires_operator_authorization INTEGER NOT NULL,
        may_promote INTEGER NOT NULL,
        may_deploy INTEGER NOT NULL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class PromotionReadyNotice:
    handoff_id: str
    work_class: str
    candidate_ref: str
    evidence_refs: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"handoff_id": self.handoff_id, "work_class": self.work_class,
                "candidate_ref": self.candidate_ref, "evidence_refs": list(self.evidence_refs),
                "requires_operator_authorization": True, "may_promote": False, "may_deploy": False,
                "policy_version": PROMOTION_READY_V1}


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


def maintenance_checklist() -> Tuple[Tuple[str, str], ...]:
    """The deterministic maintenance programme. Same answer every restart, for the same version."""
    return MAINTENANCE_CHECKS


def assert_maintenance_is_maintenance(work_class: str) -> str:
    """Refuse a governed change on the maintenance path, by name."""
    if str(work_class) in GOVERNED_CHANGES:
        raise CrucibleError(REASON_GOVERNED_CHANGE_IS_NOT_MAINTENANCE, str(work_class))
    if str(work_class) not in [item[0] for item in MAINTENANCE_CHECKS]:
        raise CrucibleError("NOT_A_MAINTENANCE_CLASS", str(work_class))
    return str(work_class)


def assert_curiosity_basis(db_path: str, uncertainty_ref: str, *, now: Optional[float] = None
                           ) -> Dict[str, Any]:
    """
    Curiosity investigates a QUESTION THE 4.4 REGISTRY HOLDS. It does not invent one.

    An already-resolved question is refused rather than quietly re-opened: re-opening it would let the
    autonomy loop manufacture its own justification for work the world has already answered.
    """
    from ciph.kernel.uncertainty_registry import STATUS_SATISFIED, uncertainty, uncertainty_status
    if not str(uncertainty_ref).strip():
        raise CrucibleError(REASON_CURIOSITY_REQUIRES_OPEN_QUESTION, str(uncertainty_ref))
    current = uncertainty(db_path, str(uncertainty_ref), now=now)
    if current is not None:
        return current.as_dict()
    status = uncertainty_status(db_path, str(uncertainty_ref), now=now)
    if status == STATUS_SATISFIED:
        raise CrucibleError(REASON_CURIOSITY_QUESTION_RESOLVED, str(uncertainty_ref))
    raise CrucibleError(REASON_CURIOSITY_REQUIRES_OPEN_QUESTION, f"{uncertainty_ref}:{status}")


def raise_promotion_ready(db_path: str, *, work_class: str, candidate_ref: Optional[str],
                          evidence_refs: Sequence[str], now: Optional[float] = None
                          ) -> PromotionReadyNotice:
    """
    Say "this is ready for an operator" - and mean exactly that.

    The notice is deliberately not a candidate record and not a promotion: 4.5 owns candidate identity
    and 4.7/R7 own promotion, and both of those are unchanged by anything written here. What this
    produces is a REFERENCE a human can act on.
    """
    if str(work_class) not in CEILING_WORK_CLASSES:
        raise CrucibleError(REASON_CLASS_CANNOT_REACH_THE_CEILING, str(work_class))
    if not candidate_ref:
        raise CrucibleError(REASON_HANDOFF_REQUIRES_A_CANDIDATE, str(work_class))
    refs = sorted(str(ref) for ref in evidence_refs)
    if not refs:
        raise CrucibleError(REASON_HANDOFF_REQUIRES_EVIDENCE, str(work_class))
    moment = time.time() if now is None else float(now)
    handoff_id = "PRN-" + digest({"class": str(work_class), "candidate": str(candidate_ref),
                                  "evidence": refs})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_autonomy_promotion_ready (handoff_id, work_class, "
            "candidate_ref, evidence_refs_json, requires_operator_authorization, may_promote, "
            "may_deploy, recorded_at) VALUES (?,?,?,?,?,?,?,?);",
            (handoff_id, str(work_class), str(candidate_ref), json.dumps(refs), 1, 0, 0, moment))
        connection.commit()
    finally:
        connection.close()
    return get_promotion_ready(db_path, handoff_id)


def get_promotion_ready(db_path: str, handoff_id: str) -> PromotionReadyNotice:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_autonomy_promotion_ready WHERE handoff_id = ?;",
                                 (handoff_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_PROMOTION_READY_NOTICE", handoff_id)
    row = dict(row)
    return PromotionReadyNotice(handoff_id=str(row["handoff_id"]), work_class=str(row["work_class"]),
                                candidate_ref=str(row["candidate_ref"]),
                                evidence_refs=tuple(json.loads(row["evidence_refs_json"] or "[]")))


def promotion_ready_notices(db_path: str) -> List[PromotionReadyNotice]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["handoff_id"]) for row in connection.execute(
            "SELECT handoff_id FROM ciph_autonomy_promotion_ready ORDER BY recorded_at, handoff_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_promotion_ready(db_path, handoff_id) for handoff_id in ids]


def promotion_ready_carries_no_authority(db_path: str) -> bool:
    """The ceiling, asserted against the durable rows rather than against the intention."""
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT COUNT(*) FROM ciph_autonomy_promotion_ready "
                                 "WHERE requires_operator_authorization = 0 OR may_promote = 1 "
                                 "OR may_deploy = 1;").fetchone()
        return int(row[0]) == 0
    except sqlite3.Error:
        return True
    finally:
        connection.close()


def maintenance_digest(db_path: str) -> str:
    return digest({"version": AUTONOMY_MAINTENANCE_V1,
                   "checklist": [list(item) for item in MAINTENANCE_CHECKS],
                   "notices": [notice.as_dict() for notice in promotion_ready_notices(db_path)]})
