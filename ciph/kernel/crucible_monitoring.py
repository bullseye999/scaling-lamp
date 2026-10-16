"""
ciph/kernel/crucible_monitoring - 4.5 Gate Five: does the promoted candidate survive reality?

A benchmark win is evidence about the benchmark. Production evidence is a separate, later act, and it can
invalidate PRACTICAL superiority without rewriting the benchmark result.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_metrics import (
    PerformanceVector,
    STATUS_DOMINATED,
    STATUS_INCOMPARABLE,
    STATUS_INVALID,
    compare,
)
from ciph.kernel.crucible_protocols import get_protocol
from ciph.kernel.crucible_types import CRUCIBLE_POST_PROMOTION_V1, CrucibleError, digest

STATUS_HEALTHY = "HEALTHY"
STATUS_DEGRADING = "DEGRADING"
STATUS_REGRESSED = "REGRESSED"
STATUS_INTEGRITY_BLOCKED = "INTEGRITY_BLOCKED"
VALID_ASSESSMENT_STATUSES = (STATUS_HEALTHY, STATUS_DEGRADING, STATUS_REGRESSED,
                             STATUS_INTEGRITY_BLOCKED)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_post_promotion (
        assessment_id TEXT PRIMARY KEY,
        promotion_id TEXT NOT NULL,
        candidate_id TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        expected_json TEXT NOT NULL,
        observed_json TEXT NOT NULL,
        regression_dimensions_json TEXT,
        constitutional_failures_json TEXT,
        status TEXT NOT NULL,
        assessed_at REAL
    );
    """,
)


@dataclass(frozen=True)
class PostPromotionAssessment:
    assessment_id: str
    promotion_id: str
    candidate_id: str
    protocol_id: str
    status: str
    regression_dimensions: Tuple[str, ...]
    constitutional_failures: Tuple[str, ...]
    assessed_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"assessment_id": self.assessment_id, "promotion_id": self.promotion_id,
                "candidate_id": self.candidate_id, "protocol_id": self.protocol_id,
                "status": self.status,
                "regression_dimensions": list(self.regression_dimensions),
                "constitutional_failures": list(self.constitutional_failures)}


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


def assess_post_promotion(db_path: str, *, promotion_id: str, candidate_id: str,
                          protocol_id: str, expected: PerformanceVector,
                          observed: PerformanceVector,
                          now: Optional[float] = None) -> PostPromotionAssessment:
    """
    Compare production performance against the basis the promotion was granted on.

    Reuses the frozen Pareto comparison: the EXPECTED vector plays the baseline role, so a status of
    DOMINATED means the promoted candidate is now outperformed by its own promotion basis - a
    regression. Hard failures block immediately and are never traded for speed.
    """
    moment = time.time() if now is None else float(now)
    protocol = get_protocol(db_path, protocol_id)
    failures = tuple(sorted(
        f"{invariant}"
        for vector in (expected, observed)
        for invariant, count in (vector.hard_violations or {}).items() if int(count) > 0))
    result = compare(expected, observed, protocol)
    regressions = tuple(sorted(list(result.worse) + (
        list(result.better) if result.status == STATUS_INCOMPARABLE else [])))
    if failures or result.status == STATUS_INVALID:
        status = STATUS_INTEGRITY_BLOCKED
    elif result.status == STATUS_DOMINATED:
        status = STATUS_REGRESSED
        regressions = tuple(sorted(result.worse))
    elif result.status == STATUS_INCOMPARABLE:
        status = STATUS_DEGRADING
    else:
        status = STATUS_HEALTHY
        regressions = ()

    assessment_id = "CPA-" + digest({"promotion": promotion_id, "candidate": candidate_id,
                                     "protocol": protocol_id, "status": status,
                                     "regressions": list(regressions),
                                     "failures": list(failures)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR REPLACE INTO ciph_crucible_post_promotion (assessment_id, promotion_id, "
            "candidate_id, protocol_id, expected_json, observed_json, regression_dimensions_json, "
            "constitutional_failures_json, status, assessed_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (assessment_id, promotion_id, candidate_id, protocol_id, str(expected.as_dict()),
             str(observed.as_dict()), str(list(regressions)), str(list(failures)), status, moment))
        connection.commit()
    finally:
        connection.close()
    return PostPromotionAssessment(
        assessment_id=assessment_id, promotion_id=promotion_id, candidate_id=candidate_id,
        protocol_id=protocol_id, status=status, regression_dimensions=regressions,
        constitutional_failures=failures, assessed_at=moment)


def assessment_history(db_path: str, *, promotion_id: Optional[str] = None
                       ) -> List[PostPromotionAssessment]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_crucible_post_promotion"
    params: Tuple[Any, ...] = ()
    if promotion_id is not None:
        query += " WHERE promotion_id = ?"
        params = (promotion_id,)
    try:
        rows = [dict(r) for r in connection.execute(
            query + " ORDER BY assessed_at, assessment_id;", params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    import ast as _ast
    return [PostPromotionAssessment(
        assessment_id=str(row["assessment_id"]), promotion_id=str(row["promotion_id"]),
        candidate_id=str(row["candidate_id"]), protocol_id=str(row["protocol_id"]),
        status=str(row["status"]),
        regression_dimensions=tuple(_ast.literal_eval(str(row["regression_dimensions_json"] or "[]"))),
        constitutional_failures=tuple(_ast.literal_eval(
            str(row["constitutional_failures_json"] or "[]"))),
        assessed_at=row["assessed_at"]) for row in rows]


def eligibility_blocked(db_path: str, candidate_id: str) -> bool:
    """A constitutional failure in production blocks the candidate regardless of performance."""
    return any(assessment.candidate_id == candidate_id
               and assessment.status == STATUS_INTEGRITY_BLOCKED
               for assessment in assessment_history(db_path))


def monitoring_digest(db_path: str) -> str:
    return digest({"version": CRUCIBLE_POST_PROMOTION_V1,
                   "assessments": [item.as_dict() for item in assessment_history(db_path)]})
