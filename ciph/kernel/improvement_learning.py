"""
ciph/kernel/improvement_learning - 4.6 Gate Five: which improvement strategies actually work?

What is learned is the quality of the GENERATION STRATEGY, never a verdict about a candidate - the
Crucible already owns that. History stays multidimensional: a strategy with one dominance and one
production rollback is described by both facts, not by an average of them.

LAWS
 1. Strategy success comes from Crucible outcomes, not self-assessment.
 2. DOMINATES once does not make a universally good strategy.
 3. Benchmark dominance followed by production rollback is preserved as BOTH facts.
 4. INVALID candidates count against the generation strategy.
 5. Failed construction is not automatically a failed hypothesis.
 6. INCOMPARABLE is not failure.
 7. INSUFFICIENT_EVIDENCE is neither failure nor success.
 8. Historical learning never grants authority.
 9. More generated candidates does not mean a better generator.
10. Duplicate attempts cannot inflate strategy history.
11. Same Crucible history -> same strategy projection.
12. Restart reproduces identical learning state.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_metrics import VALID_COMPARISON_STATUSES
from ciph.kernel.crucible_types import CrucibleError, digest

IMPROVEMENT_STRATEGY_LEARNING_V1 = "IMPROVEMENT_STRATEGY_LEARNING_V1"

PRODUCTION_NOT_PROMOTED = "NOT_PROMOTED"
PRODUCTION_HEALTHY = "HEALTHY"
PRODUCTION_REGRESSED = "REGRESSED"
PRODUCTION_ROLLED_BACK = "ROLLED_BACK"
VALID_PRODUCTION_RESULTS = (PRODUCTION_NOT_PROMOTED, PRODUCTION_HEALTHY, PRODUCTION_REGRESSED,
                            PRODUCTION_ROLLED_BACK)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_improvement_attempts (
        attempt_id TEXT PRIMARY KEY,
        opportunity_id TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL,
        candidate_id TEXT NOT NULL,
        generator_strategy_id TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        comparison_status TEXT NOT NULL,
        production_result TEXT NOT NULL,
        cost REAL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class ImprovementAttempt:
    attempt_id: str
    opportunity_id: str
    hypothesis_id: str
    candidate_id: str
    generator_strategy_id: str
    protocol_id: str
    comparison_status: str
    production_result: str
    cost: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"attempt_id": self.attempt_id, "opportunity_id": self.opportunity_id,
                "hypothesis_id": self.hypothesis_id, "candidate_id": self.candidate_id,
                "generator_strategy_id": self.generator_strategy_id,
                "protocol_id": self.protocol_id, "comparison_status": self.comparison_status,
                "production_result": self.production_result, "cost": self.cost}


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


def record_attempt(db_path: str, *, opportunity_id: str, hypothesis_id: str, candidate_id: str,
                   generator_strategy_id: str, protocol_id: str, comparison_status: str,
                   production_result: str = PRODUCTION_NOT_PROMOTED, cost: Optional[float] = None,
                   now: Optional[float] = None) -> ImprovementAttempt:
    """Record ONE attempt. The comparison status must be a real Crucible verdict (law 1)."""
    if comparison_status not in VALID_COMPARISON_STATUSES:
        raise CrucibleError("INVALID_COMPARISON_STATUS", str(comparison_status))
    if production_result not in VALID_PRODUCTION_RESULTS:
        raise CrucibleError("INVALID_PRODUCTION_RESULT", str(production_result))
    moment = time.time() if now is None else float(now)
    attempt_id = "IAT-" + digest({"hypothesis": hypothesis_id, "candidate": candidate_id,
                                  "protocol": protocol_id})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_improvement_attempts (attempt_id, opportunity_id, "
            "hypothesis_id, candidate_id, generator_strategy_id, protocol_id, comparison_status, "
            "production_result, cost, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (attempt_id, opportunity_id, hypothesis_id, candidate_id, generator_strategy_id,
             protocol_id, comparison_status, production_result, cost, moment))
        connection.commit()
    finally:
        connection.close()
    return get_attempt(db_path, attempt_id)


def record_production_result(db_path: str, *, attempt_id: str, production_result: str,
                             now: Optional[float] = None) -> ImprovementAttempt:
    """
    Later production evidence UPDATES the production column and leaves the benchmark verdict alone
    (law 3): "it dominated the benchmark" and "it regressed in production" are both true.
    """
    if production_result not in VALID_PRODUCTION_RESULTS:
        raise CrucibleError("INVALID_PRODUCTION_RESULT", str(production_result))
    attempt = get_attempt(db_path, attempt_id)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "UPDATE ciph_improvement_attempts SET production_result = ? WHERE attempt_id = ?;",
            (production_result, attempt_id))
        connection.commit()
    finally:
        connection.close()
    self_check = get_attempt(db_path, attempt_id)
    if self_check.comparison_status != attempt.comparison_status:
        raise CrucibleError("BENCHMARK_VERDICT_REWRITTEN", attempt_id)
    return self_check


def get_attempt(db_path: str, attempt_id: str) -> ImprovementAttempt:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_improvement_attempts WHERE attempt_id = ?;",
                                 (attempt_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_ATTEMPT", attempt_id)
    row = dict(row)
    return ImprovementAttempt(
        attempt_id=str(row["attempt_id"]), opportunity_id=str(row["opportunity_id"]),
        hypothesis_id=str(row["hypothesis_id"]), candidate_id=str(row["candidate_id"]),
        generator_strategy_id=str(row["generator_strategy_id"]),
        protocol_id=str(row["protocol_id"]), comparison_status=str(row["comparison_status"]),
        production_result=str(row["production_result"]), cost=row["cost"])


def attempts(db_path: str, generator_strategy_id: Optional[str] = None) -> List[ImprovementAttempt]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT attempt_id FROM ciph_improvement_attempts"
    params: Tuple[Any, ...] = ()
    if generator_strategy_id is not None:
        query += " WHERE generator_strategy_id = ?"
        params = (generator_strategy_id,)
    try:
        ids = [str(row["attempt_id"]) for row in connection.execute(
            query + " ORDER BY recorded_at, attempt_id;", params)]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_attempt(db_path, attempt_id) for attempt_id in ids]


def strategy_projection(db_path: str, *,
                        generator_strategy_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    A multidimensional projection over recorded attempts (laws 2, 4 and 6-7).

    There is deliberately no single score: INVALID counts against the strategy, INCOMPARABLE and
    INSUFFICIENT_EVIDENCE are counted honestly, and a production rollback stays visible next to the
    benchmark victory that preceded it.
    """
    grouped: Dict[str, List[ImprovementAttempt]] = {}
    for attempt in attempts(db_path, generator_strategy_id):
        grouped.setdefault(attempt.generator_strategy_id, []).append(attempt)
    projection = []
    for strategy_id in sorted(grouped):
        history = grouped[strategy_id]
        statuses = [item.comparison_status for item in history]
        projection.append({
            "strategy_id": strategy_id,
            "attempts": len(history),
            "dominates_count": statuses.count("DOMINATES"),
            "dominated_count": statuses.count("DOMINATED"),
            "incomparable_count": statuses.count("INCOMPARABLE"),
            "equivalent_count": statuses.count("EQUIVALENT"),
            "insufficient_count": statuses.count("INSUFFICIENT_EVIDENCE"),
            "invalid_count": statuses.count("INVALID"),
            "production_healthy_count": sum(1 for item in history
                                            if item.production_result == PRODUCTION_HEALTHY),
            "production_regressed_count": sum(1 for item in history
                                              if item.production_result == PRODUCTION_REGRESSED),
            "rollback_count": sum(1 for item in history
                                  if item.production_result == PRODUCTION_ROLLED_BACK),
            "statuses": statuses,
            "production_results": [item.production_result for item in history],
        })
    return projection


def learning_digest(db_path: str) -> str:
    return digest({"version": IMPROVEMENT_STRATEGY_LEARNING_V1,
                   "attempts": [item.as_dict() for item in attempts(db_path)]})
