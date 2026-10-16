"""
ciph/kernel/meta_learning - 4.7 Gate Ten: which kinds of meta-change actually work?

Descriptive, never a scalar ego score. "Three useful promotions in five meta trials, one of which
caused candidate diversity collapse" - not "I am 83% better at improving myself".

Not authority: this projection may guide future proposals and nothing else.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_metrics import VALID_COMPARISON_STATUSES
from ciph.kernel.crucible_types import CrucibleError, digest

META_STRATEGY_LEARNING_V1 = "META_STRATEGY_LEARNING_V1"

PROMOTION_NOT_PROMOTED = "NOT_PROMOTED"
PROMOTION_PROMOTED = "PROMOTED"
PROMOTION_REGRESSED = "REGRESSED"
PROMOTION_ROLLED_BACK = "ROLLED_BACK"
VALID_PROMOTION_RESULTS = (PROMOTION_NOT_PROMOTED, PROMOTION_PROMOTED, PROMOTION_REGRESSED,
                           PROMOTION_ROLLED_BACK)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_promotion_events (
        event_id TEXT PRIMARY KEY,
        attempt_id TEXT NOT NULL,
        promotion_result TEXT NOT NULL,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_strategy_attempts (
        attempt_id TEXT PRIMARY KEY,
        strategy_kind TEXT NOT NULL,
        opportunity_id TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL,
        meta_candidate_id TEXT NOT NULL,
        target_ring TEXT NOT NULL,
        meta_result TEXT NOT NULL,
        promotion_result TEXT NOT NULL,
        constitutional_block INTEGER NOT NULL,
        cost REAL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetaStrategyAttempt:
    attempt_id: str
    strategy_kind: str
    opportunity_id: str
    hypothesis_id: str
    meta_candidate_id: str
    target_ring: str
    meta_result: str
    promotion_result: str
    constitutional_block: bool
    cost: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"attempt_id": self.attempt_id, "strategy_kind": self.strategy_kind,
                "opportunity_id": self.opportunity_id, "hypothesis_id": self.hypothesis_id,
                "meta_candidate_id": self.meta_candidate_id, "target_ring": self.target_ring,
                "meta_result": self.meta_result, "promotion_result": self.promotion_result,
                "constitutional_block": self.constitutional_block, "cost": self.cost}


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


def record_meta_attempt(db_path: str, *, strategy_kind: str, opportunity_id: str,
                        hypothesis_id: str, meta_candidate_id: str, target_ring: str,
                        meta_result: str, promotion_result: str = PROMOTION_NOT_PROMOTED,
                        constitutional_block: bool = False, cost: Optional[float] = None,
                        now: Optional[float] = None) -> MetaStrategyAttempt:
    if meta_result not in VALID_COMPARISON_STATUSES:
        raise CrucibleError("INVALID_COMPARISON_STATUS", str(meta_result))
    if promotion_result not in VALID_PROMOTION_RESULTS:
        raise CrucibleError("INVALID_PROMOTION_RESULT", str(promotion_result))
    moment = time.time() if now is None else float(now)
    attempt_id = "MAT-" + digest({"hypothesis": hypothesis_id, "candidate": meta_candidate_id,
                                  "strategy": strategy_kind})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_strategy_attempts (attempt_id, strategy_kind, "
            "opportunity_id, hypothesis_id, meta_candidate_id, target_ring, meta_result, "
            "promotion_result, constitutional_block, cost, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (attempt_id, strategy_kind, opportunity_id, hypothesis_id, meta_candidate_id,
             target_ring, meta_result, promotion_result, 1 if constitutional_block else 0, cost,
             moment))
        connection.commit()
    finally:
        connection.close()
    return get_meta_attempt(db_path, attempt_id)


def record_meta_promotion_result(db_path: str, *, attempt_id: str, promotion_result: str,
                                 now: Optional[float] = None) -> MetaStrategyAttempt:
    """
    Append ONE production-side event (promoted, then regressed, then rolled back).

    The attempt row keeps the LATEST value for convenience, but the projection counts EVENTS: a single
    column would collapse "dominated, promoted, regressed, rolled back" into the last one, which is
    exactly the nuance this projection exists to preserve.
    """
    if promotion_result not in VALID_PROMOTION_RESULTS:
        raise CrucibleError("INVALID_PROMOTION_RESULT", str(promotion_result))
    attempt = get_meta_attempt(db_path, attempt_id)
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_promotion_events (event_id, attempt_id, "
            "promotion_result, recorded_at) VALUES (?,?,?,?);",
            ("MPE-" + digest({"attempt": attempt_id, "result": promotion_result})[:16].upper(),
             attempt_id, promotion_result, moment))
        connection.execute("UPDATE ciph_meta_strategy_attempts SET promotion_result = ? "
                           "WHERE attempt_id = ?;", (promotion_result, attempt_id))
        connection.commit()
    finally:
        connection.close()
    updated = get_meta_attempt(db_path, attempt_id)
    if updated.meta_result != attempt.meta_result:
        raise CrucibleError("META_VERDICT_REWRITTEN", attempt_id)
    return updated


def get_meta_attempt(db_path: str, attempt_id: str) -> MetaStrategyAttempt:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_strategy_attempts WHERE attempt_id = ?;",
                                 (attempt_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_META_ATTEMPT", attempt_id)
    row = dict(row)
    return MetaStrategyAttempt(
        attempt_id=str(row["attempt_id"]), strategy_kind=str(row["strategy_kind"]),
        opportunity_id=str(row["opportunity_id"]), hypothesis_id=str(row["hypothesis_id"]),
        meta_candidate_id=str(row["meta_candidate_id"]), target_ring=str(row["target_ring"]),
        meta_result=str(row["meta_result"]), promotion_result=str(row["promotion_result"]),
        constitutional_block=bool(row["constitutional_block"]), cost=row["cost"])


def meta_attempts(db_path: str, strategy_kind: Optional[str] = None) -> List[MetaStrategyAttempt]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT attempt_id FROM ciph_meta_strategy_attempts"
    params: Tuple[Any, ...] = ()
    if strategy_kind is not None:
        query += " WHERE strategy_kind = ?"
        params = (strategy_kind,)
    try:
        ids = [str(row["attempt_id"]) for row in connection.execute(
            query + " ORDER BY recorded_at, attempt_id;", params)]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_meta_attempt(db_path, attempt_id) for attempt_id in ids]


def meta_strategy_projection(db_path: str,
                             strategy_kind: Optional[str] = None) -> List[Dict[str, Any]]:
    """Multidimensional, descriptive, and deliberately without a scalar score."""
    grouped: Dict[str, List[MetaStrategyAttempt]] = {}
    for attempt in meta_attempts(db_path, strategy_kind):
        grouped.setdefault(attempt.strategy_kind, []).append(attempt)
    events: Dict[str, List[str]] = {}
    connection = _connect(db_path)
    try:
        for row in connection.execute("SELECT attempt_id, promotion_result FROM "
                                      "ciph_meta_promotion_events ORDER BY rowid;"):
            events.setdefault(str(row["attempt_id"]), []).append(str(row["promotion_result"]))
    except sqlite3.Error:
        pass
    finally:
        connection.close()
    projection = []
    for kind in sorted(grouped):
        history = grouped[kind]
        results = [item.meta_result for item in history]
        projection.append({
            "strategy_kind": kind,
            "attempts": len(history),
            "meta_dominates": results.count("DOMINATES"),
            "meta_dominated": results.count("DOMINATED"),
            "incomparable": results.count("INCOMPARABLE"),
            "insufficient": results.count("INSUFFICIENT_EVIDENCE"),
            "invalid": results.count("INVALID"),
            "promoted": sum(1 for item in history
                            if PROMOTION_PROMOTED in events.get(item.attempt_id, [])),
            "rollbacks": sum(1 for item in history
                             if PROMOTION_ROLLED_BACK in events.get(item.attempt_id, [])),
            "production_regressions": sum(1 for item in history
                                          if PROMOTION_REGRESSED in events.get(item.attempt_id, [])),
            "constitutional_blocks": sum(1 for item in history if item.constitutional_block),
            "target_rings": sorted({item.target_ring for item in history}),
        })
    return projection


def meta_learning_digest(db_path: str) -> str:
    return digest({"version": META_STRATEGY_LEARNING_V1,
                   "attempts": [item.as_dict() for item in meta_attempts(db_path)]})
