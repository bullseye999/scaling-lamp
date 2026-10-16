"""
ciph/kernel/swarm_learning - 6.11 (delegation strategy learning) and 6.12 (the 5.x binding).

    Historical success does not grant authority.

Ciph may learn that "research tasks go faster with two workers than five" or "worker W3 and model M1
disagree in a correlated way". That is a description of experience, and it stays a description: this
module produces a projection with counts and no scalar. There is deliberately no
`SWARM_INTELLIGENCE_SCORE`, because a number like that is an opinion wearing a lab coat - and because
the moment a swarm has a score, somebody routes work by it.

6.12 is also captured here: the escalation from a swarm result back into the constitution is a NORMAL
action through 4.0, and the helpers below exist so that path has a name instead of being improvised at
a call site.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SWARM_DELEGATION_LEARNING_V1 = "SWARM_DELEGATION_LEARNING_V1"
SWARM_ESCALATION_V1 = "SWARM_ESCALATION_V1"

OUTCOME_USEFUL = "USEFUL"
OUTCOME_USELESS = "USELESS"
OUTCOME_FAILED = "FAILED"
OUTCOME_INTERRUPTED = "INTERRUPTED"
VALID_OUTCOMES = (OUTCOME_USEFUL, OUTCOME_USELESS, OUTCOME_FAILED, OUTCOME_INTERRUPTED)

REASON_ESCALATION_REQUIRES_ACTION = "SWARM_ESCALATION_REQUIRES_A_GOVERNED_ACTION"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_delegation_attempts (
        attempt_id TEXT PRIMARY KEY,
        task_class TEXT NOT NULL,
        delegation_id TEXT NOT NULL,
        worker_mix_json TEXT NOT NULL,
        outcome TEXT NOT NULL,
        latency_seconds REAL,
        resource_cost REAL,
        stale_results INTEGER NOT NULL,
        duplicate_results INTEGER NOT NULL,
        disagreement INTEGER NOT NULL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class DelegationAttempt:
    attempt_id: str
    task_class: str
    delegation_id: str
    worker_mix: Tuple[str, ...]
    outcome: str
    latency_seconds: float
    resource_cost: float

    def as_dict(self) -> Dict[str, Any]:
        return {"attempt_id": self.attempt_id, "task_class": self.task_class,
                "delegation_id": self.delegation_id, "worker_mix": list(self.worker_mix),
                "outcome": self.outcome, "latency_seconds": self.latency_seconds,
                "resource_cost": self.resource_cost,
                "policy_version": SWARM_DELEGATION_LEARNING_V1}


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


def record_attempt(db_path: str, *, task_class: str, delegation_id: str,
                   worker_mix: Sequence[str], outcome: str, latency_seconds: float = 0.0,
                   resource_cost: float = 0.0, stale_results: int = 0, duplicate_results: int = 0,
                   disagreement: bool = False, now: Optional[float] = None) -> DelegationAttempt:
    """
    Record ONE delegation attempt. The identity is the delegation, so a replayed report is not a
    second data point - only a re-issued delegation at a new generation is.
    """
    if str(outcome) not in VALID_OUTCOMES:
        raise CrucibleError("UNKNOWN_DELEGATION_OUTCOME", str(outcome))
    moment = time.time() if now is None else float(now)
    mix = sorted(str(item) for item in worker_mix)
    attempt_id = "SDA-" + digest({"delegation": str(delegation_id),
                                  "class": str(task_class)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_swarm_delegation_attempts (attempt_id, task_class, "
            "delegation_id, worker_mix_json, outcome, latency_seconds, resource_cost, "
            "stale_results, duplicate_results, disagreement, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (attempt_id, str(task_class), str(delegation_id), json.dumps(mix), str(outcome),
             float(latency_seconds), float(resource_cost), int(stale_results),
             int(duplicate_results), 1 if disagreement else 0, moment))
        connection.commit()
    finally:
        connection.close()
    return DelegationAttempt(attempt_id=attempt_id, task_class=str(task_class),
                             delegation_id=str(delegation_id), worker_mix=tuple(mix),
                             outcome=str(outcome), latency_seconds=float(latency_seconds),
                             resource_cost=float(resource_cost))


def attempts(db_path: str, task_class: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_swarm_delegation_attempts"
    params: Tuple[Any, ...] = ()
    if task_class is not None:
        query += " WHERE task_class = ?"
        params = (str(task_class),)
    try:
        rows = [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, attempt_id;", params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    for row in rows:
        row["worker_mix"] = json.loads(row.pop("worker_mix_json") or "[]")
        row["disagreement"] = bool(row["disagreement"])
    return rows


def delegation_strategy(db_path: str, task_class: Optional[str] = None) -> Dict[str, Any]:
    """
    What delegation has actually bought, per task class, with no aggregate verdict.

    Deliberately absent: any single number that could be called "how good the swarm is". The projection
    reports attempts, outcomes, worker mixes, cost, lateness, duplication and disagreement separately,
    because those are the facts a human needs and a scalar is the fact that hides them.
    """
    rows = attempts(db_path, task_class)
    mixes: Dict[str, int] = {}
    for row in rows:
        mix_key = "+".join(row["worker_mix"]) or "(none)"
        mixes[mix_key] = mixes.get(mix_key, 0) + 1
    return {"policy_version": SWARM_DELEGATION_LEARNING_V1,
            "task_class": task_class, "attempts": len(rows),
            "useful": len([row for row in rows if row["outcome"] == OUTCOME_USEFUL]),
            "useless": len([row for row in rows if row["outcome"] == OUTCOME_USELESS]),
            "failed": len([row for row in rows if row["outcome"] == OUTCOME_FAILED]),
            "interrupted": len([row for row in rows if row["outcome"] == OUTCOME_INTERRUPTED]),
            "disagreements": len([row for row in rows if row["disagreement"]]),
            "stale_results": sum(int(row["stale_results"]) for row in rows),
            "duplicate_results": sum(int(row["duplicate_results"]) for row in rows),
            "latency_seconds_total": round(sum(float(row["latency_seconds"]) for row in rows), 6),
            "resource_cost_total": round(sum(float(row["resource_cost"]) for row in rows), 6),
            "worker_mixes": dict(sorted(mixes.items())), "no_score": True}


def escalation_requires_an_action(db_path: str, *, delegation_id: str, proposed_effect: str,
                                  now: Optional[float] = None) -> Dict[str, Any]:
    """
    6.12: a worker's conclusion NEVER becomes an effect by itself.

    An escalation is a signed statement of intent - it names what the worker thinks should change and
    then stops. Refusing here (rather than at execution time) keeps the boundary visible: the effect
    must exist as a 4.0 Action with its own authority, not as the tail of a delegated computation.
    """
    from ciph.kernel.swarm_results import current_result, results_for
    moment = time.time() if now is None else float(now)
    current = current_result(db_path, delegation_id)
    return {"policy_version": SWARM_ESCALATION_V1, "delegation_id": str(delegation_id),
            "proposed_effect": str(proposed_effect),
            "supported_by_result": current.result_id if current else None,
            "results_considered": len(results_for(db_path, delegation_id)),
            "requires": "4.0 governed action with its own authority",
            "authority": "none", "executed": False, "recorded_at": moment}


def learning_digest(db_path: str) -> str:
    return digest({"version": SWARM_DELEGATION_LEARNING_V1, "attempts": attempts(db_path)})
