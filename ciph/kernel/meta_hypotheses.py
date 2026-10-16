"""
ciph/kernel/meta_hypotheses - 4.7 Gate Two: what change to the machinery might fix that weakness?

A meta hypothesis is falsifiable at the SECOND ORDER: not "does planner B beat planner A" but "does
generator G2 produce better candidate populations than G1 across opportunity families".

LAWS  (same discipline as 4.6)
 1. Opportunity != hypothesis != candidate.
 2. Expected improvement must name measurable meta metrics.
 3. Regression risks are explicit.
 4. The hypothesis pins the EXACT baseline component identity.
 5. A changed baseline makes it STALE rather than silently rebasing.
 6. Only a measured meta-protocol outcome can make it SUPPORTED or REJECTED.
 7. History is append-only.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_metrics import (
    STATUS_DOMINATED,
    STATUS_DOMINATES,
    STATUS_EQUIVALENT,
    STATUS_INCOMPARABLE,
    STATUS_INSUFFICIENT,
    STATUS_INVALID,
)
from ciph.kernel.crucible_types import CrucibleError, digest
from ciph.kernel.meta_opportunities import get_meta_opportunity

META_HYPOTHESIS_V1 = "META_HYPOTHESIS_V1"

STATUS_PROPOSED = "PROPOSED"
STATUS_STALE = "STALE"
STATUS_TESTED = "TESTED"
STATUS_REJECTED = "REJECTED"
STATUS_SUPPORTED = "SUPPORTED"
REASON_BASELINE_MOVED = "STALE_META_HYPOTHESIS"

_OUTCOME_MAP = {STATUS_DOMINATES: STATUS_SUPPORTED, STATUS_DOMINATED: STATUS_REJECTED,
                STATUS_INVALID: STATUS_REJECTED, STATUS_INCOMPARABLE: STATUS_TESTED,
                STATUS_EQUIVALENT: STATUS_TESTED, STATUS_INSUFFICIENT: STATUS_TESTED}

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_hypotheses (
        hypothesis_id TEXT PRIMARY KEY,
        opportunity_id TEXT NOT NULL,
        baseline_component_identity TEXT NOT NULL,
        proposed_change TEXT NOT NULL,
        expected_improvements_json TEXT NOT NULL,
        forbidden_regressions_json TEXT,
        required_meta_protocol_id TEXT,
        falsification_conditions_json TEXT,
        basis_digest TEXT NOT NULL,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_hypothesis_outcomes (
        outcome_id TEXT PRIMARY KEY,
        hypothesis_id TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        comparison_status TEXT NOT NULL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetaExpectation:
    metric_id: str
    expected_direction: str
    minimum_expected_delta: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {"metric_id": self.metric_id, "expected_direction": self.expected_direction,
                "minimum_expected_delta": self.minimum_expected_delta}


@dataclass(frozen=True)
class MetaHypothesis:
    hypothesis_id: str
    opportunity_id: str
    baseline_component_identity: str
    proposed_change: str
    expected_improvements: Tuple[MetaExpectation, ...]
    forbidden_regressions: Tuple[Dict[str, Any], ...]
    required_meta_protocol_id: Optional[str]
    falsification_conditions: Tuple[str, ...]
    basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "opportunity_id": self.opportunity_id,
                "baseline_component_identity": self.baseline_component_identity,
                "proposed_change": self.proposed_change,
                "expected_improvements": [item.as_dict() for item in self.expected_improvements],
                "forbidden_regressions": [dict(item) for item in self.forbidden_regressions],
                "required_meta_protocol_id": self.required_meta_protocol_id,
                "falsification_conditions": list(self.falsification_conditions),
                "basis_digest": self.basis_digest}


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


def propose_meta_hypothesis(db_path: str, *, opportunity_id: str,
                            baseline_component_identity: str, proposed_change: str,
                            expected_improvements: Sequence[MetaExpectation],
                            forbidden_regressions: Sequence[Dict[str, Any]] = (),
                            required_meta_protocol_id: Optional[str] = None,
                            falsification_conditions: Sequence[str] = (),
                            now: Optional[float] = None) -> MetaHypothesis:
    if not expected_improvements:
        raise CrucibleError("META_HYPOTHESIS_REQUIRES_EXPECTED_IMPROVEMENT", proposed_change)
    for item in expected_improvements:
        if not item.metric_id or item.expected_direction not in ("HIGHER_BETTER", "LOWER_BETTER"):
            raise CrucibleError("INVALID_EXPECTED_DIRECTION", f"{item.metric_id}")
    opportunity = get_meta_opportunity(db_path, opportunity_id)
    if str(baseline_component_identity) != opportunity.exact_component_identity:
        # Law 4: the hypothesis must be written against the version the weakness was observed at.
        raise CrucibleError("META_HYPOTHESIS_BASELINE_MISMATCH",
                            f"{baseline_component_identity} != {opportunity.exact_component_identity}")
    moment = time.time() if now is None else float(now)
    basis = {"version": META_HYPOTHESIS_V1, "opportunity": opportunity.basis_digest,
             "baseline": str(baseline_component_identity), "change": str(proposed_change),
             "expected": sorted((item.as_dict() for item in expected_improvements),
                                key=lambda item: item["metric_id"])}
    hypothesis_id = "MH-" + digest(basis)[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_hypotheses (hypothesis_id, opportunity_id, "
            "baseline_component_identity, proposed_change, expected_improvements_json, "
            "forbidden_regressions_json, required_meta_protocol_id, falsification_conditions_json, "
            "basis_digest, created_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (hypothesis_id, opportunity_id, str(baseline_component_identity), str(proposed_change),
             json.dumps([item.as_dict() for item in expected_improvements]),
             json.dumps([dict(item) for item in forbidden_regressions], sort_keys=True),
             required_meta_protocol_id,
             json.dumps(sorted(str(item) for item in falsification_conditions)),
             json.dumps(basis, sort_keys=True), moment))
        connection.commit()
    finally:
        connection.close()
    return get_meta_hypothesis(db_path, hypothesis_id)


def get_meta_hypothesis(db_path: str, hypothesis_id: str) -> MetaHypothesis:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_hypotheses WHERE hypothesis_id = ?;",
                                 (hypothesis_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_META_HYPOTHESIS", hypothesis_id)
    row = dict(row)
    return MetaHypothesis(
        hypothesis_id=str(row["hypothesis_id"]), opportunity_id=str(row["opportunity_id"]),
        baseline_component_identity=str(row["baseline_component_identity"]),
        proposed_change=str(row["proposed_change"]),
        expected_improvements=tuple(MetaExpectation(**item) for item in
                                    json.loads(row["expected_improvements_json"] or "[]")),
        forbidden_regressions=tuple(json.loads(row["forbidden_regressions_json"] or "[]")),
        required_meta_protocol_id=row["required_meta_protocol_id"],
        falsification_conditions=tuple(json.loads(row["falsification_conditions_json"] or "[]")),
        basis_digest=str(row["basis_digest"]))


def record_meta_hypothesis_outcome(db_path: str, *, hypothesis_id: str, protocol_id: str,
                                   comparison_status: str, now: Optional[float] = None) -> str:
    if comparison_status not in _OUTCOME_MAP:
        raise CrucibleError("INVALID_COMPARISON_STATUS", str(comparison_status))
    get_meta_hypothesis(db_path, hypothesis_id)
    moment = time.time() if now is None else float(now)
    outcome_id = "MHO-" + digest({"hypothesis": hypothesis_id, "protocol": protocol_id,
                                  "status": comparison_status})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_hypothesis_outcomes (outcome_id, hypothesis_id, "
            "protocol_id, comparison_status, recorded_at) VALUES (?,?,?,?,?);",
            (outcome_id, hypothesis_id, protocol_id, comparison_status, moment))
        connection.commit()
    finally:
        connection.close()
    return outcome_id


def meta_hypothesis_status(db_path: str, hypothesis_id: str, *,
                           current_component_identity: Optional[str] = None) -> str:
    hypothesis = get_meta_hypothesis(db_path, hypothesis_id)
    if current_component_identity is not None and (
            str(current_component_identity) != hypothesis.baseline_component_identity):
        return STATUS_STALE
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute(
            "SELECT comparison_status FROM ciph_meta_hypothesis_outcomes WHERE hypothesis_id = ? "
            "ORDER BY rowid DESC LIMIT 1;", (hypothesis_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return STATUS_PROPOSED if row is None else _OUTCOME_MAP[str(row["comparison_status"])]


def meta_hypothesis_history(db_path: str) -> List[MetaHypothesis]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["hypothesis_id"]) for row in connection.execute(
            "SELECT hypothesis_id FROM ciph_meta_hypotheses ORDER BY created_at, hypothesis_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_meta_hypothesis(db_path, hypothesis_id) for hypothesis_id in ids]


def meta_hypothesis_digest(db_path: str) -> str:
    return digest({"version": META_HYPOTHESIS_V1,
                   "hypotheses": [item.as_dict() for item in meta_hypothesis_history(db_path)]})
