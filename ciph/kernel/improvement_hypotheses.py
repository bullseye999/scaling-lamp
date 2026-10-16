"""
ciph/kernel/improvement_hypotheses - 4.6 Gate One: what change might address the weakness?

A hypothesis is 4.3's causal reasoning turned inward: a stated intervention, the metrics it expects to
move, the regressions it accepts as possible, and the conditions under which it would be wrong.

    opportunity != hypothesis != candidate

and the hypothesis cannot choose its own result: an outcome only ever arrives from a Crucible
comparison recorded against a frozen protocol.

LAWS
 1. Opportunity != hypothesis.
 2. Hypothesis != candidate.
 3. "Change X will improve Y" is an epistemic proposal.
 4. Expected improvement must name measurable Crucible metrics.
 5. Regression risks are explicit where known.
 6. A hypothesis is bound to the exact baseline identity.
 7. A baseline change STALES the hypothesis rather than silently re-basing it.
 8. Model confidence does not strengthen the hypothesis.
 9. Multiple competing hypotheses may exist for one opportunity.
10. Hypothesis history is append-only.
11. Same basis plus same intervention -> same hypothesis identity.
12. The hypothesis cannot choose its own evaluation result.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.crucible_metrics import (
    STATUS_DOMINATED,
    STATUS_INCOMPARABLE,
    STATUS_EQUIVALENT,
    STATUS_INSUFFICIENT,
    STATUS_INVALID,
)
from ciph.kernel.crucible_types import (
    DIRECTION_HIGHER_BETTER,
    DIRECTION_LOWER_BETTER,
    CrucibleError,
    VALID_DIRECTIONS,
    digest,
)
from ciph.kernel.improvement_opportunities import get_opportunity

IMPROVEMENT_HYPOTHESIS_V1 = "IMPROVEMENT_HYPOTHESIS_V1"

STATUS_PROPOSED = "PROPOSED"
STATUS_STALE = "STALE"
STATUS_TESTED = "TESTED"
STATUS_REJECTED = "REJECTED"
STATUS_SUPPORTED = "SUPPORTED"
VALID_STATUSES = (STATUS_PROPOSED, STATUS_STALE, STATUS_TESTED, STATUS_REJECTED, STATUS_SUPPORTED)

REASON_BASELINE_MOVED = "STALE_IMPROVEMENT_HYPOTHESIS"

# How a Crucible comparison status becomes a hypothesis outcome. `SUPPORTED` means "the evaluation
# supported this hypothesis under this protocol" - never universal truth.
_OUTCOME_MAP = {"DOMINATES": STATUS_SUPPORTED, STATUS_DOMINATED: STATUS_REJECTED,
                STATUS_INVALID: STATUS_REJECTED, STATUS_INCOMPARABLE: STATUS_TESTED,
                STATUS_EQUIVALENT: STATUS_TESTED, STATUS_INSUFFICIENT: STATUS_TESTED}

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_improvement_hypotheses (
        hypothesis_id TEXT PRIMARY KEY,
        opportunity_id TEXT NOT NULL,
        target_component TEXT NOT NULL,
        baseline_candidate_id TEXT,
        proposed_change_class TEXT NOT NULL,
        expected_improvements_json TEXT NOT NULL,
        possible_regressions_json TEXT,
        required_protocol_kind TEXT,
        falsification_conditions_json TEXT,
        basis_digest TEXT NOT NULL,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_improvement_hypothesis_outcomes (
        outcome_id TEXT PRIMARY KEY,
        hypothesis_id TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        comparison_status TEXT NOT NULL,
        candidate_id TEXT,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class ExpectedImprovement:
    metric_id: str
    expected_direction: str
    minimum_expected_delta: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {"metric_id": self.metric_id, "expected_direction": self.expected_direction,
                "minimum_expected_delta": self.minimum_expected_delta}


@dataclass(frozen=True)
class ImprovementHypothesis:
    hypothesis_id: str
    opportunity_id: str
    target_component: str
    baseline_candidate_id: Optional[str]
    proposed_change_class: str
    expected_improvements: Tuple[ExpectedImprovement, ...]
    possible_regressions: Tuple[Dict[str, Any], ...]
    required_protocol_kind: Optional[str]
    falsification_conditions: Tuple[str, ...]
    basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "opportunity_id": self.opportunity_id,
                "target_component": self.target_component,
                "baseline_candidate_id": self.baseline_candidate_id,
                "proposed_change_class": self.proposed_change_class,
                "expected_improvements": [item.as_dict() for item in self.expected_improvements],
                "possible_regressions": [dict(item) for item in self.possible_regressions],
                "required_protocol_kind": self.required_protocol_kind,
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


def hypothesis_basis(*, opportunity_basis_digest: str, target_component: str,
                     baseline_candidate_id: Optional[str], proposed_change_class: str,
                     expected_improvements: Sequence[ExpectedImprovement]) -> Dict[str, Any]:
    """Identity is (weakness, component, baseline, intervention). A different baseline is a different
    hypothesis, which is exactly why a moved baseline cannot be silently absorbed (law 6/7)."""
    return {"version": IMPROVEMENT_HYPOTHESIS_V1,
            "opportunity": opportunity_basis_digest, "target_component": target_component,
            "baseline_candidate_id": baseline_candidate_id,
            "proposed_change_class": proposed_change_class,
            "expected": sorted((item.as_dict() for item in expected_improvements),
                                 key=lambda item: (item["metric_id"], item["expected_direction"]))}


def propose_hypothesis(db_path: str, *, opportunity_id: str, target_component: str,
                       proposed_change_class: str,
                       expected_improvements: Sequence[ExpectedImprovement],
                       baseline_candidate_id: Optional[str] = None,
                       possible_regressions: Sequence[Mapping[str, Any]] = (),
                       required_protocol_kind: Optional[str] = None,
                       falsification_conditions: Sequence[str] = (),
                       now: Optional[float] = None) -> ImprovementHypothesis:
    """Record ONE hypothesis. It names what would move, what might break, and what would falsify it."""
    if not expected_improvements:
        raise CrucibleError("HYPOTHESIS_REQUIRES_EXPECTED_IMPROVEMENT",
                            'a hypothesis with no measurable expectation is a wish')
    for item in expected_improvements:
        if item.expected_direction not in VALID_DIRECTIONS:
            raise CrucibleError("INVALID_EXPECTED_DIRECTION",
                                f"{item.metric_id}:{item.expected_direction}")
        if not item.metric_id:
            raise CrucibleError("EXPECTED_IMPROVEMENT_REQUIRES_METRIC_ID", '')
    opportunity = get_opportunity(db_path, opportunity_id)
    moment = time.time() if now is None else float(now)
    basis = hypothesis_basis(opportunity_basis_digest=opportunity.basis_digest,
                             target_component=target_component,
                             baseline_candidate_id=baseline_candidate_id,
                             proposed_change_class=proposed_change_class,
                             expected_improvements=expected_improvements)
    hypothesis_id = "IH-" + digest(basis)[:16].upper()
    payload = json.dumps(basis, sort_keys=True, default=str)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_improvement_hypotheses (hypothesis_id, opportunity_id, "
            "target_component, baseline_candidate_id, proposed_change_class, "
            "expected_improvements_json, possible_regressions_json, required_protocol_kind, "
            "falsification_conditions_json, basis_digest, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (hypothesis_id, opportunity_id, target_component, baseline_candidate_id,
             proposed_change_class,
             json.dumps([item.as_dict() for item in expected_improvements], sort_keys=True),
             json.dumps([dict(item) for item in possible_regressions], sort_keys=True, default=str),
             required_protocol_kind, json.dumps(sorted(str(item) for item in
                                                       falsification_conditions)),
             payload, moment))
        connection.commit()
    finally:
        connection.close()
    return get_hypothesis(db_path, hypothesis_id)


def _row_to_hypothesis(row: Mapping[str, Any]) -> ImprovementHypothesis:
    return ImprovementHypothesis(
        hypothesis_id=str(row["hypothesis_id"]), opportunity_id=str(row["opportunity_id"]),
        target_component=str(row["target_component"]),
        baseline_candidate_id=row["baseline_candidate_id"],
        proposed_change_class=str(row["proposed_change_class"]),
        expected_improvements=tuple(ExpectedImprovement(**item) for item in
                                    json.loads(row["expected_improvements_json"] or "[]")),
        possible_regressions=tuple(json.loads(row["possible_regressions_json"] or "[]")),
        required_protocol_kind=row["required_protocol_kind"],
        falsification_conditions=tuple(json.loads(row["falsification_conditions_json"] or "[]")),
        basis_digest=str(row["basis_digest"]))


def get_hypothesis(db_path: str, hypothesis_id: str) -> ImprovementHypothesis:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_improvement_hypotheses WHERE hypothesis_id = ?;",
                                 (hypothesis_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_HYPOTHESIS", hypothesis_id)
    return _row_to_hypothesis(dict(row))


def record_hypothesis_outcome(db_path: str, *, hypothesis_id: str, protocol_id: str,
                              comparison_status: str, candidate_id: Optional[str] = None,
                              now: Optional[float] = None) -> str:
    """
    Record what the CRUCIBLE said (law 12).

    The hypothesis does not get a status parameter: its standing is derived from a comparison that ran
    against a frozen protocol, so a confident hypothesis and a lucky one are indistinguishable here.
    """
    if comparison_status not in _OUTCOME_MAP:
        raise CrucibleError("INVALID_COMPARISON_STATUS", str(comparison_status))
    get_hypothesis(db_path, hypothesis_id)
    moment = time.time() if now is None else float(now)
    outcome_id = "IHO-" + digest({"hypothesis": hypothesis_id, "protocol": protocol_id,
                                  "status": comparison_status,
                                  "candidate": candidate_id})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_improvement_hypothesis_outcomes (outcome_id, hypothesis_id, "
            "protocol_id, comparison_status, candidate_id, recorded_at) VALUES (?,?,?,?,?,?);",
            (outcome_id, hypothesis_id, protocol_id, comparison_status, candidate_id, moment))
        connection.commit()
    finally:
        connection.close()
    return outcome_id


def hypothesis_outcomes(db_path: str, hypothesis_id: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_improvement_hypothesis_outcomes WHERE hypothesis_id = ? "
            "ORDER BY rowid;", (hypothesis_id,))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def hypothesis_status(db_path: str, hypothesis_id: str, *,
                      current_baseline_candidate_id: Optional[str] = None) -> str:
    """
    DERIVED status (laws 7 and 12).

    A moved baseline STALES the hypothesis instead of quietly re-basing it onto the new one; a recorded
    Crucible outcome is the only thing that can make it SUPPORTED or REJECTED.
    """
    hypothesis = get_hypothesis(db_path, hypothesis_id)
    if current_baseline_candidate_id is not None and (
            hypothesis.baseline_candidate_id != current_baseline_candidate_id):
        return STATUS_STALE
    outcomes = hypothesis_outcomes(db_path, hypothesis_id)
    if not outcomes:
        return STATUS_PROPOSED
    latest = outcomes[-1]
    return _OUTCOME_MAP[str(latest["comparison_status"])]


def hypothesis_history(db_path: str) -> List[ImprovementHypothesis]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["hypothesis_id"]) for row in connection.execute(
            "SELECT hypothesis_id FROM ciph_improvement_hypotheses "
            "ORDER BY created_at, hypothesis_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_hypothesis(db_path, hypothesis_id) for hypothesis_id in ids]


def hypothesis_digest(db_path: str) -> str:
    return digest({"version": IMPROVEMENT_HYPOTHESIS_V1,
                   "hypotheses": [item.as_dict() for item in hypothesis_history(db_path)]})
