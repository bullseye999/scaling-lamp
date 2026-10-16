"""
ciph/kernel/meta_comparison - 4.7: is a candidate GENERATOR better than the incumbent?

Second-order evaluation: not "does planner B beat planner A" but "does generator G2 produce better
candidate populations than G1". Both generators receive the same sealed meta corpus, and every ordinary
candidate either one produces is judged by the EXISTING authoritative 4.5 Crucible - never by the
candidate itself.

There is no scalar score. The result is the same partial order used everywhere else.
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple

from ciph.kernel.crucible_metrics import (
    STATUS_DOMINATED,
    STATUS_DOMINATES,
    STATUS_EQUIVALENT,
    STATUS_INCOMPARABLE,
    STATUS_INSUFFICIENT,
    STATUS_INVALID,
)
from ciph.kernel.crucible_types import CrucibleError, digest

META_PARETO_V1 = "META_PARETO_V1"

HIGHER_BETTER = "HIGHER_BETTER"
LOWER_BETTER = "LOWER_BETTER"

# The generator-level metrics 4.7 V1 knows how to read. Each names its direction and whether a
# regression in it is forbidden outright.
GENERATOR_METRICS: Tuple[Tuple[str, str, bool], ...] = (
    ("admissible_candidate_rate", HIGHER_BETTER, False),
    ("dominates_rate", HIGHER_BETTER, False),
    ("invalid_rate", LOWER_BETTER, False),
    ("incomparable_rate", LOWER_BETTER, False),
    ("construction_cost", LOWER_BETTER, False),
    ("production_regression_rate", LOWER_BETTER, True),
    ("constitutional_violation_rate", LOWER_BETTER, True),
)

FORBIDDEN_METRICS = tuple(metric for metric, _direction, forbidden in GENERATOR_METRICS if forbidden)


@dataclass(frozen=True)
class MetaComparisonResult:
    status: str
    better: Tuple[str, ...]
    worse: Tuple[str, ...]
    equivalent: Tuple[str, ...]
    reason_codes: Tuple[str, ...]
    metric_version: str = META_PARETO_V1

    def as_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "better": list(self.better), "worse": list(self.worse),
                "equivalent": list(self.equivalent), "reason_codes": list(self.reason_codes),
                "metric_version": self.metric_version}


def summarise_generator_outcomes(outcomes: Iterable[str]) -> Dict[str, float]:
    """
    Turn a generator's per-attempt Crucible outcomes into rates. A generator that produced nothing
    yields no rates, which is INSUFFICIENT_EVIDENCE downstream rather than a bad score.
    """
    statuses = [str(status) for status in outcomes]
    if not statuses:
        return {}
    total = float(len(statuses))
    return {"dominates_rate": statuses.count(STATUS_DOMINATES) / total,
            "invalid_rate": statuses.count(STATUS_INVALID) / total,
            "incomparable_rate": statuses.count(STATUS_INCOMPARABLE) / total,
            "admissible_candidate_rate": sum(1 for status in statuses
                                             if status != STATUS_INVALID) / total}


def compare_generators(baseline: Mapping[str, float], candidate: Mapping[str, float], *,
                       minimum_deltas: Mapping[str, float] = None,
                       constitutional_violations: int = 0,
                       production_regressions: int = 0,
                       minimum_evidence: int = 1) -> MetaComparisonResult:
    """THE frozen meta comparison. Hard invariants stay non-tradeable on the second order too."""
    if int(constitutional_violations) > 0:
        return MetaComparisonResult(status=STATUS_INVALID, better=(), worse=(), equivalent=(),
                                    reason_codes=(f"CONSTITUTIONAL_VIOLATIONS:{constitutional_violations}",))
    if int(production_regressions) > 0 and candidate.get("production_regression_rate", 0.0) > baseline.get(
            "production_regression_rate", 0.0):
        return MetaComparisonResult(
            status=STATUS_INVALID, better=(), worse=(), equivalent=(),
            reason_codes=("FORBIDDEN_REGRESSION:production_regression_rate",))
    available = [metric for metric, _direction, _forbidden in GENERATOR_METRICS
                 if metric in baseline and metric in candidate]
    if len(available) < int(minimum_evidence):
        return MetaComparisonResult(status=STATUS_INSUFFICIENT, better=(), worse=(), equivalent=(),
                                    reason_codes=(f"INSUFFICIENT_METRIC_COVERAGE:{len(available)}",))
    thresholds = dict(minimum_deltas or {})
    better, worse, equivalent = [], [], []
    for metric, direction, _forbidden in GENERATOR_METRICS:
        if metric not in available:
            continue
        delta = float(candidate[metric]) - float(baseline[metric])
        improvement = delta if direction == HIGHER_BETTER else -delta
        threshold = float(thresholds.get(metric, 0.0))
        if improvement > threshold:
            better.append(metric)
        elif improvement < -threshold:
            worse.append(metric)
        else:
            equivalent.append(metric)
    if better and not worse:
        status = STATUS_DOMINATES
    elif worse and not better:
        status = STATUS_DOMINATED
    elif better and worse:
        status = STATUS_INCOMPARABLE
    else:
        status = STATUS_EQUIVALENT
    return MetaComparisonResult(status=status, better=tuple(sorted(better)), worse=tuple(sorted(worse)),
                                equivalent=tuple(sorted(equivalent)),
                                reason_codes=(f"BETTER:{','.join(sorted(better)) or 'none'}",
                                              f"WORSE:{','.join(sorted(worse)) or 'none'}"))


def comparison_digest(result: MetaComparisonResult, *, baseline: Mapping[str, float],
                      candidate: Mapping[str, float]) -> str:
    return digest({"version": META_PARETO_V1, "result": result.as_dict(),
                   "baseline": dict(baseline), "candidate": dict(candidate)})
