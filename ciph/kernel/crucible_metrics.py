"""
ciph/kernel/crucible_metrics - 4.5 Gate Three: was the candidate actually better?

There is deliberately no single `fitness` number. A candidate is compared as a VECTOR over the metrics
the protocol froze, and the outcome is a PARTIAL ORDER (D5):

    DOMINATES | DOMINATED | INCOMPARABLE | EQUIVALENT | INSUFFICIENT_EVIDENCE | INVALID

Hard constitutional invariants are not dimensions: they are gates. A candidate that bypassed authority,
fabricated evidence or mutated history is INVALID however fast it was.
"""

import math
import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.crucible_protocols import EvaluationProtocol, MetricDefinition
from ciph.kernel.crucible_types import (
    CRUCIBLE_METRICS_V1,
    CRUCIBLE_PARETO_V1,
    CrucibleError,
    DIRECTION_HIGHER_BETTER,
    digest,
)

STATUS_DOMINATES = "DOMINATES"
STATUS_DOMINATED = "DOMINATED"
STATUS_INCOMPARABLE = "INCOMPARABLE"
STATUS_EQUIVALENT = "EQUIVALENT"
STATUS_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
STATUS_INVALID = "INVALID"
VALID_COMPARISON_STATUSES = (STATUS_DOMINATES, STATUS_DOMINATED, STATUS_INCOMPARABLE,
                             STATUS_EQUIVALENT, STATUS_INSUFFICIENT, STATUS_INVALID)

# 95% normal quantile, used for the noise band. Fixed, not tunable.
Z_95 = 1.959963984540054


@dataclass(frozen=True)
class PerformanceVector:
    """The measured performance of ONE subject under ONE protocol. Samples, not a verdict."""

    subject_id: str
    protocol_id: str
    samples: Mapping[str, Tuple[float, ...]]
    hard_violations: Mapping[str, int] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"subject_id": self.subject_id, "protocol_id": self.protocol_id,
                "samples": {key: list(value) for key, value in sorted(self.samples.items())},
                "hard_violations": {key: int(value)
                                    for key, value in sorted(self.hard_violations.items())}}


@dataclass(frozen=True)
class MetricSummary:
    metric_id: str
    n: int
    mean: Optional[float]
    median: Optional[float]
    variance: Optional[float]
    ci_low: Optional[float]
    ci_high: Optional[float]
    failures: int

    def as_dict(self) -> Dict[str, Any]:
        return {"metric_id": self.metric_id, "n": self.n, "mean": self.mean,
                "median": self.median, "variance": self.variance, "ci_low": self.ci_low,
                "ci_high": self.ci_high, "failures": self.failures}


@dataclass(frozen=True)
class ComparisonResult:
    status: str
    metric_id_deltas: Mapping[str, Optional[float]]
    better: Tuple[str, ...]
    worse: Tuple[str, ...]
    equivalent: Tuple[str, ...]
    reason_codes: Tuple[str, ...]
    metric_version: str = CRUCIBLE_METRICS_V1
    pareto_version: str = CRUCIBLE_PARETO_V1
    basis_digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"status": self.status,
                "metric_id_deltas": {key: self.metric_id_deltas[key]
                                     for key in sorted(self.metric_id_deltas,
                                                       key=lambda item: str(item))},
                "better": list(self.better), "worse": list(self.worse),
                "equivalent": list(self.equivalent), "reason_codes": list(self.reason_codes),
                "metric_version": self.metric_version, "pareto_version": self.pareto_version,
                "basis_digest": self.basis_digest}


def summarise(vector: PerformanceVector, protocol: EvaluationProtocol) -> Dict[str, MetricSummary]:
    out: Dict[str, MetricSummary] = {}
    for metric in protocol.metric_definitions:
        values = [float(value) for value in vector.samples.get(metric.metric_id, ())]
        n = len(values)
        if n == 0:
            out[metric.metric_id] = MetricSummary(metric.metric_id, 0, None, None, None, None, None, 0)
            continue
        mean = statistics.fmean(values)
        variance = statistics.variance(values) if n > 1 else 0.0
        half = Z_95 * math.sqrt(variance / n) if n > 1 else 0.0
        out[metric.metric_id] = MetricSummary(
            metric_id=metric.metric_id, n=n, mean=mean, median=statistics.median(values),
            variance=variance, ci_low=mean - half, ci_high=mean + half, failures=0)
    return out


def _noise_band(baseline: MetricSummary, candidate: MetricSummary, metric: MetricDefinition) -> float:
    """How large a difference is indistinguishable from noise, given the declared tolerance."""
    band = float(metric.tolerance or 0.0)
    if baseline.n > 1 and candidate.n > 1:
        pooled = math.sqrt((baseline.variance or 0.0) / baseline.n
                           + (candidate.variance or 0.0) / candidate.n)
        band = max(band, Z_95 * pooled)
    return band


def compare(baseline: PerformanceVector, candidate: PerformanceVector,
            protocol: EvaluationProtocol) -> ComparisonResult:
    """
    THE frozen comparison (CRUCIBLE_PARETO_V1).

    Partial order, never a scalar. A metric counts as better or worse only when the difference clears
    BOTH the protocol's minimum meaningful delta and the noise band, so a 0.001 win inside a wide
    distribution is EQUIVALENT evidence, not victory.
    """
    if baseline.protocol_id != candidate.protocol_id or baseline.protocol_id != protocol.protocol_id:
        raise CrucibleError("CROSS_PROTOCOL_COMPARISON", 'a result is only meaningful under its own '
                                                         'frozen protocol')
    reasons: List[str] = []
    for subject, vector in (('baseline', baseline), ('candidate', candidate)):
        for invariant, count in (vector.hard_violations or {}).items():
            if int(count) > 0:
                reasons.append(f"HARD_INVARIANT_VIOLATION:{subject}:{invariant}")
    if reasons:
        # No amount of performance compensates for a constitutional violation.
        return ComparisonResult(status=STATUS_INVALID, metric_id_deltas={}, better=(), worse=(),
                                equivalent=(), reason_codes=tuple(reasons),
                                basis_digest=digest({"b": baseline.as_dict(),
                                                     "c": candidate.as_dict()}))

    base_summary = summarise(baseline, protocol)
    cand_summary = summarise(candidate, protocol)
    for metric in protocol.metric_definitions:
        for summary in (base_summary[metric.metric_id], cand_summary[metric.metric_id]):
            if summary.n < protocol.minimum_evidence:
                reasons.append(f"INSUFFICIENT_SAMPLES:{metric.metric_id}:{summary.n}"
                               f"<{protocol.minimum_evidence}")
    if reasons:
        return ComparisonResult(status=STATUS_INSUFFICIENT, metric_id_deltas={}, better=(), worse=(),
                                equivalent=(), reason_codes=tuple(reasons),
                                basis_digest=digest({"b": baseline.as_dict(),
                                                     "c": candidate.as_dict()}))

    deltas: Dict[str, Optional[float]] = {}
    better: List[str] = []
    worse: List[str] = []
    equivalent: List[str] = []
    for metric in protocol.metric_definitions:
        base = base_summary[metric.metric_id]
        cand = cand_summary[metric.metric_id]
        raw = float(cand.mean) - float(base.mean)
        improvement = raw if metric.direction == DIRECTION_HIGHER_BETTER else -raw
        deltas[metric.metric_id] = improvement
        threshold = max(float(metric.minimum_meaningful_delta or 0.0),
                        _noise_band(base, cand, metric))
        if improvement > threshold:
            better.append(metric.metric_id)
        elif improvement < -threshold:
            worse.append(metric.metric_id)
        else:
            equivalent.append(metric.metric_id)

    if better and not worse:
        status = STATUS_DOMINATES
    elif worse and not better:
        status = STATUS_DOMINATED
    elif better and worse:
        status = STATUS_INCOMPARABLE
    else:
        # Nothing moved beyond its threshold. That is EQUIVALENT only if the measurement was precise
        # enough to mean it: a noise band wider than the protocol's minimum meaningful delta means the
        # evidence cannot tell the two apart at all, which is INSUFFICIENT_EVIDENCE.
        imprecise = [metric.metric_id for metric in protocol.metric_definitions
                     if _noise_band(base_summary[metric.metric_id],
                                    cand_summary[metric.metric_id], metric)
                     > float(metric.minimum_meaningful_delta or 0.0)]
        if imprecise:
            reasons.append("IMPRECISE_MEASUREMENT:" + ",".join(sorted(imprecise)))
            return ComparisonResult(
                status=STATUS_INSUFFICIENT, metric_id_deltas=deltas, better=tuple(sorted(better)),
                worse=tuple(sorted(worse)), equivalent=tuple(sorted(equivalent)),
                reason_codes=tuple(reasons),
                basis_digest=digest({"b": baseline.as_dict(), "c": candidate.as_dict()}))
        status = STATUS_EQUIVALENT
    reasons.append(f"BETTER:{','.join(sorted(better)) or 'none'}")
    reasons.append(f"WORSE:{','.join(sorted(worse)) or 'none'}")
    return ComparisonResult(status=status, metric_id_deltas=deltas, better=tuple(sorted(better)),
                            worse=tuple(sorted(worse)), equivalent=tuple(sorted(equivalent)),
                            reason_codes=tuple(reasons),
                            basis_digest=digest({"b": baseline.as_dict(),
                                                 "c": candidate.as_dict()}))
