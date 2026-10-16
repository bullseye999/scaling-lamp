"""
ciph.kernel.performance_metric - what empirical performance means, versioned.

Decision of record: **D12 - EMPIRICAL PERFORMANCE SEMANTICS.**

Performance is an optional, versioned observation derived only from resolved execution evidence.
The absence of an observation means "this record is not eligible to say anything about empirical
performance". It does **not** mean failure.

THE RULE THAT MATTERS
    Only resolved evidence may move empirical performance.
    Uncertainty does not count against performance.

This mirrors the separation the architecture already makes between `ExecutionOutcome` (did the
machinery succeed) and `EffectCertainty` (what happened to reality). A process reporting success
while the external effect remains unknown must not become `1.0` - that would turn "the command
returned cleanly" into "the capability succeeded in the world" - and must not become `0.0` either.
It is simply not yet eligible.

POLICY_BLOCKED IS NOT A FAILURE
Scoring refusals as failures would make stronger governance appear to reduce capability
performance: more safety refusals, worse empirical credit. A blocked action produced no
capability-performance trial at all.

VERSIONED SO HISTORY IS STABLE
V1 is deliberately narrow: resolved execution success. If the semantics change - a partial success
scoring 0.5, or a richer effectiveness metric - that is `EXECUTION_SUCCESS_V2` or a separate metric
id, never an edit to V1. Evidence commits to the metric that produced its observation, so changing
an adapter cannot silently reinterpret historical credit.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence, Tuple

from ciph.contracts.enums import (
    EFFECT_CERTAINTY_CUTOVER_SCHEMA,
    EffectCertainty,
    parse_schema_version,
)

EXECUTION_SUCCESS_METRIC_ID = "EXECUTION_SUCCESS"
EXECUTION_SUCCESS_METRIC_VERSION = 1
EXECUTION_SUCCESS_METRIC = f"{EXECUTION_SUCCESS_METRIC_ID}_V{EXECUTION_SUCCESS_METRIC_VERSION}"

LEGACY_EXECUTION_OUTCOME_METRIC_ID = "LEGACY_EXECUTION_OUTCOME"
LEGACY_EXECUTION_OUTCOME_METRIC_VERSION = 1


class CertaintyProvenance(str, Enum):
    """How a record's certainty evidence should be interpreted."""

    STRICT = "STRICT"
    LEGACY_OUTCOME_ONLY = "LEGACY_OUTCOME_ONLY"
    MALFORMED = "MALFORMED"


class ExclusionReason(str, Enum):
    """Why a record contributes no performance observation."""

    POLICY_BLOCKED = "POLICY_BLOCKED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    EFFECT_UNKNOWN = "EFFECT_UNKNOWN"
    UNRESOLVED = "UNRESOLVED"
    CANCELLED = "CANCELLED"
    NOT_ADJUDICATED = "NOT_ADJUDICATED"


@dataclass(frozen=True)
class PerformanceObservation:
    """
    A versioned statement about empirical performance, or an explicit exclusion.

    `score is None` means excluded, and `exclusion_reason` says why. The two are never conflated
    with a zero score, which is a resolved negative result.
    """

    metric_id: str = EXECUTION_SUCCESS_METRIC_ID
    metric_version: int = EXECUTION_SUCCESS_METRIC_VERSION
    score: Optional[float] = None
    exclusion_reason: Optional[ExclusionReason] = None

    @property
    def eligible(self) -> bool:
        return self.score is not None

    @property
    def metric_ref(self) -> "MetricRef":
        # The measurement contract this observation was produced under, as an identity object.
        # Eligibility compares this against the query metric, so an observation can never be
        # silently attributed to a metric other than the one that produced it.
        return MetricRef(metric_id=self.metric_id, metric_version=self.metric_version)


def _value(item) -> str:
    """Accept either an enum or a plain string, so callers are not forced to import enums."""
    return str(getattr(item, "value", item) or "").upper()


SUCCESS_OUTCOMES = frozenset({"SUCCESS"})
FAILURE_OUTCOMES = frozenset({
    "EXECUTION_ERROR",
    "TARGET_UNREACHABLE",
    "DEPENDENCY_FAILURE",
    "RESOURCE_EXHAUSTED",
    "SANDBOX_VIOLATION",
    "PARTIAL_SUCCESS",
})
CONFIRMED_EFFECTS = frozenset({"EFFECT_CONFIRMED"})
NO_EFFECT_EFFECTS = frozenset({"NO_EFFECT_CONFIRMED"})


class UnsupportedMetricVersion(Exception):
    """
    A credit query selected a metric version this build cannot evaluate.

    Raised rather than falling back to the newest available semantics. If it fell back, a future V2
    would silently rescore V1 authority history the moment the adapter changed - the metric version
    would be visible in the data and meaningless in practice.
    """


@dataclass(frozen=True)
class MetricRef:
    """
    An explicit metric selection, pinned by the credit query rather than chosen by the adapter.

    Raw evidence stays canonical and derived observations stay reproducible projections, so a query
    must state which scoring semantics it is asking for. A newer metric version never automatically
    replaces the version previously used for authoritative credit.
    """

    metric_id: str
    metric_version: int

    @property
    def name(self) -> str:
        return f"{self.metric_id}_V{self.metric_version}"


EXECUTION_SUCCESS_V1 = MetricRef(
    metric_id=EXECUTION_SUCCESS_METRIC_ID,
    metric_version=EXECUTION_SUCCESS_METRIC_VERSION,
)

SUPPORTED_METRIC_REFS = (EXECUTION_SUCCESS_V1,)

# The legacy lane is resolvable but NOT equivalent: it scores on outcome alone, is usable only
# for demonstrably pre-cutover records, and never satisfies an EXECUTION_SUCCESS_V1 query.
LEGACY_EXECUTION_OUTCOME_V1 = MetricRef(
    metric_id=LEGACY_EXECUTION_OUTCOME_METRIC_ID,
    metric_version=LEGACY_EXECUTION_OUTCOME_METRIC_VERSION,
)

HISTORICAL_METRIC_REFS = (LEGACY_EXECUTION_OUTCOME_V1,)


def resolve_metric_ref(metric_ref: "MetricRef") -> "MetricRef":
    """Refuse an unsupported selection instead of substituting the newest semantics."""
    if metric_ref not in SUPPORTED_METRIC_REFS:
        raise UnsupportedMetricVersion(
            f"UNSUPPORTED_METRIC_VERSION: {getattr(metric_ref, 'name', metric_ref)}"
        )
    return metric_ref


def split_performance_population(entries):
    """
    Separate the performance population from the integrity axis.

    `entries` is a sequence of (observation, is_integrity_incident). Integrity incidents are *not*
    part of the performance population at all, so they never appear in `excluded_observations` -
    otherwise "excluded = 61" would blend sixty legitimate non-trials with one malformed record and
    weaken what the statistic means. Corrupt evidence lives only on the integrity axis.
    """
    performance = []
    integrity_incidents = 0
    for observation, is_integrity_incident in entries:
        if is_integrity_incident:
            integrity_incidents += 1
            continue
        performance.append(observation)
    return performance, integrity_incidents


def observe_execution_success(
    outcome,
    effect_certainty=None,
    metric_ref: MetricRef = EXECUTION_SUCCESS_V1,
) -> PerformanceObservation:
    """
    Derive the V1 observation for one execution record.

    Exclusion is checked before scoring, because a policy-blocked or unresolved record is not a
    performance trial regardless of what the machinery reported.
    """
    # Explicit selection, never "whatever the adapter currently knows".
    resolve_metric_ref(metric_ref)
    outcome_value = _value(outcome)
    certainty = _value(effect_certainty) if effect_certainty is not None else ""

    if outcome_value == "POLICY_BLOCKED":
        return PerformanceObservation(exclusion_reason=ExclusionReason.POLICY_BLOCKED)
    if outcome_value == "RECONCILIATION_REQUIRED":
        return PerformanceObservation(exclusion_reason=ExclusionReason.RECONCILIATION_REQUIRED)
    if outcome_value == "CANCELLED":
        return PerformanceObservation(exclusion_reason=ExclusionReason.CANCELLED)
    if outcome_value == "TIMEOUT" or certainty == "EFFECT_UNKNOWN":
        # The machinery may even have reported failure, but an unknown effect is unresolved rather
        # than adjudicated, in either direction.
        return PerformanceObservation(exclusion_reason=ExclusionReason.EFFECT_UNKNOWN)

    if certainty and certainty not in CONFIRMED_EFFECTS | NO_EFFECT_EFFECTS:
        return PerformanceObservation(exclusion_reason=ExclusionReason.UNRESOLVED)

    if outcome_value in SUCCESS_OUTCOMES:
        # STRICT. Absence of a certainty claim is not a claim of confirmed effect, so an
        # outcome-only SUCCESS must never be upgraded into "reality changed as intended".
        # This condition previously read `or not certainty`, which silently awarded 1.0 to
        # every receipt predating the certainty field - the exact overclaim D12 exists to stop.
        if certainty == EffectCertainty.EFFECT_CONFIRMED.value:
            return PerformanceObservation(score=1.0)
        return PerformanceObservation(exclusion_reason=ExclusionReason.UNRESOLVED)

    if outcome_value in FAILURE_OUTCOMES:
        if certainty in ("", "EFFECT_CONFIRMED", "NO_EFFECT_CONFIRMED"):
            return PerformanceObservation(score=0.0)
        return PerformanceObservation(exclusion_reason=ExclusionReason.UNRESOLVED)

    return PerformanceObservation(exclusion_reason=ExclusionReason.NOT_ADJUDICATED)


def classify_certainty_provenance(schema_version, effect_certainty=None):
    """
    Decide how a record's certainty evidence may be interpreted.

    Provenance-based, never based on field absence alone. Defining legacy as "certainty is
    missing" would let a malformed new receipt omit the field and downgrade itself into the
    permissive lane - the same laundering shape as LEGACY_PRE_PERMIT.

        pre-cutover  + certainty absent  -> LEGACY_OUTCOME_ONLY, interpretation permitted
        post-cutover + certainty present -> STRICT
        post-cutover + certainty absent  -> MALFORMED, never legacy
    """
    version = parse_schema_version(schema_version)
    cutover = parse_schema_version(EFFECT_CERTAINTY_CUTOVER_SCHEMA)
    if version is None or cutover is None:
        return CertaintyProvenance.MALFORMED

    pre_cutover = version < cutover
    has_certainty = effect_certainty not in (None, "")

    if has_certainty:
        return CertaintyProvenance.STRICT
    return (
        CertaintyProvenance.LEGACY_OUTCOME_ONLY
        if pre_cutover
        else CertaintyProvenance.MALFORMED
    )


def observe_legacy_execution_outcome(outcome, schema_version=None):
    """
    The historical-only lane: score on outcome alone, and say so in the metric identity.

    An old receipt may truthfully say "under the outcome-only metric this was a success". It
    may never be read as "the real-world effect was confirmed". Refuses post-cutover records
    outright, so this cannot become a downgrade path for malformed new evidence.
    """
    if schema_version is not None:
        provenance = classify_certainty_provenance(schema_version, None)
        if provenance != CertaintyProvenance.LEGACY_OUTCOME_ONLY:
            raise ValueError(
                f"LEGACY_LANE_NOT_PERMITTED_FOR_PROVENANCE: {provenance.value}"
            )
    outcome_value = _value(outcome)
    if outcome_value in SUCCESS_OUTCOMES:
        return PerformanceObservation(
            metric_id=LEGACY_EXECUTION_OUTCOME_METRIC_ID,
            metric_version=LEGACY_EXECUTION_OUTCOME_METRIC_VERSION,
            score=1.0,
        )
    if outcome_value in FAILURE_OUTCOMES:
        return PerformanceObservation(
            metric_id=LEGACY_EXECUTION_OUTCOME_METRIC_ID,
            metric_version=LEGACY_EXECUTION_OUTCOME_METRIC_VERSION,
            score=0.0,
        )
    return PerformanceObservation(
        metric_id=LEGACY_EXECUTION_OUTCOME_METRIC_ID,
        metric_version=LEGACY_EXECUTION_OUTCOME_METRIC_VERSION,
        exclusion_reason=ExclusionReason.NOT_ADJUDICATED,
    )


@dataclass(frozen=True)
class SuccessRateAggregate:
    """
    The aggregate, carrying the metric identity it was computed under.

    Deliberately named for what it is. A generic `mean_performance` would invite later readers to
    imagine it includes latency, quality or partial outcomes. It does not: V1 is a resolved
    execution-success rate over eligible observations only.
    """

    metric: str
    resolved_success_rate: Optional[float]
    eligible_observations: int
    excluded_observations: int
    excluded_by_reason: Tuple[Tuple[str, int], ...]


def aggregate_success_rate(
    observations: Sequence[PerformanceObservation],
) -> SuccessRateAggregate:
    scores: List[float] = []
    excluded: List[str] = []
    for observation in observations:
        if observation.score is None:
            excluded.append(
                (observation.exclusion_reason or ExclusionReason.NOT_ADJUDICATED).value
            )
        else:
            scores.append(observation.score)

    counts: dict = {}
    for reason in excluded:
        counts[reason] = counts.get(reason, 0) + 1

    return SuccessRateAggregate(
        metric=EXECUTION_SUCCESS_METRIC,
        resolved_success_rate=(sum(scores) / len(scores)) if scores else None,
        eligible_observations=len(scores),
        excluded_observations=len(excluded),
        excluded_by_reason=tuple(sorted(counts.items())),
    )
