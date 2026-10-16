from __future__ import annotations
"""
ciph.kernel.manifest_credit - empirical credit belongs to an exact manifest identity.

Decision of record: D11, MANIFEST_HASH_V2.

THREE DIFFERENT THINGS THAT MUST NEVER LOOK ALIKE
    no current evidence                     -> UNVERIFIED            (I do not know enough yet)
    current evidence, integrity incident    -> INTEGRITY_BLOCKED     (the evidence system is unwell)
    clean current evidence                  -> VERIFIED

CORRUPT IS NOT BAD EVIDENCE. It contributes nothing in either direction: it is not evidence about
performance at all, it is evidence about the integrity of the evidence system. A corrupt record
therefore cannot lower a score, and it cannot be quietly averaged away. It is surfaced as an
incident and it blocks authority use even when the otherwise-usable evidence looks strong.

THE AUTHORITY PATH IS STRUCTURALLY LINEAGE-BLIND
`compute_current_credit` is not given a lineage object. It cannot walk ancestry because it has no
ancestry to walk. That is stronger than a rule telling callers not to: the fallback shape
`if current_credit is insufficient: maybe use predecessor_credit` cannot be written against this
signature.

Lineage answers "where did this come from". It is exposed through a different type, so feeding it to
policy code is a shape error rather than a memory test.
"""

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

from ciph.kernel.performance_metric import (
    EXECUTION_SUCCESS_V1,
    MetricRef,
    PerformanceObservation,
    resolve_metric_ref,
)
from ciph.kernel.manifest_identity import (
    ManifestBinding,
    ManifestBindingResult,
    ManifestIdentity,
)


class CreditStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    INTEGRITY_BLOCKED = "INTEGRITY_BLOCKED"


class AttributionSource(str, Enum):
    """
    Where a capability attribution came from.

    The CAPABILITY scope is only safe if the attribution is *independent of the corrupt
    evidence*. A capability name read out of the same malformed blob would let corruption be
    attributed to a harmless capability, or aimed at a critical one. So attribution carries
    its provenance, and only an independent boundary can produce a CAPABILITY-scoped
    incident.
    """

    LEDGER_PARTITION = "LEDGER_PARTITION"
    SIGNED_CAPABILITY_ID = "SIGNED_CAPABILITY_ID"
    EXECUTION_RECORD = "EXECUTION_RECORD"


_ISSUED_BY_EVIDENCE = object()


@dataclass(frozen=True)
class TrustedCapabilityAttribution:
    """
    A capability association derived from verified independent evidence.

    `source` alone would only be a *claim* about where the attribution came from, so this object
    cannot be built from one. Construction requires the module-private issuance token, which only
    the evidence-derived factories below hold - so fabricating an attribution with
    `(capability_id, source)` is not a supported shape.

    Python privacy is not absolute. The point is that fabrication becomes structurally abnormal
    rather than a one-line convenience, and that every attribution carries the evidence it came
    from so an incident can explain *why* that capability was trusted as the attribution.

    `capability_id` is the stable capability identifier, not a display label. `ManifestIdentity`
    continues to identify the exact semantic version; this identifies the evidence family when the
    exact generation cannot safely be determined.
    """

    capability_id: str
    source_type: "AttributionSource"
    source_ref: str
    source_digest: str
    _issued_by: object = field(repr=False, compare=False, default=None)

    def __post_init__(self):
        if self._issued_by is not _ISSUED_BY_EVIDENCE:
            raise ValueError(
                "CAPABILITY_ATTRIBUTION_MUST_BE_EVIDENCE_DERIVED: construct through "
                "attribution_from_ledger_partition / attribution_from_signed_capability_id / "
                "attribution_from_execution_record"
            )
        if not isinstance(self.capability_id, str) or not self.capability_id.strip():
            raise ValueError("CAPABILITY_ATTRIBUTION_REQUIRES_A_CAPABILITY_ID")
        if not isinstance(self.source_type, AttributionSource):
            raise ValueError("CAPABILITY_ATTRIBUTION_REQUIRES_AN_ATTRIBUTION_SOURCE")
        if not self.source_ref or not self.source_digest:
            raise ValueError(
                "CAPABILITY_ATTRIBUTION_REQUIRES_EVIDENCE_REFERENCE_AND_DIGEST"
            )


def _attribution_from_evidence(evidence, source_type):
    """
    Shared derivation. The evidence object must expose a stable capability id and a digest; without
    both, nothing is issued and the caller must fall back to unattributable (global) treatment.
    """
    capability_id = getattr(evidence, "capability_id", None)
    source_digest = getattr(evidence, "digest", None)
    source_ref = getattr(evidence, "source_ref", None) or getattr(evidence, "record_id", None)
    if not capability_id or not source_digest:
        raise ValueError(
            "ATTRIBUTION_EVIDENCE_INSUFFICIENT: capability_id and digest are both required"
        )
    return TrustedCapabilityAttribution(
        capability_id=capability_id,
        source_type=source_type,
        source_ref=source_ref or f"{source_type.value}:{capability_id}",
        source_digest=source_digest,
        _issued_by=_ISSUED_BY_EVIDENCE,
    )


def attribution_from_ledger_partition(partition_record) -> "TrustedCapabilityAttribution":
    """Attribution from the ledger partition the evidence was stored under."""
    return _attribution_from_evidence(partition_record, AttributionSource.LEDGER_PARTITION)


def attribution_from_signed_capability_id(verified_receipt) -> "TrustedCapabilityAttribution":
    """Attribution from a capability id whose signature still verifies."""
    return _attribution_from_evidence(verified_receipt, AttributionSource.SIGNED_CAPABILITY_ID)


def attribution_from_execution_record(canonical_record) -> "TrustedCapabilityAttribution":
    """Attribution from a canonical execution record outside the malformed provenance."""
    return _attribution_from_evidence(canonical_record, AttributionSource.EXECUTION_RECORD)


class IncidentScope(str, Enum):
    """
    Whose integrity a corrupt record contaminates.

    Without this, corruption is either discarded for being unattributable, or treated as globally
    poisoning every capability. A malformed identity in a receipt for capability X cannot be
    attributed to an exact manifest identity - but X is still a trustworthy outer association, so it
    contaminates X's evidence partition and nothing else.
    """

    EXACT_MANIFEST = "EXACT_MANIFEST"
    CAPABILITY = "CAPABILITY"
    LEDGER_GLOBAL = "LEDGER_GLOBAL"


class IncidentAxis(str, Enum):
    """
    Which trust domain an incident belongs to. Load-bearing, because the axes differ in what they
    are permitted to disable.

    EVIDENCE    canonical evidence contradicts or cannot establish its integrity contract
                -> blocks authority
    RETRIEVAL   the evidence *selection* cannot be trusted, so the set may be incomplete
                -> blocks authority, because you no longer know what was omitted
    PROJECTION  a derived cache/index disagrees with canonical evidence
                -> surfaced, but does NOT block authority

    That last one protects the hierarchy. Canonical signed evidence is authority; projections and
    checkpoints are disposable. If every mismatch blocked authority, a stale cache could deny
    credit even though canonical evidence is perfectly intact - quietly inverting
    "projection disagrees with authority" into "projection disables authority".
    """

    EVIDENCE = "EVIDENCE"
    RETRIEVAL = "RETRIEVAL"
    PROJECTION = "PROJECTION"


@dataclass(frozen=True)
class IntegrityIncident:
    reason: str
    scope: IncidentScope
    axis: IncidentAxis = IncidentAxis.EVIDENCE
    capability: Optional[str] = None
    manifest_identity: Optional[ManifestIdentity] = None
    # Diagnostic subreason under the governance reason. The top-level reason states the
    # consequence ("integrity could not be established"); the cause states exactly why. Kept
    # separate so diagnostic detail never becomes part of the authority taxonomy.
    cause: Optional[str] = None


class EvidenceVerdict(str, Enum):
    """How one evidence record relates to a queried identity."""

    CURRENT = "CURRENT"
    HISTORICAL_VERSION_MISMATCH = "HISTORICAL_VERSION_MISMATCH"
    HISTORICAL_UNBOUND = "HISTORICAL_UNBOUND"
    INTEGRITY_INCIDENT = "INTEGRITY_INCIDENT"


class ReceiptIntegrity(str, Enum):
    """
    Can the execution facts in this record be trusted at all?

    Distinct from attribution. An unauthenticated receipt's `SUCCESS` is not an authenticated
    execution fact, so performance must not be derived from it - the supposedly authoritative fields
    are authoritative only when their containing evidence passes its integrity contract.
    """

    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True)
class EvidenceRecord:
    """One piece of evidence, with the identity its binding claims."""

    binding: ManifestBindingResult
    # The performance observation, carrying the metric contract that produced it. A bare float
    # loses *which* measurement contract the number belongs to, so a strict query could silently
    # aggregate observations taken under a weaker one.
    performance: Optional[PerformanceObservation] = None
    # The outer association that says whose integrity this record belongs to when its identity
    # cannot be trusted. Optional because not every source can attribute it, and deliberately a
    # trust-carrying object rather than a bare string.
    capability_attribution: Optional[TrustedCapabilityAttribution] = None
    # Gating axis. Defaults to VERIFIED so existing construction keeps its meaning; an adapter
    # that failed to verify a signature must say so rather than defaulting into trust.
    receipt_integrity: ReceiptIntegrity = ReceiptIntegrity.VERIFIED
    # The specific reason the integrity verdict was reached when it is not VERIFIED, so the
    # integrity incident can carry a governance reason and a diagnostic cause.
    integrity_cause: Optional[str] = None


POPULATION_SUBJECT_EVIDENCE = "SUBJECT_EVIDENCE"
POPULATION_LEDGER_GLOBAL_INCIDENTS = "LEDGER_GLOBAL_INCIDENTS"

# An authoritative credit query depends on BOTH populations. Certifying only the subject's records
# would leave this hole: X's evidence is complete, a global corruption record was never examined,
# and authority wrongly remains usable. A completeness claim must therefore cover both at the same
# snapshot, or it is not a completeness claim for this query.
REQUIRED_POPULATIONS = (
    POPULATION_SUBJECT_EVIDENCE,
    POPULATION_LEDGER_GLOBAL_INCIDENTS,
)


class RetrievalIntegrity(str, Enum):
    """
    Can the *set* of canonical evidence received be trusted for a query?

    Absence of a detected retrieval problem must not be read as trustworthiness. A retrieval path
    that silently omits two failing records leaves every returned record perfectly VERIFIED, with a
    clean identity and a clean projection - and the credit is falsely perfect. So authoritative
    credit needs a **positive** basis for completeness, not merely the absence of evidence against
    it.

        VERIFIED_COMPLETE   a positive completeness basis exists for this exact query scope
        UNTRUSTWORTHY       a known contradiction or omission; retrieval is corrupt
        UNVERIFIABLE        completeness cannot currently be established

    The last two both fail closed and are different claims: one asserts corruption, the other
    declines to assert completeness.
    """

    VERIFIED_COMPLETE = "VERIFIED_COMPLETE"
    UNTRUSTWORTHY = "UNTRUSTWORTHY"
    UNVERIFIABLE = "UNVERIFIABLE"


_ISSUED_AS_COMPLETE = object()


@dataclass(frozen=True)
class RetrievalAssessment:
    """
    A scoped completeness claim, not a verdict that "retrieval looks okay".

    It states: for this subject, under this metric, through this snapshot, this is the complete
    relevant canonical evidence population - and names the evidence the claim rests on.

    **Positive completeness is evidence-derived.** `VERIFIED_COMPLETE` cannot be asserted by
    ordinary code, because otherwise the hole simply moves up a layer:

        no retrieval incident detected -> trusted
        caller says VERIFIED_COMPLETE  -> trusted

    The second is the same bug wearing a better name. Only the `assessment_from_*` factories that
    hold the issuance token can produce a complete assessment. `UNTRUSTWORTHY` and `UNVERIFIABLE`
    are deliberately easier to construct, because both fail closed - the dangerous credential is
    the positive one.

    **Scope is part of the claim.** A completeness proof for (subject, metric, snapshot) must not
    authorize a query under a different metric or a later snapshot; `covers` is the check.
    """

    capability_id: str
    manifest_identity: ManifestIdentity
    metric_ref: MetricRef
    snapshot_ref: str
    retrieval_integrity: RetrievalIntegrity
    source_ref: str
    source_digest: str
    certified_populations: Tuple[str, ...] = ()
    _issued: object = field(repr=False, compare=False, default=None)

    def __post_init__(self):
        if not self.capability_id:
            raise ValueError("RETRIEVAL_ASSESSMENT_REQUIRES_A_CAPABILITY_ID")
        if not isinstance(self.manifest_identity, ManifestIdentity):
            raise ValueError("RETRIEVAL_ASSESSMENT_REQUIRES_A_MANIFEST_IDENTITY")
        if not isinstance(self.metric_ref, MetricRef):
            raise ValueError("RETRIEVAL_ASSESSMENT_REQUIRES_A_METRIC_REF")
        if not isinstance(self.retrieval_integrity, RetrievalIntegrity):
            raise ValueError("RETRIEVAL_ASSESSMENT_REQUIRES_AN_INTEGRITY_STATE")
        if not self.snapshot_ref:
            raise ValueError("RETRIEVAL_ASSESSMENT_REQUIRES_A_SNAPSHOT_REF")
        if not self.source_ref or not self.source_digest:
            raise ValueError("RETRIEVAL_ASSESSMENT_REQUIRES_EVIDENCE_PROVENANCE")
        if (
            self.retrieval_integrity == RetrievalIntegrity.VERIFIED_COMPLETE
            and self._issued is not _ISSUED_AS_COMPLETE
        ):
            raise ValueError(
                "VERIFIED_COMPLETE_MUST_BE_EVIDENCE_DERIVED: construct through "
                "assessment_from_complete_partition_scan"
            )
        if self.retrieval_integrity == RetrievalIntegrity.VERIFIED_COMPLETE:
            missing = [
                name for name in REQUIRED_POPULATIONS
                if name not in set(self.certified_populations)
            ]
            if missing:
                raise ValueError(
                    "COMPLETENESS_MUST_COVER_SUBJECT_AND_GLOBAL_POPULATIONS: missing "
                    f"{missing}"
                )

    @property
    def authorizes_credit(self) -> bool:
        return self.retrieval_integrity == RetrievalIntegrity.VERIFIED_COMPLETE

    def covers(self, subject, metric_ref, snapshot_ref) -> bool:
        """Scope check: a completeness claim is for one subject, metric and snapshot."""
        return (
            self.capability_id == subject.capability_id
            and self.manifest_identity == subject.manifest_identity
            and self.metric_ref == metric_ref
            and self.snapshot_ref == snapshot_ref
        )


    def covers_query(self, query: CreditQuery) -> bool:
        """Does this completeness proof cover that proposition?"""
        return self.covers(query.subject, query.metric_ref, query.snapshot_ref)


def assessment_from_complete_partition_scan(
    subject,
    metric_ref,
    snapshot_ref,
    source_ref,
    source_digest,
    certified_populations=REQUIRED_POPULATIONS,
) -> RetrievalAssessment:
    """
    A positive completeness claim from a complete canonical scan of the subject's partition.

    Boring on purpose: a fixed snapshot boundary plus every qualifying record examined. The point
    is not the mechanism but that the claim exists and names what it rests on.
    """
    if not source_ref or not source_digest:
        raise ValueError("COMPLETENESS_CLAIM_REQUIRES_EVIDENCE")
    return RetrievalAssessment(
        capability_id=subject.capability_id,
        manifest_identity=subject.manifest_identity,
        metric_ref=metric_ref,
        snapshot_ref=snapshot_ref,
        retrieval_integrity=RetrievalIntegrity.VERIFIED_COMPLETE,
        source_ref=source_ref,
        source_digest=source_digest,
        certified_populations=tuple(certified_populations),
        _issued=_ISSUED_AS_COMPLETE,
    )


def _assessment_failing_closed(
    query, metric_ref, snapshot_ref, source_ref, state, source_digest="not-established"
):
    """UNTRUSTWORTHY and UNVERIFIABLE are constructible, because both fail closed."""
    # Accept a CreditQuery as well as a bare subject: retrieval scope is a property of the
    # proposition, so the negative witnesses are naturally expressed against a query.
    resolved_subject = getattr(query, "subject", query)
    return RetrievalAssessment(
        capability_id=resolved_subject.capability_id,
        manifest_identity=resolved_subject.manifest_identity,
        metric_ref=metric_ref,
        snapshot_ref=snapshot_ref,
        retrieval_integrity=state,
        source_ref=source_ref,
        source_digest=source_digest,
    )


def assessment_untrustworthy(subject, metric_ref, snapshot_ref, source_ref) -> RetrievalAssessment:
    """A known contradiction or omission was detected."""
    return _assessment_failing_closed(
        subject, metric_ref, snapshot_ref, source_ref, RetrievalIntegrity.UNTRUSTWORTHY
    )


def assessment_unverifiable(subject, metric_ref, snapshot_ref, source_ref) -> RetrievalAssessment:
    """No positive completeness basis exists, and no contradiction either."""
    return _assessment_failing_closed(
        subject, metric_ref, snapshot_ref, source_ref, RetrievalIntegrity.UNVERIFIABLE
    )


@dataclass(frozen=True)
class CurrentCreditResult:
    """
    Authoritative credit for one exact identity.

    Deliberately not shaped like lineage history, so the two cannot be substituted for each other.
    """

    manifest_identity: ManifestIdentity
    status: CreditStatus
    usable_evidence_count: int
    excluded_historical_count: int
    integrity_incidents: Tuple[str, ...] = ()
    # Projection health is reported on its own axis and never blocks: a stale cache may
    # disagree with canonical evidence, but disagreement cannot redefine authority.
    projection_incidents: Tuple[str, ...] = ()
    retrieval_integrity: Optional[RetrievalIntegrity] = None
    mean_performance: Optional[float] = None
    authority_usable: bool = False
    # Metric-eligibility accounting, deliberately separate from integrity. Evidence under a
    # different measurement contract is valid history, not corruption; a same-metric exclusion
    # (e.g. EFFECT_UNKNOWN) is a different statement again from "a different metric".
    metric_ref: Optional[MetricRef] = None
    semantic_excluded_count: int = 0
    different_metric_excluded_count: int = 0
    unobserved_count: int = 0


@dataclass(frozen=True)
class AncestorEntry:
    identity: ManifestIdentity
    reason: str


@dataclass(frozen=True)
class LineageCreditHistory:
    """
    Context about where an identity came from. **Contains no spendable credit field on purpose.**

    There is no `credit`, no `status`, no `authority_usable`. A policy function written for
    `CurrentCreditResult` simply does not accept this object.
    """

    current_identity: ManifestIdentity
    ancestor_entries: Tuple[AncestorEntry, ...] = ()
    transitions: Tuple[str, ...] = ()
    note: str = "NON_AUTHORITATIVE_CONTEXT"


@dataclass(frozen=True)
class CreditSubject:
    """
    The canonical pairing of a capability and the exact identity being queried.

    The primitive legitimately needs both: `CAPABILITY(X)` incidents have to be scoped somehow. But
    the *ledger* must not accept two independently supplied identifiers, because a caller could then
    query `H2 + Y` while `H2` actually belongs to `X` - and X's capability-scoped corruption would
    vanish from the result. That is an authority bypass created purely by the integration layer.

    So the pair is derived from canonical state through `from_manifest`, which takes the identity
    from the resolved manifest object rather than from a caller. Same rule as everywhere else:
    caller metadata may describe authority; it may not define it.
    """

    capability_id: str
    manifest_identity: ManifestIdentity

    def __post_init__(self):
        if not isinstance(self.capability_id, str) or not self.capability_id.strip():
            raise ValueError("CREDIT_SUBJECT_REQUIRES_A_CAPABILITY_ID")
        if not isinstance(self.manifest_identity, ManifestIdentity):
            raise ValueError("CREDIT_SUBJECT_REQUIRES_A_MANIFEST_IDENTITY")

    @classmethod
    def from_manifest(cls, capability_id: str, manifest) -> "CreditSubject":
        """Derive the pairing from the resolved manifest, never from a supplied identity."""
        if manifest is None or not hasattr(manifest, "identity"):
            raise ValueError("CREDIT_SUBJECT_REQUIRES_A_MANIFEST_WITH_IDENTITY")
        return cls(capability_id=capability_id, manifest_identity=manifest.identity())


@dataclass(frozen=True)
class CreditQuery:
    """The full authority proposition: subject, metric and snapshot."""

    subject: CreditSubject
    metric_ref: MetricRef
    snapshot_ref: str

    def __post_init__(self):
        if not isinstance(self.subject, CreditSubject):
            raise ValueError("CREDIT_QUERY_REQUIRES_A_CREDIT_SUBJECT")
        if not isinstance(self.metric_ref, MetricRef):
            raise ValueError("CREDIT_QUERY_REQUIRES_A_METRIC_REF")
        if not self.snapshot_ref:
            raise ValueError("CREDIT_QUERY_REQUIRES_A_SNAPSHOT_REF")


def select_evidence_for_subject(
    subject: CreditSubject,
    all_evidence: Sequence[EvidenceRecord],
) -> List[EvidenceRecord]:
    """
    The production load model.

    A corrupt record with no trustworthy attribution is LEDGER_GLOBAL, so by definition it belongs
    to no capability partition. If the ledger filtered by capability before collecting incidents,
    the exact evidence meant to block every partition would disappear. So the selection is the union
    of the subject's exact and capability-scoped evidence **plus every unattributable record**.
    """
    selected: List[EvidenceRecord] = []
    for record in all_evidence:
        attribution = record.capability_attribution
        if attribution is None:
            # Ledger-global by construction: never filtered out, or the global rule is vacuous in
            # the real retrieval path.
            selected.append(record)
            continue
        if attribution.capability_id == subject.capability_id:
            selected.append(record)
            continue
        if record.binding.identity == subject.manifest_identity:
            selected.append(record)
    return selected


def compute_subject_credit(
    query: CreditQuery,
    all_evidence: Sequence[EvidenceRecord],
    retrieval_assessment: Optional[RetrievalAssessment] = None,
    projection_incidents: Sequence[IntegrityIncident] = (),
) -> CurrentCreditResult:
    """Authority composition: scoring plus retrieval completeness.

    The scorer below stays retrieval-blind and lineage-blind; this seam decides authority.
    None can never authorize - absence of a completeness proof is not evidence of completeness.
    """
    subject = query.subject
    # Authority credit is only issuable under a currently-supported metric contract. A query
    # pinned to a historical metric (e.g. the outcome-only legacy lane) is a different proposition
    # and must not produce spendable authority - otherwise the weaker lane becomes a downgrade
    # path: pin the query to the permissive metric and spend the result.
    resolve_metric_ref(query.metric_ref)
    result = compute_current_credit(
        subject.manifest_identity,
        select_evidence_for_subject(subject, all_evidence),
        queried_capability=subject.capability_id,
        projection_incidents=projection_incidents,
        metric_ref=query.metric_ref,
    )

    if retrieval_assessment is None:
        state = RetrievalIntegrity.UNVERIFIABLE
        reason = "NO_COMPLETENESS_EVIDENCE"
    elif not retrieval_assessment.covers_query(query):
        # Not reinterpreted: it remains a valid proof for its own query.
        state = RetrievalIntegrity.UNVERIFIABLE
        reason = "ASSESSMENT_SCOPE_MISMATCH"
    else:
        state = retrieval_assessment.retrieval_integrity
        reason = (
            None if state == RetrievalIntegrity.VERIFIED_COMPLETE
            else "RETRIEVAL_" + state.value
        )

    if state == RetrievalIntegrity.VERIFIED_COMPLETE:
        return replace(result, retrieval_integrity=state)

    incident = IntegrityIncident(
        reason=reason,
        scope=IncidentScope.LEDGER_GLOBAL,
        axis=IncidentAxis.RETRIEVAL,
    )
    return replace(
        result,
        integrity_incidents=result.integrity_incidents + (incident,),
        retrieval_integrity=state,
        status=(
            CreditStatus.INTEGRITY_BLOCKED
            if result.usable_evidence_count
            else CreditStatus.UNVERIFIED
        ),
        authority_usable=False,
    )

def classify_evidence(
    record: EvidenceRecord,
    queried_identity: ManifestIdentity,
) -> EvidenceVerdict:
    """
    The mechanical rule. No lineage, no "best related manifest", no predecessor fallback.
    """
    # Receipt integrity is checked first, and **both** non-VERIFIED states fail closed:
    # without authenticated execution facts no performance observation may be derived from
    # them regardless of binding. INVALID and UNVERIFIABLE are treated identically for
    # spendability, because both are non-spendable, and differently for what they claim.
    if record.receipt_integrity != ReceiptIntegrity.VERIFIED:
        return EvidenceVerdict.INTEGRITY_INCIDENT
    binding = record.binding
    if binding.binding == ManifestBinding.CORRUPT:
        return EvidenceVerdict.INTEGRITY_INCIDENT
    if binding.binding == ManifestBinding.VERSIONED:
        if binding.identity == queried_identity:
            return EvidenceVerdict.CURRENT
        return EvidenceVerdict.HISTORICAL_VERSION_MISMATCH
    return EvidenceVerdict.HISTORICAL_UNBOUND


def _scope_incident(
    record: EvidenceRecord,
    queried_identity: ManifestIdentity,
    queried_capability: Optional[str],
) -> Optional[IntegrityIncident]:
    """
    Decide whose integrity this corrupt record contaminates, or None when it is not ours.

    Conservative in one direction only: an unattributable corrupt record is treated as global and
    blocks, because refusing on unknown corruption is recoverable while ignoring it is not.
    """
    # Distinct statements: evidence that contradicts its integrity contract is a different
    # claim from evidence whose integrity cannot currently be established. Missing historical
    # verification material is not the same finding as a failed signature.
    if record.receipt_integrity == ReceiptIntegrity.INVALID:
        reason = "RECEIPT_INTEGRITY_FAILURE"
    elif record.receipt_integrity == ReceiptIntegrity.UNVERIFIABLE:
        reason = "RECEIPT_INTEGRITY_UNVERIFIABLE"
    else:
        reason = record.binding.reason or "CORRUPT_EVIDENCE"
    cause = record.integrity_cause
    attribution = record.capability_attribution
    if attribution is None:
        # Nothing independent can attribute this, so it is conservatively global.
        return IntegrityIncident(
            reason=reason, scope=IncidentScope.LEDGER_GLOBAL, cause=cause
        )
    if queried_capability is not None and attribution.capability_id != queried_capability:
        return None
    return IntegrityIncident(
        reason=reason,
        scope=IncidentScope.CAPABILITY,
        capability=attribution.capability_id,
        cause=cause,
    )


def compute_current_credit(
    queried_identity: ManifestIdentity,
    evidence: Sequence[EvidenceRecord],
    queried_capability: Optional[str] = None,
    projection_incidents: Sequence[IntegrityIncident] = (),
    metric_ref: MetricRef = EXECUTION_SUCCESS_V1,
) -> CurrentCreditResult:
    """
    Credit for exactly this identity.

    Note the signature: no lineage, no predecessor history, no policy hook. Structural blindness
    rather than a documented promise.
    """
    if not isinstance(queried_identity, ManifestIdentity):
        raise TypeError("QUERIED_IDENTITY_MUST_BE_A_MANIFEST_IDENTITY")

    usable: List[float] = []
    excluded = 0
    incidents: List[IntegrityIncident] = []
    semantic_excluded = 0
    different_metric = 0
    unobserved = 0

    for record in evidence:
        verdict = classify_evidence(record, queried_identity)
        if verdict == EvidenceVerdict.CURRENT:
            observation = record.performance
            if observation is None:
                # Trusted binding, but no performance statement at all. Not eligible, and not an
                # exclusion *by this metric* - there is simply nothing to score.
                unobserved += 1
            elif observation.metric_ref != metric_ref:
                # Valid empirical evidence under a different measurement contract. Preserved and
                # visible, but never borrowed by a stricter aggregate.
                different_metric += 1
            elif observation.score is None:
                # Same metric, explicitly excluded (e.g. EFFECT_UNKNOWN): a statement about this
                # metric that is neither a zero score nor a different metric.
                semantic_excluded += 1
            else:
                usable.append(float(observation.score))
        elif verdict == EvidenceVerdict.INTEGRITY_INCIDENT:
            # Contributes nothing in either direction; surfaced, and blocking *within its scope*.
            incident = _scope_incident(record, queried_identity, queried_capability)
            if incident is not None:
                incidents.append(incident)
            else:
                # Attributable to a different capability: not this partition's problem, but still
                # not usable evidence here.
                excluded += 1
        else:
            excluded += 1

    # Retrieval corruption is an authority problem, not a projection one: if evidence
    # selection cannot be trusted, the set may be incomplete and you no longer know what was
    # omitted. A wrong projection value is recoverable when canonical evidence is
    # independently recoverable; compromised selection is not.
    if not usable:
        status = CreditStatus.UNVERIFIED
    elif incidents:
        status = CreditStatus.INTEGRITY_BLOCKED
    else:
        status = CreditStatus.VERIFIED

    return CurrentCreditResult(
        manifest_identity=queried_identity,
        status=status,
        usable_evidence_count=len(usable),
        excluded_historical_count=excluded,
        integrity_incidents=tuple(incidents),
        projection_incidents=tuple(projection_incidents),
        mean_performance=(sum(usable) / len(usable)) if usable else None,
        authority_usable=bool(usable) and not incidents,
        metric_ref=metric_ref,
        semantic_excluded_count=semantic_excluded,
        different_metric_excluded_count=different_metric,
        unobserved_count=unobserved,
    )
