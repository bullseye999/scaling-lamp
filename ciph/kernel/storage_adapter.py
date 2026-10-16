"""
ciph.kernel.storage_adapter - translate a stored ledger record into an EvidenceRecord.

THE RULE
    The adapter may translate evidence; it may not invent authority semantics.

Precedence, highest first:

    authenticated signed receipt fields
    > denormalized storage projections
    > descriptive metadata

This module decides no credit. It produces the primitive inputs the credit computation already
consumes - a performance observation, a manifest binding, a trusted attribution and a receipt
integrity verdict - and reports projection disagreement on the projection axis, which is visible
but never blocks authority by itself. Every rule that decides spendability lives in
`manifest_credit` and `performance_metric`; restating any of them here would create a second
authority law.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from ciph.kernel.manifest_credit import (
    EvidenceRecord,
    IncidentAxis,
    IncidentScope,
    IntegrityIncident,
    ReceiptIntegrity,
    attribution_from_signed_capability_id,
)
from ciph.kernel.manifest_identity import classify_manifest_binding
from ciph.kernel.performance_metric import (
    CertaintyProvenance,
    classify_certainty_provenance,
    observe_execution_success,
    observe_legacy_execution_outcome,
)
from ciph.workers.receipts import ExecutionReceipt


# The denormalized columns the projection must reproduce. A disagreement is surfaced on the
# projection axis and never obeyed: only the authenticated receipt decides authority.
_PROJECTED_FIELDS = (
    ("capability", lambda r: str(r.capability)),
    ("receipt_id", lambda r: str(r.receipt_id)),
    ("outcome", lambda r: r.outcome.value if hasattr(r.outcome, "value") else str(r.outcome)),
    ("exit_code", lambda r: int(r.exit_code)),
    ("output_hash", lambda r: str(r.output_hash)),
)

@dataclass(frozen=True)
class ReceiptVerificationResult:
    """
    The trust layer's verdict on one receipt, carrying the context it was reached under.

    The adapter consumes this; it never decides it. `trust_snapshot_ref` and `evidence_time` record
    *which* trust context produced the verdict - a key that was unknown, a retirement window, a
    historical key state - so a VERIFIED result can answer "verified under what" instead of
    collapsing into a bare boolean. Which rules apply is trust policy, and trust policy belongs to
    the caller that owns the ledger's key history, not to a translation function.
    """

    integrity: ReceiptIntegrity
    reason: str = ""
    trust_snapshot_ref: str = ""
    evidence_time: Optional[float] = None

    @classmethod
    def verified(cls, reason="VALID", trust_snapshot_ref="", evidence_time=None):
        return cls(ReceiptIntegrity.VERIFIED, reason, trust_snapshot_ref, evidence_time)

    @classmethod
    def invalid(cls, reason, trust_snapshot_ref="", evidence_time=None):
        return cls(ReceiptIntegrity.INVALID, reason, trust_snapshot_ref, evidence_time)

    @classmethod
    def unverifiable(cls, reason, trust_snapshot_ref="", evidence_time=None):
        return cls(ReceiptIntegrity.UNVERIFIABLE, reason, trust_snapshot_ref, evidence_time)


@dataclass(frozen=True)
class StoredReceiptRecord:
    """
    The real stored shape of one ledger receipt row.

    `receipt` is the canonical signed receipt payload and is the only source of truth.
    `projection` holds the denormalized storage columns. `metadata` holds descriptive labels which
    are, by construction, never authoritative.
    """

    receipt: Dict[str, Any]
    projection: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdaptedEvidence:
    """One stored record translated into the primitive evidence shape, plus its projection axis."""

    record: EvidenceRecord
    projection_incidents: Tuple[IntegrityIncident, ...] = ()
    notes: Tuple[str, ...] = ()
    # The trust-layer verdict that admitted this record, kept so the evidence chain is not hidden
    # inside a closure. None only when the receipt could not be reconstituted at all.
    verification: Optional[ReceiptVerificationResult] = None


@dataclass(frozen=True)
class _AttributionEvidence:
    """The minimal evidence shape `attribution_from_signed_capability_id` consumes."""

    capability_id: str
    digest: str
    source_ref: str


def _projection_incidents(projection, receipt, attribution) -> Tuple[IntegrityIncident, ...]:
    incidents = []
    scope = IncidentScope.CAPABILITY if attribution else IncidentScope.LEDGER_GLOBAL
    capability = attribution.capability_id if attribution else None
    for key, canonical in _PROJECTED_FIELDS:
        if key not in projection:
            continue
        if str(projection[key]) != str(canonical(receipt)):
            incidents.append(
                IntegrityIncident(
                    reason=f"DENORMALIZED_{key.upper()}_MISMATCH",
                    scope=scope,
                    axis=IncidentAxis.PROJECTION,
                    capability=capability,
                )
            )
    return tuple(incidents)


def _reconstitution_cause(error) -> str:
    """
    The diagnostic subreason under RECEIPT_INTEGRITY_UNVERIFIABLE.

    The governance reason states the consequence; this states exactly why the receipt's own
    contract could not be reconstituted, so a parser failure is explainable without inventing a
    new top-level incident reason for every failure mode.
    """
    text = str(error)
    if "EFFECT_CERTAINTY_REQUIRED" in text:
        return "MISSING_EFFECT_CERTAINTY_FOR_SCHEMA"
    if "EFFECT_CERTAINTY_NOT_IN_SCHEMA" in text:
        return "CERTAINTY_NOT_IN_SCHEMA"
    if "UNKNOWN_EFFECT_CERTAINTY" in text:
        return "UNKNOWN_EFFECT_CERTAINTY_VALUE"
    if "Unsupported ExecutionReceipt schema_version" in text:
        return "UNSUPPORTED_SCHEMA_VERSION"
    return "RECEIPT_RECONSTITUTION_FAILED"


def adapt_stored_receipt(
    stored: StoredReceiptRecord,
    verify_signature: Callable[[ExecutionReceipt], ReceiptVerificationResult],
) -> AdaptedEvidence:
    """
    Translate one stored ledger record into an EvidenceRecord.

    `verify_signature` is the caller's integrity oracle - the ledger's trust snapshot in
    production, a keypair check in tests. It returns a `ReceiptVerificationResult`, so the caller
    owns *which* key history and timestamp rules apply while the adapter owns only translation.
    """
    payload = stored.receipt if isinstance(stored.receipt, dict) else None

    # 1. Reconstitute the canonical signed receipt. A payload whose own contract cannot be
    #    reconstituted is unverifiable evidence: no performance may be derived from it, and it is
    #    not a ledger conflict. The binding is still read from the raw provenance so the incident
    #    is scoped as far as the data honestly allows.
    try:
        receipt = ExecutionReceipt.from_dict(payload)
    except Exception as error:
        return AdaptedEvidence(
            record=EvidenceRecord(
                binding=classify_manifest_binding((payload or {}).get("provenance")),
                performance=None,
                capability_attribution=None,
                receipt_integrity=ReceiptIntegrity.UNVERIFIABLE,
                integrity_cause=_reconstitution_cause(error),
            ),
            notes=(f"UNRECONSTITUTABLE_RECEIPT:{type(error).__name__}:{error}",),
        )

    # 2. Receipt integrity, from the caller's trust context. INVALID and UNVERIFIABLE both fail
    #    closed; they differ in what they claim, not in whether the evidence may be spent. The
    #    verdict arrives structured so the trust snapshot it was reached under stays visible
    #    instead of collapsing into a boolean.
    try:
        verification = verify_signature(receipt)
        if not isinstance(verification, ReceiptVerificationResult):
            raise TypeError("VERIFIER_MUST_RETURN_A_RECEIPT_VERIFICATION_RESULT")
    except Exception as error:
        # An oracle that cannot be consulted is unverifiable, never invalid: refusing on unknown
        # integrity is recoverable, asserting contradiction is not.
        verification = ReceiptVerificationResult.unverifiable(
            f"VERIFIER_UNAVAILABLE:{type(error).__name__}"
        )
    integrity = verification.integrity
    integrity_cause = (
        None if integrity == ReceiptIntegrity.VERIFIED
        else (verification.reason or "INTEGRITY_NOT_ESTABLISHED")
    )

    binding = classify_manifest_binding(receipt.provenance or {})

    # 3. Attribution only from evidence that still verifies. An unauthenticated capability label
    #    must not be able to aim a corruption incident at a capability of its choosing.
    attribution = None
    if integrity == ReceiptIntegrity.VERIFIED:
        attribution = attribution_from_signed_capability_id(
            _AttributionEvidence(
                capability_id=receipt.capability,
                digest=receipt.terminal_identity_digest(),
                source_ref=receipt.receipt_id,
            )
        )

    # 4. Performance, only from authenticated execution facts, under the metric contract the
    #    receipt's own provenance selects. A malformed certainty provenance yields no observation
    #    rather than a fallback into the permissive lane.
    observation = None
    notes = []
    if integrity == ReceiptIntegrity.VERIFIED:
        provenance_kind = classify_certainty_provenance(
            receipt.schema_version, receipt.effect_certainty
        )
        if provenance_kind == CertaintyProvenance.STRICT:
            observation = observe_execution_success(receipt.outcome, receipt.effect_certainty)
        elif provenance_kind == CertaintyProvenance.LEGACY_OUTCOME_ONLY:
            observation = observe_legacy_execution_outcome(
                receipt.outcome, schema_version=receipt.schema_version
            )
        else:
            notes.append(f"MALFORMED_CERTAINTY_PROVENANCE:{receipt.schema_version}")

    record = EvidenceRecord(
        binding=binding,
        performance=observation,
        capability_attribution=attribution,
        receipt_integrity=integrity,
        integrity_cause=integrity_cause,
    )

    # 5. Projection disagreement is reported, never obeyed. Descriptive metadata is not consulted
    #    at all: it sits below the projection in the precedence order and can never move a score.
    return AdaptedEvidence(
        record=record,
        projection_incidents=_projection_incidents(stored.projection or {}, receipt, attribution),
        notes=tuple(notes),
        verification=verification,
    )
