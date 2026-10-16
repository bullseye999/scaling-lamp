"""
ciph.kernel.authorization_provenance - proving that an action descended from real authority.

Step 5 of the throat plan. Decisions of record: EXECUTION PERMIT V1, TARGET_IDENTITY_V1.

DON'T ASK THE RECEIPT TO PROVE ITSELF
It is not enough that a receipt *claims* descent from a permit. The verifier independently compares
receipt claims against durable records and, when the artifact is available, against the signed
permit's own contents. Otherwise a receipt could cite *a* valid permit instead of *its* permit, and
that difference is the entire point.

TWO DIFFERENT THINGS, KEPT APART
    structural descent       Receipt -> Attempt -> Permit, provable from durable records
    authorization validity   was P authorized, under grant/epoch/envelope/leases, at execution time
The first can be VALID while the second is UNVERIFIABLE_HISTORY, because the evented authority
history does not exist yet. That is an informative result, not a failure, and collapsing the two
would hide which one is missing.

THREE FACTS, THREE SOURCES
    authorization says MAY       permit store, grant history
    receipt says ATTEMPTED       execution facts
    effect evidence says HAPPENED  effect certainty
Nothing in this module may be used to infer the third from the first two.

THIS IS NOT PART OF ExecutionReceipt.verify()
Receipt integrity asks "is this receipt authentic and intact". Provenance asks "was this execution
properly authorized". Folding them together makes receipt verification responsible for signatures,
authorization, grant history, leases, targets, envelopes and effect certainty.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

STATUS_VALID = "VALID"
STATUS_INVALID = "INVALID"
STATUS_UNVERIFIABLE = "UNVERIFIABLE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

PROVENANCE_PERMIT_V1 = "EXECUTION_PERMIT_V1"
PROVENANCE_LEGACY = "LEGACY_PRE_PERMIT"
VALID_PROVENANCE_LANES = (PROVENANCE_PERMIT_V1, PROVENANCE_LEGACY)

DESCENT_VALID = "DESCENT_VALID"
DESCENT_INVALID = "DESCENT_INVALID"
DESCENT_UNVERIFIABLE = "DESCENT_UNVERIFIABLE"
DESCENT_NOT_APPLICABLE = "DESCENT_NOT_APPLICABLE"

# Explicit lanes, because NULL is not a semantic state. If absence could mean legacy, corruption or
# programmer omission, future-you has to guess, and guessing is not verification.
DENY_MISSING_LANE = "DENY_RECEIPT_MISSING_PROVENANCE_LANE"
DENY_UNKNOWN_LANE = "DENY_RECEIPT_UNKNOWN_PROVENANCE_LANE"
DENY_LEGACY_AFTER_CUTOVER = "DENY_LEGACY_PROVENANCE_AFTER_CUTOVER"
DENY_LEGACY_CARRIES_PERMIT_REFERENCE = "DENY_LEGACY_RECEIPT_CARRIES_PERMIT_REFERENCE"
DENY_MISSING_PERMIT_REFERENCE = "DENY_RECEIPT_MISSING_PERMIT_REFERENCE"
DENY_MISSING_PERMIT_DIGEST = "DENY_RECEIPT_MISSING_PERMIT_DIGEST"
DENY_MISSING_ATTEMPT_REFERENCE = "DENY_RECEIPT_MISSING_ATTEMPT_REFERENCE"
DENY_UNKNOWN_ATTEMPT = "DENY_RECEIPT_UNKNOWN_ATTEMPT"


class ReceiptContractError(Exception):
    """Raised when a governed receipt cannot legally be constructed."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class GovernedReceiptClaims:
    """
    Which authorization lineage does this receipt claim?

    Deliberately narrow. Outcome, effect certainty and error information belong to the receipt's
    other facets, not here; this object must not become a miniature receipt.

    The lane discriminates the class at construction. `EXECUTION_PERMIT_V1` *requires* its
    references and `LEGACY_PRE_PERMIT` *forbids* them, so a receipt cannot be minted as governed
    with empty lineage and left for a verifier to clean up afterwards.
    """

    authorization_provenance: str
    execution_permit_id: str = ""
    execution_permit_digest: str = ""
    execution_attempt_id: str = ""
    authorization_epoch: Optional[int] = None

    def validate_construction(
        self,
        cutover_epoch: Optional[int] = None,
        receipt_epoch: Optional[int] = None,
    ) -> None:
        """
        Construction-time gate. Verification catches forged or historical artifacts; construction
        prevents new impossible ones from existing. Two barriers, not one.
        """
        lane = self.authorization_provenance
        if not lane:
            raise ReceiptContractError(DENY_MISSING_LANE)
        if lane not in VALID_PROVENANCE_LANES:
            raise ReceiptContractError(DENY_UNKNOWN_LANE, str(lane))

        if lane == PROVENANCE_LEGACY:
            if self.execution_permit_id or self.execution_permit_digest or self.execution_attempt_id:
                raise ReceiptContractError(
                    DENY_LEGACY_CARRIES_PERMIT_REFERENCE,
                    "a pre-permit receipt cannot cite a permit it never had",
                )
            if (
                cutover_epoch is not None
                and receipt_epoch is not None
                and receipt_epoch >= cutover_epoch
            ):
                raise ReceiptContractError(
                    DENY_LEGACY_AFTER_CUTOVER,
                    f"epoch {receipt_epoch} >= cutover {cutover_epoch}",
                )
            return

        if not self.execution_permit_id:
            raise ReceiptContractError(DENY_MISSING_PERMIT_REFERENCE)
        if not self.execution_permit_digest:
            raise ReceiptContractError(DENY_MISSING_PERMIT_DIGEST)
        if not self.execution_attempt_id:
            raise ReceiptContractError(DENY_MISSING_ATTEMPT_REFERENCE)


@dataclass(frozen=True)
class ExecutionFacts:
    """
    What the receipt says happened. Identity and timing, not authorization and not outcome.

    This is the interface the real ExecutionReceipt will expose once the contract is widened; the
    verifier consumes a defined shape rather than inventing a private one.
    """

    capability: str
    execution_started_at_us: int
    execution_finished_at_us: int
    target_digest: Optional[str] = None
    logical_action_id: Optional[str] = None
    action_fingerprint: Optional[str] = None
    execution_identity: Optional[str] = None


def create_governed_claims(
    permit_store,
    execution_attempt_id: str,
    authorization_epoch: Optional[int] = None,
) -> GovernedReceiptClaims:
    """
    Derive lineage from canonical state, never from caller-supplied metadata.

    A caller can fabricate an object that looks like a PermitClaim; it cannot fabricate a row this
    store did not write. So receipt creation takes an attempt id and looks the rest up.
    """
    record = permit_store.find_by_attempt(execution_attempt_id)
    if record is None:
        raise ReceiptContractError(DENY_UNKNOWN_ATTEMPT, execution_attempt_id)

    claims = GovernedReceiptClaims(
        authorization_provenance=PROVENANCE_PERMIT_V1,
        execution_permit_id=record["permit_id"],
        execution_permit_digest=record["permit_digest"],
        execution_attempt_id=record["execution_attempt_id"],
        authorization_epoch=(
            authorization_epoch if authorization_epoch is not None
            else record.get("authorization_epoch")
        ),
    )
    claims.validate_construction()
    return claims


@dataclass(frozen=True)
class AuthorizationProvenanceResult:
    """
    A verdict reconstructible from its component evidence.

    `missing_evidence` and `contradictions` exist so UNVERIFIABLE is never a black box: it names
    which fact could not be established, and `contradictions` names which fact is provably wrong.
    """

    status: str
    descent: str
    authorization_history: str
    checks: Dict[str, str] = field(default_factory=dict)
    missing_evidence: Tuple[str, ...] = ()
    contradictions: Tuple[str, ...] = ()
    permit_result: Optional[Any] = None


class AuthorizationProvenanceVerifier:
    """Establishes Receipt -> Attempt -> Permit, then asks whether that permit was authorized."""

    def __init__(self, permit_store, authority_history=None):
        self.permit_store = permit_store
        self.authority_history = authority_history

    def verify(
        self,
        claims: GovernedReceiptClaims,
        facts: ExecutionFacts,
        permit=None,
    ) -> AuthorizationProvenanceResult:
        checks: Dict[str, str] = {}
        missing = []
        contradictions = []

        if claims.authorization_provenance == PROVENANCE_LEGACY:
            return AuthorizationProvenanceResult(
                status=STATUS_UNVERIFIABLE,
                descent=DESCENT_NOT_APPLICABLE,
                authorization_history=STATUS_UNVERIFIABLE,
                checks={"lane": PROVENANCE_LEGACY},
                missing_evidence=("permit_descent", "authorization_history"),
            )

        try:
            record = self.permit_store.describe(claims.execution_permit_id)
        except Exception:
            return AuthorizationProvenanceResult(
                status=STATUS_UNVERIFIABLE,
                descent=DESCENT_UNVERIFIABLE,
                authorization_history=STATUS_UNVERIFIABLE,
                checks={"permit_record": "ABSENT"},
                missing_evidence=("permit_record",),
            )

        stored_digest = record["permit_digest"]

        # Three values must agree: recomputed from the envelope, stored, and receipt-claimed.
        # Without the third check, a corrupted store digest could validate a receipt on its own.
        if stored_digest != claims.execution_permit_digest:
            contradictions.append("receipt_digest_mismatch")
        if permit is None:
            missing.append("permit_artifact")
        else:
            recomputed = permit.permit_digest()
            if recomputed != stored_digest:
                contradictions.append("permit_store_digest_not_recomputable")
            if recomputed != claims.execution_permit_digest:
                contradictions.append("receipt_digest_mismatch")
            if permit.payload.capability_id != facts.capability:
                contradictions.append("capability_mismatch")
            if facts.target_digest is not None and permit.payload.target_digest != facts.target_digest:
                contradictions.append("target_identity_mismatch")
            if facts.logical_action_id is not None and permit.payload.logical_action_id != facts.logical_action_id:
                contradictions.append("logical_action_mismatch")
            if facts.action_fingerprint is not None and permit.payload.action_fingerprint != facts.action_fingerprint:
                contradictions.append("action_fingerprint_mismatch")

        recorded_attempt = record.get("execution_attempt_id")
        if recorded_attempt is None:
            missing.append("recorded_attempt_identity")
        elif recorded_attempt != claims.execution_attempt_id:
            contradictions.append("attempt_identity_mismatch")
        if (
            facts.execution_identity is not None
            and record.get("claimed_by") is not None
            and facts.execution_identity != record.get("claimed_by")
        ):
            contradictions.append("execution_identity_is_not_the_claimant")

        claimed_at = record.get("claimed_at")
        started_s = facts.execution_started_at_us / 1_000_000
        finished_s = facts.execution_finished_at_us / 1_000_000
        if finished_s < started_s:
            contradictions.append("receipt_finished_before_started")
        # Compare chronology in integer microseconds, not floats. Rounding a receipt timestamp to
        # whole microseconds can land up to half a microsecond BELOW the store's float seconds,
        # which would raise a false "started before claim" for a perfectly ordered execution.
        #
        # TRANSITIONAL DEBT, not constitutional: the slack exists only because PermitStore still
        # records float seconds. When the store moves to integer microseconds end to end, this
        # becomes a plain `<` with no tolerance. Do not let the tolerance become folklore.
        if claimed_at is not None and facts.execution_started_at_us + 1 < int(round(claimed_at * 1_000_000)):
            contradictions.append("execution_started_before_claim")
        checks["temporal_ordering"] = STATUS_INVALID if contradictions else STATUS_VALID

        descent = (
            DESCENT_INVALID if contradictions
            else DESCENT_UNVERIFIABLE if "permit_artifact" in missing
            else DESCENT_VALID
        )

        permit_result = self.permit_store.valid_at(
            claims.execution_permit_id,
            started_s,
            authority_history=self.authority_history,
            execution_attempt_id=claims.execution_attempt_id,
        )
        checks["permit_local_history"] = permit_result.outcome
        missing.extend(permit_result.unverifiable)
        for reason in (permit_result.reason,):
            if reason in (
                "CLAIMED_BY_ANOTHER_ATTEMPT",
                "NOT_YET_ISSUED",
                "EXPIRED_BEFORE_MOMENT",
                "ALREADY_CONSUMED",
            ):
                contradictions.append(reason)

        if contradictions:
            status = STATUS_INVALID
        elif missing:
            status = STATUS_UNVERIFIABLE
        else:
            status = STATUS_VALID

        return AuthorizationProvenanceResult(
            status=status,
            descent=descent,
            authorization_history=permit_result.outcome,
            checks=checks,
            missing_evidence=tuple(dict.fromkeys(missing)),
            contradictions=tuple(dict.fromkeys(contradictions)),
            permit_result=permit_result,
        )
