
"""
ciph.kernel.permit_issuance - producer-side permit carriage, without becoming an authority.

S2.1 makes duplicate spendable authority impossible. This module is orphan hygiene layered on top,
and it must never weaken S2.1:

    NEW permit + KNOWN enqueue failure  ->  revoke the permit THIS attempt registered
    ALREADY_ISSUED / replay             ->  NEVER revoke; that authority belongs to a prior attempt
    AMBIGUOUS enqueue outcome           ->  NEVER revoke; the job may exist and carry this permit

The ambiguity rule is not pedantry. This sequence is real:

    permit registered -> job stored carrying the permit -> producer loses the response
    -> producer assumes failure -> revokes -> a live queued job now carries a dead permit

So there is deliberately no blanket `except Exception: revoke()`. The producer must state that
non-enqueue was established; anything else leaves the permit intact for a retry to adopt, or for TTL
to bound.

SAFETY vs CLEANLINESS
    S2.1 is safety: a second live permit for one logical action is impossible.
    S2.2 is cleanliness: a failed enqueue should not leave a registered permit behind.
    An S2.2 failure leaves an orphan; it cannot create a second live permit.
"""

from dataclasses import dataclass
from typing import Any, Optional

from ciph.kernel.permit_store import PermitIssuanceResult, PermitStoreError


class OrphanCleanupFailed(Exception):
    """
    A cleanup revoke did not take effect.

    Raised rather than returning quietly: reporting a clean state that does not exist is worse than
    an orphan, because the next reader would believe the permit was gone.
    """

    def __init__(self, permit_id: str, reason: str = ""):
        self.permit_id = permit_id
        self.reason = reason
        super().__init__(f"ORPHAN_CLEANUP_FAILED: {permit_id} ({reason})" if reason
                         else f"ORPHAN_CLEANUP_FAILED: {permit_id}")


def register_or_adopt(store, permit, job_id: Optional[str] = None) -> PermitIssuanceResult:
    """
    Register a freshly minted permit against its logical action, or adopt the canonical one.

    The returned result distinguishes the two cases the caller must treat differently:
    `registered=True` means this attempt owns the permit and may revoke it on a known failure;
    `registered=False` means canonical authority already exists and must not be touched.
    """
    return store.register(
        permit_id=permit.payload.permit_id,
        digest=permit.permit_digest(),
        issued_at=permit.payload.issued_at_us / 1_000_000,
        expires_at=permit.payload.expires_at_us / 1_000_000,
        logical_action_id=permit.payload.logical_action_id,
        action_fingerprint=permit.payload.action_fingerprint,
        authorization_generation=getattr(permit.payload, "authorization_generation", 0) or 0,
        job_id=job_id,
    )


def revoke_orphan(store, issuance: PermitIssuanceResult, reason: str = "ENQUEUE_FAILED") -> bool:
    """
    Revoke a permit this attempt freshly registered, after a KNOWN enqueue failure.

    Returns True when the orphan was revoked, False when there is nothing this attempt owns. An
    ALREADY_ISSUED or replay result is never revoked: revoking it would kill authority belonging to
    a prior job, which is exactly the accident this function exists to prevent.
    """
    if not issuance.registered:
        return False
    if not store.revoke(issuance.permit_id, reason=reason):
        raise OrphanCleanupFailed(issuance.permit_id, reason)
    return True


def handle_enqueue_failure(
    store,
    issuance: PermitIssuanceResult,
    known_rejection: bool,
    reason: str = "ENQUEUE_FAILED",
) -> bool:
    """
    The producer's failure path. `known_rejection` is the producer's explicit statement that the
    enqueue was established to have failed (rejected, rolled back) rather than merely unanswered.

    A false `known_rejection` is an ambiguous outcome: the job may exist and carry this permit, so
    nothing is revoked here.
    """
    if not known_rejection:
        return False
    return revoke_orphan(store, issuance, reason=reason)


@dataclass(frozen=True)
class PermitCarriage:
    """
    The producer's decision about which permit, if any, may be attached to a new job.

    `permit` is the CANONICAL permit to attach, and it is set only when this attempt registered it.
    A losing signed candidate is never carried: a signature is issuance proof, the store is current
    usability, and only the store's canonical row may reach the queue.
    """

    accepted: bool
    issuance: PermitIssuanceResult
    permit: Optional[Any] = None
    adopt_job_id: Optional[str] = None
    reason: str = ""


def obtain_canonical_permit(gateway, store, request, job_id: Optional[str] = None,
                             ttl_seconds: Optional[float] = None,
                             now: Optional[float] = None) -> PermitCarriage:
    """
    Mint a candidate permit centrally, canonicalise it through the store, and decide carriage.

        REGISTERED_NEW                -> carry THIS permit on the new job
        ALREADY_ISSUED + owning job   -> adopt that job; never carry the losing candidate
        ALREADY_ISSUED + no job       -> fail closed; never mint/enqueue a replacement

    The losing candidate keeps a perfectly valid signature. It is still not authority, because
    usability lives in the store, not in the signature.
    """
    # One clock reading for the horizon and the permit, so the permit can never outlive the
    # deadline it was derived from by a scheduling skew.
    candidate = gateway.issue_permit(request, now=now, ttl_seconds=ttl_seconds)
    # The producer names the owning job BEFORE registration, so the canonical row is born owning it.
    # Otherwise a retry would see ALREADY_ISSUED with no job to adopt and could only fail closed.
    issuance = register_or_adopt(store, candidate, job_id=job_id)
    if issuance.registered:
        return PermitCarriage(
            accepted=True, issuance=issuance, permit=candidate, reason="REGISTERED_NEW"
        )
    if issuance.owning_job_id:
        # Canonical authority already exists and belongs to a job. Adopt THAT job: attaching this
        # candidate to a new job would turn logical-action idempotency into "one permit, two jobs".
        return PermitCarriage(
            accepted=True,
            issuance=issuance,
            permit=None,
            adopt_job_id=issuance.owning_job_id,
            reason="ADOPT_EXISTING_JOB",
        )
    return PermitCarriage(
        accepted=False, issuance=issuance, reason="OWNING_JOB_UNAVAILABLE"
    )
