
"""
ciph.kernel.retry_authority - who may advance the authorization generation, and on what evidence.

A′ says a retry keeps the same `logical_action_id` and receives a fresh single-use permit. This
module states WHEN that is legal. It is deliberately not a subsystem: four outcomes, one function.

    REDELIVER_SAME_GENERATION   authority was never spent - reuse the existing permit
    NEXT_GENERATION             authority was spent and the attempt is provably retry-safe
    RECONCILIATION_REQUIRED     authority was spent and the effect is unknown - N+1 is FORBIDDEN
    TERMINAL                    no further authority may be minted for this action

THE RULE THAT MATTERS: a failed call is not evidence that the effect failed. A claimed attempt whose
effect certainty is UNKNOWN may have changed the world, so it cannot be silently retried - the
previous generation must be settled first.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ciph.contracts.enums import ReplaySemantics
from ciph.kernel.policy_engine import replay_policy_digest


_RETRY_AUTHORIZED = object()


class RetryNotAuthorized(Exception):
    """Generation N+1 was requested without the canonical classifier agreeing."""

    def __init__(self, outcome: str):
        self.outcome = outcome
        super().__init__(f"RETRY_NOT_AUTHORIZED:{outcome}")


@dataclass(frozen=True)
class RetryAuthorization:
    """
    Proof that generation N+1 may be issued for one logical action.

    Cannot be constructed directly: only `authorize_next_generation` holds the issuance token, so
    "generation > 0" is reachable exclusively through the canonical classifier. The worker and the
    queue never hold one - they report a retry condition, the central path decides.
    """

    logical_action_id: str
    next_generation: int
    outcome: str = "NEXT_GENERATION"
    _issued: object = field(repr=False, compare=False, default=None)

    def __post_init__(self):
        if self._issued is not _RETRY_AUTHORIZED:
            raise ValueError(
                "RETRY_AUTHORIZATION_MUST_COME_FROM_THE_CANONICAL_CLASSIFIER"
            )


def authorize_next_generation(
    *,
    logical_action_id,
    previous_generation,
    permit_state,
    effect_certainty=None,
    retry_safe=False,
    attempts_remaining=0,
) -> RetryAuthorization:
    """The ONLY path to a generation > 0 issuance. Refuses unless the classifier says advance."""
    outcome = classify_retry(
        permit_state=permit_state,
        effect_certainty=effect_certainty,
        retry_safe=retry_safe,
        attempts_remaining=attempts_remaining,
    )
    if outcome is not RetryOutcome.NEXT_GENERATION:
        raise RetryNotAuthorized(outcome.value)
    return RetryAuthorization(
        logical_action_id=logical_action_id,
        next_generation=int(previous_generation or 0) + 1,
        _issued=_RETRY_AUTHORIZED,
    )


class ClaimProvenanceUnavailable(Exception):
    """A binding exists but the canonical store cannot corroborate the attempt. Fail closed."""

    def __init__(self, attempt_id: str):
        self.attempt_id = attempt_id
        super().__init__(f"CLAIM_PROVENANCE_UNAVAILABLE:{attempt_id}")


class ClaimProvenanceConflict(Exception):
    """The binding and the canonical claim disagree about the same attempt identity."""

    def __init__(self, attempt_id: str, detail: str = ""):
        self.attempt_id = attempt_id
        self.detail = detail
        super().__init__(f"CLAIM_BINDING_INTEGRITY_CONFLICT:{attempt_id}" + (f":{detail}" if detail else ""))


def canonical_claim_provenance(slot, permit_store):
    """
    The ONE governed-provenance block every post-claim handler records.

    Corroborates the kernel's binding against the canonical store by IDENTITY only. Lifecycle state
    is deliberately NOT required: a permit that has since moved CLAIMED -> CONSUMED still produced
    this attempt, and demanding the old state would make a legitimate terminal receipt look
    unattributable merely because terminalization consumed the permit.

    Returns None when there is no binding - a pre-claim path, where no attribution is expected.
    Raises when a binding exists but cannot be corroborated, so a daemon handler cannot silently
    record unattributable or contradictory evidence as if it were authoritative.
    """
    binding = getattr(slot, "binding", None)
    if binding is None:
        return None

    row = permit_store.find_by_attempt(binding.execution_attempt_id)
    if row is None:
        raise ClaimProvenanceUnavailable(binding.execution_attempt_id)

    if (str(row["permit_id"]) != str(binding.permit_id)
            or str(row["permit_digest"]) != str(binding.permit_digest)
            or int(row["authorization_generation"] or 0) != int(binding.authorization_generation or 0)):
        raise ClaimProvenanceConflict(binding.execution_attempt_id, "IDENTITY_MISMATCH")

    return {
        "authorization_provenance": "PROVENANCE_PERMIT_V1",
        "execution_permit_id": binding.permit_id,
        "execution_permit_digest": binding.permit_digest,
        "execution_attempt_id": binding.execution_attempt_id,
        "authorization_generation": int(binding.authorization_generation or 0),
        "logical_action_id": binding.logical_action_id,
    }


def derive_retry_request(
    previous_permit,
    *,
    params,
    target=None,
    scope_grant=None,
    envelope_expires_at=0.0,
    now=None,
    claim_horizon_seconds=600.0,
):
    """
    Derive generation N+1's request from generation N's canonical authority.

    A retry RENEWS authority; it never enlarges it. There is deliberately no `capability`,
    `logical_action_id`, `action_fingerprint`, mission or envelope parameter - those are carried
    from the signed permit, so a caller cannot repoint the retry at a different action, capability
    or envelope. The target is accepted only if it still matches the permit's bound target digest,
    and the horizon may only stay the same or shrink.
    """
    import time as _time

    from ciph.kernel.execution_authority import target_digest
    from ciph.kernel.execution_gateway import ExecutionRequest

    payload = previous_permit.payload
    moment = now if now is not None else _time.time()

    if target is not None and payload.target_digest:
        if target_digest(target) != payload.target_digest:
            raise ValueError("RETRY_TARGET_WIDENING_FORBIDDEN")

    original_remaining = max(0.0, (payload.expires_at_us / 1_000_000.0) - moment)
    horizon = min(float(claim_horizon_seconds), original_remaining)
    if envelope_expires_at:
        horizon = min(horizon, max(0.0, float(envelope_expires_at) - moment))
    if horizon <= 0:
        raise ValueError("RETRY_HORIZON_EXHAUSTED")

    return ExecutionRequest(
        capability=payload.capability_id,
        params=dict(params or {}),
        target=target,
        scope_grant=scope_grant,
        logical_action_id=payload.logical_action_id,
        authorization_generation=int(payload.authorization_generation or 0) + 1,
        action_fingerprint=payload.action_fingerprint,
        mission_id=payload.mission_id,
        authorization_envelope_id=payload.authorization_envelope_id,
        authorization_epoch=payload.authorization_epoch,
        lease_set_digest=payload.lease_set_digest,
        network_policy=payload.network_policy,
        # N+1 inherits generation N's binding. It is never re-read from the manifest here.
        replay_policy_digest=payload.replay_policy_digest,
        route="retry.central",
    )


REPLAY_DECLARATION_SOURCE = "CAPABILITY_REPLAY_DECLARATION"


@dataclass(frozen=True)
class RetrySafetyProof:
    """
    Proof that repeating THIS logical action cannot create an uncontrolled duplicate effect.

    It is a statement about the CAPABILITY's effect identity, re-validated against the exact
    attempt's evidence - not a verdict about the attempt itself, and not a claim that the attempt
    had no effect. That is why it can make an UNKNOWN effect retryable without inventing
    `NO_EFFECT_CONFIRMED`.
    """

    capability_id: str
    manifest_hash: str
    replay_policy_digest: Optional[str] = None
    source: str = REPLAY_DECLARATION_SOURCE


def canonical_retry_safety(*, permit, manifest, evidence):
    """
    The ONE derivation of retry safety. Returns `RetrySafetyProof` or `None` - never a boolean.

    Nothing a worker, daemon, queue row or caller says can stand in for this. It requires, together:

      * the resolved capability manifest declares IDEMPOTENT replay semantics (fail-closed default);
      * that manifest IS the capability the permit names;
      * the exact attempt's evidence attests the SAME manifest identity, so the declaration is
        proven about the code that actually ran rather than about whatever is registered now.

    Any disagreement returns None, which the classifier reads as "no independent guarantee" - the
    uncertainty path, never the retry path.
    """
    if permit is None or manifest is None or evidence is None:
        return None

    payload = getattr(permit, "payload", None)
    capability_id = getattr(payload, "capability_id", None)
    if not capability_id or getattr(manifest, "name", None) != capability_id:
        return None

    # THREE-WAY AGREEMENT over ONE immutable binding. Checking the manifest identity alone would
    # prove nothing here: `ReplaySemantics` is deliberately outside the frozen V1 manifest hash, so
    # the identity is EXACTLY the fact that does not move when the policy changes.
    #
    #   bound     what the permit was signed over at issuance         (immutable, authority)
    #   current   what the capability declares now                    (narrowing allowed, widening not)
    #   attested  what the exact attempt's evidence says it ran under (the attempt's own record)
    #
    # Requiring all three to be the same IDEMPOTENT binding closes retroactive broadening in both
    # directions: an attempt that ran UNSAFE can never become retryable because somebody edited the
    # declaration afterwards, and an attempt that ran IDEMPOTENT stops being retryable the moment the
    # declaration narrows.
    idempotent = replay_policy_digest(ReplaySemantics.IDEMPOTENT)
    bound = getattr(payload, "replay_policy_digest", None)
    if not bound or str(bound) != idempotent:
        return None
    if replay_policy_digest(manifest) != idempotent:
        return None

    expected = set()
    try:
        expected.add(str(manifest.compute_manifest_hash()))
    except Exception:
        pass
    try:
        expected.add(str(manifest.identity().manifest_hash))
    except Exception:
        pass
    if not expected:
        return None

    attested = False
    for event in getattr(evidence, "events", ()) or ():
        provenance = (event.get("payload") or {}).get("provenance")
        if not isinstance(provenance, dict):
            continue
        if str(provenance.get("manifest_hash") or "") not in expected:
            # The evidence describes a DIFFERENT manifest identity. A capability declaration may
            # never be borrowed across code, so this is not a weaker proof - it is no proof.
            return None
        if str(provenance.get("replay_policy_digest") or "") != str(bound):
            # The attempt did not run under the policy this permit bound. No proof.
            return None
        attested = True
    if not attested:
        return None

    return RetrySafetyProof(capability_id=str(capability_id),
                            manifest_hash=sorted(expected)[0],
                            replay_policy_digest=str(bound))


class RetryOutcome(str, Enum):
    REDELIVER_SAME_GENERATION = "REDELIVER_SAME_GENERATION"
    NEXT_GENERATION = "NEXT_GENERATION"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    TERMINAL = "TERMINAL"


def classify_retry(
    *,
    permit_state: str,
    effect_certainty: Optional[str] = None,
    retry_safe: bool = False,
    attempts_remaining: int = 0,
) -> RetryOutcome:
    """
    The single decision point for a retry.

    `retry_safe` is the capability's own policy plus any independent idempotency/replay guarantee:
    it may only be True when a repeated attempt cannot duplicate an effect. It never overrides an
    unknown effect on an already-claimed attempt.
    """
    state = str(permit_state).upper()

    # Authority not spent: redelivery reuses the SAME permit. No new generation.
    if state == "ISSUED":
        return RetryOutcome.REDELIVER_SAME_GENERATION

    # Spent authority: the effect question now decides everything.
    if state == "CLAIMED":
        # PRECEDENCE, frozen: an INDEPENDENT retry-safety proof (an idempotency/effect guarantee
        # that makes a repeat unconditionally safe) is the only thing that can make a claimed
        # attempt retryable, because effect certainty alone cannot resolve a possible duplicate
        # effect. Without that proof, effect certainty decides. This ordering is what makes the
        # claimed-retry branch reachable at all - unknown effect alone reconciles, never advances.
        certainty = str(effect_certainty or "").upper()
        if certainty == "EFFECT_CONFIRMED":
            # The effect happened; there is nothing to retry, whatever the policy says.
            return RetryOutcome.TERMINAL
        # The remaining cases are uncertain (UNKNOWN, no certainty recorded, or an explicitly
        # no-effect known-safe outcome). An independent retry-safety proof is what makes those
        # retryable without duplicating an effect; without it, uncertainty reconciles.
        if retry_safe:
            return (
                RetryOutcome.NEXT_GENERATION if attempts_remaining > 0 else RetryOutcome.TERMINAL
            )
        return RetryOutcome.RECONCILIATION_REQUIRED

    # CONSUMED is terminal; REVOKED/EXPIRED means the authority lapsed without being spent, so a
    # fresh generation may be authorized only if policy says the action is still retryable.
    if state in ("REVOKED", "EXPIRED"):
        if retry_safe and attempts_remaining > 0:
            return RetryOutcome.NEXT_GENERATION
        return RetryOutcome.TERMINAL

    if state == "CONSUMED":
        return RetryOutcome.TERMINAL

    return RetryOutcome.TERMINAL
