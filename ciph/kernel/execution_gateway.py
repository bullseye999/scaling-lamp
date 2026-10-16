"""
ciph.kernel.execution_gateway - the single transition into real capability execution.

Register items 0.5 and 0.15. Decisions of record: D2, EXECUTION PERMIT V1.

ONE PERMIT MEANING
There is exactly one permit type: the signed `ExecutionPermit` issued by `ExecutionAuthority`.
Whether the consumer is in this process, in a worker subprocess, or on a federation node is
**transport**, not semantics. An earlier revision had an in-process permit object beside the signed
one; that fork was removed deliberately, and it was not bridged with a common superclass, because
abstraction over a semantic fork keeps both meanings alive. The gateway now mints and verifies the
signed artifact itself.

THE LAW
Unauthorized capability execution is impossible regardless of route. Higher layers may reject
earlier for speed or ergonomics; this is the last responsible boundary and it fails closed.

THE DESIGN CHOICE THAT MATTERS
A gateway callers must remember to use is a convention. A gateway execution cannot proceed without
is a law: `GuardedExecutor.execute` requires a permit, so a path added tomorrow that reaches the
executor directly is refused whether or not anyone remembered to list it in a test.

Route enumeration proves "every path I know today crosses the boundary".
The permit requirement proves "a path added tomorrow still cannot execute without crossing it".
"""

import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from ciph.kernel.execution_authority import (
    ExecutionAuthority,
    ExecutionPermitPayload,
    ExecutionPermitVerifier,
    SignedExecutionPermit,
)


class ExecutionDenied(Exception):
    """Boundary refusal. Carries a machine-readable reason so receipts can record it."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


DENY_UNKNOWN_CAPABILITY = "DENY_UNKNOWN_CAPABILITY"
DENY_SCOPE_REQUIRED = "DENY_SCOPE_REQUIRED"
DENY_SCOPE_EXPIRED = "DENY_SCOPE_EXPIRED"
DENY_TARGET_NOT_PERMITTED = "DENY_TARGET_NOT_PERMITTED"
DENY_SCOPE_REVOKED = "DENY_SCOPE_REVOKED"
DENY_PERMIT_MISSING = "DENY_PERMIT_MISSING"
DENY_PERMIT_UNKNOWN = "DENY_PERMIT_UNKNOWN"
DENY_PERMIT_EXPIRED = "DENY_PERMIT_EXPIRED"
DENY_PERMIT_ALREADY_USED = "DENY_PERMIT_ALREADY_USED"
DENY_REQUEST_MUTATED = "DENY_REQUEST_MUTATED"
DENY_CAPABILITY_MISMATCH = "DENY_CAPABILITY_MISMATCH"
DENY_NO_ISSUER = "DENY_NO_EXECUTION_AUTHORITY_CONFIGURED"


def canonical_digest(*parts: Any) -> str:
    """Deterministic digest over the parts of an operation that must not change after issuance."""
    digest = hashlib.sha256()
    for part in parts:
        digest.update(json.dumps(part, sort_keys=True, default=str).encode("utf-8"))
        digest.update(b"\x1f")
    return digest.hexdigest()


@dataclass(frozen=True)
class ExecutionRequest:
    """A request to execute one capability. A permit is bound to this, not to a general intent."""

    capability: str
    params: Mapping[str, Any]
    target: Optional[str] = None
    scope_grant: Any = None
    auth_grant: Any = None
    mission_id: Optional[str] = None
    authorization_envelope_id: Optional[str] = None
    logical_action_id: Optional[str] = None
    authorization_generation: int = 0
    action_fingerprint: Optional[str] = None
    lease_set_digest: Optional[str] = None
    authorization_epoch: Optional[int] = None
    network_policy: Optional[str] = None
    route: str = "UNKNOWN"
    # The replay policy the producer resolved at issuance. Carried on the REQUEST so the signed
    # permit can bind it; deliberately absent from `request_digest` and `compute_action_fingerprint`
    # - a policy change does not change WHICH action is authorized, only whether a repeat of it is.
    replay_policy_digest: Optional[str] = None

    def request_digest(self) -> str:
        return canonical_digest(self.capability, dict(self.params or {}), self.target)

    def compute_action_fingerprint(self) -> str:
        if self.action_fingerprint:
            return self.action_fingerprint
        return canonical_digest(
            self.capability,
            dict(self.params or {}),
            self.target,
            bool(self.scope_grant),
            self.authorization_envelope_id,
        )


@dataclass
class GovernedExecutionContext:
    """
    Everything a governed execution route must supply.

    Absence of this is not a legacy lane; it is a refusal. The registry hard cutover depends on
    that distinction.
    """

    gateway: "ExecutionGateway"
    permit_store: Any
    issuer: Any = None
    scope_grant: Any = None
    target: Optional[str] = None
    mission_id: Optional[str] = None
    authorization_envelope_id: Optional[str] = None
    logical_action_id: Optional[str] = None
    authorization_epoch: Optional[int] = None
    route: str = "UNKNOWN"


class ExecutionGateway:
    """
    Mints and validates signed permits. The only way into the executor.

    Deny-by-default for target-bearing work (register item 0.5): a request that names a target is
    refused unless a scope grant exists, is unexpired, and permits that target. There is no
    "no grant supplied, therefore no check" path.
    """

    def __init__(
        self,
        registry: Optional[Any] = None,
        permit_ttl_seconds: float = 30.0,
        authorization_state_provider: Optional[Callable[[SignedExecutionPermit], bool]] = None,
        issuer: Optional[ExecutionAuthority] = None,
        verifier: Optional[ExecutionPermitVerifier] = None,
    ):
        if permit_ttl_seconds <= 0:
            raise ValueError("INVALID_PERMIT_TTL")
        self.registry = registry
        self.permit_ttl_seconds = permit_ttl_seconds
        self.authorization_state_provider = authorization_state_provider
        self.issuer = issuer
        self.verifier = verifier
        self._used_nonces: set = set()
        self.denials: Dict[str, int] = {}

    # ------------------------------------------------------------------ issuance

    def issue_permit(
        self,
        request: ExecutionRequest,
        now: Optional[float] = None,
        ttl_seconds: Optional[float] = None,
    ) -> SignedExecutionPermit:
        """
        Validate authority NOW, then mint the signed permit.

        `ttl_seconds` lets a caller state the bounded horizon it actually needs - a durable queue
        resident must not be forced into an interactive dispatch window. The frozen V1 maximum is
        still enforced downstream by `ExecutionAuthority.validate_payload`, so this can shorten a
        permit but never lengthen it beyond the version's authority horizon.
        """
        if self.issuer is None:
            self._deny(DENY_NO_ISSUER, request.capability)
        moment = now if now is not None else time.time()
        self._assert_capability_known(request)
        self._assert_scope_covers_target(request, moment)

        payload = ExecutionPermitPayload.build(
            capability_id=request.capability,
            request_digest=request.request_digest(),
            action_fingerprint=request.compute_action_fingerprint(),
            issued_at_us=int(moment * 1_000_000),
            ttl_seconds=(ttl_seconds if ttl_seconds is not None else self.permit_ttl_seconds),
            target=request.target,
            scope_grant_id=getattr(request.scope_grant, "scope_id", None),
            authorization_envelope_id=request.authorization_envelope_id,
            authorization_epoch=request.authorization_epoch,
            mission_id=request.mission_id,
            logical_action_id=request.logical_action_id,
            authorization_generation=int(getattr(request, "authorization_generation", 0) or 0),
            lease_set_digest=request.lease_set_digest,
            network_policy=request.network_policy,
            replay_policy_digest=getattr(request, "replay_policy_digest", None),
        )
        return self.issuer.issue_permit(payload)

    def _record_denial(self, reason: str) -> None:
        self.denials[reason] = self.denials.get(reason, 0) + 1

    def _deny(self, reason: str, detail: str = "") -> None:
        self._record_denial(reason)
        raise ExecutionDenied(reason, detail)

    def _assert_capability_known(self, request: ExecutionRequest) -> None:
        if self.registry is None:
            return
        try:
            capability = self.registry.get(request.capability)
        except Exception:
            capability = None
        if capability is None:
            self._deny(DENY_UNKNOWN_CAPABILITY, request.capability)

    def _assert_scope_covers_target(self, request: ExecutionRequest, now: float) -> None:
        """
        Register item 0.5. A target-bearing request without a covering scope grant is refused.
        The old behaviour consulted the grant only when one was present, which failed open.
        """
        if request.target is None:
            return

        grant = request.scope_grant
        if grant is None:
            self._deny(DENY_SCOPE_REQUIRED, f"target '{request.target}' with no scope grant")

        is_expired = getattr(grant, "is_expired", None)
        if callable(is_expired) and is_expired(now):
            self._deny(DENY_SCOPE_EXPIRED, str(getattr(grant, "scope_id", "")))

        permits = getattr(grant, "is_target_permitted", None)
        if not callable(permits):
            self._deny(DENY_SCOPE_REQUIRED, "scope grant cannot evaluate targets")
        if not permits(request.target):
            self._deny(
                DENY_TARGET_NOT_PERMITTED,
                f"'{request.target}' outside {getattr(grant, 'scope_id', '')}",
            )

    # ----------------------------------------------------------------- validation

    def authorize(
        self,
        permit: Optional[SignedExecutionPermit],
        request: ExecutionRequest,
        now: Optional[float] = None,
    ) -> SignedExecutionPermit:
        """
        Validate a signed permit against the exact request it will execute. Raises ExecutionDenied.

        This is what the executor calls. There is no path to execution that skips it.
        """
        if permit is None:
            self._deny(DENY_PERMIT_MISSING, request.capability)

        if self.verifier is None:
            self._deny(DENY_NO_ISSUER, "no permit verifier configured")
        try:
            self.verifier.verify(permit, now=now)
        except Exception as error:
            reason = getattr(error, "reason", None) or DENY_PERMIT_UNKNOWN
            self._deny(reason, str(getattr(error, "detail", "")))

        if permit.payload.nonce in self._used_nonces:
            self._deny(DENY_PERMIT_ALREADY_USED, permit.payload.permit_id)
        if permit.payload.capability_id != request.capability:
            self._deny(
                DENY_CAPABILITY_MISMATCH,
                f"permit for '{permit.payload.capability_id}', request for '{request.capability}'",
            )
        if permit.payload.request_digest != request.request_digest():
            self._deny(DENY_REQUEST_MUTATED, permit.payload.permit_id)
        if self.authorization_state_provider is not None:
            if not self.authorization_state_provider(permit):
                self._deny(DENY_SCOPE_REVOKED, permit.payload.permit_id)

        self._used_nonces.add(permit.payload.nonce)
        return permit


class GovernedPreExecutionRefusal(Exception):
    """
    A recognized governance denial that arrived BEFORE the claim transition.

    Only `GuardedExecutor` may raise this, because only `GuardedExecutor` knows where the claim
    boundary is. After the claim, an exception - even one of the same type - is a POST-claim
    failure: authority has been spent and execution uncertainty exists, so reconciliation semantics
    apply rather than a clean refusal.

    Carries the gateway's machine-readable reason verbatim so nothing is flattened into a generic
    "authorization failed".
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"GOVERNED_PRE_EXECUTION_REFUSAL:{reason}")


@dataclass(frozen=True)
class ClaimBinding:
    """
    The minimum attribution every post-claim event carries.

    Installed by `GuardedExecutor` immediately after the claim, before any enrichment or capability
    body runs, so "which attempt produced this evidence" is answerable even when enrichment throws or
    the body explodes. It grants nothing; it only names the attempt.
    """

    execution_attempt_id: str
    permit_id: str
    permit_digest: str
    authorization_generation: int = 0
    logical_action_id: Optional[str] = None


class ClaimBindingSlot:
    """
    A mutable holder supplied by the caller so the binding survives into its failure handlers.

    `GuardedExecutor` deliberately does not mutate the caller's context mapping, so the caller hands
    in a slot and reads `slot.binding` afterwards - including on the exception path.
    """

    __slots__ = ("binding",)

    def __init__(self):
        self.binding: Optional[ClaimBinding] = None


class GuardedExecutor:
    """
    The only sanctioned way to run a capability body.

    Claim-before-execute: the permit is claimed atomically *before* the body runs, so a crash
    mid-execution leaves CLAIMED with no receipt, which is the reconciliation signal.
    """

    def __init__(self, gateway: ExecutionGateway, permit_store: Optional[Any] = None):
        self.gateway = gateway
        self.permit_store = permit_store
        self.executions = 0

    def execute(
        self,
        request: ExecutionRequest,
        capability: Any,
        context: Optional[Any] = None,
        permit: Optional[SignedExecutionPermit] = None,
        claimant: Optional[str] = None,
        provenance_builder: Optional[Callable[[Any], Any]] = None,
    ) -> Any:
        """
        Authorize, claim, then run. Returns (result, claim).

        `provenance_builder` exists because `execution_attempt_id` does not exist until the
        claim succeeds. The executor stays generic - it does not know what governed
        provenance means - and simply invokes the builder with the claim, then hands the
        completed provenance to the capability. That keeps the temporal ordering visible in
        the types: pre-claim authority plus the claim produces the complete block, which the
        receipt is then built from.

        The caller's context mapping is not mutated; the capability receives a copy carrying
        the completed provenance.

        If the builder raises, the permit is already CLAIMED and stays that way: the attempt
        owns the permit and never executed, which is a reconciliation case rather than a
        silent success.
        """
        # The slot is validated BEFORE authorization: a reused slot whose binding already names a
        # previous execution must never be read as this execution's attribution. Refusing here means
        # a pre-claim refusal cannot leave a stale binding looking current.
        slot = (context or {}).get("claim_binding_slot")
        if isinstance(slot, ClaimBindingSlot) and slot.binding is not None:
            raise RuntimeError(
                "CLAIM_BINDING_SLOT_ALREADY_ASSIGNED: a binding slot is single-assignment per "
                "execution; pass a fresh slot"
            )

        # The translation site is physically ABOVE the claim, which is what makes the phase
        # distinction structural rather than a property of who currently raises what.
        try:
            self.gateway.authorize(permit, request)
        except ExecutionDenied as denied:
            raise GovernedPreExecutionRefusal(denied.reason) from denied
        claim = None
        if self.permit_store is not None and permit is not None:
            claim = self.permit_store.claim(
                permit.payload.permit_id,
                claimant or request.route,
                digest=permit.permit_digest(),
            )

        # Install the minimum attribution BEFORE enrichment or the body runs, so a post-claim
        # failure is always attributable even if either of them throws.
        if claim is not None and permit is not None:
            binding = ClaimBinding(
                execution_attempt_id=claim.execution_attempt_id,
                permit_id=permit.payload.permit_id,
                permit_digest=permit.permit_digest(),
                authorization_generation=int(getattr(permit.payload, "authorization_generation", 0) or 0),
                logical_action_id=permit.payload.logical_action_id,
            )
            slot = (context or {}).get("claim_binding_slot")
            if isinstance(slot, ClaimBindingSlot):
                slot.binding = binding

        execution_context = context
        if provenance_builder is not None and claim is not None:
            completed_provenance = provenance_builder(claim)
            execution_context = dict(context or {})
            execution_context["provenance"] = completed_provenance

        self.executions += 1
        result = capability.execute(request.params, execution_context)
        return result, claim

    def terminalize(
        self,
        permit: SignedExecutionPermit,
        claim: Any,
        receipt_factory,
        receipt_sink,
        existing_terminal_lookup: Optional[Callable[[str], Any]] = None,
        receipt_identity: Optional[Callable[[Any], str]] = None,
    ) -> Any:
        """
        Persist terminal evidence FIRST, then consume the permit.

        If the receipt cannot be made durable the permit stays CLAIMED, and the attempt is a
        reconciliation case rather than a silent success. Raw return does not justify CONSUMED;
        durable terminal evidence does.

        Idempotent with respect to the same attempt: recovery may call this again after a crash
        between persistence and consumption. The same terminal receipt advances CLAIMED to
        CONSUMED. A *different* terminal receipt for the same attempt is an integrity incident,
        never last-writer-wins.
        """
        # Terminal identity, not byte-total equality. Two receipts for the same attempt that
        # differ only in observational metadata describe the same terminal fact; comparing the
        # whole signed payload would make recovery depend on recreating the environment exactly.
        # Receipt *integrity* remains byte-strict and immutable - that is a different question.
        identity = receipt_identity or (
            lambda r: (
                r.terminal_identity_digest()
                if hasattr(r, "terminal_identity_digest")
                else r.compute_signature_payload()
                if hasattr(r, "compute_signature_payload")
                else json.dumps(r, sort_keys=True, default=str)
            )
        )

        if existing_terminal_lookup is not None and claim is not None:
            existing = existing_terminal_lookup(claim.execution_attempt_id)
            if existing is not None:
                expected = receipt_factory(claim)
                if identity(existing) != identity(expected):
                    raise TerminalIntegrityIncident(
                        claim.execution_attempt_id,
                        "a different terminal receipt already exists for this attempt",
                    )
                if self.permit_store is not None:
                    state = self.permit_store.state_of(permit.payload.permit_id)
                    if state == "CLAIMED":
                        self.permit_store.consume(
                            permit.payload.permit_id, claim.claimant
                        )
                return existing

        receipt = receipt_factory(claim)
        receipt_sink(receipt)
        if self.permit_store is not None and claim is not None:
            self.permit_store.consume(permit.payload.permit_id, claim.claimant)
        return receipt


class TerminalIntegrityIncident(Exception):
    """Two divergent terminal receipts claim the same execution attempt."""

    def __init__(self, execution_attempt_id: str, detail: str = ""):
        self.execution_attempt_id = execution_attempt_id
        self.detail = detail
        super().__init__(f"TERMINAL_INTEGRITY_INCIDENT: {execution_attempt_id} {detail}")
