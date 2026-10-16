
"""
ciph.kernel.permit_composition - the one canonical production configuration for durable permits.

This module is COMPOSITION, not authority. It resolves persistent signing lineage and the durable
permit-store namespace, and it derives the bounded durable claim horizon. It adds no authority
policy: every decision stays inside ExecutionAuthority / ExecutionGateway / PermitStore.

Two properties it must preserve:

  PERSISTENT LINEAGE
      the same environment resolves the same execution-authority identity and the same permit-store
      namespace. Constructing another runtime does not create another execution identity.

  BOUNDED HORIZON
      a durable permit may never outlive the authority it was derived from, nor the frozen V1
      maximum lifetime. A claim horizon beyond that is REFUSED at issuance - never satisfied by
      extending the permit and never refreshed by the worker.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, runtime_checkable

from ciph.kernel.crypto_identity import Ed25519KeyManager, KeyRole, TrustRegistry
from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitVerifier
from ciph.kernel.execution_gateway import ExecutionGateway
from ciph.kernel.permit_store import ExecutionPermitStore

EXECUTION_AUTHORITY_KEY_ID = "execution_authority_primary"

# The frozen V1 maximum permit lifetime, mirrored from `ExecutionAuthority.validate_payload`. Named
# here so the durable-horizon law refuses honestly and explicitly rather than relying on the
# authority to reject the payload after a candidate has already been built.
V1_MAX_PERMIT_LIFETIME_SECONDS = 3600.0

# Lazy provisioning must be serialised. Two callers racing to create the execution-authority
# keypair for the same database will otherwise collide on the registry write ("database is locked")
# rather than converging on one lineage.
_PROVISION_LOCK = threading.Lock()


class DurableHorizonRefused(Exception):
    """The requested durable claim horizon exceeds the authority that could back it."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class DurablePermitDependencies:
    """
    Composition plumbing: the canonical objects, injected downstream.

    Deliberately method-free. It must never grow `authorize()`, `decide_scope()` or
    `mint_special_worker_permit()` - those would be a second authority surface.

    The signer is deliberately NOT public. A producer receives the gateway seam (which signs inside
    the boundary) and verification material, never a signing capability - otherwise runtime/planner
    would not construct authority objects but would still possess signing power.
    """

    gateway: ExecutionGateway
    permit_store: ExecutionPermitStore
    key_id: str = EXECUTION_AUTHORITY_KEY_ID
    _authority: Optional[ExecutionAuthority] = field(repr=False, compare=False, default=None)

    @property
    def public_key_bytes(self) -> bytes:
        """Verification material only."""
        return self._authority.public_key_bytes


def build_durable_permit_dependencies(
    db_path: str,
    trust_registry: Optional[TrustRegistry] = None,
    operator_signer=None,
) -> DurablePermitDependencies:
    """
    Resolve the canonical durable-permit configuration for one environment.

    Persistent by construction: the execution-authority keypair is resolved from (or created once
    in) the shared TrustRegistry, and the permit store is namespaced by `db_path`. A second call for
    the same environment returns the same lineage - it does not mint a new execution identity.

    Provisioning the execution-authority identity is an OPERATOR-AUTHORIZED act, exactly like
    `kernel_primary` and `worker_primary`: under a pinned root the TrustRegistry refuses an
    unsigned registration. `operator_signer` is the composition boundary's operator key; it is
    consulted only when the lineage does not yet exist.
    """
    registry = trust_registry if trust_registry is not None else TrustRegistry(db_path=db_path)
    with _PROVISION_LOCK:
        provision_signature = None
        if registry.get_keypair(EXECUTION_AUTHORITY_KEY_ID) is None:
            private_bytes, public_bytes = Ed25519KeyManager.generate_keypair()
            if operator_signer is not None:
                provision_signature = operator_signer(
                    EXECUTION_AUTHORITY_KEY_ID, KeyRole.EXECUTION_AUTHORITY.value,
                    public_bytes.hex(), None
                )
            registry.store_keypair(
                EXECUTION_AUTHORITY_KEY_ID,
                KeyRole.EXECUTION_AUTHORITY,
                private_bytes,
                public_bytes,
                operator_signature=provision_signature,
            )
        private_key, _public_key = registry.get_or_create_keypair(
            EXECUTION_AUTHORITY_KEY_ID,
            KeyRole.EXECUTION_AUTHORITY,
            operator_signature=provision_signature,
        )
    authority = ExecutionAuthority(private_key, key_id=EXECUTION_AUTHORITY_KEY_ID)
    permit_store = ExecutionPermitStore(db_path)
    gateway = ExecutionGateway(
        registry=None,
        issuer=authority,
        permit_ttl_seconds=V1_MAX_PERMIT_LIFETIME_SECONDS,
    )
    return DurablePermitDependencies(
        gateway=gateway, permit_store=permit_store, _authority=authority
    )


def durable_claim_horizon_from_deadline(
    claim_deadline: Optional[float],
    *,
    now: Optional[float] = None,
    authorization_grant_expires_at: float = 0.0,
    scope_grant_expires_at: float = 0.0,
    envelope_expires_at: float = 0.0,
) -> float:
    """
    Derive the bounded horizon from the LATEST SEMANTICALLY VALID CLAIM TIME.

    A producer states when this job may legitimately begin execution - a timing fact - rather than
    how much authority it would like. An operational forecast ("workers normally pick up in 90s")
    is not an authority boundary: under load it would turn ordinary queue latency into
    unpredictable authorization failures.
    """
    if claim_deadline is None:
        raise DurableHorizonRefused("CLAIM_DEADLINE_REQUIRED")
    moment = now if now is not None else time.time()
    remaining = float(claim_deadline) - moment
    if remaining <= 0:
        raise DurableHorizonRefused("CLAIM_DEADLINE_ALREADY_PASSED")
    return durable_claim_horizon_seconds(
        remaining,
        now=moment,
        authorization_grant_expires_at=authorization_grant_expires_at,
        scope_grant_expires_at=scope_grant_expires_at,
        envelope_expires_at=envelope_expires_at,
    )


@dataclass(frozen=True)
class DurablePermitConsumerDependencies:
    """
    The WORKER side of the same canonical configuration: verify and spend only.

    Holds no `ExecutionAuthority`, no `ExecutionGateway` and no private EXECUTION_AUTHORITY key.
    The worker verifies what the central side issued and spends it through the durable store; it has
    no ability to mint authority, which is what makes "the worker never mints permits" a property of
    the composition rather than a convention someone has to remember.
    """

    permit_store: ExecutionPermitStore
    authorizer: "PermitAuthorizer"
    verifier: ExecutionPermitVerifier
    authority_public_key: bytes
    key_id: str = EXECUTION_AUTHORITY_KEY_ID


@runtime_checkable
class PermitAuthorizer(Protocol):
    """
    The worker-facing authority seam: authorize a permit, nothing else.

    Deliberately narrower than `ExecutionGateway`. The worker's public capability set says it can
    VERIFY a permit against a request; it has no `issue_permit` at all, so "the worker cannot mint
    authority" is structural rather than a method that happens to raise.
    """

    def authorize(self, permit, request, now=None):
        ...


def build_durable_permit_consumer_dependencies(db_path, trust_registry=None):
    """
    Resolve the consumer half of the canonical configuration for one environment.

    Reads the execution-authority PUBLIC key the central side provisioned. It never provisions: a
    worker that can create the signing identity is not a consumer, so a missing identity is a hard
    error rather than something this path repairs.
    """
    registry = trust_registry if trust_registry is not None else TrustRegistry(db_path=db_path)
    record = registry.get_key(EXECUTION_AUTHORITY_KEY_ID)
    if record is None:
        raise PermissionError(
            "EXECUTION_AUTHORITY_NOT_PROVISIONED: the consumer never creates the signing identity; "
            "the central composition must provision it first."
        )
    public_key = bytes.fromhex(record["public_key_hex"])
    verifier = ExecutionPermitVerifier(public_key, key_id=EXECUTION_AUTHORITY_KEY_ID)
    # Issuer deliberately absent: this gateway instance can authorize and can never mint. The
    # worker is handed only its `authorize` capability via PermitAuthorizer, so the wider object is
    # an implementation detail of the composition rather than part of the worker's surface.
    authorizer = ExecutionGateway(registry=None, issuer=None, verifier=verifier)
    return DurablePermitConsumerDependencies(
        permit_store=ExecutionPermitStore(db_path),
        authorizer=authorizer,
        verifier=verifier,
        authority_public_key=public_key,
    )


def acquire_durable_permit(
    provider,
    request,
    job_id,
    *,
    claim_deadline: Optional[float],
    now: Optional[float] = None,
    authorization_grant_expires_at: float = 0.0,
    scope_grant_expires_at: float = 0.0,
    envelope_expires_at: float = 0.0,
):
    """
    The producer's single entry point: bound the horizon, mint centrally, canonicalise, decide.

    Fail-closed by construction. A refused deadline raises BEFORE anything is minted, so a producer
    has no permit to enqueue and no path to a token-only fallback. The permit's lifetime is the
    derived horizon, so it can only ever be shorter than the job's declared claim deadline.
    """
    moment = now if now is not None else time.time()
    horizon = durable_claim_horizon_from_deadline(
        claim_deadline,
        now=moment,
        authorization_grant_expires_at=authorization_grant_expires_at,
        scope_grant_expires_at=scope_grant_expires_at,
        envelope_expires_at=envelope_expires_at,
    )
    dependencies = provider()
    from ciph.kernel.permit_issuance import obtain_canonical_permit
    return obtain_canonical_permit(
        dependencies.gateway,
        dependencies.permit_store,
        request,
        job_id=job_id,
        ttl_seconds=horizon,
        now=moment,
    )


def durable_claim_horizon_seconds(
    requested_horizon_seconds: Optional[float],
    *,
    now: Optional[float] = None,
    authorization_grant_expires_at: float = 0.0,
    scope_grant_expires_at: float = 0.0,
    envelope_expires_at: float = 0.0,
) -> float:
    """
    The latest time at which this durable job may still obtain authority to execute.

    The value is the MINIMUM of the requested claim horizon and every authority it derives from. A
    request beyond the frozen V1 maximum is refused outright: this is the honest limit, and folding
    it into a longer-lived permit (or a worker-side refresh) would quietly invent delegated
    authority the constitution does not grant.
    """
    if requested_horizon_seconds is None or float(requested_horizon_seconds) <= 0:
        raise DurableHorizonRefused("DURABLE_HORIZON_REQUIRED")

    requested = float(requested_horizon_seconds)
    if requested > V1_MAX_PERMIT_LIFETIME_SECONDS:
        raise DurableHorizonRefused(
            "CLAIM_HORIZON_EXCEEDS_V1_MAX",
            f"{requested}s > {V1_MAX_PERMIT_LIFETIME_SECONDS}s",
        )

    moment = now if now is not None else time.time()
    horizon = requested
    for name, expiry in (
        ("authorization_grant", authorization_grant_expires_at),
        ("scope_grant", scope_grant_expires_at),
        ("authorization_envelope", envelope_expires_at),
    ):
        if expiry and float(expiry) > 0:
            horizon = min(horizon, max(0.0, float(expiry) - moment))

    if horizon <= 0:
        raise DurableHorizonRefused("DURABLE_HORIZON_EXHAUSTED")
    return horizon
