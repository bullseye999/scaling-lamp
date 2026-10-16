
"""
permit_test_support - canonical permit-bearing fixture setup.

Fixtures may bypass product UX and workflow layers; they may NOT bypass the execution constitution.

ONE constitutional pipeline, TWO adapters:

    enqueue_permit_bearing_job(runtime, ...)          runtime-backed
    enqueue_permit_bearing_queue_job(...)             queue-only (TrustRegistry + operator identity)
                     ↓ both call
    _canonical_fixture_job(...)                       the actual authority sequence

The sequence is the same one production performs: persist_and_verify the scope, build the canonical
request, let the central gateway issue, register through the canonical PermitStore (the logical
action law applies), then enqueue with that exact permit. A second adapter means "a second way to
reach the pipeline", never a second authority implementation.
"""

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from ciph.contracts.enums import ScopeType
from ciph.kernel.crypto_identity import Ed25519KeyManager
from ciph.kernel.execution_gateway import ExecutionRequest
from ciph.kernel.permit_composition import acquire_durable_permit, build_durable_permit_dependencies
from ciph.kernel.policy_engine import ScopeGrant
from ciph.kernel.scope_grant_store import ScopeGrantStore


@dataclass(frozen=True)
class FixtureJob:
    """
    Canonical handles for the authority a fixture created.

    Recovery/replay/revocation tests manipulate THESE identifiers rather than reconstructing them,
    so they act on the same authority artifact instead of accidentally minting a replacement.
    """

    job_id: str
    permit: Any
    request: ExecutionRequest
    scope_grant_id: Optional[str] = None
    execution_token: Any = None

    @property
    def permit_id(self) -> str:
        return self.permit.payload.permit_id

    @property
    def logical_action_id(self) -> Optional[str]:
        return self.permit.payload.logical_action_id


def _canonical_fixture_job(
    *,
    queue,
    permit_provider,
    scope_store,
    signer,
    signing_key_id,
    capability,
    params,
    scope_targets=None,
    scope_id=None,
    scope_type=ScopeType.LOCAL_SYSTEM,
    scope_grant=None,
    idempotency_key=None,
    execution_token=None,
    plan_id=None,
    step_id=None,
    max_retries=1,
    claim_horizon_seconds=600.0,
    replay_policy_digest=None,
    enqueue=True,
) -> FixtureJob:
    """The one authority sequence every fixture adapter must go through."""
    job_id = f"JOB-{uuid.uuid4().hex[:12].upper()}"
    if scope_grant is None and scope_targets:
        scope_grant = ScopeGrant(
            scope_id=scope_id or f"scope_fixture_{job_id}",
            scope_type=scope_type,
            allowed_targets=list(scope_targets),
        )
    if scope_grant is not None:
        if signer is not None and not getattr(scope_grant, "signature", None):
            scope_grant = scope_grant.sign(signer, signing_key_id=signing_key_id)
        scope_store.persist_and_verify(scope_grant)

    request = ExecutionRequest(
        capability=capability,
        params=dict(params or {}),
        target=(params or {}).get("target"),
        scope_grant=scope_grant,
        logical_action_id=job_id,
        route="test.support",
        replay_policy_digest=replay_policy_digest,
    )
    carriage = acquire_durable_permit(
        permit_provider, request, job_id, claim_deadline=time.time() + claim_horizon_seconds
    )
    if not carriage.accepted:
        raise AssertionError(f"fixture could not acquire canonical authority: {carriage.reason}")
    if carriage.adopt_job_id:
        raise AssertionError(
            "fixture was handed an EXISTING canonical job; a fresh fixture must use a fresh logical "
            "action rather than silently recycling authority"
        )

    if not enqueue:
        return FixtureJob(
            job_id=job_id, permit=carriage.permit, request=request,
            scope_grant_id=getattr(scope_grant, "scope_id", None),
            execution_token=execution_token,
        )

    # The queue is the authority on WHICH job exists: with an idempotency-key conflict it returns
    # the existing job's id, and a fixture that reported its own generated id would claim a job that
    # was never created.
    job_id = queue.enqueue_job(
        capability=capability,
        params=params,
        job_id=job_id,
        idempotency_key=idempotency_key or job_id,
        plan_id=plan_id,
        step_id=step_id,
        max_retries=max_retries,
        execution_token=execution_token,
        execution_permit=carriage.permit,
    )
    return FixtureJob(
        job_id=job_id,
        permit=carriage.permit,
        request=request,
        scope_grant_id=getattr(scope_grant, "scope_id", None),
        execution_token=execution_token,
    )


def enqueue_permit_bearing_job(
    runtime,
    *,
    capability,
    params,
    scope_targets=None,
    scope_id=None,
    execution_token=None,
    idempotency_key=None,
    plan_id=None,
    step_id=None,
    max_retries=1,
) -> FixtureJob:
    """
    Runtime-backed adapter: coherent artifacts by default.

    A governed job still needs its transport token, so the fixture mints one whose plan/step/params
    match the job it is about to enqueue. Token and permit stay conceptually separate - the fixture
    simply stops them diverging.
    """
    job_plan = plan_id or f"plan_fixture_{uuid.uuid4().hex[:8]}"
    job_step = step_id or "step_fixture"
    scope_grant = None
    if scope_targets:
        scope_grant = ScopeGrant(
            scope_id=scope_id or f"scope_fixture_{uuid.uuid4().hex[:8]}",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=list(scope_targets),
        ).sign(runtime.kernel_priv_bytes, signing_key_id=runtime.kernel_key_id)

    if execution_token is None:
        execution_token = runtime.mint_execution_token(
            capability=capability, params=params, plan_id=job_plan, step_id=job_step,
            scope_grant=scope_grant,
        )

    # Bind the replay policy the runtime resolved, exactly as the production producer does. Without
    # it the permit carries no retry-safety binding and every claimed failure reconciles - correct
    # for an UNSAFE capability, wrong for a capability that declares its effect is idempotent.
    from ciph.kernel.policy_engine import replay_policy_digest as _replay_policy_digest
    _binding = _replay_policy_digest(
        getattr(runtime.registry.get(capability) if capability else None, "manifest", None)
    )

    return _canonical_fixture_job(
        scope_grant=scope_grant,
        queue=runtime.queue,
        permit_provider=runtime.durable_permit_dependencies,
        scope_store=runtime.scope_grant_store(),
        signer=runtime.kernel_priv_bytes,
        signing_key_id=runtime.kernel_key_id,
        capability=capability,
        params=params,
        scope_targets=scope_targets,
        scope_id=scope_id,
        execution_token=execution_token,
        idempotency_key=idempotency_key,
        # the SAME plan/step the token was minted with, or the transport check refuses the job
        plan_id=job_plan,
        step_id=job_step,
        max_retries=max_retries,
        replay_policy_digest=_binding,
    )


def enqueue_permit_bearing_queue_job(
    *,
    queue,
    trust_registry,
    operator_private_key,
    db_path=None,
    capability,
    params,
    scope_targets=None,
    scope_id=None,
    execution_token=None,
    idempotency_key=None,
    plan_id=None,
    step_id=None,
    max_retries=1,
) -> FixtureJob:
    """
    Queue-only adapter for fixtures that build an IPCJobQueue and TrustRegistry directly.

    It uses the SAME provisioning primitive production uses, with the operator identity the fixture
    already holds - it does not generate signing material itself, and the worker identity never
    signs execution authority.
    """
    path = db_path or getattr(queue, "db_path", None)
    if not path:
        raise AssertionError("queue-only fixture needs a db_path to resolve canonical authority")

    def _operator_signer(key_id, role_value, public_key_hex, valid_until):
        payload = f"REGISTER_KEY:{key_id}:{role_value}:{public_key_hex}:{valid_until}".encode("utf-8")
        return Ed25519KeyManager.sign(operator_private_key, payload)

    def _provider():
        # Re-resolved on every call, so repeated fixtures converge on ONE lineage rather than each
        # provisioning a fresh signer.
        return build_durable_permit_dependencies(
            path, trust_registry=trust_registry, operator_signer=_operator_signer
        )

    return _canonical_fixture_job(
        queue=queue,
        permit_provider=_provider,
        scope_store=ScopeGrantStore(path),
        signer=None,
        signing_key_id=None,
        capability=capability,
        params=params,
        scope_targets=scope_targets,
        scope_id=scope_id,
        execution_token=execution_token,
        idempotency_key=idempotency_key,
        plan_id=plan_id,
        step_id=step_id,
        max_retries=max_retries,
    )


def central_retry_disposition(*, db_path, queue, event_store, trust_registry, operator_private_key):
    """
    The central disposition callable for fixtures that build their own daemon.

    The worker-constructed daemon gets the same one-engine wiring production injects from the runtime:
    the worker reports facts, this decides.
    """
    from ciph.kernel.permit_composition import build_durable_permit_dependencies
    from ciph.kernel.retry_transaction import apply_retry_transition

    def _operator_signer(key_id, role_value, public_key_hex, valid_until):
        payload = f"REGISTER_KEY:{key_id}:{role_value}:{public_key_hex}:{valid_until}".encode("utf-8")
        return Ed25519KeyManager.sign(operator_private_key, payload)

    dependencies = build_durable_permit_dependencies(
        db_path, trust_registry=trust_registry, operator_signer=_operator_signer
    )

    def dispose(**kwargs):
        return apply_retry_transition(
            db_path=db_path, queue=queue, permit_store=dependencies.permit_store,
            event_store=event_store, dependencies=dependencies, **kwargs,
        )

    return dispose

def canonical_permit_for(runtime, *, capability, params, scope_targets=None, scope_id=None,
                         scope_type=ScopeType.LOCAL_SYSTEM, claim_horizon_seconds=600.0):
    """Acquire canonical authority WITHOUT enqueuing, for tests that only need handles."""
    fixture = _canonical_fixture_job(
        queue=runtime.queue,
        permit_provider=runtime.durable_permit_dependencies,
        scope_store=runtime.scope_grant_store(),
        signer=runtime.kernel_priv_bytes,
        signing_key_id=runtime.kernel_key_id,
        capability=capability, params=params,
        scope_targets=scope_targets, scope_id=scope_id,
        scope_type=scope_type, claim_horizon_seconds=claim_horizon_seconds,
        enqueue=False,
    )
    return fixture.job_id, fixture.permit
