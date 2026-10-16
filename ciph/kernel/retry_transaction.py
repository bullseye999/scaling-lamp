
"""
ciph.kernel.retry_transaction - the single atomic retry decision.

Job state, permit state and the exact attempt's evidence must be ONE authoritative proposition when
retry authority is granted. This runs one `BEGIN IMMEDIATE` over all three, classifies inside that
transaction, and applies exactly one of:

    REDELIVER_SAME_GENERATION   authority never spent -> same permit, no retry budget
    NEXT_GENERATION             authority spent, provably retry-safe -> fresh single-use permit
    RECONCILIATION_REQUIRED     uncertainty or integrity conflict -> NO next generation
    TERMINAL                    nothing more may be minted

The impossibility properties it exists to protect:

    a retryable job carrying a SPENT permit                -> impossible
    a registered N+1 permit whose job move was rolled back -> impossible
"""

import json
import sqlite3
import time

from ciph.kernel.execution_authority import SignedExecutionPermit
from ciph.kernel.permit_store import consume_permit_row
from ciph.kernel.retry_authority import (
    RetryOutcome,
    authorize_next_generation,
    canonical_retry_safety,
    classify_retry,
    derive_retry_request,
)


class _TransportRenewalRefused(Exception):
    """Internal marker: a runnable state could not be given a usable transport artifact."""


class RetryTransitionResult:
    __slots__ = ("applied", "outcome", "reason", "permit_id", "generation", "safety_source")

    def __init__(self, applied, outcome, reason="", permit_id=None, generation=None,
                 safety_source=None):
        self.applied = applied
        self.outcome = outcome
        self.reason = reason
        self.permit_id = permit_id
        self.generation = generation
        self.safety_source = safety_source

    def __repr__(self):
        return (f"RetryTransitionResult(applied={self.applied}, outcome={self.outcome}, "
                f"reason={self.reason!r}, permit_id={self.permit_id!r}, generation={self.generation})")


def apply_retry_transition(
    *,
    db_path,
    queue,
    permit_store,
    event_store,
    dependencies,
    job_id,
    expected_permit_id=None,
    now=None,
    token_renewer=None,
    manifest_resolver=None,
):
    """One atomic transition. Everything below runs inside a single write transaction."""
    conn = sqlite3.connect(db_path, isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    moment = now if now is not None else time.time()
    try:
        conn.execute("BEGIN IMMEDIATE")

        job = queue.get_job_for_retry(job_id, conn=conn)
        if job is None:
            conn.execute("ROLLBACK")
            return RetryTransitionResult(False, "REFUSED", "UNKNOWN_JOB")

        raw = job.get("execution_permit")
        if not raw:
            conn.execute("ROLLBACK")
            return RetryTransitionResult(False, "REFUSED", "NO_CARRIED_PERMIT")
        data = json.loads(raw) if isinstance(raw, str) else raw
        carried = SignedExecutionPermit.from_dict(data)

        # Correlation: the worker's observation must still describe the current job.
        if expected_permit_id is not None and carried.payload.permit_id != expected_permit_id:
            conn.execute("ROLLBACK")
            return RetryTransitionResult(False, "REFUSED", "STALE_CORRELATION")

        canonical = permit_store.get_permit_row(carried.payload.permit_id, conn=conn)
        if canonical is None:
            conn.execute("ROLLBACK")
            return RetryTransitionResult(False, "REFUSED", "PERMIT_NOT_CANONICAL")
        if str(canonical["permit_digest"]) != carried.permit_digest():
            conn.execute("ROLLBACK")
            return RetryTransitionResult(False, "REFUSED", "PERMIT_DIGEST_MISMATCH")

        generation = int(carried.payload.authorization_generation or 0)
        state = permit_store.state_of(carried.payload.permit_id, now=moment)

        # THE EXECUTION-RETRY BUDGET IS DERIVED FROM CANONICAL STATE, NOT REPORTED. It counts
        # AUTHORIZED GENERATIONS, not deliveries: the job row's `max_retries` is the total number of
        # executed attempts this logical action may spend, and a lease lost before a claim advances
        # the delivery count without advancing a generation - so an operational redelivery can never
        # eat the budget for a governed execution retry.
        attempts_remaining = max(
            0, int(job.get("max_retries") or 1) - (generation + 1)
        )

        def _renewed_transport():
            """
            A transport artifact for the NEXT delivery, minted centrally in this transaction.

            The permit is the authority; the token is the session. The previous session was consumed
            at activation, so a row made runnable again while still carrying it would be
            un-executable. A renewal failure is a refusal: a runnable job whose transport cannot be
            produced is exactly the half-state this transaction exists to make impossible.
            """
            if token_renewer is None:
                return None
            try:
                return token_renewer(job=job, permit=carried, moment=moment)
            except Exception as error:
                raise _TransportRenewalRefused(str(error))

        # Authority never spent: operational redelivery of the SAME artifact.
        if state == "ISSUED":
            try:
                renewed = _renewed_transport()
            except _TransportRenewalRefused as refusal:
                conn.execute("ROLLBACK")
                return RetryTransitionResult(False, "REFUSED", f"TRANSPORT_RENEWAL_FAILED:{refusal}")
            applied = queue.apply_retry_transition(
                job_id=job_id, status="RETRYING", carried_permit=raw, carried_token=renewed,
                expected_permit_id=carried.payload.permit_id, conn=conn,
            )
            if not applied:
                conn.execute("ROLLBACK")
                return RetryTransitionResult(False, "REFUSED", "QUEUE_TRANSITION_REFUSED")
            conn.execute("COMMIT")
            return RetryTransitionResult(
                True, RetryOutcome.REDELIVER_SAME_GENERATION.value,
                permit_id=carried.payload.permit_id, generation=generation,
            )

        def _settled_receipt():
            """The signed receipt this decision was made about, if the evidence carries one.

            Binding it to the row keeps a settled job self-describing: the operator reconciling it
            must be able to reach the exact attempt's evidence through the job, not by guessing.
            """
            for event in reversed(tuple(getattr(evidence, "events", ()) or ())):
                payload = event.get("payload")
                if isinstance(payload, dict) and payload.get("receipt_id"):
                    return payload
            return None

        def _settle(status, outcome, reason):
            """Move the job OUT of a runnable state in the SAME transaction, then commit.

            A claimed permit is unusable, so leaving the job QUEUED/RETRYING/LEASED would create
            'runnable job + spent authority'. That state must be unreachable after this returns.
            """
            moved = queue.apply_retry_transition(
                job_id=job_id, status=status, carried_permit=raw,
                expected_permit_id=carried.payload.permit_id, conn=conn,
                receipt=_settled_receipt(),
            )
            if not moved:
                conn.execute("ROLLBACK")
                return RetryTransitionResult(False, "REFUSED", "QUEUE_TRANSITION_REFUSED")
            if status == "FAILED":
                # MACHINE-PROVEN TERMINAL: the attempt is resolved, so its authority is retired in
                # the SAME transaction that says so. `CLAIMED` must never mean "resolved but still
                # claimed" - that is the lifecycle lie this transition exists to prevent.
                consume_permit_row(conn, carried.payload.permit_id, actor="retry_transaction",
                                   now=moment, allow_foreign_claimant=True)
            conn.execute("COMMIT")
            return RetryTransitionResult(True, outcome, reason, generation=generation)

        if state != "CLAIMED":
            conn.execute("ROLLBACK")
            return RetryTransitionResult(False, "REFUSED", f"PERMIT_STATE_{state}")

        # Authority spent: only the exact attempt's evidence may decide.
        attempt_id = canonical["execution_attempt_id"]
        evidence = event_store.get_attempt_evidence(
            execution_attempt_id=attempt_id,
            permit_id=carried.payload.permit_id,
            permit_digest=carried.permit_digest(),
            authorization_generation=generation,
            conn=conn,
        )
        from ciph.memory.event_store import AttemptEvidenceOutcome

        if evidence.outcome is AttemptEvidenceOutcome.INTEGRITY_CONFLICT:
            return _settle("RECONCILIATION_REQUIRED", "INTEGRITY_CONFLICT", "ATTEMPT_EVIDENCE_CONFLICT")
        if evidence.outcome is AttemptEvidenceOutcome.NO_ATTRIBUTABLE_EVIDENCE:
            return _settle(
                "RECONCILIATION_REQUIRED", RetryOutcome.RECONCILIATION_REQUIRED.value,
                "NO_ATTRIBUTABLE_EVIDENCE",
            )

        # Derive the canonical facts from the WHOLE attributable set, not the latest event.
        from ciph.memory.event_store import governed_authorization_block

        certainties = []
        for event in evidence.events:
            payload = event.get("payload") or {}
            block = governed_authorization_block(event)
            # A receipt states its certainty at the payload root; a synthetic block may state it
            # inside the block. Both describe the SAME attempt, so both are read here.
            certainty = block.get("effect_certainty") or payload.get("effect_certainty")
            if certainty:
                certainties.append(str(certainty).upper())
        effect_certainty = "EFFECT_CONFIRMED" if "EFFECT_CONFIRMED" in certainties else (
            certainties[0] if certainties else None
        )

        # RETRY SAFETY IS DERIVED, NEVER ACCEPTED. The worker reports facts; the queue row and the
        # caller state none; this resolves the capability manifest centrally and requires the exact
        # attempt's evidence to attest that same manifest identity. `None` means "no independent
        # guarantee", which is the reconciliation path.
        manifest = None
        if manifest_resolver is not None:
            try:
                manifest = manifest_resolver(carried.payload.capability_id)
            except Exception:
                manifest = None
        safety = canonical_retry_safety(permit=carried, manifest=manifest, evidence=evidence)

        outcome = classify_retry(
            permit_state="CLAIMED", effect_certainty=effect_certainty,
            retry_safe=safety is not None, attempts_remaining=attempts_remaining,
        )
        if outcome is RetryOutcome.RECONCILIATION_REQUIRED:
            return _settle("RECONCILIATION_REQUIRED", outcome.value, "EFFECT_UNCERTAIN")
        if outcome is RetryOutcome.TERMINAL:
            return _settle("FAILED", outcome.value, "TERMINAL")

        # NEXT_GENERATION: derive from the signed permit, authorize, register, requeue - one commit.
        params = json.loads(job["params"]) if isinstance(job["params"], str) else job["params"]
        request = derive_retry_request(carried, params=params or {}, now=moment)
        authorization = authorize_next_generation(
            logical_action_id=carried.payload.logical_action_id,
            previous_generation=generation, permit_state="CLAIMED",
            effect_certainty=effect_certainty, retry_safe=safety is not None,
            attempts_remaining=attempts_remaining,
        )
        horizon = max(1.0, (carried.payload.expires_at_us / 1_000_000.0) - moment)
        candidate = dependencies.gateway.issue_permit(request, now=moment, ttl_seconds=horizon)
        permit_store.register(
            permit_id=candidate.payload.permit_id, digest=candidate.permit_digest(),
            issued_at=candidate.payload.issued_at_us / 1_000_000,
            expires_at=candidate.payload.expires_at_us / 1_000_000,
            logical_action_id=candidate.payload.logical_action_id,
            action_fingerprint=candidate.payload.action_fingerprint,
            authorization_generation=candidate.payload.authorization_generation,
            retry_authorization=authorization,
            job_id=job_id,
            conn=conn,
        )
        try:
            renewed = _renewed_transport()
        except _TransportRenewalRefused as refusal:
            conn.execute("ROLLBACK")
            return RetryTransitionResult(False, "REFUSED", f"TRANSPORT_RENEWAL_FAILED:{refusal}")
        moved = queue.apply_retry_transition(
            job_id=job_id, status="RETRYING",
            carried_permit=json.dumps(candidate.to_dict(), sort_keys=True),
            carried_token=renewed,
            expected_permit_id=carried.payload.permit_id, conn=conn,
        )
        if not moved:
            conn.execute("ROLLBACK")
            return RetryTransitionResult(False, "REFUSED", "QUEUE_TRANSITION_REFUSED")
        conn.execute("COMMIT")
        return RetryTransitionResult(
            True, RetryOutcome.NEXT_GENERATION.value,
            reason=f"SAFETY:{safety.source}",
            permit_id=candidate.payload.permit_id,
            generation=int(candidate.payload.authorization_generation or 0),
            safety_source=safety.source,
        )
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass
