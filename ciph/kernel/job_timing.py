
"""
ciph.kernel.job_timing - the one job claim-deadline law.

Characterised 2026-10-04: the daemon refuses a job whose token has expired
(`EXECUTION_TOKEN_EXPIRED` at ingress), so the grace period is a real JOB-START bound rather than
session padding. A job may sit in the queue at most this long past its execution timeout before its
authority to begin lapses.

The law is neutral on purpose. Both the runtime lane and the planner lane consume it, and owning it
on `CiphRuntime` would either duplicate the formula or close a runtime -> planner -> runtime import
cycle. Nothing here decides authority: the inputs are job/authority timing facts, and every bound is
a `min` against something the caller already established.

The governing constant lives here too. A neutral calculation whose constant still belonged to one of
its consumers would not be neutral.
"""

import time

DEFAULT_QUEUE_CLAIM_GRACE_SECONDS = 300.0


def job_claim_deadline(
    *,
    explicit_expires_at=None,
    now=None,
    timeout_seconds=None,
    scope_grant=None,
    auth_grant=None,
    queue_claim_grace_seconds: float = DEFAULT_QUEUE_CLAIM_GRACE_SECONDS,
):
    """
    The latest time at which this job may legitimately begin execution.

    Derived from canonical job/authority inputs only - never from `ExecutionToken.expires_at`. The
    token lane may realise the same value as its own expiry, which is exactly why the fact belongs
    here rather than in the artifact being demoted.
    """
    moment = now if now is not None else time.time()
    if explicit_expires_at is not None:
        deadline = float(explicit_expires_at)
    else:
        timeout = float(timeout_seconds) if timeout_seconds is not None else 0.0
        deadline = moment + timeout + float(queue_claim_grace_seconds)
    if scope_grant is not None and getattr(scope_grant, "valid_until", None) is not None:
        deadline = min(deadline, float(scope_grant.valid_until))
    if auth_grant is not None and getattr(auth_grant, "expires_at", 0.0):
        deadline = min(deadline, float(auth_grant.expires_at))
    return deadline
