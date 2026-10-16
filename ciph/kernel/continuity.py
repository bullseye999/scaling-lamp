"""
ciph.kernel.continuity - cold-start reconstruction from canonical evidence only.

4.1 Gate Zero. If Ciph dies and starts from nothing but its durable stores, it must be able to say
what it was doing, what actually happened, what remains unresolved and what authority is still valid
- WITHOUT INVENTING STATE.

THE LAWS (each has a specimen in `test_gate_4_1_continuity_cold_start.py`):

 1. Restart creates no new facts. Reconstruction is a read; `source_fingerprint` is captured before
    and after so the claim is testable rather than asserted.
 2. Canonical stores (permit rows, job rows, signed event history) are authoritative. A projection or
    checkpoint is disposable and is never consulted here - there is deliberately no cache parameter.
 3. A logical action survives replanning. Identity comes from the permit's `logical_action_id`, never
    from `plan_id` / `step_id`, so a re-plan does not fork the action's history.
 4. An unresolved claimed attempt stays unresolved across restart. A claim with no terminal evidence
    is UNRESOLVED; restart never converts it to success or failure.
 5. Consumed / revoked / expired authority stays dead after restart.
 6. Restart cannot mint replacement authority because work remains unfinished. Reconstruction holds
    no signer and writes nothing; unfinished work is reported, never re-authorized.
 7. Replaying the same canonical history reconstructs the same state deterministically - the state
    has a canonical digest, and `now` is an explicit input rather than a hidden clock read.
 8. Missing or contradictory evidence produces UNKNOWN / RECONCILIATION, never a guessed state.

WHAT THIS MODULE DELIBERATELY IS NOT
    It does not decide retries (that is `retry_transaction`), does not mint or resolve authority, and
    `reconstruct()` never writes. It answers one question - "what is true right now, on this
    evidence?" - and answers it the same way every time.

`complete_pending_consumption()` is the ONE exception, spelled out separately because it is not a
decision: it closes the crash window where a terminal fact is already durable but the permit was
never consumed. It creates no fact, mints nothing, and revives nothing.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.permit_store import (
    STATE_CLAIMED,
    STATE_CONSUMED,
    STATE_ISSUED,
    STATE_UNKNOWN,
    consume_permit_row,
    derive_permit_state,
)
from ciph.memory.event_store import governed_authorization_block

RECEIPT_EVENT = "ExecutionReceiptStoredEvent"
RECONCILIATION_EVENT = "ReconciliationRequiredEvent"
RECONCILED_EVENT = "JobReconciledEvent"
ACTIVATION_EVENT = "ExecutionAttemptStartedEvent"
EVIDENCE_EVENT_TYPES = (RECEIPT_EVENT, RECONCILIATION_EVENT, RECONCILED_EVENT, ACTIVATION_EVENT)

RUNNABLE_JOB_STATES = ("QUEUED", "RETRYING")
IN_FLIGHT_JOB_STATES = ("LEASED", "EXECUTING")

INTEGRITY_RUNNABLE_JOB_WITH_SPENT_PERMIT = "RUNNABLE_JOB_WITH_SPENT_PERMIT"
INTEGRITY_JOB_PERMIT_ABSENT_FROM_STORE = "JOB_PERMIT_ABSENT_FROM_STORE"
INTEGRITY_CONTRADICTORY_ATTEMPT_EVIDENCE = "CONTRADICTORY_ATTEMPT_EVIDENCE"
INTEGRITY_PERMIT_WITHOUT_LOGICAL_ACTION = "PERMIT_WITHOUT_LOGICAL_ACTION"


class AttemptOutcome(str, Enum):
    """What the durable record proves about the latest attempt. Four answers, no fifth."""

    NOT_ATTEMPTED = "NOT_ATTEMPTED"              # authority exists and was never spent
    UNRESOLVED = "UNRESOLVED"                    # spent, and no terminal evidence exists
    TERMINAL = "TERMINAL"                        # signed terminal evidence names this exact attempt
    RESOLVED_BY_OPERATOR = "RESOLVED_BY_OPERATOR"  # a human adjudicated it; NO machine evidence
    UNKNOWN = "UNKNOWN"                          # the record is missing or self-contradictory


@dataclass(frozen=True)
class ActionContinuity:
    """Everything provable about ONE logical action from canonical stores."""

    logical_action_id: str
    latest_generation: int
    permit_id: Optional[str]
    permit_state: str
    execution_attempt_id: Optional[str]
    attempt_outcome: str
    terminal_evidence: bool
    consumption_pending: bool
    authorization_alive: bool
    job_id: Optional[str]
    job_status: Optional[str]
    capability: Optional[str]
    mission_id: Optional[str]
    permit_count: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "logical_action_id": self.logical_action_id,
            "latest_generation": self.latest_generation,
            "permit_id": self.permit_id,
            "permit_state": self.permit_state,
            "execution_attempt_id": self.execution_attempt_id,
            "attempt_outcome": self.attempt_outcome,
            "terminal_evidence": self.terminal_evidence,
            "consumption_pending": self.consumption_pending,
            "authorization_alive": self.authorization_alive,
            "job_id": self.job_id,
            "job_status": self.job_status,
            "capability": self.capability,
            "mission_id": self.mission_id,
            "permit_count": self.permit_count,
        }


@dataclass(frozen=True)
class ContinuityState:
    """The reconstructed present. Deterministic in the canonical history and the clock."""

    actions: Tuple[ActionContinuity, ...] = ()
    reconciliation_obligations: Tuple[str, ...] = ()
    completion_obligations: Tuple[str, ...] = ()
    unresolved_attempts: Tuple[str, ...] = ()
    remaining_authorized_work: Tuple[str, ...] = ()
    dead_authority: Tuple[str, ...] = ()
    integrity_flags: Tuple[str, ...] = ()
    source_counts: Tuple[Tuple[str, int], ...] = ()
    source_fingerprint: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "actions": [a.as_dict() for a in self.actions],
            "reconciliation_obligations": list(self.reconciliation_obligations),
            "completion_obligations": list(self.completion_obligations),
            "unresolved_attempts": list(self.unresolved_attempts),
            "remaining_authorized_work": list(self.remaining_authorized_work),
            "dead_authority": list(self.dead_authority),
            "integrity_flags": list(self.integrity_flags),
            "source_counts": {k: v for k, v in self.source_counts},
        }

    def canonical_digest(self) -> str:
        """Law 7: the same history yields the same digest, byte for byte."""
        blob = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _open(db_path: str, read_only: bool) -> sqlite3.Connection:
    if read_only:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            pass
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def _table_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for table in ("ciph_ipc_jobs", "execution_permits", "ciph_event_store"):
        try:
            counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        except sqlite3.Error:
            counts[table] = 0
    return counts


def _fingerprint(counts: Dict[str, int]) -> str:
    blob = json.dumps(counts, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _rows(conn: sqlite3.Connection, sql: str, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
    try:
        return [dict(r) for r in conn.execute(sql, params)]
    except sqlite3.Error:
        # A store that has never been created answers "nothing is known", not "guess".
        return []


EFFECT_CONFIRMED = "EFFECT_CONFIRMED"


def _receipt_resolves_attempt(payload: Dict[str, Any], block: Dict[str, Any]) -> bool:
    """
    Does this signed receipt RESOLVE its attempt?

    Two canonical answers: the attempt ended SUCCESSFULLY (the success is itself the proof of its
    effect), or the effect is explicitly CONFIRMED. A receipt that records a failure while the effect
    stays unknown resolves nothing - that is exactly the case that reconciles, and calling it
    "terminal" is how a resolved-looking lifecycle would lie.

    Observed and deliberate: a SUCCESS receipt attests `effect_certainty = EFFECT_UNKNOWN`, so success
    cannot be inferred from certainty alone - and certainty cannot be inferred from success.
    """
    certainty = str(block.get("effect_certainty") or payload.get("effect_certainty") or "").upper()
    if certainty == EFFECT_CONFIRMED:
        return True
    outcome = str(payload.get("outcome") or "").upper()
    if outcome.endswith("SUCCESS"):
        return True
    return payload.get("exit_code") == 0


def _payload(row: Dict[str, Any]) -> Dict[str, Any]:
    raw = row.get("payload")
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def complete_pending_consumption(db_path: str, *, now: Optional[float] = None) -> Tuple[str, ...]:
    """
    Close the crash window `CLAIMED + terminal fact already durable -> CONSUMED`.

    This is COMPLETION, not decision. It only acts on permits whose attempt is already resolved by
    canonical evidence, it creates no fact, mints nothing, revives nothing, and is idempotent. It
    exists because a crash between "the receipt is durable" and "the permit is consumed" must not
    leave a resolved attempt looking unresolved forever.
    """
    moment = time.time() if now is None else float(now)
    state = reconstruct(db_path, now=moment, read_only=False)
    completed: List[str] = []
    for action in state.actions:
        if not action.consumption_pending or not action.permit_id:
            continue
        conn = _open(db_path, read_only=False)
        try:
            conn.execute("BEGIN IMMEDIATE")
            changed = consume_permit_row(conn, action.permit_id, actor="continuity.recovery",
                                        now=moment, allow_foreign_claimant=True)
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            continue
        finally:
            conn.close()
        if changed:
            completed.append(action.permit_id)
    return tuple(completed)


def reconstruct(db_path: str, *, now: Optional[float] = None, read_only: bool = True,
                conn: Optional[sqlite3.Connection] = None) -> ContinuityState:
    """
    Rebuild the present from canonical durable evidence. Reads only; never writes, never decides.

    `now` is an explicit input because expiry is a function of the clock, and law 7 requires replay
    determinism: two readers with the same history AND the same clock must agree exactly.

    With `conn` supplied the read happens inside the CALLER's transaction, so a decision that must be
    taken against a specific state (an optimistic-concurrency check, say) can read and act without a
    writer slipping between the two.
    """
    moment = time.time() if now is None else float(now)
    owned = conn is None
    conn = _open(db_path, read_only=read_only) if owned else conn
    try:
        counts_before = _table_counts(conn)
        permits = _rows(conn, "SELECT * FROM execution_permits")
        jobs = {r["job_id"]: r for r in _rows(
            conn, "SELECT job_id, capability, status, execution_permit FROM ciph_ipc_jobs")}
        events = _rows(conn, "SELECT event_type, aggregate_id, payload FROM ciph_event_store "
                             "WHERE event_type IN (?,?,?,?)", EVIDENCE_EVENT_TYPES)
        counts_after = _table_counts(conn)
    finally:
        if owned:
            conn.close()

    # ---------------------------------------------------------------- evidence indexes
    resolved_attempts = set()          # (permit_id, attempt_id) RESOLVED by signed evidence
    attested_permit_attempts = {}      # permit_id -> {attempt_id, ...} mentioned by any receipt
    reconciliation_jobs = set()
    reconciled_jobs = set()
    activation_jobs = set()
    for event in events:
        payload = _payload(event)
        kind = event.get("event_type")
        block = governed_authorization_block({"payload": payload})
        if kind == RECEIPT_EVENT and block:
            permit_id = block.get("execution_permit_id")
            attempt_id = block.get("execution_attempt_id")
            if permit_id:
                attested_permit_attempts.setdefault(str(permit_id), set()).add(str(attempt_id))
                if attempt_id and _receipt_resolves_attempt(payload, block):
                    resolved_attempts.add((str(permit_id), str(attempt_id)))
        elif kind == RECONCILIATION_EVENT:
            job = payload.get("job_id") or event.get("aggregate_id")
            if job:
                reconciliation_jobs.add(str(job))
        elif kind == RECONCILED_EVENT:
            job = payload.get("job_id") or event.get("aggregate_id")
            if job:
                reconciled_jobs.add(str(job))
        elif kind == ACTIVATION_EVENT:
            job = payload.get("job_id") or event.get("aggregate_id")
            if job:
                activation_jobs.add(str(job))

    # ---------------------------------------------------------------- group by logical action
    by_action: Dict[str, List[Dict[str, Any]]] = {}
    flags: List[str] = []
    for permit in permits:
        action_id = permit.get("logical_action_id")
        if not action_id:
            flags.append(f"{INTEGRITY_PERMIT_WITHOUT_LOGICAL_ACTION}:{permit.get('permit_id')}")
            action_id = f"UNKNOWN_ACTION:{permit.get('permit_id')}"
        by_action.setdefault(str(action_id), []).append(permit)

    # A job that names a permit the store no longer holds is an integrity fact, not an empty action.
    carried_jobs: Dict[str, Dict[str, Any]] = {}
    for job_id, job in jobs.items():
        raw = job.get("execution_permit")
        if not raw:
            continue
        try:
            carried = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            flags.append(f"{INTEGRITY_JOB_PERMIT_ABSENT_FROM_STORE}:{job_id}:UNREADABLE")
            continue
        permit_id = carried.get("permit_id")
        carried_jobs[str(permit_id)] = job
        if permit_id and not any(p.get("permit_id") == permit_id for p in permits):
            flags.append(f"{INTEGRITY_JOB_PERMIT_ABSENT_FROM_STORE}:{job_id}:{permit_id}")
            action_id = carried.get("logical_action_id") or f"UNKNOWN_ACTION:{permit_id}"
            by_action.setdefault(str(action_id), []).append({
                "permit_id": permit_id, "code_only": True, "logical_action_id": action_id,
                "authorization_generation": carried.get("authorization_generation") or 0,
                "state": STATE_UNKNOWN, "expires_at": 0.0, "execution_attempt_id": None,
                "job_id": job_id,
            })

    actions: List[ActionContinuity] = []
    obligations: List[str] = []
    completions: List[str] = []
    unresolved: List[str] = []
    authorized_work: List[str] = []
    dead: List[str] = []

    for action_id in sorted(by_action):
        rows = sorted(by_action[action_id],
                      key=lambda r: (int(r.get("authorization_generation") or 0), str(r.get("permit_id"))))
        latest = rows[-1]
        permit_id = latest.get("permit_id")
        generation = int(latest.get("authorization_generation") or 0)
        if latest.get("state") == STATE_UNKNOWN:
            state = STATE_UNKNOWN
        else:
            state = derive_permit_state(latest.get("state"), latest.get("expires_at") or 0.0, moment)
        attempt_id = latest.get("execution_attempt_id")
        job_id = latest.get("job_id")
        job = jobs.get(str(job_id)) if job_id else None
        job_status = job.get("status") if job else None
        capability = job.get("capability") if job else None

        terminal = bool(attempt_id) and (str(permit_id), str(attempt_id)) in resolved_attempts
        mentioned = attested_permit_attempts.get(str(permit_id), set())
        contradictory = bool(mentioned) and bool(attempt_id) and not terminal and str(attempt_id) not in mentioned
        if contradictory:
            flags.append(f"{INTEGRITY_CONTRADICTORY_ATTEMPT_EVIDENCE}:{permit_id}:{attempt_id}")

        resolved_by_operator = bool(job_id) and str(job_id) in reconciled_jobs
        if not attempt_id:
            outcome = AttemptOutcome.NOT_ATTEMPTED
        elif state == STATE_UNKNOWN or contradictory:
            outcome = AttemptOutcome.UNKNOWN
        elif terminal:
            outcome = AttemptOutcome.TERMINAL
        elif resolved_by_operator:
            # An operator settled it. That is a canonical fact and clears the obligation, but it is
            # NOT machine evidence, so `terminal_evidence` stays False and nobody may read it as proof.
            outcome = AttemptOutcome.RESOLVED_BY_OPERATOR
        else:
            outcome = AttemptOutcome.UNRESOLVED

        # A resolution whose consumption never landed - the crash window "evidence durable, permit
        # not consumed". It is NOT unresolved (the fact exists); only the lifecycle is unfinished.
        consumption_pending = (
            state == STATE_CLAIMED
            and outcome in (AttemptOutcome.TERMINAL, AttemptOutcome.RESOLVED_BY_OPERATOR)
        )

        alive = state == STATE_ISSUED
        if state in (STATE_CONSUMED, "REVOKED", "EXPIRED"):
            dead.append(str(permit_id))
        if consumption_pending:
            completions.append(str(permit_id))
        if outcome in (AttemptOutcome.UNRESOLVED, AttemptOutcome.UNKNOWN):
            unresolved.append(str(attempt_id or permit_id))
        if outcome in (AttemptOutcome.UNRESOLVED, AttemptOutcome.UNKNOWN) or \
                job_status == "RECONCILIATION_REQUIRED":
            obligations.append(str(job_id or permit_id))
        if alive and job_status in RUNNABLE_JOB_STATES:
            authorized_work.append(str(job_id))
        if job_status in RUNNABLE_JOB_STATES and not alive:
            # The impossible state: a job that may be leased while its authority is unusable.
            flags.append(f"{INTEGRITY_RUNNABLE_JOB_WITH_SPENT_PERMIT}:{job_id}:{state}")

        actions.append(ActionContinuity(
            logical_action_id=str(action_id),
            latest_generation=generation,
            permit_id=str(permit_id) if permit_id else None,
            permit_state=state,
            execution_attempt_id=str(attempt_id) if attempt_id else None,
            attempt_outcome=outcome.value,
            terminal_evidence=terminal,
            consumption_pending=consumption_pending,
            authorization_alive=alive,
            job_id=str(job_id) if job_id else None,
            job_status=job_status,
            capability=capability,
            mission_id=latest.get("mission_id"),
            permit_count=sum(1 for r in rows if not r.get("code_only")),
        ))

    return ContinuityState(
        actions=tuple(actions),
        reconciliation_obligations=tuple(sorted(set(obligations))),
        completion_obligations=tuple(sorted(set(completions))),
        unresolved_attempts=tuple(sorted(set(unresolved))),
        remaining_authorized_work=tuple(sorted(set(authorized_work))),
        dead_authority=tuple(sorted(set(dead))),
        integrity_flags=tuple(sorted(set(flags))),
        source_counts=tuple(sorted(counts_after.items())),
        source_fingerprint=_fingerprint(counts_after),
    )
