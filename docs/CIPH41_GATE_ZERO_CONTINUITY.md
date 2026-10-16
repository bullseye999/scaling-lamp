# 4.1 Gate Zero — Continuity: deterministic cold-start reconstruction

The first constitutional question of 4.1 is not "does Ciph remember?" It is:

> If Ciph dies right now and starts from nothing but its durable evidence, can it say what it was
> doing, what actually happened, what remains unresolved, and what authority is still valid —
> **without inventing state**?

```
reconstructed state  ≠  checkpoint says so
reconstructed state  =  canonical history proves so
```

## The eight laws, and where each is falsifiable

Encoded in `ciph/kernel/continuity.py`; each has at least one specimen in
`test_gate_4_1_continuity_cold_start.py` (15 specimens, all green).

| # | Law | Specimen |
| --- | --- | --- |
| 1 | Restart creates no new facts | `test_reconstruction_creates_no_new_facts` — store row counts identical before/after |
| 2 | Canonical stores are authoritative; caches/checkpoints are disposable | `test_reconstruction_takes_no_projection_or_checkpoint` — the signature has no parameter that could accept one |
| 3 | A logical action survives replanning; plan version ≠ action identity | `test_a_logical_action_survives_replanning` — rewriting `plan_id`/`step_id` leaves the digest identical |
| 4 | An unresolved claimed attempt stays unresolved across restart | `test_a_claimed_attempt_killed_before_terminal_evidence_stays_unresolved`, `test_an_unresolved_attempt_never_becomes_success_or_failure` |
| 5 | Consumed / revoked / expired authority stays dead | `test_consumed_authority_stays_dead_after_restart`, `test_a_terminal_action_stays_terminal_across_restart` |
| 6 | Restart cannot mint replacement authority because work is unfinished | `test_restart_cannot_mint_authority_for_unfinished_work` — no store row moves across 3 restarts |
| 7 | The same history reconstructs the same state deterministically | `test_replaying_the_same_history_reconstructs_the_same_state` — in-process **and** cross-process digest equality; `test_the_clock_is_an_explicit_input` |
| 8 | Missing / contradictory evidence → UNKNOWN or RECONCILIATION, never a guess | `test_missing_evidence_yields_unresolved_not_success`, `test_contradictory_attempt_evidence_is_unknown_not_a_match`, `test_a_job_naming_a_permit_the_store_no_longer_holds_is_an_integrity_flag` |

## What reconstruction returns

`reconstruct(db_path, *, now, read_only=True) -> ContinuityState`, built from three canonical sources
only: `execution_permits`, `ciph_ipc_jobs`, and the signed event history
(`ExecutionReceiptStoredEvent`, `ReconciliationRequiredEvent`, `JobReconciledEvent`,
`ExecutionAttemptStartedEvent`). It never reads an `ExecutionToken`, and it holds no signer.

Per logical action:

```
logical_action_id            latest_generation        permit_id / permit_state
execution_attempt_id         attempt_outcome          terminal_evidence (machine proof?)
authorization_alive          job_id / job_status      capability / mission_id
permit_count
```

and, across actions: `reconciliation_obligations`, `unresolved_attempts` (unresolved effects),
`remaining_authorized_work` (runnable job + live authority), `dead_authority`, `integrity_flags`,
plus `source_counts` and a canonical `source_fingerprint`.

`attempt_outcome` is one of four machine answers plus one operator answer, deliberately distinct:

```
NOT_ATTEMPTED          authority exists and was never spent
UNRESOLVED             spent, and no terminal evidence exists  -> obligation
TERMINAL               signed evidence names this exact attempt
RESOLVED_BY_OPERATOR   a human settled it; NO machine evidence (terminal_evidence stays False)
UNKNOWN                the record is missing or self-contradictory
```

`RESOLVED_BY_OPERATOR` exists because otherwise an operator-settled attempt would be reported as an
obligation forever — and because collapsing it into `TERMINAL` would let a human decision masquerade
as machine proof.

## The three founding scenarios, measured

```
1. claim, then die before terminal evidence
   -> same logical action, same permit, SAME execution_attempt_id, UNRESOLVED
   -> reconciliation obligation recorded; permit count still 1; generation still 0
   -> re-claiming the spent permit raises (no second attempt, no fresh authority)

2. execute successfully, terminalize, die, restart
   -> TERMINAL with terminal_evidence = True, job SUCCEEDED, permit dead
   -> lease_next_job() returns None: no redispatch, no duplicate effect

3. permit issued, never claimed, restart
   -> NOT_ATTEMPTED with authorization_alive = True
   -> the restart neither spent it nor regenerated it; the claim afterwards succeeds exactly once
```

## Deliberate scope limits

- **Plans are not reconstructed as authority.** Law 3 makes the logical action the durable unit; a
  plan is a consumer-side arrangement and is not allowed to become a second source of truth about
  what was authorized. Re-planning is therefore invisible to continuity, which is the point.
- **No verdicts.** Reconstruction does not retry, reconcile or terminalize. It reports. The decision
  layers (`retry_transaction`, operator reconciliation) stay the only things that move state.
- **The clock is an input, not a read.** Expiry is derived (`derive_permit_state`, shared with
  `PermitStore.state_of`) so "same history, same clock ⇒ same state" is testable rather than hopeful.

## Resolved since, and what is left

1. **`CLAIMED` no longer survives a resolution.** `consume_permit_row` is runnable inside a caller's
   transaction; the daemon's success path hands it to the queue's completion transaction, and the
   retry transaction and operator settlement consume inside their own. `CLAIMED` now means exactly
   "spent, unresolved". The one surviving window - crash between durable evidence and consumption -
   is a visible `completion_obligation`, closed by `complete_pending_consumption()` (which creates no
   fact). Specimens: `test_gate_4_1_permit_lifecycle.py`.
2. **Vault identity** is now a register item (`REGISTER.md`, R1) with the decided shape
   (`vault_id` + rewrap migration) and explicitly NOT implemented yet.
3. **Gate One (missions) is implemented** - see `CIPH41_GATE_ONE_MISSIONS.md`.
4. Everything downstream — long-lived plans, replanning, scheduler recovery, swarm — now has both
   foundations: a deterministic answer to *what is true right now*, and a durable answer to *what
   unfinished purpose it belongs to*.
