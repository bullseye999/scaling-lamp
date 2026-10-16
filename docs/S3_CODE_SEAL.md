# S3 CODE SEAL

Status: **SEALED (code)**. Production cutover: **STAMPED AND RESIDENT** — the pre-S3 daemon was
retired and the current sealed build is the live process (see OPERATIONAL CUTOVER).

```
RAW BYPASSES               0
EXECUTION THROAT           CLOSED
PRODUCTION TOKEN AUTHORITY 0
CIPH 4.0                   SEALED
CLONE GATE                 OPEN (workspace-only, sanitized, read-only)
```

`SignedExecutionPermit` is the sole execution authority. `ExecutionToken` is transport. There is one
retry/disposition engine, and retry authority is derived from an **immutable binding**, never from
whatever a capability declares today.

## Evidence

| Measurement | Result |
| --- | --- |
| Captured full sweep at the S3 seal (4.0 tree) | **1183 tests, 0 failures, 0 errors, OK** (1064 s) |
| Current tree (4.0 + 4.1 + R1 + 4.2 Gates Zero–Four) | **1332 tests, OK** live, and the same suite green in a sanitized clone that created **no** ambient vault |
| Post-cutover governed smoke on the live vault | PASS — permit carried, claim attributed, receipt names the attempt |
| Failing tests before this work (reverse-patched mirror, same command) | **49** |
| Failing tests now | **0** |
| New failures introduced vs. the measured baseline | **0** (set difference, by test name) |
| Retroactive-widening probe, OLD rule | `NEXT_GENERATION` — the attack **worked** |
| Retroactive-widening probe, CURRENT rule | `RECONCILIATION_REQUIRED` — refused |
| Durable queue `live_permitless` before cutover | 3 |
| Durable queue `live_permitless` after cutover | **0** |
| Durable queue across a full test sweep | unchanged — total 427, governed 14, live_permitless 0 |

The baseline was measured, not asserted: the touched source files were reverse-applied in a mirrored
copy (each returned to its exact prior digest), the same `discover` command was run there, and failing
test *names* were diffed. `current − baseline = ∅`.

## The laws this seal covers

```
authority           SignedExecutionPermit — single use, logical_action_id + authorization_generation
transport           ExecutionToken — admission / replay / plan binding only, never authority
claim               one site: GuardedExecutor -> PermitStore.claim
evidence            every post-claim event names (execution_attempt_id, permit_id, digest, generation)
replay policy       BOUND AT ISSUANCE into the signed permit (replay_policy_digest), copied into the
                    attempt's evidence, and re-checked against the current declaration
retry safety        proof exists only when bound == attested == current == IDEMPOTENT
retry budget        derived from max_retries and the generation; deliveries never consume it
transition          one BEGIN IMMEDIATE over job + permit + exact-attempt evidence
transport renewal   minted by the central retry path inside that same transaction
```

### Why the binding exists

`ReplaySemantics` is deliberately outside the frozen V1 manifest hash, so a declaration edit does not
move the manifest identity. Checking the identity therefore cannot pin it:

```
A0 executes while the capability declares UNSAFE
evidence attests manifest identity H
somebody edits only the declaration -> IDEMPOTENT        (identity is still H)
```

Under the old rule the retry was granted: `NEXT_GENERATION`. That is retroactive authority widening,
and it was measured, not theorised. The fix binds the policy into the permit at issuance and requires
three-way agreement (bound / attested / current) on the IDEMPOTENT digest. Both directions are
specimens: widening after the fact, and narrowing after issuance, each refuse and mint no successor.
A permit minted before the binding carries no digest, so it can never produce a proof — fail-closed,
and V1 permits keep their exact signed bytes (the field is included only when present).

## Constitutional scanners (all green)

`test_gate_a0_s3_constitutional_scanners.py` — each with a paired "would catch a violation" specimen:

```
daemon raw cap.execute callers                  = 0
worker/daemon permit issuers or private signers = 0   (construction, not `from_dict`)
token-derived execution-scope consumers         = 0
PermitStore.claim outside GuardedExecutor       = 0   (one site: kernel/execution_gateway.py)
worker-stated retry verdict                     = 0
```

## Hostile / crash / replay matrix

`test_gate_a0_s3_hostile_matrix.py` plus the phase-3 and gate specimens cover: success receipt names
the exact claim; A0 evidence unreachable through A1 (mismatched generation → `INTEGRITY_CONFLICT`);
tampered carried permit refused pre-body; pre-claim transport refusal mints nothing and leaves the
permit `ISSUED`; transport and authority domains do not fuse (P1+T0 refused, P0+T1 refused, P1+T1
runs); stale retry report never advances twice; rollback after N+1 registration; crash before claim
redelivers the same permit, crash after claim reconciles; **policy widening and narrowing both
refuse**.

## Production cutover record

Read-only inspection, then a canonical settlement, then independent read-only verification.

```
before   {"SUCCEEDED": 401, "FAILED": 9, "LEASED": 2, "EXECUTING": 1}   live_permitless = 3
action   IPCJobQueue(ciph_vault.db).reclaim_expired_leases() -> 3 rows settled
after    {"SUCCEEDED": 401, "FAILED": 11, "RECONCILIATION_REQUIRED": 1} live_permitless = 0
verify   fresh mode=ro connection: live_permitless = 0, s3_gate_satisfied = true
```

The settlement used the watchdog's own law — no ad-hoc SQL and no invented states:

```
JOB-F4E6FA34  LEASED  (expired 2026-09-03) -> FAILED   "Max retries exhausted upon pre-execution lease expiry"
JOB-3389A685  LEASED  (expired 2026-09-04) -> FAILED   "Max retries exhausted upon pre-execution lease expiry"
JOB-8FE409AA  EXECUTING (expired 2026-09-04) -> RECONCILIATION_REQUIRED
                                                       "Worker lease expired while EXECUTING (uncertain
                                                        side effects) - reconciliation required"
```

The `EXECUTING` row was **not** adjudicated to a terminal outcome: no attempt attribution exists, and
inferring "harmless" from a capability name would be exactly the assumption the constitution forbids.
It is left in the non-runnable uncertainty state for an operator decision, and nothing was
resubmitted.

Backup: `/tmp/ciph_vault_backup_20261007_140652/` — a consistent `sqlite3.Connection.backup()`
snapshot plus the WAL/SHM copies. It was re-opened read-only and **serves the pre-mutation state**:
the three rows come back as `LEASED / EXECUTING / LEASED` with `live_permitless = 3`. Record:
`/tmp/ciph_vault_cutover_20261007_140652.json`.

WAL NOTE. `ciph_vault.db` is in WAL mode, so the main database file can stay byte-identical while
committed rows change — the reclaim landed in `-wal`, and the main-file digest (`8f200707…`) is the
same before and after. File digests are therefore weak evidence here; the meaningful record is the
logical one above, and the backup is verified by its CONTENT, not by its digest.

## Findings reported, not fixed

- **A live pre-S3 daemon owned the vault.** `PID 3327688`, `ciph_evolution.py --daemon`, started
  **2026-09-18** (18 days), 66 descriptors on `ciph_vault.db`, running pre-S3 code in memory - and
  actively working (its last expedition landed two minutes before it was retired). **Terminated**
  under explicit authorization; the replacement is recorded under OPERATIONAL CUTOVER below.
- **The test suite was writing the operator's live vault.** `test_ciph_contracts.py` built
  `CiphRuntime()` with no `db_path`, which defaults to `ciph_vault.db`, and executed a real
  `math.multiply` job against it — 14 permit-bearing rows in the live queue came from this. Fixed:
  the suite now builds a throwaway lane database and removes it. The proof is the queue itself: total
  427 / governed 14 / live_permitless 0 before and after a full 1168-test sweep. This is also why an
  earlier "read-only" inspection saw the queue move between two reads.

## Files changed

Production: `ciph/contracts/enums.py`, `ciph/contracts/execution.py`, `ciph/kernel/policy_engine.py`,
`ciph/kernel/execution_authority.py`, `ciph/kernel/execution_gateway.py`,
`ciph/kernel/retry_authority.py`, `ciph/kernel/retry_transaction.py`, `ciph/memory/event_store.py`,
`ciph/capabilities/registry.py`, `ciph/planner/dag_planner.py`, `ciph/runtime.py`,
`ciph/workers/daemon.py`, `ciph/workers/ipc_queue.py`, `ciph_matrix_audit.py`.

Fixtures/suites: `permit_test_support.py`, `phase5_test_support.py`, `test_ciph_contracts.py`,
`test_ciph_workers.py`, `test_gate0_adversarial_remediation.py`,
`test_gate0_barrier2_execution_tokens.py`, `test_gate_a0_authority_throat_scan.py`,
`test_gate_a0_execution_boundary_scan.py`, `test_gate_a0_execution_throat.py`,
`test_gate_a0_retry_transaction.py`, `test_phase2_reference_loop.py`,
`test_phase3_adversarial_recovery.py`, `test_phase6_internal_curiosity.py`,
`test_phase9_review4_remediation.py`.

New: `test_gate_a0_s3_constitutional_scanners.py`, `test_gate_a0_s3_hostile_matrix.py`,
`S3_CODE_SEAL.md`.

## OPERATIONAL CUTOVER (resident, not merely on disk)

| Step | Result |
| --- | --- |
| Terminate pre-S3 daemon | `PID 3327688` (started 2026-09-18) — graceful SIGTERM, exited in 800 ms, pid file removed |
| Restart on sealed code | `PID 828120`, started 2026-10-07T14:31:17, detached, current tree |
| Proof it executes current code | new cognitive blueprint `EXP-1791376290-428` written at 14:31:30 — 13 s after start |
| Read-only backlog gate | `live_permitless = 0` → PASS |
| Governed smoke on the live vault | PASS (below) |

```
job            JOB-1FCAC94B        outcome SUCCESS, job status SUCCEEDED
permit         permit_6265deba65d9 carried ON THE ROW, generation 0, replay policy bound
claim          attempt_3ab791524324 by worker_coordinator, claimed_at set
receipt names  attempt yes   permit yes   digest yes   generation yes
evidence       ATTRIBUTABLE  (exact-attempt read)
signature      valid against the trust registry
```

### Two things the smoke found

**1. The vault's key-encryption key is derived from the `db_path` STRING.** Opening the same file as
`/home/.../ciph_vault.db` instead of the relative `ciph_vault.db` produces a different KEK, so the
registered `execution_authority_primary` row cannot be decrypted (`InvalidTag`) and every governed
producer fails closed. That convention is part of the identity of every registered private key and is
invisible: the file is the same file. Not fixed here — a fix has to decide whether the identity is
the file or the string, and that is a migration, not a patch. Reported because any tool that opens the
vault by absolute path will hit it.

**2. A successful execution leaves its permit `CLAIMED`, never `CONSUMED`.** After the smoke the permit
row reads `CLAIMED` while the job reads `SUCCEEDED` and a signed receipt exists. Authority-wise this is
safe (a `CLAIMED` permit can never be claimed again), but observably it makes a *resolved* attempt look
*unresolved* to anything reading permit state alone. Continuity reconstruction therefore treats signed
terminal evidence as authoritative and never derives "resolved" from permit state — see 4.1 Gate Zero.
Whether the daemon should call `GuardedExecutor.terminalize` on the success path is an open question
for 4.1, not a silent change.

## CLONE GATE (workspace-only, read-only)

Sanitized clone at `/tmp/ciph_clone_20261007_150734/ciph_project`: code only — no `.git`, no
`ciph_vault.db`, no `ciph.key` / `ciph.salt` / `quantum.key`, no books/backups/staging, no logs.

```
clone full suite      1183 tests, OK
live vault before     FAILED 11, RECONCILIATION_REQUIRED 1, SUCCEEDED 417, permits 16, events 3020
live vault after      FAILED 11, RECONCILIATION_REQUIRED 1, SUCCEEDED 417, permits 16, events 3021
```

The single extra event is `NoRelevanceFoundEvent` for `EXP-1791377077-521` at 14:44:37 — the
**restarted production daemon's** own expedition, not the clone. Job and permit counts are identical,
so the clone ran without the vault and touched nothing live. Nothing was pushed, staged or committed;
the clone contains no git repository at all.

Two more ambient-vault leaks were found and fixed while proving that: `test_auth.py` was **writing
config into the live vault** (`CipherVault()` defaults to `ciph_vault.db`), and `test_dialogue.py`
created a vault in whatever directory the suite was started from (it runs at discovery time). Both now
use throwaway vaults, verified by running them and confirming the live vault's counts are unchanged.

## Remaining known limitations

- `ReplaySemantics` is outside the frozen V1 manifest hash by design, so the *declaration* is now
  pinned by the issuance binding rather than by the manifest identity. A future V2 manifest identity
  could fold it in; until then the binding is what carries the fact.
- `ciph_retry_tokens` remains load-bearing only for the legacy permitless lane. Governed retries write
  no lineage row, and `test_a_governed_retry_does_not_depend_on_the_retry_token_lineage` proves
  deleting the table changes no governed credit. It is deleted with the legacy seam.
- The legacy token lane itself still exists as a test-only seam (`enqueue_legacy_job_for_test`, one
  caller in `test_one_activation_per_lease_even_without_token`), and one live `RECONCILIATION_REQUIRED`
  permitless row remains by design.
- 4.1 is complete through Gate Five. Gate Zero (`ciph/kernel/continuity.py`) — deterministic cold-start
  reconstruction from canonical evidence only. Permit lifecycle closed: `CLAIMED` means "spent,
  unresolved", and resolution (machine or operator) consumes the permit. Gate One
  (`ciph/kernel/missions.py`) — durable mission identity and evidence-based completion. Gate Two —
  append-only plan projections with canonical fingerprint binding and "omission is not cancellation".
  Gate Three (`ciph/kernel/scheduler_recovery.py`) — eligibility derived from canonical state, never
  from a scheduler's memory. Gate Four — restart torture at eight boundaries plus a real killed process.
  Gate Five (`CiphRuntime.plan_mission` + `apply_plan_proposal`) — the real planner's `ExecutionDAG`
  becomes an immutable projection only after a freshness check against the mission digest, with
  identity allocated canonically and coverage distinguishing an exhaustive plan from a patch.
  See `CIPH41_GATE_ZERO_CONTINUITY.md`, `CIPH41_GATE_ONE_MISSIONS.md`, `CIPH41_GATES_TWO_TO_FOUR.md`,
  `CIPH41_GATE_FIVE_PLANNER.md`, and `REGISTER.md` for the `vault_id` migration decision.
