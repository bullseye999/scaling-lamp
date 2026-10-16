# 4.1 CONTINUITY SEAL

Status: **SEALED** through Gate Five. 4.0 remains sealed and resident beneath it.

## The finding this seal rests on

The foundational continuity problem is solved: nothing that can die is a source of truth.

```
process memory        non-authoritative
scheduler memory      non-authoritative
plan                  non-authoritative
cache / checkpoint    non-authoritative
transport token       non-execution-authority
                    --------------------------
canonical evidence    truth
mission               durable purpose
logical action        durable work identity
plan projection       durable strategy
permit                execution authority
```

## The five gates

| Gate | Question | Module | Specimens |
| --- | --- | --- | --- |
| Zero | what is TRUE? | `ciph/kernel/continuity.py` | 15 |
| One | what PURPOSE does it belong to? | `ciph/kernel/missions.py` | 12 |
| Two | what STRATEGY references that truth? | `ciph/kernel/missions.py` (projections) | 12 |
| Three | what may RUN next? | `ciph/kernel/scheduler_recovery.py` | 10 |
| Four | does it survive death at every boundary? | restart torture matrix | 10 |
| Five | can the REAL planner change strategy without changing truth? | `CiphRuntime.plan_mission` + `apply_plan_proposal` | 12 |
| — | permit lifecycle (`CLAIMED` = spent + unresolved) | `consume_permit_row` at all three resolution points | 6 |

**77 specimens.** Each gate's laws are listed in its own record; every law has a specimen that could
falsify it, and every scanner has a paired "would catch a violation" case.

## Evidence

| Measurement | Result |
| --- | --- |
| Captured full sweep (live tree) | **1332 tests, 0 failures, 0 errors, OK** |
| Sanitized clone, same suite | **1332 tests, OK** — and it creates no ambient vault |
| Live vault | 429 jobs, 16 permits, `live_permitless = 0`; unchanged by every run |
| Reverse-patched baseline (start of the 4.0 work) | 49 failing → 0, no new failing names |

## Properties proven, not asserted

```
restart creates no new facts                (journal + digest equality at every boundary)
same history -> same digest                 (in-process, cross-restart, and cross-PROCESS)
an unresolved claim stays unresolved        (same execution_attempt_id; never success or failure)
resolved authority is permanently dead      (CONSUMED; claim refuses afterwards)
a plan cannot rewrite history               (append-only projections; pointer moves only)
omission is a pause, never a cancellation   (action, authority and obligations untouched)
a truncated plan cannot pause anything      (PATCH coverage: absence means nothing)
a stale planner cannot commit               (basis digest inside BEGIN IMMEDIATE; zero side effects)
the planner cannot choose identity          (it proposes semantics; the canonical layer allocates)
the scheduler cannot invent work            (eligibility derived from canonical state only)
the worker cannot state a retry verdict     (safety and budget are derived centrally)
```

## Deliberate scope boundaries

- **Missions are opt-in.** `plan_mission` exists and is tested; every DAG execution becoming
  mission-scoped is a product decision and was not taken silently.
- **Plan ordering is not identity.** A projection is a set of action references; step ORDER belongs to
  the planner/DAG layer.
- **Completion blocks on live unattempted authority**, stricter than the minimum law: closing a
  purpose while one of its permits is still spendable would leave fresh authority attached to it.
- **`ciph_retry_tokens` remains legacy-lane only**; governed retries write no lineage row.

## R1 — CLOSED

The vault's cryptographic identity is now a `vault_id` bound in an authenticated header, and the
key-encryption key is derived from it rather than from the path the file happened to be opened with.
Migrated live on 2026-10-08 and proven: the same key decrypts at relative, absolute, dot-relative,
renamed and copied paths, a different `vault_id` cannot decrypt and never falls back, a tampered header
is an authentication failure, a crash mid-rewrap leaves the legacy representation authoritative with no
shadow rows, and three private keys that had been stored unencrypted since 2026-09-03 are now encrypted.
See `CIPH_R1_VAULT_IDENTITY_SEAL.md`.

Boundary that remains: the root secret is still machine-local. This makes a vault independent of its
**path**, not of its **machine**; multi-machine portability and federation still need a key-custody
decision of their own.

## Records

`CIPH41_GATE_ZERO_CONTINUITY.md`, `CIPH41_GATE_ONE_MISSIONS.md`, `CIPH41_GATES_TWO_TO_FOUR.md`,
`CIPH41_GATE_FIVE_PLANNER.md`, `CIPH_R1_VAULT_IDENTITY_SEAL.md`, `REGISTER.md`, and `S3_CODE_SEAL.md`
for the 4.0 layer beneath.
