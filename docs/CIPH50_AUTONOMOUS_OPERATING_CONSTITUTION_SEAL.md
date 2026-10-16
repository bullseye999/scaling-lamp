# CIPH 5.x — CONTINUOUS GOVERNED AUTONOMY

## AUTONOMOUS OPERATING CONSTITUTION

**Status:** SEALED, on measured evidence (2026-10-10).

```text
Continuity grants persistence, NOT permission.
A wake-up is not authority.
```

Everything in 5.x follows from that one sentence. A process that wakes up, that has been running for a
week, or that holds a standing authorisation does not thereby hold the right to act: it holds the right
to be *reconsidered*. 4.0 already said a mission is not authority, 4.4 already said uncertainty is not a
licence to investigate, and 4.7 already said a candidate cannot ratify itself. 5.x adds the last shape
of that idea - **time is not authority either**.

```text
4.0  Execution Constitution          SEALED
4.1  Continuity                      SEALED
...
4.7  Meta-Evolution                  SEALED
R8   Meta-Evolution Register         CLOSED
5.0  Autonomous Operating Const.     SEALED   <- this seal
5.1  Mission Stewardship             SEALED
5.2  Temporal Governance             SEALED
5.3  Attention / Priority            SEALED
5.4  Resource & Risk Budgets         SEALED
5.5  Interrupts & Quiescence         SEALED
5.6  Autonomous Maintenance          SEALED
5.7  Continuous Curiosity/Improvement SEALED
5.8  Autonomy Calibration            SEALED
5.9  Autonomy Torture                SEALED
```

## What was built

| Phase | Module | What it owns |
| --- | --- | --- |
| 5.0 G0 | `ciph/kernel/autonomous_work.py` | `AutonomousWorkIntent`, work-class risk table, duplicate-tick identity, temporal window |
| 5.0 G1 | `ciph/kernel/standing_authorization.py` | bounded persistent authority; **only an operator may grant**; revocation |
| 5.0 G2 | `ciph/kernel/autonomy_eligibility.py` | `AUTONOMY_ELIGIBILITY_V1`, the pure eligibility function and the stop reasons |
| 5.0 G3/G6/G9 | `ciph/kernel/autonomy_session.py` | durable sessions, constitutional idleness, the `autonomy_state` audit chain, calibration |
| 5.0 G7 | `ciph/kernel/autonomy_modes.py` | the operator control plane; effective mode = most restrictive assertion |
| 5.2 | `ciph/kernel/autonomy_schedule.py` | recurrence, backoff, clock certainty, per-period work identity |
| 5.3 | `ciph/kernel/autonomy_priority.py` | deterministic arbitration, operator override outranking every computed factor |
| 5.4 | `ciph/kernel/autonomy_budgets.py` | rolling-window budgets; only governance may raise a limit |
| 5.5 | `ciph/kernel/autonomy_interrupts.py` | quiesce / stop / emergency stop against live work; DRAIN refusal |
| 5.6/5.7 | `ciph/kernel/autonomy_maintenance.py` | the maintenance programme, the `PROMOTION_READY` ceiling, the curiosity grounding |
| 5.0/5.x scanners | `ciph/kernel/autonomy_scanners.py` | the twelve structural zeros |

No new executor, no second permit authority, no second deployment path: autonomous work is proposed by
these modules and executed by 4.0's normal `Mission -> Action -> Permit -> GuardedExecutor` chain, or it
does not happen.

## Measured evidence

```text
5.x suite                      69 specimens, OK
  test_gate_5_0_...            16
  test_gate_5_1_...            11
  test_gate_5_2_...            11
  test_gate_5_5_...            11
  test_gate_5_6_5_7_...         9
  test_gate_5_9_...            11   (the program torture)

full project sweep             Ran 1666 tests in 1109.857s   OK   (frozen tree)
sanitized clone sweep          Ran 1666 tests in 1019.826s   OK   (no ambient vault)
live vault                     VAULT-0E79C7AFD84940BB / VAULT_ID_V1, 4 protected rows all decrypt,
                               live_permitless = 0, integrity_check ok, zero autonomy tables
```

Scanner censuses on the real tree, both measured:

```text
autonomy scanners (5.x)        12 of 12 zero, each with its own catch-specimen
meta scanners (4.7)            12 of 12 zero, catch-specimens unchanged and passing
R6 ownership violations        0        R6 retained-machinery missing   0
R7 unguarded primitives        0        R7 activation bypasses          0
duplicate canonical owners     0        schema-ownership scan           clean
```

The twelve 5.x invariants:

```text
a01 raw autonomous executor                       0
a02 daemon direct permit claim                    0
a03 daemon direct file activation                 0
a04 autonomy private signer                       0
a05 autonomy creates StandingAuthorization        0
a06 autonomy overrides operator mode              0
a07 autonomous production deploy outside R7       0
a08 autonomous meta promotion outside 4.7         0
a09 autonomy spawns a process                     0
a10 autonomy deletes canonical history            0
a11 charter purpose is rewritten                  0
a12 maintenance mutates the environment           0
```

## The founding torture, and the eighteen hostile cases

The founding torture runs a real maintenance mission end to end: standing authority -> eligibility ->
session -> consumption -> evidence -> report -> session closed; then the same wake again inside the same
budget window is refused for want of *budget*, and the next day's window restores the allowance without
anybody approving anything.

| 5.0 hostile case | Specimen |
| --- | --- |
| 1. wake with no standing authority | `test_hostile_no_authority_expired_and_revoked` |
| 2. expired authorisation | same specimen (now answers `EXPIRED`, not "unauthorized") |
| 3. stale mission basis | `test_hostile_stale_basis_and_completed_mission` |
| 4. scheduler fires twice -> one identity | `test_hostile_duplicate_wakes_are_one_work_identity` |
| 5. restart during permit claim -> no duplicate | `test_hostile_restart_reconstructs_the_exact_autonomy_state` |
| 6. intent widens scope | `test_hostile_scope_widening_and_prohibited_work_classes` |
| 7. prohibited work class | same specimen |
| 8. curiosity tries to deploy | same specimen + `a07` |
| 9. improvement "DOMINATES" but may not deploy | `test_continuous_cycle_stops_at_promotion_ready_and_never_promotes` |
| 10. budget reaches zero | founding torture |
| 11. operator QUIESCE -> no new permits | `test_hostile_operator_modes_override_everything` |
| 12. operator AUTONOMY_OFF -> zero work | same specimen |
| 13. no useful work -> IdleDecision | `test_hostile_conflicting_work_and_idleness` |
| 14. stale schedule after a completed mission | `test_hostile_stale_basis_and_completed_mission` |
| 15. conflicting missions need arbitration | `test_hostile_urgency_is_not_authority` |
| 16. daemon cannot mint standing authority | `test_hostile_a_daemon_cannot_lower_an_operator_hold_or_mint_authority` |
| 17. "urgent" is not authority | `test_hostile_urgency_is_not_authority` |
| 18. restart reproduces autonomy state exactly | `test_hostile_restart_reconstructs_the_exact_autonomy_state` |

## The program torture (5.9)

Thirty accelerated days of one live cadence against one datastore, with a second mission added and then
abolished, an operator hold every week, a dependency outage, a resource squeeze, an improvement cycle
that reaches the ceiling, an interrupt that lands mid-attempt, a process restart mid-history, and
stretches where nothing is worth doing.

Proven in that run, each as an assertion rather than a narrative:

```text
no authority drift            the effective mode is NORMAL at day 30, and no non-operator ever asserted a
                              permissive mode
no duplicated execution       one session per wake; one logical work item per session; no repeated pair
no zombie cadence             the abolished mission's cadence was never reconsidered again
no runaway curiosity          three extra ticks at an idle instant offered no runnable work and opened
                              no session
no runaway spending           each cadence period is its own work identity, and the budget refused the
                              extra wake inside the spent window
no silent production deploy   zero epochs exist; the promotion-ready notice carries may_promote = False,
                              may_deploy = False and requires_operator_authorization = True
no rewritten history          the interrupted session, its unresolved attempt and every intervention are
                              still present
```

The end-to-end reconstruction is checked at five boundaries (before the nomination, after it, at session
open, after the spend, after the settlement), each by a **fresh process**, with the local state asserted
equal - and then the whole thirty-day history is reconstructed one more time at the end.

## Defects found and fixed in this campaign

The seal is worth what the defects in it are worth, so they are recorded rather than omitted.

1. **The daemon could record a permissive mode while the operator held one.** `set_mode`'s guard was
   written as a comparison against the wrong floor, so a non-operator asserting `NORMAL` under an
   `EMERGENCY_STOP` was accepted. Relaxation is now an operator act: a non-operator may only assert a
   mode at least as restrictive as the one in force. (Found by `test_hostile_a_daemon_cannot_lower...`.)
2. **A lapsed grant answered `BLOCKED_NO_AUTHORITY`.** "You were never granted this" and "your grant ran
   out" are different facts, and only the second is repaired by a clock. `EXPIRED` is now its own
   outcome with `AUTHORITY_EXPIRED` as its stop reason. (Found by the same specimen.)
3. **An exactly-on-time wake was classified `UNCERTAIN`.** With no uncertainty declared, the certainty
   test used a strict comparison, so a punctual due looked doubtful and a thirty-day cadence refused to
   run. `>=` is the correct comparison against the band the schedule declared. (Found by the 5.9
   torture.)
4. **A cadence nomination stayed perpetually due.** The work identity was derived without the due
   moment, so one nomination was offered as runnable at every instant after it fired, and a daily review
   could be turned into continuous activity. Each cadence period is now its own identity (two ticks of
   the *same* period remain one) and its usefulness is bounded by one interval, so a stale nomination
   lapses instead of haunting the loop. (Found by the 5.9 idle assertion.)
5. **A session work item could never be resolved.** `record_session_work` ignored a re-record, so an
   attempt's evidence could never be attached and `DRAIN_REQUIRED` could never be cleared. Re-recording
   now completes the same logical item, only ever filling a gap - a resolution already recorded is never
   overwritten. (Found by the 5.5 settle specimen.)
6. **A retried interrupt reported a change it had not made.** The quiesce branch re-stopped already
   quiescing sessions and reported `changed` from intent rather than from the record. (Found by the 5.5
   idempotency specimen.)
7. **4.7's `s03` read the 5.x pattern catalogue as a caller.** 5.x's scanner must contain
   `transition_epoch(` as *data*, and 4.7's caller scanner fired on the pattern instead of on a bypass.
   Scanner modules are now explicitly not read as callers, and a specimen proves the exclusion is
   narrow: a module that really calls the symbol is still caught. This is the same class of
   between-phase collision as the R4 table and the R6 census defects - it appeared only when the two
   phases' surfaces touched.

## Stated limits (not implied absences)

- The scanners are **static and syntactic**. They narrow the bypass surface; they cannot decide semantic
  equivalence, and the architectural review remains the root fallback - exactly as with 4.5-4.7.
- `a09` (process spawning) and `a12` (environment mutation) cover the **autonomy namespace only**. The
  pre-5.x daemon entry points (`ciph_evolution.py`, `run_ciph.py`) still spawn processes and still
  mention package installation; they are governed by the R6 ownership census and the R7 choke point, and
  5.x has not migrated them. Claiming them here would be a scanner asserting a property over code it
  does not own.
- **No production autonomy history exists.** The live vault has zero autonomy and zero meta tables, so
  the live check confirms *absence* rather than exercising a read path. Nothing was written to the live
  vault to make the verification look better.
- The dependency outage in the torture is modelled as an operator `READ_ONLY` hold plus a refusal of an
  external-effect class; it is not a simulated network partition.
- Quiescence is a **single-host** protocol: it settles this datastore's sessions and refuses new permits.
  It is not a distributed consensus protocol, and 6.x (Swarm) will need its own answer for that.
- The sweep leaves gitignored scratch datastores (`*.db`, `*.db-wal`) in the working directory; these are
  legacy-suite byproducts, are excluded from the sanitized clone, and are not project state.
- Process note: the first full sweep began 29 seconds after the last source write (12:55:25 and
  12:55:54), which is close enough that "the tree was frozen" would have been an assumption rather than a
  measurement. The cited run therefore started 46 minutes later, began from a tree whose newest Python
  file predates it, and is accompanied by a check that no `*.py` file changed while it ran. The two runs
  agree (1666 tests, OK, 1122.4s and 1109.9s); the second is the one the seal cites.

## Seal criteria

```text
Autonomous wake != authority                        PROVEN
Standing authorization explicit and bounded         PROVEN
Autonomous intent cannot widen authority            PROVEN
Eligibility deterministic                           PROVEN
Autonomous work uses the normal 4.0 path            PROVEN
No second executor                                  PROVEN
No second permit authority                          PROVEN
Duplicate wake cannot duplicate action              PROVEN
Restart cannot duplicate attempt                    PROVEN
Resource exhaustion stops new work                  PROVEN
Operator mode overrides autonomy                    PROVEN
Quiescence stops new permits                        PROVEN
Idleness is a valid outcome                         PROVEN
No-useful-work creates zero fake activity           PROVEN
Completed or abandoned mission blocks stale work    PROVEN
Curiosity cannot bypass 4.4 / 4.0                   PROVEN
Improvement cannot bypass 4.5 / R7                  PROVEN
Meta evolution cannot bypass 4.7 / R7               PROVEN
Recovery uses canonical 4.1 state                   PROVEN
Cross-process autonomy state deterministic          PROVEN
Twelve structural scanner invariants = 0            PROVEN
4.5 / 4.6 / R6 / R7 / 4.7 regressions green         PROVEN
Full project sweep green                            PROVEN
Sanitized clone green, fresh state empty            PROVEN
Live vault compatible and read-only-verified        PROVEN
```

```text
CIPH 5.0 — AUTONOMOUS OPERATING CONSTITUTION
SEALED
```

*Ciph has a mind. 5.x is the beginning of the organism: the same mind, continuing, under the same law,
with the clock added to the list of things that are not authority.*
