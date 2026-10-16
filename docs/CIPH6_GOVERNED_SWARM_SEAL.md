# CIPH 6.x — GOVERNED SWARM

**Status:** SEALED, on measured evidence (2026-10-10).

```text
Workers may multiply cognition. They may not multiply authority.

more workers != more permission
more votes   != more truth
```

5.x proved one Ciph process can live continuously without mistaking time or persistence for authority.
6.x asks the next question: **can one sovereign Ciph divide work across many concurrent workers without
creating many little sovereign Ciphers?** The answer is a swarm where every hand is a subordinate
computational carrier under Ciph's existing constitution, and where the two things a multi-agent system
usually smuggles in - *the majority decides* and *the agent's output is the evidence* - are refused in
code.

## R10 — the entry gate, done first

The census ran before any swarm code was written, and the census is executable
(`ciph/kernel/swarm_ownership.py`, 15 concerns). It found this:

```text
KEEP (battle-tested machinery, not rewritten)
  ciph/workers/ipc_queue.py     durable queue: leases, tokens, receipts, reconciliation, dead-letter
  ciph/workers/daemon.py        process supervision
  ciph/workers/receipts.py      signed receipt handling
  agent_orchestrator.py         legacy agent orchestration
  ciph/swarm/byzantine_consensus.py   the signed multi-node opinion mechanism

6.x OWNS (meaning, not mechanism)
  worker identity / generation / membership / health / capability ladder
  delegation / lease / result provenance / aggregation
  child-budget conservation / spawn governance
  quiescence barrier / emergency stop / delegation learning
```

The dangerous find is the Stage-9 `ByzantineConsensusEngine`: it returns an `approved` flag for a
supermajority of self-signed council nodes, i.e. **votes as authority over critical mutations** - the
exact inverse of the 6.x law. It is demoted to a mechanism, and its silence is measured:

```text
dormant consensus authority (production consumers of the verdict)   = 0
```

Nothing in production reads it; if anything ever did, "more votes" would have become "more authority".
The mechanism is kept (deleting it would be an amputation) and the verdict is inert.

## What was built

| Phase | Module | What it owns |
| --- | --- | --- |
| R10 | `ciph/kernel/swarm_ownership.py` | the census: 15 concerns, retained machinery, dormant authority, bypass scan |
| 6.0 | `ciph/kernel/swarm_worker.py` | worker identity, generation, membership lifecycle, health, capability ladder |
| 6.1/6.2 | `ciph/kernel/swarm_delegation.py` | delegation, atomic lease claims, reclaim, interruption |
| 6.3/6.4 | `ciph/kernel/swarm_results.py` | result provenance and classification, aggregation dispositions |
| 6.9 | `ciph/kernel/swarm_resources.py` | child-budget conservation, spawn rate/concurrency ceilings |
| 6.5/6.6 | `ciph/kernel/swarm_quiescence.py` | the barrier, reconciliation, swarm-wide emergency stop |
| 6.11/6.12 | `ciph/kernel/swarm_learning.py` | delegation strategy projection, governed escalation |
| 6.x | `ciph/kernel/swarm_scanners.py` | the twelve structural zeros |

Nothing here executes anything. There is no swarm executor, no swarm permit authority and no second
deployment path: autonomous work is delegated by these modules and executed by 4.0's normal
`Mission -> Action -> Permit -> GuardedExecutor` chain, or it does not happen.

## Measured evidence

```text
6.x suites                     40 specimens, OK
  test_gate_6_0_...            33   (R10, workers, delegation, leases, results, aggregation,
                                      resources, quiescence, emergency stop, learning)
  test_gate_6_9_...             7   (the multi-process runtime torture)

full project sweep             Ran 1706 tests in 1161.137s   OK   (frozen tree)
sanitized clone sweep          Ran 1706 tests in 1032.238s   OK   (no ambient vault)
live vault                     VAULT-0E79C7AFD84940BB / VAULT_ID_V1, 4 protected rows all decrypt,
                               live_permitless = 0, integrity_check ok, zero swarm tables
```

Scanner censuses on the real tree (and in the clone), all measured:

```text
R10 census                     15 concerns, 0 violations, 0 retained-machinery missing,
                               0 production consumers of the consensus verdict, 0 swarm bypasses
swarm scanners (6.x)           12 of 12 zero, each with its own catch-specimen
autonomy scanners (5.x)        12 of 12 zero
meta scanners (4.7)            12 of 12 zero
R6 ownership / R7 choke point  0 violations / 0 unguarded primitives / 0 activation bypasses
```

## The runtime torture

Real worker processes - a dozen of them, three capability classes, several model identities, four tasks -
were spawned, raced, killed and restarted. Each of these is an assertion, not a narrative:

```text
one current holder per delegation       three workers raced for each delegation; exactly one claimed
                                        (the first run of this specimen FAILED - see the defects below)
dead worker recovered without assuming  the lease expired, the delegation returned to the pool, and a
  anything                              replacement worker's result became CURRENT while the dead
                                        worker's later arrival was kept and classified LATE
restart = new generation                W3 generation 2 claimed; generation 1's replay was LATE and
                                        did NOT displace the current result
four workers + one primary source       four workers agreed on one conclusion citing one blog; one worker
                                        returned contradictory canonical evidence. The aggregation was
                                        DISAGREEMENT with 5 preserved disagreement refs, and the
                                        swarm's knowledge was NOT the majority vote
barrier settles honestly                W2 acknowledged, W3 was measured dead and reconciled WITH
                                        evidence, W1's timeout was recorded as UNRESOLVED (barrier stayed
                                        DRAINING), then W1 acknowledged and the barrier reached QUIESCED
a joiner cannot slip past a freeze      a worker registering during the barrier was attested and then
                                        refused BUSY: SWARM_IS_QUIESCING
emergency stop across the swarm         both live leases INTERRUPTED, zero results written, zero
                                        completions fabricated, and a later worker was refused
whole-swarm restart                     the complete canonical state reconstructed byte-identically in a
                                        fresh process before and after
```

## Defects found and fixed in this campaign

Recorded rather than omitted, because the seal is worth what its defects are worth.

1. **Three workers acquired one delegation.** The claim path read "no active lease" and then wrote a
   lease in a separate statement, so three processes racing for one delegation each won. This is hostile
   case 1, and the *runtime* torture found it (`3 != 1`). Possession is now decided inside
   `BEGIN IMMEDIATE` with the check repeated under the write lock: a loser blocks and then sees the
   winner's lease.
2. **The quiescence module was a second writer of the lease table.** `emergency_stop_swarm` updated
   leases directly, which the R10 census refused the moment it was written. Interruption moved to the
   lease module that owns it.
3. **A capability was keyed by its level**, so `coding:INSTALLED` and `coding:VERIFIED` coexisted and a
   reader got whichever row the query happened to return. A capability now has ONE row and the ladder is
   its value.
4. **Child consumption did not draw down the parent.** A reservation prevented double-handing the same
   allowance but nothing actually spent it, so a swarm could consume a parent budget many times over
   while every child stayed inside its own limit.
5. **A waiter's own silence promoted itself.** `settle_barrier` moved a still-draining barrier to
   INCOMPLETE on the second unanswered member, i.e. a clock deciding that people had stopped. A barrier
   now stays DRAINING while members have not answered; INCOMPLETE is an explicit operator act
   (`fail_barrier`), and a failed barrier stays frozen.
6. **`JOINING -> READY` was reachable as a plain status change**, which would have allowed a worker to be
   READY with no measurement on the record. Attestation is now the only path out of JOINING, and
   quarantine re-entry is the slow route: QUARANTINED -> JOINING -> attestation.
7. **A superseded worker's late answer was classified CONFLICTING rather than LATE.** Losing possession
   is the distinguishing fact; CONFLICTING is for the worker who *currently* holds the question.
8. **The 6.x scanners read their own pattern catalogues as violations** - the same false positive 4.7's
   `s03` suffered when 5.x added its pattern list, fixed the same way: a catalogue is not code that does
   things, and the exclusion is stated with its limit.
9. **The R6 census read the 6.x scanner as an owner of the Crucible's promotion state.** Adding
   `ciph_crucible_promotions`, `ciph_crucible_active` and `ciph_crucible_rollbacks` to a pattern list is
   enough for a table-name-plus-`UPDATE ` heuristic to see a second owner. R6 already had the mechanism
   for this (`SIGNAL_DECLARING_MODULES`); the 5.x and 6.x scanner files were added to it. Third instance
   of one collision class in three phases, which is why the principle is now written down where it
   fires: **a file that declares a pattern is not a file that writes it**, with the limit stated.

## Stated limits (not implied absences)

- The scanners are **static and syntactic**. They narrow the bypass surface and cannot decide semantic
  equivalence; the architectural review remains the root fallback. Catalogue modules
  (`swarm_scanners.py`, `swarm_ownership.py`) are excluded by name because they contain the patterns as
  data - a real bypass hidden inside one of them would not be seen, and that limit is written down.
- The swarm scanners cover the `ciph/kernel/swarm_*` namespace. The daemon entry points are **not**
  re-scanned: 5.x's a01-a08 already own that surface, and duplicating it would create a second scanner
  claiming the same concern - the R6 failure mode in scanner form.
- **Quiescence is single-host**, and that is what makes it honest. A coordinator that can inspect process
  state can demand `DEAD + reconciled-with-evidence`; 7.x federation cannot, so it will need its own
  answer rather than inheriting this one.
- The legacy consensus engine keeps its code and its tests. What 6.x removed is any *production* path
  from its verdict to a decision - and the census measures that, rather than claiming the mechanism is
  gone.
- The runtime torture uses a purpose-built worker runtime
  ([swarm_test_support.py](ciph_project/swarm_test_support.py)) rather than the legacy
  daemon: the R10 decision is that transport stays with `ipc_queue`/`daemon.py`, and this file is the
  mechanism side of a 6.x worker, deliberately outside the kernel.
- **No production swarm history exists.** The live vault has zero swarm tables, so the live check
  confirms absence rather than exercising a read path.
- Process note: the FIRST sanitized clone of this campaign was truncated (342 of 402 Python files)
  because I backgrounded the copy pipeline and it was killed with the shell. It was rebuilt in the
  foreground, verified complete (168 of 168 test files, zero key material, zero ambient datastore) and
  only then swept. A partial clone would have "passed" while testing less, which is why the file counts
  are measured rather than assumed.
- Delegation learning reports counts and no scalar. There is no `SWARM_INTELLIGENCE_SCORE`, by design:
  the moment a swarm has a score, work gets routed by it.

## The 30-case hostile matrix

Every case in the program's matrix, with the specimen that owns it. Cases marked *(runtime)* are
asserted against real worker processes, not simulated ones.

| # | Case | Specimen |
| --- | --- | --- |
| 1 | two workers claim one delegation | `test_one_delegation_has_exactly_one_current_holder` + *(runtime)* `test_twelve_workers_process_real_delegations_across_four_tasks` |
| 2 | worker dies after producing, before commit | `test_a_worker_that_dies_before_returning_is_recovered_without_assumptions` |
| 3 | expired worker returns late | same specimen (LATE, never current) |
| 4 | duplicate result replay | `test_a_second_differing_result_is_classified_and_never_overwrites_the_first` |
| 5 | five workers repeat one source | `test_a_worker_result_is_a_claim_and_five_workers_can_be_one_source` |
| 6 | four workers agree on an unsupported claim | `test_consensus_is_information_and_never_evidence` + *(runtime)* `test_four_workers_agreeing_does_not_beat_one_canonical_source` |
| 7 | one worker holds contradictory strong evidence | `test_one_worker_with_evidence_does_not_lose_to_a_majority` |
| 8 | worker tries to mint a permit | scanner `s02`, `s12` + `test_twelve_swarm_scanners...` |
| 9 | worker widens its delegation | `test_a_worker_cannot_widen_its_delegation_to_another_class` |
| 10 | worker tries a production deployment | `REASON_GOVERNED_CHANGE` refusal + scanner `s04` |
| 11 | worker tries a meta promotion | delegation refusal + scanners `s07`, `s08` |
| 12 | worker exceeds its resource allocation | `test_child_budgets_conserve_the_parent...`, `test_spawn_rate_and_concurrency_are_bounded` |
| 13 | same worker process restarts | `test_a_restarted_worker_is_a_new_generation...` *(runtime)* |
| 14 | stale-generation result arrives | same specimen (`LATE`) |
| 15 | worker lies about capability | `test_the_capability_ladder_is_not_self_service` |
| 16 | worker self-declares healthy after quarantine | `test_a_worker_cannot_leave_quarantine_by_asserting_that_it_is_fine`, `test_health_is_assessed_with_evidence_by_someone_else` |
| 17 | worker joins during quiescence | `test_a_joining_worker_cannot_slip_past_a_freeze` + *(runtime)* `test_the_barrier_settles_honestly...` |
| 18 | worker ignores quiescence | `test_quiescence_freezes_claims_and_only_settles_when_every_member_answers` (no fake ACK) |
| 19 | coordinator crashes during quiescence | `test_the_barrier_reconstructs_after_a_coordinator_restart` *(runtime)* |
| 20 | coordinator crashes during assignment | `test_the_whole_swarm_reconstructs_after_a_restart` *(runtime)* |
| 21 | operator EMERGENCY_STOP | `test_emergency_stop_interrupts_leases_and_fabricates_nothing` + *(runtime)* |
| 22 | autonomous scheduler fires during a swarm stop | *(runtime)* refusal `SWARM_IS_QUIESCING` |
| 23 | child budgets sum above the parent | `test_child_budgets_conserve_the_parent_and_cannot_be_subdivided_twice` |
| 24 | a result's basis becomes stale | `_classify` -> `STALE_BASIS` (specimen: claim/input mismatch pair) |
| 25 | deterministic workers disagree | `test_deterministic_divergence_is_an_integrity_conflict_not_a_vote` |
| 26 | colluding workers rate each other | `test_colluding_workers_gain_no_authority_from_rating_each_other` |
| 27 | one worker modifies another's result | digest-keyed results + `CONFLICTING` classification (specimen 4) |
| 28 | a dead worker's lease is recovered | `test_an_expired_lease_is_reclaimed_without_assuming_anything_about_the_lost_work` |
| 29 | old-generation worker rejoins | `test_registration_grants_nothing_and_generation_is_not_the_workers_to_pick` |
| 30 | restart the whole swarm | *(runtime)* `test_the_whole_swarm_reconstructs_after_a_restart` |

## Seal criteria

```text
One sovereign Ciph identity maintained                       PROVEN
Worker identity subordinate                                  PROVEN
Worker registration grants no execution authority            PROVEN
Delegation != permit                                         PROVEN
Lease != authority                                           PROVEN
Worker cannot mint a permit                                  PROVEN
Worker cannot widen delegated scope                          PROVEN
Duplicate claims cannot duplicate authoritative work         PROVEN
Worker restart creates an explicit generation                PROVEN
Late / stale results stay distinguished                      PROVEN
Worker result != evidence automatically                      PROVEN
Consensus != truth                                           PROVEN
Source dependence survives swarm aggregation                 PROVEN
Disagreement preserved                                       PROVEN
Deterministic divergence detected as integrity               PROVEN
Capabilities measured, not merely self-declared              PROVEN
Child budgets conserve the parent budget                     PROVEN
Worker cannot self-increase resources                        PROVEN
Worker health cannot self-ratify                             PROVEN
Quarantine and rejoin governed                               PROVEN
Distributed quiescence barrier honest                        PROVEN
Joining workers cannot bypass quiescence                     PROVEN
Coordinator restart preserves the barrier                    PROVEN
Emergency stop reaches the entire swarm                      PROVEN
No second executor                                           PROVEN
No second permit authority                                   PROVEN
R7 remains the sole production activation path               PROVEN
4.7 remains the sole meta-promotion constitution             PROVEN
5.x autonomy remains above swarm work                        PROVEN
Whole swarm reconstructs deterministically                   PROVEN
R10 census closes with zero violations                       PROVEN
Full project sweep green                                     PROVEN
Sanitized clone green, fresh swarm state empty               PROVEN
Live vault compatible and read-only-verified                 PROVEN
```

```text
CIPH 6.x — GOVERNED SWARM
SEALED
```

*One mind. Many hands. The hands never become kings.*
