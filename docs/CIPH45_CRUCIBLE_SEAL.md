# 4.5 Crucible — Governed Self-Improvement — SEALED

The Crucible answers one question:

> **When Ciph creates or receives a supposedly better strategy, model configuration, planner,
> capability implementation or reasoning policy, how does it prove that it is actually better before
> allowing it to replace what already works?**

It is the courtroom and the proving ground, not the evolutionary organism. In Ciph language:

```
Candidate != improvement
Benchmark win != general improvement
Score != truth
Trial != promotion
Promotion != execution authority
Self-assessment != evidence
```

## Entry Gate — production storage composition

`SEALED`. The read-only preflight found that the live vault still held the legacy
`MaterializedWorldview` observation table (**18 columns**, the legacy shape plus two additive-upgrade
columns) with the name the 4.2 ledger needs, so a ledger write against production was impossible.

That was found *before* the Crucible wrote its first durable record, which is what an entry gate is for.
Sequence applied to the live vault:

```
graceful daemon stop -> SQLite backup (49.8 MB) -> re-classify the live fingerprint immediately
before migrating (matched the proven value exactly, so no abort was needed) -> BEGIN IMMEDIATE ->
rename to ciph_mv_observations -> let the ledger create its canonical 6-column ciph_observations ->
verify row count and full-content digest -> COMMIT
```

Post-migration invariants on the live vault: `0` duplicate canonical owners, the ledger reconstructs
read-only, the vault identity is unchanged (`VAULT-0E79C7AFD84940BB` / `VAULT_ID_V1`), all protected
rows decrypt, `live_permitless = 0`, and the pre-migration backup still serves the exact original
state. Full record: `CIPH45_ENTRY_STORAGE_COMPOSITION.md`, `REGISTER.md` R5 (CLOSED).

## The gates

| Gate | Question | Module | Specimens |
| --- | --- | --- | --- |
| Entry | can all layers inhabit one runtime-shaped vault? | `ciph/kernel/schema_ownership.py` | 11 |
| Zero | what exactly is being evaluated? | `ciph/kernel/crucible_candidates.py` | 8 |
| One | how will it be judged, decided before it runs? | `ciph/kernel/crucible_protocols.py` | 7 |
| Two | can both subjects be tested equivalently? | `ciph/kernel/crucible_trials.py` | 6 |
| Three | was it actually better? | `ciph/kernel/crucible_metrics.py` | 9 |
| Four | when may it replace the baseline? | `ciph/kernel/crucible_promotion.py` | 7 |
| Five | does it survive reality? | `ciph/kernel/crucible_monitoring.py` | 4 |
| Six | who may generate candidates? | `ciph/kernel/crucible_generation.py` | 2 |
| — | does it COMPOSE? | `test_gate_4_5_cross_gate_torture.py` | 6 |

**58 specimens.** Shared vocabulary in `ciph/kernel/crucible_types.py`; no `crucible_god.py`, no
`self_improvement_engine.py`, no `autonomous_evolution.py`.

Frozen policy identities, from day one:

```
CRUCIBLE_CANDIDATE_ID_V1   CRUCIBLE_PROTOCOL_V1    CRUCIBLE_METRICS_V1
CRUCIBLE_PARETO_V1         CRUCIBLE_PROMOTION_V1   CRUCIBLE_POST_PROMOTION_V1
```

## The seal criteria, as enforced properties

| Property | How it is proven |
| --- | --- |
| Candidate ≠ improvement | Gate Zero has no score, rank or comparison surface at all |
| Candidate self-report ≠ evidence | declarations are absent from the identity payload and read by nothing |
| Candidate identity immutable | editing bytes/config yields a different id; a stale artifact is refused |
| Protocol frozen before results | the id is a pure function of the payload; any edit is a different protocol |
| Baseline and candidate comparable | one protocol, one environment, per-role trials under it |
| Candidate cannot edit evaluator | out-of-band edits are detected by payload re-derivation; trials refuse to close |
| Candidate cannot edit benchmark | same detection; a tampered protocol blocks promotion |
| Candidate cannot fabricate evidence | `NO_FABRICATED_EVIDENCE > 0` forces INVALID regardless of score |
| Hard failures non-tradeable | comparison short-circuits to INVALID; no weighting is consulted |
| No scalar score decides superiority | DOMINATES / DOMINATED / INCOMPARABLE / EQUIVALENT / INSUFFICIENT_EVIDENCE |
| Noise yields INSUFFICIENT_EVIDENCE | a band wider than the frozen minimum delta cannot be called equal |
| Evaluation ≠ promotion | the torture restarts with DOMINATES recorded and the pointer unmoved |
| Promotion ≠ execution authority | promotion creates 0 permits; the module has no execution surface |
| Candidate cannot self-promote | the only pointer-moving function requires an authorization reference |
| Promotion is append-only | pointer moves; the baseline record, the promotion and the rollback all persist |
| Production evidence can roll back | a REGRESSED assessment restores the previous candidate |
| Rollback preserves history | candidate, benchmark victory, regression and rollback all still readable |
| Restart changes nothing | candidate/protocol/trial/promotion/monitoring digests reproduced in a fresh process |
| Production-storage composition | the integration matrix, the scanner, and the migrated live vault |

## The ladder, measured

```
register B0 (H0) and C1 (H1)          two identities, C1's lineage pointing at B0
freeze protocol                       100 development + 50 sealed cases, 4 metrics, 3 invariants
3 repetitions per subject              6 trials, one frozen protocol, one environment
compare                               C1 DOMINATES B0 on all four dimensions
RESTART                               every digest identical; ACTIVE POINTER STILL UNSET
                                      -> better is not promoted
governed promotion                    operator authorization required; 0 execution permits created
RESTART                               every digest identical; active = C1
production regression                 C1 REGRESSED against its own promotion basis
governed rollback                     active = B0; nothing rewritten
RESTART                               every digest identical
```

## Classified findings

**1. R5 — production storage, found and closed.** See the Entry Gate above. The live vault was
migrated with proof, not hope.

**2. An exact-fingerprint classifier was blind to additive upgrades.** The live table carried two
columns added by an upgrade, so exact matching recognized it as *nobody's* table and would have
migrated nothing. Classification is now relational (`EXACT` / `EXTENDS` / `INCOMPATIBLE`) and matches
across names, because the production question is "which declared shape does this table have?", not
"is this the ledger's table?".

**3. The scanner invented a table called `if`.** Folding the optional `IF NOT EXISTS` into the name
capture let the regex backtrack onto the keyword when the name was a template placeholder
(`{HEADER_TABLE}`). A declaration now requires a real column list, and prose mentioning the idiom is
not parsed. Both properties are specimens.

**4. The promotion gate refused my own torture fixture — correctly.** It demanded 3 repetitions
because the protocol declared them, and the fixture had supplied 2 trials. The gate was right and the
fixture was wrong.

**5. A regression verdict named the wrong dimensions.** The monitoring layer reported an empty
regression list for a REGRESSED candidate; caught by the torture, fixed, and now asserted.

## What is deliberately NOT here

```
continuous autonomous self-rewriting     candidate generation is a PROPOSAL, never a mutation
unbounded recursive candidate generation  one candidate per explicit act
automatic architecture mutation           not modelled at all
automatic constitution rewriting          not modelled at all
automatic promotion without governance    authorization_ref is a required argument
cross-machine federation                  out of scope
swarm evolution / hardware mutation       out of scope
```

The Crucible does not write new code. It establishes whether a candidate *is* better. Giving Ciph a
richer internal candidate generator is the next phase, and it should come after natural selection
exists — not before mutation.

## Verification

Measured, not estimated.

```
4.5 suite                    58 specimens,  0 failures, 0 errors    (Ran 58, OK)
full project suite           1494 tests,    0 failures, 0 errors    (Ran 1494 in 1954.9s, OK)
sanitized read-only clone    1494 tests,    0 failures, 0 errors    (Ran 1494 in 1366.6s, OK)
ambient vault in clone       none - no ciph_vault.db, no key material, no backups
crucible clone assertion     fresh vault starts empty (0 candidates, no active pointer, 0 trials,
                             0 promotions, 0 rollbacks, 0 assessments) and no Crucible module
                             imports ciph.evolution / evolution_bridge / ciph_evolution /
                             ciph.crucible  (tools/crucible_clone_assertion.py)

production
  vault identity             VAULT-0E79C7AFD84940BB / VAULT_ID_V1
  storage composition        migrated; duplicate canonical owners = 0
  live_permitless            0
  protected rows decrypt     4/4
  pre-migration backup       serves the exact original state
  curiosity daemon           DISABLED BY PRODUCTION POLICY (CURIOSITY_DAEMON_ENABLED != "1")
```

This pass wrote to the live vault exactly once, deliberately: the authorized R5 migration.
