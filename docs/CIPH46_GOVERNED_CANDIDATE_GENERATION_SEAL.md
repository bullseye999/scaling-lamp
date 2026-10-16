# 4.6 — Governed Candidate Generation

The constitutional question:

> **Can Ciph recognize a bounded weakness in itself, formulate a falsifiable improvement hypothesis,
> construct a candidate in isolation, and hand it to the Crucible — without modifying the active system
> or grading its own work?**

The hierarchy this phase enforces, in every gate:

```
4.6 proposes         4.5 judges          governance promotes          evolution machinery deploys
```

and the one-line law the whole phase exists to make true:

> **Generation has creativity, but no standing.**

## Status

```
G0-G6 + torture                      IMPLEMENTED, 35 specimens green
R7 production choke point            CLOSED, 7 specimens green (real machinery)
cross-gate + hostile matrix          GREEN
suite-level proofs                   see Verification
4.6 SEAL                             EARNED - all four criteria measured
```

**R7 is closed.** The real production activation primitives now ask the constitution before they act:
`CanaryDeploymentManager.approve_production` (the file swap) and `EvolutionCoordinator._install` (the
revision registration) both require a canonical Crucible `PromotionRecord` for the exact candidate, and
the file swap additionally verifies the expected baseline before installing and the installed bytes
afterwards. The legacy lifecycle kept its machinery and lost its authority.

## The gates

| Gate | Question | Module | Specimens |
| --- | --- | --- | --- |
| Zero | what measured weakness exists? | `ciph/kernel/improvement_opportunities.py` | 7 |
| One | what change might address it, and what would falsify that? | `ciph/kernel/improvement_hypotheses.py` | 5 |
| Two | can it become an isolated artifact? | `ciph/kernel/candidate_construction.py` | 5 |
| Three | is it admissible at all? | `ciph/kernel/candidate_safety.py` | 3 |
| Four | can 4.6 hand it over and become a spectator? | `ciph/kernel/crucible_handoff.py` | 2 |
| Five | which generation strategies actually work? | `ciph/kernel/improvement_learning.py` | 4 |
| Six | what happens when the target is the machinery itself? | `ciph/kernel/meta_evolution.py` | 2 |
| — | does it compose? | `test_gate_4_6_cross_gate_torture.py` | 4 |

**35 specimens.** No `gap_detector` was rewritten, no second sandbox executor built, no second canary
manager. `ciph/evolution/` keeps the mechanism; the new modules own the meaning - which is the R6
architecture rule applied one level up.

Frozen identities, from day one:

```
IMPROVEMENT_OPPORTUNITY_V1     IMPROVEMENT_HYPOTHESIS_V1    CANDIDATE_CONSTRUCTION_V1
CANDIDATE_SAFETY_POLICY_V1     CRUCIBLE_HANDOFF_V1          IMPROVEMENT_STRATEGY_LEARNING_V1
META_EVOLUTION_BOUNDARY_V1     OPPORTUNITY_REPRODUCIBILITY_V1
```

## The load-bearing specimens

**A detector cannot invent a weakness.** A gap with one distinct receipt is refused
(`OPPORTUNITY_NOT_REPRODUCIBLE`); a gap with no evidence at all is refused
(`OPPORTUNITY_REQUIRES_EVIDENCE`); an operator may raise one and still has to cite something. There is
no function anywhere that accepts a model's dissatisfaction as a basis.

**More evidence does not mint more weakness.** A third failure enriches the same opportunity - the
identity basis is the *weakness* (component, revision, environment, symptom), not the pile of evidence
for it, so the registry cannot fill with duplicates of one problem.

**A moved baseline stales the hypothesis.** It is not silently re-based; the record still names the
baseline it was written against.

**Construction writes only inside staging, and only real bytes.** Containment is computed on the
resolved path, so `..`, symlinks and absolute paths are refused (`STAGING_ESCAPE_REFUSED`); writes are
atomic, so a crash leaves a `.partial` and never a registered candidate; and the live implementation's
bytes, the active pointer, permits, promotions and deployments are all asserted unchanged. The only
identity that results is the `CC-*` that 4.5 allocates.

**The safety review reads the diff, not the story.** A candidate described as "optimize planner
latency" whose changed files include `ciph/kernel/crucible_promotion.py` is
`REQUIRES_ARCHITECTURE_REVIEW`. Dependencies reaching a protected surface, and privilege deltas
(`signer`, `network`, `key_material`), count the same way.

**The generator cannot see the exam.** `generator_visible_view` exposes development cases, metric
definitions and the *count* of sealed cases - and there is no code path that returns a held-out answer,
so the firewall is structural rather than a filter someone could forget.

**A dominating candidate is not a promoted one.** In the torture, C2 dominates the baseline, every
digest is reproduced in a fresh process, and the active pointer is still unset.

**Benchmark dominance and production regression both survive.** After promotion and a production
regression, the strategy projection shows `dominates_count = 1` *and* `production_regressed_count = 1`.
The benchmark verdict was not rewritten, and the rollback did not erase the victory.

## The hostile matrix

| Attack | Result |
| --- | --- |
| detector invents a weakness | refused (`OPPORTUNITY_NOT_REPRODUCIBLE` / `OPPORTUNITY_REQUIRES_EVIDENCE`) |
| one noisy failure presented as reproducible | refused (versioned reproducibility policy) |
| hypothesis silently rebased to a new baseline | `STALE_IMPROVEMENT_HYPOTHESIS` |
| candidate writes outside staging | `STAGING_ESCAPE_REFUSED`, nothing registered |
| bytes changed after `CC-*` registration | `CANDIDATE_IDENTITY_MISMATCH` |
| candidate touches the Crucible or the constitution | `REQUIRES_ARCHITECTURE_REVIEW` |
| meta change hidden inside an unrelated diff | `META_EVOLUTION_REQUIRES_ARCHITECTURE_REVIEW` |
| generator says the candidate passed | zero standing: no such API exists |
| generator reads sealed held-out answers | no code path exists |
| one-dimensional win (faster, ten times the cost) | `INCOMPARABLE`, and 4.6 accepts it |
| duplicate generation attempt | cannot inflate strategy history (attempt identity dedupes) |
| construction failure | recorded as a generator failure; the hypothesis is untouched |

## What 4.6 deliberately does not do

```
no self-promotion                 4.6 has no pointer-moving API at all
no self-grading                   outcomes only arrive as Crucible comparisons
no sealed-corpus access           not merely filtered - unrepresentable in the view
no recursive generation           recursive_generation_enabled() is False
no meta targets as ordinary candidates   they are a separate request class
no constitution changes           4.0-4.5 untouched by this phase
```

## Verification

```
4.6 suite                     35 specimens, 0 failures, 0 errors
R7 choke-point suite           7 specimens, 0 failures, 0 errors
full project suite            1561 tests,  0 failures, 0 errors   (1128.2s)
sanitized read-only clone     1561 tests,  0 failures, 0 errors   (1017.0s, no ambient .db)
live vault                    untouched by 4.6 and R7 (no production write in this phase)

scanners
  unguarded activation primitives      0   (catch-specimen detects a synthetic unguarded one)
  direct activation bypasses           0
  legacy evolution suite               153 tests green after migration
```

## R7 - the production choke point, closed

```
approve_production  -> check_constitutional_promotion -> assert_expected_baseline
                    -> staging_manager.apply (the REAL file swap)
                    -> verify_installed_artifact -> PROMOTED, or DEPLOYMENT_INTEGRITY_CONFLICT
_install            -> check_constitutional_promotion -> register the revision, or refuse
```

Measured fallout and migration, taken empirically rather than guessed:

```
tests reaching production activation      6, in 2 files (Phase 8 workflow, Phase 9 remediation)
everything else in the legacy suite       147 tests, untouched - the canary stage never touched
                                          the production file, so it needed no promotion
migration                                 phase8_test_support gains `adopt_and_promote`: adopt the
                                          candidate into the Crucible and promote it, then run the
                                          legacy workflow. No compatibility fallback was added.
```

The hostile specimens, all against the real machinery:

```
valid legacy grant, no promotion     -> PRODUCTION_APPROVAL_REJECTED / NO_PROMOTION_RECORD,
                                        filesystem unchanged, pointer unchanged, no ACTIVATED event
promotion for a different candidate  -> NO_PROMOTION_RECORD
drifting target file                 -> ACTIVE_BASELINE_MISMATCH (refused before installing)
installed bytes are not the candidate-> DEPLOYMENT_INTEGRITY_CONFLICT
canonical pointer vs filesystem      -> DEPLOYMENT_INTEGRITY_CONFLICT, never silently resolved
```

and the real-machinery specimen: a real `EvolutionCoordinator`, the real canary manager, the real
staging manager, real `file_activation` bytes, a real `PromotionRecord` - the installer replaces the
baseline with exactly the candidate bytes, `verify_active_consistency` reports `CONSISTENT`, and the
real rollback restores the baseline physically.

Scanned, with catch-specimens: `unguarded_primitives()` reports an activation primitive that does not
call `check_constitutional_promotion`, and `activation_bypasses()` still reports zero direct
`file_activation.activate` call sites. Both are zero on the project, and the synthetic unguarded
primitive is detected - a scanner that never fires proves nothing.
