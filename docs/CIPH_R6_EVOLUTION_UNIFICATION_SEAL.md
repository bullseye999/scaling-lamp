# R6 — Single Evolution Lifecycle Ownership — SEALED

R4 was one table name with two owners. R6 was the same defect one level up: **one lifecycle with two
owners.** `ciph/evolution/` (Program-1 Phase 8/9) already implemented a complete, signed, operator-gated
improvement pipeline, and the 4.5 Crucible implemented the same lifecycle again.

## The decision

```
TARGET ARCHITECTURE   Option A - ciph/evolution becomes the MACHINERY,
                                 the Crucible remains the CONSTITUTION
MIGRATION METHOD      Option C adapters (temporary, not the end state)
REJECTED              Option B - rebuilding battle-tested machinery
```

The core law:

> **There may be many mechanisms for testing and deploying candidates, but exactly one constitutional
> owner for candidate identity, comparative standing, promotion, active state and rollback lineage.**

The old side mostly held *mechanisms* (sandbox candidate execution, benchmarking, file activation,
canaries, recovery, signed grants). The new side holds the *canonical meaning*. So the constitution
absorbs the machinery rather than replacing it.

## The ownership census (Gate A, executable)

| Concern | Canonical owner | Legacy ownership allowed |
| --- | --- | --- |
| candidate identity | `crucible_candidates.py` | NO |
| evaluation protocol | `crucible_protocols.py` | NO |
| trial identity | `crucible_trials.py` | NO |
| comparison verdict | `crucible_metrics.py` | NO |
| promotion state | `crucible_promotion.py` | NO |
| active candidate pointer | `crucible_promotion.py` | NO |
| rollback lineage | `crucible_promotion.py` | NO |
| regression verdict | `crucible_monitoring.py` | NO |
| deployment record | `evolution_deployment.py` | NO |
| raw sandbox execution | `isolated_execution.py` | YES |
| benchmark mechanism | `benchmark_harness.py` | YES |
| dependency and resource review | `review.py` | YES |
| physical installation mechanism | `file_activation.py` | YES |
| canary measurement mechanism | `canary_manager.py` | YES |
| workflow orchestration | `evolution.workflow` | YES |

Measured on the project:

```
ownership violations                     0
direct file-activation bypasses          0
retained machinery missing               0
distinct constitutional owners           7
```

Every `NO` is scanner-enforced, and the scanner has catch-specimens - a synthetic second owner, a
synthetic activation bypass and a synthetic deletion are all detected, so the scan is not vacuous.

**Coverage is stated, not implied.** The scanner flags UNIQUE names (`ciph_crucible_active`,
`CRUCIBLE_PARETO_V1`, ...). It deliberately does not flag generic words like `STATUS_INVALID`, which
unrelated 4.2/4.5 modules legitimately define in their own domains. A scanner that cries wolf is worse
than one whose narrower coverage is written down.

## The gates

```
A  ownership census          executable matrix + scanners + catch-specimens       7 specimens
B  candidate identity         adopt_legacy_candidate -> ONE CC-* identity         3 specimens
C  evaluation adapter         legacy grant -> TrialRun; no legacy verdict path     3 specimens
D  deployment choke point     GovernedDeploymentGateway; installer never cold      4 specimens
E  canonical active state     pointer is canonical; filesystem corroborates        1 specimen
F  canary + rollback adapter  verdict from monitoring; pointer moves first         2 specimens
-  naming                     RedShadowHarness, RedShadowCrucible legacy alias     -
-  torture                    legacy lifecycle end to end, restarts included       2 specimens
```

**25 specimens**, in `test_r6_ownership_census.py`, `test_r6_deployment_gateway.py`,
`test_r6_evolution_adapters.py`, `test_r6_cross_gate_torture.py`.

## Seal conditions, measured

| Condition | Result |
| --- | --- |
| canonical candidate identity owners | 1 |
| canonical protocol owners | 1 |
| canonical comparison owners | 1 |
| canonical active-pointer owners | 1 |
| canonical promotion owners | 1 |
| canonical rollback-lineage owners | 1 |
| legacy raw execution machinery | retained |
| legacy benchmarking machinery | retained |
| legacy activation mechanism | retained |
| legacy canary mechanism | retained |
| direct legacy promotion authority | 0 |
| direct file activation bypass | 0 |
| legacy self-approved deployment | 0 (`NO_PROMOTION_RECORD`) |
| filesystem-as-canonical-active-state | 0 (`DEPLOYMENT_INTEGRITY_CONFLICT`) |

## The load-bearing specimens

**A valid authorization with no promotion deploys nothing.** In the torture, a deployment carrying a
legacy-style signed authorization reference and no `PromotionRecord` is refused on the constitutional
question, the injected installer is never called, and the active pointer does not move. Promotion is
checked FIRST, so the refusal names the constitutional reason rather than a mechanical one.

**The mechanism is cold on every refusal path.** The installer records its calls; every refusal
specimen asserts the call list is empty. That is what a choke point means: the machinery cannot run
before the constitution says yes.

**The canonical pointer moves before any byte is restored.** `governed_rollback` performs the canonical
decision and only then invokes the restore mechanism, and the specimen proves the ordering by observing
the active pointer *from inside* the restore callback.

**A changed artifact cannot inherit an identity.** A legacy candidate is adopted once; editing the
artifact adopts a new candidate, and a stale hash is refused with `CANDIDATE_IDENTITY_MISMATCH`.

## What R6 deliberately does not do

```
no 4.6 code                 candidate generation is not started here
no machinery deleted        the demoted modules are asserted present, symbol by symbol
no real file swap wired     the gateway takes an injected installer; production wiring to the
                            legacy activation path is a separate, deliberate step
no Constitution rewrite     nothing in 4.0-4.5 changed
```

The real legacy activation path is `EvolutionCoordinator._install()` registering a revision capability
after `canary_manager.approve_production()`. R6 puts that path behind the gateway conceptually and
proves no direct route exists (`file_activation.activate` still has zero call sites); wiring the
gateway's installer to that path for real is the remaining integration step, and it is deliberately
left visible rather than smuggled in.

## Verification

Measured, not estimated.

```
R6 suite                      25 specimens, 0 failures, 0 errors
full project suite            1519 tests,  0 failures, 0 errors   (1181.8s)
sanitized read-only clone     1519 tests,  0 failures, 0 errors   (1050.8s)
ambient vault in clone        none; ciph.salt regenerated inside the clone (create-if-missing),
                              live ciph.salt untouched (timestamp unchanged)
R6 census inside the clone    0 violations, 0 bypasses, 0 missing machinery, 7 owners
fresh vault inside the clone  0 legacy bindings, 0 deployments

production
  live vault                  untouched by R6 - no production write in this gate
```

### One measurement worth recording

The first full sweep of this gate returned `Ran 1519 ... FAILED (failures=2)`: two wall-clock budget
assertions in `test_ciph_matrix_audit.py` (7.0s against a 6.0s budget, 20.1s against 15.0s). That module
passes in isolation (3 tests, 8.5s), the machine carried a load average of 1.5-3.1 with eleven logged-in
users, and the same sweep ran in 2321s on the loaded pass against 1182s on the quiet one. The failures
were ambient contention, not a defect - and the seal rests on the clean re-run, not on the excuse.
