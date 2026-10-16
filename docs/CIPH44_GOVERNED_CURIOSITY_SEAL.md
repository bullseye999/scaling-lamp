# 4.4 Governed Curiosity — SEALED (Gates Zero → Four)

The constitutional question of this phase:

> **Given everything Ciph knows, does not know, and is uncertain about, which uncertainty is worth
> investigating — without curiosity itself becoming authority?**

The answer is a disciplined loop:

```
ignorance -> question -> authorized investigation -> evidence -> learning
```

and the constitutional thesis the phase had to prove:

> **Curiosity can desire information without acquiring authority to obtain it.**

## The gates

| Gate | Question | Module | Specimens |
| --- | --- | --- | --- |
| Zero | what is uncertain enough to deserve attention? | `ciph/kernel/uncertainty_registry.py` | 11 |
| One | which uncertainty is useful to reduce? | `ciph/kernel/curiosity_priority.py` | 9 |
| Two | how could it be reduced? | `ciph/kernel/curiosity_proposal.py` | 11 |
| Three | how does it actually happen? | `ciph/kernel/governed_investigation.py` | 8 |
| Four | did it actually reduce uncertainty? | `ciph/kernel/curiosity_learning.py` | 10 |
| — | does it COMPOSE? | `test_gate_4_4_cross_gate_torture.py` | 2 |

**51 specimens.**

New versioned identities, with nothing existing re-versioned:

```
CURIOSITY_PRIORITY_V1            Gate One (frozen weight tables, no learned weights)
CURIOSITY_INFORMATION_GAIN_V1    Gate Four (canonical movement only)
```

4.4 reads the 4.2/4.3 identities (`SOURCE_INDEPENDENCE_V1`, `CONVERGENCE_V1`,
`PREDICTION_CALIBRATION_V1`, `COUNTERFACTUAL_PROJECTION_V1`) and rewrites none of them.

## The anti-drift rules, as enforced properties

| Rule | How it is proven |
| --- | --- |
| Curiosity ≠ authority | Gate Two: create AND accept a proposal with jobs/permits/attempts/claims all 0 |
| Unknown ≠ worth investigating | Gate Zero: a bare model mention is not a target; Gate One: uncertainty alone scores low |
| Interesting ≠ valuable | Gate One: no interest/novelty term exists; ten model outputs move no score or digest |
| Proposal ≠ action | Gate Two: the proposal record contains no action/job/permit identity |
| Action ≠ authority | Gate Three: `prepare_investigation` creates an action with zero permits |
| Execution success ≠ epistemic success | Gate Three: `exit_code == 0`, permit `CONSUMED`, evidence count unchanged |
| Model output ≠ evidence | Gate Four: twenty model-written "insights" give `information_gain = 0` |
| Simulation ≠ observation | Gate Two: a `RUN_SIMULATION` proposal runs no simulation and writes no evidence |
| More questions ≠ information gain | Gate Four: the anti-reward-hacking specimen |
| Curiosity cannot score itself | Gate Four: the result is a pure function of before/after canonical state |
| All external effects use the 4.0 throat | Gate Three: source contains no signer, no `PermitStore.claim`, no second executor |
| Restart cannot duplicate investigation | Gate Three: claim → crash → restart → 1 job, 1 permit, attempt `UNRESOLVED` |
| "Do nothing" is a valid conclusion | Gate Two: `DO_NOTHING` is a first-class, recordable proposal |

## The cross-gate ladder, measured

One real epistemic problem, run through 4.2, 4.3 and all of 4.4, with a restart at the end:

```
4.2 / 4.3   service.c HEALTHY -> DEGRADED; H1 deployment, H2 upstream;
            two falsifiable predictions linked
4.4 Gate 0  both competing explanations DERIVE as uncertainties
4.4 Gate 1  a mission makes the causal question relevant -> score > 0
4.4 Gate 2  proposal created:      jobs 0 | permits 0 | mission actions 0
            proposal ACCEPTED:     jobs 0 | permits 0
4.4 Gate 4  the BEFORE state is frozen
4.4 Gate 3  prepare -> canonical ACT; jobs 0, permits 0
            authorize -> 1 job, 1 permit bound to that ACT
            GuardedExecutor -> exit_code 0 -> Observation
4.2         evidence admitted; prediction TRUE resolved, prediction FALSE resolved
4.3         H1 SUPPORTED, H2 REFUTED - on canonical evidence alone
4.4 Gate 4  before/after compared -> RESOLVED, information_gain > 0
RESTART     every 4.2 / 4.3 / 4.4 digest identical in a fresh process
```

And the hostile twin:

```
same problem, same proposal
operator NEVER authorises
RESTART

EXPECTED: proposal preserved historically (no decision)
          jobs 0 | permits 0 | attempts 0 | mission actions 0
          observations 0 | every digest unchanged
```

## Classified findings

**1. `ciph_observations` was claimed by two subsystems — found and closed.** The first integration of
the 4.2 ledger with the runtime failed in *both* directions: runtime-first broke the ledger
(`no column named source_ref`), ledger-first broke the runtime (`no such column: subject`). No 4.2 or
4.3 specimen had ever put a `CiphRuntime` and the ledger in one file, because every gate test used a
bare temporary database. Fixed by renaming the older, internal `MaterializedWorldview` table to
`ciph_mv_observations` (10 references, all in one module) and leaving the sealed ledger alone. Full
record in `REGISTER.md` R4; the legacy subsystem's 56 tests remain green.

**2. `WORSENED` had to be pinned to epistemic worsening, not error.** Gate Four originally distinguished
only "attempted" from "not attempted", which would have made a failed operation read as `UNCHANGED`.
An explicit operational status (`COMPLETED` / `FAILED` / `NOT_ATTEMPTED`) was added, stored separately
from the epistemic result, so an operation that fails before producing admissible evidence is
`INCONCLUSIVE`.

**3. The priority↔learning feedback is one-way, by construction.** `outcome_penalty` reads closed
canonical outcomes; the priority layer never writes one and never labels its own investigation barren.
The specimen asserts both the exact frozen weight (0.5) and that repeatedly recomputing the penalty
leaves the learning digest unchanged.

**4. A failed permit clock was a fixture bug, not a design bug.** Gate Three's first run raised
`PERMIT_ISSUED_IN_THE_FUTURE` because the fixtures used a fixed 2027 timestamp; the authority allows
only 300 s of clock slack. The fixtures now run in the recent past.

## What is deliberately NOT here

```
autonomous recurring curiosity      not in this phase; the loop is disciplined, not continuous
self-directed goal generation        a mission is still opened by someone
curiosity as a value source          relevance comes from canonical missions only
learned priority weights            the weight tables are frozen under CURIOSITY_PRIORITY_V1
curiosity inside 4.3                4.3 exposes uncertainty; 4.4 is what acts on it
Crucible / self-improvement          the next layer, built on this one
```

## Verification

```
4.4 gate suite                     51 specimens, green            (Ran 51, OK)
full project suite                 1436 tests, green             (+51 on the 1385 before this pass)
sanitized read-only clone          1436 tests, green; no ambient .db is created in the clone
legacy subsystem after R4          test_phase5_epistemic_stage1..4 + convergence + memory:
                                     56 tests, green
live vault                         unchanged and healthy:
                                     VAULT-0E79C7AFD84940BB / VAULT_ID_V1
                                     4 protected rows, all decrypt
                                     live_permitless = 0, s3_gate_satisfied = True
```

This pass wrote no file outside the project and `/tmp`; the live vault was opened strictly read-only,
and the sanitized clone was built and tortured instead of the live tree.
