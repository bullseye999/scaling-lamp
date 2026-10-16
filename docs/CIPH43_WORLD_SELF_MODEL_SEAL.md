# 4.3 World + Self Model — SEALED (Gates Zero → Four)

4.1 answered *what is true about Ciph's own durable state?* 4.2 answered *what does Ciph believe
about the world, why, how certain, and what would change it?* 4.3 answers *what does Ciph model as
existing and changing, why might it have changed, what can it itself do, and what might happen if —
without any of those becoming a source of truth.*

```
I model this as currently true.        Gate Zero  world state, projected from epistemics
I observed this state transition.      Gate One   a bounded change, no invented instant
These are competing explanations.      Gate Two   causal hypotheses, credit only from tests
This hypothesis predicted X and was    Gate Two   REFUTED via 4.2 Gate Three
wrong.
I can do capability Y in environment   Gate Three the claim ladder, VERIFIED only by execution
E under manifest H.
I cannot currently establish Z.        Gate Three UNKNOWN / INSTALLED / AVAILABLE (all valid)
If assumption A changed, my model      Gate Four  a SIMULATION — never an observation
projects B.
```

## The gates

| Gate | Question | Module | Specimens |
| --- | --- | --- | --- |
| Zero | what exists, relates, or is unknown? | `ciph/kernel/world_model.py` | 9 |
| One | what changed from one state to another? | `ciph/kernel/world_dynamics.py` | 12 |
| Two | what might explain the transitions? | `ciph/kernel/causal_model.py` | 11 |
| Three | what does Ciph know about itself? | `ciph/kernel/self_model.py` | 10 |
| Four | what might happen under an intervention? | `ciph/kernel/counterfactuals.py` | 10 |
| — | do the gates COMPOSE? | `test_gate_4_3_cross_gate_torture.py` | 1 |

**53 specimens.**

Two versioned identities are added, and nothing existing is re-versioned:

```
COUNTERFACTUAL_PROJECTION_V1   Gate Four's model version
the Gate Zero/One/Two/Three status sets and the Gate Three claim ladder
                               are frozen functions, not tunable policy
```

No new *evidence* metric is introduced: 4.3 adds projections only. The 4.2 identities it consumes
(`SOURCE_INDEPENDENCE_V1`, `CONVERGENCE_V1`, `PREDICTION_CALIBRATION_V1`) are read, never rewritten.

## The anti-drift rules, as enforced properties

```
world model != source of truth     projecting entities/snapshots/revisions leaves the ledger digest
                                   byte-identical, in a loop
no FACT anywhere                   the world, causal, self and convergence status sets contain none
no invented time                   a change between two observations is a window; require_exact_time()
                                   refuses, on purpose
a refutation is not a state        an ABSENT fact can never be read as a state value (finding, below)
sequence is not causation          a hypothesis citing a real transition is still PROPOSED
prose is not evidence              model output moves no status, no claim level, no provenance
permission is not execution        AUTHORIZED is not VERIFIED; only a governed success verifies
manifest identity matters          H1 execution evidence does not verify H2
imagination is not reality         a simulation cannot modify world state, create evidence, issue
                                   authority, or create a prediction
curiosity is not here              4.3 EXPOSES uncertainty; it does not act on it (that is 4.4)
```

## The cross-gate ladder, measured

One phenomenon — *service.x degraded after deployment D* — through the whole stack, with a restart at
the boundary:

```
4.2     independent evidence: DEGRADED@T2     -> CONVERGED_SUPPORTED
4.3/0   world state                           -> DEGRADED (PRESENT)
4.3/1   bounded change                        -> HEALTHY -> DEGRADED somewhere in (T1, T2]
4.3/2   H1 deployment, H2 upstream            -> both PROPOSED
        two falsifiable predictions           -> linked, pending
4.3/4   simulate rollback                     -> projects recovery; canonical state, ledger and
                                                 prediction count all unchanged
RESTART every layer reconstructs identically in a fresh process
REAL    rollback; new observations            -> the predictions resolve
4.2     P(0.70) TRUE, P(0.80) FALSE           -> Brier = (0.09 + 0.64) / 2, from the ISSUED probabilities
4.3/2   H1 SUPPORTED, H2 REFUTED              -> no cause was "proven"
4.3/0   new state, old history intact         -> HEALTHY@T3 PRESENT; DEGRADED@T2 still PRESENT
4.3/3   diagnostics capability                -> VERIFIED only after a governed execution; the LLM's
                                                 claim of competence moved nothing
RESTART every digest identical, again
```

## Classified findings

**1. Dynamics read a refutation as a state — found and closed during this pass.** An early Gate One
admitted `PRESENT` *and* `ABSENT` facts as state values, so a refuted claim's asserted text was read
as the world's state. That fabricated a "recovery" the evidence denied, and in a second case produced
a transition with an **invented exact instant**. Fixed: only `PRESENT` establishes a world state;
dynamics now under-reports rather than inventing. Two specimens lock it down. Full reproduction in
`CIPH43_GATE_ONE_DYNAMICS.md`.

**2. Gate One under-reports when a state is only ever expressed as a refutation.** Encoding "offline"
as `is_online = True` refuted yields no transition; encoding it as `is_online = False` (present), as
Gate Zero's own founding specimen does, yields one. This is the deliberate, conservative direction,
not a defect — recorded so the asymmetry is not rediscovered as a surprise.

**3. `vault_id` (R1) boundary holds.** 4.3 introduces no key material and does not touch vault
identity; R1 remains closed and its multi-machine boundary unchanged.

**4. Curiosity stays out.** 4.3 may expose `UNKNOWN` relations, `CONTESTED` states, weak causal
hypotheses, poorly calibrated dynamics and self-model uncertainty. It acts on none of them.

## What is deliberately NOT here

```
FACT promotion                     the world is a projection; convergence has a policy id
causal credit from plausibility    only resolved predictions move a hypothesis
capability from code or prose      only governed execution verifies
self-scored performance            performance is execution evidence, never self-assessment
simulation as evidence             no import path exists from the counterfactual layer
attention/goal selection           4.4 Governed Curiosity asks which uncertainty is worth spending
curiosity inside 4.3               on; 4.3 only says where the uncertainty is
multi-machine key custody          R1's boundary, untouched here
```

## Verification

```
4.3 gate suite                     53 specimens, green            (Ran 53, OK)
full project suite                 1385 tests, green             (+53 on the 1332 before this pass)
sanitized read-only clone          1385 tests, green; no ambient ciph_vault.db is created
live vault                         unchanged and healthy:
                                     VAULT-0E79C7AFD84940BB / VAULT_ID_V1
                                     4 protected rows, all decrypt
                                     live_permitless = 0, s3_gate_satisfied = True
```

This pass wrote no file outside the project and `/tmp`; the live vault was opened strictly read-only.
