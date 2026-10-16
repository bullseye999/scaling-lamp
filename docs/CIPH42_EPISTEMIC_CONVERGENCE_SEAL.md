# 4.2 Epistemic Convergence — SEALED (Gates Zero → Four)

4.1 answered *what is true about Ciph's own durable state?* 4.2 answers *what does Ciph believe about
the world, why, how certain, and what would change it?* — with the distinctions that are routinely
collapsed kept apart at every step:

```
I observed this.                      Gate Zero  observation
I was told this.                      Gate Zero  claim
I have evidence for this.             Gate Zero  evidence + belief projection
These sources are/aren't independent. Gate One   source dependence
I currently believe this.             Gate Zero  belief + confidence
I inferred this.                      Gate Two   inference lineage
I predicted this.                     Gate Three prediction + calibration
I was right / wrong.                  Gate Three resolution + Brier
The evidence converged.               Gate Four  CONVERGENCE_V1
The evidence conflicts.               Gate Four  CONTESTED
I genuinely do not know.              Gate Four  UNRESOLVED (a valid terminus)
```

## The gates

| Gate | Question | Module | Specimens |
| --- | --- | --- | --- |
| Zero | what evidence bears on P? | `ciph/kernel/epistemic_ledger.py` | 16 |
| One | how independent is that evidence? | `ciph/kernel/source_dependence.py` | 15 |
| Two | how did the position change, and what reasoning produced it? | `ciph/kernel/belief_revision.py` | 14 |
| Three | what did Ciph expect, and was it right? | `ciph/kernel/predictions.py` | 12 |
| Four | has it converged, or is "we don't know" the answer? | `ciph/kernel/epistemic_convergence.py` | 13 |
| — | do the gates COMPOSE? | `test_gate_4_2_cross_gate_torture.py` | 4 |

**74 specimens.** Each gate's laws are listed in its own record, and every metric/policy carries an
explicit version identity:

```
belief confidence          frozen at Gate Zero, untouched by every later gate
SOURCE_INDEPENDENCE_V1     Gate One
CONVERGENCE_V1             Gate Four (a pure function, so it can be read and tested)
PREDICTION_CALIBRATION_V1  Gate Three (Brier over RESOLVED predictions only)
```

## The anti-drift rules, as enforced properties

```
Gate Zero is not reopened          every later gate asserts the ledger digest it does not move
no source reputation in Gate One   counts originate from provenance, never from reliability
inference never becomes evidence   ten inferences: evidence count 1, confidence unchanged
V1 predictions are binary          a prediction resolves TRUE / FALSE / UNRESOLVED, nothing else
no reputation weighting in V1      calibration is diagnostic metadata, not an evidence weight
there is no FACT state             Gate Four's status set and public surface contain none
model output mutates nothing       shouting at all four gates moves no digest (torture specimen)
projections are reconstructible    delete the projections: Gate Zero, One and Four digests unchanged
                                   replay the revision history: the same revisions, ids included
every metric is versioned          four ids above, each frozen
```

## The cross-gate ladder, measured

One proposition through all four gates, then a restart:

```
E1 SUPPORTS P                            Gate Zero: SUPPORTED
+ 3 reports derived from E1              Gate Zero: 4 links;  Gate One: 1 proven origin
+ independent primary                    Gate One: 2 proven origins
                                         Gate Four: CONVERGED_SUPPORTED
model infers Q from P                    Gate Two: inference pinned; Gate Zero evidence +0
predict P, p = 0.8, basis H0             Gate Three: frozen
independent contradiction arrives        Gate Zero: CONTESTED; Gate One: 2 vs 1;
                                         Gate Four: CONTESTED, with CONVERGED_SUPPORTED still in history;
                                         the old inference is STALE, still pinning its premise version
prediction resolves FALSE                Gate Three: Brier = 0.64 from the ISSUED 0.8
restart / second process                 every gate's digest identical
```

## What is deliberately NOT here

```
FACT promotion                    convergence is a projection with a policy id
source/predictor reputation       a well-calibrated source does not get extra evidential weight
inference-as-evidence             the echo-chamber specimen is a standing guard
numeric forecasting               Gate Three V1 is binary on purpose
multi-machine key custody         that is R1's boundary, not 4.2's
```
