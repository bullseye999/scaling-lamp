# 4.4 Gate One — Curiosity Priority

**Question:** *which uncertainty would actually be USEFUL to reduce?*

**Module:** `ciph/kernel/curiosity_priority.py` — `test_gate_4_4_curiosity_priority.py`, 9 specimens.

## The frozen metric

```
CURIOSITY_PRIORITY_V1

score = decision_relevance
      + expected_information_gain
      + expected_prediction_improvement
      + expected_self_model_improvement
      - estimated_cost
      - estimated_risk
      - barren_investigation_penalty
```

Every term is read from canonical state. There is **no parameter for how interesting the model finds
something**, so interest cannot be smuggled in as a term: novelty alone gives no priority, and high
uncertainty alone gives none either.

## The frozen inputs

```
INFO_GAIN_BY_REDUCIBILITY   REDUCIBLE 1.0 | POSSIBLY_REDUCIBLE 0.5 | UNKNOWN 0.25 | IRREDUCIBLE 0.0
COST_BY_KIND                stale 0.10 | epistemic 0.30 | calibration 0.20 | dynamics 0.40
                            | weak causal 0.50 | self model 0.70
RISK_BY_KIND                stale 0.10 | epistemic unresolved 0.10 | contested 0.30
                            | dynamics 0.20 | weak causal 0.40 | self model 0.60
PREDICTION_IMPROVEMENT_SATURATION   2   (two open predictions already carry the decision stake)
```

`decision_relevance` is `mission_relevance`: the subject appears in the objective of an ACTIVE
mission. Relevance may *raise* priority; mission existence grants no investigation authority.

## Laws

```
 1. Novelty alone gives no priority.
 2. High uncertainty alone gives no priority.
 3. Curiosity must have an expected epistemic benefit.
 4. Cost and risk are first-class.
 5. Mission relevance may raise priority; mission existence grants no investigation authority.
 6. Model fascination/interest is not a scoring input.
 7. A lower-cost uncertainty may outrank a theoretically richer one.
 8. The priority metric cannot itself modify evidence or world state.
 9. Score changes require canonical input changes.
10. Same uncertainty inputs -> same priority digest.
```

## The hostile specimen

```
U1  SELF_MODEL_UNKNOWN, no mission relevance, expensive and risky   -> 0.70
U2  WORLD_STALE about the mission's subject, cheap and low risk      -> 1.80

EXPECTED: U2 outranks U1
```

Then the same cheap fact is made mission-relevant, and its score rises by **exactly 1.0** — the frozen
weight — while the mystery's score does not move at all. This is what stops "AI curiosity" turning into
random wandering toward the most mysterious thing available.

## The one-way feedback path

Gate Four's closed outcomes feed a deterministic penalty:

```
canonical CuriosityOutcome  ->  deterministic penalty  ->  future priority
```

and never the reverse. The priority layer never labels its own prior investigation barren; it only
consumes a result the learning gate derived from canonical state. The specimen asserts the delta is
exactly `BARREN_OUTCOME_PENALTY = 0.5` per barren outcome, and that recomputing the penalty repeatedly
leaves the learning record's digest unchanged.

## Specimens that matter

Two uncertainties that differ only in cost/risk are ordered by cost/risk, and the score always equals
the frozen formula recomputed from its own exposed terms.
