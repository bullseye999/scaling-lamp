# 4.3 Gate Two — Causal Hypotheses

**Question:** *what might explain the observed transitions?*

Not "*what caused them*".

**Module:** `ciph/kernel/causal_model.py` — `test_gate_4_3_causality.py`, 11 specimens.

## The absolute law

> **correlation / temporal order != causation.** "A preceded B" is not "A caused B".

## Shape

```
CausalHypothesis
    cause, effect
    evidence_refs, inference_refs, transition_refs
    basis_digest

CausalAssessment           # DERIVED, never stored on the hypothesis
    status: PROPOSED | SUPPORTED | CONTESTED | REFUTED | STALE
    linked_predictions, resolved_true, resolved_false, unresolved, stale_inferences
    reason_codes, basis_digest
```

The status is **not a column**. It is recomputed from the linked predictions every time it is asked
for, so there is no function that can write "SUPPORTED" onto a story no test has touched.

## The frozen status function

```
explicitly invalidated              -> REFUTED   (EXPLICITLY_INVALIDATED)
any referenced inference is STALE   -> STALE     (INFERENCE_BASIS_STALE)
no linked prediction at all         -> PROPOSED  (NO_FALSIFIABLE_PREDICTION)
nothing resolved yet                -> PROPOSED  (PREDICTIONS_PENDING)
one success and one failure         -> CONTESTED (PREDICTIONS_CONFLICT)
a failure, no success               -> REFUTED   (PREDICTIONS_REFUTE)
a success, no failure               -> SUPPORTED (PREDICTIONS_SUPPORT)
```

## Laws

```
 1. Causes are never inferred merely because A preceded B.
 2. Causal hypotheses are not evidence: nothing here writes the epistemic ledger.
 3. Model-generated causal stories add zero support - proposing NEVER yields SUPPORTED.
 4. Competing causal hypotheses may coexist.
 5. A hypothesis must generate falsifiable predictions before gaining any empirical credit.
 6. Prediction outcomes flow through 4.2 Gate Three, so a hypothesis moves only on canonical,
    resolved prediction evidence - never on a model's say-so.
 7. Failed predictions weaken (CONTESTED) or refute (REFUTED) the hypothesis.
 8. Successful predictions SUPPORT but never prove causality absolutely.
 9. Historical hypotheses are immutable: status is DERIVED, never written onto the record.
10. Same evidence/prediction history -> same causal projection.
```

## Founding example

```
observation: API latency rises after deployment D

H1  deployment D caused the latency
H2  upstream provider degradation caused the latency
    -> both PROPOSED, no empirical credit, coexisting

H1 predicts: a rollback should reduce latency
H2 predicts: latency stays elevated after the rollback
future evidence resolves the predictions -> the hypotheses move accordingly
```

Now Ciph learns from being wrong instead of narrating causes.

## Specimens that matter

**Prose adds nothing.** A model output asserting the cause, followed by `propose_hypothesis`, still
leaves the status `PROPOSED`, and the ledger digest is unchanged. The module's public surface contains
no `set_status`, `mark_supported`, `prove_hypothesis`, `assert_cause` or `record_cause`.

**A sequence is not a cause.** A hypothesis citing a real derived transition is still `PROPOSED` —
however clean the ordering looks.

**A model asserting its own prediction was right** resolves nothing: the prediction stays `OPEN`
until canonical evidence resolves it, and re-issuing the same forecast is one prediction.

**Support is not proof.** A supported hypothesis passes `assert_empirically_supported`, which returns
`SUPPORTED` — there is no `PROVEN` and no `FACT` in the status set.

**Stale reasoning.** A hypothesis citing an inference whose pinned premise has since moved becomes
`STALE`; the inference keeps the premise versions it pinned.
