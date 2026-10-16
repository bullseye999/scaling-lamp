# 4.2 Gate Three — Predictions + Calibration (V1: binary only)

`ciph/kernel/predictions.py`. This is where confidence becomes **accountable**.

```
PredictionRecord      a forecast bound to the epistemic state at issuance
PredictionResolution  an immutable resolution, from canonical admissible evidence only
```

Two structural anti-cheats:

```
PROBABILITY IS FROZEN AT ISSUANCE   later beliefs cannot rewrite it (no retroactive 0.95)
THE FINGERPRINT IS CANONICAL        the same forecast is ONE prediction, not fifty data points
```

## The twelve laws, and where each is falsifiable

`test_gate_4_2_predictions_calibration.py` — 12 specimens, all green.

| # | Law | Specimen |
| --- | --- | --- |
| 1 | Probability is immutable after issuance | `test_probability_has_no_setter_anywhere` |
| 2 | A prediction binds the state at issuance | `test_founding_probability_is_frozen_at_issuance` |
| 3 | Later beliefs do not rewrite it | same specimen |
| 4 | A model cannot resolve its own prediction | `test_hostile_model_cannot_resolve_its_own_prediction` |
| 5 | Resolution uses canonical admissible evidence | `test_resolution_evidence_must_agree_with_the_outcome` |
| 6 | UNRESOLVED ≠ FALSE | `test_unresolved_is_not_false` |
| 7 | Missing evidence never becomes failure | same specimen |
| 8 | No backdating | `test_law_8_predictions_cannot_be_backdated` |
| 9 | Duplicates cannot inflate statistics | `test_anti_cheat_duplicate_forecasts_are_one_prediction` |
| 10 | Resolution is append-only | `test_law_10_resolution_is_append_only` |
| 11 | Calibration uses RESOLVED only | `test_law_11_calibration_uses_only_resolved_predictions` |
| 12 | Same history → same calibration | `test_law_12_calibration_digest_is_stable_across_restart_and_process` |

## Measured behaviour

```
p = 0.8 issued at basis H0; later belief moves (a contradiction arrives)
    -> the prediction still says 0.8 and still binds H0
resolve TRUE from canonical supporting evidence
    -> Brier = (0.8 - 1)^2 = 0.04, mean_probability 0.8

issue the same forecast 10 times      -> 1 canonical prediction, 1 calibration data point
issue it again at 0.95                -> the SAME prediction, still 0.8
deadline passes with no evidence      -> EXPIRED_UNRESOLVED, resolved_count unchanged,
                                         unresolved_count +1, brier None
model says "my prediction was right"  -> RESOLUTION_EVIDENCE_NOT_CANONICAL, zero effect
```

## The frozen metric

```
metric_id = PREDICTION_CALIBRATION_V1
Brier = mean((p - y)^2) over RESOLVED predictions only,  y = 1 TRUE / 0 FALSE
also: resolved_count, unresolved_count, invalidated_count, open_count,
      mean_probability, observed_frequency, and the ten FIXED reliability bins
```

Bins are fixed constants rather than tunables, so binning cannot quietly become authority.

## One design decision worth naming

**Invalidation is only possible while a forecast is still OPEN.** My first pass allowed invalidating a
resolved prediction — which is a hindsight loophole: you could erase an inconvenient data point after
seeing the outcome. It is now refused with `CANNOT_INVALIDATE_RESOLVED_PREDICTION`, and the status
precedence puts invalidation first precisely because it can no longer coexist with a resolution.
