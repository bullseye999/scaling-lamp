# CIPH 4.7 — META-EVOLUTION — SEALED

The constitutional law of this phase:

> **No generation of an evaluator may judge its own legitimacy.** New rules cannot ratify themselves.

## The measured campaign

```
4.7 suite                    36 specimens, 0 failures, 0 errors
full project suite           1597 tests,  0 failures, 0 errors   (1124.9s, measured)
sanitized read-only clone    1597 tests,  0 failures, 0 errors   (1174.6s, measured)
ambient vault in clone       none
fresh-state assertion        0 of everything in BOTH trees, including all 4.7 state
12-scanner census            ALL ZERO in both trees
R6 ownership                 0 violations, 0 bypasses, 0 missing machinery (both trees)
R7 choke point               0 unguarded primitives, 0 activation bypasses (both trees)
schema ownership             0 duplicate canonical table owners (both trees)
live vault                   VAULT-0E79C7AFD84940BB / VAULT_ID_V1, all rows decrypt,
                             live_permitless = 0, no production meta history exists
```

The first full sweep of this campaign returned `Ran 1597 ... FAILED (failures=2)`: the R6 census
flagged the new `meta_scanners.py` as a second owner of the active-pointer table, because a scanner
necessarily *names* the tables it inspects. That is a composition defect of exactly the kind isolated
gates cannot see, and it was closed by generalising the census's stated signal-declaring exclusion. The
seal rests on the clean re-run.

## Claim → evidence

| Claim | Evidence |
| --- | --- |
| Meta target classification deterministic | ring classification specimens; identical digests across restarts |
| Ring-0 automatic modification impossible | refused at `register_meta_candidate` AND at `meta_promote`; scanner s07 |
| Meta weakness requires canonical evidence | below the reproducibility threshold → `META_OPPORTUNITY_NOT_REPRODUCIBLE` |
| Hypothesis pins exact machinery baseline | mismatch refused; a moved baseline yields `STALE_META_HYPOTHESIS` |
| Meta candidate starts shadow-only | `register_shadow` records `shadow_only=1`; registering changes no authority |
| Candidate cannot become evaluator during its own test | `assert_independent_judgment`; self-judgment standing `(0,)` |
| Candidate-facing process cannot read sealed answers | sandboxed probe handed the exact sealed path: `PermissionError` on every read, 0 entries by walk/glob; corpus still arrives as payload data |
| Pre-change authority judges the replacement | judges are `AUTHORITATIVE:<epoch>`; a candidate id as judge is refused |
| Self-rating zero standing | standing `(0,)`; only an independent judge yields `1` |
| Collusion zero standing | two shadow candidates judging each other → `(0, 0)` |
| Unadjudicated disagreement stays unresolved | `EvaluatorDisagreement(UNRESOLVED)` → `INSUFFICIENT_EVIDENCE`, no win for either |
| Protocol/corpus frozen before results | payload identity + column-level tamper detection |
| Hard invariants non-tradeable | a miss is `INVALID` however well the candidate scored; shadow closes `INVALID` |
| Meta DOMINATES ≠ meta promotion | restart after DOMINATES: epoch unchanged, pointer unmoved |
| Promotion requires dual/strong authorization | requirements cover shadow eligibility, both standings, invariants and authorization |
| Real meta deployment crosses R7 | `meta_promote` installs through `evolution_deployment.deploy` with real bytes; scanner s12 |
| Epoch transition only after verified installation | ordering enforced; a post-installation failure raises `META_DEPLOYMENT_RECONCILIATION_REQUIRED` |
| Rollback produces a new epoch | `rollback_of` + `restored_identity_from`; three epochs retained |
| Historical evaluations retain their epoch | both verdicts readable under their own epochs; s10 forbids UPDATE/DELETE |
| New evaluator cannot rewrite old verdicts | `assert_history_not_rewritten`; append-only judgments |
| Meta rollback preserves the failed era | rollback torture: dominated, promoted, regressed and rolled back all true at once |
| Recursive depth bounded | `MAX_META_GENERATION_DEPTH_V1 = 1`; depth-2 refused; scanner s11 |
| Meta path cannot modify the constitutional root | Ring 0 refused at both boundaries; s07 |
| Restart preserves the whole state | cross-process reconstruction of classifications, epochs, opportunities, hypotheses, shadow, promotions, learning |
| Twelve scanner invariants = 0 | census in both trees, each scanner with a synthetic catch-specimen |
| 4.5 / 4.6 / R6 / R7 / legacy regressions | included in the 1597-test sweep, fresh measurement |
| Full sweep green | `Ran 1597 tests ... OK (1124.9s)` |
| Sanitized clone green | `Ran 1597 tests ... OK (1174.6s)`, no ambient vault |

## The functional loop, as it actually runs

```
Epoch 7 (G1 generator, E0 evaluator)
  MO1 -> MH1 -> CC-G2 shadow -> sealed corpus -> real 4.5 Crucible judges every candidate
  -> META_PARETO_V1: G2 DOMINATES G1
RESTART   epoch 7 current, G1 authoritative, G2 shadow, digests identical
  dual control -> R7 governed install -> exact bytes verified -> Epoch 8 = G2
  meta regression -> governed rollback -> exact bytes restored -> Epoch 9 = G1
                    rollback_of Epoch 8, restored_identity_from Epoch 7; 7 and 8 preserved
```

## Stated limits — recorded, not hidden

1. **Comparative generator capability is NOT claimed.** The two generators are represented as outcome
   streams whose verdicts come from the real 4.5 Crucible. What is proven is the *governance* of
   replacing a generator; no second runnable generator implementation was written, and no fake one was
   invented for a torture that requires it.
2. **The scanners are static and syntactic.** A protected implementation copied under a new name that
   imports nothing from the original still reads as ordinary code. The scanners narrow the bypass
   surface; architectural review is the root fallback.
3. **The corpus boundary is OS-level, not cryptographic.** A process holding both database paths could
   read the sealed answers; the enforced assumption is that the orchestrator never hands the candidate
   a general filesystem capability.
4. **No production meta history exists.** The live-vault check confirms that absence rather than
   exercising a production read path — no meta artifacts were created to prove one.
