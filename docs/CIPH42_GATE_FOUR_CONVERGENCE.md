# 4.2 Gate Four — Epistemic Convergence

The last gate. **There is no `FACT` status**: convergence is another projection with an explicit policy
identity, `CONVERGENCE_V1`.

```
ciph/kernel/epistemic_convergence.py
apply_policy(...)  is a PURE FUNCTION, so the policy can be read, tested and versioned
```

## The frozen V1 policy

```
INTEGRITY conflict                                    -> INTEGRITY_BLOCKED
all current evidence stale                            -> STALE
proven support >= 2 AND possible contradiction == 0    -> CONVERGED_SUPPORTED
proven contradiction >= 2 AND possible support == 0    -> CONVERGED_REFUTED
proven support >= 1 AND proven contradiction >= 1      -> CONTESTED
otherwise                                             -> UNRESOLVED
```

Two details that matter:

- **`possible contradiction == 0`** is why unknown provenance blocks convergence. Two proven supports
  plus one unattributable contradiction is NOT convergence; possibility has to be resolved first.
- **The `2` is policy, not metaphysics.** A different standard becomes `CONVERGENCE_V2` rather than a
  quiet edit to V1.

## The twelve laws, and where each is falsifiable

`test_gate_4_2_convergence.py` — 13 specimens, all green. Notably:

```
1  CONVERGED != FACT                    test_no_promotion_to_fact_exists
2  raw counts do not decide             test_law_2_raw_counts_do_not_determine_convergence
                                        (6 raw supports, 1 proven origin -> UNRESOLVED)
3  dependence precedes convergence      test_the_policy_is_a_pure_function (policy takes Gate One counts)
4  unknown provenance can block         test_unknown_provenance_blocks_convergence
5  copies never outvote                 test_hostile_mirrors_never_outvote_an_independent_contradiction
6  symmetry                             test_support_and_contradiction_are_symmetric
7  append-only history                  test_founding_convergence_then_reversal_without_rewriting_history
8  reversal without rewrite             same specimen
9  STALE != REFUTED                     test_stale_is_not_refuted
10 integrity always blocks              test_integrity_conflict_always_blocks
11 model confidence cannot force it     test_law_11_model_confidence_cannot_force_convergence
12 same history -> same digest          test_law_12_convergence_digest_is_stable_across_restart_and_process
```

## Measured reversals

```
Reuters family + independent primary      -> proven support 2, possible contradict 0 -> CONVERGED_SUPPORTED
+ independent contradiction               -> proven support 2, proven contradict 1  -> CONTESTED
                                             history still holds CONVERGED_SUPPORTED
```

The earlier judgement was correct *given what was known then*, and convergence history keeps it.

## Design note

The convergence digest covers the projection's **identity** (status, counts, reasons, refs, basis) and
excludes the wall clock: `created_at` records when we looked, not what we found. I caught that with the
cross-gate torture specimen, where the same history read at two moments produced two "different"
digests.
