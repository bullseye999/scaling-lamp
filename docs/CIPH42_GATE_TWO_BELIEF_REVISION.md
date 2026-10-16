# 4.2 Gate Two — Belief Revision + Inference Lineage

> **Inference is not evidence.**

`ciph/kernel/belief_revision.py`. A model may reason from evidence; its reasoning never becomes another
observation, so an inference can enter the REASONING graph and can never move Gate Zero's counts.

```
InferenceRecord     conclusion + the EXACT premise belief versions/digests + rule + model
BeliefRevision      append-only bookkeeping of how a proposition's basis changed
```

Every current projection is derived, so nothing here is an input to Gate Zero.

## The twelve laws, and where each is falsifiable

`test_gate_4_2_belief_revision.py` — 14 specimens, all green.

| # | Law | Specimen |
| --- | --- | --- |
| 1 | Revision is append-only | `test_law_1_and_11_revision_history_is_append_only_and_reconstructible` |
| 2 | "The model changed its mind" is not a cause | `test_law_10_and_2_revisions_need_a_real_basis_change` |
| 3 | An inference pins exact premise versions/digests | `test_founding_inference_pins_premises_and_does_not_become_evidence` |
| 4 | A changed premise STALEs the inference | same specimen |
| 5 | Inference ≠ evidence | `test_law_5_and_6_inference_cannot_increment_gate_zero` |
| 6 | Repeating an inference adds zero evidence | `test_anti_echo_ten_identical_inferences_add_no_evidence` |
| 7 | Contradictory inferences coexist | `test_law_7_contradictory_inferences_coexist` |
| 8 | A conclusion need not become SUPPORTED | `test_law_8_a_conclusion_does_not_become_supported` |
| 9 | A stale inference cannot be used | `test_hostile_premise_substitution_is_refused`, `test_law_9_an_invalidated_inference_is_never_usable` |
| 10 | Revision needs a real basis change | `test_law_10_and_2_...` |
| 11 | Historical revisions are reconstructible | `test_law_1_and_11_...` |
| 12 | Same history → same assessment and digest | `test_law_12_revision_digest_is_stable_across_restart_and_process` |

## The founding specimen, measured

```
E1 SUPPORTS P                   -> P = SUPPORTED, digest H1
infer P -> Q (MODUS_PONENS_V1)  -> premise ref pins (version, H1)
                                -> Q is in the REASONING graph
                                -> Gate Zero evidence for Q = 0
                                -> Q has no belief at all (nothing asserted it)
E2 CONTRADICTS P                -> P = CONTESTED
                                -> I1 = STALE, still pinning H1
new inference from P            -> different basis digest; the old one is untouched
```

**The hostile specimen** pins premises at `A@v2, B@v2`, then lets A move. `assert_usable` raises
`STALE_INFERENCE_BASIS`, and the record still says `v2` — **no silent premise upgrade**.

## Revision causes are derived, with a frozen precedence

```
EVIDENCE_STALE / EVIDENCE_REFRESHED   (the staleness flag flipped)
NEW_SUPPORT                           (the support set grew)
NEW_CONTRADICTION                     (the contradiction set grew)
PROVENANCE_CHANGED                    (Gate One's digest moved)
INFERENCE_ADDED / INFERENCE_INVALIDATED
otherwise                             -> no revision at all
```

A caller cannot supply a cause, so "the model changed its mind" produces no revision; identical
re-evaluation adds no version (`record_revisions` twice returns `()` the second time).

One design note: **revision ids are derived, not random.** A revision is bookkeeping *derived* from
canonical history, so replaying that history must reproduce the same records — otherwise "same history,
same digest" would hold for the assessment and fail for the record of how it was reached.
