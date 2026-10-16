# 4.2 Gate Zero — Epistemic Ledger

> **Evidence is durable. Beliefs are projections over evidence. Confidence is a property of that
> projection, never evidence itself.**

## The five layers, kept apart

```
Observation   the raw thing Ciph received or measured      asserts nothing
Claim         a proposition asserted by an observation      a proposition, not a belief
Evidence      a durable SUPPORTS / CONTRADICTS / CONTEXT_ONLY link between the two
Belief        Ciph's CURRENT projection over the evidence   derived, never declared
Confidence    how strongly the current evidence supports it derived, never writable

Model output  recorded as a MODEL OUTPUT                     explicitly NOT evidence
```

`ciph/kernel/epistemic_ledger.py`. Nothing here can promote a proposition to fact: there is no `FACT`
status, no API that writes a confidence, and no path from a model output into the evidence table.

## Proposition identity

```
Proposition{ proposition_id, proposition_version, canonical_subject, canonical_predicate,
             canonical_object/value, temporal_scope }
```

`proposition_id` is the hash of the canonical form, so identity comes from **meaning** — and temporal
scope is part of meaning:

```
"server.x is_online"                              PROP-9C34ADE974A613F5
"server.x is_online AT:2026-10-08T14:03Z"         PROP-7B78532C005984CB
```

Same intension, different propositions. If identity were fuzzy, evidence linkage, contradiction,
confidence and staleness would all be mush downstream.

## The twelve laws, and where each is falsifiable

`test_gate_4_2_epistemic_ledger.py` — 16 specimens, all green.

| # | Law | Specimen |
| --- | --- | --- |
| 1 | Observation ≠ claim | `test_law_1_receiving_text_is_not_a_claim` — a received report leaves zero evidence and zero propositions |
| 2 | Claim ≠ belief | `test_law_2_and_3_a_source_asserting_p_does_not_make_it_believed_or_true` |
| 3 | Belief ≠ fact | same specimen — there is no `FACT` status to promote into |
| 4 | Model repetition adds zero evidence | `test_model_repetition_adds_zero_evidence` |
| 5 | Evidence is append-only | `test_law_5_and_7_...`, `test_law_5_context_evidence_is_not_support_or_contradiction` |
| 6 | Belief state is reconstructible | `test_law_6_belief_state_is_reconstructible_without_the_projection` — delete the projections, same digest |
| 7 | Contradiction is first-class | `test_law_5_and_7_...` — 2 contradictions + 1 support is `CONTESTED` at 1/3, never "last one wins" |
| 8 | Absence of support ≠ refutation | `test_law_8_absence_of_support_is_not_refutation` |
| 9 | Staleness is temporal, not falsehood | `test_law_9_staleness_is_temporal_not_falsehood`, `test_law_9_stale_support_beside_fresh_contradiction` |
| 10 | Confidence cannot create evidence | `test_law_10_confidence_cannot_create_evidence` — no such API exists, and the only thing that moved the score is the link behind it |
| 11 | Unknown is valid | `test_law_11_unresolved_is_a_valid_standing_answer` |
| 12 | History is never rewritten | `test_law_12_previous_projections_remain_historical` — version 1 stays `SUPPORTED` at 1.0 after version 2 becomes `CONTESTED` at 0.5 |

## The founding specimen

```
E1: source A asserts P            -> P = SUPPORTED, confidence 1.0
E2: independent source B says NOT P -> P = CONTESTED, confidence 0.5
                                     E1 still exists, E2 exists, neither deleted
restart -> same proposition id, same evidence set, same status, same confidence, same digest
```

## The anti-echo specimen

```
10 model outputs restating P
-> supporting_evidence unchanged
-> confidence unchanged
-> epistemic digest unchanged
-> the outputs exist as audit facts, and the evidence table still holds exactly one link
```

That is law 4 as an executable property, not a promise: Ciph cannot build an echo chamber inside
itself by re-reading its own conclusions.

## Design decisions worth naming

- **Evidence polarity is recorded, not inferred.** `relation` lives on the link; a status label is
  never consulted to reconstruct what an item meant.
- **Confidence has one frozen formula** (`fresh_support / (fresh_support + fresh_contradict)`, 0.0 when
  nothing is fresh). There is no setter, so a score cannot appear without a link behind it.
- **Stale support stays support.** It moves to `stale_evidence`, not to `context_evidence`, and it
  stops counting only for the *current* projection (law 9).
- **`CONTEXT_ONLY` is first-class**, so background material can be recorded without being counted as
  agreement.
- **Projections only re-version on change**, so history stays meaningful instead of accumulating
  identical rows, and the projection is never an input to its own derivation.

## Gate Zero seal

```
same canonical evidence history
-> same proposition identities
-> same belief statuses
-> same confidence outputs
-> same epistemic digest
-> independent of process restart      (same digest in a second process)
-> independent of model phrasing       (10 restatements change nothing)
```

## Out of scope in Gate Zero (deliberately, so it cannot balloon)

```
Gate One    source dependence: are five sites repeating Reuters one witness or five?
Gate Two    belief revision and inference lineage
Gate Three  predictions and calibration
Gate Four   convergence across conflicting evidence, with UNRESOLVED as a valid terminus
```
