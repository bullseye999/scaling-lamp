# 4.2 Gate One — Source Dependence

The question is not *"are these five different websites?"* It is:

> **How many epistemically independent observations are actually represented by this evidence?**

`ciph/kernel/source_dependence.py`. Gate Zero is untouched: its confidence formula
(`fresh_support / (fresh + fresh_contradict)`) is frozen, and every Gate One specimen asserts that
recording provenance does not move the Gate Zero ledger digest or its numbers.

```
Gate Zero    raw evidence confidence        metric: belief confidence (frozen)
Gate One     independence-adjusted picture  metric_id: SOURCE_INDEPENDENCE_V1
```

Independence belongs to **evidence instances**, not publishers. Reuters can publish two genuinely
independent observations; two unrelated domains can publish one identical Reuters observation.

## Vocabulary note

This gate is written with two names for the same facts, deliberately without duplicating the
derivation:

```
families / min / max            the implementation's own words
proven_support_count            independent_support_min      (property)
possible_support_count          independent_support_max      (property)
verified_/unknown_*_groups      grounded / ungrounded families
resolution_status               RESOLVED | PARTIAL | UNKNOWN | INTEGRITY_CONFLICT
```

They are properties over ONE derivation and ONE digest, so the two vocabularies cannot drift apart.

## Families, not declarations

Provenance is a graph over evidence instances, with narrow edge types: `SYNDICATED_FROM`, `COPIED_FROM`,
`QUOTES`, `DERIVED_FROM`, `COMMON_ORIGIN`, plus `PRIMARY_OBSERVATION` and `INDEPENDENCE_PROVEN`.
Dependency edges merge evidence into **families** (union-find), so a relay chain is one witness and a
mutual-citation cycle is one component plus an integrity flag, never two witnesses.

```
evidence E1 --ORIGINATES------> Reuters report R
evidence E2 --SYNDICATED_FROM-> R
evidence E3 --QUOTES----------> R
evidence E4 --DERIVED_FROM----> E2
```

## The grounding rule (frozen, and why the bounds are honest)

```
A family is GROUNDED when its lineage is anchored:
    * more than one member (a relay chain with a known origin), or
    * a member is declared a PRIMARY observation, or
    * an explicit INDEPENDENCE_PROVEN statement names it

grounded family    -> counts toward the LOWER bound
ungrounded family  -> counts only toward the UPPER bound
```

**Unknown dependence is not independence.** Five unrelated reports with no provenance at all yield
`min = 0, max = 5` — not "5 witnesses", and not "0 witnesses who might exist either". Filling in
ancestry moves the lower bound; it never quietly changes what the upper one meant.

```
min = grounded families
max = min + ungrounded families
lower = Smin / (Smin + Cmax)          upper = Smax / (Smax + Cmin)
```

## The founding specimen, measured

```
R  Reuters           SUPPORTS   (origin)
A  syndicates R      SUPPORTS   B  quotes R   SUPPORTS
C  copied A          SUPPORTS   D  syndicates R SUPPORTS

Gate Zero : 5 supporting links, confidence 1.0        (unchanged by anything below)
Gate One  : 1 family, bounds [1, 1], PROVEN_DEPENDENT

X  firsthand source  SUPPORTS  (+ PRIMARY_OBSERVATION)
          : 2 families, bounds [2, 2], PROVEN_INDEPENDENT

Y  blog, provenance unresolved  SUPPORTS
          : 3 families, bounds [2, 3], DEPENDENCE_UNKNOWN
```

Nothing is deleted: the family's `members` list every dependent link.

*Note on the frozen formula.* With uncertainty on one side and nothing on the other, `[Smin/(Smin+0),
Smax/(Smax+0)]` is `(1.0, 1.0)` — the ratio has nothing to widen against, and the **bounds** are the
honest signal. The interval becomes an interval the moment there is opposition, which the hostile
specimen demonstrates directly.

## The hostile specimen, measured

```
5 Reuters descendants SUPPORT P        Gate Zero: confidence 0.8333…
1 independent primary CONTRADICTS P    Gate One : support [1,1], contradict [1,1] -> interval [0.5, 0.5]

+ one contradiction with unresolved provenance
                                        contradict [1,2] -> interval [0.333…, 0.5]
                                        DEPENDENCE_UNKNOWN
```

The five mirrors cannot outvote the independent contradiction, because syndication made the support
*more numerous*, not *more independent*.

## The twelve laws, and where each is falsifiable

`test_gate_4_2_source_dependence.py` — 15 specimens, all green.

| # | Law | Specimen |
| --- | --- | --- |
| 1 | Source identity ≠ source independence | `test_law_1_different_domains_are_not_different_witnesses` |
| 2 | Same source ≠ automatic dependence | `test_law_2_one_publisher_can_produce_independent_observations` |
| 3 | Proven relays do not multiply corroboration | `test_law_3_proven_relays_do_not_multiply_corroboration` |
| 4 | Unknown dependence ≠ independence | `test_law_4_unknown_provenance_is_never_counted_as_independent` |
| 5 | Dependent evidence is not deleted | `test_law_5_and_6_grouping_deletes_nothing_and_changes_no_polarity` |
| 6 | Dependence does not change polarity | same specimen — Gate Zero's ledger digest is identical before and after |
| 7 | Content similarity is not proof of dependence | `test_law_7_and_8_similarity_and_model_assertions_cannot_create_edges` |
| 8 | A model assertion cannot create a provenance edge | same specimen — the provenance picture is unmoved |
| 9 | Contradiction is grouped the same way | `test_law_9_contradictions_are_grouped_symmetrically` |
| 10 | Provenance history is append-only | `test_law_10_provenance_history_is_append_only` |
| 11 | Cycles do not create independence | `test_law_11_a_cycle_is_one_component_and_an_integrity_condition` |
| 12 | Same graph → same families → same bounds → same digest | `test_law_12_same_graph_same_bounds_same_digest` (in-process **and** cross-process) |

## Two digests, two jobs

```
provenance_digest          families, bounds, interval, status, integrity flags   -> the provenance picture
canonical_digest()         the above PLUS outstanding hypotheses                -> the full projection identity
```

A similarity hypothesis is a real fact to investigate, so it belongs in the projection's identity —
and it must not belong to the provenance picture. `provenance_only_digest()` exposes exactly that, so
"a model's suspicion cannot change the picture" is checkable rather than asserted.

Confirmed ancestry also beats a *claimed* independence: if A is proven derived from B and something
also claims A and B are independent, they stay in one family and a `PROVENANCE_CONFLICT` integrity
flag is raised. The conservative direction wins, loudly.

## Deliberately out of scope

**Source reputation.** "Reuters is usually reliable" and "these four stories came from Reuters" are
different questions, and mixing them would let a reputable origin collect extra votes for being
reputable. Gate One counts independent origins; a later gate may weigh their historical reliability.
