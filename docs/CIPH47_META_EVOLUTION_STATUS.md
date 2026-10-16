# 4.7 — Meta-Evolution: SEALED

**This file is retained as the working record. The seal itself is `CIPH47_META_EVOLUTION_SEAL.md`.**

```
4.7 suite                36 specimens, 0 failures, 0 errors
full project suite       1597 tests, 0 failures, 0 errors   (1124.9s, measured)
sanitized clone          1597 tests, 0 failures, 0 errors   (1174.6s, measured)
twelve scanners          ALL ZERO in both trees, each with a catch-specimen
fresh-state assertion    0 of everything, including all 4.7 state, in both trees
live vault               unchanged; no production meta history exists
```

Three things were found and closed during the campaign rather than papered over: 4.6's protected-surface
set did not cover the new Ring-0 modules (scanner s08 caught the drift); the promotion-result column
collapsed "promoted, regressed, rolled back" into one value, so production-side events are now
append-only; and the R6 census flagged the new scanner module as a second table owner, because a
scanner necessarily names the tables it inspects.

The constitutional question:

> **Can Ciph propose changes to the machinery that generates, evaluates, governs or interprets
> improvements without allowing the proposed new rules to approve themselves?**

The law, in one line:

> **New rules cannot ratify themselves.**

## What is built

| Piece | Module | Specimens |
| --- | --- | --- |
| Gate Four — sealed meta corpus + protocol | `ciph/kernel/meta_corpus.py` | 7 |
| Gate Four — candidate-process isolation | `ciph/kernel/meta_corpus_isolation.py` | 6 |
| Gate One — meta opportunities | `ciph/kernel/meta_opportunities.py` | — |
| Gate Two — meta hypotheses | `ciph/kernel/meta_hypotheses.py` | — |
| Gate Three — durable shadow lifecycle | `ciph/kernel/meta_shadow.py` | — |
| generator meta-evaluation (META_PARETO_V1) | `ciph/kernel/meta_comparison.py` | — |
| Gate Five — dual-control promotion + real R7 install | `ciph/kernel/meta_promotion.py` | — |
| Gate Ten — meta strategy learning | `ciph/kernel/meta_learning.py` | — |
| the complete loop, end to end | `test_gate_4_7_end_to_end.py` | 4 |
| Gate Zero — ring classification | `ciph/kernel/meta_targets.py` | 4 |
| Gates Six/Seven/Eight — epochs, no retroactive ratification, meta rollback | `ciph/kernel/evolution_epochs.py` | 3 |
| Gates Three/Four/Five/Nine — shadow-only, self-ratification predicate, collusion, hard invariants, recursion bound, meta promotion | `ciph/kernel/meta_guard.py` | 5 |

**36 specimens.** Frozen identities: `META_TARGET_POLICY_V1`, `META_CORPUS_V1`,
`META_CRUCIBLE_PROTOCOL_V1`, `META_CANDIDATE_V1`, `META_RECURSION_POLICY_V1`,
`META_PROMOTION_POLICY_V1`, `EVOLUTION_EPOCH_V1`, `META_ROLLBACK_V1`.

### Gate Four - the sealed corpus, and its boundary

The trust bottleneck, built as asked. Two case classes (`GENERATOR_CASE`, `EVALUATOR_CASE`) and three
adjudication classes:

```
MECHANICAL   decidable from a constitutional invariant (fabricated evidence -> INVALID)
OPERATOR     an independent adjudication was already recorded
NONE         unresolvable - an evaluator disagreement is recorded and decides nothing
```

E0's historical answer is deliberately **not** ground truth: only adjudicated cases move a verdict, and
an unadjudicated disagreement is recorded as `EvaluatorDisagreement(class=UNRESOLVED)` that neither
side wins.

**The access boundary is a file, not a convention.** Public inputs live in one database; sealed
answers, expected verdicts and adjudication notes live in a *separate database file* that the
candidate-facing handle is never given. `CandidateFacingCorpus` exposes exactly two methods (`cases`,
`case_input`) and has no `reveal` at all - and the specimen proves the sealed table is absent from the
public file, so a candidate-side process cannot read an answer even by opening the whole database.
`MetaCorpusVault.reveal` requires an allow-listed adjudicator reference (`operator:` / `protocol:` /
`adjudicator:`) and audits every access.

### The execution boundary, proven rather than stated

`CandidateFacingCorpus` having no `reveal()` is necessary and not sufficient: the hostile case is a
candidate that ignores the API, lists a directory and opens the file. A candidate is now executed
through the EXISTING `isolated_execution` machinery (no second sandbox - the module is scanned for
that), and the hostile probe is **handed the exact sealed path** and told where the project root is:

```
open_sealed      PermissionError          open_public      PermissionError
sqlite_sealed    OperationalError         sqlite_public    OperationalError
listdir_parent   PermissionError          listdir_root     PermissionError
traversal        PermissionError          walk_root        0 entries found
                                         glob_sealed      0 matches
as data          {'verdicts': {...}, 'case_count': 2}      <- the intended channel still works
```

So the corpus reaches the candidate as **payload data**, and no host file is readable or even
enumerable. The last measurement matters as much as the denials: it proves the child is isolated
rather than broken.

Residual limit, stated: this is OS-level namespace isolation on the evaluation host, not cryptography,
and it assumes the orchestrator never hands the candidate a general filesystem capability. If isolation
cannot run, the response is a refusal (`CANDIDATE_ISOLATION_UNAVAILABLE`) - never an unisolated run.

### The rings

```
RING 3  ORDINARY                 planner, tools, prompts, capability implementations  -> 4.6
RING 2  IMPROVEMENT_MACHINERY    gap detector, generator, review, benchmark, learning -> META_ALLOWED
RING 1  EVALUATION_CONSTITUTION  metrics, Pareto, protocols, candidate identity, safety,
                                 held-out isolation, rollback semantics  -> EXTERNAL REVIEW
RING 0  CONSTITUTIONAL_ROOT      execution authority, permits, vault identity, canonical evidence,
                                 promotion authority, meta authority     -> FORBIDDEN
```

Classification is deterministic, dependency-aware, versioned, and fails **upward**: an unclassified
file inside `ciph/kernel/`, `ciph/evolution/` or the evolution contracts is treated as Ring 1 rather
than as ordinary. `declared_description` is stored and read by nothing, so a change that claims to
"improve gap_detector" while editing `crucible_metrics.py` is Ring 1.

**Stated limit.** A protected module copied to a new name that imports nothing from the original is
indistinguishable from an ordinary new file by path/dependency scanning. The Constitutional Root is
protected by the scanner *plus* explicit architecture review, not by path strings alone. That limit is
in the module docstring, not just here.

### The predicate

```
a candidate may not be judged by itself,
by another candidate under evaluation,
or by anything it would replace.
```

Measured: a candidate judging itself confers standing `0`; two shadow candidates judging each other
confer `0` and `0`; the pre-change authoritative generation judging confers `1`. A promoted candidate
judges as `AUTHORITATIVE:<epoch>`, never as its own candidate id - which is why promotion is an epoch
transition and not a flag.

### Epochs

A judgment is recorded **under** an epoch. `CC-C17 DOMINATED under Epoch 7` and
`CC-C17 DOMINATES under Epoch 9` both survive, each naming its own epoch; restating a verdict inside
the epoch that produced it is refused (`EPOCH_HISTORY_IS_APPEND_ONLY`). A meta rollback restores the
predecessor and does **not** delete the era it came from.

## The functional loop (Chunk A) - complete

One campaign built items 2-10 and finished with a real end-to-end cycle, not a set of independent APIs:

```
Epoch 7 (generator G1, evaluator E0)
  MO1   generator weakness, from historical evidence at a versioned reproducibility threshold
  MH1   proposed generator change, pinned to G1's exact identity
  CC-G2 registered as a SHADOW candidate (4.5 owns the identity)
  G1 and G2 outputs judged by the REAL 4.5 Crucible, not by G2
  META_PARETO_V1: G2 DOMINATES G1
RESTART   epoch 7 still active, G1 still authoritative, G2 still shadow, same digests
  dual control -> real R7 governed install -> exact bytes verified -> Epoch 8 = G2
  meta regression -> governed rollback -> exact bytes restored -> Epoch 9 = G1
                    with rollback_of=Epoch 8 and restored_identity_from=Epoch 7
                    7 and 8 preserved as history
```

Specimens that carry the weight:

```
a new generator version does not inherit the weakness       MO1 goes STALE
a moved baseline stales the hypothesis                       STALE_META_HYPOTHESIS
registering a shadow changes no authority                    epoch id unchanged
a dominating meta candidate is still not authority           restart, pointer unmoved
a hard-invariant miss is INVALID, never ELIGIBLE             shadow closes INVALID
a refused promotion installs nothing                         file bytes unchanged
restoration is a NEW epoch, not time travel                  rollback_of + restored_identity_from
a greedy evaluator that sells a hard invariant               status INVALID, 1 constitutional miss
an honest evaluator with one unresolved disagreement        DOMINATES, disagreements still counted
E1 rating itself / two shadows rating each other             standing (0, 0)
```

## What is NOT built — this is not a seal

```
G1  meta opportunities           BUILT
G2  meta hypotheses              BUILT
G3  durable shadow lifecycle     BUILT
G4  meta evaluation protocol     BUILT: corpus, protocol, API boundary, execution boundary
G5  meta promotion + epoch       BUILT: dual control, real R7 install, new-epoch rollback
G10 meta strategy learning       BUILT: descriptive projection, no scalar
scanners                         the 12 structural scanners with catch-specimens     NOT BUILT  (Chunk B)
tortures                         generator / evaluator / rollback as standalone suites  PARTLY: covered
                                 inside the end-to-end loop, not as separate tortures
verification                     full project sweep, sanitized clone for 4.7          NOT RUN    (Chunk C)
```

So the constitutional *vocabulary* exists - classification, epochs, and the self-ratification
predicate - and the phase's hard core ("new rules cannot ratify themselves") is enforced by 12
specimens. But the machinery that would actually run a meta-evolution cycle end to end is not there,
and nothing in 4.7 proves what happens when a shadow generator is evaluated against a real sealed
corpus.

## Verification so far

```
4.7 suite                     36 specimens, 0 failures, 0 errors
targeted regression           143 tests green across 4.5 / 4.6 / R6 / R7 / 4.7
targeted regression           113 tests green across 4.5 / 4.6 / R6 / 4.7 suites
full project sweep            NOT RUN for 4.7
sanitized clone               NOT RUN for 4.7
live vault                    untouched by 4.7
```

## Recommendation

Do not start anything after 4.7 on this foundation. The next work is either to finish 4.7 (G1, G2, the
meta protocol with a sealed corpus, the promotion record, the scanner suite and the torture), or to
stop and consolidate - but the "Ciph's mind is finished" milestone belongs after a *sealed* 4.7, not
after a constitutional vocabulary for it.

---

## Superseded (2026-10-10)

This file is the checkpoint written before 4.7 was finished. Everything it lists as NOT RUN has since
run: the 4.7 suite is green, the full project sweep and the sanitized clone both ran clean, and 4.7 is
**SEALED** - the record is `CIPH47_META_EVOLUTION_SEAL.md` and register entry R8. The checkpoint text
above is kept because deleting it would hide how the phase actually went.

## Cross-phase note from 5.x

5.x (Continuous Governed Autonomy) added twelve structural scanners of its own, and one of its pattern
lists necessarily contains `transition_epoch(` as **data**. 4.7's `s03` read that catalogue of patterns
as a caller of the symbol and fired on `ciph/kernel/autonomy_scanners.py` - the same class of
between-phase collision as the R4 table clash and the R6 census misclassification.

The repair is that a scanner is not a caller: `meta_scanners._callers` now excludes `*_scanners.py`
modules, and a 5.x specimen proves the exclusion is narrow by injecting a real caller and watching `s03`
catch it. **No 4.7 law changed and no scanner was weakened for convenience** - what changed is that a
catalogue of forbidden patterns is no longer mistaken for a violation of them.

After the repair, all twelve 4.7 scanners and all twelve 5.x scanners are zero on the real tree and in
the sanitized clone, with the R6 census and the R7 choke-point scanners still zero in both.
