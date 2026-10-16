# 4.4 Gate Four — Curiosity Learning

**Question:** *did the investigation actually reduce uncertainty?*

**Module:** `ciph/kernel/curiosity_learning.py` — `test_gate_4_4_curiosity_learning.py`, 10 specimens.

## The hard law

> `CuriosityOutcome` is calculated from canonical before/after state. **It is never writable.**

```
before    canonical state when the investigation started (immutable reference)
after     canonical state when it closed              (immutable reference)
result    RESOLVED | REDUCED | UNCHANGED | WORSENED | INCONCLUSIVE
gain      how much CANONICAL state actually moved
```

## The frozen result function

```
the uncertainty is no longer derivable     -> RESOLVED     UNCERTAINTY_CLOSED
convergence reached a definite status      -> RESOLVED     CONVERGENCE_REACHED
canonical state moved, or support narrowed -> REDUCED      CANONICAL_STATE_MOVED
the support interval WIDENED               -> WORSENED     SUPPORT_INTERVAL_WIDENED
attempted, completed, nothing moved        -> UNCHANGED    NO_CANONICAL_MOVEMENT
failed or never attempted                  -> INCONCLUSIVE OPERATION_FAILED / OPERATION_NOT_ATTEMPTED
```

`WORSENED` means the canonical epistemic picture actually got worse — uncertainty widened or
contradiction grew. It never means "the tool returned an error". A failed operation that produced no
admissible evidence is `INCONCLUSIVE`: it taught nothing, and it is not evidence of anything.

Operational status (`COMPLETED` / `FAILED` / `NOT_ATTEMPTED`) is stored separately from the epistemic
result, so "the machinery worked" and "we learned something" stay distinguishable facts.

## Laws

```
 1. Curiosity success is measured by canonical state change, not by whether the result "interesting".
 2. An investigation can succeed operationally yet yield zero information.
 3. An investigation can fail operationally and remain epistemically inconclusive.
 4. Model commentary cannot mark an investigation RESOLVED.
 5. The before-state and after-state are immutable references.
 6. Information gain cannot be retroactively rewritten.
 7. Repeated low-value investigation lowers future priority.
 8. Curiosity cannot reward itself for generating more uncertainty.
 9. Closing one uncertainty may expose another, but that new uncertainty enters Gate Zero on its own.
10. Same before/after canonical history -> same outcome digest.
```

## The anti-reward-hacking specimen

```
before:  uncertainty U, canonical digests captured
run:     the investigation "produces"
           10 new questions
            5 summaries
            3 explanations
            2 "insights"
canonical 4.2 / 4.3 state: unchanged

EXPECTED: result = UNCHANGED
          information_gain = 0
```

Twenty pieces of prose are not one piece of information. The ledger digest and the world digest are
both asserted unchanged afterwards.

## Specimens that matter

**Real resolution.** A proposition that was `UNRESOLVED` converges on admissible evidence; the
uncertainty disappears and the outcome is `RESOLVED` with `information_gain > 0`.

**The model cannot award itself a result.** A model output saying *"that investigation RESOLVED the
question completely"* changes nothing; the derived result is still `UNCHANGED`.

**The measurement is immutable.** The stored `before_state` is byte-identical to the probe taken at
`begin_investigation`, closing twice raises `OUTCOME_ALREADY_CLOSED`, and the closed record's digest
does not move.

**Penalty is deterministic.** Three barren investigations of the same question give
`outcome_penalty == 1.5`, and each remains its own historical record.

**Closure exposes, it does not invent.** Resolving one uncertainty leaves the other one present as an
ordinary registry entry; nothing new is created to replace what closed.
