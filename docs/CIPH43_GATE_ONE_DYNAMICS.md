# 4.3 Gate One — Dynamics / State Transitions

**Question:** *what changed from one state to another?*

**Module:** `ciph/kernel/world_dynamics.py` — `test_gate_4_3_dynamics.py`, 12 specimens.

## The promise

```
T1  service OFFLINE
T3  service ONLINE
-> OFFLINE -> ONLINE happened somewhere in (T1, T3]
```

and **not** "it came online at T2", because nothing observed T2.

## Shape

```
TransitionRecord
    entity, relation
    from_fact / to_fact, from_value / to_value
    window_lower, window_upper      # the interval the change is squeezed into
    exact_at                        # populated ONLY when the evidence pins an instant
    intermediate_observations       # how many observations sat strictly inside the window
    evidence_basis_digest
```

Identity is `(entity, relation, from_fact, to_fact)`, so re-observing the same change appends
nothing, while a *refined* window derives a **new** id and is appended — the wider one stays as
history.

## Laws

```
1. State difference != causal explanation. A transition carries no cause and has no API for one.
2. A transition records change, not why it changed.
3. Missing intermediate observations remain UNKNOWN.
4. Temporal ordering must be evidence-backed: an unorderable scope forms no transition.
5. Transition history is append-only.
6. Later evidence may REFINE a window; it may never fabricate an exact time.
7. Repeated observations of the same transition do not duplicate it.
8. World dynamics reconstruct deterministically.
```

`require_exact_time()` is the guard behind law 6: a caller that needs a precise moment is *refused*
(`TRANSITION_TIME_NOT_OBSERVED`) rather than handed a guess.

## The hostile specimen

Observe T1 and T3, never T2. The derived record must report a window, must refuse
`require_exact_time()`, and `describe_window()` must read `somewhere in (T1, T3]` — the string must
not contain a T2.

## A refutation is not a state (finding, closed)

An early version admitted **both** `PRESENT` and `ABSENT` world facts as "state values", which meant
the *asserted claim* of a refuted fact was read as the world's state. Two reachable cases were
reproduced:

```
CASE A   HEALTHY@T1 and DEGRADED@T2 present; "HEALTHY@T3" refuted
         -> world is still DEGRADED at T3
         WRONG: a fabricated DEGRADED -> HEALTHY "recovery"

CASE B   HEALTHY@T1, DEGRADED@T2 present, HEALTHY@T3 present,
         and "DEGRADED@T3" refuted
         WRONG: an extra DEGRADED -> HEALTHY transition with exact_at = T3,
                an invented instant, from a claim the evidence denied
```

An `ABSENT` fact is knowledge that a claim **did not hold**, which is not the same token as a state
value — "not healthy" is not "degraded". Treating it as one narrates changes that never happened and
can pin an invented moment to them, which is precisely what this gate exists to prevent.

The fix: **only a `PRESENT` fact establishes a world state.** A state that matters is asserted as its
own `PRESENT` proposition (which is already how Gate Zero's founding specimen encodes "offline": as
`is_online = False`, present). Where that leaves a relation under-described, dynamics **under-reports
rather than inventing a transition** — the same direction the rest of the constitution resolves
uncertainty.

Two specimens lock this down: a later refutation cannot fabricate a recovery, and a same-scope
refutation of the complement cannot add an instant-pinned flip.
