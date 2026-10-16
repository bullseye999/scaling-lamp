# 4.4 Gate Zero — Uncertainty Registry

**Question:** *what exactly is unknown, contested, weakly modelled, or prediction-poor enough to
deserve attention?*

**Module:** `ciph/kernel/uncertainty_registry.py` — `test_gate_4_4_uncertainty_registry.py`, 11
specimens.

## The core rule

Curiosity targets are **derived**, never invented. There is deliberately no `add_uncertainty`,
`create_uncertainty` or `nominate_uncertainty`: the only way something becomes a target is for
canonical 4.2/4.3 state to already say the uncertainty exists. A model that finds something
interesting cannot manufacture a question to chase.

## The source kinds

| Kind | Traces to |
| --- | --- |
| `EPISTEMIC_UNRESOLVED` | convergence `UNRESOLVED` **with real evidence behind it** |
| `EPISTEMIC_CONTESTED` | convergence `CONTESTED` |
| `WORLD_STALE` | a world fact whose evidence is too old to be current |
| `WEAK_CAUSAL_HYPOTHESIS` | a hypothesis that is `PROPOSED`, `STALE` or `CONTESTED` |
| `DYNAMICS_GAP` | a bounded state change whose interior was never observed |
| `SELF_MODEL_UNKNOWN` | a capability that is not `VERIFIED` |
| `CALIBRATION_WEAKNESS` | predictions that expired unresolved, so they can never be scored |

The evidence requirement on `EPISTEMIC_UNRESOLVED` is law 3 in practice: a proposition that only a
model ever *mentioned* is not a target, otherwise every sentence Ciph utters would mint a question.

## The frozen reducibility policy

```
EPISTEMIC_UNRESOLVED       POSSIBLY_REDUCIBLE
EPISTEMIC_CONTESTED        POSSIBLY_REDUCIBLE     # law 4: contested is not automatically reducible
WORLD_STALE                REDUCIBLE
WEAK_CAUSAL_HYPOTHESIS     REDUCIBLE
DYNAMICS_GAP               REDUCIBLE
SELF_MODEL_UNKNOWN         REDUCIBLE
CALIBRATION_WEAKNESS       POSSIBLY_REDUCIBLE
anything with an INTEGRITY conflict -> IRREDUCIBLE (investigation cannot fix a broken provenance)
```

## Status is derived, never stored

```
OPEN        derivable now, and the recorded projection matches the current basis
STALE       derivable now, but the recorded projection was built on an older basis
SATISFIED   no longer derivable - the underlying state resolved, so the question closed itself
INVALID     this id was never derivable and never recorded
```

Closure is automatic. There is no `resolve_uncertainty`, `satisfy_uncertainty` or
`close_uncertainty`: a question ends because the evidence moved, not because someone decided it had.

## Laws

```
 1. Curiosity cannot create an uncertainty merely because the model finds something interesting.
 2. Every uncertainty traces to canonical 4.2/4.3 state.
 3. UNKNOWN is not automatically a problem worth solving.
 4. CONTESTED is not automatically reducible.
 5. The uncertainty is immutable as a historical record; a new basis is a new projection version.
 6. If the underlying epistemic/world state resolves, the uncertainty closes automatically.
 7. Model phrasing does not change uncertainty identity.
 8. Same canonical uncertainty state -> same digest after restart.
```

## Specimens that matter

**Closure is derived.** A proposition with one grounded support is `UNRESOLVED` and produces a record;
adding a second support converges it, and the record disappears with status `SATISFIED` — while the
single earlier snapshot stays exactly as it was.

**Identity is the uncertainty, not the phrasing.** `uncertainty_id_for(kind, source_ref)` is a hash of
what is uncertain; re-deriving twice yields identical ids, and no `interesting` ever appears in one.

**History is a series.** A basis change appends snapshot version 2 and leaves version 1 byte-identical.

**The registry is not a source of evidence.** Deriving, snapshotting and digging in a loop leaves the
ledger digest and the world digest unchanged.
