# 4.3 Gate Zero — World State

**Question:** *what does Ciph currently model as existing, related, or unknown?*

**Module:** `ciph/kernel/world_model.py` — `test_gate_4_3_world_state.py`, 9 specimens.

## The core rule

> The world model is a **projection over epistemic state**. It is not another source of truth.

Nothing in it may create evidence simply because the model represents it. The only direction that
exists is:

```
epistemic ledger  ──project──▶  world state
```

and never the reverse.

## Shapes

```
Entity               stable identity: entity_id derived from a canonical key
WorldFactProjection  entity . relation . value @ temporal scope
                     + the proposition it traces to, its epistemic status, confidence,
                       reason codes and an evidence-basis digest
```

World statuses are deliberately **not** 4.2 belief statuses:

| Status | Means |
| --- | --- |
| `PRESENT` | the proposition's claim holds in the world |
| `ABSENT` | it does not hold (this is **not** "no evidence" — that is `UNKNOWN`) |
| `UNCERTAIN` | evidence exists but has not converged |
| `CONTESTED` | epistemically contested, so the world state is not definite |
| `STALE` | the evidence is too old to be current |
| `UNKNOWN` | nothing epistemic bears on it at all |

The single mapping from convergence to world state lives in one function (`_world_status`) and is
frozen: `CONVERGED_SUPPORTED → PRESENT`, `CONVERGED_REFUTED → ABSENT`,
`CONTESTED → CONTESTED`, `STALE → STALE`, `INTEGRITY_BLOCKED → UNCERTAIN`, anything else `UNCERTAIN`.

## Laws

```
 1. WORLD STATE != EVIDENCE.
 2. Every modeled relation traces to an epistemic proposition.
 3. CONTESTED epistemics cannot become definite world state.
 4. UNKNOWN survives projection as UNKNOWN.
 5. Time is part of state identity.
 6. Historical world states are immutable snapshots.
 7. Model output cannot directly insert a world fact.
 8. Removing support does not rewrite historical state.
 9. Same epistemic basis -> same world-state digest.
10. World-state reconstruction survives restart and model replacement.
```

## Specimens that matter

**Temporal scope is identity.** `service.x online @ T1` and `service.x online @ T2` are different
facts with different ids, so the later observation is not a contradiction of the earlier one.

**Contested cannot be definite.** An unattributable contradiction only makes a fact `UNCERTAIN`; a
*proven independent* contradiction is what reaches `CONTESTED`. Both are excluded from any definite
state, and the conservative direction is preferred.

**ABSENT is not UNKNOWN.** A refuted claim is `ABSENT`; a claim with no evidence at all is `UNKNOWN`.
These must never collapse.

**History is a snapshot series.** Re-deriving a changed state appends a new snapshot version; the
previous version is never rewritten, and an unchanged state appends nothing.

**The model is not an input.** Projecting entities, taking snapshots and running revisions in a loop
leaves the ledger digest byte-identical: the world layer reads the ledger and writes only its own
projections.
