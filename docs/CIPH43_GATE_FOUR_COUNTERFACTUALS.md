# 4.3 Gate Four — Counterfactual / Simulation Model

**Question:** *if X changed, what might happen?*

**Module:** `ciph/kernel/counterfactuals.py` — `test_gate_4_3_counterfactuals.py`, 10 specimens.

## The most important law

> **Simulation results are never observations, evidence, or world facts.**

They are hypothetical projections. Every simulation carries `epistemic_kind = "SIMULATION"`, and the
module imports **no** ledger, permit or execution machinery — so there is no call path from a
simulation to evidence or to authority, structurally rather than by reviewer discipline.

## Shape

```
Simulation
    simulation_id, simulation_fingerprint
    model_version = COUNTERFACTUAL_PROJECTION_V1
    world_basis_digest          # the world state the projection started from
    assumptions, interventions, projected_outcomes
    epistemic_kind = SIMULATION
```

The basis is captured (or supplied explicitly by a caller that already holds one), and identity is
canonical: the same basis, assumptions, interventions and model produce **one** simulation.
`attach_outcome(...)` scores a projection against reality afterwards and appends a separate row,
never editing the projection.

## Laws

```
 1. Simulation begins from an explicit world-state basis.
 2. Assumptions are explicit.
 3. Interventions are explicit.
 4. Simulated output never modifies the canonical world state.
 5. Simulation cannot create evidence.
 6. Simulation cannot issue execution authority.
 7. Multiple counterfactuals may coexist.
 8. Unknown model dynamics remain unknown, not filled with confident narrative.
 9. A simulation becomes a real 4.2 prediction only through that gate's separate boundary.
10. Actual observations may score the simulation afterward, but cannot rewrite what it projected.
11. Same basis + assumptions + deterministic model -> same simulation digest.
12. Historical simulations are immutable.
```

## Founding specimen

```
world: service X degraded

S1  IF rollback deployment D  THEN projected health restored (p = 0.7)
S2  IF do nothing             THEN projected stays degraded

NEITHER changes world.service_x.status
NEITHER creates evidence
NEITHER issues a permit, an action or a prediction
```

Only if the operator or planner *separately* decides to act does the normal execution constitution
start.

## Specimens that matter

**Nothing canonical moves.** Two simulations leave the ledger digest, the world digest and the
derived fact set byte-identical.

**A simulation is refused as evidence.** `as_evidence_ref(...)` raises
`SIMULATION_IS_NOT_EVIDENCE`, and the evidence table stays empty.

**No authority surface.** The module source imports no permit/authority module, exposes no
`execute`/`issue_permit`/`dispatch`, and creates no prediction.

**Determinism.** Same inputs → same `simulation_id` even when run at a different wall-clock moment;
different assumptions → a different id; and a second process reproduces `simulation_digest`.

**Reality cannot rewrite the projection.** Scoring a simulation `matched = False` leaves the
simulation's digest unchanged and appends an outcome record instead.

**UNKNOWN stays UNKNOWN.** A projection whose outcome is unknown is preserved as unknown; no evidence
or world fact is invented to fill it.
