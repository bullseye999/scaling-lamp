# 4.1 Gate Five — planner-driven replanning

> The planner may propose a new projection. It may not rewrite mission truth, choose authority, or
> silently redefine an existing action.

```
Mission reconstruction
        ↓
canonical state + digest H
        ↓
Planner                     (ciph.planner.schemas.ExecutionDAG - the REAL planner object)
        ↓
PlanProposal(H)             ephemeral: existing action refs + proposed new semantic work + coverage
        ↓
validator / materializer    freshness, fingerprints, membership, identity allocation, NO permit
        ↓
record_plan()               append immutable projection + move the current pointer
```

## The two load-bearing properties

**1. Replanning is bound to the state it planned against.** `PlanProposal.basis_continuity_digest` is
optimistic concurrency for cognition. `apply_plan_proposal` runs one `BEGIN IMMEDIATE`, recomputes the
mission digest *inside* that transaction, and refuses with `STALE_PLAN_PROPOSAL` if it moved. The LLM
does not need to be deterministic; it only needs to be unable to commit a projection generated against
stale truth. A refusal leaves **zero durable side effects** - no projection, no pointer move, no new
action.

**2. Omission requires explicit completeness.**

```
coverage = COMPLETE   absence means "not scheduled now" -> omitted_action_ids (never cancelled)
coverage = PATCH      absence means NOTHING            -> cannot pause anything
```

A PATCH layers onto the last exhaustive projection, so a truncated or partial planner response cannot
pause legitimate work by failing to mention it - while a complete plan can still pause work by
omission, which remains exactly a pause.

## Identity, one-way

The planner states **semantics**; the canonical layer allocates **identity**. `NewActionProposal`
carries capability/parameters/target and a label, never a logical action id. Existing work is the
opposite: the planner must reference it by explicit id (`reuse={step_id: logical_action_id}`), and the
reference's canonical fingerprint - taken from the authority record, never from the plan - must agree.
Similarity is never enough to reuse an identity, and a disagreement is a hard conflict.

Planned work that has no authority yet is reported as `unauthorised_action_ids`: real work the mission
intends, invisible to Gate Zero (which speaks only about attempts and authority), and never
dispatchable - `NEEDS_NEW_AUTHORITY`, "planning grants nothing".

## Production entry point

`CiphRuntime.plan_mission(mission_id, dag=..., reuse=..., coverage=...)` is the bridge: reconstruct the
mission, feed the planner's real `ExecutionDAG` to the proposal validator, let the canonical layer
decide. It plans; it never authorises.

Deliberately **not** wired into `execute_dag_plan`: making every DAG execution mission-scoped is a
product decision about which work belongs to a mission, and 4.1 should not take it silently. Callers
that run missions call this explicitly.

## Specimens (12, all green)

```
1  a real planner proposal records an immutable projection; the new step gets an allocated
   ACT- identity and planning mints NO permit
2  changed semantics for an existing action -> PLAN_SEMANTIC_CONFLICT, pointer never moves
3  a stale basis -> STALE_PLAN_PROPOSAL with zero durable side effects
4  a partial (truncated) response cannot pause work
5  a complete projection may omit, and omission is only a pause
6  a plan cannot make terminal work runnable
7  omitting an unresolved action keeps the obligation
8  a plan cannot resurrect operator-resolved work; repeating it is a NEW action
9  a planner that crashes after proposing leaves nothing durable
10 a crash after recording reconstructs the same projection (P2 current, P1 historical)
11 the runtime bridge is the production entry point, and it plans without authorising
12 the bridge refuses a stale planner
```

## Long-lived plans, cleanly defined

```
not:  the LLM remembers the plan
but:  accepted immutable projections persist
      + the current pointer persists
      + mission and actions persist
      + the planner can be recreated from nothing
```

The planner can die every five minutes and continuity still works.

## Known sharp edge (fail-closed, documented)

The kernel's action fingerprint includes whether a scope grant is present, so if a later enqueue
authorises planned work *with* a scope, the canonical fingerprint will differ from the plan-time
proposal and a later plan reference to it reports a conflict instead of silently accepting the drift.
Scope-ness is part of the kernel's notion of semantic identity; surfacing the disagreement is the
honest direction. If planned→executed binding should tolerate that difference, it needs an explicit
decision, not a quieter comparison.
