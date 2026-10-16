# 4.4 Gate Three — Governed Investigation

**Question:** *what happens when curiosity is finally allowed to cause something?*

**Module:** `ciph/kernel/governed_investigation.py` —
`test_gate_4_4_governed_investigation.py`, 8 specimens.

## The composition

```
uncertainty -> priority -> proposal -> governance decision
    -> logical action (allocated by the canonical mission layer)
    -> permit (minted ONLY by the central authority)
    -> GuardedExecutor
    -> Observation
```

There is **no second executor, no curiosity signer and no curiosity permit path**. The module contains
no signing key, no `ExecutionAuthority`, and no `PermitStore.claim`. The one authority step it performs
is a call to the canonical producer entry point, `acquire_durable_permit`, exactly as any other
producer does.

## Laws

```
 1. All external investigation uses the existing execution authority system.
 2. Curiosity has no private signer.
 3. Curiosity has no PermitStore.claim path.
 4. Curiosity cannot bypass mission/authorization boundaries.
 5. Investigation results enter as Observation first, not as conclusions.
 6. Failed investigation != disproven hypothesis.
 7. No-result investigation fabricates no epistemic evidence.
 8. Investigation side effects obey normal effect-certainty/reconciliation rules.
 9. Curiosity retries obey the normal A' generation law.
10. Restart cannot duplicate an investigation already claimed or resolved.
```

## Specimens that matter

**The boundary holds.** An un-accepted proposal cannot even *prepare* an investigation:
`PROPOSAL_NOT_ACCEPTED`, with zero mission actions. Curiosity cannot route around governance by
preparing work early.

**The identity is allocated, not chosen.** `prepare_investigation` produces a canonical `ACT-...`
identity from the mission layer. Preparing twice yields the same action, and exactly one mission-action
row. The permit is then bound to that same `logical_action_id` — curiosity cannot dress an old action
up as new to obtain fresh authority.

**Preparing is not authorising.** After `prepare_investigation`: zero jobs, zero permits. After
`authorize_and_enqueue`: one job and one permit, and the action's permit state is `ISSUED` with
`execution_attempt_id is None` — no attempt exists until a worker claims it.

**Operational success is not epistemic success.** A `SimpleComputeCapability` executes with
`exit_code == 0`, the permit is `CONSUMED` through the normal path and the attempt becomes `TERMINAL` —
and the ledger evidence count and world digest are both unchanged. A command can run perfectly and
teach Ciph absolutely nothing.

**A result is an observation.** `record_investigation_observation` writes an `OBS-` record and nothing
else: the evidence count is unchanged, because receiving a result asserts nothing about the world.

**The crash specimen.** Claim the permit, then let the process die before any evidence exists. After a
restart on the same durable stores:

```
same ACT | same permit | attempt UNRESOLVED | authorization_alive False
jobs 1 | permits 1 | attempts 1
```

Re-running the authorization path cannot produce a second job or a second permit, because the job id
and idempotency key are derived deterministically from the proposal.

## A collision this gate exposed

The first integration of the 4.2 ledger with the runtime failed: two subsystems both claimed
`ciph_observations`, with different shapes, and were mutually exclusive in one database. See
`REGISTER.md` R4 — the older `MaterializedWorldview` table was renamed to `ciph_mv_observations`, and
the sealed ledger was left alone.
