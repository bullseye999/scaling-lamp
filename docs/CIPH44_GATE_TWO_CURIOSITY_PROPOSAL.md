# 4.4 Gate Two — Curiosity Proposal

**Question:** *how could this uncertainty be reduced?*

**Module:** `ciph/kernel/curiosity_proposal.py` — `test_gate_4_4_curiosity_proposal.py`, 11 specimens.

## The absolute law

> **A curiosity proposal grants ZERO execution authority.**

Creating one, and even *accepting* one, moves no job, no permit, no attempt and no claim. Acceptance
means:

```
this investigation is approved as a proposal
```

and never:

```
this investigation has execution authority
```

## Investigation types

```
QUERY_EXISTING_EVIDENCE     re-read what is already durable
OBSERVE                     take a new observation through governed execution
COMPARE                     contrast two existing states
RESEARCH                    consult an external source
TEST_HYPOTHESIS             run the falsification a causal hypothesis needs
RUN_SIMULATION              a counterfactual only - it can never become evidence
REQUEST_OPERATOR_INPUT      ask a human
DO_NOTHING                  the honest recommendation that this is not worth reducing
```

`DO_NOTHING` is a first-class outcome on purpose. A curiosity system that cannot conclude "this is not
worth investigating" is structurally biased toward activity.

## Laws

```
 1. Curiosity proposal != action.
 2. Proposal != permit.
 3. A proposal cannot fabricate a logical action identity.
 4. A proposal binds to the uncertainty basis it was generated from.
 5. If the uncertainty changes before acceptance -> STALE_CURIOSITY_PROPOSAL.
 6. A proposal cannot broaden capability or scope (it may only REQUEST capabilities).
 7. Simulation-only investigations remain simulations.
 8. External observation must cross the normal mission/action/permit boundary.
 9. A proposal may recommend "do nothing".
10. A rejected curiosity remains historical.
```

## Specimens that matter

**The load-bearing specimen.** Create a proposal and accept it, then assert the entire authority
footprint is still zero:

```
jobs 0 | permits 0 | attempts 0 | claims 0
```

**Optimistic concurrency for cognition.** A proposal binds the uncertainty's `basis_digest`. When the
canonical uncertainty then moves, the proposal reads `STALE`, and `accept_proposal` is refused with
`STALE_CURIOSITY_PROPOSAL` — with no durable authority side effect.

**A request is not a grant.** A proposal listing `required_capabilities=['probe.port']` leaves that
capability exactly where it was (`AVAILABLE`, not `VERIFIED`), and writes no authorization or execution
row. The self model is unchanged.

**No action identity to reuse.** The proposal record contains no `logical_action_id`, `job_id` or
`permit_id` — there is nothing to smuggle an existing action through.

**Identity is canonical.** The same investigation of the same uncertainty on the same basis, proposed
at two different moments, is ONE proposal: re-phrasing buys no second attempt.

**The module has no authority surface.** Its source contains no `acquire_durable_permit`, no
`permit_store`, no `ExecutionAuthority`, no `enqueue_job`, no `apply_plan_proposal`, no
`mint_execution_token` and no `GuardedExecutor`.
