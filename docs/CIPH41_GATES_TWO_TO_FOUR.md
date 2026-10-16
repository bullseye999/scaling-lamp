# 4.1 Gates Two–Four

```
Gate Zero   reconstruct what is TRUE                    done - continuity.py            (15 specimens)
Gate One    reconstruct what PURPOSE it belongs to      done - missions.py              (12 specimens)
Gate Two    reconstruct the current STRATEGY            done - missions.py (projections) (12 specimens)
Gate Three  reconstruct what MAY RUN NEXT               done - scheduler_recovery.py     (10 specimens)
Gate Four   kill it everywhere and prove it survives    done - restart torture matrix    (10 specimens)
```

One rule spans all four, and it is the reason they are sequenced this way:

```
truth -> mission -> current plan projection -> eligibility -> dispatch
```

never the reverse. No layer may be the source of truth for a layer beneath it.

## Gate Two — durable plan projections

> A plan describes how a mission might proceed. It never changes what already happened, never grants
> authority, and never changes the identity of an existing logical action.

*PlanProjection* rows are **append-only**. Supersession is a pointer move in
`ciph_mission_current_plan`; the projection itself is never edited or deleted, so law 12 (immutability)
and law 13 (superseded ≠ deleted) are structural rather than disciplinary. Re-recording a projection id
is refused outright (`PLAN_ALREADY_EXISTS`).

An action reference records the **canonical semantic fingerprint** taken from the authority record
(`execution_permits.action_fingerprint`) - never from the plan. A reference whose declared fingerprint
disagrees with the canonical one, or with what a previous projection recorded, is a
`PLAN_SEMANTIC_CONFLICT`. If the work changed meaning, it is a new action, not a mutated one.

The founding specimen is the requested one:

```
P1 = [A(terminal), B(unresolved), C(issued, unattempted)]
P2 = [A, B, D(new)]

A -> same id, still TERMINAL, not runnable
B -> same id, still UNRESOLVED, obligation survives
C -> absent from P2 and listed as OMITTED: still a mission action, permit still ISSUED and alive
D -> genuinely new id
P1 -> historical, references byte-identical
P2 -> current projection
M  -> same identity, ACTIVE
```

Then C is revoked as an **explicit** transition, proving plan evolution and authority evolution are
separate operations. The hostile specimen (same action id, different fingerprint) returns a hard
conflict, and re-proposing genuinely different work produces a new action id.

Plan omission therefore means exactly one thing: *not scheduled right now*. It is not cancellation,
not revocation, and not an erasure - which is what stops a planner from gaining authority by leaving
something out.

## Gate Three — scheduler recovery

The scheduler is deliberately stupid. It keeps nothing of its own and may run only what reconstruction
says is eligible:

```
TERMINAL                       -> never eligible
UNRESOLVED / UNKNOWN           -> reconciliation, not dispatch
RESOLVED_BY_OPERATOR           -> not eligible; trying again means a NEW action
NOT_ATTEMPTED + live permit    -> ELIGIBLE (when a runnable carrier exists)
NOT_ATTEMPTED + dead authority -> NEEDS_NEW_AUTHORITY; nothing is dispatched on its behalf
live permit, no runnable job   -> NEEDS_NEW_CARRIER
omitted from the current plan  -> NOT_IN_CURRENT_PLAN; still authorized, just not scheduled
```

`resume_eligible()` offers only the derived set to the dispatcher and returns what was dispatched.
A specimen asserts that exactly one action survives a crash mid-mission and that a scheduler which
*believes* a terminal action is runnable is overruled by the derivation.

One distinction the specimens forced into the open: **leaseability is a carrier property, not an
authority one.** A revoked-permit job whose row is still `QUEUED` *can* be leased - and the execution
still fails closed, because the permit store refuses the claim. The scheduler declines to dispatch it,
and the authority refuses even if something else tries. Both halves are asserted.

## Gate Four — restart torture

Eight boundaries, each built through real operations, then a restart and:

```
the canonical digest is identical across the restart
the durable journal (permits, generations, events, jobs, missions, actions, plans) is identical
the expected outcome for that boundary holds
nothing is invented
```

```
1  nothing durable but the mission          -> ACTIVE, no authority, nothing dispatchable
2  issued, never claimed                    -> NOT_ATTEMPTED, still eligible
3  leased, never claimed                    -> authority untouched (a lost delivery spends nothing)
4  claimed, no evidence                     -> UNRESOLVED, obligation, not dispatchable
5  evidence durable, not consumed           -> TERMINAL + consumption_pending; completed by recovery,
                                               and only then CONSUMED
6  after a completed execution              -> TERMINAL + CONSUMED, no redispatch
7  mid-replanning                           -> P2 current, P1 historical, omitted action keeps authority
8  after the mission completed              -> COMPLETED, nothing dispatchable
```

Boundary 4 is also exercised with a **real killed process** that claims a permit and dies: the attempt
id it created is the one reconstruction reports, the obligation is present, and nothing is
re-dispatchable.

## What the ladder buys

```
report a crash          -> reconstruct what is true          (Gate Zero)
                        -> reconstruct what it was for       (Gate One)
                        -> reconstruct the current strategy  (Gate Two)
                        -> reconstruct what may run          (Gate Three)
prove it                -> kill at every boundary            (Gate Four)
```

All four layers are deterministic: each has a canonical digest, and Gate Two/Three/Four compare those
digests across a real restart and (in Gate Zero/Two) across a real second process.
