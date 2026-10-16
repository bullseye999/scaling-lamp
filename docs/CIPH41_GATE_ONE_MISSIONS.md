# 4.1 Gate One — Mission Continuity

Gate Zero answered *can Ciph reconstruct the truth after death?* Gate One answers the next question:

> After Ciph reconstructs the truth, can it reconstruct **what it was trying to accomplish** —
> without confusing a plan, a scheduler, or old process memory for authority?

## The layering (one direction only)

```
Mission M            durable identity and intent          survives everything below
    ↓
logical actions      durable identity of work             survives replanning
    ↓
attempts / evidence  what actually happened               Gate Zero reconstructs it
    ↓
plans                a PROPOSAL over those actions        replaceable; never authority
    ↓
scheduler            a mechanism for advancing work       never a source of truth
    ↓
permits              authority for one execution          central mint only
```

`ciph/kernel/missions.py` holds only the top two layers plus the plan *projection*. Everything it says
about actions is read straight out of `ciph/kernel/continuity.py`; it holds no signer and mints
nothing.

## The nine laws, and where each is falsifiable

`test_gate_4_1_mission_continuity.py` — 12 specimens, all green.

| # | Law | Specimen |
| --- | --- | --- |
| 1 | Mission identity is stable across restart and replanning | `test_law_1_mission_identity_is_stable` |
| 2 | A mission existing authorises nothing | `test_law_2_a_mission_confers_no_authority` — a mission + plan mint zero permits |
| 3 | Actions outlive plans | `test_law_3_and_4_actions_outlive_plans_and_plans_are_not_truth` |
| 4 | A plan is a projection, not truth | same specimen — deleting plan rows leaves actions, evidence and obligations untouched |
| 5 | Restart ≠ replan | `test_law_5_restart_does_not_imply_replanning` — `needs_replanning` comes from mission state, and a restart with an open durable plan does not set it |
| 6 | Unresolved work survives, attached to the mission | `test_law_6_unresolved_work_survives_restart_attached_to_the_mission` — same attempt id, not a replacement |
| 7 | Terminal work stays dead | `test_law_7_terminal_work_is_not_redispatched_by_a_new_plan` — a new plan naming a finished action mints nothing |
| 8 | Replanning cannot duplicate action identity | `test_law_8_a_plan_cannot_disguise_an_old_action_as_new` — reuse is reported as reuse; no fresh generation |
| 9 | Completion is evidence-based | `test_law_9_completion_is_evidence_based`, `test_law_9_an_unresolved_attempt_blocks_completion` |

## The two founding scenarios, measured

```
scenario one — kill Ciph mid-mission
    M + P1 + actions A(terminal) B(claimed, unresolved) C(issued, unattempted)
    kill, restart
    -> same M, ACTIVE
    -> A still TERMINAL from machine evidence
    -> B still UNRESOLVED, same execution_attempt_id, listed as an obligation
    -> C still NOT_ATTEMPTED with its authority alive and unspent
    -> P1 still present as planning context
    -> action count unchanged, permit count unchanged, mission still ACTIVE
    -> needs_replanning = True (there is unresolved work)

scenario two — replan P1 -> P2
    P2 names A, B, C (existing) and D (new)
    -> already_known = {A, B, C}      identities unchanged
    -> newly_attached = {D}           a genuinely new requirement gets a new action
    -> mission identity unchanged, P1 demoted to history, not deleted
```

## Completion

`complete_mission(...)` refuses while any of these remain, and names them:

```
unresolved attempts / obligations        the attempt's outcome is unknown
completion obligations                   resolved-but-not-yet-consumed permits
live authority for unattempted actions   a spendable permit attached to a finished purpose
```

The third one is a deliberate choice beyond the letter of law 9: an unused permit is not an
*unresolved effect*, but closing a mission while one of its permits can still be spent would leave
fresh authority attached to a finished purpose. Revoking the permit (dead-lettering it) is how it is
cleared - and the specimen does exactly that (`MISSION_HAS_OPEN_OBLIGATIONS`, then a revoke, then a
successful completion).

## What this makes boring later

Scheduler recovery (Gate Three) becomes mechanical, because it can no longer be a source of truth:

```
reconstruct truth          (Gate Zero)
-> reconstruct missions    (Gate One)
-> derive eligible work    (remaining_authorized_work, minus obligations)
-> resume
```
