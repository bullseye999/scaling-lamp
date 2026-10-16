# CIPH 10.x — 10.1 UNIFIED CONVERSATIONAL CONTINUITY + 10.2 PERSISTENT OPERATIONAL PRESENCE

**Status:** IMPLEMENTED · ADVERSARIALLY VERIFIED · FULL-TREE AND CLONE SWEEPS GREEN · **10.x NOT SEALED**
(R13 and R14 stay OPEN; CiphOS 9.x stays on its independent privileged-host SEAL HOLD).

```text
Conversational memory is not an alternative source of operational truth.

A conversational record establishes what was SAID, by whom, in which conversation - and nothing more.
An execution claim must resolve to execution evidence.  A discovery claim must resolve to findings.
A commitment is a promise, not permission.  Persistent presence does not require constant activity.
Ciph must not confuse remembering a promise with having fulfilled it.
```

---

# PART A — ownership

| Concern | Canonical owner |
| ------- | --------------- |
| conversation participants, channels, sessions, turns, questions, regenerable summaries | `ciph/kernel/conversational_continuity.py` (10.1, NEW) |
| channel adapters and the interface-independent contract | `ciph/kernel/conversation_channels.py` (10.1, NEW) |
| presence, commitments vs authorization, honest progress, resumption, initiative boundary | `ciph/kernel/operational_presence.py` (10.2, NEW) |
| durable findings, result sets, announcements, follow-ups | `ciph/kernel/referential_continuity.py` (10.0) |
| epistemic observations and evidence | `ciph/kernel/epistemic_ledger.py` (4.2) |
| remaining authorized work, dead authority, unresolved attempts | `ciph/kernel/continuity.py` (4.1) |
| investigation identity | `ciph/kernel/governed_investigation.py` + `curiosity_proposal.py` (4.4) |
| standing authorizations | `ciph/kernel/standing_authorization.py` (5.x) |
| worker delegations and results | `ciph/kernel/swarm_*.py` (6.x) |
| federation identity | `ciph/kernel/federation_node.py` (7.x) |
| relationship projection | `ciph/kernel/operational_awareness.py` (10.5) |
| attention checkpoints | `ciph/kernel/selective_attention.py` (10.6) |
| existing conversational mechanisms, reclassified not replaced | `smart_memory.py` (utterances), `enhanced_conversation.py` (presentation) |

**Census:** `ciph/kernel/conversation_ownership.py` (10 concerns, clean, catch-specimen for every zero). It
enforces the two rules that matter: the conversation modules may never WRITE a canonical table (permits,
standing authorizations, findings, observations, swarm results, deployments), and a summary must be marked
non-canonical in code as well as in prose.

---

# PART B — 10.1 unified conversational continuity

**B1 durable identity.** Participants (with a role and an authority ref), channels, sessions, turns, questions
and summaries all carry durable identities. Turns carry ordinal ordering, speaker, kind, provenance and
VALIDATED references: a reference is recorded with `resolved: true` only if the owning module can confirm it
(a finding in 10.0, a result set, an investigation, a 6.x worker result, a 10.6 focus). Every `record_turn`
return states what it establishes ("what was said, by whom, in which conversation") and what it does **not**
("that the statement was correct", "that an action occurred", "that work is authorized"). A fresh process
reconstructs the same history from durable rows - `used_the_model_context_window: False`.

**B2 referential understanding.** `resolve_reference` resolves deterministically FIRST (10.0 owns ordinals and
result sets), then the conversational cases: a prior session ("what were we talking about before I
disconnected" -> the closed session), which worker ("which worker investigated that" -> the 10.5 correlation),
"continue the investigation" (-> the result set). Where several referents are plausible the AMBIGUITY is
returned with its candidates rather than silently resolved; where nothing resolves it says so.

**B3 two genuine channel adapters.** `LocalTerminalChannel` and `DisposableMessageChannel` are separate
disposable adapters over the SAME continuity contract; the second models the shape of Session's future
messaging integration. Identity and access are re-checked on the way IN (`receive`) and on the way OUT
(`authorized_history`), so a forged or unauthorized participant is refused whatever channel it arrives on. A
local adapter reports `external_delivery: False` and **refuses** to claim external delivery; the message
adapter's states are `QUEUED_NOT_TRANSMITTED`, never "delivered", and it claims no external identity
verification.

**B4 context selection.** `context_selection` integrates with 10.6: bounded turn references plus focus refs,
with summaries offered as clearly-marked NON-CANONICAL hints. Canonical evidence stays in its owner, so a
stale summary cannot override newer canonical evidence, and a summary may be regenerated while the canonical
history is untouched.

---

# PART C — 10.2 persistent operational presence

**C1 commitments are not authorization.** A COMMITMENT turn optional-carries an `authorization_ref`;
`commitment_authorization` resolves that pointer against the granting owner (5.x `authorization_status`) and
**never grants anything**. With no reference it is `NO_AUTHORIZATION_ATTACHED`; an unresolvable reference is
`AUTHORIZATION_REFERENCE_DOES_NOT_RESOLVE`; a revoked or expired grant is `AUTHORIZATION_IS_NOT_ACTIVE`.

**C2 honest progress.** `honest_progress` and `absence_report` derive progress ONLY from the authoritative
work owner (6.x results, 10.0 announcements). A paused investigation did not progress overnight: the report
says `nothing_authorized_happened: True` and `elapsed_time_is_not_progress: True`. A delegation that is not
COMPLETED is listed as outstanding, never as progress. Work that is not `CURRENT` is reported as unverified.

**C3 recovery and resumption.** `resume_plan` reconstructs a subject's last verified state and the 4.1
`remaining_authorized_work` / `dead_authority` / `unresolved_attempts`, and refuses to restart consequential
work under expired permission (`may_resume_under_expired_permission: False`). The original identity is kept.

**C4 initiative boundaries.** `initiative_boundary` records a vague wish as a preference: `authorization_granted:
False`, `proposal_allowed: True`, naming the owners that actually permit work.

---

# PART D — the founding integrated scenario (executed)

operator establishes an authorized investigation (5.x grant) -> Ciph produces seven real findings -> announces
them -> asks for the third and receives the exact third finding -> authorizes further work with a COMMITMENT
pointing at the real grant -> Worker A runs an authorized task and Worker B produces a related result ->
10.5 correlates the result to the investigation -> a 10.6 attention checkpoint preserves the investigation
context -> the main LLM goes unavailable and authorized machinery pauses safely -> the conversational process
restarts and operator contacts Ciph through the SECOND authorized channel -> "What happened with that third
idea?" returns the original finding, the worker results and the restored attention context -> "What happened
while I was away?" separates completed work from outstanding work -> a fresh process reconstructs the
identical conversation, presence and attention digests -> no permit, no deployment and no invented history.

---

# PART E — negative specimens (24)

two twenty-finding sets stay distinct · ambiguous ordinal exposed · a summary cannot override canonical
evidence · a completion claim needs result evidence · summary regeneration supersedes only the previous
summary · an interrupted subject keeps identity and refuses expired authority · a disconnected node is not
currently active · duplicate deliveries do not duplicate turns · two simultaneous conversations reference
different investigations · a model inventing history creates no turn · an attention checkpoint survives a
conversation restart · model outage with durable continuity persisting · outstanding questions survive and can
be answered · bounded context selection · a forged participant cannot reach private history · a local adapter
cannot claim external delivery · an untrusted channel is refused · an unknown grant reference authorizes
nothing · a promise without a reference authorizes nothing · a vague wish authorizes nothing · a paused
investigation did not progress overnight · an honest absence report when nothing happened · an absence report
that names real completions · fresh-process reconstruction with identical canonical references.

---

# PART F — verification

```text
frozen tree         4829f5ddb2fa2ed669b4136d4bce8511   (identical before and after BOTH sweeps)
full project sweep  Ran 1991 tests in 1712.811s   OK    (184 test files)
sanitized clone     Ran 1991 tests in 1204.326s   OK    (184/184 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (1991 both; 1954 + 37 = 1991).

```text
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                    10.1/10.2 conversation 10 · federation 19 · swarm 15 · R6 15 (0/0/0) ·
                    sovereignty 19 - all clean in BOTH trees
schema ownership    231 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.x in production
affected regressions 243 tests green across the 10.x gates and the 4.1/4.2/4.4/6.x/7.x owners
```

## Defects this campaign found in its own new code (each caught by a specimen)

1. The founding scenario assumed 10.0's `announce()` return carried the `statement`; it carries the verified
   count and status, so the specimen now asserts those instead of a field that does not exist.
2. A stored TURN row does not carry the `does_not_establish` boundary (that is on the record's RETURN value);
   the specimen was corrected rather than the row being widened.
3. `absence_report` filtered delegations by invented status names (`PROPOSED`/`CLAIMED`/`PAUSED`); the real
   lifecycle is `ELIGIBLE` -> `COMPLETED`, so outstanding work is now "anything not COMPLETED".
4. The same invented status was used for `awaiting_decision`; it is now `ELIGIBLE`.
5. The founding scenario asserted a single task's worker results by index; the projection orders tasks by
   delegation id, so the assertion now searches the produced result set.
6. A subject with no witness resolves to `UNKNOWN`, not `STALE` - both are honest, and the specimen now
   accepts either while still refusing a "subject failed" reading.

## Honest limitations

- The second channel is a LOCAL disposable adapter. It does not deliver anything outside this process, and no
  real Session delivery or external identity verification is claimed.
- No privileged-host or hardware-attestation claim; 9.x remains on HOLD.
- The census is syntactic and cannot catch an alias or obfuscation.
- "Honest progress" is only as good as the owners it reads; it reports what they recorded and never infers.
