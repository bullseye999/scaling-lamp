# CIPH 10.x — 10.9 INDEPENDENT EXPEDITIONS + 10.10 INCUBATION & COGNITIVE MODES

**Status:** IMPLEMENTED · ADVERSARIALLY VERIFIED · FULL-TREE AND CLONE SWEEPS GREEN · **10.x NOT SEALED**
(R13 and R14 stay OPEN; CiphOS 9.x stays on its independent privileged-host SEAL HOLD).

```text
A system deciding that a question is worth investigating does not establish permission to investigate it.

Interestingness is not authorization.   A hypothesis is not a discovery.
A promise of exploration is not an execution right.  A mode is a projection, not an authority.
Ciph must never confuse wanting to investigate something with having permission to investigate it.
Ciph must never confuse having an interesting hypothesis with having made a discovery.
```

---

# PART A — ownership

**Two new owners, and nothing else.**

| Concern | Canonical owner |
| ------- | --------------- |
| expedition identity, authorization decisions, checkpoints, notification candidates | `ciph/kernel/independent_expeditions.py` (10.9, NEW) |
| hypothesis lineage, question review, operating-mode projection, resource envelope | `ciph/kernel/incubation.py` (10.10, NEW) |
| uncertainty and question derivation | `ciph/kernel/uncertainty_registry.py` (4.4) |
| curiosity proposals and their priority | `ciph/kernel/curiosity_proposal.py`, `curiosity_priority.py` (4.4) |
| standing authorization, autonomy modes, budgets | 5.x (`standing_authorization`, `autonomy_modes`, `autonomy_budgets`) |
| worker delegation and results | 6.x |
| durable findings and result sets | `ciph/kernel/referential_continuity.py` (10.0) |
| relationships, anomalies, attention, baselines | 10.5, 10.8, 10.6 |

**Census:** `ciph/kernel/expedition_ownership.py` (8 concerns, clean, catch-specimen for every zero). It
forbids a rival expedition/hypothesis store, a forged canonical write, a minted permit, a second curiosity
priority, a second mode authority, a module that reasons by itself, and a fabricated delivery or finding.

---

# PART B — 10.9 independent expeditions

**Selection is not permission.** `select_candidates` ranks worthwhile questions using 4.4's OWN curiosity
priority (which itself "authorises nothing") plus 10.8 anomalies, 10.5 contradictions and 10.4 disputes, and
returns every candidate marked `authorization_required: True` and
`interestingness_is_not_authorization: True`. It executes nothing.

**The authorization boundary is 5.x's.** `authorize_expedition` consults the autonomy MODE first (which can
only be more restrictive), then the grant's STATUS, then the owner's own `assert_work_permitted` for work
class, scope and risk ceiling. A refusal is recorded with the owner's verbatim reason and the expedition stays
`REFUSED`. No expedition mints a permit, widens its scope, renews an expired grant, changes authority rules,
scans an unapproved target, self-deploys, conceals consumption or converts enthusiasm into standing authority.
`revalidate` stops a long-running expedition whose grant expired or was revoked, and reports
`renews_itself: False`.

**Lifecycle mapped to existing states** with a transition table that refuses impossible moves:
`PROPOSED -> ACTIVE/REFUSED -> PAUSED/INTERRUPTED -> COMPLETED/INCONCLUSIVE/FAILED/EXPIRED`. An inconclusive
expedition stays inconclusive and carries no result set.

**Findings and notification.** `record_result` commits through 10.0, so two expeditions with identical
findings keep distinct identities and revisiting old evidence is not a new discovery.
`create_notification_candidate` produces a durable, evidence-backed CANDIDATE with `external_delivery: False`
and `delivered: False`, and `claim_external_delivery()` REFUSES
(`NO_EXTERNAL_NOTIFICATION_TRANSPORT_IS_WIRED`) - 10.13 will own that adapter.

---

# PART C — 10.10 incubation

**A hypothesis is never a result.** `generate_hypothesis` records `HYPOTHESIS` with its full lineage: source
question, origin evidence, the reason the connection was proposed, whether a model participated (and its
identity), supporting and contradictory evidence, the proposed verification method, authorization status and a
resource estimate. `set_status` REFUSES a "verified" status outright
(`A_VERIFIED_FINDING_IS_COMMITTED_TO_10_0_NOT_CLAIMED_HERE`), and support or refutation each require an
evidence reference.

**No false novelty.** The novelty key is order-independent over the normalised tokens, so a re-wording is
reported as a `paraphrase_of` the existing hypothesis rather than suppressed, while a genuinely distinct
question stays novel. Two distinct investigations with identical final evidence keep distinct identities.

**Review sources** are existing evidence: unresolved 4.4 questions, unexplained 10.8 anomalies (with
`cause: None`) and inconclusive experiments - each marked `executes_nothing: True`.

---

# PART D — cognitive operating modes

`operating_modes` is a **projection**, not an authority: `is_an_authority: False`, `grants_permission: False`,
`mutually_exclusive: False`. It reads 5.x (autonomy mode, quiescence), 10.3 (sensor freshness), 10.6 (model
availability and pending attention) and the expedition/delegation state, and reports which of
`OBSERVING` / `DELIBERATING` / `INVESTIGATING` / `INCUBATING` / `GOVERNED_HOLD` are active, each with its
evidence. Several hold at once - background observation and an authorized investigation genuinely coexist.
`GOVERNED_HOLD` is populated from its OWNER's blocking condition (5.x mode, 6.x quiescence), never invented
here. `model_outage_behavior` lists what may continue and states `may_claim_new_reasoning: False`.
`resource_envelope` reports measured counters (inference calls this window, queued requests, live workers,
concurrent expeditions) and NAMES what it cannot measure rather than fabricating precision.

---

# PART E — continuity and future communication

Findings are committed through 10.0 and retrieved through the same conversational path (the founding scenario
reopens a session and reads the exact result set). Notification candidates carry the real investigation
reference, the finding references, a confidence, an uncertainty and a relevance reason - and no delivery
claim. No Session adapter, no personality change.

---

# PART F — the founding scenario (executed, 32 steps)

A bounded standing objective -> authorization verified -> operator absent -> the model unavailable -> the fabric
keeps collecting -> homeostasis produces an evidence-backed anomaly with NO cause -> an unresolved research
question is also eligible -> attention evaluates with no model and NO fictional deliberation is recorded ->
the model returns -> Ciph evaluates real evidence, selects an expedition, passes the existing authority checks,
delegates to existing workers -> one result supports and another contradicts -> the conflict stays UNRESOLVED
-> an urgent event interrupts attention and the expedition context is preserved -> a worker goes unavailable
and Ciph does NOT fabricate progress -> the expedition pauses and resumes through the legitimate lifecycle ->
a finding is committed through 10.0 -> a separate hypothesis stays explicitly unverified -> an evidence-backed
notification candidate is created with no delivery claim -> operator returns and retrieves the exact results and
the hypothesis's support, contradiction and uncertainty -> a FRESH PROCESS reconstructs the expedition,
hypothesis and conversation digests identically -> zero permits, zero deployments, zero invented authority.

---

# PART G — adversarial torture (30 cases)

selection without a valid grant · expired grant mid-expedition · refused scope/class · model unavailable
during deliberation · hypothesis announced as a discovery · an old finding not repackaged as new · distinct
investigations with identical findings · a worker that never attested · contradictory workers left UNRESOLVED ·
a disconnected node not presumed complete · a revoked grant stopping the expedition · a narrower grant
refusing the tool scope · an anomaly without a cause claim · a sensor alarm authorizing nothing · idle
producing no fictional reasoning · interruption preserving the expedition context · impossible lifecycle
transitions refused · an inconclusive expedition staying inconclusive · duplicate attention spending no second
budget · a paraphrased hypothesis reported as a paraphrase · a fabricated permit/finding/delivery refused by
the census · a starved attention queue not blocking deterministic paths · fresh-process reconstruction.

---

# PART H — verification

```text
frozen tree         ab59399dd087f6d1974bc3531be9aa99   (identical before and after BOTH sweeps)
full project sweep  Ran 2062 tests in 1706.500s   OK    (186 test files)
sanitized clone     Ran 2062 tests in 1234.994s   OK    (186/186 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (2062 both; 2025 + 37 = 2062).

```text
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                    10.1/10.2 conversation 10 · 10.7/10.8 reflex 10 · 10.9/10.10 expedition 8 ·
                    federation 19 · swarm 15 · R6 15 (0/0/0) · sovereignty 19 - all clean in BOTH trees
schema ownership    244 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.x in production
affected regressions 316 tests green across every 10.x gate and the 4.4/5.x/6.x/7.x owners
```

**Measured overhead on this host** (no model anywhere in either module):

```text
select_candidates     200x : 1.925 s   (9.63 ms/call)
operating_modes       200x : 1.366 s   (6.83 ms/call)
generate_hypothesis   200x : 0.867 s   (4.34 ms/call)
model invocations           : 0
CPU for the benchmark       : 3.700 s
max RSS delta               : 2872 kB
UNMEASURABLE (named, not estimated): token consumption (no provider accounting is wired),
                                     network usage (no governed egress accounting on this host)
```

## Defects this campaign found in its own new code (each caught by a specimen)

1. The transition table forbade `PROPOSED -> ACTIVE`, so a legitimate authorization could not activate an
   expedition; authorization IS the transition to work, and the edge was added.
2. The specimens asserted a refusal string the OWNER does not use; they now assert the owner's actual reason
   (`...SCOPE...`) rather than a spelling invented here.
3. A second worker arriving on the SAME delegation is correctly `LATE` for the lease but is still retained,
   which is how a contradiction is detected - the specimens now model that properly instead of creating two
   unrelated delegations.
4. Re-registering a worker role allocates a NEW generation, which silently made earlier arrivals `LATE`; the
   specimen helper now caches one identity per role, and the finding is recorded because it is a genuine trap
   for any caller that re-registers.
5. `revoke_standing_authorization` requires an explicit `actor`; the specimen was missing it.

## Honest limitations

- No real Session transport exists and none is claimed; notification candidates are durable records only.
- No real model participated: a clearly identified test double stands in for the deliberation step, so the
  ORCHESTRATION is proven and the CREATIVE QUALITY of autonomous reasoning is NOT verified here.
- Token and network consumption cannot be measured on this host and are reported as limitations rather than
  estimated.
- The census is syntactic and cannot catch an alias or obfuscation.
- 4.4's priority is reused rather than reimplemented, so the quality of "worthwhile" inherits its own
  declared scoring limits.
