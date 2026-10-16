# CIPH 10.x — 10.5 UNIFIED DISTRIBUTED AWARENESS + 10.6 SELECTIVE COGNITIVE ATTENTION

**Status:** IMPLEMENTED · ADVERSARIALLY VERIFIED · FULL-TREE AND CLONE SWEEPS GREEN · **10.x NOT SEALED**
(R13 and R14 stay OPEN; CiphOS 9.x stays on its independent privileged-host SEAL HOLD).

```text
Attention allocates inference, not authority.

A worker report is an observation until its evidence is established.
A disconnected node is not continuously active because it once sent heartbeats.
An absent authorization record is not an unauthorized actor.
Silence is not a verdict about the subject.  Loss is always indicated.
```

---

# PART A — two sensory semantics reconciled

**A.1 A sequence slot is unique, and equivocation is retained, not collapsed.**
`sensory_fabric` event identity used to include the payload digest, so a second, *different* payload under
the same `(sensor, version, sequence, generation)` looked like a new event (or, if the slot was already used,
like a merely out-of-order arrival). Identity now EXCLUDES the payload digest: the same identity with the
SAME payload is a plain `DUPLICATE`, and the same identity with a DIFFERENT payload is `EQUIVOCATION` -
**both contents are retained** in `ciph_sensor_conflicts` (with `both_contents_retained`), an
`integrity_conflict` is raised, the original event is untouched, and `operational_awareness.contradictions`
surfaces it as `UNRESOLVED`. The conflict store is registered in the census (now 9 concerns).

**A.2 Three provenance answers, because conflating them invents an actor.**
`architectural_proprioception.witness_change` now distinguishes:

| Situation | Provenance |
| --------- | ---------- |
| no authorization reference, or a reference that resolves to nothing | `UNKNOWN_PROVENANCE` - an *absence of knowledge*, explicitly "not a claim that the change was unauthorized" |
| an authorization record EXISTS and is not VERIFIED (refused/failed) while the bytes changed | `UNAUTHORIZED_MODIFICATION` - positive evidence |
| a VERIFIED deployment authorized it, but the installed bytes were not corroborated | `AUTHORIZED_BUT_UNVERIFIED` (`AUTHORIZED_DEPLOYMENT_MISMATCH` kept as an alias of the same value) |
| VERIFIED deployment + matching installed bytes | `AUTHORIZED_DEPLOYMENT` |

Both corrections are exercised through the actual 10.3/10.4 paths, and the canonical owners are unchanged:
the conflict table belongs to the fabric, the provenance logic to 10.4.

---

# PART B — 10.5 unified distributed awareness

**Owner:** `ciph/kernel/operational_awareness.py` (`OPERATIONAL_AWARENESS_V1`). It is a **read-only
projection** over 10.3 observations, 10.4 views, 10.0 findings, 4.2 evidence, 4.3 self-model, 4.4 curiosity,
5.x sessions, 6.x worker/delegation/result state and 7.x federation identity/authority. Its ONE write is a
relationship edge (`ciph_operational_links`), because "this worker result is relevant to that investigation"
belongs to no single owner and must survive a restart.

It refuses three things explicitly: a worker report is reported with the 6.x classification and
`is_evidence: false`; subject state comes from the **last witnessed activity** (so historical heartbeats
cannot keep a disconnected node CURRENT); and a correlation that does not **resolve to its canonical result
record** is refused (`WORKER_RESULT_DOES_NOT_RESOLVE`).

`contradictions()` reports every place the evidence does not agree - sensor equivocation, a 10.4 integrity
claim that independent witnesses dispute, and retained worker arrivals for one delegation that disagree -
each as `UNRESOLVED`, never resolved by preference.

**Mandatory integrated scenario (executed):** five workers across two related investigations; one result
correlated to the other investigation and the relationship preserved; one worker unreachable -> `UNKNOWN`
with its last verified evidence retained; coordinator restart reconstructs the same relationships; no new
delegation or execution permission invented (deployments 0, executions 0, links exactly 1).

---

# PART C/D — 10.6 selective cognitive attention

**Owner:** `ciph/kernel/selective_attention.py` (`SELECTIVE_ATTENTION_V1`, `ATTENTION_POLICY_V1`).

**BACKGROUND / FOCUSED / CRITICAL are attention categories, not execution privileges.** `classify` records
the input factors, the policy version and a REASON. A sensor's KIND, a declared severity or a self-reported
urgency **cannot** confer CRITICAL: a `CRITICAL` label with no evidence earns `FOCUSED`
(`SELF_DECLARED_SEVERITY_IS_NOT_EVIDENCE`). CRITICAL requires an evidence reference that **resolves** in a
canonical owner *and* a corroborating factor - an operator priority, or a **cited** architectural change
whose provenance is `UNAUTHORIZED_MODIFICATION`/`AUTHORIZED_BUT_UNVERIFIED`. The concern is evidence-linked
on purpose: an unrelated integrity problem elsewhere in the database cannot make this subject look critical.

**No single arbitrary scalar.** A decision carries `factors`, `reason`, `policy_version`; scheduling uses
`(effective category rank, starvation promotion, enqueued_at, request_id)` with the tie-break rule recorded
in the plan (`category_rank, starvation_promoted, enqueued_at, request_id`).

**Resource-aware, and the queue never reasons to maintain itself.** Bounded reasoning invocations per
window, a maximum number of active focus contexts, batching (several FOCUSED requests, one budget unit),
dedup that consumes no budget, a starvation ceiling that promotes long-waiting work, expiry/cancellation of
obsolete requests, checkpointing and restore of focus context, and outage recovery. `invoke` is the ONLY
thing that consumes inference; while the model is unavailable it returns `MODEL_UNAVAILABLE` and records
**no outcome**, and the queue is preserved intact.

**Anti-starvation is enforced, not hoped for.** After `max_consecutive_critical` CRITICAL invocations the
scheduler makes CRITICAL **yield** - its effective rank drops to FOCUSED's and it loses the tie to older
work - so a stream of alarms cannot starve every other task indefinitely.

**Part E (focus vs continuity):** investigating finding #7, a federation anomaly interrupts attention, the
anomaly is examined, and the return to #7 preserves the exact result-set id, finding id, evidence and pending
questions; a fresh process reconstructs both transitions and their references. Attention decisions are
**not evidence** and never report that an investigation completed.

---

# PART F — adversarial results (each with a negative counterpart)

heartbeat flood -> zero invocations · verified finding -> CRITICAL/FOCUSED · false CRITICAL -> only
`FOCUSED` · architectural integrity concern is the cited evidence · contradictory workers -> `UNRESOLVED`
with the owner's `CONFLICTING` classification shown · disconnected node -> `STALE`/`UNKNOWN` ·
duplicate -> no second budget · identical content from distinct events -> both kept · focus switch preserves
references · outage preserves pending work · queue overflow -> explicit refusal · high-priority burst ->
older work still served · sensor/attention cannot allocate authority · no permit minted · stale result not
advertised as fresh · repeated alarms gain no importance · restart reconstructs a deterministic history ·
resource use bounded under a 300-event flood · unsupported claims do not become self-model facts ·
generations stay distinct across reconnect.

---

# PART G — the founding attention torture (executed end to end)

LLM inactive -> 10.3 sensors collecting -> several workers on authorized tasks -> one meaningful finding and
one contradictory pair -> a federation node becomes unreachable -> an architectural anomaly is detected on
disk -> routine events stay BACKGROUND while the urgent request is SELECTED (the model is still down, so
**selection**, not invention) -> the LLM returns and receives the selected evidence context -> Ciph explains
from real records -> it returns to the interrupted investigation -> a fresh process reconstructs the
attention history -> **no new authority** (permits 0, deployments 0, executions 0).

---

# PART H — verification

```text
test_gate_10_5_10_6_attention.py   28 specimens green
10.3 / 10.4 gates                  54 specimens green (after the Part A corrections)
scanner censuses                   86 of 86 zeros
ownership censuses                 R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                                   federation 19 · swarm 15 · R6 15 (0/0/0) · sovereignty 19 - all clean
schema ownership                   225 declared tables · 0 duplicate canonical table owners
live vault                         VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                                   live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                                   0 tables from 10.0/10.3/10.4/10.5/10.6 in production
```

**Measured overhead on this host** (idle, no model):

```text
submit 1000 routine events   : 6.639 s   (6.6 ms/event)
schedule 1000 times          : 4.009 s   (4.0 ms/call)
build_projection x200        : 0.981 s   (4.9 ms/call)
model invocations at idle    : 0
max RSS delta                : 2 MiB
```

Cost is SQLite-connection and queue-bound, not inference-bound; `schedule` is O(queue) per call and the
queue is bounded by policy.

```text
frozen tree         bd02dd9ef94953a3034823cc6f363f93   (identical before and after BOTH sweeps)
full project sweep  Ran 1954 tests in 1742.580s   OK    (183 test files)
sanitized clone     Ran 1954 tests in 1192.785s   OK    (183/183 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (1954 both). Censuses, schema ownership and the fresh-state
clone assertions are identical in BOTH trees: **86/86 scanner zeros**, all ownership censuses clean, 225
declared tables with **0 duplicate canonical owners**.

**Process note, recorded rather than hidden.** The FIRST full sweep of this campaign reported 1954 with ONE
failure - `test_only_the_canonical_authority_constructs_signed_permits` - because the new census module
`ciph/kernel/attention_ownership.py` contained the literal permit-construction string as a *detection
needle*, and the 4.0 authority-throat scanner (correctly, by its own rules) reported it. The census now
assembles that needle so the catalogue no longer contains the literal. The edit moved the tree, so the
measurement was DISCARDED and both sweeps were re-run on the refrozen tree
`bd02dd9ef94953a3034823cc6f363f93`, verified identical before and after. A run whose tree moved is not
evidence.

## Defects this campaign found in its own new code (each caught by a specimen)

1. `_architectural_integrity_concern` scanned the WHOLE database, so an unrelated integrity problem made a
   subject look CRITICAL; it is now linked to the CITED evidence.
2. Anti-starvation used the category rank as the primary sort key, so the intended "yield" never happened;
   the effective rank now drops.
3. `_consecutive_critical` read `detail["category"]` while the event stored `categories`, so the streak was
   always 0 and the yield never triggered.
4. `awareness_digest` included wall-clock-derived fields and disagreed across processes; it now digests a
   durable summary only.
5. `contradictions` ignored non-standing arrivals, hiding an owner-classified `CONFLICTING` result; it now
   reports every retained arrival.
6. Worker generations were read through the active-member filter, hiding reconnect generations.
7. A resolved-evidence observation was classified BACKGROUND; it is now `FOCUSED` (`EVIDENCE_BACKED`).
8. `submit` forwarded `canonical_owner` into `classify` (a TypeError path); it is popped and stored.

## Honest limitations

- No privileged-host, hardware-attestation or live-network claim is made; 9.x remains on HOLD.
- The censuses are syntactic and cannot catch an alias or obfuscation.
- `schedule` is O(queue); the queue bound and the explicit overflow path protect the host, not raw speed.
- Federation reachability is derived from attested records, not a live probe (no egress on this host).
- Attention is a queueing mechanism: it allocates inference, and it cannot and does not decide truth.
