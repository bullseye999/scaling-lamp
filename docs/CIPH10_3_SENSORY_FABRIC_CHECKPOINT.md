# CIPH 10.x — 10.3 SENSORY FABRIC

**Status:** IMPLEMENTED · ADVERSARIALLY VERIFIED · FULL-TREE AND CLONE SWEEPS GREEN · **10.x NOT SEALED**
(this is a checkpoint; R13 and R14 stay OPEN).

```text
The LLM may rest. Ciph's operational continuity does not.

Observation != authority.  A sensor reports; it does not certify.
Silence is not a verdict about the subject.  Loss is always indicated.
Loaded code != source code currently on disk.  One observer is not enough.
```

---

## 1. Ownership first

**Canonical owner:** `ciph/kernel/sensory_fabric.py` (`SENSORY_FABRIC_V1`) - the sensor registry and the
bounded transport of observations. It owns NO canonical fact. Its census is
`ciph/kernel/sensory_ownership.py` (8 concerns, clean, catch-specimen for every zero).

| Concern | Canonical owner bound to |
| ------- | ------------------------ |
| sensor registry, event transport, status, generations, gaps | `sensory_fabric.py` (10.3, NEW) |
| epistemic observations and evidence | `ciph/kernel/epistemic_ledger.py` (4.2) |
| empirical execution record | `ciph/kernel/self_model.py` (4.3) |
| four architectural views | `ciph/kernel/architectural_proprioception.py` (10.4) |
| worker / delegation / result state | `ciph/kernel/swarm_worker.py`, `swarm_delegation.py`, `swarm_results.py` (6.x) |
| federation membership and reachability | `ciph/kernel/federation_node.py` (7.x) |
| findings and announcements | `ciph/kernel/referential_continuity.py` (10.0) |

Lightweight local adapters are NOT registered as swarm workers: observing a file or this process's own
resources does not require a 6.x identity. Distributed sensors reuse 6.x/7.x generations where they exist.

## 2. The shared sensor contract

`register_sensor` declares, and refuses to change without a version bump: stable `sensor_id` + `version`,
capability, scope, canonical owner, evidence source, collection method, ordering, freshness TTL, retention,
queue bound, failure behaviour and restart behaviour; plus a derived `contract_digest`. Re-declaring the
identical contract is idempotent; changing it under the same version raises
`SENSOR_CONTRACT_CHANGED_WITHOUT_A_VERSION`.

A sensor observation is NOT canonical evidence: it is an `EVENT` row with a payload digest, an optional
evidence reference and a canonical owner. Only the owner can turn it into a fact.

## 3. The low-cost fabric and its adapters

`ciph/kernel/sensory_adapters.py` binds every adapter to an existing owner. Event-driven reads where the
owner already recorded something; a bounded poll of this process's own kernel counters (`getrusage` +
`/proc/self/status`) for resources; reconciliation to catch a change no subscription saw.

**All architectural observations map into 10.4's four views** via an explicit `VIEW_BY_ADAPTER` map:

```text
architecture.source    -> SOURCE      runtime.loaded -> LOADED
architecture.installed -> INSTALLED   execution.history -> EXECUTED
integrity.observation  -> SOURCE (the 10.4 integrity_claim disposition, passed through verbatim)
swarm · federation · investigation · communications · resource   -> no architectural view (they are not
                                                                   claims about Ciph's own anatomy)
```

An on-disk change is recorded in 10.4's SOURCE view and witnessed as `UNAUTHORIZED_MODIFICATION` (the
fabric does not know who changed the file). It is **never** promoted into a LOADED or EXECUTED claim.

## 4. Persistent awareness without continuous inference

The fabric performs registration, ingestion, deduplication, retention, status, gap recording and restart
reconstruction with **no model call**; a specimen asserts the two sensory modules contain no model reference
at all and that `run_cycle` reports `invoked_the_model: False`. **Measured overhead on this host:**

```text
idle    2000 status calls : 1.448 s   (724 us/call)
load    2000 ingests      : 10.149 s  (5.07 ms/event)
reconstruct 2000 events   : 0.046 s
process RSS               : 20 276 kB -> 20 276 kB  (delta 0 kB)
CPU                       : 5.78 s user for the whole benchmark
```

Ingest cost is dominated by SQLite connection churn, not by inference; it is bounded and CPU-only, suitable
for a small VPS. Bounded by `max_queue` and `retention_seconds` per sensor.

## 5. Events versus durable evidence

Raw events are bounded and retained. Heartbeats do **not** enter the 4.2 append-only ledger (a specimen
asserts `ciph_observations` is untouched by 20 heartbeats, and the census forbids the fabric core from
calling `record_observation` at all). Retention expiry is counted (`expired_count`); queue overflow drops
ROUTINE events **with an explicit `OVERFLOW` marker and `loss_indicated: True`**, while ANOMALY events bypass
the ordinary bound and, past a hard cap (`10 x max_queue`), the ingest FAILS CLOSED
(`SENSOR_HARD_CAP_EXCEEDED`) rather than losing critical observations quietly.

**Deduplication distinguishes a retry from a repeat.** Event identity is derived from
`(sensor, version, sequence, payload digest, generation)`, so re-delivering the same event is `DUPLICATE`
(no second row, no state move), while two DISTINCT events carrying identical payloads have different
sequences and are both kept.

## 6. Delivery and recovery

Bounded queue; idempotent ingestion; generation-aware identity (a SUPERSEDED generation is refused with a
marker, an UNSEEN generation is new and accepted); out-of-order events are stored and flagged
`OUT_OF_ORDER`; backpressure as above; explicit gaps; restart reconstruction that marks a
`SENSOR_DOWN`/`OBSERVATION_GAP` and invents nothing; and `sensor_status` that reports the SENSOR's state
(`LIVE`/`STALE`/`UNKNOWN`/`STOPPED`/`FAILED`) with `is_a_verdict_about_the_subject: False`.

## 7. Trust and self-observation

The 10.4 rule is reused, not reimplemented: the `integrity.observation` adapter reads
`integrity_claim` and passes its disposition through verbatim - `SELF_CERTIFICATION_REFUSED` with only local
evidence, `DISPUTED` when independent witnesses disagree. `policy_reference()` (10.4) reports the ownership
censuses as a versioned policy reference, NOT a cryptographic root of trust, and states the
shared-compromise limitation. **No TPM / secure boot / privileged OS isolation is claimed while 9.x remains
uncertified.**

## 8. Attention interface

`context_for_reasoning` returns normalized, evidence-linked event references (`event_id`, `sensor_id`,
`kind`, `observed_at`, `evidence_ref`, `payload_digest`, `canonical_owner`, `freshness`) plus coarse KIND
counts, and `urgency_score: None`. A sensor declaring `ANOMALY` gains no authority: a specimen asserts a
`CRITICAL` payload creates no deployment, permit or execution standing.

---

## 9. The founding integrated scenario (executed)

```text
fabric started (7 adapters, no model) -> source file modified -> LOADED unchanged, distinction MISMATCH
-> W1 completes an authorized delegation -> W2 announced but never attested = UNKNOWN reachability, NOT
failed -> a real investigation commits 3 durable findings + an announcement -> fabric restarts (nothing
invented, gaps marked) -> reconstruction -> context handed back to reasoning -> EVERY concrete reference
resolves to a real 10.4 observation / 10.0 result set / announcement -> no deployment, permit or execution
standing created
```

## 10. Hostile verification (each with a negative counterpart)

duplicate delivery (idempotent) · identical payloads from distinct events (both kept) · tampered payload
under a reused sequence (stored AND flagged `OUT_OF_ORDER`; the original is untouched) · reordering (stored,
flagged) · queue overflow (explicit marker; ANOMALY bypasses; hard cap fails closed) · sensor restart
(gap marked) · sensor crash / disappearance (`mark_unavailable`, no subject verdict) · observer downtime
(`restart`) · forged event (`RCP-FORGED` stays an event; `observe_executed` refuses it) · stale generation
(refused; unseen generation accepted) · sensor disagreement (`DISPUTED`) · reconciliation finds a missed
modification · source changed but loaded unchanged · runtime witness absent (`UNRESOLVED`) · unregistered
sensor refused · sensor trying privileged access (no `subprocess`/`socket`/`sudo` in either sensory module) ·
sensor trying direct constitutional writes (census zero + catch-specimen) · LLM unavailable (no model
reference; sentinel untouched) · LLM claiming observations (stored as 4.2 model output, not a fabric event) ·
retention expiry (counted) · fresh-process reconstruction (identical digest) · CPU/memory budget (measured).

## 11. Verification

```text
test_gate_10_3_sensory_fabric.py   34 specimens green
scanner censuses                   86 of 86 zeros (real tree)
ownership censuses                 R13 11 · R14 11 · 10.4 architectural 6 · 10.3 sensory 8 (NEW) ·
                                   federation 19 · swarm 15 · R6 15 (0/0/0) · sovereignty 19 - all clean
schema ownership                   218 declared tables · 0 duplicate canonical table owners
live vault                         VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                                   live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                                   0 tables from 10.0/10.3/10.4 in production
```

## Defects found by this campaign's own specimens (and fixed)

1. `sensory_digest` included the wall-clock-derived `age_seconds`, so two processes disagreed; the digest
   now covers durable state only.
2. A test assumed a REUSED sequence with a different payload would be `ACCEPTED`; the honest answer is
   `OUT_OF_ORDER` (stored and flagged), and the test now asserts that.
3. `changes()` rows carry `provenance`, not the `authorized` key (which is a *return* field) - the
   assertion was corrected rather than the store being widened.
4. A naive needle flagged the word "subprocess" inside a docstring; the host-reach check now looks for
   import/call forms.
5. A retention test conflated expiry with staleness; the TTL is now explicit.
6. An unseen generation was assumed stale; the store correctly treats it as NEW, so the specimen now
   establishes G1 -> G2 -> G1 before asserting the refusal.

## Honest limitations

- The fabric is exercised on THIS host; no privileged-host or network-boundary enforcement is claimed, and
  9.x remains on HOLD.
- The census is syntactic and cannot catch obfuscation or an alias.
- Ingest throughput (~5 ms/event) is CPU and SQLite bound; at very high event rates the queue bound and the
  explicit overflow path are what protect the host, not raw speed.
- Federation "reachability" is derived from attested records, not from a live network probe (no egress).

## Final measurements (post-10.3 frozen tree)

```text
frozen tree         843d59fd55ce164e198e1bde42f4ea78   (identical before and after BOTH sweeps)
full project sweep  Ran 1925 tests in 1634.308s   OK    (182 test files)
sanitized clone     Ran 1925 tests in 1167.495s   OK    (182/182 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (1925 both; 1891 + 34 = 1925).

```text
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 architectural 6 · 10.3 sensory 8 · federation 19 ·
                    swarm 15 · R6 15 (0 violations / 0 bypasses / 0 missing) · sovereignty 19
                    - all clean in BOTH trees
schema ownership    218 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.0/10.3/10.4 in production · no leftover CiphOS user units
```

## Next

10.6 selective attention consumes `context_for_reasoning`; 10.7 reflexes and 10.8 homeostasis build on the
same representation. None of them is implemented here, and none may use a sensor's KIND as authority.
