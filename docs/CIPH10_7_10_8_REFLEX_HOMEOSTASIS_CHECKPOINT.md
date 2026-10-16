# CIPH 10.x — 10.7 GOVERNED REFLEXES + 10.8 OPERATIONAL HOMEOSTASIS

**Status:** IMPLEMENTED · ADVERSARIALLY VERIFIED · FULL-TREE AND CLONE SWEEPS GREEN · **10.x NOT SEALED**
(R13 and R14 stay OPEN; CiphOS 9.x stays on its independent privileged-host SEAL HOLD).

```text
Homeostasis RECOGNIZES patterns.  Reflexes APPLY deterministic existing rules.
Attention ALLOCATES inference.   Existing constitutional authorities CONTROL execution.

A deviation is not a danger.  A correlation is not a cause.  A recent deviation is not the new normal.
A reflex applies a rule that already exists; it does not decide what should be true.
"REFLEX_TRIGGERED" does not prove "PROTECTIVE_ACTION_EXECUTED".
```

---

# PART A — the two 10.2 corrections

**Delegation terminality.** The real lifecycle is `PROPOSED`/`ELIGIBLE` -> `ASSIGNED` -> `COMPLETED`, with
`CANCELLED`/`STALE` terminal, and leases `ACTIVE` -> `RELEASED`/`EXPIRED`/`INTERRUPTED`.
`delegation_disposition` now returns `TERMINAL` (COMPLETED - a re-run is a NEW delegation),
`REFUSED_OR_EXPIRED` (CANCELLED/STALE), `AWAITING_CLAIM` (PROPOSED/ELIGIBLE), `IN_PROGRESS` (ACTIVE unexpired
lease) or `ORPHANED` (an assigned delegation whose lease expired or was interrupted - resumable ONLY through
the lease reclamation path) - and `UNKNOWN` (not resumable) for an unrecognised state. "Not COMPLETED" is no
longer treated as resumable.

**Absence of activity.** `absence_report` now states its interval, its covered sources and its observation
completeness. Work sources (delegations, results, announcements) are canonical and always readable; the
SENSORY dimension is covered only when a sensor is registered and fresh, and FEDERATION only when no known
node is disconnected. An uncovered source means `global_claim_permitted: False`, `nothing_authorized_happened:
None` and a `qualification` naming what is missing - never a global "nothing happened".

---

# PART B — 10.7 governed reflexes

**Owner:** `ciph/kernel/governed_reflexes.py` (`GOVERNED_REFLEX_V1`). A reflex is a predefined response to
canonical state satisfying an explicitly versioned rule. It is NOT a natural-language interpretation, a
planner, a permit issuer, an emergency sovereign authority, an LLM bypassing a boundary, or a sensor
executing commands.

**Triggers are computable from CANONICAL STATE ALONE**: spawn counts from 6.x, sensor freshness from 10.3,
`integrity_claim` from 10.4, `authorization_status` from 5.x, gap/conflict markers from 10.3.
`evaluate()` returns `computable_from_canonical_state: True` and `used_the_model: False`. If a trigger needed
prose interpreted, the result would be a hypothesis, not a reflex.

**Execution goes through the existing owners.** Each reflex declares an `authority_basis`
(`OPERATOR_ACTOR`, `STANDING_AUTHORIZATION`, `EXISTING_OWNER_GUARD`, `READ_ONLY_ASSERTION`), and the response
is a call into an owner that already exists: 6.x spawn governance for a ceiling, 5.x `swarm_quiescence` for a
safe state, 10.3 for a witness mark, 10.6 for an attention flag, 5.x authorization status for an expired
grant. The reflex crafts no permit, owns no executor, and when its authority basis cannot be satisfied it
REFUSES and preserves the reason (`NO_VALID_AUTHORIZATION_FOR_THIS_RESPONSE`,
`THE_RESPONSE_OWNER_REQUIRES_AN_OPERATOR_ACTOR`).

**Decision is not effect.** `ciph_reflex_decisions` records that a rule fired; `ciph_reflex_outcomes` records
what the OWNER did (`ENFORCED_BY_OWNER`, `NO_ACTION_REQUIRED`, `REFUSED_BY_OWNER`, `FLAGGED_FOR_ATTENTION`,
`MARKER_PRESERVED`, `REFUSAL_RECORDED`). `decisions_without_an_outcome()` is exactly what an interruption
between deciding and recording looks like, and it is reported rather than repaired. Idempotency is per
(rule, subject, window), so a duplicate delivery is applied once.

---

# PART C — 10.8 operational homeostasis

**Owner:** `ciph/kernel/operational_homeostasis.py` (`OPERATIONAL_HOMEOSTASIS_V1`). Every baseline declares
metric definition, canonical source, units, window, workload context, sample size, coverage, missing
fraction, version, reference period, comparison method, confidence, and the threshold WITH its justification.

**Integrity of "normal".** A proposed baseline is a `CANDIDATE` and is explicitly
`candidate_is_not_normal_yet`; promotion requires an operator identity
(`BASELINE_PROMOTION_REQUIRES_AN_OPERATOR`), records the effective date, and SUPERSEDES the previous approved
version rather than rewriting it. A 200-observation flood left the approved baseline at its original value.

**Honest comparison.** `evaluate` returns `INCONCLUSIVE` with a named reason when there is no approved
baseline, when the live workload context differs (`WORKLOAD_CONTEXT_CHANGED` - unlike workloads are never
compared), or when the window is incomplete (`INSUFFICIENT_OBSERVATIONS`). The comparison window starts AFTER
the reference period ends, so reference observations cannot mask a departure.

**Separated interpretation.** `OBSERVED_DEVIATION -> ANOMALY -> CONCERN -> HYPOTHESIS -> VERIFIED_CAUSE ->
PROPOSED_RESPONSE -> AUTHORIZED_RESPONSE -> OUTCOME` are separate, ordered, and append-only; a causal claim is
recorded ONLY at `VERIFIED_CAUSE` with an evidence reference, and every verdict carries `causal_claim: None`.

**Reflective awareness** is arithmetic over real records: `attention_allocation_ratio` returns numerator,
denominator, both windows, the workload definition, the versioned baseline and `model_intuition: False`.

**Connection to attention**: `to_attention` produces an evidence-linked candidate for 10.6 and asserts
`self_declared_critical: False` and `grants_authority: False`; 10.6's own evidence rules decide the category.

---

# PART D — the separation, demonstrated

**Deterministic limit:** canonical 6.x spawn evidence meets the ceiling -> the predefined path calls 6.x spawn
governance -> the OWNER refuses -> the outcome is recorded as `ENFORCED_BY_OWNER` -> no model was involved.
**Emerging anomaly:** a latency departure against an APPROVED baseline produces an evidence-backed anomaly
with NO cause claim; it routes to 10.6; no stop, restart, configuration rewrite or self-modification happens.

---

# PART E — the founding end-to-end scenario (executed, 22 steps)

Fabric started -> the main model made unavailable -> authorized workers spawn -> canonical resource
observations collected -> the ceiling condition triggers -> the reflex evaluates with NO inference -> the
legitimate owner enforces -> an EXPIRED authorization REFUSES instead of executing -> decisions and effects
recorded separately -> a latency departure against an approved baseline is detected WITHOUT a cause claim ->
a conflicting sensor observation leaves the baseline untouched -> the anomaly routes into 10.6 without
execution standing -> the process is interrupted -> reflex history, baseline identity and unresolved anomalies
reconstruct identically in a FRESH process -> the model is restored -> the account distinguishes executed
reflexes, refusals, anomalies and hypotheses -> no causal conclusion is drawn -> zero permits, zero
deployments, zero execution standing.

---

# PART F — adversarial verification (28 cases, each with a refusal or uncertainty counterpart)

trigger without canonical evidence -> NOT_TRIGGERED · sensor CRITICAL without evidence -> FOCUSED · reflex
minting a permit -> census zero + no permit rows · expired authorization -> REFUSED with the owner's status ·
retry after an outcome -> applied once · duplicate delivery · identical payload from a distinct event ·
equivocating sensor sequence · interruption between decision and outcome -> visible · model unavailable ->
reflex still enforces · quiescence without authorization -> owner refusal preserved · missing resource
witness -> UNKNOWN, never FAILED · stale federation observation -> not current · incomplete window ->
INCONCLUSIVE · baseline poisoning -> approved baseline unchanged · silent rewrite -> impossible (operator
promotion + supersede) · changed workload -> INCONCLUSIVE · correlation-as-causation -> `causal_claim: None` ·
anomaly triggering corrective execution -> none, and no authority minted · anomaly flood -> bounded attention,
enforcement path unaffected · false positive from missing data -> INCONCLUSIVE · ratio against a versioned
baseline -> arithmetic · wrong denominator -> visible · completed/cancelled task -> not resumable · absence
report with a gap -> qualified · fresh-process reconstruction -> identical digests · model account claiming a
refused reflex executed -> no outcome row · starved attention queue -> the deterministic enforcement path
still runs.

---

# PART G — measurement and regressions

```text
frozen tree         226a2258b3457caaaa1e646c5981f4b9   (identical before and after BOTH sweeps)
full project sweep  Ran 2025 tests in 1675.051s   OK    (185 test files)
sanitized clone     Ran 2025 tests in 1265.648s   OK    (185/185 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (2025 both; 1991 + 30 new + 4 corrected = 2025).

```text
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                    10.1/10.2 conversation 10 · 10.7/10.8 reflex 10 · federation 19 · swarm 15 ·
                    R6 15 (0/0/0) · sovereignty 19 - all clean in BOTH trees
schema ownership    239 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.x in production
affected regressions 243 tests green across the 10.x gates, the 4.0 executor and authority-throat scans,
                    and the 4.1/4.2/4.3/6.x/7.x owners
```

**Measured overhead on this host** (no model anywhere in either module):

```text
reflex evaluate      200x : 0.172 s   (0.86 ms/call)
reflex invoke        200x : 2.271 s   (11.35 ms/call, incl. the owner ask, idempotency and two writes)
baseline evaluate    200x : 0.628 s   (3.14 ms/call)
model invocations         : 0
CPU for the benchmark     : 2.215 s
max RSS delta             : 896 kB
```

**Bounded queue/retry behaviour:** idempotency is per (rule, subject, window) so a replay spends no second
action; the attention queue stays bounded under a 50-event anomaly flood while the deterministic enforcement
path is unaffected.

## Defects this campaign found in its own new code (each caught by a specimen)

1. `mark_unavailable` was called with `STALE`, which 10.3 correctly refuses (STALE is DERIVED from the
   freshness TTL, not assertable); a missing witness is now marked `UNKNOWN`.
2. The founding scenario witnessed an architectural component it had never registered.
3. The comparison window overlapped the baseline's reference period, so reference observations masked the
   departure and an incomplete window read NORMAL; the window now starts after the reference period ends.
4. A ratio specimen asserted a tautology; it now asserts the honest fact that no approved baseline means no
   comparison, while still exposing numerator and denominator.
5. An assertion that an explicitly-marked-UNKNOWN sensor becomes STALE was simply wrong: a deliberate
   "we do not know" stays UNKNOWN and never becomes FAILED.

## Honest limitations

- No privileged-host enforcement is claimed. The reflex responses are read-only or explicitly disposable
  mechanisms (owner guards, sensor status, attention flags, refusal records); nothing here restarts a
  machine, rewrites configuration or self-modifies.
- The census is syntactic and cannot catch an alias or obfuscation.
- Baselines are only as good as the observations fed to them; the module refuses to compare what it cannot
  cover, but it cannot detect a systematically biased canonical source.
- Statistical comparison is a mean-vs-reference-mean policy with a declared threshold; it is deliberately
  simple, versioned and auditable, not a general anomaly-detection engine.
