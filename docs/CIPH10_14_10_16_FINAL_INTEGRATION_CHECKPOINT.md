# CIPH 10.x — 10.14 UNIFIED COGNITION · 10.15 ADVERSARIAL TORTURE · 10.16 FINAL EVIDENCE

**Status:** IMPLEMENTATION COMPLETE WITH DEFINED HOLDS · **FINAL SEAL: HOLD** · the real-model judgement gate
is **FAILED** and is reported as such rather than converted into a pass.

```text
Ciph's operational behaviour must be real, its evidence retrievable, its actions governed,
its uncertainty acknowledged, its reasoning evaluated, and its personality subordinate to the truth.

One Ciph. One continuing history. Many operational senses. Selective attention. Governed initiative.
Evidence before every claim.
```

## FINAL DECISION

```
CIPH 10.x — REMEDIATION REQUIRED
```

Reason: **a required cognitive capability was shown to FAIL its acceptance test.** The real-model judgement
benchmark (12 held-out cases, expectations derived from declared reconciliation rules) recorded **0/5 correct
abstentions for BOTH models**, **2/7 and 0/7 correct on rule-settled questions**, and **9/12 output-contract
failures for `llama3.2:3b`**. Integration mechanics pass; the reasoning capability does not.

The narrower software-mechanics scope is reported independently as verified below, and **is not** offered as
proof of the original vision.

---

## PART A — the executable integration map

`ciph/kernel/integration_ownership.py` declares **36 boundaries** — phase, canonical owner, the public surface
the integration actually calls, the tables that owner is the SOLE writer of, who reads it, and its identity,
authorization, recovery and failure semantics. `validate()` checks the map against the ACTUAL source tree and
fails loudly when a declared surface has disappeared (a synthetic removal of `selective_attention.schedule`
is caught by a specimen). `rival_writers()`/`ownership_conflicts()` implement the "no competing canonical
ownership" check over sampled tables, and the result is **zero conflicts**.

There is no central "Ciph brain": 36 owners with declared boundaries, and a map that is checked like code.

## PART B — unified cognition

**B1 lifecycle.** One specimen walks `Observation → 4.2 evidence → attention → proposal → 5.x authorization →
6.x execution → 10.0 finding → 10.1 conversation → follow-up` and proves the chain is evidence-linked: every
reference resolves to a durable identity, and **a REQUEST is not a completion** (the expedition is `ACTIVE`,
not `COMPLETED`, at the moment it was merely authorized).

**B2 inference independence.** With the model unavailable the fabric still ingests, the boundary REFUSES and
records no output, and `attention.invoke` returns `MODEL_UNAVAILABLE` with `outcome_recorded: False`. No
fiction is recorded: the recorded real-model outputs list is empty.

**B3/C1-C2 evidence reconciliation.** `ciph/kernel/evidence_reconciliation.py` applies a DECLARED standing
rule and computes the conclusion itself — nothing in it knows the word "OPEN", and the same rule on different
evidence gives a different answer (both proven by specimen). It exposes supporting and contradicting evidence,
observation times and freshness, the applicable rule, unresolved assumptions, the conclusion and the
confidence — or an explicit ABSTENTION when the evidence does not settle the question (no rule, equal
credibility, or a missing required source). `citation_consistency` fails the named failure directly: citing
the decisive evidence while concluding the opposite.

**B4/B5.** Conversational follow-ups resolve through 10.0 to exact finding identities and ordinals;
personality is downstream of the structured claims (`facts_preserved` on every render, and a rejected claim
renders a conservative fallback).

## PART D — the 40-step founding torture (executed)

Bounded objective → authorized → operator absent → model unavailable → sensors collecting → architectural
change detected with SOURCE ≠ LOADED → worker finding and a contradictory arrival → a node reported
UNKNOWN/STALE and never DEAD → homeostasis deviation with NO cause claim → a deterministic reflex whose
response is performed BY ITS OWNER (`ENFORCED_BY_OWNER`, `ciph/kernel/swarm_resources.py`) → attention
prioritises with no fictional reasoning → the model returns → an authorized expedition → a finding committed
through 10.0 → a hypothesis left unverified → the contradiction still visible → an interruption with a
checkpoint → resume through valid authority only → an evidence-backed notification queued locally with NO
delivery claimed → operator retrieves the exact findings → a challenge changes nothing → **NEW evidence changes
the rule-derived conclusion** → a legitimate preference change that adapts expression but not facts → restart
→ a fresh process reconstructs the integration map, reconciliation, personality, expedition, outbox and
conversation digests identically → zero permits, zero deployments, zero invented discoveries.

Cross-boundary hostile specimens: sensor equivocation retained and raised · unwitnessed LOADED state
UNRESOLVED · self-certification refused · a forged authorization cannot activate an expedition · a personality
change cannot alter a canonical count · a false read claim refused end-to-end.

## PART E — session reality boundary

The three 10.13 gates are preserved unchanged. **Real Session delivery remains HOLD**; no identity was
fabricated, no personal credentials were used and no message was transmitted. Onion-routing metadata
protection above encryption remains **UNVERIFIED** and is BLOCKED when required.

## PART G — final verification

```text
frozen tree         e500fb38c93b164558aa414e3bfa49bc   (identical before and after BOTH sweeps)
full project sweep  Ran 2147 tests in 1849.598s   OK    (189 test files)
sanitized clone     Ran 2147 tests in 1318.876s   OK    (189/189 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (2147 both; 2130 + 17 = 2147).

```text
scanner censuses    86 of 86 zeros in BOTH trees
integration map     36 boundaries · 0 missing files · 0 missing surfaces · 0 rival writers across 12
                    sampled canonical tables
ownership censuses  14 censuses, all clean in BOTH trees (R13 11 · R14 11 · 10.4 6 · 10.3 9 · attention 7 ·
                    conversation 10 · reflex 10 · expedition 8 · communication 8 · personality 7 · ...)
schema ownership    253 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.14 in production
real-model          llama3.1:8b 12/12 answered · accuracy 0.167 · settled 2/7 · abstained 0/5 · 17.5 s mean
                    llama3.2:3b 12/12 answered · 9 format failures · settled 0/7 · abstained 0/5 · 8.8 s mean
```

**Discarded measurement, recorded rather than hidden:** the first final sweep reported `Ran 2147 tests ... 
FAILED (failures=1)` — `test_matrix_audit_never_invokes_live_external_backends` saw 15 of 16 capabilities
compliant. The real-model benchmark was running concurrently and starved the audit's 5-second per-capability
timeout. Re-run alone, that test passes and the clean sweep is green. The contaminated run was discarded and
is recorded here because a run whose host was under self-inflicted load is not evidence.

## Defects this campaign found (including in its own measurement tooling)

1. **The scorer over-credited non-answers.** `real_model_benchmark` treated a missing/unparseable `VERDICT`
   as a correct abstention, which inflated the 3B model's apparent performance. Fixed: a format failure is a
   failure, and only an EXPLICIT abstention token counts. This changed the measured numbers and is the
   reason they are reported as they are.
2. **The integration map's first draft had three wrong surface names** (`ACTION_CONTINUITY_V1`,
   `reconstruct_beliefs`, `RECOVERY_STATE_V1`). `validate()` caught all three against the real tree — which is
   the entire point of an executable map — and they were corrected to the actual names.
3. **The benchmark's docstring claimed twelve categories while implementing five.** Corrected, and the
   uncovered categories are recorded as a COVERAGE GAP rather than implied to be tested.
4. **A sweep measured 2,147 tests with one failure under self-inflicted load** (the real-model benchmark
   running concurrently starved a 5-second per-capability audit timeout). The audit passes on an unloaded
   host, so that measurement was DISCARDED and re-run cleanly; the discarded run is recorded here rather than
   quietly dropped.

## Honest limitations

- **Real-model judgement FAILED.** Containment is verified; competence is not. The deterministic layer will
  not publish what the evidence does not support, but the model itself remains unreliable at revision and
  abstention.
- **Autonomous research quality is UNVERIFIED**; no criterion-scored model-supported expedition was run.
- Benchmark scope is 12 cases in 5 categories; causal inference, long-context history and
  authorized-versus-proposed action are unmeasured.
- 9.x privileged-host enforcement, hardware attestation, physical multi-host federation, real Session
  delivery and onion-routing privacy all remain HOLD/UNVERIFIED.
- The censuses are syntactic and cannot catch an alias or obfuscation.
