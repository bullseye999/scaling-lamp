# CIPH 10.x — REALITY AND QUALITY REGISTER

**Purpose:** one place where every load-bearing 10.x claim is mapped to its owner, its positive and negative
specimens, its measured result, and — the point — **its actual status, including the ones that failed.**

The statuses are used strictly: **VERIFIED** (exercised with adequate evidence) · **PARTIALLY VERIFIED**
(meaningful properties passed, scope or quality limited) · **UNVERIFIED** (no sufficient test executed) ·
**FAILED** (a test showed the requirement was not met) · **HOLD** (a load-bearing proof is blocked) ·
**OUT OF SCOPE** (excluded before measurement).

---

## 1. The three reality gates

| Gate | Status | Exactly what it proves |
| ---- | ------ | ---------------------- |
| **MODEL_REALITY_GATE** | **VERIFIED** | a REAL local model (`llama3.2:3b`, `llama3.1:8b` via ollama on `127.0.0.1:11434`) produced recorded output through the canonical boundary, with real model identity, output digest, latency and purpose, distinguishable from a test double |
| **SESSION_LOCAL_ADAPTER_GATE** | **VERIFIED** | outbox states and transitions, evidence-gated delivery/read, forgery/replay/attachment/injection refusal, quiet hours, rate limit, stale suppression, fresh-process reconstruction |
| **SESSION_REAL_NETWORK_GATE** | **HOLD** | nothing is claimed: no operator-approved disposable identity and no endpoint exist here, so `RealSessionConnector` REFUSES by design |

## 2. The real-model judgement gate — **FAILED**

**Benchmark:** `tools/real_model_benchmark.py`, 5 categories, 12 held-out cases, expectations DERIVED FROM THE
DECLARED RECONCILIATION RULE (never hardcoded), scored on verdict correctness, citation consistency and
explicit abstention. Prompts were written once and never tuned against the cases.

| Model | answered | format failures | explicit abstentions | accuracy | settled correct | abstained appropriately | citation-consistent | mean latency |
| ----- | -------- | --------------- | -------------------- | -------- | --------------- | ----------------------- | ------------------- | ------------ |
| `llama3.1:8b` | 12/12 | 0 | 1 | **0.167** | **2/7** | **0/5** | 6/7 | 17.5 s |
| `llama3.2:3b` | 12/12 | **9** | 2 | **0.0** | **0/7** | **0/5** | 0/7 | 8.8 s |

**The load-bearing failures, stated plainly:**

- **Neither model abstained when the evidence did not settle the question.** 0/5 correct abstentions for both,
  across `NO_DECLARED_RULE`, `EQUAL_CREDIBILITY` and `SOURCE_MISSING`. Both answered confidently instead.
- **Both failed evidence revision.** 2/7 and 0/7 on rule-settled questions; the 8B model repeatedly returned
  the STALE verdict (e.g. `CLOSED` when the freshly calibrated evidence says `OPEN`).
- **The 3B model failed the required output contract in 9 of 12 cases**, so its accuracy is not merely low -
  it could not be measured on most cases at all.
- **A valid citation is not a correct conclusion:** the 8B model was citation-consistent 6/7 while being
  right only 2/7 - it cites real evidence labels and still draws the wrong conclusion, which is exactly the
  failure `citation_consistency` exists to catch.

**Coverage gap, stated rather than implied:** the benchmark covers FIVE categories. Categories named in the
campaign and **NOT measured** - unsupported causal inference, long-context historical reference resolution,
authorized-versus-proposed action - are **UNVERIFIED**.

## 3. Phase-by-phase status

| Phase | Owner | Status | Note |
| ----- | ----- | ------ | ---- |
| 4.0–4.7 | `execution_authority`, `continuity`, `epistemic_ledger`, `self_model`, `curiosity_*`, `crucible_*` | **SEALED** (prior programs) | unaffected; regressions green |
| 5.x autonomy | `standing_authorization`, `autonomy_modes`, `autonomy_budgets` | **VERIFIED** | |
| 6.x swarm | `swarm_worker`, `swarm_delegation`, `swarm_results` | **VERIFIED** | |
| 7.x federation | `federation_node`, `federation_authority` | **VERIFIED** | loopback only - **physical multi-host: UNVERIFIED** |
| 8.x recovery | `recovery_engine` | **VERIFIED** | |
| 9.x CiphOS | `environment_*` | **HOLD** | privileged-host enforcement, isolation and attestation are NOT verified here |
| R13 | `environment_ownership` (11 concerns) | **OPEN** | census enforced and clean; host items outstanding |
| R14 | `referential_ownership` (11) + 13 later censuses | **OPEN** | enforced and clean; dispositions settled |
| 10.0 | `referential_continuity` | **VERIFIED** | |
| 10.1/10.2 | `conversational_continuity`, `operational_presence` | **VERIFIED** | second channel is a LOCAL disposable adapter |
| 10.3 | `sensory_fabric` | **VERIFIED** | |
| 10.4 | `architectural_proprioception` | **VERIFIED** | |
| 10.5 | `operational_awareness` | **VERIFIED** | |
| 10.6 | `selective_attention` | **VERIFIED** | |
| 10.7 | `governed_reflexes` | **VERIFIED** | responses are read-only/disposable; no privileged enforcement claimed |
| 10.8 | `operational_homeostasis` | **VERIFIED** | |
| 10.9/10.10 | `independent_expeditions`, `incubation` | **PARTIALLY VERIFIED** | orchestration verified; **autonomous research quality UNVERIFIED** |
| 10.11 | existing 4.6/4.7/R7/10.4 | **OUT OF SCOPE** | retained, no new owner created |
| 10.12 | `personality_policy`, `claim_validation` | **MECHANICS VERIFIED · REAL-MODEL PARTIALLY VERIFIED · QUALITY n=1** | |
| 10.13 | `model_boundary`, `notification_pipeline`, `session_adapter` | **LOCAL VERIFIED · REAL MODEL VERIFIED · REAL NETWORK HOLD** | |
| 10.14 | `integration_ownership` (36 boundaries), `evidence_reconciliation` | **VERIFIED** | map validated against the source tree; zero rival writers on sampled tables |
| 10.15 | torture specimens | **VERIFIED** | 40-step founding scenario + cross-boundary matrix |
| 10.16 | this register | — | |

## 4. Unverified properties and required remediation

| Property | Status | Why it is not verified | Remediation |
| -------- | ------ | ---------------------- | ----------- |
| Real-model evidence revision | **FAILED** | 2/7 and 0/7 on rule-settled cases | fine-tuning, a larger local model, or a retrieval+rule-scaffolded interface that never lets the model state a conclusion the reconciliation does not license |
| Real-model abstention | **FAILED** | 0/5 both models | same; the interface must be able to force ABSTAIN from the reconciliation rather than ask the model to choose it |
| Real-model output contract | **FAILED** (3B) | 9/12 unparseable | structured/JSON output or grammar-constrained decoding |
| Autonomous research quality | **UNVERIFIED** | no criterion-based expedition evaluation was run against a real model | run a bounded model-supported expedition scored against predeclared criteria |
| Benchmark category coverage | **UNVERIFIED** | causal inference, long-context history, authorized-vs-proposed are not measured | extend the benchmark |
| Privileged-host enforcement | **HOLD** | 9.x needs a suitable disposable Linux host | run `tools/ciphos_host_verification.py --run --json` there |
| Hardware attestation | **HOLD** | no TPM/measured boot was exercised | implement and test it before claiming it |
| Physical multi-host federation | **UNVERIFIED** | loopback only | two real hosts |
| Real Session network delivery | **HOLD** | no approved identity or endpoint | exercise with explicit operator authorization |
| Onion-routing metadata protection | **UNVERIFIED** | the default connector documents a generic proxy | independently validate a real onion transport |

## 5. What the architecture does about a model that is wrong

The model's judgement failures do NOT propagate into published facts, because the deterministic layer
independently refuses: `claim_validation` will not publish a count the result set does not support, a
hypothesis as a discovery, or a delivery that the outbox does not confirm; `evidence_reconciliation` computes
the conclusion from the declared rule and fails a citation that contradicts its own conclusion; and
`suspicious_assertions` flags unsupported shapes and names the owner that would have to corroborate them.

**That is a containment property, not a competence property.** Containment is verified. Competence is not.

---

## 6. 10.x-R — DeepSeek V4 is the primary model: it is available and it is the best measured, but the gate still fails

Ciph's **intended** reasoning engine is **DeepSeek V4 (`deepseek-chat`)** via `ciph_router.py`
(`https://api.deepseek.com/v1`), and it is reachable from this host. Prior benchmarks were Ollama-only by
**harness default**, not by decision.

**Held-out judgment (24 cases, identical scorer, prompts never tuned):**

| Model | answered | format failures | correct | settled correct | abstained appropriately | citation-consistent | mean latency |
| ----- | -------- | --------------- | ------- | --------------- | ----------------------- | ------------------- | ------------ |
| **`deepseek-chat`** | 24/24 | 0 | **16 (66.7%)** | **10/13** | **6/11** | 6/13 | **1.2 s** |
| `llama3.2:3b` | 24/24 | 0 | 12 (50%) | 9/13 | 3/11 | 5/13 | 11.3 s |
| `llama3.1:8b` | 18/24 | 6 | 8 (33.3%) | 7/13 | 1/11 | 3/9 | 17.7 s |

**Status: `DEEPSEEK_V4_REASONING_QUALITY` — PARTIALLY VERIFIED.** Best accuracy, no format failures, fastest;
abstains on `CORRECT_ABSTENTION`/`UNSUPPORTED_CAUSATION`. But it **still fails abstention (6/11)** (confident
on `MISSING_SOURCES` ×2, `grant-absent`, `single-weak-source`, `calibrated-tie`) and scores **0/2 on
`OLDER_CONTROLS`** — a real rule-selection failure, not a formatting artifact.

**Fixed this pass:** `model_boundary` dropped the system prompt on the configured path; the benchmark
mislabelled its provider. **Published the same pass:** `ciph/kernel/evidence_publication.py` (containment,
attribution). **Holds unchanged** (9.x host, attestation, physical federation, real Session, onion routing,
autonomous research quality); **R13/R14 OPEN**. Full record: `CIPH10_XR_REMEDIATION_CHECKPOINT.md`.
