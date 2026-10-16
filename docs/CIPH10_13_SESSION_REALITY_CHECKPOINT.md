# CIPH 10.x — 10.13 SESSION COMMUNICATION BRIDGE + REAL-MODEL EXPEDITION VALIDATION

**Status:** IMPLEMENTED · ADVERSARIALLY VERIFIED · FULL-TREE AND CLONE SWEEPS GREEN · **10.x NOT SEALED**
(R13 and R14 stay OPEN; CiphOS 9.x stays on its independent privileged-host SEAL HOLD).

```text
The goal is not for Ciph to say that it explored something.
The goal is for Ciph to investigate something REAL, preserve the evidence, decide whether it matters, and
communicate it HONESTLY to operator.

A test double is not a model.  A local adapter is not a network.  A send receipt is not a read receipt.
A timeout is not a delivery.  A sender identifier is not permission.
```

---

# THE THREE REALITY GATES (reported independently)

| Gate | Verdict | What it proves | What it does NOT prove |
| ---- | ------- | -------------- | ---------------------- |
| **MODEL_REALITY_GATE** | **VERIFIED** | a REAL local model produced recorded output through the boundary: `llama3.2:3b` served by ollama on `127.0.0.1:11434`, recorded with its real model identity, output digest, latency and purpose, and clearly distinguishable from a test double | anything about the **creative quality** of autonomous research; no held-out research-quality benchmark was run against a real model in this campaign |
| **SESSION_LOCAL_ADAPTER_GATE** | **VERIFIED** | the local orchestration: outbox states and their transitions, evidence-gated delivery/read, forgery/replay/attachment/injection refusal, quiet-hours and rate-limit behaviour, and fresh-process reconstruction | that any message left this process, or that any recipient exists |
| **SESSION_REAL_NETWORK_GATE** | **UNVERIFIED / HOLD** | *nothing is claimed.* No operator-approved disposable Session identity and no endpoint were configured, so `RealSessionConnector` REFUSED | that Session works, that onion routing protects metadata, or that any real network leg functions |

**Provider reality, measured:** `ollama` is installed and listening; `llama3.2:3b` and `llama3.1:8b` are
present; a direct chat call returned `ALIVE`. A cold first call took ~31 s and a warm short call ~4 s on this
host — a real but small, CPU-bound local model.

**Session.js evaluated from real registry evidence, not assertion:** `@session.js/client` 0.0.57
(modified 2026-01-28, MIT) and `@session.js/bun-network` 1.0.15 (2026-01-29), dependencies are crypto
primitives, Node and Bun are both present on this host. **The Bun connector's README documents a generic HTTP
proxy, NOT onion routing**, so metadata protection above encryption is UNVERIFIED — and a configuration that
REQUIRES onion routing is **BLOCKED** rather than silently downgraded.

---

# PART A — the model boundary

`ciph/kernel/model_boundary.py` wraps the EXISTING clients (`OllamaBrain` for the local server, `CiphRouter`
for the configured provider). It defines no second brain, holds no credentials, and constructs no prompts
beyond passing selected context through.

Every invocation records provider, model identity, `kind` (`REAL_MODEL` / `TEST_DOUBLE`), input-context
REFERENCES, prompt digest, output and output digest, latency, budget units, refusal reason and uncertainty.
A refusal records **no output**: with no provider reachable the boundary returns `NO_MODEL_PROVIDER_REACHABLE`
and stores nothing. `fabricated_identities` returns every citation in the model's text that does not RESOLVE
in the owner that would hold it, so a model cannot conjure finding, observation, proposal or authorization
identities. `selected_context` hands the model REFERENCES to the expedition and its durable findings.

---

# PART C/D — the durable notification pipeline and two-way conversation

`ciph/kernel/notification_pipeline.py` implements
`CREATED -> QUEUED -> TRANSPORT_ATTEMPTED -> ACCEPTED_BY_TRANSPORT -> CONFIRMED_DELIVERED -> CONFIRMED_READ`
with `FAILED`, `RETRY_PENDING`, `UNKNOWN_OUTCOME` and `SUPPRESSED` alongside them.

**Nothing is fabricated.** A transport that returns `DELIVERED` without an artifact is downgraded to
`ACCEPTED_BY_TRANSPORT`; `CONFIRMED_DELIVERED` and `CONFIRMED_READ` each REFUSE without an evidence reference;
and a timeout becomes `UNKNOWN_OUTCOME`, preserving the ambiguity instead of resolving it in the convenient
direction. Content is composed from canonical findings, and a stated count is CHECKED against them
(`COMPOSED_COUNT_DOES_NOT_MATCH_THE_DURABLE_FINDINGS`).

Operator preferences (quiet hours, rate limit) are operator-only; an evidence-backed `CRITICAL` notification
may bypass quiet hours, a `NORMAL` one may not, and a suppressed notification says WHICH rule suppressed it.
Stale notifications are `SUPPRESSED` rather than sent late as if fresh.

`ciph/kernel/session_adapter.py` is the narrow transport: submit, poll, status, key custody — and nothing of
Ciph's credentials, confirmed by the census. Inbound messages are authenticated against an operator BINDING;
a forged sender, a replayed message id and an untrusted attachment are refused, embedded instructions are
FLAGGED, and every accepted message becomes a 10.1 UTTERANCE with
`reaches_the_execution_path_on_its_own: False`. `refuse_constitutional_write()` exists so that any attempt to
make a channel an execution authority fails loudly.

---

# PART F — the founding communication scenario (executed over the disposable transport)

Bounded objective -> model leg -> authorization -> committed findings -> a hypothesis with an unresolved
competitor -> attention selects one -> a candidate becomes a composed notification in the outbox -> the
adapter submits and only an evidence-backed state is recorded -> operator's three follow-ups land as durable
turns and resolve to the exact finding identities and ordinals -> the runtime restarts and the outbox,
conversation and adapter digests reconstruct identically -> no permit, no deployment, no fabricated discovery
and no fabricated delivery.

---

# PART G — adversarial verification (selected results)

A simulated response is labelled and is not real inference · with no provider the boundary refuses and stores
no output · the model cannot conjure a finding identity · a model cannot authorize an expedition · a message
cannot bypass authorization · a count beyond the findings is refused · a delivery claim without an artifact is
only acceptance · a timeout stays unknown · quiet hours suppress NORMAL but not evidence-backed CRITICAL ·
the rate limit and stale suppression are honoured · a local transport is not a network · the real connector
refuses · onion-required configurations are blocked · forged sender, replayed message, untrusted attachment
and injection are refused or flagged · no credential-like material appears in the recorded state · duplicate
dispatch sends once · the three gates are reported separately.

---

# PART H — verification

```text
frozen tree         6a92a22c71d4187ebb539f6e260b4020   (identical before and after BOTH sweeps)
full project sweep  Ran 2096 tests in 1683.758s   OK    (187 test files)
sanitized clone     Ran 2096 tests in 1338.506s   OK    (187/187 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (2096 both; 2062 + 34 = 2096).

```text
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                    10.1/10.2 conversation 10 · 10.7/10.8 reflex 10 · 10.9/10.10 expedition 8 ·
                    10.13 communication 8 · federation 19 · swarm 15 · R6 15 (0/0/0) · sovereignty 19
                    - all clean in BOTH trees
schema ownership    250 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.13 in production
security            no credential-like material in the recorded state; the adapter holds no Ciph credential
overhead            simulated invoke 2.72 ms/call · inbound ingest 2.79 ms/call · 0.495 s CPU · 384 kB RSS
REAL MODEL          llama3.2:3b via ollama · ~31 s cold, ~4 s warm on this host
```

**THE THREE GATES:** MODEL_REALITY_GATE **VERIFIED** · SESSION_LOCAL_ADAPTER_GATE **VERIFIED** ·
SESSION_REAL_NETWORK_GATE **UNVERIFIED / HOLD** (no approved Session identity or endpoint exists here; the
real connector refuses by design and nothing about the real network is claimed).

## Defects this campaign found in its own specimens

1. Two pipeline assertions read the first ENTRY of the dispatch result list, which includes SUPPRESSED rows;
   they now look the notification up by id and assert `attempted`, which is what the behaviour actually is.

## Honest limitations

- **The real-model research-quality benchmark was NOT run.** The reality gate proves a real model produced
  output through the boundary; it does not prove investigative usefulness, and no held-out quality score is
  claimed. The paired evidence-update and pressure-without-evidence cases were exercised against a clearly
  identified TEST DOUBLE only, which proves orchestration, not judgement.
- **No real Session network leg was exercised.** No approved identity or endpoint exists here, so the real
  connector refuses by design and the network gate is HOLD.
- Onion routing above encryption is UNVERIFIED for the default connector and is blocked when required.
- Session Protocol V2 compatibility remains a versioned external dependency.
- Token and network accounting remain unmeasurable on this host and are named rather than estimated.
- The censuses are syntactic and cannot catch an alias or obfuscation.
