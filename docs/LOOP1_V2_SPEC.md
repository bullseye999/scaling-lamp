# Loop 1 v2 — Outward Research & Upgrade Proposals (Specification)

Status: **DRAFT for operator review. No implementation authorized by this document.**
Date: 2026-09-18 · Author: Codex (assessment) · Operator: operator

## 1. Objective

Turn the background expedition engine from a philosophy generator into a **governed outward
research engine** that proposes a small number of high-quality upgrades (1–2 per day), anchored
to observable needs and written against the current codebase so they can be merged cleanly.

## 2. Component map (what exists, what is missing)

| Concern | Existing component | Status |
| --- | --- | --- |
| Outward research (domain/topic cycle) | `ciph_evolution.py` expedition daemon + `DynamicSpectrumBalancer` | Exists; domains are 4 humanities + 1 AI; no operational domains |
| Relevance to Ciph | `evolution_bridge.py::SelfRelevanceAnalyzer` (+ `CAPABILITY_MAPPINGS`) | Exists; 5 canned mappings targeting legacy files; hypothesis is computed then dropped |
| Engineering gap detection | `ciph/evolution/gap_detector.py::EngineeringGapDetector` (`required_failure_count=2`) | Exists and is the correct gate for defects |
| Codebase self-knowledge | `code_index.json`, AST inspection in `ciph/capabilities/evolution.py` | Exists; not wired into the loop |
| Candidate staging | `code_staging.py`, `ciph/evolution/*` (isolated tests, benchmarks, canary, rollback) | Exists (Phase 8 pipeline) |
| Proposal artifacts | `ciph_proposals/UP-*.py` | Format exists; produced by hand/heuristics, quality varies |
| Governed external evidence | `ciph/capabilities/external_evidence.py` + Phase 7 sandbox/network policy | Exists; not used by the expedition loop |

Terminology note: the **curiosity daemon (Phase 6)** investigates *knowledge* gaps and produces
claims. It is not the code-fix pipeline. Defects belong to the **Phase 8 gap detector**.

## 3. Design

### 3.1 Research cycle (outward)

- Cadence: 4–6 research cycles per day (not 110). Each cycle explores one topic in one domain.
- Domains (weighted, operator decision 2026-09-18):
  1. **Runtime & Memory Reliability** (highest weight — DB, event store, claim leases, maintenance, performance)
  2. **Security Ops** (second — recon, transport, scope discipline, adversarial surface)
  3. Data Integrity · Capability Coverage · Frontier AI · then the intellectual domains at lowest weight.
- All external content is fetched through the governed external-evidence capability and enters
  as an **untrusted observation** with a `ReliabilityClass` and provenance. Raw fetching is not
  permitted; network policy applies.

### 3.2 Self-scan (inward, at proposal time only)

- Load the code index and AST-inspect the specific modules the observation touches.
- Record the current file hashes for every file the candidate would modify.
- Reverse-scan for defects: if the self-scan finds a defect (failing invariant, missing check,
  broken reference), file it to the Phase 8 gap detector as **urgent** with the evidence.

### 3.3 Quality gate (before a candidate is written)

A candidate proposal is written only if all of the following hold:

1. It cites the observation ID(s) it came from.
2. It cites an observable need: a Phase 8 gap, a ledger metric (defect rate, FAILING/DEGRADED
   capability, missing coverage), or an operator-requested domain.
3. It names the exact target files and the smallest diff that achieves the change.
4. It includes a test that would prove the change.
5. It includes a rollback path.
6. It is **not** a keyword/heuristic patch (e.g. `if "phrase" in response`).

Quota (operator decision 2026-09-18): **maximum 4 accepted candidates per day**, with at most **4
concurrently open**. Rationale: a proposal held pending a bug fix must never stall the engine — the
loop keeps producing the next proposal while the held one runs its 12-hour re-verification.
Excess ideas are recorded as blueprints, not proposals.

### 3.4 Rejection learning (operator decision 2026-09-18)

Rejected proposals are **retained as training signal**, never discarded:

- Every rejection is recorded with: proposal ID, target area, the operator's reason, and a derived
  **pattern signature** (e.g. `KEYWORD_HACK`, `NO_TEST`, `ALREADY_IMPLEMENTED`, `UNSAFE_MUTATION`,
  `DUPLICATE`, `OUT_OF_SCOPE`).
- A compact **rejection digest** (top reasons + the areas they hit) is injected into future proposal
  generation, so the engine does not repeat the same class of mistake.
- A pattern signature blocks an identical resubmission **unless new evidence exists** (a new gap, a
  changed ledger metric, or an operator instruction). Rejections must never permanently close an
  area — the constitution requires that new evidence can reopen a question.
- Metrics: rejection rate by signature, and how often a previously-rejected area is later accepted
  with new evidence.

### 3.5 Proposal lifecycle (hold-and-continue)

    DISCOVERED -> PROPOSED -> UNDER_OPERATOR_REVIEW -> APPLIED | REJECTED | SUPERSEDED

- A proposal never blocks the loop. Once written, Loop 1 marks it held and moves to the next topic.
- **Re-verification:** every 12 hours, Loop 1 re-hashes the target files of every open proposal.
  Hash unchanged → still open. Hash changed (and a matching receipt/staging record exists) →
  mark `APPLIED` and release the thread so work on that area can resume.
- Operator remains the only actor who can apply (`/apply` requires a bound authorization grant).

### 3.6 Guardrails (constitutional)

- Candidate code is written **only into staging**. Never into live files. Nothing self-deploys.
- LLM output is never evidence; a proposal's justification is the observed gap, not the model's opinion.
- External content is untrusted; it may inspire a hypothesis but may not justify one.
- Blueprints injected into conversation context must be explicitly labelled *unverified synthesis*.

### 3.7 Metrics (so value is measurable)

- Proposals produced / applied / rejected per week (with rejection signatures).
- Referral rate: how often a stored blueprint is ever read after creation.
- Cost per accepted proposal (LLM spend ÷ accepted proposals).
- Retirement rule: if no proposal is accepted in two consecutive weeks, reduce cadence or retire.

### 3.8 Liveness & failure handling (added 2026-09-18 from an observed stall)

**Observed failure:** the running expedition daemon (PID 3226268) stayed alive for 12h38m while
consuming only **12 seconds of CPU**, sitting asleep at 0% CPU, and produced no output for ~12 hours
— roughly 55 missed cycles — with no error written anywhere. To `ps` it looked perfectly healthy.
The vault also stopped receiving new blueprints, silently.

Requirements for Loop 1 v2:

- **Per-cycle timeout:** every research cycle, self-scan, and proposal-generation call is bounded.
  A timeout aborts the cycle and records a failure event; it never blocks the loop indefinitely.
- **Heartbeat:** write a heartbeat timestamp plus cycle counter (vault or PID file) on every cycle.
- **Watchdog restart:** if the heartbeat is older than 2× the cycle interval, the supervisor restarts
  the loop and records the restart as an operational incident.
- **No silent failure:** the current implementation wraps each cycle in a bare `except: pass`.
  Every exception must be recorded with type and message.
- **Liveness surfaced to the operator:** status output reports last cycle time, consecutive failures,
  and restart count, so a stalled engine is visible without reading logs.

## 4. Acceptance criteria

1. Domains include the operational set and the balancer still guarantees coverage.
2. A defect found by self-scan appears in the Phase 8 gap pipeline with evidence attached.
3. A candidate proposal can be traced: observation → need → file → test → rollback.
4. Held proposals are released automatically within 12 hours of the underlying fix landing.
5. No candidate bypasses staging or the operator gate.
6. Metrics report produced/applied/rejected and referral rate.

## 5. Implementation steps

1. Domains + weights in `ciph_evolution.py`.
2. Governed external-evidence wiring for the research fetch.
3. Self-scan integration (code index + AST + file hashes) at proposal time.
4. Proposal writer into `ciph_proposals/` with the quality-gate fields.
5. Proposal registry + 12-hour re-verification timer.
6. Bug escalation into `EngineeringGapDetector`.
7. Blueprint labelling + retention cap + referral counter.
8. Tests: quality-gate rejection cases, escalation, re-verify release, no-staging-bypass.

## 6. Operator decisions (recorded 2026-09-18)

- **Domain priority:** Runtime & Memory Reliability first, Security Ops second, then the rest.
- **Ceiling:** maximum 4 accepted proposals per day, at most 4 open concurrently, so held proposals
  never block new work.
- **Rejections:** retained and used as learning material with pattern signatures (see 3.4).

## 7. Historical Blueprint Corpus Salvage & Re-Grounding (Analysis & Strategy)

### 7.1 Empirical Finding
- **Corpus Redundancy:** The vault holds 2,493 blueprints covering only 40 distinct topics. The top topic appears 77 times (~98% repetition).
- **Engineering Content:** Zero blueprints cleared even three relevant engineering keywords. None discuss code, database, receipts, or workers; all are abstract essays.
- **Root Cause of Historical Failure:** Explains why `evaluate_blueprint()` in `evolution_bridge.py` never produced actionable hypotheses — the relevance bridge had nothing concrete to bite on.
- **Negative Result as Justification:** "Three weeks, 2,493 documents, 40 topics, zero engineering content" is the empirical justification for the Loop 1 v2 redesign and domain re-weighting.

### 7.2 The 4 Salvage Pillars
1. **Deduped 40-Topic Bank:** Seed list for Loop 1 v2 marked "already covered" to prevent redundant conceptual re-exploration.
2. **Representative Blueprint Retention:** Keep the single best instance per topic (40 records total), archiving 2,453 duplicate records to shrink the vault database and restore usability to `/blueprints`.
3. **Novel Syntheses Preservation:** Extract unique cross-domain links and council theses before archival.
4. **Subsystem-Adjacent Technical Re-grounding:** Focus on the ~12 technical topics mapped directly to subsystems, generating proposals with code AST in prompt:
   - *Test-Time Compute Scaling and Reasoning Verifiers* → Verification & evidence layer
   - *Transformer Context Compression and State Space Models* → Memory and context assembly
   - *Sparse Mixture of Experts and Routing Efficiency* → Query / Intent router
   - *Mechanistic Interpretability and Polysemantic Neurons* → Introspection and self-scan
   - *Reinforcement Learning from Sovereign Feedback Loops* → Ledger feedback metrics
   - *Self-Reflective Alignment, Decentralized Compute, Privacy-Preserving Inference, First-Principles Reasoning, Quantum Information* → Epistemic & cryptographic layers

### 7.3 Existing Scavenger Limitation
- `reanalyze_historical_blueprints()` in `evolution_bridge.py` has AST/LOC tools (`_inspect_target_module()`), but its CLI command `/reanalyze-blueprints` is retired, and it yields the same 5 canned hypotheses from the mapping table because the input documents are ungrounded.
- **The Path Forward:** Re-grounding with concrete code in prompt (gap-anchored generation), not scavenging abstract essays.
