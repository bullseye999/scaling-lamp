<div align="center">

# ⚫ CIPH
### An Operator-Governed AI Agent for Research, Intelligence, Analytics & Continuous Cognitive Work

A long-running, evidence-grounded architecture for governed initiative, memory, investigation, and operational
continuity.

**[Overview](#overview) · [Capabilities](#capabilities) · [Architecture](#architecture) · [Development history](#development-history) · [Verification](#verification--evidence) · [Installation](#installation) · [Security](#security-boundaries) · [Limitations](#known-limitations-and-holds)**

</div>

---

## Overview

CIPH is a Python-based, modular AI-agent runtime developed around a simple distinction:

> An agent's intent is not authority. A model's claim is not evidence. A successful execution is not proof
> that its conclusions are true.

It combines an interactive command system with governed execution, durable memory and evidence, bounded
autonomous work, distributed-worker and federation mechanisms, model-assisted investigation, and conversational
continuity. The architecture is designed so that observation, reasoning, authorization, execution, and reporting
remain **distinct responsibilities**.

Its historical domains include authorized security research, OSINT and threat intelligence, knowledge retrieval,
sports analytics, market analysis, code inspection, and research automation. Some capabilities require
credentials, network access, an approved target, or an explicitly enabled module; presence in the source tree
does not imply a publicly deployable or universally enabled command.

CIPH is **not** a claim of consciousness, infallible autonomous reasoning, or independently certified security. It
is a research and engineering project with documented internal tests, measured demonstrations, known failures,
and deliberately retained verification holds.

**Project state (October 2026):** the 10.x feature-development cycle is **frozen at its demonstrated scope, not
sealed**. Private-runtime and infrastructure evidence described in the phase documents is historical checkpoint
evidence; it does not automatically certify any sanitized public release.

## Core design principles

| Principle | Operational meaning |
| :--- | :--- |
| **Authority is explicit** | Wakes, missions, hypotheses, urgency, and model outputs cannot create execution grants. |
| **One canonical owner per concern** | Evidence, permits, budgets, deployment, conversational records, and personality policy have defined ownership boundaries. |
| **Evidence before assertion** | Model statements about findings, counts, work progress, or delivery must resolve to the relevant records. |
| **Decision ≠ effect** | Selecting an action does not prove it ran; an execution receipt does not prove an analytical conclusion. |
| **Continuity ≠ permission** | Persistence and scheduled autonomy remain subject to operator grants, resource ceilings, and quiescence. |
| **Hypothesis ≠ finding** | Incubated possibilities are retained as hypotheses until supported by the proper evidence. |
| **Uncertainty is representable** | Incomplete observations, stale workers, contradictory evidence, unavailable models, and unverified delivery have explicit outcomes. |

---

## Capabilities

### Four historical operational domains

These domains span the older interactive command core and the later governed capability adapters. The exact
currently supported command set should be checked against [`COMMAND_MIGRATION.md`](docs/COMMAND_MIGRATION.md) and the
running CLI; retired commands have no implied legacy fallback.

| Domain | Implemented components and examples | Boundaries |
| :--- | :--- | :--- |
| **Authorized reconnaissance and bug-bounty research** | Scope-policy ingestion, passive source collection, historical URL/asset changes, dangling-CNAME fingerprints, web-surface checks, CVSS v3.1 scoring, structured reporting | A parsed scope is not proof of authorization. External targeting requires independent scope verification. |
| **Threat intelligence and world telemetry** | RSS/CVE feeds, defensive monitoring, darknet-related research via configured transports, asset history, stored briefings and alerts | Transport policy is capability-specific; Tor routing must not be assumed for every module. |
| **Cognition, memory and code analysis** | Encrypted selected memory, document ingestion and retrieval, source/AST inspection, staged proposals, event-backed claims, model-assisted analysis | Proposals and curiosity cannot independently authorize deployment or execution. |
| **Sports and market analysis** | Poisson-based sports predictions, result tracking, odds enrichment, market snapshots, arbitrage comparisons, paper portfolio, heuristic signals | Outputs are analyses, not guaranteed profits, betting outcomes, or authorized live financial execution. |

### Governed agent capabilities

The later phases add a broader operating architecture:

- **4.x — Execution and epistemic constitution:** typed manifests, risk/transport lanes, permits and guarded
  execution, event-backed continuity, claim standing and supersession, world/self-models, governed curiosity,
  comparative trials, candidate evolution, and deployment ownership.
- **5.x — Continuous governed autonomy:** standing grants, time-scoped work identity, scheduling, deterministic
  eligibility, operator modes, risk/resource ceilings, quiescence, safe idleness, and bounded maintenance.
- **6.x — Governed swarm:** worker generations, delegations, budgets, provenance, aggregation, and bounded
  coordination without creating universal worker authority.
- **7.x — Federation:** node identity, authority domains, transport, partition/staleness handling, and membership
  controls. Tests included local multi-process/socket arrangements; **separate physical hosts remain unverified**.
- **8.x — Sovereignty and recovery:** authority-material separation, fencing/recovery contracts,
  backup/reconstitution rules, and stale-node treatment, with documented limitations for disconnected hosts.
- **9.x — CiphOS environment:** Linux-host isolation/boot/operator concepts, environment observation and
  scanners. Implementation complete within the reported software scope; **privileged-host verification on HOLD**.
- **10.x — Cognitive and operational continuity:** durable referents and conversations, sensory fabric,
  architectural proprioception, awareness and selective attention, governed reflexes, homeostasis, bounded
  expeditions, incubation, personality policy, real-model boundary, evidence publication, notification outbox
  and a Session local adapter.

### What the 10.x runtime demonstrated

In bounded tests, the ordinary `CiphRuntime` can:

1. Receive an eligible scheduled work nomination through the existing 5.x owners, enforcing operator grants and budgets.
2. Invoke the configured reasoning model through a **single recorded model boundary**.
3. Gather and reconcile canonical evidence, distinguishing rule-derived conclusions from actual model contributions.
4. Store a supported result, or retain a model-generated contribution as an explicitly **unresolved hypothesis** (`is_a_result: false`).
5. Create an evidence-backed notification candidate **without claiming it was delivered** on a real messaging network.
6. Reconstruct previous findings, hypotheses and conversational references after a **fresh-process restart**.
7. Stop or remain **idle** when there is no eligible work, grants expire, resource ceilings are exhausted, or the operator imposes a hold.

These behaviours were demonstrated in bounded local / fixture-based trials. **General autonomous research
dependability has not been established.** In one small contribution evaluation, the configured model supplied
**6 correct contributions out of 8** tasks that were not settled by the deterministic rule owner; two were
missed. An ordinary scheduled demonstration preserved a model-produced contradiction interpretation as an
**unresolved hypothesis** rather than publishing it as a verified finding.

---

## Architecture

```text
                       Operator / CLI / Approved Runtime Entry Points
                                        |
                        Intent, mission, work nomination
                                        |
               +------------------- Governance -------------------+
               | Standing authority · Scope · Risk · Budgets      |
               | Operator modes · Quiescence · Execution permits  |
               +-----------------------+--------------------------+
                                       |
                              CiphRuntime (ciph/runtime.py)
                                       |
               +-----------------------+--------------------------+
               |                       |                          |
         Model boundary          Evidence owners           Governed execution
         Served identity         Observations/claims       GuardedExecutor,
         Failure/usage           Standing/reconciliation   receipts, effects
         Actual vs derived       Findings vs hypotheses
               |                       |                          |
               +-----------------------+--------------------------+
                                       |
                           Continuity and projections
                  Memory · Conversation · Attention · Awareness
                        Notifications (local adapter)
                                       |
                          Evidence-grounded reporting
```

This diagram is conceptual, not a claim that every historical CLI command passes through every subsystem.
Supported commands are routed through the registered governance surface; unsupported legacy commands are
unavailable. Worker queues and DAG planning are implemented but are not automatically involved in every
interactive command.

### Execution, evidence and model attribution

- **Execution.** Consequential work is subject to existing authorization and guarded execution; a mission, a schedule, or an LLM response is not itself a permit.
- **Epistemic state.** Observations, inferences, disputed claims, supported findings, stale evidence, and supersession are tracked separately from job-execution states.
- **Model identity.** The model boundary records the model **actually served**, rather than equating a requested alias with the served model.
- **Inference failure.** Empty final completions do not count as successful answers. `REASONING_BUDGET_EXHAUSTED` is distinguished from `EMPTY_MODEL_OUTPUT` where provider metadata supports it.
- **Result attribution.** `MODEL_SUPPORTED`, `MODEL_CORRECTED`, `RULE_DERIVED`, and unresolved outcomes are distinguished. A model's *abstention* on a rule-settled case is not misrepresented as a false factual assertion.
- **Publication.** Rule-derived corrections and safe abstentions do not earn independent model-reasoning credit.

### Selected implementation surfaces

| Surface | Responsibility |
| :--- | :--- |
| `ciph_core.py` | Historical interactive command core and domain-facing CLI integrations. |
| `ciph/runtime.py` | Governed runtime integration, including bounded investigation and autonomy ticks. |
| `ciph/kernel/model_boundary.py` | Real/simulated model separation, model identity, output/failure and invocation metadata. |
| `ciph/kernel/evidence_reconciliation.py` | Rule-governed standing, support/contradiction and unresolved outcomes. |
| `ciph/kernel/evidence_publication.py` | Evidence-grounded publication and model-versus-rule attribution. |
| `ciph/kernel/referential_continuity.py` | Durable findings and result-set references for later follow-up. |
| `ciph/kernel/personality_policy.py` | Versioned conversational preference authority, without storing operational facts. |
| `ciph/kernel/session_adapter.py` | Narrow Session transport adapter; local semantics tested, external network delivery unverified. |
| `ciph/kernel/integration_ownership.py` | Executable integration-boundary ownership map. |
| `tests/` | Discovered unit, integration, adversarial, negative-specimen and regression suites. |
| `tools/` | Verification and controlled demonstration utilities; not all are production daemon entry points. |

Other historical packages include `ciph.memory`, `ciph.workers`, `ciph.planner`, `ciph.perception`, `ciph.operator`,
and capability adapters. Consult the source and phase documents for precise ownership and integration contracts.

---

## Development history

The historical documents should be browsed in **numeric phase order**, starting with the earliest extant phase.
Historical seal labels are internal, scope-specific checkpoints — **not independent audits or certifications**.
See [`docs/DOCUMENTATION_INDEX.md`](docs/DOCUMENTATION_INDEX.md).

| Phase | Focus | Historical status / boundary |
| :--- | :--- | :--- |
| 0.x–3.x | Early architecture and remediation | See surviving records; do not infer a seal for undocumented phases. |
| 4.0–4.7 | Execution constitution, epistemic continuity, governed research and evolution | Internally verified in the reported scopes. |
| 5.x | Continuous governed autonomy | Internally sealed in the reported software/test scope. |
| 6.x | Swarm work and delegation | Internally sealed in the reported scope. |
| 7.x | Federation | Internally sealed in the reported scope; separate physical multi-host proof absent. |
| 8.x | Recovery and sovereignty | Internally sealed in the reported scope; disconnected-host limitations stated. |
| 9.x | CiphOS environment | Final seal **HOLD** pending privileged-host proof and related external validation. |
| 10.x / 10.x-R | Continuous cognitive integration, real model, investigation, personality, evidence publication | **Feature development frozen at demonstrated scope — NOT SEALED.** |

---

## Verification & evidence

**This public tree's own measurement** (clean virtual environment, current release):

| Measurement | Result |
| :--- | :--- |
| Full-tree test discovery/run | **2,191 tests — OK (1 skipped)** |
| Sanitized public-tree fingerprint (all `*.py`) | `cb2879c298927b9997038a1fdb4ee3b6` |
| Contribution-path regression | 5/5 discovered tests (hypothesis status, provenance, refs, notification candidate, empty-output refusal, verdict preservation) |
| Program status | 10.x frozen, not sealed |

A historical private-tree checkpoint reported a full run of 2,191 tests OK with fingerprint
`e45fa9641dabaeebe4ad718cc2b8533a`; the public tree above is a **separate, sanitized tree** with its own
fingerprint. A historical result is not proof that every feature, host configuration, live external service, or
source disclosure has been audited.

Typical local checks, subject to dependencies and the released test tree:

```bash
python -m unittest discover -s tests -p "test_*.py"
python ciph_matrix_audit.py
```

Some real-model tests may **skip** when the configured provider is temporarily unreachable. A skipped external
leg should not be described as a passed real-network or real-model verification. Negative specimens, scanner
censuses, ownership checks and sanitized-clone comparisons are explained in the project documentation. The
reported governance matrix was 16/16 compliant within its specified scope; that number is **not** a general
security rating.

### Historical offline examples

Earlier clean-environment demonstrations included a local read-only capability returning `42` with a generated
receipt, a hash-chain integrity check, an isolated durable worker progressing from QUEUED to SUCCEEDED, a
synthetic knowledge-library retrieval, and deterministic CVSS v3.1 scoring (9.8 for the displayed critical
vector). These are illustrative offline fixtures — **not** evidence of real-world intelligence collection or
unattended external actions.

## Known limitations and holds

| Area | Status / limitation |
| :--- | :--- |
| CiphOS privileged-host enforcement (9.x) | **HOLD** — privileged Linux/host validation not completed. |
| Hardware attestation | **HOLD** — no verified hardware attestation proof. |
| Physical multi-host federation | **UNVERIFIED** — local/process/socket tests do not establish independent-host deployment. |
| Real Session network | **HOLD** — local adapter/outbox verified; actual end-to-end delivery untested. |
| Session onion-routing metadata protection | **UNVERIFIED** for the intended integration; no silent downgrade should be inferred. |
| R13 / R14 | **OPEN** — tracked independently of the 10.x software-mechanics results. |
| General autonomous research dependability | **NOT ESTABLISHED** — promising contributions observed in small bounded evaluations; no broad field validation. |
| Model reasoning | Model responses can still abstain on settled rule-verdict tasks or miss valuable relationships/next questions. Canonical correction is not model competence. |
| Long-running production autonomy | Bounded wall-clock / disposable-runner demonstrations exist; a sustained production deployment is not thereby verified. |
| Historical command coverage | Registered commands and legacy modules have different support status; consult the migration record. |

---

## Installation

Requires **Python 3.12+** and the repository's declared dependencies. Do not use production keys, vaults or
sensitive datasets for first-run testing.

### Linux / Ubuntu

```bash
git clone https://github.com/bullseye999/scaling-lamp.git
cd scaling-lamp
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
# Edit .env locally with credentials and services you intentionally enable.
python run_ciph.py
```

Optional worker, if included and configured:

```bash
python run_worker.py --workers 2
```

### Windows and macOS

WSL2 with Ubuntu is the preferred Windows path for Linux-oriented integrations (process isolation, Linux host
controls, Tor). Native Python virtual environments may support subsets of the codebase. On macOS, use an
appropriate Python 3.12+ environment and configure optional network services separately.

### Configuration

Public configuration uses **placeholders only** in `.env.example`; never commit a working `.env`.

| Setting | Purpose |
| :--- | :--- |
| `DEEPSEEK_API_KEY` | Credential for configured DeepSeek inference, if used. |
| `DEEPSEEK_BASE_URL` / `DEEPSEEK_MODEL` | Endpoint and model selection. The last reported private configuration used `deepseek-v4-pro`; served identity should be checked rather than assumed. |
| `CIPH_VAULT_PASSPHRASE` | Primary vault passphrase where the applicable vault setup requires it. |
| `BACKUP_PASSPHRASE` | Encryption for explicitly configured backup operations. |
| `FOOTBALL_DATA_API_KEY` / `ODDS_API_KEY` | Optional sports enrichment integrations. |

On first run Ciph asks for a **callsign** (and pronouns) and addresses you by it; change it later with
`/name <new>`, `/callsign <new>` or `/set-name <new>`.

Optional services and model-provider usage can incur charges. Governed ceilings are not a promise of zero cost;
verify allowed quotas, credentials, model usage, and deployment grants before unattended operation.

### Command surface

The interactive CLI contains commands across these families; the following are examples from the historical
catalogue, **not** a promise that every command is enabled in every release.

| Family | Examples |
| :--- | :--- |
| Core and model | `/status`, `/reality-check`, `/model-status`, `/router-status`, `/modules`, `/help` |
| Recon and bounty | `/bounty-scope`, `/bounty-scan`, `/bounty-report`, `/what-changed`, `/port-scan`, `/web-scan` |
| Intelligence | `/osint`, `/alerts`, `/world-brief`, `/darknet-status`, `/tor-check` |
| Memory and research | `/search`, `/memory-stats`, `/timeline`, `/add-book`, `/ask-book`, `/hypotheses` |
| Self-inspection and jobs | `/self-report`, `/self-analyze`, `/inspect`, `/jobs`, `/job-status`, `/workflow-status` |
| Operator identity | `/name`, `/callsign`, `/set-name` |
| Sports and markets | `/predict`, `/sports-stats`, `/market-data`, `/arbitrage-scan`, `/portfolio-health` |
| Security and host | `/security-scan`, `/integrity-check`, `/backup-now` |

> Potentially destructive commands and actions involving remote systems should never be treated as harmless
> merely because they are offered by an AI interface.

---

## Security boundaries

1. **Authorization remains external reality.** CIPH's scope files, model decisions and command inputs are not substitutes for explicit authorization to assess a third-party system.
2. **Execution is governed.** The architecture distinguishes proposals, permits, guarded execution, effects and receipts. Do not assume a successful job proves the correctness of its analytical output.
3. **Transport assurances are scoped.** The historical `GhostTransport` path was designed to fail closed using Tor-aware SOCKS5h, while other telemetry paths may permit configured direct connections. Runtime-level policy checks are not proof of whole-host isolation.
4. **OS controls have limits.** Python audit hooks, static scanners and subprocess restrictions reduce selected bypass opportunities but are not a substitute for a privileged-host sandbox or comprehensive isolation.
5. **Storage encryption is selective.** Fernet-protected vault fields do not mean all event-store, queue, projection and log payloads are encrypted.
6. **Rollback has boundaries.** Local file restoration does not undo emails, external network effects, trades or other irreversible actions.
7. **No inference is inherently authoritative.** Models may produce wrong conclusions, overly cautious abstentions or unsupported claims; structured evidence publication and explicit uncertainty remain necessary.
8. **Sensitive data must stay private.** Do not commit real secrets, credential-bearing configuration, private conversation archives, security targets, identifiers, databases, or operator backups.

## Public release notes

This README describes a **sanitized public copy** of a privately developed project. The public tree is a
different tree from the private development tree and carries **its own** verification; see
[Verification & evidence](#verification--evidence). Blueprints and personal working notes are intentionally not
published; the retained phase records are the seals, checkpoints, remediation and gate records under `docs/`.

---

## Contact

For research inquiries, responsible vulnerability disclosure, or project feedback:

- **Encrypted Mail:** `ciphcontact.ranger783@passinbox.com`
- **Session ID:** `05fa17d37438cb789700327416962eaa8649a582f66d06be63ef1b7f8b85b8fd09`

## Support

CIPH is an independent project. If it improves your research or engineering workflow:

| Network | Asset | Address |
| :--- | :--- | :--- |
| **Bitcoin** | `BTC` | `bc1q7wr0zkhk92aqr33fdy0tynadxuxgepnrpqds85` |

---

## License & responsible use

Licensed under the **MIT License** — see the bundled [`LICENSE`](LICENSE) file (`Copyright (c) 2026 bullseye999`).

> CIPH is designed for authorized security research, education, defensive intelligence, and bug-bounty programs
> operating within explicit scope. Operators are responsible for complying with applicable law, provider terms,
> and program rules.
