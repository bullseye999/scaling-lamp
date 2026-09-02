<div align="center">

# ⚫ CIPH 4.0
### Operator-Governed Security Research, Intelligence, Analytics & Cognitive Automation Runtime

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-80%2F80%20Passing-success?style=flat-square)](test_ciph_hardened_invariants.py)
[![Storage](https://img.shields.io/badge/Storage-Fernet%20%7C%20WAL%20SQLite-00599C?style=flat-square)](https://sqlite.org)
[![Transport](https://img.shields.io/badge/Transport-Tor%20SOCKS5h%20%7C%20Direct--Approved-7D4698?style=flat-square&logo=tor-project&logoColor=white)](https://torproject.org)
[![State](https://img.shields.io/badge/Epistemic%20Graph-9%20States-008080?style=flat-square)](ciph/kernel/transmutation_dag.py)
[![Predicates](https://img.shields.io/badge/Predicates-Restricted%20AST-critical?style=flat-square)](ciph/planner/predicates.py)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](#license--responsible-use)

**[Overview](#what-is-ciph) · [Capabilities](#the-four-operational-pillars) · [Real Output](#real-output-from-a-clean-public-environment) · [Architecture](#architecture) · [Status](#implementation-status) · [Commands](#command-catalog) · [Install](#installation--quickstart) · [Security](#security-boundaries) · [Tests](#verification)**

</div>

---

## What is CIPH?

CIPH is an open-source, operator-governed runtime that brings security research, threat intelligence, cognitive memory, code introspection, sports modeling, and market analysis into one terminal system.

The project has two connected layers:

- A mature interactive command core in `ciph_core.py` that exposes CIPH's domain engines.
- A CIPH 4.0 governing layer that adds typed capability manifests, deterministic execution lanes, authorization checks, receipts, durable workers, DAG execution, epistemic state, and remediation primitives.

CIPH 4.0 is an incremental migration, not a claim that every legacy command already traverses every new subsystem. This README marks the distinction directly.

### Status legend

| Label | Meaning |
| :--- | :--- |
| **LIVE** | Wired to a current CLI or runtime path. Focused and command-level test coverage varies by capability. |
| **IMPLEMENTED** | Working module or contract exists and has focused verification, but is not universal across all commands. |
| **PARTIAL** | Useful implementation exists; an important integration or enforcement boundary remains. |
| **OPTIONAL** | Requires an API key, local model, Tor service, loaded module, or other operator configuration. |

---

## The Four Operational Pillars

### 1. Authorized Recon & Bug-Bounty Research

| Capability | Status | What exists today |
| :--- | :---: | :--- |
| Scope-policy ingestion | **PARTIAL** | Parses raw policy text or a policy URL and stores structured scope. Automatic target enforcement is currently disabled, so the operator must independently verify authorization. |
| GhostTransport | **LIVE** | Pooled SOCKS5h Tor transport, remote DNS through Tor-aware requests, randomized headers, and no clearnet fallback inside `GhostTransport`. |
| Passive discovery cascade | **LIVE** | AlienVault OTX, Wayback CDX, URLScan, crt.sh, and common high-value subdomain candidates. |
| Dangling-CNAME analysis | **IMPLEMENTED** | Fingerprints for GitHub Pages, AWS S3, Heroku, Fastly, Azure, Shopify, Pantheon, Ghost, Fly.io, and Bitbucket. |
| Web surface analysis | **IMPLEMENTED** | GraphQL introspection checks, JavaScript/API-route extraction, header review, historical parameter mining, baseline comparison, and soft-404 handling. |
| CVSS and reporting | **LIVE** | Deterministic FIRST CVSS v3.1 base scoring and structured vulnerability-report generation. |
| Pentest module | **OPTIONAL** | Port, web, SSL, network-discovery, and security-audit commands after explicit module loading. Use only against systems you own or are authorized to test. |

Primary commands: `/bounty-scope`, `/bounty-scan`, `/bounty-report`, `/what-changed`, `/hit-list`, `/chain-reaction`, `/watchtower`, `/ghost-rating`.

### 2. Threat Intelligence, World Telemetry & Darknet Radar

| Capability | Status | What exists today |
| :--- | :---: | :--- |
| RSS and CVE intelligence | **LIVE** | Curated security feeds, CVE extraction, severity heuristics, alert scoring, and stored scan summaries. |
| Optional X intelligence | **OPTIONAL** | Recent-search integration when an operator supplies an X bearer token through the encrypted vault. |
| World telemetry | **LIVE** | Cybersecurity, technology, macro, and darknet-topology collection with synthesized briefings. |
| Darknet monitor | **LIVE** | Ahmia search, Tor status, onion-signal collection, bounty-lead queries, and defensive identifier monitoring. |
| Proactive briefing | **OPTIONAL** | Named intelligence synthesis when a supported model is configured; deterministic fallback summaries remain available. |
| Asset and change memory | **LIVE** | Recon snapshots, historical diffs, watchtower events, asset inventory, OPSEC history, and alert retrieval. |

Transport is capability-specific: `GhostTransport` fails closed over Tor, while `WorldTelemetry` deliberately falls back to direct clearnet when Tor verification fails. The runtime does not pretend these are the same policy.

Primary commands: `/osint`, `/world-brief`, `/sync-reality`, `/world-map`, `/darknet-deep`, `/darknet-scan`, `/darknet-report`, `/darknet-status`, `/tor-check`, `/monitor-id`.

### 3. Cognition, Memory, Strategy & Self-Evolution

| Capability | Status | What exists today |
| :--- | :---: | :--- |
| Model routing | **LIVE** | Unified routing across configured cloud and local-model paths, with explicit status and model-test commands. |
| Encrypted operator memory | **LIVE** | Conversation history, configuration values, narrative milestones, profile facts, entity links, decisions, evidence, and selected telemetry fields through `CipherVault`. |
| Knowledge library | **LIVE** | PDF and text ingestion, encrypted chunks, cached inverted index, passage retrieval, and situational book context. |
| War Room | **OPTIONAL** | Three-perspective Hunter / Stoic / Arbiter stress testing when a reasoning model is configured. |
| Cognitive evolution | **LIVE** | Runtime-bound curiosity daemon, cross-domain blueprints, synthesis links, council theses, self-audits, and engineering-hypothesis mining. It runs while the CIPH process is active, not as a guaranteed OS service. |
| Self-awareness and proposals | **IMPLEMENTED** | AST/source inspection, code index, issue detection, proposal generation, benchmarking, staging cards, approval, rejection, and rollback paths. |
| Dialogue and cadence | **IMPLEMENTED** | Six epistemic dialogue registers plus deep-focus, tactical, async-away, and re-engaging alert rhythms. Integration is not yet universal across legacy responses. |
| Memory governance | **IMPLEMENTED** | Hash-chained events, materialized claims, claim leases, disputed-state circuit breaker, supersession, and recursive descendant invalidation. |

Primary commands: `/router-status`, `/search`, `/memory-stats`, `/profile`, `/memory-graph`, `/timeline`, `/retroactive-learn`, `/add-book`, `/ask-book`, `/book-advice`, `/war-room`, `/curiosity`, `/mind-log`, `/mind-metrics`, `/operator-council`, `/self-audit`, `/hypotheses`, `/bridge-status`.

### 4. Sports, Markets & Decision Analytics

| Capability | Status | What exists today |
| :--- | :---: | :--- |
| Deterministic sports layer | **LIVE** | Poisson scoreline distributions, expected-goals calculations, outcome probabilities, and confidence aggregation. |
| Multi-layer match analysis | **OPTIONAL** | Team data, odds, news, reasoning, and arbiter layers improve when football/odds/model integrations are configured. |
| Sports learning and reporting | **IMPLEMENTED** | Stored predictions, result resolution, adaptive weighting, performance statistics, scheduled reports, and optional email delivery. |
| Public market data | **OPTIONAL** | BTC/crypto market snapshots and trend analysis from public exchange endpoints after loading the trading module. |
| Arbitrage analysis | **OPTIONAL** | Cross-exchange price comparison and threshold-based opportunity reporting. This is analysis, not guaranteed executable profit. |
| Paper portfolio and signals | **IMPLEMENTED** | Local paper trades, portfolio state, health checks, risk labels, and heuristic signals. No authenticated live-exchange order execution is documented as production-ready. |

Primary commands: `/predict`, `/today`, `/predictions`, `/result`, `/sports-stats`, `/sports-mode`, `/market-data`, `/arbitrage-scan`, `/market-trends`, `/trading-signals`, `/portfolio-health`.

---

## Real Output from a Clean Public Environment

The following output was generated from an isolated copy containing only Git-tracked files. Credential-like environment variables were removed, the vault was empty, no real security target was contacted, and generated receipt identifiers were normalized before publication.

### Runtime and evolution status

```text
$ /bridge-status
🌉 CIPH EVOLUTION BRIDGE STATUS
• Status: ACTIVE
• Capability Mappings: verification, compression, concurrency, rate_limiting, resilience
• Unified CiphRouter: ACTIVE
• Pre/Post Empirical Benchmarking: ACTIVE
• Retroactive Blueprints Mining: READY (/reanalyze-blueprints)

$ /modules
‖ Available: ['osint', 'memory', 'pentest', 'trading', 'bounty', 'orchestrator']
  Active: ['memory', 'osint', 'orchestrator'] ‖

$ /darknet-status
Last scan: Never | Feeds: 5 | Alerts: 0
```

This intentionally shows an empty public state rather than fabricated intelligence findings.

### Knowledge-library ingestion and retrieval

```text
Text ingested: Public Systems Fixture. 1 chunks stored.
Search hits: 1 | Top source: Public Systems Fixture | Relevance: 2
```

The fixture contained synthetic documentation text; no private books or conversation memory were loaded.

### Lane-derived receipt and event integrity

```text
Lane: LANE_1_READ_ONLY
Outcome: SUCCESS | Result: 42 | Exit: 0
✅ [RECEIPT <generated>] • Capability: demo.multiply
  Target   : local_system
  Outcome  : SUCCESS (Exit: 0, Duration: 0.0s)
  Transport: OFFLINE_ONLY (Idempotency: <generated>)

Events: 2 | Hash chain valid: True | Corrupted event: None
```

### Durable worker and deterministic CVSS

```text
Initial worker state: QUEUED
Final worker state: SUCCEEDED | Result: 81

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Base score: 9.8 | Severity: CRITICAL
Impact: 5.87 | Exploitability: 3.89
```

These examples are reproducible offline fixtures exercising the real runtime, queue, receipt, event-store, library, and CVSS implementations—not mocked terminal screenshots.

---

## Architecture

```text
                                  OPERATOR CLI
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
          MATURE COMMAND CORE                    CIPH 4.0 RUNTIME
            ciph_core.py                          ciph/runtime.py
                    │                                     │
     ┌──────────────┼──────────────┐          ┌───────────┼───────────┐
     │              │              │          │           │           │
 Security/Intel  Cognition     Analytics   Manifests   Receipts   Event Store
     │              │              │          │           │           │
 Bounty, OSINT,  Memory, Books,  Sports,    Policy &    Typed      Worldview,
 Darknet,        Evolution,      Markets    Lanes       Outcomes   Claims, Leases
 Pentest         War Room
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                         ┌─────────────┴─────────────┐
                         │                           │
                    DAG PLANNER                DURABLE WORKERS
                 Predicates, rollback,       Queue, leases, heartbeat,
                 compensation, skills        watchdog, daemon
```

### CIPH 4.0 operating model

Runtime-routed capabilities follow this model:

$$\text{Intent} \longrightarrow \text{Manifest-Derived Lane} \longrightarrow \text{Policy and Authorization} \longrightarrow \text{Execution Receipt} \longrightarrow \text{Optional Adversarial Gate} \longrightarrow \text{Event Record}$$

The DAG planner and durable worker are implemented subsystems, but they are not inserted automatically into every interactive command path.

### Five execution lanes

| Lane | Manifest derivation | Intended workload |
| :--- | :--- | :--- |
| **Lane 1: Read-only** | `READ_ONLY` + `NONE` risk + local/offline policy | Vault and memory reads |
| **Lane 2: Local compute** | `READ_ONLY` + elevated risk + local/offline policy | Deterministic local analysis |
| **Lane 3: External observation** | `READ_ONLY` + external network policy | Passive recon, feeds, and live data |
| **Lane 4: Consequential** | `REVERSIBLE` or `COMPENSATABLE` | Local mutation, staging, and compensatable work |
| **Lane 5: Irreversible** | `IRREVERSIBLE` | Explicitly authorized external side effects |

Network and authorization policies remain independent manifest fields; a lane does not silently grant either one.

### Core CIPH 4.0 packages

| Package | Responsibility |
| :--- | :--- |
| `ciph.kernel` | Network/reversibility/risk/authorization contracts, nine-state epistemic categories, assurance scoring, and adversarial-gate logic. |
| `ciph.memory` | SHA-256 hash-chained event log, indexed active worldview, claim leases, dispute handling, supersession, and recursive invalidation. |
| `ciph.workers` | Persistent SQLite IPC jobs, operational state machine, typed receipts, worker leases, heartbeats, retries, watchdog recovery, and standalone daemon. |
| `ciph.planner` | Restricted AST success predicates, topological DAG execution, compensation hooks, explicit-path rollback, and five-stage skill promotion. |
| `ciph.perception` | Typed observations with source reliability and freshness deadlines plus a pub/sub sensory bus. |
| `ciph.operator` | Epistemic dialogue formatting and attention/cadence management. |
| `ciph.capabilities` | Typed capability base class, registry, and current bounty, OSINT, and sports adapters. |
| `ciph.runtime` | Registry wiring, lane derivation, `NETWORK_DENIED` blocking, mandatory authorization checks, receipts, gate hooks, and event recording. |

### Operational and epistemic state are different

```text
Operational job: QUEUED → LEASED → EXECUTING → SUCCEEDED / FAILED / TIMED_OUT
Epistemic claim: INTELLIGENCE_GAP ↔ OBSERVED ↔ INFERRED ↔ HYPOTHESIZED
                                      ↓             ↓
                                  SUPPORTED ↔ DISPUTED → REFUTED
                                      ↓
                              STALE / SUPERSEDED
```

A successful process exit is evidence that a job ran; it is not automatically proof that every claim in its output is true.

---

## Implementation Status

| Area | Current boundary |
| :--- | :--- |
| Interactive command core | `ciph_core.py` remains the primary interactive CLI path. The thinner runtime migration is incremental. |
| Live runtime routing | `/bounty-scan` and `/predict` route through `CiphRuntime`. The OSINT adapter is registered, while `/osint` remains on the legacy path. |
| Network enforcement | Runtime blocks `NETWORK_DENIED` and enforces `MANDATORY_INTERRUPT`. Central enforcement of every `TOR_MANDATORY`, `LOCAL_ONLY`, and `OFFLINE_ONLY` socket boundary is not complete. |
| Durable dispatch | Queue, daemon, leases, heartbeat, retries, and recovery work in focused tests and `run_worker.py`; interactive commands do not universally enqueue through it. |
| DAG execution | Dependency ordering, restricted predicates, compensation, and explicit-path rollback work. Natural-language requests do not universally compile into DAGs. |
| Claim leases | The lease manager blocks supersession of explicitly pinned claims. Worker jobs do not automatically pin every epistemic dependency. |
| Adversarial gate | Gate logic is wired into the runtime. Current built-in manifests do not set `requires_red_team=True`. |
| Scope enforcement | Bounty scope policies can be parsed and stored, but `BountyHunter.is_in_scope()` currently permits open recon. Treat explicit external authorization as mandatory. |
| Event sourcing | `ciph_event_store` is append-only and hash-chained. Vault tables, queues, leases, and materialized views are mutable by design. |
| Encryption | Selected `CipherVault` fields use Fernet authenticated encryption. The event store, IPC queue, and materialized worldview are not blanket-encrypted. |
| Code staging | AST parsing, compilation, and timeout-bound subprocess execution are implemented. The subprocess is not an OS-level security sandbox. |

This table is intentionally direct: visitors can distinguish capability breadth from integration completeness without reverse-engineering the repository first.

---

## Command Catalog

### Core, models and modules

| Command | Purpose |
| :--- | :--- |
| `/status`, `/reality-check` | Runtime and deterministic local-state summaries. |
| `/model-status`, `/test-deepseek`, `/router-status` | Model and router diagnostics. |
| `/modules`, `/load <module>`, `/unload <module>` | Inspect and change hot-loadable modules. |
| `/help`, `/exit` | Command help and graceful shutdown. |

### Authorized recon and pentesting

| Command | Purpose |
| :--- | :--- |
| `/bounty-scope <text-or-url>` | Parse and store a program policy; does not replace manual authorization verification. |
| `/bounty-scan <target>` | Run the bounty reconnaissance pipeline through the registered runtime adapter. |
| `/bounty-report <target>` | Generate a structured report from stored scan results. |
| `/bounty-list`, `/what-changed <target>` | Review scopes/programs and historical reconnaissance differences. |
| `/hit-list [target]`, `/chain-reaction [target]` | Rank stored findings and construct stored attack-path relationships. |
| `/watchtower`, `/ghost-rating`, `/asset-inventory` | Review sentry events, OPSEC score, and known assets. |
| `/port-scan <target>`, `/web-scan <url>` | Optional pentest-module scans for explicitly authorized targets. |
| `/security-audit <target>`, `/ssl-scan <domain>` | Optional composite and TLS checks. |
| `/network-discovery` | Local-network discovery; load the pentest module and confirm scope first. |

### Intelligence and darknet

| Command | Purpose |
| :--- | :--- |
| `/osint`, `/osint-status`, `/alerts` | Refresh or inspect feed-derived intelligence. |
| `/world-brief`, `/sync-reality`, `/world-map` | Inspect or refresh world telemetry. |
| `/darknet-deep <query>`, `/darknet-scan` | Query Ahmia/onion intelligence through the configured transport. |
| `/darknet-status`, `/darknet-report`, `/tor-check` | Review stored darknet findings and Tor state. |
| `/monitor-id <identifier>` | Add a defensive breach-monitoring identifier to the private local vault; never put identifiers in public screenshots. |
| `/briefing`, `/war-room <proposal>` | Model-assisted intelligence briefing and three-perspective stress test. |

### Memory, books and cognition

| Command | Purpose |
| :--- | :--- |
| `/search <query>`, `/memory-stats`, `/tag <tag>` | Search and inspect stored conversational memory. |
| `/profile`, `/profile-clear`, `/memory-graph <query>` | Review or manage encrypted operator memory and entity links. |
| `/timeline`, `/retroactive-learn` | Narrative history and cold-start entity extraction. |
| `/add-book <path> [| title]`, `/library` | Ingest PDFs and list the encrypted library. |
| `/ask-book <question>`, `/book-advice <situation>` | Retrieve source-grounded passages or situational context. |
| `/curiosity on|off|status`, `/mind-log`, `/mind-metrics` | Control and inspect the runtime-bound evolution engine. |
| `/operator-council`, `/self-audit` | Review generated theses and metacognitive audits. |
| `/hypotheses`, `/bridge-status`, `/reanalyze-blueprints` | Connect historical blueprints to actionable engineering hypotheses. |

### Self-awareness, staging and orchestration

| Command | Purpose |
| :--- | :--- |
| `/self-report`, `/self-analyze`, `/inspect <module>` | Inspect source structure and detected engineering issues. |
| `/upgrades`, `/review <id>`, `/reject <id>` | Review staged proposals without applying them. |
| `/apply <id>`, `/rollback <file>` | Consequential local writes; review staged code and backups first. |
| `/benchmark-proposals`, `/changelog` | Run proposal checks and inspect mutation history. |
| `/start-workflow <name>`, `/stop-workflow <name>` | Control orchestrated background workflows. |
| `/workflow-status`, `/auto-mode`, `/stop-all-workflows` | Inspect or control orchestration. |
| `/schedule-start`, `/schedule-stop`, `/schedule-status` | Control the in-process scheduler. |
| `/jobs`, `/job-status <id>` | Inspect the persistent job queue. |

### Sports and market analytics

| Command | Purpose |
| :--- | :--- |
| `/predict <home> vs <away>`, `/today`, `/predictions` | Create or review sports-model outputs. |
| `/result <id> <outcome>`, `/sports-stats`, `/sports-mode on|off` | Resolve predictions, inspect performance, and control the sports daemon. |
| `/market-data`, `/market-trends`, `/arbitrage-scan` | Public market and cross-exchange analysis after `/load trading`. |
| `/trading-signals`, `/portfolio-health`, `/wealth-strategy <amount>` | Heuristic signals, paper-portfolio state, and scenario projections—not financial advice. |

### Host and vault operations

| Command | Risk | Purpose |
| :--- | :---: | :--- |
| `/security-scan`, `/integrity-check` | Read-only | Inspect host permissions and tracked-file integrity. |
| `/backup-now` | Consequential | Create an encrypted backup; requires `BACKUP_PASSPHRASE`. |
| `/clean-footprints` | **Host-destructive** | Clears shell/temp/cache data. Read `security_layer.py` and understand its scope before use. |
| `/zeroize-mind` | **Data-destructive** | Erases cognitive-evolution records from the local vault. |
| `/emergency-wipe` | Stub | Intentionally not implemented for safety. |

---

## Installation & Quickstart

> CIPH requires **Python 3.12 or newer**.

### Linux / VPS

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git tor curl
sudo systemctl enable --now tor

git clone https://github.com/bullseye999/scaling-lamp.git
cd scaling-lamp
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
python3 run_ciph.py
```

Optional standalone durable worker:

```bash
python3 run_worker.py --workers 2
```

### Windows through WSL2

```powershell
wsl --install -d Ubuntu
```

Then follow the Linux instructions inside Ubuntu.

### Windows native

```powershell
winget install Python.Python.3.12 Git.Git
git clone https://github.com/bullseye999/scaling-lamp.git
cd scaling-lamp
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python run_ciph.py
```

Install and run the Tor Expert Bundle or Tor Browser separately when using Tor-dependent capabilities. Native Tor commonly exposes SOCKS5 on `127.0.0.1:9050` or `127.0.0.1:9150`; confirm your own configuration.

### macOS

```bash
brew install python git tor
brew services start tor

git clone https://github.com/bullseye999/scaling-lamp.git
cd scaling-lamp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 run_ciph.py
```

### Configuration

`.env.example` documents the supported public configuration surface:

| Variable | Required? | Purpose |
| :--- | :---: | :--- |
| `DEEPSEEK_API_KEY` | Optional | Cloud reasoning, War Room, briefings, and synthesis paths. |
| `DEEPSEEK_BASE_URL`, `DEEPSEEK_MODEL` | Optional | Compatible endpoint and model selection. |
| `FOOTBALL_DATA_API_KEY` | Optional | Fixtures, results, and team-data enrichment. |
| `ODDS_API_KEY` | Optional | Market-odds enrichment for sports analysis. |
| `CIPH_VAULT_PASSPHRASE` | Recommended | Derives the primary vault key. Without it, CIPH creates an ignored random installation key. |
| `BACKUP_PASSPHRASE` | Required for backups | Encrypts `/backup-now` output; there is no plaintext fallback. |

Never commit `.env`, `*.key`, `*.salt`, SQLite databases, reports containing targets, monitored identifiers, or operator-profile exports.

---

## Security Boundaries

1. **Authorization is external ground truth.** CIPH is for systems you own or are explicitly authorized to assess. Stored scope parsing currently does not enforce target denial automatically.
2. **Transport & Network Policy Enforcement.** `GhostTransport` fails closed over SOCKS5h Tor. `WorldTelemetry` handles configurable transport. `CiphRuntime` and `network_sandbox.py` enforce `OFFLINE_ONLY`, `LOCAL_ONLY`, and `TOR_MANDATORY` at runtime across `socket` and `_socket` using CPython PEP 578 audit hooks.
3. **Rollback is explicit.** `DAGExecutor` restores only file and directory paths supplied for a reversible plan. External requests, messages, trades, and other irreversible effects cannot be rolled back by copying files.
4. **Predicates avoid Python `eval()`.** DAG success conditions use a restricted AST interpreter. This does not make arbitrary generated code safe.
5. **Code Staging & Evolution Filesystem Isolation.** Code self-evolution performs static AST analysis, fail-closed manifest extraction, and timeout-bound subprocess execution with PEP 578 filesystem isolation hooks preventing host-side modifications outside sandbox directories.
6. **Encryption is scoped.** Sensitive `CipherVault` fields use Fernet authenticated encryption (AES-128-CBC with HMAC-SHA256). Event-store payloads, job queues, and materialized projections are not blanket-encrypted; protect the host and database file.
7. **Adversarial gating is opt-in.** Gate logic can reject execution failures, soft-404s, and unsupported takeover claims, but current built-in manifests do not require it by default.
8. **Analytics are not guarantees.** Market, arbitrage, and sports outputs are probabilistic or heuristic and are not financial advice or automatic live execution.
9. **Destructive commands are real.** `/clean-footprints` and `/zeroize-mind` can remove local data. Inspect their implementation and maintain backups before use.

---

## Verification

The current suite covers typed contracts, lane derivation, cryptographic receipts, network policy blocking, safe predicates, event integrity, multi-claim leases, recursive invalidation, durable workers with atomic CAS leases, DAG compensation, rollback, skill promotion, cadence, authentication, and 25 command-level regression paths.

```text
======================================================================
  Test Suite                                      Pass / Total   Result
======================================================================
  test_ciph_hardened_invariants.py (Security)        16 / 16      PASS
  test_ciph_contracts.py (Contracts & Policy)        13 / 13      PASS
  test_ciph_planner_operator.py (DAG & Operator)     10 / 10      PASS
  test_ciph_memory.py (Leases & Invalidation)         8 / 8       PASS
  test_ciph_commands.py (Governed Commands)           6 / 6       PASS
  test_ciph_curiosity.py (Curiosity & Inquiry)        5 / 5       PASS
  test_ciph_workers.py (Queue, Leases & Daemon)       5 / 5       PASS
  test_auth.py (Authentication & OpSec)               5 / 5       PASS
  test_ciph_dag_compensation.py (Compensations)       4 / 4       PASS
  test_ciph_evolution.py (Evolution & Staging)        4 / 4       PASS
  test_ciph_reference_loop.py (Execution Loop)        4 / 4       PASS
----------------------------------------------------------------------
  test_ciph_project_suite.py (Command Regression)     25 / 25      PASS
======================================================================
  TOTAL: 80 / 80 Unit & Integration Tests + 25 / 25 Audit Commands
======================================================================
```

Run the same verification locally:

```bash
python3 -m unittest discover -s . -p "test_*.py"
python3 test_ciph_project_suite.py
```

Passing tests demonstrate the covered behavior; they are not a claim that every external integration, target, feed, or host configuration has been exhaustively validated.

---

## Near-Term Engineering Priorities

- Route more interactive commands through `CiphRuntime` and the persistent worker queue.
- Couple worker checkout to automatic epistemic dependency leases.
- Make stored bounty scope deny by default before dispatch.
- Promote adversarial gating only where deterministic tests and latency budgets justify it.
- Define encrypted or redacted storage policy for event, queue, and projection payloads.
- Add package metadata that enforces the Python 3.12 minimum mechanically.
- Add a standalone `LICENSE` file matching the MIT declaration in this README.

---

## Fuel the Build & Support CIPH

CIPH is an independent open-source project. If it improves your research or engineering workflow, you can support continued development:

| Network | Asset | Address |
| :--- | :--- | :--- |
| **Bitcoin** | `BTC` | `bc1q7wr0zkhk92aqr33fdy0tynadxuxgepnrpqds85` |

---

## Contact

For research inquiries, responsible vulnerability disclosure, or project feedback:

- **Encrypted Mail:** `ciphcontact.ranger783@passinbox.com`
- **Session ID:** `05fa17d37438cb789700327416962eaa8649a582f66d06be63ef1b7f8b85b8fd09`

---

## License & Responsible Use

Declared under the **MIT License** in this README; the repository still needs a standalone `LICENSE` file containing the complete terms.

> CIPH is designed for authorized security research, education, defensive intelligence, and bug-bounty programs operating within explicit scope. Operators are responsible for complying with applicable law, provider terms, and program rules.
