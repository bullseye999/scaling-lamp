<div align="center">

# ⚫️ CIPH 4.0
### Modular Cognitive Runtime for Security Research and Operator-Governed Automation

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-52%2F52%20Passing-success?style=flat-square)](test_ciph_contracts.py)
[![Storage](https://img.shields.io/badge/Storage-Fernet%20%7C%20WAL%20SQLite-00599C?style=flat-square)](https://sqlite.org)
[![Network Policy](https://img.shields.io/badge/Network-Tor%20SOCKS5h%20%7C%20DoH-7D4698?style=flat-square&logo=tor-project&logoColor=white)](https://torproject.org)
[![State Machine](https://img.shields.io/badge/Epistemic%20FSM-9--State%20DAG-008080?style=flat-square)](ciph/kernel/transmutation_dag.py)
[![Predicate Safety](https://img.shields.io/badge/AST%20Validator-Zero%20eval()-critical?style=flat-square)](ciph/planner/predicates.py)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)

<p align="center">
  <a href="#-what-is-ciph-40">Overview</a> •
  <a href="#-the-5-execution-lanes">Execution Lanes</a> •
  <a href="#-architecture--core-subsystems">Architecture</a> •
  <a href="#-implementation-status--limitations">Status</a> •
  <a href="#-verified-test-matrix">Verification</a> •
  <a href="#-installation--quickstart">Installation</a> •
  <a href="#-command-catalog">Command Catalog</a> •
  <a href="#-security-boundaries--opsec">Security Boundaries</a> •
  <a href="#-fuel-the-build--support-ciph">Donate</a> •
  <a href="#-sovereign-contact">Contact</a>
</p>

</div>

---

## 🧠 What is CIPH 4.0?

**CIPH 4.0** is an open-source, operator-governed cognitive runtime and modular security-research platform. It combines a mature interactive command core with typed capability contracts, policy-aware routing, durable workers, epistemic state, and deterministic remediation components.

CIPH 4.0 is an incremental migration rather than a claim that every legacy command already uses the complete pipeline. Runtime-routed capabilities follow this operating model:

$$\text{Intent} \longrightarrow \text{Manifest-Derived Lane} \longrightarrow \text{Policy and Authorization} \longrightarrow \text{Execution Receipt} \longrightarrow \text{Optional Adversarial Gate} \longrightarrow \text{Event Record}$$

The DAG planner, standalone worker daemon, rollback engine, and epistemic graph are implemented and tested subsystems. Their integration status is documented below.

### Key Architectural Shifts in CIPH 4.0

* **Typed Capability Boundary**: `ciph.runtime` interfaces with registered capabilities through `CapabilityManifest`, `BaseCapability`, and `CapabilityRegistry` contracts.
* **Tamper-Evident Event Store**: Runtime and epistemic events can be appended to a SHA-256 hash-chained event log. Other operational tables remain conventional mutable SQLite projections.
* **Separation of Job and Claim States**: Operational machine execution (`JobState`: `QUEUED`, `LEASED`, `EXECUTING`, `SUCCEEDED`) is decoupled from epistemic belief state (`EpistemicCategory`: `OBSERVED`, `SUPPORTED`, `DISPUTED`, `SUPERSEDED`).
* **Anti-TOCTOU Claim Leases**: `ClaimLeaseManager` can pin claim dependencies so active-forgetting operations defer supersession while those claims are leased. Automatic lease acquisition is not yet coupled to every worker job.
* **Two-Phase Invalidation Circuit Breakers**: Contradicting observations transition claims to `DISPUTED` before executing recursive invalidation cascades, protecting the knowledge base against transient network glitches.
* **Zero-`eval()` AST Predicates**: Plan success conditions and policy guards evaluate strictly through Python AST validation.

---

## 🚦 The 5 Execution Lanes

Registered capabilities are classified deterministically from their manifests. A lane does not hard-code one network or authorization policy; those controls remain explicit fields on each capability:

| Lane | Manifest derivation | Intended workload |
| :--- | :--- | :--- |
| **Lane 1: Read-only** | `READ_ONLY` + `NONE` risk + local/offline policy | Vault and memory reads |
| **Lane 2: Local compute** | `READ_ONLY` + elevated risk + local/offline policy | Deterministic local analysis |
| **Lane 3: External observation** | `READ_ONLY` + external network policy | Passive recon, feeds, and live data |
| **Lane 4: Consequential** | `REVERSIBLE` or `COMPENSATABLE` | Local mutation, staging, and compensatable work |
| **Lane 5: Irreversible** | `IRREVERSIBLE` | Explicitly authorized external side effects |

Lane derivation is implemented in `CapabilityManifest.derive_execution_lane()`. Network and authorization enforcement are separate runtime concerns.

---

## 🏛️ Architecture & Core Subsystems

```text
                               ┌──────────────────────────────────────────────┐
                               │                 CIPH RUNTIME                 │
                               │        (Unified Cognitive Coordinator)       │
                               └──────────────────────┬───────────────────────┘
                                                      │
         ┌───────────────────┬────────────────────────┼────────────────────────┬───────────────────┐
         ▼                   ▼                        ▼                        ▼                   ▼
┌─────────────────┐ ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐ ┌─────────────────┐
│ PERCEPTION BUS  │ │   WORLDVIEW     │      │  DAG PLANNER &  │      │ DURABLE WORKER  │ │   REMEDIATION   │
│   (Sensory)     │ │    MEMORY       │      │ SKILL REGISTRY  │      │     SERVICE     │ │  & ROLLBACK     │
│                 │ │                 │      │                 │      │                 │ │                 │
│ • Telemetry     │ │ • Active Forget │      │ • Fast-Path DAG │      │ • Out-of-Proc   │ │ • Failure       │
│ • Darknet Tor   │ │ • 9-State FSM   │      │ • AST Safe Pred │      │   Daemon        │ │   Quarantine    │
│ • CVE Feeds     │ │ • Transmutation │      │ • Parameterized │      │ • Canonical     │ │ • Deterministic │
│ • System State  │ │   Belief DAG    │      │   Skill Cache   │      │   Receipts      │ │   Backups (T₀)  │
│ • Git / Files   │ │ • Event Store   │      │ • Policy Engine │      │ • Red Team Gate │ │ • Compensations │
└────────┬────────┘ └────────┬────────┘      └────────┬────────┘      └────────┬────────┘ └────────┬────────┘
         │                   │                        │                        │                   │
         └───────────────────┴────────────────────────┼────────────────────────┴───────────────────┘
                                                      │
                                                      ▼
                                       ┌──────────────────────────────┐
                                       │    OPERATOR SYNC ENGINE      │
                                       │ • Deep-State Focus Cadence   │
                                       │ • Interrupt Budget Batching  │
                                       │ • Epistemic Dialogue Cards   │
                                       └──────────────────────────────┘
```

| Package / Module | Description | Core Responsibilities |
| :--- | :--- | :--- |
| **`ciph.kernel`** | Policy & Epistemic Engine | `NetworkPolicy`, `ReversibilityClass`, `TransmutationDAG` (9-state FSM), algorithmic `calculate_assurance_score()`, and `AdversarialRedTeamGate`. |
| **`ciph.memory`** | Cryptographic Event Sourcing | SQLite WAL `EventStore` with SHA-256 hash chaining, composite `ClaimLeaseManager` (Anti-TOCTOU), `MaterializedWorldview` indexed projections, and recursive `ActiveForgettingEngine`. |
| **`ciph.workers`** | Durable Worker System | Persistent `IPCJobQueue`, 11-state `JobState` machine, `ExecutionReceipt` with payload hashing, and `DurableWorkerDaemon` with background heartbeats. |
| **`ciph.planner`** | Safe Deterministic Planner | AST-based `SafePredicateEvaluator` (zero `eval()`), `DAGExecutor` with Kahn's topological sort and explicit-path $T_0$ rollback, and 5-stage `SkillRegistry`. |
| **`ciph.perception`** | Sensory Ingestion Bus | Canonical `Observation` contracts with freshness TTL checking and central `SensoryBus` pub/sub. |
| **`ciph.operator`** | Attention & Dialogue Protocol | `DialogueFormatter` across 6 epistemic registers (`[FACT]`, `[OBSERVATION]`, `[INFERENCE]`, etc.) and `CadenceManager` focus rhythms. |
| **`ciph.capabilities`** | Capability Plugins | Uniform `BaseCapability` interface and `CapabilityRegistry` with in-place adapters for `BountyHunter`, `OSINTMiner`, and `SportsPredictor`. |
| **`ciph/runtime.py`** | Cognitive Runtime Coordinator | Runtime routing for registered capabilities, deterministic lane derivation, `NETWORK_DENIED` blocking, mandatory authorization checks, receipts, and adversarial-gate hooks. |

---

## 📍 Implementation Status & Limitations

| Area | Current status |
| :--- | :--- |
| **Interactive command core** | Production path remains `ciph_core.py`; the migration to the thinner runtime is incremental. |
| **Live runtime routing** | `/bounty-scan` and sports prediction route through `CiphRuntime`. The OSINT adapter is registered, while `/osint` still follows the legacy command path. |
| **Durable workers** | Persistent queue, leases, heartbeats, watchdog recovery, and standalone `run_worker.py` are implemented and tested; they are not yet the universal dispatch path for interactive commands. |
| **DAG execution** | Topological execution, restricted AST success predicates, compensation hooks, and explicit-path rollback are implemented and tested. Natural-language requests do not automatically become DAGs in every command path. |
| **Adversarial gate** | Gate logic and runtime hooks exist. Activation is manifest-driven, and current built-in manifests do not set `requires_red_team=True`. |
| **Epistemic memory** | Event log, materialized worldview, claim leases, dispute handling, and recursive invalidation are implemented. Legacy vault tables remain mutable by design. |

This status table deliberately distinguishes implemented components from universally integrated behavior. Contributions that complete the migration are welcome.

## 🧪 Verified Test Matrix

CIPH 4.0 includes unit and command-level regression tests covering typed contracts, state machines, hash-chain integrity, concurrency leases, worker behavior, rollback, and existing command handling:

```text
======================================================================
  Test Suite                                      Pass / Total   Result
======================================================================
  test_ciph_contracts.py (Contracts & Policy)         9 / 9       PASS
  test_ciph_memory.py (Leases & Multi-Gen Cascade)    5 / 5       PASS
  test_ciph_workers.py (Daemon & Heartbeat)           2 / 2       PASS
  test_ciph_planner_operator.py (T0, Skill Registry)  6 / 6       PASS
  test_auth.py (Authentication & OpSec)               5 / 5       PASS
  test_ciph_project_suite.py (Command Regression)    25 / 25      PASS
======================================================================
  TOTAL: 52 / 52 Tests Passing (0 Failures, 0 Regressions)
======================================================================
```

To run the complete verification harness locally:
```bash
python3 test_ciph_contracts.py && python3 test_ciph_memory.py && python3 test_ciph_workers.py && python3 test_ciph_planner_operator.py && python3 test_auth.py && python3 test_ciph_project_suite.py
```

---

## 🚀 Installation & Quickstart

> **Prerequisite**: CIPH 4.0 requires **Python 3.12 or higher**.

---

### 🐧 Option A: Linux / VPS (Debian, Ubuntu, Kali, Arch — Recommended)

#### 1. Install System Dependencies & Tor Daemon
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git tor curl

# Start & verify local Tor daemon
sudo systemctl enable --now tor
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

#### 2. Clone & Setup Virtual Environment
```bash
git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

#### 3. Launch CIPH 4.0
```bash
# Launch Interactive Cognitive Shell
python3 run_ciph.py

# (Optional) Launch Background Durable Worker Daemon in separate terminal/tmux
python3 run_worker.py --workers 2
```

---

### 🐧 Option B: Windows via WSL2 (Windows Subsystem for Linux)

#### 1. Enable WSL2 & Install Ubuntu
```powershell
wsl --install -d Ubuntu
```
*(Restart your machine if prompted, then open your Ubuntu terminal)*.

#### 2. Install Dependencies, Setup & Launch
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git tor curl
sudo systemctl enable --now tor

git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

python3 run_ciph.py
```

---

### 🪟 Option C: Windows Native (PowerShell / Command Prompt)

#### 1. Prerequisites on Windows
* **Python 3.12+**: Download from [python.org](https://www.python.org/downloads/) *(Ensure **"Add python.exe to PATH"** is checked)* or install via Windows Package Manager:
  ```powershell
  winget install Python.Python.3.12 Git.Git TorProject.Tor
  ```
* **Tor on Windows**: Run the Tor Expert Bundle or keep [Tor Browser](https://www.torproject.org/download/) open in the background (provides SOCKS5 on `127.0.0.1:9150` or `127.0.0.1:9050`).

#### 2. Clone & Setup Environment
* **PowerShell**:
  ```powershell
  git clone https://github.com/pendragon360/scaling-lamp.git
  cd scaling-lamp
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  pip install -r requirements.txt
  copy .env.example .env
  python run_ciph.py
  ```

---

### 🍎 Option D: macOS (Homebrew)

#### 1. Install Prerequisites
```bash
brew install python git tor
brew services start tor
```

#### 2. Clone & Launch
```bash
git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 run_ciph.py
```

---

## 📖 Command Catalog

### 🎯 Bug Bounty & Reconnaissance
* `/bounty-scan <target>` — Execute Tor-routed passive surface audit & subdomain enumeration
* `/bounty-report <target>` — Generate structured vulnerability report with CVSS scoring
* `/bounty-programs` — List locally configured and discovered bounty programs
* `/bounty-status` — Review current bounty target telemetry

### 📡 Real-World Telemetry & Darknet
* `/darknet-scan` — Query Ahmia Tor index for threat disclosures
* `/darknet-status` — Review active darknet feed telemetry
* `/osint` — Trigger real-time threat feed aggregation
* `/briefing` — Generate proactive login intelligence briefing

### 🧠 Epistemics, Planning & Memory
* `/hypotheses` — Review active engineering and intelligence hypotheses
* `/memory-stats` — Inspect semantic entity and claim counts
* `/retroactive-learn` — Ingest and link historical conversation entities
* `/operator-council` — Review dialectic theses and strategic synthesis
* `/book-advice <topic>` — Query in-memory inverted index of strategy and systems literature

### ⚙️ Runtime, Security & Core
* `/status` — Display live subsystem operational telemetry
* `/reality-check` — Verify live runtime assertions and integrity
* `/modules` — List active decoupled modules
* `/auth-status` — Inspect operator authorization mode
* `/help` — Display operational manual
* `/exit` — Gracefully flush episodic memory and terminate

---

## 🛡️ Security Boundaries & OpSec

1. **Explicit Policy Contracts**: Capability manifests declare network, risk, reversibility, and authorization requirements. `CiphRuntime` currently blocks `NETWORK_DENIED` operations and enforces `MANDATORY_INTERRUPT`. `TOR_MANDATORY` transport behavior is implemented by applicable Tor-aware capabilities; centralized Tor-health enforcement is still an integration boundary.
2. **Conditional $T_0$ Rollback**: `DAGExecutor` can snapshot explicit file and directory paths for reversible plans. When those paths are supplied and a later step fails, it restores pre-existing content and removes newly created artifacts.
3. **Safe Success Predicates**: DAG step success conditions use a restricted AST evaluator with no Python `eval()`. General runtime policy checks use typed enums and explicit branches.
4. **Opt-In Adversarial Gate**: `AdversarialRedTeamGate` can reject execution failures, soft-404s, and unsupported takeover claims. Built-in capability manifests currently do not require the gate by default.
5. **Scoped Encryption at Rest**: Sensitive fields managed by `CipherVault` use Fernet authenticated encryption (AES-128-CBC with HMAC-SHA256) over SQLite WAL storage. The event store, IPC queue, and materialized projections are not blanket-encrypted, so the database file and host still require normal filesystem protection.

---

## ☕ Fuel the Build & Support CIPH

CIPH is an independent, open-source security intelligence runtime built for researchers. If CIPH accelerates your workflow or security operations, consider supporting continuous development:

| Network | Asset | Address |
| :--- | :--- | :--- |
| **Bitcoin** | `BTC` | `bc1q7wr0zkhk92aqr33fdy0tynadxuxgepnrpqds85` |

---

## 📡 Sovereign Contact

For research inquiries, vulnerability disclosure, or feedback:

* **Encrypted Mail**: `ciphcontact.ranger783@passinbox.com`
* **Session ID**: `05fa17d37438cb789700327416962eaa8649a582f66d06be63ef1b7f8b85b8fd09`

---

## 📄 License & Responsible Use

Distributed under the **MIT License**.

> **Notice**: CIPH is designed for authorized security research, educational purposes, and bug bounty programs operating within explicit scope rules. Users are strictly responsible for adhering to applicable laws and program guidelines.
