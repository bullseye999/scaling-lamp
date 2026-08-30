<div align="center">

# ⚫️ CIPH 4.0
### Unified Cognitive Nervous System & Autonomous Security Operations Runtime

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-52%2F52%20Passing-success?style=flat-square)](test_ciph_contracts.py)
[![Storage](https://img.shields.io/badge/Storage-AES--256%20%7C%20WAL%20SQLite-00599C?style=flat-square)](https://sqlite.org)
[![Network Policy](https://img.shields.io/badge/Network-Tor%20SOCKS5h%20%7C%20DoH-7D4698?style=flat-square&logo=tor-project&logoColor=white)](https://torproject.org)
[![State Machine](https://img.shields.io/badge/Epistemic%20FSM-9--State%20DAG-008080?style=flat-square)](ciph/kernel/transmutation_dag.py)
[![Predicate Safety](https://img.shields.io/badge/AST%20Validator-Zero%20eval()-critical?style=flat-square)](ciph/planner/predicates.py)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)

<p align="center">
  <a href="#-what-is-ciph-40">Overview</a> •
  <a href="#-the-5-execution-lanes">Execution Lanes</a> •
  <a href="#-architecture--core-subsystems">Architecture</a> •
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

**CIPH 4.0** is an open-source, operator-governed cognitive runtime and autonomous security operations platform. Designed for vulnerability researchers, penetration testers, and security engineers, CIPH replaces sprawling tool monoliths with a **disciplined, decoupled nervous system**.

Every action within CIPH follows a deterministic operating grammar:

$$\text{Intent} \longrightarrow \text{Risk Lane} \longrightarrow \text{Policy Check} \longrightarrow \text{Plan (AST Safe)} \longrightarrow \text{Worker Daemon} \longrightarrow \text{Execution Receipt} \longrightarrow \text{Red Team Gate} \longrightarrow \text{Epistemic DAG} \longrightarrow \text{Materialized Worldview}$$

### Key Architectural Shifts in CIPH 4.0:
* **Decoupled Limb Architecture**: Core coordinate runtime (`ciph.runtime`) interfaces with capabilities through formal typed manifests (`CapabilityManifest`) and dynamic registries (`CapabilityRegistry`).
* **Cryptographic Event Store**: All state mutations are append-only and linked via SHA-256 tamper-evident hash chaining.
* **Separation of Job and Claim States**: Operational machine execution (`JobState`: `QUEUED`, `LEASED`, `EXECUTING`, `SUCCEEDED`) is decoupled from epistemic belief state (`EpistemicCategory`: `OBSERVED`, `SUPPORTED`, `DISPUTED`, `SUPERSEDED`).
* **Anti-TOCTOU Concurrency Leases**: Running workers pin claims to prevent race conditions during state supersessions.
* **Two-Phase Invalidation Circuit Breakers**: Contradicting observations transition claims to `DISPUTED` before executing recursive invalidation cascades, protecting the knowledge base against transient network glitches.
* **Zero-`eval()` AST Predicates**: Plan success conditions and policy guards evaluate strictly through Python AST validation.

---

## 🚦 The 5 Execution Lanes

CIPH routes incoming commands through five distinct risk lanes to eliminate unnecessary latency and enforce strict isolation:

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CIPH 4.0 EXECUTION LANES                                       │
├─────────────────────┬──────────────────┬─────────────────┬───────────────────┬───────────────────┤
│ Lane                │ Risk / Reversib. │ Network Policy  │ Authorization     │ Handled Subsystem │
├─────────────────────┼──────────────────┼─────────────────┼───────────────────┼───────────────────┤
│ LANE 1: READ-ONLY   │ NONE / READ_ONLY │ OFFLINE_ONLY    │ AUTO              │ Vault & Memory    │
│ LANE 2: LOCAL MATH  │ NONE / READ_ONLY │ OFFLINE_ONLY    │ AUTO              │ CVSS & Predictors │
│ LANE 3: OBSERVATION │ LOW / READ_ONLY  │ TOR_MANDATORY   │ AUTO              │ OSINT & CT Recon  │
│ LANE 4: CONSEQUENCE │ MED / REVERSIBLE │ LOCAL_ONLY      │ AUTO / BATCH      │ Staging & DB Rows │
│ LANE 5: AUTONOMOUS  │ HIGH / COMPENS.  │ DIRECT_APPROVED │ MANDATORY_INTERR. │ Multi-Step DAGs   │
└─────────────────────┴──────────────────┴─────────────────┴───────────────────┴───────────────────┘
```

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
| **`ciph.memory`** | Cryptographic Event Sourcing | SQLite WAL `EventStore` with SHA-256 hash chaining, composite `ClaimLeaseManager` (Anti-TOCTOU), `MaterializedWorldview` ($O(1)$ views), and recursive `ActiveForgettingEngine`. |
| **`ciph.workers`** | Durable Worker System | Persistent `IPCJobQueue`, 11-state `JobState` machine, `ExecutionReceipt` with payload hashing, and `DurableWorkerDaemon` with background heartbeats. |
| **`ciph.planner`** | Safe Deterministic Planner | AST-based `SafePredicateEvaluator` (zero `eval()`), `DAGExecutor` with Kahn's topological sort and atomic $T_0$ rollback, and 5-stage `SkillRegistry`. |
| **`ciph.perception`** | Sensory Ingestion Bus | Canonical `Observation` contracts with freshness TTL checking and central `SensoryBus` pub/sub. |
| **`ciph.operator`** | Attention & Dialogue Protocol | `DialogueFormatter` across 6 epistemic registers (`[FACT]`, `[OBSERVATION]`, `[INFERENCE]`, etc.) and `CadenceManager` focus rhythms. |
| **`ciph.capabilities`** | Decoupled Limb Plugins | Uniform `BaseCapability` interface and `CapabilityRegistry` with in-place adapters for `BountyHunter`, `OSINTMiner`, and `SportsPredictor`. |
| **`ciph/runtime.py`** | Cognitive Runtime Coordinator | Unified runtime dispatching execution across the 5 risk lanes, enforcing fail-closed network policies and authorization gates. |

---

## 🧪 Verified Test Matrix

CIPH 4.0 maintains a comprehensive unit and regression test suite verifying state machines, cryptographic hash chains, concurrency locks, and backward-compatible command handling:

```text
======================================================================
  Test Suite                                      Pass / Total   Result
======================================================================
  test_ciph_contracts.py (Contracts & Policy)         9 / 9       PASS (0.043s)
  test_ciph_memory.py (Leases & Multi-Gen Cascade)    5 / 5       PASS (0.174s)
  test_ciph_workers.py (Daemon & Heartbeat)           2 / 2       PASS (0.563s)
  test_ciph_planner_operator.py (T0, 5-Stage Skill)   6 / 6       PASS (0.009s)
  test_auth.py (Authentication & OpSec)               5 / 5       PASS (2.442s)
  test_ciph_project_suite.py (Full Legacy Audit)     25 / 25      PASS (8.580s)
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
* `/bounty-programs` — Query active HackerOne/Bugcrowd targets
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

1. **Fail-Closed Network Policy**: If a capability requires `TOR_MANDATORY` and the local Tor SOCKS5h circuit is unreachable, execution halts immediately without clearnet leakage. Capabilities marked `NETWORK_DENIED` are rejected at the runtime policy engine before execution.
2. **Deterministic $T_0$ Rollbacks**: Operations classified as `REVERSIBLE` create structured file backups in `ciph_backups/` before execution. If a subsequent step in a DAG plan fails, the executor restores the pre-execution state and purges newly created dirty artifacts.
3. **Safe AST Predicate Evaluation**: Plan conditions and dynamic policy checks are parsed strictly through Python Abstract Syntax Trees (AST), completely eliminating `eval()` code execution vectors.
4. **Adversarial Gate Validation**: High-impact vulnerability claims undergo automated Red Team challenge checks to eliminate soft-404 false positives and ungrounded finding claims.
5. **Local Cryptographic Encryption**: All conversation logs, system states, and configuration tokens are encrypted at rest using AES-256 in SQLite `WAL` mode.

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
