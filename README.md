<div align="center">

# ⚫️ CIPH 3.0
### Sovereign Autonomous Intelligence, Offensive Reconnaissance & Tactical Operations Platform

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tor](https://img.shields.io/badge/Network-Tor%20SOCKS5h-7D4698?style=flat-square&logo=tor-project&logoColor=white)](https://torproject.org)
[![Storage](https://img.shields.io/badge/Storage-AES--256%20%7C%20WAL%20SQLite-00599C?style=flat-square)](https://sqlite.org)
[![Intelligence](https://img.shields.io/badge/Engine-OpenAI--Compatible%20%2F%20LLM-412991?style=flat-square)](https://platform.openai.com)
[![CVSS](https://img.shields.io/badge/Standard-CVSS%20v3.1-critical?style=flat-square)](https://www.first.org/cvss/)
[![State Machine](https://img.shields.io/badge/State%20Machine-Epistemic%20CAS-008080?style=flat-square)](https://sqlite.org)
[![Verification](https://img.shields.io/badge/Verification-Empirical%20AST%20%7C%20Receipts-success?style=flat-square)](https://github.com/pendragon360/scaling-lamp)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)

<p align="center">
  <a href="#-what-is-ciph-30">Architecture</a> •
  <a href="#-the-core-operational-engines">Core Engines</a> •
  <a href="#-installation--quickstart">Quickstart & Installation</a> •
  <a href="#-interactive-cli--demonstrations">Interactive Demos</a> •
  <a href="#-categorized-command-catalog">Command Catalog</a> •
  <a href="#-system-architecture-map">System Map</a> •
  <a href="#-fuel-the-build--support-ciph">Donate</a> •
  <a href="#-sovereign-contact">Contact</a>
</p>

</div>

---

## 🧠 What is CIPH 3.0?

**CIPH 3.0** is a sovereign, terminal-native autonomous intelligence operative designed for security researchers, bug bounty hunters, and tactical operators. Built for local execution and strict operational security, CIPH unifies real-time threat telemetry, Tor-routed passive reconnaissance, encrypted memory persistence, and multi-perspective strategic simulation into a single command-line interface.

Unlike generic AI chat wrappers, CIPH is deeply coupled with host system utilities, encrypted local storage, and an isolated SOCKS5h Tor transport layer. It operates under a **Fail-Closed** security architecture: zero external telemetry, local AES-256 encrypted SQLite databases, and autonomous background monitors that track live CVE disclosures, zero-day threat feeds, and attack surface changes.

When initialized, CIPH executes proactive terminal telemetry—detecting its Git repository remote, commit state, and incoming SSH/TTY environment. On first run, it guides the operator through an encrypted identity registry. On subsequent logins, CIPH calculates offline elapsed time, synthesizes critical vulnerability alerts, and bridges slash-command tool executions directly into conversational memory to eliminate AI context drift.

---

## ⚡ The Core Operational Engines

```
                                  ┌───────────────────┐
                                  │     CIPH 3.0      │
                                  │ SOVEREIGN RUNTIME │
                                  └─────────┬─────────┘
        ┌───────────────────┬───────────────┼───────────────┬───────────────────┐
        ▼                   ▼               ▼               ▼                   ▼
┌───────────────┐   ┌───────────────┐ ┌───────────┐ ┌───────────────┐   ┌───────────────┐
│ RECON & OPSEC │   │ THREAT INTEL  │ │ STRATEGY  │ │ COGNITIVE MEM │   │ DEV & STAGING │
│ - GhostTor    │   │ - 24/7 Radar  │ │ - War Room│ │ - Neural Graph│   │ - Auto-Sandbox│
│ - Takeovers   │   │ - Darknet Tor │ │ - Inverted│ │ - Callsign Id │   │ - Code Staging│
│ - Subdomains  │   │ - CVE Feeds   │ │ - Red/Blue│ │ - Retroactive │   │ - Hot-Patching│
└───────────────┘   └───────────────┘ └───────────┘ └───────────────┘   └───────────────┘
```

| Engine | Primary Modules | Operational Capabilities |
| :--- | :--- | :--- |
| **1. Ghost Transport & OPSEC Routing** | `ghost_transport.py`, `tor_proxy.py`, `ciph_link_reader.py` | SOCKS5h Tor session pooling (`127.0.0.1:9050`), DoH remote DNS resolution over Tor, tracking parameter sanitization (`utm_*`, `fbclid=`), canary token and IP logger blocking, and fail-closed clearnet isolation. |
| **2. Passive Bug Bounty Recon & Sentry** | `bounty_hunter.py`, `cvss_calculator.py` | Passive subdomain discovery cascade (AlienVault OTX, Wayback CDX, crt.sh), automated dangling CNAME takeover detection across 10+ cloud providers, GraphQL `__schema` introspection, historical surface diffs, and FIRST.org CVSS v3.1 scoring. |
| **3. 24/7 Threat Radar & Sensory Telemetry** | `world_telemetry.py` | Continuous sensory sweeps across NVD NIST CVE feeds, PacketStorm, Exploit-DB, BleepingComputer, HackerNews, and security advisories. |
| **4. Darknet Threat Intelligence** | `darknet_monitor.py` | Tor hidden service searching (Ahmia index), zero-day disclosure monitoring, ransomware data leak tracking, and technical breach correlation. |
| **5. Proactive Terminal & Context Memory Bridge** | `ciph_core.py`, `enhanced_conversation.py` | Session offline time-away calculation, proactive login intelligence briefing, dynamic Git & SSH environment introspection, and seamless tool-to-memory context bridging. |
| **6. Code Staging & Auto-Sandbox** | `code_staging.py` | Isolated code artifact generation (`ciph_staging/`), AST syntax verification, dependency resolution, subprocess sandbox execution tests, and 1-click atomic application with pre-write backups (`ciph_backups/`). |
| **7. OSINT & Intelligence Mining** | `osint_miner.py`, `osint_catalog.py` | Live RSS threat feed aggregation, security advisory parsing, target profiling, and 3-tier failover feeds. |
| **8. Network Pentest & Header Auditing** | `pentest_engine.py` | Local subnet host discovery, multi-threaded TCP port scanning, service banner grabbing, HTTP security header auditing, and CORS misconfiguration testing. |
| **9. Adversarial War Room** | `war_room.py` | 3-perspective adversarial plan stress-testing (*The Hunter* / Red Team, *The Stoic* / Blue Team Risk, *The Arbiter* / CIPH Strategic Synthesis). |
| **10. Cognitive Evolution & Knowledge Synthesis** | `ciph_evolution.py` | Autonomous background research exploration across philosophy, strategy, computer science, and systems design; structured blueprint synthesis and cross-domain knowledge linking. |
| **11. High-Performance Knowledge Index** | `book_engine.py`, `file_analyzer.py` | In-memory inverted keyword indexing, local PDF/document library ingestion, and strategic knowledge synthesis. |
| **12. Self-Awareness & Code Health** | `self_awareness.py` | Continuous AST code scanning, architectural stub detection, and automated upgrade proposals (`ciph_proposals/`) with safe review workflows. |
| **13. Sovereign Neural Memory & Entity Graph** | `smart_memory.py`, `cipher_vault.py` | Encrypted operator identity management, episodic session narrative milestones, associative semantic entity graphs (Targets ↔ CVEs ↔ Tool Results), and retroactive conversation learning (`/retroactive-learn`). |
| **14. Wealth Operations & Trading** *[Experimental]* | `trading_engine.py` | Real-time market data feeds, cross-exchange spread monitoring, momentum tracking, and quantitative indicators *(In Active Development)*. |
| **15. Sports Analytics Engine** *[Experimental]* | `sports_predictor.py`, `sports_performance.py` | Multi-factor probabilistic modeling (Poisson distribution + xG metrics + historical form), result tracking, and automated performance summaries *(In Active Development)*. |
| **16. Grounded Epistemic State Machine & Anti-Hallucination Receipts** | `ciph_kernel_v3.py`, `intent_resolver.py`, `cipher_vault.py` | 3-tier cryptographic runtime receipts (`DISPATCH`, `PROGRESS`, `COMPLETION` with SHA-256 integrity proofs), `HYPOTHESIS ➔ VERIFIED_REAL` state machine, Tabu Graveyard negative memory, Atomic CAS concurrency locks, and self-exhaustive pronoun/intent resolution. |
| **17. Empirical Benchmarking & Evolution Bridge** | `ciph_benchmark.py`, `evolution_bridge.py` | Curiosity-to-code hypothesis converter (`SelfRelevanceAnalyzer`), isolated subprocess cold-load latency benchmarking, AST validation, and head-to-head empirical delta scorecards. |

---

## 🚀 Installation & Quickstart

CIPH 3.0 is cross-platform and runs on **Linux**, **WSL2**, **macOS**, and native **Windows**.

---

### 🐧 Option A: Linux / VPS (Debian, Ubuntu, Arch, Kali - Recommended)

#### 1. System Requirements & Tor Setup
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git tor curl

# Start & verify Tor daemon
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

#### 3. Configure API Keys & Launch
```bash
# Optional: Set your OpenAI-compatible / DeepSeek API key in .env or via /setkey inside CLI
nano .env

# Launch CIPH
python run_ciph.py
```

---

### 🐧 Option B: Windows via WSL2 (Windows Subsystem for Linux)

#### 1. Enable WSL2 & Install Ubuntu
```powershell
wsl --install -d Ubuntu
```
*(Restart your machine if prompted, then open Ubuntu terminal)*.

#### 2. Install Dependencies & Native Tor Daemon
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git tor curl
sudo systemctl enable --now tor
```

#### 3. Clone & Setup CIPH
```bash
git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

#### 4. Launch CIPH in WSL2
```bash
python run_ciph.py
```

---

### 🪟 Option C: Windows Installation (Native PowerShell / Command Prompt)

#### 1. Prerequisites on Windows
* **Python 3.10+**: Download from [python.org](https://www.python.org/downloads/) *(Ensure **"Add python.exe to PATH"** is checked)* or install via Windows Package Manager:
  ```powershell
  winget install Python.Python.3.11 Git.Git TorProject.Tor
  ```
* **Tor on Windows**: Install the Tor Expert Bundle via `winget` or run the [Tor Browser](https://www.torproject.org/download/) in the background (which provides a local SOCKS5 proxy on `127.0.0.1:9150` or `127.0.0.1:9050`).

#### 2. Clone the Repository
```powershell
git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp
```

#### 3. Create & Activate Virtual Environment
* **PowerShell**:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
* **Command Prompt (CMD)**:
  ```cmd
  python -m venv venv
  venv\Scripts\activate.bat
  ```

#### 4. Install Dependencies & Launch
```powershell
pip install -r requirements.txt
copy .env.example .env
python run_ciph.py
```

---

### 🍎 Option D: macOS (Homebrew)

#### 1. Install Prerequisites via Homebrew
```bash
brew install python git tor
brew services start tor
```

#### 2. Clone & Setup
```bash
git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run_ciph.py
```

---

## 🖥️ Interactive CLI & Demonstrations

### 1. Dynamic Startup & Telemetry Banner
```text
╔════════════════════════════════════════════════════════════════════════════════╗
║                  CIPH 3.0 • SOVEREIGN AUTONOMOUS INTELLIGENCE                  ║
║    Repo: scaling-lamp (main@896ec7c) • Session: SSH Remote (102.88.110.233)    ║
║   Operator: Operator • AI: Active (Sovereign) • Tor: ACTIVE • Vault: ENCRYPTED ║
╚════════════════════════════════════════════════════════════════════════════════╝

Offline duration: 2 hours 14 minutes.

While you were away, three critical threads surfaced on the 24/7 wire:
1. Microsoft SharePoint RCE Chain: Two unpatched vulnerabilities chained for arbitrary code execution.
2. CISA Red Team Assessment: Dual critical infrastructure compromises analyzed.
3. OpenSSL Security Advisory: Vulnerability disclosed allowing arbitrary parameter overflow.

Type /help for commands, /exit to quit
```

### 2. First-Run Operator Registry Protocol
```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                     CIPH 3.0 • OPERATOR REGISTRY PROTOCOL                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

🕶️ Ciph: ‖ Neural core online. Identity registry uninitialized. ‖
🕶️ Ciph: ‖ Good day, Operator. What callsign or name shall I address you by? ‖

Callsign > Spectre

🕶️ Ciph: ‖ Identity established: Operator 'Spectre'. Knowledge architecture bound to your command. ‖
```

### 3. Passive Bug Bounty Recon Cascade
```text
You: /bounty-scan stripe-sandbox.com

[BountyHunter] Scanning target: stripe-sandbox.com
[GhostTransport] Tor SOCKS5 active. Identity: 104.244.76.13
[Phase 1] Passive Subdomain Cascade (AlienVault, Wayback, crt.sh):
  • api-dev.stripe-sandbox.com (200 OK)
  • static-assets.stripe-sandbox.com (404 Not Found - Azure Blob CNAME)
  • graphql.stripe-sandbox.com (200 OK)

[Phase 2] Subdomain Takeover Verification:
  [CRITICAL] static-assets.stripe-sandbox.com points to unclaimed Azure Blob container!
  [CVSS Calculator] Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (Score: 9.1 CRITICAL)

[Phase 3] GraphQL Introspection Probe:
  • Querying __schema { types { name } }...
  • Introspection response: 242 types exposed (Sensitive mutations: resetPassword, elevateRole)

[Phase 4] Report Synthesis:
  • Markdown report compiled: bounty_reports/stripe-sandbox.com_report.md
```

### 4. Historical Recon Diffing (`/what-changed`)
```text
You: /what-changed stripe-sandbox.com

[BountyHunter] Comparing current surface against SQLite baseline (2026-08-20)...

🔄 RECON HISTORICAL DIFF:
  [+] NEW ASSET: admin-internal.stripe-sandbox.com (First observed 2 hours ago)
  [+] NEW PORT: api-dev.stripe-sandbox.com:8443 (HTTP/2 Alt-Svc)
  [-] REMOVED: legacy-portal.stripe-sandbox.com (DNS NXDOMAIN)
  [!] CHANGE: static-assets.stripe-sandbox.com CNAME updated to CloudFront

Top Recommendation: Focus on newly spawned admin-internal.stripe-sandbox.com.
```

### 5. Tor-Routed Darknet Threat Hunting
```text
You: /darknet-deep "ransomware data leak"

🌑 DARKNET TOR SEARCH RESULTS FOR: 'ransomware data leak'
════════════════════════════════════════════════════════
01. LockBit Ransomware Group Leak Blog
    Onion: http://lockbit7z256lnpr...onion
02. DarkLeak Repository - Incident Disclosures
    Onion: http://darkleak3x9a10b...onion
03. CyberThreat Technical Intelligence Drops
    Onion: http://intelarchive4y1...onion
════════════════════════════════════════════════════════
```

### 6. Autonomous Code Staging & Sandbox Verification
```text
You: "write a custom multi-threaded onion proxy scraper script"

Ciph: I've engineered the requested multi-threaded Tor proxy scraper with automated
      circuit rotation, error backoff, and fail-closed validation.

┌─────────────────────────────────────────────────────────────────┐
│ 📦 CODE ARTIFACT STAGED: ciph_staging/STG-001_tor_scraper.py    │
│ Target: tools/tor_scraper.py | Size: 84 lines                   │
│ Syntax: ✅ VALID                                                │
│ Dependencies: requests, stem                                    │
│   → ✅ Installed in virtual environment                         │
│ Sandbox Test: ✅ PASSED (0.47s runtime, zero errors)            │
│ Description: Multi-threaded onion scraper with circuit rotation │
│ Status: PENDING OPERATOR APPROVAL                               │
│                                                                 │
│ Actions:                                                        │
│   /apply STG-001   → Write to workspace (with backup)          │
│   /review STG-001  → Preview the code cleanly                  │
│   /reject STG-001  → Discard staged file                       │
└─────────────────────────────────────────────────────────────────┘
```

### 7. Adversarial War Room Simulation
```text
You: /war-room "Targeting high-bounty enterprise GraphQL endpoints over Tor"

════════════════════════════════════════════════════════════
⚔️ CIPH WAR ROOM ADVERSARIAL STRESS-TEST
════════════════════════════════════════════════════════════
🔴 THE HUNTER (RED TEAM / ADVERSARY):
- Rate-limiting thresholds: Enterprise WAFs flag burst introspection queries within 15 seconds.
- Counter: Enforce timing jitter (1.5s - 3.5s) and rotate query field structures.

🔵 THE STOIC (BLUE TEAM / RISK AUDIT):
- Scope verification: Ensure target is explicitly in-scope before firing schema payloads.
- Data containment: Never pull live customer records; rely strictly on type definitions.

⚖️ THE ARBITER (CIPH STRATEGIC SYNTHESIS):
- 1. Execute schema discovery passively through Wayback archives first.
- 2. Trigger single-query introspection probes only on verified target endpoints.
- 3. Generate instant CVSS v3.1 reports upon sensitive type confirmation.
```

### 8. Network Pentest & Header Audit
```text
You: /web-scan https://api.internal-target.com

‖ Web scan: 3 vulnerabilities found ‖ Risk: HIGH ‖
  • Missing Content-Security-Policy (CSP)
  • Missing Strict-Transport-Security (HSTS)
  • Access-Control-Allow-Origin: * (Wildcard with Credentials)
```

### 9. Grounded Autonomy & Self-Exhaustive Intent Resolution
```text
You: "what about the ones with teeth?"

[IntentResolver] Scanning active runtime receipts and verified CVE disclosures...
[Resolved] Target: ServiceNow CVSS 10.0 unauthenticated RCE, cPanel root takeover (Confidence: 0.95)

Ciph: 🏛️ GROUNDED SITREP (VERIFIED RUNTIME RECEIPTS):
      1. VERIFIED REALITY:
         • ServiceNow (CVE-2024-4577): Critical unauthenticated RCE confirmed across 3 perimeter assets.
         • cPanel Root Vector: Unclaimed DNS alias verified via receipt rcpt_comp_a56207de.
      2. INFERENCE & BLAST RADIUS:
         • High probability of lateral movement if external authentication bypass is chained with existing assets.
      3. PROPOSED ACTION (KERNEL-SUBORDINATE):
         • Stage passive vulnerability template verification against target in-scope endpoints.
         • Run /bounty-scan stripe-sandbox.com to confirm perimeter boundary isolation.
```

### 10. Empirical Subprocess Benchmark Scorecard
```text
You: /benchmark-proposals

🧪 EMPIRICAL BENCHMARK: 8 Historical Upgrade Proposals Audited
═════════════════════════════════════════════════════════════════════
• UP-006_brain_router_expansion.py: ✅ Syntax (LOC: 14, Latency: 0.16ms)
• UP-007_brain_router_expansion.py: ✅ Syntax (LOC: 25, Latency: 0.18ms)
• UP-008_ollama_optimizer.py:       ✅ Syntax (LOC: 15, Latency: 0.19ms)
• UP-009_brain_router_expansion.py: ✅ Syntax (LOC: 24, Latency: 0.16ms)
• UP-010_ollama_optimizer.py:       ✅ Syntax (LOC: 20, Latency: 0.16ms)
• UP-011_hallucination_guard.py:    ✅ Syntax (LOC: 22, Latency: 0.19ms)
• UP-012_brain_router_expansion.py: ✅ Syntax (LOC: 24, Latency: 0.21ms)
• UP-013_brain_router_expansion.py: ✅ Syntax (LOC: 24, Latency: 0.16ms)

┌─────────────────────────────────────────────────────────────────┐
│ 🧪 CIPH EMPIRICAL BENCHMARK SCORECARD                           │
├─────────────────────────────────────────────────────────────────┤
│ Verdict       : ✅ IMPROVED (Recommendation: PROMOTE)           │
│ Performance   : Baseline: 912.91ms  |  Candidate: 867.20ms      │
│ Delta Score   : +5.01% latency improvement                      │
│ Diagnostic    : Candidate is 5.01% faster with 0 syntax errors. │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🕹️ Categorized Command Catalog

### 🧠 Cognitive Evolution & Grounded Epistemics
* `/curiosity <on|off|status>` — 24/7 background research daemon
* `/hypotheses` — View structured engineering hypotheses formulated by curiosity expeditions
* `/bridge-status` — Inspect curiosity-to-code cognitive bridge & capability mappings
* `/reanalyze-blueprints` — Retroactively mine historical blueprints and extract testable hypotheses
* `/benchmark-proposals` — Run empirical AST and latency benchmarks across upgrade proposals
* `/provenance <claim_id>` — Reconstruct full causal audit trail of evidence and state transitions
* `/mind-log` — Recent cognitive discovery blueprints
* `/mind-metrics` — Cognitive knowledge topology and growth dashboard
* `/council` — Strategic dialectic synthesis
* `/self-audit` — 24-hour metaconscious alignment & blind-spot self-audit
* `/fetch <url>` — Anonymous link extraction & OPSEC audit over Tor
* `/zeroize-mind` — Emergency cognitive purge & memory wipe

### 🌐 Real-World & Darknet Intel
* `/world-brief` — Real-time global threat radar & telemetry
* `/sync-reality` — Instant multi-source sensory synchronization
* `/world-map` — Clearnet & Tor sensor topology overview
* `/darknet-scan` — Full asynchronous Tor threat & leak scan
* `/darknet-deep <query>` — Search onion services & technical threat drops
* `/darknet-report` — Itemized 3-tier darknet intelligence briefing

### 🎯 Bounty Recon & Sentry
* `/bounty-scope <text/url>` — Lock program scope & rules of engagement
* `/bounty-scan <target>` — Comprehensive passive recon & attack surface audit
* `/bounty-report <target>` — Draft verified HackerOne/Bugcrowd submission
* `/bounty-list` — View active scopes and generated reports
* `/what-changed <target>` — Historical recon snapshot diff engine
* `/hit-list <target>` — Mathematical attack surface prioritization
* `/chain-reaction <target>` — Multi-stage exploit graph & attack chains
* `/watchtower` — Passive certificate transparency & sentry cycle
* `/ghost-rating` — Tor SOCKS5h OPSEC & anonymity verification

### 🤖 Agent Orchestration
* `/auto-mode` — Launch autonomous intelligence workflows
* `/start-workflow <name>` — Start specific background operation
* `/stop-workflow <name>` — Terminate active workflow
* `/workflow-status` — Inspect orchestrator pipeline state
* `/stop-all-workflows` — Stop all background tasks

### ⚔️ Strategy & War Room
* `/daily-brief` — Executive summary of intelligence & operations
* `/war-room <plan>` — Multi-perspective red team adversarial stress-test
* `/timeline` — Narrative milestones & session compressions

### 🔍 Pentesting & Code Auditing
* `/port-scan <target>` — Network port & service enumeration
* `/web-scan <url>` — Web application vulnerability scan
* `/security-audit <target>` — Automated infrastructure security audit
* `/network-discovery` — Discover live hosts on local network
* `/ssl-scan <domain>` — SSL/TLS certificate & cipher audit
* `/scan-project [path]` — AST codebase analysis & security scanning
* `/search-in-files <term>` — High-speed pattern search across project
* `/clean-footprints` — Secure shell and temporary trace sanitization
* `/integrity-check` — Cryptographic verification of core system files
* `/backup-now` — Create encrypted AES256 backup archive

### 💰 Trading & Wealth Operations *[Experimental]*
* `/market-data` — Real-time price and volume metrics across crypto assets
* `/arbitrage-scan` — Detect cross-exchange spread and yield arbitrage
* `/trading-signals` — Generate quantitative momentum and trend signals
* `/market-trends` — Multi-asset market trend evaluation
* `/wealth-strategy <amount>` — Projected wealth allocation model
* `/portfolio-health` — Portfolio risk and health check

### ⚽ Sports Analytics Engine *[Experimental]*
* `/predict <home> vs <away>` — Run multi-factor probabilistic prediction model
* `/sports-performance` — Display historical model accuracy telemetry
* `/sports-stats` — Terminal performance report
* `/auto-predict` — Trigger daily scheduled prediction workflow

### 📦 Code Staging & Hot-Patching
* `/staged` (or `/code`, `/upgrades`) — List pending, applied, and rejected code artifacts
* `/apply <id>` — Verify AST syntax, backup target, and atomically apply staged code
* `/review <id>` — Preview staged code lines cleanly
* `/reject <id>` — Dismiss and archive a staged code proposal
* `/rollback <file>` — Instantly restore the most recent pre-write backup

### 🛡️ System & Identity
* `/status` — Real-time subsystem operational metrics
* `/model-status` — AI engine connection diagnostics
* `/test-model` — Ping AI API latency and model response
* `/setkey <key>` — Set or update your AI API key
* `/set-name <callsign>` — Update operator callsign in encrypted vault
* `/help` — Display command manual
* `/exit` — Terminate session securely

---

## 🧱 System Architecture Map

```text
run_ciph.py (Launcher & Dependency Verification)
  └── ciph_core.py (Session Core, Router & Telemetry Event Loop)
        ├── ciph_router.py ─────────► OpenAI-Compatible / Sovereign LLM Cognitive Engine
        ├── intent_resolver.py ─────► Self-Exhaustive Pronoun & Context Target Resolver
        ├── ciph_kernel_v3.py ──────► Epistemic State Machine, CAS Concurrency Locks & Receipts
        ├── evolution_bridge.py ────► Curiosity-to-Code Self-Relevance & Hypothesis Analyzer
        ├── ciph_benchmark.py ──────► Subprocess AST Syntax & Cold-Load Latency Benchmarker
        ├── ghost_transport.py ─────► Fail-Closed Tor SOCKS5h & DoH DNS Resolver
        ├── bounty_hunter.py ───────► Takeover, GraphQL, Parameter & CT Recon
        │     └── cvss_calculator.py  ► Deterministic FIRST.org CVSS v3.1 Engine
        ├── darknet_monitor.py ─────► Tor Hidden Service Threat Intelligence
        ├── world_telemetry.py ─────► 24/7 Clearnet CVE & Tor Sensory Engine
        ├── smart_memory.py ────────► Sovereign Neural Memory (Callsign & Entity Graph)
        ├── code_staging.py ────────► Auto-Sandbox, Pip Resolver & Empirical Scorecards
        ├── pentest_engine.py ──────► Port Scanner, Header Audit & CORS Analyzer
        ├── war_room.py ────────────► 3-Perspective Adversarial Stress Tester
        ├── ciph_evolution.py ──────► 24/7 Polymath Curiosity Daemon & Knowledge Engine
        ├── ciph_link_reader.py ────► OPSEC Link Fetcher & Canary Blocker
        ├── book_engine.py ─────────► High-Speed Inverted Index Strategic Wisdom
        ├── self_awareness.py ──────► AST Code Auditor & Upgrade Proposals
        ├── cipher_vault.py ────────► Epistemic Ledger, Runtime Receipts & AES-256 SQLite
        ├── module_manager.py ──────► Dynamic Module Lifecycle Manager
        └── security_layer.py ──────► GPG Backup Archive & Footprint Sanitizer
```

---

## 🛡️ Security & OPSEC Guarantees

1. **Zero Clearnet Leakage**: `GhostTransport` enforces strict fail-closed connection pooling. If Tor drops, requests abort immediately without falling back to clearnet.
2. **Leak-Proof Remote DNS**: Hostnames are resolved through DNS-over-HTTPS (DoH) over the Tor circuit, eliminating local ISP DNS resolver exposure.
3. **Local Encryption**: All conversation logs, system states, and configuration tokens are encrypted before storage in SQLite `WAL` databases.
4. **Context Bridge Synchronization**: Slash command execution outputs are parsed and bridged into conversational attention windows, preventing AI hallucinations on multi-turn technical queries.
5. **Fail-Closed Code Execution**: Staged code is parsed via AST and tested in an isolated subprocess before any file write occurs; pre-write backups prevent code loss.

---

## ☕ Fuel the Build & Support CIPH

CIPH is an open-source sovereign intelligence and autonomous security research platform built without corporate backing. If CIPH accelerates your vulnerability research, bug bounty workflows, or operational intelligence, consider supporting continuous development.

| Network | Asset | Address |
| :--- | :--- | :--- |
| **Bitcoin** | `BTC` | `bc1q7wr0zkhk92aqr33fdy0tynadxuxgepnrpqds85` |

---

## 📡 Sovereign Contact

For research collaboration, operational feedback, or direct operator communication:

* **Encrypted Mail**: `ciphcontact.ranger783@passinbox.com`
* **Anonymous Session ID**: `05fa17d37438cb789700327416962eaa8649a582f66d06be63ef1b7f8b85b8fd09`

---

## 📄 License & Responsible Use

Distributed under the **MIT License**.

> **Notice**: CIPH is designed for authorized security research, educational purposes, and bug bounty programs operating within explicit scope rules. Users are strictly responsible for adhering to applicable laws and program guidelines.
