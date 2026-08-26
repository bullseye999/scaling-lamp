<div align="center">

# ⚫️ CIPH 3.0
### Sovereign Autonomous Intelligence, Offensive Reconnaissance & Tactical Operations Platform

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tor](https://img.shields.io/badge/Network-Tor%20SOCKS5h-7D4698?style=flat-square&logo=tor-project&logoColor=white)](https://torproject.org)
[![Storage](https://img.shields.io/badge/Storage-AES--256%20%7C%20WAL%20SQLite-00599C?style=flat-square)](https://sqlite.org)
[![Intelligence](https://img.shields.io/badge/Engine-DeepSeek%20V4%20Pro-412991?style=flat-square)](https://api.deepseek.com)
[![CVSS](https://img.shields.io/badge/Standard-CVSS%20v3.1-critical?style=flat-square)](https://www.first.org/cvss/)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)

<p align="center">
  <a href="#-what-is-ciph-30">Architecture</a> •
  <a href="#-the-15-core-operational-engines">The 15 Engines</a> •
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

**CIPH 3.0** is an autonomous, sovereign intelligence operative built for local execution, 24/7 real-world sensory telemetry, darknet mapping, bug bounty reconnaissance, wealth operations, sports analytics, and strategic adversarial simulation.

Unlike conventional AI wrappers, CIPH is directly wired to its host operating system, persistent encrypted databases, and an isolated SOCKS5h Tor transport layer. It operates under a strict **Fail-Closed** security architecture with zero third-party telemetry, local AES-256 encrypted vaults, and continuous 24/7 background radar that monitors live CVEs, zero-days, and macro technological shifts while offline.

When you log in, CIPH takes the initiative—greeting you with exact offline durations, synthesizing named vulnerabilities and breaches, and formulating proactive tactical questions rather than passively waiting for user input. All slash commands and tool outputs are automatically bridged into conversational working context, eliminating AI hallucinations on multi-turn technical follow-ups.

When engineering code, CIPH never pollutes the interactive terminal with massive raw code blocks. Instead, it extracts and stages the code into an isolated artifact, runs automated dependency resolution via venv pip, executes an isolated sandbox test, and presents an executive summary with a clean 1-click approval card (`/apply <id>`) featuring automated backups, rollback failsafes, and structured changelog tracking.

---

## ⚡ The 15 Core Operational Engines

```
                                  ┌───────────────────┐
                                  │     CIPH 3.0      │
                                  │ SOVEREIGN RUNTIME │
                                  └─────────┬─────────┘
        ┌───────────────────┬───────────────┼───────────────┬───────────────────┐
        ▼                   ▼               ▼               ▼                   ▼
┌───────────────┐   ┌───────────────┐ ┌───────────┐ ┌───────────────┐   ┌───────────────┐
│ RECON & OPSEC │   │ THREAT INTEL  │ │  WEALTH   │ │ SPORTS ENGINE │   │ PROACTIVE AI  │
│ - GhostTor    │   │ - 24/7 Radar  │ │ - Crypto  │ │ - 5-Layer ML  │   │ - Session Log │
│ - Takeovers   │   │ - Darknet Tor │ │ - Signals │ │ - Poisson/xG  │   │ - Zero-Halluc │
│ - GraphQL     │   │ - NVD & CVEs  │ │ - Arbs    │ │ - Auto-Report │   │ - Code Staging│
└───────────────┘   └───────────────┘ └───────────┘ └───────────────┘   └───────────────┘
```

| Engine | Primary Modules | Operational Capabilities |
| :--- | :--- | :--- |
| **1. Ghost Transport (OPSEC)** | `ghost_transport.py`, `tor_proxy.py` | SOCKS5h Tor session pooling (`127.0.0.1:9050`), DoH remote DNS resolution over Tor (zero ISP leaks), anti-fingerprint headers, timing jitter, strict fail-closed enforcement. |
| **2. Elite Bug Bounty Suite v3** | `bounty_hunter.py`, `cvss_calculator.py` | Passive subdomain discovery cascade (AlienVault, Wayback CDX, crt.sh), automated dangling CNAME takeover detection across 10+ cloud providers, GraphQL `__schema` introspection, and SPA baseline calibration. |
| **3. 24/7 World Telemetry & Sensory Radar** | `world_telemetry.py` | 24/7 autonomous background sensory sweeps across NVD NIST CVE feeds, PacketStorm, Exploit-DB, BleepingComputer, HackerNews, and Reuters macro news. |
| **4. Darknet Threat Intelligence** | `darknet_monitor.py` | Tor hidden service crawling (Ahmia & Onion mirrors), ransomware tracker monitoring, zero-day threat indexing, and credential breach search. |
| **5. Proactive Terminal & Memory Bridge** | `enhanced_conversation.py`, `ciph_core.py` | Session offline time-away calculation, dynamic proactive login briefing with named zero-days, tactical operator questioning, and short-term command-to-memory context bridge (zero hallucinations). |
| **6. Unified Code Staging & Auto-Sandbox** | `code_staging.py` | Automatic conversational code staging (`ciph_staging/`), auto-import dependency resolution in venv, isolated subprocess sandbox execution tests, zero terminal clutter via Staging Cards, 1-click safe atomic application with pre-write backups (`ciph_backups/`), instant rollback, and structured audit changelog (`ciph_changelog.json`). |
| **7. OSINT & Intelligence Mining** | `osint_miner.py`, `osint_catalog.py` | Live RSS threat feed aggregation, X/Twitter OSINT monitoring, target profiling, and 3-tier self-healing failover feeds. |
| **8. Wealth Ops & Crypto Arbitrage** | `trading_engine.py` | Real-time crypto market data feeds, cross-exchange arbitrage detector, momentum indicators, volatility metrics, and quantitative trading signals. |
| **9. 5-Layer Sports Intelligence** | `sports_predictor.py`, `sports_performance.py` | 5-factor probabilistic engine (Poisson distribution + xG modeling + odds movement + sports news context + LLM reasoning arbiter), daily automated result resolution, and email briefing dispatch. |
| **10. Network Pentest Engine** | `pentest_engine.py` | Local subnet discovery, multi-threaded TCP port scanning, service banner grabbing, HTTP security header auditing, and CORS reflection testing. |
| **11. Strategic Wisdom & Philosophy** | `book_engine.py`, `file_analyzer.py` | Local PDF library ingestion, knowledge extraction, and strategic wisdom synthesis (Sun Tzu, Machiavelli, Robert Greene, Marcus Aurelius) applied to operational decisions. |
| **12. Self-Awareness & Auto-Patches** | `self_awareness.py` | Continuous AST code scanning, architectural stub detection, and automated upgrade proposals (`ciph_proposals/`) with review and safe self-patching workflows. |
| **13. Autonomous Action Agent** | `ciph_autonomous_agent.py` | Conversational action dispatcher. Evaluates natural-language dialogue, triggers back-end tools over Tor, and synthesizes findings without command friction. |
| **14. Adversarial War Room** | `war_room.py` | 3-perspective adversarial stress-testing (*The Hunter* / Red Team, *The Stoic* / Blue Team Risk, *The Arbiter* / CIPH Synthesis). |
| **15. Defense, Vault & Emergency** | `cipher_vault.py`, `security_layer.py`, `dead_mans_switch.py` | High-concurrency SQLite `WAL` mode, AES-256 encryption, memory graph pinning, footprint cleaner, integrity checks, and emergency kill-switch wipe. |

---

## 🚀 Installation & Quickstart

CIPH 3.0 runs seamlessly across **Windows**, **Linux**, **macOS**, and **WSL2**. Choose your platform below.

---

### 🪟 Option A: Windows Installation (Native PowerShell / Command Prompt)

#### 1. Prerequisites on Windows
* **Python 3.10+**: Download from [python.org](https://www.python.org/downloads/) *(Ensure **"Add python.exe to PATH"** is checked)* or install via Windows Package Manager:
  ```powershell
  winget install Python.Python.3.11 Git.Git TorProject.Tor
  ```
* **Tor on Windows**: You can install the Tor Expert Bundle via `winget` above or launch the [Tor Browser](https://www.torproject.org/download/) in the background (which provides a local SOCKS5 proxy on `127.0.0.1:9150` or `127.0.0.1:9050`).

#### 2. Clone the Repository
Open **PowerShell** or **Command Prompt** and clone the repo:
```powershell
git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp
```

#### 3. Create & Activate Virtual Environment
* **PowerShell**:
  ```powershell
  # If script execution is restricted, enable process bypass once:
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
* **Command Prompt (CMD)**:
  ```cmd
  python -m venv venv
  venv\Scripts\activate.bat
  ```

#### 4. Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### 5. Configure Environment Variables
Copy the template configuration file:
```powershell
copy .env.example .env
```
Open `.env` in Notepad or VS Code and set your API keys:
```ini
# DeepSeek V4 Pro API Configuration (PRIMARY)
DEEPSEEK_API_KEY=your_deepseek_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
DEEPSEEK_MODEL=deepseek-chat

# Optional API Integrations
FOOTBALL_DATA_API_KEY=your_football_data_api_key_here
ODDS_API_KEY=your_odds_api_key_here
```

#### 6. Start Tor Daemon
* If installed via `winget` / Tor Expert Bundle, start the service in a separate terminal:
  ```powershell
  tor
  ```
* *Alternatively*, simply keep the Tor Browser open in the background.

#### 7. Verify & Launch CIPH
```powershell
# Run self-test
python test_auth.py

# Launch CIPH interactive terminal
python run_ciph.py
```

---

### 🐧 Option B: Windows via WSL2 (Windows Subsystem for Linux - Recommended)

For the closest parity with production cloud environments and native Tor daemon systemd management:

#### 1. Enable WSL2 & Install Ubuntu
```powershell
wsl --install -d Ubuntu
```
*(Restart your machine if prompted, then open Ubuntu terminal)*.

#### 2. Install Dependencies & Native Tor Daemon
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git tor curl

# Start & enable Tor daemon
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

### 🐧 Option C: Linux / VPS (Debian, Ubuntu, Arch, Kali)

#### 1. System Requirements & Tor Setup
```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git tor curl

# Verify Tor service is running
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
nano .env
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
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

#### 3. Launch
```bash
python run_ciph.py
```

---

## 🖥️ Interactive CLI & Demonstrations

### 1. Proactive Session Intelligence & Real-World CVE Radar
```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                  CIPH v1.0 - AUTONOMOUS AGENT ORCHESTRATION                  ║
║ Encrypted • Sovereign • Adaptive • AI READY • SECURE • 14 feeds • BOUNTY READY ║  
╚══════════════════════════════════════════════════════════════════════════════╝

Welcome back. Offline duration: 4 hours 18 minutes.

While you were away, three critical threads surfaced on the 24/7 wire:
1. Microsoft SharePoint RCE Chain: Two unpatched vulnerabilities chained for arbitrary code execution with active public PoC weaponization.
2. CISA Red Team Assessment: Dual critical infrastructure compromises executed simultaneously, one entirely undetected.
3. Kaltura mwEmbed Vulnerabilities: Unpatched remote flaws [CVE-2026-19913, CVE-2026-19912] allowing arbitrary file disclosure and execution.

🎯 Tactical Question for You:
"Given the active weaponization of the SharePoint RCE chain and Kaltura mwEmbed (CVE-2026-19913), should we map an exploit validation chain on this vulnerability today, or execute a surface audit on our primary target list?"

You: What was the first critical vulnerability in that brief and why does it matter?

Ciph: The first one — Microsoft SharePoint RCE chain with a public PoC.
      Why it matters: it's not a single bug, it's a chain. Attackers are actively
      weaponizing it right now. That means unpatched SharePoint servers are being
      hit in the wild, not just theoretically vulnerable.
```

### 2. Autonomous Code Staging & Sandbox Verification (Zero Terminal Clutter)
```text
You: "write a custom multi-threaded onion proxy scraper script"

Ciph: I've engineered the requested multi-threaded Tor proxy scraper with automated
      circuit rotation, error backoff, and fail-closed validation.

┌─────────────────────────────────────────────────────────────────┐
│ 📦 CODE ARTIFACT STAGED: ciph_staging/STG-001_tor_scraper.py    │
│ Target: tools/tor_scraper.py | Size: 84 lines                   │
│ Syntax: ✅ VALID                                                │
│ Dependencies: requests, stem                                    │
│   → ✅ Both installed in virtual environment                    │
│ Sandbox Test: ✅ PASSED (0.47s runtime, zero errors)            │
│ Description: Multi-threaded onion scraper with circuit rotation │
│ Status: PENDING OPERATOR APPROVAL                               │
│                                                                 │
│ Actions:                                                        │
│   /apply STG-001   → Write to workspace (with backup)          │
│   /review STG-001  → Preview the code cleanly                  │
│   /reject STG-001  → Discard staged file                       │
│                                                                 │
│ Rollback available after apply: /rollback tools/tor_scraper.py  │
└─────────────────────────────────────────────────────────────────┘

Would you like me to apply this to tools/tor_scraper.py now?
```

### 3. Autonomous Dialogue & Intent Routing
```text
Operator: "audit gitlab.target.com and tell me if they left anything open"

[IntentRouter] Autonomous dispatch: /bounty-scan gitlab.target.com
[GhostTransport] Routing via Tor SOCKS5h circuit [Exit IP: 185.220.101.5]
[BountyHunter] Discovering subdomains across AlienVault + Wayback CDX...
[BountyHunter] Passive recon complete. 18 subdomains discovered.
[BountyHunter] Testing dangling CNAME records against AWS S3, Azure, CloudFront...
[BountyHunter] Probing GraphQL endpoints for introspection exposure...

🎯 Recon Results for gitlab.target.com:
- Status: Active (HTTP 200)
- Dangling DNS: dev-staging.gitlab.target.com -> target-staging.s3-website.amazonaws.com (S3 Bucket Unclaimed!)
- Vulnerability: Subdomain Takeover (High - CVSS 7.5)
- GraphQL: /api/graphql introspection ENABLED (__schema exported)

Ciph: Found an unclaimed AWS S3 bucket on dev-staging.gitlab.target.com. 
      Full takeover is possible. GraphQL introspection is also open. 
      Report generated at bounty_reports/gitlab.target.com_report.md.
```

### 4. Elite Bug Bounty Recon Cascade
```text
Operator: /bounty-scan stripe-sandbox.com

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

### 5. Historical Recon Diffing & What-Changed
```text
Operator: /what-changed stripe-sandbox.com

[BountyHunter] Comparing current surface against SQLite baseline (2026-08-20)...

🔄 RECON HISTORICAL DIFF:
  [+] NEW ASSET: admin-internal.stripe-sandbox.com (First observed 2 hours ago)
  [+] NEW PORT: api-dev.stripe-sandbox.com:8443 (HTTP/2 Alt-Svc)
  [-] REMOVED: legacy-portal.stripe-sandbox.com (DNS NXDOMAIN)
  [!] CHANGE: static-assets.stripe-sandbox.com CNAME updated to CloudFront

Top Recommendation: Focus on newly spawned admin-internal.stripe-sandbox.com.
```

### 6. Tor-Routed Darknet Threat Hunting
```text
Operator: /darknet-scan

[DarknetMonitor] Querying Ahmia hidden service index over Tor SOCKS5...
[DarknetMonitor] Crawling active ransomware tracker leak sites...

🌑 DARKNET THREAT INTEL:
  • LockBit 3.0 Mirror: 4 new victim announcements in past 24h
  • BreachForums RSS: Database dump posted matching keyword "FinTech API Keys"
  • Ahmia Index: 12 new .onion endpoints indexed under "0day exploit"

Threat Context saved to encrypted SQLite vault.
```

### 7. 5-Layer Sports Analytics Simulation
```text
Operator: /predict "Arsenal vs Chelsea"

[SportsPredictor] Running 5-layer probabilistic model...
  • Layer 1 (Poisson Distribution): Arsenal Expected Goals (xG) 2.14, Chelsea xG 1.05
  • Layer 2 (Historical Form & H2H): Arsenal home win rate 78% in last 10 derbies
  • Layer 3 (Market Odds Movement): Asian Handicap line shifted from -0.75 to -1.0
  • Layer 4 (Live Context & Injuries): Key Chelsea defender sidelined (hamstring)
  • Layer 5 (LLM Reasoning Arbiter): DeepSeek V4 Pro evaluates game dynamics

📊 PREDICTION SYNTHESIS:
  • Primary Pick: Arsenal Win (-1 Handicap)
  • Win Probability: 68.4%
  • Expected Value (+EV): +8.2%
  • Recommended Stake: 2.5% Bankroll
```

### 8. Internal Network Pentest & Header Audit
```text
Operator: /vuln-scan https://api.internal-target.com

[PentestEngine] Auditing HTTP security headers...
  [MISSING] Content-Security-Policy (CSP)
  [MISSING] Strict-Transport-Security (HSTS)
  [VULNERABLE] Access-Control-Allow-Origin: * (Wildcard with Credentials)
  [EXPOSED] Server: Apache/2.4.41 (Ubuntu) mod_ssl/2.4.41 OpenSSL/1.1.1f

Security Score: 42/100 (HIGH RISK)
```

### 9. Strategic Wisdom Ingestion
```text
Operator: "our competitor is aggressively lowering prices to squeeze our margin what is our counter move"

[BookEngine] Searching strategic library (Sun Tzu - Art of War, Greene - 48 Laws of Power)...
[Worldview] Applying strategic principles directly to operational problem...

Ciph: Greene's Law 21: Play a sucker to catch a sucker. Do not enter a direct price race to the bottom. 
Let them bleed their operating capital on low margins. 

1. **Shift the Battleground**: Differentiate on speed and custom integration, where price elasticity is lower.
2. **Conceal Your Real Reserves**: Maintain high-tier pricing while bundling value invisibly.
3. **Counter on Your Timeline**: Wait until their initial momentum exhausts itself, then strike where they left themselves exposed.
```

### 10. Self-Awareness & Self-Evolving Code Proposals
```text
Operator: /self-analyze

Ciph analyzing own architecture & codebase...

PROPOSAL UP-014: AST query optimization for state telemetry
Priority: HIGH | Target: query_router.py
File: ciph_proposals/UP-014_ast_optimization.py
Review: cat ciph_proposals/UP-014_ast_optimization.py
Apply: /apply UP-014

PROPOSAL UP-015: Connection pool health check daemon
Priority: MEDIUM | Target: ghost_transport.py
File: ciph_proposals/UP-015_pool_health_check.py
Apply: /apply UP-015

Analysis complete. 2 upgrade proposals generated. Use /staged to review.
```

### 11. Adversarial War Room Simulation
```text
Operator: /war-room "Targeting high-bounty enterprise GraphQL endpoints over Tor"

[WarRoom] Running 3-perspective adversarial stress test via DeepSeek V4 Pro...

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

---

## 🕹️ Categorized Command Catalog

### 🌐 System Core & Real-World Telemetry
* `/world-brief` — Comprehensive situational report (Clearnet CVEs, macro tech, Tor Darknet)
* `/sync-reality` — Force immediate real-time Clearnet + Tor intelligence sweep
* `/world-map` — Visual sensory topology map of active feeds and onion hubs
* `/help` — Display full command menu
* `/status` — System health, active modules, and database metrics
* `/reality-check` — Raw ground-truth system telemetry (no hallucination)
* `/clear` — Clear terminal session screen
* `/exit` — Encrypt database connections and cleanly terminate

### 📦 Code Staging, Sandbox & Hot-Patching
* `/staged` (or `/code`, `/upgrades`) — List all pending, applied, and rejected code artifacts
* `/apply <id>` (or `/approve <id>`) — Verify AST syntax, backup target, and atomically apply staged code to workspace
* `/review <id>` — Cleanly preview staged code lines without terminal scrollback clutter
* `/reject <id>` — Dismiss and archive a staged code proposal
* `/rollback <file>` — Instantly restore the most recent pre-write backup from `ciph_backups/`
* `/changelog` — View chronological audit log of all applied code evolutions

### 🎯 Bug Bounty & Reconnaissance
* `/bounty-scan <target>` — Full passive recon, takeover check, and GraphQL audit
* `/what-changed <target>` — Historical diff comparing current recon against SQLite snapshot
* `/hit-list <target>` — Prioritized top-5 highest-severity attack surfaces
* `/chain-reaction <target>` — Exploit chain correlation mapping
* `/bounty-report <target>` — Generate submission-ready Markdown vulnerability report
* `/ghost-audit` — Audit Tor transport circuit, exit IP, and latency

### 🕵️ Darknet & Threat Intelligence
* `/darknet-scan` — Scan Tor onion networks, ransomware trackers, and threat boards
* `/darknet-search <keyword>` — Query Ahmia and darknet search indices over Tor
* `/threat-intel` — Display indexed CVE alerts and zero-day threat signals
* `/credential-check` — Search credential leak indices for exposed assets
* `/osint-scan <target>` — Run deep OSINT intelligence profiling
* `/intel-feed` — Stream live cybersecurity RSS threat intelligence

### 💰 Wealth Operations & Trading
* `/market-data` — Real-time price and volume metrics across crypto assets
* `/arbitrage-scan` — Detect cross-exchange spread and yield arbitrage opportunities
* `/trading-signals` — Generate quantitative momentum and trend signals
* `/market-trends` — Multi-asset market trend evaluation

### ⚽ Sports Prediction Engine
* `/predict <home> vs <away>` — Run 5-layer probabilistic prediction model
* `/sports-performance` — Display historical model accuracy and ROI telemetry
* `/sports-stats` — Terminal performance report
* `/auto-predict` — Trigger daily scheduled prediction workflow

### 🔍 Network & Pentesting
* `/port-scan <target>` — Multi-threaded TCP port scan and service detection
* `/network-discovery` — Local network host discovery
* `/web-scan <url>` — HTTP security headers and CORS configuration check
* `/ssl-scan <domain>` — Audit SSL/TLS cipher suites and certificate validity

### 📚 Strategic Wisdom & Memory
* `/load-book <file.pdf>` — Ingest PDF document into local strategic library
* `/ask-book <query>` — Synthesize strategic wisdom from ingested library
* `/memory` — View active memory entities and context load
* `/timeline` — View episodic memory narrative timeline

### 🧠 Self-Awareness & War Room
* `/self-analyze` — Scan codebase, detect gaps, and write upgrade proposals
* `/war-room <plan>` — Run 3-perspective adversarial stress test on strategy

### 🛡️ Defense & Emergency Protocols
* `/integrity-check` — Validate file hashes and detect unauthorized tampering
* `/clean-footprints` — Scrub temporary logs, caches, and terminal artifacts
* `/emergency-wipe` — Secure multi-pass wipe of local vaults and keys

---

## 🧱 System Architecture Map

```text
run_ciph.py (Bootstrap & Dependency Verification)
  └── ciph_core.py (Session Core & Proactive Event Loop)
        ├── code_staging.py ────────► Auto-Sandbox, Pip Resolver & Hot-Patching
        ├── world_telemetry.py ─────► 24/7 Clearnet CVE & Tor Darknet Sensory Engine
        ├── enhanced_conversation.py ► Unified Command & Staging Context Bridge
        ├── ciph_router.py ─────────► DeepSeek V4 Pro Engine (Direct Cognitive API)
        ├── ciph_autonomous_agent.py ► Natural Language Tool Dispatcher
        ├── ghost_transport.py ─────► Fail-Closed Tor SOCKS5h & DoH DNS Resolver
        ├── bounty_hunter.py ───────► Takeover, GraphQL, Parameter & SPA Recon
        │     └── cvss_calculator.py  ► Deterministic FIRST.org CVSS v3.1 Engine
        ├── darknet_monitor.py ─────► Tor Ahmia & Onion Threat Intelligence
        ├── trading_engine.py ──────► Crypto Arbitrage & Quantitative Signals
        ├── sports_predictor.py ────► 5-Layer Probabilistic Analytics Engine
        ├── pentest_engine.py ──────► Port Scanner & Banner Grabbing
        ├── book_engine.py ─────────► PDF Strategic Wisdom Ingestion
        ├── self_awareness.py ──────► AST Code Auditor & Upgrade Proposals
        ├── war_room.py ────────────► 3-Perspective Adversarial Stress Tester
        ├── osint_catalog.py ───────► Multi-Tier Failover Threat Intelligence
        ├── cipher_vault.py ────────► High-Concurrency WAL SQLite, Session & Diffs
        └── query_router.py ────────► Deterministic AST Math (LLM-Bypass)
```

---

## 🛡️ Security & OPSEC Guarantees

1. **Zero Clearnet Leakage**: `GhostTransport` enforces strict fail-closed connection pooling. If Tor drops, requests abort immediately without falling back to clearnet.
2. **Leak-Proof Remote DNS**: Hostnames are resolved through DNS-over-HTTPS (DoH) over the Tor circuit, eliminating local ISP DNS resolver exposure.
3. **Local Encryption**: All conversation logs, system states, and configuration tokens are encrypted with AES-256 before storage in SQLite `WAL` databases.
4. **Context Bridge Synchronization**: Slash command execution outputs are parsed and bridged into conversational attention windows, preventing AI hallucinations on multi-turn technical queries.
5. **Fail-Closed Code Execution**: Staged code is parsed via AST and tested in an isolated subprocess before any file write occurs; pre-write backups prevent code loss.

---

## ☕ Fuel the Build & Support CIPH

CIPH is an open-source sovereign intelligence and autonomous security research platform built without corporate backing or venture capital. If CIPH accelerates your vulnerability research, bug bounty workflows, or operational intelligence, consider supporting continuous development.

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
