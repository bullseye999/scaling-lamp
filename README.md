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
  <a href="#-the-12-core-operational-engines">The 12 Engines</a> •
  <a href="#-interactive-cli--demonstrations">Interactive Demos</a> •
  <a href="#-categorized-command-catalog">Command Catalog</a> •
  <a href="#-installation--quickstart">Quickstart</a> •
  <a href="#-system-architecture-map">System Map</a>
</p>

</div>

---

## 🧠 What is CIPH 3.0?

**CIPH 3.0** is an autonomous, sovereign intelligence operative built for local execution, darknet telemetry, bug bounty reconnaissance, wealth operations, sports analytics, and strategic adversarial simulation.

Unlike conventional AI wrappers, CIPH is directly wired to its host operating system, persistent encrypted databases, and an isolated SOCKS5h Tor transport layer. It operates under a strict **Fail-Closed** security architecture with zero third-party telemetry, local AES-256 encrypted vaults, and autonomous tool-dispatching capabilities that eliminate the need for rigid slash commands.

---

## ⚡ The 12 Core Operational Engines

```
                                  ┌───────────────────┐
                                  │     CIPH 3.0      │
                                  │ SOVEREIGN RUNTIME │
                                  └─────────┬─────────┘
        ┌───────────────────┬───────────────┼───────────────┬───────────────────┐
        ▼                   ▼               ▼               ▼                   ▼
┌───────────────┐   ┌───────────────┐ ┌───────────┐ ┌───────────────┐   ┌───────────────┐
│ RECON & OPSEC │   │ THREAT INTEL  │ │  WEALTH   │ │ SPORTS ENGINE │   │ SELF-EVOLVING │
│ - GhostTor    │   │ - Darknet Tor │ │ - Crypto  │ │ - 5-Layer ML  │   │ - AST Audit   │
│ - Takeovers   │   │ - Cred Leaks  │ │ - Signals │ │ - Poisson/xG  │   │ - Auto-Patch  │
│ - GraphQL     │   │ - OSINT Feeds │ │ - Arbs    │ │ - Auto-Report │   │ - War Room    │
└───────────────┘   └───────────────┘ └───────────┘ └───────────────┘   └───────────────┘
```

| Engine | Primary Modules | Operational Capabilities |
| :--- | :--- | :--- |
| **1. Ghost Transport (OPSEC)** | `ghost_transport.py`, `tor_proxy.py` | SOCKS5h Tor session pooling (`127.0.0.1:9050`), DoH remote DNS resolution over Tor (zero ISP leaks), anti-fingerprint headers, timing jitter, strict fail-closed enforcement. |
| **2. Elite Bug Bounty Suite v3** | `bounty_hunter.py`, `cvss_calculator.py` | Passive subdomain discovery cascade (AlienVault, Wayback CDX, crt.sh), automated dangling CNAME takeover detection across 10+ cloud providers, GraphQL `__schema` introspection, and SPA baseline calibration. |
| **3. Darknet Threat Intelligence** | `darknet_monitor.py` | Tor hidden service crawling (Ahmia & Onion mirrors), ransomware tracker monitoring, zero-day threat indexing, and credential breach search. |
| **4. OSINT & Intelligence Mining** | `osint_miner.py`, `osint_catalog.py` | Live RSS threat feed aggregation, X/Twitter OSINT monitoring, target profiling, and 3-tier self-healing failover feeds. |
| **5. Wealth Ops & Crypto Arbitrage** | `trading_engine.py` | Real-time crypto market data feeds, cross-exchange arbitrage detector, momentum indicators, volatility metrics, and trading signal generation. |
| **6. 5-Layer Sports Intelligence** | `sports_predictor.py`, `sports_performance.py` | 5-factor probabilistic engine (Poisson distribution + xG modeling + odds movement + sports news context + LLM reasoning arbiter), daily automated result resolution, and email briefing dispatch. |
| **7. Network Pentest Engine** | `pentest_engine.py` | Local subnet discovery, multi-threaded TCP port scanning, service banner grabbing, HTTP security header auditing, and CORS reflection testing. |
| **8. Strategic Wisdom & Philosophy** | `book_engine.py`, `file_analyzer.py` | Local PDF library ingestion, knowledge extraction, and strategic wisdom synthesis (Sun Tzu, Machiavelli, Robert Greene, Marcus Aurelius) applied to operational decisions. |
| **9. Self-Awareness & Auto-Patches** | `self_awareness.py` | Continuous AST code scanning, architectural stub detection, and automated upgrade proposals (`ciph_proposals/`) with review and self-patching workflows. |
| **10. Autonomous Action Agent** | `ciph_autonomous_agent.py` | Conversational action dispatcher. Evaluates natural-language dialogue, triggers back-end tools over Tor, and synthesizes findings without command friction. |
| **11. Adversarial War Room** | `war_room.py` | 3-perspective adversarial stress-testing (*The Hunter* / Red Team, *The Stoic* / Blue Team Risk, *The Arbiter* / CIPH Synthesis). |
| **12. Defense, Vault & Emergency** | `cipher_vault.py`, `security_layer.py`, `dead_mans_switch.py` | High-concurrency SQLite `WAL` mode, AES-256 encryption, memory graph pinning, footprint cleaner, integrity checks, and emergency kill-switch wipe. |

---

## 📸 Interactive CLI & Demonstrations

### 1. System Boot & Sovereign Telemetry
```text
🕶️ CIPH 3.0 - Sovereign Autonomous Intelligence
🔒 Checking system compatibility...
📚 Code index loaded from cache.
✅ AI: DeepSeek V4 Pro | deepseek-chat | Sovereign
🔧 Passing 2 modules to orchestrator: ['memory', 'osint']
✅ Orchestrator auto-loaded with all modules.
✅ Autonomous sports learning loop activated.

======================================================================
  CIPH 3.0 — SOVEREIGN AGENT SYSTEM
  Encrypted • Sovereign • Fail-Closed Tor • CVSS v3.1 Engine
======================================================================
```

### 2. Autonomous Bug Bounty Reconnaissance
```text
Operator: scan target.com and check if there are any takeover or graphql issues

[GhostTransport] Initializing pooled Tor SOCKS5h session (127.0.0.1:9050)...
[BountyHunter] Calibrating SPA baseline on target.com (Status: 404, Length: 162)...
[BountyHunter] Querying passive subdomains via AlienVault OTX & Wayback CDX...
[BountyHunter] 18 subdomains discovered.
[BountyHunter] Checking CNAME records for dangling provider signatures...
[BountyHunter] Probing GraphQL endpoints (/graphql, /v1/graphql, /api/graphql)...

CIPH: Recon completed for target.com over Tor. Operational breakdown:

1. 🔴 Dangling CNAME (Subdomain Takeover Vector):
   - Subdomain: docs.target.com
   - CNAME Target: target-docs.s3-website-us-east-1.amazonaws.com
   - Signature Match: AWS S3 ('NoSuchBucket' response)
   - Status: Unclaimed cloud asset detected.

2. 🟡 GraphQL Introspection Exposed:
   - Endpoint: https://api.target.com/graphql
   - Sensitive Models Discovered: User, AdminRole, PaymentMethod, AuthToken
   - Status: Schema introspection is enabled in production.

3. 🛡️ SPA Baseline Calibration:
   - Filtered soft-404 false positives across 12 default endpoints.

Tactical Next Steps:
- Run `/bounty-report target.com` to compile a submission-ready Markdown report.
- Run `/war-room` to stress-test your disclosure timeline and response scenario.
```

### 3. Tor Darknet Threat Intelligence & Credential Leaks
```text
Operator: /darknet-scan

===========================================
CIPH DARKNET SCAN INITIATED (TOR SOCKS5h)
===========================================
✓ Tor circuit active. Exit IP: 185.220.101.5
✓ Scanning onion threat feeds and ransomware leak boards...
  → Threat intel: 14 indexed alerts
✓ Scanning bug bounty leads via Tor...
  → Active leads: 4 high-severity advisories
✓ Checking breach dumps and credential exposure...
  → Credential check: Clean

Top Threat Signal: CISA Adds Actively Exploited SolarWinds Serv-U Flaw to KEV Catalog (CVSS 8.8).
CVEs Detected: CVE-2026-20245, CVE-2026-28318.
```

### 4. Wealth Operations & Crypto Arbitrage Scanner
```text
Operator: /arbitrage

[TradingEngine] Scanning liquidity pairs across CEX/DEX endpoints...
[TradingEngine] Calculating bid/ask spread and gas fee thresholds...

⚡ ARBITRAGE OPPORTUNITY IDENTIFIED:
- Asset: SOL / USDC
- Primary Exchange: Raydium ($184.20)
- Secondary Exchange: Binance ($187.10)
- Gross Spread: +1.57%
- Estimated Slippage & Gas: 0.22%
- Net Projected Yield: +1.35% (Conviction: HIGH)
```

### 5. 5-Layer Probabilistic Sports Analytics
```text
Operator: /predict Arsenal vs Chelsea

[Ciph Sports] Analyzing: arsenal vs chelsea  
[1/5] Math layer (Poisson distribution + xG modeling)...  
[2/5] Market layer (Sharp odds & volume movement)...  
[3/5] News layer (Lineup updates & tactical context)...  
[4/5] Ciph reasoning layer (DeepSeek V4 Pro)...  
[5/5] Arbiter calculating conviction metrics...  

CIPH INTELLIGENCE - MATCH PREDICTION
- **PREDICTION**: HOME WIN (Arsenal)
- **CONVICTION**: 74% [HIGH]
- **PROBABILITIES**: Home Win: 58.4% | Draw: 24.1% | Away Win: 17.5%
- **KEY MARKETS**: Over 2.5 Goals (68.2%) | Both Teams to Score (Yes)
- **ARBITER RATIONALE**: Arsenal home xG differential (+1.42) significantly outpaces Chelsea away defensive baseline.
```

### 6. Strategic Philosophy & Book Wisdom Synthesis
```text
Operator: /ask-book "How do we handle a rival trying to bait us into a premature move?"

[BookEngine] Searching ingested library (48 Laws of Power, Art of War, Discourses)...
[BookEngine] Extracting strategic maxims...

CIPH: Greene (Law 8: Make other people come to you) and Sun Tzu (Chapter 6: Weak Points & Strong) align here:
1. **Control the Terrain**: The rival baits you because they lack leverage on their own ground. Moving now surrenders initiative.
2. **Withhold Reaction**: Acknowledge nothing publicly. Silence forces them to expend more resources trying to confirm your position.
3. **Counter on Your Timeline**: Wait until their initial momentum exhausts itself, then strike where they left themselves exposed.
```

### 7. Self-Awareness & Self-Evolving Code Proposals
```text
Operator: /self-analyze

Ciph analyzing own architecture & codebase...

PROPOSAL UP-014: AST query optimization for state telemetry
Priority: HIGH | Target: query_router.py
File: ciph_proposals/UP-014_ast_optimization.py
Review: cat ciph_proposals/UP-014_ast_optimization.py
Apply: /apply-upgrade UP-014

PROPOSAL UP-015: Connection pool health check daemon
Priority: MEDIUM | Target: ghost_transport.py
File: ciph_proposals/UP-015_pool_health_check.py
Apply: /apply-upgrade UP-015

Analysis complete. 2 upgrade proposals generated. Use /upgrades to review.
```

### 8. Adversarial War Room Simulation
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

### 🌐 System Core & Runtime
* `/help` — Display full command menu
* `/status` — System health, active modules, and database metrics
* `/reality-check` — Raw ground-truth system telemetry (no hallucination)
* `/clear` — Clear terminal session screen
* `/exit` — Encrypt database connections and cleanly terminate

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
* `/market-scan` — Real-time price and volume metrics across crypto assets
* `/arbitrage` — Detect cross-exchange spread and yield arbitrage opportunities
* `/trading-signals` — Generate quantitative momentum and trend signals
* `/crypto-price <symbol>` — Instant price and volatility check for specific token

### ⚽ Sports Prediction Engine
* `/predict <home> vs <away>` — Run 5-layer probabilistic prediction model
* `/sports-performance` — Display historical model accuracy and ROI telemetry
* `/sports-accuracy` — Check rolling hit rates across leagues
* `/auto-predict` — Trigger daily scheduled prediction workflow

### 🔍 Network & Pentesting
* `/port-scan <target>` — Multi-threaded TCP port scan and service detection
* `/network-scan <subnet>` — Local network host discovery
* `/vuln-scan <url>` — HTTP security headers and CORS configuration check
* `/headers-check <url>` — Analyze missing defense headers and cookie flags

### 📚 Strategic Wisdom & Memory
* `/load-book <file.pdf>` — Ingest PDF document into local strategic library
* `/ask-book <query>` — Synthesize strategic wisdom from ingested library
* `/library-status` — List all indexed books and knowledge nodes
* `/pin <key> <fact>` — Pin persistent memory fact into encrypted knowledge graph
* `/remember <query>` — Search semantic memory graph
* `/memory-status` — View active memory entities and context load

### 🧠 Self-Awareness & Self-Evolution
* `/self-analyze` — Scan codebase, detect gaps, and write upgrade proposals
* `/upgrades` — List pending system upgrade proposals
* `/apply-upgrade <id>` — Automatically apply and verify code patch proposal
* `/reject-upgrade <id>` — Dismiss upgrade proposal
* `/war-room <plan>` — Run 3-perspective adversarial stress test on strategy

### 🛡️ Defense & Emergency Protocols
* `/integrity-check` — Validate file hashes and detect unauthorized tampering
* `/clean-footprint` — Scrub temporary logs, caches, and terminal artifacts
* `/emergency-wipe` — Secure multi-pass wipe of local vaults and keys
* `/dead-mans-switch` — Configure heartbeat check and failsafe actions

---

## 🚀 Installation & Quickstart

### 1. Prerequisites
* **Operating System**: Linux (Ubuntu/Debian, Arch, Fedora), macOS, or WSL2.
* **Python**: `Python 3.10+`
* **Tor Daemon**: Required for anonymous threat intel and fail-closed recon.

### 2. Clone the Repository
```bash
git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp
```

### 3. Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure Environment
Copy the example environment file and add your credentials:
```bash
cp .env.example .env
```
Edit `.env` with your API configuration:
```ini
# DeepSeek V4 Pro API Configuration (PRIMARY)
DEEPSEEK_API_KEY=your_deepseek_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
DEEPSEEK_MODEL=deepseek-chat

# Optional API Integrations
FOOTBALL_DATA_API_KEY=your_football_data_api_key_here
ODDS_API_KEY=your_odds_api_key_here
```

### 5. Start Tor Daemon
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install tor -y
sudo systemctl start tor

# macOS (Homebrew)
brew install tor
brew services start tor
```

### 6. Run System Verification
Verify all cryptographic vault operations, AST math evaluation, Tor headers, and scope enforcement:
```bash
python3 test_auth.py
```
*Expected Output: `Ran 5 tests in ~0.15s - OK`*

### 7. Launch CIPH
```bash
python3 run_ciph.py
```

---

## 🧱 System Architecture Map

```text
run_ciph.py (Bootstrap & Dependency Verification)
  └── ciph_core.py (Session Core & Event Loop)
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
        ├── cipher_vault.py ────────► High-Concurrency WAL SQLite & Recon Diffs
        └── query_router.py ────────► Deterministic AST Math (LLM-Bypass)
```

---

## 🛡️ Security & OPSEC Guarantees

1. **Zero Clearnet Leakage**: `GhostTransport` enforces strict fail-closed connection pooling. If Tor drops, requests abort immediately without falling back to clearnet.
2. **Leak-Proof Remote DNS**: Hostnames are resolved through DNS-over-HTTPS (DoH) over the Tor circuit, eliminating local ISP DNS resolver exposure.
3. **Local Encryption**: All conversation logs, system states, and configuration tokens are encrypted with AES-256 before storage in SQLite `WAL` databases.
4. **Code & Payload Masking**: `personality_engine.py` isolates fenced code blocks, inline code, and JSON dictionaries before applying conversational formatting, preventing corruption of technical payloads.

---

## 📄 License & Responsible Use

Distributed under the **MIT License**.

> **Notice**: CIPH is designed for authorized security research, educational purposes, and bug bounty programs operating within explicit scope rules. Users are strictly responsible for adhering to applicable laws and program guidelines.
