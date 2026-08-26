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
  <a href="#-the-14-core-operational-engines">The 14 Engines</a> •
  <a href="#-proactive-session-intelligence--zero-day-radar">Proactive Intelligence</a> •
  <a href="#-installation--quickstart">Quickstart</a> •
  <a href="#-categorized-command-catalog">Command Catalog</a> •
  <a href="#-fuel-the-build--support-ciph">Donate</a> •
  <a href="#-sovereign-contact--security-disclosure">Contact</a>
</p>

</div>

---

## 🧠 What is CIPH 3.0?

**CIPH 3.0** is an autonomous, sovereign intelligence operative built for local execution, real-world sensory telemetry, darknet mapping, bug bounty reconnaissance, wealth operations, sports analytics, and strategic adversarial simulation.

Unlike conventional AI wrappers, CIPH is directly wired to its host operating system, persistent encrypted databases, and an isolated SOCKS5h Tor transport layer. It operates under a strict **Fail-Closed** security architecture with zero third-party telemetry, local AES-256 encrypted vaults, and continuous 24/7 background radar that indexes live CVEs, zero-days, and macro technological shifts while offline.

When you log in, CIPH takes the initiative—greeting you with exact offline durations, synthesizing named vulnerabilities and breaches, and formulating proactive tactical questions rather than passively waiting for user input.

---

## ⚡ The 14 Core Operational Engines

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
│ - GraphQL     │   │ - NVD & CVEs  │ │ - Arbs    │ │ - Auto-Report │   │ - War Room    │
└───────────────┘   └───────────────┘ └───────────┘ └───────────────┘   └───────────────┘
```

| Engine | Primary Modules | Operational Capabilities |
| :--- | :--- | :--- |
| **1. Ghost Transport (OPSEC)** | `ghost_transport.py`, `tor_proxy.py` | SOCKS5h Tor session pooling (`127.0.0.1:9050`), DoH remote DNS resolution over Tor (zero ISP leaks), anti-fingerprint headers, timing jitter, strict fail-closed enforcement. |
| **2. Elite Bug Bounty Suite v3** | `bounty_hunter.py`, `cvss_calculator.py` | Passive subdomain discovery cascade (AlienVault, Wayback CDX, crt.sh), automated dangling CNAME takeover detection across 10+ cloud providers, GraphQL `__schema` introspection, and SPA baseline calibration. |
| **3. 24/7 World Telemetry & Sensory Radar** | `world_telemetry.py` | 24/7 autonomous background sensory sweeps across NVD NIST CVE feeds, PacketStorm, Exploit-DB, BleepingComputer, HackerNews, and Reuters macro news. |
| **4. Darknet Threat Intelligence** | `darknet_monitor.py` | Tor hidden service crawling (Ahmia & Onion mirrors), ransomware tracker monitoring, zero-day threat indexing, and credential breach search. |
| **5. Proactive Terminal & Memory Bridge** | `enhanced_conversation.py`, `ciph_core.py` | Session offline time-away calculation, dynamic proactive login briefing with named zero-days, tactical operator questioning, and short-term command-to-memory context bridge (zero hallucinations). |
| **6. OSINT & Intelligence Mining** | `osint_miner.py`, `osint_catalog.py` | Live RSS threat feed aggregation, X/Twitter OSINT monitoring, target profiling, and 3-tier self-healing failover feeds. |
| **7. Wealth Ops & Crypto Arbitrage** | `trading_engine.py` | Real-time crypto market data feeds, cross-exchange arbitrage detector, momentum indicators, volatility metrics, and quantitative trading signals. |
| **8. 5-Layer Sports Intelligence** | `sports_predictor.py`, `sports_performance.py` | 5-factor probabilistic engine (Poisson distribution + xG modeling + odds movement + sports news context + LLM reasoning arbiter), daily automated result resolution, and email briefing dispatch. |
| **9. Network Pentest Engine** | `pentest_engine.py` | Local subnet discovery, multi-threaded TCP port scanning, service banner grabbing, HTTP security header auditing, and CORS reflection testing. |
| **10. Strategic Wisdom & Philosophy** | `book_engine.py`, `file_analyzer.py` | Local PDF library ingestion, knowledge extraction, and strategic wisdom synthesis (Sun Tzu, Machiavelli, Robert Greene, Marcus Aurelius) applied to operational decisions. |
| **11. Self-Awareness & Auto-Patches** | `self_awareness.py` | Continuous AST code scanning, architectural stub detection, and automated upgrade proposals (`ciph_proposals/`) with review and self-patching workflows. |
| **12. Autonomous Action Agent** | `ciph_autonomous_agent.py` | Conversational action dispatcher. Evaluates natural-language dialogue, triggers back-end tools over Tor, and synthesizes findings without command friction. |
| **13. Adversarial War Room** | `war_room.py` | 3-perspective adversarial stress-testing (*The Hunter* / Red Team, *The Stoic* / Blue Team Risk, *The Arbiter* / CIPH Synthesis). |
| **14. Defense, Vault & Emergency** | `cipher_vault.py`, `security_layer.py`, `dead_mans_switch.py` | High-concurrency SQLite `WAL` mode, AES-256 encryption, memory graph pinning, footprint cleaner, integrity checks, and emergency kill-switch wipe. |

---

## 🖥️ Proactive Session Intelligence & Zero-Day Radar

CIPH does not act like a passive chatbot. When you start an interactive session, it calculates the exact time you have been away, summarizes what the 24/7 background telemetry caught on the wire, and challenges you with proactive tactical questions:

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

---

## 🚀 Installation & Quickstart

CIPH 3.0 runs seamlessly across **Linux**, **WSL2**, **macOS**, and **Windows**.

---

### 🐧 Linux / VPS Installation (Recommended)

#### 1. System Requirements & Tor Setup
```bash
# Update and install system dependencies + Tor
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
```

#### 3. Configure API Keys
```bash
cp .env.example .env
nano .env
```
Set your DeepSeek V4 Pro API key:
```ini
DEEPSEEK_API_KEY=your_deepseek_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
DEEPSEEK_MODEL=deepseek-chat
```

#### 4. Launch CIPH
```bash
python run_ciph.py
```

---

### 🪟 Windows Installation (Native PowerShell)

#### 1. Prerequisites on Windows
* **Python 3.10+**: Install via winget:
  ```powershell
  winget install Python.Python.3.11 Git.Git TorProject.Tor
  ```
* **Tor on Windows**: Start the Tor service or run the [Tor Browser](https://www.torproject.org/download/) in the background (provides SOCKS5 on `127.0.0.1:9050` or `127.0.0.1:9150`).

#### 2. Clone & Setup
```powershell
git clone https://github.com/pendragon360/scaling-lamp.git
cd scaling-lamp

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python run_ciph.py
```

---

## 🕹️ Categorized Command Catalog

### 🌐 System Core & Real-World Telemetry
* `/world-brief` — Comprehensive real-world threat radar (Clearnet CVEs, macro tech, Tor Darknet)
* `/sync-reality` — Force immediate full-spectrum Clearnet + Tor intelligence sweep
* `/world-map` — Visual sensory topology map of active feeds and onion hubs
* `/help` — Display full command menu
* `/status` — System health, active modules, and database metrics
* `/reality-check` — Raw ground-truth system telemetry (no hallucination)
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

### 💰 Wealth Operations & Trading
* `/market-data` — Real-time price, 24h change, and volume metrics across crypto assets
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
        ├── world_telemetry.py ─────► 24/7 Clearnet CVE & Tor Darknet Sensory Engine
        ├── enhanced_conversation.py ► Unified Command-to-Memory Context Bridge
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
        ├── cipher_vault.py ────────► High-Concurrency WAL SQLite, Session & Diffs
        └── query_router.py ────────► Deterministic AST Math (LLM-Bypass)
```

---

## 🛡️ Security & OPSEC Guarantees

1. **Zero Clearnet Leakage**: `GhostTransport` enforces strict fail-closed connection pooling. If Tor drops, requests abort immediately without falling back to clearnet.
2. **Leak-Proof Remote DNS**: Hostnames are resolved through DNS-over-HTTPS (DoH) over the Tor circuit, eliminating local ISP DNS resolver exposure.
3. **Local Encryption**: All conversation logs, system states, and configuration tokens are encrypted with AES-256 before storage in SQLite `WAL` databases.
4. **Context Bridge Synchronization**: Slash command execution outputs are parsed and bridged into conversational attention windows, preventing AI hallucinations on multi-turn technical queries.

---

## ☕ Fuel the Build & Support CIPH

CIPH is an open-source sovereign intelligence and autonomous security research platform built without corporate backing or venture capital. If CIPH accelerates your vulnerability research, bug bounty workflows, or operational intelligence, consider supporting continuous development.

| Network | Asset | Address |
| :--- | :--- | :--- |
| **Bitcoin** | `BTC` | `bc1q7wr0zkhk92aqr33fdy0tynadxuxgepnrpqds85` |

---

## 📡 Sovereign Contact & Security Disclosure

For vulnerability coordination, strategic research collaboration, or operator inquiries:

* **Encrypted Mail**: `ciphcontact.ranger783@passinbox.com`
* **Anonymous Session ID**: `05fa17d37438cb789700327416962eaa8649a582f66d06be63ef1b7f8b85b8fd09`
* **Security Advisories**: Open a confidential [GitHub Security Advisory](https://github.com/pendragon360/scaling-lamp/security/advisories/new)

---

## 📄 License & Responsible Use

Distributed under the **MIT License**.

> **Notice**: CIPH is designed for authorized security research, educational purposes, and bug bounty programs operating within explicit scope rules. Users are strictly responsible for adhering to applicable laws and program guidelines.
