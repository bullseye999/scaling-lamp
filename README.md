

markdown
<div align="center">
<h1>⚫️ Ciph Core</h1>
<p><strong>Your sovereign AI agent – modular, encrypted, self‑evolving.</strong></p>

<p>
<img src="https://img.shields.io/badge/Python-3.9+-blue.svg" alt="Python">
<img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
<img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20WSL2-blue" alt="Platforms">
<img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
</p>

<p>
<a href="#-what-is-ciph-core">What is it?</a> •
<a href="#-why-ciph--advantages">Advantages</a> •
<a href="#-roadmap--where-im-going">Roadmap</a> •
<a href="#-get-started">Get Started</a> •
<a href="#-known-bugs">Bugs</a> •
<a href="#-demo--screenshots">Demo</a>
</p>
</div>


---

## 🧠 What is Ciph Core?

Ciph Core is your **personal, sovereign AI agent**.
It's not another chatbot or a cloud API wrapper. It's a complete, modular system that you control 100%.

- **Encrypted by default** – conversations, keys, and configurations live in a local SQLite vault (AES‑256 + quantum‑resistant fallback).
- **Modular** – OSINT, pentesting, trading, darknet monitoring, sports prediction – each feature is a hot‑swappable module.
- **Autonomous** – background orchestrator runs workflows, task scheduler handles daily jobs, and the agent can even propose its own upgrades.
- **Sovereign** – no third‑party cloud required. Works with local LLMs (Ollama) or OpenAI, but you stay in control.

---

## ✨ Why Ciph? (Advantages)

| Advantage | What it means for you |
|-----------|----------------------|
| **🔐 Privacy by design** | Everything is encrypted locally. No telemetry, no "phone home". |
| **🌐 Dark‑net ready** | Built‑in Tor proxy + control port for anonymous threat intelligence. |
| **💰 Wealth ops** | Crypto arbitrage scans, trading signals, bug bounty automation, monetizable threat detection. |
| **🧠 Self‑awareness** | `self_awareness.py` reads its own code, finds issues, and writes upgrade proposals. |
| **⚽ Sports intelligence** | 5‑layer prediction engine (Poisson + xG + market + news + LLM). |
| **🕹️ Complete CLI** | 50+ slash commands – from `/darknet-scan` to `/self-analyze`. |
| **🛡️ Security layer** | Integrity checks, footprint cleaner, encrypted backups, emergency wipe. |

---

## 🧭 Roadmap where I'm going

### 🔜 Next (short term)

- [ ] **UI Control Panel** – web‑based dashboard to monitor modules, view logs, and trigger commands.
- [ ] **Swarm intelligence** – multiple orchestrated agents working on different tasks simultaneously.
- [ ] **Personal data lake** – all encrypted conversations, scans, trades in one queryable format.

### 🚀 Long‑term vision

- **Decentralized operation** – run Ciph across your own hardware, no cloud dependencies, no single point of failure.
- **Proactive defense** – detect and respond to threats in real time, before they impact you.
- **Augmented intelligence** – Ciph becomes a seamless extension of your own thinking, not just a tool you use.

## 🐞 Known bugs

| Bug | Status |
|-----|--------|
| Ollama timeouts on very long prompts | workaround: `/ai` switch to OpenAI; proper optimizer planned |
| `smart_memory` can sometimes repeat old context | being refactored |
| Command `/help` is overwhelming – too many commands | will be categorised in the UI release |
| Filename typos (`ciph_verson.json`) already fixed | ✅ done |

> If you find something else, please open an issue.

---

## 📸 Demo & screenshots

Below you see exactly how Ciph looks and feels in the terminal.

### 1. Startup banner
When you launch Ciph:

```bash
python3 ciph_core.py

AI: RunPod Serverless | llama3.1:8b | Sovereign
Passing 2 modules to orchestrator: ['memory', 'osint']
Orchestrator auto-loaded with all modules.
[Auto] Running daily prediction resolution...
Autonomous sports learning loop activated.
Running integrity check...
[Auto] Fetching result for Liverpool vs Chelsea on 2026-04-01
Scanning project: .

CIPH v1.0 - AUTONOMOUS AGENT ORCHESTRATION
Encrypted • Sovereign • Adaptive • AI READY • SECURE • 2984 files • 5336 entities • 1.5 GB
PENTEST OFF • TRADING OFF • BOUNTY OFF • ORCHESTRATOR READY • SCHEDULER OFF • PERSISTENT ACTIVITY

Type /help for commands, /exit to quit
/load orchestrator - Load autonomous agent system
/auto-mode - Start all autonomous workflows
/workflow-status - Check autonomous operations
/start-workflow <name> - Start specific workflow
/reality-check - See actual system status (not AI fantasy)
```

### 2. `/status` – overall system health
*AI, security, project stats, memory entities, scheduled jobs.*

```bash
You: /status

- Running integrity check...
- Scanning project: .

Operational AI: Active | Security: SECURE | Project: 2984 files | Entities: 5336 | Jobs: 0
```

### 3. `/darknet-scan` – live threat intelligence through Tor
*Finds zero‑day mentions, ransomware alerts, credential leaks.*

```bash
You: /darknet-scan

===========================================
CIPH DARKNET SCAN INITIATED
===========================================
✓ Tor active. Exit IP: 192.42.116.18

✓ Scanning threat intel via Tor...
  → Threat intel: 13 findings

✓ Scanning bug bounty leads via Tor...
  → Bounty leads: 4 leads

✓ Checking credential leaks via Tor...
  → Credential check: complete

✓ Scanning market trends via Tor...
  → Market trends: 0 signals

===========================================
SCAN COMPLETE – 17 total alerts, 3 critical
===========================================

Darknet scan complete via Tor exit 192.42.116.18. 
Threat intel: 13 findings. Top signal: CISA Adds Actively Exploited SolarWinds Serv-U DoS Flaw to KEV Catalog (MEDIUM, score 13). 
Bug bounty leads: 4 found. CVEs detected: CVE-2026-20245, CVE-2026-28318, CVE-2026-20245. 
Credential check: clean.
```

### 4. `/predict Arsenal vs Chelsea` – 5‑layer sports prediction
*Poisson + market + news + LLM reasoning + arbiter. Shows conviction and contrarian signals.*

```bash
You: /predict Arsenal vs Chelsea

[Ciph Sports] Analyzing: arsenal vs chelsea  
[1/4] Math layer (Poisson + xG)...  
[2/4] Market layer (Odds movement)...  
[3/4] News layer (Context)...  
[4/4] Ciph reasoning layer...  
[5/5] Arbiter calculating conviction...  

---

CIPH INTELLIGENCE - 06 Jun 2026  

---

arsenal vs chelsea  
- **PREDICTION**: DRAW  
- **CONVICTION**: 63% [MEDIUM]  
- **PROBABILITIES**:  
  - Home Win : 18.2%  
  - Draw : 63.3%  
  - Away Win : 18.5%  
- **MARKETS**:  
  - Over 2.5 Goals : 10.0%  
  - Both Teams Score : 8.0%  
  - Top Scoreline : 0-0  
- **LAYER VERDICTS**:  
  - MATH: DRAW  
  - CIPH: DRAW  
- **KEY FACTORS**:  
  - No key factors  
- **CIPH REASONING**:  
  - N/A  

---

Powered by Ciph Intelligence Engine
```

### 5. `/self-analyze` – Ciph reads its own code and proposes upgrades
*Generates `system_proposals/` files with actual code changes.*

```bash
You: /self-analyze

Ciph analyzing own architecture...

PROPOSAL UP-010: Ollama query optimizer - reduce timeouts
Priority: HIGH | Target: enhanced_conversation.py
File: ciph_proposals/UP-010_ollama_optimizer.py
Review: cat ciph_proposals/UP-010_ollama_optimizer.py
Apply: /apply-upgrade UP-010
Reject: /reject-upgrade UP-010

PROPOSAL UP-011: Hallucination guard - verify claims against real scan data
Priority: HIGH | Target: enhanced_conversation.py
File: ciph_proposals/UP-011_hallucination_guard.py
Review: cat ciph_proposals/UP-011_hallucination_guard.py
Apply: /apply-upgrade UP-011
Reject: /reject-upgrade UP-011

PROPOSAL UP-012: Expand brain router trigger list
Priority: MEDIUM | Target: brain_router.py
File: ciph_proposals/UP-012_brain_router_expansion.py
Review: cat ciph_proposals/UP-012_brain_router_expansion.py
Apply: /apply-upgrade UP-012
Reject: /reject-upgrade UP-012

Analysis complete. 3 proposals generated.
Analysis complete. 3 upgrade proposals generated. Use /upgrades to review.
```

### 🧱 Architecture – how the files link together

```
run_ciph.py
└── ciph_core.py # main orchestrator, command router
    ├── handle_command() → calls modules via ModuleManager
    └── generate_response() → mood + memory + AI (Ollama / OpenAI)

ModuleManager (module_manager.py)
├── loads/unloads: osint, pentest, trading, bounty, orchestrator, memory, …
└── passes modules to AgentOrchestrator

CipherVault (cipher_vault.py + quantum_vault.py)
└── encrypted SQLite storage for conversations, config, knowledge graph

Darknet / OSINT chain
darknet_monitor.py + osint_miner.py → RSS + Tor + X → threat scoring → monetization

Trading / Wealth
trading_engine.py → market data, arbitrage, signals

Sports
sports_predictor.py + sports_performance.py → 5‑layer predictions + email reports

Self‑awareness
self_awareness.py → scans code, detects stubs, writes upgrade proposals via Ollama

Security & OPSEC
security_layer.py + dead_mans_switch.py + tor_proxy.py
```

All modules communicate through the vault, the module manager, and the core event loop. No spaghetti.

---

## 🚀 Installation & running

### 1. Clone the repository

```bash
git clone https://github.com/pendragon360/scaling-lamp.git
```

Expected output:

```bash
Cloning into 'scaling-lamp'...
remote: Enumerating objects: 40, done.
remote: Counting objects: 100% (40/40), done.
remote: Compressing objects: 100% (39/39), done.
remote: Total 40 (delta 2), reused 36 (delta 1), pack-reused 0 (from 0)
Receiving objects: 100% (40/40), 106.99 KiB | 4.65 MiB/s, done.
Resolving deltas: 100% (2/2), done.
```

### 2. Enter the directory

```bash
cd scaling-lamp
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Expected output:

```bash
Defaulting to user installation because normal site-packages is not writeable
Collecting cryptography>=41.0.0 (from -r requirements.txt (line 2))
  Downloading cryptography-48.0.0-cp311-abi3-win_amd64.whl.metadata (4.3 kB)
Collecting pymupdf>=1.23.0 (from -r requirements.txt (line 3))
  Downloading pymupdf-1.27.2.3-cp310-abi3-win_amd64.whl.metadata (24 kB)
Requirement already satisfied: requests>=2.31.0 in c:\users\arthu\appdata\roaming\python\python313\site-packages (from -r requirements.txt (line 6)) (2.32.5)
Collecting feedparser>=6.0.10 (from -r requirements.txt (line 7))
  Downloading feedparser-6.0.12-py3-none-any.whl.metadata (2.7 kB)
Collecting schedule>=1.2.0 (from -r requirements.txt (line 8))
  Downloading schedule-1.2.2-py3-none-any.whl.metadata (3.8 kB)
Collecting stem>=1.8.2 (from -r requirements.txt (line 9))
  Downloading stem-1.8.2.tar.gz (2.9 MB)
```

### 4. Run Ciph

```bash
python ciph_core.py
```

Expected output on first run:

```bash
AI: No API key found. Options:
1. Set OPENAI_API_KEY environment variable
2. Enter key now (stored encrypted locally)
3. Use /setkey command later

Enter API key (or press Enter to skip):
AI disabled. Use /setkey to add API key later.

Running integrity check...
Scanning project: .

AUTONOMOUS AGENT SYSTEM v1.0

Encrypted • Adaptive • BASIC MODE • SECURE • 1826 files • 0 entities • 
OSINT OFF • PENTEST OFF • TRADING OFF • BOUNTY OFF • ORCHESTRATOR OFF • 
SCHEDULER OFF • PERSONALITY ACTIVE

Type /help for commands, /exit to quit
/load orchestrator - Load autonomous agent system
/auto-mode - Start all autonomous workflows
/workflow-status - Check autonomous operations
/start-workflow <name> - Start specific workflow
/reality-check - See actual system status (not AI fantasy)
```

---

### 🔧 Optional: Tor Setup (for darknet features)

```bash
sudo apt install tor
```

---

## 📄 License

MIT – free for educational and research use.  
The author assumes no liability for misuse of the security or darknet features.

---

**Built to be sovereign.**
```
