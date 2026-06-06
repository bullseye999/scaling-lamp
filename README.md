

```markdown
<div align="center">

# ⚫️ Ciph Core

**Your sovereign AI agent – modular, encrypted, self‑evolving.**

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20WSL2-blue)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)]()

[📖 What is it?](#-what-is-ciph-core) •
[✨ Advantages](#-why-ciph--advantages) •
[🧭 Roadmap](#-roadmap--where-im-going) •
[🚀 Get Started](#-get-started) •
[🐞 Bugs](#-known-bugs) •
[📸 Demo](#-demo--screenshots)

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
When you launch ciph

<br/>

### 2. `/status` – overall system health
*AI, security, project stats, memory entities, scheduled jobs.*



![Status command]()

<br/>

### 3. `/darknet-scan` – live threat intelligence through Tor
*Finds zero‑day mentions, ransomware alerts, credential leaks.*



<br/>

### 4. `/predict Arsenal vs Chelsea` – 5‑layer sports prediction
*Poisson + market + news + LLM reasoning + arbiter. Shows conviction and contrarian signals.*



![Sports prediction]()

<br/>

### 5. `/self-analyze` – Ciph reads its own code and proposes upgrades
*Generates `system_proposals/` files with actual code changes.*



![Self‑analysis]()

<br/>

🧱 Architecture – how the files link together

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

---

```markdown
## 🚀 Installation & running

### 1. Clone the repository

```bash
git clone https://github.com/pendragon360/scaling-lamp.git
```


2. Enter the directory

```bash
cd YOUR_REPO_NAME
```


3. Install dependencies

```bash
pip install -r requirements.txt
```


4. Run Ciph

```bash
python ciph_core.py
```

---

📄 License

MIT – free for educational and research use.
The author assumes no liability for misuse of the security or darknet features.

---

Built to be sovereign.

```

---

---




