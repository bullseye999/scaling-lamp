
---

## `README.md`

```markdown
# Autonomous Agent System

A modular, self‑evolving AI orchestration platform with OSINT, pentesting, trading automation, darknet monitoring, sports prediction, and autonomous agent coordination.

> **Warning:** This system includes security testing and monitoring tools. Use only on systems you own or have explicit permission to test. The author assumes no liability for misuse.

---

## 🧠 Overview

This is a complete, production‑ready AI agent system that:

- 🔐 **Encrypts everything** – Fernet + AES‑GCM + quantum‑resistant fallback
- 🌐 **Routes through Tor** – Anonymous darknet monitoring and OSINT
- 🕵️ **Scans for threats & opportunities** – RSS feeds, Twitter/X, exploit databases
- 💰 **Finds monetizable vulnerabilities** – Bug bounties, zero‑day leads, arbitrage signals
- 🛡️ **Performs security audits** – Port scanning, web vuln detection, SSL checks
- 📈 **Trades crypto** – Market data, trend analysis, arbitrage scanning
- ⚽ **Predicts sports outcomes** – Poisson + xG + market movement + LLM reasoning
- 🧠 **Self‑awareness & evolution** – Reads its own code, proposes upgrades, writes new code
- 🤖 **Orchestrates autonomous workflows** – Agent coordination, scheduling, background tasks

---

## 📦 Modules

| Module | Description |
|--------|-------------|
| `ciph_core.py` | Main orchestrator, CLI, command handler |
| `agent_orchestrator.py` | Multi‑workflow autonomous agent runner |
| `cipher_vault.py` | Encrypted SQLite storage (AES‑256) |
| `quantum_vault.py` | Quantum‑resistant encrypted storage |
| `darknet_monitor.py` | Threat intel via Tor (RSS + onion sources) |
| `osint_miner.py` | RSS + X monitoring, threat scoring, monetization |
| `pentest_engine.py` | Port scanning, web vulns, SSL audit |
| `bounty_hunter.py` | Automated bug bounty vulnerability detection |
| `trading_engine.py` | Crypto market data, arbitrage, signals |
| `sports_predictor.py` | 5‑layer football prediction engine |
| `sports_performance.py` | Tracks win rate, ROI, email reports |
| `self_awareness.py` | Self‑code analysis, upgrade proposals |
| `task_scheduler.py` | Background jobs (OSINT, backups, cleanup) |
| `tor_proxy.py` | SOCKS5 proxy + control port for Tor |
| `dead_mans_switch.py` | Automatic data destruction on inactivity |
| `module_manager.py` | Hot‑swappable dynamic module loader |
| `response_formatter.py` | Clean, color‑coded terminal output |
| `personality_engine.py` | Casual, direct response styling |
| `mood_engine.py` | Detects user mood from text |
| `smart_memory.py` | Context‑aware memory with pinned facts |
| `brain_router.py` | Routes queries to Ollama (local) or OpenAI |
| `enhanced_conversation.py` | Conversation manager with personality |
| `ollama_interface.py` | Local LLM interface (Ollama) |
| `file_analyzer.py` | Project scanning, file search, code analysis |
| `config_manager.py` | JSON/YAML/env configuration |
| `security_layer.py` | Footprint cleaning, integrity checks, emergency wipe |

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Install & start Tor for darknet features

```bash
sudo apt install tor
sudo systemctl start tor
```

### 4. (Optional) Install Ollama for local LLM

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b
```

### 5. Run the system

```bash
python run_ciph.py
```

---

## 🎮 Basic Commands

Once inside the CLI:

| Command | Description |
|---------|-------------|
| `/status` | Show system status (AI, security, modules) |
| `/reality-check` | Show actual module status (no AI fantasy) |
| `/load osint` | Load OSINT module |
| `/darknet-scan` | Run darknet threat intel via Tor |
| `/osint` | Run RSS + X threat scan |
| `/bounty-scan <url>` | Scan website for vulnerabilities |
| `/market-data` | Get live crypto prices |
| `/arbitrage-scan` | Find price differences across exchanges |
| `/predict Arsenal vs Chelsea` | Sports prediction (5‑layer) |
| `/sports-mode on` | Start background sports prediction daemon |
| `/self-analyze` | Have the system propose upgrades |
| `/upgrades` | List pending upgrades |
| `/apply-upgrade <id>` | Apply an approved upgrade |
| `/ghost-mode` | Route all traffic through Tor |
| `/emergency-wipe CONFIRM_WIPE_ALL` | Destroy all sensitive data |
| `/help` | Show all commands |

---

## ⚙️ Configuration

Create a `.env` file or set environment variables:

```bash
OPENAI_API_KEY=your_key_here
OPENAI_API_BASE=https://api.openai.com/v1
AI_MODEL=gpt-4o-mini
OLLAMA_API_URL=http://localhost:11434/api/chat
TWITTER_BEARER_TOKEN=your_token_here   # optional
ODDS_API_KEY=your_key_here              # optional
```

For persistent secrets, use the built‑in vault (`/setkey` command).

---

## 🧪 Testing

Each module can be tested individually:

```bash
python cipher_vault.py
python darknet_monitor.py
python trading_engine.py
python sports_predictor.py
```

---

## 📁 Directory Structure

| Path | Purpose |
|------|---------|
| `secure_vault.db` | Encrypted conversation storage |
| `vault.key` | Encryption key (keep secure) |
| `sports_predictions/` | JSON files of predictions |
| `sports_logs/` | LLM reasoning logs |
| `system_proposals/` | Upgrade proposal files |
| `system_version.json` | Version & evolution tracking |

---

## ⚠️ Legal & Ethics

- **Only scan systems you own or have explicit permission to test.**
- **Darknet monitoring should be used for threat intelligence research only.**
- **Trading signals are educational – not financial advice.**
- **The emergency wipe is permanent – use with caution.**

By using this software, you agree to comply with all applicable laws.

---

## 🛠️ Requirements

- Python 3.9+
- Tor (for darknet features)
- Ollama (optional, for local LLM)
- OpenAI API key (optional, for cloud LLM)

See `requirements.txt` for Python dependencies.

---

## 📄 License

MIT License – free for educational and research use.

---

## 🙏 Acknowledgements

Built with:
- [PyMuPDF](https://pymupdf.readthedocs.io/) – PDF ingestion
- [Feedparser](https://pythonhosted.org/feedparser/) – RSS parsing
- [Stem](https://stem.torproject.org/) – Tor control
- [Ollama](https://ollama.com/) – Local LLM
- [Cryptography](https://cryptography.io/) – Fernet & HKDF

---

**Built by an independent developer.**  
*For questions or collaborations, open an issue on GitHub.*
```
