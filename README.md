<div align="center">

# ⚫️ CIPH 3.0
### Sovereign Autonomous Intelligence & Security Reconnaissance Platform

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tor](https://img.shields.io/badge/Network-Tor%20SOCKS5h-7D4698?style=flat-square&logo=tor-project&logoColor=white)](https://torproject.org)
[![Storage](https://img.shields.io/badge/Storage-AES--256%20%7C%20WAL%20SQLite-00599C?style=flat-square)](https://sqlite.org)
[![Intelligence](https://img.shields.io/badge/Engine-DeepSeek%20V4%20Pro-412991?style=flat-square)](https://api.deepseek.com)
[![CVSS](https://img.shields.io/badge/Standard-CVSS%20v3.1-critical?style=flat-square)](https://www.first.org/cvss/)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)

<p align="center">
  <a href="#-what-is-ciph-30">Architecture</a> •
  <a href="#-core-operational-modules">Core Modules</a> •
  <a href="#-installation--quickstart">Quickstart</a> •
  <a href="#-interactive-cli--dialogue-examples">CLI & Demos</a> •
  <a href="#-system-architecture-map">System Map</a> •
  <a href="#-security--opsec-guarantees">OPSEC</a>
</p>

</div>

---

## 🧠 What is CIPH 3.0?

**CIPH 3.0** is an autonomous, sovereign intelligence operative built for local execution, darknet telemetry, bug bounty reconnaissance, and strategic scenario simulation.

Unlike conventional AI wrappers, CIPH is directly wired to its host operating system, persistent encrypted databases, and an isolated SOCKS5h Tor transport layer. It operates under a strict **Fail-Closed** security architecture with zero third-party telemetry, local AES-256 encrypted vaults, and autonomous tool-dispatching capabilities that eliminate the need for rigid slash commands.

---

## ⚡ Key Capabilities at a Glance

* **🛡️ Fail-Closed Ghost Transport**: Persistent Tor SOCKS5h session pooling (`127.0.0.1:9050`), anti-fingerprint headers, timing jitter, and DoH remote DNS resolution over Tor (zero local ISP resolver leaks).
* **🎯 Elite Bug Bounty Suite v3**: Multi-source passive subdomain discovery cascade (AlienVault, Wayback CDX, crt.sh), automated dangling CNAME subdomain takeover detection across 10+ cloud providers, GraphQL `__schema` introspection auditing, and Single Page Application (SPA) baseline calibration to eradicate soft-404 false positives.
* **🤖 Autonomous Action Agent**: Natural-language tool dispatcher. Translates conversational intent into multi-step recon and intelligence workflows behind the scenes, synthesizing findings without raw command clutter.
* **⚔️ Adversarial War Room**: 3-perspective strategic stress-testing (*The Hunter* / Red Team, *The Stoic* / Blue Team Risk, *The Arbiter* / CIPH Strategic Synthesis).
* **🗄️ Sovereign Hardened Vault**: Local SQLite database running in high-concurrency `WAL` mode with 5-second busy timeout locks, encrypted configuration tables, historical recon snapshot diffing, and watchtower event tracking.
* **📊 Deterministic CVSS v3.1 Engine**: Mathematical FIRST.org vector scoring and automatic HackerOne-ready vulnerability report generation.
* **⚽ 5-Layer Sports Intelligence**: Multi-factor probabilistic prediction engine (Poisson distribution + xG modeling + market odds variance + live sports context + LLM reasoning).

---

## 🛠️ Core Operational Modules

| Module | Component File | Description |
| :--- | :--- | :--- |
| **Transport Layer** | `ghost_transport.py` | SOCKS5h Tor session pool with remote DNS resolution and strict fail-closed enforcement. |
| **Bounty Suite** | `bounty_hunter.py` | Automated recon, takeover signatures, GraphQL auditing, and historical URL parameter mining. |
| **Scoring Engine** | `cvss_calculator.py` | Standalone mathematical calculation of CVSS v3.1 base score and vector metrics. |
| **Cognitive Router** | `ciph_router.py` | Direct integration with DeepSeek V4 Pro API with custom temperature and reasoning pipelines. |
| **Action Dispatcher**| `ciph_autonomous_agent.py` | Conversational action dispatcher that triggers back-end recon tools dynamically. |
| **War Room** | `war_room.py` | Multi-lens adversarial stress-testing and strategic scenario simulation. |
| **OSINT Catalog** | `osint_catalog.py` | Anti-fragile threat intelligence directory with 3-tier self-healing failover. |
| **Encrypted Vault** | `cipher_vault.py` | AES-256 SQLite storage with WAL journal mode, recon snapshots, and telemetry history. |
| **Fast AST Router** | `query_router.py` | Deterministic factual and AST math parser that completely bypasses LLM latency. |
| **Personality Mask**| `personality_engine.py` | Context sanitizer that protects technical code blocks, inline code, and JSON objects from formatting alterations. |

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
Edit `.env` with your preferred API keys:
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

## 📸 Interactive CLI & Dialogue Examples

### 1. System Boot & Autonomous Initialization
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

### 2. Autonomous Recon & Bug Bounty Audit
Communicate naturally with CIPH—the autonomous agent parses your intent, triggers the recon engine over Tor, and returns prioritized findings without command overhead.

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

### 3. Automated CVSS v3.1 Report Generation
Generate deterministic, professional vulnerability disclosure reports directly into `bounty_reports/`:

```text
Operator: /bounty-report target.com

[BountyHunter] Generating submission report for target.com...
[CVSSCalculator] Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
[CVSSCalculator] Base Score: 9.1 [CRITICAL]
✅ Report generated: bounty_reports/report_target.com_20260823.md
```

### 4. Adversarial War Room Simulation
Stress-test strategies or operational moves through 3 opposing analytical lenses:

```text
Operator: /war-room "Responsible disclosure of GraphQL exposure on major fintech platform"

[WarRoom] Running 3-perspective adversarial stress test via DeepSeek V4 Pro...

🔴 THE HUNTER (RED TEAM / ADVERSARIAL LENS):
- Platform triage may classify introspection as informative unless sensitive query paths are mapped.
- Disclosure timing must ensure zero exposure to public search scrapers during remediation.

🔵 THE STOIC (BLUE TEAM / RISK AUDIT):
- Scope boundary check required: Confirm if api.target.com is explicitly listed in program policy.
- Ensure proof-of-concept remains strictly read-only to prevent policy invalidation.

⚖️ THE ARBITER (CIPH STRATEGIC SYNTHESIS):
- 1. Provide exact remediation steps (disabling introspection in production config).
- 2. Reference FIRST.org CVSS vector for deterministic severity alignment.
- 3. Maintain secure communication channels exclusively through the coordinated disclosure program.
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
        ├── war_room.py ────────────► 3-Perspective Adversarial Stress Tester
        ├── osint_catalog.py ───────► Multi-Tier Failover Threat Intelligence
        ├── cipher_vault.py ────────► High-Concurrency WAL SQLite & Recon Diffs
        └── query_router.py ────────► Deterministic AST Math (LLM-Bypass)
```

---

## 🛡️ Security & OPSEC Guarantees

1. **Zero Clearnet Leakage**: `GhostTransport` uses SOCKS5h connection pooling. Requests strictly fail-closed if the Tor circuit drops; no clearnet fallbacks are permitted.
2. **Leak-Proof Remote DNS**: Hostnames are resolved through DNS-over-HTTPS (DoH) over the Tor circuit, preventing local OS DNS queries from leaking to your ISP.
3. **Local Encryption**: All conversation logs, system states, and configuration tokens are encrypted with AES-256 before storage in SQLite `WAL` databases.
4. **Code & Payload Masking**: `personality_engine.py` isolates fenced code blocks, inline code, and JSON dictionaries before applying conversational formatting, preventing corruption of technical payloads.

---

## 🧪 Running Verification Tests

To verify vault encryption, AST math evaluation, Tor headers, and scope enforcement:

```bash
python3 test_auth.py
```

```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.150s

OK
```

---

## 📄 License & Responsible Use

Distributed under the **MIT License**.

> **Notice**: CIPH is designed for authorized security research, educational purposes, and bug bounty programs operating within explicit scope rules. Users are strictly responsible for adhering to applicable laws and program guidelines.
