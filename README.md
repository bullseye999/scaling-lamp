<div align="center">

# CIPH 4.0
### Operator-Governed Security Research, Intelligence & Cognitive Automation Runtime

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-621%20Passing-success?style=flat-square)](#testing)
[![Governance](https://img.shields.io/badge/Governance%20Matrix-16%2F16%20Compliant-success?style=flat-square)](ciph_matrix_audit.py)
[![License](https://img.shields.io/badge/License-MIT-black?style=flat-square)](LICENSE)

</div>

---

## What is CIPH

CIPH is an open-source, operator-governed runtime for security research, threat intelligence, encrypted memory, code introspection, and decision analytics. It has two layers:

- **The CIPH 4.0 governing layer** (`ciph/`): typed capability manifests, deterministic execution lanes, authorization grants, signed execution tokens, a durable job queue, worker daemons, Ed25519-signed receipts, an append-only event store, a materialized worldview, an empirical capability ledger, and governed self-knowledge. Every execution is authorized, receipted and verifiable; unverified history confers no credit.
- **The interactive core** (`ciph_core.py`): the operator-facing conversation and command surface, wired into the governing layer as a composition root.

Core principle: the system never claims a capability because its prompt or manifest mentions it. "What can you do?" is answered from verified execution history.

## Governed pipeline

Every action follows one path:

`typed intent -> validated plan -> scope/policy gates -> signed execution token -> durable queue -> isolated worker -> signed receipt -> atomic event commit -> evidence projection`

Failed and policy-blocked actions also produce receipts. LLM output is never evidence.

## Architecture

| Package | Responsibility |
| :--- | :--- |
| `ciph.contracts` | Immutable, versioned typed contracts: grants, plans, receipts, observations, claims |
| `ciph.capabilities` | Capability manifests, governed registry, command registry, empirical capability ledger |
| `ciph.kernel` | Cryptographic identity, policy engine, scope enforcement, network sandbox, epistemic projector |
| `ciph.workers` | Durable job queue, worker daemons, activation evidence, signed receipts |
| `ciph.memory` | Append-only event store, claim leases, materialized worldview, active forgetting |
| `ciph.planner` | Intent parsing and execution DAG planning |
| `ciph.perception` | Governed curiosity, durable question store, untrusted external observations |
| `ciph.evolution` | Engineering gap detection, isolated execution, benchmarks, canary deployment, promotion/rollback |
| `ciph.maintenance` | Shared exclusion protocol and the idle maintenance engine |
| `ciph.operator` | Dialogue formatting with explicit epistemic registers |

Additional packages exist (`ciph.crucible`, `ciph.federation`, `ciph.sovereignty`, `ciph.swarm`, `ciph.silicon`, `ciph.zk`) as **experimental, not-enabled** primitives. They are not advertised as working capabilities and are not part of the governed surface.

## Installation

Automated bootstrap:

```bash
./setup_ciph.sh
```

Manual:

```bash
python3 -m venv ciph_env
source ciph_env/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your own keys; never commit .env
```

## Testing

Run the full suite from the repository root:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

Current verified state:

| Check | Result |
| :--- | :--- |
| Full discovery (58 suites) | 621/621 passing |
| Dynamic governance matrix | 16/16 compliant |

```bash
python3 ciph_matrix_audit.py
```

Tests are isolated: they use temporary databases and directories, and they do not require network access, API keys, or external services.

## Command surface

All slash commands route through the governed registry. Commands without a governed implementation return `COMMAND_UNAVAILABLE` with a reason code — never a raw fallback. The supported command catalog and per-command status is the authoritative reference in `COMMAND_MIGRATION.md`.

## Security notes

This repository is the public surface of a larger system. It contains no credentials, private keys, personal memory, databases, logs, or target reports. Local test runs may create temporary artifacts (`*.db`, `*.log`, `__pycache__`) next to the code; those are gitignored and safe to delete.

## License

MIT — see `LICENSE`.
