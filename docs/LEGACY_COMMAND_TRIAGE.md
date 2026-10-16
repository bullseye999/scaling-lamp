# Legacy Command Triage & Restoration Plan

Date: 2026-09-18 · Reviewer: Codex

## Current state (after Batch 2)

- Legacy names inventoried: **204**
- Governed (registered) legacy names: **84**
- Unavailable legacy names: **120**

Breakdown by reason code:

| Reason | Count | Meaning |
| --- | ---: | --- |
| `GOVERNED_ADAPTER_MISSING` | 47 | Feature exists in code, no reviewed governed adapter yet — the restorable pool |
| `EXTERNAL_ADAPTER_MISSING` | 29 | Needs a real per-source sandbox/broker adapter (network policy, isolation) |
| `EXPERIMENTAL_WORK_DEFERRED` | 15 | Deferred batch — now unblocked (Phase 9 ends Program 2) but needs design, not wiring |
| `SCHEDULER_ADAPTER_MISSING` | 13 | Needs durable scheduling + per-action authorization |
| `CODE_LIFECYCLE_ADAPTER_MISSING` | 8 | Needs the bounded artifact adapter |
| `SECRET_CONFIGURATION_RETIRED` | 5 | Retired by design — do not restore |
| `DESTRUCTIVE_WORKFLOW_RETIRED` | 3 | Retired by design — do not restore |

## Restoration method (repeatable, one command at a time)

1. Confirm a real backing store exists (vault table, file, or runtime state). No backing store → do not restore.
2. Add a `LocalCommand` spec and, for vault reads, a `RECORDS` entry (fixed SELECT list, no credential columns).
3. Run `test_command_restoration.py` — it automatically requires a verifiable receipt, an `OBSERVED` claim, the local-record display, and rejection of stray arguments.
4. Regenerate `COMMAND_COVERAGE.json` via `command_retirement.coverage()`.
5. Document the command in `COMMAND_MIGRATION.md`.

## Batch 1 — complete (asset family)

| Command | Backing store | Evidence |
| --- | --- | --- |
| `/assets` (aliases `/asset-inventory`, `/global-assets`) | `recon_snapshots` | 24/24 restoration suite; 612/612 full sweep in both interpreters; coverage moved 76 → 79 registered |

The pre-existing guard test was preserved: asset inspection must never be classified as
`SECRET_CONFIGURATION_RETIRED`, and it now additionally asserts the command is governed.

## Batch 2 — complete (read-only inspections with verified stores)

| Command | Backing store | Evidence |
| --- | --- | --- |
| `/alignment-check` (alias `/interrogation-audit`) | `evolution_audit_log` | 25/25 restoration suite in dual interpreters; decodes audit alignment score and agenda |
| `/convo-summary` | `conversations` | 25/25 restoration suite; metadata-only inspection (id, timestamp, tag) protecting prompt secrets |
| `/changelog` | `ciph_changelog.json` | 25/25 restoration suite; reads bounded staging changelog records safely |
| `/predictions` | `ciph_predictions/*.json` | 25/25 restoration suite; inspects local match prediction records without external network |

### Batch 2 Candidate Verification Dispositions

- `/mind-metrics`: Store verification negative (no table, file, or runtime state exists). **Do not restore**.
- `/rejection-stats`: Store verification negative (`proposal_history.json` missing). **Do not restore**.
- `/benchmark-proposals`: Evaluator requires evaluation grant and isolated runner (`EVALUATION_GRANT_REQUIRED`). Reclassified under code lifecycle.
- `/self-audit`: Requires active execution in isolated runner, not a static offline snapshot. Retained as unavailable.
- `/router-status`: Direct router to external DeepSeek API (`https://api.deepseek.com/v1`). Retained under external adapter.
- `/bridge-status`: Belongs to experimental `evolution_bridge.py` blueprint scavenger prohibited by Blueprint §18.1.
- `/osint-status`: Already covered by canonical `osint.find_monetizable_threats` (`/osint`).
- `/top-targets`: Already covered by `/assets` and `/recon-diff`.
- `/notifications` + `/clear-notifications`: Volatile in-memory list on `CiphCore`, not durable SQLite. Mutation requires authorization grant.

## Explicitly out of scope for restoration

- **8 retired by design** (5 credential, 3 destructive) — restoring them would undo a security decision.
- **29 external** — per-source sandbox/broker adapters are subsystem projects, each with its own
  network policy, isolation tier and adversarial review.
- **13 scheduler** — requires durable scheduling plus per-action authorization before any command exists.
- **8 code lifecycle** — requires the bounded artifact adapter.
- **15 experimental** — unblocked by Program 2 completion, but each needs a scoped design and review
  (see `DEFERRED_COMPONENT_REVIEW.md`); a command restore would be the wrong shape.

## Guard

A command is restored only when a governed implementation exists behind it. The reason codes
exist precisely so that naming a command never substitutes for building it.
