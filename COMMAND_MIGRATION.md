# Phase 4 command migration boundary

Updated: 2026-09-08. This file describes the supported command surface after remediation.

All supported command effects use the governed runtime. The old raw dispatch tree has been removed. Missing runtime, dispatch failure, and unsupported commands stop explicitly; they never invoke a legacy handler. `/help` (alias `/?`) and `/capabilities` (alias `/self-knowledge`) are presentation-only: they render derived views from the declarative command catalog and empirical capability ledger without producing execution receipts or worldview claims. `/capabilities` supports an optional target argument to inspect a single Section 19 capability card.

## Supported commands

| Command | Capability | Aliases |
| --- | --- | --- |
| `/apply` | `code.promote_upgrade` | `/approve`, `/apply-code`, `/apply-upgrade` |
| `/book-advice` | `wisdom.consult_library` | `/ask-book` |
| `/bounty` | `cybersecurity.bounty_scan` | `/bounty-scan`, `/scan` |
| `/bounty-status` | `cybersecurity.bounty_summary` | `/bounty-programs`, `/bounties`, `/bounty-list` |
| `/capabilities` | `system.capabilities` | `/self-knowledge` |
| `/code-audit` | `code.audit_dependencies` | `/audit-deps`, `/check-deps` |
| `/cvss` | `pentest.cvss_calculate` | `/calc-cvss` |
| `/darknet-report` | `darknet.get_detailed_report` | `/detailed-darknet-scan`, `/alerts`, `/darknet-alerts` |
| `/darknet-status` | `darknet.get_status` | — |
| `/deadman` | `security.deadman_status` | `/deadmans-switch`, `/failsafe` |
| `/help` | `system.help` | `/?` |
| `/learn` | `memory.store` | — |
| `/library` | `wisdom.consult_library` | `/books` |
| `/memory` | `memory.retrieve` | `/vault`, `/mem` |
| `/osint` | `osint.find_monetizable_threats` | `/threats`, `/feed`, `/money-ops`, `/bounty-ops` |
| `/sports` | `sports.predict_match` | `/predict`, `/match`, `/predict-match` |
| `/tor` | `tor.check_status` | `/tor-status`, `/circuit` |
| `/trading` | `trading.portfolio_check` | `/portfolio`, `/trade-status`, `/portfolio-health` |
| `/upgrades` | `code.list_staged` | `/staged`, `/code` |

`/memory set KEY VALUE` selects `memory.store`; `/memory get KEY` retrieves a record. Values are encrypted and persistent in a dedicated vault table. `/learn TEXT` stores operator-supplied text with a new key; this does not establish that the text is true.

`/sports` accepts quoted team names, `HOME vs AWAY`, or `home=... away=...`. `/cvss` requires one complete vector, optionally `vector=...`. Unknown/duplicate assignments, extra positional arguments and malformed quoting are rejected. `/deadman` only inspects monitor-thread state; it does not reset, arm, or stop the failsafe.

## Authority and invocation lifecycle

`CiphCore.handle_command` and `CiphRuntime.dispatch_slash_command` accept explicit `scope_grant` and `auth_grant` arguments. Core retains structured responses in `last_command_result`. No CLI input automatically signs a grant.

Bounty commands require a signed kernel `TARGET_DOMAIN` scope grant. Missing, unsigned, forged, future-dated, expired, wrong-type, or policy-override grants are rejected before execution. Outside-scope denial receipts are signed and appended to the event store; storage errors are reported explicitly. Execution tokens cannot outlive the supplied grants.

Each new command invocation has a fresh identity. Repeating a read observes current state, and repeating a write is a new request. A privileged command returns its plan, step and parameter bindings. A matching authentic grant resumes that exact request, including through aliases. Reusing the same grant replays the authenticated result rather than executing twice. Challenges last five minutes, are bounded to 256 per registry, and must be requested again after runtime restart or eviction.

## Restored local commands (2026-09-18)

These 32 governed capabilities restore 56 legacy names and introduce `/command-status`. Every executed command produces a signed receipt; inspection claims describe local reports at OBSERVED assurance 0.40 with a 300-second ceiling. They do not certify the truth of stored text. `/help` lists their arguments and aliases.

| Command | Aliases | Behavior |
| --- | --- | --- |
| `/status` | `/project-status`, `/engine-status` | Inspect runtime uptime, job counts and curiosity pause state |
| `/modules` | `/module-status`, `/inventory` | List governed capabilities and their execution policies |
| `/jobs` | — | List the 50 most recent governed jobs |
| `/job-status` `job_id` | — | Inspect one governed job without exposing tokens or input payloads |
| `/result` `job_id` | — | Retrieve a job's cryptographically verified execution result |
| `/auth-status` | — | Inspect enrolled authority roles and status; no key material |
| `/integrity-check` | — | Verify the local event hash chain (not a security certification) |
| `/memory-stats` | `/memory-status`, `/memory-health` | Count encrypted memory records and canonical claim states |
| `/reality-check` | `/world-map` | Inspect current usable, evidenced claims |
| `/hypotheses` | — | Inspect current hypotheses and disputed claims |
| `/inspect` `claim_id` | — | Inspect a canonical claim and its current usability |
| `/memory-timeline` | `/mind-log` | Show recent canonical claim transitions |
| `/what-changed` | — | Show recent event metadata without raw payloads |
| `/curiosity-status` | `/curiosity`, `/curiousity`, `/curiousity-status` | Inspect durable internal questions, quotas and pause state |
| `/curiosity-off` `reason` | `/curiousity-off` | Pause autonomous curiosity; requires an authorization grant and reason |
| `/curiosity-on` `reason` | `/curiousity-on` | Resume curiosity eligibility without resetting quota or starting a thread |
| `/profile` | `/my-profile`, `/operator-profile` | Read stored operator profile assertions |
| `/narrative-timeline` | `/timeline` | Read stored narrative milestones |
| `/memory-graph` | `/graph` | Read stored entity relationships; these are unverified records |
| `/opsec-history` | `/opsec-trends` | Read past OPSEC telemetry; does not run a fresh network audit |
| `/bounty-scope` | `/bounty-rules` | Read stored bounty scope records; records do not confer grants |
| `/bounty-report` | — | List stored report metadata; does not generate or send reports |
| `/watchtower` | — | Read stored watchtower events without launching a monitor |
| `/blueprints` | — | Read stored blueprint records without running experimental evolution |
| `/recon-diff` `target` | — | Compare the two latest stored reconnaissance snapshots |
| `/assets` | `/asset-inventory`, `/global-assets` | Read stored reconnaissance assets and counts; records are unverified |
| `/briefing` | `/daily-brief`, `/morning-brief`, `/today` | Summarize local jobs, usable claims and curiosity state |
| `/command-status` | — | Show command coverage and deferred legacy families |
| `/alignment-check` | `/interrogation-audit` | Read stored evolution and alignment audit records |
| `/convo-summary` | — | Read stored conversation log metadata and context tags |
| `/changelog` | — | Read recorded audit changelog entries from staging |
| `/predictions` | — | Read stored match predictions without external network calls |

`/curiosity-off "reason"` and `/curiosity-on "reason"` require a bound authorization grant through the existing challenge-response API. They do not auto-sign grants. Resume keeps spent inquiry quota and unresolved attempts intact, and does not start a background thread. Experimental workflows remain deferred.

Job listings omit raw parameters, execution tokens and key material. `/result JOB_ID` explicitly retrieves authenticated result content and preserves its original outcome, including failure. Results and local record reports are bounded to 64 KiB; terminal previews are capped at 12,000 characters and disclose shortening. Record lists show at most 25 records with a truncation flag. Evidence summaries inspect at most 100 recent non-operator claims and return at most 25 matching records; they are not exhaustive inventories.

Stored profile, graph, bounty, blueprint and telemetry readers use fixed SQL columns and strict decryption. Missing tables or corrupted records produce errors. `/bounty-scope` returns historical scope records, not executable authorization grants. `/recon-diff TARGET` compares the newest two stored snapshots without a network request.

## Legacy commands still unavailable

The original inventory has 204 names: **84 now have registered routes; 120 remain unavailable**. Registration alone does not prove that an external backend is operational.

Unavailable commands return `COMMAND_UNAVAILABLE` with a specific `reason_code`. `/command-status` and [COMMAND_COVERAGE.json](COMMAND_COVERAGE.json) expose the full accounting. These names were not registered to success stubs or raw-module fallbacks.

| Command | Remaining implementation requirement |
| --- | --- |
| `/add-book` | `GOVERNED_ADAPTER_MISSING` |
| `/ai` | `GOVERNED_ADAPTER_MISSING` |
| `/arbitrage-scan` | `EXTERNAL_ADAPTER_MISSING` |
| `/operator-council` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/attack-path` | `GOVERNED_ADAPTER_MISSING` |
| `/auto-mode` | `SCHEDULER_ADAPTER_MISSING` |
| `/backup-now` | `GOVERNED_ADAPTER_MISSING` |
| `/benchmark-proposals` | `GOVERNED_ADAPTER_MISSING` |
| `/bounty-plan` | `GOVERNED_ADAPTER_MISSING` |
| `/bridge-status` | `GOVERNED_ADAPTER_MISSING` |
| `/chain-reaction` | `GOVERNED_ADAPTER_MISSING` |
| `/check-in` | `GOVERNED_ADAPTER_MISSING` |
| `/clean-footprints` | `DESTRUCTIVE_WORKFLOW_RETIRED` |
| `/clear-notifications` | `GOVERNED_ADAPTER_MISSING` |
| `/cold-start-learn` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/council` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/crypto-monitor` | `GOVERNED_ADAPTER_MISSING` |
| `/darknet-dashboard` | `EXTERNAL_ADAPTER_MISSING` |
| `/darknet-deep` | `EXTERNAL_ADAPTER_MISSING` |
| `/darknet-scan` | `EXTERNAL_ADAPTER_MISSING` |
| `/darknet-search` | `EXTERNAL_ADAPTER_MISSING` |
| `/debug-on` | `GOVERNED_ADAPTER_MISSING` |
| `/dialogue` | `GOVERNED_ADAPTER_MISSING` |
| `/emergency-wipe` | `DESTRUCTIVE_WORKFLOW_RETIRED` |
| `/evolution` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/evolution-dash` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/evolution-dashboard` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/evolution-log` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/execute-plan` | `GOVERNED_ADAPTER_MISSING` |
| `/fetch` | `EXTERNAL_ADAPTER_MISSING` |
| `/fix-all-modules` | `CODE_LIFECYCLE_ADAPTER_MISSING` |
| `/ghost-history` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/ghost-mode` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/ghost-rating` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/ghost-score` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/hit-list` | `GOVERNED_ADAPTER_MISSING` |
| `/load` | `CODE_LIFECYCLE_ADAPTER_MISSING` |
| `/lock` | `GOVERNED_ADAPTER_MISSING` |
| `/market-data` | `EXTERNAL_ADAPTER_MISSING` |
| `/market-trends` | `EXTERNAL_ADAPTER_MISSING` |
| `/mind-metrics` | `GOVERNED_ADAPTER_MISSING` |
| `/model-status` | `EXTERNAL_ADAPTER_MISSING` |
| `/monetize-plan` | `GOVERNED_ADAPTER_MISSING` |
| `/money-plan` | `GOVERNED_ADAPTER_MISSING` |
| `/monitor-id` | `EXTERNAL_ADAPTER_MISSING` |
| `/network-discovery` | `EXTERNAL_ADAPTER_MISSING` |
| `/new-identity` | `EXTERNAL_ADAPTER_MISSING` |
| `/next-step` | `GOVERNED_ADAPTER_MISSING` |
| `/notifications` | `GOVERNED_ADAPTER_MISSING` |
| `/opsec` | `GOVERNED_ADAPTER_MISSING` |
| `/opsec-audit` | `GOVERNED_ADAPTER_MISSING` |
| `/osint-status` | `GOVERNED_ADAPTER_MISSING` |
| `/ping-model` | `EXTERNAL_ADAPTER_MISSING` |
| `/ping-runpod` | `EXTERNAL_ADAPTER_MISSING` |
| `/ponder` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/port-scan` | `EXTERNAL_ADAPTER_MISSING` |
| `/profile-clear` | `GOVERNED_ADAPTER_MISSING` |
| `/read-file` | `GOVERNED_ADAPTER_MISSING` |
| `/reanalyze-blueprints` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/red-team` | `GOVERNED_ADAPTER_MISSING` |
| `/reject` | `CODE_LIFECYCLE_ADAPTER_MISSING` |
| `/reject-upgrade` | `CODE_LIFECYCLE_ADAPTER_MISSING` |
| `/rejection-stats` | `GOVERNED_ADAPTER_MISSING` |
| `/retroactive-learn` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/review` | `CODE_LIFECYCLE_ADAPTER_MISSING` |
| `/review-code` | `CODE_LIFECYCLE_ADAPTER_MISSING` |
| `/rollback` | `CODE_LIFECYCLE_ADAPTER_MISSING` |
| `/router` | `GOVERNED_ADAPTER_MISSING` |
| `/router-status` | `GOVERNED_ADAPTER_MISSING` |
| `/runpod-test` | `EXTERNAL_ADAPTER_MISSING` |
| `/scan-project` | `EXTERNAL_ADAPTER_MISSING` |
| `/schedule-start` | `SCHEDULER_ADAPTER_MISSING` |
| `/schedule-status` | `SCHEDULER_ADAPTER_MISSING` |
| `/schedule-stop` | `SCHEDULER_ADAPTER_MISSING` |
| `/schedule-update` | `SCHEDULER_ADAPTER_MISSING` |
| `/search` | `GOVERNED_ADAPTER_MISSING` |
| `/search-in-files` | `GOVERNED_ADAPTER_MISSING` |
| `/security-audit` | `GOVERNED_ADAPTER_MISSING` |
| `/security-scan` | `EXTERNAL_ADAPTER_MISSING` |
| `/self-analyze` | `EXPERIMENTAL_WORK_DEFERRED` |
| `/self-audit` | `GOVERNED_ADAPTER_MISSING` |
| `/self-report` | `GOVERNED_ADAPTER_MISSING` |
| `/send-report` | `SCHEDULER_ADAPTER_MISSING` |
| `/sentry` | `GOVERNED_ADAPTER_MISSING` |
| `/set-football-api` | `SECRET_CONFIGURATION_RETIRED` |
| `/set-odds-api` | `SECRET_CONFIGURATION_RETIRED` |
| `/set-passphrase` | `SECRET_CONFIGURATION_RETIRED` |
| `/setkey` | `SECRET_CONFIGURATION_RETIRED` |
| `/setup-email` | `SECRET_CONFIGURATION_RETIRED` |
| `/show-workflow-log` | `SCHEDULER_ADAPTER_MISSING` |
| `/sports-mode` | `EXTERNAL_ADAPTER_MISSING` |
| `/sports-stats` | `EXTERNAL_ADAPTER_MISSING` |
| `/ssl-scan` | `EXTERNAL_ADAPTER_MISSING` |
| `/start-daily-reports` | `SCHEDULER_ADAPTER_MISSING` |
| `/start-workflow` | `SCHEDULER_ADAPTER_MISSING` |
| `/stop-all-workflows` | `SCHEDULER_ADAPTER_MISSING` |
| `/stop-daily-reports` | `SCHEDULER_ADAPTER_MISSING` |
| `/stop-workflow` | `SCHEDULER_ADAPTER_MISSING` |
| `/switch-model` | `EXTERNAL_ADAPTER_MISSING` |
| `/sync-reality` | `GOVERNED_ADAPTER_MISSING` |
| `/tag` | `GOVERNED_ADAPTER_MISSING` |
| `/talk-test` | `GOVERNED_ADAPTER_MISSING` |
| `/test-command` | `GOVERNED_ADAPTER_MISSING` |
| `/test-deepseek` | `EXTERNAL_ADAPTER_MISSING` |
| `/test-model` | `EXTERNAL_ADAPTER_MISSING` |
| `/test-runpod` | `EXTERNAL_ADAPTER_MISSING` |
| `/testrunpod` | `EXTERNAL_ADAPTER_MISSING` |
| `/top-targets` | `GOVERNED_ADAPTER_MISSING` |
| `/topology` | `GOVERNED_ADAPTER_MISSING` |
| `/tor-check` | `EXTERNAL_ADAPTER_MISSING` |
| `/trading-signals` | `EXTERNAL_ADAPTER_MISSING` |
| `/unload` | `CODE_LIFECYCLE_ADAPTER_MISSING` |
| `/war-room` | `GOVERNED_ADAPTER_MISSING` |
| `/watch` | `GOVERNED_ADAPTER_MISSING` |
| `/watchtower-check` | `GOVERNED_ADAPTER_MISSING` |
| `/wealth-strategy` | `GOVERNED_ADAPTER_MISSING` |
| `/web-scan` | `EXTERNAL_ADAPTER_MISSING` |
| `/workflow-status` | `SCHEDULER_ADAPTER_MISSING` |
| `/world-brief` | `GOVERNED_ADAPTER_MISSING` |
| `/zeroize-mind` | `DESTRUCTIVE_WORKFLOW_RETIRED` |

## Verification limits

Parity tests cover parser forms, aliases, production encrypted storage across restart, and supported backend interfaces. External services are replaced with constrained test doubles; no live scans, market operations, model calls, destructive failsafe operations or production code promotions are part of verification. The 16-capability matrix runs in deterministic isolated mode and does not prove live backend behavior or OS isolation.

See [COMMAND_RESTORATION_REPORT.md](COMMAND_RESTORATION_REPORT.md) for current restoration verification. Historical Phase 4 evidence remains in [PHASE4_REMEDIATION_CHECKPOINT.md](PHASE4_REMEDIATION_CHECKPOINT.md) for measured final verification and [CIPH_CONVERGENCE_BLUEPRINT.md](CIPH_CONVERGENCE_BLUEPRINT.md) for Program 1, Phase 5: Epistemic Convergence.
