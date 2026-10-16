# Command restoration verification

Verified 20260908T165212Z. Restored **48 formerly unavailable legacy names** (aliases included), implemented as **27 explicit local capabilities**, and added `/command-status`. The original 204-name inventory now has **76 registered names and 128 still unavailable**. This is a verified local-command restoration, not full legacy feature parity.

## What works now

- Runtime and capability inspection: `/status`, `/project-status`, `/engine-status`, `/modules`, `/module-status`, `/inventory`, `/auth-status`, `/integrity-check`.
- Governed job inspection: `/jobs`, `/job-status JOB_ID`, `/result JOB_ID`. Result lookup authenticates the receipt, payload, job, input binding, signature and attempt number; failed execution remains a failed original outcome.
- Evidence and memory inspection: `/memory-stats`, `/memory-status`, `/memory-health`, `/reality-check`, `/world-map`, `/hypotheses`, `/inspect CLAIM_ID`, `/memory-timeline`, `/mind-log`, `/what-changed`.
- Curiosity status and controls: `/curiosity-status` and existing spelling aliases; `/curiosity-off "reason"` and `/curiosity-on "reason"` use the existing bound authorization challenge. Pause survives restart. Resume retains spent quota and unresolved attempts, and does not start a background thread.
- Stored records: `/profile` and aliases, `/narrative-timeline`, `/timeline`, `/memory-graph`, `/graph`, `/opsec-history`, `/opsec-trends`, `/bounty-scope`, `/bounty-rules`, `/bounty-report`, `/watchtower`, `/blueprints`, `/recon-diff TARGET`.
- Local briefings: `/briefing`, `/daily-brief`, `/morning-brief`, `/today`.

Every execution follows the existing governed worker/receipt/admission path. Inspection reports are OBSERVED at assurance 0.40, with evidence-anchored freshness capped at 300 seconds. Reading stored assertions never promotes them to external truth. Stored scopes do not confer execution grants. Experimental engines are not activated by reading their stored records.

Job metadata excludes input payloads, execution tokens and signing keys. Record readers use fixed column lists, bound SQL parameters and strict decryption. Missing schemas and corrupt ciphertext fail explicitly instead of returning healthy-looking empty data. Reports are capped at 64 KiB; terminal previews escape control characters and disclose shortening beyond 12,000 characters. Record lists have a 25-row limit and truncation flag. Evidence summaries consider 100 recent non-operator claims and show at most 25; these are bounded views, not exhaustive inventories.

## Bugs caught and fixed

- Memory statistics initially used the blueprint column name instead of the actual canonical schema column; corrected to `state` and read command-memory counts from the bound vault.
- Disputed claims were being omitted by active-only querying; hypothesis inspection now includes them without making them usable premises.
- Generic retirement classification incorrectly matched `set-` inside `/asset-inventory`; credential-command matching now uses exact names/prefixes.
- Result lookup now rejects receipts from a different attempt or mismatched stored worker signature.
- The canonical matrix accidentally expanded from 16 to 43 capabilities after registration. It now uses the explicit canonical set, rejects missing canonical capabilities, lists the other 27 separately, and exits nonzero on failed compliance. Its existing 16-capability assertions were retained.

## Verification

| Check | .venv | ciph_env |
| --- | --- | --- |
| Full discovery on final code | 470/470 PASS (331.534s) | 470/470 PASS (286.740s) |
| Restoration + matrix regression tests | 27/27 PASS | 27/27 PASS |
| Canonical governance matrix | 16/16 compliant | 16/16 compliant |
| Existing command audit | 25/25 PASS | 25/25 PASS |

All 169 Python sources parse, and their contents match the tested snapshot. The 27 focused checks contain 24 command-restoration tests and 3 matrix tests. Initial full runs found the three audit-scope failures described above; the table records the reruns after correction. Fixture audits also test expected refusals; 25 passing audit cases do not mean 25 live external backends were exercised.

Tests ran in source-only temporary workspaces with disposable databases and keys. No live scans, trades, messages or code promotions were performed. This verification does not remove Phase 7's separately documented host/container limitations.

## Remaining work

**128 names are still unavailable.** They include missing external adapters, legacy schedulers/workflows, code lifecycle and filesystem operations, destructive/configuration interfaces, and deferred experimental work. They have explicit `reason_code` diagnostics and were not registered to fake-success stubs. Some registered original network commands can still refuse execution when their real backend lacks the required sandbox adapter.

Use [COMMAND_MIGRATION.md](COMMAND_MIGRATION.md) for arguments, aliases and the remaining list, and [COMMAND_COVERAGE.json](COMMAND_COVERAGE.json) for exact accounting. Machine-readable results and source hashes are in [COMMAND_RESTORATION_RESULTS.json](COMMAND_RESTORATION_RESULTS.json); logs are under `verification/command-restoration/20260908T165212Z`.

No changes were staged or committed.
