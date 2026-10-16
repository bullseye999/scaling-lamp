# Phase 4 remediation and verification checkpoint

Updated: 2026-09-06

Status: **Canonical command boundary REMEDIATED & VERIFIED**, with unsupported legacy commands explicitly unavailable. This supersedes the earlier blanket sealing report. Full legacy feature parity is not claimed.

The operator explicitly authorized Codex to implement and verify these Phase 4 fixes. Changes remain local and unstaged. The next planned milestone is **Program 1, Phase 5: Epistemic Convergence**; Program 2 begins with Phase 6, Internal Governed Curiosity.

## Final verification

| Environment | Full discovery | Duration | Isolated governance matrix | Compilation |
| --- | --- | --- | --- | --- |
| `./.venv` | **320/320 PASS** | 167.973s | **16/16 PASS** | PASS |
| `./ciph_env` | **320/320 PASS** | 141.932s | **16/16 PASS** | PASS |

Both full suites exited 0 with no failures, errors, or skipped tests. Expected missing-API-key diagnostics appeared because production configuration was excluded from verification; this is not a zero-warning claim.

The 320 tests comprise 52 Gate Zero tests, 46 Phase 1 tests, 36 Phase 2 tests, 40 Phase 3 tests, 16 original Phase 4 tests, 24 new Phase 4 boundary regressions, 12 command-registry tests, and 94 other regressions. The original 296-test breakdown was arithmetically correct.

Runs used independent source-only temporary copies and databases, excluding production `.env`, keys, salts, database files, and runtime configuration. All 149 Python source files in each final copy matched workspace SHA-256 hashes at verification. A subsequent cleanup removed whitespace on one blank line in `ciph_core.py`; its AST remains identical to the tested version, and both hashes are retained in the verification summary. Compilation wrote bytecode only under temporary verification directories.

Artifacts:

- [Primary suite log](/tmp/ciph-p4-final-venv-n7sckggr/full-suite.log)
- [Second-environment suite log](/tmp/ciph-p4-final-ciph-env-46e8gtxi/full-suite.log)
- [Primary matrix](/tmp/ciph-p4-audit-venv/matrix-final.json)
- [Second-environment matrix](/tmp/ciph-p4-audit-ciph-env/matrix-final.json)
- [Verification summary and source hashes](PHASE4_VERIFICATION_RESULTS.json)
- [New boundary regressions](test_phase4_boundary_regressions.py)
- [Pre-edit snapshots](/tmp/ciph-p4-before-vvavh0mw)
- [Session source diff](/tmp/ciph-p4-changes.patch)

## Command boundary and compatibility

`CiphCore.handle_command` has no raw module dispatch tree. Supported commands use `CiphRuntime.dispatch_slash_command`; missing runtime, dispatch errors, and unsupported names stop explicitly. Slash-command response handling no longer triggers raw status scans, vault writes, or conversational memory mutations after governed execution. Core forwards explicit scope/authorization grants and retains the structured result in `last_command_result`.

The registry exposes 18 primary commands and 53 total names/aliases spanning all 16 canonical capabilities. `/help` and `/?` are presentation-only: they do not execute a capability, create a receipt, or assert a worldview claim.

The pre-edit inventory contains 204 legacy command names. Of those, 28 have registered routes and **176 are now explicitly unavailable**. These include unadapted scan, rollback, module, workflow and failsafe-mutation commands. This is an intentional compatibility reduction to remove execution bypasses. No generic raw-module adapter is retained. See [COMMAND_MIGRATION.md](COMMAND_MIGRATION.md) for the exact inventory and supported syntax.

## Remediations

1. **Production memory:** `CipherVault.store_memory/get_memory` persist authenticated encrypted JSON in a separate command-memory table. Store/retrieve survive vault and runtime restart, share actual storage, and reject corruption. Unsupported backends cannot fabricate records or claim a write occurred. `/learn` stores operator text; it does not establish its truth.
2. **Fresh invocation identity:** independent commands receive distinct full-width identities, preventing stale reads and suppressed repeated writes. A matching authentic authorization response resumes its exact pending challenge, including via aliases. The same grant replays authenticated evidence without a second execution. Challenges expire after five minutes, are bounded to 256, and require renewal after registry restart or eviction.
3. **Strict parsing:** unknown or duplicate assignments, excess positional arguments, malformed structured quoting, incomplete memory writes, and missing CVSS vectors are rejected before enqueue. Quoted team names, mixed positional/named inputs, aliases, and memory values are covered by parity tests.
4. **Scope and grants:** bounty commands require authentic kernel-signed `TARGET_DOMAIN` grants. Missing, unsigned, forged, future-dated, expired, wrong-type and policy-override grants cannot reach the handler. Outside-scope denial receipts have matching payload hashes and durable event evidence; denial-storage failure is explicit. Token lifetime is bounded by supplied grant expiry.
5. **Actual application backends:** core adapters share the application's bounty, OSINT, sports, darknet, staging, books, trading, Tor and failsafe instances. The Tor adapter supports the production `get_tor_ip` interface. Sports text, library output, staging lists and portfolio results are preserved in dialogue.
6. **Honest status and promotion:** missing staging backends and missing promotion IDs no longer report successful dry runs. Failsafe status observes the monitor thread and cannot perform a check-in under a read-only manifest. A failed write with uncertain effects retains signed pending evidence and requires reconciliation rather than publishing success.
7. **Worker exemption removed:** the hard-coded `worker_valid_01` test identity no longer bypasses worker-context authentication. Its regression now rejects the caller-asserted identity and verifies real kernel/queue/worker execution.
8. **Audit isolation:** the governance matrix explicitly isolates code promotion as well as external I/O. A regression asserts that the audit never invokes production code promotion. Matrix output records its control-flow-only verification scope.

## Limits and next step

The matrix exercises deterministic control-flow probes and retains some metadata-based gates; 16/16 is not certification of live backend behavior, compensation, universal factual truth, or OS isolation. Network/backend parity uses constrained doubles; production encrypted storage is tested directly. No live scans, model calls, market operations, destructive failsafe actions, or production code promotions were performed.

The fixes close the supported slash-command boundary. Arbitrary hostile Python/native code in the same process, broader legacy feature migration, and blueprint process/container isolation remain separate work. Natural-language cognitive paths are outside this Phase 4 command-migration assessment.

Proceed next with **Program 1, Phase 5: Epistemic Convergence**: consolidate evidence-gated worldview claims, decay/TTL behavior, contradiction and evidence links, and duplicate epistemic state paths. Do not skip directly to autonomous curiosity.
