# Phase 8 — Independent audit and hardening

Date: 2026-09-09. Scope: local `ciph_project` only.

## What this audit established

The earlier “fully sealed” report overstated the implementation. Two disposable pre-fix probes reproduced a candidate changing the benchmark verdict to success and `CodeStagingManager.apply()` changing a target without an evolution grant. Their results are retained in `verification/phase8/before_fix_probe_results.json`.

The repaired path is:

1. Authenticate terminal worker receipts against enrolled keys, the immutable event stream, and their persisted jobs.
2. Group repeatable failures by capability, inputs, revision, environment, target, and failure class. Operational failures produce durable `NO_RELEVANCE_FOUND` evidence instead of engineering defects.
3. Require a separate, signed, single-use evaluation grant bound to the candidate, baseline, gap, isolation tier, and resource budget.
4. Execute candidate and baseline through the actual Phase 7 OS sandbox. Only source and declared runtime libraries enter the child. Expected answers and signing authority remain in the supervisor.
5. Compare returned data against supervisor-owned assertions. Sign and persist the benchmark evidence, including the exact test suite and measured elapsed times.
6. Require a deployment grant bound to that verification evidence. Run canary samples in isolation while leaving the production file unchanged.
7. Count authenticated, independently checked canary observations. Refuse caller-supplied success flags. Stop on failed criteria, expiry, withdrawn artifacts, or revoked authority.
8. When production is explicitly authorized and the canary passes, preserve the exact baseline in a durable checkpoint and replace the target atomically. Recover uncertain transitions without overwriting a newer revision.

## Bugs fixed

- **Evaluation was not OS-isolated.** Replaced plain subprocess/audit-hook evaluation with `OfflineSandboxRunner` or the explicitly requested `RootlessContainerRunner`. Required containment failures have no fallback.
- **Candidate-controlled verdicts.** Removed the child-owned verdict file/nonce as verification authority. Candidate JSON is data; the parent owns assertions and signs evidence.
- **Grantless file application and legacy activation.** `apply()` requires verified deployment and canary evidence. HMAC execution grants no longer authorize code activation. Direct hot reload and legacy skill-promotion shortcuts refuse activation.
- **Additional legacy execution routes.** Staging no longer launches import benchmarks. `CiphBenchmark.measure_import_speed()` and the old disposable-test shortcuts require the governed replacement. Dependency inspection cannot fall back to importing candidate-selected packages.
- **Unbound or replayable evidence.** Reject unsigned, uncommitted, tampered, or job-mismatched receipts. Persist failure deduplication across restarts. Revalidate group membership instead of trusting an unsigned index. Deduplicate telemetry gap evidence and check that fields really are absent.
- **Approval and budget validation.** Require pinned operator authority, valid roles, finite grant lifetimes, valid hashes, explicit production permission, and finite positive resource limits. Fixed an immutable-budget validation bug exposed by full discovery.
- **Hidden interface/manifest changes.** Require a single named candidate class and preserve named public signatures. Unsupported manifest and dependency migrations are refused.
- **Canary self-certification.** Actual isolated execution plus the approved test oracle supplies observations. Success booleans, invented evidence references, reused grants, and unknown test inputs cannot produce accepted samples.
- **Crash and rollback misreporting.** Keep uncertain execution in `RECONCILIATION_REQUIRED`. Sandbox refusal records denial, not an execution observation. Failed rollback remains unresolved. Recovery handles an interrupted file replacement even after the canary deadline.
- **Unsafe backup selection and file races.** Preserve exact bytes and permissions in a grant-bound checkpoint. Use no-follow directory/file access, a cooperative exclusive lock, a sibling temporary file, file and directory fsync, and atomic replacement. Rollback rejects modified checkpoints and newer target revisions.
- **Operator withdrawal and staging identity.** Rejected artifacts cannot start or continue canary work. Staging preserves candidate bytes exactly; successful application updates the artifact status.

## Verification scope and limitations

The supported evolution path is deliberately bounded to **offline, read-only capability candidates with explicit test cases**. The canary exercises these cases in isolated workers; it is not a certification of arbitrary live workloads, side-effecting capabilities, or unrestricted self-modification.

- Elapsed-time benchmarks include process launch and containment overhead. Memory limits are enforced; memory-performance improvement is not measured or claimed.
- Nonempty dependency/manifest migration requests and custom canary comparison/rollback policies are refused until their semantics are implemented. An unsupported request does not silently become an approved no-op.
- Rootless-container availability is a separate host capability. Passing the disposable-process tests does not establish that the container tier is available.
- The legacy hot-reload/skill-promotion interfaces intentionally refuse direct activation. Use `EngineeringGapDetector`, `IndependentBenchmarkHarness`, and `CanaryDeploymentManager` for the governed path. This audit does not introduce an autonomous scheduler for evolving arbitrary modules.
- Filesystem replacement and SQLite cannot form one native transaction. A signed PREPARED checkpoint makes the interruption recoverable. The cooperative lock does not claim to prevent a privileged unrelated process from editing the same file.
- A signed benchmark proves what the trusted harness checked. Its finite test suite is not a mathematical proof of correctness, and assurance ceilings are not calibrated probabilities.

## Verification artifacts

Final discovery passed against identical source-only copies in both environments.

| Environment | Full discovery | Duration |
|---|---|---|
| venv | 522/522 PASS | 428.885s |
| ciph-env | 522/522 PASS | 379.066s |

This includes all **52 Phase 8 tests**. The canonical governance matrix passed **16/16 in both environments**; static compilation passed for **182 Python files**. No tests were skipped. Detailed machine-readable results are in `PHASE8_VERIFICATION_RESULTS.json`; raw logs, exact source hashes, and before-fix probes are under `verification/phase8/`.

The original 24 Phase 8 tests were replaced with 39 authenticated acceptance tests, and 13 additional adversarial regressions were added. Existing legacy evolution tests were updated to assert refusal of the retired HMAC activation paths. Thus this is a revised security contract, not a claim that insecure legacy activation behavior remains compatible. A development run caught 24 errors from immutable budget handling; after correction, the intermediate 519-test run and final 522-test run both passed in both environments.

Testing uses source-only disposable directories with test databases and identities. No real project key or vault content is copied into candidate sandboxes. Existing work remains local and unstaged.
