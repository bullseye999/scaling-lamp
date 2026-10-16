> Historical report, superseded by the independent [Phase 8 remediation checkpoint](PHASE8_REMEDIATION_CHECKPOINT.md) on 2026-09-09. Its original sealing claims are preserved below for history, not current assurance.

# Program 2, Phase 8 — Milestones 8.1 & 8.2: Automated Gap Detection, Independent Benchmark Harness & Canary Deployment Pipeline

**Updated:** 2026-09-09  
**Workspace:** `ciph_project`  
**Status:** **Milestones 8.1 and 8.2 Fully Implemented and Verified Across Dual Environments (`.venv` and `ciph_env`).**

---

## Executive Summary

Phase 8 implements the complete evidence-driven self-evolution pipeline specified in the CIPH Convergence Blueprint:
$$\text{Verified Gap} \longrightarrow \text{Evaluation Grant} \longrightarrow \text{Independent Benchmark} \longrightarrow \text{Deployment Grant} \longrightarrow \text{Canary Evaluation} \longrightarrow \text{Auto-Promotion / Rollback} \longrightarrow \text{Evolution Receipt}$$

Following Milestone 8.0's bypass-sealing foundation, Milestones 8.1 and 8.2 establish:
1. **Automated Engineering Gap Detection with Operational Separation (Milestone 8.1):** Ingests execution receipts, strictly classifies operational/environmental failures away from code defects, requires $\ge 2$ distinct execution receipts demonstrating reproducible conditions, and binds operator evaluation grants.
2. **Independent Benchmark & Verification Harness (Milestone 8.2):** Nonced, disposable subprocess test runner with strict filesystem audit hooks, supervisor-controlled assertions, and latency/memory benchmarking, generating unforgeable verification evidence hashes.
3. **Canary Deployment State Machine & Crash-Resilient Rollback (Milestone 8.2):** Persistent SQLite canary tracking, immediate automatic rollback on error threshold breach or deadline expiry, automatic production promotion, and crash recovery reconciliation.

---

## Architectural Boundaries Implemented

### 1. Operational Failure Separation & Strict Defect Taxonomy
- **Operational Failures Filtered:** External network timeouts (`TARGET_UNREACHABLE`), missing credentials (`AUTH_REQUIRED`), resource exhaustion (`RESOURCE_EXHAUSTED`), security policy blocks (`POLICY_BLOCKED`), and missing sandbox tiers (`SANDBOX_UNAVAILABLE`) are classified as `FailureClassification.OPERATIONAL`. They are recorded in `ciph_operational_incidents` and **strictly forbidden** from generating `EngineeringGapCandidate` objects under `GapCategory.DEFECT`.
- **Engineering Defects:** Only repeatable unhandled exceptions (`EXECUTION_ERROR`), missing imports (`DEPENDENCY_FAILURE`), or logic errors with non-zero exit codes qualify as defects.
- **Evidence Guarantee:** An engineering gap candidate requires $\ge 2$ distinct execution receipts with unique receipt IDs and canonical payload hashes under identical input/capability conditions.
- **Telemetry & Behavior Deficits:** Clean runs (`exit_code == 0`) that fail to produce expected telemetry keys or results formulate `GapCategory.MISSING_TELEMETRY` or `GapCategory.MISSING_BEHAVIOR` candidates.
- **Durable Persistence:** All gaps persist in SQLite table `ciph_engineering_gaps` with status progression (`DETECTED` $\rightarrow$ `EVALUATION_GRANTED` $\rightarrow$ `RESOLVED` / `DISMISSED`).

### 2. Independent Supervisor Benchmark & Verification Harness
- **Zero Candidate Self-Certification:** Test execution is executed inside isolated disposable subprocesses with supervisor-controlled nonced verdict envelopes (`.supervisor_verdict.json`). Candidate stdout forgery is completely ignored.
- **Audited Filesystem Isolation:** Subprocess filesystem mutations outside the dedicated temporary directory trigger `PermissionError` via Python audit hooks.
- **Supervisor-Controlled Test Assertions:** Test fixtures, expected return values, and assertions are defined and verified by the harness; candidate code cannot alter test expectations.
- **Pre/Post Empirical Benchmark:** Measures cold-start and execution latency (ms) across iterations for both baseline and candidate, recording `delta_pct` and `latency_improvement`.
- **Cryptographic Evidence Receipt:** Successful evaluations generate an `EvolutionReceipt` (`outcome="BENCHMARK_VERIFIED"`), whose canonical payload hash serves as the required `verification_evidence_hashes` for deployment.

### 3. Canary Deployment Lifecycle, Auto-Rollback & Crash Recovery
- **Cryptographic Operator Deployment Grant:** Activation requires an `EvolutionDeploymentGrant` signed with Ed25519 by an active `KeyRole.OPERATOR`, binding the candidate hash, base file hash, verification evidence hash, permitted stages (`CANARY`, `PRODUCTION`), and `CanaryCriteria`.
- **Atomic Locking & File Replacement:** Handled via `CodeStagingManager.apply()`, acquiring `fcntl.flock(LOCK_EX)` on lockfiles, verifying the active base file hash, writing via sibling `.tmp.<uuid>` files, and issuing directory `fsync`.
- **Durable State Machine:** Tracked in SQLite table `ciph_canary_deployments` (`canary_id`, `grant_id`, `status`, `sample_size`, `samples_evaluated`, `error_threshold`, `errors_detected`, `deadline_at`).
- **Immediate Fail-Closed Auto-Rollback:**
  - If `errors_detected / samples_evaluated > error_threshold`: triggers instant rollback via `CodeStagingManager.rollback()`, verifies the active file hash matches the candidate hash to prevent clobbering newer deployments, and records an `EvolutionReceipt` (`outcome="CANARY_ROLLED_BACK"`).
  - If `now > deadline_at` and `samples_evaluated < sample_size`: triggers auto-rollback due to insufficient observation evidence.
- **Automatic Production Promotion:**
  - If `samples_evaluated >= sample_size`, `error_rate <= error_threshold`, and `grant.allow_auto_promotion == True`: automatically promotes status to `PROMOTED`, sets stage to `PRODUCTION`, and records success `EvolutionReceipt`.
- **Crash Recovery & Downtime Reconciliation:**
  - `CanaryDeploymentManager.recover_in_flight_canaries()` scans all `ACTIVE` canaries on supervisor startup.
  - If the canary's deadline expired while the supervisor was down, it triggers automatic rollback and logs downtime reconciliation.

---

## Verification Evidence

| Test Suite / Target | Environment | Results | Key Invariants Covered |
| :--- | :--- | :--- | :--- |
| **Milestone 8.1 Acceptance** ([`test_phase8_milestone_8_1_gap_detection.py`](file://ciph_project/test_phase8_milestone_8_1_gap_detection.py)) | `.venv` | **7 / 7 PASS** (0.64s) | Operational separation, distinct receipt requirement, telemetry gaps, grant binding |
| **Milestone 8.1 Acceptance** ([`test_phase8_milestone_8_1_gap_detection.py`](file://ciph_project/test_phase8_milestone_8_1_gap_detection.py)) | `ciph_env` | **7 / 7 PASS** (0.55s) | Dual-environment parity |
| **Milestone 8.2 Acceptance** ([`test_phase8_milestone_8_2_canary_pipeline.py`](file://ciph_project/test_phase8_milestone_8_2_canary_pipeline.py)) | `.venv` | **7 / 7 PASS** (2.65s) | Independent benchmark, AST safety veto, auto-rollback, auto-promotion, crash recovery |
| **Milestone 8.2 Acceptance** ([`test_phase8_milestone_8_2_canary_pipeline.py`](file://ciph_project/test_phase8_milestone_8_2_canary_pipeline.py)) | `ciph_env` | **7 / 7 PASS** (2.41s) | Dual-environment parity |
| **Milestone 8.0 Acceptance** ([`test_phase8_milestone_8_0_foundations.py`](file://ciph_project/test_phase8_milestone_8_0_foundations.py)) | `.venv` | **10 / 10 PASS** (9.69s) | Regression check on foundational invariants |
| **Core Evolution & Invariants** ([`test_ciph_evolution.py`](file://ciph_project/test_ciph_evolution.py) & [`test_ciph_hardened_invariants.py`](file://ciph_project/test_ciph_hardened_invariants.py)) | `.venv` | **20 / 20 PASS** (18.57s) | Core evolution hot-reload and invariant safety |
| **Dynamic Governance Matrix** ([`ciph_matrix_audit.py`](file://ciph_project/ciph_matrix_audit.py)) | Both | **16 / 16 GOVERNED** (100.0%) | Zero gate regressions across canonical capabilities |
| **Static Compilation** (`compileall`) | Both | **0 errors** | Clean syntax across all Python modules |
