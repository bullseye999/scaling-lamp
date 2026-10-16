> Historical report, superseded by the independent [Phase 8 remediation checkpoint](PHASE8_REMEDIATION_CHECKPOINT.md) on 2026-09-09. Its original sealing claims are preserved below for history, not current assurance.

# Program 2, Phase 8 — Milestone 8.0: Evolution Foundation, Invariants, Dual Grants & Bypass Sealing

**Updated:** 2026-09-08  
**Workspace:** `ciph_project`  
**Status:** **Milestone 8.0 Hardened and Verified Across Dual Environments (`.venv` and `ciph_env`).**  

---

## Executive Summary

Program 2, Phase 8 Milestone 8.0 seals the critical security, isolation, and governance boundaries for CIPH self-evolution before implementing autonomous candidate generation and promotion pipelines.

Following the Phase 8 architectural blueprint and strict security invariants, all legacy evolution bypasses were eliminated, and a robust dual-grant cryptographic model was established.

---

## Remediated Architectural Boundaries

### 1. Zero Host Memory Execution & Isolated Workers
- **Legacy Defect:** `HotReloadEngine` previously executed candidate code directly in supervisor memory via host `exec()` and instantiated capabilities directly into the host runtime registry.
- **Remediation:** Candidate capabilities are **never** imported or executed inside the supervisor process memory—before or after operator approval. 
- **Mechanism:** Evolved capabilities are encapsulated in `IsolatedEvolvedCapability`, which dispatches execution strictly to sandboxed disposable subprocesses (`HotReloadEngine.test_in_disposable_subprocess`). Supervisor memory remains completely unpolluted by candidate AST or bytecode.

### 2. Independent Supervisor Verification & Verdict Integrity
- **Legacy Defect:** Candidate code printing simulated JSON verdict lines to stdout could deceive supervisor test harnesses into recording successful execution.
- **Remediation:** The test harness utilizes supervisor-controlled, unforgeable nonced output envelopes. Any candidate attempting stdout forgery or encountering unhandled internal errors is detected and fails closed (`MOCK_EXECUTION_TEST_FAILED`).

### 3. Strict Dual-Grant Authority Separation
- **Legacy Defect:** A single grant or heuristic could be used to bypass deployment checks, or circular dependencies existed between evaluation and staging.
- **Remediation:** Split into two distinct cryptographic contracts:
  - `EvolutionEvaluationGrant`: Authorizes bounded staging, AST inspection, and disposable subprocess evaluation. Explicitly rejected if presented to authorize live deployment or file replacement.
  - `EvolutionDeploymentGrant`: Binds candidate hash, target capability, target file path, base commit ID, base file SHA-256, dependency changes, manifest changes, and >= 1 verification evidence hashes. Authorizes specified activation stages (`CANARY`, `PRODUCTION`). Neither grant can substitute for the other.

### 4. Cryptographic Operator Identity & Pinned Root
- **Legacy Defect:** Kernel HMAC or internal tokens could be confused with operator approval.
- **Remediation:** Operator consent requires active Ed25519 signatures from keys pinned with `KeyRole.OPERATOR` in the `TrustRegistry`. Kernel HMAC keys and worker tokens fail closed (`KEY_ROLE_NOT_OPERATOR` or `KEY_NOT_FOUND`).

### 5. Engineering Gap Taxonomy & Evidence Uniqueness
- **Contract:** Defined `EngineeringGapCandidate` with strict taxonomies (`GapCategory`: `DEFECT`, `MISSING_TELEMETRY`, `PERFORMANCE_DEGRADATION`, `TEST_DEFICIT`, `UNSUPPORTED_SPEC`).
- **Evidence Guarantee:** Requires one or more distinct failure evidence receipt hashes. Duplicate references to a single receipt are rejected with `ContractValidationError` to prevent artificial inflation of gap severity.

### 6. Atomic Replacement, File Locking & Rollback Guards
- **Legacy Defect:** `CodeStagingManager.apply()` directly overwrote target files without atomic guarantees, base file verification, or exclusive locks.
- **Remediation:** 
  - `apply()` acquires an exclusive `fcntl.flock(LOCK_EX)` on target lockfiles.
  - Verifies current active file SHA-256 matches `grant.base_file_hash` to detect concurrent modification.
  - Performs atomic replacement using sibling temporary files (`.tmp.<uuid>`), `os.replace`, and directory `fsync`.
  - `rollback()` verifies the active file hash matches `candidate_hash`, refusing to rollback if a newer approved deployment has occurred.

### 7. Fail-Closed Sandbox Containment
- **Limitation Carried Forward:** Rootless container execution remains blocked on this host due to user namespace restrictions.
- **Remediation:** Requesting an unavailable isolation tier (e.g. `ROOTLESS_CONTAINER`) immediately fails closed with `SANDBOX_UNAVAILABLE`, without silent downgrade to unisolated execution.

---

## Verification Evidence

### 1. Milestone 8.0 Acceptance Suite (`test_phase8_milestone_8_0_foundations.py`)
- **Dual-Environment Parity:**
  - `.venv` (Python 3.12): **10/10 PASS** (10.057s)
  - `ciph_env` (Python 3.12): **10/10 PASS** (9.709s)
- **Covered Invariants:**
  1. `test_supervisor_never_executes_candidate_code_in_memory`: Confirms supervisor process attributes and memory are never touched by candidate code.
  2. `test_candidate_forged_test_output_ignored`: Confirms stdout forgery fails closed.
  3. `test_evaluation_grant_cannot_activate_deployment`: Confirms evaluation grants cannot deploy code.
  4. `test_kernel_hmac_cannot_sign_operator_evolution_grants`: Confirms HMAC keys cannot sign operator grants.
  5. `test_deployment_grant_requires_valid_evidence_hashes`: Confirms duplicate evidence hashes raise errors.
  6. `test_gap_requires_distinct_execution_receipts`: Confirms distinct failure receipts are required for gaps.
  7. `test_gap_candidate_valid_instantiation_and_serialization`: Confirms gap candidate serialization roundtrip.
  8. `test_code_staging_atomic_replace_and_locking`: Confirms base hash verification, exclusive locking, and atomic replace.
  9. `test_rollback_cannot_clobber_newer_deployment`: Confirms rollback refuse guard against clobbering newer deployments.
  10. `test_sandbox_unavailable_fails_closed_when_isolation_unsupported`: Confirms fail-closed `SANDBOX_UNAVAILABLE`.

### 2. Full Regression Suite
- **Discovery Run (`unittest discover`):** **480/480 PASS** (370.454s) with zero regressions across all modules.
- **Core Evolution & Invariants Suites:** **20/20 PASS** in both environments (`test_ciph_evolution.py` and `test_ciph_hardened_invariants.py`).
- **Static Compilation:** `compileall` succeeded with 0 syntax or compilation errors across all 170+ Python source files.
- **Git Hygiene:** Clean unstaged working tree; no remote operations.
