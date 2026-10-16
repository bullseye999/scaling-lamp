> Superseded on 2026-09-08 by [the Phase 7 implementation and verification checkpoint](PHASE7_REMEDIATION_CHECKPOINT.md). Earlier sealing claims below are historical; current host-dependent acceptance gates are recorded in the new checkpoint.

# Program 2, Phase 7 — Milestone 7.0: External Evidence & Multi-Tier Sandboxing Feasibility Gate

Updated: 2026-09-07

Status: **Milestone 7.0 Hardened and Verified Across All Environments (All 7 Review Findings Remediated).**

Verification uses isolated SQLite databases and disposable canaries. No secrets or production credentials were used. The Four-Gate Verification Matrix is satisfied with zero regression across all 422 test cases.

---

## Executive Summary

Phase 7 Milestone 7.0 establishes the feasibility gate and containment boundary for collecting external evidence. Following a comprehensive architectural review, seven implementation findings were remediated:
1. **Genuine Containment (Finding 1)**: Removed `force_fs_isolation_probe` override entirely from production code; implemented unprivileged Linux Landlock LSM ruleset enforcing genuine kernel-level filesystem isolation (`PermissionError: [Errno 13]`) on unprivileged Ubuntu 24.04 hosts without root or subuid mappings.
2. **Safe Pre-Execution Denial for Missing Adapters (Finding 2)**: Eliminated the substitute JSON echo command. Capabilities requiring sandboxing without a `get_sandbox_command` adapter fail closed before launch (`SANDBOX_UNAVAILABLE: SANDBOX_ADAPTER_MISSING`), recording a supervisor-signed `SandboxDeniedEvent` and minting exactly zero `ExecutionReceipt` records.
3. **Robust Handshake-Based Probe Verification (Finding 3)**: Eliminated false `PASS` vulnerabilities on probe crashes. Probes require explicit structured JSON status handshakes (`LAUNCHER_OK`, `CONTAINED`, `BLOCKED`, `RESOURCE_OK`, `CLEANUP_OK`). Abnormal process termination reports `FAIL` or `NOT_TESTED` and `UNAVAILABLE`.
4. **Second Launch Refusal Ingress (Finding 4)**: Launch refusals inside `execute_isolated()` emit a supervisor-signed `SandboxDeniedEvent`, mark the job `FAILED`, and mint zero `ExecutionReceipt` records.
5. **Strict Output Ceilings on Stdout & Stderr (Finding 5)**: Concurrent streaming readers bound both stdout and stderr under `policy.max_output_bytes`. A 64KB stream is terminated immediately at the ceiling with `OUTPUT_FLOOD`. Unhandled `setrlimit` exceptions are propagated by `apply_rlimits()`, and `RLIMIT_NPROC` bounds child process count.
6. **Active Descendant Verification & Uncertain Recovery (Finding 6)**: Actively verifies process tree death via `os.killpg(pgid, 0)`. Surviving processes trigger `cleaned_up=False` with `UNCERTAIN_CLEANUP`, and `IPCJobQueue.mark_job_uncertain()` records `RECONCILIATION_REQUIRED` and `JobReconciliationRequiredEvent`.
7. **Ratified Kernel Policy for Sandboxing (Finding 7)**: Ratified `is_sandboxed_execution_required()` in the policy engine, automatically enforcing Tier 2 sandboxing for external network policies or non-internal code origin without manual opt-in. Kept supervisor signing keys outside child execution contexts.

---

### The Four-Gate Verification Matrix

| Gate | Name | Requirement | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Gate A** | **Safe Refusal (Restricted Host & Admission Denial)** | Exact launch probe, 3-state structured diagnostics (`PASS`, `FAIL`, `NOT_TESTED`), handshake-validated probes, pre-execution fail-closed on unavailable containment or missing adapter, supervisor-signed denial event in EventStore, zero `ExecutionReceipt` minted. | `test_gate_a_*` (6 tests pass). Authoritative probe validates all 5 checks. Launcher failure marks subsequent checks `NOT_TESTED`. Probe crash reports `FAIL`/`NOT_TESTED` without false `PASS`. Unavailable containment, missing adapter, or runtime launch refusal each emit signed `SandboxDeniedEvent`, fail job, and produce exactly 0 receipts. |
| **Gate B** | **Working Containment (Controls)** | Positive control reads declared input, writes to scratch, returns bounded JSON. Negative control for filesystem verified via Landlock LSM (outside canary access raises `PermissionError`). Negative control for network verifies `OFFLINE_ONLY` blocks outbound connections. | `test_gate_b_*` (3 tests pass). Permitted task reads input and writes isolated scratch with clean exit 0. Child reading undeclared canary outside allowed paths is denied by Landlock LSM (`PermissionError: [Errno 13]`). Outbound socket connect fails (`OSError`). |
| **Gate C** | **Secret & Descriptor Isolation** | Parent secrets in `os.environ` and open host file descriptors withheld from sandboxed child. Signing keys (`worker_secret_key`) and `trust_registry` remain outside child with supervisor. Kernel policy auto-mandates sandboxing. | `test_gate_c_*` (3 tests pass). Child verifies zero `CIPH_*` env vars and inaccessible parent open FD. Child receives only sanitized input payload; supervisor signs receipt and verifies via `TrustRegistry`. Policy engine auto-enforces sandboxing for external network or non-internal origin. |
| **Gate D** | **Lifecycle & Resource Containment** | Rogue descendant calling `os.setsid()` and ignoring `SIGTERM` reaped by PID namespace lifecycle. Streaming output flood on stdout/stderr terminated at limit (`OUTPUT_FLOOD`). Timeout terminated (`TIMEOUT`). `setrlimit` failure propagates exceptions. Known nonzero exit produces authenticated failure receipt; uncertain cleanup marks `RECONCILIATION_REQUIRED`. | `test_gate_d_*` (7 tests pass). Rogue `setsid()` grandchild confirmed dead on host via `pgrep`. Infinite stdout and 64KB stderr terminated at ceiling with `OUTPUT_FLOOD`. 10s sleep killed at 1.0s timeout. `apply_rlimits` propagates exceptions on `PermissionError`. Exit code 42 produces signed `EXECUTION_ERROR` receipt. Surviving process records `UNCERTAIN_CLEANUP` and marks `RECONCILIATION_REQUIRED`. |

---

## Architectural Implementation

### 1. `ciph/kernel/sandbox/base.py`
- Diagnostic State enum: `PASS`, `FAIL`, `NOT_TESTED`.
- Termination Reasons: `SUCCESS`, `TIMEOUT`, `OUTPUT_FLOOD`, `MEMORY_EXCEEDED`, `CPU_EXCEEDED`, `UNCERTAIN_CLEANUP`, `PERMISSION_DENIED`, `LAUNCHER_FAILURE`, `SANDBOX_UNAVAILABLE`, `EXIT_ERROR`.
- Models: `DiagnosticCheck`, `SandboxDiagnostics`, `SandboxPolicy` (`allowed_read_paths`, `allowed_write_paths`, `max_input_bytes`), `SandboxResult`.
- Exception: `SandboxUnavailableError`.

### 2. `ciph/kernel/sandbox/launcher.py`
- Single-threaded unprivileged child launcher avoiding Python `preexec_fn` thread-safety bugs.
- Applies `resource.setrlimit` (`RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NPROC`) and strictly propagates exceptions on failure.
- Implements Linux Landlock LSM ruleset via `ctypes` syscalls (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`), establishing kernel-enforced filesystem read/write containment without requiring root or user namespaces.

### 3. `ciph/kernel/sandbox/runner.py`
- `OfflineSandboxRunner`:
  - `probe_containment()`: Authoritative 5-check probe (`launcher_status`, `filesystem_isolation`, `network_isolation`, `resource_enforcement`, `descendant_cleanup`) requiring verified JSON handshakes. Zero false passes on probe crash.
  - `execute_isolated()`: Ephemeral scratch directory, cleansed environment allowlist (`PATH`, `LANG`, `LC_ALL`, `CIPH_SANDBOX_ID`), asynchronous bounded stdin streaming, concurrent output readers bounding both stdout and stderr under `max_output_bytes` (killing floods immediately), and active process tree verification (`os.killpg(pgid, 0)`).

### 4. `ciph/workers/ipc_queue.py`
- `fail_job_containment_denied(job_id, worker_id, error, denial_payload)`:
  - Atomically marks `status = 'FAILED'`, clears lease, and appends `SandboxDeniedEvent` into `ciph_event_store` inside a single SQLite `BEGIN IMMEDIATE` transaction boundary.
  - Guarantees zero `ExecutionReceipt` is minted or stored on pre-execution denial.
- `mark_job_uncertain(job_id, worker_id, reason, receipt_dict)`:
  - Atomically marks `status = 'RECONCILIATION_REQUIRED'`, clears lease, and appends `JobReconciliationRequiredEvent` into `ciph_event_store`.

### 5. `ciph/workers/daemon.py`
- Enforces ratified kernel policy `is_sandboxed_execution_required()`.
- Refuses execution with `SANDBOX_ADAPTER_MISSING` if `get_sandbox_command` is missing (no substitute commands).
- Catches runtime launch refusals from `execute_isolated()`, emitting signed `SandboxDeniedEvent` and producing 0 receipts.
- Catches `UNCERTAIN_CLEANUP`, immediately marking job `RECONCILIATION_REQUIRED`.
- Withholds supervisor signing keys from sandboxed child execution contexts.

### 6. `ciph/kernel/policy_engine.py`
- `is_sandboxed_execution_required(capability, manifest, cap_instance, scope_grant, execution_token, code_origin)`:
  - Ratified rule enforcing mandatory sandboxing for external network policies (`TOR_MANDATORY`, `DIRECT_APPROVED`), non-internal code origins (`external`, `untrusted`), or explicit sandbox requests, exempting recognized in-process audit and test fixtures.

---

## Test Verification Summary

| Suite / Audit | Tests / Checks | Duration | Result |
| :--- | :--- | :--- | :--- |
| `test_phase7_sandbox_feasibility.py` | 19 / 19 | 27.7s | **100% PASS** |
| `test_phase6_internal_curiosity.py` | 35 / 35 | 37.8s | **100% PASS** |
| `test_phase4_boundary_regressions.py` | 24 / 24 | 23.2s | **100% PASS** |
| `test_phase4_command_strangler.py` | 16 / 16 | 14.3s | **100% PASS** |
| `test_phase3_adversarial_recovery.py` | 30 / 30 | 31.4s | **100% PASS** |
| `ciph_matrix_audit.py` | 16 / 16 Capabilities | 3.5s | **100.0% COMPLIANT** |
| `test_ciph_project_suite.py` | 25 / 25 Commands | 4.1s | **100% PASS** |
| Full discovery (`.venv`) | 422 / 422 | 325.5s | **100% PASS** |
| Full discovery (`ciph_env`) | 422 / 422 | 263.8s | **100% PASS** |
