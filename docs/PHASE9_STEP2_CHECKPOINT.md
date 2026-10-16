# Phase 9, Step 2 Checkpoint: Idle Maintenance Engine & Shared Exclusion Protocol

### Idle Maintenance Engine, Shared Exclusion Protocol & SQLite Interceptor Hardening
- **Milestone:** Phase 9, Step 2
- **Date:** 2026-09-18
- **Workspace:** `ciph_project`
- **Dual Interpreters:** `./.venv/bin/python3` and `ciph_project/ciph_env/bin/python3`
- **Status:** **REMEDIATED & FULLY RATIFIED/VERIFIED (199/199 PASS DUAL-INTERPRETER, 16/16 COMPLIANT, 0 FILES STAGED)**

---

## 1. Architectural Summary & Scope

Phase 9 Step 2 upgrades the legacy unauthenticated `MaintenanceLeaseManager` into a production-grade, cryptographically verified **Shared Exclusion Protocol & Idle Maintenance Engine**.

### 1.1 Remediation of Review Blockers & Hardening

1. **Blocker 1: Eradication of Destructive Evidence Deletion (Section 17 Invariant):**
   - Removed `_task4_ephemeral_token_cleanup` entirely.
   - Strictly prohibited any DELETE operations on `ciph_consumed_tokens` or `ciph_authorization_grants`.
   - Preserves all historical activation statement verification tokens in `SnapshotActivationVerifier`, preventing health demotion of `VERIFIED_ACTIVE` capabilities to `HISTORICAL_ONLY`.
   - Verified via Probe 10 (`test_probe10_maintenance_never_erases_raw_evidence`).

2. **Blocker 2: Full Realization of Blueprint v4 §7 Task Pipeline:**
   - **Task 1: Event-Chain Integrity (`TASK1_EVENT_INTEGRITY`):** Directly walks the cryptographic hash chain from genesis in `ciph_event_store`. Row streaming refactored in `ciph/memory/event_store.py:verify_integrity` to stream row-by-row (`for row in cursor:`) instead of `cursor.fetchall()`, guaranteeing bounded memory consumption.
   - **Task 2: Hardened Scavenger (`TASK2_HARDENED_SCAVENGER`):** Scavenges expired IPC job leases via `IPCJobQueue.reclaim_expired_leases(calling_holder_id=self.operator_key_id)` and expired claim locks via `ClaimLeaseManager.cleanup_expired_leases(calling_holder_id=self.operator_key_id)`.
   - **Task 3: Safe Database Maintenance (`TASK3_SAFE_DB_MAINTENANCE`):** Executes routine non-blocking `PRAGMA wal_checkpoint(PASSIVE);` followed by `PRAGMA optimize;`.
   - **Task 4: Capability Ledger Cache Compilation (`TASK4_LEDGER_CACHE_COMPILATION`):** Compiles empirical capability profiles and ledger checkpoint using `CapabilityLedger(self.event_store, registry=self.registry, ...).compile_empirical_ledger()`. Dynamically synthesizes `StaticDependencyInspector.check_declared_modules` evidence across `self.registry.list_manifests()`, outputting `dependency_blind: False` and enabling proven capabilities to attain `VERIFIED_ACTIVE`. Stores immutable `(profiles, checkpoint)` in memory (`self.compiled_ledger_cache`).
   - **Task 5: Worldview Stale Hypothesis Expiry (`TASK5_STALE_HYPOTHESIS_EXPIRY`):** Scans `ciph_active_claims` for claims where `lifecycle_state = 'ACTIVE'`, `state NOT IN ('REFUTED', 'SUPERSEDED', 'STALE')`, and `freshness_deadline IS NOT NULL AND freshness_deadline <= ?`. Transitions them cleanly to `state = 'STALE'` without refutation. Fails closed on database errors.
   - **Task 6: Static AST Dependency Audit (`TASK6_STATIC_AST_AUDIT`):** Statically audits registered capability classes and module source codes via `HotReloadEngine.audit_code_safety()` without importing untrusted code. Extracts AST import dependencies and reports safety diagnostics.

3. **Engine Hardening & Runtime Wiring:**
   - **Transient Heartbeat Recovery:** `run_cycle()` unconditionally resets `self._heartbeat_failed = False` per cycle. Transient renewal failures abort the active cycle with `ABORTED_LEASE_LOST`, while subsequent cycles recover cleanly on the same engine instance.
   - **Runtime Wiring & Accessors:** `CiphRuntime` initializes `self.idle_maintenance_engine` bound to its operator credentials, trust registry, and capability registry. Exposes `runtime.run_idle_maintenance()`, `runtime.check_and_run_maintenance_if_idle()`, and `runtime.get_cached_capability_ledger()`.
   - **Task Timeout Watchdog Safety:** Each maintenance task executes under a thread join watchdog enforcing `task_timeout_seconds`. If a task hangs, `timed_out = True` suppresses premature lease release in `finally`, allowing the lease to expire safely by TTL rather than racing external writers.
   - **Fail-Closed Quiescence & Storage Errors:** Replaced `except OperationalError: pass` in quiescence checks and lease acquisition with explicit fail-closed checks (`if "no such table" not in str(ex): return False, STORAGE_ERROR`).
   - **Fail-Closed Operator Authority:** `SharedExclusionCoordinator._verify_operator_authority` raises `PermissionError("MAINTENANCE_TRUST_REGISTRY_REQUIRED: ...")` when `trust_registry` is not configured.
   - **SQLite Authorizer Coverage:** Intercepts `PRAGMA wal_checkpoint` and `VACUUM` queries to deny unauthorized non-holders from triggering checkpoints or compaction during maintenance.

---

## 2. Component Implementation Details

### 2.1 Shared Exclusion Protocol (`ciph/maintenance/exclusion.py`)
- **Exclusive Lease Table (`ciph_maintenance_leases`):** Idempotently migrated to 8 columns: `lease_name`, `holder_id`, `acquired_at`, `expires_at`, `cycle_id`, `task_name`, `heartbeat_at`, `holder_signature`.
- **Atomic CAS Acquisition:** Executes under `BEGIN IMMEDIATE` with clock sampled strictly after write lock acquisition.
- **Ed25519 Authority Verification:** Signs domain-separated canonical statement `CIPH_MAINTENANCE_LEASE_V1:{lease_name}:{holder_id}:{cycle_id}:{acquired_at}:{expires_at}`. Requires `KeyRole.OPERATOR`.
- **Connection Proxies (`ExcludedConnection`, `ExcludedCursor`):** Transparently permits SELECT reads while intercepting all write commands (`INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `CREATE`, `DROP`, `ALTER`, `VACUUM`, `PRAGMA WAL_CHECKPOINT`) via command parser and SQLite-level authorizer (`set_authorizer`).

### 2.2 Idle Maintenance Engine (`ciph/maintenance/engine.py`)
- **`IdleDetector`:** Evaluates 5 durable SQLite quiescence criteria:
  1. `ciph_ipc_jobs`: zero active jobs (`QUEUED`, `EXECUTING`, or unexpired `LEASED`).
  2. `ciph_curiosity_questions`: zero questions with `status == 'SEARCHING'`.
  3. `ciph_curiosity_attempts`: zero attempts with `status == 'RESERVED'`.
  4. `ciph_phase8_canary_state`: zero active canaries with `in_flight IS NOT NULL`.
  5. Quiescence window: $\ge 10.0\text{s}$ elapsed since last completed job or event (`COALESCE` handles empty history).
- **`IdleMaintenanceEngine`:** Sequentially executes Tasks 1–6 within a 120s budget, renews lease every 10s (TTL 30s) via background Ed25519 signed heartbeat thread, and emits lifecycle audit events:
  - `MaintenanceCycleStartedEvent`
  - `MaintenanceTaskExecutedEvent`
  - `MaintenanceCycleCompletedEvent`

---

## 3. Empirical Verification Evidence (Dual-Interpreter)

### 3.1 Phase 9 Test Suite (62 Tests)
- `test_phase9_capability_ledger.py` (22 tests)
- `test_phase9_review4_remediation.py` (27 tests)
- `test_phase9_step2_idle_maintenance.py` (13 tests)

| Environment | Interpreter Path | Command | Results |
|---|---|---|---|
| Workspace `.venv` | `./.venv/bin/python3` | `python3 -m unittest test_phase9_capability_ledger.py test_phase9_review4_remediation.py test_phase9_step2_idle_maintenance.py` | **62/62 PASS** (58.713s) |
| Project `ciph_env` | `ciph_project/ciph_env/bin/python3` | `python3 -m unittest test_phase9_capability_ledger.py test_phase9_review4_remediation.py test_phase9_step2_idle_maintenance.py` | **62/62 PASS** (53.910s) |

### 3.2 Phase 3 Adversarial Recovery Suite (30 Tests)
- `test_phase3_adversarial_recovery.py` (30 tests)

| Environment | Interpreter Path | Command | Results |
|---|---|---|---|
| Workspace `.venv` | `./.venv/bin/python3` | `python3 -m unittest test_phase3_adversarial_recovery.py` | **30/30 PASS** (32.227s) |
| Project `ciph_env` | `ciph_project/ciph_env/bin/python3` | `python3 -m unittest test_phase3_adversarial_recovery.py` | **30/30 PASS** (27.704s) |

### 3.3 Full Baseline Regression Suites (107 Tests)
- `test_gate0_remediation_exploits`
- `test_phase1_canonical_contracts`
- `test_ciph_evolution`
- `test_phase2_reference_loop`
- `test_phase8_complete_workflow`

| Environment | Interpreter Path | Command | Results |
|---|---|---|---|
| Workspace `.venv` | `./.venv/bin/python3` | `python3 -m unittest test_gate0_remediation_exploits test_phase1_canonical_contracts test_ciph_evolution test_phase2_reference_loop test_phase8_complete_workflow` | **107/107 PASS** (101.839s) |
| Project `ciph_env` | `ciph_project/ciph_env/bin/python3` | `python3 -m unittest test_gate0_remediation_exploits test_phase1_canonical_contracts test_ciph_evolution test_phase2_reference_loop test_phase8_complete_workflow` | **107/107 PASS** (92.725s) |

### 3.4 Total Active Test Count
$$\mathbf{62 \text{ (Phase 9)} + 30 \text{ (Phase 3)} + 107 \text{ (Baseline Regressions)} = 199 \text{ Active Tests Evaluated across Dual Interpreters}}$$
Zero regressions detected. 100% pass rate.

### 3.5 Dynamic Penetration Governance Matrix
- Script: `ciph_matrix_audit.py`
- Result in `.venv`: **16/16 Canonical Capabilities Fully Governed (100.0% COMPLIANT)**
- Result in `ciph_env`: **16/16 Canonical Capabilities Fully Governed (100.0% COMPLIANT)**

### 3.6 Git Hygiene
- Staging verification: `git diff --cached` $\to$ **0 files staged** (strictly clean).

---

## 4. Adversarial Probes in `test_phase9_step2_idle_maintenance.py`

| Probe # | Target Invariant | Expected & Verified Outcome |
|---|---|---|
| **Probe 1** | Schema Migration Idempotency | Legacy 4-column `ciph_maintenance_leases` migrates to 8 columns; existing data preserved. |
| **Probe 2** | Authority Model & Role Enforcement | WORKER key and unenrolled keys rejected with `PermissionError`; OPERATOR key succeeds. |
| **Probe 3** | Canary In-Flight Bi-Directional Blocker | Active canary blocks maintenance acquisition; active maintenance blocks canary activation & execution. |
| **Probe 4** | Curiosity Searching Blocker | `SEARCHING` questions or `RESERVED` curiosity attempts block maintenance acquisition. |
| **Probe 5** | Idle-to-Acquire CAS Race | Concurrently enqueued jobs inside `BEGIN IMMEDIATE` transaction abort lease acquisition. |
| **Probe 6** | Write-Only Interception & Reader Freedom | Reads unhindered; unauthorized in-process and cross-process writes fail closed. |
| **Probe 7** | Engine Holder Exemption | Active maintenance holder successfully writes lifecycle events to `ciph_event_store`. |
| **Probe 8** | Crash Recovery & TTL Expiry | Dead holder's lease expires automatically by TTL; queue writers resume without manual intervention. |
| **Probe 9** | Full Spec Tasks 1–6 Execution | Executes all 6 spec tasks: verifies event chain, scavenges leases, PASSIVE checkpoint, compiles ledger cache, marks expired claim `STALE`, and audits capability AST. |
| **Probe 10** | Non-Destruction of Raw Evidence | Maintenance strictly preserves `ciph_consumed_tokens` and `ciph_authorization_grants`; verifies ledger compiles with consumed tokens intact. |
| **Probe 11** | Heartbeat Failure / Abort & Recovery | Mid-cycle heartbeat failure aborts with `ABORTED_LEASE_LOST`; transient failure resets and subsequent cycle completes cleanly on same instance. |
| **Probe 12** | Missing TrustRegistry Fails Closed | Coordinator without trust registry raises `PermissionError(MAINTENANCE_TRUST_REGISTRY_REQUIRED)`. |
| **Probe 13** | CiphRuntime Maintenance Wiring & Ledger Cache | Runtime executes maintenance, automatically generates dependency evidence for registered capabilities, and compiles non-dependency-blind `VERIFIED_ACTIVE` profiles into memory cache. |

---

## 5. Artifacts and Source Manifest

### Modified Files:
- [`ciph/memory/event_store.py`](file://ciph_project/ciph/memory/event_store.py): Refactored `verify_integrity()` from `cursor.fetchall()` to streaming `for row in cursor:`.
- [`ciph/capabilities/capability_ledger.py`](file://ciph_project/ciph/capabilities/capability_ledger.py): Retired `MaintenanceLeaseManager` compatibility wrapper; added backward compatible `"empirically_verified_capabilities"` key to `generate_self_knowledge_report()`.
- [`ciph/maintenance/exclusion.py`](file://ciph_project/ciph/maintenance/exclusion.py): Fail-closed TrustRegistry requirement; PRAGMA and VACUUM authorizer and statement protection; fail-closed quiescence checks.
- [`ciph/maintenance/engine.py`](file://ciph_project/ciph/maintenance/engine.py): Strict Tasks 1–6 pipeline matching Blueprint v4 §7; removed destructive token deletion; per-cycle reset of heartbeat failure flag for transient recovery; dynamic synthesis of `StaticDependencyInspector` evidence in Task 4; fail-closed quiescence and operational error handling; thread watchdog lease retention on timeout.
- [`ciph/runtime.py`](file://ciph_project/ciph/runtime.py): Wired `self.idle_maintenance_engine = IdleMaintenanceEngine(...)` bound to operator identity and capability registry; added `run_idle_maintenance()`, `check_and_run_maintenance_if_idle()`, and `get_cached_capability_ledger()`.
- [`test_phase9_step2_idle_maintenance.py`](file://ciph_project/test_phase9_step2_idle_maintenance.py): 13 comprehensive adversarial probes covering two-cycle heartbeat recovery, runtime maintenance wiring, empirical ledger caching, cross-process write protection, and raw evidence immutability.
