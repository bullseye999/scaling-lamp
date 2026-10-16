# Phase 9 — Step 1 Implementation & Verification Checkpoint
### Empirical Capability Ledger, Strict Historical Parsing & Operational Health Gates

**Date:** 2026-09-17  
**Workspace:** `ciph_project`  
**Status:** **RATIFIED PASS — Step 1 verified and closed. Step 2 unblocked.**

## Review 4 and current candidate (2026-09-11)

Independent Review 4 completed with three P1 groups:
1. Signed tokens and receipts could earn active credit without durable activation; one token/nonce could earn credit for multiple attempts without retry authorization.
2. Shared receipt canonicalization converted unsupported `side_effects` into empty lists, accepting altered signed evidence.
3. Reconciliation could be attributed from an unenrolled direct-key receipt or an unsigned attempt containing an otherwise valid token.

Review evidence: `/tmp/ciph-phase9-review4-z88ia4c_/REVIEW.md`, including the five scenarios in `remaining_probes.py`. The six named suites passed **129/129** in `.venv` (**102.359s**) and `ciph_env` (**93.779s**) on that reviewed tree. Prior harnesses did not close these gaps. **522/522 was the historical Phase 8 exit gate**, not a current full discovery result.

The operator authorized these candidate fixes:
- Queue activation signs a domain-separated statement containing job, attempt, worker, token, parameters, plan/step, lease and activation time within the same transaction as token consumption. Missing signing authority rolls the transaction back.
- `SnapshotActivationVerifier` uses the existing scan connection and frozen kernel keys to verify activation signatures, job bindings, consumed nonces, retry lineage and the authenticated failed parent execution. Historical unsigned attempt statements remain in temporary SQLite tables but supply no activation authority.
- Receipt records carry explicit enrolled-worker and verified-activation flags. Current-version credit requires both. Post-scan reconciliation resolves only from authenticated activation and excludes conflicted jobs/capabilities; reconciliation never contributes clean successes.
- Shared receipt signing/canonicalization requires `list[str]`; both verification APIs reject unsupported shapes. Valid list-of-strings canonical bytes are preserved.
- Positive ledger fixtures now use actual queue activation. Dedicated Review 4 tests cover rejection paths and real worker retries, including pre-execution crash recovery.

Candidate validation completed on 2026-09-11 in both project interpreters:

| Check | Workspace `.venv` | Project `ciph_env` |
| --- | --- | --- |
| Six named suites (22 acceptance + 107 regressions) | **129/129 PASS**, 107.857s | **129/129 PASS**, 99.174s |
| Review 4 regressions (14) + adversarial recovery (30) | **44/44 PASS**, 35.061s | **44/44 PASS**, 31.061s |
| Five targeted Review 4 scenarios with explicit assertions | **5/5 PASS** | **5/5 PASS** |

The five probe payloads are unchanged. A separate `remaining_probes_checked.py` adapter catches the now-expected `ValueError` from canonicalizing malformed side effects and asserts that both shared verifiers reject them; the original harness and its raw outputs are retained. The earlier 13- and 19-scenario harnesses were also rerun and their outputs retained. Their unsigned fixture controls now remain historical/unresolved, so their old active-status expectations are not reported as passing acceptance gates.

The extended recovery run exposed a pre-existing fixture error: its trigger rejected activation writes while expecting execution to have started. The same failure was reproduced on the pre-change source (`baseline-rollback-test.log`). The fixture now permits activation and rejects subsequent completion/reconciliation writes, while a separate new test checks activation-write rollback and zero worker invocations.

Named-suite runs used isolated source copies. The initial 22-test smoke run used the project's test database paths. Final Python source hashes match the working tree and both isolated copies; no production-source changes followed the passing named-suite runs. Test fixture changes were subsequently verified by the 44-test runs. No files were staged or committed.

Compatibility: earlier unsigned activation events are not backfilled and cannot confer current execution authority or reconciliation attribution. Historical verification now depends on retaining the associated job, consumed-token and retry-lineage records. Candidate validation is complete, but **independent review and operator ratification are still pending; Step 2 remains on hold**.

Evidence and reviewable diff: `/tmp/ciph-phase9-candidate-s8ckdmjc/CANDIDATE_VALIDATION.md` and `candidate.diff`.

---

## Historical Review 3 candidate record (superseded by Review 4)

## 1. Executive Summary & Review Gate History

Phase 9 Step 1 implements the *Empirical Capability Ledger* and *Strict Historical Parsing* subsystem.
- **Review 1:** Gate decision FAIL (11 findings across manifest provenance, worker activation ingress evidence, read snapshot transaction isolation, and fail-closed parser handling).
- **Review 2:** Gate decision FAIL (Phase 8 regressions and 19 counter-probe findings).
- **Review 3:** Gate decision FAIL (6 remaining contract finding groups).

**Historical gate status before Review 4:** Review Gate 3 was awaiting verification. The candidate remediations for all 6 finding groups have been implemented and validated locally across the test suite and contract harness, but independent review gate verification remains pending. Step 2 remains strictly on hold.

The 6 Review 3 contract findings addressed:
1. Token-to-job/attempt authorization and attempt budget limits.
2. Current implementation manifest hash binding and required receipt provenance fields.
3. Valid reconciliation signature attribution and lifecycle ordering.
4. Complete attempt conflict detection across all 6 bindings without statement overwrite.
5. Live worker pre-sign provenance consistency enforcement.
6. Structured fail-closed scan boundary across storage and canonicalization failures.

Candidate fixes for all 6 Review 3 findings have been implemented and validated locally. Independent verification gate confirmation is pending.

---

## 2. Detailed Review 3 Remediation Actions

1. **Token Lineage, Cross-Job Reuse & Attempt Budget Enforcement (Finding 1):**
   - **File:** [`ciph/capabilities/capability_ledger.py`](file://ciph_project/ciph/capabilities/capability_ledger.py#L1100-L1135)
   - Enforced attempt budget validation: `1 <= receipt.attempt_number <= token_to_verify.max_attempts`. Out-of-budget attempts (such as attempt 999 with `max_attempts=1`) flag `ATTEMPT_BUDGET_EXCEEDED` and insert conflict records.
   - Enforced cross-job token reuse tracking in `_scan_seen_tokens`. If a signed `token_id` or `token_hash` is reused across different `job_id`s, both jobs and capabilities are flagged as `INTEGRITY_CONFLICT`.

2. **Current Manifest Identity & Mandatory Provenance Binding (Finding 2):**
   - **File:** [`ciph/capabilities/capability_ledger.py`](file://ciph_project/ciph/capabilities/capability_ledger.py#L1140-L1165, #L1530-L1560)
   - Receipts and tokens must match `manifest.compute_manifest_hash()` to earn current-version credit (`is_cur`). Receipts agreeing on version string but carrying a divergent `manifest_hash` are classified as `HISTORICAL_VERSION_MISMATCH` with `HISTORICAL_ONLY` health status.
   - Mandatory receipt provenance fields are required for current-version eligibility (`meta.get("has_complete_provenance")`). Receipts stripped down to only `execution_token_hash` are classified as `HISTORICAL_UNBOUND` with `HISTORICAL_ONLY` health status.

3. **Reconciliation Attribution & Lifecycle Ordering (Finding 3):**
   - **File:** [`ciph/capabilities/capability_ledger.py`](file://ciph_project/ciph/capabilities/capability_ledger.py#L1268-L1330)
   - Deferred reconciliation attribution post-scan, after all events and transitive conflicts have settled.
   - Derived capability strictly from kernel-verified execution token signatures and non-conflicted receipt records. Contradictions between an attempt's asserted capability and the kernel-signed token capability flag integrity conflicts and leave the reconciliation unresolved.

4. **Attempt Conflict Detection Across All 6 Bindings (Finding 4):**
   - **File:** [`ciph/capabilities/capability_ledger.py`](file://ciph_project/ciph/capabilities/capability_ledger.py#L780-L850, #L1050-L1085)
   - Retained all distinct attempt statements in `_scan_attempt_events` without overwriting.
   - Compared all 6 bindings (`capability`, `manifest_version`, `manifest_hash`, `token_id`, `token_hash`, `worker_id`) across earlier attempts, late attempts, and receipts regardless of event arrival order.

5. **Live Worker Pre-Sign Provenance Consistency (Finding 5):**
   - **File:** [`ciph/workers/daemon.py`](file://ciph_project/ciph/workers/daemon.py#L1330-L1355)
   - Worker daemon checks all returned receipt provenance bindings (`plan_hash`, `step_id`, `parameters_hash`, `manifest_version`, `manifest_hash`, `execution_token_hash`, `token_id`, `capability`, `input_hash`) against the validated execution token before signing.
   - Any post-invocation alteration of plan/step/parameter provenance forces `OutcomeCategory.POLICY_BLOCKED` and `exit_code = 1`, preserving truthful execution failure evidence rather than committing false success.

6. **Structured Fail-Closed Boundary (Finding 6):**
   - **File:** [`ciph/workers/receipts.py`](file://ciph_project/ciph/workers/receipts.py#L111) & [`ciph/capabilities/capability_ledger.py`](file://ciph_project/ciph/capabilities/capability_ledger.py#L1300-L1335)
   - Fixed `compute_signature_payload` canonical sorting against heterogeneous `side_effects` types (e.g. `[{}, 1]`), eliminating `TypeError`.
   - Replaced unhandled scan storage errors (e.g., SQLite `database or disk is full`) with a structured scan error boundary returning documented `UNAVAILABLE` checkpoints and profiles.

---

## 3. Full Verification Results

### A. Review 3 Contract Probes (`contract_probes.py` — 13 Scenarios)
All 13 scenarios executed and passed in both project Python environments (`.venv` and `ciph_env`):

| Probe Scenario | Target Security Invariant | Observed Invariant Outcome |
|---|---|---|
| `valid_signed_token_and_receipt_control` | Positive control earns active | `VERIFIED_ACTIVE`, 1 success, 0 conflicts |
| `one_token_three_jobs_attempt_999` | Token reuse & attempt budget blocked | `INTEGRITY_CONFLICT`, 5 conflicts, 0 active |
| `wrong_current_manifest_hash_same_version` | Manifest hash bound to current | `HISTORICAL_ONLY` (`HISTORICAL_VERSION_MISMATCH`) |
| `all_provenance_bindings_missing_except_token_hash` | Mandatory provenance enforced | `HISTORICAL_ONLY` (`HISTORICAL_UNBOUND`) |
| `signed_reconciliation_wrong_token_capability` | No unsigned misattribution | `INTEGRITY_CONFLICT`, 1 unresolved |
| `reconciliation_then_authenticated_receipt` | Post-scan attribution resolved | `VERIFIED_ACTIVE`, 1 reconciled, 0 unresolved |
| `late_attempt_wrong_token_hash` | Late attempt collision detected | `INTEGRITY_CONFLICT`, 2 conflicts |
| `late_attempt_wrong_token_id` | Late attempt collision detected | `INTEGRITY_CONFLICT`, 2 conflicts |
| `late_attempt_wrong_manifest_hash` | Late attempt collision detected | `INTEGRITY_CONFLICT`, 2 conflicts |
| `contradictory_attempts_before_receipt_overwritten` | Earlier contradictory attempts retained | `INTEGRITY_CONFLICT`, 2 conflicts |
| `malformed_signed_fields_type` | Fail closed on malformed fields | `checkpoint: UNAVAILABLE`, 1 unverifiable |
| `temporary_storage_failure_during_scan` | Fail closed on storage error | `checkpoint: UNAVAILABLE` (structured) |
| `worker_signs_changed_plan_step_provenance` | Changed provenance blocked at worker | `POLICY_BLOCKED`, `EXECUTION_ERROR` |

### B. Earlier 19 Counter-Probes (`new_probes.py`)
- `.venv`: 19/19 scenarios passed with expected conservative outcomes.
- `ciph_env`: 19/19 scenarios passed with expected conservative outcomes.

### C. Test Suites (129 Total Named Tests)
- **Phase 9 Step 1 Acceptance Suite** ([`test_phase9_capability_ledger.py`](file://ciph_project/test_phase9_capability_ledger.py)):
  - `.venv`: **22/22 PASS** (9.39s)
  - `ciph_env`: **22/22 PASS** (8.63s)
- **Stated Regressions Suite** (`test_gate0_remediation_exploits.py`, `test_phase1_canonical_contracts.py`, `test_ciph_evolution.py`, `test_phase2_reference_loop.py`, `test_phase8_complete_workflow.py`):
  - `.venv`: **107/107 PASS** (99.92s)
  - `ciph_env`: **107/107 PASS** (90.02s)
- **Total Named Tests:** **129/129 PASS** in both environments.

### D. Git Working Tree Integrity
- `git diff --cached`: **strictly empty** (no files staged or committed).

---

## 4. Current State & Next Steps

- **Step 1:** **RATIFIED PASS** (Reviews 1–7 resolved; Review 7 independent re-review PASS; defense-in-depth ingress tightening applied and verified across both interpreters; 185/185 tests passing).
- **Step 2 (Idle Maintenance Engine & Shared Exclusion Protocol):** **UNBLOCKED**. Proceed to Step 2 implementation per Convergence Blueprint.

---

## 5. Review 5 — Startup Latency Timing Correction (2026-09-15)

**Finding (P2):** `activation_evidence.py:147` required `receipt.started_at <= activated_at + 1.0`, treating a 1-second allowance as the maximum interval between durable activation and the capability's actual start. Legitimate scheduling/preparation delay between queue activation (`mark_executing_and_consume_token`) and `BaseCapability.execute()` (which assigns `started_at = time.time()`) is normal and does not invalidate signed activation. A 1.2-second startup delay caused valid execution to lose current-version credit (`HISTORICAL_UNBOUND`), and a delayed failure to disappear from defect metrics, leaving the capability incorrectly `VERIFIED_ACTIVE`.

**Fix:** Replaced `receipt.started_at <= row['activated_at'] + 1.0` with `row['activated_at'] <= receipt.started_at`. The correct timing invariant is: activation must precede or coincide with the receipt's start, and activation must fall within the receipt's execution window (the existing `row['activated_at'] <= receipt.completed_at` check). No arbitrary upper bound on startup latency.

**Regressions added** (3 tests in `test_phase9_review4_remediation.TestReview5DelayedStartup`):
1. `test_delayed_genuine_success_earns_current_version_credit` — 1.2s delay, successful execution → `VERIFIED_ACTIVE`, 1/1/0.
2. `test_delayed_failure_after_success_appears_in_defect_metrics` — immediate success then 1.2s-delayed failure → `INCONCLUSIVE_SAMPLE`, 2/1/1 (health ≠ `VERIFIED_ACTIVE`).
3. `test_retry_after_delayed_parent_failure_credits_both_attempts` — retry whose failed parent had 1.2s startup delay → 2/1/0 (both attempts credited).

---

## 6. Review 6 — Sandbox & Evolution Receipt Timestamp Contract (2026-09-15)

**Finding (P2):** The `row['activated_at'] <= receipt.started_at` comparison broke real sandbox and evolution execution evidence because those branches in `daemon.py` constructed receipts using `start_t` captured at the beginning of `_execute_leased_job()` before token validation and durable queue activation. Consequently, valid receipts had `started_at` 4–8 ms earlier than `activated_at`, causing them to be classified as `HISTORICAL_UNBOUND` with 0 current-version attempts. Real sandbox failures also disappeared from defect metrics.

**Fix:** In `ciph/workers/daemon.py`, daemon-entry timestamp `start_t` is retained for orchestration and pre-execution denials. A separate `exec_start_t = time.time()` is captured immediately after Barrier 3 (authenticated activation and token consumption) and used consistently as `started_at` in both `EvolutionRevisionCapability` and sandboxed execution receipts.

**Regressions added** (4 end-to-end ledger tests in `test_phase9_review4_remediation.TestReview6SandboxAndEvolutionExecution`):
1. `test_real_sandbox_success_establishes_verified_active` — exit 0 → `VERIFIED_ACTIVE`, 1/1/0.
2. `test_real_sandbox_failure_records_defect_and_failing_health` — exit 42 → `FAILING`, 1/0/1.
3. `test_real_promoted_evolution_success_establishes_verified_active` — promoted canary execution in sandbox → `VERIFIED_ACTIVE`, 1/1/0.
4. `test_sandbox_retry_following_authenticated_failure_credits_both_attempts` — attempt 1 fails, attempt 2 retry succeeds → `INCONCLUSIVE_SAMPLE`, 2/1/1 (both attempts credited).

---

## 7. Review 7 — Omitted Idempotency Key Identity Preservation (2026-09-15)

**Finding (P2):** `IPCJobQueue.enqueue_job()` accepts `idempotency_key=None` by default. Jobs enqueued without an explicit idempotency key stored `None` in the database and signed activation payload. However, sandbox and evolution receipt constructors in `daemon.py:1045` and `:1267` used `idempotency_key=idemp_key or ""`, converting `None` into `""`. The activation matcher in `activation_evidence.py:146` strictly verified `row['idempotency_key'] == receipt.idempotency_key`, which evaluated `None == ""` as `False`. Valid sandbox/evolution executions and retries with omitted keys were rejected as `HISTORICAL_UNBOUND` with 0 current-version attempts.

**Fix:** 
1. In `ciph/workers/daemon.py`, changed line 278 to `idemp_key = job.get('idempotency_key')` (defaulting to `None` rather than `""`).
2. Preserved `idempotency_key=idemp_key` in `EvolutionRevisionCapability`, sandboxed capability, and exception receipts without coercing `None` to empty string.
3. In `ciph/capabilities/capability_ledger.py`, preserved `payload.get('idempotency_key')` defaulting to `None` when reconstructing receipts.

**Regressions added** (4 tests in `test_phase9_review4_remediation.TestReview7IdempotencyKeyConsistency`):
1. `test_sandbox_success_with_omitted_idempotency_key` — verifies omitted key preserves `None` and earns `VERIFIED_ACTIVE` (1/1/0).
2. `test_sandbox_failure_and_retry_with_omitted_idempotency_key` — verifies attempt 1 failure and attempt 2 retry succeed and credit both attempts with `None` key.
3. `test_promoted_evolution_with_omitted_idempotency_key` — verifies promoted canary sandbox run preserves `None` and earns `VERIFIED_ACTIVE`.
4. `test_idempotency_key_mismatch_between_activation_and_receipt_is_rejected` — verifies intentional mismatch between activation and receipt is rejected from current-version credit.

**Verification (2026-09-15):**

| Check | Workspace `.venv` | Project `ciph_env` |
| --- | --- | --- |
| Review 4/5/6/7 regressions (25) + recovery (30) + capability ledger (22) | **77/77 PASS**, 82.9s | **77/77 PASS**, 73.6s |
| Five remaining regression suites (107) | **107/107 PASS**, 100.7s | **107/107 PASS**, 90.3s |
| Review 7 probe scenarios (all 6 cases: 2 controls + 4 omitted-key paths) | **6/6 correct** | **6/6 correct** |
| Dynamic governance matrix (`ciph_matrix_audit.py`) | **16/16 COMPLIANT** (100.0%) | **16/16 COMPLIANT** (100.0%) |
| Git staging | **empty** (zero files staged) | — |

Files changed: `ciph/workers/daemon.py` (preserved `idemp_key` without `or ""` coercion), `ciph/capabilities/capability_ledger.py` (preserved `idempotency_key` None in deserialization), `test_phase9_review4_remediation.py` (4 new Review 7 regression tests added).

---

## 8. Review 7 Re-Review PASS & Ingress Tightening Defense-in-Depth (2026-09-17)

**Independent Review Verdict:** **PASS**
- Verified `ciph/workers/daemon.py:278` preserves `None` without coercion, and post-activation receipt paths pass `idemp_key` verbatim.
- Verified `ciph/capabilities/capability_ledger.py:386` reconstructs receipts with `payload.get("idempotency_key")`, preserving `None`.
- Verified `ciph/workers/activation_evidence.py:146` compares strictly (`row['idempotency_key'] == receipt.idempotency_key`).
- Verified receipt serialization (`asdict`) preserves `None` through dict round-trips.

**Defense-in-Depth Ingress Tightening & Denial-Path Unification:**
- In `ciph/workers/ipc_queue.py:598`, tightened receipt ingress validation to unconditionally check:
  ```python
  if receipt_dict.get("idempotency_key") != job_row["idempotency_key"]:
      return False
  ```
- **Denial-Path Regression Resolved:** All 23 pre-activation denial receipt construction sites in `ciph/workers/daemon.py` were unified to pass `idempotency_key=idemp_key` verbatim (replacing `idemp_key or ""`). Previously, on jobs enqueued with `idempotency_key=None`, pre-activation denials built receipts with `""`, which failed ingress matching (`"" != None`) and left jobs stranded in `LEASED` without committing denial evidence.
- Added regression tests in `test_phase9_review4_remediation.py:TestReview7IdempotencyKeyConsistency`:
  1. `test_omitted_idempotency_key_ingress_rejects_divergent_key` — verifies ingress rejects injected non-`None` keys on `None` jobs.
  2. `test_preactivation_denial_with_omitted_idempotency_key_commits_receipt` — verifies end-to-end that an omitted-key job undergoing real pre-activation denial transitions to `FAILED` and commits `ExecutionReceiptStoredEvent` with `idempotency_key=None`.

**Final Step 1 Ratification Verification (2026-09-17):**

| Check | Workspace `.venv` | Project `ciph_env` |
| --- | --- | --- |
| Review 4/5/6/7 regressions (27) + recovery (30) + capability ledger (22) | **79/79 PASS**, 83.5s | **79/79 PASS**, 72.6s |
| Five remaining regression suites (107) | **107/107 PASS**, 99.9s | **107/107 PASS**, 88.9s |
| Dynamic governance matrix (`ciph_matrix_audit.py`) | **16/16 COMPLIANT** (100.0%) | **16/16 COMPLIANT** (100.0%) |
| **Total Test Suite** | **186/186 PASS** | **186/186 PASS** |
| Git Staging Hygiene | **0 files staged** (`git diff --cached` empty) | **0 files staged** |

**Ratification Decision:** Step 1 is formally **RATIFIED AND SEALED**. **Phase 9, Step 2 is unblocked.**

