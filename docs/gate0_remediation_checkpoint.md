# CIPH 4.0 Gate Zero Remediation Checkpoint

**Date:** 2026-09-03  
**Conversation ID:** `ffa5f3cf-4347-4515-a1a4-8a33f97ac34d`  
**Status:** ✅ **ALL 4 HARD BARRIERS FULLY RESOLVED & RATIFIED**  
**Assessor Findings 1–6 (Barrier 1 Re-Audit):** ✅ **6/6 RESOLVED & VERIFIED**  
**Test Coverage:** **145/145 tests passing** independently in both `./.venv` and `ciph_project/ciph_env`.  
**Constitutional Matrix Audit:** **16/16 Canonical Capabilities Fully Governed (100.0%)**.  
**Git Status:** Untracked files and unstaged modifications present; **no changes staged for commit**.

---

## 1. Resolution of Assessor's 6 Blocking Findings (Barrier 1 Hardening)

### Finding 1: Revocation Bypassed at Successful Ingress
* **Vulnerability:** When the TrustRegistry rejected a receipt as `KEY_REVOKED`, ingress fell back to worker private key / HMAC verification, committing the event anyway.
* **Resolution:** Ingress verification via `ExecutionReceipt.verify_signature` enforces that the `TrustRegistry` is the sole authority for registered keys. If a key is in the registry, any rejection (`KEY_REVOKED`, `SIGNED_AFTER_RETIREMENT`, `KEY_EXPIRED`, `INVALID_SIGNATURE`) is fatal and terminates immediately with zero fallback to private keys or HMAC.
* **Verification:** `test_gate0_barrier1_remediation_findings.py::test_finding1_revocation_cannot_be_bypassed_at_ingress` passes.

### Finding 2: Failure Ingress Performs No Cryptographic Verification
* **Vulnerability:** Unauthenticated receipts with garbage signatures could transition jobs to `FAILED` and insert events into `EventStore`.
* **Resolution:** Applied `_verify_receipt_ingress` symmetrically to both `complete_job_and_append_receipt_event` and `fail_job_and_append_receipt_event`. Failure ingress strictly verifies worker signature authenticity, output hash integrity, and contextual job bindings before changing job state or logging events.
* **Verification:** `test_gate0_barrier1_remediation_findings.py::test_finding2_failure_ingress_performs_cryptographic_verification` passes.

### Finding 3: Receipts Not Bound to Committed Job Context
* **Vulnerability:** A signed receipt referencing a different job ID or capability was able to complete a leased job.
* **Resolution:** In `_verify_receipt_ingress`, mandatory strict equality checks were instituted against the committed database record:
  - `receipt.job_id == job_row["job_id"]`
  - `receipt.capability == job_row["capability"]`
  - `receipt.worker_id == job_row["leased_to"] == worker_id`
  - `receipt.idempotency_key == job_row["idempotency_key"]` (when set)
  - `receipt.plan_id == job_row["plan_id"]` and `receipt.step_id == job_row["step_id"]`
  - `receipt.input_hash == execution_token.parameters_hash`
* **Verification:** `test_gate0_barrier1_remediation_findings.py::test_finding3_receipt_bound_to_committed_job_context` passes.

### Finding 4: Retirement Defeated by Backdating
* **Vulnerability:** A key used after retirement remained valid if the signer supplied an earlier `completed_at` timestamp.
* **Resolution:** Live ingress evaluates key validity at the current ingress evaluation timestamp (`current_time = time.time()`), rather than relying solely on the signer-controlled `completed_at`. Furthermore, receipts claiming future timestamps (`completed_at > current_time + 5.0`) are rejected.
* **Verification:** `test_gate0_barrier1_remediation_findings.py::test_finding4_retirement_cannot_be_defeated_by_backdating` passes.

### Finding 5: Pinned-Root Initialization Fails Open
* **Vulnerability:** Runtimes configured with a pinned operator public key started successfully even if the local operator did not match the pin, or if key registration failed.
* **Resolution:** Pinned operator root enforcement is strictly fail-closed:
  - `CiphRuntime.__init__` compares `self.operator_pub_bytes.hex()` against `pinned_operator_pub_hex` and raises a fatal `PermissionError` on mismatch.
  - `store_keypair` and `get_or_create_keypair` in `TrustRegistry` raise fatal `PermissionError` if operator signature validation fails under a pinned root.
  - All three core identities (`operator_root`, `kernel_primary`, `worker_primary`) must be registered in `ciph_trust_registry`.
* **Verification:** `test_gate0_barrier1_remediation_findings.py::test_finding5_pinned_root_initialization_fails_closed` passes.

### Finding 6: Key Vault Plaintext & Permissions
* **Vulnerability:** SQLite database file was created with default `0644` permissions, and private keys were stored in plaintext hex in `ciph_key_vault`. Additionally, `secrets.token_bytes(32)` was used in worker daemons instead of authentic Ed25519 keys.
* **Resolution:**
  - Files are created using `os.open` with `0o600` permissions, and `os.chmod(..., 0o600)` is enforced.
  - Private keys stored in `ciph_key_vault` are encrypted at rest with AES-GCM (`ENC:<nonce_hex>:<ciphertext_hex>`) using a hardware- and path-derived Key Encryption Key (KEK).
  - In `DurableWorkerDaemon`, replaced raw random tokens with `Ed25519KeyManager.generate_keypair()`.
* **Verification:** `test_gate0_barrier1_remediation_findings.py::test_finding6_key_vault_encryption_and_file_permissions` passes.

---

## 2. Hard Barrier Summary (Barriers 1–4)

1. **Barrier 1: Persistent Ed25519 Identity End-to-End**  
   Encrypted vault (`0600`), persistent Ed25519 identity, non-bypassable TrustRegistry verification, symmetrical failure verification, context binding, and fatal pinned-root initialization.  
   *Test suites:* `test_gate0_barrier1_persistent_identity.py` (5/5) & `test_gate0_barrier1_remediation_findings.py` (6/6).

2. **Barrier 2: Signed Execution Tokens Verified by Workers**  
   Worker authority verification over signed 14-field `ExecutionToken`, parameter hash binding, token expiration, replay defense, and fail-closed mandatory interrupt enforcement.  
   *Test suite:* `test_gate0_barrier2_execution_tokens.py` (6/6).

3. **Barrier 3: Cryptographic Receipt Ingress Verification**  
   Atomic queue and event store commit requiring non-empty worker signature, public TrustRegistry signature verification, output hash integrity, and parameter hash matching.  
   *Test suite:* `test_gate0_barrier3_receipt_ingress.py` (4/4).

4. **Barrier 4: Removal of Direct `cap.execute()` Fallbacks**  
   Eliminated direct execution fallbacks across `route_and_execute`, `DAGExecutor.execute_dag`, and `DAGExecutor._handle_failure_remediation`. All production execution routes through the durable worker daemon.  
   *Test suite:* `test_gate0_barrier4_no_direct_execute.py` (3/3).

---

## 3. Verification & Compliance Matrix

| Test Suite / Audit | Target / Details | Result |
|---|---|---|
| `test_gate0_barrier1_persistent_identity.py` | Key persistence, restart survival, revocation, retirement, tamper detection | **5/5 PASS** |
| `test_gate0_barrier1_remediation_findings.py` | Findings 1–6 (revocation bypass, failure verification, context binding, anti-backdating, pinned root, encrypted vault) | **6/6 PASS** |
| `test_gate0_barrier2_execution_tokens.py` | 14-field ExecutionToken, worker verification, expiration, replay, tamper | **6/6 PASS** |
| `test_gate0_barrier3_receipt_ingress.py` | Receipt ingress cryptographic verification, input hash binding, forgery rejection | **4/4 PASS** |
| `test_gate0_barrier4_no_direct_execute.py` | Direct `cap.execute()` fallbacks removed, fail-closed enforcement | **3/3 PASS** |
| Combined Barrier Suite | All 5 barrier test suites run together | **24/24 PASS** |
| `ciph_matrix_audit.py` (`.venv`) | 16 Canonical capabilities across 11 gates | **16/16 COMPLIANT (100.0%)** |
| `ciph_matrix_audit.py` (`ciph_env`) | Virtualenv parity audit | **16/16 COMPLIANT (100.0%)** |
| Full Discovery (`.venv`) | `python3 -m unittest discover -s . -p "test_*.py"` | **145/145 PASS** |
| Full Discovery (`ciph_env`) | `python3 -m unittest discover -s . -p "test_*.py"` | **145/145 PASS** |
