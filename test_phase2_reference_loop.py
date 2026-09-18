"""
test_phase2_reference_loop.py - Comprehensive Verification Harness for Program 1, Phase 2.

Covers the Safe Reference Loop with Durable Persistent Queue:
1. End-to-end integration: Intent -> Plan -> Scope/Auth -> Queue -> Worker -> Ed25519 Receipt -> EventStore -> Worldview -> Canonical Claim.
2. Low-risk offline capabilities (memory.retrieve, memory.store, pentest.cvss_calculate).
3. JobAttempt typed contract lifecycle and fingerprinting.
4. Policy gates: Incomplete intent rejection, ScopeGrant denial, and Mandatory Interrupt AuthorizationGrants.
5. Crash-interruption: Pre-execution lease expiry (RETRYING), in-flight crash (RECONCILIATION_REQUIRED), lease heartbeat renewals.
6. Governed operator reconciliation workflow and quarantine.
7. Idempotency replay deduplication (zero duplicate executions, zero duplicate event emissions).
8. Atomic SQLite WAL single-transaction commits and EventStore SHA-256 hash chaining.
"""

import os
import time
import json
import uuid
import sqlite3
import hashlib
import unittest
from typing import Dict, Any, Optional

from ciph.runtime import CiphRuntime
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import (
    CapabilityManifest,
    RiskTier,
    NetworkPolicy,
    ReversibilityClass,
    AuthorizationTier,
    ScopeGrant,
    ScopeType,
    AuthorizationGrant,
)
from ciph.planner.schemas import IntentProposal
from ciph.workers.receipts import OutcomeCategory, JobState, ExecutionReceipt
from ciph.contracts.enums import EpistemicState
from ciph.contracts.execution import JobAttempt, compute_idempotency_key


class TestPhase2ReferenceLoop(unittest.TestCase):
    """Rigorous Exit Gate Suite for Phase 2 Safe Reference Loop."""

    def setUp(self):
        self.test_db = f"test_phase2_ref_loop_{uuid.uuid4().hex[:12]}.db"
        for f in [self.test_db, f"{self.test_db}-wal", f"{self.test_db}-shm"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass
        self.runtime = CiphRuntime(db_path=self.test_db)

        # Register a high-consequence capability requiring MANDATORY_INTERRUPT
        class ConsequentialPatchCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="system.apply_critical_patch",
                    description="Apply critical patch requiring operator authorization",
                    risk_tier=RiskTier.CRITICAL,
                    network_policy=NetworkPolicy.LOCAL_ONLY,
                    reversibility=ReversibilityClass.REVERSIBLE,
                    authorization=AuthorizationTier.MANDATORY_INTERRUPT,
                )

            def run(self, params, context=None):
                return {"patched": True, "patch_id": params.get("patch_id")}

        self.runtime.register_capability(ConsequentialPatchCapability())

    def tearDown(self):
        self.runtime.shutdown()
        for f in [self.test_db, f"{self.test_db}-wal", f"{self.test_db}-shm"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    # =========================================================================
    # 1. INTEGRATION TESTS (Complete Reference Loop Spine)
    # =========================================================================

    def test_complete_offline_reference_loop_memory_retrieve(self):
        """Complete offline reference loop on memory.retrieve produces signed receipt and canonical Claim."""
        proposal = IntentProposal(
            proposal_id="prop_p2_mem_01",
            objective="Retrieve operator profile key",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "operator_alias", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_p2_mem",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
            valid_until=time.time() + 120,
        )

        res = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIsNotNone(res["receipt"])
        self.assertEqual(res["receipt"].exit_code, 0)
        self.assertEqual(res["receipt"].outcome, OutcomeCategory.SUCCESS)

        # 1. Verify Ed25519 signature verified via TrustRegistry
        valid_sig, sig_reason = res["receipt"].verify(self.runtime.trust_registry)
        self.assertTrue(valid_sig, f"Receipt verification failed: {sig_reason}")

        # 2. Verify Canonical Claim projected and bound to runtime authority fingerprint
        claim = res.get("claim")
        self.assertIsNotNone(claim)
        self.assertEqual(claim.epistemic_state, EpistemicState.OBSERVED)
        self.assertEqual(claim.predicate, "retrieval_report")
        self.assertEqual(claim.authority_fingerprint, self.runtime.claim_projector.authority_fingerprint)
        self.assertIn(res["receipt"].receipt_id, claim.evidence_receipt_ids)

        # 3. Verify Atomic EventStore Append
        events = self.runtime.event_store.get_events(aggregate_id=res["receipt"].receipt_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "ExecutionReceiptStoredEvent")

        # 4. Verify EventStore cryptographic SHA-256 hash chaining
        valid_chain, corrupted_id = self.runtime.event_store.verify_integrity()
        self.assertTrue(valid_chain)
        self.assertIsNone(corrupted_id)

        # 5. Verify Persistent Queue job state in SQLite WAL
        job = self.runtime.queue.get_job(res["job_id"])
        self.assertIsNotNone(job)
        self.assertEqual(job["status"], JobState.SUCCEEDED.value)
        self.assertIsNotNone(job["worker_signature"])

        # 6. Verify Grounded Dialogue Card
        self.assertIn("memory.retrieve", res["dialogue"])

    def test_complete_offline_reference_loop_cvss_calculate(self):
        """Complete offline reference loop on pentest.cvss_calculate verifies deterministic math and facts."""
        vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        proposal = IntentProposal(
            proposal_id="prop_p2_cvss_01",
            objective="Compute CVSS 3.1 base score for critical vulnerability",
            proposed_capability="pentest.cvss_calculate",
            provided_parameters={"vector": vector, "target": "vuln_assessment"},
        )
        scope = ScopeGrant(
            scope_id="scope_p2_cvss",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["vuln_assessment"],
        )

        res = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(res["status"], "SUCCESS")
        receipt = res["receipt"]
        self.assertEqual(receipt.results["base_score"], 9.8)
        self.assertEqual(receipt.results["severity"], "CRITICAL")

        # Verify claim in worldview
        claims = self.runtime.worldview.query_active_claims(subject="vuln_assessment")
        self.assertGreaterEqual(len(claims), 1)
        self.assertEqual(claims[0].value.get("base_score"), 9.8)

    def test_job_attempt_contract_during_lease(self):
        """IPCJobQueue produces and validates immutable JobAttempt typed contracts during worker lease."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "test_lease_key"},
            plan_id="plan_lease_01",
            step_id="step_lease_01",
            max_retries=3,
        )

        leased_job = self.runtime.queue.lease_next_job(worker_id="worker_attempt_test", lease_ttl_seconds=30)
        self.assertIsNotNone(leased_job)
        self.assertEqual(leased_job["job_id"], job_id)
        self.assertIn("lease_expires_at", leased_job)
        self.assertIn("started_at", leased_job)

        attempt = self.runtime.queue.get_job_attempt(job_id)
        self.assertIsNotNone(attempt)
        self.assertIsInstance(attempt, JobAttempt)
        self.assertEqual(attempt.job_id, job_id)
        self.assertEqual(attempt.worker_id, "worker_attempt_test")
        self.assertEqual(attempt.capability, "memory.retrieve")
        self.assertEqual(attempt.attempt_number, 1)
        self.assertEqual(attempt.max_retries, 3)
        self.assertFalse(attempt.is_lease_expired())

        # Deterministic attempt fingerprinting
        fp1 = attempt.compute_attempt_fingerprint()
        fp2 = attempt.compute_attempt_fingerprint()
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

    # =========================================================================
    # 2. POLICY & GOVERNANCE GATES
    # =========================================================================

    def test_incomplete_intent_rejected_without_execution(self):
        """Missing parameters halt the reference loop before queue or worker execution."""
        incomplete_prop = IntentProposal(
            proposal_id="prop_bad_params",
            objective="Retrieve memory",
            proposed_capability="memory.retrieve",
            provided_parameters={},
            missing_parameters=["key"],
        )

        res = self.runtime.execute_reference_loop(incomplete_prop)
        self.assertEqual(res["status"], "INCOMPLETE_INTENT")
        self.assertIsNone(res["receipt"])

        # Zero events emitted to EventStore
        events = self.runtime.event_store.get_events()
        self.assertEqual(len(events), 0)

    def test_scope_violation_produces_policy_blocked_receipt(self):
        """Target outside ScopeGrant produces a POLICY_BLOCKED receipt without running payload."""
        proposal = IntentProposal(
            proposal_id="prop_scope_violation",
            objective="Retrieve external memory",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "secret", "target": "unauthorized_external_host"},
        )
        restricted_scope = ScopeGrant(
            scope_id="scope_restricted_01",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
            denied_targets=["unauthorized_external_host"],
            valid_until=time.time() + 60,
        )

        res = self.runtime.execute_reference_loop(proposal, scope_grant=restricted_scope)
        self.assertEqual(res["status"], "POLICY_BLOCKED")
        self.assertEqual(res["receipt"].outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertEqual(res["receipt"].exit_code, 1)

    def test_mandatory_interrupt_requires_valid_cryptographic_grant(self):
        """MANDATORY_INTERRUPT capabilities require a verified AuthorizationGrant."""
        proposal = IntentProposal(
            proposal_id="prop_critical_patch",
            objective="Apply critical kernel patch",
            proposed_capability="system.apply_critical_patch",
            provided_parameters={"patch_id": "PATCH-2026-REF-01"},
        )

        # 1. Without grant -> Blocked with AUTHORIZATION_REQUIRED
        res_no_grant = self.runtime.execute_reference_loop(proposal)
        self.assertEqual(res_no_grant["status"], "AUTHORIZATION_REQUIRED")
        plan_hash = res_no_grant["plan_hash"]
        params_hash = res_no_grant["params_hash"]
        step_id = res_no_grant["step_id"]

        # 2. With forged signature grant -> Fails closed
        forged_grant = AuthorizationGrant(
            grant_id="grant_forged",
            plan_hash=plan_hash,
            step_id=step_id,
            capability="system.apply_critical_patch",
            params_hash=params_hash,
            scope_grant_id="scope_default",
            expires_at=time.time() + 120,
            signature="deadbeefbadsignature"
        )
        res_bad = self.runtime.execute_reference_loop(proposal, auth_grant=forged_grant)
        self.assertEqual(res_bad["status"], "INVALID_AUTHORIZATION_SIGNATURE")

        # 3. With validly signed grant -> Proceeds and succeeds
        valid_grant = AuthorizationGrant(
            grant_id="grant_valid_p2",
            plan_hash=plan_hash,
            step_id=step_id,
            capability="system.apply_critical_patch",
            params_hash=params_hash,
            scope_grant_id="scope_default",
            expires_at=time.time() + 120,
        ).sign(self.runtime.kernel_priv_bytes)

        res_ok = self.runtime.execute_reference_loop(proposal, auth_grant=valid_grant)
        self.assertEqual(res_ok["status"], "SUCCESS")
        self.assertEqual(res_ok["receipt"].results["patched"], True)

    # =========================================================================
    # 3. CRASH-INTERRUPTION & LEASE LIFECYCLE
    # =========================================================================

    def test_crash_pre_execution_reclaims_to_retrying(self):
        """Worker dies while LEASED before execution begins -> Safely transitions to RETRYING."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "k_pre_exec"},
            plan_id="plan_pre_exec",
            step_id="step_pre_exec",
            max_retries=2
        )
        leased = self.runtime.queue.lease_next_job(worker_id="worker_crashed_early", lease_ttl_seconds=0.05)
        self.assertIsNotNone(leased)

        time.sleep(0.06)
        reclaimed = self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(reclaimed, 1)

        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.RETRYING.value)
        self.assertIsNone(job["leased_to"])

        # Second worker can now lease and execute it
        worker2_lease = self.runtime.queue.lease_next_job(worker_id="worker_recovery", lease_ttl_seconds=30)
        self.assertIsNotNone(worker2_lease)
        self.assertEqual(worker2_lease["job_id"], job_id)
        self.assertEqual(worker2_lease["attempt_number"], 2)

    def test_crash_in_flight_transitions_to_reconciliation_required(self):
        """Worker crashes while EXECUTING -> Transitions to RECONCILIATION_REQUIRED (no blind auto-retry)."""
        job_id = self.runtime.queue.enqueue_job(
            capability="system.apply_critical_patch",
            params={"patch_id": "CRASH-TEST"},
            plan_id="plan_inflight",
            step_id="step_inflight",
            max_retries=3
        )
        self.runtime.queue.lease_next_job(worker_id="worker_doomed", lease_ttl_seconds=0.05)
        self.runtime.queue.mark_executing(job_id, worker_id="worker_doomed")

        time.sleep(0.06)
        reclaimed = self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(reclaimed, 1)

        crashed_job = self.runtime.queue.get_job(job_id)
        self.assertEqual(crashed_job["status"], JobState.RECONCILIATION_REQUIRED.value)

        # Constitutional Invariant: Worker leasing must NOT receive this job
        next_lease = self.runtime.queue.lease_next_job(worker_id="worker_innocent", lease_ttl_seconds=10)
        self.assertIsNone(next_lease)

    def test_lease_heartbeat_renewal_prevents_premature_reclamation(self):
        """Worker heartbeat lease renewal extends lease deadline during long-running tasks."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "heartbeat_key"},
            plan_id="plan_hb",
            step_id="step_hb"
        )
        self.runtime.queue.lease_next_job(worker_id="worker_hb", lease_ttl_seconds=0.08)
        self.runtime.queue.mark_executing(job_id, worker_id="worker_hb")

        # Renew lease at 40ms with a 100ms extension
        time.sleep(0.04)
        renewed = self.runtime.queue.renew_lease(job_id, worker_id="worker_hb", extension_seconds=0.20)
        self.assertTrue(renewed)

        # At 90ms (past initial lease TTL), job must still be actively EXECUTING
        time.sleep(0.05)
        reclaimed = self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(reclaimed, 0)

        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.EXECUTING.value)

    def test_governed_operator_reconciliation_workflow(self):
        """Operator explicitly reconciles a crashed job with audit documentation."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "recon_key"},
            plan_id="plan_recon",
            step_id="step_recon"
        )
        self.runtime.queue.lease_next_job(worker_id="worker_recon_victim", lease_ttl_seconds=0.05)
        self.runtime.queue.mark_executing(job_id, worker_id="worker_recon_victim")
        time.sleep(0.06)
        self.runtime.queue.reclaim_expired_leases()

        # Reconcile to SUCCEEDED using governed operator reconciliation
        reconciled = self.runtime.reconcile_job(
            job_id=job_id,
            target_state=JobState.SUCCEEDED,
            resolution_notes="Operator verified side-effect completed prior to crash.",
            result={"retrieved": True, "note": "manual_reconciliation"}
        )
        self.assertTrue(reconciled)

        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.SUCCEEDED.value)
        self.assertIn("manual_reconciliation", str(job["result"]))

    # =========================================================================
    # 4. IDEMPOTENCY & REPLAY RESISTANCE
    # =========================================================================

    def test_idempotency_exact_replay_deduplication(self):
        """Submitting identical IntentProposal twice returns cached receipt with zero duplicate event commits."""
        proposal = IntentProposal(
            proposal_id="prop_idemp_01",
            objective="Retrieve operator profile key",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "operator_alias", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_idemp",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )

        res1 = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(res1["status"], "SUCCESS")
        receipt_id_1 = res1["receipt"].receipt_id

        # Events count after first execution
        events_count_1 = len(self.runtime.event_store.get_events())

        # Second execution with identical proposal
        res2 = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertTrue(res2.get("idempotent_replay", False))
        self.assertEqual(res2["receipt"].receipt_id, receipt_id_1)

        # Events count after second execution must be identical (zero duplicate commits)
        events_count_2 = len(self.runtime.event_store.get_events())
        self.assertEqual(events_count_1, events_count_2)

    def test_execution_token_replay_rejected_by_sqlite_table(self):
        """Replaying an execution token violates uniqueness constraint on ciph_consumed_tokens and fails closed."""
        from ciph.kernel.crypto_identity import ExecutionToken
        now = time.time()
        token = self.runtime.mint_execution_token(
            capability="memory.retrieve",
            params={"key": "test_tok_replay"},
            issued_at=now,
        )

        job_id_1 = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "test_tok_replay"},
            execution_token=token,
            job_id="JOB-TOK-1"
        )
        leased_1 = self.runtime.queue.lease_next_job(worker_id="worker_t1", lease_ttl_seconds=30)
        rcpt1 = self.runtime.worker_daemon._execute_leased_job(leased_1, worker_id="worker_t1")
        self.assertEqual(rcpt1.exit_code, 0)

        # Attempt to enqueue a second job using the EXACT same consumed token and nonce
        job_id_2 = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "test_tok_replay"},
            execution_token=token,
            job_id="JOB-TOK-2"
        )
        leased_2 = self.runtime.queue.lease_next_job(worker_id="worker_t2", lease_ttl_seconds=30)
        rcpt2 = self.runtime.worker_daemon._execute_leased_job(leased_2, worker_id="worker_t2")

        # Second attempt must be rejected with POLICY_BLOCKED and EXECUTION_TOKEN_REPLAYED error
        self.assertEqual(rcpt2.exit_code, 1)
        self.assertEqual(rcpt2.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertIn("REPLAYED", rcpt2.error_message)

    def test_worker_cas_lease_guard_blocks_unauthorized_completion(self):
        """Worker attempting to complete a job leased to a different worker is rejected by CAS."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "cas_key"}
        )
        self.runtime.queue.lease_next_job(worker_id="worker_legitimate", lease_ttl_seconds=60)

        # Worker 'worker_impostor' tries to complete it
        completed = self.runtime.queue.complete_job(
            job_id=job_id,
            worker_id="worker_impostor",
            result={"stolen": True}
        )
        self.assertFalse(completed)

        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.LEASED.value)
        self.assertEqual(job["leased_to"], "worker_legitimate")


    # =========================================================================
    # 5. ADVERSARIAL GAP VERIFICATIONS (Codex Audit Findings Remediation)
    # =========================================================================

    def test_adversarial_gap1_stale_lease_execution_prevented_and_unrecorded_execution_blocked(self):
        """Gap 1: Daemon aborts on failed mark_executing, and unrecorded executions fail closed."""
        token1 = self.runtime.mint_execution_token(
            capability="memory.retrieve",
            params={"key": "gap1_key", "target": "local_memory"},
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "gap1_key", "target": "local_memory"},
            max_retries=2,
            execution_token=token1
        )
        # Lease with very short TTL
        leased = self.runtime.queue.lease_next_job(worker_id="worker_gap1", lease_ttl_seconds=0.05)
        self.assertIsNotNone(leased)

        # Allow lease to expire and reclaim it
        time.sleep(0.06)
        reclaimed = self.runtime.queue.reclaim_expired_leases()
        self.assertGreaterEqual(reclaimed, 1)

        # 1. Calling mark_executing on an expired/reclaimed lease must return False
        marked = self.runtime.queue.mark_executing(job_id, worker_id="worker_gap1")
        self.assertFalse(marked)

        # 2. Worker daemon executing a stale/reclaimed lease must fail-closed and return POLICY_BLOCKED
        rcpt = self.runtime.worker_daemon._execute_leased_job(leased, worker_id="worker_gap1")
        self.assertIsNotNone(rcpt)
        self.assertEqual(rcpt.exit_code, 1)
        self.assertEqual(rcpt.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertIn("LEASE_LOST_BEFORE_EXECUTION", rcpt.error_message)

        # Job must NOT have been marked SUCCEEDED, and 0 events committed for worker_gap1
        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], JobState.RETRYING.value)
        events = self.runtime.event_store.get_events(aggregate_id=rcpt.receipt_id)
        self.assertEqual(len(events), 0)

        # 3. Test atomic completion commit failure:
        # If execution completed but complete_job_and_append_receipt_event fails (returns 0),
        # daemon fails closed turning the receipt into COMMIT_FAILED_LEASE_LOST
        token3 = self.runtime.mint_execution_token(
            capability="memory.retrieve",
            params={"key": "gap1_commit_key_3", "target": "local_memory"},
        )
        job_id3 = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "gap1_commit_key_3", "target": "local_memory"},
            max_retries=2,
            execution_token=token3
        )
        leased3 = self.runtime.queue.lease_next_job(worker_id="worker_gap1_c", lease_ttl_seconds=30, target_job_id=job_id3)
        orig_complete = self.runtime.queue.complete_job_and_append_receipt_event
        try:
            self.runtime.queue.complete_job_and_append_receipt_event = lambda *args, **kwargs: 0
            rcpt3 = self.runtime.worker_daemon._execute_leased_job(leased3, worker_id="worker_gap1_c")
            self.assertIsNotNone(rcpt3)
            self.assertEqual(rcpt3.exit_code, 1)
            self.assertEqual(rcpt3.outcome, OutcomeCategory.POLICY_BLOCKED)
            self.assertIn("COMMIT_FAILED_LEASE_LOST", rcpt3.error_message)
        finally:
            self.runtime.queue.complete_job_and_append_receipt_event = orig_complete

    def test_adversarial_gap2_reference_loop_job_recovers_from_first_pre_execution_crash(self):
        """Gap 2: Stale worker lease expiration does not burn token; healthy retry recovers successfully."""
        now = time.time()
        token = self.runtime.mint_execution_token(
            capability="memory.retrieve",
            params={"key": "gap2_key", "target": "local_memory"},
            issued_at=now,
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "gap2_key", "target": "local_memory"},
            max_retries=2,
            execution_token=token
        )

        # 1. First lease: attempt 1 with short TTL
        leased_1 = self.runtime.queue.lease_next_job(worker_id="worker_crash_1", lease_ttl_seconds=0.05, target_job_id=job_id)
        self.assertIsNotNone(leased_1)
        self.assertEqual(leased_1["attempt_number"], 1)
        self.assertEqual(leased_1["max_retries"], 2)

        # 2. Worker stalls/dies before mark_executing; lease expires
        time.sleep(0.06)

        # 3. Stale worker wakes up and attempts execution after lease expiration:
        # Must abort with LEASE_LOST_BEFORE_EXECUTION and MUST NOT burn the token in ciph_consumed_tokens!
        rcpt_stale = self.runtime.worker_daemon._execute_leased_job(leased_1, worker_id="worker_crash_1")
        self.assertIsNotNone(rcpt_stale)
        self.assertEqual(rcpt_stale.exit_code, 1)
        self.assertEqual(rcpt_stale.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertIn("LEASE_LOST_BEFORE_EXECUTION", rcpt_stale.error_message)

        # 4. Supervisor/Queue watchdog reclaims the expired lease
        reclaimed = self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(reclaimed, 1)

        job_after_crash = self.runtime.queue.get_job(job_id)
        self.assertEqual(job_after_crash["status"], JobState.RETRYING.value)
        self.assertIsNone(job_after_crash["leased_to"])

        # 5. Healthy second worker leases and completes successfully (attempt 2):
        # Token MUST NOT trigger EXECUTION_TOKEN_REPLAYED because the stale worker never executed it!
        leased_2 = self.runtime.queue.lease_next_job(worker_id="worker_healthy_2", lease_ttl_seconds=30, target_job_id=job_id)
        self.assertIsNotNone(leased_2)
        self.assertEqual(leased_2["attempt_number"], 2)
        rcpt = self.runtime.worker_daemon._execute_leased_job(leased_2, worker_id="worker_healthy_2")
        self.assertEqual(rcpt.exit_code, 0)
        self.assertEqual(rcpt.outcome, OutcomeCategory.SUCCESS)
        self.assertNotIn("EXECUTION_TOKEN_REPLAYED", getattr(rcpt, "error_message", "") or "")

        # Final job state is SUCCEEDED
        job_final = self.runtime.queue.get_job(job_id)
        self.assertEqual(job_final["status"], JobState.SUCCEEDED.value)

    def test_adversarial_gap3_reference_loop_leases_submitted_job_not_global_oldest(self):
        """Gap 3: Reference loop leases its own submitted job instead of stranding older queued jobs."""
        # 1. Enqueue an older dummy job A
        old_job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "old_job_key", "target": "local_memory"},
            max_retries=2
        )
        self.assertEqual(self.runtime.queue.get_job(old_job_id)["status"], JobState.QUEUED.value)

        # 2. Execute a new proposal B via reference loop
        proposal_b = IntentProposal(
            proposal_id="prop_gap3_target",
            objective="Execute proposal B despite older job in queue",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "key_b", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_gap3",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )

        res = self.runtime.execute_reference_loop(proposal_b, scope_grant=scope)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertNotEqual(res["job_id"], old_job_id)
        self.assertGreater(res["event_id"], 0)

        # 3. Verify old job A was NOT leased, stolen, or stranded; remains QUEUED
        old_job = self.runtime.queue.get_job(old_job_id)
        self.assertEqual(old_job["status"], JobState.QUEUED.value)
        self.assertIsNone(old_job["leased_to"])

    def test_adversarial_gap3_expired_leases_cannot_be_resurrected(self):
        """Gap 3 (Hardening): Expired leases cannot be renewed, executed, or completed."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "resurrection_key", "target": "local_memory"},
            max_retries=2
        )
        leased = self.runtime.queue.lease_next_job(worker_id="worker_zombie", lease_ttl_seconds=0.05, target_job_id=job_id)
        self.assertIsNotNone(leased)

        # Wait for lease to expire
        time.sleep(0.06)

        # 1. Heartbeat renew_lease MUST be rejected on expired lease
        renewed = self.runtime.queue.renew_lease(job_id, worker_id="worker_zombie", extension_seconds=30)
        self.assertFalse(renewed, "renew_lease must not resurrect an expired lease.")

        # 2. mark_executing MUST be rejected on expired lease
        marked = self.runtime.queue.mark_executing(job_id, worker_id="worker_zombie")
        self.assertFalse(marked, "mark_executing must not transition an expired lease.")

        # 3. complete_job_and_append_receipt_event MUST be rejected on expired lease
        dummy_receipt = ExecutionReceipt(
            receipt_id="rcpt_zombie_attempt",
            job_id=job_id,
            capability="memory.retrieve",
            target="local_memory",
            started_at=time.time(),
            completed_at=time.time(),
            input_hash=ExecutionReceipt.hash_payload({"key": "resurrection_key", "target": "local_memory"}),
            output_hash=ExecutionReceipt.hash_payload({"result": "zombie"}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"result": "zombie"},
            side_effects=[],
            idempotency_key="",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="NONE",
            worker_id="worker_zombie"
        ).sign(self.runtime.worker_secret_key, worker_key_id=self.runtime.worker_key_id)

        completed_ev = self.runtime.queue.complete_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="worker_zombie",
            receipt_dict=dummy_receipt.to_dict()
        )
        self.assertEqual(completed_ev, 0, "Receipt completion must fail on expired lease.")

        # Reclaim and verify clean transition to RETRYING
        reclaimed = self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(reclaimed, 1)
        job_now = self.runtime.queue.get_job(job_id)
        self.assertEqual(job_now["status"], JobState.RETRYING.value)

    def test_adversarial_gap4_governed_reconciliation_rules_and_audit_event(self):
        """Gap 4: Governed reconciliation rejects unauthenticated callers, invalid signatures, and result tampering."""
        from ciph.kernel.crypto_identity import Ed25519KeyManager

        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "gap4_recon_key"},
            max_retries=2
        )
        self.runtime.queue.lease_next_job(worker_id="worker_gap4_victim", lease_ttl_seconds=0.05)
        self.runtime.queue.mark_executing(job_id, worker_id="worker_gap4_victim")
        time.sleep(0.06)
        self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(self.runtime.queue.get_job(job_id)["status"], JobState.RECONCILIATION_REQUIRED.value)

        # 1. Invalid target state (e.g. QUEUED, RETRYING) must be rejected
        with self.assertRaises(ValueError):
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state=JobState.QUEUED,
                resolution_notes="Trying to push back to queued state illegally."
            )

        with self.assertRaises(ValueError):
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state="RETRYING",
                resolution_notes="Trying to retry an uncertain side-effect job."
            )

        # 2. Empty or trivially short resolution notes (< 10 chars) must be rejected
        with self.assertRaises(ValueError):
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state=JobState.SUCCEEDED,
                resolution_notes="ok"
            )

        # 3. Unauthenticated call (no signature provided) MUST be rejected
        with self.assertRaises(PermissionError):
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state=JobState.SUCCEEDED,
                resolution_notes="Audited VPS via probe: verified resource exists.",
                operator_id="operator_root",
                operator_signature=None
            )

        # 4. Unregistered operator (e.g. "attacker") MUST be rejected
        with self.assertRaises(PermissionError):
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state=JobState.SUCCEEDED,
                resolution_notes="Attacker trying to resolve job without credentials.",
                operator_id="attacker",
                operator_signature="00" * 64
            )

        # 5. Invalid operator signature must be rejected with PermissionError
        with self.assertRaises(PermissionError):
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state=JobState.SUCCEEDED,
                resolution_notes="Legitimate investigation performed by operator.",
                operator_id="operator_root",
                operator_signature="00" * 64
            )

        # 6. Result tampering / substitution check:
        # Sign payload for result_original, but submit result_tampered -> MUST be rejected!
        res_original = {"reconciled": True, "amount": 100}
        res_tampered = {"reconciled": True, "amount": 999999}
        res_str_orig = json.dumps(res_original, sort_keys=True)
        res_hash_orig = hashlib.sha256(res_str_orig.encode('utf-8')).hexdigest()
        notes = "Verified database write succeeded prior to worker crash."
        payload_orig = f"RECONCILE:{job_id}:{JobState.SUCCEEDED.value}:{res_hash_orig}:{notes}".encode('utf-8')
        sig_orig = Ed25519KeyManager.sign(self.runtime.operator_priv_bytes, payload_orig)

        with self.assertRaises(PermissionError):
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state=JobState.SUCCEEDED,
                resolution_notes=notes,
                result=res_tampered,  # Substituted result!
                operator_id="operator_root",
                operator_signature=sig_orig
            )

        # 7. Valid reconciliation using runtime helper commits JobReconciledEvent to EventStore
        success = self.runtime.reconcile_job(
            job_id=job_id,
            target_state=JobState.SUCCEEDED,
            resolution_notes=notes,
            result=res_original
        )
        self.assertTrue(success)

        # Verify audit event in EventStore
        events = self.runtime.event_store.get_events(aggregate_id=job_id, event_type="JobReconciledEvent")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "JobReconciledEvent")
        self.assertEqual(events[0]["payload"]["target_state"], JobState.SUCCEEDED.value)
        self.assertEqual(events[0]["payload"]["operator_id"], "operator_root")
        self.assertEqual(events[0]["payload"]["result"]["amount"], 100)

        # Cryptographic chain integrity must hold
        is_valid, corrupted = self.runtime.event_store.verify_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(corrupted)

    def test_adversarial_gap5_returned_event_ids_monotonic_across_sequential_executions(self):
        """Gap 5 & Gap 4: Returned event IDs are exact and monotonic; zero commits never fall back to prior events."""
        scope = ScopeGrant(
            scope_id="scope_gap5",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )

        p1 = IntentProposal(
            proposal_id="prop_gap5_seq_1",
            objective="Retrieve seq 1",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "gap5_key_1", "target": "local_memory"},
        )
        res1 = self.runtime.execute_reference_loop(p1, scope_grant=scope)
        self.assertEqual(res1["status"], "SUCCESS")
        ev1 = res1["event_id"]

        p2 = IntentProposal(
            proposal_id="prop_gap5_seq_2",
            objective="Retrieve seq 2",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "gap5_key_2", "target": "local_memory"},
        )
        res2 = self.runtime.execute_reference_loop(p2, scope_grant=scope)
        self.assertEqual(res2["status"], "SUCCESS")
        ev2 = res2["event_id"]

        p3 = IntentProposal(
            proposal_id="prop_gap5_seq_3",
            objective="Retrieve seq 3",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "gap5_key_3", "target": "local_memory"},
        )
        res3 = self.runtime.execute_reference_loop(p3, scope_grant=scope)
        self.assertEqual(res3["status"], "SUCCESS")
        ev3 = res3["event_id"]

        self.assertGreater(ev1, 0)
        self.assertGreater(ev2, ev1)
        self.assertGreater(ev3, ev2)

        # Exact matching against EventStore aggregate_id
        ev_matches = self.runtime.event_store.get_events(aggregate_id=res2["receipt"].receipt_id)
        self.assertEqual(len(ev_matches), 1)
        self.assertEqual(ev_matches[0]["event_id"], ev2)

        # Gap 4 verification: If the receipt commit fails (0 events inserted),
        # returned event_id MUST be None, NEVER falling back to ev3 or any earlier event!
        p4 = IntentProposal(
            proposal_id="prop_gap4_fail_commit",
            objective="Retrieve with simulated commit failure",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "gap4_commit_key", "target": "local_memory"},
        )
        orig_complete = self.runtime.queue.complete_job_and_append_receipt_event
        try:
            # Force commit to fail and return 0
            self.runtime.queue.complete_job_and_append_receipt_event = lambda *args, **kwargs: 0
            res4 = self.runtime.execute_reference_loop(p4, scope_grant=scope)
            # The failing execution must have event_id=None, NEVER ev3 or any unrelated event!
            self.assertIsNone(res4["event_id"])
        finally:
            self.runtime.queue.complete_job_and_append_receipt_event = orig_complete

    def test_adversarial_worker_key_cannot_authorize_reconciliation(self):
        """Issue 1: Worker identities cannot authorize reconciliation; strictly OPERATOR role required."""
        from ciph.kernel.crypto_identity import Ed25519KeyManager

        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "worker_recon_probe"},
            max_retries=2
        )
        self.runtime.queue.lease_next_job(worker_id="worker_probe_victim", lease_ttl_seconds=0.05)
        self.runtime.queue.mark_executing(job_id, worker_id="worker_probe_victim")
        time.sleep(0.06)
        self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(self.runtime.queue.get_job(job_id)["status"], JobState.RECONCILIATION_REQUIRED.value)

        # Attacker signs a reconciliation request with worker_primary credentials
        res_dict = {"reconciled": True, "escalated": True}
        res_hash = hashlib.sha256(json.dumps(res_dict, sort_keys=True).encode('utf-8')).hexdigest()
        notes = "Worker trying to illegitimately reconcile job to SUCCEEDED."
        msg = f"RECONCILE:{job_id}:{JobState.SUCCEEDED.value}:{res_hash}:{notes}".encode('utf-8')
        worker_sig = Ed25519KeyManager.sign(self.runtime.worker_secret_key, msg)

        # Must strictly fail with PermissionError because worker_primary is NOT an OPERATOR
        with self.assertRaises(PermissionError) as ctx:
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state=JobState.SUCCEEDED,
                resolution_notes=notes,
                result=res_dict,
                operator_id="worker_primary",
                operator_signature=worker_sig
            )
        self.assertIn("not an authorized OPERATOR", str(ctx.exception))

    def test_adversarial_reconciled_job_replay_does_not_fabricate_receipt(self):
        """Issue 2: Replay of reconciled job returns explicit RECONCILED artifact, never a fabricated receipt."""
        proposal = IntentProposal(
            proposal_id="prop_recon_replay_probe",
            objective="Retrieve with prior reconciliation",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "recon_replay_key", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_recon_replay",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )

        deterministic_hash = hashlib.sha256(proposal.proposal_id.encode('utf-8')).hexdigest()[:8]
        step_id = f"step_{deterministic_hash}"
        plan_id = f"plan_{deterministic_hash}"
        params_hash = ExecutionReceipt.hash_payload(proposal.provided_parameters)
        idemp_key = compute_idempotency_key(plan_id, step_id, params_hash)

        # Enqueue and crash job into RECONCILIATION_REQUIRED
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params=proposal.provided_parameters,
            plan_id=plan_id,
            step_id=step_id,
            idempotency_key=idemp_key,
            max_retries=2
        )
        self.runtime.queue.lease_next_job(worker_id="worker_replay_crash", lease_ttl_seconds=0.05)
        self.runtime.queue.mark_executing(job_id, worker_id="worker_replay_crash")
        time.sleep(0.06)
        self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(self.runtime.queue.get_job(job_id)["status"], JobState.RECONCILIATION_REQUIRED.value)

        # Operator reconciles job
        rec_res = {"retrieved": True, "source": "operator_manual_audit"}
        self.runtime.reconcile_job(
            job_id=job_id,
            target_state=JobState.SUCCEEDED,
            resolution_notes="Operator verified memory key was recorded in underlying storage.",
            result=rec_res
        )

        # Replay the proposal through execute_reference_loop
        replay_res = self.runtime.execute_reference_loop(proposal, scope_grant=scope)

        # Must return explicit RECONCILED status, NOT fabricated ExecutionReceipt
        self.assertEqual(replay_res["status"], "RECONCILED")
        self.assertTrue(replay_res.get("reconciled", False))
        self.assertTrue(replay_res.get("idempotent_replay", False))
        self.assertIsNone(replay_res["receipt"], "Reconciliation replay must NEVER fabricate an unsigned ExecutionReceipt.")
        self.assertIsNotNone(replay_res.get("reconciliation_event"))
        self.assertEqual(replay_res["result"]["source"], "operator_manual_audit")

    def test_adversarial_token_expiry_race_rejected_at_activation_boundary(self):
        """Issue 3: Token that expires right at activation boundary is rejected without state mutation."""
        now = time.time()
        token = self.runtime.mint_execution_token(
            capability="memory.retrieve",
            params={"key": "expiry_race_key", "target": "local_memory"},
            issued_at=now - 50.0,
            expires_at=now + 0.04  # Very short TTL
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "expiry_race_key", "target": "local_memory"},
            max_retries=2,
            execution_token=token
        )
        leased = self.runtime.queue.lease_next_job(worker_id="worker_race_test", lease_ttl_seconds=30, target_job_id=job_id)
        self.assertIsNotNone(leased)

        # Allow token to expire before execution activation
        time.sleep(0.05)

        rcpt = self.runtime.worker_daemon._execute_leased_job(leased, worker_id="worker_race_test")
        self.assertIsNotNone(rcpt)
        self.assertEqual(rcpt.exit_code, 1)
        self.assertEqual(rcpt.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertIn("EXECUTION_TOKEN_EXPIRED", rcpt.error_message)

        # Job must NOT be EXECUTING, and token must NOT be consumed
        job = self.runtime.queue.get_job(job_id)
        self.assertNotEqual(job["status"], JobState.EXECUTING.value)

    def test_adversarial_activation_commit_failure_fails_closed(self):
        """Probe 1: Atomic activation fails closed and returns STORAGE_FAILURE if transaction commit fails."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "commit_fail_key"},
            max_retries=2
        )
        leased = self.runtime.queue.lease_next_job(worker_id="worker_commit_fail", lease_ttl_seconds=30, target_job_id=job_id)
        self.assertIsNotNone(leased)

        from unittest.mock import patch
        real_get_conn = self.runtime.queue._get_connection

        class BrokenCommitConn:
            def __init__(self, conn):
                self._conn = conn
            def execute(self, sql, *args):
                return self._conn.execute(sql, *args)
            def commit(self):
                raise sqlite3.OperationalError("Simulated disk I/O failure during commit")
            def rollback(self):
                return self._conn.rollback()
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                return self._conn.__exit__(exc_type, exc_val, exc_tb)

        with patch.object(self.runtime.queue, '_get_connection', side_effect=lambda: BrokenCommitConn(real_get_conn())):
            success, err_reason = self.runtime.queue.mark_executing_and_consume_token(
                job_id=job_id,
                worker_id="worker_commit_fail"
            )

        self.assertFalse(success, "mark_executing_and_consume_token must NOT report success when commit fails!")
        self.assertIn("STORAGE_FAILURE", str(err_reason))

    def test_adversarial_token_expiry_evaluated_after_tx_lock(self):
        """Probe 2: Token expiry is sampled inside the transaction write lock, blocking expired execution."""
        from unittest.mock import patch
        now = time.time()
        token = self.runtime.mint_execution_token(
            capability="memory.retrieve",
            params={"key": "lock_delay_key", "target": "local_memory"},
            issued_at=now - 10.0,
            expires_at=now + 0.05
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "lock_delay_key", "target": "local_memory"},
            max_retries=2,
            execution_token=token
        )
        leased = self.runtime.queue.lease_next_job(worker_id="worker_lock_delay", lease_ttl_seconds=30, target_job_id=job_id)
        self.assertIsNotNone(leased)

        real_get_conn = self.runtime.queue._get_connection

        class DelayedLockConn:
            def __init__(self, conn):
                self._conn = conn
            def execute(self, sql, *args):
                if "BEGIN IMMEDIATE" in sql:
                    # Simulate lock contention delay where token expires during wait
                    time.sleep(0.08)
                return self._conn.execute(sql, *args)
            def commit(self):
                return self._conn.commit()
            def rollback(self):
                return self._conn.rollback()
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                return self._conn.__exit__(exc_type, exc_val, exc_tb)

        with patch.object(self.runtime.queue, '_get_connection', side_effect=lambda: DelayedLockConn(real_get_conn())):
            success, err_reason = self.runtime.queue.mark_executing_and_consume_token(
                job_id=job_id,
                worker_id="worker_lock_delay",
                token_id=token.token_id,
                nonce=token.nonce,
                token_expires_at=token.expires_at
            )

        self.assertFalse(success, "Token expired during lock acquisition must be rejected!")
        self.assertEqual(err_reason, "TOKEN_EXPIRED")
        job = self.runtime.queue.get_job(job_id)
        self.assertNotEqual(job["status"], JobState.EXECUTING.value)

    def test_adversarial_revoked_operator_key_cannot_reconcile_via_vault_fallback(self):
        """Probe 3: Revoked subordinate operator keys fail immediately and cannot use vault fallback."""
        from ciph.kernel.crypto_identity import Ed25519KeyManager, KeyRole
        priv_bytes, pub_bytes = Ed25519KeyManager.generate_keypair()
        sub_op_id = f"operator_sub_{uuid.uuid4().hex[:6]}"

        # Register subordinate operator key in trust registry signed by pinned root
        reg_payload = f"REGISTER_KEY:{sub_op_id}:{KeyRole.OPERATOR.value}:{pub_bytes.hex()}:None".encode("utf-8")
        reg_sig = Ed25519KeyManager.sign(self.runtime.operator_priv_bytes, reg_payload)
        self.runtime.trust_registry.register_key(
            key_id=sub_op_id,
            role=KeyRole.OPERATOR,
            public_key_hex=pub_bytes.hex(),
            operator_signature=reg_sig
        )
        # Also store into ciph_key_vault to simulate the vault fallback path
        with self.runtime.trust_registry._get_connection() as conn:
            conn.execute("""
                INSERT INTO ciph_key_vault (key_id, role, private_key_hex, public_key_hex, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (sub_op_id, KeyRole.OPERATOR.value, priv_bytes.hex(), pub_bytes.hex(), time.time()))
            conn.commit()

        # Explicitly revoke it
        rev_payload = f"REVOKE_KEY:{sub_op_id}:Subordinate operator compromised".encode("utf-8")
        rev_sig = Ed25519KeyManager.sign(self.runtime.operator_priv_bytes, rev_payload)
        self.runtime.trust_registry.revoke_key(sub_op_id, reason="Subordinate operator compromised", operator_signature=rev_sig)

        # Create job requiring reconciliation
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "sub_revoked_key"},
            max_retries=2
        )
        self.runtime.queue.lease_next_job(worker_id="worker_sub_probe", lease_ttl_seconds=0.05)
        self.runtime.queue.mark_executing(job_id, worker_id="worker_sub_probe")
        time.sleep(0.06)
        self.runtime.queue.reclaim_expired_leases()

        # Sign reconciliation payload with revoked operator key
        res_dict = {"recovered": True}
        res_digest = hashlib.sha256(json.dumps(res_dict, sort_keys=True).encode('utf-8')).hexdigest()
        notes = "Attempting to reconcile with revoked operator key."
        recon_msg = f"RECONCILE:{job_id}:{JobState.SUCCEEDED.value}:{res_digest}:{notes}".encode('utf-8')
        sig = Ed25519KeyManager.sign(priv_bytes, recon_msg)

        # Must raise PermissionError and NEVER fall through to the key vault
        with self.assertRaises(PermissionError) as ctx:
            self.runtime.queue.reconcile_job(
                job_id=job_id,
                target_state=JobState.SUCCEEDED,
                resolution_notes=notes,
                result=res_dict,
                operator_id=sub_op_id,
                operator_signature=sig
            )
        self.assertIn("revoked or inactive", str(ctx.exception).lower())

    def test_adversarial_completed_job_without_evidence_returns_evidence_missing(self):
        """Probe 4: Completed job lacking both ExecutionReceipt and JobReconciledEvent returns EVIDENCE_MISSING."""
        proposal = IntentProposal(
            proposal_id="prop_missing_evidence",
            objective="Retrieve memory with missing evidence row",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "missing_ev_key", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_missing_ev",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )
        deterministic_hash = hashlib.sha256(proposal.proposal_id.encode('utf-8')).hexdigest()[:8]
        step_id = f"step_{deterministic_hash}"
        plan_id = f"plan_{deterministic_hash}"
        params_hash = ExecutionReceipt.hash_payload(proposal.provided_parameters)
        idemp_key = compute_idempotency_key(plan_id, step_id, params_hash)

        # Enqueue job and artificially mark completed without receipt or reconciliation event
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params=dict(proposal.provided_parameters),
            plan_id=plan_id,
            step_id=step_id,
            idempotency_key=idemp_key,
            max_retries=2
        )
        with self.runtime.queue._get_connection() as conn:
            conn.execute("UPDATE ciph_ipc_jobs SET status = 'SUCCEEDED', completed_at = ? WHERE job_id = ?", (time.time(), job_id))
            conn.commit()

        # Replay proposal through execute_reference_loop
        res = self.runtime.execute_reference_loop(proposal, scope_grant=scope)

        # Must fail closed with EVIDENCE_MISSING, NOT RECONCILED!
        self.assertEqual(res["status"], "EVIDENCE_MISSING")
        self.assertFalse(res.get("reconciled", True))
        self.assertIsNone(res.get("receipt"))
        self.assertIsNone(res.get("reconciliation_event"))
        self.assertIn("EVIDENCE_MISSING", res.get("error", ""))

    def test_adversarial_begin_immediate_failure_aborts_activation(self):
        """A failed write-lock acquisition cannot fall through to token activation."""
        from unittest.mock import patch

        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "begin_failure_key"},
            max_retries=2,
        )
        self.runtime.queue.lease_next_job(
            worker_id="worker_begin_failure",
            lease_ttl_seconds=30,
            target_job_id=job_id,
        )
        real_get_conn = self.runtime.queue._get_connection

        class BrokenBeginConn:
            def __init__(self, conn):
                self._conn = conn
            def execute(self, sql, *args):
                if "BEGIN IMMEDIATE" in sql:
                    raise sqlite3.OperationalError("simulated lock acquisition failure")
                return self._conn.execute(sql, *args)
            def commit(self):
                return self._conn.commit()
            def rollback(self):
                return self._conn.rollback()
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                return self._conn.__exit__(exc_type, exc_val, exc_tb)

        with patch.object(
            self.runtime.queue,
            "_get_connection",
            side_effect=lambda: BrokenBeginConn(real_get_conn()),
        ):
            success, reason = self.runtime.queue.mark_executing_and_consume_token(
                job_id=job_id,
                worker_id="worker_begin_failure",
                token_id="tok_begin_failure",
                nonce="nonce_begin_failure",
                token_expires_at=time.time() + 30,
            )

        self.assertFalse(success)
        self.assertIn("STORAGE_FAILURE", reason)
        self.assertEqual(self.runtime.queue.get_job(job_id)["status"], JobState.LEASED.value)
        with self.runtime.queue._get_connection() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM ciph_consumed_tokens WHERE token_id = ?",
                ("tok_begin_failure",),
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_adversarial_vault_only_operator_is_never_authority(self):
        """Denied or manually orphaned vault keys cannot authorize reconciliation."""
        from ciph.kernel.crypto_identity import Ed25519KeyManager, KeyRole

        operator_id = f"operator_vault_only_{uuid.uuid4().hex[:8]}"
        private_key, public_key = Ed25519KeyManager.generate_keypair()
        with self.assertRaises(PermissionError):
            self.runtime.trust_registry.store_keypair(
                operator_id,
                KeyRole.OPERATOR,
                private_key,
                public_key,
            )
        self.assertIsNone(self.runtime.trust_registry.get_key(operator_id))
        with self.runtime.trust_registry._get_connection() as conn:
            self.assertIsNone(conn.execute(
                "SELECT key_id FROM ciph_key_vault WHERE key_id = ?", (operator_id,)
            ).fetchone())
            conn.execute("""
                INSERT INTO ciph_key_vault
                (key_id, role, private_key_hex, public_key_hex, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (operator_id, KeyRole.OPERATOR.value, private_key.hex(), public_key.hex(), time.time()))
            conn.commit()

        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve", params={"key": "vault_only"}, max_retries=2
        )
        self.runtime.queue.lease_next_job("worker_vault_only", 0.05, target_job_id=job_id)
        self.runtime.queue.mark_executing(job_id, "worker_vault_only")
        time.sleep(0.06)
        self.runtime.queue.reclaim_expired_leases()
        result = {"forged": True}
        notes = "Vault-only operator attempted governed reconciliation."
        digest = hashlib.sha256(json.dumps(result, sort_keys=True).encode("utf-8")).hexdigest()
        signature = Ed25519KeyManager.sign(
            private_key,
            f"RECONCILE:{job_id}:SUCCEEDED:{digest}:{notes}".encode("utf-8"),
        )
        with self.assertRaises(PermissionError):
            self.runtime.queue.reconcile_job(
                job_id,
                JobState.SUCCEEDED,
                notes,
                result=result,
                operator_id=operator_id,
                operator_signature=signature,
            )
        self.assertEqual(
            self.runtime.queue.get_job(job_id)["status"],
            JobState.RECONCILIATION_REQUIRED.value,
        )

    def test_adversarial_forged_reconciliation_event_replay_rejected(self):
        """A hash-chained event with a signature-shaped string is not authenticated evidence."""
        proposal = IntentProposal(
            proposal_id="prop_forged_reconciliation_event",
            objective="Retrieve forged reconciliation target",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "forged_recon", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_forged_reconciliation",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )
        suffix = hashlib.sha256(proposal.proposal_id.encode("utf-8")).hexdigest()[:8]
        params_hash = ExecutionReceipt.hash_payload(proposal.provided_parameters)
        idempotency_key = compute_idempotency_key(
            f"plan_{suffix}", f"step_{suffix}", params_hash
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params=proposal.provided_parameters,
            plan_id=f"plan_{suffix}",
            step_id=f"step_{suffix}",
            idempotency_key=idempotency_key,
            max_retries=2,
        )
        result = {"forged": True}
        notes = "Attacker supplied a signature-shaped but invalid audit record."
        event_id = self.runtime.event_store.append_event(
            "JobReconciledEvent",
            job_id,
            {
                "job_id": job_id,
                "target_state": JobState.SUCCEEDED.value,
                "resolution_notes": notes,
                "result": result,
                "operator_id": "operator_root",
                "operator_signature": "00" * 64,
                "reconciled_at": 0.0,
            },
        )
        event = self.runtime.event_store.get_events(aggregate_id=job_id)[0]
        payload = dict(event["payload"])
        payload["reconciled_at"] = event["timestamp"]
        # Preserve a valid hash chain while constructing the adversarial fixture.
        with self.runtime.queue._get_connection() as conn:
            payload_str = json.dumps(payload, sort_keys=True, default=str)
            event_hash = hashlib.sha256(
                f"{event['previous_hash']}|JobReconciledEvent|{job_id}|{payload_str}|{event['timestamp']}".encode("utf-8")
            ).hexdigest()
            conn.execute(
                "UPDATE ciph_event_store SET payload = ?, event_hash = ? WHERE event_id = ?",
                (payload_str, event_hash, event_id),
            )
            conn.execute("""
                UPDATE ciph_ipc_jobs
                SET status = 'SUCCEEDED', result = ?, error = ?, completed_at = ?
                WHERE job_id = ?
            """, (
                json.dumps(result, sort_keys=True),
                f"Reconciled (operator_root): {notes}",
                event["timestamp"],
                job_id,
            ))
            conn.commit()

        replay = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(replay["status"], "EVIDENCE_MISSING")
        self.assertIsNone(replay["reconciliation_event"])

    def test_adversarial_forged_execution_receipt_replay_rejected(self):
        """A structurally valid receipt with a bogus signature cannot replay as SUCCESS."""
        proposal = IntentProposal(
            proposal_id="prop_forged_receipt_event",
            objective="Retrieve forged receipt target",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "forged_receipt", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_forged_receipt",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )
        suffix = hashlib.sha256(proposal.proposal_id.encode("utf-8")).hexdigest()[:8]
        params_hash = ExecutionReceipt.hash_payload(proposal.provided_parameters)
        idempotency_key = compute_idempotency_key(
            f"plan_{suffix}", f"step_{suffix}", params_hash
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params=proposal.provided_parameters,
            plan_id=f"plan_{suffix}",
            step_id=f"step_{suffix}",
            idempotency_key=idempotency_key,
            max_retries=2,
        )
        created_at = self.runtime.queue.get_job(job_id)["created_at"]
        result = {"forged": True}
        receipt = ExecutionReceipt(
            receipt_id=f"rcpt_forged_{uuid.uuid4().hex[:8]}",
            job_id=job_id,
            capability="memory.retrieve",
            target="local_memory",
            started_at=created_at,
            completed_at=created_at + 0.001,
            input_hash=params_hash,
            output_hash=ExecutionReceipt.hash_payload(result),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=result,
            side_effects=[],
            idempotency_key=idempotency_key,
            attempt_number=1,
            requested_network_policy=self.runtime.registry.get("memory.retrieve").manifest.network_policy,
            actual_transport_used="FORGED",
            worker_id="attacker",
            worker_key_id="worker_primary",
            worker_signature="00" * 64,
        )
        event_id = self.runtime.event_store.append_event(
            "ExecutionReceiptStoredEvent", receipt.receipt_id, receipt.to_dict()
        )
        event = self.runtime.event_store.get_events(aggregate_id=receipt.receipt_id)[0]
        with self.runtime.queue._get_connection() as conn:
            conn.execute("""
                UPDATE ciph_ipc_jobs
                SET status = 'SUCCEEDED', result = ?, receipt_id = ?, worker_signature = ?, completed_at = ?
                WHERE job_id = ?
            """, (
                json.dumps(result, sort_keys=True),
                receipt.receipt_id,
                receipt.worker_signature,
                event["timestamp"],
                job_id,
            ))
            conn.commit()

        replay = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(replay["status"], "EVIDENCE_MISSING")
        self.assertIsNone(replay["receipt"])
        self.assertNotEqual(replay.get("event_id"), event_id)

    def test_adversarial_reconciliation_row_result_substitution_rejected(self):
        """Mutable terminal-row data cannot override the operator-signed event result."""
        proposal = IntentProposal(
            proposal_id="prop_reconciliation_result_substitution",
            objective="Retrieve reconciled result binding",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "result_binding", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_reconciliation_result_binding",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )
        suffix = hashlib.sha256(proposal.proposal_id.encode("utf-8")).hexdigest()[:8]
        params_hash = ExecutionReceipt.hash_payload(proposal.provided_parameters)
        idempotency_key = compute_idempotency_key(
            f"plan_{suffix}", f"step_{suffix}", params_hash
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params=proposal.provided_parameters,
            plan_id=f"plan_{suffix}",
            step_id=f"step_{suffix}",
            idempotency_key=idempotency_key,
            max_retries=2,
        )
        self.runtime.queue.lease_next_job("worker_result_binding", 0.05, target_job_id=job_id)
        self.runtime.queue.mark_executing(job_id, "worker_result_binding")
        time.sleep(0.06)
        self.runtime.queue.reclaim_expired_leases()
        self.assertTrue(self.runtime.reconcile_job(
            job_id,
            JobState.SUCCEEDED,
            "Operator verified the authoritative result after worker interruption.",
            result={"authoritative": True},
        ))
        with self.runtime.queue._get_connection() as conn:
            conn.execute(
                "UPDATE ciph_ipc_jobs SET result = ? WHERE job_id = ?",
                (json.dumps({"substituted": True}), job_id),
            )
            conn.commit()

        replay = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(replay["status"], "EVIDENCE_MISSING")
        self.assertNotEqual(replay.get("result"), {"substituted": True})

    def test_adversarial_event_chain_tampering_blocks_replay(self):
        """Cryptographically valid receipt evidence is rejected if its event chain was altered."""
        proposal = IntentProposal(
            proposal_id="prop_event_chain_tamper",
            objective="Retrieve event chain integrity target",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "event_chain_tamper", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_event_chain_tamper",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )
        first = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(first["status"], "SUCCESS")
        with self.runtime.queue._get_connection() as conn:
            conn.execute(
                "UPDATE ciph_event_store SET previous_hash = ? WHERE event_id = ?",
                ("tampered-chain-link", first["event_id"]),
            )
            conn.commit()

        replay = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(replay["status"], "EVIDENCE_MISSING")
        self.assertIsNone(replay["receipt"])

    def test_adversarial_all_lease_cas_clocks_sampled_after_write_lock(self):
        """Lock contention cannot resurrect, execute, complete, or fail an expired lease."""
        from unittest.mock import patch

        real_get_conn = self.runtime.queue._get_connection

        class DelayedBeginConn:
            def __init__(self, conn):
                self._conn = conn
            def execute(self, sql, *args):
                if "BEGIN IMMEDIATE" in sql:
                    time.sleep(0.06)
                return self._conn.execute(sql, *args)
            def commit(self):
                return self._conn.commit()
            def rollback(self):
                return self._conn.rollback()
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                return self._conn.__exit__(exc_type, exc_val, exc_tb)

        operations = {
            "renew": lambda jid, wid: self.runtime.queue.renew_lease(jid, wid, extension_seconds=30),
            "mark": lambda jid, wid: self.runtime.queue.mark_executing(jid, wid),
            "complete": lambda jid, wid: self.runtime.queue.complete_job(jid, wid, {"unsafe": True}),
            "fail": lambda jid, wid: self.runtime.queue.fail_job(jid, wid, "unsafe stale failure"),
        }
        for name, operation in operations.items():
            with self.subTest(operation=name):
                job_id = self.runtime.queue.enqueue_job(
                    capability="memory.retrieve",
                    params={"key": f"delayed_{name}"},
                    max_retries=2,
                )
                worker_id = f"worker_delayed_{name}"
                leased = self.runtime.queue.lease_next_job(
                    worker_id, 0.03, target_job_id=job_id
                )
                self.assertIsNotNone(leased)
                with patch.object(
                    self.runtime.queue,
                    "_get_connection",
                    side_effect=lambda: DelayedBeginConn(real_get_conn()),
                ):
                    self.assertFalse(operation(job_id, worker_id))
                self.assertEqual(
                    self.runtime.queue.get_job(job_id)["status"],
                    JobState.LEASED.value,
                )

    def test_adversarial_retry_clears_stale_receipt_before_reconciliation(self):
        """Prior-attempt evidence cannot shadow a later governed crash reconciliation."""
        proposal = IntentProposal(
            proposal_id="prop_retry_crash_reconciliation",
            objective="Retrieve after a failed attempt and worker crash",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "retry_crash", "target": "local_memory"},
        )
        scope = ScopeGrant(
            scope_id="scope_retry_crash_reconciliation",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
        )
        suffix = hashlib.sha256(proposal.proposal_id.encode("utf-8")).hexdigest()[:8]
        params_hash = ExecutionReceipt.hash_payload(proposal.provided_parameters)
        idempotency_key = compute_idempotency_key(
            f"plan_{suffix}", f"step_{suffix}", params_hash
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params=proposal.provided_parameters,
            plan_id=f"plan_{suffix}",
            step_id=f"step_{suffix}",
            idempotency_key=idempotency_key,
            max_retries=3,
        )
        with self.runtime.queue._get_connection() as conn:
            conn.execute("""
                UPDATE ciph_ipc_jobs
                SET status = 'RETRYING', result = ?, error = ?, receipt_id = ?,
                    worker_signature = ?, completed_at = ?
                WHERE job_id = ?
            """, (
                json.dumps({"attempt": 1, "failed": True}),
                "first attempt failed",
                "rcpt_prior_failed_attempt",
                "prior-attempt-signature",
                time.time(),
                job_id,
            ))
            conn.commit()

        leased = self.runtime.queue.lease_next_job(
            "worker_retry_crash", 0.05, target_job_id=job_id
        )
        self.assertIsNotNone(leased)
        active = self.runtime.queue.get_job(job_id)
        self.assertIsNone(active["receipt_id"])
        self.assertIsNone(active["worker_signature"])
        self.assertIsNone(active["result"])
        self.assertIsNone(active["error"])
        self.assertIsNone(active["completed_at"])

        self.assertTrue(self.runtime.queue.mark_executing(job_id, "worker_retry_crash"))
        time.sleep(0.06)
        self.runtime.queue.reclaim_expired_leases()
        self.assertEqual(
            self.runtime.queue.get_job(job_id)["status"],
            JobState.RECONCILIATION_REQUIRED.value,
        )
        self.assertTrue(self.runtime.reconcile_job(
            job_id,
            JobState.SUCCEEDED,
            "Operator verified the second attempt completed before its worker crashed.",
            result={"attempt": 2, "verified": True},
        ))

        replay = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(replay["status"], "RECONCILED")
        self.assertEqual(replay["result"], {"attempt": 2, "verified": True})
        self.assertIsNone(replay["receipt"])

    def test_adversarial_governed_job_cannot_bypass_reconciliation_via_quarantine(self):
        """Direct quarantine cannot mutate governed jobs or jobs leased to another worker."""
        token = self.runtime.mint_execution_token(
            capability="memory.retrieve",
            params={"key": "governed_quarantine", "target": "local_memory"},
        )
        governed_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "governed_quarantine", "target": "local_memory"},
            execution_token=token,
            max_retries=2,
        )
        self.runtime.queue.lease_next_job(
            "worker_governed_quarantine", 30, target_job_id=governed_id
        )
        self.assertFalse(self.runtime.queue.quarantine_job(
            governed_id,
            "worker_governed_quarantine",
            "attempt to skip signed operator reconciliation",
        ))
        self.assertEqual(
            self.runtime.queue.get_job(governed_id)["status"], JobState.LEASED.value
        )

        legacy_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "legacy_quarantine"},
            max_retries=2,
        )
        self.runtime.queue.lease_next_job(
            "worker_legacy_quarantine", 30, target_job_id=legacy_id
        )
        self.assertFalse(self.runtime.queue.quarantine_job(
            legacy_id, "attacker", "wrong lease owner cannot quarantine"
        ))
        self.assertTrue(self.runtime.queue.quarantine_job(
            legacy_id, "worker_legacy_quarantine", "lease owner safety quarantine"
        ))
        self.assertEqual(
            self.runtime.queue.get_job(legacy_id)["status"], JobState.QUARANTINED.value
        )

    def test_adversarial_dead_letter_cannot_consume_inflight_crash(self):
        """Expired EXECUTING work always reaches RECONCILIATION_REQUIRED, even at max attempts."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "inflight_dead_letter"},
            max_retries=1,
        )
        self.runtime.queue.lease_next_job(
            "worker_inflight_dead_letter", 0.05, target_job_id=job_id
        )
        self.assertTrue(self.runtime.queue.mark_executing(
            job_id, "worker_inflight_dead_letter"
        ))
        time.sleep(0.06)

        self.assertEqual(self.runtime.queue.dead_letter_unrecoverable_jobs(), 0)
        self.assertEqual(
            self.runtime.queue.get_job(job_id)["status"], JobState.EXECUTING.value
        )
        self.assertEqual(self.runtime.queue.reclaim_expired_leases(), 1)
        self.assertEqual(
            self.runtime.queue.get_job(job_id)["status"],
            JobState.RECONCILIATION_REQUIRED.value,
        )


if __name__ == "__main__":
    unittest.main()
