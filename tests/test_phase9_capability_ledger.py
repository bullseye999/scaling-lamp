"""
test_phase9_capability_ledger.py - Exhaustive Adversarial Tests for CIPH Phase 9 Step 1.
Validates complete pagination, cryptographic chain verification, conflict detection,
operational reliability gates, strict dependency inspection, and the empirical state machine.
"""

import os
import sys
import time
import json
import sqlite3
import hashlib
import unittest
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch
from ciph.workers.ipc_queue import IPCJobQueue
from typing import Dict, Any, List, Optional

from ciph.memory.event_store import EventStore
from ciph.capabilities.registry import CapabilityRegistry
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import (
    CapabilityManifest,
    NetworkPolicy,
    ReversibilityClass,
    RiskTier,
    AuthorizationTier,
)
from ciph.kernel.crypto_identity import (
    TrustRegistry,
    KeyRole,
    Ed25519KeyManager,
    ExecutionToken,
)
from ciph.workers.receipts import ExecutionReceipt, generate_environment_fingerprint
from ciph.contracts.enums import OutcomeCategory
from ciph.capabilities.capability_ledger import (
    CapabilityLedger,
    CapabilityEvidenceState,
    CapabilityHealthStatus,
    DependencyCheckResult,
    DependencyHealthEvidence,
    StaticDependencyInspector,
)


class DummyMathCapability(BaseCapability):
    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="math.compute",
            description="Pure deterministic arithmetic",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            version="1.0"
        )

    def run(self, params, context=None):
        return {"success": True, "result": 42}


class TestPhase9CapabilityLedger(unittest.TestCase):
    TEST_DB = "test_phase9_ledger.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

        self.event_store = EventStore(self.TEST_DB)
        self.trust_registry = TrustRegistry(self.TEST_DB)
        self.registry = CapabilityRegistry()
        self.math_cap = DummyMathCapability()
        self.registry.register(self.math_cap)

        # Setup pinned operator, worker, and kernel identities
        self.op_priv, self.op_pub = self.trust_registry.get_or_create_keypair("operator_root", KeyRole.OPERATOR)
        self.worker_priv, self.worker_pub = self.trust_registry.get_or_create_keypair("worker_primary", KeyRole.WORKER)
        self.kernel_priv, self.kernel_pub = self.trust_registry.get_or_create_keypair("kernel_primary", KeyRole.KERNEL)
        self.env_fingerprint = generate_environment_fingerprint()
        self.queue = IPCJobQueue(self.TEST_DB, trust_registry=self.trust_registry)

    def tearDown(self):
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def _create_signed_receipt(
        self,
        capability: str = "math.compute",
        job_id: str = "JOB-1",
        attempt_number: int = 1,
        exit_code: int = 0,
        outcome: OutcomeCategory = OutcomeCategory.SUCCESS,
        results: Optional[Dict[str, Any]] = None,
        started_at: Optional[float] = None,
        completed_at: Optional[float] = None,
        manifest_version: str = "1.0",
        env_fingerprint: Optional[str] = None,
        token_hash: Optional[str] = None,
        token_obj: Optional[ExecutionToken] = None,
        receipt_id: Optional[str] = None,
        worker_priv: Optional[bytes] = None,
        worker_key_id: str = "worker_primary"
    ) -> ExecutionReceipt:
        res = results if results is not None else {"result": 42}
        rid = receipt_id or f"rcpt_{job_id}_{attempt_number}"
        fingerprint = env_fingerprint if env_fingerprint is not None else self.env_fingerprint

        now = time.time()
        start_t = started_at if started_at is not None else (now - 10.0)
        end_t = completed_at if completed_at is not None else (now - 9.95)

        # Handle token generation / bindings
        if token_obj is not None:
            eff_token_hash = token_obj.token_hash()
            tok_id = token_obj.token_id
            m_hash_val = token_obj.manifest_hash
            params_hash_val = token_obj.parameters_hash
            plan_hash_val = token_obj.plan_hash
            step_id_val = token_obj.step_id
        elif token_hash is not None:
            eff_token_hash = token_hash
            tok_id = f"tok_{job_id}_{attempt_number}"
            m_hash_val = "manifest_hash_default"
            params_hash_val = ExecutionReceipt.hash_payload({"x": 1})
            plan_hash_val = "plan_default"
            step_id_val = "step_default"
        else:
            manifest = self.registry.get_manifest(capability) if hasattr(self.registry, "get_manifest") else None
            if not manifest:
                cap = self.registry.get(capability)
                manifest = cap.manifest if cap else None
            m_hash = manifest.compute_manifest_hash() if manifest else "manifest_hash_default"
            tok = ExecutionToken(
                token_id=f"tok_{job_id}_{attempt_number}",
                nonce=f"nonce_{job_id}",
                plan_hash="plan_default",
                step_id="step_default",
                capability=capability,
                manifest_hash=m_hash,
                manifest_version=manifest_version,
                parameters_hash=ExecutionReceipt.hash_payload({"x": 1}),
                scope_grant_id=None,
                authorization_grant_id=None,
                execution_lane="OFFLINE",
                authorized_worker_class="ALL",
                issued_at=start_t - 5.0,
                expires_at=end_t + 60.0,
                max_attempts=3,
                kernel_key_id="kernel_primary"
            ).sign(self.kernel_priv)
            eff_token_hash = tok.token_hash()
            tok_id = tok.token_id
            m_hash_val = tok.manifest_hash
            params_hash_val = tok.parameters_hash
            plan_hash_val = tok.plan_hash
            step_id_val = tok.step_id

        receipt = ExecutionReceipt(
            receipt_id=rid,
            job_id=job_id,
            capability=capability,
            target="local",
            started_at=start_t,
            completed_at=end_t,
            input_hash=ExecutionReceipt.hash_payload({"x": 1}),
            output_hash=ExecutionReceipt.hash_payload(res),
            exit_code=exit_code,
            outcome=outcome,
            results=res,
            side_effects=[],
            idempotency_key=f"idemp_{job_id}_{attempt_number}",
            attempt_number=attempt_number,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="OFFLINE_LOCAL",
            worker_id="worker_primary",
            worker_key_id=worker_key_id,
            environment_fingerprint=fingerprint,
            provenance={
                "execution_token_hash": eff_token_hash,
                "token_id": tok_id,
                "manifest_version": manifest_version,
                "manifest_hash": m_hash_val,
                "parameters_hash": params_hash_val,
                "plan_hash": plan_hash_val,
                "step_id": step_id_val
            }
        )
        priv = worker_priv or self.worker_priv
        return receipt.sign(priv, worker_key_id=worker_key_id)

    def _activate(self, receipt, token):
        """Exercise the actual atomic queue boundary for positive evidence fixtures."""
        with patch("time.time", return_value=receipt.started_at):
            self.queue.enqueue_job(receipt.capability, {"x": 1}, max_retries=token.max_attempts,
                                   job_id=receipt.job_id, idempotency_key=receipt.idempotency_key,
                                   execution_token=token)
            self.assertIsNotNone(self.queue.lease_next_job(receipt.worker_id, target_job_id=receipt.job_id))
            ok, reason = self.queue.mark_executing_and_consume_token(
                receipt.job_id, receipt.worker_id, token.token_id, token.nonce, token.expires_at)
            self.assertTrue(ok, reason)

    def _record_attempt_and_receipt(
        self,
        receipt: ExecutionReceipt,
        token_hash: Optional[str] = None,
        manifest_version: Optional[str] = None,
        token_obj: Optional[ExecutionToken] = None
    ):
        """Append both ExecutionAttemptStartedEvent and ExecutionReceiptStoredEvent."""
        prov = receipt.provenance or {}
        tok_hash = token_hash or prov.get("execution_token_hash")
        m_ver = manifest_version or prov.get("manifest_version") or "1.0"

        # Synthesize matching kernel-signed token if not provided and not adversarial
        if token_obj is None and (token_hash is None or not token_hash.startswith("NOT_A_")):
            manifest = self.registry.get_manifest(receipt.capability) if hasattr(self.registry, "get_manifest") else None
            if not manifest:
                cap = self.registry.get(receipt.capability)
                manifest = cap.manifest if cap else None
            m_hash = prov.get("manifest_hash") or (manifest.compute_manifest_hash() if manifest else "manifest_hash_default")
            token_obj = ExecutionToken(
                token_id=prov.get("token_id") or f"tok_{receipt.job_id}_{receipt.attempt_number}",
                nonce=f"nonce_{receipt.job_id}",
                plan_hash=prov.get("plan_hash") or "plan_default",
                step_id=prov.get("step_id") or "step_default",
                capability=receipt.capability,
                manifest_hash=m_hash,
                manifest_version=m_ver,
                parameters_hash=prov.get("parameters_hash") or receipt.input_hash,
                scope_grant_id=None,
                authorization_grant_id=None,
                execution_lane="OFFLINE",
                authorized_worker_class="ALL",
                issued_at=receipt.started_at - 5.0,
                expires_at=receipt.completed_at + 60.0,
                max_attempts=3,
                kernel_key_id="kernel_primary"
            ).sign(self.kernel_priv)

        attempt_payload = {
            "job_id": receipt.job_id,
            "attempt_number": receipt.attempt_number,
            "capability": receipt.capability,
            "params_hash": receipt.input_hash,
            "token_id": token_obj.token_id if token_obj else prov.get("token_id"),
            "token_hash": tok_hash or (token_obj.token_hash() if token_obj else None),
            "manifest_version": m_ver,
            "manifest_hash": token_obj.manifest_hash if token_obj else prov.get("manifest_hash"),
            "worker_id": receipt.worker_id,
            "attempted_at": receipt.started_at,
            "token": token_obj.to_dict() if token_obj else None
        }
        if (token_obj is not None and not self.queue.get_job(receipt.job_id)
                and token_obj.token_hash() == prov.get("execution_token_hash")
                and receipt.attempt_number == 1):
            self._activate(receipt, token_obj)
        else:
            # Explicitly adversarial or replay metadata is deliberately unsigned.
            self.event_store.append_event("ExecutionAttemptStartedEvent",
                f"attempt:{receipt.job_id}:{receipt.attempt_number}", attempt_payload)
        self.event_store.append_event(
            "ExecutionReceiptStoredEvent",
            receipt.receipt_id,
            receipt.to_dict()
        )

    # -----------------------------------------------------------------
    # TEST 1: PAGINATION CROSSES 250-PAGE BOUNDARY (251 RECEIPTS)
    # -----------------------------------------------------------------
    def test_adversarial_pagination_crosses_page_boundary(self):
        """Verify complete cursor pagination over 251 receipts without 100 or 250 truncations."""
        now = time.time()
        t0 = now - 600.0
        for i in range(1, 252):
            jid = f"JOB-PAGINATE-{i}"
            rcpt = self._create_signed_receipt(
                job_id=jid,
                attempt_number=1,
                started_at=t0 + (i * 0.5),
                completed_at=t0 + (i * 0.5) + 0.01,
            )
            self._record_attempt_and_receipt(rcpt)

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        dep_evidence = {
            "math.compute": DependencyHealthEvidence(
                capability_name="math.compute",
                status=DependencyCheckResult.PASS,
                checked_at=time.time(),
                source="TEST",
                declared_modules=(),
                missing_modules=(),
                environment_fingerprint=self.env_fingerprint
            )
        }
        profiles, checkpoint = ledger.compile_empirical_ledger(dependency_evidence_map=dep_evidence)

        self.assertEqual(checkpoint.verification_status, "VERIFIED_COMPLETE")
        self.assertTrue(checkpoint.is_complete)
        self.assertEqual(checkpoint.total_events_scanned, 502) # 251 attempts + 251 receipts
        self.assertEqual(checkpoint.qualifying_receipts_count, 251)
        self.assertEqual(checkpoint.unverifiable_receipts_count, 0)

        profile = profiles["math.compute"]
        self.assertEqual(profile.current_version_clean_successes, 251)
        self.assertEqual(profile.health_status, CapabilityHealthStatus.VERIFIED_ACTIVE)
        self.assertEqual(profile.evidence_state, CapabilityEvidenceState.CURRENT_VERSION_PROVEN)

    # -----------------------------------------------------------------
    # TEST 2: PAYLOAD TAMPERING WITH INTACT HASH LINKS
    # -----------------------------------------------------------------
    def test_adversarial_payload_tampering_with_intact_hash_links(self):
        """Detect payload tampering where previous_hash and event_hash links appear intact."""
        for i in range(1, 10):
            rcpt = self._create_signed_receipt(job_id=f"JOB-TAMP-{i}", attempt_number=1)
            self._record_attempt_and_receipt(rcpt)

        # Tamper payload directly in SQLite without updating event_hash
        with sqlite3.connect(self.TEST_DB) as conn:
            conn.execute("UPDATE ciph_event_store SET payload = '{\"tampered\": true}' WHERE event_id = 4;")
            conn.commit()

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()

        self.assertEqual(checkpoint.verification_status, "TAMPERED_EVENT_STORE")
        self.assertFalse(checkpoint.is_complete)
        self.assertEqual(profiles["math.compute"].health_status, CapabilityHealthStatus.UNAVAILABLE)

    # -----------------------------------------------------------------
    # TEST 3: CONFLICTING RECEIPTS FOR SAME EXECUTION ATTEMPT
    # -----------------------------------------------------------------
    def test_adversarial_conflicting_receipts_for_same_attempt(self):
        """Reject conflicting signed receipts for the same attempt and flag INTEGRITY_CONFLICT."""
        # Receipt 1: clean success
        rcpt1 = self._create_signed_receipt(job_id="JOB-CONF-1", attempt_number=1, exit_code=0, results={"r": 1})
        self._record_attempt_and_receipt(rcpt1)

        # Receipt 2: conflicting failure for the SAME attempt
        rcpt2 = self._create_signed_receipt(
            job_id="JOB-CONF-1",
            attempt_number=1,
            exit_code=1,
            outcome=OutcomeCategory.EXECUTION_ERROR,
            results={"error": "conflicting"},
            receipt_id="rcpt_conflicting_second"
        )
        self.event_store.append_event("ExecutionReceiptStoredEvent", rcpt2.receipt_id, rcpt2.to_dict())

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()

        self.assertEqual(checkpoint.conflicting_receipts_count, 1)
        profile = profiles["math.compute"]
        self.assertEqual(profile.health_status, CapabilityHealthStatus.INTEGRITY_CONFLICT)
        self.assertTrue(any("Conflicting receipt" in r for r in profile.conflict_reasons))

    # -----------------------------------------------------------------
    # TEST 4: REUSED RECEIPT ID ACROSS DIFFERENT ATTEMPTS
    # -----------------------------------------------------------------
    def test_adversarial_reused_receipt_id_across_different_attempts(self):
        """Detect and reject receipt ID reuse across different jobs/attempts as an integrity conflict."""
        rcpt1 = self._create_signed_receipt(job_id="JOB-REUSE-A", attempt_number=1, receipt_id="rcpt_shared_id")
        self._record_attempt_and_receipt(rcpt1)

        rcpt2 = self._create_signed_receipt(job_id="JOB-REUSE-B", attempt_number=1, receipt_id="rcpt_shared_id")
        self._record_attempt_and_receipt(rcpt2)

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()

        self.assertGreaterEqual(checkpoint.conflicting_receipts_count, 1)
        profile = profiles["math.compute"]
        self.assertEqual(profile.health_status, CapabilityHealthStatus.INTEGRITY_CONFLICT)

    # -----------------------------------------------------------------
    # TEST 5: IDENTICAL REPLAY DEDUPLICATION
    # -----------------------------------------------------------------
    def test_adversarial_identical_replay_deduplication(self):
        """Deduplicate exact replays without false-positive conflict alarms."""
        rcpt = self._create_signed_receipt(job_id="JOB-DUP-1", attempt_number=1)
        self._record_attempt_and_receipt(rcpt)

        # Append identical receipt event again
        self.event_store.append_event("ExecutionReceiptStoredEvent", rcpt.receipt_id, rcpt.to_dict())

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()

        self.assertEqual(checkpoint.duplicate_replays_count, 1)
        self.assertEqual(checkpoint.conflicting_receipts_count, 0)
        self.assertEqual(profiles["math.compute"].current_version_clean_successes, 1)

    # -----------------------------------------------------------------
    # TEST 6: RECONCILIATION-ONLY DOES NOT CONFER VERIFIED_ACTIVE
    # -----------------------------------------------------------------
    def test_adversarial_reconciliation_only_does_not_confer_verified_active(self):
        """JobReconciledEvent records operator action but never counts as software success."""
        # Append only JobReconciledEvent with genuine operator signature
        now = time.time()
        job_id = "JOB-RECON-1"
        target_state = "SUCCEEDED"
        notes = "Manual operator intervention after daemon crash."
        res_dict = {"reconciled": True}
        res_str = json.dumps(res_dict, sort_keys=True)
        res_digest = hashlib.sha256(res_str.encode('utf-8')).hexdigest()
        recon_msg = f"RECONCILE:{job_id}:{target_state}:{res_digest}:{notes}".encode('utf-8')
        op_sig = Ed25519KeyManager.sign(self.op_priv, recon_msg)

        recon_payload = {
            "job_id": job_id,
            "target_state": target_state,
            "resolution_notes": notes,
            "result": res_dict,
            "operator_id": "operator_root",
            "operator_signature": op_sig,
            "reconciled_at": now
        }
        self.event_store.append_event("JobReconciledEvent", "JOB-RECON-1", recon_payload)

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()

        self.assertEqual(checkpoint.reconciled_jobs_count, 1)
        self.assertEqual(checkpoint.unresolved_reconciled_jobs_count, 1)
        profile = profiles["math.compute"]
        self.assertEqual(profile.current_version_clean_successes, 0)
        self.assertEqual(profile.lifetime_reconciled_jobs, 0)
        self.assertIsNone(profile.defect_failure_rate)
        self.assertEqual(profile.health_status, CapabilityHealthStatus.UNTESTED)

    # -----------------------------------------------------------------
    # TEST 7: ENVIRONMENT AND VERSION MISMATCH HANDLING
    # -----------------------------------------------------------------
    def test_adversarial_environment_and_version_mismatch(self):
        """Ensure historical receipts on older versions or differing OS/Python fingerprints remain unproven."""
        # Receipt on older version 0.9
        rcpt_old_ver = self._create_signed_receipt(job_id="JOB-OLDVER", manifest_version="0.9")
        self._record_attempt_and_receipt(rcpt_old_ver, manifest_version="0.9")

        # Receipt on different environment fingerprint
        rcpt_diff_env = self._create_signed_receipt(job_id="JOB-DIFFENV", env_fingerprint="other_host_env_999")
        self._record_attempt_and_receipt(rcpt_diff_env)

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()

        profile = profiles["math.compute"]
        self.assertEqual(profile.current_version_attempts, 0)
        self.assertEqual(profile.current_version_clean_successes, 0)
        self.assertIn(profile.evidence_state, (
            CapabilityEvidenceState.HISTORICAL_VERSION_MISMATCH,
            CapabilityEvidenceState.HISTORICAL_ENVIRONMENT_MISMATCH
        ))
        self.assertEqual(profile.health_status, CapabilityHealthStatus.HISTORICAL_ONLY)

    # -----------------------------------------------------------------
    # TEST 8: OPERATIONAL FAILURE GATE (1 SUCCESS + 100 TIMEOUTS)
    # -----------------------------------------------------------------
    def test_adversarial_operational_failure_gate_1_success_100_timeouts(self):
        """1 clean success followed by 100 timeouts triggers OPERATIONAL_DEGRADED, preventing VERIFIED_ACTIVE."""
        now = time.time()
        t0 = now - 3600.0
        # 1 clean success
        rcpt_succ = self._create_signed_receipt(job_id="JOB-OP-SUCC", started_at=t0, completed_at=t0 + 0.05)
        self._record_attempt_and_receipt(rcpt_succ)

        # 100 operational timeouts
        for i in range(1, 101):
            jid = f"JOB-OP-TIMEOUT-{i}"
            rcpt_to = self._create_signed_receipt(
                job_id=jid,
                outcome=OutcomeCategory.TIMEOUT,
                exit_code=1,
                results={"error": "Operation timed out"},
                started_at=t0 + (i * 2.0),
                completed_at=t0 + (i * 2.0) + 1.0
            )
            self._record_attempt_and_receipt(rcpt_to)

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        dep_evidence = {
            "math.compute": DependencyHealthEvidence(
                capability_name="math.compute",
                status=DependencyCheckResult.PASS,
                checked_at=time.time(),
                source="TEST",
                declared_modules=(),
                missing_modules=(),
                environment_fingerprint=self.env_fingerprint
            )
        }
        profiles, checkpoint = ledger.compile_empirical_ledger(dependency_evidence_map=dep_evidence)

        profile = profiles["math.compute"]
        self.assertEqual(profile.current_version_clean_successes, 1)
        self.assertEqual(profile.current_version_operational_failures, 100)
        self.assertEqual(profile.current_version_defect_failures, 0)
        self.assertEqual(profile.defect_failure_rate, 0.0) # Defect rate is 0!
        self.assertAlmostEqual(profile.operational_failure_rate, 100 / 101, places=3) # ~99% operational fail rate
        self.assertEqual(profile.health_status, CapabilityHealthStatus.OPERATIONAL_DEGRADED)
        self.assertNotEqual(profile.health_status, CapabilityHealthStatus.VERIFIED_ACTIVE)

    # -----------------------------------------------------------------
    # TEST 9: STALE SUCCESS WITH RECENT FAILURE
    # -----------------------------------------------------------------
    def test_adversarial_stale_success_with_recent_failure(self):
        """A recent failure cannot refresh or extend the freshness TTL of an old success."""
        now = time.time()
        stale_time = now - (30 * 86400.0) # 30 days ago (> 14d TTL)
        recent_time = now - 3600.0        # 1 hour ago

        # Old success
        rcpt_old = self._create_signed_receipt(job_id="JOB-STALE-1", started_at=stale_time, completed_at=stale_time + 0.05)
        self._record_attempt_and_receipt(rcpt_old)

        # Recent failure
        rcpt_fail = self._create_signed_receipt(
            job_id="JOB-FAIL-RECENT",
            exit_code=1,
            outcome=OutcomeCategory.EXECUTION_ERROR,
            results={"error": "Crash"},
            started_at=recent_time,
            completed_at=recent_time + 0.05
        )
        self._record_attempt_and_receipt(rcpt_fail)

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger(current_time=now)

        profile = profiles["math.compute"]
        self.assertEqual(profile.last_qualifying_success_at, stale_time + 0.05)
        self.assertEqual(profile.last_attempt_at, recent_time + 0.05)
        self.assertNotEqual(profile.health_status, CapabilityHealthStatus.VERIFIED_ACTIVE)

    # -----------------------------------------------------------------
    # TEST 10: STATIC DEPENDENCY INSPECTION (ZERO IMPORTS)
    # -----------------------------------------------------------------
    def test_adversarial_static_dependency_inspection_zero_imports(self):
        """Verify static dependency check does not import modules into sys.modules and blocks VERIFIED_ACTIVE on failure."""
        cap_name = "math.compute"
        # Warm up metadata loader once by checking a dummy package
        StaticDependencyInspector.check_declared_modules(cap_name, ("__warmup_pkg__",), self.env_fingerprint)
        modules_before = set(sys.modules.keys())

        # Inspect declared non-existent module
        evidence = StaticDependencyInspector.check_declared_modules(
            capability_name=cap_name,
            declared_modules=("non_existent_ciph_fake_pkg_xyz123",),
            current_env_fingerprint=self.env_fingerprint
        )
        modules_after = set(sys.modules.keys())
        self.assertEqual(modules_before, modules_after) # Zero modules imported!
        self.assertNotIn("non_existent_ciph_fake_pkg_xyz123", sys.modules)
        self.assertEqual(evidence.status, DependencyCheckResult.FAIL)

        # Add 1 clean success
        rcpt = self._create_signed_receipt(job_id="JOB-DEP-CHECK")
        self._record_attempt_and_receipt(rcpt)

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger(dependency_evidence_map={cap_name: evidence})

        profile = profiles[cap_name]
        self.assertEqual(profile.health_status, CapabilityHealthStatus.DEPENDENCY_FAILED)
        self.assertNotEqual(profile.health_status, CapabilityHealthStatus.VERIFIED_ACTIVE)

    # -----------------------------------------------------------------
    # TEST 11: TRUST REVOCATION AT SCAN TIME
    # -----------------------------------------------------------------
    def test_adversarial_trust_revocation_at_scan_time(self):
        """Worker key revoked after receipt completion must fail closed when active authority is required at scan."""
        t0 = time.time() - 3600.0
        rcpt = self._create_signed_receipt(job_id="JOB-REVOKE", started_at=t0, completed_at=t0 + 0.05)
        self._record_attempt_and_receipt(rcpt)

        # Revoke worker key in TrustRegistry
        self.trust_registry.revoke_key("worker_primary", "Key compromise detected")

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger(require_active_key_at_scan=True)

        self.assertEqual(checkpoint.unverifiable_receipts_count, 1)
        self.assertEqual(profiles["math.compute"].current_version_clean_successes, 0)
        self.assertEqual(profiles["math.compute"].health_status, CapabilityHealthStatus.UNTESTED)

    # -----------------------------------------------------------------
    # TEST 12: EXHAUSTIVE STATE TRANSITIONS
    # -----------------------------------------------------------------
    def test_adversarial_exhaustive_state_transitions(self):
        """Verify FAILING, INCONCLUSIVE_SAMPLE, DEGRADED, PARTIAL_ONLY, and POLICY_RESTRICTED_ONLY states."""
        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        dep_evidence = {
            "math.compute": DependencyHealthEvidence(
                capability_name="math.compute",
                status=DependencyCheckResult.PASS,
                checked_at=time.time(),
                source="TEST",
                declared_modules=(),
                missing_modules=(),
                environment_fingerprint=self.env_fingerprint
            )
        }

        # Case A: 1 failure, 0 successes -> FAILING
        rcpt_fail = self._create_signed_receipt(job_id="JOB-FAIL-1", exit_code=1, outcome=OutcomeCategory.EXECUTION_ERROR)
        self._record_attempt_and_receipt(rcpt_fail)
        p, _ = ledger.compile_empirical_ledger(dependency_evidence_map=dep_evidence)
        self.assertEqual(p["math.compute"].health_status, CapabilityHealthStatus.FAILING)

        # Case B: 1 success, 1 failure (N=2 < 3, fail rate 50%) -> INCONCLUSIVE_SAMPLE
        rcpt_succ = self._create_signed_receipt(job_id="JOB-SUCC-1")
        self._record_attempt_and_receipt(rcpt_succ)
        p, _ = ledger.compile_empirical_ledger(dependency_evidence_map=dep_evidence)
        self.assertEqual(p["math.compute"].health_status, CapabilityHealthStatus.INCONCLUSIVE_SAMPLE)

        # Case C: 2 successes, 1 failure (N=3 >= 3, fail rate 33.3%) -> DEGRADED
        rcpt_succ2 = self._create_signed_receipt(job_id="JOB-SUCC-2")
        self._record_attempt_and_receipt(rcpt_succ2)
        p, _ = ledger.compile_empirical_ledger(dependency_evidence_map=dep_evidence)
        self.assertEqual(p["math.compute"].health_status, CapabilityHealthStatus.DEGRADED)

        # Case D: Only PARTIAL_SUCCESS runs -> PARTIAL_ONLY
        class PartialCap(DummyMathCapability):
            @property
            def manifest(self):
                return replace(super().manifest, name="math.partial")
        self.registry.register(PartialCap())
        rcpt_part = self._create_signed_receipt(capability="math.partial", job_id="JOB-PART-1", outcome=OutcomeCategory.PARTIAL_SUCCESS, exit_code=0)
        self._record_attempt_and_receipt(rcpt_part)
        dep_part = DependencyHealthEvidence(capability_name="math.partial", status=DependencyCheckResult.PASS, checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(), environment_fingerprint=self.env_fingerprint)
        p, _ = ledger.compile_empirical_ledger(dependency_evidence_map={"math.compute": dep_evidence["math.compute"], "math.partial": dep_part})
        self.assertEqual(p["math.partial"].health_status, CapabilityHealthStatus.PARTIAL_ONLY)

        # Case E: Only POLICY_BLOCKED runs -> POLICY_RESTRICTED_ONLY
        class PolicyCap(DummyMathCapability):
            @property
            def manifest(self):
                return replace(super().manifest, name="math.policy")
        self.registry.register(PolicyCap())
        rcpt_pol = self._create_signed_receipt(capability="math.policy", job_id="JOB-POL-1", outcome=OutcomeCategory.POLICY_BLOCKED, exit_code=0)
        self._record_attempt_and_receipt(rcpt_pol)
        dep_pol = DependencyHealthEvidence(capability_name="math.policy", status=DependencyCheckResult.PASS, checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(), environment_fingerprint=self.env_fingerprint)
        p, _ = ledger.compile_empirical_ledger(dependency_evidence_map={"math.compute": dep_evidence["math.compute"], "math.policy": dep_pol})
        self.assertEqual(p["math.policy"].health_status, CapabilityHealthStatus.POLICY_RESTRICTED_ONLY)

    # -----------------------------------------------------------------
    # TEST 13: EMPTY EVENT STORE GENESIS CHECKPOINT
    # -----------------------------------------------------------------
    def test_adversarial_empty_event_store_genesis(self):
        """Verify empty event store attestation adheres strictly to genesis barrier."""
        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()

        self.assertEqual(checkpoint.verification_status, "VERIFIED_EMPTY")
        self.assertTrue(checkpoint.is_complete)
        self.assertEqual(checkpoint.total_events_scanned, 0)
        self.assertEqual(checkpoint.attempted_barrier_hash, "GENESIS_BLOCK_CIPH_4.0")
        self.assertEqual(profiles["math.compute"].health_status, CapabilityHealthStatus.UNTESTED)

    # -----------------------------------------------------------------
    # TEST 14: FORGED OPERATOR RECONCILIATION SIGNATURE REJECTED
    # -----------------------------------------------------------------
    def test_adversarial_forged_reconciliation_signature_rejected(self):
        """Forged operator reconciliation signature is rejected and does not count as reconciled."""
        now = time.time()
        recon_payload = {
            "job_id": "JOB-FORGE-RECON",
            "target_state": "SUCCEEDED",
            "resolution_notes": "Attempted forgery of operator signature",
            "result": {"forged": True},
            "operator_id": "operator_root",
            "operator_signature": "00" * 64,
            "reconciled_at": now
        }
        self.event_store.append_event("JobReconciledEvent", "JOB-FORGE-RECON", recon_payload)
        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()
        self.assertEqual(checkpoint.reconciled_jobs_count, 0)
        self.assertEqual(profiles["math.compute"].health_status, CapabilityHealthStatus.UNTESTED)

    # -----------------------------------------------------------------
    # TEST 15: DUPLICATE RECONCILIATION COUNTED ONCE
    # -----------------------------------------------------------------
    def test_adversarial_duplicate_reconciliation_counted_once(self):
        """Duplicate reconciliation events for the same job are deduplicated and counted once."""
        now = time.time()
        job_id = "JOB-DUP-RECON"
        target_state = "SUCCEEDED"
        notes = "Resolution notes for duplicate job test."
        res_dict = {"status": "ok"}
        res_str = json.dumps(res_dict, sort_keys=True)
        res_digest = hashlib.sha256(res_str.encode('utf-8')).hexdigest()
        recon_msg = f"RECONCILE:{job_id}:{target_state}:{res_digest}:{notes}".encode('utf-8')
        op_sig = Ed25519KeyManager.sign(self.op_priv, recon_msg)

        recon_payload = {
            "job_id": job_id,
            "target_state": target_state,
            "resolution_notes": notes,
            "result": res_dict,
            "operator_id": "operator_root",
            "operator_signature": op_sig,
            "reconciled_at": now
        }
        self.event_store.append_event("JobReconciledEvent", job_id, recon_payload)
        self.event_store.append_event("JobReconciledEvent", job_id, recon_payload)

        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()
        self.assertEqual(checkpoint.reconciliation_events_count, 2)
        self.assertEqual(checkpoint.reconciled_jobs_count, 1)

    # -----------------------------------------------------------------
    # TEST 16: RECONCILIATION ATTRIBUTED VIA ATTEMPT WITHOUT RECEIPT
    # -----------------------------------------------------------------
    def test_adversarial_reconciliation_attributed_via_attempt_without_receipt(self):
        """Reconciliation without receipt attributes to capability from attempt event, not conferring active."""
        manifest = self.math_cap.manifest
        now = time.time()
        tok = ExecutionToken(
            token_id="tok_attrib",
            nonce="nonce_attrib",
            plan_hash="plan_attrib",
            step_id="step_attrib",
            capability="math.compute",
            manifest_hash=manifest.compute_manifest_hash(),
            manifest_version="1.0",
            parameters_hash=ExecutionReceipt.hash_payload({"x": 1}),
            scope_grant_id=None,
            authorization_grant_id=None,
            execution_lane="OFFLINE",
            authorized_worker_class="ALL",
            issued_at=now - 20.0,
            expires_at=now + 60.0,
            max_attempts=3,
            kernel_key_id="kernel_primary"
        ).sign(self.kernel_priv)

        receipt = self._create_signed_receipt(job_id="JOB-ATTRIB", token_obj=tok)
        self._activate(receipt, tok)
        target_state = "SUCCEEDED"
        notes = "Resolution notes for authenticated attribution."
        res_dict = {"status": "ok"}
        res_str = json.dumps(res_dict, sort_keys=True)
        res_digest = hashlib.sha256(res_str.encode('utf-8')).hexdigest()
        recon_msg = f"RECONCILE:JOB-ATTRIB:{target_state}:{res_digest}:{notes}".encode('utf-8')
        op_sig = Ed25519KeyManager.sign(self.op_priv, recon_msg)

        self.event_store.append_event(
            "JobReconciledEvent",
            "JOB-ATTRIB",
            {
                "job_id": "JOB-ATTRIB",
                "target_state": target_state,
                "resolution_notes": notes,
                "result": res_dict,
                "operator_id": "operator_root",
                "operator_signature": op_sig,
                "reconciled_at": now
            }
        )
        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger()
        self.assertEqual(checkpoint.reconciled_jobs_count, 1)
        self.assertEqual(checkpoint.unresolved_reconciled_jobs_count, 0)
        profile = profiles["math.compute"]
        self.assertEqual(profile.lifetime_reconciled_jobs, 1)
        self.assertEqual(profile.current_version_clean_successes, 0)
        self.assertEqual(profile.health_status, CapabilityHealthStatus.UNTESTED)

    # -----------------------------------------------------------------
    # TEST 17: CROSS-CAPABILITY COLLISION INVALIDATES BOTH SIDES
    # -----------------------------------------------------------------
    def test_adversarial_cross_capability_collision_invalidates_both(self):
        """Cross-capability receipt collisions disqualify BOTH implicated capabilities."""
        class OtherCap(DummyMathCapability):
            @property
            def manifest(self):
                return replace(super().manifest, name="math.other")
        self.registry.register(OtherCap())

        # Same receipt_id used by both math.compute and math.other
        rcpt1 = self._create_signed_receipt(capability="math.compute", job_id="JOB-XCAP-1", receipt_id="rcpt_collision_shared")
        self._record_attempt_and_receipt(rcpt1)
        rcpt2 = self._create_signed_receipt(capability="math.other", job_id="JOB-XCAP-2", receipt_id="rcpt_collision_shared")
        self._record_attempt_and_receipt(rcpt2)

        dep_map = {
            "math.compute": DependencyHealthEvidence(capability_name="math.compute", status=DependencyCheckResult.PASS, checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(), environment_fingerprint=self.env_fingerprint),
            "math.other": DependencyHealthEvidence(capability_name="math.other", status=DependencyCheckResult.PASS, checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(), environment_fingerprint=self.env_fingerprint)
        }
        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        profiles, checkpoint = ledger.compile_empirical_ledger(dependency_evidence_map=dep_map)

        self.assertGreaterEqual(checkpoint.conflicting_receipts_count, 1)
        self.assertEqual(profiles["math.compute"].health_status, CapabilityHealthStatus.INTEGRITY_CONFLICT)
        self.assertEqual(profiles["math.other"].health_status, CapabilityHealthStatus.INTEGRITY_CONFLICT)
        self.assertEqual(profiles["math.compute"].current_version_clean_successes, 0)
        self.assertEqual(profiles["math.other"].current_version_clean_successes, 0)

    # -----------------------------------------------------------------
    # TEST 18: DEPENDENCY GATES ENFORCE ALL FOUR CONDITIONS
    # -----------------------------------------------------------------
    def test_adversarial_dependency_gates_all_four_conditions(self):
        """Dependency evaluation requires PASS, freshness, matching capability/environment, and coverage."""
        rcpt = self._create_signed_receipt(job_id="JOB-DEP-GATES")
        self._record_attempt_and_receipt(rcpt)
        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)

        # Condition 1: Wrong environment fingerprint -> DEPENDENCY_UNVERIFIED
        dep_wrong_env = DependencyHealthEvidence(
            capability_name="math.compute", status=DependencyCheckResult.PASS,
            checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
            environment_fingerprint="WRONG_ENV_FP"
        )
        p1, _ = ledger.compile_empirical_ledger(dependency_evidence_map={"math.compute": dep_wrong_env})
        self.assertEqual(p1["math.compute"].health_status, CapabilityHealthStatus.DEPENDENCY_UNVERIFIED)

        # Condition 2: Wrong capability name -> DEPENDENCY_UNVERIFIED
        dep_wrong_cap = DependencyHealthEvidence(
            capability_name="other.capability", status=DependencyCheckResult.PASS,
            checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
            environment_fingerprint=self.env_fingerprint
        )
        p2, _ = ledger.compile_empirical_ledger(dependency_evidence_map={"math.compute": dep_wrong_cap})
        self.assertEqual(p2["math.compute"].health_status, CapabilityHealthStatus.DEPENDENCY_UNVERIFIED)

        # Condition 3: Stale evidence -> DEPENDENCY_UNVERIFIED
        dep_stale = DependencyHealthEvidence(
            capability_name="math.compute", status=DependencyCheckResult.PASS,
            checked_at=time.time() - 7200.0, freshness_ttl_seconds=3600.0, source="TEST",
            declared_modules=(), missing_modules=(), environment_fingerprint=self.env_fingerprint
        )
        p3, _ = ledger.compile_empirical_ledger(dependency_evidence_map={"math.compute": dep_stale})
        self.assertEqual(p3["math.compute"].health_status, CapabilityHealthStatus.DEPENDENCY_UNVERIFIED)

        # Condition 4: Missing declared modules -> DEPENDENCY_FAILED
        dep_fail = DependencyHealthEvidence(
            capability_name="math.compute", status=DependencyCheckResult.FAIL,
            checked_at=time.time(), source="TEST", declared_modules=("numpy",), missing_modules=("numpy",),
            environment_fingerprint=self.env_fingerprint
        )
        p4, _ = ledger.compile_empirical_ledger(dependency_evidence_map={"math.compute": dep_fail})
        self.assertEqual(p4["math.compute"].health_status, CapabilityHealthStatus.DEPENDENCY_FAILED)

    # -----------------------------------------------------------------
    # TEST 19: MALFORMED RECEIPT DATA HANDLING FAIL-CLOSED
    # -----------------------------------------------------------------
    def test_adversarial_malformed_receipt_data_handling(self):
        """Strict parser rejects boolean for int, non-finite timestamps, and fail-closes."""
        # Case A: Boolean exit_code (True is an instance of int in Python, but not strict int)
        rcpt = self._create_signed_receipt(job_id="JOB-MALFORMED-1")
        raw = rcpt.to_dict()
        raw["exit_code"] = True
        self.event_store.append_event("ExecutionReceiptStoredEvent", rcpt.receipt_id, raw)
        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        p, c = ledger.compile_empirical_ledger()
        self.assertGreaterEqual(c.unverifiable_receipts_count, 1)

        # Case B: Non-finite started_at
        rcpt2 = self._create_signed_receipt(job_id="JOB-MALFORMED-2", receipt_id="rcpt_nan")
        raw2 = rcpt2.to_dict()
        raw2["started_at"] = float("nan")
        self.event_store.append_event("ExecutionReceiptStoredEvent", "rcpt_nan", raw2)
        p2, c2 = ledger.compile_empirical_ledger()
        self.assertGreaterEqual(c2.unverifiable_receipts_count, 2)

    # -----------------------------------------------------------------
    # TEST 20: SNAPSHOT ISOLATION ACROSS PAGE BOUNDARIES
    # -----------------------------------------------------------------
    def test_adversarial_snapshot_isolation_deferred_transaction(self):
        """Read transaction spans barrier selection through page reads with snapshot isolation."""
        from unittest.mock import patch
        for i in range(251):
            self.event_store.append_event("ReviewEvent", str(i), {"i": i})
        with sqlite3.connect(self.TEST_DB) as c:
            c.execute("CREATE TABLE IF NOT EXISTS review_snapshot_marker (value TEXT)")
            c.execute("DELETE FROM review_snapshot_marker")
            c.execute("INSERT INTO review_snapshot_marker VALUES ('before')")

        db_file = self.TEST_DB
        original_connect = sqlite3.connect
        observations = []
        class Conn(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if "WHERE event_id > ?" in sql:
                    if parameters[0] > 0:
                        with original_connect(db_file) as writer:
                            writer.execute("UPDATE review_snapshot_marker SET value='after'")
                    row = super().execute("SELECT value FROM review_snapshot_marker").fetchone()
                    observations.append({"cursor": parameters[0], "marker": row[0], "in_transaction": self.in_transaction})
                return super().execute(sql, parameters)

        def connect_mock(*args, **kwargs):
            kwargs["factory"] = Conn
            return original_connect(*args, **kwargs)

        with patch("sqlite3.connect", connect_mock):
            ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
            p, c = ledger.compile_empirical_ledger()

        self.assertEqual(c.verification_status, "VERIFIED_COMPLETE")
        self.assertGreaterEqual(len(observations), 2)
        for obs in observations:
            self.assertTrue(obs["in_transaction"])
            self.assertEqual(obs["marker"], "before")

    # -----------------------------------------------------------------
    # TEST 21: BOUNDED MEMORY WITH LARGE RECEIPT PAYLOADS
    # -----------------------------------------------------------------
    def test_adversarial_bounded_memory_with_large_payloads(self):
        """Page-streaming releases large receipt payloads, bounding memory usage."""
        import tracemalloc
        base = self._create_signed_receipt(results={"blob": "x" * 8192})
        for i in range(100):
            r = replace(base, job_id=f"JOB-MEM-{i}", receipt_id=f"rcpt_mem_{i}").sign(self.worker_priv, worker_key_id="worker_primary")
            self.event_store.append_event("ExecutionReceiptStoredEvent", r.receipt_id, r.to_dict())

        tracemalloc.start()
        ledger = CapabilityLedger(self.event_store, self.registry, trust_registry=self.trust_registry, db_path=self.TEST_DB)
        p, c = ledger.compile_empirical_ledger()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(c.qualifying_receipts_count, 100)
        self.assertLess(peak, 2_500_000)

    # -----------------------------------------------------------------
    # TEST 22: REAL WORKER REFERENCE LOOP EARNS VERIFIED ACTIVE
    # -----------------------------------------------------------------
    def test_adversarial_real_worker_reference_loop_execution(self):
        """Reference loop execution generates attempt event, signed receipt with full provenance, and earns active."""
        from ciph.runtime import CiphRuntime
        from ciph.planner.schemas import IntentProposal
        from ciph.kernel.policy_engine import ScopeGrant, ScopeType
        rt_db = str(Path(self.TEST_DB).with_name("test_rt_loop.db"))
        if os.path.exists(rt_db):
            os.remove(rt_db)
        rt = CiphRuntime(db_path=rt_db)
        try:
            proposal = IntentProposal(
                proposal_id="test_mem_prop",
                objective="Retrieve key for empirical ledger",
                proposed_capability="memory.retrieve",
                provided_parameters={"key": "test_key", "target": "local_memory"}
            )
            scope = ScopeGrant(
                scope_id="test_scope",
                scope_type=ScopeType.LOCAL_SYSTEM,
                allowed_targets=["local_memory"],
                valid_until=time.time() + 120
            )
            res = rt.execute_reference_loop(proposal, scope_grant=scope)
            self.assertEqual(res["status"], "SUCCESS")
            receipt = res.get("receipt")
            self.assertIsNotNone(receipt)
            self.assertIn("manifest_version", receipt.provenance)
            self.assertIn("token_id", receipt.provenance)

            # Compile ledger with fresh dependency pass
            dep_evidence = DependencyHealthEvidence(
                capability_name="memory.retrieve",
                status=DependencyCheckResult.PASS,
                checked_at=time.time(),
                source="TEST",
                declared_modules=(),
                missing_modules=(),
                environment_fingerprint=generate_environment_fingerprint()
            )
            profiles, checkpoint = rt.capability_ledger.compile_empirical_ledger(
                dependency_evidence_map={"memory.retrieve": dep_evidence}
            )
            self.assertEqual(checkpoint.verification_status, "VERIFIED_COMPLETE")
            mem_prof = profiles["memory.retrieve"]
            self.assertEqual(mem_prof.health_status, CapabilityHealthStatus.VERIFIED_ACTIVE)
            self.assertEqual(mem_prof.evidence_state, CapabilityEvidenceState.CURRENT_VERSION_PROVEN)
            self.assertEqual(mem_prof.current_version_clean_successes, 1)
        finally:
            rt.shutdown()
            if os.path.exists(rt_db):
                try:
                    os.remove(rt_db)
                except Exception:
                    pass


    def test_malformed_legacy_receipt_does_not_blank_the_ledger(self):
        """A legacy receipt that fails strict parsing is unverifiable per-row, never a global scan failure."""
        # 1. A legacy row that cannot be canonicalised (stored output hash does not match the results).
        legacy = self._create_signed_receipt(job_id="JOB-LEGACY-1", receipt_id="rcpt_legacy_bad")
        raw = legacy.to_dict()
        raw["output_hash"] = "0" * 64
        self.event_store.append_event("ExecutionReceiptStoredEvent", "rcpt_legacy_bad", raw)

        # 2. A well-formed receipt for the registered capability.
        good = self._create_signed_receipt(job_id="JOB-GOOD-1", receipt_id="rcpt_good_1")
        self.event_store.append_event("ExecutionReceiptStoredEvent", "rcpt_good_1", good.to_dict())

        ledger = CapabilityLedger(
            self.event_store, self.registry,
            trust_registry=self.trust_registry, db_path=self.TEST_DB
        )
        profiles, checkpoint = ledger.compile_empirical_ledger()

        # P1 regression: one poisoned legacy row must not abort the scan.
        self.assertEqual(checkpoint.verification_status, "VERIFIED_COMPLETE")
        self.assertTrue(checkpoint.is_complete, "Scan must complete despite unparseable legacy receipts")
        self.assertGreaterEqual(checkpoint.unverifiable_receipts_count, 1)

        # And it must not blank capabilities or mark them as integrity conflicts.
        for profile in profiles.values():
            status = str(getattr(profile.health_status, "value", profile.health_status))
            self.assertNotIn(status, ("UNAVAILABLE", "INTEGRITY_CONFLICT"),
                             f"{profile.capability_name} was degraded to {status} by legacy-format rows")


if __name__ == "__main__":
    unittest.main()
