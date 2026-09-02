"""
test_ciph_reference_loop.py - End-to-end integration tests for CIPH 4.0 Phase 2 Governed Reference Loop.
Validates the complete chain: Intent -> Plan -> Scope/Auth -> Queue -> Worker -> HMAC Receipt -> EventStore -> Worldview.
"""

import os
import time
import unittest
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
from ciph.workers.receipts import OutcomeCategory, JobState


class TestCiphReferenceLoop(unittest.TestCase):
    TEST_DB = "test_ciph_reference_loop.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.auth_key = b"test_secret_auth_key_1234567890!"
        self.worker_key = b"test_secret_worker_key_0987654321!"
        self.runtime = CiphRuntime(
            db_path=self.TEST_DB,
            auth_secret_key=self.auth_key,
            worker_secret_key=self.worker_key
        )

        # Register a safe local memory capability
        class LocalMemoryRetrieveCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="memory.retrieve",
                    description="Retrieve memory record",
                    risk_tier=RiskTier.NONE,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                key = params.get("key", "default")
                return {"found": True, "key": key, "value": f"stored_val_for_{key}"}

        # Register a high-consequence capability requiring MANDATORY_INTERRUPT
        class ConsequentialPatchCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="system.apply_critical_patch",
                    description="Apply critical patch",
                    risk_tier=RiskTier.CRITICAL,
                    network_policy=NetworkPolicy.LOCAL_ONLY,
                    reversibility=ReversibilityClass.REVERSIBLE,
                    authorization=AuthorizationTier.MANDATORY_INTERRUPT,
                )

            def run(self, params, context=None):
                return {"patched": True, "patch_id": params.get("patch_id")}

        self.runtime.register_capability(LocalMemoryRetrieveCapability())
        self.runtime.register_capability(ConsequentialPatchCapability())

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_complete_offline_reference_loop(self):
        """Test complete end-to-end governed reference loop on memory.retrieve."""
        proposal = IntentProposal(
            proposal_id="prop_mem_01",
            objective="Retrieve operator profile key",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "operator_alias", "target": "local_memory"},
            missing_parameters=[],
        )

        scope = ScopeGrant(
            scope_id="scope_local_01",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory", "system"],
            valid_until=time.time() + 60,
        )

        result = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
        self.assertEqual(result["status"], "SUCCESS")

        receipt = result["receipt"]
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.outcome, OutcomeCategory.SUCCESS)
        self.assertEqual(receipt.results["value"], "stored_val_for_operator_alias")

        # 1. Verify HMAC signature on receipt
        self.assertTrue(receipt.verify_signature(self.worker_key))
        self.assertFalse(receipt.verify_signature(b"wrong_key"))

        # 2. Verify EventStore commit
        events = self.runtime.event_store.get_events(event_type="ExecutionReceiptStoredEvent")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["aggregate_id"], receipt.receipt_id)

        # 3. Verify Materialized Worldview projection
        claims = self.runtime.worldview.query_active_claims(subject="local_memory")
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0].value["value"], "stored_val_for_operator_alias")
        self.assertIn(receipt.receipt_id, claims[0].evidence_receipt_ids)

        # 4. Verify Persistent Queue job state is SUCCEEDED
        job = self.runtime.queue.get_job(result["job_id"])
        self.assertIsNotNone(job)
        self.assertEqual(job["status"], JobState.SUCCEEDED.value)

        # 5. Verify Grounded Dialogue
        self.assertIn("memory.retrieve", result["dialogue"])

    def test_incomplete_intent_rejected_without_execution(self):
        """Missing parameters must halt execution with no receipts or events emitted."""
        incomplete_proposal = IntentProposal(
            proposal_id="prop_bad_01",
            objective="Retrieve memory",
            proposed_capability="memory.retrieve",
            provided_parameters={},
            missing_parameters=["key"],
        )

        result = self.runtime.execute_reference_loop(incomplete_proposal)
        self.assertEqual(result["status"], "INCOMPLETE_INTENT")
        self.assertIsNone(result["receipt"])

        # Ensure zero events and zero queue jobs created
        events = self.runtime.event_store.get_events()
        self.assertEqual(len(events), 0)

    def test_scope_violation_blocked_safely(self):
        """Target outside ScopeGrant must produce POLICY_BLOCKED receipt without running payload."""
        proposal = IntentProposal(
            proposal_id="prop_scope_violation",
            objective="Retrieve unauthorized memory",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "secret", "target": "unauthorized_server.com"},
        )

        restricted_scope = ScopeGrant(
            scope_id="scope_restricted",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
            denied_targets=["unauthorized_server.com"],
            valid_until=time.time() + 60,
        )

        result = self.runtime.execute_reference_loop(proposal, scope_grant=restricted_scope)
        self.assertEqual(result["status"], "POLICY_BLOCKED")
        self.assertEqual(result["receipt"].outcome, OutcomeCategory.POLICY_BLOCKED)

    def test_mandatory_interrupt_authorization_grant_enforcement(self):
        """MANDATORY_INTERRUPT requires valid cryptographic AuthorizationGrant."""
        proposal = IntentProposal(
            proposal_id="prop_crit_patch",
            objective="Apply critical kernel patch",
            proposed_capability="system.apply_critical_patch",
            provided_parameters={"patch_id": "PATCH-2026-X9"},
        )

        # 1. Without grant -> Blocked with AUTHORIZATION_REQUIRED
        res_no_grant = self.runtime.execute_reference_loop(proposal)
        self.assertEqual(res_no_grant["status"], "AUTHORIZATION_REQUIRED")
        plan_hash = res_no_grant["plan_hash"]
        params_hash = res_no_grant["params_hash"]
        step_id = res_no_grant["step_id"]

        # 2. With invalid signature grant -> Blocked
        invalid_grant = AuthorizationGrant(
            grant_id="grant_fake",
            plan_hash=plan_hash,
            step_id=step_id,
            capability="system.apply_critical_patch",
            params_hash=params_hash,
            scope_grant_id="scope_default",
            expires_at=time.time() + 120,
            signature="bad_signature_hex"
        )
        res_invalid_sig = self.runtime.execute_reference_loop(proposal, auth_grant=invalid_grant)
        self.assertEqual(res_invalid_sig["status"], "INVALID_AUTHORIZATION_SIGNATURE")

        # 3. With validly signed grant -> Execution proceeds & succeeds
        valid_grant = AuthorizationGrant(
            grant_id="grant_valid_01",
            plan_hash=plan_hash,
            step_id=step_id,
            capability="system.apply_critical_patch",
            params_hash=params_hash,
            scope_grant_id="scope_default",
            expires_at=time.time() + 120,
        ).sign(self.auth_key)

        res_authorized = self.runtime.execute_reference_loop(proposal, auth_grant=valid_grant)
        self.assertEqual(res_authorized["status"], "SUCCESS")
        self.assertEqual(res_authorized["receipt"].results["patched"], True)


if __name__ == "__main__":
    unittest.main()
