"""
test_ciph_stage7_sovereignty.py - Verification for Stage 7 Governed Singularity & Sovereign Autonomy.
"""

import os
import time
import unittest

from ciph.runtime import CiphRuntime
from ciph.sovereignty.singularity_engine import SovereigntyEngine
from ciph.kernel.policy_engine import AuthorizationGrant, AuthorizationTier


class TestCiphStage7Sovereignty(unittest.TestCase):
    TEST_DB = "test_stage7_sovereignty.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.auth_key = b"stage7_sovereignty_auth_key_32b!"
        self.runtime = CiphRuntime(db_path=self.TEST_DB, auth_secret_key=self.auth_key)
        self.engine = SovereigntyEngine()

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_economic_solvency_and_health_audit(self):
        """Verify autonomous solvency monitoring and runway calculation."""
        solvency = self.engine.calculate_solvency(reserve_override=5000.0)
        self.assertTrue(solvency.is_solvent)
        self.assertGreater(solvency.runway_days, 100.0)

        health = self.engine.evaluate_system_health(self.runtime)
        self.assertEqual(health["status"], "HEALTHY")
        self.assertGreaterEqual(health["active_capabilities"], 16)

    def test_constitutional_leash_blocks_unauthorized_self_promotion(self):
        """Verify system cannot self-promote code upgrade without operator signature."""
        res = self.engine.execute_governed_evolution_promotion(
            runtime=self.runtime,
            proposal_id="UP-STAGE7-TEST",
            operator_grant=None  # No grant!
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "CONSTITUTIONAL_VETO")
        self.assertIn("K_operator", res["error"])

    def test_governed_evolution_with_authentic_grant(self):
        """Verify promotion proceeds when authentic operator grant is provided."""
        grant = AuthorizationGrant(
            grant_id="GRANT-STAGE7-01",
            plan_hash="hash_promo_v4",
            step_id="step_promo_01",
            capability="code.promote_upgrade",
            params_hash="params_hash_01",
            scope_grant_id="scope_01",
            expires_at=time.time() + 3600
        ).sign(self.auth_key)

        res = self.engine.execute_governed_evolution_promotion(
            runtime=self.runtime,
            proposal_id="UP-STAGE7-TEST",
            operator_grant=grant
        )
        # Even if proposal isn't on disk, it successfully bypasses constitutional veto to reach capability handler
        self.assertIn(res["status"], ("PROMOTION_COMMITTED", "PROMOTION_FAILED"))


if __name__ == "__main__":
    unittest.main()
