"""
test_ciph_evolution.py - Integration Tests for CIPH 4.0 Governed Self-Evolution & Skill Promotion (Phase 9).
"""

import os
import time
import unittest
from ciph.runtime import CiphRuntime
from ciph.capabilities.evolution import HotReloadEngine
from ciph.kernel.policy_engine import AuthorizationGrant
from ciph.planner.schemas import PlanStep, SkillPromotionTier


class TestCiphEvolution(unittest.TestCase):
    TEST_DB = "test_ciph_evolution.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.auth_key = b"auth_secret_key_evolution_32b!"
        self.runtime = CiphRuntime(db_path=self.TEST_DB, auth_secret_key=self.auth_key)

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_hot_reload_safe_capability_success(self):
        """Dynamically stage, audit, and hot-reload a new capability without restarting."""
        code = """
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier

class FactorialCapability(BaseCapability):
    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="math.factorial",
            description="Compute factorial of a number",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
        )

    def run(self, params, context=None):
        n = params.get("n", 1)
        res = 1
        for i in range(1, n + 1):
            res *= i
        return {"success": True, "n": n, "factorial": res}
"""
        reload_res = self.runtime.hot_reload_evolved_capability(
            code_source=code,
            class_name="FactorialCapability",
            test_params={"n": 5}
        )

        self.assertTrue(reload_res["success"])
        self.assertEqual(reload_res["status"], "HOT_RELOAD_SUCCESS")
        self.assertEqual(reload_res["capability_name"], "math.factorial")

        # Verify capability can now be executed directly through the runtime
        cap = self.runtime.registry.get("math.factorial")
        self.assertIsNotNone(cap)
        receipt = cap.execute({"n": 6})
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.results["factorial"], 720)

    def test_hot_reload_vetoes_unsafe_ast_patterns(self):
        """Reject code containing forbidden AST calls (eval, exec, process spawn)."""
        bad_code_eval = """
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier

class DangerousEvalCap(BaseCapability):
    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="unsafe.eval",
            description="Bad capability",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
        )

    def run(self, params, context=None):
        return {"result": eval(params.get("expr", "1+1"))}
"""
        res_eval = self.runtime.hot_reload_evolved_capability(
            code_source=bad_code_eval,
            class_name="DangerousEvalCap"
        )
        self.assertFalse(res_eval["success"])
        self.assertEqual(res_eval["status"], "COMPILATION_OR_AUDIT_FAILED")
        self.assertIn("Forbidden dynamic execution", res_eval["errors"][0])

    def test_hot_reload_red_team_falsification_veto(self):
        """Adversarial destructive pattern in parameter fails Red Team gate."""
        code = """
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier

class EchoCap(BaseCapability):
    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="test.echo",
            description="Echo",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
        )

    def run(self, params, context=None):
        return {"msg": params.get("msg")}
"""
        res = self.runtime.hot_reload_evolved_capability(
            code_source=code,
            class_name="EchoCap",
            test_params={"msg": "safe_arg; rm -rf /"}
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "RED_TEAM_FALSIFICATION_VETO")
        self.assertIn("Adversarial Veto", res["errors"][0])

    def test_skill_promotion_with_cryptographic_grant(self):
        """Skill promotion to ACTIVE requires valid cryptographic operator grant."""
        sig = "recon.subdomain_audit"
        self.runtime.skill_registry.register_candidate(
            signature=sig,
            parameter_slots=["domain"],
            dag_nodes=[
                PlanStep(step_id="S1", capability="cybersecurity.bounty_scan", parameters={"domain": "$domain"})
            ],
            precondition_hash="env_hash_v4_0"
        )

        # 1. Promote with invalid signature -> Fails
        fake_grant = AuthorizationGrant(
            grant_id="grant_fake",
            plan_hash="hash_001",
            step_id="promo_step",
            capability=sig,
            params_hash="params_001",
            scope_grant_id="scope_01",
            expires_at=time.time() + 60,
            signature="bad_sig_hex"
        )
        res_fake = self.runtime.promote_evolved_skill(sig, fake_grant)
        self.assertFalse(res_fake["success"])
        self.assertEqual(res_fake["status"], "INVALID_AUTHORIZATION_SIGNATURE")

        # 2. Promote with valid signed grant -> Succeeds
        valid_grant = AuthorizationGrant(
            grant_id="grant_valid_promo",
            plan_hash="hash_promo_v4",
            step_id="promo_step",
            capability=sig,
            params_hash="params_promo",
            scope_grant_id="scope_01",
            expires_at=time.time() + 60
        ).sign(self.auth_key)

        res_valid = self.runtime.promote_evolved_skill(sig, valid_grant)
        self.assertTrue(res_valid["success"])
        self.assertEqual(res_valid["status"], "SKILL_PROMOTED_ACTIVE")
        self.assertEqual(res_valid["promotion_tier"], SkillPromotionTier.ACTIVE.value)

        # Verify skill is immediately active for fast-path compilation
        dag = self.runtime.skill_registry.match_and_instantiate(
            signature=sig,
            runtime_params={"domain": "corp.target.com"},
            current_env_hash="env_hash_v4_0"
        )
        self.assertIsNotNone(dag)
        self.assertEqual(dag.steps[0].parameters["domain"], "corp.target.com")


if __name__ == "__main__":
    unittest.main()
