"""
test_ciph_contracts.py - Unit tests for CIPH 4.0 Canonical Contracts and Safe Predicates.
"""

import unittest
import time
from ciph.kernel.policy_engine import (
    NetworkPolicy,
    ReversibilityClass,
    RiskTier,
    AuthorizationTier,
    ExecutionLane,
    CapabilityManifest,
)
from ciph.perception.observation import Observation, ReliabilityClass
from ciph.workers.receipts import ExecutionReceipt, JobState, OutcomeCategory
from ciph.planner.predicates import evaluate_success_condition
from ciph.planner.schemas import PlanStep, ExecutionDAG, SkillTemplate, SkillPromotionTier
from ciph.kernel.transmutation_dag import (
    EpistemicCategory,
    TransmutationNode,
    calculate_assurance_score,
)


class TestCiphContracts(unittest.TestCase):

    def test_capability_manifest_lane_derivation(self):
        # Read-only + offline -> Lane 1
        m1 = CapabilityManifest(
            name="memory.read",
            description="Read memory",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
        )
        self.assertEqual(m1.derive_execution_lane(), ExecutionLane.LANE_1_READ_ONLY)

        # Passive recon with Tor -> Lane 3
        m2 = CapabilityManifest(
            name="cybersecurity.subdomain_scan",
            description="Recon",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.TOR_MANDATORY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
        )
        self.assertEqual(m2.derive_execution_lane(), ExecutionLane.LANE_3_OBSERVATION)

        # Local mutation with snapshot -> Lane 4
        m3 = CapabilityManifest(
            name="code_engine.apply_patch",
            description="Apply patch",
            risk_tier=RiskTier.MEDIUM,
            network_policy=NetworkPolicy.LOCAL_ONLY,
            reversibility=ReversibilityClass.REVERSIBLE,
            authorization=AuthorizationTier.BATCH_APPROVE,
        )
        self.assertEqual(m3.derive_execution_lane(), ExecutionLane.LANE_4_CONSEQUENTIAL)

    def test_observation_contract(self):
        obs = Observation(
            observation_id="obs_001",
            source="perception.git",
            subject="ciph_project",
            predicate="git_branch",
            value="main",
            reliability_class=ReliabilityClass.AUTHORITATIVE_LOCAL,
            expires_at=time.time() + 60,
        )
        self.assertFalse(obs.is_expired())
        d = obs.to_dict()
        reconstituted = Observation.from_dict(d)
        self.assertEqual(reconstituted.observation_id, "obs_001")
        self.assertEqual(reconstituted.reliability_class, ReliabilityClass.AUTHORITATIVE_LOCAL)

    def test_execution_receipt(self):
        payload = {"subdomains": ["api.crypto.com", "dev.crypto.com"]}
        h_out = ExecutionReceipt.hash_payload(payload)
        receipt = ExecutionReceipt(
            receipt_id="rcpt_001",
            job_id="JOB-001",
            capability="cybersecurity.subdomain_scan",
            target="crypto.com",
            started_at=100.0,
            completed_at=105.0,
            input_hash="hash_in",
            output_hash=h_out,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=payload,
            side_effects=[],
            idempotency_key="idemp_001",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.TOR_MANDATORY,
            actual_transport_used="TOR_SOCKS5H",
        )
        d = receipt.to_dict()
        reconstituted = ExecutionReceipt.from_dict(d)
        self.assertEqual(reconstituted.receipt_id, "rcpt_001")
        self.assertEqual(reconstituted.outcome, OutcomeCategory.SUCCESS)
        self.assertEqual(reconstituted.requested_network_policy, NetworkPolicy.TOR_MANDATORY)

    def test_safe_predicate_evaluator(self):
        context = {
            "exit_code": 0,
            "results": {
                "status_code": 200,
                "domain": "crypto.com",
                "items": ["a", "b", "c"]
            }
        }
        self.assertTrue(evaluate_success_condition("exit_code == 0", context))
        self.assertTrue(evaluate_success_condition("results.status_code == 200 and exit_code == 0", context))
        self.assertTrue(evaluate_success_condition("'a' in results.items", context))
        self.assertFalse(evaluate_success_condition("exit_code != 0", context))
        self.assertFalse(evaluate_success_condition("results.status_code == 404", context))

    def test_deterministic_assurance_scoring(self):
        # Authoritative local with 2 corroborations and 0 contradictions
        score = calculate_assurance_score(
            reliability=ReliabilityClass.AUTHORITATIVE_LOCAL,
            corroboration_count=2,
            contradiction_count=0,
        )
        self.assertGreaterEqual(score, 0.95)

        # Passive recon with 1 contradiction
        penalized_score = calculate_assurance_score(
            reliability=ReliabilityClass.PASSIVE_RECON,
            corroboration_count=1,
            contradiction_count=1,
        )
    def test_capability_registry(self):
        from ciph.capabilities.registry import CapabilityRegistry
        from ciph.capabilities.base import BaseCapability

        class MockReconCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="mock.recon",
                    description="Mock recon capability",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.TOR_MANDATORY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                return {"success": True, "target": params.get("target"), "found": 42}

        reg = CapabilityRegistry()
        mock_cap = MockReconCapability()
        reg.register(mock_cap)

        self.assertIn("mock.recon", reg.list_names())
        receipt = reg.dispatch("mock.recon", {"target": "example.com"})
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.outcome, OutcomeCategory.SUCCESS)
        self.assertEqual(receipt.results["found"], 42)
        self.assertEqual(receipt.requested_network_policy, NetworkPolicy.TOR_MANDATORY)

    def test_ciph_runtime_execution(self):
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability

        class LocalMathCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="math.multiply",
                    description="Multiply two numbers",
                    risk_tier=RiskTier.NONE,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                a = params.get("a", 0)
                b = params.get("b", 0)
                return {"success": True, "result": a * b}

        runtime = CiphRuntime()
        runtime.register_capability(LocalMathCapability())

        receipt = runtime.route_and_execute("math.multiply", {"a": 6, "b": 7})
    def test_network_denied_policy_enforcement(self):
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability

        class BlockedCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="dangerous.exploit",
                    description="Blocked exploit",
                    risk_tier=RiskTier.CRITICAL,
                    network_policy=NetworkPolicy.NETWORK_DENIED,
                    reversibility=ReversibilityClass.IRREVERSIBLE,
                    authorization=AuthorizationTier.MANDATORY_INTERRUPT,
                )

            def run(self, params, context=None):
                return {"success": True, "pwned": True}

        runtime = CiphRuntime()
        runtime.register_capability(BlockedCapability())

        receipt = runtime.route_and_execute("dangerous.exploit", {})
        self.assertEqual(receipt.exit_code, 1)
        self.assertEqual(receipt.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertIn("NETWORK_DENIED", receipt.results["error"])

    def test_sports_adapter_manifest(self):
        from ciph.capabilities.registry import SportsPredictCapability

        class MockSportsPredictor:
            def predict_match(self, home, away):
                return {"home": home, "away": away, "winner": home}

        cap = SportsPredictCapability(MockSportsPredictor())
        self.assertEqual(cap.manifest.network_policy, NetworkPolicy.DIRECT_APPROVED)
        receipt = cap.execute({"home": "Arsenal", "away": "Chelsea"})
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.results["prediction"]["winner"], "Arsenal")


if __name__ == "__main__":
    unittest.main()
