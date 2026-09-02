"""
test_ciph_planner_operator.py - Unit tests for CIPH 4.0 DAG Executor, Dialogue Formatter, and Cadence Engine.
"""

import unittest
from ciph.planner.schemas import PlanStep, ExecutionDAG, ReversibilityClass
from ciph.planner.dag_planner import DAGExecutor
from ciph.capabilities.registry import CapabilityRegistry
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, AuthorizationTier
from ciph.operator.dialogue_formatter import DialogueFormatter
from ciph.operator.cadence_engine import CadenceManager, OperatorCadence, AlertSeverity
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.perception.observation import ReliabilityClass


class TestCiphPlannerOperator(unittest.TestCase):

    def test_dag_executor_multi_step_and_compensation(self):
        registry = CapabilityRegistry()
        db_state = {}

        class CreateItemCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="db.create_item",
                    description="Create item in DB",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.COMPENSATABLE,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                item_id = params.get("item_id")
                db_state[item_id] = params.get("val")
                return {"success": True, "item_id": item_id, "status": 200}

        class DeleteItemCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="db.delete_item",
                    description="Delete item from DB (Inverse)",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                item_id = params.get("item_id")
                if item_id in db_state:
                    del db_state[item_id]
                return {"success": True}

        class FailingCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="service.fail_action",
                    description="Action that fails",
                    risk_tier=RiskTier.HIGH,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                return {"success": False, "error": "Simulated hardware error"}

        registry.register(CreateItemCapability())
        registry.register(DeleteItemCapability())
        registry.register(FailingCapability())

        executor = DAGExecutor(registry)

        # 1. Test Successful DAG
        dag_success = ExecutionDAG(
            plan_id="PLAN-SUCCESS-01",
            objective="Create item in database",
            steps=[
                PlanStep(
                    step_id="S1",
                    capability="db.create_item",
                    parameters={"item_id": "item_42", "val": "gold"},
                    reversibility=ReversibilityClass.COMPENSATABLE,
                    compensation_action="db.delete_item",
                    compensation_params={"item_id": "item_42"},
                    success_condition="exit_code == 0 and results.status == 200"
                )
            ]
        )
        res1 = executor.execute_dag(dag_success)
        self.assertTrue(res1["success"])
        self.assertIn("item_42", db_state)

        # 2. Test Failing DAG with Compensation Execution
        dag_fail = ExecutionDAG(
            plan_id="PLAN-FAIL-01",
            objective="Create item then fail",
            steps=[
                PlanStep(
                    step_id="S1",
                    capability="db.create_item",
                    parameters={"item_id": "item_99", "val": "silver"},
                    reversibility=ReversibilityClass.COMPENSATABLE,
                    compensation_action="db.delete_item",
                    compensation_params={"item_id": "item_99"}
                ),
                PlanStep(
                    step_id="S2",
                    capability="service.fail_action",
                    parameters={},
                    depends_on=["S1"]
                )
            ]
        )
        res2 = executor.execute_dag(dag_fail)
        self.assertFalse(res2["success"])
        # Compensation ran -> item_99 removed from db_state
        self.assertNotIn("item_99", db_state)

    def test_dialogue_formatter(self):
        # Format epistemic entry
        entry = DialogueFormatter.format_entry(
            register="INFERENCE",
            content="Staging environment may leak internal endpoints",
            evidence_id="rcpt_66c7f",
            assurance=0.85
        )
        self.assertIn("[INFERENCE]", entry)
        self.assertIn("Evidence: rcpt_66c7f", entry)
        self.assertIn("Assurance: 85%", entry)

        # Format worldview briefing
        claim = TransmutationNode(
            claim_id="CLM-01",
            subject="crypto.com",
            predicate="open_ports",
            value=[443, 80],
            state=EpistemicCategory.SUPPORTED,
            reliability=ReliabilityClass.DIRECT_SENSOR,
            assurance_score=0.90
        )
        briefing = DialogueFormatter.format_worldview_briefing([claim])
        self.assertIn("crypto.com -> open_ports", briefing)
        self.assertIn("[SUPPORTED]", briefing)

    def test_cadence_engine_interrupt_budgeting(self):
        manager = CadenceManager(initial_cadence=OperatorCadence.DEEP_FOCUS)

        # Deep focus: Info and Medium are batched (should_interrupt == False)
        int_info = manager.record_alert("CVE_FEED", "New CVE-2026-999 logged", AlertSeverity.INFO)
        int_med = manager.record_alert("PORT_SCAN", "Port 8080 detected open", AlertSeverity.MEDIUM)
        self.assertFalse(int_info)
        self.assertFalse(int_med)

        # Deep focus: Critical breaks through (should_interrupt == True)
        int_crit = manager.record_alert("INTEGRITY_BREACH", "Vault checksum altered", AlertSeverity.CRITICAL)
        self.assertTrue(int_crit)

        # Transition to Re-engaging -> Generate executive debrief
        manager.set_cadence(OperatorCadence.RE_ENGAGING)
        debrief = manager.generate_executive_debrief()
        self.assertIn("EXECUTIVE DEBRIEF", debrief)
        self.assertIn("CVE_FEED", debrief)
        self.assertIn("PORT_SCAN", debrief)


    def test_real_t0_filesystem_rollback(self):
        import os
        import tempfile
        from pathlib import Path

        # Create temporary working file
        test_file = "test_rollback_target.txt"
        with open(test_file, "w") as f:
            f.write("ORIGINAL_CONTENT_T0")

        registry = CapabilityRegistry()

        class MutateFileCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="fs.mutate_file",
                    description="Mutate file content",
                    risk_tier=RiskTier.MEDIUM,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.REVERSIBLE,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                with open(test_file, "w") as f:
                    f.write("MODIFIED_CONTENT_DIRTY")
                return {"success": True}

        class FailingStepCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="fs.fail_step",
                    description="Fail intentionally",
                    risk_tier=RiskTier.HIGH,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                return {"success": False, "error": "Planned crash"}

        registry.register(MutateFileCapability())
        registry.register(FailingStepCapability())

        executor = DAGExecutor(registry, backups_dir="test_backups")

        dag = ExecutionDAG(
            plan_id="PLAN-ROLLBACK-TEST",
            objective="Mutate file then fail and rollback",
            steps=[
                PlanStep(
                    step_id="S1",
                    capability="fs.mutate_file",
                    parameters={},
                    reversibility=ReversibilityClass.REVERSIBLE
                ),
                PlanStep(
                    step_id="S2",
                    capability="fs.fail_step",
                    parameters={},
                    depends_on=["S1"]
                )
            ]
        )

        res = executor.execute_dag(dag, target_backup_paths=[test_file])
        self.assertFalse(res["success"])

        # Verify file was rolled back cleanly to T₀ content
        with open(test_file, "r") as f:
            restored_content = f.read()
        self.assertEqual(restored_content, "ORIGINAL_CONTENT_T0")

        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)
        import shutil
        if os.path.exists("test_backups"):
            shutil.rmtree("test_backups")

    def test_skill_registry_promotion_and_drift(self):
        from ciph.planner.skill_registry import SkillRegistry
        from ciph.planner.schemas import SkillPromotionTier

        registry = SkillRegistry()
        template = registry.register_candidate(
            signature="recon.takeover_audit",
            parameter_slots=["target_domain"],
            dag_nodes=[
                PlanStep(
                    step_id="S1",
                    capability="cybersecurity.bounty_scan",
                    parameters={"domain": "$target_domain"}
                )
            ],
            precondition_hash="env_hash_v1_0",
            confidence_decay_ttl=3600
        )
        self.assertEqual(template.promotion_tier, SkillPromotionTier.CANDIDATE)

        # Record 2 flawless runs -> auto-promote to VALIDATED
        registry.record_run("recon.takeover_audit", success=True)
        registry.record_run("recon.takeover_audit", success=True)
        self.assertEqual(template.promotion_tier, SkillPromotionTier.VALIDATED)

        # Approve skill -> APPROVED
        self.assertTrue(registry.approve_skill("recon.takeover_audit"))
        self.assertEqual(template.promotion_tier, SkillPromotionTier.APPROVED)

        # Activate skill -> ACTIVE
        self.assertTrue(registry.activate_skill("recon.takeover_audit"))
        self.assertEqual(template.promotion_tier, SkillPromotionTier.ACTIVE)

        # Match with matching env hash -> SUCCESS
        matched_dag = registry.match_and_instantiate(
            signature="recon.takeover_audit",
            runtime_params={"target_domain": "crypto.com"},
            current_env_hash="env_hash_v1_0"
        )
        self.assertIsNotNone(matched_dag)
        self.assertEqual(matched_dag.steps[0].parameters["domain"], "crypto.com")

        # Match with drifted env hash -> None (Cache Miss)
        drifted_dag = registry.match_and_instantiate(
            signature="recon.takeover_audit",
            runtime_params={"target_domain": "crypto.com"},
            current_env_hash="env_hash_v2_DRIFTED"
        )
        self.assertIsNone(drifted_dag)

    def test_sensory_bus_pub_sub(self):
        from ciph.perception.bus import SensoryBus
        from ciph.perception.observation import Observation, ReliabilityClass

        bus = SensoryBus()
        received_obs = []

        bus.subscribe("git_branch", lambda obs: received_obs.append(obs))

        obs = Observation(
            observation_id="obs_999",
            source="perception.git",
            subject="ciph_project",
            predicate="git_branch",
            value="main",
            reliability_class=ReliabilityClass.AUTHORITATIVE_LOCAL
        )
        bus.publish(obs)

        self.assertEqual(len(received_obs), 1)
        self.assertEqual(received_obs[0].value, "main")

    def test_weakest_link_assurance_cap_in_dag(self):
        """Verify weakest-link assurance cap in Transmutation DAG."""
        from ciph.kernel.transmutation_dag import TransmutationDAG, TransmutationNode, EpistemicCategory
        from ciph.perception.observation import ReliabilityClass

        dag = TransmutationDAG()

        # Parent 1: High assurance local fact (0.95)
        p1 = TransmutationNode(
            claim_id="CLM-P1",
            subject="api_service",
            predicate="port",
            value=443,
            state=EpistemicCategory.SUPPORTED,
            reliability=ReliabilityClass.AUTHORITATIVE_LOCAL,
            assurance_score=0.95,
            evidence_receipt_ids=["rcpt_01"]
        )
        # Parent 2: Moderate assurance sensor telemetry (0.60)
        p2 = TransmutationNode(
            claim_id="CLM-P2",
            subject="api_service",
            predicate="response_status",
            value="502_BAD_GATEWAY",
            state=EpistemicCategory.OBSERVED,
            reliability=ReliabilityClass.PASSIVE_RECON,
            assurance_score=0.60,
            evidence_receipt_ids=["rcpt_02"]
        )
        dag.add_node(p1)
        dag.add_node(p2)

        # Derived Inference: API is degrading
        inferred = dag.derive_inference(
            derived_claim_id="CLM-INF-01",
            subject="api_service",
            predicate="health",
            value="DEGRADED",
            parent_claim_ids=["CLM-P1", "CLM-P2"],
            rule_name="bad_gateway_correlation"
        )

        # Assurance must be capped by weakest parent: 0.60 * 0.95 = 0.57
        self.assertEqual(inferred.assurance_score, 0.57)
        self.assertLessEqual(inferred.assurance_score, p2.assurance_score)
        self.assertLessEqual(inferred.assurance_score, p1.assurance_score)
        self.assertEqual(inferred.state, EpistemicCategory.INFERRED)
        self.assertTrue(dag.verify_weakest_link_invariants("CLM-INF-01"))

        # Inferred node inherits all parent evidence receipts
        self.assertIn("rcpt_01", inferred.evidence_receipt_ids)
        self.assertIn("rcpt_02", inferred.evidence_receipt_ids)

    def test_grounded_dialogue_register_formatting(self):
        """Verify epistemic dialogue formatting across categories."""
        # 1. Supported Fact (Assurance >= 0.90)
        fact_node = TransmutationNode(
            claim_id="CLM-FACT-01",
            subject="firewall",
            predicate="status",
            value="ACTIVE",
            state=EpistemicCategory.SUPPORTED,
            assurance_score=0.95,
            evidence_receipt_ids=["rcpt_fw_01"]
        )
        dialogue = DialogueFormatter.format_grounded_response(fact_node)
        self.assertTrue(dialogue.startswith("[FACT]"))
        self.assertIn("Evidence: rcpt_fw_01", dialogue)
        self.assertIn("Assurance: 95%", dialogue)

        # 2. Inferred belief
        inf_node = TransmutationNode(
            claim_id="CLM-INF-01",
            subject="network",
            predicate="congestion",
            value="HIGH",
            state=EpistemicCategory.INFERRED,
            assurance_score=0.65,
            evidence_receipt_ids=["rcpt_traffic"]
        )
        inf_dialogue = DialogueFormatter.format_grounded_response(inf_node)
        self.assertTrue(inf_dialogue.startswith("[INFERENCE]"))

    def test_epistemic_integrity_verification(self):
        """Verify epistemic tagging validator."""
        valid_text = """
        [FACT] Firewall rule applied successfully (Evidence: rcpt_01 | Assurance: 95%)
        [OBSERVATION] Target responded on port 8080 (Assurance: 80%)
        [INFERENCE] Backend proxy is misconfigured (Evidence: rcpt_02 | Assurance: 60%)
        """
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(valid_text))

        invalid_text = """
        [FACT] Firewall rule applied.
        This server is definitely compromised without any evidence tag.
        """
        self.assertFalse(DialogueFormatter.verify_epistemic_integrity(invalid_text))

    def test_hypothesis_card_rendering(self):
        """Verify hypothesis card formatting."""
        card = DialogueFormatter.format_hypothesis_card(
            hypothesis_id="HYP-AUTH-BYPASS",
            premise="JWT token lacks signature verification on /admin endpoint",
            parent_evidence_ids=["rcpt_recon_44"],
            proposed_test="Replay crafted request with None alg header"
        )
        self.assertIn("🧪 [HYPOTHESIS HYP-AUTH-BYPASS]", card)
        self.assertIn("Premise      : JWT token lacks signature verification", card)
        self.assertIn("Grounding Ev : rcpt_recon_44", card)


if __name__ == "__main__":
    unittest.main()
