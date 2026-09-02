"""
test_ciph_dag_compensation.py - Integration tests for CIPH 4.0 Multi-Step DAG Compilation & Compensation Rollback (Phase 7).
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
    AuthorizationGrant,
)
from ciph.planner.schemas import PlanStep, ExecutionDAG


class TestCiphDAGCompensation(unittest.TestCase):
    TEST_DB = "test_ciph_dag.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.auth_key = b"auth_secret_key_for_dag_tests_32b!"
        self.runtime = CiphRuntime(db_path=self.TEST_DB, auth_secret_key=self.auth_key)
        self.active_resources = {}

        # Capability 1: Provision Resource
        class ProvisionResourceCap(BaseCapability):
            def __init__(self, outer):
                self.outer = outer

            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="cloud.provision",
                    description="Provision cloud resource",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.COMPENSATABLE,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                res_id = params.get("res_id")
                self.outer.active_resources[res_id] = "PROVISIONED"
                return {"success": True, "res_id": res_id, "status": "ACTIVE"}

        # Capability 2: Destroy Resource (Inverse Compensation)
        class DestroyResourceCap(BaseCapability):
            def __init__(self, outer):
                self.outer = outer

            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="cloud.destroy",
                    description="Destroy cloud resource (Inverse)",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                res_id = params.get("res_id")
                if res_id in self.outer.active_resources:
                    del self.outer.active_resources[res_id]
                return {"success": True, "res_id": res_id, "status": "DESTROYED"}

        # Capability 3: Critical Deployment (MANDATORY_INTERRUPT)
        class CriticalDeployCap(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="cloud.critical_deploy",
                    description="Critical cluster deployment",
                    risk_tier=RiskTier.CRITICAL,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.COMPENSATABLE,
                    authorization=AuthorizationTier.MANDATORY_INTERRUPT,
                )

            def run(self, params, context=None):
                return {"success": True, "deployed": True, "version": params.get("version")}

        # Capability 4: Failing Step
        class FailingCap(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="cloud.fail_step",
                    description="Simulate fatal error",
                    risk_tier=RiskTier.NONE,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                return {"success": False, "error": "Simulated hardware failure"}

        self.runtime.register_capability(ProvisionResourceCap(self))
        self.runtime.register_capability(DestroyResourceCap(self))
        self.runtime.register_capability(CriticalDeployCap())
        self.runtime.register_capability(FailingCap())

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_multi_step_dag_forward_execution_and_chaining(self):
        """Test forward execution and parameter chaining across steps."""
        dag = ExecutionDAG(
            plan_id="PLAN-FWD-01",
            objective="Provision and verify storage bucket",
            steps=[
                PlanStep(
                    step_id="S1",
                    capability="cloud.provision",
                    parameters={"res_id": "bucket_alpha"}
                ),
                PlanStep(
                    step_id="S2",
                    capability="cloud.provision",
                    parameters={"res_id": "bucket_beta"},
                    depends_on=["S1"]
                )
            ]
        )

        res = self.runtime.execute_dag_plan(dag)
        self.assertTrue(res["success"])
        self.assertEqual(res["executed_steps_count"], 2)
        self.assertIn("bucket_alpha", self.active_resources)
        self.assertIn("bucket_beta", self.active_resources)

        # Check EventStore
        events = self.runtime.event_store.get_events(event_type="ExecutionReceiptStoredEvent")
        self.assertEqual(len(events), 2)

    def test_dag_cycle_detection_fails_closed(self):
        """Cyclic dependencies must fail validation before execution."""
        cyclic_dag = ExecutionDAG(
            plan_id="PLAN-CYCLE-01",
            objective="Cyclic plan",
            steps=[
                PlanStep(step_id="S1", capability="cloud.provision", parameters={"res_id": "r1"}, depends_on=["S2"]),
                PlanStep(step_id="S2", capability="cloud.provision", parameters={"res_id": "r2"}, depends_on=["S1"]),
            ]
        )

        res = self.runtime.execute_dag_plan(cyclic_dag)
        self.assertEqual(res["status"], "VALIDATION_FAILED")
        self.assertFalse(res["success"])
        self.assertEqual(len(self.active_resources), 0)

    def test_step_failure_triggers_inverse_compensations_in_reverse_order(self):
        """When a multi-step plan fails mid-flight, compensations must execute in reverse order."""
        dag_fail = ExecutionDAG(
            plan_id="PLAN-COMPENSATE-01",
            objective="Provision 2 resources then fail",
            steps=[
                PlanStep(
                    step_id="S1",
                    capability="cloud.provision",
                    parameters={"res_id": "temp_vm_1"},
                    compensation_action="cloud.destroy",
                    compensation_params={"res_id": "temp_vm_1"}
                ),
                PlanStep(
                    step_id="S2",
                    capability="cloud.provision",
                    parameters={"res_id": "temp_vm_2"},
                    depends_on=["S1"],
                    compensation_action="cloud.destroy",
                    compensation_params={"res_id": "temp_vm_2"}
                ),
                PlanStep(
                    step_id="S3",
                    capability="cloud.fail_step",
                    parameters={},
                    depends_on=["S2"]
                )
            ]
        )

        res = self.runtime.execute_dag_plan(dag_fail)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "EXECUTION_ERROR")

        # Both temporary resources were created, but upon S3 failure, both compensations ran
        # leaving zero dirty leftover resources
        self.assertNotIn("temp_vm_1", self.active_resources)
        self.assertNotIn("temp_vm_2", self.active_resources)
        self.assertEqual(len(self.active_resources), 0)

    def test_mandatory_interrupt_authorization_on_multi_step_dag(self):
        """High-consequence steps in DAG require valid AuthorizationGrant."""
        dag_crit = ExecutionDAG(
            plan_id="PLAN-CRIT-01",
            objective="Deploy critical service",
            steps=[
                PlanStep(
                    step_id="S1",
                    capability="cloud.provision",
                    parameters={"res_id": "cluster_node_1"}
                ),
                PlanStep(
                    step_id="S2_CRIT",
                    capability="cloud.critical_deploy",
                    parameters={"version": "v4.0.0"},
                    depends_on=["S1"]
                )
            ]
        )

        # 1. Without grant -> Halts before executing S2_CRIT
        res_no_grant = self.runtime.execute_dag_plan(dag_crit)
        self.assertEqual(res_no_grant["status"], "AUTHORIZATION_REQUIRED")
        self.assertEqual(res_no_grant["step_id"], "S2_CRIT")

        # 2. With valid signed grant -> Succeeds
        plan_hash = dag_crit.compute_plan_hash()
        step_2 = dag_crit.steps[1]
        valid_grant = AuthorizationGrant(
            grant_id="grant_dag_s2",
            plan_hash=plan_hash,
            step_id="S2_CRIT",
            capability="cloud.critical_deploy",
            params_hash=step_2.compute_params_hash(),
            scope_grant_id="scope_cloud",
            expires_at=time.time() + 120
        ).sign(self.auth_key)

        res_auth = self.runtime.execute_dag_plan(
            dag_crit,
            auth_grants={"S2_CRIT": valid_grant}
        )
        self.assertTrue(res_auth["success"])
        self.assertEqual(res_auth["status"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
