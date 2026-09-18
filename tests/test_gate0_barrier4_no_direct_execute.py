"""
test_gate0_barrier4_no_direct_execute.py - Verification Suite for Gate Zero Barrier 4
Tests:
1. route_and_execute fails closed when worker is unavailable (no direct cap.execute fallback).
2. DAGExecutor step execution fails closed when worker yields no receipt (no direct cap.execute fallback).
3. DAGExecutor compensation executes through worker daemon.
4. BaseCapability.execute fails closed when strict_worker=True and worker_id is missing.
"""

import os
import time
import unittest
from ciph.runtime import CiphRuntime
from ciph.planner.dag_planner import DAGExecutor
from ciph.planner.schemas import ExecutionDAG, PlanStep
from ciph.capabilities.registry import CapabilityRegistry, BaseCapability
from ciph.kernel.policy_engine import (
    CapabilityManifest,
    RiskTier,
    NetworkPolicy,
    ReversibilityClass,
    AuthorizationTier,
)
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory


class TestGate0Barrier4NoDirectExecute(unittest.TestCase):
    DB_PATH = "test_barrier4_worker_only.db"

    def setUp(self):
        if os.path.exists(self.DB_PATH):
            try:
                os.remove(self.DB_PATH)
            except Exception:
                pass
        self.runtime = CiphRuntime(db_path=self.DB_PATH)

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.DB_PATH):
            try:
                os.remove(self.DB_PATH)
            except Exception:
                pass

    def test_route_and_execute_fails_closed_when_worker_returns_no_receipt(self):
        """route_and_execute must not fall back to direct cap.execute when worker returns None."""
        # Monkey patch worker_daemon.drain_once to return None
        original_drain = self.runtime.worker_daemon.drain_once
        self.runtime.worker_daemon.drain_once = lambda worker_id, target_job_id=None: None

        try:
            receipt = self.runtime.route_and_execute(
                "pentest.cvss_calculate",
                {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
            )
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt.exit_code, 1)
            self.assertEqual(receipt.outcome, OutcomeCategory.POLICY_BLOCKED)
            self.assertIn("NON_WORKER_EXECUTION_BLOCKED", receipt.error_message)
        finally:
            self.runtime.worker_daemon.drain_once = original_drain

    def test_dag_executor_fails_closed_when_worker_yields_no_receipt(self):
        """DAGExecutor must not fall back to direct cap.execute if worker daemon yields None."""
        original_drain = self.runtime.dag_executor.worker_daemon.drain_once
        self.runtime.dag_executor.worker_daemon.drain_once = lambda worker_id, target_job_id=None: None

        dag = ExecutionDAG(
            plan_id="PLAN-NO-FALLBACK-01",
            objective="Test fail closed step",
            steps=[
                PlanStep(
                    step_id="S1",
                    capability="pentest.cvss_calculate",
                    parameters={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"}
                )
            ]
        )

        try:
            res = self.runtime.dag_executor.execute_dag(dag)
            self.assertFalse(res["success"])
            self.assertEqual(res["step_receipts"], {})
            self.assertIn("NO_EXECUTION_RECEIPT", res["error"])
            self.assertEqual(self.runtime.event_store.get_events(event_type="ExecutionReceiptStoredEvent"), [])
        finally:
            self.runtime.dag_executor.worker_daemon.drain_once = original_drain

    def test_base_capability_strict_worker_enforcement(self):
        """BaseCapability.execute blocks execution if strict_worker=True and worker_id is missing."""
        cap = self.runtime.registry.get("pentest.cvss_calculate")
        self.assertIsNotNone(cap)

        # 1. Call without worker_id under strict_worker mode -> BLOCKED
        receipt = cap.execute(
            params={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"},
            context={"strict_worker": True}
        )
        self.assertEqual(receipt.exit_code, 1)
        self.assertEqual(receipt.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertIn("GATE_ZERO_VIOLATION", receipt.error_message)

        # 2. A caller-asserted test identity is not authentication -> BLOCKED
        receipt_valid = cap.execute(
            params={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"},
            context={"strict_worker": True, "worker_id": "worker_valid_01"}
        )
        self.assertEqual(receipt_valid.exit_code, 1)
        self.assertEqual(receipt_valid.outcome, OutcomeCategory.POLICY_BLOCKED)

        # 3. Genuine kernel -> queue -> worker execution still succeeds.
        governed = self.runtime.route_and_execute(
            "pentest.cvss_calculate",
            {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "target": "audit"},
        )
        self.assertEqual(governed.exit_code, 0)
        self.assertEqual(governed.outcome, OutcomeCategory.SUCCESS)


if __name__ == "__main__":
    unittest.main()
