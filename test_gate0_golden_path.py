"""
test_gate0_golden_path.py - Gate Zero Milestone 0.6 Golden Reference Path
Verifies the end-to-end deterministic golden path for CVSS calculation:
IntentProposal -> DAG Plan -> Policy & Scope -> Queue -> Worker ->
Signed Receipt -> Atomic EventStore Append -> MaterializedWorldview -> Grounded Fact.
"""

import os
import time
import unittest
from ciph.runtime import CiphRuntime
from ciph.planner.schemas import IntentProposal
from ciph.kernel.policy_engine import ScopeGrant, ScopeType
from ciph.workers.receipts import OutcomeCategory


class TestGate0GoldenPath(unittest.TestCase):
    TEST_DB = "test_gate0_golden_path.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.runtime = CiphRuntime(db_path=self.TEST_DB)

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_cvss_golden_path_end_to_end_governance(self):
        """CVSS calculation traverses the complete canonical spine and materializes facts."""
        vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        proposal = IntentProposal(
            proposal_id="prop_cvss_golden_01",
            objective="Calculate critical network vulnerability CVSS score",
            proposed_capability="pentest.cvss_calculate",
            provided_parameters={"vector": vector, "target": "vulnerability_assessment"},
            constraints={"lane": "LANE_1_READ_ONLY"}
        )

        scope = ScopeGrant(
            scope_id="scope_cvss_local",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["vulnerability_assessment"]
        )

        res = self.runtime.execute_reference_loop(
            proposal=proposal,
            scope_grant=scope,
            worker_id="worker_golden_01"
        )

        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "SUCCESS")

        receipt = res["receipt"]
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.capability, "pentest.cvss_calculate")
        self.assertEqual(receipt.outcome, OutcomeCategory.SUCCESS)
        self.assertEqual(receipt.exit_code, 0)
        self.assertIsNotNone(receipt.worker_signature)

        # Mathematical verification of CVSS score
        results = receipt.results
        self.assertIn("base_score", results)
        self.assertEqual(results["base_score"], 9.8)
        self.assertEqual(results["severity"], "CRITICAL")

        # Cryptographic verification in EventStore
        events = self.runtime.event_store.get_events(aggregate_id=receipt.receipt_id)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "ExecutionReceiptStoredEvent")

        # Verify hash chain continuity
        valid_chain, corrupted_id = self.runtime.event_store.verify_integrity()
        self.assertTrue(valid_chain)
        self.assertIsNone(corrupted_id)

        # Verify projection in Materialized Worldview
        claims = self.runtime.worldview.query_active_claims(subject="vulnerability_assessment")
        self.assertGreaterEqual(len(claims), 1)
        self.assertEqual(claims[0].value.get("base_score"), 9.8)
        self.assertIn(receipt.receipt_id, claims[0].evidence_receipt_ids)


if __name__ == "__main__":
    unittest.main()
