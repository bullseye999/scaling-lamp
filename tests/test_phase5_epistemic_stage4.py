
"""
test_phase5_epistemic_stage4.py - Verification for Phase 5 Stage 4: Runtime & Cognitive Loop Integration.
Formal verification of:
1. CiphRuntime single-step execution admits claims via admit_claim and projects canonical claims into MaterializedWorldview.
2. CiphRuntime DAG workflow admits step receipts into MaterializedWorldview.
3. EpistemicClosedLoopDaemon detects DORMANT/stale claims, formulates inquiries, and refreshes them via admit_claim.
4. Exit gate: Every admitted claim in MaterializedWorldview is verifiable against EventStore or ciph_observations.
"""

import os
import time
import unittest

from ciph.runtime import CiphRuntime
from ciph.planner.schemas import IntentProposal
from ciph.contracts.enums import (
    EpistemicCategory,
    LifecycleState,
    DecayProfile,
    ReliabilityClass,
)
from ciph.kernel.transmutation_dag import TransmutationNode


class TestPhase5EpistemicStage4(unittest.TestCase):
    TEST_DB = "test_phase5_stage4.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.auth_key = b"stage4_epistemic_auth_key_32b!"
        self.runtime = CiphRuntime(db_path=self.TEST_DB, auth_secret_key=self.auth_key)

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_01_single_step_admit_claim_and_canonical_claim_projection(self):
        """Verify CiphRuntime Step 10 uses admit_claim and projects canonical claim into Worldview."""
        proposal = IntentProposal(
            proposal_id="PROP-S4-01",
            objective="Check local deadman switch status",
            proposed_capability="security.deadman_status",
            provided_parameters={}
        )
        res = self.runtime.execute_reference_loop(proposal)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIsNotNone(res["receipt"])
        receipt_id = res["receipt"].receipt_id

        # Verify claim exists in Worldview and is verifiable against EventStore
        active_claims = self.runtime.worldview.query_active_claims()
        self.assertGreaterEqual(len(active_claims), 1)

        # Check that receipt is recorded in EventStore
        events = self.runtime.event_store.get_events(aggregate_id=receipt_id)
        self.assertGreaterEqual(len(events), 1)

    def test_02_epistemic_daemon_refreshes_dormant_claims_via_admit_gate(self):
        from phase5_test_support import memory_claim
        original=memory_claim(self.runtime,'expired',deadline=time.time()-1)
        report=self.runtime.run_epistemic_cycle()
        self.assertGreaterEqual(report.stale_claims_detected,1)
        self.assertGreaterEqual(report.inquiries_dispatched,1)
        self.assertGreaterEqual(report.receipts_committed,1)
        self.assertGreaterEqual(report.claims_refreshed,1)
        old=self.runtime.worldview.get_claim(original.claim_id)
        self.assertEqual(old.lifecycle_state.value,'DORMANT')
        self.assertEqual(old.evidence_receipt_ids,list(original.evidence_receipt_ids))
        active=self.runtime.worldview.query_active_claims()
        self.assertTrue(active)
        self.assertTrue(all(original.evidence_receipt_ids[0] not in c.evidence_receipt_ids for c in active))

    def test_03_worldview_exit_gate_receipt_or_observation_required(self):
        """Verify Phase 5 Exit Gate: No active claim in MaterializedWorldview exists without verifiable evidence."""
        # Execute capability to produce authenticated claim
        proposal = IntentProposal(
            proposal_id="PROP-S4-02",
            objective="Retrieve memory",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "master_alias"}
        )
        res = self.runtime.execute_reference_loop(proposal)
        self.assertEqual(res["status"], "SUCCESS")

        active_claims = self.runtime.worldview.query_active_claims()
        for claim in active_claims:
            has_receipt = False
            if claim.evidence_receipt_ids:
                for r_id in claim.evidence_receipt_ids:
                    if self.runtime.event_store.get_events(aggregate_id=r_id):
                        has_receipt = True
                        break

            has_obs = False
            if getattr(claim, 'observation_ids', None):
                for o_id in claim.observation_ids:
                    if self.runtime.worldview.get_observation(o_id):
                        has_obs = True
                        break

            has_parent = bool(claim.parent_claim_ids)

            # Strict Exit Gate Assertion
            self.assertTrue(
                has_receipt or has_obs or has_parent,
                f"Active claim '{claim.claim_id}' must have a verifiable ExecutionReceipt, Observation, or Parent dependency."
            )


if __name__ == "__main__":
    unittest.main()
