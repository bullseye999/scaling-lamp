
"""
test_ciph_stage4_epistemic_loop.py - Verification for Stage 4 Autonomous Epistemic Closed-Loop.
"""

import os
import time
import unittest

from ciph.runtime import CiphRuntime
from ciph.epistemic.closed_loop import EpistemicClosedLoopDaemon
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.perception.observation import ReliabilityClass


class TestCiphStage4EpistemicLoop(unittest.TestCase):
    TEST_DB = "test_stage4_epistemic.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.auth_key = b"stage4_epistemic_auth_key_32b!"
        self.runtime = CiphRuntime(db_path=self.TEST_DB, auth_secret_key=self.auth_key)
        self.daemon = EpistemicClosedLoopDaemon()

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_epistemic_cycle_refreshes_stale_claims(self):
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


if __name__ == "__main__":
    unittest.main()
