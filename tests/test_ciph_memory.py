from ciph.runtime import CiphRuntime
from ciph.contracts.enums import LifecycleState, DecayProfile
from phase5_test_support import claim, receipt
"""
test_ciph_memory.py - Unit tests for CIPH 4.0 Event Store, Claim Leases, and Active Forgetting.
"""

import os
import unittest
import time
from ciph.memory.event_store import EventStore
from ciph.memory.claim_leases import ClaimLeaseManager
from ciph.memory.materialized_views import MaterializedWorldview
from ciph.memory.active_forgetting import ActiveForgettingEngine
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.perception.observation import ReliabilityClass


class TestCiphMemory(unittest.TestCase):
    TEST_DB = "test_ciph_memory.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.event_store = EventStore(self.TEST_DB)
        self.leases = ClaimLeaseManager(self.TEST_DB)
        self.worldview = MaterializedWorldview(self.TEST_DB)
        self.forgetting = ActiveForgettingEngine(
            worldview=self.worldview,
            leases=self.leases,
            event_store=self.event_store,
            db_path=self.TEST_DB
        )

    def tearDown(self):
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_event_store_hash_chaining_and_integrity(self):
        # Append 3 events
        ev1 = self.event_store.append_event("ClaimCreated", "CLM-001", {"subject": "srv1", "port": 22})
        ev2 = self.event_store.append_event("ReceiptLinked", "CLM-001", {"receipt": "rcpt_1"})
        ev3 = self.event_store.append_event("ClaimCreated", "CLM-002", {"subject": "srv2", "port": 80})

        self.assertEqual(ev1, 1)
        self.assertEqual(ev2, 2)
        self.assertEqual(ev3, 3)

        # Verify integrity
        valid, corrupt_id = self.event_store.verify_integrity()
        self.assertTrue(valid)
        self.assertIsNone(corrupt_id)

    def test_claim_leases_anti_toctou(self):
        # Acquire lease for worker on claim CLM-001
        lease_id = self.leases.acquire_claim_leases(["CLM-001"], "worker-1", "JOB-101", ttl_seconds=10)
        self.assertTrue(self.leases.is_claim_pinned("CLM-001"))
        self.assertFalse(self.leases.is_claim_pinned("CLM-002"))

        # Pinning worker details
        pinners = self.leases.get_pinning_workers("CLM-001")
        self.assertEqual(len(pinners), 1)
        self.assertEqual(pinners[0]['worker_id'], "worker-1")

        # Release lease
        self.leases.release_lease(lease_id)
        self.assertFalse(self.leases.is_claim_pinned("CLM-001"))

    def test_materialized_worldview_and_active_forgetting(self):
        runtime=CiphRuntime(db_path=self.TEST_DB)
        self.worldview=runtime.worldview
        forgetting=runtime.active_forgetting
        parent=claim(runtime,'parent')
        claim(runtime,'child',parents=['parent'])
        self.assertEqual(len(self.worldview.query_active_claims()),2)
        self.assertFalse(forgetting.dispute_claim('parent',{'error':'timeout'})['success'])
        negative=receipt(runtime,{'status':'OFFLINE'})
        result=forgetting.dispute_claim('parent',{'receipt_id':negative.receipt_id})
        self.assertTrue(result['success'])
        self.assertEqual(self.worldview.get_claim('child').state,EpistemicCategory.DISPUTED)
        self.assertIsNotNone(self.worldview.get_claim('child'))
        self.assertFalse(forgetting.restore_disputed_claim('parent')['success'])
        lease=self.leases.acquire_claim_leases(['parent'],'worker','job',ttl_seconds=10)
        self.assertEqual(forgetting.confirm_supersession('parent','missing')['error'],'TOCTOU_COLLISION_DETECTED')
        self.leases.release_lease(lease)
        self.assertEqual(forgetting.confirm_supersession('parent','missing')['error'],'AUTHENTIC_SUCCESSOR_REQUIRED')
        runtime.close()

    def test_claim_leases_multi_claim_atomic(self):
        # Acquire atomic lease across multiple claims
        claim_list = ["CLM-101", "CLM-102", "CLM-103"]
        lease_id = self.leases.acquire_claim_leases(claim_list, "worker-multi", "JOB-MULTI", ttl_seconds=15)
        
        # All claims must be pinned
        for cid in claim_list:
            self.assertTrue(self.leases.is_claim_pinned(cid))
        self.assertFalse(self.leases.is_claim_pinned("CLM-OTHER"))

        # Release lease unlocks all
        self.leases.release_lease(lease_id)
        for cid in claim_list:
            self.assertFalse(self.leases.is_claim_pinned(cid))

    def test_recursive_multi_generation_active_forgetting_cascade(self):
        runtime=CiphRuntime(db_path=self.TEST_DB)
        claim(runtime,'root');claim(runtime,'child',parents=['root']);claim(runtime,'grandchild',parents=['child'])
        result=runtime.worldview.propagate_invalidation_cascade('root')
        self.assertEqual(result['invalidated_count'],2)
        for cid in ('child','grandchild'):
            node=runtime.worldview.get_claim(cid)
            self.assertEqual(node.lifecycle_state,LifecycleState.DORMANT)
            self.assertEqual(node.state,EpistemicCategory.VERIFIED_REAL)
        self.assertEqual(runtime.worldview.query_active_claims(),[])
        runtime.close()

    def test_decay_profiles_and_ttl_expiration(self):
        now=time.time()
        self.assertEqual(self.worldview.get_decay_deadline(DecayProfile.LIVE_NETWORK_STATE,now),now+300)
        self.assertIsNone(self.worldview.get_decay_deadline(DecayProfile.MATHEMATICAL_FACT,now))
        runtime=CiphRuntime(db_path=self.TEST_DB)
        candidate=claim(runtime,'expiring')
        self.assertEqual(runtime.worldview.reap_expired_claims(candidate.freshness_deadline+1),1)
        self.assertEqual(runtime.worldview.get_claim('expiring').state,candidate.epistemic_state)
        self.assertEqual(runtime.worldview.get_claim('expiring').lifecycle_state,LifecycleState.DORMANT)
        self.assertEqual(runtime.worldview.query_active_claims(),[])
        runtime.close()

    def test_contradiction_detection_and_quarantine(self):
        runtime=CiphRuntime(db_path=self.TEST_DB)
        first=claim(runtime,'online')
        second=claim(runtime,'offline',value='OFFLINE',admit=False)
        result=runtime.worldview.detect_and_handle_contradiction(second)
        self.assertTrue(result['contradiction_detected'])
        self.assertEqual(set(result['disputed_claim_ids']),{'online','offline'})
        self.assertEqual(runtime.worldview.query_active_claims(),[])
        runtime.close()

    def test_tabu_graveyard_quarantine(self):
        runtime=CiphRuntime(db_path=self.TEST_DB)
        candidate=claim(runtime,'buried')
        grave=runtime.worldview.bury_in_graveyard(candidate.subject,candidate.predicate,'maintenance suppression',claim_id=candidate.claim_id)
        self.assertTrue(grave.startswith('GRV-'))
        self.assertTrue(runtime.worldview.is_in_graveyard(candidate.subject,candidate.predicate))
        self.assertFalse(runtime.worldview.is_in_graveyard('different',candidate.predicate))
        self.assertEqual(runtime.worldview.get_claim(candidate.claim_id).state,candidate.epistemic_state)
        self.assertEqual(runtime.worldview.get_claim(candidate.claim_id).lifecycle_state,LifecycleState.ARCHIVED)
        runtime.close()


if __name__ == "__main__":
    unittest.main()
