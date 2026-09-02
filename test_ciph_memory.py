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
        # 1. Create Parent Claim (Server IP)
        parent = TransmutationNode(
            claim_id="CLM-PARENT",
            subject="server_x",
            predicate="ip_address",
            value="192.168.1.10",
            state=EpistemicCategory.SUPPORTED,
            reliability=ReliabilityClass.AUTHORITATIVE_LOCAL,
            assurance_score=0.95
        )
        self.worldview.upsert_claim(parent)

        # 2. Create Child Claim (Nginx Port on Server IP)
        child = TransmutationNode(
            claim_id="CLM-CHILD-1",
            subject="server_x",
            predicate="port_80_open",
            value=True,
            state=EpistemicCategory.SUPPORTED,
            reliability=ReliabilityClass.DIRECT_SENSOR,
            assurance_score=0.85,
            parent_claim_ids=["CLM-PARENT"]
        )
        self.worldview.upsert_claim(child)

        # Verify active query returns both
        active = self.worldview.query_active_claims()
        self.assertEqual(len(active), 2)

        # 3. Test Invalidation Circuit Breaker (Transient Glitch)
        # Dispute parent claim
        disp_res = self.forgetting.dispute_claim("CLM-PARENT", {"error": "Connection timed out"})
        self.assertTrue(disp_res["success"])
        self.assertEqual(disp_res["state"], "DISPUTED")

        # Child claim is PRESERVED (zero memory wipeout)
        child_retrieved = self.worldview.get_claim("CLM-CHILD-1")
        self.assertEqual(child_retrieved.state, EpistemicCategory.SUPPORTED)

        # 4. Restore disputed claim
        rest_res = self.forgetting.restore_disputed_claim("CLM-PARENT")
        self.assertTrue(rest_res["success"])
        self.assertEqual(self.worldview.get_claim("CLM-PARENT").state, EpistemicCategory.SUPPORTED)

        # 5. Test TOCTOU protection on Supersession
        lease_id = self.leases.acquire_claim_leases(["CLM-PARENT"], "worker-2", "JOB-202", ttl_seconds=10)
        # Attempt to supersede while worker is actively running
        toctou_res = self.forgetting.confirm_supersession("CLM-PARENT", "CLM-NEW", force=False)
        self.assertFalse(toctou_res["success"])
        self.assertEqual(toctou_res["error"], "TOCTOU_COLLISION_DETECTED")

        # Worker finishes and releases lease
        self.leases.release_lease(lease_id)

        # 6. Confirmed Supersession
        # Now supersede cleanly
        sup_res = self.forgetting.confirm_supersession("CLM-PARENT", "CLM-NEW", force=False)
        self.assertTrue(sup_res["success"])
        self.assertEqual(sup_res["cascaded_stale_count"], 1)

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
        # 1. Gen 1: Root Domain
        root = TransmutationNode(
            claim_id="CLM-ROOT",
            subject="example.com",
            predicate="domain_active",
            value=True,
            state=EpistemicCategory.SUPPORTED,
            reliability=ReliabilityClass.AUTHORITATIVE_LOCAL,
            assurance_score=0.99
        )
        self.worldview.upsert_claim(root)

        # 2. Gen 2: Subdomain
        child = TransmutationNode(
            claim_id="CLM-SUB",
            subject="api.example.com",
            predicate="subdomain_active",
            value=True,
            state=EpistemicCategory.SUPPORTED,
            parent_claim_ids=["CLM-ROOT"]
        )
        self.worldview.upsert_claim(child)

        # 3. Gen 3: API Endpoint
        grandchild = TransmutationNode(
            claim_id="CLM-ENDPOINT",
            subject="api.example.com/v1/auth",
            predicate="endpoint_active",
            value=True,
            state=EpistemicCategory.SUPPORTED,
            parent_claim_ids=["CLM-SUB"]
        )
        self.worldview.upsert_claim(grandchild)

        # 4. Supersede ROOT claim
        sup_res = self.forgetting.confirm_supersession("CLM-ROOT", "CLM-ROOT-NEW", force=True)
        self.assertTrue(sup_res["success"])
        self.assertEqual(sup_res["cascaded_stale_count"], 2)
        self.assertIn("CLM-SUB", sup_res["cascaded_claim_ids"])
        self.assertIn("CLM-ENDPOINT", sup_res["cascaded_claim_ids"])

        # All descendants are STALE
        self.assertEqual(self.worldview.get_claim("CLM-SUB").state, EpistemicCategory.STALE)
        self.assertEqual(self.worldview.get_claim("CLM-ENDPOINT").state, EpistemicCategory.STALE)

    def test_decay_profiles_and_ttl_expiration(self):
        """Verify decay profile computation and automated reaping of stale claims."""
        from ciph.memory.materialized_views import DecayProfile

        now = time.time()
        # 1. Live network state with 300s TTL
        net_deadline = self.worldview.get_decay_deadline(DecayProfile.LIVE_NETWORK_STATE, from_time=now)
        self.assertEqual(net_deadline, now + 300.0)

        # 2. Mathematical fact (no decay)
        math_deadline = self.worldview.get_decay_deadline(DecayProfile.MATHEMATICAL_FACT, from_time=now)
        self.assertIsNone(math_deadline)

        # 3. Store expired claim
        expired_node = TransmutationNode(
            claim_id="CLM-EXPIRED",
            subject="gateway.target.com",
            predicate="latency_ms",
            value=45,
            state=EpistemicCategory.SUPPORTED,
            freshness_deadline=now - 10.0,
            created_at=now - 100.0
        )
        self.worldview.upsert_claim(expired_node)

        # Active claims query should exclude expired claim
        active = self.worldview.query_active_claims(subject="gateway.target.com")
        self.assertEqual(len(active), 0)

        # Run reap_expired_claims
        reaped = self.worldview.reap_expired_claims(current_time=now)
        self.assertEqual(reaped, 1)
        self.assertEqual(self.worldview.get_claim("CLM-EXPIRED").state, EpistemicCategory.STALE)

    def test_contradiction_detection_and_quarantine(self):
        """Verify conflicting observations trigger automatic quarantine to DISPUTED."""
        # Baseline claim: Server status is ONLINE
        node1 = TransmutationNode(
            claim_id="CLM-STATUS-01",
            subject="api.ciph.local",
            predicate="system_status",
            value="ONLINE",
            state=EpistemicCategory.SUPPORTED,
            reliability=ReliabilityClass.DIRECT_SENSOR,
            assurance_score=0.90
        )
        res1 = self.worldview.detect_and_handle_contradiction(node1)
        self.assertFalse(res1["contradiction_detected"])

        # Conflicting claim: Server status is OFFLINE
        node2 = TransmutationNode(
            claim_id="CLM-STATUS-02",
            subject="api.ciph.local",
            predicate="system_status",
            value="OFFLINE",
            state=EpistemicCategory.OBSERVED,
            reliability=ReliabilityClass.DIRECT_SENSOR,
            assurance_score=0.85
        )
        res2 = self.worldview.detect_and_handle_contradiction(node2)
        self.assertTrue(res2["contradiction_detected"])
        self.assertIn("CLM-STATUS-01", res2["disputed_claim_ids"])
        self.assertIn("CLM-STATUS-02", res2["disputed_claim_ids"])

        # Verify both are now quarantined as DISPUTED
        self.assertEqual(self.worldview.get_claim("CLM-STATUS-01").state, EpistemicCategory.DISPUTED)
        self.assertEqual(self.worldview.get_claim("CLM-STATUS-02").state, EpistemicCategory.DISPUTED)

    def test_tabu_graveyard_quarantine(self):
        """Verify refuted hypotheses are buried in Tabu Graveyard and prevent redundant queries."""
        grave_id = self.worldview.bury_in_graveyard(
            subject="exploit.cve_2026_1111",
            predicate="vulnerable",
            reason="Patch verified in kernel 6.8.0-2026",
            refuted_value=True,
            negative_evidence={"exit_code": 1, "tested_at": time.time()}
        )
        self.assertTrue(grave_id.startswith("GRV-"))

        # Check Tabu Graveyard index
        self.assertTrue(self.worldview.is_in_graveyard("exploit.cve_2026_1111", "vulnerable"))
        self.assertFalse(self.worldview.is_in_graveyard("exploit.cve_2026_9999", "vulnerable"))

        # Query graveyard
        graves = self.worldview.query_graveyard()
        self.assertEqual(len(graves), 1)
        self.assertEqual(graves[0]["subject"], "exploit.cve_2026_1111")
        self.assertIn("Patch verified", graves[0]["reason"])


if __name__ == "__main__":
    unittest.main()
