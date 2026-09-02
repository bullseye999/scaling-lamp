"""
test_ciph_curiosity.py - Unit and Integration Tests for CIPH 4.0 Sensory Bus & Curiosity Daemon (Phase 8).
"""

import os
import time
import unittest
from ciph.runtime import CiphRuntime
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.perception.curiosity_daemon import CuriosityDaemon
from ciph.perception.observation import Observation, ReliabilityClass
from ciph.perception.bus import SensoryBus
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier


class TestCiphCuriosity(unittest.TestCase):
    TEST_DB = "test_ciph_curiosity.db"

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

    def test_curiosity_discovers_and_refreshes_stale_claims(self):
        """Test autonomous discovery and refresh of stale epistemic gaps."""
        now = time.time()
        # Insert a stale claim in worldview
        stale_claim = TransmutationNode(
            claim_id="CLM-STALE-MEM",
            subject="memory.vault",
            predicate="active_profile",
            value="old_val",
            state=EpistemicCategory.SUPPORTED,
            freshness_deadline=now - 50.0,
            created_at=now - 200.0
        )
        self.runtime.worldview.upsert_claim(stale_claim)

        # Run curiosity cycle
        results = self.runtime.run_curiosity_cycle()
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "SUCCESS")
        self.assertIsNotNone(results[0]["receipt_id"])

        # Check EventStore recorded the refresh event
        events = self.runtime.event_store.get_events(aggregate_id=results[0]["receipt_id"])
        self.assertEqual(len(events), 1)

    def test_curiosity_respects_tabu_graveyard(self):
        """Claims buried in Tabu Graveyard must not be selected as inquiry gaps."""
        now = time.time()
        # 1. Buried claim
        self.runtime.worldview.bury_in_graveyard(
            subject="exploit.cve_2026_0001",
            predicate="vulnerable",
            reason="Confirmed patched by vendor"
        )
        
        # Insert matching stale node
        stale_refuted = TransmutationNode(
            claim_id="CLM-REFUTED",
            subject="exploit.cve_2026_0001",
            predicate="vulnerable",
            value=True,
            state=EpistemicCategory.STALE,
            freshness_deadline=now - 10.0
        )
        self.runtime.worldview.upsert_claim(stale_refuted)

        gaps = self.runtime.curiosity_daemon.discover_epistemic_gaps(self.runtime.worldview)
        # Must not contain the buried claim
        gap_subjects = [g.subject for g in gaps]
        self.assertNotIn("exploit.cve_2026_0001", gap_subjects)

    def test_curiosity_rate_limiter_budget(self):
        """Inquiries must strictly respect hourly rate limit."""
        daemon = CuriosityDaemon(max_inquiries_per_hour=2)
        now = time.time()

        self.assertTrue(daemon.can_inquire_under_budget(now))
        daemon.record_inquiry(now)
        self.assertTrue(daemon.can_inquire_under_budget(now))
        daemon.record_inquiry(now)

        # Third inquiry blocked
        self.assertFalse(daemon.can_inquire_under_budget(now))

        # After 1 hour, budget resets
        self.assertTrue(daemon.can_inquire_under_budget(now + 3601.0))

    def test_curiosity_strictly_bans_modifying_capabilities(self):
        """Modifying or high-risk capabilities cannot be executed autonomously by curiosity daemon."""
        class HighRiskModifyingCapability(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="code.audit_dependencies",
                    description="High risk code modify",
                    risk_tier=RiskTier.CRITICAL,
                    network_policy=NetworkPolicy.LOCAL_ONLY,
                    reversibility=ReversibilityClass.REVERSIBLE,
                    authorization=AuthorizationTier.MANDATORY_INTERRUPT
                )

            def run(self, params, context=None):
                return {"modified": True}

        # Override capability with high risk manifest
        self.runtime.register_capability(HighRiskModifyingCapability())

        gap_node = TransmutationNode(
            claim_id="CLM-CODE-GAP",
            subject="ciph_core.py",
            predicate="dependencies",
            value="unknown",
            state=EpistemicCategory.INTELLIGENCE_GAP
        )
        self.runtime.worldview.upsert_claim(gap_node)

        results = self.runtime.run_curiosity_cycle()
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "SAFETY_BLOCKED_REQUIRES_OPERATOR")

    def test_sensory_bus_routing(self):
        """Sensory bus dispatches observations to relevant subscribers."""
        bus = SensoryBus()
        tor_events = []
        git_events = []

        bus.subscribe("tor_circuit", lambda obs: tor_events.append(obs))
        bus.subscribe("git_branch", lambda obs: git_events.append(obs))

        bus.publish(Observation(
            observation_id="obs_tor_01",
            source="tor_monitor",
            subject="proxy",
            predicate="tor_circuit",
            value="104.244.72.115",
            reliability_class=ReliabilityClass.DIRECT_SENSOR
        ))

        self.assertEqual(len(tor_events), 1)
        self.assertEqual(len(git_events), 0)
        self.assertEqual(tor_events[0].value, "104.244.72.115")


if __name__ == "__main__":
    unittest.main()
