#!/usr/bin/env python3
"""
test_loop1_v2_evolution.py - Regression & Verification Tests for Loop 1 v2
========================================================================
Validates outward research cycles, weighted operational domains,
scraper search query integration, quality-gated proposal generation,
and quota enforcement under Blueprint §18 / LOOP1_V2_SPEC.
"""

import os
import json
import shutil
import tempfile
import unittest

from cipher_vault import CipherVault
from ciph_evolution import (
    CognitiveEvolutionEngine,
    DynamicSpectrumBalancer,
    KNOWLEDGE_DOMAINS,
)


class TestLoop1V2Evolution(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ciph_loop1_test_")
        self.db_path = os.path.join(self.test_dir, "test_vault.db")
        self.vault = CipherVault(self.db_path)
        self.proposals_dir = os.path.join(self.test_dir, "ciph_proposals")
        os.makedirs(self.proposals_dir, exist_ok=True)
        self.engine = CognitiveEvolutionEngine(self.vault, proposals_dir=self.proposals_dir)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_domain_weights_and_spectrum_balancing(self):
        """Operational domains have top priority weights and balancer selects top-deficit domain."""
        domain_map = {d["id"]: d for d in KNOWLEDGE_DOMAINS}
        
        # 1. Verify weight hierarchy per operator specification
        self.assertEqual(domain_map["runtime_memory_reliability"]["weight"], 35.0)
        self.assertEqual(domain_map["security_ops"]["weight"], 25.0)
        self.assertEqual(domain_map["data_integrity_capability_coverage"]["weight"], 20.0)
        self.assertEqual(domain_map["frontier_ai"]["weight"], 12.0)
        
        humanities_weights = [
            domain_map["macro_history"]["weight"],
            domain_map["epistemology_strategy"]["weight"],
            domain_map["human_psychology"]["weight"],
            domain_map["quantum_physics"]["weight"],
        ]
        self.assertTrue(all(w == 2.0 for w in humanities_weights))
        self.assertEqual(sum(d.get("weight", 0.0) for d in KNOWLEDGE_DOMAINS), 100.0)

        # 2. Deficit-based prioritization when operational domain counts are 0
        balancer = DynamicSpectrumBalancer(self.vault)
        picked = balancer.pick_next_domain()
        # With 0 counts across all domains, Runtime & Memory Reliability (35% target) has highest deficit
        self.assertEqual(picked["id"], "runtime_memory_reliability")

    def test_outward_research_signal_generation(self):
        """Outward research incorporates search queries and falls back safely when offline."""
        runtime_domain = next(d for d in KNOWLEDGE_DOMAINS if d["id"] == "runtime_memory_reliability")
        self.assertIn("search_queries", runtime_domain)
        self.assertGreater(len(runtime_domain["search_queries"]), 0)

        signal = self.engine._fetch_topic_signal(
            runtime_domain,
            "SQLite WAL Mode Concurrency, Checkpointing, and Lock Contention"
        )
        self.assertIsInstance(signal, str)
        self.assertGreater(len(signal), 50)
        self.assertTrue(
            any(kw in signal.lower() for kw in ["sqlite", "lease", "distributed", "concurrency", "heartbeat", "inquiry"]),
            "Signal must contain relevant domain keywords from search or deterministic fallback"
        )

    def test_quality_gate_produces_substantive_diff_for_defective_target(self):
        """A target with a silent swallow yields a proposal whose diff modifies existing lines."""
        from unittest import mock
        runtime_domain = next(d for d in KNOWLEDGE_DOMAINS if d["id"] == "runtime_memory_reliability")
        topic = "Shared Exclusion Locks and Maintenance Window Coordination"
        blueprint = self.engine._generate_deterministic_blueprint(runtime_domain["name"], topic)

        with tempfile.TemporaryDirectory(prefix="loop1-defect-") as td:
            target = os.path.join(td, "defective_module.py")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("def guarded():\n    try:\n        return 1\n    except Exception:\n        pass\n")

            with mock.patch.object(self.engine, "_resolve_ast_target_module", return_value=(target, "guarded")):
                proposal = self.engine._formulate_upgrade_proposal("EXP-QUAL-001", runtime_domain, topic, blueprint, "signal")

            self.assertIsNotNone(proposal, "A defective target must yield a proposal")
            self.assertTrue(proposal["id"].startswith("UP-"))
            self.assertTrue(proposal["observation_id"].startswith("OBS-"))
            self.assertIn("Runtime & Memory Reliability:", proposal["observable_need"])
            self.assertEqual(proposal["status"], "PENDING_OPERATOR_REVIEW")

            # The diff must MODIFY existing code - not merely append comments or a no-op helper.
            lines = proposal["diff"].splitlines()
            removed = [l for l in lines if l.startswith("-") and not l.startswith("---")]
            added = [l for l in lines if l.startswith("+") and not l.startswith("+++")]
            self.assertTrue(removed, "Diff must replace existing code, not only append")
            self.assertTrue(added, "Diff must add real statements")
            self.assertIn("exc_info", proposal["diff"], "Diff must surface the swallowed failure")
            self.assertNotIn("def candidate_invariant_check()", proposal["diff"], "No-op helper is not a change")

            # Rollback stays a staged backup; never a destructive git checkout.
            self.assertNotIn("git checkout", proposal["rollback"])
            self.assertTrue(proposal["rollback"].startswith("restore from ciph_proposals/backups/"))
            self.assertTrue(proposal["test"].startswith("test_upgrade_"))
            self.assertTrue(os.path.exists(proposal["proposal_file"]))
            for key in ("proposal_file", "backup_artifact"):
                path = proposal.get(key)
                if path and os.path.exists(path):
                    os.remove(path)

    def test_quality_gate_refuses_target_without_defect(self):
        """A clean target module yields no proposal: the gate refuses to fabricate a no-op diff."""
        from unittest import mock
        runtime_domain = next(d for d in KNOWLEDGE_DOMAINS if d["id"] == "runtime_memory_reliability")
        topic = "Shared Exclusion Locks and Maintenance Window Coordination"
        blueprint = self.engine._generate_deterministic_blueprint(runtime_domain["name"], topic)

        with tempfile.TemporaryDirectory(prefix="loop1-clean-") as td:
            target = os.path.join(td, "clean_module.py")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("def guarded():\n    try:\n        return 1\n    except ValueError:\n        raise\n")

            with mock.patch.object(self.engine, "_resolve_ast_target_module", return_value=(target, "guarded")):
                proposal = self.engine._formulate_upgrade_proposal("EXP-CLEAN-001", runtime_domain, topic, blueprint, "signal")

            self.assertIsNone(proposal, "Gate must refuse to fabricate a proposal for a clean target")

    def test_substance_ast_target_resolution(self):
        """AST code search maps research topics to appropriate modern modules and nodes."""
        runtime_domain = next(d for d in KNOWLEDGE_DOMAINS if d["id"] == "runtime_memory_reliability")
        cands = runtime_domain["target_modules"]

        # Topic 1: Shared exclusion locks -> exclusion.py / SharedExclusionCoordinator
        mod1, node1 = self.engine._resolve_ast_target_module("Shared Exclusion Locks and Maintenance Window Coordination", cands)
        self.assertEqual(mod1, "ciph/maintenance/exclusion.py")
        self.assertEqual(node1, "SharedExclusionCoordinator")

        # Topic 2: Event store hash chaining -> event_store.py
        mod2, node2 = self.engine._resolve_ast_target_module("Event Store Immutable Hash Chaining and Barrier Snapshot Recovery", cands)
        self.assertEqual(mod2, "ciph/memory/event_store.py")

        # Topic 3: Lease expiry & heartbeat fencing -> ipc_queue.py
        mod3, node3 = self.engine._resolve_ast_target_module("Lease Expiry, Heartbeat Fencing, and Zombie Process Reclamation", cands)
        self.assertEqual(mod3, "ciph/workers/ipc_queue.py")

    def test_slug_collision_deduplication(self):
        """Proposals with identical topic generate disambiguated slugs instead of colliding."""
        from unittest import mock
        runtime_domain = next(d for d in KNOWLEDGE_DOMAINS if d["id"] == "runtime_memory_reliability")
        topic = "Memory Index Compaction, AST Parsing Overhead, and Cache Invalidation"
        blueprint = self.engine._generate_deterministic_blueprint(runtime_domain["name"], topic)
        created = []

        with tempfile.TemporaryDirectory(prefix="loop1-slug-") as td:
            target = os.path.join(td, "defective_module.py")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("def guarded():\n    try:\n        return 1\n    except Exception:\n        pass\n")
            with mock.patch.object(self.engine, "_resolve_ast_target_module", return_value=(target, "guarded")):
                try:
                    prop1 = self.engine._formulate_upgrade_proposal("EXP-SLUG-1", runtime_domain, topic, blueprint, "signal")
                    self.assertIsNotNone(prop1)
                    created.append(prop1)
                    prop2 = self.engine._formulate_upgrade_proposal("EXP-SLUG-2", runtime_domain, topic, blueprint, "signal")
                    self.assertIsNotNone(prop2)
                    created.append(prop2)

                    self.assertNotEqual(prop1["proposal_file"], prop2["proposal_file"])
                    self.assertTrue(prop2["proposal_file"].endswith("_2.py"))
                    self.assertTrue(os.path.exists(prop1["proposal_file"]))
                    self.assertTrue(os.path.exists(prop2["proposal_file"]))
                finally:
                    # Keep the real proposals directory clean so the 4-open quota stays unaffected.
                    for prop in created:
                        for key in ("proposal_file", "backup_artifact"):
                            path = prop.get(key)
                            if path and os.path.exists(path):
                                os.remove(path)

    def test_quota_enforcement_binds_to_disk_proposals(self):
        """Max 4 concurrently open proposals binds to disk files even if pending_upgrades.json is missing."""
        runtime_domain = next(d for d in KNOWLEDGE_DOMAINS if d["id"] == "runtime_memory_reliability")
        blueprint = self.engine._generate_deterministic_blueprint(runtime_domain["name"], "Test Topic")

        # Write 4 proposal files directly to isolated proposals_dir on disk
        for i in range(1, 5):
            fname = f"UP-{i:03d}_mock_test_topic_{i}.py"
            fpath = os.path.join(self.proposals_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(f"# CIPH UPGRADE PROPOSAL UP-{i:03d}\n# Status: PENDING_OPERATOR_REVIEW\n# Title: Mock {i}\n")

        # Remove pending_upgrades.json to prove disk binding
        index_file = os.path.join(self.proposals_dir, "pending_upgrades.json")
        if os.path.exists(index_file):
            os.remove(index_file)

        # 5th candidate must be rejected because disk has 4 open proposals
        prop5 = self.engine._formulate_upgrade_proposal("EXP-DISK-5", runtime_domain, "Topic 5", blueprint, "signal")
        self.assertIsNone(prop5, "Quota gate must count proposals on disk and withhold 5th candidate")

        # Verify index was re-synchronized with all 4 disk proposals
        self.assertTrue(os.path.exists(index_file))
        with open(index_file, "r", encoding="utf-8") as f:
            synced = json.load(f)
        self.assertEqual(len(synced), 4)
        self.assertEqual({p["id"] for p in synced}, {"UP-001", "UP-002", "UP-003", "UP-004"})


if __name__ == "__main__":
    unittest.main()
