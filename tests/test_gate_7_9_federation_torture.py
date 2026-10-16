"""
7.14 - the three-node federation torture.

    One Ciph. Many nodes. No node becomes sovereign merely because the others went silent.

Three REAL node processes, each with its own datastore, identity, key and runtime directory. Records
travel between stores EXPLICITLY (a peer process delivering a message into a coordinator's store), which
is what a replication path does - there is no shared database pretending to be a network. Against running
processes, the anchors of 7.x are asserted:

    quorum cannot seize authority          B + C vote about A's domain: effect zero
    evidence merges, authority does not    valid observations union; incompatible lineages conflict
    quiescence honesty                     a silent node is not a quiescent one
    stale rejoin                           epoch 12 cannot walk into epoch 26
    clock attack                           a fast clock wins nothing
    consensus attack                       approved=True has ZERO authority effect
    sovereignty attack                     a favourable projection has ZERO authority effect
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.federation_authority import (DOMAIN_FROZEN, INTEGRITY_CONFLICT, QUORUM_REFUSED,
                                              authority_digest, get_domain, record_partition_view,
                                              safe_mode_for)
from ciph.kernel.federation_keys import (assert_node_key_boundary, key_digest,
                                         node_holds_root_authority)
from ciph.kernel.federation_node import node_digest
from ciph.kernel.federation_quiescence import (DRAINING, QUIESCENT, REVOKED_FROM_AUTHORITY,
                                               emergency_stop, quiescence_digest)
from ciph.kernel.federation_replication import (DUPLICATE, INTEGRITY_CONFLICT as RECON_CONFLICT,
                                                MERGED, authority_winner_by_wall_clock, causal_order,
                                                reconciliation_history, records_for, replication_digest)
from ciph.kernel.federation_scanners import federation_scanner_census
from ciph.kernel.federation_state import classification_digest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = str(ROOT / "federation_test_support.py")
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
NODES = ("N-A", "N-B", "N-C")


class TestFederationTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-714-")
        self.base = Path(self.temp.name)
        self.dbs = {}
        for node in NODES:
            directory = self.base / node
            directory.mkdir()
            self.dbs[node] = str(directory / f"{node}.db")
        self.coordinator = self.dbs["N-A"]

    def tearDown(self):
        self.temp.cleanup()

    # ---------------------------------------------------------------- runtime helpers
    def run_node(self, node, action, *, on_db=None, **arguments):
        """Run one node process. `on_db` delivers this node's action into another node's store."""
        command = [sys.executable, "-B", RUNTIME, on_db or self.dbs[node], "--node", node,
                   "--action", action, "--args", json.dumps(arguments)]
        out = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True, timeout=180)
        self.assertEqual(out.returncode, 0, f"{node}/{action}: {out.stderr}")
        return json.loads(out.stdout.strip().splitlines()[-1])

    def join_all(self):
        return {node: self.run_node(node, "join") for node in NODES}

    # ---------------------------------------------------------------- the torture
    def test_the_three_node_federation_foundation(self):
        joined = self.join_all()
        for node in NODES:
            self.assertEqual(joined[node]["generation"], 1)
            self.assertEqual(joined[node]["membership"], "TRUSTED")
        domain = self.run_node("N-A", "domain", domain="D-1", owner="N-A", scope="core")
        self.assertEqual((domain["owner"], domain["epoch"]), ("N-A", 1))
        allowed = self.run_node("N-A", "attempt", domain="D-1", generation=1, epoch=1)
        self.assertTrue(allowed["allowed"])
        refused = self.run_node("N-B", "attempt", domain="D-1", generation=1, epoch=1,
                                on_db=self.coordinator)
        self.assertFalse(refused["allowed"])
        self.assertEqual(refused["reason"], "NOT_THE_AUTHORITY_OWNER")

    def test_quorum_cannot_seize_authority(self):
        self.join_all()
        self.run_node("N-A", "domain", domain="D-1", owner="N-A", scope="core")
        # A is unreachable from B and C. B and C can reach each other and they agree.
        for observer in ("N-B", "N-C"):
            self.run_node(observer, "barrier", snapshot=["N-A@1", "N-B@1", "N-C@1"],
                          on_db=self.dbs[observer])
        view = record_partition_view(self.dbs["N-B"], observed_by="N-B", reachable=["N-C"],
                                    unreachable=["N-A"])
        self.assertFalse(view["implies_death"])
        self.assertEqual(safe_mode_for(self.coordinator, "D-1", view=view)["mode"], "SAFE_MODE")
        quorum = self.run_node("N-B", "quorum", domain="D-1", voters=["N-B", "N-C"], epoch=1,
                               on_db=self.coordinator)
        self.assertEqual(quorum["disposition"], QUORUM_REFUSED)
        self.assertEqual(quorum["authority_effect"], "none")
        self.assertFalse(quorum["owner_among_voters"])
        for voter in ("N-B", "N-C"):
            attempt = self.run_node(voter, "attempt", domain="D-1", generation=1, epoch=1,
                                    on_db=self.coordinator)
            self.assertFalse(attempt["allowed"], f"{voter} seized a domain it does not own")
        claim = self.run_node("N-C", "claim", domain="D-1", generation=1, epoch=1,
                              on_db=self.coordinator)
        self.assertEqual(claim["status"], INTEGRITY_CONFLICT)
        self.assertFalse(claim["adopted"])
        self.assertEqual(get_domain(self.coordinator, "D-1").owner_node_id, "N-A")
        self.assertEqual(get_domain(self.coordinator, "D-1").authority_epoch, 1)

    def test_evidence_merges_and_incompatible_authority_conflicts(self):
        self.join_all()
        self.run_node("N-A", "domain", domain="D-1", owner="N-A", scope="core")
        first = self.run_node("N-A", "offer", canonical_id="OBS-1", digest=DIGEST_A, epoch=1,
                              sequence=1, family="epistemic_evidence")
        self.assertEqual(first["disposition"], MERGED)
        # B independently observed the SAME thing: one standing record, not two confirmations.
        duplicate = self.run_node("N-B", "offer", canonical_id="OBS-1", digest=DIGEST_A, epoch=1,
                                  sequence=2, family="epistemic_evidence", on_db=self.coordinator)
        self.assertEqual(duplicate["disposition"], DUPLICATE)
        # B independently observed something ELSE: both survive, because evidence is not a contest.
        distinct = self.run_node("N-B", "offer", canonical_id="OBS-2", digest=DIGEST_B, epoch=1,
                                 sequence=3, family="epistemic_evidence", on_db=self.coordinator)
        self.assertEqual(distinct["disposition"], MERGED)
        self.assertEqual(len(records_for(self.coordinator, "epistemic_evidence")), 2)
        # Authority does not merge: B asserting canonical state for A's domain is a CONFLICT.
        # B names its OWN generation against A's epoch: a lineage claim that is not the lineage.
        conflict = self.run_node("N-B", "offer", canonical_id="MSN-9", digest=DIGEST_C, epoch=1,
                                 generation=1, sequence=4, domain="D-1", family="missions",
                                 on_db=self.coordinator)
        self.assertEqual(conflict["disposition"], INTEGRITY_CONFLICT)
        self.assertFalse(conflict["stored"])
        self.assertEqual(conflict["adopted"], False)
        self.assertEqual(conflict["quorum_claim"]["authority_effect"], "none")
        self.assertEqual(get_domain(self.coordinator, "D-1").owner_node_id, "N-A")
        self.assertEqual(reconciliation_history(self.coordinator, "missions")[0]["disposition"],
                         RECON_CONFLICT)

    def test_clock_attack_wins_nothing(self):
        self.join_all()
        ahead = self.run_node("N-B", "offer", canonical_id="OBS-7", digest=DIGEST_B, epoch=1,
                              sequence=5, clock_skew=9999.0, family="epistemic_evidence")
        behind = self.run_node("N-A", "offer", canonical_id="OBS-8", digest=DIGEST_A, epoch=2,
                               sequence=1, clock_skew=-9999.0, family="epistemic_evidence")
        self.assertEqual((ahead["disposition"], behind["disposition"]), (MERGED, MERGED))
        ordered = causal_order(records_for(self.coordinator, "epistemic_evidence"))
        self.assertEqual([item.canonical_id for item in ordered][-1], "OBS-8",
                         "the higher epoch orders first regardless of a clock 9999s behind")
        with self.assertRaises(CrucibleError):
            authority_winner_by_wall_clock(candidates=[{"node": "N-A"}, {"node": "N-B"}])

    def test_quiescence_honesty_across_a_partition(self):
        self.join_all()
        barrier = self.run_node("N-A", "barrier", snapshot=["N-A@1", "N-B@1", "N-C@1"])
        self.run_node("N-A", "ack", barrier=barrier["barrier_id"], generation=1)
        # N-C's acknowledgement ARRIVES at the coordinator (delivered by the C process).
        delivered = self.run_node("N-C", "ack", barrier=barrier["barrier_id"], generation=1,
                                  on_db=self.coordinator)
        self.assertEqual(delivered["status"], DRAINING)
        observed = self.run_node("N-A", "unreach", barrier=barrier["barrier_id"], peer="N-B")
        self.assertEqual(observed["status"], DRAINING, "the federation is NOT quiescent yet")
        self.assertIn("N-B@1", observed["unresolved"])
        settled = self.run_node("N-A", "ack", barrier=barrier["barrier_id"], generation=1,
                                outcome=REVOKED_FROM_AUTHORITY, subject="N-B",
                                on_db=self.coordinator)
        self.assertEqual(settled["status"], QUIESCENT)
        self.assertEqual(settled["unresolved"], [])

    def test_stale_rejoin_is_refused_while_valid_evidence_still_merges(self):
        self.join_all()
        self.run_node("N-A", "domain", domain="D-1", owner="N-A", scope="core")
        stale = self.run_node("N-B", "rejoin", generation=1, presented_epoch=12, current_epoch=26)
        self.assertEqual(stale["disposition"], "STALE_AUTHORITY_EPOCH")
        self.assertFalse(stale["authority_revived"])
        old_generation = self.run_node("N-B", "rejoin", generation=99, presented_epoch=26,
                                       current_epoch=26)
        self.assertEqual(old_generation["disposition"], "STALE_GENERATION")
        current = self.run_node("N-B", "rejoin", generation=1, presented_epoch=26, current_epoch=26)
        self.assertEqual(current["disposition"], "ACCEPTED")
        merged = self.run_node("N-B", "offer", canonical_id="OBS-REJOIN", digest=DIGEST_B, epoch=26,
                               sequence=1, family="epistemic_evidence")
        self.assertEqual(merged["disposition"], MERGED,
                         "its evidence is still valid evidence and merges")

    def test_emergency_stop_during_a_partition(self):
        self.join_all()
        self.run_node("N-A", "domain", domain="D-1", owner="N-A", scope="core")
        stopped = emergency_stop(self.coordinator, actor="operator:operator")
        self.assertEqual(stopped["domains_frozen"], ["D-1"])
        self.assertEqual(stopped["acknowledgements_fabricated"], 0)
        self.assertEqual(get_domain(self.coordinator, "D-1").status, DOMAIN_FROZEN)
        self.assertEqual(get_domain(self.coordinator, "D-1").owner_node_id, "N-A",
                         "emergency stop freezes authority; it does not transfer it")
        attempt = self.run_node("N-A", "attempt", domain="D-1", generation=1, epoch=1)
        self.assertFalse(attempt["allowed"], "a frozen domain refuses even its own owner")

    def test_key_revocation_bounds_the_damage(self):
        self.join_all()
        revoked = self.run_node("N-B", "keys", op="revoke", generation=1)
        self.assertEqual(revoked["revoked"], ["N-B:revoked:1"])
        with self.assertRaises(CrucibleError):
            assert_node_key_boundary(self.dbs["N-B"], node_id="N-B", generation=1)
        self.assertFalse(node_holds_root_authority("N-B")["holds_root_authority"])
        self.assertFalse(node_holds_root_authority("N-A")["holds_root_authority"])
        rotated = self.run_node("N-A", "keys", op="rotate", generation=1, ref="pub-N-A-2")
        self.assertEqual((rotated["state"], rotated["key"].startswith("FNK-")), ("ACTIVE", True))

    def test_consensus_and_sovereignty_attacks_have_zero_authority_effect(self):
        """Both legacy mechanisms may approve whatever they like; nothing here acts on it."""
        self.join_all()
        self.run_node("N-A", "domain", domain="D-1", owner="N-A", scope="core")
        from ciph.swarm.byzantine_consensus import (ByzantineConsensusEngine, ConsensusProposal,
                                                    CouncilNode)
        council = [CouncilNode(node, "council") for node in NODES]
        proposal = ConsensusProposal(proposal_id="P-1", subject="D-1", mutation_type="SEIZE",
                                     details={})
        verdict = ByzantineConsensusEngine(council).evaluate_consensus(
            proposal, [node.vote(proposal, decision="APPROVE") for node in council])
        self.assertTrue(verdict.approved, "the legacy engine does approve; that is the point")
        from ciph.sovereignty.singularity_engine import SovereigntyEngine
        self.assertTrue(SovereigntyEngine().calculate_solvency(
            reserve_override=10_000_000.0).is_solvent,
            "the projection is favourable; that is the point")
        attempt = self.run_node("N-B", "attempt", domain="D-1", generation=1, epoch=1,
                                on_db=self.coordinator)
        self.assertFalse(attempt["allowed"],
                         "an approved verdict and a favourable projection changed nothing")
        self.assertEqual(get_domain(self.coordinator, "D-1").owner_node_id, "N-A")
        census = federation_scanner_census()
        self.assertEqual(census["s03_quorum_verdict_changes_authority"], 0)
        self.assertEqual(census["s05_sovereignty_authorizes_transition"], 0)

    def test_the_whole_federation_reconstructs_across_fresh_processes(self):
        self.join_all()
        self.run_node("N-A", "domain", domain="D-1", owner="N-A", scope="core")
        self.run_node("N-A", "offer", canonical_id="OBS-1", digest=DIGEST_A, epoch=1, sequence=1,
                      family="epistemic_evidence")
        for node in NODES:
            first = self.run_node(node, "digest")
            second = self.run_node(node, "digest")
            self.assertEqual(first["node"], second["node"])
            self.assertEqual(first["replication"], second["replication"])
            self.assertEqual(first["quiescence"], second["quiescence"])
            self.assertTrue(first["node"])
        # The coordinator's full constitutional picture reproduces from a fresh process.
        self.assertTrue(node_digest(self.coordinator))
        self.assertTrue(authority_digest(self.coordinator))
        self.assertTrue(key_digest(self.coordinator))
        self.assertTrue(quiescence_digest(self.coordinator))
        self.assertTrue(replication_digest(self.coordinator))
        self.assertTrue(classification_digest())

    def test_a_fresh_node_datastore_has_no_phantom_federation_state(self):
        fresh = str(self.base / "fresh.db")
        self.assertEqual(records_for(fresh), [])
        self.assertEqual(reconciliation_history(fresh), [])
        self.assertEqual(node_digest(fresh), node_digest(fresh))
        self.assertTrue(classification_digest())
        census = federation_scanner_census()
        self.assertEqual({name: count for name, count in census.items() if count}, {})
        self.assertEqual(len(census), 16)


if __name__ == "__main__":
    unittest.main()
