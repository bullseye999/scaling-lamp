"""
7.0-7.3, 7.7, 7.8 - the federal foundation.

    Distribution grants reach, not sovereignty.

The specimens that decide whether that is a law or a slogan: a node that changes address without changing
identity, a restart that makes a generation, a handshake that grants nothing, a family of state that
refuses to replicate, a domain nobody but its owner may touch, a quorum that tries to take one anyway,
and a clock that thinks it decides something.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.evolution_ownership import production_sources
from ciph.kernel.federation_authority import (DOMAIN_FROZEN, CLAIM_OK, INTEGRITY_CONFLICT, MODE_NORMAL,
                                             MODE_SAFE, QUORUM_REFUSED, REASON_NOT_OPERATOR,
                                             REASON_NOT_OWNER, REASON_STALE_EPOCH,
                                             assert_authoritative, authority_digest, evaluate_quorum_claim,
                                             get_domain, open_domain, record_partition_view,
                                             reconcile_authority_claim, safe_mode_for,
                                             set_domain_status, transfer_domain)
from ciph.kernel.federation_node import (CANDIDATE, DEGRADED, HEALTH_DEGRADED, HEALTH_QUARANTINE, HEALTHY,
                                         QUARANTINED, REASON_ATTESTATION_MISMATCH,
                                         REASON_SELF_HEALTH, REASON_WORKER_IDENTITY,
                                         REJOIN_ACCEPTED, REJOIN_STALE_EPOCH, REJOIN_STALE_GENERATION,
                                         RETIRED, TRUSTED, UNREACHABLE, assess_node_health, attest_node,
                                         current_generation, evaluate_rejoin, get_node, health_of,
                                         is_current_generation, membership_history, node_digest,
                                         nodes, register_node, retire_node, set_membership,
                                         update_endpoint)
from ciph.kernel.federation_ownership import (CENSUS, RETAINED_MACHINERY, _consumers,
                                              assert_ownership_clean,
                                              authority_shaped_consumers, federation_bypasses,
                                              ownership_digest, retained_machinery_missing,
                                              second_federation_authority)
from ciph.kernel.federation_replication import (AUTHORITY_CONFIRMED, DUPLICATE, KEPT_LOCAL, MERGED,
                                                REBUILT, REFUSED_CLASS, REFUSED_CORRUPT,
                                                REFUSED_NOT_OWNER, REASON_WALL_CLOCK, authority_winner_by_wall_clock,
                                                causal_order, clock_law, offer_record,
                                                reconciliation_history, records_for, reconcile,
                                                replication_digest)
from ciph.kernel.federation_scanners import FEDERATION_SCANNERS, federation_scanner_census
from ciph.kernel.federation_state import (DERIVED_PROJECTION, EPHEMERAL, GLOBAL_CANONICAL, NODE_LOCAL,
                                          REPLICATED_EVIDENCE, REASON_NOT_REPLICABLE,
                                          REASON_UNKNOWN_FAMILY, SECRET_LOCAL, classify,
                                          classification_digest, explain, rebuild_plan, state_class,
                                          travels_in_ordinary_replication)

T1 = 1_800_000_000.0
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


class FederationTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-70-")
        self.db = str(Path(self.temp.name) / "federation.db")

    def tearDown(self):
        self.temp.cleanup()

    def node(self, node_id="N-A", *, endpoint="10.0.0.1:7001", when=T1, public_key_ref=None):
        registered = register_node(self.db, node_id=node_id,
                                   public_key_ref=public_key_ref or f"key-{node_id}",
                                   code_digest="code-1", environment_digest="env-1",
                                   endpoint=endpoint, host_label=node_id.lower(),
                                   actor="operator:operator", now=when)
        return attest_node(self.db, node_id, registered.node_generation,
                           observed_code_digest="code-1", observed_environment_digest="env-1",
                           observed_public_key_ref=public_key_ref or f"key-{node_id}",
                           actor="operator:operator", now=when)

    def three_nodes(self):
        return [self.node(node_id) for node_id in ("N-A", "N-B", "N-C")]

    def domain(self, *, owner="N-A", scope="crucible-promotion", transitions=("PROMOTE",)):
        return open_domain(self.db, domain_id="D-1", scope=scope, owner_node_id=owner,
                           permitted_transitions=list(transitions), actor="operator:operator", now=T1)


class TestR11Census(FederationTestCase):

    def test_r11_census_is_clean_and_the_mechanisms_are_retained(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 19)
        self.assertEqual(retained_machinery_missing(), ())
        self.assertEqual(second_federation_authority(), ())
        self.assertEqual(federation_bypasses(), ())
        self.assertEqual(authority_shaped_consumers(),
                         {"consensus_verdict": (), "ghost_mesh_constitutional": (),
                          "sovereignty_transition": ()})
        self.assertTrue(ownership_digest())
        owners = {concern.canonical_owner for concern in CENSUS}
        for owner in ("ciph/kernel/federation_node.py", "ciph/kernel/federation_authority.py",
                      "ciph/federation/ghost_mesh.py", "ciph/sovereignty/singularity_engine.py"):
            self.assertIn(owner, owners)
        self.assertEqual(len(RETAINED_MACHINERY), 4)

    def test_r11_census_fires_on_a_synthetic_second_authority_owner(self):
        real = dict(production_sources())
        injected = {**real, "ciph/kernel/federation_rogue.py":
                    "def seize(c):\n    c.execute('INSERT INTO ciph_federation_authority_domains "
                    "VALUES (1);')\n"}
        from ciph.kernel.federation_ownership import _consumers, _contains_signal, _is_allowed
        found = [concern.concern for concern in CENSUS
                 if not concern.mechanism_ownership_allowed
                 and any(_contains_signal(injected["ciph/kernel/federation_rogue.py"], signal)
                         for signal in concern.signals)
                 and not _is_allowed("ciph/kernel/federation_rogue.py", concern)]
        self.assertEqual(found, ["authority domains"])

    def test_r11_authority_shaped_consumers_fire_on_a_synthetic_consumer(self):
        real = dict(production_sources())
        injected = {**real, "ciph/kernel/some_decision_maker.py":
                    "from ciph.federation import GhostMeshNode\n\n\ndef decide(node):\n"
                    "    return GhostMeshNode(node)\n",
                    "ciph/kernel/some_promoter.py":
                    "def promote(runtime, proposal_id, grant):\n"
                    "    return runtime.sovereignty.execute_governed_evolution_promotion("
                    "runtime, proposal_id, grant)\n",
                    "ciph/kernel/some_voter.py":
                    "from ciph.swarm import ByzantineConsensusEngine\n\n\ndef decide(engine, "
                    "proposal, votes):\n    return ByzantineConsensusEngine.evaluate_consensus("
                    "engine, proposal, votes)\n"}
        # The real predicate, driven over the synthetic tree.
        self.assertEqual(_consumers(symbols=("GhostMeshNode",), sources=list(injected.items())),
                         ("ciph/kernel/some_decision_maker.py",))
        self.assertEqual(_consumers(symbols=("execute_governed_evolution_promotion",),
                                    sources=list(injected.items())),
                         ("ciph/kernel/some_promoter.py",))
        self.assertEqual(_consumers(symbols=("ByzantineConsensusEngine",),
                                    sources=list(injected.items())),
                         ("ciph/kernel/some_voter.py",))

    def test_sixteen_scanners_are_zero_and_each_fires_on_its_own_violation(self):
        census = federation_scanner_census()
        self.assertEqual(len(census), 16)
        self.assertEqual({name: count for name, count in census.items() if count}, {})
        real = dict(production_sources())
        rogue = "ciph/kernel/federation_rogue.py"
        catches = [
            ("s01_node_self_membership_authorization",
             "def self_enrol(c):\n    c.execute('UPDATE ciph_federation_membership SET event = 1;')\n"),
            ("s02_node_self_authority_domain_assignment",
             "def grab(c):\n    c.execute('UPDATE ciph_federation_authority_domains SET "
             "owner_node_id = 1;')\n"),
            ("s03_quorum_verdict_changes_authority",
             "def decide(engine, p, v):\n    return engine.evaluate_consensus(p, v)\n"),
            ("s04_ghostmesh_changes_authority",
             "def send(node):\n    return MeshTaskEnvelope(node)\n"),
            ("s05_sovereignty_authorizes_transition",
             "def promote(s, runtime, pid, grant):\n"
             "    return s.execute_governed_evolution_promotion(runtime, pid, grant)\n"),
            ("s06_node_permit_signing",
             "def sign(): shape = 'SignedExecutionPermit'\n    return shape\n"),
            ("s07_node_r7_bypass",
             "def activate(target, blob):\n    target.write_bytes(blob)\n"),
            ("s08_node_meta_mutation",
             "def bump(c):\n    c.execute('INSERT INTO ciph_evolution_epochs VALUES (1);')\n"),
            ("s09_universal_last_write_wins",
             "def merge(a, b):\n    return last_write_wins(a, b)\n"),
            ("s10_wall_clock_authority",
             "def winner(records):\n    return sorted(records, key=lambda r: r.wall_time)[-1]\n"),
            ("s11_timeout_as_death",
             "def sweep(node):\n    return assume_dead(node)\n"),
            ("s12_secret_local_replicated",
             "def ship(family):\n    return family == 'SECRET_LOCAL'\n"),
            ("s13_stale_generation_accepted",
             "def use(node):\n    return node.node_generation\n"),
            ("s14_replication_overwrites_owner",
             "def steal(c):\n    c.execute('UPDATE ciph_federation_authority_domains SET 1');\n"),
            ("s15_delegation_widens_scope",
             "def go(delegation):\n    return widen_scope(delegation)\n"),
            ("s16_second_execution_constitution",
             "class FederationExecutor:\n    pass\n"),
        ]
        self.assertEqual(len(catches), 16)
        for name, body in catches:
            with self.subTest(scanner=name):
                self.assertTrue(dict(FEDERATION_SCANNERS)[name]({**real, rogue: body}),
                                f"{name} did not fire on its own synthetic violation")


class TestNodeIdentity(FederationTestCase):

    def test_identity_is_not_address_process_or_worker(self):
        node = self.node("N-A", endpoint="10.0.0.1:7001")
        moved = update_endpoint(self.db, "N-A", node.node_generation, endpoint="192.168.9.9:8080",
                                actor="operator:operator", now=T1 + 1)
        self.assertEqual(moved.node_id, node.node_id)
        self.assertEqual(moved.node_generation, node.node_generation)
        self.assertEqual(moved.endpoint, "192.168.9.9:8080")
        # Events written in the same instant order by id, so compare as a set of facts rather than
        # pretending the microsecond ordering of one registration is constitutional.
        self.assertEqual(sorted(event["event"] for event in membership_history(self.db, "N-A")),
                         sorted(["REGISTER", "ATTEST", TRUSTED, "ENDPOINT_CHANGED"]))

    def test_a_worker_id_cannot_be_enrolled_as_a_node(self):
        import sqlite3
        connection = sqlite3.connect(self.db)
        connection.execute("CREATE TABLE ciph_swarm_workers (worker_id TEXT, instance_generation "
                           "INTEGER);")
        connection.execute("INSERT INTO ciph_swarm_workers VALUES ('W1', 1);")
        connection.commit()
        connection.close()
        with self.assertRaises(CrucibleError) as refused:
            register_node(self.db, node_id="W1", public_key_ref="key-W1", code_digest="c",
                          environment_digest="e", actor="operator:operator", now=T1)
        self.assertEqual(refused.exception.reason, REASON_WORKER_IDENTITY)

    def test_generation_is_allocated_and_a_stale_one_is_not_current(self):
        first = register_node(self.db, node_id="N-A", public_key_ref="key-A", code_digest="code-1",
                              environment_digest="env-1", actor="operator:operator", now=T1)
        second = register_node(self.db, node_id="N-A", public_key_ref="key-A", code_digest="code-1",
                               environment_digest="env-1", actor="operator:operator", now=T1 + 1)
        self.assertEqual((first.node_generation, second.node_generation), (1, 2))
        self.assertTrue(is_current_generation(self.db, "N-A", 2))
        self.assertFalse(is_current_generation(self.db, "N-A", 1))
        self.assertEqual(current_generation(self.db, "N-A"), 2)

    def test_attestation_is_measured_and_self_enrolment_is_refused(self):
        with self.assertRaises(CrucibleError) as not_operator:
            register_node(self.db, node_id="N-B", public_key_ref="key-B", code_digest="code-1",
                          environment_digest="env-1", actor="node:N-B", now=T1)
        self.assertIn("OPERATOR", not_operator.exception.reason)
        identity = register_node(self.db, node_id="N-B", public_key_ref="key-B", code_digest="code-1",
                                 environment_digest="env-1", actor="operator:operator", now=T1)
        self.assertEqual(identity.membership, CANDIDATE)
        self.assertEqual(nodes(self.db, memberships=(TRUSTED,)), [])
        with self.assertRaises(CrucibleError) as mismatch:
            attest_node(self.db, "N-B", identity.node_generation, observed_code_digest="other-build",
                        observed_environment_digest="env-1", observed_public_key_ref="key-B",
                        actor="operator:operator", now=T1)
        self.assertEqual(mismatch.exception.reason, REASON_ATTESTATION_MISMATCH)
        self.assertEqual(get_node(self.db, "N-B", 1).membership, CANDIDATE)

    def test_membership_is_governed_revocable_and_retirement_is_terminal(self):
        self.node("N-A")
        self.node("N-B")
        set_membership(self.db, "N-B", 1, membership=QUARANTINED, actor="operator:operator",
                       reason="audit", now=T1 + 1)
        self.assertEqual(get_node(self.db, "N-B", 1).membership, QUARANTINED)
        with self.assertRaises(CrucibleError):
            set_membership(self.db, "N-B", 1, membership=TRUSTED, actor="node:N-B", now=T1 + 2)
        set_membership(self.db, "N-B", 1, membership=CANDIDATE, actor="operator:operator",
                       reason="re-attest", now=T1 + 3)
        retired = retire_node(self.db, "N-B", reason="decommissioned", actor="operator:operator", now=T1 + 4)
        self.assertEqual(retired.membership, RETIRED)
        with self.assertRaises(CrucibleError):
            set_membership(self.db, "N-B", 1, membership=CANDIDATE, actor="operator:operator",
                           now=T1 + 5)
        self.assertEqual(len(membership_history(self.db, "N-B")), 6,
                         "revocation keeps the whole history")

    def test_health_is_observed_and_unreachable_is_not_death(self):
        self.node("N-A")
        with self.assertRaises(CrucibleError) as self_report:
            assess_node_health(self.db, "N-A", status=HEALTHY, assessor="node:N-A", now=T1)
        self.assertEqual(self_report.exception.reason, REASON_SELF_HEALTH)
        with self.assertRaises(CrucibleError):
            assess_node_health(self.db, "N-A", status=HEALTH_DEGRADED, assessor="operator:operator",
                               evidence_refs=(), now=T1)
        observation = assess_node_health(self.db, "N-A", status=UNREACHABLE,
                                        assessor="node:N-B", now=T1 + 1)
        self.assertEqual(observation["status"], UNREACHABLE)
        self.assertFalse(observation["is_death"])
        self.assertEqual(get_node(self.db, "N-A", 1).membership, TRUSTED,
                         "an unreachable node is still a trusted node")

    def test_stale_rejoin_cannot_revive_stale_authority(self):
        self.node("N-A")
        self.node("N-B")
        self.domain(owner="N-A")
        stale = evaluate_rejoin(self.db, node_id="N-B", generation=1, presented_epoch=12,
                                current_epoch=26, actor="operator:operator", now=T1 + 2)
        self.assertEqual(stale["disposition"], REJOIN_STALE_EPOCH)
        self.assertFalse(stale["authority_revived"])
        previous_generation = evaluate_rejoin(self.db, node_id="N-B", generation=0,
                                              presented_epoch=26, current_epoch=26,
                                              actor="operator:operator", now=T1 + 3)
        self.assertEqual(previous_generation["disposition"], REJOIN_STALE_GENERATION)
        current = evaluate_rejoin(self.db, node_id="N-B", generation=1, presented_epoch=26,
                                  current_epoch=26, actor="operator:operator", now=T1 + 4)
        self.assertEqual(current["disposition"], REJOIN_ACCEPTED)


class TestStateClassification(FederationTestCase):

    def test_every_family_is_classified_and_unknown_fails_upward(self):
        self.assertGreaterEqual(len(rebuild_plan()["rebuildable"]), 4)
        with self.assertRaises(CrucibleError) as unknown:
            classify("something_nobody_classified")
        self.assertEqual(unknown.exception.reason, REASON_UNKNOWN_FAMILY)
        self.assertEqual(state_class("missions"), GLOBAL_CANONICAL)
        self.assertEqual(state_class("autonomy_state"), NODE_LOCAL)
        self.assertEqual(state_class("vault_root_secret"), SECRET_LOCAL)
        self.assertEqual(state_class("beliefs"), DERIVED_PROJECTION)
        self.assertEqual(state_class("epistemic_evidence"), REPLICATED_EVIDENCE)

    def test_secret_and_local_families_never_ordinarily_replicate(self):
        for family in ("vault_root_secret", "node_keys", "autonomy_state", "swarm_worker_state"):
            with self.assertRaises(CrucibleError) as refused:
                from ciph.kernel.federation_state import assert_may_replicate
                assert_may_replicate(family)
            self.assertEqual(refused.exception.reason, REASON_NOT_REPLICABLE)
        self.assertTrue(travels_in_ordinary_replication("epistemic_evidence"))
        self.assertFalse(travels_in_ordinary_replication("beliefs"))
        self.assertTrue(classification_digest())
        self.assertIn("replication grants provenance", explain("epistemic_evidence")["law"])


class TestAuthorityDomains(FederationTestCase):

    def test_only_the_owner_lineage_may_perform_an_authoritative_transition(self):
        self.three_nodes()
        self.domain(owner="N-A")
        assert_authoritative(self.db, "D-1", node_id="N-A", generation=1, epoch=1)
        with self.assertRaises(CrucibleError) as observer:
            assert_authoritative(self.db, "D-1", node_id="N-B", generation=1, epoch=1)
        self.assertEqual(observer.exception.reason, REASON_NOT_OWNER)
        with self.assertRaises(CrucibleError) as stale:
            assert_authoritative(self.db, "D-1", node_id="N-A", generation=1, epoch=7)
        self.assertEqual(stale.exception.reason, REASON_STALE_EPOCH)
        with self.assertRaises(CrucibleError) as superseded:
            assert_authoritative(self.db, "D-1", node_id="N-A", generation=2, epoch=1)
        self.assertEqual(superseded.exception.reason, REASON_NOT_OWNER)

    def test_a_quorum_cannot_seize_a_domain(self):
        self.three_nodes()
        self.domain(owner="N-A")
        claim = evaluate_quorum_claim(self.db, domain_id="D-1", voters=["N-B", "N-C"],
                                      claimed_epoch=1, now=T1 + 1)
        self.assertEqual(claim["disposition"], QUORUM_REFUSED)
        self.assertEqual(claim["authority_effect"], "none")
        self.assertFalse(claim["owner_among_voters"])
        self.assertEqual(get_domain(self.db, "D-1").owner_node_id, "N-A")
        self.assertEqual(get_domain(self.db, "D-1").authority_epoch, 1)
        self.assertEqual(claim["votes_for"], 2)

    def test_owner_silence_does_not_transfer_ownership(self):
        self.three_nodes()
        self.domain(owner="N-A")
        view = record_partition_view(self.db, observed_by="N-B", reachable=["N-C"],
                                    unreachable=["N-A"], now=T1 + 1)
        self.assertFalse(view["implies_death"])
        self.assertFalse(view["is_a_fact_about_the_world"])
        decision = safe_mode_for(self.db, "D-1", view=view)
        self.assertEqual(decision["mode"], MODE_SAFE)
        self.assertFalse(decision["can_perform_authoritative_transitions"])
        self.assertFalse(decision["creates_replacement_owner"])
        self.assertTrue(decision["may_do_local_work"])
        reachable = record_partition_view(self.db, observed_by="N-B", reachable=["N-A", "N-C"],
                                         unreachable=[], now=T1 + 2)
        self.assertEqual(safe_mode_for(self.db, "D-1", view=reachable)["mode"], MODE_NORMAL)
        self.assertEqual(get_domain(self.db, "D-1").owner_node_id, "N-A")

    def test_transfer_requires_a_governed_act_and_survives_a_race(self):
        self.three_nodes()
        self.domain(owner="N-A")
        with self.assertRaises(CrucibleError) as by_node:
            transfer_domain(self.db, "D-1", to_node_id="N-B", to_generation=1, actor="node:N-A",
                            evidence_ref="EVD-1", expected_epoch=1, now=T1 + 1)
        self.assertEqual(by_node.exception.reason, REASON_NOT_OPERATOR)
        with self.assertRaises(CrucibleError):
            transfer_domain(self.db, "D-1", to_node_id="N-B", to_generation=1, actor="operator:operator",
                            evidence_ref="", expected_epoch=1, now=T1 + 2)
        with self.assertRaises(CrucibleError) as stale_epoch:
            transfer_domain(self.db, "D-1", to_node_id="N-B", to_generation=1, actor="operator:operator",
                            evidence_ref="EVD-1", expected_epoch=9, now=T1 + 3)
        self.assertEqual(stale_epoch.exception.reason, REASON_STALE_EPOCH)
        transferred = transfer_domain(self.db, "D-1", to_node_id="N-B", to_generation=1,
                                      actor="operator:operator", evidence_ref="EVD-1", expected_epoch=1,
                                      now=T1 + 4)
        self.assertEqual(transferred.owner_node_id, "N-B")
        self.assertEqual(transferred.authority_epoch, 2)
        with self.assertRaises(CrucibleError) as old_owner:
            assert_authoritative(self.db, "D-1", node_id="N-A", generation=1, epoch=2)
        self.assertEqual(old_owner.exception.reason, REASON_NOT_OWNER)
        assert_authoritative(self.db, "D-1", node_id="N-B", generation=1, epoch=2)

    def test_two_owners_for_one_epoch_is_an_integrity_conflict(self):
        self.three_nodes()
        self.domain(owner="N-A")
        confirmed = reconcile_authority_claim(self.db, domain_id="D-1", node_id="N-A", generation=1,
                                             epoch=1, now=T1 + 1)
        self.assertEqual(confirmed["status"], CLAIM_OK)
        conflicting = reconcile_authority_claim(self.db, domain_id="D-1", node_id="N-C",
                                               generation=1, epoch=1, now=T1 + 2)
        self.assertEqual(conflicting["status"], INTEGRITY_CONFLICT)
        self.assertFalse(conflicting["adopted"])
        self.assertEqual(get_domain(self.db, "D-1").owner_node_id, "N-A")
        self.assertIn("no timestamp tiebreak", conflicting["resolution"])


class TestReplicationLaw(FederationTestCase):

    def test_evidence_merges_dedupes_and_grants_no_standing(self):
        first = offer_record(self.db, family="epistemic_evidence", origin_node="N-A",
                             canonical_id="OBS-1", payload_digest=DIGEST_A, sequence=1, authority_epoch=1,
                             now=T1)
        self.assertEqual(first["disposition"], MERGED)
        self.assertFalse(first["standing_gained"])
        duplicate = offer_record(self.db, family="epistemic_evidence", origin_node="N-B",
                                 canonical_id="OBS-1", payload_digest=DIGEST_A, sequence=2, authority_epoch=1,
                                 now=T1 + 1)
        self.assertEqual(duplicate["disposition"], DUPLICATE)
        self.assertFalse(duplicate["stored"])
        distinct = offer_record(self.db, family="epistemic_evidence", origin_node="N-B",
                                canonical_id="OBS-1", payload_digest=DIGEST_B, sequence=3, authority_epoch=1,
                                now=T1 + 2)
        self.assertEqual(distinct["disposition"], MERGED)
        self.assertEqual(len(records_for(self.db, "epistemic_evidence")), 2)
        merged = reconcile(self.db, family="epistemic_evidence",
                           records=records_for(self.db, "epistemic_evidence"))
        self.assertEqual(merged["disposition"], MERGED)
        self.assertEqual(len(merged["detail"]["duplicates"]), 0)

    def test_secret_local_and_node_local_and_derived_are_refused_or_rebuilt(self):
        secret = offer_record(self.db, family="vault_root_secret", origin_node="N-A",
                              canonical_id="ROOT", payload_digest=DIGEST_A, now=T1)
        self.assertEqual(secret["disposition"], REFUSED_CLASS)
        self.assertFalse(secret["stored"])
        local = offer_record(self.db, family="autonomy_state", origin_node="N-A",
                             canonical_id="SESSION-1", payload_digest=DIGEST_A, now=T1 + 1)
        self.assertEqual(local["disposition"], KEPT_LOCAL)
        derived = offer_record(self.db, family="beliefs", origin_node="N-A", canonical_id="BELIEF-1",
                               payload_digest=DIGEST_A, now=T1 + 2)
        self.assertEqual(derived["disposition"], REBUILT)
        self.assertEqual(records_for(self.db), [])
        self.assertEqual(len(reconciliation_history(self.db)), 3)

    def test_a_corrupt_digest_is_refused(self):
        refused = offer_record(self.db, family="epistemic_evidence", origin_node="N-A",
                               canonical_id="OBS-9", payload_digest="not-a-digest", now=T1)
        self.assertEqual(refused["disposition"], REFUSED_CORRUPT)
        self.assertEqual(records_for(self.db), [])

    def test_canonical_state_replicates_only_along_the_lineage(self):
        self.three_nodes()
        self.domain(owner="N-A")
        confirmed = offer_record(self.db, family="missions", origin_node="N-A", node_id="N-A",
                                 generation=1, domain_id="D-1", canonical_id="MSN-1",
                                 payload_digest=DIGEST_A, authority_epoch=1, sequence=1, now=T1 + 1)
        self.assertEqual(confirmed["disposition"], AUTHORITY_CONFIRMED)
        self.assertEqual(confirmed["authority"], "confirmed, not created")
        observer = offer_record(self.db, family="missions", origin_node="N-B", node_id="N-B",
                                generation=1, domain_id="D-1", canonical_id="MSN-2",
                                payload_digest=DIGEST_B, authority_epoch=1, sequence=2, now=T1 + 2)
        self.assertEqual(observer["disposition"], INTEGRITY_CONFLICT)
        self.assertFalse(observer["stored"])
        self.assertEqual(observer["quorum_claim"]["authority_effect"], "none")
        older_epoch = offer_record(self.db, family="missions", origin_node="N-B", node_id="N-B",
                                   generation=1, domain_id="D-1", canonical_id="MSN-3",
                                   payload_digest=DIGEST_B, authority_epoch=7, sequence=3, now=T1 + 3)
        self.assertEqual(older_epoch["disposition"], REFUSED_NOT_OWNER)

    def test_wall_clock_never_orders_constitutional_events(self):
        law = clock_law()
        self.assertIn("constitutional event order", law["wall_time_must_not_establish"])
        with self.assertRaises(CrucibleError) as refused:
            authority_winner_by_wall_clock(candidates=[{"node": "N-A"}, {"node": "N-B"}])
        self.assertEqual(refused.exception.reason, REASON_WALL_CLOCK)
        late_but_earlier = offer_record(self.db, family="epistemic_evidence", origin_node="N-B",
                                        canonical_id="OBS-1", payload_digest=DIGEST_A, authority_epoch=2,
                                        sequence=1, wall_time=T1 - 9999.0, now=T1)
        early_but_later = offer_record(self.db, family="epistemic_evidence", origin_node="N-A",
                                       canonical_id="OBS-2", payload_digest=DIGEST_B, authority_epoch=1,
                                       sequence=9, wall_time=T1 + 9999.0, now=T1)
        ordered = causal_order(records_for(self.db, "epistemic_evidence"))
        self.assertEqual([item.canonical_id for item in ordered], ["OBS-2", "OBS-1"],
                         "epoch then sequence decides, not the clock")

    def test_the_authority_domain_can_be_frozen_without_a_transfer(self):
        self.three_nodes()
        self.domain(owner="N-A")
        set_domain_status(self.db, "D-1", status=DOMAIN_FROZEN, actor="operator:operator", now=T1 + 1)
        with self.assertRaises(CrucibleError):
            assert_authoritative(self.db, "D-1", node_id="N-A", generation=1, epoch=1)
        self.assertEqual(get_domain(self.db, "D-1").owner_node_id, "N-A",
                         "freezing is not transferring")
        self.assertTrue(authority_digest(self.db))
        self.assertTrue(replication_digest(self.db))
        self.assertTrue(node_digest(self.db))

    def test_federal_state_reconstructs_identically_in_a_fresh_process(self):
        self.three_nodes()
        self.domain(owner="N-A")
        offer_record(self.db, family="epistemic_evidence", origin_node="N-A", canonical_id="OBS-1",
                     payload_digest=DIGEST_A, authority_epoch=1, sequence=1, now=T1)
        bundle = {"nodes": node_digest(self.db), "authority": authority_digest(self.db),
                  "replication": replication_digest(self.db),
                  "classification": classification_digest(),
                  "ownership": ownership_digest()}
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.federation_node import node_digest;"
                "from ciph.kernel.federation_authority import authority_digest;"
                "from ciph.kernel.federation_replication import replication_digest;"
                "from ciph.kernel.federation_state import classification_digest;"
                "from ciph.kernel.federation_ownership import ownership_digest;"
                "print(json.dumps({'nodes': node_digest(%r), 'authority': authority_digest(%r), "
                "'replication': replication_digest(%r), 'classification': classification_digest(), "
                "'ownership': ownership_digest()}, sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.db, self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), bundle)


if __name__ == "__main__":
    unittest.main()
