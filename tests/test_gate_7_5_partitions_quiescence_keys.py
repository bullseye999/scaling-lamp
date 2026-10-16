"""
7.4-7.6, 7.9, 7.10, 7.12, 7.13 - partitions, distributed control, custody, routing.

    Loss of communication does not manufacture authority.
    UNREACHABLE is not DEAD, and a timeout is not an acknowledgement.

The specimens are the ones that separate a federation from a distributed voting system: two nodes voting
about a third node's domain, a barrier that refuses to finish while a machine stays silent, a barriered
federation a newcomer cannot slip into, an emergency stop during a partition, and keys that do not carry
the root with them.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.federation_authority import (DOMAIN_FROZEN, QUORUM_REFUSED, evaluate_quorum_claim,
                                             get_domain, open_domain, record_partition_view,
                                             safe_mode_for)
from ciph.kernel.federation_delegation import (GOVERNED_CHANGE_CLASSES, OUTCOME_FAILED, OUTCOME_USEFUL,
                                              PROPOSED, REASON_FROZEN, REASON_GOVERNED_CHANGE,
                                              REASON_TARGET_NOT_TRUSTED,
                                              REASON_WORK_CLASS_NOT_DELEGATED,
                                              assert_scope_within_delegation, delegation_digest,
                                              federation_learning, get_delegation, placements,
                                              record_attempt, record_placement, request_delegation,
                                              result_is_not_evidence, route, set_delegation_status)
from ciph.kernel.federation_keys import (KEY_REVOKED, REASON_NO_ACTIVE_KEY,
                                         REASON_NOT_OPERATOR as KEY_REASON_NOT_OPERATOR, active_key,
                                         assert_node_key_boundary, key_digest, key_history,
                                         node_holds_root_authority, register_node_key,
                                         revoke_node_key, root_custody_law, rotate_node_key)
from ciph.kernel.federation_node import (DEGRADED, HEALTH_QUARANTINE, HEALTHY, QUARANTINED,
                                         REASON_SELF_HEALTH, TRUSTED, UNREACHABLE, assess_node_health,
                                         attest_node, current_generation, get_node,
                                         is_current_generation, node_digest, register_node,
                                         set_membership)
from ciph.kernel.federation_quiescence import (ACKNOWLEDGED_QUIESCENT, DRAINING, INCOMPLETE,
                                               OBSERVED_UNREACHABLE, QUIESCENT, RECONCILED,
                                               RELEASED, REVOKED_FROM_AUTHORITY,
                                               REASON_ALREADY_FROZEN, REASON_NOT_IN_SNAPSHOT,
                                               REASON_NOT_OPERATOR, acknowledge, barrier_state,
                                               current_barrier, emergency_stop, federation_is_frozen,
                                               get_barrier, mark_incomplete, observe_unreachable,
                                               open_barrier, quiescence_digest, release_barrier)
from ciph.kernel.federation_state import state_class

T1 = 1_800_000_000.0
DIGEST_A = "a" * 64


class FederalTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-75-")
        self.db = str(Path(self.temp.name) / "federation.db")

    def tearDown(self):
        self.temp.cleanup()

    def node(self, node_id, *, when=T1):
        registered = register_node(self.db, node_id=node_id, public_key_ref=f"key-{node_id}",
                                   code_digest="code-1", environment_digest="env-1",
                                   actor="operator:operator", now=when)
        return attest_node(self.db, node_id, registered.node_generation, observed_code_digest="code-1",
                           observed_environment_digest="env-1",
                           observed_public_key_ref=f"key-{node_id}", actor="operator:operator", now=when)

    def three_nodes(self):
        for node_id in ("N-A", "N-B", "N-C"):
            self.node(node_id)

    def domain(self, owner="N-A"):
        return open_domain(self.db, domain_id="D-1", scope="crucible-promotion", owner_node_id=owner,
                           permitted_transitions=["PROMOTE"], actor="operator:operator", now=T1)


class TestPartitionSemantics(FederalTestCase):

    def test_a_majority_of_the_remaining_nodes_still_owns_nothing(self):
        self.three_nodes()
        self.domain(owner="N-A")
        view = record_partition_view(self.db, observed_by="N-B", reachable=["N-C"],
                                    unreachable=["N-A"], now=T1 + 1)
        claim = evaluate_quorum_claim(self.db, domain_id="D-1", voters=["N-B", "N-C"],
                                      claimed_epoch=1, now=T1 + 2)
        self.assertEqual(claim["disposition"], QUORUM_REFUSED)
        self.assertEqual(claim["authority_effect"], "none")
        self.assertEqual(safe_mode_for(self.db, "D-1", view=view)["mode"], "SAFE_MODE")
        self.assertEqual(get_domain(self.db, "D-1").owner_node_id, "N-A")
        self.assertEqual(get_domain(self.db, "D-1").authority_epoch, 1)

    def test_the_frozen_domain_refuses_its_own_owner_too(self):
        self.three_nodes()
        self.domain(owner="N-A")
        from ciph.kernel.federation_authority import assert_authoritative, set_domain_status
        set_domain_status(self.db, "D-1", status=DOMAIN_FROZEN, actor="operator:operator", now=T1 + 1)
        with self.assertRaises(CrucibleError):
            assert_authoritative(self.db, "D-1", node_id="N-A", generation=1, epoch=1)


class TestDistributedQuiescence(FederalTestCase):

    def test_a_barrier_freezes_the_federation_and_a_newcomer_cannot_slip_in(self):
        self.three_nodes()
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        self.assertTrue(federation_is_frozen(self.db))
        self.assertEqual(sorted(barrier.required), ["N-A@1", "N-B@1", "N-C@1"])
        newcomer = self.node("N-D", when=T1 + 1)
        self.assertFalse(is_current_generation(self.db, "N-D", 2))
        with self.assertRaises(CrucibleError) as refused:
            _ = request_delegation(self.db, requester_node="N-A", target_node="N-D",
                                   task_identity="T-1", input_digest="IN-1", basis_digest="B-1",
                                   allowed_work_class="READ_REPOSITORY", now=T1 + 2)
        self.assertEqual(refused.exception.reason, REASON_FROZEN)
        self.assertEqual(get_barrier(self.db, barrier.barrier_id).required, ("N-A@1", "N-B@1", "N-C@1"),
                         "a joiner is not in the snapshot")

    def test_a_timeout_is_not_an_acknowledgement(self):
        self.three_nodes()
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        acknowledge(self.db, barrier.barrier_id, node_id="N-A", generation=1, now=T1 + 1)
        observe_unreachable(self.db, barrier.barrier_id, node_id="N-B", generation=1,
                            observed_by="N-A", now=T1 + 30)
        after = get_barrier(self.db, barrier.barrier_id)
        self.assertEqual(after.acks["N-B@1"], OBSERVED_UNREACHABLE)
        self.assertEqual(after.status, DRAINING, "a silence is not a stop")
        self.assertIn("N-B@1", after.unresolved)
        self.assertTrue(federation_is_frozen(self.db))

    def test_the_federation_is_quiescent_only_when_every_member_is_accounted_for(self):
        self.three_nodes()
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        acknowledge(self.db, barrier.barrier_id, node_id="N-A", generation=1, now=T1 + 1)
        acknowledge(self.db, barrier.barrier_id, node_id="N-B", generation=1, now=T1 + 2)
        observe_unreachable(self.db, barrier.barrier_id, node_id="N-C", generation=1,
                            observed_by="N-A", now=T1 + 3)
        self.assertEqual(get_barrier(self.db, barrier.barrier_id).status, DRAINING)
        with self.assertRaises(CrucibleError) as worker_release:
            release_barrier(self.db, barrier.barrier_id, actor="node:N-A", now=T1 + 4)
        self.assertEqual(worker_release.exception.reason, REASON_NOT_OPERATOR)
        # Unreachable is resolved the governed way: withdraw what it could do, reconcile what it left.
        acknowledge(self.db, barrier.barrier_id, node_id="N-C", generation=1,
                    outcome=REVOKED_FROM_AUTHORITY, actor="operator:operator", now=T1 + 5)
        settled = get_barrier(self.db, barrier.barrier_id)
        self.assertEqual(settled.status, QUIESCENT)
        self.assertEqual(settled.unresolved, ())
        released = release_barrier(self.db, barrier.barrier_id, actor="operator:operator", now=T1 + 6)
        self.assertEqual(released.status, RELEASED)
        self.assertFalse(federation_is_frozen(self.db))

    def test_a_federation_that_cannot_settle_stays_frozen(self):
        self.three_nodes()
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        unable = mark_incomplete(self.db, barrier.barrier_id, actor="operator:operator",
                                 reason="N-B cannot be reached and cannot be reconciled",
                                 now=T1 + 1)
        self.assertEqual(unable.status, INCOMPLETE)
        self.assertEqual(unable.unresolved, ("N-A@1", "N-B@1", "N-C@1"))
        self.assertTrue(federation_is_frozen(self.db), "an unfinished stop stays stopped")

    def test_emergency_stop_during_a_partition_fabricates_nothing(self):
        self.three_nodes()
        self.domain(owner="N-A")
        view = record_partition_view(self.db, observed_by="N-A", reachable=["N-C"],
                                    unreachable=["N-B"], now=T1 + 1)
        stopped = emergency_stop(self.db, actor="operator:operator", now=T1 + 2)
        self.assertEqual(stopped["domains_frozen"], ["D-1"])
        self.assertEqual(stopped["acknowledgements_fabricated"], 0)
        self.assertEqual(get_domain(self.db, "D-1").owner_node_id, "N-A",
                         "emergency stop freezes authority; it does not transfer it")
        self.assertEqual(get_domain(self.db, "D-1").status, DOMAIN_FROZEN)
        state = barrier_state(self.db)
        self.assertTrue(state["frozen"])
        self.assertEqual(len(state["unresolved"]), 3)
        self.assertEqual(view["unreachable"], ["N-B"])

    def test_the_barrier_reconstructs_after_a_coordinator_restart(self):
        self.three_nodes()
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        acknowledge(self.db, barrier.barrier_id, node_id="N-A", generation=1, now=T1 + 1)
        expected = quiescence_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.federation_quiescence import quiescence_digest, current_barrier;"
                "print(json.dumps({'d': quiescence_digest(%r), "
                "'b': current_barrier(%r).as_dict()}, sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        recovered = json.loads(out.stdout.strip())
        self.assertEqual(recovered["d"], expected)
        self.assertEqual(recovered["b"]["status"], DRAINING)
        self.assertEqual(recovered["b"]["acks"]["N-A@1"], ACKNOWLEDGED_QUIESCENT)

    def test_a_node_may_not_acknowledge_a_barrier_it_is_not_in(self):
        self.three_nodes()
        barrier = open_barrier(self.db, actor="operator:operator", snapshot=["N-A@1"], now=T1)
        with self.assertRaises(CrucibleError) as refused:
            acknowledge(self.db, barrier.barrier_id, node_id="N-B", generation=1, now=T1 + 1)
        self.assertEqual(refused.exception.reason, REASON_NOT_IN_SNAPSHOT)
        with self.assertRaises(CrucibleError) as twice:
            open_barrier(self.db, actor="operator:operator", now=T1 + 2)
        self.assertEqual(twice.exception.reason, REASON_ALREADY_FROZEN)


class TestKeyCustody(FederalTestCase):

    def test_a_node_key_is_not_the_root(self):
        self.node("N-A")
        key = register_node_key(self.db, node_id="N-A", node_generation=1, public_key_ref="pub-A",
                                actor="operator:operator", now=T1)
        self.assertEqual(key.key_state, "ACTIVE")
        self.assertEqual(active_key(self.db, "N-A").public_key_ref, "pub-A")
        boundary = node_holds_root_authority("N-A")
        self.assertFalse(boundary["holds_root_authority"])
        self.assertEqual(boundary["root_custody"], "operator")
        self.assertIn("stated_limit", root_custody_law())
        with self.assertRaises(CrucibleError) as not_operator:
            register_node_key(self.db, node_id="N-A", node_generation=1, public_key_ref="pub-X",
                              actor="node:N-A", now=T1 + 1)
        self.assertEqual(not_operator.exception.reason, KEY_REASON_NOT_OPERATOR)

    def test_rotation_and_revocation_are_auditable_and_revoked_means_revoked(self):
        self.node("N-A")
        original = register_node_key(self.db, node_id="N-A", node_generation=1,
                                     public_key_ref="pub-A", actor="operator:operator", now=T1)
        rotated = rotate_node_key(self.db, node_id="N-A", node_generation=1,
                                  new_public_key_ref="pub-A2", actor="operator:operator",
                                  evidence_ref="ROT-1", now=T1 + 1)
        self.assertEqual(rotated.public_key_ref, "pub-A2")
        self.assertEqual(rotated.rotated_from, original.key_id)
        assert_node_key_boundary(self.db, node_id="N-A", generation=1)
        revoke_node_key(self.db, node_id="N-A", node_generation=1, actor="operator:operator",
                        reason="host compromise", now=T1 + 2)
        with self.assertRaises(CrucibleError) as revoked:
            assert_node_key_boundary(self.db, node_id="N-A", generation=1)
        self.assertEqual(revoked.exception.reason, REASON_NO_ACTIVE_KEY)
        states = [row["key_state"] for row in key_history(self.db, "N-A")]
        self.assertIn(KEY_REVOKED, states)
        self.assertTrue(key_digest(self.db))

    def test_a_stale_generation_cannot_authenticate(self):
        self.node("N-A")
        register_node_key(self.db, node_id="N-A", node_generation=1, public_key_ref="pub-A",
                          actor="operator:operator", now=T1)
        self.node("N-A", when=T1 + 1)
        self.assertEqual(current_generation(self.db, "N-A"), 2)
        with self.assertRaises(CrucibleError):
            assert_node_key_boundary(self.db, node_id="N-A", generation=1)


class TestCrossNodeDelegation(FederalTestCase):

    def test_a_delegation_cannot_carry_a_governed_change(self):
        self.three_nodes()
        for work_class in GOVERNED_CHANGE_CLASSES:
            with self.assertRaises(CrucibleError) as refused:
                request_delegation(self.db, requester_node="N-A", target_node="N-B",
                                   task_identity=f"T-{work_class}", input_digest="IN-1",
                                   basis_digest="B-1", allowed_work_class=work_class, now=T1)
            self.assertEqual(refused.exception.reason, REASON_GOVERNED_CHANGE)

    def test_only_a_trusted_current_target_may_be_asked(self):
        self.three_nodes()
        set_membership(self.db, "N-C", 1, membership=QUARANTINED, actor="operator:operator",
                       reason="audit", now=T1 + 1)
        with self.assertRaises(CrucibleError) as untrusted:
            request_delegation(self.db, requester_node="N-A", target_node="N-C",
                               task_identity="T-2", input_digest="IN-1", basis_digest="B-1",
                               allowed_work_class="READ_REPOSITORY", now=T1 + 2)
        self.assertEqual(untrusted.exception.reason, REASON_TARGET_NOT_TRUSTED)
        with self.assertRaises(CrucibleError) as stale:
            request_delegation(self.db, requester_node="N-A", target_node="N-B",
                               target_generation=7, task_identity="T-3", input_digest="IN-1",
                               basis_digest="B-1", allowed_work_class="READ_REPOSITORY", now=T1 + 3)
        self.assertIn("STALE_NODE_GENERATION", str(stale.exception.reason))
        accepted = request_delegation(self.db, requester_node="N-A", target_node="N-B",
                                      task_identity="T-4", input_digest="IN-1", basis_digest="B-1",
                                      allowed_work_class="READ_REPOSITORY", now=T1 + 4)
        self.assertEqual(accepted.status, PROPOSED)
        self.assertFalse(accepted.as_dict()["authority_transferred"])

    def test_a_remote_result_is_not_evidence_and_scope_cannot_widen(self):
        self.three_nodes()
        delegation = request_delegation(self.db, requester_node="N-A", target_node="N-B",
                                        task_identity="T-5", input_digest="IN-1", basis_digest="B-1",
                                        allowed_work_class="READ_REPOSITORY", now=T1)
        assert_scope_within_delegation(self.db, delegation.delegation_id,
                                       requested_work_class="READ_REPOSITORY")
        for widened in ("GENERATE_CANDIDATE", "PRODUCTION_INSTALL"):
            with self.assertRaises(CrucibleError) as refused:
                assert_scope_within_delegation(self.db, delegation.delegation_id,
                                               requested_work_class=widened)
            self.assertEqual(refused.exception.reason, REASON_WORK_CLASS_NOT_DELEGATED)
        claim = result_is_not_evidence(delegation.delegation_id, result_digest=DIGEST_A)
        self.assertFalse(claim["is_evidence"])
        self.assertFalse(claim["authority_transferred"])
        self.assertIn("4.2", claim["requires"])
        done = set_delegation_status(self.db, delegation.delegation_id, status="COMPLETED",
                                     result_ref="RESULT-1", now=T1 + 1)
        self.assertEqual(done.status, "COMPLETED")
        self.assertEqual(get_delegation(self.db, delegation.delegation_id).result_ref, "RESULT-1")


class TestRoutingAndLearning(FederalTestCase):

    def test_routing_prefers_healthy_reachable_nodes_and_grants_nothing(self):
        self.three_nodes()
        assess_node_health(self.db, "N-C", status=UNREACHABLE, assessor="node:N-A", now=T1 + 1)
        ranked = route(self.db, task_class="RESEARCH", required_capabilities=["research"],
                       latency_hint_by_node={"N-A": 40.0, "N-B": 5.0}, now=T1 + 2)
        self.assertEqual([item["node_id"] for item in ranked], ["N-B", "N-A"])
        self.assertNotIn("N-C", [item["node_id"] for item in ranked],
                         "unreachable is not eligible, and it is also not dead")
        for item in ranked:
            self.assertFalse(item["authority_granted"])
        placement = record_placement(self.db, task_class="RESEARCH", chosen_node="N-B",
                                     candidates=ranked, reason_codes=["health:HEALTHY"], now=T1 + 3)
        self.assertFalse(placement["authority_granted"])
        self.assertFalse(placement["is_domain_owner"])
        self.assertEqual(placements(self.db, "RESEARCH")[0]["authority_granted"], 0)

    def test_routing_refuses_while_the_federation_is_frozen(self):
        self.three_nodes()
        open_barrier(self.db, actor="operator:operator", now=T1)
        self.assertEqual(route(self.db, task_class="RESEARCH", now=T1 + 1), [])

    def test_a_quarantined_node_is_not_a_routing_target(self):
        self.three_nodes()
        assess_node_health(self.db, "N-B", status=HEALTH_QUARANTINE,
                           assessor="operator:operator", evidence_refs=["CORRUPT-REPLICA-1"],
                           generation=1, now=T1 + 1)
        self.assertEqual(get_node(self.db, "N-B", 1).membership, QUARANTINED)
        ranked = route(self.db, task_class="RESEARCH", now=T1 + 2)
        self.assertEqual([item["node_id"] for item in ranked], ["N-A", "N-C"])

    def test_learning_is_descriptive_and_does_not_inflate_on_replay(self):
        self.three_nodes()
        record_attempt(self.db, task_class="RESEARCH", target_node="N-B", outcome=OUTCOME_USEFUL,
                       latency_seconds=12.5, resource_cost=2.0, reconciliation_conflicts=1, now=T1)
        record_attempt(self.db, task_class="RESEARCH", target_node="N-B", outcome=OUTCOME_FAILED,
                       latency_seconds=900.0, resource_cost=99.0, now=T1 + 1)
        record_attempt(self.db, task_class="RESEARCH", target_node="N-A", outcome=OUTCOME_FAILED,
                       stale_work=2, now=T1 + 2)
        projection = federation_learning(self.db, "RESEARCH")
        self.assertEqual(projection["attempts"], 2)
        self.assertEqual(projection["useful"], 1)
        self.assertEqual(projection["failed"], 1)
        self.assertEqual(projection["reconciliation_conflicts"], 1)
        self.assertEqual(projection["stale_work"], 2)
        self.assertEqual(projection["attempts_by_node"], {"N-A": 1, "N-B": 1})
        self.assertTrue(projection["no_score"])
        self.assertNotIn("score", projection)
        self.assertTrue(delegation_digest(self.db))


if __name__ == "__main__":
    unittest.main()
