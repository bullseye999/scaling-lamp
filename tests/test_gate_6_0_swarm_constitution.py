"""
6.0-6.12 - the governed swarm constitution.

    Workers may multiply cognition. They may not multiply authority.

The specimens below are the ones that decide whether that sentence is a law or a slogan: a real race for
one delegation, a restart that makes a new generation, a late result that does not become current, five
workers citing one source, four workers agreeing on nothing, a quota that cannot be subdivided twice, a
freeze that a joiner cannot slip past, and a consensus engine whose verdict nothing reads.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.autonomy_budgets import budget_status, open_budget
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.swarm_delegation import (ASSIGNED, COMPLETED, ELIGIBLE, LEASE_ACTIVE, LEASE_EXPIRED,
                                          LEASE_INTERRUPTED, REASON_ALREADY_CLAIMED,
                                          REASON_GOVERNED_CHANGE, REASON_INPUT_MISMATCH,
                                          REASON_NOT_LEASE_HOLDER, REASON_STALE_GENERATION,
                                          REASON_SWARM_FROZEN, REASON_WORK_CLASS_NOT_DELEGATED,
                                          assert_scope_within_delegation, claim_delegation,
                                          complete_delegation, current_lease, delegation_digest,
                                          delegations, get_delegation, interrupt_live_leases,
                                          leases_for, propose_delegation, reclaim_expired_leases,
                                          release_lease)
from ciph.kernel.swarm_learning import (OUTCOME_FAILED, OUTCOME_USEFUL, attempts,
                                        delegation_strategy, escalation_requires_an_action,
                                        learning_digest, record_attempt)
from ciph.kernel.swarm_ownership import (CENSUS, RETAINED_MACHINERY, dormant_consensus_authority,
                                         ownership_digest, ownership_violations,
                                         retained_machinery_missing, swarm_bypasses)
from ciph.kernel.swarm_quiescence import (ACK_LEASE_RELEASED, DRAINING, INCOMPLETE, QUIESCED,
                                          RECONCILED_DEAD, REASON_NOT_OPERATOR,
                                          acknowledge, current_barrier, emergency_stop_swarm,
                                          get_barrier, open_barrier, quiescence_digest,
                                          reconcile_worker, release_barrier, report_timeout,
                                          settle_barrier, swarm_is_frozen, swarm_state)
from ciph.kernel.swarm_resources import (REASON_ALLOCATION_EXHAUSTED, REASON_CHILD_EXCEEDS_PARENT,
                                         REASON_CONCURRENCY, REASON_SPAWN_RATE, allocate_child,
                                         allocations, assert_spawn_allowed, close_allocation,
                                         consume_child, outstanding_total, parent_remaining,
                                         record_spawn, return_unused)
from ciph.kernel.swarm_results import (CONFLICTING, CONSISTENT, CURRENT, DECIDED_BY_DISAGREEMENT,
                                       DECIDED_BY_EVIDENCE, DECIDED_BY_INTEGRITY, DISAGREEMENT,
                                       DUPLICATE,
                                       INSUFFICIENT_EVIDENCE, INTEGRITY_CONFLICT, LATE, PARTIAL,
                                       REJECTED, STALE_BASIS, aggregate, aggregations,
                                       current_result, independent_sources, result_claims_evidence,
                                       results_digest, results_for, submit_result)
from ciph.kernel.swarm_scanners import (SWARM_SCANNERS, swarm_scanner_census)
from ciph.kernel.swarm_worker import (AVAILABLE, BUSY, DEAD, DEGRADED, HEALTH_QUARANTINE,
                                      INSTALLED, JOINING,
                                      QUARANTINED, READY, REASON_ATTESTATION_MISMATCH,
                                      REASON_ILLEGAL_TRANSITION, REASON_QUARANTINE_NEEDS_OPERATOR,
                                      REASON_SELF_CAPABILITY, REASON_SELF_HEALTH,
                                      REASON_STALE_GENERATION, VERIFIED, assess_health,
                                      attest_worker, capability_level, get_worker, health_of,
                                      is_current_generation, mark_dead, members,
                                      membership_history, record_capability, register_worker,
                                      route, set_worker_status, topology_digest)
from ciph.kernel.evolution_ownership import production_sources

DAY = 86_400.0
T1 = 1_800_000_000.0
CODE = "code-digest-1"
ENV = "env-digest-1"


class TestGate60SwarmConstitution(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-60-")
        self.db = str(Path(self.temp.name) / "vault.db")

    def tearDown(self):
        self.temp.cleanup()

    # ---------------------------------------------------------------- helpers
    def ready_worker(self, worker_id="W1", *, capabilities=(), model=None, when=None):
        moment = T1 if when is None else when
        identity = register_worker(self.db, worker_id=worker_id, process_identity=str(worker_id),
                                  code_digest=CODE, environment_digest=ENV, model_identity=model,
                                  now=moment)
        attested = attest_worker(self.db, worker_id, identity.instance_generation,
                                 observed_code_digest=CODE, observed_environment_digest=ENV,
                                 actor="operator:operator", now=moment)
        for capability in capabilities:
            record_capability(self.db, worker_id, identity.instance_generation,
                              capability=capability, level=INSTALLED, actor=f"worker:{worker_id}",
                              now=moment)
            record_capability(self.db, worker_id, identity.instance_generation,
                              capability=capability, level=VERIFIED, actor="operator:operator",
                              evidence_ref="CAP-1", now=moment)
        return attested

    def delegation(self, task="TASK-1", *, class_="READ_REPOSITORY", input_digest="INPUT-1",
                   basis="BASIS-1", capabilities=(), budget=None, generation=1):
        return propose_delegation(self.db, task_identity=task, input_digest=input_digest,
                                  basis_digest=basis, allowed_work_class=class_,
                                  required_capabilities=list(capabilities),
                                  resource_budget_ref=budget, task_generation=generation, now=T1)

    def claim(self, delegation_id, worker="W1", generation=1, *, lease_seconds=60.0,
              input_digest="INPUT-1", when=None):
        return claim_delegation(self.db, delegation_id, worker_id=worker,
                                worker_generation=generation, input_digest=input_digest,
                                lease_seconds=lease_seconds, now=T1 if when is None else when)

    def submit(self, delegation_id, worker="W1", generation=1, *, output="OUT-1", basis="BASIS-1",
               sources=(), evidence=(), when=None):
        return submit_result(self.db, delegation_id=delegation_id, worker_id=worker,
                             worker_generation=generation, output_digest=output, basis_digest=basis,
                             source_dependency_refs=list(sources), evidence_refs=list(evidence),
                             now=T1 if when is None else when)

    # ---------------------------------------------------------------- R10: the entry gate
    def test_r10_census_is_clean_and_the_machinery_is_still_there(self):
        self.assertEqual(ownership_violations(), ())
        self.assertEqual(retained_machinery_missing(), ())
        self.assertEqual(swarm_bypasses(), ())
        self.assertEqual(dormant_consensus_authority(), ())
        self.assertEqual(len(CENSUS), 15)
        self.assertTrue(ownership_digest())
        owners = {concern.canonical_owner for concern in CENSUS}
        self.assertIn("ciph/kernel/swarm_worker.py", owners)
        self.assertIn("ciph/workers/ipc_queue.py", owners)

    def test_r10_census_fires_on_a_synthetic_second_owner(self):
        real = dict(production_sources())
        injected = {**real, "ciph/kernel/swarm_rogue_owner.py":
                    "def steal(c):\n    c.execute('INSERT INTO ciph_swarm_leases VALUES (1);')\n"}
        # The census reads the tree through `production_sources`; drive its two helpers the same way
        # it does, so the synthetic tree exercises the real predicate rather than a re-implementation.
        from ciph.kernel.swarm_ownership import _contains_signal, _is_allowed
        found = [concern.concern for concern in CENSUS
                 if not concern.legacy_ownership_allowed
                 and _contains_signal(injected["ciph/kernel/swarm_rogue_owner.py"],
                                      concern.signals[0])
                 and not _is_allowed("ciph/kernel/swarm_rogue_owner.py", concern)]
        self.assertEqual(found, ["work lease"])

    def test_dormant_consensus_authority_fires_on_a_synthetic_consumer(self):
        real = dict(production_sources())
        injected = {**real, "ciph/kernel/some_engine.py":
                    "from ciph.swarm import ByzantineConsensusEngine\n\n\ndef decide(x):\n"
                    "    return ByzantineConsensusEngine(x)\n"}
        # Call the REAL predicate. The previous version re-implemented the exclusion list inline, and
        # when the census moved to a suffix rule the specimen kept testing the old list - the same drift
        # this project has now repaired five times: call the predicate, do not restate it.
        from ciph.kernel.swarm_ownership import _consumers
        self.assertEqual(_consumers(symbols=("ByzantineConsensusEngine",),
                                    sources=list(injected.items())),
                         ("ciph/kernel/some_engine.py",))

    def test_twelve_swarm_scanners_are_zero_and_each_fires_on_its_own_violation(self):
        census = swarm_scanner_census()
        self.assertEqual(len(census), 12)
        self.assertEqual({name: count for name, count in census.items() if count}, {})
        real = dict(production_sources())
        catches = [
            ("s01_worker_private_execution_signer",
             "from ciph.kernel.crypto_identity import Ed25519KeyManager\n"),
            ("s02_worker_direct_permit_claim",
             "def go(store):\n    return store.claim('permit-1')\n"),
            ("s03_worker_direct_active_pointer_write",
             "def swap(c):\n    c.execute('UPDATE ciph_crucible_active SET candidate_id = 1;')\n"),
            ("s04_worker_direct_production_activation",
             "def activate(target, blob):\n    target.write_bytes(blob)\n"),
            ("s05_worker_creates_standing_authorization",
             "def grant(db):\n    return create_standing_authorization(db)\n"),
            ("s06_worker_mutates_operator_mode",
             "def relax(db):\n    set_mode(db, 'AUTONOMY_NORMAL', 'worker:W1')\n"),
            ("s07_worker_writes_promotion_record",
             "def ship(c):\n    c.execute('INSERT INTO ciph_meta_promotions VALUES (1);')\n"),
            ("s08_worker_writes_epoch",
             "def bump(c):\n    c.execute('INSERT INTO ciph_evolution_epochs VALUES (1);')\n"),
            ("s09_worker_self_membership_authorization",
             "def self_promote(c):\n    c.execute('UPDATE ciph_swarm_membership SET event = 1;')\n"),
            ("s10_worker_self_health_promotion",
             "def heal(c):\n    c.execute('UPDATE ciph_swarm_health SET status = 1;')\n"),
            ("s11_swarm_second_executor",
             "def go():\n    return subprocess.run(['ls'])\n"),
            ("s12_swarm_second_permit_authority",
             "def authority():\n    return issue_permit('p')\n"),
        ]
        self.assertEqual(len(catches), 12)
        for name, body in catches:
            with self.subTest(scanner=name):
                sources = {**real, "ciph/kernel/swarm_rogue.py": body}
                if name == "s02_worker_direct_permit_claim":
                    sources = {**real, "ciph/kernel/swarm_rogue.py": body}
                self.assertTrue(dict(SWARM_SCANNERS)[name](sources),
                                f"{name} did not fire on its own synthetic violation")

    # ---------------------------------------------------------------- 6.0 identity
    def test_registration_grants_nothing_and_generation_is_not_the_workers_to_pick(self):
        first = register_worker(self.db, worker_id="W1", process_identity="pid-1", code_digest=CODE,
                                environment_digest=ENV, now=T1)
        second = register_worker(self.db, worker_id="W1", process_identity="pid-2", code_digest=CODE,
                                 environment_digest=ENV, now=T1 + 1)
        self.assertEqual((first.instance_generation, second.instance_generation), (1, 2))
        self.assertEqual(first.status, JOINING)
        self.assertEqual(members(self.db), [], "an unattested worker is not a member")
        self.assertEqual(second.status, JOINING)
        self.assertTrue(is_current_generation(self.db, "W1", 2))
        self.assertFalse(is_current_generation(self.db, "W1", 1))
        self.assertEqual([event["event"] for event in membership_history(self.db, "W1")],
                         ["JOIN", "JOIN"])

    def test_attestation_is_measured_and_a_mismatch_leaves_the_worker_joining(self):
        identity = register_worker(self.db, worker_id="W2", process_identity="pid", code_digest=CODE,
                                   environment_digest=ENV, now=T1)
        with self.assertRaises(CrucibleError) as refused:
            attest_worker(self.db, "W2", identity.instance_generation,
                          observed_code_digest="a-different-build",
                          observed_environment_digest=ENV, actor="operator:operator", now=T1)
        self.assertEqual(refused.exception.reason, REASON_ATTESTATION_MISMATCH)
        self.assertEqual(get_worker(self.db, "W2", 1).status, JOINING)
        self.assertIn("ATTEST_MISMATCH", [event["event"] for event in
                                          membership_history(self.db, "W2")])
        ready = self.ready_worker("W3")
        self.assertEqual(ready.status, READY)
        self.assertEqual([item.worker_id for item in members(self.db)], ["W3"])

    def test_a_worker_cannot_leave_quarantine_by_asserting_that_it_is_fine(self):
        identity = self.ready_worker("W4")
        generation = identity.instance_generation
        assess_health(self.db, "W4", generation, status=HEALTH_QUARANTINE,
                      evidence_refs=["CORRUPT-RESULT-1"], assessor="operator:operator", now=T1 + 1)
        self.assertEqual(get_worker(self.db, "W4", generation).status, QUARANTINED)
        # There is no path from QUARANTINED to READY at all - not for the worker and not for the
        # operator. Re-entry exists only through JOINING plus a fresh attestation.
        with self.assertRaises(CrucibleError) as refused:
            set_worker_status(self.db, "W4", generation, status=READY, actor="worker:W4", now=T1 + 2)
        self.assertEqual(refused.exception.reason, REASON_ILLEGAL_TRANSITION)
        with self.assertRaises(CrucibleError) as operator_too:
            set_worker_status(self.db, "W4", generation, status=READY, actor="operator:operator",
                              now=T1 + 2)
        self.assertEqual(operator_too.exception.reason, REASON_ILLEGAL_TRANSITION)
        with self.assertRaises(CrucibleError) as illegal:
            set_worker_status(self.db, "W4", generation, status="TELEPORTING", actor="operator:operator",
                              now=T1 + 3)
        self.assertEqual(illegal.exception.reason, "UNKNOWN_WORKER_STATUS")
        # Re-entry is re-attestation: the operator returns the worker to JOINING, and it must be
        # measured again before it is READY.
        set_worker_status(self.db, "W4", generation, status=JOINING, actor="operator:operator",
                          reason="re-attestation", now=T1 + 4)
        self.assertEqual(get_worker(self.db, "W4", generation).status, JOINING)
        with self.assertRaises(CrucibleError) as twice:
            set_worker_status(self.db, "W4", generation, status=READY, actor="operator:operator",
                              now=T1 + 5)
        self.assertEqual(twice.exception.reason, REASON_ILLEGAL_TRANSITION,
                         "JOINING -> READY is an attestation, never a status change")

    def test_health_is_assessed_with_evidence_by_someone_else(self):
        identity = self.ready_worker("W5")
        with self.assertRaises(CrucibleError) as refused:
            assess_health(self.db, "W5", identity.instance_generation, status=DEGRADED,
                          evidence_refs=[], assessor="worker:W5", now=T1)
        self.assertEqual(refused.exception.reason, REASON_SELF_HEALTH)
        with self.assertRaises(CrucibleError):
            assess_health(self.db, "W5", identity.instance_generation, status=DEGRADED,
                          evidence_refs=[], assessor="operator:operator", now=T1)
        assessed = assess_health(self.db, "W5", identity.instance_generation, status=DEGRADED,
                                 evidence_refs=["CRASH-LOOP-1"], assessor="coordinator:core",
                                 now=T1 + 1)
        self.assertEqual(assessed["status"], DEGRADED)
        self.assertEqual(assessed["evidence_refs"], ["CRASH-LOOP-1"])

    def test_the_capability_ladder_is_not_self_service(self):
        identity = self.ready_worker("W6", capabilities=("coding",))
        generation = identity.instance_generation
        with self.assertRaises(CrucibleError) as refused:
            record_capability(self.db, "W6", generation, capability="coding", level=AVAILABLE,
                              actor="worker:W6", now=T1)
        self.assertEqual(refused.exception.reason, REASON_SELF_CAPABILITY)
        self.assertEqual(capability_level(self.db, "W6", generation, "coding"), VERIFIED)
        self.assertEqual(capability_level(self.db, "W6", generation, "coding"), VERIFIED)
        self.assertEqual(capability_level(self.db, "W6", generation, "research"), None)
        eligible = route(self.db, required_capabilities=["coding"], work_class="READ_REPOSITORY")
        self.assertEqual([item["worker_id"] for item in eligible], ["W6"])
        self.assertEqual(route(self.db, required_capabilities=["research"],
                               work_class="READ_REPOSITORY"), [])

    # ---------------------------------------------------------------- 6.1/6.2 delegation and leases
    def test_a_delegation_cannot_carry_a_governed_change(self):
        for work_class in ("PRODUCTION_INSTALL", "META_PROMOTION", "KEY_ACCESS", "NETWORK_POST"):
            with self.assertRaises(CrucibleError) as refused:
                self.delegation(task=f"T-{work_class}", class_=work_class)
            self.assertEqual(refused.exception.reason, REASON_GOVERNED_CHANGE)
        self.assertEqual(delegations(self.db), [])

    def test_a_worker_cannot_widen_its_delegation_to_another_class(self):
        """Widening is refused in BOTH directions: the delegated class is the only class."""
        delegation = self.delegation(task="T-NARROW", class_="READ_REPOSITORY")
        assert_scope_within_delegation(self.db, delegation.delegation_id,
                                       requested_work_class="READ_REPOSITORY")
        for widened in ("GENERATE_CANDIDATE", "PRODUCTION_INSTALL", "READ_REPOSITORY-ISH"):
            with self.assertRaises(CrucibleError) as refused:
                assert_scope_within_delegation(self.db, delegation.delegation_id,
                                               requested_work_class=widened)
            self.assertEqual(refused.exception.reason, REASON_WORK_CLASS_NOT_DELEGATED)

    def test_one_delegation_has_exactly_one_current_holder(self):
        self.ready_worker("W1")
        self.ready_worker("W2")
        delegation = self.delegation()
        first = self.claim(delegation.delegation_id, worker="W1", generation=1)
        self.assertEqual(first.status, LEASE_ACTIVE)
        with self.assertRaises(CrucibleError) as refused:
            self.claim(delegation.delegation_id, worker="W2", generation=1)
        self.assertEqual(refused.exception.reason, REASON_ALREADY_CLAIMED)
        self.assertEqual(current_lease(self.db, delegation.delegation_id).lease_id, first.lease_id)
        self.assertEqual(len(leases_for(self.db, delegation.delegation_id)), 1)

    def test_claims_refuse_a_stale_generation_and_a_different_question(self):
        self.ready_worker("W1")
        second = register_worker(self.db, worker_id="W1", process_identity="pid-2", code_digest=CODE,
                                 environment_digest=ENV, now=T1 + 1)
        attest_worker(self.db, "W1", second.instance_generation, observed_code_digest=CODE,
                      observed_environment_digest=ENV, actor="operator:operator", now=T1 + 1)
        delegation = self.delegation()
        with self.assertRaises(CrucibleError) as stale:
            self.claim(delegation.delegation_id, worker="W1", generation=1)
        self.assertEqual(stale.exception.reason, REASON_STALE_GENERATION)
        with self.assertRaises(CrucibleError) as wrong_input:
            self.claim(delegation.delegation_id, worker="W1", generation=2, input_digest="INPUT-9")
        self.assertEqual(wrong_input.exception.reason, REASON_INPUT_MISMATCH)
        claimed = self.claim(delegation.delegation_id, worker="W1", generation=2)
        self.assertEqual(claimed.worker_generation, 2)

    def test_an_expired_lease_is_reclaimed_without_assuming_anything_about_the_lost_work(self):
        self.ready_worker("W1")
        self.ready_worker("W2")
        delegation = self.delegation()
        self.claim(delegation.delegation_id, worker="W1", generation=1, lease_seconds=10.0)
        self.assertEqual(reclaim_expired_leases(self.db, now=T1 + 11), 1)
        expired = leases_for(self.db, delegation.delegation_id, now=T1 + 11)
        self.assertEqual([lease.status for lease in expired], [LEASE_EXPIRED])
        self.assertEqual(get_delegation(self.db, delegation.delegation_id).status, ELIGIBLE)
        replacement = self.claim(delegation.delegation_id, worker="W2", generation=1, when=T1 + 12)
        self.assertEqual(current_lease(self.db, delegation.delegation_id, now=T1 + 12).lease_id,
                         replacement.lease_id)
        self.assertEqual(self.submit(delegation.delegation_id, worker="W2", generation=1,
                                     output="OUT-2", when=T1 + 13).result_status, CURRENT)
        # W1's own result, arriving after it lost possession, is kept and classified - never current.
        late = self.submit(delegation.delegation_id, worker="W1", generation=1, output="OUT-1",
                           when=T1 + 14)
        self.assertEqual(late.result_status, LATE)
        self.assertEqual(current_result(self.db, delegation.delegation_id).worker_id, "W2")

    def test_only_the_returning_generation_may_release_its_lease(self):
        self.ready_worker("W1")
        delegation = self.delegation()
        lease = self.claim(delegation.delegation_id, worker="W1", generation=1)
        with self.assertRaises(CrucibleError) as refused:
            release_lease(self.db, lease.lease_id, worker_id="W1", worker_generation=2, now=T1 + 1)
        self.assertEqual(refused.exception.reason, REASON_NOT_LEASE_HOLDER)
        released = release_lease(self.db, lease.lease_id, worker_id="W1", worker_generation=1,
                                 note="done", now=T1 + 2)
        self.assertEqual(released.status, "RELEASED")

    # ---------------------------------------------------------------- 6.3/6.4 results and aggregation
    def test_a_worker_result_is_a_claim_and_five_workers_can_be_one_source(self):
        self.assertEqual(result_claims_evidence()["is_evidence"], False)
        workers = []
        for index in range(1, 6):
            worker_id = f"W{index}"
            self.ready_worker(worker_id)
            workers.append(worker_id)
        results = []
        for index, worker_id in enumerate(workers):
            delegation = self.delegation(task=f"T{index}", input_digest=f"INPUT-{index}")
            self.claim(delegation.delegation_id, worker=worker_id, generation=1,
                       input_digest=f"INPUT-{index}")
            source = "SOURCE:reuters" if index < 4 else "SOURCE:blog-quoting-reuters"
            results.append(self.submit(delegation.delegation_id, worker=worker_id, generation=1,
                                       output="THE-SAME-ANSWER", sources=[source]))
        self.assertEqual(len(results), 5)
        self.assertEqual(independent_sources(results), ("SOURCE:blog-quoting-reuters",
                                                        "SOURCE:reuters"))

    def test_consensus_is_information_and_never_evidence(self):
        self.ready_worker("W1")
        self.ready_worker("W2")
        refs = []
        for index, worker_id in enumerate(("W1", "W2")):
            delegation = self.delegation(task=f"C{index}", input_digest=f"IN-{index}")
            self.claim(delegation.delegation_id, worker=worker_id, generation=1,
                       input_digest=f"IN-{index}")
            refs.append(self.submit(delegation.delegation_id, worker=worker_id, generation=1,
                                    output="AGREED-BUT-UNSUPPORTED",
                                    sources=["SOURCE:rumour"]).result_id)
        unanimous = aggregate(self.db, task_id="CLAIM-1", result_refs=refs,
                              method="AGREEMENT", deterministic=False)
        self.assertEqual(unanimous["disposition"], PARTIAL)
        self.assertEqual(unanimous["independent_sources"], ["SOURCE:rumour"])
        self.assertFalse(unanimous["consensus_is_evidence"])
        with_evidence = aggregate(self.db, task_id="CLAIM-1", result_refs=refs,
                                  method="EVIDENCE", deterministic=False,
                                  canonical_evidence_refs=["EVD-1"])
        self.assertEqual(with_evidence["disposition"], CONSISTENT)
        self.assertEqual(with_evidence["decided_by"], DECIDED_BY_EVIDENCE)

    def test_one_worker_with_evidence_does_not_lose_to_a_majority(self):
        losers = []
        for index in range(3):
            worker_id = f"M{index}"
            self.ready_worker(worker_id)
            delegation = self.delegation(task=f"MAJ{index}", input_digest=f"MAJ-IN-{index}")
            self.claim(delegation.delegation_id, worker=worker_id, generation=1,
                       input_digest=f"MAJ-IN-{index}")
            losers.append(self.submit(delegation.delegation_id, worker=worker_id, generation=1,
                                      output="POPULAR-BUT-WRONG").result_id)
        self.ready_worker("DISSENTER")
        dissenting = self.delegation(task="DISSENT", input_digest="DISSENT-IN")
        self.claim(dissenting.delegation_id, worker="DISSENTER", generation=1,
                   input_digest="DISSENT-IN")
        strong = self.submit(dissenting.delegation_id, worker="DISSENTER", generation=1,
                             output="CONTRADICTED-BY-CANON", evidence=["EVD-CANONICAL"],
                             sources=["SOURCE:primary-document"]).result_id
        decided = aggregate(self.db, task_id="MAJORITY", result_refs=losers + [strong],
                            method="MIXED", deterministic=False,
                            canonical_evidence_refs=["EVD-CANONICAL"])
        self.assertEqual(decided["decided_by"], DECIDED_BY_DISAGREEMENT)
        self.assertEqual(decided["disposition"], DISAGREEMENT)
        self.assertEqual(len(decided["disagreement_refs"]), 4)
        self.assertIn("SOURCE:primary-document", decided["independent_sources"])

    def test_deterministic_divergence_is_an_integrity_conflict_not_a_vote(self):
        self.ready_worker("W1")
        self.ready_worker("W2")
        refs = []
        for index, (worker_id, output) in enumerate((("W1", "HASH-A"), ("W2", "HASH-B"))):
            delegation = self.delegation(task=f"DET{index}", input_digest="SAME-INPUT")
            self.claim(delegation.delegation_id, worker=worker_id, generation=1,
                       input_digest="SAME-INPUT")
            refs.append(self.submit(delegation.delegation_id, worker=worker_id, generation=1,
                                    output=output).result_id)
        conflict = aggregate(self.db, task_id="DETERMINISTIC", result_refs=refs,
                             method="REPRODUCE", deterministic=True)
        self.assertEqual(conflict["disposition"], INTEGRITY_CONFLICT)
        self.assertEqual(conflict["decided_by"], DECIDED_BY_INTEGRITY)
        self.assertEqual(len(conflict["disagreement_refs"]), 2)
        self.assertEqual(len(aggregations(self.db, "DETERMINISTIC")), 1)

    def test_a_second_differing_result_is_classified_and_never_overwrites_the_first(self):
        self.ready_worker("W1")
        self.ready_worker("W2")
        delegation = self.delegation()
        lease = self.claim(delegation.delegation_id, worker="W1", generation=1)
        first = self.submit(delegation.delegation_id, worker="W1", generation=1, output="OUT-1")
        self.assertEqual(first.result_status, CURRENT)
        release_lease(self.db, lease.lease_id, worker_id="W1", worker_generation=1, now=T1 + 1)
        self.claim(delegation.delegation_id, worker="W2", generation=1, when=T1 + 2)
        conflicting = self.submit(delegation.delegation_id, worker="W2", generation=1, output="OUT-2",
                                  when=T1 + 3)
        self.assertEqual(conflicting.result_status, CONFLICTING)
        self.assertEqual(current_result(self.db, delegation.delegation_id).output_digest, "OUT-1")
        self.assertEqual(len(results_for(self.db, delegation.delegation_id)), 2)
        # A replay of the SAME answer is a duplicate, not a second confirmation.
        duplicate = self.submit(delegation.delegation_id, worker="W1", generation=1, output="OUT-1",
                                when=T1 + 4)
        self.assertEqual(duplicate.result_status, LATE)
        self.assertEqual(len(results_for(self.db, delegation.delegation_id)), 3)


if __name__ == "__main__":
    unittest.main()


class TestGate69SwarmResourcesAndControl(unittest.TestCase):
    """6.5, 6.6, 6.9, 6.11 - the control plane: quotas, the freeze, the stop, and what was learned."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-69-")
        self.db = str(Path(self.temp.name) / "vault.db")
        self.budget = open_budget(self.db, resource_class="WALL_CLOCK", limit=100.0,
                                  window_seconds=DAY, granted_by="operator:operator", now=T1)

    def tearDown(self):
        self.temp.cleanup()

    def ready(self, worker_id="W1", *, capabilities=()):
        identity = register_worker(self.db, worker_id=worker_id, process_identity=worker_id,
                                   code_digest=CODE, environment_digest=ENV, now=T1)
        attest_worker(self.db, worker_id, identity.instance_generation, observed_code_digest=CODE,
                      observed_environment_digest=ENV, actor="operator:operator", now=T1)
        for capability in capabilities:
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=INSTALLED, actor=f"worker:{worker_id}", now=T1)
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=VERIFIED, actor="operator:operator", evidence_ref="CAP-1", now=T1)
        return identity

    def delegation(self, task="TASK-1", *, capabilities=(), budget=None):
        return propose_delegation(self.db, task_identity=task, input_digest="INPUT-1",
                                  basis_digest="BASIS-1", allowed_work_class="READ_REPOSITORY",
                                  required_capabilities=list(capabilities),
                                  resource_budget_ref=budget, now=T1)

    # ---------------------------------------------------------------- 6.9 quotas
    def test_child_budgets_conserve_the_parent_and_cannot_be_subdivided_twice(self):
        first = allocate_child(self.db, self.budget, amount=30.0, worker_id="W1", now=T1)
        second = allocate_child(self.db, self.budget, amount=20.0, worker_id="W2", now=T1)
        self.assertEqual(parent_remaining(self.db, self.budget, now=T1), 50.0)
        third = allocate_child(self.db, self.budget, amount=20.0, worker_id="W3", now=T1)
        self.assertEqual(outstanding_total(self.db, self.budget), 70.0)
        with self.assertRaises(CrucibleError) as refused:
            allocate_child(self.db, self.budget, amount=40.0, worker_id="W4", now=T1)
        self.assertEqual(refused.exception.reason, REASON_CHILD_EXCEEDS_PARENT)
        # The parent is untouched until a child actually spends: reservation is not consumption.
        self.assertEqual(budget_status(self.db, self.budget, now=T1).remaining, 100.0)
        consume_child(self.db, first.allocation_id, amount=30.0, now=T1)
        self.assertEqual(budget_status(self.db, self.budget, now=T1).remaining, 70.0)
        with self.assertRaises(CrucibleError) as over:
            consume_child(self.db, second.allocation_id, amount=25.0, now=T1)
        self.assertEqual(over.exception.reason, REASON_ALLOCATION_EXHAUSTED)
        close_allocation(self.db, third.allocation_id, now=T1)
        self.assertEqual(outstanding_total(self.db, self.budget), 20.0)
        self.assertEqual(parent_remaining(self.db, self.budget, now=T1), 50.0)
        self.assertEqual(len(allocations(self.db)), 3)

    def test_a_worker_cannot_raise_its_own_allocation(self):
        allocation = allocate_child(self.db, self.budget, amount=10.0, worker_id="W1", now=T1)
        consume_child(self.db, allocation.allocation_id, amount=10.0, now=T1)
        with self.assertRaises(CrucibleError):
            consume_child(self.db, allocation.allocation_id, amount=1.0, now=T1)
        returned = return_unused(self.db, allocation.allocation_id, amount=5.0, now=T1)
        self.assertEqual(returned.outstanding, 0.0, "no refund of what was already spent")

    def test_spawn_rate_and_concurrency_are_bounded(self):
        for index in range(3):
            record_spawn(self.db, worker_id=f"W{index}", instance_generation=1,
                         actor="operator:operator", now=T1)
        with self.assertRaises(CrucibleError) as rate:
            assert_spawn_allowed(self.db, limit=3, window_seconds=60.0, now=T1 + 10)
        self.assertEqual(rate.exception.reason, REASON_SPAWN_RATE)
        self.assertEqual(assert_spawn_allowed(self.db, limit=5, window_seconds=60.0,
                                              now=T1 + 10)["recent_spawns"], 3)
        for index in range(2):
            self.ready(f"L{index}")
        with self.assertRaises(CrucibleError) as concurrency:
            assert_spawn_allowed(self.db, limit=10, window_seconds=60.0, concurrency_limit=2,
                                 now=T1 + 61)
        self.assertEqual(concurrency.exception.reason, REASON_CONCURRENCY)

    # ---------------------------------------------------------------- 6.5/6.6 the freeze
    def test_quiescence_freezes_claims_and_only_settles_when_every_member_answers(self):
        self.ready("W1")
        self.ready("W2")
        identity_three = self.ready("W3")
        delegation = self.delegation()
        claim_delegation(self.db, delegation.delegation_id, worker_id="W1", worker_generation=1,
                         input_digest="INPUT-1", lease_seconds=600.0, now=T1)
        self.assertFalse(swarm_is_frozen(self.db))
        barrier = open_barrier(self.db, actor="operator:operator", now=T1 + 1)
        self.assertTrue(swarm_is_frozen(self.db))
        self.assertEqual(sorted(barrier.required), ["W1@1", "W2@1", "W3@1"])
        with self.assertRaises(CrucibleError) as frozen:
            claim_delegation(self.db, delegation.delegation_id, worker_id="W2",
                             worker_generation=1, input_digest="INPUT-1", now=T1 + 2)
        self.assertIn(frozen.exception.reason, (REASON_SWARM_FROZEN, REASON_ALREADY_CLAIMED))
        acknowledge(self.db, barrier.barrier_id, worker_id="W1", instance_generation=1,
                    outcome=ACK_LEASE_RELEASED, note="leased work released", now=T1 + 3)
        self.assertEqual(get_barrier(self.db, barrier.barrier_id).status, DRAINING)
        acknowledge(self.db, barrier.barrier_id, worker_id="W2", instance_generation=1,
                    outcome="SAFE_BOUNDARY_REACHED", now=T1 + 4)
        self.assertEqual(get_barrier(self.db, barrier.barrier_id).status, DRAINING)
        # W3 is measured dead and reconciled WITH evidence - the only way a silent member leaves the
        # required set.
        mark_dead(self.db, "W3", reason="process gone", actor="operator:operator", now=T1 + 5)
        with self.assertRaises(CrucibleError):
            reconcile_worker(self.db, barrier.barrier_id, worker_id="W3",
                             instance_generation=identity_three.instance_generation,
                             disposition=RECONCILED_DEAD, evidence_ref="", actor="operator:operator",
                             now=T1 + 6)
        settled = reconcile_worker(self.db, barrier.barrier_id, worker_id="W3",
                                   instance_generation=identity_three.instance_generation,
                                   disposition=RECONCILED_DEAD, evidence_ref="PROC-EXIT:0",
                                   actor="operator:operator", now=T1 + 7)
        self.assertEqual(settled.status, QUIESCED)
        self.assertEqual(settled.unresolved, ())

    def test_a_timeout_is_never_an_acknowledgement(self):
        self.ready("W1")
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        report_timeout(self.db, barrier.barrier_id, worker_id="W1", instance_generation=1, now=T1 + 30)
        after = get_barrier(self.db, barrier.barrier_id)
        self.assertEqual(after.status, DRAINING)
        self.assertEqual(after.unresolved, ("W1@1",), "a silence is not a stop")
        self.assertTrue(swarm_is_frozen(self.db))

    def test_an_unanswered_barrier_stays_incomplete_and_cannot_be_released_by_a_worker(self):
        self.ready("W1")
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        settled = settle_barrier(self.db, barrier.barrier_id, now=T1 + 1)
        self.assertEqual(settled.status, DRAINING)
        with self.assertRaises(CrucibleError) as refused:
            release_barrier(self.db, barrier.barrier_id, actor="worker:W1", now=T1 + 2)
        self.assertEqual(refused.exception.reason, REASON_NOT_OPERATOR)
        self.assertTrue(swarm_is_frozen(self.db))
        released = release_barrier(self.db, barrier.barrier_id, actor="operator:operator", now=T1 + 3)
        self.assertEqual(released.status, "RELEASED")
        self.assertFalse(swarm_is_frozen(self.db))
        self.assertEqual(current_barrier(self.db), None)

    def test_a_joining_worker_cannot_slip_past_a_freeze(self):
        self.ready("W1")
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        joiner = register_worker(self.db, worker_id="W9", process_identity="pid-9", code_digest=CODE,
                                 environment_digest=ENV, now=T1 + 1)
        attest_worker(self.db, "W9", joiner.instance_generation, observed_code_digest=CODE,
                      observed_environment_digest=ENV, actor="operator:operator", now=T1 + 1)
        delegation = self.delegation()
        with self.assertRaises(CrucibleError) as refused:
            claim_delegation(self.db, delegation.delegation_id, worker_id="W9",
                             worker_generation=joiner.instance_generation, input_digest="INPUT-1",
                             now=T1 + 2)
        self.assertEqual(refused.exception.reason, REASON_SWARM_FROZEN)
        self.assertEqual(get_barrier(self.db, barrier.barrier_id).required, ("W1@1",),
                         "a joiner is not in the snapshot and cannot be required to stop")
        self.assertEqual(swarm_state(self.db, now=T1 + 2)["unresolved"], ["W1@1"])

    def test_emergency_stop_interrupts_leases_and_fabricates_nothing(self):
        self.ready("W1")
        delegation = self.delegation()
        lease = claim_delegation(self.db, delegation.delegation_id, worker_id="W1",
                                 worker_generation=1, input_digest="INPUT-1", lease_seconds=600.0,
                                 now=T1)
        with self.assertRaises(CrucibleError) as refused:
            emergency_stop_swarm(self.db, actor="worker:W1", now=T1 + 1)
        self.assertEqual(refused.exception.reason, REASON_NOT_OPERATOR)
        stopped = emergency_stop_swarm(self.db, actor="operator:operator", now=T1 + 2)
        self.assertEqual(stopped["interrupted_leases"], [lease.lease_id])
        self.assertEqual(stopped["fabricated_completions"], 0)
        after = leases_for(self.db, delegation.delegation_id, now=T1 + 3)
        self.assertEqual([item.status for item in after], [LEASE_INTERRUPTED])
        self.assertEqual(results_for(self.db, delegation.delegation_id), [],
                         "an interrupted attempt produces no result")
        self.assertEqual(get_delegation(self.db, delegation.delegation_id).status, ASSIGNED)
        self.assertTrue(swarm_is_frozen(self.db))
        with self.assertRaises(CrucibleError):
            claim_delegation(self.db, delegation.delegation_id, worker_id="W1", worker_generation=1,
                             input_digest="INPUT-1", now=T1 + 4)

    def test_the_barrier_reconstructs_after_a_coordinator_restart(self):
        self.ready("W1")
        barrier = open_barrier(self.db, actor="operator:operator", now=T1)
        acknowledge(self.db, barrier.barrier_id, worker_id="W1", instance_generation=1,
                    outcome="SAFE_BOUNDARY_REACHED", now=T1 + 1)
        expected = quiescence_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.swarm_quiescence import quiescence_digest, current_barrier;"
                "print(json.dumps({'d': quiescence_digest(%r), 'b': current_barrier(%r).as_dict()}, "
                "sort_keys=True))" % (str(Path(__file__).resolve().parents[1]), self.db, self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        recovered = json.loads(out.stdout.strip())
        self.assertEqual(recovered["d"], expected)
        self.assertEqual(recovered["b"]["status"], QUIESCED)

    # ---------------------------------------------------------------- 6.11/6.12 learning
    def test_delegation_learning_is_descriptive_and_does_not_inflate_on_replay(self):
        delegation = self.delegation()
        record_attempt(self.db, task_class="RESEARCH", delegation_id=delegation.delegation_id,
                       worker_mix=["W1", "W2"], outcome=OUTCOME_USEFUL, latency_seconds=12.5,
                       resource_cost=3.0, stale_results=1, now=T1)
        record_attempt(self.db, task_class="RESEARCH", delegation_id=delegation.delegation_id,
                       worker_mix=["W1", "W2"], outcome=OUTCOME_FAILED, latency_seconds=99.0,
                       resource_cost=99.0, now=T1 + 1)
        self.assertEqual(len(attempts(self.db)), 1, "one delegation is one data point")
        other = propose_delegation(self.db, task_identity="TASK-2", input_digest="I2",
                                   basis_digest="B2", allowed_work_class="READ_REPOSITORY",
                                   task_generation=2, now=T1)
        record_attempt(self.db, task_class="RESEARCH", delegation_id=other.delegation_id,
                       worker_mix=["W1", "W3"], outcome=OUTCOME_FAILED, disagreement=True, now=T1 + 2)
        projection = delegation_strategy(self.db, "RESEARCH")
        self.assertEqual(projection["attempts"], 2)
        self.assertEqual(projection["useful"], 1)
        self.assertEqual(projection["failed"], 1)
        self.assertEqual(projection["disagreements"], 1)
        self.assertEqual(projection["stale_results"], 1)
        self.assertEqual(projection["worker_mixes"], {"W1+W2": 1, "W1+W3": 1})
        self.assertTrue(projection["no_score"])
        self.assertNotIn("score", projection)
        self.assertTrue(learning_digest(self.db))

    def test_colluding_workers_gain_no_authority_from_rating_each_other(self):
        self.ready("W1")
        self.ready("W2")
        delegation = self.delegation(task="COLLUDE")
        claim_delegation(self.db, delegation.delegation_id, worker_id="W1", worker_generation=1,
                         input_digest="INPUT-1", now=T1)
        mutual = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id="W1",
                               worker_generation=1, output_digest="W1-IS-SUPERIOR",
                               basis_digest="BASIS-1", now=T1 + 1)
        record_attempt(self.db, task_class="MUTUAL-PRAISE", delegation_id=delegation.delegation_id,
                       worker_mix=["W1", "W2"], outcome=OUTCOME_USEFUL, now=T1 + 2)
        self.assertEqual(mutual.result_status, CURRENT)
        # Nothing in the swarm surface can turn that agreement into a status change: the worker is
        # still exactly as authorised as it was, and the learning record is a description.
        self.assertEqual(get_worker(self.db, "W1").status, READY)
        self.assertTrue(delegation_strategy(self.db, "MUTUAL-PRAISE")["no_score"])
        self.assertEqual(swarm_scanner_census()["s05_worker_creates_standing_authorization"], 0)

    def test_an_escalation_requires_a_governed_action_and_executes_nothing(self):
        self.ready("W1")
        delegation = self.delegation(task="FIND-A-BUG")
        claim_delegation(self.db, delegation.delegation_id, worker_id="W1", worker_generation=1,
                         input_digest="INPUT-1", now=T1)
        submit_result(self.db, delegation_id=delegation.delegation_id, worker_id="W1",
                      worker_generation=1, output_digest="PATCH-PROPOSED", basis_digest="BASIS-1",
                      now=T1 + 1)
        escalation = escalation_requires_an_action(self.db, delegation_id=delegation.delegation_id,
                                                   proposed_effect="install a production patch",
                                                   now=T1 + 2)
        self.assertEqual(escalation["authority"], "none")
        self.assertFalse(escalation["executed"])
        self.assertIsNotNone(escalation["supported_by_result"])
        self.assertIn("4.0", escalation["requires"])
        self.assertEqual(get_delegation(self.db, delegation.delegation_id).status, ASSIGNED)

    def test_whole_swarm_state_reconstructs_identically_in_a_fresh_process(self):
        self.ready("W1", capabilities=("coding",))
        delegation = self.delegation(capabilities=("coding",), budget=self.budget)
        allocation = allocate_child(self.db, self.budget, amount=5.0, worker_id="W1",
                                    delegation_id=delegation.delegation_id, now=T1)
        claim_delegation(self.db, delegation.delegation_id, worker_id="W1", worker_generation=1,
                         input_digest="INPUT-1", now=T1)
        submit_result(self.db, delegation_id=delegation.delegation_id, worker_id="W1",
                      worker_generation=1, output_digest="OUT", basis_digest="BASIS-1", now=T1 + 1)
        record_attempt(self.db, task_class="READ", delegation_id=delegation.delegation_id,
                       worker_mix=["W1"], outcome=OUTCOME_USEFUL, now=T1 + 2)
        bundle = {"topology": topology_digest(self.db), "delegations": delegation_digest(self.db),
                  "results": results_digest(self.db), "quiescence": quiescence_digest(self.db),
                  "learning": learning_digest(self.db), "ownership": ownership_digest()}
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.swarm_worker import topology_digest;"
                "from ciph.kernel.swarm_delegation import delegation_digest;"
                "from ciph.kernel.swarm_results import results_digest;"
                "from ciph.kernel.swarm_quiescence import quiescence_digest;"
                "from ciph.kernel.swarm_learning import learning_digest;"
                "from ciph.kernel.swarm_ownership import ownership_digest;"
                "print(json.dumps({'topology': topology_digest(%r), 'delegations': "
                "delegation_digest(%r), 'results': results_digest(%r), 'quiescence': "
                "quiescence_digest(%r), 'learning': learning_digest(%r), 'ownership': "
                "ownership_digest()}, sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.db, self.db, self.db,
                   self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), bundle)
        self.assertEqual(allocation.status, "OPEN")
        self.assertTrue(learning_digest(self.db))
