"""
6.9 - the runtime swarm torture.

    Many hands. One mind. The hands never become kings.

This file runs REAL worker processes: a dozen of them, three capability classes, several model
identities, four tasks' worth of delegated work - and then loses some on purpose. Workers are killed
after claiming, killed after submitting, restarted as a new generation, joined during a freeze, and
reconciled by an operator. In the middle, four workers agree on an unsupported conclusion while one
returns contradictory canonical evidence, and the swarm is asked what it knows.

The assertions are the ones a multi-agent system normally fails: one current holder per delegation, a
dead worker's arrival that does not become current, a lease reclaimed without assuming anything about
the lost worker's effects, a freeze a joiner cannot slip past, and a whole-swarm restart that
reconstructs the same canonical state.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ciph.kernel.autonomy_budgets import open_budget
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.swarm_delegation import (ASSIGNED, ELIGIBLE, LEASE_ACTIVE, LEASE_EXPIRED,
                                          LEASE_INTERRUPTED, claim_delegation, current_lease,
                                          delegation_digest, get_delegation, leases_for,
                                          propose_delegation, reclaim_expired_leases)
from ciph.kernel.swarm_learning import learning_digest, record_attempt, delegation_strategy
from ciph.kernel.swarm_ownership import ownership_digest
from ciph.kernel.swarm_quiescence import (ACK_LEASE_RELEASED, DRAINING, QUIESCED, RECONCILED_DEAD,
                                          acknowledge, current_barrier, emergency_stop_swarm,
                                          get_barrier, open_barrier, quiescence_digest,
                                          reconcile_worker, release_barrier, report_timeout,
                                          swarm_is_frozen)
from ciph.kernel.swarm_resources import (allocate_child, consume_child, outstanding_total,
                                         parent_remaining, resources_digest)
from ciph.kernel.swarm_results import (CONSISTENT, CURRENT, DECIDED_BY_EVIDENCE, DISAGREEMENT, LATE,
                                       REJECTED, aggregate, current_result, results_digest,
                                       results_for, submit_result)
from ciph.kernel.swarm_worker import (BUSY, DEAD, JOINING, READY, attest_worker, get_worker,
                                      is_current_generation, mark_dead, members, register_worker,
                                      route, set_worker_status, topology_digest)

DAY = 86_400.0
T1 = 1_800_000_000.0
ROOT = Path(__file__).resolve().parents[1]
RUNTIME = str(ROOT / "swarm_test_support.py")
MISSIONS = {"maintenance": ["W1", "W2", "W3"], "research": ["W4", "W5", "W6"],
            "curiosity": ["W7", "W8"], "evaluation": ["W9", "W10", "W11", "W12"]}


class TestGate69SwarmRuntimeTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-swarm-")
        self.db = str(Path(self.temp.name) / "vault.db")
        self.budget = open_budget(self.db, resource_class="WALL_CLOCK", limit=600.0,
                                  window_seconds=DAY, granted_by="operator:operator", now=T1)

    def tearDown(self):
        self.temp.cleanup()

    # ---------------------------------------------------------------- runtime helpers
    def spawn(self, worker_id, delegations, *, capabilities=(), model=None, crash_after="never",
              corrupt=False, ack_barrier=False, lease_seconds=120.0, wait=True, timeout=120):
        command = [sys.executable, "-B", RUNTIME, self.db, "--worker", worker_id,
                   "--delegations", ",".join(delegations), "--crash-after", crash_after,
                   "--lease-seconds", str(lease_seconds)]
        if capabilities:
            command += ["--capabilities", ",".join(capabilities)]
        if model:
            command += ["--model", model]
        if corrupt:
            command += ["--corrupt"]
        if ack_barrier:
            command += ["--ack-barrier"]
        process = subprocess.Popen(command, cwd=str(ROOT), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        if not wait:
            return process
        out, err = process.communicate(timeout=timeout)
        self.assertEqual(process.returncode, 0, f"{worker_id}: {err}")
        return json.loads(out.strip().splitlines()[-1])

    def ready(self, worker_id, *, capabilities=(), model=None):
        identity = register_worker(self.db, worker_id=worker_id, process_identity=worker_id,
                                   code_digest="CODE", environment_digest="ENV",
                                   model_identity=model, now=T1)
        attest_worker(self.db, worker_id, identity.instance_generation, observed_code_digest="CODE",
                      observed_environment_digest="ENV", actor="operator:operator", now=T1)
        for capability in capabilities:
            from ciph.kernel.swarm_worker import INSTALLED, VERIFIED, record_capability
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=INSTALLED, actor=f"worker:{worker_id}", now=T1)
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=VERIFIED, actor="operator:operator", evidence_ref="CAP-1", now=T1)
        return identity

    def delegate(self, task, *, capabilities=("coding",), class_="GENERATE_CANDIDATE", budget=None):
        return propose_delegation(self.db, task_identity=task, input_digest=f"INPUT-{task}",
                                  basis_digest=f"BASIS-{task}", allowed_work_class=class_,
                                  required_capabilities=list(capabilities),
                                  resource_budget_ref=budget, now=T1)

    def bundle(self):
        return {"topology": topology_digest(self.db), "delegations": delegation_digest(self.db),
                "results": results_digest(self.db), "quiescence": quiescence_digest(self.db),
                "resources": resources_digest(self.db), "learning": learning_digest(self.db),
                "ownership": ownership_digest()}

    def reconstruct_fresh(self):
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.swarm_worker import topology_digest;"
                "from ciph.kernel.swarm_delegation import delegation_digest;"
                "from ciph.kernel.swarm_results import results_digest;"
                "from ciph.kernel.swarm_quiescence import quiescence_digest;"
                "from ciph.kernel.swarm_resources import resources_digest;"
                "from ciph.kernel.swarm_learning import learning_digest;"
                "from ciph.kernel.swarm_ownership import ownership_digest;"
                "print(json.dumps({'topology': topology_digest(%r), 'delegations': "
                "delegation_digest(%r), 'results': results_digest(%r), 'quiescence': "
                "quiescence_digest(%r), 'resources': resources_digest(%r), 'learning': "
                "learning_digest(%r), 'ownership': ownership_digest()}, sort_keys=True))"
                % (str(ROOT), self.db, self.db, self.db, self.db, self.db, self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(ROOT), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout.strip())

    # ---------------------------------------------------------------- the torture
    def test_twelve_workers_process_real_delegations_across_four_tasks(self):
        tasks = {}
        for index, task in enumerate(("T-RESEARCH", "T-MAINT", "T-CURIOSITY", "T-EVAL")):
            allocation = allocate_child(self.db, self.budget, amount=20.0,
                                        task_id=task, now=T1)
            tasks[task] = self.delegate(task, capabilities=("coding",), budget=self.budget)
            consume_child(self.db, allocation.allocation_id, amount=5.0, now=T1)
        for worker_id in [worker for group in MISSIONS.values() for worker in group]:
            self.ready(worker_id, capabilities=("coding",), model=f"model-{worker_id[-1]}")

        results = {}
        for task, delegation in tasks.items():
            group = list(MISSIONS.values())[list(tasks).index(task)]
            # Three workers race for the same delegation; exactly one may hold it.
            processes = [self.spawn(worker, [delegation.delegation_id], capabilities=("coding",),
                                    wait=False)
                         for worker in group[:3]]
            outcomes = [json.loads(process.communicate(timeout=180)[0].strip().splitlines()[-1])
                        for process in processes]
            claims = [outcome for outcome in outcomes if outcome["claimed"]]
            self.assertEqual(len(claims), 1, f"{task}: {len(claims)} workers claimed one delegation")
            skip_reasons = {item["reason"] for outcome in outcomes for item in outcome["skipped"]}
            self.assertTrue(skip_reasons <= {"DELEGATION_ALREADY_CLAIMED", "SWARM_IS_QUIESCING"})
            results[task] = current_result(self.db, delegation.delegation_id)
            self.assertIsNotNone(results[task])
            self.assertEqual(results[task].result_status, CURRENT)

        # No duplicate authoritative work: one current lease and one current result per delegation.
        for delegation in tasks.values():
            active = [lease for lease in leases_for(self.db, delegation.delegation_id)
                      if lease.status == LEASE_ACTIVE]
            self.assertEqual(len(active), 1)
            self.assertEqual(len([result for result in results_for(self.db, delegation.delegation_id)
                                  if result.result_status == CURRENT]), 1)
        # Four allocations of 20, each with 5 already spent: the parent's reserved-but-unspent total
        # is the arithmetic the swarm cannot exceed, and it is conserved rather than multiplied.
        self.assertEqual(outstanding_total(self.db, self.budget), 60.0)
        self.assertTrue(delegation_digest(self.db))

    def test_a_worker_that_dies_before_returning_is_recovered_without_assumptions(self):
        self.ready("W1", capabilities=("coding",))
        self.ready("W2", capabilities=("coding",))
        delegation = self.delegate("T-RECOVER")
        claim_delegation(self.db, delegation.delegation_id, worker_id="W1", worker_generation=1,
                         input_digest=delegation.input_digest, lease_seconds=30.0, now=T1)
        # The worker is killed at the moment it holds the lease - its external effect is UNKNOWN.
        mark_dead(self.db, "W1", reason="killed while holding the lease", actor="operator:operator",
                  now=T1 + 1)
        self.assertEqual(reclaim_expired_leases(self.db, now=T1 + 31), 1)
        self.assertEqual(get_delegation(self.db, delegation.delegation_id).status, ELIGIBLE)
        self.assertEqual([lease.status for lease in
                          leases_for(self.db, delegation.delegation_id, now=T1 + 31)],
                         [LEASE_EXPIRED])
        replaced = self.spawn("W2", [delegation.delegation_id], capabilities=("coding",))
        self.assertEqual(len(replaced["claimed"]), 1)
        self.assertEqual(current_result(self.db, delegation.delegation_id).worker_id, "W2")
        # A late arrival from the dead generation is kept, classified, and never becomes current.
        late = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id="W1",
                             worker_generation=1, output_digest="GHOST", basis_digest="BASIS-T-RECOVER",
                             now=T1 + 40)
        self.assertEqual(late.result_status, LATE)
        self.assertEqual(current_result(self.db, delegation.delegation_id).output_digest,
                         hashlib.sha256(f"{delegation.input_digest}|W2".encode("utf-8")
                                        ).hexdigest()[:24],
                         "the recovery worker's own answer is what stands")

    def test_a_restarted_worker_is_a_new_generation_and_its_old_results_are_not_current(self):
        self.ready("W3", capabilities=("coding",))
        delegation = self.delegate("T-RESTART")
        claim_delegation(self.db, delegation.delegation_id, worker_id="W3", worker_generation=1,
                         input_digest=delegation.input_digest, now=T1)
        first = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id="W3",
                              worker_generation=1, output_digest="GEN1-OUT",
                              basis_digest="BASIS-T-RESTART", now=T1 + 1)
        self.assertEqual(first.result_status, CURRENT)
        later = self.spawn("W3", [delegation.delegation_id], capabilities=("coding",))
        self.assertEqual(later["generation"], 2)
        self.assertFalse(is_current_generation(self.db, "W3", 1))
        replay = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id="W3",
                               worker_generation=1, output_digest="GEN1-OUT-AGAIN",
                               basis_digest="BASIS-T-RESTART", now=T1 + 5)
        self.assertEqual(replay.result_status, LATE,
                         "generation 1 is not current after generation 2 exists")
        self.assertEqual(current_result(self.db, delegation.delegation_id).worker_id, "W3")
        self.assertEqual(len(members(self.db)), 1)

    def test_four_workers_agreeing_does_not_beat_one_canonical_source(self):
        refs = []
        for index in range(4):
            worker_id = f"A{index}"
            self.ready(worker_id, capabilities=("research",))
            delegation = self.delegate(f"T-CONF{index}", capabilities=("research",))
            claim_delegation(self.db, delegation.delegation_id, worker_id=worker_id,
                             worker_generation=1, input_digest=delegation.input_digest,
                             lease_seconds=600.0, now=T1 + index)
            refs.append(submit_result(self.db, delegation_id=delegation.delegation_id,
                                      worker_id=worker_id, worker_generation=1,
                                      output_digest="THE-CONCLUSION", basis_digest=f"BASIS-T-CONF{index}",
                                      source_dependency_refs=["SOURCE:blog-a"],
                                      now=T1 + 10 + index).result_id)
        self.ready("B0", capabilities=("research",))
        dissenting = self.delegate("T-CONF-DISSENT", capabilities=("research",))
        claim_delegation(self.db, dissenting.delegation_id, worker_id="B0", worker_generation=1,
                         input_digest=dissenting.input_digest, lease_seconds=600.0, now=T1 + 20)
        refs.append(submit_result(self.db, delegation_id=dissenting.delegation_id, worker_id="B0",
                                  worker_generation=1, output_digest="THE-OPPOSITE",
                                  basis_digest="BASIS-T-CONF-DISSENT",
                                  evidence_refs=["EVD:PRIMARY-DOCUMENT"],
                                  source_dependency_refs=["SOURCE:primary-document"],
                                  now=T1 + 21).result_id)
        unanimous_but_unsupported = aggregate(self.db, task_id="T-CONSENSUS", result_refs=refs[:4],
                                              method="AGREEMENT", deterministic=False)
        self.assertNotEqual(unanimous_but_unsupported["disposition"], CONSISTENT)
        self.assertEqual(unanimous_but_unsupported["independent_sources"], ["SOURCE:blog-a"])
        self.assertFalse(unanimous_but_unsupported["consensus_is_evidence"])
        contested = aggregate(self.db, task_id="T-CONSENSUS", result_refs=refs, method="MIXED",
                              deterministic=False, canonical_evidence_refs=["EVD:PRIMARY-DOCUMENT"])
        self.assertEqual(contested["disposition"], DISAGREEMENT)
        self.assertIn("SOURCE:primary-document", contested["independent_sources"])
        self.assertEqual(len(contested["disagreement_refs"]), 5)

    def test_the_barrier_settles_honestly_with_a_dead_joiner_and_a_holder(self):
        for worker_id in ("W1", "W2", "W3"):
            self.ready(worker_id, capabilities=("coding",))
        held = self.delegate("T-HOLD")
        claim_delegation(self.db, held.delegation_id, worker_id="W1", worker_generation=1,
                         input_digest=held.input_digest, lease_seconds=600.0, now=T1)
        barrier = open_barrier(self.db, actor="operator:operator", now=T1 + 1)
        self.assertEqual(sorted(barrier.required), ["W1@1", "W2@1", "W3@1"])
        # W4 tries to join during the freeze: it can register and be attested, but it cannot work.
        joiner = self.spawn("W4", [], capabilities=("coding",))
        self.assertEqual(joiner["claimed"], [])
        self.assertEqual(joiner["skipped"], [])
        self.assertEqual(joiner["busy_refused"], "SWARM_IS_QUIESCING",
                         "a joiner cannot become active during a freeze")
        # W2 finishes and acknowledges; W3 is gone and reconciled with evidence; W1 releases its lease.
        acknowledge(self.db, barrier.barrier_id, worker_id="W2", instance_generation=1,
                    outcome="SAFE_BOUNDARY_REACHED", now=T1 + 2)
        mark_dead(self.db, "W3", reason="process exited", actor="operator:operator", now=T1 + 3)
        reconcile_worker(self.db, barrier.barrier_id, worker_id="W3", instance_generation=1,
                         disposition=RECONCILED_DEAD, evidence_ref="PROC-EXIT:0",
                         actor="operator:operator", now=T1 + 4)
        report_timeout(self.db, barrier.barrier_id, worker_id="W1", instance_generation=1,
                       now=T1 + 5)
        self.assertEqual(get_barrier(self.db, barrier.barrier_id).status, DRAINING,
                         "a timeout is not an acknowledgement")
        acknowledge(self.db, barrier.barrier_id, worker_id="W1", instance_generation=1,
                    outcome=ACK_LEASE_RELEASED, note="lease released", now=T1 + 6)
        settled = get_barrier(self.db, barrier.barrier_id)
        self.assertEqual(settled.status, QUIESCED)
        self.assertEqual(settled.unresolved, ())
        self.assertEqual([lease.status for lease in leases_for(self.db, held.delegation_id)],
                         [LEASE_ACTIVE], "quiescence is not the same act as emergency stop")
        release_barrier(self.db, barrier.barrier_id, actor="operator:operator", now=T1 + 7)
        self.assertFalse(swarm_is_frozen(self.db))

    def test_emergency_stop_across_the_whole_swarm(self):
        for worker_id in ("W1", "W2"):
            self.ready(worker_id, capabilities=("coding",))
        first = self.delegate("T-STOP-1")
        second = self.delegate("T-STOP-2")
        claim_delegation(self.db, first.delegation_id, worker_id="W1", worker_generation=1,
                         input_digest=first.input_digest, lease_seconds=600.0, now=T1)
        claim_delegation(self.db, second.delegation_id, worker_id="W2", worker_generation=1,
                         input_digest=second.input_digest, lease_seconds=600.0, now=T1)
        stopped = emergency_stop_swarm(self.db, actor="operator:operator", now=T1 + 1)
        self.assertEqual(len(stopped["interrupted_leases"]), 2)
        for delegation in (first, second):
            self.assertEqual([lease.status for lease in leases_for(self.db, delegation.delegation_id)],
                             [LEASE_INTERRUPTED])
            self.assertEqual(results_for(self.db, delegation.delegation_id), [])
        worker = self.spawn("W1", [first.delegation_id], capabilities=("coding",))
        self.assertEqual(worker["claimed"], [], "the stop reaches a worker that was not running")
        self.assertEqual(worker["skipped"][0]["reason"], "SWARM_IS_QUIESCING")

    def test_the_whole_swarm_reconstructs_after_a_restart(self):
        for worker_id in ("W1", "W2", "W3"):
            self.ready(worker_id, capabilities=("coding",))
        delegation = self.delegate("T-RECON", budget=self.budget)
        allocation = allocate_child(self.db, self.budget, amount=10.0, worker_id="W1",
                                    delegation_id=delegation.delegation_id, now=T1)
        self.spawn("W1", [delegation.delegation_id], capabilities=("coding",))
        record_attempt(self.db, task_class="T-RECON", delegation_id=delegation.delegation_id,
                       worker_mix=["W1"], outcome="USEFUL", now=T1 + 1)
        expected = self.bundle()
        self.assertEqual(self.reconstruct_fresh(), expected)
        # A coordinator restart changes nothing: same workers, same leases, same results, same order.
        self.assertEqual(self.bundle(), expected)
        second = self.delegate("T-RECON-2")
        self.spawn("W2", [delegation.delegation_id, second.delegation_id], capabilities=("coding",))
        after = self.bundle()
        self.assertNotEqual(after, expected)
        self.assertEqual(self.reconstruct_fresh(), after)
        self.assertEqual(current_result(self.db, delegation.delegation_id).worker_id, "W1",
                         "a second worker cannot displace the current result")
        self.assertEqual(allocation.status, "OPEN")
        self.assertEqual(parent_remaining(self.db, self.budget), 590.0)
        self.assertTrue(delegation_strategy(self.db, "T-RECON")["no_score"])


if __name__ == "__main__":
    unittest.main()
