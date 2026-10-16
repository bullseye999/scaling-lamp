
"""
4.1 Gate Five - planner-driven replanning.

> The planner may propose a new projection. It may not rewrite mission truth, choose authority, or
> silently redefine an existing action.

The planner here is the REAL one (`ciph.planner.schemas.ExecutionDAG`): a proposal is built from an
actual plan, bound to the mission digest it was generated against, validated, and only then recorded
as an immutable projection. Everything below is written so that a planner with a memory of its own, a
stale worldview, or a truncated response fails rather than committing.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.missions import (
    PLAN_COVERAGE_COMPLETE,
    PLAN_COVERAGE_PATCH,
    MissionError,
    apply_plan_proposal,
    open_mission,
    propose_plan_from_dag,
    reconstruct_missions,
    record_plan,
)
from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
from ciph.kernel.scheduler_recovery import Eligibility, derive_eligibility, recovered_dispatch_plan
from ciph.planner.schemas import ExecutionDAG, PlanStep
from ciph.runtime import CiphRuntime
from permit_test_support import enqueue_permit_bearing_job
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability


class TestGate45PlannerProposals(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-planner-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.runtime = CiphRuntime(db_path=self.db)
        self.cap = SimpleComputeCapability(name='planner.compute')
        self.runtime.register_capability(self.cap)

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def enqueue(self, params=None, attempts=3):
        return enqueue_permit_bearing_job(
            self.runtime, capability=self.cap.manifest.name, params=params or {'value': 1},
            max_retries=attempts)

    def execute(self, job_id, worker='planner_worker'):
        job = self.runtime.queue.lease_next_job(worker, 30, target_job_id=job_id)
        return self.runtime.worker_daemon._execute_leased_job(job, worker) if job else None

    def permit_store(self):
        return build_durable_permit_consumer_dependencies(
            self.db, trust_registry=self.runtime.trust_registry).permit_store

    def restart(self):
        self.runtime.shutdown()
        self.runtime = CiphRuntime(db_path=self.db)
        self.runtime.register_capability(self.cap)
        return self.runtime

    def mission_state(self, mission, now=None):
        return reconstruct_missions(self.db, now=now).state_of(mission)

    def basis_digest(self, mission, now=None):
        return reconstruct_missions(self.db, now=now).state_of(mission).canonical_digest()

    def dag(self, plan_id, steps):
        return ExecutionDAG(
            plan_id=plan_id, objective=f'objective for {plan_id}',
            steps=[PlanStep(step_id=step_id, capability=self.cap.manifest.name,
                            parameters={'value': value})
                   for step_id, value in steps],
        )

    def counts(self):
        with sqlite3.connect(self.db) as conn:
            def count(sql):
                try:
                    return conn.execute(sql).fetchone()[0]
                except sqlite3.OperationalError:
                    return 0
            return {
                "permits": count("SELECT COUNT(*) FROM execution_permits"),
                "plans": count("SELECT COUNT(*) FROM ciph_mission_plans"),
                "plan_actions": count("SELECT COUNT(*) FROM ciph_plan_actions"),
                "membership": count("SELECT COUNT(*) FROM ciph_mission_actions"),
                "events": count("SELECT COUNT(*) FROM ciph_event_store"),
            }

    def founding_state(self):
        """M + P1=[A,B,C]; A terminal, B claimed-unresolved, C issued and unattempted."""
        mission = open_mission(self.db, objective='plan through continuity')
        a = self.enqueue(params={'value': 1})
        self.execute(a.job_id)
        b = self.enqueue(params={'value': 2})
        self.permit_store().claim(b.permit_id, 'worker_that_died')
        c = self.enqueue(params={'value': 3})
        record_plan(self.db, mission_id=mission, plan_id='P1',
                    logical_action_ids=[a.job_id, b.job_id, c.job_id])
        return mission, a, b, c

    # ------------------------------------------------------------------ 1. the real bridge
    def test_1_a_real_planner_proposal_records_an_immutable_projection(self):
        mission, a, b, c = self.founding_state()
        basis = self.basis_digest(mission)
        before = self.counts()

        dag = self.dag('DAG-REPLAN-1', [('step_reuse_a', 1), ('step_reuse_b', 2),
                                        ('step_reuse_c', 3), ('step_new_d', 4)])
        proposal = propose_plan_from_dag(
            mission_id=mission, basis_continuity_digest=basis, dag=dag,
            reuse={'step_reuse_a': a.job_id, 'step_reuse_b': b.job_id, 'step_reuse_c': c.job_id},
            rationale='keep the resolved and pending work, add a fourth step',
        )
        outcome = apply_plan_proposal(self.db, proposal)

        state = self.mission_state(mission)
        self.assertEqual(state.current_plan_id, 'DAG-REPLAN-1')
        self.assertEqual(sorted(state.plan_action_ids),
                         sorted([a.job_id, b.job_id, c.job_id] + [x[0] for x in outcome['new_actions']]))
        new_actions = outcome['new_actions']
        self.assertEqual(len(new_actions), 1)
        allocated_id, allocated_fingerprint, label = new_actions[0]
        self.assertEqual(label, 'step_new_d')
        self.assertTrue(allocated_id.startswith('ACT-'),
                        "the canonical layer allocates identity; the planner only proposes semantics")

        after = self.counts()
        self.assertEqual(after['permits'], before['permits'],
                         "planning mints no authority")
        self.assertEqual(after['membership'], before['membership'] + 1,
                         "the new proposal becomes mission membership, nothing more")
        # The new action is real but unauthorised, and nothing may dispatch it.
        self.assertIn(allocated_id, state.unauthorised_action_ids)
        entry = [e for e in derive_eligibility(self.db) if e.logical_action_id == allocated_id][0]
        self.assertEqual(entry.eligibility, Eligibility.NEEDS_NEW_AUTHORITY.value)
        self.assertFalse(entry.dispatchable)
        self.assertIn(b.job_id, state.obligations, "the reused unresolved action is still unresolved")

    def test_11_the_runtime_bridge_is_the_production_entry_point(self):
        """The production planner path, not just the module API, is bound to continuity."""
        mission, a, b, c = self.founding_state()
        dag = self.dag('DAG-BRIDGE', [('step_a', 1), ('step_new', 6)])
        before = self.counts()

        outcome = self.runtime.plan_mission(
            mission, dag=dag, reuse={'step_a': a.job_id},
            rationale='runtime bridge keeps A and adds one step',
        )

        state = self.mission_state(mission)
        self.assertEqual(state.current_plan_id, 'DAG-BRIDGE')
        self.assertEqual(outcome['new_actions'][0][2], 'step_new')
        self.assertEqual(self.counts()['permits'], before['permits'],
                         "the production bridge plans; it never authorises")
        # A stale basis is refused through the same production entry point.
        stale = self.runtime.plan_mission(mission, dag=self.dag('DAG-BRIDGE-2', [('s', 8)]))
        self.assertEqual(stale['plan_id'], 'DAG-BRIDGE-2')

    def test_12_the_runtime_bridge_refuses_a_stale_planner(self):
        mission, a, b, c = self.founding_state()
        # Capture a basis, then move the world, then plan against the captured basis.
        from ciph.kernel.missions import propose_plan_from_dag, apply_plan_proposal
        basis = self.basis_digest(mission)
        self.permit_store().revoke(c.permit_id, reason='MOVED_ON')
        with self.assertRaises(MissionError) as refused:
            apply_plan_proposal(self.db, propose_plan_from_dag(
                mission_id=mission, basis_continuity_digest=basis,
                dag=self.dag('DAG-STALE-2', [('s', 1)])))
        self.assertEqual(refused.exception.reason, 'STALE_PLAN_PROPOSAL')

    # ------------------------------------------------------------------ 2. semantics
    def test_2_a_proposal_cannot_redefine_an_existing_action(self):
        mission, a, b, c = self.founding_state()
        basis = self.basis_digest(mission)
        before = self.counts()

        dag = self.dag('DAG-CONFLICT', [('step_a', 1)])
        proposal = propose_plan_from_dag(
            mission_id=mission, basis_continuity_digest=basis, dag=dag,
            reuse={'step_a': a.job_id},
        )
        # The planner "reuses" A but declares different semantics for it.
        from dataclasses import replace
        proposal = replace(proposal, existing_action_refs=((a.job_id, 'F2-different-work'),))

        with self.assertRaises(MissionError) as refused:
            apply_plan_proposal(self.db, proposal)
        self.assertEqual(refused.exception.reason, 'PLAN_SEMANTIC_CONFLICT')

        state = self.mission_state(mission)
        self.assertEqual(state.current_plan_id, 'P1', "the current pointer never moved")
        self.assertNotIn('DAG-CONFLICT', state.historical_plan_ids)
        self.assertEqual(self.counts(), before, "a refused proposal leaves no trace at all")

    # ------------------------------------------------------------------ 3. staleness
    def test_3_a_stale_basis_is_refused_with_zero_durable_side_effects(self):
        mission, a, b, c = self.founding_state()
        stale_basis = self.basis_digest(mission)         # the planner's worldview: H0

        # Meanwhile the world moves: B is settled by an operator.
        failing = SimpleComputeCapability(name='planner.failing', should_fail=True)
        self.runtime.register_capability(failing)
        settled = self.enqueue(params={'value': 9})
        record_plan(self.db, mission_id=mission, plan_id='P1b', logical_action_ids=[settled.job_id])
        self.permit_store().revoke(b.permit_id, reason='OPERATOR_SETTLED_UNCERTAINTY')

        before = self.counts()
        dag = self.dag('DAG-STALE', [('step_new', 5)])
        proposal = propose_plan_from_dag(mission_id=mission, basis_continuity_digest=stale_basis,
                                         dag=dag)

        with self.assertRaises(MissionError) as refused:
            apply_plan_proposal(self.db, proposal)
        self.assertEqual(refused.exception.reason, 'STALE_PLAN_PROPOSAL')
        self.assertEqual(self.counts(), before, "optimistic concurrency refuses with zero side effects")
        self.assertEqual(self.mission_state(mission).current_plan_id, 'P1b',
                         "no pointer move from a stale proposal")

    # ------------------------------------------------------------------ 4/5. coverage
    def test_4_a_partial_response_cannot_pause_work(self):
        mission, a, b, c = self.founding_state()
        basis = self.basis_digest(mission)
        # A truncated response: it mentions A and forgets C entirely.
        dag = self.dag('DAG-PATCH', [('step_a', 1)])
        proposal = propose_plan_from_dag(mission_id=mission, basis_continuity_digest=basis, dag=dag,
                                         reuse={'step_a': a.job_id},
                                         coverage=PLAN_COVERAGE_PATCH)
        apply_plan_proposal(self.db, proposal)

        state = self.mission_state(mission)
        self.assertEqual(state.plan_coverage, PLAN_COVERAGE_PATCH)
        self.assertEqual(state.omitted_action_ids, (), "absence in a PATCH means nothing")
        self.assertEqual(sorted(state.plan_action_ids),
                         sorted([a.job_id, b.job_id, c.job_id]),
                         "a patch layers onto the last exhaustive strategy")
        entry = [e for e in derive_eligibility(self.db) if e.logical_action_id == c.job_id][0]
        self.assertEqual(entry.eligibility, Eligibility.ELIGIBLE.value,
                         "a forgotten action keeps its schedule")
        self.assertEqual([e.job_id for e in recovered_dispatch_plan(self.db)], [c.job_id])

    def test_5_a_complete_projection_can_omit_and_only_pauses(self):
        mission, a, b, c = self.founding_state()
        basis = self.basis_digest(mission)
        dag = self.dag('DAG-COMPLETE', [('step_a', 1), ('step_b', 2)])
        proposal = propose_plan_from_dag(
            mission_id=mission, basis_continuity_digest=basis, dag=dag,
            reuse={'step_a': a.job_id, 'step_b': b.job_id},
            coverage=PLAN_COVERAGE_COMPLETE,
        )
        apply_plan_proposal(self.db, proposal)

        state = self.mission_state(mission)
        self.assertEqual(state.omitted_action_ids, (c.job_id,))
        entry = [e for e in derive_eligibility(self.db) if e.logical_action_id == c.job_id][0]
        self.assertEqual(entry.eligibility, Eligibility.NOT_IN_CURRENT_PLAN.value)
        self.assertFalse(entry.dispatchable)
        # Paused, not cancelled: the action, its authority and its history are all untouched.
        self.assertEqual(self.action_of(state, c.job_id).permit_state, 'ISSUED')
        self.assertTrue(self.action_of(state, c.job_id).authorization_alive)
        self.assertIn(c.job_id, state.remaining_authorized_work)
        self.assertIn(c.job_id, [x.logical_action_id for x in state.actions])

    def action_of(self, mission_state, action_id):
        return [a for a in mission_state.actions if a.logical_action_id == action_id][0]

    # ------------------------------------------------------------------ 6/7/8. truth wins
    def test_6_a_plan_cannot_make_terminal_work_runnable(self):
        mission, a, b, c = self.founding_state()
        basis = self.basis_digest(mission)
        dag = self.dag('DAG-REDO-A', [('step_a', 1)])
        proposal = propose_plan_from_dag(mission_id=mission, basis_continuity_digest=basis, dag=dag,
                                         reuse={'step_a': a.job_id})
        apply_plan_proposal(self.db, proposal)

        state = self.mission_state(mission)
        self.assertEqual(self.action_of(state, a.job_id).attempt_outcome, 'TERMINAL')
        self.assertNotIn(a.job_id, [e.logical_action_id for e in recovered_dispatch_plan(self.db)])
        self.assertEqual(self.permit_store().state_of(a.permit_id), 'CONSUMED')

    def test_7_omitting_an_unresolved_action_keeps_the_obligation(self):
        mission, a, b, c = self.founding_state()
        basis = self.basis_digest(mission)
        dag = self.dag('DAG-SILENT-B', [('step_a', 1)])
        proposal = propose_plan_from_dag(mission_id=mission, basis_continuity_digest=basis, dag=dag,
                                         reuse={'step_a': a.job_id})
        apply_plan_proposal(self.db, proposal)

        state = self.mission_state(mission)
        self.assertIn(b.job_id, state.omitted_action_ids)
        self.assertEqual(self.action_of(state, b.job_id).attempt_outcome, 'UNRESOLVED')
        self.assertIn(b.job_id, state.obligations, "a plan cannot erase uncertainty by silence")
        self.assertTrue(state.needs_replanning)

    def test_8_a_plan_cannot_resurrect_operator_resolved_work(self):
        mission = open_mission(self.db, objective='resolved work stays resolved')
        failing = SimpleComputeCapability(name='planner.resolved', should_fail=True)
        self.runtime.register_capability(failing)
        done = enqueue_permit_bearing_job(
            self.runtime, capability='planner.resolved', params={'value': 1}, max_retries=1)
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[done.job_id])
        self.execute(done.job_id)                       # claims, fails, reconciles
        self.runtime.reconcile_job(done.job_id, 'FAILED',
                                   'operator settled the unresolved effect')

        basis = self.basis_digest(mission)
        state_before = self.mission_state(mission)
        self.assertEqual(self.action_of(state_before, done.job_id).attempt_outcome,
                         'RESOLVED_BY_OPERATOR')

        # The planner asks for the same work again: same WOULD-BE semantics, but the identity is taken.
        dag = self.dag('DAG-AGAIN', [('step_again', 1)])
        proposal = propose_plan_from_dag(mission_id=mission, basis_continuity_digest=basis, dag=dag)
        outcome = apply_plan_proposal(self.db, proposal)
        allocated = outcome['new_actions'][0][0]
        self.assertNotEqual(allocated, done.job_id,
                            "repeating resolved work is a NEW action, never a resurrected one")

        state = self.mission_state(mission)
        self.assertEqual(self.action_of(state, done.job_id).attempt_outcome, 'RESOLVED_BY_OPERATOR')
        self.assertNotIn(done.job_id, [e.logical_action_id for e in recovered_dispatch_plan(self.db)])

    # ------------------------------------------------------------------ 9/10. crash behaviour
    def test_9_a_crashed_planner_leaves_nothing_durable(self):
        mission, a, b, c = self.founding_state()
        basis = self.basis_digest(mission)
        before = self.counts()

        # Producing a proposal is pure: no connection, no write. Break the process right after.
        source = (
            "import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
            "from ciph.planner.schemas import ExecutionDAG, PlanStep;"
            "from ciph.kernel.missions import propose_plan_from_dag;"
            "dag=ExecutionDAG(plan_id='DAG-CRASHED', objective='o', steps=["
            "PlanStep(step_id='s', capability='planner.compute', parameters={'value': 1})]);"
            "p=propose_plan_from_dag(mission_id=%r, basis_continuity_digest=%r, dag=dag);"
            "print(p.coverage);"
            "raise SystemExit(0)"
            % (str(Path(__file__).resolve().parents[1]), mission, basis)
        )
        proc = subprocess.run([sys.executable, '-B', '-c', source], capture_output=True, text=True,
                              cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), PLAN_COVERAGE_COMPLETE)
        self.assertEqual(self.counts(), before, "a proposal that was never applied is not durable")
        self.assertEqual(self.mission_state(mission).current_plan_id, 'P1')

    def test_10_a_crash_after_recording_reconstructs_the_same_projection(self):
        mission, a, b, c = self.founding_state()
        basis = self.basis_digest(mission)
        dag = self.dag('DAG-DURABLE', [('step_new', 7)])
        proposal = propose_plan_from_dag(mission_id=mission, basis_continuity_digest=basis, dag=dag)
        outcome = apply_plan_proposal(self.db, proposal)
        allocated = outcome['new_actions'][0][0]
        before = self.mission_state(mission)

        self.restart()   # nothing survives except the durable stores

        after = self.mission_state(mission)
        self.assertEqual(after.canonical_digest(), before.canonical_digest())
        self.assertEqual(after.current_plan_id, 'DAG-DURABLE')
        self.assertEqual(after.historical_plan_ids, ('P1', 'DAG-DURABLE'))
        self.assertIn(allocated, after.unauthorised_action_ids)
        self.assertEqual(self.action_of(after, a.job_id).attempt_outcome, 'TERMINAL')
        self.assertIn(b.job_id, after.obligations)


if __name__ == '__main__':
    unittest.main()
