
"""
4.1 Gate One - mission continuity.

Gate Zero answers *what is true*. Gate One answers *what unfinished purpose those truths belong to*,
without letting a plan, a scheduler, or old process memory stand in for authority.

The two founding scenarios are `test_scenario_one_*` and `test_scenario_two_*`; the nine laws each have
a specimen that could falsify them.
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.continuity import complete_pending_consumption, reconstruct
from ciph.kernel.missions import (
    MISSION_ACTIVE,
    MISSION_COMPLETED,
    MissionError,
    attach_action,
    complete_mission,
    open_mission,
    reconstruct_missions,
    record_plan,
    supersede_plan,
)
from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
from ciph.runtime import CiphRuntime
from permit_test_support import enqueue_permit_bearing_job
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability


class TestGate41MissionContinuity(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-41-mission-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.runtime = CiphRuntime(db_path=self.db)
        self.cap = SimpleComputeCapability(name='mission.compute')
        self.runtime.register_capability(self.cap)

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def enqueue(self, cap=None, params=None, attempts=3):
        cap = cap or self.cap
        return enqueue_permit_bearing_job(
            self.runtime, capability=cap.manifest.name, params=params or {'value': 1},
            max_retries=attempts)

    def execute(self, job_id, worker='mission_worker'):
        job = self.runtime.queue.lease_next_job(worker, 30, target_job_id=job_id)
        return self.runtime.worker_daemon._execute_leased_job(job, worker) if job else None

    def permit_store(self):
        return build_durable_permit_consumer_dependencies(
            self.db, trust_registry=self.runtime.trust_registry).permit_store

    def restart(self):
        self.runtime.shutdown()
        self.runtime = CiphRuntime(db_path=self.db)
        return self.runtime

    def action(self, mission_state, logical_action_id):
        return [a for a in mission_state.actions if a.logical_action_id == logical_action_id][0]

    def permit_count(self):
        # A store that has never held a permit has no table yet; "no authority exists" is zero, not
        # an error.
        with sqlite3.connect(self.db) as conn:
            try:
                return conn.execute("SELECT COUNT(*) FROM execution_permits").fetchone()[0]
            except sqlite3.OperationalError:
                return 0

    def max_generation(self, logical_action_id):
        with sqlite3.connect(self.db) as conn:
            try:
                return conn.execute(
                    "SELECT COALESCE(MAX(authorization_generation), -1) FROM execution_permits "
                    "WHERE logical_action_id = ?;", (logical_action_id,)).fetchone()[0]
            except sqlite3.OperationalError:
                return -1

    # ------------------------------------------------------------------ scenario one
    def test_scenario_one_restart_reconstructs_the_same_mission(self):
        mission = open_mission(self.db, objective='publish the audit')
        done = self.enqueue(params={'value': 1})
        self.execute(done.job_id)                      # A: terminal
        pending = self.enqueue(params={'value': 2})
        self.permit_store().claim(pending.permit_id, 'worker_that_died')   # B: unresolved
        queued = self.enqueue(params={'value': 3})     # C: issued, never attempted
        record_plan(self.db, mission_id=mission, plan_id='P1',
                    logical_action_ids=[done.job_id, pending.job_id, queued.job_id])

        before = reconstruct_missions(self.db).state_of(mission)
        permits_before = self.permit_count()

        self.restart()
        after = reconstruct_missions(self.db).state_of(mission)

        self.assertEqual(after.mission_id, mission)
        self.assertEqual(after.canonical_digest(), before.canonical_digest(),
                         "a restart changed what the durable record says about the mission")
        self.assertEqual(after.status, MISSION_ACTIVE)
        self.assertEqual(self.action(after, done.job_id).attempt_outcome, 'TERMINAL')
        self.assertEqual(self.action(after, pending.job_id).attempt_outcome, 'UNRESOLVED')
        self.assertIn(pending.job_id, after.obligations)
        self.assertEqual(self.action(after, queued.job_id).attempt_outcome, 'NOT_ATTEMPTED')
        self.assertTrue(self.action(after, queued.job_id).authorization_alive)
        # P1 survives as planning context; it is not authority.
        self.assertIn('P1', after.historical_plan_ids)
        # No new action, no fresh permit, no invented completion.
        self.assertEqual(len(after.actions), 3)
        self.assertEqual(self.permit_count(), permits_before)
        self.assertFalse(after.completion_eligible)
        self.assertTrue(after.needs_replanning)

    # ------------------------------------------------------------------ scenario two
    def test_scenario_two_replanning_preserves_identity_and_only_adds_new_actions(self):
        mission = open_mission(self.db, objective='publish the audit')
        done = self.enqueue(params={'value': 1})
        self.execute(done.job_id)
        pending = self.enqueue(params={'value': 2})
        self.permit_store().claim(pending.permit_id, 'worker_that_died')
        queued = self.enqueue(params={'value': 3})
        record_plan(self.db, mission_id=mission, plan_id='P1',
                    logical_action_ids=[done.job_id, pending.job_id, queued.job_id])

        # P2: A done, B needs reconciliation, C still needed, D newly required.
        new_needed = self.enqueue(params={'value': 4})
        outcome = record_plan(self.db, mission_id=mission, plan_id='P2',
                              logical_action_ids=[done.job_id, pending.job_id,
                                                   queued.job_id, new_needed.job_id])
        supersede_plan(self.db, plan_id='P1', superseded_by='P2')

        self.assertEqual(set(outcome['already_known']),
                         {done.job_id, pending.job_id, queued.job_id},
                         "a plan reuses existing action identities, it never renames them")
        self.assertEqual(outcome['newly_attached'], (new_needed.job_id,),
                         "a genuinely new requirement gets a genuinely new action")

        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(state.mission_id, mission, "replanning never moves mission identity")
        self.assertEqual(self.action(state, done.job_id).attempt_outcome, 'TERMINAL')
        self.assertEqual(self.action(state, pending.job_id).attempt_outcome, 'UNRESOLVED')
        self.assertEqual(self.action(state, queued.job_id).attempt_outcome, 'NOT_ATTEMPTED')
        self.assertEqual(self.action(state, new_needed.job_id).attempt_outcome, 'NOT_ATTEMPTED')
        self.assertEqual(state.plan_ids, ('P2',))
        self.assertIn('P1', state.historical_plan_ids, "the old plan is history, not garbage")
        self.assertEqual(len(state.actions), 4)

    # ------------------------------------------------------------------ law 1
    def test_law_1_mission_identity_is_stable(self):
        mission = open_mission(self.db, objective='identity')
        self.restart()
        self.assertEqual(reconstruct_missions(self.db).state_of(mission).mission_id, mission)
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[])
        self.assertEqual(reconstruct_missions(self.db).state_of(mission).mission_id, mission)

    # ------------------------------------------------------------------ law 2
    def test_law_2_a_mission_confers_no_authority(self):
        mission = open_mission(self.db, objective='no authority')
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=['ACT-NEVER-ISSUED'])
        self.assertEqual(self.permit_count(), 0, "a mission and its plan mint nothing")
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(state.remaining_authorized_work, ())
        self.assertFalse(state.completion_eligible)
        # Attaching the same action again is idempotent: membership is not authority.
        self.assertFalse(attach_action(self.db, mission_id=mission, logical_action_id='ACT-NEVER-ISSUED'))

    # ------------------------------------------------------------------ law 3 + 4
    def test_law_3_and_4_actions_outlive_plans_and_plans_are_not_truth(self):
        mission = open_mission(self.db, objective='plans are projections')
        done = self.enqueue(params={'value': 1})
        self.execute(done.job_id)
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[done.job_id])
        before = reconstruct_missions(self.db).state_of(mission)
        events_before = reconstruct(self.db).source_counts

        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM ciph_plan_actions WHERE plan_id = 'P1'")
            conn.execute("DELETE FROM ciph_mission_plans WHERE plan_id = 'P1'")

        after = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual([a.logical_action_id for a in after.actions],
                         [a.logical_action_id for a in before.actions],
                         "deleting a plan cannot erase a mission action")
        self.assertEqual(self.action(after, done.job_id).attempt_outcome, 'TERMINAL',
                         "nor the evidence that resolved it")
        self.assertEqual(after.obligations, before.obligations)
        self.assertEqual(reconstruct(self.db).source_counts, events_before)
        self.assertEqual(after.historical_plan_ids, ())

    # ------------------------------------------------------------------ law 5
    def test_law_5_restart_does_not_imply_replanning(self):
        mission = open_mission(self.db, objective='restart ne replan')
        done = self.enqueue(params={'value': 1})
        self.execute(done.job_id)
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[done.job_id])

        before = reconstruct_missions(self.db).state_of(mission)
        self.assertFalse(before.needs_replanning, "an open durable plan needs no new planning")
        self.restart()
        after = reconstruct_missions(self.db).state_of(mission)
        self.assertFalse(after.needs_replanning,
                         "restart must not manufacture a reason to replan")
        self.assertEqual(after.canonical_digest(), before.canonical_digest())

    # ------------------------------------------------------------------ law 6
    def test_law_6_unresolved_work_survives_restart_attached_to_the_mission(self):
        mission = open_mission(self.db, objective='unresolved survives')
        blocked = self.enqueue(params={'value': 1})
        claim = self.permit_store().claim(blocked.permit_id, 'worker_that_died')
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[blocked.job_id])

        self.restart()
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertIn(blocked.job_id, state.obligations)
        self.assertIn(claim.execution_attempt_id, state.unresolved_attempts)
        self.assertEqual(self.action(state, blocked.job_id).execution_attempt_id,
                         claim.execution_attempt_id, "the same attempt, not a new one")

    # ------------------------------------------------------------------ law 7
    def test_law_7_terminal_work_is_not_redispatched_by_a_new_plan(self):
        mission = open_mission(self.db, objective='terminal stays dead')
        done = self.enqueue(params={'value': 1})
        self.execute(done.job_id)
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[done.job_id])
        permits_before = self.permit_count()
        generation_before = self.max_generation(done.job_id)

        record_plan(self.db, mission_id=mission, plan_id='P2', logical_action_ids=[done.job_id])

        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(self.action(state, done.job_id).attempt_outcome, 'TERMINAL')
        self.assertEqual(self.permit_count(), permits_before,
                         "naming a finished action in a new plan mints nothing")
        self.assertEqual(self.max_generation(done.job_id), generation_before)
        self.assertNotIn(done.job_id, state.remaining_authorized_work)

    # ------------------------------------------------------------------ law 8
    def test_law_8_a_plan_cannot_disguise_an_old_action_as_new(self):
        mission = open_mission(self.db, objective='no duplication')
        done = self.enqueue(params={'value': 1})
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[done.job_id])
        generation_before = self.max_generation(done.job_id)

        # A later plan that "proposes" the same action must be recognised as a REUSE.
        outcome = record_plan(self.db, mission_id=mission, plan_id='P2',
                              logical_action_ids=[done.job_id])
        self.assertEqual(outcome['already_known'], (done.job_id,))
        self.assertEqual(outcome['newly_attached'], ())

        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(len([a for a in state.actions if a.logical_action_id == done.job_id]), 1,
                         "one action identity cannot appear twice")
        self.assertEqual(self.max_generation(done.job_id), generation_before,
                         "reuse grants no fresh authority")
        self.assertEqual(self.permit_count(), 1)

    # ------------------------------------------------------------------ law 9
    def test_law_9_completion_is_evidence_based(self):
        mission = open_mission(self.db, objective='evidence-based completion')
        done = self.enqueue(params={'value': 1})
        self.execute(done.job_id)
        queued = self.enqueue(params={'value': 2})
        record_plan(self.db, mission_id=mission, plan_id='P1',
                    logical_action_ids=[done.job_id, queued.job_id])

        # Live, unattempted authority blocks closure: it would leave a spendable permit attached to a
        # finished purpose.
        with self.assertRaises(MissionError) as refused:
            complete_mission(self.db, mission_id=mission, reason='looks finished')
        self.assertEqual(refused.exception.reason, 'MISSION_HAS_OPEN_OBLIGATIONS')
        self.assertIn(queued.job_id, refused.exception.detail)

        # Dead-letter the unused authority, then the mission is provably complete.
        self.permit_store().revoke(self.unclaimed_permit_id(queued.job_id), reason='MISSION_ABANDONED')
        self.assertTrue(complete_mission(self.db, mission_id=mission, reason='all actions resolved'))
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(state.status, MISSION_COMPLETED)

    def test_law_9_an_unresolved_attempt_blocks_completion(self):
        mission = open_mission(self.db, objective='unresolved blocks')
        blocked = self.enqueue(params={'value': 1})
        self.permit_store().claim(blocked.permit_id, 'worker_that_died')
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[blocked.job_id])
        with self.assertRaises(MissionError) as refused:
            complete_mission(self.db, mission_id=mission, reason='looks finished')
        self.assertEqual(refused.exception.reason, 'MISSION_HAS_OPEN_OBLIGATIONS')
        self.assertIn(blocked.job_id, refused.exception.detail)

    def unclaimed_permit_id(self, job_id):
        raw = self.runtime.queue.get_job(job_id)['execution_permit']
        return (json.loads(raw) if isinstance(raw, str) else raw)['permit_id']

    # ------------------------------------------------------------------ determinism
    def test_mission_reconstruction_is_deterministic_across_restart(self):
        mission = open_mission(self.db, objective='determinism')
        a = self.enqueue(params={'value': 1})
        self.execute(a.job_id)
        b = self.enqueue(params={'value': 2})
        self.permit_store().claim(b.permit_id, 'w')
        record_plan(self.db, mission_id=mission, plan_id='P1',
                    logical_action_ids=[a.job_id, b.job_id])
        moment = 1_800_000_000.0

        first = reconstruct_missions(self.db, now=moment).canonical_digest()
        self.restart()
        second = reconstruct_missions(self.db, now=moment).canonical_digest()
        self.assertEqual(first, second)


if __name__ == '__main__':
    unittest.main()
