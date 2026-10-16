
"""
4.1 Gate Two - durable plan projections.

    A plan describes how a mission might proceed. It never changes what already happened,
    never grants authority, and never changes the identity of an existing logical action.

The founding specimen and the hostile specimen come first; then one case per law.
"""

import json
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.missions import (
    MISSION_ACTIVE,
    MissionError,
    complete_mission,
    open_mission,
    reconstruct_missions,
    record_plan,
)
from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
from ciph.runtime import CiphRuntime
from permit_test_support import enqueue_permit_bearing_job
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability


class TestGate42PlanProjections(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-42-plans-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.runtime = CiphRuntime(db_path=self.db)
        self.cap = SimpleComputeCapability(name='plan.compute')
        self.runtime.register_capability(self.cap)

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def enqueue(self, params=None, attempts=3):
        return enqueue_permit_bearing_job(
            self.runtime, capability=self.cap.manifest.name, params=params or {'value': 1},
            max_retries=attempts)

    def execute(self, job_id, worker='plan_worker'):
        job = self.runtime.queue.lease_next_job(worker, 30, target_job_id=job_id)
        return self.runtime.worker_daemon._execute_leased_job(job, worker) if job else None

    def permit_store(self):
        return build_durable_permit_consumer_dependencies(
            self.db, trust_registry=self.runtime.trust_registry).permit_store

    def restart(self):
        self.runtime.shutdown()
        self.runtime = CiphRuntime(db_path=self.db)
        return self.runtime

    def action(self, mission_state, action_id):
        return [a for a in mission_state.actions if a.logical_action_id == action_id][0]

    def plan(self, mission_state, plan_id):
        return [p for p in mission_state.plan_history if p.plan_id == plan_id][0]

    def founding_state(self):
        """M + P1=[A,B,C] with A terminal, B unresolved, C issued and unattempted."""
        mission = open_mission(self.db, objective='publish the audit')
        a = self.enqueue(params={'value': 1})
        self.execute(a.job_id)
        b = self.enqueue(params={'value': 2})
        self.permit_store().claim(b.permit_id, 'worker_that_died')
        c = self.enqueue(params={'value': 3})
        record_plan(self.db, mission_id=mission, plan_id='P1',
                    logical_action_ids=[a.job_id, b.job_id, c.job_id])
        return mission, a, b, c

    def permit_count(self):
        with sqlite3.connect(self.db) as conn:
            try:
                return conn.execute("SELECT COUNT(*) FROM execution_permits").fetchone()[0]
            except sqlite3.OperationalError:
                return 0

    # ------------------------------------------------------------------ founding specimen
    def test_replanning_records_what_it_reuses_omits_and_adds(self):
        mission, a, b, c = self.founding_state()
        d = self.enqueue(params={'value': 4})

        outcome = record_plan(self.db, mission_id=mission, plan_id='P2',
                              logical_action_ids=[a.job_id, b.job_id, d.job_id])

        self.assertEqual(set(outcome['already_known']), {a.job_id, b.job_id})
        self.assertEqual(outcome['newly_attached'], (d.job_id,))
        state = reconstruct_missions(self.db).state_of(mission)

        # A - reused by identity, still terminal, still not runnable
        self.assertEqual(self.action(state, a.job_id).attempt_outcome, 'TERMINAL')
        self.assertNotIn(a.job_id, state.remaining_authorized_work)

        # B - reused by identity, still unresolved, obligation survives
        self.assertEqual(self.action(state, b.job_id).attempt_outcome, 'UNRESOLVED')
        self.assertIn(b.job_id, state.obligations)

        # C - omitted from P2, and omission is NOT cancellation
        self.assertNotIn(c.job_id, state.plan_action_ids)
        self.assertIn(c.job_id, state.omitted_action_ids)
        self.assertIn(c.job_id, [x.logical_action_id for x in state.actions],
                      "an omitted action is still a mission action")
        self.assertEqual(self.action(state, c.job_id).permit_state, 'ISSUED')
        self.assertTrue(self.action(state, c.job_id).authorization_alive,
                        "omission alone must not revoke anything")

        # D - genuinely new semantic work, genuinely new identity
        self.assertEqual(self.action(state, d.job_id).attempt_outcome, 'NOT_ATTEMPTED')

        # Plan history: P1 intact and historical, P2 current
        self.assertEqual(state.current_plan_id, 'P2')
        # A projection records a SET of action references; reconstruction orders them canonically
        # so the digest is stable regardless of insertion order (step ORDER belongs to the
        # planner/DAG layer, not to identity).
        self.assertEqual(sorted(self.plan(state, 'P1').action_ids),
                         sorted((a.job_id, b.job_id, c.job_id)))
        self.assertFalse(self.plan(state, 'P1').is_current)
        self.assertTrue(self.plan(state, 'P2').is_current)
        self.assertEqual(state.mission_id, mission)
        self.assertEqual(state.status, MISSION_ACTIVE)

        # Plan evolution and authority evolution are SEPARATE operations: cancel C explicitly.
        self.permit_store().revoke(self.permit_id_of(c.job_id), reason='STRATEGY_DROPPED_C')
        after = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(self.action(after, c.job_id).permit_state, 'REVOKED')
        self.assertFalse(self.action(after, c.job_id).authorization_alive)
        self.assertIn(c.job_id, [x.logical_action_id for x in after.actions],
                      "cancelling authority does not erase the historical action")

    def permit_id_of(self, job_id):
        raw = self.runtime.queue.get_job(job_id)['execution_permit']
        return (json.loads(raw) if isinstance(raw, str) else raw)['permit_id']

    # ------------------------------------------------------------------ hostile specimen
    def test_a_plan_cannot_change_an_existing_actions_semantics(self):
        mission = open_mission(self.db, objective='hostile replan')
        a = self.enqueue(params={'value': 1})
        canonical = a.permit.payload.action_fingerprint
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id],
                    action_fingerprints={a.job_id: canonical})

        # P2 tries: same logical action id, different semantics.
        with self.assertRaises(MissionError) as refused:
            record_plan(self.db, mission_id=mission, plan_id='P2', logical_action_ids=[a.job_id],
                        action_fingerprints={a.job_id: 'F2-different-work'})
        self.assertEqual(refused.exception.reason, 'PLAN_SEMANTIC_CONFLICT')
        self.assertIn(a.job_id, refused.exception.detail)

        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(state.current_plan_id, 'P1', "the refused plan was not made current")
        self.assertEqual(state.historical_plan_ids, ('P1',))
        # If the work changed semantically, it is a NEW action - not a mutated old one.
        same_id_again = self.enqueue(params={'value': 1})   # identical params, new intent
        self.assertNotEqual(same_id_again.job_id, a.job_id)
        outcome = record_plan(self.db, mission_id=mission, plan_id='P2',
                              logical_action_ids=[a.job_id, same_id_again.job_id])
        self.assertEqual(outcome['newly_attached'], (same_id_again.job_id,))

    # ------------------------------------------------------------------ laws 10, 11
    def test_law_10_a_plan_is_not_authority(self):
        mission = open_mission(self.db, objective='no authority')
        before = self.permit_count()
        record_plan(self.db, mission_id=mission, plan_id='P1',
                    logical_action_ids=['ACT-NEVER-ISSUED'])
        self.assertEqual(self.permit_count(), before, "recording a plan mints nothing")
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(state.remaining_authorized_work, ())
        self.assertFalse(state.completion_eligible)

    def test_law_11_a_plan_cannot_alter_history(self):
        mission, a, _b, _c = self.founding_state()
        before = reconstruct_missions(self.db).state_of(mission)
        # Record a plan whose rationale flatly contradicts the evidence.
        record_plan(self.db, mission_id=mission, plan_id='P2', logical_action_ids=[a.job_id],
                    objective='pretend A is still outstanding')
        after = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(self.action(after, a.job_id).attempt_outcome, 'TERMINAL')
        self.assertEqual(self.action(after, a.job_id).attempt_outcome,
                         self.action(before, a.job_id).attempt_outcome)
        self.assertEqual(after.obligations, before.obligations)

    # ------------------------------------------------------------------ laws 12, 13
    def test_law_12_and_13_projections_are_immutable_and_supersession_is_a_pointer(self):
        mission, a, b, c = self.founding_state()
        p1_before = self.plan(reconstruct_missions(self.db).state_of(mission), 'P1').as_dict()

        record_plan(self.db, mission_id=mission, plan_id='P2', logical_action_ids=[a.job_id])
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(self.plan(state, 'P1').as_dict(), {**p1_before, 'is_current': False},
                         "only currentness moved; the projection itself is untouched")
        # A projection records a SET of action references; reconstruction orders them canonically
        # so the digest is stable regardless of insertion order (step ORDER belongs to the
        # planner/DAG layer, not to identity).
        self.assertEqual(sorted(self.plan(state, 'P1').action_ids),
                         sorted((a.job_id, b.job_id, c.job_id)))

        with self.assertRaises(MissionError) as refused:
            record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])
        self.assertEqual(refused.exception.reason, 'PLAN_ALREADY_EXISTS')

    # ------------------------------------------------------------------ law 14
    def test_law_14_identity_is_by_id_never_by_similarity(self):
        mission = open_mission(self.db, objective='identity is explicit')
        first = self.enqueue(params={'value': 7})
        second = self.enqueue(params={'value': 7})   # identical work, different intent
        self.assertEqual(first.permit.payload.action_fingerprint,
                         second.permit.payload.action_fingerprint,
                         "same semantics, so the fingerprints agree")
        self.assertNotEqual(first.job_id, second.job_id)
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[first.job_id])
        outcome = record_plan(self.db, mission_id=mission, plan_id='P2',
                              logical_action_ids=[second.job_id])
        self.assertEqual(outcome['newly_attached'], (second.job_id,),
                         "similarity is never enough to reuse an identity")
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(len(state.actions), 2)

    # ------------------------------------------------------------------ laws 15, 16
    def test_law_15_conflict_also_applies_to_recorded_fingerprints(self):
        mission = open_mission(self.db, objective='recorded fingerprint conflict')
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=['ACT-X'],
                    action_fingerprints={'ACT-X': 'F1'})
        with self.assertRaises(MissionError) as refused:
            record_plan(self.db, mission_id=mission, plan_id='P2', logical_action_ids=['ACT-X'],
                        action_fingerprints={'ACT-X': 'F2'})
        self.assertEqual(refused.exception.reason, 'PLAN_SEMANTIC_CONFLICT')
        # The same fingerprint is fine: that is a genuine reuse.
        ok = record_plan(self.db, mission_id=mission, plan_id='P2', logical_action_ids=['ACT-X'],
                         action_fingerprints={'ACT-X': 'F1'})
        self.assertEqual(ok['already_known'], ('ACT-X',))

    # ------------------------------------------------------------------ laws 17, 18, 19
    def test_law_17_replanning_cannot_resurrect_terminal_work(self):
        mission, a, b, c = self.founding_state()
        permits_before = self.permit_count()
        record_plan(self.db, mission_id=mission, plan_id='P2',
                    logical_action_ids=[a.job_id, b.job_id, c.job_id])
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(self.action(state, a.job_id).attempt_outcome, 'TERMINAL')
        self.assertEqual(self.permit_count(), permits_before)

    def test_law_18_replanning_cannot_erase_uncertainty(self):
        mission, a, b, c = self.founding_state()
        # P2 omits B entirely.
        record_plan(self.db, mission_id=mission, plan_id='P2', logical_action_ids=[a.job_id, c.job_id])
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertIn(b.job_id, state.omitted_action_ids)
        self.assertEqual(self.action(state, b.job_id).attempt_outcome, 'UNRESOLVED')
        self.assertIn(b.job_id, state.obligations, "omitting an unresolved action erases nothing")
        self.assertTrue(state.needs_replanning)

    def test_law_19_omission_neither_cancels_nor_revokes(self):
        mission, a, b, c = self.founding_state()
        record_plan(self.db, mission_id=mission, plan_id='P2', logical_action_ids=[a.job_id])
        state = reconstruct_missions(self.db).state_of(mission)
        self.assertFalse(self.action(state, c.job_id).permit_state == 'REVOKED')
        self.assertTrue(self.action(state, c.job_id).authorization_alive)
        # The mission still cannot be completed while that live authority exists.
        with self.assertRaises(MissionError) as refused:
            complete_mission(self.db, mission_id=mission, reason='strategy said we are done')
        self.assertEqual(refused.exception.reason, 'MISSION_HAS_OPEN_OBLIGATIONS')
        self.assertIn(c.job_id, refused.exception.detail)

    # ------------------------------------------------------------------ law 20
    def test_law_20_losing_the_current_plan_pointer_loses_no_truth(self):
        mission, a, b, c = self.founding_state()
        before = reconstruct_missions(self.db).state_of(mission)

        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM ciph_mission_current_plan")

        after = reconstruct_missions(self.db).state_of(mission)
        self.assertIsNone(after.current_plan_id, "the pointer is gone")
        self.assertEqual(after.plan_action_ids, ())
        self.assertEqual([x.logical_action_id for x in after.actions],
                         [x.logical_action_id for x in before.actions])
        self.assertEqual(after.obligations, before.obligations)
        self.assertEqual(after.status, before.status)
        self.assertEqual(after.historical_plan_ids, before.historical_plan_ids,
                         "the projections themselves are still there")
        self.assertTrue(after.needs_replanning, "with no current projection, planning is needed")

        # Rebuilding the pointer restores the previous projection exactly.
        record_plan(self.db, mission_id=mission, plan_id='P3', logical_action_ids=[a.job_id])
        restored = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual(restored.current_plan_id, 'P3')

    # ------------------------------------------------------------------ law 21
    def test_law_21_plan_reconstruction_is_deterministic_across_restart(self):
        mission, a, b, c = self.founding_state()
        d = self.enqueue(params={'value': 4})
        record_plan(self.db, mission_id=mission, plan_id='P2',
                    logical_action_ids=[a.job_id, b.job_id, d.job_id])
        moment = 1_800_000_000.0

        first = reconstruct_missions(self.db, now=moment).canonical_digest()
        self.restart()
        second = reconstruct_missions(self.db, now=moment).canonical_digest()
        self.assertEqual(first, second)

        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.missions import reconstruct_missions;"
                "print(reconstruct_missions(%r, now=%r).canonical_digest())"
                % (str(Path(__file__).resolve().parents[1]), self.db, moment))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), first)


if __name__ == '__main__':
    unittest.main()
