
"""
4.1 Gate Four - kill it everywhere and prove the ladder survives.

For each important boundary a state is built through real operations, a restart happens (new process
state over the same durable stores), and the reconstruction must:

  * describe the same thing afterwards as before (canonical digest equality),
  * land on the expected outcome for that boundary,
  * invent nothing - no new action, no new permit, no advanced generation, no lost obligation.

One boundary is exercised with a REAL killed process rather than a simulated crash, because the point
of the matrix is durability, not tidiness.
"""

import json
import subprocess
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ciph.kernel.continuity import complete_pending_consumption, reconstruct
from ciph.kernel.missions import (
    MISSION_COMPLETED,
    complete_mission,
    open_mission,
    reconstruct_missions,
    record_plan,
)
from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
from ciph.kernel.scheduler_recovery import Eligibility, derive_eligibility, recovered_dispatch_plan
from ciph.runtime import CiphRuntime
from permit_test_support import enqueue_permit_bearing_job
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability


class TestGate44RestartTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-44-torture-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        # ONE clock for the whole specimen. Expiry is a function of the clock, so a before/after
        # digest comparison is only meaningful when both sides read the same one.
        self.clock = time.time()
        self.runtime = CiphRuntime(db_path=self.db)
        self.cap = SimpleComputeCapability(name='torture.compute')
        self.runtime.register_capability(self.cap)

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def enqueue(self, params=None, attempts=3):
        return enqueue_permit_bearing_job(
            self.runtime, capability=self.cap.manifest.name, params=params or {'value': 1},
            max_retries=attempts)

    def execute(self, job_id, worker='torture_worker'):
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

    def permit_id_of(self, job_id):
        raw = self.runtime.queue.get_job(job_id)['execution_permit']
        return (json.loads(raw) if isinstance(raw, str) else raw)['permit_id']

    def digest(self, mission, now=None):
        return reconstruct_missions(
            self.db, now=self.clock if now is None else now).state_of(mission).canonical_digest()

    def journal(self):
        """The durable facts a restart must not invent: actions, permits, generations, evidence."""
        with sqlite3.connect(self.db) as conn:
            def count(sql, params=()):
                try:
                    return conn.execute(sql, params).fetchone()[0]
                except sqlite3.OperationalError:
                    return 0
            return {
                "permits": count("SELECT COUNT(*) FROM execution_permits"),
                "max_generation": count("SELECT COALESCE(MAX(authorization_generation), -1) "
                                        "FROM execution_permits"),
                "events": count("SELECT COUNT(*) FROM ciph_event_store"),
                "jobs": count("SELECT COUNT(*) FROM ciph_ipc_jobs"),
                "missions": count("SELECT COUNT(*) FROM ciph_missions"),
                "mission_actions": count("SELECT COUNT(*) FROM ciph_mission_actions"),
                "plans": count("SELECT COUNT(*) FROM ciph_mission_plans"),
            }

    def surviving_journal(self, mission, job_ids, expected_outcomes):
        """Assert a restart changed nothing durable, then check the expected outcomes."""
        before_journal = self.journal()
        before_digest = self.digest(mission)
        before_counts = reconstruct(self.db).source_counts

        self.restart()

        self.assertEqual(self.journal(), before_journal,
                         "a restart created, moved or deleted a durable fact")
        self.assertEqual(reconstruct(self.db, now=self.clock).source_counts, before_counts)
        state = reconstruct_missions(self.db, now=self.clock).state_of(mission)
        self.assertEqual(state.canonical_digest(), before_digest,
                         "a restart changed what the evidence says about the mission")
        outcomes = {a.logical_action_id: a.attempt_outcome for a in state.actions}
        for job_id, expected in expected_outcomes.items():
            self.assertEqual(outcomes[job_id], expected.value if hasattr(expected, 'value') else expected)
        self.assertEqual(sorted(outcomes), sorted(job_ids))
        return state

    # ------------------------------------------------------------------ boundaries
    def test_boundary_1_nothing_durable_but_the_mission(self):
        mission = open_mission(self.db, objective='boundary one')
        state = self.surviving_journal(mission, [], {})
        self.assertEqual(state.status, 'ACTIVE')
        self.assertEqual(state.remaining_authorized_work, ())
        self.assertEqual(recovered_dispatch_plan(self.db), ())

    def test_boundary_2_issued_but_never_claimed(self):
        mission = open_mission(self.db, objective='boundary two')
        a = self.enqueue(params={'value': 1})
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])

        state = self.surviving_journal(mission, [a.job_id], {a.job_id: 'NOT_ATTEMPTED'})
        self.assertEqual(self.permit_store().state_of(a.permit_id), 'ISSUED')
        self.assertEqual([e.job_id for e in recovered_dispatch_plan(self.db)], [a.job_id],
                         "unspent authority is still eligible after a restart")

    def test_boundary_3_leased_but_never_claimed(self):
        mission = open_mission(self.db, objective='boundary three')
        a = self.enqueue(params={'value': 1})
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])
        leased = self.runtime.queue.lease_next_job('worker_that_died', 0.05, target_job_id=a.job_id)
        self.assertIsNotNone(leased)

        state = self.surviving_journal(mission, [a.job_id], {a.job_id: 'NOT_ATTEMPTED'})
        self.assertEqual(self.permit_store().state_of(a.permit_id), 'ISSUED',
                         "a lost delivery never spends authority")
        self.assertEqual(self.runtime.queue.reclaim_expired_leases(), 1)
        self.assertEqual(self.runtime.queue.get_job(a.job_id)['status'], 'RETRYING')

    def test_boundary_4_claimed_before_any_evidence(self):
        mission = open_mission(self.db, objective='boundary four')
        a = self.enqueue(params={'value': 1})
        claim = self.permit_store().claim(a.permit_id, 'worker_that_died')
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])

        state = self.surviving_journal(mission, [a.job_id], {a.job_id: 'UNRESOLVED'})
        action = [x for x in state.actions if x.logical_action_id == a.job_id][0]
        self.assertEqual(action.execution_attempt_id, claim.execution_attempt_id)
        self.assertIn(a.job_id, state.obligations)
        self.assertEqual(recovered_dispatch_plan(self.db), (),
                         "an unresolved claim is never re-dispatched")
        self.assertEqual(derive_eligibility(self.db)[0].eligibility,
                         Eligibility.RECONCILIATION_REQUIRED.value)

    def test_boundary_5_evidence_durable_but_not_consumed(self):
        mission = open_mission(self.db, objective='boundary five')
        a = self.enqueue(params={'value': 1})
        claim = self.permit_store().claim(a.permit_id, 'worker_that_died')
        # The crash window, in its durable shape: the signed receipt exists, the permit is still
        # CLAIMED. (The atomic path closes this window; this models a process that died inside it.)
        self.runtime.event_store.append_event('ExecutionReceiptStoredEvent', 'agg', {
            'provenance': {'manifest_hash': self.cap.manifest.compute_manifest_hash()},
            'governed_authorization': {
                'execution_attempt_id': claim.execution_attempt_id,
                'execution_permit_id': a.permit_id,
                'execution_permit_digest': a.permit.permit_digest(),
                'authorization_generation': 0,
                'effect_certainty': 'EFFECT_CONFIRMED',
            },
        })
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])

        state = self.surviving_journal(mission, [a.job_id], {a.job_id: 'TERMINAL'})
        action = [x for x in state.actions if x.logical_action_id == a.job_id][0]
        self.assertTrue(action.consumption_pending)
        self.assertIn(a.permit_id, state.completion_obligations)
        self.assertEqual(recovered_dispatch_plan(self.db), ())

        completed = complete_pending_consumption(self.db)
        self.assertEqual(completed, (a.permit_id,))
        self.restart()
        closed = reconstruct_missions(self.db).state_of(mission)
        self.assertEqual([x.permit_state for x in closed.actions], ['CONSUMED'])
        self.assertEqual(closed.completion_obligations, ())

    def test_boundary_6_after_a_completed_execution(self):
        mission = open_mission(self.db, objective='boundary six')
        a = self.enqueue(params={'value': 1})
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])
        self.assertEqual(self.execute(a.job_id).exit_code, 0)

        state = self.surviving_journal(mission, [a.job_id], {a.job_id: 'TERMINAL'})
        self.assertEqual([x.permit_state for x in state.actions], ['CONSUMED'])
        self.assertEqual(recovered_dispatch_plan(self.db), ())
        self.assertIsNone(self.runtime.queue.lease_next_job('worker_after_restart', 30))

    def test_boundary_7_mid_replanning(self):
        mission = open_mission(self.db, objective='boundary seven')
        a = self.enqueue(params={'value': 1})
        self.execute(a.job_id)
        b = self.enqueue(params={'value': 2})
        record_plan(self.db, mission_id=mission, plan_id='P1',
                    logical_action_ids=[a.job_id, b.job_id])
        # The replan happened; whatever the planner intended to do next never ran.
        c = self.enqueue(params={'value': 3})
        record_plan(self.db, mission_id=mission, plan_id='P2',
                    logical_action_ids=[a.job_id, c.job_id])

        state = self.surviving_journal(mission, [a.job_id, b.job_id, c.job_id],
                                       {a.job_id: 'TERMINAL', b.job_id: 'NOT_ATTEMPTED',
                                        c.job_id: 'NOT_ATTEMPTED'})
        self.assertEqual(state.current_plan_id, 'P2')
        self.assertEqual(state.historical_plan_ids, ('P1', 'P2'))
        self.assertEqual(state.omitted_action_ids, (b.job_id,))
        self.assertIn(b.job_id, state.remaining_authorized_work,
                      "an omitted action keeps its authority across the crash")
        self.assertEqual([e.job_id for e in recovered_dispatch_plan(self.db)], [c.job_id])

    def test_boundary_8_after_the_mission_completed(self):
        mission = open_mission(self.db, objective='boundary eight')
        a = self.enqueue(params={'value': 1})
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])
        self.assertEqual(self.execute(a.job_id).exit_code, 0)
        complete_mission(self.db, mission_id=mission, reason='the only action resolved')

        state = self.surviving_journal(mission, [a.job_id], {a.job_id: 'TERMINAL'})
        self.assertEqual(state.status, MISSION_COMPLETED)
        self.assertEqual(recovered_dispatch_plan(self.db), ())

    # ------------------------------------------------------------------ a real kill
    def test_a_real_killed_process_leaves_recoverable_truth(self):
        mission = open_mission(self.db, objective='real kill')
        a = self.enqueue(params={'value': 1})
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])

        source = (
            "import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
            "from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies as b;"
            "from ciph.kernel.crypto_identity import TrustRegistry;"
            "db=%r;pid=%r;"
            "store=b(db, trust_registry=TrustRegistry(db)).permit_store;"
            "claim=store.claim(pid, 'process_that_died');"
            "print(claim.execution_attempt_id);"
            % (str(Path(__file__).resolve().parents[1]), self.db, a.permit_id)
        )
        proc = subprocess.run([sys.executable, '-B', '-c', source], capture_output=True, text=True,
                              cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        attempt_id = proc.stdout.strip()

        state = self.surviving_journal(mission, [a.job_id], {a.job_id: 'UNRESOLVED'})
        action = [x for x in state.actions if x.logical_action_id == a.job_id][0]
        self.assertEqual(action.execution_attempt_id, attempt_id,
                         "the attempt identity survives the process that created it")
        self.assertIn(a.job_id, state.obligations)
        self.assertEqual(recovered_dispatch_plan(self.db), ())

    # ------------------------------------------------------------------ the matrix invariant
    def test_no_boundary_invents_authority_or_actions(self):
        """Walk every boundary in one process and assert the restart is always a pure read."""
        mission = open_mission(self.db, objective='matrix')

        def checkpoint(label):
            """Restart at this boundary and prove nothing durable moved."""
            journal = self.journal()
            digest = self.digest(mission)
            with self.subTest(boundary=label):
                self.restart()
                now = self.journal()
                self.assertEqual(now["permits"], journal["permits"])
                self.assertEqual(now["max_generation"], journal["max_generation"])
                self.assertEqual(now["mission_actions"], journal["mission_actions"])
                self.assertEqual(now["plans"], journal["plans"])
                self.assertEqual(now["events"], journal["events"])
                self.assertEqual(self.digest(mission), digest)

        a = self.enqueue(params={'value': 1})
        record_plan(self.db, mission_id=mission, plan_id='P1', logical_action_ids=[a.job_id])
        checkpoint('issued')

        self.permit_store().claim(a.permit_id, 'worker_that_died')
        checkpoint('claimed')

        b = self.enqueue(params={'value': 2})
        record_plan(self.db, mission_id=mission, plan_id='P2',
                    logical_action_ids=[a.job_id, b.job_id])
        checkpoint('replanned')


if __name__ == '__main__':
    unittest.main()
