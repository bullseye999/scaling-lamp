"""
5.2 - temporal governance.

    A schedule says when something may be RECONSIDERED. It never says that something must execute.

The specimens below attack the three ways a cadence becomes authority: it fires and is treated as a
decision, it retries forever because nobody noticed it is permanently blocked, or it is treated as due
by a process whose clock cannot actually tell.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.autonomy_eligibility import OUTCOME_ELIGIBLE, OUTCOME_NO_AUTHORITY, evaluate_eligibility
from ciph.kernel.autonomy_schedule import (
    MAX_BACKOFF_LEVEL,
    OUTCOME_BLOCKED,
    OUTCOME_CLOCK_UNCERTAIN,
    OUTCOME_NOMINATED,
    REASON_CLOCK_UNCERTAIN,
    REASON_NOT_DUE,
    REASON_SCHEDULE_REQUIRES_OPERATOR,
    SCHEDULE_ACTIVE,
    advance_schedule,
    get_schedule,
    reconsider,
    reconsideration_due,
    reconsideration_history,
    register_schedule,
    schedule_digest,
    schedules,
)
from ciph.kernel.autonomy_session import continuous_cycle
from ciph.kernel.missions import open_mission
from ciph.kernel.standing_authorization import create_standing_authorization

DAY = 86_400.0


class TestGate52TemporalGovernance(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-52-")
        self.db = str(Path(self.temp.name) / "vault.db")
        self.t1 = 1_800_000_000.0
        self.mission = open_mission(self.db, objective="Maintain repository health", now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def schedule(self, *, interval=DAY, uncertainty=0.0, first_due=None, work_class="RUN_TEST_SUITE",
                 actor="operator:operator"):
        return register_schedule(self.db, origin_kind="SCHEDULED_REVIEW", work_class=work_class,
                                 interval_seconds=interval, actor=actor, mission_id=self.mission,
                                 clock_uncertainty_seconds=uncertainty,
                                 first_due_at=first_due, now=self.t1)

    def authorize(self):
        return create_standing_authorization(self.db, mission_id=self.mission,
                                             permitted_work_classes=["RUN_TEST_SUITE"],
                                             granted_by="operator:operator", now=self.t1)

    # ---------------------------------------------------------------- authority over the future
    def test_only_an_operator_may_register_a_recurring_obligation(self):
        with self.assertRaises(CrucibleError) as refused:
            self.schedule(actor="daemon:curiosity")
        self.assertEqual(refused.exception.reason, REASON_SCHEDULE_REQUIRES_OPERATOR)
        self.assertEqual(schedules(self.db), [])

    def test_a_schedule_that_is_not_due_is_not_reconsidered(self):
        schedule = self.schedule(first_due=self.t1 + 100)
        self.assertEqual(reconsideration_due(self.db, now=self.t1 + 99), [])
        with self.assertRaises(CrucibleError) as refused:
            reconsider(self.db, schedule.schedule_id, now=self.t1 + 99)
        self.assertEqual(refused.exception.reason, REASON_NOT_DUE)

    def test_an_exactly_on_time_due_is_certain_when_no_uncertainty_was_declared(self):
        schedule = self.schedule(first_due=self.t1 + 100)
        band = reconsideration_due(self.db, now=self.t1 + 100)
        self.assertEqual([item["certainty"] for item in band], ["CERTAIN"])
        reconsidered = reconsider(self.db, schedule.schedule_id, now=self.t1 + 100)
        self.assertEqual(reconsidered.outcome, OUTCOME_NOMINATED)

    def test_a_clock_that_cannot_tell_does_not_act(self):
        schedule = self.schedule(first_due=self.t1 + 100, uncertainty=60.0)
        band = reconsideration_due(self.db, now=self.t1 + 130)
        self.assertEqual(band[0]["certainty"], "UNCERTAIN")
        reconsidered = reconsider(self.db, schedule.schedule_id, now=self.t1 + 130)
        self.assertEqual(reconsidered.outcome, OUTCOME_CLOCK_UNCERTAIN)
        self.assertIsNone(reconsidered.intent_id)
        self.assertEqual(reconsideration_history(self.db)[0]["outcome"], OUTCOME_CLOCK_UNCERTAIN)

    def test_a_nomination_is_a_nomination_not_an_authorisation(self):
        schedule = self.schedule(first_due=self.t1 + 100)
        reconsidered = reconsider(self.db, schedule.schedule_id, now=self.t1 + 100)
        self.assertEqual(reconsidered.outcome, OUTCOME_NOMINATED)
        self.assertIsNotNone(reconsidered.intent_id)
        # The nomination created WORK, not permission: with no standing authority the very next
        # question is still refused.
        decision = evaluate_eligibility(self.db, intent_id=reconsidered.intent_id, now=self.t1 + 100)
        self.assertEqual(decision.outcome, OUTCOME_NO_AUTHORITY)
        self.authorize()
        self.assertEqual(evaluate_eligibility(self.db, intent_id=reconsidered.intent_id,
                                              now=self.t1 + 100).outcome, OUTCOME_ELIGIBLE)

    def test_a_repeated_tick_is_one_reconsideration_identity(self):
        schedule = self.schedule(first_due=self.t1 + 100)
        first = reconsider(self.db, schedule.schedule_id, now=self.t1 + 100)
        second = reconsider(self.db, schedule.schedule_id, now=self.t1 + 100)
        self.assertEqual(first.reconsideration_id, second.reconsideration_id)
        self.assertEqual(first.intent_id, second.intent_id)
        self.assertEqual(len(reconsideration_history(self.db)), 1)
        # ...and a second tick for the same purpose is still ONE piece of work.
        self.assertEqual(len({item["intent_id"] for item in reconsideration_history(self.db)}), 1)

    def test_repeated_blocks_back_off_to_the_ceiling_and_a_success_resets(self):
        schedule = self.schedule(first_due=self.t1 + 100, interval=100.0)
        call = self.t1 + 100
        for _ in range(10):
            last_call = call
            advanced = advance_schedule(self.db, schedule.schedule_id, outcome=OUTCOME_BLOCKED,
                                        now=call)
            call = advanced.next_reconsideration_at + 1
        self.assertEqual(advanced.backoff_level, MAX_BACKOFF_LEVEL)
        self.assertEqual(advanced.interval_seconds, 100.0, "the registered interval is a fact")
        self.assertAlmostEqual(advanced.max_interval_seconds, 100.0 * (2 ** MAX_BACKOFF_LEVEL))
        self.assertEqual(advanced.effective_interval_seconds, advanced.max_interval_seconds)
        # The ceiling is real: the next appointment is a full maximum interval after the last look.
        self.assertEqual(advanced.next_reconsideration_at,
                         last_call + advanced.effective_interval_seconds)
        self.assertGreater(advanced.next_reconsideration_at, self.t1 + 100)
        # A single successful reconsideration collapses the cadence back to its interval.
        recovered = advance_schedule(self.db, schedule.schedule_id, outcome=OUTCOME_NOMINATED,
                                     now=call)
        self.assertEqual(recovered.backoff_level, 0)
        self.assertEqual(recovered.effective_interval_seconds, 100.0)
        self.assertEqual(recovered.next_reconsideration_at, call + 100.0)

    def test_a_paused_schedule_is_inert(self):
        import sqlite3
        schedule = self.schedule(first_due=self.t1 + 100)
        connection = sqlite3.connect(self.db)
        connection.execute("UPDATE ciph_autonomy_schedules SET status = ? WHERE schedule_id = ?;",
                           ("PAUSED", schedule.schedule_id))
        connection.commit()
        connection.close()
        self.assertEqual(reconsideration_due(self.db, now=self.t1 + 10_000), [])
        with self.assertRaises(CrucibleError):
            reconsider(self.db, schedule.schedule_id, now=self.t1 + 10_000)
        self.assertEqual(get_schedule(self.db, schedule.schedule_id).status, "PAUSED")

    def test_the_continuous_cycle_still_sees_the_nominated_work(self):
        self.authorize()
        schedule = self.schedule(first_due=self.t1 + 100)
        self.assertEqual(continuous_cycle(self.db, now=self.t1 + 50)["idle"], True)
        moment = self.t1 + 100
        while len(reconsideration_history(self.db)) < 2:
            reconsidered = reconsider(self.db, schedule.schedule_id, now=moment)
            advance_schedule(self.db, schedule.schedule_id, outcome=reconsidered.outcome, now=moment)
            moment = get_schedule(self.db, schedule.schedule_id).next_reconsideration_at + 1
        cycle = continuous_cycle(self.db, now=moment)
        self.assertGreaterEqual(cycle["evaluated"], 1)

    def test_schedule_state_reconstructs_identically_in_a_fresh_process(self):
        schedule = self.schedule(first_due=self.t1 + 100, uncertainty=60.0)
        reconsider(self.db, schedule.schedule_id, now=self.t1 + 130)
        advance_schedule(self.db, schedule.schedule_id, outcome=OUTCOME_CLOCK_UNCERTAIN,
                         now=self.t1 + 131)
        expected = schedule_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.autonomy_schedule import schedule_digest;"
                "print(json.dumps(schedule_digest(%r)))"
                % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)

    def test_an_active_schedule_never_grants_itself_a_wider_class(self):
        schedule = self.schedule(first_due=self.t1 + 100, work_class="READ_REPOSITORY")
        self.authorize()
        reconsidered = reconsider(self.db, schedule.schedule_id, now=self.t1 + 100)
        from ciph.kernel.autonomous_work import get_work_intent
        intent = get_work_intent(self.db, reconsidered.intent_id)
        self.assertEqual(intent.work_class, "READ_REPOSITORY")
        self.assertEqual(intent.risk_class, "LOW")
        self.assertEqual(schedule.status, SCHEDULE_ACTIVE)


if __name__ == "__main__":
    unittest.main()
