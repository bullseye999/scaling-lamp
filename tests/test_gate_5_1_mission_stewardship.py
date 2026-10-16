"""
5.1 - long-horizon mission stewardship.

    Persistence of a mission does not permit reinterpretation of its purpose.

The specimens here are about the two ways a long-lived mission goes wrong: it DRIFTS (the objective
quietly becomes something more convenient) or it never honestly ENDS (it just stops appearing in the
plan while the row still says ACTIVE).
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.mission_stewardship import (
    PROPOSAL_OPEN,
    REASON_ABANDONMENT_REQUIRES_OPERATOR,
    REASON_CHARTER_REQUIRES_OPERATOR,
    REASON_MILESTONE_REQUIRES_EVIDENCE,
    REASON_NO_CHARTER,
    REASON_PURPOSE_DRIFT,
    abandon_mission,
    abandonment_proposals,
    authorize_plan_revision,
    charter_for,
    declare_milestone,
    detect_mission_conflicts,
    detect_purpose_drift,
    mission_health,
    open_charter,
    propose_abandonment,
    satisfy_milestone,
    stewardship_digest,
)
from ciph.kernel.missions import (MISSION_ABANDONED, attach_action, open_mission, record_plan,
                                  reconstruct_missions)

DAY = 86_400.0
PURPOSE = "Maintain repository health"


class TestGate51MissionStewardship(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-51-")
        self.db = str(Path(self.temp.name) / "vault.db")
        self.t1 = 1_800_000_000.0
        self.mission = open_mission(self.db, objective=PURPOSE, now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def charter(self, purpose=PURPOSE, mission=None, constraints=()):
        return open_charter(self.db, mission_id=mission or self.mission, purpose=purpose,
                            success_criteria=["suite green"], constraints=list(constraints),
                            actor="operator:operator", now=self.t1)

    # ---------------------------------------------------------------- the purpose gate
    def test_a_daemon_cannot_state_what_a_mission_is_for(self):
        with self.assertRaises(CrucibleError) as refused:
            open_charter(self.db, mission_id=self.mission, purpose="anything the daemon likes",
                         actor="daemon:curiosity", now=self.t1)
        self.assertEqual(refused.exception.reason, REASON_CHARTER_REQUIRES_OPERATOR)
        self.assertIsNone(charter_for(self.db, self.mission))

    def test_purpose_drift_is_refused_before_it_reaches_4_1(self):
        self.charter()
        attach_action(self.db, mission_id=self.mission, logical_action_id="ACT-A", now=self.t1)
        authorize_plan_revision(self.db, mission_id=self.mission, plan_id="PLAN-1",
                               logical_action_ids=["ACT-A"], objective=PURPOSE, now=self.t1)
        attach_action(self.db, mission_id=self.mission, logical_action_id="ACT-B", now=self.t1 + 1)
        with self.assertRaises(CrucibleError) as refused:
            authorize_plan_revision(self.db, mission_id=self.mission, plan_id="PLAN-2",
                                   logical_action_ids=["ACT-B"],
                                   objective="Improve model accuracy instead", now=self.t1 + 2)
        self.assertEqual(refused.exception.reason, REASON_PURPOSE_DRIFT)
        # The refusal left no trace: a drifting revision is not a plan that failed validation, it is a
        # plan that was never written.
        state = reconstruct_missions(self.db).state_of(self.mission)
        self.assertNotIn("PLAN-2", state.historical_plan_ids)

    def test_strategy_changes_freely_inside_the_same_purpose(self):
        self.charter()
        attach_action(self.db, mission_id=self.mission, logical_action_id="ACT-A", now=self.t1)
        attach_action(self.db, mission_id=self.mission, logical_action_id="ACT-B", now=self.t1)
        authorize_plan_revision(self.db, mission_id=self.mission, plan_id="PLAN-1",
                               logical_action_ids=["ACT-A"], objective=PURPOSE, now=self.t1)
        second = authorize_plan_revision(self.db, mission_id=self.mission, plan_id="PLAN-2",
                                        logical_action_ids=["ACT-B"], objective=PURPOSE,
                                        now=self.t1 + 1)
        self.assertEqual(second["plan_id"], "PLAN-2")
        state = reconstruct_missions(self.db).state_of(self.mission)
        self.assertEqual(state.current_plan_id, "PLAN-2")
        self.assertEqual(detect_purpose_drift(self.db, self.mission), ())

    def test_drift_is_measured_against_the_canonical_plan_history(self):
        # The front door is guarded, so the second line has to MEASURE: a plan that reached 4.1 by
        # another route is still drift, and the charter is what says so.
        self.charter()
        attach_action(self.db, mission_id=self.mission, logical_action_id="ACT-A", now=self.t1)
        record_plan(self.db, mission_id=self.mission, plan_id="PLAN-DIRECT",
                    logical_action_ids=["ACT-A"], objective="Something else entirely", now=self.t1)
        self.assertEqual(detect_purpose_drift(self.db, self.mission), ("PLAN-DIRECT",))
        health = mission_health(self.db, self.mission, now=self.t1)
        self.assertFalse(health["healthy"])
        self.assertEqual(health["drifted_plan_ids"], ["PLAN-DIRECT"])

    def test_an_unchartered_mission_is_not_revised(self):
        attach_action(self.db, mission_id=self.mission, logical_action_id="ACT-A", now=self.t1)
        with self.assertRaises(CrucibleError) as refused:
            authorize_plan_revision(self.db, mission_id=self.mission, plan_id="PLAN-1",
                                   logical_action_ids=["ACT-A"], objective=PURPOSE, now=self.t1)
        self.assertEqual(refused.exception.reason, REASON_NO_CHARTER)

    # ---------------------------------------------------------------- honest endings
    def test_milestones_are_satisfied_by_evidence(self):
        charter = self.charter()
        milestone = declare_milestone(self.db, mission_id=self.mission, label="suite green",
                                      now=self.t1)
        self.assertEqual(milestone.charter_id, charter.charter_id)
        self.assertFalse(milestone.satisfied)
        with self.assertRaises(CrucibleError) as refused:
            satisfy_milestone(self.db, milestone.milestone_id, evidence_ref="", now=self.t1)
        self.assertEqual(refused.exception.reason, REASON_MILESTONE_REQUIRES_EVIDENCE)
        satisfied = satisfy_milestone(self.db, milestone.milestone_id, evidence_ref="EVD-1",
                                     now=self.t1 + 1)
        self.assertTrue(satisfied.satisfied)
        self.assertEqual(satisfied.evidence_ref, "EVD-1")
        # Recording it twice does not rewrite the moment it was first satisfied.
        again = satisfy_milestone(self.db, milestone.milestone_id, evidence_ref="EVD-2",
                                  now=self.t1 + 100)
        self.assertEqual(again.satisfied_at, satisfied.satisfied_at)
        self.assertEqual(again.evidence_ref, "EVD-1")

    def test_abandonment_is_a_recorded_decision_not_a_silence(self):
        self.charter()
        proposal = propose_abandonment(self.db, mission_id=self.mission, rationale="obsolete",
                                       now=self.t1)
        self.assertEqual(abandonment_proposals(self.db, self.mission)[0]["status"], PROPOSAL_OPEN)
        with self.assertRaises(CrucibleError) as refused:
            abandon_mission(self.db, mission_id=self.mission, rationale="obsolete",
                            actor="daemon:curiosity", now=self.t1)
        self.assertEqual(refused.exception.reason, REASON_ABANDONMENT_REQUIRES_OPERATOR)
        self.assertEqual(reconstruct_missions(self.db).state_of(self.mission).status, "ACTIVE")
        self.assertTrue(abandon_mission(self.db, mission_id=self.mission, rationale="obsolete",
                                        actor="operator:operator", now=self.t1 + 10))
        self.assertEqual(reconstruct_missions(self.db).state_of(self.mission).status,
                         MISSION_ABANDONED)
        self.assertEqual(abandonment_proposals(self.db, self.mission)[0]["status"], "ACCEPTED")

    def test_abandoning_refuses_on_a_mission_that_already_ended(self):
        self.charter()
        abandon_mission(self.db, mission_id=self.mission, rationale="obsolete",
                        actor="operator:operator", now=self.t1)
        with self.assertRaises(Exception) as refused:
            abandon_mission(self.db, mission_id=self.mission, rationale="again",
                            actor="operator:operator", now=self.t1 + 1)
        self.assertEqual(getattr(refused.exception, "reason", ""), "MISSION_NOT_ACTIVE")

    def test_conflicting_exclusive_missions_are_reported_never_resolved(self):
        other = open_mission(self.db, objective="Train the model", now=self.t1)
        self.charter(constraints=("exclusive:gpu",))
        self.charter(purpose="Train the model", mission=other, constraints=("exclusive:gpu",))
        conflicts = detect_mission_conflicts(self.db)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["resource"], "gpu")
        self.assertEqual(conflicts[0]["missions"], sorted([self.mission, other]))
        # A conflict is a REPORT. Nothing picked a winner, and both missions are still live.
        for mission_id in (self.mission, other):
            self.assertEqual(reconstruct_missions(self.db).state_of(mission_id).status, "ACTIVE")

    def test_health_reports_a_stalled_mission_without_inventing_work(self):
        self.charter()
        health = mission_health(self.db, self.mission, now=self.t1 + 30 * DAY)
        self.assertTrue(health["stalled"])
        self.assertFalse(health["healthy"])
        self.assertEqual(health["actions"], 0)
        self.assertEqual(health["open_obligations"], [])
        self.assertFalse(health["completion_eligible"])

    def test_stewardship_state_reconstructs_identically_in_a_fresh_process(self):
        self.charter()
        declare_milestone(self.db, mission_id=self.mission, label="suite green", now=self.t1)
        propose_abandonment(self.db, mission_id=self.mission, rationale="obsolete", now=self.t1)
        expected = stewardship_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.mission_stewardship import stewardship_digest;"
                "print(json.dumps(stewardship_digest(%r)))"
                % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)
        self.assertEqual(stewardship_digest(self.db), expected)


if __name__ == "__main__":
    unittest.main()
