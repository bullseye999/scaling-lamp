"""
5.9 - the continuous autonomy torture.

Thirty accelerated days of a live cadence: several missions, an operator hold every week, a dependency
outage, a resource squeeze, an abandoned mission, an improvement cycle that reaches the ceiling, an
interrupt that lands mid-attempt, a restarted process, and stretches where there is genuinely nothing to
do.

The point is not that the loop keeps running. It is that the loop keeps running WITHOUT any of these:
authority drift, duplicated execution, zombie schedules, runaway curiosity, runaway spending, silent
production deployment, or a rewritten history.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.autonomy_budgets import budget_digest, consume_budget, open_budget
from ciph.kernel.autonomy_eligibility import (OUTCOME_ELIGIBLE, OUTCOME_EXPIRED, OUTCOME_NO_AUTHORITY,
                                              OUTCOME_OPERATOR_HOLD, OUTCOME_RESOURCE,
                                              OUTCOME_SATISFIED, evaluate_eligibility)
from ciph.kernel.autonomy_interrupts import (enforce_operator_mode, intervention_digest,
                                             interventions, settle_session)
from ciph.kernel.autonomy_maintenance import (assert_curiosity_basis, maintenance_digest,
                                             promotion_ready_carries_no_authority,
                                             promotion_ready_notices, raise_promotion_ready)
from ciph.kernel.autonomy_modes import (MODE_EMERGENCY_STOP, MODE_NORMAL, MODE_QUIESCE,
                                        MODE_READ_ONLY, current_mode, mode_digest, mode_history,
                                        set_mode)
from ciph.kernel.autonomy_schedule import (OUTCOME_BLOCKED, OUTCOME_NOMINATED, advance_schedule,
                                           reconsider, reconsideration_due,
                                           reconsideration_history, register_schedule,
                                           schedule_digest)
from ciph.kernel.autonomy_scanners import (AUTONOMY_SCANNERS, autonomy_scanner_census)
from ciph.kernel.autonomy_session import (SESSION_CLOSED, SESSION_INTERRUPTED, SESSION_QUIESCING,
                                          autonomy_calibration, autonomy_session_digest,
                                          close_session, continuous_cycle, get_session, open_session,
                                          record_session_work, session_history)
from ciph.kernel.autonomous_work import (STATUS_SATISFIED, autonomous_work_digest,
                                         propose_work_intent, terminate_work_intent,
                                         work_intent_status)
from ciph.kernel.autonomy_eligibility import eligibility_digest
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.evolution_epochs import current_epoch, epoch_digest, epoch_history
from ciph.kernel.evolution_ownership import production_sources
from ciph.kernel.mission_stewardship import (abandon_mission, mission_health, open_charter,
                                             stewardship_digest)
from ciph.kernel.missions import open_mission, reconstruct_missions
from ciph.kernel.standing_authorization import (authorization_status,
                                                create_standing_authorization, standing_digest)

DAY = 86_400.0
MAINTAIN = "Maintain repository health"
TRAIN = "Train the model"


def bundle(db_path, now):
    """The whole 5.x durable state, as one comparable object."""
    return {"modes": mode_digest(db_path), "standing": standing_digest(db_path),
            "budgets": budget_digest(db_path),
            "work": autonomous_work_digest(db_path), "sessions": autonomy_session_digest(db_path),
            "schedules": schedule_digest(db_path), "interventions": intervention_digest(db_path),
            "stewardship": stewardship_digest(db_path),
            "maintenance": maintenance_digest(db_path),
            "eligibility": eligibility_digest(db_path, now=now),
            "epochs": epoch_digest(db_path)}


class TestGate59ContinuousAutonomyTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-59-")
        self.db = str(Path(self.temp.name) / "vault.db")
        self.t1 = 1_800_000_000.0
        self.mission = open_mission(self.db, objective=MAINTAIN, now=self.t1)
        open_charter(self.db, mission_id=self.mission, purpose=MAINTAIN, actor="operator:operator",
                     now=self.t1)
        self.budget = open_budget(self.db, resource_class="WALL_CLOCK", limit=1.0,
                                  window_seconds=DAY, granted_by="operator:operator", now=self.t1)
        self.authorization = create_standing_authorization(
            self.db, mission_id=self.mission,
            permitted_work_classes=["RUN_TEST_SUITE", "MAINTENANCE_CHECK", "GENERATE_CANDIDATE"],
            resource_budget_ref=self.budget, granted_by="operator:operator", now=self.t1)
        self.schedule = register_schedule(self.db, origin_kind="SCHEDULED_REVIEW",
                                          work_class="RUN_TEST_SUITE", interval_seconds=DAY,
                                          actor="operator:operator", mission_id=self.mission,
                                          first_due_at=self.t1 + DAY, now=self.t1)
        # Every nomination this mission ever made, so a specimen can ask about THIS mission's wake
        # rather than whichever nomination happens to sort first.
        self.nominated = []

    def tearDown(self):
        self.temp.cleanup()

    # ---------------------------------------------------------------- helpers
    def drive_day(self, day):
        """One maintenance cadence tick, the way the loop would actually take it."""
        moment = self.t1 + day * DAY + 60
        opened = []
        for candidate in reconsideration_due(self.db, now=moment):
            schedule_id = candidate["schedule_id"]
            if candidate["certainty"] != "CERTAIN":
                continue
            reconsidered = reconsider(self.db, schedule_id, now=moment)
            if candidate["mission_id"] == self.mission:
                self.nominated.append(reconsidered.intent_id)
            decision = evaluate_eligibility(self.db, intent_id=reconsidered.intent_id, now=moment)
            if decision.outcome != OUTCOME_ELIGIBLE:
                advance_schedule(self.db, schedule_id, outcome=OUTCOME_BLOCKED, now=moment)
                continue
            session = open_session(self.db, trigger_kind="SCHEDULED_REVIEW",
                                   trigger_ref=reconsidered.intent_id, mission_id=self.mission,
                                   standing_auth_id=decision.standing_auth_id, now=moment)
            consume_budget(self.db, self.budget, amount=1.0, now=moment)
            record_session_work(self.db, session_id=session.session_id,
                                intent_id=reconsidered.intent_id,
                                eligibility_outcome=decision.outcome,
                                attempt_ref=f"ATT-{day}", evidence_ref=f"EVD-{day}", now=moment)
            close_session(self.db, session.session_id, stop_reason="WORK_SATISFIED",
                          now=moment + 1)
            # The nomination is FINISHED, and finishing it is the driver's act: the work identity for
            # this morning is closed, and tomorrow brings its own.
            terminate_work_intent(self.db, reconsidered.intent_id, status=STATUS_SATISFIED,
                                  now=moment + 2)
            advance_schedule(self.db, schedule_id, outcome=OUTCOME_NOMINATED, now=moment)
            opened.append(session.session_id)
        return opened

    def reconstruct_in_a_fresh_process(self, now):
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from test_gate_5_9_continuous_autonomy_torture import bundle;"
                "print(json.dumps(bundle(%r, %r), sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, now))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout.strip())

    # ---------------------------------------------------------------- the 5.x scanner zeros
    def test_the_four_5x_scanner_zeros_fire_on_their_own_violations(self):
        real = dict(production_sources())
        catches = [
            ("a09_autonomy_spawns_a_process",
             {**real, "ciph/kernel/autonomy_rogue9.py": "import subprocess\n\n\ndef go():\n"
                                                        "    return subprocess.run(['ls'])\n"}),
            ("a10_autonomy_deletes_canonical_history",
             {**real, "ciph/kernel/autonomy_rogue10.py": "def purge(c):\n"
                                                         "    c.execute('DELETE FROM "
                                                         "ciph_autonomy_sessions')\n"}),
            ("a11_charter_purpose_is_rewritten",
             {**real, "ciph/kernel/autonomy_rogue11.py": "def rewrite(c):\n"
                                                         "    c.execute('UPDATE "
                                                         "ciph_mission_charters SET purpose = ?')\n"}),
            ("a12_maintenance_mutates_the_environment",
             {**real, "ciph/kernel/autonomy_rogue12.py": "# then: pip install everything\n"}),
        ]
        self.assertEqual(len(catches), 4)
        for name, sources in catches:
            with self.subTest(scanner=name):
                self.assertTrue(dict(AUTONOMY_SCANNERS)[name](sources),
                                f"{name} did not fire on its own synthetic violation")
        census = autonomy_scanner_census()
        self.assertEqual(len(census), 12)
        self.assertEqual({name: count for name, count in census.items() if count}, {},
                         "a real-tree scanner offence appeared")

    def test_the_scanner_catalogue_is_not_read_as_a_caller(self):
        """
        The 5.x pattern list contains 4.7's forbidden calls as DATA, and the repair is that a scanner is
        not a caller - not that 4.7's scanner should stop looking. The exclusion is narrow: a module
        that really calls the symbol is still caught.
        """
        from ciph.kernel.autonomy_scanners import scan as autonomy_scan
        from ciph.kernel.meta_scanners import scan as meta_scan
        real = dict(production_sources())
        self.assertEqual({name: offences for name, offences in meta_scan(real).items() if offences},
                         {})
        self.assertEqual({name: offences for name, offences in autonomy_scan(real).items()
                          if offences}, {})
        injected = {**real, "ciph/kernel/rogue_caller.py":
                    "def go(db, a, b):\n    return transition_epoch(db, a, b)\n"}
        self.assertIn("ciph/kernel/rogue_caller.py",
                      meta_scan(injected)["s03_shadow_generator_writes_active_generator"])

    # ---------------------------------------------------------------- the thirty-day torture
    def test_accelerated_thirty_day_continuous_torture(self):
        other = open_mission(self.db, objective=TRAIN, now=self.t1)
        open_charter(self.db, mission_id=other, purpose=TRAIN, actor="operator:operator", now=self.t1)
        other_schedule = register_schedule(self.db, origin_kind="CURIOSITY",
                                           work_class="MAINTENANCE_CHECK", interval_seconds=DAY,
                                           actor="operator:operator", mission_id=other,
                                           first_due_at=self.t1 + DAY, now=self.t1)
        seen = []
        restarts = 0
        for day in range(30):
            moment = self.t1 + day * DAY + 60
            seen.extend(self.drive_day(day))

            if day == 5:
                # Resource squeeze: another wake for the same mission in the same window is refused
                # for want of budget, whatever class it belongs to.
                probe = propose_work_intent(self.db, origin_kind="MONITORING",
                                            work_class="MAINTENANCE_CHECK",
                                            triggering_evidence_refs=["PRESSURE"],
                                            parent_mission_id=self.mission,
                                            subject_ref="pressure-probe",
                                            latest_useful_time=moment + 60, now=moment + 1)
                squeezed = evaluate_eligibility(self.db, intent_id=probe.intent_id, now=moment + 5)
                self.assertEqual(squeezed.outcome, OUTCOME_RESOURCE)
                self.assertEqual(squeezed.stop_reason, "BUDGET_EXHAUSTED")

            if day in (10, 11, 12):
                # dependency outage: the operator forbids anything with an external effect
                set_mode(self.db, mode=MODE_READ_ONLY, actor="operator:operator", now=moment + 10)
                external = propose_work_intent(self.db, origin_kind="MONITORING",
                                               work_class="NETWORK_POST",
                                               triggering_evidence_refs=["OUTAGE"],
                                               parent_mission_id=other, now=moment + 11)
                self.assertEqual(evaluate_eligibility(self.db, intent_id=external.intent_id,
                                                      now=moment + 12).outcome,
                                 OUTCOME_OPERATOR_HOLD)
                if day == 12:
                    set_mode(self.db, mode=MODE_NORMAL, actor="operator:operator", now=moment + 20)
                    # Releasing the outage grant nothing: the class still has no standing authority.
                    self.assertEqual(evaluate_eligibility(self.db, intent_id=external.intent_id,
                                                          now=moment + 21).outcome,
                                     OUTCOME_NO_AUTHORITY)

            if day == 15:
                # A mission ends. The cadence is not what makes work happen - the DECISION is - so the
                # schedule may still hold an appointment and nothing about that appointment is runnable.
                self.assertTrue(abandon_mission(self.db, mission_id=other, rationale="superseded",
                                                actor="operator:operator", now=moment + 30))
                self.assertEqual(work_intent_status(self.db, external.intent_id,
                                                    now=moment + 31), STATUS_SATISFIED)
                self.assertEqual(evaluate_eligibility(self.db, intent_id=external.intent_id,
                                                      now=moment + 31).outcome, OUTCOME_SATISFIED)
                self.assertEqual([session for session in session_history(self.db)
                                  if session.mission_id == other], [])

            if day == 18:
                # An improvement cycle reaches the ceiling - and it is still subject to the budget the
                # operator set, so a busy day cannot also be an improvement day.
                improvement = propose_work_intent(self.db, origin_kind="IMPROVEMENT",
                                                  work_class="GENERATE_CANDIDATE",
                                                  triggering_evidence_refs=["WEAKNESS-1"],
                                                  parent_mission_id=self.mission, now=moment)
                cycle = continuous_cycle(self.db, now=moment)
                self.assertEqual(cycle["ceiling"], "PROMOTION_READY")
                self.assertFalse(cycle["may_promote"])
                self.assertFalse(cycle["may_deploy"])
                self.assertNotIn(improvement.intent_id, cycle["eligible"],
                                 "the day's allowance was already spent")

                # In the next window the same wake is eligible, and the ceiling has not moved.
                later = continuous_cycle(self.db, now=self.t1 + 19 * DAY + 60)
                self.assertIn(improvement.intent_id, later["eligible"])
                self.assertEqual(later["ceiling"], "PROMOTION_READY")
                self.assertFalse(later["may_promote"])
                self.assertFalse(later["may_deploy"])
                notice = raise_promotion_ready(self.db, work_class="GENERATE_CANDIDATE",
                                               candidate_ref="CC-30DAY", evidence_refs=["EVD-30DAY"],
                                               now=moment)
                self.assertFalse(notice.as_dict()["may_deploy"])
                self.assertTrue(notice.as_dict()["requires_operator_authorization"])
                # The work is FINISHED at the ceiling: what remains is an operator decision, not an
                # open piece of autonomy that keeps waking up to ask again.
                terminate_work_intent(self.db, improvement.intent_id, status=STATUS_SATISFIED,
                                      now=moment + 1)
                self.assertEqual(evaluate_eligibility(self.db, intent_id=improvement.intent_id,
                                                      now=moment + 2).outcome, OUTCOME_SATISFIED)

            if day == 20:
                # a weekly operator hold, released the same day
                set_mode(self.db, mode=MODE_QUIESCE, actor="operator:operator", now=moment + 50)
                intervention = enforce_operator_mode(self.db, actor="operator:operator", now=moment + 51)
                self.assertEqual(intervention.kind, "QUIESCE")
                set_mode(self.db, mode=MODE_NORMAL, actor="operator:operator", now=moment + 52)

            if day == 24:
                # restart mid-history: the durable state must reconstruct byte-identically
                expected = bundle(self.db, moment)
                self.assertEqual(self.reconstruct_in_a_fresh_process(moment), expected)
                restarts += 1

            if day in (3, 17, 24):
                set_mode(self.db, mode=MODE_NORMAL, actor="operator:operator", now=moment + 60)

        # ------------------------------------------------------------ the invariants
        final = self.t1 + 30 * DAY
        self.assertEqual(current_mode(self.db), MODE_NORMAL, "authority drifted over thirty days")

        # no duplicated execution: one logical work item per session, ever
        connection = sqlite3.connect(self.db)
        sessions = connection.execute("SELECT COUNT(*) FROM ciph_autonomy_sessions;").fetchone()[0]
        work_items = connection.execute(
            "SELECT COUNT(*) FROM ciph_autonomy_session_work;").fetchone()[0]
        distinct_pairs = connection.execute(
            "SELECT COUNT(*) FROM (SELECT DISTINCT session_id, intent_id "
            "FROM ciph_autonomy_session_work);").fetchone()[0]
        connection.close()
        self.assertEqual(len(seen), sessions, "a session was opened without being driven")
        self.assertEqual(work_items, distinct_pairs, "an attempt was recorded twice")
        self.assertEqual(work_items, sessions, "one wake must record exactly one logical work item")

        # every recorded attempt happened under an ELIGIBLE decision
        for item in [dict(entry) for entry in self._session_work()]:
            self.assertEqual(item["eligibility_outcome"], OUTCOME_ELIGIBLE)

        # no zombie cadence: the abandoned mission's schedule was not reconsidered again
        self.assertEqual([row for row in reconsideration_history(self.db, other_schedule.schedule_id)
                          if row["considered_at"] > self.t1 + 16 * DAY], [],
                         "the abandoned mission's cadence kept ticking")
        self.assertEqual([session for session in session_history(self.db)
                          if session.mission_id != self.mission], [])

        # no runaway curiosity or spending: extra ticks at the same instant change nothing, and a
        # moment with nothing outstanding is reported as idle rather than filled with an insight
        before = len(session_history(self.db))
        for _ in range(3):
            cycle = continuous_cycle(self.db, now=final)
        self.assertTrue(cycle["idle"], "the loop manufactured work out of an idle moment")
        self.assertEqual(cycle["eligible"], [], "an idle moment offered runnable work")
        self.assertEqual(len(session_history(self.db)), before)

        # every cadence period was its own piece of work: the daily review repeated without the
        # identity of yesterday's review being reused or silently collapsed into it
        self.assertEqual(len(self.nominated), 29)
        self.assertEqual(len(set(self.nominated)), 29)

        # no silent production deployment, and no autonomous epoch
        self.assertIsNone(current_epoch(self.db))
        self.assertEqual(epoch_history(self.db), [])
        self.assertTrue(promotion_ready_carries_no_authority(self.db))
        self.assertEqual(len(promotion_ready_notices(self.db)), 1)

        # no rewritten history: the interventions and the refusal that happened are still there
        self.assertTrue(interventions(self.db))
        calibration = autonomy_calibration(self.db, now=final)
        self.assertTrue(calibration["no_score"])
        self.assertGreater(calibration["blocked"], 0)
        self.assertEqual(calibration["sessions"], sessions)

        # authority never drifted in the other direction either: nobody relaxed the mode but the operator
        for record in mode_history(self.db):
            if not str(record["actor"]).startswith("operator:"):
                self.assertNotEqual(record["mode"], MODE_NORMAL,
                                    "a non-operator asserted a permissive mode")

        # the whole thing still reconstructs
        self.assertEqual(self.reconstruct_in_a_fresh_process(final), bundle(self.db, final))
        self.assertGreaterEqual(restarts, 1)

    def _session_work(self):
        connection = sqlite3.connect(self.db)
        connection.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM ciph_autonomy_session_work ORDER BY recorded_at, work_item_id;")]
        finally:
            connection.close()

    # ---------------------------------------------------------------- the individual attacks
    def test_an_interrupt_never_erases_an_unresolved_attempt(self):
        self.drive_day(1)
        intent = reconsider(self.db, self.schedule.schedule_id, now=self.t1 + 2 * DAY + 60)
        moment = self.t1 + 2 * DAY + 70
        session = open_session(self.db, trigger_kind="SCHEDULED_REVIEW", trigger_ref=intent.intent_id,
                               mission_id=self.mission, now=moment)
        record_session_work(self.db, session_id=session.session_id, intent_id=intent.intent_id,
                            eligibility_outcome=OUTCOME_ELIGIBLE, attempt_ref="ATT-OPEN", now=moment)
        set_mode(self.db, mode=MODE_EMERGENCY_STOP, actor="operator:operator", now=moment + 1)
        intervention = enforce_operator_mode(self.db, actor="operator:operator", now=moment + 2)
        self.assertEqual(intervention.sessions_interrupted, (session.session_id,))
        self.assertEqual(get_session(self.db, session.session_id).status, SESSION_INTERRUPTED)
        with self.assertRaises(CrucibleError) as refused:
            settle_session(self.db, session.session_id, actor="operator:operator", now=moment + 3)
        self.assertEqual(refused.exception.reason, "INTERVENTION_DRAIN_REQUIRED")
        self.assertEqual(len(self._session_work()), 2, "the unresolved attempt disappeared")
        self.assertEqual(session_history(self.db)[-1].status, SESSION_INTERRUPTED)

    def test_under_pressure_the_wake_stops_and_the_next_window_restores_it(self):
        opened = self.drive_day(1)
        self.assertEqual(len(opened), 1)
        probe = propose_work_intent(self.db, origin_kind="MONITORING",
                                    work_class="MAINTENANCE_CHECK",
                                    triggering_evidence_refs=["PRESSURE"],
                                    parent_mission_id=self.mission, subject_ref="pressure-probe",
                                    latest_useful_time=self.t1 + 3 * DAY, now=self.t1 + DAY + 70)
        exhausted = evaluate_eligibility(self.db, intent_id=probe.intent_id,
                                        now=self.t1 + DAY + 80)
        self.assertEqual(exhausted.outcome, OUTCOME_RESOURCE)
        self.assertEqual(exhausted.stop_reason, "BUDGET_EXHAUSTED")
        # Budget can constrain authority; only GOVERNANCE may raise it. The allowance simply returns
        # in the next window, and nobody had to approve that.
        self.assertEqual(evaluate_eligibility(self.db, intent_id=probe.intent_id,
                                              now=self.t1 + 2 * DAY + 80).outcome, OUTCOME_ELIGIBLE)
        next_day = self.drive_day(2)
        self.assertEqual(len(next_day), 1, "the next window did not restore the allowance")

    def test_an_expired_grant_is_a_stop_not_a_softer_way_to_proceed(self):
        # A grant that lapses answers EXPIRED - the authority existed and the clock ended it - and
        # EXPIRED is a refusal, not a hint that the work may proceed anyway.
        mission = open_mission(self.db, objective="Seasonal review", now=self.t1)
        expiring = create_standing_authorization(
            self.db, mission_id=mission, permitted_work_classes=["RUN_TEST_SUITE"],
            granted_by="operator:operator", valid_until=self.t1 + 10 * DAY, now=self.t1)
        intent = propose_work_intent(self.db, origin_kind="SCHEDULED_REVIEW",
                                     work_class="RUN_TEST_SUITE", triggering_evidence_refs=["E-1"],
                                     parent_mission_id=mission, now=self.t1)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1 + 9 * DAY).outcome, OUTCOME_ELIGIBLE)
        later = evaluate_eligibility(self.db, intent_id=intent.intent_id, now=self.t1 + 11 * DAY)
        self.assertEqual(later.outcome, OUTCOME_EXPIRED)
        self.assertEqual(authorization_status(self.db, expiring.standing_auth_id,
                                              now=self.t1 + 11 * DAY), "EXPIRED")
        self.assertEqual(later.stop_reason, "AUTHORITY_EXPIRED")

    def test_a_quiesced_session_settles_only_with_evidence(self):
        self.drive_day(1)
        moment = self.t1 + 2 * DAY + 60
        intent = reconsider(self.db, self.schedule.schedule_id, now=moment)
        session = open_session(self.db, trigger_kind="SCHEDULED_REVIEW", trigger_ref=intent.intent_id,
                               mission_id=self.mission, now=moment)
        record_session_work(self.db, session_id=session.session_id, intent_id=intent.intent_id,
                            eligibility_outcome=OUTCOME_ELIGIBLE, attempt_ref="ATT-OPEN", now=moment)
        set_mode(self.db, mode=MODE_QUIESCE, actor="operator:operator", now=moment + 1)
        enforce_operator_mode(self.db, actor="operator:operator", now=moment + 2)
        self.assertEqual(get_session(self.db, session.session_id).status, SESSION_QUIESCING)
        with self.assertRaises(CrucibleError):
            settle_session(self.db, session.session_id, actor="operator:operator", now=moment + 3)
        record_session_work(self.db, session_id=session.session_id, intent_id=intent.intent_id,
                            eligibility_outcome=OUTCOME_ELIGIBLE, attempt_ref="ATT-2",
                            evidence_ref="EVD-1", now=moment + 4)
        settled = settle_session(self.db, session.session_id, actor="operator:operator", now=moment + 5)
        self.assertEqual(settled["status"], SESSION_CLOSED)
        set_mode(self.db, mode=MODE_NORMAL, actor="operator:operator", now=moment + 6)
        self.assertEqual(current_mode(self.db), MODE_NORMAL)

    def test_an_abandoned_mission_leaves_no_runnable_wake(self):
        other = open_mission(self.db, objective=TRAIN, now=self.t1)
        open_charter(self.db, mission_id=other, purpose=TRAIN, actor="operator:operator", now=self.t1)
        intent = propose_work_intent(self.db, origin_kind="MAINTENANCE",
                                     work_class="RUN_TEST_SUITE",
                                     triggering_evidence_refs=["E-1"], parent_mission_id=other,
                                     now=self.t1)
        abandon_mission(self.db, mission_id=other, rationale="superseded", actor="operator:operator",
                        now=self.t1 + 1)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1 + 2).outcome, OUTCOME_SATISFIED)
        health = mission_health(self.db, other, now=self.t1 + 2)
        self.assertEqual(health["status"], "ABANDONED")
        before = len(session_history(self.db))
        # The wake is not merely refused on the way through - it is not even reconsidered.
        self.assertEqual(continuous_cycle(self.db, now=self.t1 + 3)["evaluated"], 0)
        self.assertEqual(len(session_history(self.db)), before)

    def test_a_curiosity_wake_cannot_invent_its_own_question(self):
        with self.assertRaises(CrucibleError):
            assert_curiosity_basis(self.db, "UNC-INVENTED", now=self.t1)
        intent = propose_work_intent(self.db, origin_kind="CURIOSITY",
                                     work_class="INVESTIGATE_UNCERTAINTY",
                                     triggering_evidence_refs=["UNC-INVENTED"],
                                     parent_mission_id=self.mission, now=self.t1)
        # The wake is evaluated like any other; with no authority for the class it is refused, and
        # nothing about it being "curiosity" changes that.
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_NO_AUTHORITY)
        self.assertEqual(session_history(self.db), [])

    def checkpoint(self, label, moment):
        """
        Capture the durable state AND prove a fresh process sees the same thing - right now.

        Checking it later would be meaningless: the point is that the state at THIS boundary is
        reconstructible, and the state moves on.
        """
        local = bundle(self.db, moment)
        self.assertEqual(self.reconstruct_in_a_fresh_process(moment), local,
                         f"{label}: a fresh process reconstructed a different state")
        return (label, local)

    def test_restart_at_every_boundary_duplicates_nothing(self):
        moment = self.t1 + DAY + 60
        checkpoints = [self.checkpoint("proposed", moment)]
        reconsidered = reconsider(self.db, self.schedule.schedule_id, now=moment)
        checkpoints.append(self.checkpoint("reconsidered", moment))
        decision = evaluate_eligibility(self.db, intent_id=reconsidered.intent_id, now=moment)
        self.assertEqual(decision.outcome, OUTCOME_ELIGIBLE)
        session = open_session(self.db, trigger_kind="SCHEDULED_REVIEW",
                               trigger_ref=reconsidered.intent_id, mission_id=self.mission,
                               standing_auth_id=decision.standing_auth_id, now=moment)
        checkpoints.append(self.checkpoint("session-open", moment))
        consume_budget(self.db, self.budget, amount=1.0, now=moment)
        checkpoints.append(self.checkpoint("budget-spent", moment))
        record_session_work(self.db, session_id=session.session_id,
                            intent_id=reconsidered.intent_id,
                            eligibility_outcome=decision.outcome, attempt_ref="ATT-1",
                            evidence_ref="EVD-1", now=moment)
        close_session(self.db, session.session_id, stop_reason="WORK_SATISFIED", now=moment + 1)
        checkpoints.append(self.checkpoint("settled", moment + 1))

        # The boundaries really were distinct states, so the reconstruction above was not five copies
        # of one observation.
        self.assertEqual([label for label, _ in checkpoints],
                         ["proposed", "reconsidered", "session-open", "budget-spent", "settled"])
        self.assertEqual(len({json.dumps(value, sort_keys=True) for _, value in checkpoints}),
                         len(checkpoints))

        # Replaying the whole tick against the settled state changes nothing.
        repeat = reconsider(self.db, self.schedule.schedule_id, now=moment)
        self.assertEqual(repeat.reconsideration_id, reconsidered.reconsideration_id)
        self.assertEqual(len(reconsideration_history(self.db)), 1)
        self.assertEqual(len(session_history(self.db)), 1)
        self.assertEqual(self.reconstruct_in_a_fresh_process(moment), bundle(self.db, moment))

    def test_a_fresh_datastore_has_no_phantom_autonomy_history(self):
        fresh = str(Path(self.temp.name) / "fresh.db")
        connection = sqlite3.connect(fresh)
        connection.close()
        self.assertEqual(current_mode(fresh), MODE_NORMAL)
        self.assertIsNone(current_epoch(fresh))
        self.assertEqual(epoch_history(fresh), [])
        self.assertEqual(promotion_ready_notices(fresh), [])
        self.assertTrue(promotion_ready_carries_no_authority(fresh))
        self.assertEqual(reconstruct_missions(fresh).missions, ())
        self.assertEqual(len(reconsideration_history(fresh)), 0)
        self.assertEqual(len(session_history(fresh)), 0)
        self.assertEqual(len(interventions(fresh)), 0)
        self.assertTrue(maintenance_digest(fresh))


if __name__ == "__main__":
    unittest.main()
