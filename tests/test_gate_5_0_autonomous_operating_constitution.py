"""
5.0 - the autonomous operating constitution.

    A wake-up is not permission.

The founding torture runs a maintenance mission end to end through the normal 4.0 path; the hostile
matrix exercises the eighteen ways autonomy over-reaches; the accelerated torture simulates thirty days
of waking, spending, interrupting and going idle.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.autonomous_work import (
    ORIGIN_MAINTENANCE,
    ORIGIN_SCHEDULED_REVIEW,
    STATUS_SATISFIED,
    autonomous_work_digest,
    due_for_reconsideration,
    get_work_intent,
    propose_work_intent,
    terminate_work_intent,
    work_intent_status,
)
from ciph.kernel.autonomy_budgets import (
    REASON_EXHAUSTED,
    consume_budget,
    increase_budget,
    open_budget,
    budget_status,
    budget_digest,
)
from ciph.kernel.autonomy_eligibility import (
    OUTCOME_ELIGIBLE,
    OUTCOME_EXPIRED,
    OUTCOME_NO_AUTHORITY,
    OUTCOME_OPERATOR_HOLD,
    OUTCOME_RESOURCE,
    OUTCOME_RISK,
    OUTCOME_SATISFIED,
    OUTCOME_STALE_BASIS,
    OUTCOME_CONFLICT,
    STOP_NO_USEFUL_NEXT_ACTION,
    evaluate_eligibility,
    eligibility_digest,
)
from ciph.kernel.autonomy_modes import (
    MODE_EMERGENCY_STOP,
    MODE_LIMITED,
    MODE_NORMAL,
    MODE_OFF,
    MODE_QUIESCE,
    MODE_READ_ONLY,
    current_mode,
    mode_digest,
    set_mode,
)
from ciph.kernel.autonomy_priority import arbitrate
from ciph.kernel.autonomy_scanners import (
    AUTONOMY_SCANNERS,
    autonomy_scanner_census,
    scan,
)
from ciph.kernel.autonomy_session import (
    PROMOTION_READY,
    autonomy_calibration,
    autonomy_session_digest,
    autonomy_state,
    close_session,
    close_with_idle,
    continuous_cycle,
    open_session,
    record_session_work,
    session_history,
)
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.evolution_ownership import production_sources
from ciph.kernel.missions import MISSION_COMPLETED, complete_mission, open_mission
from ciph.kernel.standing_authorization import (
    REASON_NOT_OPERATOR,
    REASON_SCOPE_WIDENED,
    REASON_WORK_CLASS_NOT_PERMITTED,
    STATUS_REVOKED,
    STANDING_AUTHORIZATION_V1,
    authorization_status,
    create_standing_authorization,
    revoke_standing_authorization,
    standing_digest,
)

DAY = 86_400.0
MAINTAIN = "Maintain repository health"


class TestGate50AutonomousOperatingConstitution(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-50-")
        self.db = str(Path(self.temp.name) / "vault.db")
        self.t1 = 1_800_000_000.0
        self.mission = open_mission(self.db, objective=MAINTAIN, now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def budget(self, limit=1.0, window=DAY):
        return open_budget(self.db, resource_class="WALL_CLOCK", limit=limit,
                           window_seconds=window, granted_by="operator:operator", now=self.t1)

    def authorize(self, *, classes=("RUN_TEST_SUITE", "READ_REPOSITORY", "PRODUCE_REPORT",
                                    "MAINTENANCE_CHECK"), ceiling="LOW", budget_ref=None,
                 mission=None, valid_until=None):
        return create_standing_authorization(
            self.db, mission_id=mission or self.mission, permitted_work_classes=list(classes),
            granted_by="operator:operator", risk_ceiling=ceiling, resource_budget_ref=budget_ref,
            valid_until=valid_until, now=self.t1)

    def intent(self, *, work_class="RUN_TEST_SUITE", evidence=("EVIDENCE-1",), scope=(),
               latest=None, when=None):
        return propose_work_intent(self.db, origin_kind=ORIGIN_MAINTENANCE, work_class=work_class,
                                   triggering_evidence_refs=list(evidence),
                                   parent_mission_id=self.mission, requested_scope=list(scope),
                                   latest_useful_time=latest,
                                   now=self.t1 if when is None else when)

    def bundle(self):
        from ciph.kernel.autonomy_eligibility import eligibility_digest as ed
        return {"modes": mode_digest(self.db), "standing": standing_digest(self.db),
                "budgets": budget_digest(self.db), "work": autonomous_work_digest(self.db),
                "sessions": autonomy_session_digest(self.db), "eligibility": ed(self.db, now=self.t1)}

    # ------------------------------------------------------------------ the founding torture
    def test_founding_maintenance_wake_runs_and_then_runs_out_of_budget(self):
        budget = self.budget(limit=1.0)
        authorization = self.authorize(budget_ref=budget)
        intent = self.intent()

        decision = evaluate_eligibility(self.db, intent_id=intent.intent_id, now=self.t1)
        self.assertEqual(decision.outcome, OUTCOME_ELIGIBLE)
        self.assertEqual(decision.standing_auth_id, authorization.standing_auth_id)
        self.assertEqual(decision.budget_ref, budget)

        session = open_session(self.db, trigger_kind=ORIGIN_SCHEDULED_REVIEW, trigger_ref=intent.intent_id,
                               mission_id=self.mission, standing_auth_id=authorization.standing_auth_id,
                               now=self.t1)
        record_session_work(self.db, session_id=session.session_id, intent_id=intent.intent_id,
                            eligibility_outcome=decision.outcome, job_id="JOB-1",
                            attempt_ref="ATT-1", evidence_ref="EVD-1", now=self.t1)
        consume_budget(self.db, budget, amount=1.0, now=self.t1)
        closed = close_session(self.db, session.session_id, stop_reason="WORK_SATISFIED",
                               now=self.t1 + 10)
        self.assertEqual(closed.status, "CLOSED")
        self.assertEqual(len(session_history(self.db)), 1)

        # waking again immediately finds the budget spent
        again = evaluate_eligibility(self.db, intent_id=intent.intent_id, now=self.t1 + 20)
        self.assertEqual(again.outcome, OUTCOME_RESOURCE)
        self.assertIn(REASON_EXHAUSTED, again.reason_codes)
        self.assertEqual(again.stop_reason, "BUDGET_EXHAUSTED")

        # the next window restores the allowance without anyone raising a limit
        tomorrow = budget_status(self.db, budget, now=self.t1 + DAY + 60)
        self.assertEqual(tomorrow.remaining, 1.0)
        self.assertTrue(tomorrow.window_expired)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1 + DAY + 60).outcome, OUTCOME_ELIGIBLE)

    def test_continuous_cycle_stops_at_promotion_ready_and_never_promotes(self):
        self.authorize(classes=("GENERATE_CANDIDATE", "EVALUATE_CANDIDATE", "META_DISCOVERY"))
        self.intent(work_class="GENERATE_CANDIDATE", evidence=("WEAKNESS-1",))
        cycle = continuous_cycle(self.db, now=self.t1)
        self.assertGreaterEqual(cycle["evaluated"], 1)
        self.assertEqual(cycle["ceiling"], PROMOTION_READY)
        self.assertFalse(cycle["may_promote"])
        self.assertFalse(cycle["may_deploy"])

    # ------------------------------------------------------------------ hostile matrix
    def test_hostile_no_authority_expired_and_revoked(self):
        intent = self.intent()
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_NO_AUTHORITY)
        authorization = self.authorize(valid_until=self.t1 + 100)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_ELIGIBLE)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                             now=self.t1 + 200).outcome, OUTCOME_EXPIRED)
        revoke_standing_authorization(self.db, authorization.standing_auth_id, reason="operator",
                                      actor="operator:operator", now=self.t1)
        self.assertEqual(authorization_status(self.db, authorization.standing_auth_id, now=self.t1),
                         STATUS_REVOKED)

    def test_hostile_scope_widening_and_prohibited_work_classes(self):
        self.authorize(classes=("READ_REPOSITORY",))
        widened = self.intent(work_class="READ_REPOSITORY", scope=("production",))
        decision = evaluate_eligibility(self.db, intent_id=widened.intent_id, now=self.t1)
        self.assertEqual(decision.outcome, OUTCOME_NO_AUTHORITY)
        self.assertIn(REASON_SCOPE_WIDENED, decision.reason_codes)

        for work_class in ("PRODUCTION_INSTALL", "KEY_ACCESS", "NETWORK_POST", "META_PROMOTION"):
            intent = self.intent(work_class=work_class, evidence=(f"E-{work_class}",))
            refused = evaluate_eligibility(self.db, intent_id=intent.intent_id, now=self.t1)
            self.assertIn(refused.outcome, (OUTCOME_NO_AUTHORITY, OUTCOME_RISK),
                          f"{work_class} must not be autonomously eligible")

    def test_hostile_risk_ceiling_blocks_a_permitted_class(self):
        self.authorize(classes=("NETWORK_POST",), ceiling="LOW")
        intent = self.intent(work_class="NETWORK_POST", evidence=("POST-1",))
        decision = evaluate_eligibility(self.db, intent_id=intent.intent_id, now=self.t1)
        self.assertEqual(decision.outcome, OUTCOME_RISK)

    def test_hostile_operator_modes_override_everything(self):
        self.authorize()
        intent = self.intent()
        set_mode(self.db, mode=MODE_QUIESCE, actor="operator:operator", now=self.t1)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_OPERATOR_HOLD)
        set_mode(self.db, mode=MODE_OFF, actor="operator:operator", now=self.t1)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_OPERATOR_HOLD)
        set_mode(self.db, mode=MODE_NORMAL, actor="operator:operator", now=self.t1)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_ELIGIBLE)
        # LIMITED is a risk ceiling, not a shutdown: it still permits LOW, and it refuses what is
        # above LOW *before* the authority question is reached, so a MEDIUM class is refused even if
        # some grant would have allowed it.
        set_mode(self.db, mode=MODE_LIMITED, actor="operator:operator", now=self.t1)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_ELIGIBLE,
                         "a LOW-risk maintenance wake is exactly what LIMITED still permits")
        medium = self.intent(work_class="NETWORK_POST", evidence=("POST-1",))
        self.assertEqual(evaluate_eligibility(self.db, intent_id=medium.intent_id,
                                              now=self.t1).outcome, OUTCOME_RISK)
        set_mode(self.db, mode=MODE_READ_ONLY, actor="operator:operator", now=self.t1)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_ELIGIBLE,
                         "a read-only mode still permits read-class maintenance")

    def test_hostile_a_daemon_cannot_lower_an_operator_hold_or_mint_authority(self):
        set_mode(self.db, mode=MODE_EMERGENCY_STOP, actor="operator:operator", now=self.t1)
        with self.assertRaises(CrucibleError) as refused:
            set_mode(self.db, mode=MODE_NORMAL, actor="daemon:curiosity", now=self.t1)
        self.assertEqual(refused.exception.reason, "DAEMON_CANNOT_OVERRIDE_OPERATOR_MODE")
        self.assertEqual(current_mode(self.db), MODE_EMERGENCY_STOP)
        with self.assertRaises(CrucibleError) as not_operator:
            create_standing_authorization(self.db, mission_id=self.mission,
                                          permitted_work_classes=["RUN_TEST_SUITE"],
                                          granted_by="daemon:curiosity", now=self.t1)
        self.assertEqual(not_operator.exception.reason, REASON_NOT_OPERATOR)

    def test_hostile_duplicate_wakes_are_one_work_identity(self):
        self.authorize()
        first = self.intent()
        second = self.intent()
        self.assertEqual(first.intent_id, second.intent_id)
        self.assertEqual(len(due_for_reconsideration(self.db, now=self.t1)), 1)

    def test_hostile_stale_basis_and_completed_mission(self):
        self.authorize()
        intent = self.intent()
        from ciph.kernel.missions import attach_action
        attach_action(self.db, mission_id=self.mission, logical_action_id="ACT-DRIFT", now=self.t1 + 5)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1 + 10).outcome, OUTCOME_STALE_BASIS)
        other = propose_work_intent(self.db, origin_kind=ORIGIN_MAINTENANCE,
                                    work_class="RUN_TEST_SUITE",
                                    triggering_evidence_refs=["E-2"], parent_mission_id=self.mission,
                                    now=self.t1 + 20)
        complete_mission(self.db, mission_id=self.mission, reason="done", now=self.t1 + 30)
        self.assertEqual(work_intent_status(self.db, other.intent_id, now=self.t1 + 40),
                         STATUS_SATISFIED)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=other.intent_id,
                                              now=self.t1 + 40).outcome, OUTCOME_SATISFIED)

    def test_hostile_conflicting_work_and_idleness(self):
        self.authorize()
        intent = self.intent()
        session = open_session(self.db, trigger_kind=ORIGIN_SCHEDULED_REVIEW,
                               trigger_ref="other", mission_id=self.mission, now=self.t1)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_CONFLICT)
        close_session(self.db, session.session_id, stop_reason="WORK_SATISFIED", now=self.t1 + 1)

        idle = close_with_idle(self.db, session.session_id, evaluated=3, blocked=3, eligible=0,
                               reason=STOP_NO_USEFUL_NEXT_ACTION, next_review_at=self.t1 + DAY,
                               now=self.t1 + 2)
        self.assertEqual(idle.eligible_work_count, 0)
        self.assertEqual(idle.reason, STOP_NO_USEFUL_NEXT_ACTION)
        state = autonomy_state(self.db, now=self.t1 + 3)
        self.assertIn(state["mode"], (MODE_NORMAL, MODE_LIMITED, MODE_READ_ONLY))
        self.assertTrue(state["work_chain"])

    def test_hostile_urgency_is_not_authority(self):
        intent_a = self.intent(evidence=("A",))
        intent_b = self.intent(work_class="READ_REPOSITORY", evidence=("B",), latest=self.t1 + 60)
        ranked = arbitrate(self.db, intent_ids=[intent_a.intent_id, intent_b.intent_id], now=self.t1,
                           operator_priority_refs=[])
        self.assertEqual(len(ranked), 2)
        self.assertTrue(ranked[0].score >= ranked[1].score)
        # The highest-priority intent in the system still has no authority of its own.
        decision = evaluate_eligibility(self.db, intent_id=ranked[0].intent_id, now=self.t1)
        self.assertEqual(decision.outcome, OUTCOME_NO_AUTHORITY)
        override = arbitrate(self.db, intent_ids=[intent_a.intent_id, intent_b.intent_id], now=self.t1,
                             operator_priority_refs=[intent_b.intent_id])
        self.assertEqual(override[0].intent_id, intent_b.intent_id)
        self.assertIn("OPERATOR_PRIORITY", override[0].reason_codes)

    def test_hostile_budget_increase_requires_governance(self):
        budget = self.budget(limit=1.0)
        with self.assertRaises(CrucibleError) as refused:
            increase_budget(self.db, budget, new_limit=100.0, authority_ref="daemon:curiosity",
                            now=self.t1)
        self.assertEqual(refused.exception.reason, "BUDGET_INCREASE_REQUIRES_AN_OPERATOR")
        increased = increase_budget(self.db, budget, new_limit=5.0, authority_ref="operator:operator",
                                    now=self.t1)
        self.assertEqual(increased.limit, 5.0)

    def test_hostile_restart_reconstructs_the_exact_autonomy_state(self):
        budget = self.budget(limit=2.0)
        authorization = self.authorize(budget_ref=budget)
        intent = self.intent()
        session = open_session(self.db, trigger_kind=ORIGIN_SCHEDULED_REVIEW,
                               trigger_ref=intent.intent_id, mission_id=self.mission,
                               standing_auth_id=authorization.standing_auth_id, now=self.t1)
        record_session_work(self.db, session_id=session.session_id, intent_id=intent.intent_id,
                            eligibility_outcome=OUTCOME_ELIGIBLE, now=self.t1)
        evaluate_eligibility(self.db, intent_id=intent.intent_id, now=self.t1)
        expected = self.bundle()
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from test_gate_5_0_autonomous_operating_constitution import TestGate50AutonomousOperatingConstitution as T;"
                "print(json.dumps(T.bundle_of(%r, %r), sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.t1))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)
        self.assertEqual(self.bundle(), expected)
        self.assertTrue(autonomy_calibration(self.db, now=self.t1)["no_score"])

    @staticmethod
    def bundle_of(db, now):
        from ciph.kernel.autonomy_eligibility import eligibility_digest as ed
        return {"modes": mode_digest(db), "standing": standing_digest(db), "budgets": budget_digest(db),
                "work": autonomous_work_digest(db), "sessions": autonomy_session_digest(db),
                "eligibility": ed(db, now=now)}

    # ------------------------------------------------------------------ scanners
    def test_all_eight_autonomy_scanners_are_zero(self):
        # The 5.0 EIGHT are asserted by NAME, so a later phase that adds its own scanners to this file
        # cannot make 5.0's claim vacuous by inflating the tuple.
        census = autonomy_scanner_census()
        self.assertEqual(len(census), len(AUTONOMY_SCANNERS))
        self.assertEqual({name: count for name, count in census.items() if count}, {})
        for name in ("a01_raw_autonomous_executor", "a02_daemon_direct_permit_claim",
                     "a03_daemon_direct_file_activation", "a04_autonomy_private_signer",
                     "a05_autonomy_creates_standing_authorization",
                     "a06_autonomy_overrides_operator_mode", "a07_autonomous_production_deploy",
                     "a08_autonomous_meta_promotion"):
            self.assertIn(name, census, f"{name} disappeared from the census")
            self.assertEqual(census[name], 0)

    def test_every_autonomy_scanner_fires_on_a_synthetic_violation(self):
        real = dict(production_sources())
        catches = [
            ("a01_raw_autonomous_executor",
             {**real, "ciph/kernel/autonomy_rogue.py": "def background_execute():\n    pass\n"}),
            ("a02_daemon_direct_permit_claim",
             {**real, "ciph/kernel/autonomy_rogue2.py": "def go(store):\n    return store.claim('p')\n"}),
            ("a03_daemon_direct_file_activation",
             {**real, "ciph/kernel/autonomy_rogue3.py": "def write(p, d):\n    p.write_bytes(d)\n"}),
            ("a04_autonomy_private_signer",
             {**real, "ciph/kernel/autonomy_rogue4.py": "from ciph.kernel.crypto_identity import Ed25519KeyManager\n"}),
            ("a05_autonomy_creates_standing_authorization",
             {**real, "ciph/kernel/autonomy_rogue5.py": "def grant(db):\n    return create_standing_authorization(db)\n"}),
            ("a06_autonomy_overrides_operator_mode",
             {**real, "ciph/kernel/autonomy_rogue6.py": "def relax(db):\n    set_mode(db, 'AUTONOMY_NORMAL', 'daemon')\n"}),
            ("a07_autonomous_production_deploy",
             {**real, "ciph/kernel/autonomy_rogue7.py": "def ship(db, p):\n    return promote(db, p)\n"}),
            ("a08_autonomous_meta_promotion",
             {**real, "ciph/kernel/autonomy_rogue8.py": "def bump(db, a, b):\n    return transition_epoch(db, a, b)\n"}),
        ]
        self.assertEqual(len(catches), 8)
        for name, sources in catches:
            with self.subTest(scanner=name):
                self.assertTrue(dict(AUTONOMY_SCANNERS)[name](sources),
                                f"{name} did not fire on its own synthetic violation")

    # ------------------------------------------------------------------ 5.9 accelerated torture
    def test_accelerated_thirty_day_torture(self):
        budget = self.budget(limit=1.0, window=DAY)
        authorization = self.authorize(budget_ref=budget)
        sessions_opened = 0
        for day in range(30):
            now = self.t1 + day * DAY
            self.intent(evidence=("DAILY-REVIEW",), when=now)
            for intent in due_for_reconsideration(self.db, now=now):
                decision = evaluate_eligibility(self.db, intent_id=intent.intent_id, now=now)
                if decision.outcome != OUTCOME_ELIGIBLE:
                    continue
                session = open_session(self.db, trigger_kind=ORIGIN_SCHEDULED_REVIEW,
                                       trigger_ref=f"day-{day}", mission_id=self.mission,
                                       standing_auth_id=authorization.standing_auth_id, now=now)
                sessions_opened += 1
                consume_budget(self.db, budget, amount=1.0, now=now)
                record_session_work(self.db, session_id=session.session_id,
                                    intent_id=intent.intent_id,
                                    eligibility_outcome=decision.outcome, now=now)
                close_session(self.db, session.session_id, stop_reason="WORK_SATISFIED", now=now + 1)
                # an operator interrupt once a week, then release
                if day % 7 == 0:
                    set_mode(self.db, mode=MODE_QUIESCE, actor="operator:operator", now=now + 2)
                    set_mode(self.db, mode=MODE_NORMAL, actor="operator:operator", now=now + 3)
        self.assertEqual(current_mode(self.db), MODE_NORMAL, "no authority drift across 30 days")
        self.assertEqual(len(session_history(self.db)), sessions_opened)
        self.assertLessEqual(sessions_opened, 30)
        calibration = autonomy_calibration(self.db, now=self.t1 + 30 * DAY)
        self.assertEqual(calibration["sessions"], sessions_opened)
        self.assertNotIn("score", calibration)
        self.assertTrue(calibration["no_score"])
        self.assertEqual(autonomy_scanner_census(), {name: 0 for name, _ in AUTONOMY_SCANNERS})


if __name__ == "__main__":
    unittest.main()
