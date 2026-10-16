"""
10.x-R tick gate: the unattended runtime edge (`CiphRuntime.run_autonomy_tick`) must carry authorized work
across wakes and refuse everything it must refuse, without the model being real (the boundary is patched).

    These are MECHANICS specimens. They assert eligibility, ceilings, idempotency and safe failure - not the
    model's judgment.
"""

import pathlib
import sqlite3
import tempfile
import unittest
from unittest import mock

from ciph.runtime import CiphRuntime
from ciph.kernel.autonomy_schedule import register_schedule, reconsideration_history
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.missions import open_mission
from ciph.kernel.self_model import record_installation
from ciph.kernel.standing_authorization import create_standing_authorization
from ciph.kernel.uncertainty_registry import derive_uncertainties
from ciph.kernel import autonomy_budgets, autonomy_modes, model_boundary

T = 1_800_000_000.0
OPERATOR = "operator:operator"
CLASS = "INVESTIGATE_UNCERTAINTY"


def _canned(output='{"verdict":"ABSTAIN","decisive":null,"rule_applied":"NEWEST_CALIBRATED_WINS"}'):
    return {"invocation_id": "MOD-TEST", "purpose": "runtime.investigation", "provider": "TEST_DOUBLE",
            "kind": "REAL_MODEL", "model_identity": "test-double", "output": output, "refused": False,
            "refusal_reason": None, "latency_seconds": 0.0, "is_real_model_output": True}


class TickCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-tick-")
        self.db = str(pathlib.Path(self.temp.name) / "v.db")
        self.runtime = CiphRuntime(vault=None, db_path=self.db)
        record_installation(self.db, capability_id="research.public-sources", module_ref="fx", now=T)
        self.uncertainty = derive_uncertainties(self.db, now=T)[0].uncertainty_id
        self.evidence = []
        for name in ("a", "b"):
            obs = record_observation(self.db, source_ref=name, raw_text=f"source {name}", now=T)
            self.evidence.append({"ref": name, "value": f"V_{name}", "observed_at": T, "source": name,
                                  "evidence_ref": obs["observation_id"]})
        autonomy_modes.set_mode(self.db, mode=autonomy_modes.MODE_NORMAL, actor=OPERATOR, reason="t",
                                now=T)

    def tearDown(self):
        self.temp.cleanup()

    def _objective(self, mission, grant_ref, budget_ref, *, work_class=CLASS, scope=None, question="q"):
        return {"uncertainty_ref": self.uncertainty, "grant_ref": grant_ref, "mission_id": mission,
                "work_class": work_class, "evidence": self.evidence, "question": question,
                "rule": "NEWEST_CALIBRATED_WINS", "scope": scope or ["public-sources"],
                "budget_ref": budget_ref}

    def _world(self, mission="M1", *, due=T + 10, valid_until=None, classes=(CLASS,), scope=("public-sources",),
               budget=5):
        mission_id = open_mission(self.db, objective=f"obj:{mission}", now=T)
        budget_ref = autonomy_budgets.open_budget(self.db, resource_class="API_TOKENS", limit=budget,
                                                  window_seconds=10_000_000.0, granted_by=OPERATOR, now=T)
        grant = create_standing_authorization(
            self.db, mission_id=mission_id, permitted_work_classes=list(classes), granted_by=OPERATOR,
            risk_ceiling="LOW", scope_constraints=list(scope),
            resource_budget_ref=budget_ref, valid_until=valid_until or T + 1_000_000, now=T)
        schedule = register_schedule(self.db, origin_kind="SCHEDULED_REVIEW", work_class=classes[0],
                                     interval_seconds=1000.0, actor=OPERATOR, mission_id=mission_id,
                                     first_due_at=due, now=T)
        return mission_id, grant.standing_auth_id, budget_ref, schedule.schedule_id

    def tick(self, mission_id, grant_ref, budget_ref, *, now, invoke=_canned()):
        with mock.patch.object(model_boundary, "invoke", return_value=invoke):
            return self.runtime.run_autonomy_tick(
                objective=self._objective(mission_id, grant_ref, budget_ref), model_ref="deepseek-v4-pro",
                model_provider=model_boundary.CONFIGURED, allow_network=False, now=now)


class TestTickMechanics(TickCase):

    def test_a_due_authorized_wake_executes_one_investigation(self):
        mid, grant, budget, _ = self._world()
        out = self.tick(mid, grant, budget, now=T + 10)
        self.assertEqual(out["eligible_for_objective"], 1)
        self.assertEqual(len(out["executed"]), 1)
        self.assertIsNotNone(out["executed"][0]["result_set_id"])
        self.assertEqual(out["stop"], "WORK_SATISFIED")

    def test_nothing_due_is_idle_not_busy(self):
        mid, grant, budget, _ = self._world(due=T + 100)
        out = self.tick(mid, grant, budget, now=T + 15)
        self.assertEqual(out["executed"], [])
        self.assertEqual(out["nominations"], [])
        self.assertEqual(out["stop"], "NO_USEFUL_NEXT_ACTION")

    def test_duplicate_due_period_is_one_intent(self):
        mid, grant, budget, schedule = self._world()
        first = self.tick(mid, grant, budget, now=T + 10)
        # the schedule advanced; a second tick at the SAME time finds nothing due (no duplicate work)
        second = self.tick(mid, grant, budget, now=T + 10)
        self.assertEqual(len(first["executed"]), 1)
        self.assertEqual(second["executed"], [])
        self.assertEqual(len(reconsideration_history(self.db, schedule)), 1)

    def test_expired_grant_blocks(self):
        mid, grant, budget, _ = self._world(due=T + 100, valid_until=T + 5)
        out = self.tick(mid, grant, budget, now=T + 200)
        self.assertEqual(out["executed"], [])

    def test_operator_quiescence_blocks(self):
        mid, grant, budget, _ = self._world()
        autonomy_modes.set_mode(self.db, mode=autonomy_modes.MODE_QUIESCE, actor=OPERATOR, reason="hold",
                                now=T + 5)
        out = self.tick(mid, grant, budget, now=T + 10)
        self.assertEqual(out["executed"], [])
        from ciph.kernel.autonomy_eligibility import evaluate_eligibility
        intent_ids = [n["intent_id"] for n in out["nominations"] if n.get("intent_id")]
        self.assertTrue(intent_ids)
        outcomes = [evaluate_eligibility(self.db, intent_id=i, now=T + 10, record=False).outcome
                    for i in intent_ids]
        self.assertIn("BLOCKED_OPERATOR_HOLD", outcomes)

    def test_resource_ceiling_blocks_a_second_investigation(self):
        mid, grant, budget, _ = self._world(budget=1)
        first = self.tick(mid, grant, budget, now=T + 10)
        self.assertEqual(len(first["executed"]), 1)
        self.assertEqual(autonomy_budgets.budget_status(self.db, budget, now=T + 10).remaining, 0)
        # a NEW due period is refused by the exhausted ceiling
        second = self.tick(mid, grant, budget, now=T + 1010)
        self.assertEqual(second["executed"], [])

    def test_scope_expansion_is_refused(self):
        mid, grant, budget, _ = self._world(scope=("public-sources",))
        out = self.tick(mid, grant, budget, now=T + 10)
        # the objective widens scope beyond the grant -> authorize refuses -> nothing executed
        with mock.patch.object(model_boundary, "invoke", return_value=_canned()):
            widened = self.runtime.run_autonomy_tick(
                objective={**self._objective(mid, grant, budget),
                           "scope": ["public-sources", "private-lan"]},
                model_ref="deepseek-v4-pro", model_provider=model_boundary.CONFIGURED, allow_network=False,
                now=T + 2010)
        self.assertEqual(widened["executed"], [])
        self.assertTrue(widened["refusals"])

    def test_empty_model_output_is_refused_and_not_counted(self):
        mid, grant, budget, _ = self._world()
        empty = {**_canned(output=""), "refused": True,
                 "refusal_reason": model_boundary.EMPTY_MODEL_OUTPUT}
        out = self.tick(mid, grant, budget, now=T + 10, invoke=empty)
        # the investigation ran but the model contributed NOTHING: publication is rule-derived, no credit
        self.assertEqual(len(out["executed"]), 1)
        self.assertEqual(out["executed"][0]["attribution"], "RULE_DERIVED")

    def test_provider_unavailable_records_no_fiction(self):
        mid, grant, budget, _ = self._world()
        refused = {**_canned(output=""), "refused": True, "model_identity": None,
                   "refusal_reason": model_boundary.NO_PROVIDER}
        out = self.tick(mid, grant, budget, now=T + 10, invoke=refused)
        self.assertEqual(out["executed"][0]["model_refused"], True)
        self.assertEqual(out["executed"][0]["attribution"], "RULE_DERIVED")

    def test_a_failed_attempt_still_consumes_the_ceiling(self):
        mid, grant, budget, _ = self._world(budget=1)
        empty = {**_canned(output=""), "refused": True,
                 "refusal_reason": model_boundary.EMPTY_MODEL_OUTPUT}
        self.tick(mid, grant, budget, now=T + 10, invoke=empty)
        # the FAILED invocation spent the one unit: a later period cannot borrow it.
        self.assertEqual(autonomy_budgets.budget_status(self.db, budget, now=T + 1010).remaining, 0)
        later = self.tick(mid, grant, budget, now=T + 1010)
        self.assertEqual(later["executed"], [])

    def test_budget_is_shared_across_missions_in_the_same_class_and_window(self):
        # the budget identity is (class, window, actor): two missions share ONE ceiling.
        m1, g1, b1, _ = self._world(mission="M1", budget=1)
        m2, g2, b2, _ = self._world(mission="M2", budget=1)
        self.assertEqual(b1, b2)                       # the canonical shared ceiling
        self.assertEqual(len(self.tick(m1, g1, b1, now=T + 10)["executed"]), 1)
        self.assertEqual(self.tick(m2, g2, b2, now=T + 10)["executed"], [])   # M2 cannot borrow


    def test_a_nomination_lapses_after_its_useful_window(self):
        # 5.2: work identified for a due moment is useful only until the next cadence. Inside the window it
        # is eligible; after it, the nomination LAPSES (legitimate expiry, not a scheduler fault).
        mid, grant, budget, _ = self._world(mission="MLAP", due=T + 10)
        from ciph.kernel.autonomous_work import propose_work_intent
        from ciph.kernel.autonomy_eligibility import evaluate_eligibility
        intent = propose_work_intent(self.db, origin_kind="SCHEDULED_REVIEW", work_class=CLASS,
                                     triggering_evidence_refs=["SCHEDULE:X"], parent_mission_id=mid,
                                     latest_useful_time=T + 20, now=T)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id, now=T + 10).outcome,
                         "ELIGIBLE")
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id, now=T + 30).outcome,
                         "EXPIRED")


if __name__ == "__main__":
    unittest.main()
