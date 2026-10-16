"""
10.x-R contribution gate: the runtime CONTRIBUTION path must record a HYPOTHESIS, never a verified finding.

    Covers the behaviour added for the normal-runtime investigative contribution: dispatch through the
    ordinary autonomy tick, hypothesis (not finding) status, model provenance, evidence references and the
    notification candidate.

The model boundary is patched: these are MECHANICS specimens, not model-quality specimens.
"""

import pathlib
import sqlite3
import tempfile
import unittest
from unittest import mock

from ciph.runtime import CiphRuntime
from ciph.kernel import autonomy_budgets, autonomy_modes, incubation, model_boundary
from ciph.kernel.autonomy_schedule import register_schedule
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.missions import open_mission
from ciph.kernel.self_model import record_installation
from ciph.kernel.standing_authorization import create_standing_authorization
from ciph.kernel.uncertainty_registry import derive_uncertainties

T = 1_800_000_000.0
OPERATOR = "operator:operator"
CLASS = "INVESTIGATE_UNCERTAINTY"
_JSON = ('{"contribution":"R3 contradicts R1 and R2 (UP vs DOWN for pump P1)",'
         '"evidence_refs":["R1","R3"],"confidence":0.6,"testable_next_step":"re-read source c"}')


def _canned(output=_JSON, model_identity="deepseek-v4-pro"):
    return {"invocation_id": "MOD-CONTRIB", "purpose": "runtime.contribution", "provider": "TEST_DOUBLE",
            "kind": "REAL_MODEL", "model_identity": model_identity, "output": output, "refused": False,
            "refusal_reason": None, "latency_seconds": 0.0, "is_real_model_output": True,
            "usage": {"prompt_tokens": 40, "completion_tokens": 12, "total_tokens": 52},
            "finish_reason": "stop"}


class ContributionCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-contrib-")
        self.db = str(pathlib.Path(self.temp.name) / "v.db")
        self.runtime = CiphRuntime(vault=None, db_path=self.db)
        record_installation(self.db, capability_id="research.public-sources", module_ref="fx", now=T)
        self.uncertainty = derive_uncertainties(self.db, now=T)[0].uncertainty_id
        self.evidence = []
        for ref, text in (("R1", "pump P1 state=UP"), ("R2", "pump P1 state=UP"), ("R3", "pump P1 state=DOWN")):
            obs = record_observation(self.db, source_ref=ref, raw_text=text, now=T)
            self.evidence.append({"ref": ref, "value": text, "observed_at": T, "source": ref,
                                  "evidence_ref": obs["observation_id"]})
        self.budget = autonomy_budgets.open_budget(self.db, resource_class="API_TOKENS", limit=60000.0,
                                                   window_seconds=10_000_000.0, granted_by=OPERATOR, now=T)
        mission = open_mission(self.db, objective="contribution objective", now=T)
        grant = create_standing_authorization(self.db, mission_id=mission, permitted_work_classes=[CLASS],
                                              granted_by=OPERATOR, risk_ceiling="LOW",
                                              scope_constraints=["public-sources"],
                                              resource_budget_ref=self.budget, valid_until=T + 86400, now=T)
        register_schedule(self.db, origin_kind="SCHEDULED_REVIEW", work_class=CLASS, interval_seconds=1000.0,
                          actor=OPERATOR, mission_id=mission, first_due_at=T + 10, now=T)
        autonomy_modes.set_mode(self.db, mode=autonomy_modes.MODE_NORMAL, actor=OPERATOR, reason="t", now=T)
        self.mission = mission
        self.grant = grant.standing_auth_id

    def tearDown(self):
        self.temp.cleanup()

    def tick(self, *, invoke=_canned(), investigation_kind="CONTRIBUTION"):
        objective = {"uncertainty_ref": self.uncertainty, "grant_ref": self.grant, "mission_id": self.mission,
                     "work_class": CLASS, "investigation_kind": investigation_kind, "task_kind": "CONTRADICTION",
                     "evidence": self.evidence, "rule": "NEWEST_CALIBRATED_WINS",
                     "question": "Which record contradicts the others?", "scope": ["public-sources"],
                     "budget_ref": self.budget}
        with mock.patch.object(model_boundary, "invoke", return_value=invoke):
            return self.runtime.run_autonomy_tick(objective=objective, model_ref="deepseek-v4-pro",
                                                  model_provider=model_boundary.CONFIGURED,
                                                  allow_network=False, now=T + 10)

    def counts(self, table):
        connection = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            return int(connection.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            connection.close()


class TestContributionPath(ContributionCase):

    def test_a_contribution_is_recorded_as_a_hypothesis_not_a_finding(self):
        out = self.tick()
        self.assertEqual(len(out["executed"]), 1)
        run = out["executed"][0]
        self.assertEqual(run["kind"], "CONTRIBUTION")
        self.assertEqual(run["hypothesis_status"], "HYPOTHESIS")
        self.assertFalse(run["is_a_result"])
        # nothing was verified: no durable result set / finding was created
        self.assertIsNone(run["result_set_id"])
        self.assertEqual(self.counts("ciph_result_sets"), 0)

    def test_the_hypothesis_keeps_model_provenance_and_evidence_refs(self):
        self.tick()
        hypotheses = incubation.hypotheses(self.db)
        self.assertEqual(len(hypotheses), 1)
        hypothesis = hypotheses[0]
        self.assertEqual(hypothesis["epistemic_status"], incubation.HYPOTHESIS)
        self.assertFalse(hypothesis["is_a_result"])
        self.assertTrue(hypothesis["model_participated"])
        self.assertEqual(hypothesis["model_identity"], "deepseek-v4-pro")
        # the original evidence references are preserved on the hypothesis
        self.assertEqual(len(hypothesis["origin_evidence"]), len(self.evidence))

    def test_a_contribution_creates_a_notification_candidate(self):
        self.tick()
        from ciph.kernel import independent_expeditions as expeditions
        candidates = expeditions.notification_candidates(self.db)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["status"], "CANDIDATE")   # a candidate, not a delivery

    def test_an_empty_model_contribution_is_not_verified(self):
        out = self.tick(invoke=_canned(output=""))
        run = out["executed"][0]
        self.assertEqual(run["kind"], "CONTRIBUTION")
        self.assertEqual(run["hypothesis_status"], "HYPOTHESIS")
        self.assertFalse(run["is_a_result"])
        self.assertFalse(incubation.hypotheses(self.db)[0]["model_participated"])

    def test_a_verdict_objective_is_unaffected_by_the_contribution_path(self):
        # the same tick with a VERDICT objective does NOT go through the contribution recorder
        verdict = {"invocation_id": "MOD-V", "purpose": "runtime.investigation", "provider": "TEST_DOUBLE",
                   "kind": "REAL_MODEL", "model_identity": "deepseek-v4-pro",
                   "output": '{"verdict":"UP","decisive":"R1","rule_applied":"NEWEST_CALIBRATED_WINS"}',
                   "refused": False, "refusal_reason": None, "latency_seconds": 0.0,
                   "is_real_model_output": True, "usage": {}, "finish_reason": "stop"}
        out = self.tick(invoke=verdict, investigation_kind="VERDICT")
        self.assertEqual(out["executed"][0]["kind"], "VERDICT")
        self.assertEqual(len(incubation.hypotheses(self.db)), 0)   # no hypothesis on the verdict path


if __name__ == "__main__":
    unittest.main()
