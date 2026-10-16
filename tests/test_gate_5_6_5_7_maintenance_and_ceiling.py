"""
5.6 + 5.7 - autonomous maintenance, and the ceiling of the continuous loop.

    Maintenance is work Ciph does to ITSELF. An upgrade is a governed change.
    The loop may discover, hypothesise, generate and evaluate. It stops at PROMOTION_READY, and a
    promotion-ready NOTICE IS NOT AUTHORITY.

The specimens attack both halves: a governed change dressed as housekeeping, and a handoff that tries to
travel with the authority it explicitly does not have.
"""

import tempfile
import unittest
from pathlib import Path

from ciph.kernel.autonomy_eligibility import OUTCOME_ELIGIBLE, evaluate_eligibility
from ciph.kernel.autonomy_maintenance import (
    CEILING_WORK_CLASSES,
    GOVERNED_CHANGES,
    MAINTENANCE_CHECKS,
    REASON_CLASS_CANNOT_REACH_THE_CEILING,
    REASON_CURIOSITY_QUESTION_RESOLVED,
    REASON_CURIOSITY_REQUIRES_OPEN_QUESTION,
    REASON_GOVERNED_CHANGE_IS_NOT_MAINTENANCE,
    REASON_HANDOFF_REQUIRES_A_CANDIDATE,
    REASON_HANDOFF_REQUIRES_EVIDENCE,
    assert_curiosity_basis,
    assert_maintenance_is_maintenance,
    maintenance_checklist,
    maintenance_digest,
    promotion_ready_carries_no_authority,
    promotion_ready_notices,
    raise_promotion_ready,
)
from ciph.kernel.autonomy_session import PROMOTION_READY, continuous_cycle, open_session
from ciph.kernel.autonomous_work import propose_work_intent
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.missions import open_mission
from ciph.kernel.standing_authorization import create_standing_authorization


class TestGate56And57(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-567-")
        self.db = str(Path(self.temp.name) / "vault.db")
        self.t1 = 1_800_000_000.0
        self.mission = open_mission(self.db, objective="Maintain repository health", now=self.t1)
        create_standing_authorization(
            self.db, mission_id=self.mission,
            permitted_work_classes=["RUN_TEST_SUITE", "MAINTENANCE_CHECK", "READ_REPOSITORY",
                                    "GENERATE_CANDIDATE", "INVESTIGATE_UNCERTAINTY"],
            granted_by="operator:operator", now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    # ---------------------------------------------------------------- 5.6
    def test_the_maintenance_programme_is_deterministic(self):
        self.assertEqual(maintenance_checklist(), maintenance_checklist())
        self.assertEqual(maintenance_checklist(), MAINTENANCE_CHECKS)

    def test_a_governed_change_is_not_maintenance(self):
        for work_class in GOVERNED_CHANGES:
            with self.assertRaises(CrucibleError) as refused:
                assert_maintenance_is_maintenance(work_class)
            self.assertEqual(refused.exception.reason, REASON_GOVERNED_CHANGE_IS_NOT_MAINTENANCE)
        self.assertEqual(assert_maintenance_is_maintenance("RUN_TEST_SUITE"), "RUN_TEST_SUITE")

    def test_a_maintenance_wake_produces_no_external_effect(self):
        for work_class, _ in MAINTENANCE_CHECKS:
            intent = propose_work_intent(self.db, origin_kind="MAINTENANCE",
                                         work_class=work_class,
                                         triggering_evidence_refs=[f"E-{work_class}"],
                                         parent_mission_id=self.mission, now=self.t1)
            self.assertFalse(intent.external_effect, work_class)
            self.json_check(intent)

    def json_check(self, intent):  # local helper: the class decides the risk, not the caller
        self.assertIn(intent.risk_class, ("NONE", "LOW"))

    # ---------------------------------------------------------------- 5.7
    def test_the_ceiling_only_accepts_classes_that_can_reach_it(self):
        with self.assertRaises(CrucibleError) as refused:
            raise_promotion_ready(self.db, work_class="PRODUCTION_INSTALL", candidate_ref="CC-1",
                                  evidence_refs=["EVD-1"], now=self.t1)
        self.assertEqual(refused.exception.reason, REASON_CLASS_CANNOT_REACH_THE_CEILING)
        for work_class in CEILING_WORK_CLASSES:
            notice = raise_promotion_ready(self.db, work_class=work_class, candidate_ref="CC-1",
                                           evidence_refs=["EVD-1"], now=self.t1)
            self.assertTrue(notice.as_dict()["requires_operator_authorization"])
            self.assertFalse(notice.as_dict()["may_promote"])
            self.assertFalse(notice.as_dict()["may_deploy"])

    def test_a_handoff_requires_a_candidate_and_evidence(self):
        with self.assertRaises(CrucibleError) as no_candidate:
            raise_promotion_ready(self.db, work_class="GENERATE_CANDIDATE", candidate_ref=None,
                                  evidence_refs=["EVD-1"], now=self.t1)
        self.assertEqual(no_candidate.exception.reason, REASON_HANDOFF_REQUIRES_A_CANDIDATE)
        with self.assertRaises(CrucibleError) as no_evidence:
            raise_promotion_ready(self.db, work_class="GENERATE_CANDIDATE", candidate_ref="CC-1",
                                  evidence_refs=[], now=self.t1)
        self.assertEqual(no_evidence.exception.reason, REASON_HANDOFF_REQUIRES_EVIDENCE)
        self.assertEqual(promotion_ready_notices(self.db), [])

    def test_no_handoff_row_can_claim_authority(self):
        raise_promotion_ready(self.db, work_class="EVALUATE_CANDIDATE", candidate_ref="CC-9",
                              evidence_refs=["EVD-9"], now=self.t1)
        self.assertTrue(promotion_ready_carries_no_authority(self.db))
        self.assertEqual(len(promotion_ready_notices(self.db)), 1)
        # The same reference raised twice is ONE notice: a retry cannot inflate the record.
        raise_promotion_ready(self.db, work_class="EVALUATE_CANDIDATE", candidate_ref="CC-9",
                              evidence_refs=["EVD-9"], now=self.t1 + 10)
        self.assertEqual(len(promotion_ready_notices(self.db)), 1)

    def test_curiosity_investigates_a_question_the_registry_holds(self):
        with self.assertRaises(CrucibleError) as unknown:
            assert_curiosity_basis(self.db, "UNC-DOES-NOT-EXIST", now=self.t1)
        self.assertEqual(unknown.exception.reason, REASON_CURIOSITY_REQUIRES_OPEN_QUESTION)
        with self.assertRaises(CrucibleError):
            assert_curiosity_basis(self.db, "", now=self.t1)

    def test_the_continuous_cycle_stops_at_the_ceiling(self):
        intent = propose_work_intent(self.db, origin_kind="IMPROVEMENT",
                                     work_class="GENERATE_CANDIDATE",
                                     triggering_evidence_refs=["WEAKNESS-1"],
                                     parent_mission_id=self.mission, now=self.t1)
        cycle = continuous_cycle(self.db, now=self.t1)
        self.assertEqual(cycle["ceiling"], PROMOTION_READY)
        self.assertFalse(cycle["may_promote"])
        self.assertFalse(cycle["may_deploy"])
        self.assertEqual(cycle["eligible"], [intent.intent_id])
        # The wake is eligible, and the cycle still cannot turn eligibility into a promotion.
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_ELIGIBLE)

    def test_an_open_session_does_not_become_a_promotion(self):
        propose_work_intent(self.db, origin_kind="IMPROVEMENT", work_class="META_DISCOVERY",
                            triggering_evidence_refs=["WEAKNESS-2"],
                            parent_mission_id=self.mission, now=self.t1)
        session = open_session(self.db, trigger_kind="IMPROVEMENT", trigger_ref="cycle-1",
                               mission_id=self.mission, now=self.t1)
        cycle = continuous_cycle(self.db, now=self.t1)
        self.assertFalse(cycle["may_promote"])
        self.assertEqual(session.status, "OPEN")
        notice = raise_promotion_ready(self.db, work_class="META_DISCOVERY", candidate_ref="CC-77",
                                       evidence_refs=["EVD-77"], now=self.t1)
        self.assertFalse(notice.as_dict()["may_deploy"])
        self.assertTrue(maintenance_digest(self.db))


if __name__ == "__main__":
    unittest.main()
