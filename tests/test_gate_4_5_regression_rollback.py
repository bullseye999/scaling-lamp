"""
4.5 Gates Five and Six - production regression, rollback, and the generation boundary.
"""

import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_candidates import register_candidate
from ciph.kernel.crucible_generation import (
    SOURCE_CIPH_PLANNER,
    SOURCE_OPERATOR,
    propose_candidate,
)
from ciph.kernel.crucible_metrics import PerformanceVector, STATUS_DOMINATES
from ciph.kernel.crucible_monitoring import (
    STATUS_DEGRADING,
    STATUS_HEALTHY,
    STATUS_INTEGRITY_BLOCKED,
    STATUS_REGRESSED,
    assess_post_promotion,
    assessment_history,
    eligibility_blocked,
    monitoring_digest,
)
from ciph.kernel.crucible_promotion import (
    active_candidate,
    promote,
    rollback,
    rollback_history,
)
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_types import CrucibleError, KIND_PLANNER_STRATEGY

ROLE = 'planner'


class TestGate45RegressionRollback(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-canary-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.baseline = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY,
                                           artifact_digest='H0', configuration_digest='C0')
        self.candidate = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY,
                                            artifact_digest='H1', configuration_digest='C1')
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_PLANNER_STRATEGY, development_cases=['d'],
            heldout_cases=['h'],
            metric_definitions=[
                MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02),
                MetricDefinition('prediction_brier', 'v1', 'LOWER_BETTER',
                                 minimum_meaningful_delta=0.02)],
            environment_identity='host:eval', minimum_evidence=3,
            hard_invariants=('NO_FABRICATED_EVIDENCE',), now=self.t1)
        self.promotion = promote(
            self.db, role=ROLE, candidate_id=self.candidate.candidate_id,
            protocol_id=self.protocol.protocol_id, comparison_status=STATUS_DOMINATES,
            evaluation_refs=('T1', 'T2', 'T3'), authorization_ref='operator:operator',
            replaced_candidate_id=self.baseline.candidate_id, now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def vector(self, success, brier=0.19, *, violations=None):
        if isinstance(success, (int, float)):
            success = [success] * 3
        if isinstance(brier, (int, float)):
            brier = [brier] * 3
        return PerformanceVector(subject_id='B0', protocol_id=self.protocol.protocol_id,
                                 samples={'task_success': tuple(success),
                                          'prediction_brier': tuple(brier)},
                                 hard_violations=violations or {})

    # ------------------------------------------------------------------ healthy canary
    def test_a_candidate_that_holds_up_in_production_is_healthy(self):
        assessment = assess_post_promotion(
            self.db, promotion_id=self.promotion.promotion_id,
            candidate_id=self.candidate.candidate_id, protocol_id=self.protocol.protocol_id,
            expected=self.vector(0.88), observed=self.vector(0.88), now=self.t1)
        self.assertEqual(assessment.status, STATUS_HEALTHY)
        self.assertFalse(eligibility_blocked(self.db, self.candidate.candidate_id))

    # ------------------------------------------------------------------ regression
    def test_production_regression_is_detected_and_can_roll_back(self):
        degraded = assess_post_promotion(
            self.db, promotion_id=self.promotion.promotion_id,
            candidate_id=self.candidate.candidate_id, protocol_id=self.protocol.protocol_id,
            expected=self.vector(0.88), observed=self.vector(0.70, 0.30), now=self.t1)
        self.assertEqual(degraded.status, STATUS_REGRESSED)
        self.assertIn('task_success', degraded.regression_dimensions)

        # Better on success, worse on Brier: neither dominates, so this is DEGRADING.
        mixed = assess_post_promotion(
            self.db, promotion_id=self.promotion.promotion_id,
            candidate_id=self.candidate.candidate_id, protocol_id=self.protocol.protocol_id,
            expected=self.vector(0.88, 0.19), observed=self.vector(0.95, 0.30), now=self.t1 + 1)
        self.assertEqual(mixed.status, STATUS_DEGRADING)

        record = rollback(self.db, role=ROLE, evidence_refs=[degraded.assessment_id],
                          reason_codes=['PRODUCTION_REGRESSION'], now=self.t1 + 2)
        self.assertEqual(record.restored_candidate_id, self.baseline.candidate_id)
        self.assertEqual(active_candidate(self.db, ROLE), self.baseline.candidate_id)

    # ------------------------------------------------------------------ hard block
    def test_a_constitutional_failure_blocks_eligibility_regardless_of_performance(self):
        blocked = assess_post_promotion(
            self.db, promotion_id=self.promotion.promotion_id,
            candidate_id=self.candidate.candidate_id, protocol_id=self.protocol.protocol_id,
            expected=self.vector(0.80),
            observed=self.vector(0.99, violations={'NO_FABRICATED_EVIDENCE': 1}), now=self.t1)
        self.assertEqual(blocked.status, STATUS_INTEGRITY_BLOCKED)
        self.assertTrue(eligibility_blocked(self.db, self.candidate.candidate_id))
        self.assertIn('NO_FABRICATED_EVIDENCE', blocked.constitutional_failures)

    # ------------------------------------------------------------------ laws 1-3
    def test_rollback_is_a_pointer_move_that_preserves_all_history(self):
        assessment = assess_post_promotion(
            self.db, promotion_id=self.promotion.promotion_id,
            candidate_id=self.candidate.candidate_id, protocol_id=self.protocol.protocol_id,
            expected=self.vector(0.88), observed=self.vector(0.60, 0.30), now=self.t1)
        rollback(self.db, role=ROLE, evidence_refs=[assessment.assessment_id],
                 reason_codes=['PRODUCTION_REGRESSION'], now=self.t1 + 1)
        # Nothing was rewritten: the candidate, the promotion, the assessment and the rollback all
        # remain, and the earlier benchmark victory is still TRUE as a historical statement.
        self.assertEqual(len(rollback_history(self.db)), 1)
        self.assertEqual(len(assessment_history(self.db)), 1)
        self.assertEqual(assessment_history(self.db)[0].status, STATUS_REGRESSED)
        from ciph.kernel.crucible_candidates import get_candidate
        self.assertEqual(get_candidate(self.db, self.candidate.candidate_id).artifact_digest, 'H1')
        self.assertTrue(monitoring_digest(self.db))

    def test_rollback_refuses_when_there_is_nothing_to_restore(self):
        rollback(self.db, role=ROLE, evidence_refs=['A'], reason_codes=['R'], now=self.t1 + 1)
        with self.assertRaises(CrucibleError) as refused:
            rollback(self.db, role=ROLE, evidence_refs=['A'], reason_codes=['R'], now=self.t1 + 2)
        self.assertEqual(refused.exception.reason, 'NO_PREVIOUS_CANDIDATE_TO_RESTORE')

    # ------------------------------------------------------------------ Gate Six
    def test_law_gate_six_a_generator_only_proposes(self):
        proposal = propose_candidate(kind=KIND_PLANNER_STRATEGY, artifact_digest='H2',
                                     configuration_digest='C2', source=SOURCE_CIPH_PLANNER,
                                     rationale='try a different scorer')
        self.assertTrue(proposal.proposal_id.startswith('CPP-'))
        # Proposing writes nothing: no candidate exists until the registry freezes one.
        from ciph.kernel.crucible_candidates import candidate_history
        self.assertEqual({c.candidate_id for c in candidate_history(self.db)},
                         {self.baseline.candidate_id, self.candidate.candidate_id})
        self.assertEqual(active_candidate(self.db, ROLE), self.candidate.candidate_id,
                         'a proposal cannot move the active pointer')
        operator = propose_candidate(kind=KIND_PLANNER_STRATEGY, artifact_digest='H2',
                                     configuration_digest='C2', source=SOURCE_OPERATOR)
        self.assertEqual(operator.artifact_digest, 'H2')
        with self.assertRaises(CrucibleError) as bad_source:
            propose_candidate(kind=KIND_PLANNER_STRATEGY, artifact_digest='H3',
                              configuration_digest='C3', source='THE_MODEL_ITSELF')
        self.assertEqual(bad_source.exception.reason, 'INVALID_CANDIDATE_SOURCE')


if __name__ == '__main__':
    unittest.main()
