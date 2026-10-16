"""
4.6 Gate One - improvement hypotheses.

    opportunity != hypothesis != candidate

A hypothesis states an intervention, its measurable expectations, its regression risks and what would
falsify it. It cannot state its own outcome.
"""

import inspect
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import improvement_hypotheses as hypotheses_module
from ciph.kernel.crucible_metrics import (
    STATUS_DOMINATED,
    STATUS_DOMINATES,
    STATUS_INCOMPARABLE,
    STATUS_INSUFFICIENT,
)
from ciph.kernel.crucible_types import DIRECTION_HIGHER_BETTER, DIRECTION_LOWER_BETTER, CrucibleError
from ciph.kernel.improvement_hypotheses import (
    STATUS_PROPOSED,
    STATUS_REJECTED,
    STATUS_STALE,
    STATUS_SUPPORTED,
    STATUS_TESTED,
    ExpectedImprovement,
    get_hypothesis,
    hypothesis_history,
    hypothesis_status,
    propose_hypothesis,
    record_hypothesis_outcome,
)
from ciph.kernel.improvement_opportunities import adopt_gap

GAP = {'gap_id': 'GAP-1', 'category': 'MISSING_BEHAVIOR', 'target_capability': 'planner',
       'affected_revision': 'H1', 'failure_evidence_hashes': ['e1', 'e2'],
       'testable_improvement_criterion': 'results match oracle'}
EXPECTED = [ExpectedImprovement('task_success', DIRECTION_HIGHER_BETTER, 0.02),
            ExpectedImprovement('latency', DIRECTION_LOWER_BETTER, 10.0)]


class TestGate46Hypotheses(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-46-hypotheses-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.opportunity = adopt_gap(self.db, GAP, environment_identity='host:alpha', now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def propose(self, *, baseline='CC-B0', change='RESCHEDULE_WORKERS', expected=None, **kwargs):
        return propose_hypothesis(
            self.db, opportunity_id=self.opportunity.opportunity_id, target_component='planner',
            proposed_change_class=change,
            expected_improvements=EXPECTED if expected is None else expected,
            baseline_candidate_id=baseline, falsification_conditions=['latency regresses'], now=self.t1,
            **kwargs)

    # ------------------------------------------------------------------ founding
    def test_founding_a_hypothesis_pins_its_baseline_and_its_expectations(self):
        hypothesis = self.propose()
        self.assertTrue(hypothesis.hypothesis_id.startswith('IH-'))
        self.assertEqual(hypothesis.baseline_candidate_id, 'CC-B0')
        # The record preserves the caller's order; the IDENTITY basis is what sorts.
        self.assertEqual({item.metric_id for item in hypothesis.expected_improvements},
                         {'task_success', 'latency'})
        self.assertEqual({item.expected_direction for item in hypothesis.expected_improvements},
                         {'HIGHER_BETTER', 'LOWER_BETTER'})
        self.assertEqual(hypothesis.falsification_conditions, ('latency regresses',))
        self.assertEqual(hypothesis_status(self.db, hypothesis.hypothesis_id), STATUS_PROPOSED)
        # Same basis plus same intervention is the same hypothesis.
        self.assertEqual(self.propose().hypothesis_id, hypothesis.hypothesis_id)
        self.assertEqual(len(hypothesis_history(self.db)), 1)

    # ------------------------------------------------------------------ laws 4, 5, 8
    def test_law_4_and_5_expectations_must_be_measurable_and_a_proposal_must_be_epistemic(self):
        with self.assertRaises(CrucibleError) as no_expectation:
            self.propose(expected=[])
        self.assertEqual(no_expectation.exception.reason, 'HYPOTHESIS_REQUIRES_EXPECTED_IMPROVEMENT')
        with self.assertRaises(CrucibleError) as bad_direction:
            self.propose(expected=[ExpectedImprovement('latency', 'SIDEWAYS', 1.0)])
        self.assertEqual(bad_direction.exception.reason, 'INVALID_EXPECTED_DIRECTION')
        # Law 8: there is no confidence parameter to inflate.
        for forbidden in ('confidence', 'model_confidence', 'certainty', 'self_assessed_quality'):
            self.assertNotIn(forbidden, inspect.signature(propose_hypothesis).parameters)

    # ------------------------------------------------------------------ law 7
    def test_law_7_a_moved_baseline_stales_the_hypothesis(self):
        hypothesis = self.propose(baseline='CC-B0')
        self.assertEqual(hypothesis_status(self.db, hypothesis.hypothesis_id,
                                           current_baseline_candidate_id='CC-B0'), STATUS_PROPOSED)
        self.assertEqual(hypothesis_status(self.db, hypothesis.hypothesis_id,
                                           current_baseline_candidate_id='CC-B1'), STATUS_STALE)
        # It is not silently re-based: the record still names the baseline it was written against.
        self.assertEqual(get_hypothesis(self.db, hypothesis.hypothesis_id).baseline_candidate_id,
                         'CC-B0')
        self.assertEqual(self.propose(baseline='CC-B1').hypothesis_id != hypothesis.hypothesis_id,
                         True)

    # ------------------------------------------------------------------ laws 9, 10, 11
    def test_law_9_and_11_competing_hypotheses_coexist_with_distinct_identities(self):
        first = self.propose(change='RESCHEDULE_WORKERS')
        second = self.propose(change='CACHE_ORACLE_RESULTS')
        third = self.propose(change='RESCHEDULE_WORKERS', baseline='CC-OTHER')
        self.assertEqual(len({first.hypothesis_id, second.hypothesis_id, third.hypothesis_id}), 3)
        self.assertEqual(len(hypothesis_history(self.db)), 3)

    # ------------------------------------------------------------------ law 12
    def test_law_12_only_a_crucible_comparison_can_set_the_outcome(self):
        hypothesis = self.propose()
        with self.assertRaises(CrucibleError) as invented:
            record_hypothesis_outcome(self.db, hypothesis_id=hypothesis.hypothesis_id,
                                      protocol_id='CP-1', comparison_status='DEFINITELY_BETTER',
                                      now=self.t1)
        self.assertEqual(invented.exception.reason, 'INVALID_COMPARISON_STATUS')
        record_hypothesis_outcome(self.db, hypothesis_id=hypothesis.hypothesis_id, protocol_id='CP-1',
                                  comparison_status=STATUS_INCOMPARABLE, now=self.t1)
        self.assertEqual(hypothesis_status(self.db, hypothesis.hypothesis_id), STATUS_TESTED,
                         'a trade-off is a valid, honest outcome')
        record_hypothesis_outcome(self.db, hypothesis_id=hypothesis.hypothesis_id, protocol_id='CP-1',
                                  comparison_status=STATUS_DOMINATES, now=self.t1 + 1)
        self.assertEqual(hypothesis_status(self.db, hypothesis.hypothesis_id), STATUS_SUPPORTED)
        other = self.propose(change='CACHE_ORACLE_RESULTS')
        record_hypothesis_outcome(self.db, hypothesis_id=other.hypothesis_id, protocol_id='CP-1',
                                  comparison_status=STATUS_DOMINATED, now=self.t1)
        self.assertEqual(hypothesis_status(self.db, other.hypothesis_id), STATUS_REJECTED)
        self.assertEqual(hypotheses_module.STATUS_SUPPORTED, 'SUPPORTED')
        self.assertNotEqual(STATUS_INSUFFICIENT, STATUS_SUPPORTED)


if __name__ == '__main__':
    unittest.main()
