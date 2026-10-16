"""
4.5 Gate Three - metrics and Pareto comparison (D5).

    Was C1 actually better than B0?

Never a scalar. Every specimen is written so that one magical fitness number, or a weighting scheme,
would produce the wrong answer.
"""

import inspect
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import crucible_metrics as metrics_module
from ciph.kernel.crucible_metrics import (
    ComparisonResult,
    PerformanceVector,
    STATUS_DOMINATED,
    STATUS_DOMINATES,
    STATUS_EQUIVALENT,
    STATUS_INCOMPARABLE,
    STATUS_INSUFFICIENT,
    STATUS_INVALID,
    compare,
    summarise,
)
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_types import (
    CRUCIBLE_METRICS_V1,
    CRUCIBLE_PARETO_V1,
    CrucibleError,
    KIND_PLANNER_STRATEGY,
)


class TestGate45MetricsPareto(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-metrics-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_PLANNER_STRATEGY, development_cases=['d'],
            heldout_cases=['h'],
            metric_definitions=[
                MetricDefinition('task_success', 'v1', 'HIGHER_BETTER',
                                 minimum_meaningful_delta=0.02),
                MetricDefinition('prediction_brier', 'v1', 'LOWER_BETTER',
                                 minimum_meaningful_delta=0.02),
                MetricDefinition('latency', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=10.0),
                MetricDefinition('cost', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=0.02)],
            environment_identity='host:eval', repetition_count=3, minimum_evidence=3,
            hard_invariants=('NO_AUTHORITY_BYPASS', 'NO_FABRICATED_EVIDENCE',
                             'NO_HISTORY_MUTATION'))

    def tearDown(self):
        self.temp.cleanup()

    def vector(self, subject, *, violations=None, protocol_id=None, **metrics):
        return PerformanceVector(subject_id=subject,
                                 protocol_id=protocol_id or self.protocol.protocol_id,
                                 samples={key: tuple(value) if isinstance(value, (list, tuple))
                                          else (float(value),) * 3
                                          for key, value in metrics.items()},
                                 hard_violations=violations or {})

    def demo_pair(self):
        baseline = self.vector('B0', task_success=0.82, prediction_brier=0.19, latency=600,
                               cost=1.00)
        candidate = self.vector('C1', task_success=0.88, prediction_brier=0.16, latency=570,
                                cost=0.93)
        return baseline, candidate

    # ------------------------------------------------------------------ the founding comparison
    def test_founding_dominance_requires_better_everywhere_and_worse_nowhere(self):
        baseline, candidate = self.demo_pair()
        result = compare(baseline, candidate, self.protocol)
        self.assertEqual(result.status, STATUS_DOMINATES)
        self.assertEqual(set(result.better), {'task_success', 'prediction_brier', 'latency', 'cost'})
        self.assertEqual(result.worse, ())
        self.assertEqual(result.metric_version, CRUCIBLE_METRICS_V1)
        self.assertEqual(result.pareto_version, CRUCIBLE_PARETO_V1)

    # ------------------------------------------------------------------ one-dimensional win
    def test_a_one_dimensional_win_is_incomparable_not_victory(self):
        baseline, _ = self.demo_pair()
        lopsided = self.vector('C2', task_success=0.95, prediction_brier=0.16, latency=3000,
                               cost=10.00)
        result = compare(baseline, lopsided, self.protocol)
        self.assertEqual(result.status, STATUS_INCOMPARABLE)
        self.assertIn('task_success', result.better)
        self.assertIn('latency', result.worse)
        self.assertIn('cost', result.worse)

    # ------------------------------------------------------------------ noise
    def test_a_tiny_noisy_win_is_insufficient_evidence(self):
        noisy_base = self.vector('B0', task_success=[0.85, 0.95] * 5, prediction_brier=[0.18, 0.20] * 5,
                                 latency=[580, 620] * 5, cost=[0.99, 1.01] * 5)
        noisy_cand = self.vector('C1', task_success=[0.851, 0.951] * 5,
                                 prediction_brier=[0.181, 0.201] * 5,
                                 latency=[581, 621] * 5, cost=[0.991, 1.011] * 5)
        result = compare(noisy_base, noisy_cand, self.protocol)
        self.assertEqual(result.status, STATUS_INSUFFICIENT)
        self.assertNotEqual(result.status, STATUS_DOMINATES)
        self.assertTrue(any('IMPRECISE' in code for code in result.reason_codes))

    def test_a_precise_no_difference_is_equivalent(self):
        base = self.vector('B0', task_success=0.90, prediction_brier=0.20, latency=600, cost=1.00)
        same = self.vector('C1', task_success=0.90, prediction_brier=0.20, latency=600, cost=1.00)
        result = compare(base, same, self.protocol)
        self.assertEqual(result.status, STATUS_EQUIVALENT)

    # ------------------------------------------------------------------ hard invariants
    def test_a_constitutional_violation_cannot_be_bought_with_performance(self):
        baseline, _ = self.demo_pair()
        brilliant_but_broken = self.vector('C3', task_success=0.999, prediction_brier=0.01,
                                           latency=100, cost=0.10,
                                           violations={'NO_AUTHORITY_BYPASS': 1})
        result = compare(baseline, brilliant_but_broken, self.protocol)
        self.assertEqual(result.status, STATUS_INVALID)
        self.assertEqual(result.better, ())
        self.assertTrue(any('HARD_INVARIANT_VIOLATION' in code for code in result.reason_codes))

    # ------------------------------------------------------------------ the rest of the order
    def test_dominated_and_insufficient_samples(self):
        baseline, candidate = self.demo_pair()
        self.assertEqual(compare(baseline, candidate, self.protocol).status, STATUS_DOMINATES)
        reversed_result = compare(candidate, baseline, self.protocol)
        self.assertEqual(reversed_result.status, STATUS_DOMINATED)
        thin = PerformanceVector(subject_id='C4', protocol_id=self.protocol.protocol_id,
                                 samples={'task_success': (0.99,), 'prediction_brier': (0.01,),
                                          'latency': (100.0,), 'cost': (0.10,)})
        self.assertEqual(compare(baseline, thin, self.protocol).status, STATUS_INSUFFICIENT)

    def test_a_result_is_only_meaningful_under_its_own_frozen_protocol(self):
        baseline, candidate = self.demo_pair()
        other_protocol = freeze_protocol(
            self.db, candidate_kind=KIND_PLANNER_STRATEGY, development_cases=['d'],
            heldout_cases=['h'],
            metric_definitions=[MetricDefinition('task_success', 'v1', 'HIGHER_BETTER',
                                                 minimum_meaningful_delta=0.02)],
            environment_identity='host:other', minimum_evidence=3)
        stray = self.vector('C5', protocol_id=other_protocol.protocol_id, task_success=0.99)
        with self.assertRaises(CrucibleError) as refused:
            compare(baseline, stray, self.protocol)
        self.assertEqual(refused.exception.reason, 'CROSS_PROTOCOL_COMPARISON')

    # ------------------------------------------------------------------ no scalar
    def test_there_is_no_scalar_fitness_anywhere(self):
        fields = set(ComparisonResult.__dataclass_fields__)
        for forbidden in ('score', 'fitness', 'total', 'winner', 'rank'):
            self.assertNotIn(forbidden, fields)
        public = [name for name, _ in inspect.getmembers(metrics_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('fitness', 'total_score', 'rank_candidates', 'pick_winner'):
            self.assertNotIn(forbidden, public)
        summary = summarise(self.demo_pair()[0], self.protocol)
        self.assertEqual(set(summary), {'task_success', 'prediction_brier', 'latency', 'cost'})


if __name__ == '__main__':
    unittest.main()
