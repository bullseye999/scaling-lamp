"""
4.6 Gate Five - improvement strategy learning.

    What is learned is the quality of the GENERATION STRATEGY, never a verdict about a candidate.

History stays multidimensional, and a production rollback is preserved beside the benchmark victory
that preceded it.
"""

import inspect
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import improvement_learning as learning_module
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.improvement_learning import (
    PRODUCTION_HEALTHY,
    PRODUCTION_REGRESSED,
    PRODUCTION_ROLLED_BACK,
    attempts,
    learning_digest,
    record_attempt,
    record_production_result,
    strategy_projection,
)


class TestGate46Learning(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-46-learning-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    def attempt(self, *, candidate='CC-1', status='DOMINATES', strategy='SMALL_SCHEDULING',
                hypothesis='IH-1', protocol='CP-1'):
        return record_attempt(self.db, opportunity_id='OPP-1', hypothesis_id=hypothesis,
                              candidate_id=candidate, generator_strategy_id=strategy,
                              protocol_id=protocol, comparison_status=status, now=self.t1)

    # ------------------------------------------------------------------ founding
    def test_founding_strategy_history_is_multidimensional(self):
        self.attempt(candidate='CC-1', status='DOMINATES')
        self.attempt(candidate='CC-2', status='INCOMPARABLE', hypothesis='IH-2')
        self.attempt(candidate='CC-3', status='DOMINATED', hypothesis='IH-3', strategy='FULL_REWRITE')
        projection = {entry['strategy_id']: entry for entry in strategy_projection(self.db)}
        self.assertEqual(projection['SMALL_SCHEDULING']['attempts'], 2)
        self.assertEqual(projection['SMALL_SCHEDULING']['dominates_count'], 1)
        self.assertEqual(projection['SMALL_SCHEDULING']['incomparable_count'], 1)
        self.assertEqual(projection['FULL_REWRITE']['dominated_count'], 1)
        for entry in projection.values():
            for forbidden in ('score', 'fitness', 'rank', 'grade'):
                self.assertNotIn(forbidden, entry)

    # ------------------------------------------------------------------ law 4
    def test_law_4_invalid_counts_against_the_strategy(self):
        self.attempt(candidate='CC-9', status='INVALID')
        entry = strategy_projection(self.db)[0]
        self.assertEqual(entry['invalid_count'], 1)
        self.assertEqual(entry['dominates_count'], 0)

    # ------------------------------------------------------------------ law 1
    def test_law_1_only_real_crucible_verdicts_can_be_recorded(self):
        with self.assertRaises(CrucibleError) as refused:
            self.attempt(status='I_THINK_IT_PASSED')
        self.assertEqual(refused.exception.reason, 'INVALID_COMPARISON_STATUS')
        with self.assertRaises(CrucibleError) as production:
            record_attempt(self.db, opportunity_id='OPP-1', hypothesis_id='IH-1',
                           candidate_id='CC-1', generator_strategy_id='S', protocol_id='CP-1',
                           comparison_status='DOMINATES', production_result='SEEMS_FINE',
                           now=self.t1)
        self.assertEqual(production.exception.reason, 'INVALID_PRODUCTION_RESULT')
        self.assertEqual(attempts(self.db), [])

    # ------------------------------------------------------------------ law 3
    def test_law_3_benchmark_victory_and_production_regression_both_survive(self):
        attempt = self.attempt()
        self.assertEqual(attempt.production_result, 'NOT_PROMOTED')
        again = record_attempt(self.db, opportunity_id='OPP-1', hypothesis_id='IH-1',
                               candidate_id='CC-1', generator_strategy_id='SMALL_SCHEDULING',
                               protocol_id='CP-1', comparison_status='DOMINATES', now=self.t1 + 5)
        self.assertEqual(again.attempt_id, attempt.attempt_id, 'a duplicate cannot inflate history')
        updated = record_production_result(self.db, attempt_id=attempt.attempt_id,
                                           production_result=PRODUCTION_REGRESSED, now=self.t1 + 10)
        self.assertEqual(updated.comparison_status, 'DOMINATES',
                         'production evidence does not rewrite the benchmark verdict')
        self.assertEqual(updated.production_result, PRODUCTION_REGRESSED)
        entry = strategy_projection(self.db)[0]
        self.assertEqual(entry['dominates_count'], 1)
        self.assertEqual(entry['production_regressed_count'], 1)
        self.assertEqual(entry['attempts'], 1)
        self.assertEqual(len(attempts(self.db)), 1)
        rolled = record_production_result(self.db, attempt_id=attempt.attempt_id,
                                          production_result=PRODUCTION_ROLLED_BACK, now=self.t1 + 20)
        self.assertEqual(rolled.production_result, PRODUCTION_ROLLED_BACK)
        self.assertEqual(rolled.comparison_status, 'DOMINATES')
        self.assertTrue(learning_digest(self.db))
        self.assertEqual(PRODUCTION_HEALTHY, 'HEALTHY')

    # ------------------------------------------------------------------ laws 8, 9
    def test_learning_grants_no_authority_and_no_scalar(self):
        self.attempt()
        public = [name for name, _ in inspect.getmembers(learning_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('promote', 'deploy', 'issue_permit', 'best_strategy', 'pick_winner'):
            self.assertNotIn(forbidden, public)
        self.assertTrue(strategy_projection(self.db))


if __name__ == '__main__':
    unittest.main()
