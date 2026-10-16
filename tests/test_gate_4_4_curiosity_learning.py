"""
4.4 Gate Four - curiosity learning.

    CuriosityOutcome is calculated from canonical before/after state. It is never writable.

The most important specimen is the anti-reward-hacking one: an investigation can produce a pile of
model-generated prose and still gain exactly nothing, because information gain is measured in
canonical 4.2/4.3 movement and model text moves none of it.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.curiosity_learning import (
    OPERATIONAL_COMPLETED,
    OPERATIONAL_FAILED,
    OPERATIONAL_NOT_ATTEMPTED,
    RESULT_INCONCLUSIVE,
    RESULT_RESOLVED,
    RESULT_UNCHANGED,
    RESULT_WORSENED,
    VALID_RESULTS,
    CuriosityLearningError,
    begin_investigation,
    close_investigation,
    curiosity_state_probe,
    get_outcome,
    information_gain,
    learning_digest,
    outcome_history,
    outcome_penalty,
)
from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs, record_model_output
from ciph.kernel.uncertainty_registry import (
    KIND_EPISTEMIC_UNRESOLVED,
    STATUS_SATISFIED,
    derive_uncertainties,
    record_uncertainty_snapshots,
    uncertainty_status,
)
from ciph.kernel.world_model import world_digest
from curiosity_test_support import contested, converge, unconverged


class TestGate44CuriosityLearning(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-44-learning-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.t2 = self.t1 + 100

    def tearDown(self):
        self.temp.cleanup()

    def open_uncertainty(self, subject='service.a'):
        """Seed the uncertainty AND let the registry record it, which is what makes closure visible."""
        prop = unconverged(self.db, subject, 'is_healthy', True, at=self.t1)
        record_uncertainty_snapshots(self.db, now=self.t2)
        return 'UNC-' + __import__('hashlib').sha256(
            f'EPISTEMIC_UNRESOLVED|{prop.proposition_id}'.encode()).hexdigest()[:12].upper()

    # ------------------------------------------------------------------ the anti-reward-hacking specimen
    def test_more_questions_is_not_information_gain(self):
        uncertainty_id = self.open_uncertainty()
        before_ledger = reconstruct_beliefs(self.db, now=self.t2).canonical_digest()
        before_world = world_digest(self.db, now=self.t2)
        outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)

        # "The investigation ran." Everything it "produced" is model prose.
        for index in range(10):
            record_model_output(self.db, model_ref='llm', output_text=f'new question {index}',
                                now=self.t2)
        for index in range(5):
            record_model_output(self.db, model_ref='llm', output_text=f'summary {index}', now=self.t2)
        for index in range(3):
            record_model_output(self.db, model_ref='llm', output_text=f'explanation {index}',
                                now=self.t2)
        for index in range(2):
            record_model_output(self.db, model_ref='llm', output_text=f'insight {index}',
                                now=self.t2)

        outcome = close_investigation(self.db, outcome_id, attempted=True,
                                      operational_status=OPERATIONAL_COMPLETED, now=self.t2)
        self.assertEqual(outcome.result, RESULT_UNCHANGED)
        self.assertEqual(outcome.information_gain, 0,
                         'twenty pieces of prose are not one piece of information')
        self.assertEqual(reconstruct_beliefs(self.db, now=self.t2).canonical_digest(), before_ledger)
        self.assertEqual(world_digest(self.db, now=self.t2), before_world)

    # ------------------------------------------------------------------ real resolution
    def test_real_canonical_movement_is_measured_as_resolution(self):
        uncertainty_id = self.open_uncertainty()
        outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        before = get_outcome(self.db, outcome_id)
        self.assertIsNone(before.result)
        self.assertTrue(before.before_state['present'])

        # The investigation obtains admissible evidence, and the proposition converges.
        converge(self.db, 'service.a', 'is_healthy', True, at=self.t1)

        outcome = close_investigation(self.db, outcome_id, attempted=True, now=self.t2)
        self.assertEqual(outcome.result, RESULT_RESOLVED)
        self.assertGreater(outcome.information_gain, 0)
        self.assertFalse(outcome.after_state['present'])
        self.assertEqual(uncertainty_status(self.db, uncertainty_id, now=self.t2), STATUS_SATISFIED)

    # ------------------------------------------------------------------ the subtle case
    def test_a_failed_operation_is_inconclusive_not_worse(self):
        uncertainty_id = self.open_uncertainty()
        outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        outcome = close_investigation(self.db, outcome_id, attempted=True,
                                      operational_status=OPERATIONAL_FAILED, now=self.t2)
        self.assertEqual(outcome.result, RESULT_INCONCLUSIVE,
                         'a tool returning an error is not a worse epistemic picture')
        self.assertNotEqual(outcome.result, RESULT_WORSENED)
        self.assertEqual(outcome.information_gain, 0)
        self.assertEqual(outcome.reason_code, 'OPERATION_FAILED')

    # ------------------------------------------------------------------ laws 1 and 4
    def test_model_commentary_cannot_mark_an_investigation_resolved(self):
        uncertainty_id = self.open_uncertainty()
        outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        record_model_output(self.db, model_ref='llm',
                            output_text='That investigation RESOLVED the question completely',
                            now=self.t2)
        outcome = close_investigation(self.db, outcome_id, attempted=True, now=self.t2)
        self.assertEqual(outcome.result, RESULT_UNCHANGED,
                         'the model does not get to award itself a result')

    def test_a_never_attempted_investigation_is_inconclusive(self):
        uncertainty_id = self.open_uncertainty()
        outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        outcome = close_investigation(self.db, outcome_id, attempted=False,
                                      operational_status=OPERATIONAL_NOT_ATTEMPTED, now=self.t2)
        self.assertEqual(outcome.result, RESULT_INCONCLUSIVE)

    # ------------------------------------------------------------------ laws 5 and 6
    def test_law_5_and_6_the_measurement_is_immutable(self):
        uncertainty_id = self.open_uncertainty()
        outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        snapshot = curiosity_state_probe(self.db, uncertainty_id, now=self.t2)
        self.assertEqual(get_outcome(self.db, outcome_id).before_state, snapshot)
        close_investigation(self.db, outcome_id, attempted=True, now=self.t2)
        closed = get_outcome(self.db, outcome_id)
        self.assertEqual(closed.before_state, snapshot, 'the before state is untouched')
        with self.assertRaises(CuriosityLearningError) as refused:
            close_investigation(self.db, outcome_id, attempted=True, now=self.t2)
        self.assertEqual(refused.exception.reason, 'OUTCOME_ALREADY_CLOSED')
        self.assertEqual(get_outcome(self.db, outcome_id).canonical_digest(), closed.canonical_digest())

    # ------------------------------------------------------------------ refusals
    def test_begin_refuses_unknown_and_double_open(self):
        with self.assertRaises(CuriosityLearningError) as unknown:
            begin_investigation(self.db, uncertainty_id='UNC-NOPE', now=self.t2)
        self.assertEqual(unknown.exception.reason, 'UNKNOWN_UNCERTAINTY')
        uncertainty_id = self.open_uncertainty()
        begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        with self.assertRaises(CuriosityLearningError) as twice:
            begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        self.assertEqual(twice.exception.reason, 'INVESTIGATION_ALREADY_OPEN')
        with self.assertRaises(CuriosityLearningError) as bad:
            close_investigation(self.db, 'CI-NOPE', now=self.t2)
        self.assertEqual(bad.exception.reason, 'UNKNOWN_OUTCOME')

    # ------------------------------------------------------------------ law 7
    def test_law_7_repeated_barren_work_accumulates_penalty(self):
        uncertainty_id = self.open_uncertainty()
        for _ in range(3):
            outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
            close_investigation(self.db, outcome_id, attempted=True, now=self.t2)
        closed = outcome_history(self.db, uncertainty_id)
        self.assertEqual(len(closed), 3, 'each investigation is its own historical record')
        self.assertTrue(all(o.result == RESULT_UNCHANGED for o in closed))
        self.assertEqual(outcome_penalty(self.db, uncertainty_id), 1.5)

    # ------------------------------------------------------------------ law 9
    def test_law_9_closing_one_uncertainty_exposes_another_independently(self):
        uncertainty_id = self.open_uncertainty()
        other = contested(self.db, 'service.b', 'is_healthy', True, at=self.t1)
        self.assertEqual(len(derive_uncertainties(self.db, now=self.t2)), 2)
        outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        converge(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        close_investigation(self.db, outcome_id, attempted=True, now=self.t2)

        remaining = derive_uncertainties(self.db, now=self.t2)
        self.assertEqual(len(remaining), 1, 'the resolved one closed; nothing was invented')
        self.assertEqual(remaining[0].source_ref, other.proposition_id,
                         'the surviving uncertainty is an ordinary registry entry')
        self.assertEqual(uncertainty_status(self.db, uncertainty_id, now=self.t2), STATUS_SATISFIED)

    # ------------------------------------------------------------------ law 10
    def test_law_10_learning_digest_is_deterministic_across_restart(self):
        uncertainty_id = self.open_uncertainty()
        outcome_id = begin_investigation(self.db, uncertainty_id=uncertainty_id, now=self.t2)
        close_investigation(self.db, outcome_id, attempted=True, now=self.t2)
        expected = learning_digest(self.db)
        self.assertEqual(learning_digest(self.db), expected)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.curiosity_learning import learning_digest;'
                'print(learning_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)
        self.assertIn(RESULT_UNCHANGED, VALID_RESULTS)
        self.assertEqual(information_gain(outcome_history(self.db)[0].before_state,
                                         outcome_history(self.db)[0].after_state), 0)


if __name__ == '__main__':
    unittest.main()
