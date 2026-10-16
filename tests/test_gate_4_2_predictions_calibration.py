
"""
4.2 Gate Three - predictions and calibration (V1: binary only).

    confidence finally becomes accountable.

The two structural anti-cheats are that a probability cannot be rewritten after the fact and that the
same forecast cannot be issued fifty times to inflate a score.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    canonical_proposition,
    record_evidence,
    record_model_output,
    record_observation,
)
from ciph.kernel.predictions import (
    OUTCOME_FALSE,
    OUTCOME_TRUE,
    OUTCOME_UNRESOLVED,
    PREDICTION_CALIBRATION_V1,
    STATUS_EXPIRED_UNRESOLVED,
    STATUS_INVALIDATED,
    STATUS_OPEN,
    STATUS_RESOLVED,
    PredictionError,
    calibrate,
    get_prediction,
    invalidate_prediction,
    issue_prediction,
    prediction_history,
    prediction_status,
    resolution_history,
    resolve_prediction,
)

RULE_SERVICE_HEALTH = "SERVICE_HEALTH_V1"


class TestGate42PredictionsAndCalibration(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-42-predictions-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.clock = 1_800_000_000.0
        self.tomorrow = self.clock + 86_400
        self.p = canonical_proposition('service.x', 'is_online', True,
                                       temporal_scope='AT:2026-10-10')

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def link(self, relation=RELATION_SUPPORTS, source='source', when=None):
        moment = when or self.clock
        observation = record_observation(self.db, source_ref=source, raw_text='report', now=moment)
        return record_evidence(self.db, self.p, relation=relation, source_ref=source,
                               observation_ref=observation['observation_id'], evidence_time=moment,
                               now=moment)

    def issue(self, probability=0.8, predictor='ciph', **kwargs):
        return issue_prediction(self.db, predictor_id=predictor, proposition=self.p,
                                probability=probability, resolution_deadline=self.tomorrow,
                                resolution_rule_id=RULE_SERVICE_HEALTH, now=self.clock, **kwargs)

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_probability_is_frozen_at_issuance(self):
        self.link(source='a')
        prediction = self.issue(0.8)
        self.assertTrue(prediction.created)
        issued_basis = prediction.epistemic_basis_digest

        # The world moves on: a contradiction arrives and the current belief is no longer 1.0.
        self.link(RELATION_CONTRADICTS, source='b', when=self.clock + 60)
        current = get_prediction(self.db, prediction.prediction_id, now=self.clock + 61)
        self.assertEqual(current.probability, 0.8, "no retroactive rewrite of the forecast")
        self.assertEqual(current.epistemic_basis_digest, issued_basis,
                         "the prediction still binds the state it was issued against")

        # Canonical evidence resolves it TRUE, and the score is computed from the ISSUED number.
        evidence = [e[0] for e in sqlite3.connect(self.db).execute(
            "SELECT evidence_id FROM ciph_evidence WHERE proposition_id = ? AND relation = 'SUPPORTS';",
            (self.p.proposition_id,))]
        resolution = resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_TRUE,
                                       evidence_refs=evidence, now=self.clock + 120)
        self.assertEqual(resolution.outcome, OUTCOME_TRUE)
        calibration = calibrate(self.db, now=self.clock + 121)
        self.assertEqual(calibration['metric_id'], PREDICTION_CALIBRATION_V1)
        self.assertEqual(calibration['resolved_count'], 1)
        self.assertAlmostEqual(calibration['brier_score'], 0.04, places=12)
        self.assertAlmostEqual(calibration['mean_probability'], 0.8, places=12)
        self.assertEqual(calibration['observed_frequency'], 1.0)

    # ------------------------------------------------------------------ the anti-cheat specimen
    def test_anti_cheat_duplicate_forecasts_are_one_prediction(self):
        self.link(source='a')
        issued = [self.issue(0.8) for _ in range(10)]
        self.assertEqual(len({p.prediction_id for p in issued}), 1,
                         "the same forecast on the same basis is ONE canonical prediction")
        self.assertEqual(sum(1 for p in issued if p.created), 1)
        self.assertEqual(len(prediction_history(self.db, self.p.proposition_id)), 1)

        # Even a later, luckier-sounding number is refused: the fingerprint has no probability in it.
        better = self.issue(0.95)
        self.assertEqual(better.prediction_id, issued[0].prediction_id)
        self.assertEqual(better.probability, 0.8, "the issued probability is the one that counts")

        evidence = [e[0] for e in sqlite3.connect(self.db).execute(
            "SELECT evidence_id FROM ciph_evidence WHERE relation = 'SUPPORTS';")]
        resolve_prediction(self.db, issued[0].prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=evidence, now=self.clock + 120)
        calibration = calibrate(self.db, now=self.clock + 121)
        self.assertEqual(calibration['resolved_count'], 1,
                         "ten issuances cannot become ten calibration data points")

    # ------------------------------------------------------------------ unresolved specimen
    def test_unresolved_is_not_false(self):
        self.link(source='a')
        prediction = self.issue(0.7)
        after_deadline = self.tomorrow + 60

        self.assertEqual(prediction_status(self.db, prediction.prediction_id, now=after_deadline),
                         STATUS_EXPIRED_UNRESOLVED)
        resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_UNRESOLVED,
                           now=after_deadline)
        calibration = calibrate(self.db, now=after_deadline + 1)
        self.assertEqual(calibration['resolved_count'], 0, "nothing was resolved, so nothing is scored")
        self.assertEqual(calibration['unresolved_count'], 1)
        self.assertIsNone(calibration['brier_score'])
        self.assertEqual(prediction_status(self.db, prediction.prediction_id, now=after_deadline),
                         STATUS_EXPIRED_UNRESOLVED)

    # ------------------------------------------------------------------ the hostile specimen
    def test_hostile_model_cannot_resolve_its_own_prediction(self):
        self.link(source='a')
        prediction = self.issue(0.9)
        output_id = record_model_output(self.db, model_ref='reasoner',
                                        output_text='My prediction was correct.',
                                        proposition=self.p, now=self.clock + 60)

        with self.assertRaises(PredictionError) as refused:
            resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_TRUE,
                               evidence_refs=[output_id], now=self.clock + 61)
        self.assertEqual(refused.exception.reason, 'RESOLUTION_EVIDENCE_NOT_CANONICAL')
        self.assertEqual(resolution_history(self.db, prediction.prediction_id), (),
                         "zero resolution effect")
        self.assertEqual(prediction_status(self.db, prediction.prediction_id, now=self.clock + 62),
                         STATUS_OPEN)

    def test_resolution_evidence_must_agree_with_the_outcome(self):
        contradiction = self.link(RELATION_CONTRADICTS, source='b')
        prediction = self.issue(0.3)
        with self.assertRaises(PredictionError) as refused:
            resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_TRUE,
                               evidence_refs=[contradiction], now=self.clock + 10)
        self.assertEqual(refused.exception.reason, 'RESOLUTION_EVIDENCE_MISMATCH')
        # The same evidence resolves FALSE, which is what it actually says.
        resolution = resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_FALSE,
                                        evidence_refs=[contradiction], now=self.clock + 11)
        self.assertEqual(resolution.outcome, OUTCOME_FALSE)
        self.assertAlmostEqual(calibrate(self.db, now=self.clock + 12)['brier_score'], 0.09, places=12)

    # ------------------------------------------------------------------ laws
    def test_law_8_predictions_cannot_be_backdated(self):
        with self.assertRaises(PredictionError) as refused:
            issue_prediction(self.db, predictor_id='ciph', proposition=self.p, probability=0.5,
                             resolution_deadline=self.clock - 1, resolution_rule_id=RULE_SERVICE_HEALTH,
                             now=self.clock)
        self.assertEqual(refused.exception.reason, 'RESOLUTION_DEADLINE_IN_THE_PAST')

        prediction = self.issue(0.5, resolution_not_before=self.clock + 600)
        with self.assertRaises(PredictionError) as early:
            resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_UNRESOLVED,
                               now=self.clock + 10)
        self.assertEqual(early.exception.reason, 'RESOLUTION_TOO_EARLY')

    def test_law_10_resolution_is_append_only(self):
        evidence = self.link(source='a')
        prediction = self.issue(0.6)
        first = resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_TRUE,
                                   evidence_refs=[evidence], now=self.clock + 10)
        again = resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_TRUE,
                                   evidence_refs=[evidence], now=self.clock + 11)
        self.assertEqual(again.resolution_id, first.resolution_id, "idempotent for the same outcome")
        with self.assertRaises(PredictionError) as refused:
            resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_FALSE,
                               now=self.clock + 12)
        self.assertEqual(refused.exception.reason, 'PREDICTION_ALREADY_RESOLVED')
        self.assertEqual(len(resolution_history(self.db, prediction.prediction_id)), 1,
                         "the first resolution is the record; nothing was overwritten")

    def test_law_11_calibration_uses_only_resolved_predictions(self):
        evidence = self.link(source='a')
        resolved = self.issue(0.9)
        second_proposition = canonical_proposition('service.y', 'is_online', True)
        unresolved = issue_prediction(self.db, predictor_id='ciph', proposition=second_proposition,
                                      probability=0.2, resolution_deadline=self.tomorrow,
                                      resolution_rule_id=RULE_SERVICE_HEALTH, now=self.clock)
        invalidated = self.issue(0.5, window_key='another-window')
        invalidate_prediction(self.db, invalidated.prediction_id, reason='superseded')
        third = canonical_proposition('service.z', 'is_online', True)
        issue_prediction(self.db, predictor_id='ciph', proposition=third, probability=0.4,
                         resolution_deadline=self.tomorrow,
                         resolution_rule_id=RULE_SERVICE_HEALTH, now=self.clock)

        resolve_prediction(self.db, resolved.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=[evidence], now=self.clock + 10)
        resolve_prediction(self.db, unresolved.prediction_id, outcome=OUTCOME_UNRESOLVED,
                           now=self.clock + 11)

        calibration = calibrate(self.db, now=self.clock + 12)
        self.assertEqual(calibration['resolved_count'], 1)
        self.assertEqual(calibration['unresolved_count'], 1)
        self.assertEqual(calibration['invalidated_count'], 1)
        self.assertEqual(calibration['open_count'], 1)
        self.assertAlmostEqual(calibration['brier_score'], 0.01, places=12,
                               msg="only the resolved prediction is scored, and from its own number")

    def test_reliability_bins_are_fixed_and_reported(self):
        evidence = self.link(source='a')
        counter = self.link(RELATION_CONTRADICTS, source='b')
        first = self.issue(0.15)
        second = self.issue(0.85, window_key='second-window')
        resolve_prediction(self.db, first.prediction_id, outcome=OUTCOME_FALSE,
                           evidence_refs=[counter], now=self.clock + 10)
        resolve_prediction(self.db, second.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=[evidence], now=self.clock + 11)
        calibration = calibrate(self.db, now=self.clock + 12)
        self.assertEqual([(b['low'], b['high']) for b in calibration['bins']], [(0.1, 0.2), (0.8, 0.9)])
        self.assertEqual(sum(b['count'] for b in calibration['bins']), calibration['resolved_count'])
        self.assertAlmostEqual(calibration['brier_score'],
                               ((0.15 - 0) ** 2 + (0.85 - 1) ** 2) / 2, places=12)

    def test_law_12_calibration_digest_is_stable_across_restart_and_process(self):
        evidence = self.link(source='a')
        counter = self.link(RELATION_CONTRADICTS, source='b')
        first = self.issue(0.8)
        second = self.issue(0.6, window_key='second-window')
        resolve_prediction(self.db, first.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=[evidence], now=self.clock + 10)
        resolve_prediction(self.db, second.prediction_id, outcome=OUTCOME_FALSE,
                           evidence_refs=[counter], now=self.clock + 11)
        expected = calibrate(self.db, now=self.clock + 12)
        self.assertEqual(calibrate(self.db, now=self.clock + 12)['calibration_digest'],
                         expected['calibration_digest'])

        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.predictions import calibrate;"
                "print(calibrate(%r, now=%r)['calibration_digest'])"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.clock + 12))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected['calibration_digest'])

    def test_probability_has_no_setter_anywhere(self):
        """Law 1 by construction: the module exposes no way to write a probability after issuance."""
        import inspect
        from ciph.kernel import predictions
        public = [name for name, _ in inspect.getmembers(predictions, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('set_probability', 'update_prediction', 'revise_prediction',
                          'reopen_prediction'):
            self.assertNotIn(forbidden, public)
        self.link(source='a')
        prediction = self.issue(0.42)
        with sqlite3.connect(self.db) as conn:
            stored = conn.execute("SELECT probability FROM ciph_predictions WHERE prediction_id = ?;",
                                  (prediction.prediction_id,)).fetchone()[0]
        self.assertEqual(stored, 0.42)

    def test_invalidation_is_possible_only_while_the_forecast_is_open(self):
        """Voiding an OPEN prediction removes it from calibration; voiding a RESOLVED one is refused."""
        evidence = self.link(source='a')
        open_prediction = self.issue(0.9, window_key='open-window')
        invalidate_prediction(self.db, open_prediction.prediction_id, reason='rule withdrawn')
        self.assertEqual(prediction_status(self.db, open_prediction.prediction_id, now=self.clock + 12),
                         STATUS_INVALIDATED)
        calibration = calibrate(self.db, now=self.clock + 12)
        self.assertEqual(calibration['invalidated_count'], 1)
        self.assertEqual(calibration['resolved_count'], 0)

        resolved = self.issue(0.6, window_key='resolved-window')
        resolve_prediction(self.db, resolved.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=[evidence], now=self.clock + 10)
        with self.assertRaises(PredictionError) as refused:
            invalidate_prediction(self.db, resolved.prediction_id, reason='hindsight rejected')
        self.assertEqual(refused.exception.reason, 'CANNOT_INVALIDATE_RESOLVED_PREDICTION')
        self.assertEqual(calibrate(self.db, now=self.clock + 13)['resolved_count'], 1,
                         "a known outcome cannot be voided after the fact")
        self.assertTrue(json.dumps(calibrate(self.db, now=self.clock + 13)))


if __name__ == '__main__':
    unittest.main()
