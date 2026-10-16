"""
4.3 Gate Two - causal hypotheses.

    Correlation / temporal order is NOT causation. A hypothesis is a candidate explanation, and it
    earns empirical credit ONLY through falsifiable predictions that canonical evidence resolved.

Every specimen is written so a causal model that let a plausible story, a model's confidence, or a
simple "A happened before B" become a supported cause would fail.
"""

import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.causal_model import (
    HYPOTHESIS_CONTESTED,
    HYPOTHESIS_PROPOSED,
    HYPOTHESIS_REFUTED,
    HYPOTHESIS_STALE,
    HYPOTHESIS_SUPPORTED,
    REASON_NO_FALSIFIABLE_PREDICTION,
    REASON_PREDICTIONS_CONFLICT,
    REASON_PREDICTIONS_PENDING,
    REASON_PREDICTIONS_REFUTE,
    REASON_PREDICTIONS_SUPPORT,
    VALID_HYPOTHESIS_STATUSES,
    CausalModelError,
    assert_empirically_supported,
    causal_digest,
    hypothesis,
    hypothesis_assessment,
    hypothesis_history,
    link_prediction,
    propose_hypothesis,
)
from ciph.kernel.belief_revision import record_inference
from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    canonical_proposition,
    reconstruct as reconstruct_beliefs,
    record_evidence,
    record_model_output,
    record_observation,
)
from ciph.kernel.predictions import (
    OUTCOME_FALSE,
    OUTCOME_TRUE,
    STATUS_OPEN,
    issue_prediction,
    resolve_prediction,
)
from ciph.kernel.source_dependence import RELATION_PRIMARY_OBSERVATION, record_provenance
from ciph.kernel.world_model import canonical_scope, entity_for, project_fact, world_digest


class TestGate43Causality(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-43-causal-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t0 = 1_800_000_000.0
        self.t1 = self.t0 + 100
        self.t2 = self.t0 + 200
        self.t3 = self.t0 + 300
        self.deadline = self.t0 + 10_000_000

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def add_evidence(self, proposition, *, relation=RELATION_SUPPORTS, source='s', at=None,
                     independent=True):
        at = self.t1 if at is None else at
        observation = record_observation(self.db, source_ref=source, raw_text='x', now=at)
        evidence = record_evidence(self.db, proposition, relation=relation, source_ref=source,
                                   observation_ref=observation['observation_id'], evidence_time=at,
                                   now=at)
        if independent:
            record_provenance(self.db, from_evidence=evidence, relation=RELATION_PRIMARY_OBSERVATION,
                              now=at)
        return evidence

    def converge(self, proposition, *, relation=RELATION_SUPPORTS, sources=2, at=None):
        return tuple(self.add_evidence(proposition, relation=relation, source=f'src-{index}',
                                       at=(self.t1 if at is None else at))
                     for index in range(sources))

    def make_prediction(self, proposition, *, probability=0.8, rule='RULE', now=None):
        return issue_prediction(self.db, predictor_id='ciph', proposition=proposition,
                                probability=probability, resolution_deadline=self.deadline,
                                resolution_rule_id=rule, now=(self.t1 if now is None else now))

    # ------------------------------------------------------------------ founding specimen
    def test_founding_competing_hypotheses_coexist_as_proposals(self):
        h1 = propose_hypothesis(self.db, cause='deployment D', effect='api latency rise', now=self.t1)
        h2 = propose_hypothesis(self.db, cause='upstream provider degradation',
                                effect='api latency rise', now=self.t1)
        self.assertNotEqual(h1.hypothesis_id, h2.hypothesis_id, "two explanations, two identities")
        self.assertEqual(len(hypothesis_history(self.db)), 2)

        first = hypothesis_assessment(self.db, h1.hypothesis_id, now=self.t1)
        second = hypothesis_assessment(self.db, h2.hypothesis_id, now=self.t1)
        for assessment in (first, second):
            self.assertEqual(assessment.status, HYPOTHESIS_PROPOSED)
            self.assertIn(REASON_NO_FALSIFIABLE_PREDICTION, assessment.reason_codes)
        # Re-proposing the same story is the same hypothesis, not a second one.
        self.assertEqual(propose_hypothesis(self.db, cause='deployment D',
                                            effect='api latency rise', now=self.t2).hypothesis_id,
                         h1.hypothesis_id)

    # ------------------------------------------------------------------ law 1
    def test_law_1_temporal_order_alone_is_not_causation(self):
        service = entity_for('service.x', kind='service')
        before = canonical_proposition('service.x', 'is_healthy', True,
                                       temporal_scope=canonical_scope(self.t1))
        after = canonical_proposition('service.x', 'is_healthy', False,
                                      temporal_scope=canonical_scope(self.t2))
        self.converge(before, at=self.t1)
        self.converge(after, at=self.t2)
        self.assertEqual(project_fact(self.db, entity=service, relation='is_healthy', value=False,
                                      scope=self.t2, now=self.t2).world_status, 'PRESENT')

        from ciph.kernel.world_dynamics import derive_transitions
        transitions = derive_transitions(self.db, now=self.t2)
        self.assertEqual(len(transitions), 1)
        hypothesis_row = propose_hypothesis(self.db, cause='event A',
                                            effect='the transition', now=self.t2,
                                            transition_refs=[transitions[0].transition_id])
        self.assertEqual(hypothesis_assessment(self.db, hypothesis_row.hypothesis_id,
                                               now=self.t2).status, HYPOTHESIS_PROPOSED,
                         "A preceding B is not a cause, however clean the sequence looks")

    # ------------------------------------------------------------------ laws 2 and 3
    def test_law_2_and_3_a_model_story_adds_zero_support_and_writes_no_evidence(self):
        before = reconstruct_beliefs(self.db, now=self.t1).canonical_digest()
        record_model_output(self.db, model_ref='llm', output_text='the deployment caused the latency',
                            now=self.t1)
        story = propose_hypothesis(self.db, cause='deployment D', effect='latency rise', now=self.t1)
        self.assertEqual(hypothesis_assessment(self.db, story.hypothesis_id, now=self.t1).status,
                         HYPOTHESIS_PROPOSED)
        self.assertEqual(reconstruct_beliefs(self.db, now=self.t1).canonical_digest(), before)

        # No writable verdict exists anywhere in the module.
        public = [name for name, _ in inspect.getmembers(__import__(
            'ciph.kernel.causal_model', fromlist=['x']), inspect.isfunction)
            if not name.startswith('_')]
        for forbidden in ('set_status', 'mark_supported', 'prove_hypothesis', 'assert_cause',
                          'record_cause'):
            self.assertNotIn(forbidden, public)
        self.assertNotIn('PROVEN', VALID_HYPOTHESIS_STATUSES)
        self.assertNotIn('FACT', VALID_HYPOTHESIS_STATUSES)

    # ------------------------------------------------------------------ laws 5 and 8
    def test_law_5_and_8_a_prediction_supports_but_never_proves_causality(self):
        hypothesis_row = propose_hypothesis(self.db, cause='deployment D', effect='latency rise',
                                            now=self.t1)
        target = canonical_proposition('service.x', 'is_healthy', True,
                                       temporal_scope=canonical_scope(self.t3))
        prediction = self.make_prediction(target, probability=0.8)
        link_prediction(self.db, hypothesis_id=hypothesis_row.hypothesis_id,
                        prediction_id=prediction.prediction_id, expect='rollback restores health',
                        now=self.t1)
        self.assertEqual(hypothesis_assessment(self.db, hypothesis_row.hypothesis_id,
                                               now=self.t1).status, HYPOTHESIS_PROPOSED)
        self.assertIn(REASON_PREDICTIONS_PENDING,
                      hypothesis_assessment(self.db, hypothesis_row.hypothesis_id,
                                            now=self.t1).reason_codes)

        refs = self.converge(target, at=self.t3)
        resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=list(refs), now=self.t3)
        assessment = hypothesis_assessment(self.db, hypothesis_row.hypothesis_id, now=self.t3)
        self.assertEqual(assessment.status, HYPOTHESIS_SUPPORTED)
        self.assertIn(REASON_PREDICTIONS_SUPPORT, assessment.reason_codes)
        # Supported is still not proven: the guard hands back SUPPORTED, never a cause.
        self.assertEqual(assert_empirically_supported(self.db, hypothesis_row.hypothesis_id,
                                                      now=self.t3), HYPOTHESIS_SUPPORTED)
        self.assertNotIn('PROVEN', assessment.status)

    # ------------------------------------------------------------------ law 7 (refute)
    def test_law_7_a_failed_prediction_refutes_the_hypothesis(self):
        hypothesis_row = propose_hypothesis(self.db, cause='upstream degradation',
                                            effect='latency rise', now=self.t1)
        target = canonical_proposition('service.x', 'is_degraded', True,
                                       temporal_scope=canonical_scope(self.t3))
        prediction = self.make_prediction(target, probability=0.7)
        link_prediction(self.db, hypothesis_id=hypothesis_row.hypothesis_id,
                        prediction_id=prediction.prediction_id, now=self.t1)
        refs = self.converge(target, relation=RELATION_CONTRADICTS, at=self.t3)
        resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_FALSE,
                           evidence_refs=list(refs), now=self.t3)
        assessment = hypothesis_assessment(self.db, hypothesis_row.hypothesis_id, now=self.t3)
        self.assertEqual(assessment.status, HYPOTHESIS_REFUTED)
        self.assertIn(REASON_PREDICTIONS_REFUTE, assessment.reason_codes)
        with self.assertRaises(CausalModelError):
            assert_empirically_supported(self.db, hypothesis_row.hypothesis_id, now=self.t3)

    # ------------------------------------------------------------------ laws 4 and 7
    def test_law_4_and_7_one_success_and_one_failure_contest_but_do_not_delete(self):
        hypothesis_row = propose_hypothesis(self.db, cause='mixed cause', effect='latency rise',
                                            now=self.t1)
        win = canonical_proposition('service.x', 'is_healthy', True,
                                    temporal_scope=canonical_scope(self.t3))
        lose = canonical_proposition('service.x', 'is_degraded', True,
                                     temporal_scope=canonical_scope(self.t3))
        p_win = self.make_prediction(win, probability=0.6, rule='WIN')
        p_lose = self.make_prediction(lose, probability=0.6, rule='LOSE')
        link_prediction(self.db, hypothesis_id=hypothesis_row.hypothesis_id,
                        prediction_id=p_win.prediction_id, now=self.t1)
        link_prediction(self.db, hypothesis_id=hypothesis_row.hypothesis_id,
                        prediction_id=p_lose.prediction_id, now=self.t1)
        resolve_prediction(self.db, p_win.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=list(self.converge(win, at=self.t3)), now=self.t3)
        resolve_prediction(self.db, p_lose.prediction_id, outcome=OUTCOME_FALSE,
                           evidence_refs=list(self.converge(lose, relation=RELATION_CONTRADICTS,
                                                            at=self.t3)), now=self.t3)
        assessment = hypothesis_assessment(self.db, hypothesis_row.hypothesis_id, now=self.t3)
        self.assertEqual(assessment.status, HYPOTHESIS_CONTESTED)
        self.assertIn(REASON_PREDICTIONS_CONFLICT, assessment.reason_codes)
        self.assertEqual(len(assessment.resolved_true), 1)
        self.assertEqual(len(assessment.resolved_false), 1)

    # ------------------------------------------------------------------ law 6
    def test_law_6_a_model_saying_it_was_right_resolves_nothing(self):
        hypothesis_row = propose_hypothesis(self.db, cause='deployment D', effect='latency rise',
                                            now=self.t1)
        target = canonical_proposition('service.x', 'is_healthy', True,
                                       temporal_scope=canonical_scope(self.t3))
        # The model asserts its own future success. That registers a proposition and no evidence.
        record_model_output(self.db, model_ref='llm', output_text='my prediction will be correct',
                            proposition=target, now=self.t1)
        prediction = issue_prediction(self.db, predictor_id='ciph', proposition=target,
                                      probability=0.9, resolution_deadline=self.deadline,
                                      resolution_rule_id='RULE', window_key='W6', now=self.t2)
        link_prediction(self.db, hypothesis_id=hypothesis_row.hypothesis_id,
                        prediction_id=prediction.prediction_id, now=self.t2)
        # The same forecast, re-issued, is ONE prediction rather than a fresh scoring chance.
        again = issue_prediction(self.db, predictor_id='ciph', proposition=target, probability=0.9,
                                 resolution_deadline=self.deadline, resolution_rule_id='RULE',
                                 window_key='W6', now=self.t3)
        self.assertEqual(again.prediction_id, prediction.prediction_id)

        from ciph.kernel.predictions import get_prediction
        self.assertEqual(get_prediction(self.db, prediction.prediction_id, now=self.t3).status,
                         STATUS_OPEN, "with no canonical evidence the prediction is still open")
        assessment = hypothesis_assessment(self.db, hypothesis_row.hypothesis_id, now=self.t3)
        self.assertEqual(assessment.status, HYPOTHESIS_PROPOSED)
        self.assertIn(REASON_PREDICTIONS_PENDING, assessment.reason_codes)

    # ------------------------------------------------------------------ law 9
    def test_law_9_status_is_derived_so_the_hypothesis_record_never_changes(self):
        hypothesis_row = propose_hypothesis(self.db, cause='deployment D', effect='latency rise',
                                            now=self.t1)
        snapshot = json.dumps(hypothesis_history(self.db), sort_keys=True)
        target = canonical_proposition('service.x', 'is_healthy', True,
                                       temporal_scope=canonical_scope(self.t3))
        prediction = self.make_prediction(target, probability=0.5)
        link_prediction(self.db, hypothesis_id=hypothesis_row.hypothesis_id,
                        prediction_id=prediction.prediction_id, now=self.t1)
        resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=list(self.converge(target, at=self.t3)), now=self.t3)
        self.assertEqual(hypothesis_assessment(self.db, hypothesis_row.hypothesis_id,
                                               now=self.t3).status, HYPOTHESIS_SUPPORTED)
        self.assertEqual(json.dumps(hypothesis_history(self.db), sort_keys=True), snapshot,
                         "gaining support must not rewrite the hypothesis row")
        self.assertEqual(hypothesis(self.db, hypothesis_row.hypothesis_id).cause, 'deployment D')

    # ------------------------------------------------------------------ stale inference
    def test_a_stale_inference_basis_stales_the_hypothesis(self):
        premise = canonical_proposition('service.x', 'is_healthy', True,
                                        temporal_scope=canonical_scope(self.t1))
        self.converge(premise, at=self.t1)
        conclusion = canonical_proposition('service.x', 'will_recover', True,
                                          temporal_scope=canonical_scope(self.t3))
        inference = record_inference(self.db, premise_proposition_ids=[premise.proposition_id],
                                     conclusion=conclusion, inference_rule_id='heuristic',
                                     model_id='llm', now=self.t1)
        hypothesis_row = propose_hypothesis(self.db, cause='deployment D', effect='latency rise',
                                            now=self.t1, inference_refs=[inference.inference_id])
        self.assertEqual(hypothesis_assessment(self.db, hypothesis_row.hypothesis_id,
                                               now=self.t1).status, HYPOTHESIS_PROPOSED)
        # New evidence moves the premise's belief digest, so the pinned inference is now unusable.
        self.add_evidence(premise, source='late', at=self.t2)
        assessment = hypothesis_assessment(self.db, hypothesis_row.hypothesis_id, now=self.t2)
        self.assertEqual(assessment.status, HYPOTHESIS_STALE)
        self.assertEqual(assessment.stale_inferences, (inference.inference_id,))

    # ------------------------------------------------------------------ law 10
    def test_law_10_causal_digest_is_deterministic_across_restart_and_process(self):
        hypothesis_row = propose_hypothesis(self.db, cause='deployment D', effect='latency rise',
                                            now=self.t1)
        target = canonical_proposition('service.x', 'is_healthy', True,
                                       temporal_scope=canonical_scope(self.t3))
        prediction = self.make_prediction(target, probability=0.8)
        link_prediction(self.db, hypothesis_id=hypothesis_row.hypothesis_id,
                        prediction_id=prediction.prediction_id, now=self.t1)
        resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=list(self.converge(target, at=self.t3)), now=self.t3)

        expected = causal_digest(self.db, now=self.t3)
        self.assertEqual(causal_digest(self.db, now=self.t3), expected)
        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.causal_model import causal_digest;"
                "print(causal_digest(%r, now=%r))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.t3))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)

    # ------------------------------------------------------------------ law 2 (no writes)
    def test_law_2_causal_work_never_touches_the_ledger_or_the_world_model(self):
        target = canonical_proposition('service.x', 'is_healthy', True,
                                       temporal_scope=canonical_scope(self.t3))
        self.converge(target, at=self.t3)
        ledger_before = reconstruct_beliefs(self.db, now=self.t3).canonical_digest()
        world_before = world_digest(self.db, now=self.t3)

        hypothesis_row = propose_hypothesis(self.db, cause='deployment D', effect='latency rise',
                                            now=self.t3)
        prediction = self.make_prediction(target, probability=0.8, now=self.t3)
        link_prediction(self.db, hypothesis_id=hypothesis_row.hypothesis_id,
                        prediction_id=prediction.prediction_id, now=self.t3)
        hypothesis_assessment(self.db, hypothesis_row.hypothesis_id, now=self.t3)
        causal_digest(self.db, now=self.t3)

        self.assertEqual(reconstruct_beliefs(self.db, now=self.t3).canonical_digest(), ledger_before,
                         "proposing, linking and assessing write no evidence")
        self.assertEqual(world_digest(self.db, now=self.t3), world_before,
                         "the causal layer casts no shadow on the world model")


if __name__ == '__main__':
    unittest.main()
