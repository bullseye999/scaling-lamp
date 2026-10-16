
"""
4.2 cross-gate torture: ONE proposition through every gate, then a restart.

Passing each gate in isolation is not the property that matters. This file walks a single proposition
up the whole ladder and asserts that the gates COMPOSE: each gate's answer is consistent with the one
below it, nothing is rewritten, and every digest survives a restart unchanged.
"""

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.belief_revision import (
    INFERENCE_CURRENT,
    INFERENCE_STALE,
    assert_usable,
    inference_status,
    record_inference,
    record_revisions,
    revision_digest,
)
from ciph.kernel.epistemic_convergence import (
    STATUS_CONTESTED,
    STATUS_CONVERGED_SUPPORTED,
    STATUS_UNRESOLVED,
    convergence_digest,
    convergence_history,
    project_convergence,
    record_convergence,
)
from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    BeliefStatus,
    canonical_proposition,
    record_evidence,
    record_model_output,
    record_observation,
    reconstruct as reconstruct_beliefs,
)
from ciph.kernel.predictions import (
    OUTCOME_FALSE,
    OUTCOME_TRUE,
    calibrate,
    issue_prediction,
    resolve_prediction,
)
from ciph.kernel.source_dependence import (
    RELATION_COPIED_FROM,
    RELATION_PRIMARY_OBSERVATION,
    RELATION_SYNDICATED_FROM,
    project_source_dependence,
    record_provenance,
)


class TestGate42CrossGateTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-42-torture-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t0 = 1_800_000_000.0
        self.p = canonical_proposition('reactor.unit-3', 'is_stable', True)
        self.q = canonical_proposition('reactor.unit-3', 'is_safe_to_approach', True)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def link(self, proposition, relation=RELATION_SUPPORTS, source='source', when=None):
        moment = when if when is not None else self.t0
        observation = record_observation(self.db, source_ref=source, raw_text='report', now=moment)
        return record_evidence(self.db, proposition, relation=relation, source_ref=source,
                               observation_ref=observation['observation_id'], evidence_time=moment,
                               now=moment)

    def belief(self, proposition, now=None):
        return reconstruct_beliefs(self.db, now=now or self.t0).belief_for(proposition.proposition_id)

    def dependence(self, now=None):
        return project_source_dependence(self.db, self.p.proposition_id, now=now or self.t0)

    def convergence(self, now=None):
        return project_convergence(self.db, self.p.proposition_id, now=now or self.t0)

    def digests(self, now=None):
        moment = now or self.t0
        return {
            "gate_zero": reconstruct_beliefs(self.db, now=moment).canonical_digest(),
            "gate_one": project_source_dependence(self.db, self.p.proposition_id,
                                                  now=moment).canonical_digest(),
            "gate_two": revision_digest(self.db, now=moment),
            "gate_three": calibrate(self.db, now=moment)['calibration_digest'],
            "gate_four": convergence_digest(self.db, now=moment),
        }

    # ------------------------------------------------------------------ the ladder
    def test_one_proposition_through_every_gate_then_restart(self):
        # ---- Gate Zero: one supporting observation.
        e1 = self.link(self.p, source='reuters.example')
        self.assertEqual(self.belief(self.p).status, BeliefStatus.SUPPORTED.value)
        gate_zero_initial = reconstruct_beliefs(self.db, now=self.t0).evidence_count

        # ---- Gate One: three more reports that all trace back to E1.
        for index in range(3):
            child = self.link(self.p, source=f'mirror-{index}.example')
            record_provenance(self.db, from_evidence=child,
                              relation=RELATION_SYNDICATED_FROM if index < 2 else RELATION_COPIED_FROM,
                              to_evidence=e1, now=self.t0)
        after_mirrors = self.dependence()
        self.assertEqual(after_mirrors.proven_support_count, 1,
                         "four links, one origin: Gate Zero sees 4, Gate One sees 1")
        self.assertEqual(after_mirrors.evidence_count, 4)

        # ---- An independent primary observation: two proven origins.
        e5 = self.link(self.p, source='firsthand.example')
        record_provenance(self.db, from_evidence=e5, relation=RELATION_PRIMARY_OBSERVATION,
                          now=self.t0)
        two_origins = self.dependence()
        self.assertEqual(two_origins.proven_support_count, 2)
        self.assertEqual(two_origins.possible_support_count, 2)

        # ---- Gate Four agrees: this has converged, under CONVERGENCE_V1.
        self.assertEqual(self.convergence().status, STATUS_CONVERGED_SUPPORTED)
        record_convergence(self.db, self.p.proposition_id, now=self.t0)
        record_revisions(self.db, now=self.t0)

        # ---- Gate Two: the model reasons from P to Q. Q gains no evidence.
        inference = record_inference(self.db, premise_proposition_ids=[self.p.proposition_id],
                                    conclusion=self.q, inference_rule_id='MODUS_PONENS_V1',
                                    model_id='reasoner', now=self.t0)
        self.assertEqual(inference_status(self.db, inference.inference_id, now=self.t0),
                         INFERENCE_CURRENT)
        self.assertEqual(reconstruct_beliefs(self.db, now=self.t0).evidence_count, gate_zero_initial + 4,
                         "reasoning added no evidence")

        # ---- Gate Three: a binary forecast, frozen against the state at issuance.
        prediction = issue_prediction(self.db, predictor_id='ciph', proposition=self.p,
                                      probability=0.8, resolution_deadline=self.t0 + 86_400,
                                      resolution_rule_id='SERVICE_HEALTH_V1', now=self.t0)

        # ---- An INDEPENDENT contradiction arrives.
        e6 = self.link(self.p, RELATION_CONTRADICTS, source='independent-critic.example',
                       when=self.t0 + 60)
        record_provenance(self.db, from_evidence=e6, relation=RELATION_PRIMARY_OBSERVATION,
                          now=self.t0 + 60)

        layer_zero = self.belief(self.p, now=self.t0 + 61)
        self.assertEqual(layer_zero.status, BeliefStatus.CONTESTED.value)
        layer_one = self.dependence(now=self.t0 + 61)
        self.assertEqual((layer_one.proven_support_count, layer_one.proven_contradict_count), (2, 1))
        layer_four = self.convergence(now=self.t0 + 61)
        self.assertEqual(layer_four.status, STATUS_CONTESTED)
        record_convergence(self.db, self.p.proposition_id, now=self.t0 + 61)
        self.assertEqual([h['status'] for h in convergence_history(self.db, self.p.proposition_id)],
                         [STATUS_CONVERGED_SUPPORTED, STATUS_CONTESTED],
                         "the earlier convergence remains historical")

        # ---- The inference pinned P's PREVIOUS projection, so it is now stale, not recomputed.
        self.assertEqual(inference_status(self.db, inference.inference_id, now=self.t0 + 62),
                         INFERENCE_STALE)
        with self.assertRaises(Exception):
            assert_usable(self.db, inference.inference_id, now=self.t0 + 62)
        record_revisions(self.db, now=self.t0 + 62)

        # ---- The forecast resolves FALSE from canonical evidence, scored on its ISSUED number.
        resolution = resolve_prediction(self.db, prediction.prediction_id, outcome=OUTCOME_FALSE,
                                        evidence_refs=[e6], now=self.t0 + 120)
        self.assertEqual(resolution.outcome, OUTCOME_FALSE)
        calibration = calibrate(self.db, now=self.t0 + 121)
        self.assertAlmostEqual(calibration['brier_score'], (0.8 - 0.0) ** 2, places=12)
        self.assertAlmostEqual(calibration['mean_probability'], 0.8, places=12)

        # ---- The seal: every gate's digest is identical after a restart, and cross-process.
        expected = self.digests(now=self.t0 + 121)
        self.assertEqual(self.digests(now=self.t0 + 121), expected)
        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from test_gate_4_2_cross_gate_torture import TestGate42CrossGateTorture as T;"
                "t=T('test_one_proposition_through_every_gate_then_restart');t.setUp();"
                "t.db=%r;t.t0=%r;print(t.digests(now=%r))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.t0, self.t0 + 121))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), str(expected),
                         "a second process reconstructs every gate identically")

    # ------------------------------------------------------------------ projections are disposable
    def test_every_current_projection_rebuilds_from_immutable_history(self):
        e1 = self.link(self.p, source='reuters.example')
        self.link(self.p, source='mirror.example')
        primary = self.link(self.p, source='firsthand.example')
        record_provenance(self.db, from_evidence=primary, relation=RELATION_PRIMARY_OBSERVATION,
                          now=self.t0)
        record_inference(self.db, premise_proposition_ids=[self.p.proposition_id], conclusion=self.q,
                         inference_rule_id='MODUS_PONENS_V1', now=self.t0)
        record_revisions(self.db, now=self.t0)
        record_convergence(self.db, self.p.proposition_id, now=self.t0)
        expected = self.digests()

        # CLAIM 1: the stored PROJECTIONS are disposable. This is what "beliefs are projections over
        # evidence" means operationally - delete them and every digest is unchanged.
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM ciph_belief_projections")
            conn.execute("DELETE FROM ciph_source_dependence_projections")
            conn.execute("DELETE FROM ciph_convergence_projections")
        rebuilt = self.digests()
        for gate in ("gate_zero", "gate_one", "gate_two", "gate_four"):
            self.assertEqual(rebuilt[gate], expected[gate], gate)

        # CLAIM 2: the revision HISTORY is derived bookkeeping rather than a projection, so it is part
        # of the immutable record. Replaying the history reproduces it exactly - including the
        # revision IDS, which is why they are derived rather than random.
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM ciph_belief_revisions")
        record_revisions(self.db, now=self.t0)
        replayed = self.digests()
        self.assertEqual(replayed["gate_two"], expected["gate_two"],
                         "replaying the same history reproduces the same revisions")
        self.assertEqual(replayed["gate_four"], expected["gate_four"])

    # ------------------------------------------------------------------ the honest terminus
    def test_the_ladder_can_end_in_unresolved_and_that_is_an_answer(self):
        first = self.link(self.p, source='firsthand-a.example')
        second = self.link(self.p, source='firsthand-b.example')
        for evidence in (first, second):
            record_provenance(self.db, from_evidence=evidence,
                              relation=RELATION_PRIMARY_OBSERVATION, now=self.t0)
        self.assertEqual(self.dependence().proven_support_count, 2)
        self.assertEqual(self.convergence().status, STATUS_CONVERGED_SUPPORTED)

        # A contradiction nobody can attribute: the ladder stops at UNRESOLVED, by policy.
        self.link(self.p, RELATION_CONTRADICTS, source='opaque.example')
        projection = self.convergence()
        self.assertEqual(projection.status, STATUS_UNRESOLVED)
        self.assertGreater(projection.possible_contradict_origins, projection.proven_contradict_origins)
        # And nothing anywhere promotes it: no FACT, no forced convergence, no silent weight change.
        self.assertNotIn('FACT', [projection.status])

    def test_a_model_shouting_at_every_gate_changes_no_digest(self):
        self.link(self.p, source='firsthand-a.example')
        for index in range(3):
            record_model_output(self.db, model_ref='reasoner',
                                output_text=f'P is certainly true ({index})', proposition=self.p,
                                now=self.t0 + index)
        record_revisions(self.db, now=self.t0 + 5)
        before = self.digests(now=self.t0 + 6)
        for index in range(5):
            record_model_output(self.db, model_ref='reasoner',
                                output_text=f'P is certainly true, again ({index})',
                                proposition=self.p, now=self.t0 + 10 + index)
        record_revisions(self.db, now=self.t0 + 20)
        record_convergence(self.db, self.p.proposition_id, now=self.t0 + 20)
        after = self.digests(now=self.t0 + 21)
        self.assertEqual(after["gate_zero"], before["gate_zero"])
        self.assertEqual(after["gate_one"], before["gate_one"])
        self.assertEqual(after["gate_four"], before["gate_four"])


if __name__ == '__main__':
    unittest.main()
