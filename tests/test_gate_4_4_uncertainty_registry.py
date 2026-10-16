"""
4.4 Gate Zero - the uncertainty registry.

    Curiosity targets are DERIVED from canonical 4.2/4.3 state, never invented from thin air.

Every specimen is written so a registry that let the model nominate its own questions, or that kept a
question open after the underlying state resolved, would fail.
"""

import inspect
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from ciph.kernel import uncertainty_registry as registry
from ciph.kernel.causal_model import propose_hypothesis
from ciph.kernel.epistemic_ledger import (
    canonical_proposition,
    reconstruct as reconstruct_beliefs,
    record_model_output,
)
from ciph.kernel.predictions import issue_prediction
from ciph.kernel.self_model import known_capabilities, record_installation
from ciph.kernel.uncertainty_registry import (
    KIND_CALIBRATION_WEAKNESS,
    KIND_DYNAMICS_GAP,
    KIND_EPISTEMIC_CONTESTED,
    KIND_EPISTEMIC_UNRESOLVED,
    KIND_SELF_MODEL_UNKNOWN,
    KIND_WEAK_CAUSAL_HYPOTHESIS,
    KIND_WORLD_STALE,
    POSSIBLY_REDUCIBLE,
    REDUCIBLE,
    STATUS_OPEN,
    STATUS_SATISFIED,
    derive_uncertainties,
    record_uncertainty_snapshots,
    uncertainty,
    uncertainty_digest,
    uncertainty_history,
    uncertainty_id_for,
    uncertainty_status,
)
from ciph.kernel.world_dynamics import derive_transitions
from ciph.kernel.world_model import world_digest
from curiosity_test_support import add_evidence, contested, converge, unconverged


class TestGate44UncertaintyRegistry(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-44-registry-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.t2 = self.t1 + 100

    def tearDown(self):
        self.temp.cleanup()

    def kinds(self, **kwargs):
        return Counter(record.source_kind for record in derive_uncertainties(self.db, **kwargs))

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_an_unresolved_question_closes_itself_when_the_state_resolves(self):
        prop = unconverged(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        uncertainty_id = uncertainty_id_for(KIND_EPISTEMIC_UNRESOLVED, prop.proposition_id)
        self.assertEqual(record_uncertainty_snapshots(self.db, now=self.t1), 1)
        self.assertEqual(uncertainty_status(self.db, uncertainty_id, now=self.t1), STATUS_OPEN)

        # More evidence converges the SAME proposition. Nobody has to decide it is answered.
        converge(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        self.assertIsNone(uncertainty(self.db, uncertainty_id, now=self.t2),
                          "the question closed itself once the state resolved")
        self.assertEqual(uncertainty_status(self.db, uncertainty_id, now=self.t2), STATUS_SATISFIED)
        self.assertEqual(len(uncertainty_history(self.db, uncertainty_id)), 1,
                         "closure is derived; it rewrites no history")

    # ------------------------------------------------------------------ law 1
    def test_law_1_the_model_cannot_mint_an_uncertainty(self):
        public = [name for name, _ in inspect.getmembers(registry, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('add_uncertainty', 'create_uncertainty', 'register_uncertainty',
                          'nominate_uncertainty', 'open_uncertainty'):
            self.assertNotIn(forbidden, public)

        converge(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        before = uncertainty_digest(self.db, now=self.t2)
        for _ in range(3):
            record_model_output(self.db, model_ref='llm',
                                output_text='I find this deeply interesting and worth investigating',
                                now=self.t2)
        self.assertEqual(uncertainty_digest(self.db, now=self.t2), before)

    # ------------------------------------------------------------------ law 2
    def test_law_2_every_uncertainty_traces_to_canonical_state(self):
        prop = unconverged(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        contested(self.db, 'service.b', 'is_healthy', True, at=self.t1)
        converge(self.db, 'service.c', 'health', 'HEALTHY', at=self.t1)
        converge(self.db, 'service.c', 'health', 'DEGRADED', at=self.t2)
        hypothesis = propose_hypothesis(self.db, cause='deploy', effect='degrade', now=self.t1)
        record_installation(self.db, capability_id='osint.identify', module_ref='osint.py',
                            environment_ref='host:a', now=self.t1)

        known_propositions = {p.proposition_id
                              for p in reconstruct_beliefs(self.db, now=self.t2).propositions}
        capabilities = set(known_capabilities(self.db))
        transitions = {t.transition_id for t in derive_transitions(self.db, now=self.t2)}

        records = derive_uncertainties(self.db, now=self.t2)
        self.assertTrue(records)
        for record in records:
            if record.source_kind in (KIND_EPISTEMIC_UNRESOLVED, KIND_EPISTEMIC_CONTESTED):
                self.assertIn(record.source_ref, known_propositions)
            elif record.source_kind == KIND_DYNAMICS_GAP:
                self.assertIn(record.source_ref, transitions)
            elif record.source_kind == KIND_SELF_MODEL_UNKNOWN:
                self.assertIn(record.source_ref, capabilities)
            elif record.source_kind == KIND_WEAK_CAUSAL_HYPOTHESIS:
                self.assertTrue(record.source_ref.startswith('HY-'))
            elif record.source_kind == KIND_CALIBRATION_WEAKNESS:
                self.assertEqual(record.source_ref, 'PREDICTIONS')
        self.assertTrue(any(r.source_kind == KIND_DYNAMICS_GAP for r in records))
        self.assertIn(prop.proposition_id, {r.source_ref for r in records})
        self.assertIn(hypothesis.hypothesis_id, {r.source_ref for r in records})

    # ------------------------------------------------------------------ law 3
    def test_law_3_a_bare_model_mention_is_not_a_target(self):
        prop = canonical_proposition('service.z', 'is_haunted', True)
        record_model_output(self.db, model_ref='llm', output_text='service z is haunted',
                            proposition=prop, now=self.t1)
        self.assertEqual(self.kinds(now=self.t2), Counter(),
                         "a proposition only a model ever mentioned is not an uncertainty")

    # ------------------------------------------------------------------ law 4
    def test_law_4_contested_is_not_automatically_reducible(self):
        prop = contested(self.db, 'service.b', 'is_healthy', True, at=self.t1)
        uncertainty_id = uncertainty_id_for(KIND_EPISTEMIC_CONTESTED, prop.proposition_id)
        record = uncertainty(self.db, uncertainty_id, now=self.t2)
        self.assertIsNotNone(record)
        self.assertEqual(record.reducibility, POSSIBLY_REDUCIBLE)
        self.assertNotEqual(record.reducibility, REDUCIBLE)

    # ------------------------------------------------------------------ law 5
    def test_law_5_history_is_an_append_only_projection_series(self):
        prop = unconverged(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        uncertainty_id = uncertainty_id_for(KIND_EPISTEMIC_UNRESOLVED, prop.proposition_id)
        self.assertEqual(record_uncertainty_snapshots(self.db, now=self.t1), 1)
        first = uncertainty_history(self.db, uncertainty_id)
        self.assertEqual([row['snapshot_version'] for row in first], [1])
        # The basis moves WITHOUT resolving: a second, ungrounded support leaves the proposition
        # UNRESOLVED while changing the source-dependence picture, so it must re-record.
        add_evidence(self.db, prop, source_ref='mirror', at=self.t1, independent=False)
        self.assertEqual(record_uncertainty_snapshots(self.db, now=self.t2), 1)
        history = uncertainty_history(self.db, uncertainty_id)
        self.assertEqual([row['snapshot_version'] for row in history], [1, 2])
        self.assertEqual(history[0]['basis_digest'], first[0]['basis_digest'],
                         "an earlier projection is never rewritten")

    # ------------------------------------------------------------------ law 6
    def test_law_6_no_api_decides_that_a_question_is_answered(self):
        public = [name for name, _ in inspect.getmembers(registry, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('resolve_uncertainty', 'satisfy_uncertainty', 'close_uncertainty',
                          'mark_resolved'):
            self.assertNotIn(forbidden, public)

    # ------------------------------------------------------------------ law 7
    def test_law_7_identity_is_what_is_uncertain_not_how_it_is_phrased(self):
        prop = unconverged(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        first = derive_uncertainties(self.db, now=self.t2)
        second = derive_uncertainties(self.db, now=self.t2)
        self.assertEqual([r.uncertainty_id for r in first], [r.uncertainty_id for r in second])
        self.assertEqual(uncertainty_id_for(KIND_EPISTEMIC_UNRESOLVED, prop.proposition_id),
                         first[0].uncertainty_id)
        self.assertNotIn('interesting', ' '.join(r.uncertainty_id for r in first).lower())

    # ------------------------------------------------------------------ law 8
    def test_law_8_digest_is_deterministic_across_restart_and_process(self):
        unconverged(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        contested(self.db, 'service.b', 'is_healthy', True, at=self.t1)
        expected = uncertainty_digest(self.db, now=self.t2)
        self.assertEqual(uncertainty_digest(self.db, now=self.t2), expected)
        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.uncertainty_registry import uncertainty_digest;"
                "print(uncertainty_digest(%r, now=%r))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.t2))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)

    # ------------------------------------------------------------------ kind coverage
    def test_all_seven_kinds_are_reachable(self):
        unconverged(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        contested(self.db, 'service.b', 'is_healthy', True, at=self.t1)
        converge(self.db, 'service.c', 'health', 'HEALTHY', at=self.t1)
        converge(self.db, 'service.c', 'health', 'DEGRADED', at=self.t2)
        propose_hypothesis(self.db, cause='deploy', effect='degrade', now=self.t1)
        record_installation(self.db, capability_id='osint.identify', module_ref='osint.py',
                            environment_ref='host:a', now=self.t1)
        prop = converge(self.db, 'service.d', 'is_ok', True, at=self.t1)[0]
        issue_prediction(self.db, predictor_id='ciph', proposition=prop, probability=0.8,
                         resolution_deadline=self.t1 + 10, resolution_rule_id='R', now=self.t1)

        kinds = self.kinds(now=self.t2 + 10_000)
        for expected in (KIND_EPISTEMIC_UNRESOLVED, KIND_EPISTEMIC_CONTESTED, KIND_DYNAMICS_GAP,
                         KIND_WEAK_CAUSAL_HYPOTHESIS, KIND_SELF_MODEL_UNKNOWN,
                         KIND_CALIBRATION_WEAKNESS):
            self.assertIn(expected, kinds)
        stale_kinds = self.kinds(now=self.t2 + 10_000_000, stale_after=1_000)
        self.assertIn(KIND_WORLD_STALE, stale_kinds)

    # ------------------------------------------------------------------ no side effects
    def test_the_registry_writes_no_evidence_and_no_world_state(self):
        converge(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        ledger_before = reconstruct_beliefs(self.db, now=self.t2).canonical_digest()
        world_before = world_digest(self.db, now=self.t2)
        for _ in range(3):
            derive_uncertainties(self.db, now=self.t2)
            record_uncertainty_snapshots(self.db, now=self.t2)
            uncertainty_digest(self.db, now=self.t2)
        self.assertEqual(reconstruct_beliefs(self.db, now=self.t2).canonical_digest(), ledger_before)
        self.assertEqual(world_digest(self.db, now=self.t2), world_before)


if __name__ == '__main__':
    unittest.main()
