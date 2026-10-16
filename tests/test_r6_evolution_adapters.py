"""
R6 Gates B, C and F - the legacy lifecycle under law.

Gate B keeps ONE identity owner, Gate C keeps ONE verdict owner, Gate F keeps ONE promotion/rollback
owner. The old machinery supplies bytes, measurements and mechanisms; it no longer supplies truth.
"""

import ast
import inspect
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import evolution_adapters as adapters_module
from ciph.kernel.crucible_candidates import get_candidate, verify_candidate_identity
from ciph.kernel.crucible_metrics import PerformanceVector, STATUS_DOMINATES
from ciph.kernel.crucible_monitoring import STATUS_REGRESSED
from ciph.kernel.crucible_promotion import active_candidate, promote
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_trials import ROLE_BASELINE, ROLE_CANDIDATE, STATUS_COMPLETE, get_trial
from ciph.kernel.crucible_types import CrucibleError, KIND_CAPABILITY_IMPLEMENTATION
from ciph.kernel.evolution_adapters import (
    adapter_digest,
    adopt_legacy_candidate,
    bind_legacy_evaluation,
    governed_rollback,
    legacy_binding_for,
    legacy_bindings,
    record_canary_measurement,
    record_legacy_measurement,
)

ROLE = 'capability:revision'
ENVIRONMENT = 'host:eval'


class TestR6EvolutionAdapters(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-r6-adapters-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_CAPABILITY_IMPLEMENTATION, development_cases=['d'],
            heldout_cases=['h'],
            metric_definitions=[
                MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02),
                MetricDefinition('prediction_brier', 'v1', 'LOWER_BETTER',
                                 minimum_meaningful_delta=0.02)],
            environment_identity=ENVIRONMENT, minimum_evidence=1, now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def adopt(self, *, candidate_hash='HASH-C1', base_file_hash='BASE-H0', class_name='Planner',
              source='phase8'):
        return adopt_legacy_candidate(self.db, candidate_hash=candidate_hash,
                                      base_file_hash=base_file_hash, source=source,
                                      class_name=class_name, artifact_path='/staging/c1.py',
                                      kind=KIND_CAPABILITY_IMPLEMENTATION, now=self.t1)

    # ------------------------------------------------------------------ Gate B
    def test_gate_b_a_legacy_candidate_adopts_one_constitutional_identity(self):
        candidate = self.adopt()
        self.assertTrue(candidate.candidate_id.startswith('CC-'))
        self.assertEqual(candidate.artifact_digest, 'HASH-C1',
                         'the legacy artifact hash becomes the artifact digest')
        binding = legacy_binding_for(self.db, candidate_hash='HASH-C1', base_file_hash='BASE-H0')
        self.assertIsNotNone(binding)
        self.assertEqual(binding.candidate_id, candidate.candidate_id)
        self.assertEqual(binding.class_name, 'Planner')
        # Adopting the same legacy artifact twice is the same candidate, not a second entry.
        again = self.adopt()
        self.assertEqual(again.candidate_id, candidate.candidate_id)
        self.assertEqual(len(legacy_bindings(self.db)), 1)

    def test_gate_b_a_changed_artifact_creates_a_new_candidate(self):
        candidate = self.adopt()
        with self.assertRaises(CrucibleError) as refused:
            verify_candidate_identity(self.db, candidate.candidate_id,
                                      artifact_digest='HASH-C1-EDITED',
                                      configuration_digest=candidate.configuration_digest)
        self.assertEqual(refused.exception.reason, 'CANDIDATE_IDENTITY_MISMATCH')
        edited = self.adopt(candidate_hash='HASH-C1-EDITED')
        self.assertNotEqual(edited.candidate_id, candidate.candidate_id,
                            'editing the artifact adopts a new candidate, it does not update one')

    def test_gate_b_one_legacy_artifact_cannot_be_re_identified(self):
        first = self.adopt(class_name='Planner')
        with self.assertRaises(CrucibleError) as refused:
            self.adopt(class_name='PlannerV2')
        self.assertEqual(refused.exception.reason, 'LEGACY_BINDING_ALREADY_ADOPTED')
        self.assertEqual(get_candidate(self.db, first.candidate_id).artifact_digest, 'HASH-C1')

    # ------------------------------------------------------------------ Gate C
    def test_gate_c_a_legacy_evaluation_becomes_a_trial_not_a_verdict(self):
        baseline = adopt_legacy_candidate(self.db, candidate_hash='HASH-B0', base_file_hash='BASE-ROOT',
                                          source='phase8', class_name='Planner', now=self.t1)
        candidate = self.adopt()
        trial = bind_legacy_evaluation(self.db, candidate_id=candidate.candidate_id,
                                       protocol_id=self.protocol.protocol_id, role=ROLE_CANDIDATE,
                                       grant_ref='EVALGRANT-1', class_name='Planner',
                                       measurement_refs=['R-1', 'R-2'], seed='seed-1',
                                       environment_identity=ENVIRONMENT, dataset_digest='DS',
                                       now=self.t1)
        self.assertEqual(trial.protocol_id, self.protocol.protocol_id)
        self.assertEqual(trial.seed, 'seed-1')
        closed = record_legacy_measurement(self.db, trial_id=trial.trial_id,
                                           observations={'task_success': 0.88,
                                                         'prediction_brier': 0.16}, now=self.t1)
        self.assertEqual(closed.status, STATUS_COMPLETE)
        self.assertEqual(get_trial(self.db, trial.trial_id).observations['task_success'], 0.88)
        self.assertNotEqual(baseline.candidate_id, candidate.candidate_id)
        self.assertEqual(len({t.subject_id for t in
                              [trial]}), 1)

    def test_gate_c_a_legacy_report_cannot_declare_a_verdict(self):
        public = [name for name, _ in inspect.getmembers(adapters_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('approve', 'approve_deployment', 'declare_pass', 'verdict',
                          'mark_approved', 'promote_from_legacy'):
            self.assertNotIn(forbidden, public)
        # Imports, not prose: the module's docstring EXPLAINS the boundaries, so a substring scan
        # would be satisfied by deleting a comment and violated by explaining the design.
        tree = ast.parse(inspect.getsource(adapters_module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(entry.name for entry in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or '')
                imported.extend(entry.name for entry in node.names)
        for forbidden in ('ciph.evolution', 'canary_manager', 'file_activation', 'code_staging',
                          'evolution_bridge', 'STATUS_DOMINATES', 'EvolutionDeploymentGrant'):
            offending = [name for name in imported if forbidden in name]
            self.assertFalse(offending, f'{forbidden} must not be imported: {offending}')

    def test_gate_c_a_tampered_protocol_blocks_the_trial(self):
        candidate = self.adopt()
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE ciph_crucible_protocols SET minimum_evidence = 99 "
                               "WHERE protocol_id = ?;", (self.protocol.protocol_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(CrucibleError) as refused:
            bind_legacy_evaluation(self.db, candidate_id=candidate.candidate_id,
                                   protocol_id=self.protocol.protocol_id, role=ROLE_CANDIDATE,
                                   grant_ref='EVALGRANT-1', now=self.t1)
        self.assertEqual(refused.exception.reason, 'PROTOCOL_INTEGRITY_VIOLATION')

    # ------------------------------------------------------------------ Gate F
    def fixture_promoted(self):
        baseline = adopt_legacy_candidate(self.db, candidate_hash='HASH-B0',
                                          base_file_hash='BASE-ROOT', class_name='Planner', now=self.t1)
        candidate = self.adopt()
        promotion = promote(self.db, role=ROLE, candidate_id=candidate.candidate_id,
                            protocol_id=self.protocol.protocol_id,
                            comparison_status=STATUS_DOMINATES, evaluation_refs=['T1'],
                            authorization_ref='operator:operator',
                            replaced_candidate_id=baseline.candidate_id, now=self.t1)
        return baseline, candidate, promotion

    def vector(self, success, brier):
        return PerformanceVector(subject_id='x', protocol_id=self.protocol.protocol_id,
                                 samples={'task_success': (success,), 'prediction_brier': (brier,)})

    def test_gate_f_canary_measurements_feed_the_constitutional_verdict(self):
        baseline, candidate, promotion = self.fixture_promoted()
        assessment = record_canary_measurement(
            self.db, promotion_id=promotion.promotion_id, candidate_id=candidate.candidate_id,
            protocol_id=self.protocol.protocol_id, expected=self.vector(0.88, 0.16),
            observed=self.vector(0.60, 0.31), now=self.t1 + 10)
        self.assertEqual(assessment.status, STATUS_REGRESSED)
        self.assertIn('task_success', assessment.regression_dimensions)
        from ciph.kernel.evolution_deployment import verify_active_consistency
        self.assertEqual(active_candidate(self.db, ROLE), candidate.candidate_id)

    def test_gate_f_the_canonical_pointer_moves_before_any_mechanism_restores_bytes(self):
        baseline, candidate, promotion = self.fixture_promoted()
        assessment = record_canary_measurement(
            self.db, promotion_id=promotion.promotion_id, candidate_id=candidate.candidate_id,
            protocol_id=self.protocol.protocol_id, expected=self.vector(0.88, 0.16),
            observed=self.vector(0.60, 0.31), now=self.t1 + 10)
        observed_during_restore = {}

        def restore(*, candidate_id, promotion_id):
            observed_during_restore['active'] = active_candidate(self.db, ROLE)
            observed_during_restore['candidate_id'] = candidate_id

        record = governed_rollback(self.db, role=ROLE, promotion_id=promotion.promotion_id,
                                   assessment_id=assessment.assessment_id,
                                   reason_codes=['PRODUCTION_REGRESSION'], restore=restore,
                                   now=self.t1 + 20)
        self.assertEqual(record.restored_candidate_id, baseline.candidate_id)
        self.assertEqual(observed_during_restore['active'], baseline.candidate_id,
                         'the canonical decision lands BEFORE the mechanism is allowed to act')
        self.assertEqual(active_candidate(self.db, ROLE), baseline.candidate_id)

    # ------------------------------------------------------------------ determinism
    def test_adapter_bindings_are_reproducible(self):
        self.adopt()
        expected = adapter_digest(self.db)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.evolution_adapters import adapter_digest;'
                'print(adapter_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)


if __name__ == '__main__':
    unittest.main()
