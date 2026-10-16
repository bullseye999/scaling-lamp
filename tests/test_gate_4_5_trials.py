"""
4.5 Gate Two - controlled trials.

    Can baseline and candidate be tested under equivalent, controlled conditions?
"""

import ast
import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import crucible_trials as trials_module
from ciph.kernel.crucible_candidates import register_candidate
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_trials import (
    ROLE_BASELINE,
    ROLE_CANDIDATE,
    STATUS_COMPLETE,
    STATUS_FAILED,
    STATUS_INVALID,
    STATUS_RUNNING,
    complete_trial,
    fail_trial,
    get_trial,
    init_schema,
    invalidate_trial,
    start_trial,
    trial_digest,
    trials_for,
)
from ciph.kernel.crucible_types import CrucibleError, KIND_PLANNER_STRATEGY

ENVIRONMENT = 'host:eval-alpha'
METRICS = [MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02),
           MetricDefinition('latency', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=10.0)]


class TestGate45Trials(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-trials-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.baseline = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY,
                                           artifact_digest='H0', configuration_digest='C0')
        self.candidate = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY,
                                            artifact_digest='H1', configuration_digest='C1',
                                            baseline_candidate_id=self.baseline.candidate_id)
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_PLANNER_STRATEGY,
            development_cases=['d1', 'd2'], heldout_cases=['h1', 'h2'], metric_definitions=METRICS,
            environment_identity=ENVIRONMENT, repetition_count=3, minimum_evidence=1,
            hard_invariants=('NO_AUTHORITY_BYPASS', 'NO_FABRICATED_EVIDENCE'), now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def start(self, subject, role, seed='s1'):
        return start_trial(self.db, protocol_id=self.protocol.protocol_id,
                           subject_id=subject.candidate_id, role=role, seed=seed,
                           environment_identity=ENVIRONMENT, dataset_digest='DS-1',
                           now=self.t1)

    # ------------------------------------------------------------------ founding
    def test_founding_both_subjects_run_under_one_frozen_protocol(self):
        base = self.start(self.baseline, ROLE_BASELINE)
        cand = self.start(self.candidate, ROLE_CANDIDATE)
        self.assertEqual(base.status, STATUS_RUNNING)
        self.assertNotEqual(base.trial_id, cand.trial_id)
        self.assertEqual(base.environment_identity, ENVIRONMENT)
        self.assertEqual(base.dataset_digest, 'DS-1')

        complete_trial(self.db, base.trial_id, observations={'task_success': 0.82, 'latency': 600},
                       result_refs=['R-1'], now=self.t1)
        complete_trial(self.db, cand.trial_id, observations={'task_success': 0.88, 'latency': 570},
                       now=self.t1)
        self.assertEqual(get_trial(self.db, base.trial_id).status, STATUS_COMPLETE)
        self.assertEqual(get_trial(self.db, cand.trial_id).observations['task_success'], 0.88)
        self.assertEqual(len(trials_for(self.db, protocol_id=self.protocol.protocol_id)), 2)

    # ------------------------------------------------------------------ law 7
    def test_law_7_a_restart_resumes_the_same_trial(self):
        first = self.start(self.candidate, ROLE_CANDIDATE)
        again = self.start(self.candidate, ROLE_CANDIDATE)
        self.assertEqual(first.trial_id, again.trial_id,
                         'the same measurement is the same trial, however many times it is opened')
        self.assertEqual(len(trials_for(self.db)), 1)

    # ------------------------------------------------------------------ law 9
    def test_law_9_the_environment_identity_is_part_of_the_evidence(self):
        with self.assertRaises(CrucibleError) as mismatch:
            start_trial(self.db, protocol_id=self.protocol.protocol_id,
                        subject_id=self.candidate.candidate_id, role=ROLE_CANDIDATE,
                        environment_identity='host:somewhere-else', now=self.t1)
        self.assertEqual(mismatch.exception.reason, 'TRIAL_ENVIRONMENT_MISMATCH')
        with self.assertRaises(CrucibleError) as bad_role:
            self.start(self.candidate, 'ARBITER')
        self.assertEqual(bad_role.exception.reason, 'INVALID_TRIAL_ROLE')

    # ------------------------------------------------------------------ law 4
    def test_law_4_a_moved_evaluator_blocks_trial_completion(self):
        trial = self.start(self.candidate, ROLE_CANDIDATE)
        import sqlite3
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE ciph_crucible_protocols SET minimum_evidence = 99 "
                               "WHERE protocol_id = ?;", (self.protocol.protocol_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(CrucibleError) as tampered:
            complete_trial(self.db, trial.trial_id, observations={'task_success': 1.0}, now=self.t1)
        self.assertEqual(tampered.exception.reason, 'PROTOCOL_INTEGRITY_VIOLATION')

    # ------------------------------------------------------------------ law 6
    def test_law_6_failure_and_invalidation_are_recorded_not_hidden(self):
        failed = self.start(self.baseline, ROLE_BASELINE, seed='s2')
        self.assertEqual(fail_trial(self.db, failed.trial_id, reason='worker died',
                                    now=self.t1).status, STATUS_FAILED)
        suspect = self.start(self.candidate, ROLE_CANDIDATE, seed='s3')
        self.assertEqual(invalidate_trial(self.db, suspect.trial_id,
                                          reason='candidate_edited_benchmark', now=self.t1).status,
                         STATUS_INVALID)
        self.assertEqual(get_trial(self.db, suspect.trial_id).invalid_reason,
                         'candidate_edited_benchmark')
        for trial in (failed, suspect):
            with self.assertRaises(CrucibleError) as closed:
                complete_trial(self.db, trial.trial_id, observations={'task_success': 1.0},
                               now=self.t1)
            self.assertEqual(closed.exception.reason, 'TRIAL_ALREADY_CLOSED')

    # ------------------------------------------------------------------ structural
    def test_the_crucible_has_no_execution_and_no_promotion_surface(self):
        public = [name for name, _ in inspect.getmembers(trials_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('promote', 'set_active', 'issue_permit', 'claim_permit', 'execute'):
            self.assertNotIn(forbidden, public)
        tree = ast.parse(inspect.getsource(trials_module))
        identifiers = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                identifiers.add(node.id)
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                identifiers.add(node.name)
        lowered = {name.lower() for name in identifiers}
        for forbidden in ('permitsigner', 'executionauthority', 'signedexecutionpermit',
                          'permitstore', 'guardedexecutor', 'active_candidate'):
            self.assertNotIn(forbidden, lowered)

    # ------------------------------------------------------------------ determinism
    def test_trial_digest_is_deterministic_across_restart(self):
        trial = self.start(self.candidate, ROLE_CANDIDATE)
        complete_trial(self.db, trial.trial_id, observations={'task_success': 0.5}, now=self.t1)
        expected = trial_digest(self.db)
        self.assertEqual(trial_digest(self.db), expected)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.crucible_trials import trial_digest;'
                'print(trial_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)


if __name__ == '__main__':
    unittest.main()
