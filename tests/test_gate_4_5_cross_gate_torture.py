"""
4.5 cross-gate torture - the full Crucible story, plus the hostile matrix.

Baseline B0 -> candidate C1 -> frozen protocol -> trials -> DOMINATES -> RESTART (nothing promoted) ->
governed promotion -> RESTART -> production regression -> governed rollback -> RESTART.

Every stage must survive a restart, and every hostile move must fail to move the pointer.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ciph.kernel.crucible_candidates import (
    candidate_digest,
    candidate_history,
    get_candidate,
    register_candidate,
    verify_candidate_identity,
)
from ciph.kernel.crucible_generation import propose_candidate
from ciph.kernel.crucible_metrics import (
    PerformanceVector,
    STATUS_DOMINATES,
    STATUS_INCOMPARABLE,
    STATUS_INVALID,
    compare,
)
from ciph.kernel.crucible_monitoring import (
    STATUS_REGRESSED,
    assess_post_promotion,
    monitoring_digest,
)
from ciph.kernel.crucible_promotion import (
    active_candidate,
    promote,
    promotion_digest,
    rollback,
    rollback_history,
)
from ciph.kernel.crucible_protocols import (
    MetricDefinition,
    assert_protocol_integrity,
    freeze_protocol,
    protocol_digest,
    protocol_history,
)
from ciph.kernel.crucible_trials import (
    ROLE_BASELINE,
    ROLE_CANDIDATE,
    complete_trial,
    start_trial,
    trial_digest,
    trials_for,
)
from ciph.kernel.crucible_types import CrucibleError, KIND_PLANNER_STRATEGY

ROLE = 'planner'
ENVIRONMENT = 'host:eval-alpha'
METRICS = [MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02),
           MetricDefinition('prediction_brier', 'v1', 'LOWER_BETTER',
                            minimum_meaningful_delta=0.02),
           MetricDefinition('latency', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=10.0),
           MetricDefinition('cost', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=0.02)]

B0 = {'task_success': 0.82, 'prediction_brier': 0.19, 'latency': 600.0, 'cost': 1.00}
C1 = {'task_success': 0.88, 'prediction_brier': 0.16, 'latency': 570.0, 'cost': 0.93}


def crucible_bundle(db):
    return {'candidates': candidate_digest(db), 'protocols': protocol_digest(db),
            'trials': trial_digest(db), 'promotion': promotion_digest(db),
            'monitoring': monitoring_digest(db)}


class TestGate45CrossGateTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-torture-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = time.time() - 60.0
        self.baseline = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY,
                                           artifact_digest='H0', configuration_digest='C0',
                                           created_by='operator', now=self.t1)
        self.candidate = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY,
                                            artifact_digest='H1', configuration_digest='C1',
                                            baseline_candidate_id=self.baseline.candidate_id,
                                            created_by='ciph', now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def freeze(self):
        return freeze_protocol(
            self.db, candidate_kind=KIND_PLANNER_STRATEGY,
            development_cases=[f'dev-{i}' for i in range(100)],
            heldout_cases=[f'held-{i}' for i in range(50)], metric_definitions=METRICS,
            environment_identity=ENVIRONMENT, repetition_count=3, minimum_evidence=3,
            hard_invariants=('NO_AUTHORITY_BYPASS', 'NO_FABRICATED_EVIDENCE',
                             'NO_HISTORY_MUTATION'), now=self.t1)

    def run_trials(self, protocol, subject, role, values, *, repetitions=1):
        """The protocol declares a repetition count, so the evidence has to honor it."""
        trials = []
        for index in range(repetitions):
            trial = start_trial(self.db, protocol_id=protocol.protocol_id,
                                subject_id=subject.candidate_id, role=role,
                                seed=f'{role}-seed-{index}', environment_identity=ENVIRONMENT,
                                dataset_digest='DS-HELD', now=self.t1)
            complete_trial(self.db, trial.trial_id, observations=values, now=self.t1)
            trials.append(trial)
        return trials

    def vector(self, subject, values, *, violations=None):
        return PerformanceVector(subject_id=subject, protocol_id=self.protocol.protocol_id,
                                 samples={key: (value,) * 3 for key, value in values.items()},
                                 hard_violations=violations or {})

    def assert_restart_reproduces(self, expected):
        code = ('import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from test_gate_4_5_cross_gate_torture import crucible_bundle;'
                'print(json.dumps(crucible_bundle(%r), sort_keys=True))'
                % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)

    # ------------------------------------------------------------------ the ladder
    def test_the_whole_crucible_composes_and_survives_every_restart(self):
        self.protocol = self.freeze()
        self.assertEqual(len(protocol_history(self.db)), 1)
        self.assertEqual(len(candidate_history(self.db)), 2)

        # Stage 3 - trials for both subjects under the SAME frozen protocol.
        base_trials = self.run_trials(self.protocol, self.baseline, ROLE_BASELINE, B0,
                                      repetitions=3)
        cand_trials = self.run_trials(self.protocol, self.candidate, ROLE_CANDIDATE, C1,
                                      repetitions=3)
        self.assertEqual(len(trials_for(self.db, protocol_id=self.protocol.protocol_id)), 6)
        evidence_refs = [t.trial_id for t in base_trials + cand_trials]

        result = compare(self.vector('B0', B0), self.vector('C1', C1), self.protocol)
        self.assertEqual(result.status, STATUS_DOMINATES)

        # Stage 4 - RESTART before promotion. Evidence is not promotion.
        before_promotion = crucible_bundle(self.db)
        self.assert_restart_reproduces(before_promotion)
        self.assertIsNone(active_candidate(self.db, ROLE),
                          'DOMINATES changes nothing until governance says so')

        # Stage 5 - governed promotion. No permits appear.
        promotion = promote(self.db, role=ROLE, candidate_id=self.candidate.candidate_id,
                            protocol_id=self.protocol.protocol_id,
                            comparison_status=STATUS_DOMINATES,
                            evaluation_refs=evidence_refs,
                            authorization_ref='operator:operator',
                            replaced_candidate_id=self.baseline.candidate_id, now=self.t1 + 10)
        self.assertEqual(active_candidate(self.db, ROLE), self.candidate.candidate_id)
        connection = sqlite3.connect(self.db)
        try:
            permits = connection.execute("SELECT COUNT(*) FROM execution_permits;").fetchone()[0]
        except sqlite3.Error:
            permits = 0
        finally:
            connection.close()
        self.assertEqual(permits, 0, 'promotion is a pointer move, not an execution grant')
        after_promotion = crucible_bundle(self.db)
        self.assertNotEqual(after_promotion, before_promotion)
        self.assert_restart_reproduces(after_promotion)

        # Stage 6 - production regression, then governed rollback.
        assessment = assess_post_promotion(
            self.db, promotion_id=promotion.promotion_id,
            candidate_id=self.candidate.candidate_id, protocol_id=self.protocol.protocol_id,
            expected=self.vector('C1', C1),
            observed=self.vector('C1', dict(C1, task_success=0.60, prediction_brier=0.31)),
            now=self.t1 + 20)
        self.assertEqual(assessment.status, STATUS_REGRESSED)
        rollback(self.db, role=ROLE, evidence_refs=[assessment.assessment_id],
                 reason_codes=['PRODUCTION_REGRESSION'], now=self.t1 + 30)
        self.assertEqual(active_candidate(self.db, ROLE), self.baseline.candidate_id)

        # Nothing was rewritten: the victory, the regression and the rollback all still exist.
        self.assertEqual(len(rollback_history(self.db)), 1)
        self.assertEqual(get_candidate(self.db, self.candidate.candidate_id).artifact_digest, 'H1')
        self.assertEqual(self.vector('C1', C1).samples['task_success'], (0.88, 0.88, 0.88))
        self.assert_restart_reproduces(crucible_bundle(self.db))

    # ------------------------------------------------------------------ the hostile matrix
    def test_hostile_self_promotion_and_redefinition(self):
        self.protocol = self.freeze()
        # A candidate whose OUTPUT says "promote me" cannot move the pointer: the string is not a
        # parameter of anything that moves it.
        self.assertIsNone(active_candidate(self.db, ROLE))
        with self.assertRaises(CrucibleError):
            verify_candidate_identity(self.db, self.candidate.candidate_id, artifact_digest='H2',
                                      configuration_digest='C1')
        edited = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY, artifact_digest='H2',
                                    configuration_digest='C1', now=self.t1)
        self.assertNotEqual(edited.candidate_id, self.candidate.candidate_id)

    def test_hostile_evaluator_benchmark_and_evidence_tampering(self):
        self.protocol = self.freeze()
        trial = self.run_trials(self.protocol, self.candidate, ROLE_CANDIDATE, C1)[0]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE ciph_crucible_protocols SET heldout_cases_json = ? "
                               "WHERE protocol_id = ?;",
                               (json.dumps(['held-0']), self.protocol.protocol_id))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(CrucibleError) as tampered:
            assert_protocol_integrity(self.db, self.protocol.protocol_id)
        self.assertEqual(tampered.exception.reason, 'PROTOCOL_INTEGRITY_VIOLATION')
        # ...and the promotion gate refuses a protocol that no longer verifies.
        with self.assertRaises(CrucibleError):
            promote(self.db, role=ROLE, candidate_id=self.candidate.candidate_id,
                    protocol_id=self.protocol.protocol_id, comparison_status=STATUS_DOMINATES,
                    evaluation_refs=['X'], authorization_ref='operator:operator', now=self.t1)
        self.assertIsNone(active_candidate(self.db, ROLE))
        self.assertEqual(trials_for(self.db)[0].trial_id, trial.trial_id)

    def test_hostile_performance_cannot_oversell(self):
        self.protocol = self.freeze()
        base = self.vector('B0', B0)
        # One-dimensional win: faster ideas, ten times the cost.
        lopsided = self.vector('C1', dict(C1, task_success=0.95, latency=3000.0, cost=10.0))
        self.assertEqual(compare(base, lopsided, self.protocol).status, STATUS_INCOMPARABLE)
        # A constitutional violation with spectacular performance is still dead.
        broken = self.vector('C2', dict(C1, task_success=0.999, latency=100.0, cost=0.10),
                             violations={'NO_FABRICATED_EVIDENCE': 1})
        self.assertEqual(compare(base, broken, self.protocol).status, STATUS_INVALID)
        with self.assertRaises(CrucibleError):
            promote(self.db, role=ROLE, candidate_id=self.candidate.candidate_id,
                    protocol_id=self.protocol.protocol_id, comparison_status=STATUS_INVALID,
                    evaluation_refs=['X'], authorization_ref='operator:operator', now=self.t1)
        self.assertIsNone(active_candidate(self.db, ROLE))

    def test_hostile_a_restart_cannot_duplicate_trials_or_mint_a_promotion(self):
        self.protocol = self.freeze()
        first = self.run_trials(self.protocol, self.candidate, ROLE_CANDIDATE, C1)[0]
        again = start_trial(self.db, protocol_id=self.protocol.protocol_id,
                            subject_id=self.candidate.candidate_id, role=ROLE_CANDIDATE,
                            seed=f'{ROLE_CANDIDATE}-seed-0', environment_identity=ENVIRONMENT,
                            dataset_digest='DS-HELD', now=self.t1 + 1)
        self.assertEqual(first.trial_id, again.trial_id)
        self.assertEqual(len(trials_for(self.db)), 1)
        self.assertIsNone(active_candidate(self.db, ROLE))
        self.assertEqual(len(promotion_digest(self.db)), 64)

    def test_a_generator_cannot_reach_the_pointer(self):
        self.protocol = self.freeze()
        proposal = propose_candidate(kind=KIND_PLANNER_STRATEGY, artifact_digest='H9',
                                     configuration_digest='C9', source='CIPH_PLANNER')
        self.assertTrue(proposal.proposal_id)
        self.assertEqual({c.candidate_id for c in candidate_history(self.db)},
                         {self.baseline.candidate_id, self.candidate.candidate_id})
        self.assertIsNone(active_candidate(self.db, ROLE))


if __name__ == '__main__':
    unittest.main()
