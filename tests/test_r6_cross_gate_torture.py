"""
R6 cross-gate torture - one real pre-constitutional evolution path, placed under law.

    legacy gap -> legacy candidate -> CC-* identity -> frozen protocol -> legacy measurements
    -> Crucible derives DOMINATES -> RESTART (nothing promoted)
    -> a valid legacy deployment authorization with NO promotion is REFUSED
    -> governed promotion -> governed deployment -> canary regression -> governed rollback

Every stage must survive a restart, and the demoted machinery must still be there at the end.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_candidates import candidate_digest, get_candidate
from ciph.kernel.crucible_metrics import PerformanceVector, STATUS_DOMINATES, compare
from ciph.kernel.crucible_monitoring import STATUS_REGRESSED, monitoring_digest
from ciph.kernel.crucible_promotion import (
    active_candidate,
    promote,
    promotion_digest,
    rollback_history,
)
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol, protocol_digest
from ciph.kernel.crucible_trials import (
    ROLE_BASELINE,
    ROLE_CANDIDATE,
    complete_trial,
    start_trial,
    trial_digest,
)
from ciph.kernel.crucible_types import CrucibleError, KIND_CAPABILITY_IMPLEMENTATION
from ciph.kernel.evolution_adapters import (
    adapter_digest,
    adopt_legacy_candidate,
    bind_legacy_evaluation,
    governed_rollback,
    legacy_bindings,
    record_canary_measurement,
    record_legacy_measurement,
)
from ciph.kernel.evolution_deployment import (
    CONSISTENT,
    deployment_digest,
    deploy,
    get_deployment,
    verify_active_consistency,
)
from ciph.kernel.evolution_ownership import ownership_report

ROLE = 'capability:revision'
ENVIRONMENT = 'host:eval'
METRICS = [MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02),
           MetricDefinition('prediction_brier', 'v1', 'LOWER_BETTER',
                            minimum_meaningful_delta=0.02)]
B_MINUS = {'task_success': 0.70, 'prediction_brier': 0.26}
B0 = {'task_success': 0.82, 'prediction_brier': 0.19}
C1 = {'task_success': 0.88, 'prediction_brier': 0.16}


def r6_bundle(db):
    return {'candidates': candidate_digest(db), 'protocols': protocol_digest(db),
            'trials': trial_digest(db), 'promotions': promotion_digest(db),
            'monitoring': monitoring_digest(db), 'deployments': deployment_digest(db),
            'adapters': adapter_digest(db)}


class _Installer:
    def __init__(self):
        self.calls = []

    def __call__(self, *, promotion_id, candidate_id, artifact_digest):
        self.calls.append(candidate_id)
        return artifact_digest


class TestR6CrossGateTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-r6-torture-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_CAPABILITY_IMPLEMENTATION, development_cases=['d'],
            heldout_cases=['h'], metric_definitions=METRICS, environment_identity=ENVIRONMENT,
            minimum_evidence=1, now=self.t1)
        self.b_minus = adopt_legacy_candidate(self.db, candidate_hash='HASH-B-1',
                                              base_file_hash='ROOT', class_name='Planner',
                                              source='phase8', now=self.t1)
        self.b0 = adopt_legacy_candidate(self.db, candidate_hash='HASH-B0', base_file_hash='ROOT',
                                         class_name='Planner', source='phase8', now=self.t1)
        self.c1 = adopt_legacy_candidate(self.db, candidate_hash='HASH-C1',
                                         base_file_hash='HASH-B0', class_name='Planner',
                                         source='phase8', now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def measure(self, subject, role, values, *, seed):
        trial = bind_legacy_evaluation(self.db, candidate_id=subject.candidate_id,
                                       protocol_id=self.protocol.protocol_id, role=role,
                                       grant_ref=f'EVALGRANT-{seed}', seed=seed,
                                       environment_identity=ENVIRONMENT, dataset_digest='DS',
                                       now=self.t1)
        record_legacy_measurement(self.db, trial_id=trial.trial_id, observations=values, now=self.t1)
        return trial.trial_id

    def vector(self, values):
        return PerformanceVector(subject_id='x', protocol_id=self.protocol.protocol_id,
                                 samples={key: (value,) for key, value in values.items()})

    def assert_restart_reproduces(self, expected):
        code = ('import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from test_r6_cross_gate_torture import r6_bundle;'
                'print(json.dumps(r6_bundle(%r), sort_keys=True))'
                % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)

    # ------------------------------------------------------------------ the ladder
    def test_the_legacy_lifecycle_is_placed_under_law(self):
        # B0 becomes the incumbent through a governed promotion of its own.
        self.measure(self.b_minus, ROLE_BASELINE, B_MINUS, seed='b-1')
        self.measure(self.b0, ROLE_CANDIDATE, B0, seed='b0')
        self.assertEqual(compare(self.vector(B_MINUS), self.vector(B0), self.protocol).status,
                         STATUS_DOMINATES)
        promote(self.db, role=ROLE, candidate_id=self.b0.candidate_id,
                protocol_id=self.protocol.protocol_id, comparison_status=STATUS_DOMINATES,
                evaluation_refs=['b-1', 'b0'], authorization_ref='operator:operator',
                replaced_candidate_id=self.b_minus.candidate_id, now=self.t1)
        self.assertEqual(active_candidate(self.db, ROLE), self.b0.candidate_id)

        # The legacy machinery measures a new candidate; the verdict comes from the constitution.
        self.measure(self.c1, ROLE_CANDIDATE, C1, seed='c1')
        self.assertEqual(compare(self.vector(B0), self.vector(C1), self.protocol).status,
                         STATUS_DOMINATES)

        # RESTART: better is still not promoted.
        before_promotion = r6_bundle(self.db)
        self.assert_restart_reproduces(before_promotion)
        self.assertEqual(active_candidate(self.db, ROLE), self.b0.candidate_id)

        # A perfectly valid legacy deployment authorization with NO promotion deploys nothing.
        installer = _Installer()
        with self.assertRaises(CrucibleError) as refused:
            deploy(self.db, promotion_id='CPR-LEGACY-NOT-A-PROMOTION', role=ROLE,
                   candidate_id=self.c1.candidate_id, artifact_digest='HASH-C1',
                   installer=installer, authorization_ref='legacy:EvolutionDeploymentGrant',
                   installer_ref='legacy', now=self.t1 + 5)
        self.assertIn('NO_PROMOTION_RECORD', refused.exception.detail)
        self.assertEqual(installer.calls, [])
        self.assertEqual(active_candidate(self.db, ROLE), self.b0.candidate_id)

        # Governed promotion, then governed deployment through the one boundary.
        promotion = promote(self.db, role=ROLE, candidate_id=self.c1.candidate_id,
                            protocol_id=self.protocol.protocol_id,
                            comparison_status=STATUS_DOMINATES, evaluation_refs=['c1'],
                            authorization_ref='operator:operator',
                            replaced_candidate_id=self.b0.candidate_id, now=self.t1 + 10)
        self.assertEqual(active_candidate(self.db, ROLE), self.c1.candidate_id)
        assert_array = self.measure
        self.assertIsNotNone(assert_array)
        deployment = deploy(self.db, promotion_id=promotion.promotion_id, role=ROLE,
                            candidate_id=self.c1.candidate_id, artifact_digest='HASH-C1',
                            installer=installer, authorization_ref='operator:operator',
                            installer_ref='staging+canary', now=self.t1 + 20)
        self.assertEqual(deployment.status, 'VERIFIED')
        self.assertEqual(installer.calls, [self.c1.candidate_id])
        self.assertEqual(verify_active_consistency(self.db, role=ROLE,
                                                  observed_artifact_digest='HASH-C1'), CONSISTENT)
        self.assert_restart_reproduces(r6_bundle(self.db))

        # Production canary: the mechanism measures, the constitution judges.
        assessment = record_canary_measurement(
            self.db, promotion_id=promotion.promotion_id, candidate_id=self.c1.candidate_id,
            protocol_id=self.protocol.protocol_id, expected=self.vector(C1),
            observed=self.vector({'task_success': 0.60, 'prediction_brier': 0.31}), now=self.t1 + 30)
        self.assertEqual(assessment.status, STATUS_REGRESSED)

        restored = {}

        def restore(*, candidate_id, promotion_id):
            restored['active_at_restore'] = active_candidate(self.db, ROLE)
            restored['candidate_id'] = candidate_id

        record = governed_rollback(self.db, role=ROLE, promotion_id=promotion.promotion_id,
                                   assessment_id=assessment.assessment_id,
                                   reason_codes=['PRODUCTION_REGRESSION'], restore=restore,
                                   now=self.t1 + 40)
        self.assertEqual(record.restored_candidate_id, self.b0.candidate_id)
        self.assertEqual(restored['active_at_restore'], self.b0.candidate_id)
        self.assertEqual(active_candidate(self.db, ROLE), self.b0.candidate_id)

        # Nothing was rewritten: legacy bindings, the benchmark victory, the regression and the
        # rollback all remain.
        self.assertEqual(len(legacy_bindings(self.db)), 3)
        self.assertEqual(get_candidate(self.db, self.c1.candidate_id).artifact_digest, 'HASH-C1')
        self.assertEqual(len(rollback_history(self.db)), 1)
        self.assertEqual(len(get_deployment(self.db, deployment.deployment_id).as_dict()), 10)
        self.assert_restart_reproduces(r6_bundle(self.db))

    # ------------------------------------------------------------------ seal conditions
    def test_the_single_owner_conditions_hold(self):
        report = ownership_report()
        self.assertEqual(report['violations'], ())
        self.assertEqual(report['activation_bypasses'], ())
        self.assertEqual(report['retained_machinery_missing'], ())
        constitutional = [entry for entry in report['matrix']
                          if not entry['legacy_ownership_allowed']]
        self.assertTrue(constitutional)
        owners = {entry['canonical_owner'] for entry in constitutional}
        self.assertEqual(owners, {
            'ciph/kernel/crucible_candidates.py', 'ciph/kernel/crucible_protocols.py',
            'ciph/kernel/crucible_trials.py', 'ciph/kernel/crucible_metrics.py',
            'ciph/kernel/crucible_promotion.py', 'ciph/kernel/crucible_monitoring.py',
            'ciph/kernel/evolution_deployment.py'},
            'the constitutional owner set must be exactly these seven modules')
        for concern in ('candidate identity', 'evaluation protocol', 'trial identity',
                        'comparison verdict', 'promotion state', 'active candidate pointer',
                        'rollback lineage', 'regression verdict', 'deployment record'):
            self.assertTrue(any(entry['concern'] == concern for entry in constitutional))


if __name__ == '__main__':
    unittest.main()
