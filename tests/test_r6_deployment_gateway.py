"""
R6 Gates D and E - one governed deployment boundary, one canonical active state.

The load-bearing specimen is the one operator asked for by name:

    valid deployment authorization
    +
    no PromotionRecord
    -> REFUSED, filesystem unchanged, active pointer unchanged

and its companion, which is the whole point of a choke point:

    the installer is never called when the constitution has not said yes.
"""

import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import evolution_deployment as deployment_module
from ciph.kernel.crucible_candidates import register_candidate
from ciph.kernel.crucible_metrics import STATUS_DOMINATES
from ciph.kernel.crucible_promotion import active_candidate, promote, rollback
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_types import CrucibleError, KIND_CAPABILITY_IMPLEMENTATION
from ciph.kernel.evolution_deployment import (
    CONSISTENT,
    DEPLOYMENT_INTEGRITY_CONFLICT,
    REASON_ACTIVE_POINTER_MOVED,
    REASON_CANDIDATE_IDENTITY_MISMATCH,
    REASON_INSTALLED_MISMATCH,
    REASON_NO_PROMOTION,
    canonical_active_candidate,
    deploy,
    deployment_digest,
    deployment_history,
    get_deployment,
    verify_active_consistency,
)

ROLE = 'planner'


class FakeInstaller:
    """Stands in for staging / canary activation / file swap / capability re-registration."""

    def __init__(self, result=None):
        self.calls = []
        self.result = result

    def __call__(self, *, promotion_id, candidate_id, artifact_digest):
        self.calls.append({'promotion_id': promotion_id, 'candidate_id': candidate_id,
                           'artifact_digest': artifact_digest})
        return self.result if self.result is not None else artifact_digest


class TestR6DeploymentGateway(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-r6-deploy-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.baseline = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                           artifact_digest='H0', configuration_digest='C0')
        self.candidate = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                            artifact_digest='H1', configuration_digest='C1',
                                            baseline_candidate_id=self.baseline.candidate_id)
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_CAPABILITY_IMPLEMENTATION, development_cases=['d'],
            heldout_cases=['h'],
            metric_definitions=[MetricDefinition('task_success', 'v1', 'HIGHER_BETTER',
                                                 minimum_meaningful_delta=0.02)],
            environment_identity='host:eval', minimum_evidence=1, now=self.t1)
        self.promotion = promote(
            self.db, role=ROLE, candidate_id=self.candidate.candidate_id,
            protocol_id=self.protocol.protocol_id, comparison_status=STATUS_DOMINATES,
            evaluation_refs=['T1'], authorization_ref='operator:operator',
            replaced_candidate_id=self.baseline.candidate_id, now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def ship(self, installer, candidate=None, promotion=None, artifact='H1', auth='operator:operator'):
        return deploy(self.db, promotion_id=(promotion or self.promotion).promotion_id, role=ROLE,
                      candidate_id=(candidate or self.candidate).candidate_id,
                      artifact_digest=artifact, configuration_digest='C1', installer=installer,
                      authorization_ref=auth, installer_ref='fake', now=self.t1)

    # ------------------------------------------------------------------ founding
    def test_founding_a_deployment_follows_a_promotion_and_verifies_what_landed(self):
        installer = FakeInstaller()
        record = self.ship(installer)
        self.assertEqual(record.status, 'VERIFIED')
        self.assertEqual(record.installed_artifact_digest, 'H1')
        self.assertEqual(installer.calls, [{'promotion_id': self.promotion.promotion_id,
                                            'candidate_id': self.candidate.candidate_id,
                                            'artifact_digest': 'H1'}])
        self.assertEqual(record.promotion_id, self.promotion.promotion_id)
        self.assertEqual(len(deployment_history(self.db, ROLE)), 1)

    # ------------------------------------------------------------------ the named specimen
    def test_a_valid_authorization_without_a_promotion_deploys_nothing(self):
        installer = FakeInstaller()
        with self.assertRaises(CrucibleError) as refused:
            deploy(self.db, promotion_id='CPR-DOES-NOT-EXIST', role=ROLE,
                   candidate_id=self.candidate.candidate_id, artifact_digest='H1',
                   configuration_digest='C1', installer=installer,
                   authorization_ref='legacy:EvolutionDeploymentGrant-signed', now=self.t1)
        self.assertEqual(refused.exception.reason, 'DEPLOYMENT_REFUSED')
        self.assertIn(REASON_NO_PROMOTION, refused.exception.detail)
        self.assertEqual(installer.calls, [], 'the mechanism must not run without a promotion')
        self.assertEqual(deployment_history(self.db), [])
        self.assertEqual(active_candidate(self.db, ROLE), self.candidate.candidate_id)

    def test_the_installer_never_runs_on_a_refused_deployment(self):
        """Every refusal path is checked for the same property: the mechanism stays cold."""
        installer = FakeInstaller()
        rollback(self.db, role=ROLE, evidence_refs=['A'], reason_codes=['R'], now=self.t1 + 1)
        attempts = [
            dict(kwargs=dict(candidate=None, artifact='H0'), expect=REASON_ACTIVE_POINTER_MOVED),
            dict(kwargs=dict(artifact='WRONG-ARTIFACT'), expect=REASON_CANDIDATE_IDENTITY_MISMATCH),
            dict(kwargs=dict(auth=''), expect='AUTHORIZATION_REQUIRED'),
        ]
        for attempt in attempts:
            with self.assertRaises(CrucibleError) as refused:
                self.ship(installer, **attempt['kwargs'])
            self.assertIn(attempt['expect'], refused.exception.detail)
        self.assertEqual(installer.calls, [])
        self.assertEqual(deployment_history(self.db), [])

    def test_an_installer_that_lands_the_wrong_artifact_is_refused(self):
        installer = FakeInstaller(result='SOMETHING-ELSE')
        with self.assertRaises(CrucibleError) as refused:
            self.ship(installer)
        self.assertEqual(refused.exception.reason, REASON_INSTALLED_MISMATCH)
        self.assertEqual(deployment_history(self.db), [],
                         'a deployment that cannot be corroborated is not recorded as one')

    # ------------------------------------------------------------------ Gate E
    def test_the_canonical_pointer_is_the_answer_and_the_filesystem_corroborates(self):
        self.ship(FakeInstaller())
        self.assertEqual(canonical_active_candidate(self.db, ROLE), self.candidate.candidate_id)
        self.assertEqual(verify_active_consistency(self.db, role=ROLE, observed_artifact_digest='H1'),
                         CONSISTENT)
        # The canonical pointer says C1 but the installed bytes are the baseline: a conflict, never a
        # silent choice of one over the other.
        self.assertEqual(verify_active_consistency(self.db, role=ROLE, observed_artifact_digest='H0'),
                         DEPLOYMENT_INTEGRITY_CONFLICT)
        self.assertEqual(verify_active_consistency(self.db, role=ROLE,
                                                   observed_artifact_digest='H9'),
                         DEPLOYMENT_INTEGRITY_CONFLICT)

    # ------------------------------------------------------------------ structure
    def test_the_gateway_is_the_only_deployment_path(self):
        source = inspect.getsource(deployment_module)
        self.assertNotIn('file_activation', source)
        public = [name for name, _ in inspect.getmembers(deployment_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('install_directly', 'bypass', 'force_deploy', 'activate_file'):
            self.assertNotIn(forbidden, public)
        self.assertIn('installer', inspect.signature(deploy).parameters)

    # ------------------------------------------------------------------ determinism
    def test_deployment_records_are_append_only_and_reproducible(self):
        self.ship(FakeInstaller())
        expected = deployment_digest(self.db)
        self.assertEqual(deployment_digest(self.db), expected)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.evolution_deployment import deployment_digest;'
                'print(deployment_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)
        record = deployment_history(self.db)[0]
        self.assertEqual(get_deployment(self.db, record.deployment_id).as_dict(), record.as_dict())


if __name__ == '__main__':
    unittest.main()
