"""
4.6 Gate Two - bounded candidate construction.

    Generation has creativity, but no standing.

The load-bearing properties: a candidate can only be written inside staging, construction changes
nothing live, and the only identity that results is the one 4.5 allocates.
"""

import ast
import inspect
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import candidate_construction as construction_module
from ciph.kernel.candidate_construction import (
    CANDIDATE_CONSTRUCTION_V1,
    StagingSandbox,
    construct_candidate,
    construction_history,
)
from ciph.kernel.crucible_candidates import get_candidate, verify_candidate_identity
from ciph.kernel.crucible_promotion import active_candidate
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.improvement_hypotheses import (
    STATUS_PROPOSED,
    ExpectedImprovement,
    hypothesis_status,
    propose_hypothesis,
)
from ciph.kernel.improvement_opportunities import adopt_gap

GAP = {'gap_id': 'GAP-1', 'category': 'MISSING_BEHAVIOR', 'target_capability': 'planner',
       'affected_revision': 'H1', 'failure_evidence_hashes': ['e1', 'e2'],
       'testable_improvement_criterion': 'results match oracle'}
ARTIFACT = b'class Planner:\n    def schedule(self, jobs):\n        return sorted(jobs)\n'


class TestGate46Construction(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-46-construction-')
        self.root = Path(self.temp.name)
        self.db = str(self.root / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.staging = StagingSandbox(self.root / 'staging')
        self.live_file = self.root / 'production' / 'planner.py'
        self.live_file.parent.mkdir(parents=True, exist_ok=True)
        self.live_file.write_text('# the live implementation\n', encoding='utf-8')
        self.live_bytes = self.live_file.read_bytes()
        self.opportunity = adopt_gap(self.db, GAP, environment_identity='host:alpha', now=self.t1)
        self.hypothesis = propose_hypothesis(
            self.db, opportunity_id=self.opportunity.opportunity_id, target_component='planner',
            proposed_change_class='RESCHEDULE_WORKERS',
            expected_improvements=[ExpectedImprovement('task_success', 'HIGHER_BETTER', 0.02)],
            baseline_candidate_id='CC-B0', now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def construct(self, *, name='C1.py', data=ARTIFACT):
        return construct_candidate(self.db, hypothesis_id=self.hypothesis.hypothesis_id,
                                   sandbox=self.staging, artifact_name=name, artifact_bytes=data,
                                   generator_identity='ciph.planner.generator',
                                   generator_version='v1', generator_strategy_id='RESCHEDULE',
                                   now=self.t1)

    # ------------------------------------------------------------------ founding
    def test_founding_construction_writes_to_staging_and_freezes_one_identity(self):
        record = self.construct()
        self.assertEqual(record.status, 'REGISTERED')
        self.assertTrue(record.crucible_candidate_id.startswith('CC-'),
                        '4.5 allocates the identity; 4.6 mints none')
        self.assertEqual(record.generator_identity, 'ciph.planner.generator')
        self.assertEqual(record.generator_version, 'v1')
        self.assertEqual((self.staging.root / 'C1.py').read_bytes(), ARTIFACT)
        candidate = get_candidate(self.db, record.crucible_candidate_id)
        self.assertEqual(candidate.artifact_digest, record.artifact_digest)
        self.assertEqual(candidate.baseline_candidate_id, 'CC-B0')

    # ------------------------------------------------------------------ laws 1, 2, 3, 4
    def test_construction_changes_nothing_live(self):
        before = self.live_file.read_bytes()
        record = self.construct()
        self.assertEqual(self.live_file.read_bytes(), before, 'the live implementation is untouched')
        self.assertEqual(self.live_file.read_bytes(), self.live_bytes)
        self.assertIsNone(active_candidate(self.db, 'planner'), 'no pointer was moved')
        connection = sqlite3.connect(self.db)
        try:
            def count(table):
                try:
                    return connection.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0]
                except sqlite3.Error:
                    return 0
            footprint = {table: count(table) for table in
                         ('execution_permits', 'ciph_ipc_jobs', 'ciph_crucible_promotions',
                          'ciph_crucible_deployments')}
        finally:
            connection.close()
        self.assertEqual(footprint, {'execution_permits': 0, 'ciph_ipc_jobs': 0,
                                     'ciph_crucible_promotions': 0, 'ciph_crucible_deployments': 0})
        self.assertTrue(record.construction_id.startswith('CON-'))

    def test_law_the_generator_cannot_write_outside_staging(self):
        for escape in ('../escape.py', '../../etc/passwd', '/tmp/absolute-escape.py'):
            with self.assertRaises(CrucibleError) as refused:
                self.staging.write(escape, b'x')
            self.assertEqual(refused.exception.reason, 'STAGING_ESCAPE_REFUSED')
        self.assertFalse((self.root / 'escape.py').exists())
        tree = ast.parse(inspect.getsource(construction_module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(entry.name for entry in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or '')
        for forbidden in ('permit', 'execution_authority', 'GuardedExecutor', 'crucible_promotion',
                          'evolution_deployment'):
            self.assertFalse([name for name in imported if forbidden in name], forbidden)

    # ------------------------------------------------------------------ laws 9, 10
    def test_law_9_and_10_a_failed_construction_mints_nothing_and_falsifies_nothing(self):
        record = construct_candidate(self.db, hypothesis_id=self.hypothesis.hypothesis_id,
                                     sandbox=self.staging, artifact_name='../escape.py',
                                     artifact_bytes=b'x', generator_identity='ciph.planner.generator',
                                     now=self.t1)
        self.assertEqual(record.status, 'FAILED')
        self.assertIn('STAGING_ESCAPE_REFUSED', str(record.reason))
        self.assertIsNone(record.crucible_candidate_id, 'no phantom CC-* exists')
        self.assertEqual(len(self._candidates()), 0)
        self.assertEqual(hypothesis_status(self.db, self.hypothesis.hypothesis_id), STATUS_PROPOSED,
                         'a generator failing says nothing about the hypothesis')
        self.assertTrue(list(self.staging.root.glob('*.partial')) == [],
                        'a partial artifact is never left under its final name')

    def _candidates(self):
        connection = sqlite3.connect(self.db)
        try:
            return connection.execute("SELECT candidate_id FROM ciph_crucible_candidates").fetchall()
        except sqlite3.Error:
            return []
        finally:
            connection.close()

    # ------------------------------------------------------------------ laws 7, 12
    def test_law_12_same_bytes_are_one_identity_and_edited_bytes_are_a_new_one(self):
        first = self.construct()
        again = self.construct()
        self.assertEqual(again.crucible_candidate_id, first.crucible_candidate_id)
        edited = self.construct(data=ARTIFACT + b'# tweak\n')
        self.assertNotEqual(edited.crucible_candidate_id, first.crucible_candidate_id)
        with self.assertRaises(CrucibleError) as stale:
            verify_candidate_identity(self.db, first.crucible_candidate_id,
                                      artifact_digest=edited.artifact_digest,
                                      configuration_digest=first.configuration_digest)
        self.assertEqual(stale.exception.reason, 'CANDIDATE_IDENTITY_MISMATCH')
        # Two distinct artifacts are two construction records; the identical rebuild is the first one.
        history = construction_history(self.db)
        self.assertEqual(len(history), 2)
        self.assertEqual(len({item.crucible_candidate_id for item in history}), 2)
        self.assertEqual(CANDIDATE_CONSTRUCTION_V1, 'CANDIDATE_CONSTRUCTION_V1')


if __name__ == '__main__':
    unittest.main()
