"""
4.5 Gate Four - governed promotion.

    Evaluation says DOMINATES. That alone must change NOTHING.
"""

import ast
import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import crucible_promotion as promotion_module
from ciph.kernel.crucible_candidates import register_candidate
from ciph.kernel.crucible_metrics import STATUS_DOMINATES, STATUS_INCOMPARABLE
from ciph.kernel.crucible_promotion import (
    active_candidate,
    get_promotion,
    init_schema,
    promote,
    promotion_digest,
    promotion_history,
    promotion_requirements,
)
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_types import CrucibleError, KIND_PLANNER_STRATEGY

ROLE = 'planner'
METRICS = [MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02)]


class TestGate45Promotion(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-promotion-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.baseline = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY,
                                           artifact_digest='H0', configuration_digest='C0')
        self.candidate = register_candidate(self.db, kind=KIND_PLANNER_STRATEGY,
                                            artifact_digest='H1', configuration_digest='C1',
                                            baseline_candidate_id=self.baseline.candidate_id)
        self.protocol = freeze_protocol(self.db, candidate_kind=KIND_PLANNER_STRATEGY,
                                        development_cases=['d'], heldout_cases=['h'],
                                        metric_definitions=METRICS, environment_identity='host:eval',
                                        minimum_evidence=3, now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def promote(self, *, status=STATUS_DOMINATES, refs=('T1', 'T2', 'T3'), auth='operator:operator',
                candidate=None, now=None):
        return promote(self.db, role=ROLE, candidate_id=(candidate or self.candidate).candidate_id,
                       protocol_id=self.protocol.protocol_id, comparison_status=status,
                       evaluation_refs=refs, authorization_ref=auth,
                       replaced_candidate_id=self.baseline.candidate_id, now=now or self.t1)

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_promotion_is_a_governed_pointer_move(self):
        self.assertIsNone(active_candidate(self.db, ROLE), 'nothing is active before promotion')
        record = self.promote()
        self.assertEqual(active_candidate(self.db, ROLE), self.candidate.candidate_id)
        self.assertEqual(record.replaced_candidate_id, self.baseline.candidate_id)
        self.assertEqual(record.authorization_ref, 'operator:operator')
        # The baseline record is not mutated by being replaced (law 3).
        from ciph.kernel.crucible_candidates import get_candidate
        self.assertEqual(get_candidate(self.db, self.baseline.candidate_id).artifact_digest, 'H0')
        self.assertEqual(len(promotion_history(self.db, ROLE)), 1)

    # ------------------------------------------------------------------ laws 1, 2
    def test_law_1_and_2_promotion_requires_dominance_evidence_and_authorization(self):
        self.assertEqual(promotion_requirements(
            self.db, protocol_id=self.protocol.protocol_id,
            candidate_id=self.candidate.candidate_id, comparison_status=STATUS_DOMINATES,
            evaluation_refs=('T1', 'T2', 'T3'), authorization_ref='operator:operator'), ())
        cases = [
            dict(status=STATUS_INCOMPARABLE, refs=('T1', 'T2', 'T3'), auth='operator:operator'),
            dict(status=STATUS_DOMINATES, refs=('T1',), auth='operator:operator'),
            dict(status=STATUS_DOMINATES, refs=(), auth='operator:operator'),
            dict(status=STATUS_DOMINATES, refs=('T1', 'T2', 'T3'), auth=''),
        ]
        for case in cases:
            with self.assertRaises(CrucibleError) as refused:
                self.promote(**case)
            self.assertEqual(refused.exception.reason, 'PROMOTION_REFUSED')
        self.assertIsNone(active_candidate(self.db, ROLE), 'a refused promotion changes nothing')

    # ------------------------------------------------------------------ law 5
    def test_law_5_a_candidate_cannot_promote_itself(self):
        public = [name for name, _ in inspect.getmembers(promotion_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('self_promote', 'promote_from_candidate', 'apply_candidate_output'):
            self.assertNotIn(forbidden, public)
        tree = ast.parse(inspect.getsource(promotion_module))
        identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        identifiers |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        lowered = {name.lower() for name in identifiers}
        # There is no path from candidate OUTPUT to the pointer: an authorization reference is a
        # required argument of the only function that moves it.
        self.assertNotIn('candidate_output', lowered)
        self.assertIn('authorization_ref', inspect.signature(promote).parameters)

    # ------------------------------------------------------------------ law 4
    def test_law_4_promotion_creates_no_execution_authority(self):
        import sqlite3
        self.promote()
        connection = sqlite3.connect(self.db)
        try:
            def count(table):
                try:
                    return connection.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0]
                except sqlite3.Error:
                    return 0
            counts = {table: count(table) for table in
                      ('execution_permits', 'ciph_ipc_jobs', 'ciph_mission_actions',
                       'ciph_curiosity_investigation_authorizations')}
        finally:
            connection.close()
        self.assertEqual(counts, {'execution_permits': 0, 'ciph_ipc_jobs': 0,
                                  'ciph_mission_actions': 0,
                                  'ciph_curiosity_investigation_authorizations': 0},
                         'becoming the preferred planner grants no authority to act')

    # ------------------------------------------------------------------ determinism / idempotence
    def test_promotion_history_and_digest_are_stable(self):
        self.promote()
        self.promote()
        self.assertEqual(len(promotion_history(self.db, ROLE)), 1,
                         'an identical governed promotion is one record')
        expected = promotion_digest(self.db)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.crucible_promotion import promotion_digest;'
                'print(promotion_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)
        self.assertEqual(get_promotion(self.db, self.promote().promotion_id).role, ROLE)


if __name__ == '__main__':
    unittest.main()
