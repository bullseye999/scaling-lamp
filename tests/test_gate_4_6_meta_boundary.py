"""
4.6 Gate Six - the meta-evolution boundary.

    Ordinary self-improvement may not improve the machinery that generates or judges improvements.
"""

import inspect
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import meta_evolution as meta_module
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.meta_evolution import (
    META_EVOLUTION_BOUNDARY_V1,
    REVIEW_OPERATOR_ARCHITECTURE,
    assert_ordinary_candidate_scope,
    is_meta_target,
    meta_boundary_digest,
    meta_request_history,
    recursive_generation_enabled,
    request_meta_evolution,
)

ORDINARY = ['ciph/capabilities/planner.py']


class TestGate46MetaBoundary(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-46-meta-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ laws 1-4, 9
    def test_laws_1_to_4_the_machinery_is_not_an_ordinary_candidate_target(self):
        for path in ('ciph/kernel/candidate_construction.py',
                     'ciph/kernel/candidate_safety.py',
                     'ciph/kernel/crucible_metrics.py',
                     'ciph/kernel/crucible_promotion.py',
                     'ciph/kernel/execution_authority.py',
                     'ciph/kernel/permit_store.py',
                     'ciph/kernel/vault_identity.py',
                     'ciph/evolution/gap_detector.py'):
            with self.subTest(path=path):
                self.assertTrue(is_meta_target([path])[0])
        self.assertFalse(is_meta_target(ORDINARY)[0])
        # An ordinary capability change passes; a dependency reaching the Crucible does not.
        assert_ordinary_candidate_scope(self.db, changed_files=ORDINARY)
        with self.assertRaises(CrucibleError) as dependency:
            assert_ordinary_candidate_scope(
                self.db, changed_files=ORDINARY,
                new_dependencies=['ciph/kernel/crucible_metrics.py'])
        self.assertEqual(dependency.exception.reason,
                         'META_EVOLUTION_REQUIRES_ARCHITECTURE_REVIEW')

    # ------------------------------------------------------------------ law 8
    def test_law_8_meta_changes_cannot_hide_inside_an_unrelated_diff(self):
        with self.assertRaises(CrucibleError) as smuggled:
            assert_ordinary_candidate_scope(self.db,
                                            changed_files=ORDINARY + ['ciph/kernel/crucible_metrics.py'])
        self.assertEqual(smuggled.exception.reason, 'META_EVOLUTION_REQUIRES_ARCHITECTURE_REVIEW')
        with self.assertRaises(CrucibleError):
            assert_ordinary_candidate_scope(self.db, changed_files=ORDINARY,
                                            new_dependencies=['ciph/kernel/candidate_safety.py'])
        assert_ordinary_candidate_scope(self.db, changed_files=ORDINARY)

    # ------------------------------------------------------------------ laws 5, 6, 7, 10
    def test_laws_5_to_7_and_10_a_meta_request_carries_no_authority(self):
        request = request_meta_evolution(self.db, target_component='ciph/kernel/crucible_metrics.py',
                                         proposed_change='weight latency less',
                                         reason='planner candidates keep losing on latency',
                                         evidence_refs=['IAT-1', 'IAT-2'], requested_by='ciph',
                                         now=self.t1)
        self.assertEqual(request.required_review_class, REVIEW_OPERATOR_ARCHITECTURE)
        self.assertFalse(request.creates_authority)
        self.assertEqual(len(meta_request_history(self.db)), 1)
        self.assertFalse(recursive_generation_enabled())
        public = [name for name, _ in inspect.getmembers(meta_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('promote', 'deploy', 'register_candidate', 'issue_permit'):
            self.assertNotIn(forbidden, public)
        self.assertEqual(META_EVOLUTION_BOUNDARY_V1, 'META_EVOLUTION_BOUNDARY_V1')
        self.assertTrue(meta_boundary_digest(self.db))


if __name__ == '__main__':
    unittest.main()
