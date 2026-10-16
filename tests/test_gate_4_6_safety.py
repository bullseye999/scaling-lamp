"""
4.6 Gate Three - candidate safety review.

    Pre-evaluation admissibility, not performance.

The load-bearing specimen: a candidate whose description says one thing and whose diff touches the
Crucible is judged by the DIFF.
"""

import inspect
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import candidate_safety as safety_module
from ciph.kernel.candidate_safety import (
    CANDIDATE_SAFETY_POLICY_V1,
    GENERATOR_SURFACES,
    PROTECTED_SURFACES,
    REASON_DEPENDENCY_GROWTH,
    REASON_DIFF_EMPTY,
    REASON_GENERATOR_SURFACE,
    REASON_PRIVILEGE_SURFACE,
    REASON_PROTECTED_SURFACE,
    VERDICT_ADMISSIBLE,
    VERDICT_ARCHITECTURE_REVIEW,
    VERDICT_REJECTED,
    is_admissible,
    review_candidate,
    reviews_for,
    safety_digest,
)
from ciph.kernel.crucible_candidates import register_candidate
from ciph.kernel.crucible_types import KIND_CAPABILITY_IMPLEMENTATION

ORDINARY = ['ciph/capabilities/planner.py']


class TestGate46Safety(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-46-safety-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.candidate = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                            artifact_digest='H1', configuration_digest='C1',
                                            now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def review(self, *, files=ORDINARY, **kwargs):
        return review_candidate(self.db, candidate_id=self.candidate.candidate_id,
                                changed_files=files, now=self.t1, **kwargs)

    # ------------------------------------------------------------------ founding
    def test_founding_an_ordinary_capability_change_is_admissible(self):
        review = self.review()
        self.assertEqual(review.verdict, VERDICT_ADMISSIBLE)
        self.assertEqual(review.reason_codes, ())
        self.assertEqual(review.policy_version, CANDIDATE_SAFETY_POLICY_V1)
        self.assertTrue(is_admissible(self.db, self.candidate.candidate_id))
        self.assertEqual(len(PROTECTED_SURFACES), len(set(PROTECTED_SURFACES)))
        self.assertGreater(len(PROTECTED_SURFACES), 10)

    # ------------------------------------------------------------------ law 9
    def test_law_9_the_review_reads_the_diff_not_the_description(self):
        review = self.review(files=['ciph/kernel/crucible_promotion.py'],
                             declared_description='optimize planner latency only')
        self.assertEqual(review.verdict, VERDICT_ARCHITECTURE_REVIEW)
        self.assertIn(REASON_PROTECTED_SURFACE, review.reason_codes)
        self.assertIn('ciph/kernel/crucible_promotion.py', review.constitutional_touchpoints)

    # ------------------------------------------------------------------ laws 5, 6, 7, 8
    def test_every_protected_surface_class_requires_architecture_review(self):
        cases = [
            (['ciph/kernel/execution_authority.py'], REASON_PROTECTED_SURFACE),
            (['ciph/kernel/permit_store.py'], REASON_PROTECTED_SURFACE),
            (['ciph/kernel/vault_identity.py'], REASON_PROTECTED_SURFACE),
            (['ciph/kernel/candidate_construction.py'], REASON_GENERATOR_SURFACE),
            (['ciph/evolution/gap_detector.py'], REASON_GENERATOR_SURFACE),
        ]
        for files, expected in cases:
            with self.subTest(files=files):
                review = self.review(files=files)
                self.assertEqual(review.verdict, VERDICT_ARCHITECTURE_REVIEW)
                self.assertIn(expected, review.reason_codes)
        self.assertFalse(is_admissible(self.db, self.candidate.candidate_id))
        growth = self.review(files=ORDINARY, new_dependencies=['ciph/kernel/crucible_metrics.py'])
        self.assertEqual(growth.verdict, VERDICT_ARCHITECTURE_REVIEW)
        self.assertIn(REASON_DEPENDENCY_GROWTH, growth.reason_codes)
        privileges = self.review(files=ORDINARY, privilege_delta={'signer': True})
        self.assertEqual(privileges.verdict, VERDICT_ARCHITECTURE_REVIEW)
        self.assertIn(REASON_PRIVILEGE_SURFACE, privileges.reason_codes)

    # ------------------------------------------------------------------ laws 1, 3, 4
    def test_an_empty_diff_is_rejected_and_the_policy_cannot_be_edited(self):
        review = self.review(files=[])
        self.assertEqual(review.verdict, VERDICT_REJECTED)
        self.assertIn(REASON_DIFF_EMPTY, review.reason_codes)
        public = [name for name, _ in inspect.getmembers(safety_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('set_policy', 'add_protected_surface', 'relax_review',
                          'override_verdict'):
            self.assertNotIn(forbidden, public)
        # Law 3: admissibility is the LATEST review, and one ADMISSIBLE does not outlive a later fail.
        self.review()
        self.assertTrue(is_admissible(self.db, self.candidate.candidate_id))
        self.review(files=['ciph/kernel/crucible_metrics.py'])
        self.assertFalse(is_admissible(self.db, self.candidate.candidate_id))
        self.assertEqual(len(reviews_for(self.db, self.candidate.candidate_id)), 3)
        self.assertTrue(safety_digest(self.db))


if __name__ == '__main__':
    unittest.main()
