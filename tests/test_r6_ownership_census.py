"""
R6 Gate A - ownership census.

    There may be many MECHANISMS for testing and deploying candidates, but exactly one constitutional
    OWNER for candidate identity, comparative standing, promotion, active state and rollback lineage.

Every specimen is written so that a second owner of a constitutional concern - the R4 defect class, one
level up - would be a test failure rather than a discovery.
"""

import pathlib
import tempfile
import unittest

from ciph.kernel import evolution_ownership as ownership
from ciph.kernel.evolution_ownership import (
    CENSUS,
    RETAINED_MACHINERY,
    activation_bypasses,
    canonical_owner_count,
    canonical_owners,
    ownership_matrix,
    ownership_report,
    ownership_violations,
    production_sources,
    retained_machinery_missing,
)

CONSTITUTIONAL_CONCERNS = ("candidate identity", "evaluation protocol", "trial identity",
                           "comparison verdict", "promotion state", "active candidate pointer",
                           "rollback lineage", "regression verdict", "deployment record")


class TestR6OwnershipCensus(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-r6-census-')

    def tearDown(self):
        self.temp.cleanup()

    def synthetic_tree(self, files):
        root = pathlib.Path(self.temp.name)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        return root

    # ------------------------------------------------------------------ the census itself
    def test_every_constitutional_concern_has_exactly_one_owner(self):
        matrix = {entry['concern']: entry for entry in ownership_matrix()}
        for concern in CONSTITUTIONAL_CONCERNS:
            self.assertIn(concern, matrix)
            self.assertFalse(matrix[concern]['legacy_ownership_allowed'],
                             f'{concern} must not be owned by legacy code')
            self.assertEqual(canonical_owner_count(concern), 1,
                             f'{concern} must have exactly one canonical owner')
            self.assertNotEqual(canonical_owners(concern), (),
                                f'{concern} must name a canonical owner')
        for concern in matrix.values():
            if concern['legacy_ownership_allowed']:
                self.assertIn('ciph/evolution/', concern['canonical_owner'],
                              'only the old machinery may own a concern outright')

    def test_the_project_has_no_ownership_violation_and_no_activation_bypass(self):
        report = ownership_report()
        self.assertEqual(report['violations'], (),
                         f'a second owner exists: {report["violations"]}')
        self.assertEqual(report['activation_bypasses'], (),
                         'the physical file swap must have zero direct call sites')
        self.assertEqual(report['retained_machinery_missing'], (),
                         'R6 demotes the machinery, it does not remove it')

    def test_the_demoted_machinery_is_still_present(self):
        for relative, symbols in RETAINED_MACHINERY:
            self.assertTrue((pathlib.Path(ownership._PROJECT_ROOT) / relative).exists())
            self.assertTrue(symbols)
        source = (pathlib.Path(ownership._PROJECT_ROOT) / 'ciph/evolution/workflow.py').read_text()
        self.assertIn('class EvolutionCoordinator', source)
        self.assertIn('def _install', source)

    # ------------------------------------------------------------------ catch-specimens
    def test_the_scanner_detects_a_second_owner(self):
        """A scanner that never fires is not a scanner."""
        root = self.synthetic_tree({
            'ciph/evolution/rogue.py': (
                'CREATE TABLE IF NOT EXISTS ciph_crucible_active (role TEXT PRIMARY KEY, '
                'candidate_id TEXT NOT NULL);\n'),
            'ciph/kernel/innocent.py': 'VALUE = 1\n',
        })
        violations = ownership_violations(root)
        self.assertTrue(violations)
        self.assertEqual(violations[0]['concern'], 'active candidate pointer')
        self.assertEqual(violations[0]['offender'], 'ciph/evolution/rogue.py')

    def test_the_scanner_detects_a_direct_activation_bypass(self):
        root = self.synthetic_tree({
            'ciph/evolution/rogue_deploy.py': (
                'from ciph.evolution.file_activation import activate\n'
                'def ship(artifact, grant, store):\n'
                '    return activate(artifact, grant, store)\n'),
        })
        self.assertTrue(activation_bypasses(root))

    def test_the_scanner_detects_missing_machinery(self):
        root = self.synthetic_tree({'ciph/evolution/workflow.py': 'X = 1\n'})
        missing = retained_machinery_missing(root)
        self.assertTrue(any('EvolutionCoordinator' in entry for entry in missing))
        self.assertTrue(any('MISSING_FILE' in entry for entry in missing))

    def test_the_census_and_the_scan_are_deterministic(self):
        first = ownership_report()
        second = ownership_report()
        self.assertEqual(first, second)
        sources = production_sources()
        self.assertGreater(len(sources), 50)
        self.assertFalse([relative for relative, _ in sources if relative.startswith('test_')])
        self.assertTrue(any(relative.endswith('crucible_promotion.py') for relative, _ in sources))


if __name__ == '__main__':
    unittest.main()
