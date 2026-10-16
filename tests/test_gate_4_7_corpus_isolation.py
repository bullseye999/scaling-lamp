"""
4.7 G4 - the sealed corpus is unreachable BY CONSTRUCTION, not by API courtesy.

The hostile case is a candidate that ignores `CandidateFacingCorpus` entirely: it is handed the exact
path of the sealed database, lists the directory, walks the tree and opens the file. It must fail -
because it runs as a confined child process, not because a method was politely absent.

This reuses `ciph.evolution.isolated_execution`; no second sandbox was built. The limitations are
stated in the module: this is OS-level namespace isolation on the evaluation host, not cryptography.
"""

import inspect
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import meta_corpus_isolation as isolation
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.evolution_ownership import activation_bypasses
from ciph.kernel.meta_corpus import CandidateFacingCorpus, MetaCorpusVault
from ciph.kernel.meta_corpus_isolation import (
    HOSTILE_DISCOVERY_SOURCE,
    assert_sealed_corpus_unreachable,
    probe_host_filesystem,
    probe_receives_corpus_as_data,
)

CORPUS = 'META-CORPUS-ISO'
CONTENT_KEYS = ('open_sealed', 'sqlite_sealed', 'open_public', 'sqlite_public', 'listdir_parent',
                'listdir_root', 'traversal')


class TestGate47CorpusIsolation(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-47-isolation-')
        self.root = Path(self.temp.name)
        self.public = str(self.root / 'meta_corpus.db')
        self.sealed = str(self.root / 'meta_corpus_sealed.db')
        self.vault = MetaCorpusVault(self.public, self.sealed)
        self.vault.register_case(corpus_version=CORPUS, case_kind='EVALUATOR_CASE',
                                 case_input={'situation': 'fabricated evidence'},
                                 adjudication_class='MECHANICAL', expected_result='INVALID',
                                 sealed_payload={'answer': 'INVALID'}, now=1_800_000_000.0)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ the boundary
    def test_a_candidate_told_exactly_where_the_answers_are_still_cannot_read_them(self):
        probe = assert_sealed_corpus_unreachable(sealed_path=self.sealed, public_path=self.public,
                                                 project_root=str(self.root))
        attempts, found = probe['attempts'], probe['found']
        for key in CONTENT_KEYS:
            self.assertIn(key, attempts)
            self.assertNotEqual(attempts[key], 'SUCCEEDED',
                                f'{key} must be denied, got {attempts[key]}')
        self.assertEqual(found['walk_root'], 0, 'the tree is not discoverable either')
        self.assertEqual(found['glob_sealed'], 0, 'and neither is the sealed file by name')
        # The probe is HANDED the exact path it must not reach, so the denial is not an
        # accident of ignorance.
        parameters = set(inspect.signature(probe_host_filesystem).parameters)
        self.assertEqual(parameters, {'sealed_path', 'public_path', 'project_root'})

    def test_the_hostile_probe_is_actually_hostile(self):
        source = HOSTILE_DISCOVERY_SOURCE
        for attempt in ('open', 'sqlite3.connect', 'os.listdir', 'os.walk', 'glob', '..'):
            self.assertIn(attempt, source, f'the probe must attempt {attempt}')

    def test_the_child_is_isolated_not_broken(self):
        """The same machinery delivers the corpus as DATA, which is the intended channel."""
        result = probe_receives_corpus_as_data(cases=[{'case_id': 'MCC-1'}, {'case_id': 'MCC-2'}])
        self.assertEqual(result['case_count'], 2)
        self.assertEqual(result['verdicts'], {'MCC-1': 'INVALID', 'MCC-2': 'INVALID'})

    def test_the_candidate_is_never_handed_a_path_in_the_first_place(self):
        facing = CandidateFacingCorpus(self.public)
        visible = facing.cases(CORPUS)
        self.assertEqual(len(visible), 1)
        for key, value in visible[0].items():
            self.assertNotIn(self.sealed, str(value))
            self.assertNotIn(self.public, str(value))
            self.assertFalse(str(value).startswith('/'), f'{key} leaks a filesystem path')
        self.assertEqual(sorted(name for name in dir(facing) if not name.startswith('_')),
                         ['case_input', 'cases'])

    def test_no_new_sandbox_was_built(self):
        source = inspect.getsource(isolation)
        self.assertIn('execute_candidate', source, 'the existing isolated-execution path is reused')
        for forbidden in ('unshare', 'clone(', 'sandbox_policy', 'RootlessContainerRunner'):
            self.assertNotIn(forbidden, source,
                             'the module must not grow its own isolation mechanism')
        self.assertEqual(activation_bypasses(), (),
                         'and the R6/R7 activation scan is still clean')

    def test_a_missing_sandbox_fails_closed(self):
        """If isolation cannot run, the answer is a refusal - never an unisolated run."""
        from unittest import mock
        with mock.patch.object(isolation, "_run") as patched:
            patched.side_effect = CrucibleError("CANDIDATE_ISOLATION_UNAVAILABLE", "forced")
            with self.assertRaises(CrucibleError) as refused:
                assert_sealed_corpus_unreachable(sealed_path=self.sealed, public_path=self.public)
        self.assertEqual(refused.exception.reason, "CANDIDATE_ISOLATION_UNAVAILABLE")


if __name__ == '__main__':
    unittest.main()
