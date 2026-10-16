"""
Proof that the transactional edit helper is actually atomic.

The helper failed once in exactly the way it claims to prevent: anchor 1 written, anchor 2 missing,
file left referencing an unimported name. That made "verify everything before writing" a claim
about the helper rather than a verified property. These tests are what turns it into a property.

The load-bearing assertion is not "it raises" - it is "the file's bytes are identical afterwards".
"""

import pathlib
import tempfile
import unittest

from transactional_edit import (
    GeneratedContentInvalid,
    apply_batch_transaction,
    PreconditionFailed,
    replace_file_generated,
    TransactionalEditError,
    apply_edits,
    file_digest,
)


class TransactionalEditTests(unittest.TestCase):

    def setUp(self):
        handle, self.path = tempfile.mkstemp(prefix="test_txn_", suffix=".txt")
        import os
        os.close(handle)
        self.original = "alpha\nbeta\ngamma\n"
        pathlib.Path(self.path).write_text(self.original, encoding="utf-8")

    def tearDown(self):
        import os
        try:
            os.remove(self.path)
        except OSError:
            pass

    def test_missing_anchor_leaves_the_file_byte_identical(self):
        """The exact historical failure: a later anchor is absent."""
        before = file_digest(self.path)
        edits = [
            ("alpha", "ALPHA", "first"),
            ("this anchor does not exist", "x", "second"),
        ]
        with self.assertRaises(TransactionalEditError) as caught:
            apply_edits(self.path, edits)
        self.assertEqual(caught.exception.tag, "second")
        self.assertEqual(
            file_digest(self.path), before,
            "a failed edit must not have written anything, including the edits that matched",
        )
        self.assertEqual(pathlib.Path(self.path).read_text(), self.original)

    def test_the_first_matching_edit_is_also_not_written(self):
        """"Verify before write" means the matching edit is discarded too, not just the failure."""
        before = file_digest(self.path)
        with self.assertRaises(TransactionalEditError):
            apply_edits(self.path, [
                ("beta", "BETA", "ok"),
                ("absent", "x", "bad"),
            ])
        self.assertEqual(file_digest(self.path), before)
        self.assertNotIn("BETA", pathlib.Path(self.path).read_text())

    def test_ambiguous_anchor_is_refused(self):
        before = file_digest(self.path)
        with self.assertRaises(TransactionalEditError) as caught:
            apply_edits(self.path, [("a", "z", "ambiguous")])
        # The property is "not exactly one", not a specific count: hand-counting characters is
        # how a test encodes the author's arithmetic instead of the contract.
        self.assertGreater(caught.exception.found, 1)
        self.assertEqual(file_digest(self.path), before)

    def test_valid_edits_write_once_and_report_what_landed(self):
        digest = apply_edits(self.path, [
            ("alpha", "ALPHA", "one"),
            ("gamma", "GAMMA", "two"),
        ])
        content = pathlib.Path(self.path).read_text()
        self.assertEqual(content, "ALPHA\nbeta\nGAMMA\n")
        self.assertEqual(digest, file_digest(self.path))

    def test_a_stale_precondition_refuses_the_edit(self):
        """A stale generation must surface as a conflict, not land in the wrong place."""
        before = file_digest(self.path)
        with self.assertRaises(PreconditionFailed) as caught:
            apply_edits(
                self.path,
                [("alpha", "ALPHA", "one")],
                expected_old_hash="0" * 64,
            )
        self.assertEqual(caught.exception.actual, before)
        self.assertEqual(file_digest(self.path), before)
        self.assertEqual(pathlib.Path(self.path).read_text(), self.original)

    def test_a_matching_precondition_permits_the_edit(self):
        before = file_digest(self.path)
        digest = apply_edits(
            self.path,
            [("alpha", "ALPHA", "one")],
            expected_old_hash=before,
        )
        self.assertNotEqual(digest, before)
        self.assertEqual(pathlib.Path(self.path).read_text(), "ALPHA\nbeta\ngamma\n")

    def test_omitting_the_precondition_keeps_prior_behaviour(self):
        digest = apply_edits(self.path, [("beta", "BETA", "one")])
        self.assertEqual(digest, file_digest(self.path))

    def test_empty_edit_list_is_a_no_op(self):
        before = file_digest(self.path)
        digest = apply_edits(self.path, [])
        self.assertEqual(digest, before)


GENERATED_OK = """
import unittest


class GeneratedTests(unittest.TestCase):

    def test_alpha(self):
        self.assertTrue(True)

    def test_beta(self):
        self.assertTrue(True)
"""

class WholeFileGenerationTests(unittest.TestCase):

    def setUp(self):
        # Own fixture: this class overrides the base setUp, so it must create the temp file itself.
        import os as _os
        handle, self.path = tempfile.mkstemp(prefix="test_gen_", suffix=".py")
        _os.close(handle)
        pathlib.Path(self.path).write_text("original\n", encoding="utf-8")
        self.target = pathlib.Path(self.path)

    def tearDown(self):
        import os as _os
        try:
            _os.remove(self.path)
        except OSError:
            pass

    def _expected_nodes(self):
        return [
            "GeneratedTests.test_alpha",
            "GeneratedTests.test_beta",
        ]

    def test_a_stale_generation_is_refused(self):
        before = file_digest(self.path)
        with self.assertRaises(PreconditionFailed):
            replace_file_generated(
                self.path, GENERATED_OK,
                expected_old_hash="0" * 64,
                expected_test_nodes=self._expected_nodes(),
            )
        self.assertEqual(file_digest(self.path), before)

    def test_content_that_does_not_compile_is_refused(self):
        before = file_digest(self.path)
        with self.assertRaises(GeneratedContentInvalid) as caught:
            replace_file_generated(
                self.path, "def broken(:\n    pass\n",
                expected_old_hash=before,
            )
        self.assertIn("DOES_NOT_COMPILE", str(caught.exception))
        self.assertEqual(file_digest(self.path), before)

    def test_a_node_set_mismatch_is_refused_even_when_the_count_matches(self):
        """
        The reason a count check is insufficient: a misplaced regeneration can preserve the
        number of tests while replacing or moving one.
        """
        before = file_digest(self.path)
        with self.assertRaises(GeneratedContentInvalid) as caught:
            replace_file_generated(
                self.path, GENERATED_OK,
                expected_old_hash=before,
                expected_test_nodes=["GeneratedTests.test_alpha", "GeneratedTests.test_gamma"],
            )
        self.assertIn("NODES_MISMATCH", str(caught.exception))
        self.assertEqual(file_digest(self.path), before)

    def test_a_correct_generation_lands_and_collects_from_the_final_path(self):
        before = file_digest(self.path)
        digest = replace_file_generated(
            self.path, GENERATED_OK,
            expected_old_hash=before,
            expected_test_nodes=self._expected_nodes(),
        )
        self.assertNotEqual(digest, before)
        self.assertEqual(digest, file_digest(self.path))
        self.assertIn("test_beta", self.target.read_text())

class BatchTransactionTests(unittest.TestCase):

    def setUp(self):
        import os as _os
        self.paths = []
        for name in ("one", "two", "three"):
            handle, path = tempfile.mkstemp(prefix=f"test_batch_{name}_", suffix=".txt")
            _os.close(handle)
            pathlib.Path(path).write_text(f"content of {name}\n", encoding="utf-8")
            self.paths.append(path)

    def tearDown(self):
        import os as _os
        for path in self.paths:
            try:
                _os.remove(path)
            except OSError:
                pass

    def test_a_failure_on_the_last_file_leaves_every_file_untouched(self):
        """
        The property per-file atomicity cannot give: production and half the call sites migrated
        is a worse state than not starting, because it invites a compatibility escape hatch.
        """
        before = [file_digest(p) for p in self.paths]
        replacements = [
            (self.paths[0], "rewritten one\n", before[0]),
            (self.paths[1], "rewritten two\n", before[1]),
            (self.paths[2], "rewritten three\n", "0" * 64),   # stale on purpose
        ]
        with self.assertRaises(PreconditionFailed):
            apply_batch_transaction(replacements)
        self.assertEqual([file_digest(p) for p in self.paths], before)

    def test_a_staged_check_failure_also_leaves_every_file_untouched(self):
        before = [file_digest(p) for p in self.paths]
        replacements = [(p, "rewritten\n", before[i]) for i, p in enumerate(self.paths)]

        def _refuse(staged):
            raise GeneratedContentInvalid("POSTCONDITION_FAILED: escape hatch still present")

        with self.assertRaises(GeneratedContentInvalid):
            apply_batch_transaction(replacements, staged_checks=[_refuse])
        self.assertEqual([file_digest(p) for p in self.paths], before)

    def test_a_clean_batch_commits_every_file(self):
        before = [file_digest(p) for p in self.paths]
        replacements = [(p, "rewritten\n", before[i]) for i, p in enumerate(self.paths)]
        digests = apply_batch_transaction(replacements)
        self.assertEqual(len(digests), 3)
        for path in self.paths:
            self.assertEqual(pathlib.Path(path).read_text(), "rewritten\n")
            self.assertEqual(digests[path], file_digest(path))

    def test_a_mid_commit_failure_rolls_back_every_file_already_written(self):
        """
        Commit phase, not just validation. Without rollback a failure on the third write leaves
        the first two migrated, which is the half-migrated repository this helper exists to
        prevent. The third target is a directory, so its write fails after two have succeeded.
        """
        import shutil
        before = [file_digest(p) for p in self.paths]
        directory = tempfile.mkdtemp(prefix="test_batch_dir_")
        try:
            replacements = [
                (self.paths[0], "rewritten one\n", before[0]),
                (self.paths[1], "rewritten two\n", before[1]),
                (directory, "cannot write this\n", None),
            ]
            with self.assertRaises(Exception):
                apply_batch_transaction(replacements)
            self.assertEqual(
                [file_digest(p) for p in self.paths], before,
                "a commit-phase failure must restore every file already replaced",
            )
        finally:
            shutil.rmtree(directory, ignore_errors=True)

    def test_every_file_is_untouched_when_the_first_write_fails(self):
        import shutil
        before = [file_digest(p) for p in self.paths]
        directory = tempfile.mkdtemp(prefix="test_batch_dir2_")
        try:
            with self.assertRaises(Exception):
                apply_batch_transaction([(directory, "x\n", None)])
            self.assertEqual([file_digest(p) for p in self.paths], before)
        finally:
            shutil.rmtree(directory, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
