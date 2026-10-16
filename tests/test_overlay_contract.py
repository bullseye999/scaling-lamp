"""Contract test: the staged-overlay collector validates co-dependent candidate artifacts."""

import pathlib
import tempfile
import unittest

from transactional_edit import (
    GeneratedContentInvalid,
    collect_test_node_ids_with_overlay,
)

DISK_PRODUCTION = "OLD_SYMBOL = 1\n"
CANDIDATE_PRODUCTION = "OLD_SYMBOL = 1\nNEW_SYMBOL = 2\n"

CANDIDATE_TEST = "\n".join([
    "import unittest",
    "from pkg.production import NEW_SYMBOL",
    "",
    "",
    "class PairTests(unittest.TestCase):",
    "",
    "    def test_symbol_available(self):",
    "        self.assertEqual(NEW_SYMBOL, 2)",
    "",
])


class OverlayContractTests(unittest.TestCase):

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp(prefix="overlay_repo_"))
        package = self.repo / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        self.production = package / "production.py"
        self.production.write_text(DISK_PRODUCTION, encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_plain_collection_against_disk_fails(self):
        with self.assertRaises(GeneratedContentInvalid) as caught:
            collect_test_node_ids_with_overlay(
                "cand_pair_test", CANDIDATE_TEST, {}, repo_root=self.repo
            )
        self.assertIn("STAGED_COLLECTION_FAILED", str(caught.exception))

    def test_overlay_collection_succeeds_with_the_candidate_pair(self):
        nodes = collect_test_node_ids_with_overlay(
            "cand_pair_test",
            CANDIDATE_TEST,
            {"pkg/production.py": CANDIDATE_PRODUCTION},
            repo_root=self.repo,
        )
        self.assertEqual(nodes, ["PairTests.test_symbol_available"])

    def test_the_inverse_fails_when_the_candidate_lacks_the_symbol(self):
        with self.assertRaises(GeneratedContentInvalid):
            collect_test_node_ids_with_overlay(
                "cand_pair_test",
                CANDIDATE_TEST,
                {"pkg/production.py": DISK_PRODUCTION},
                repo_root=self.repo,
            )

    def test_the_real_repository_is_untouched(self):
        before = self.production.read_bytes()
        collect_test_node_ids_with_overlay(
            "cand_pair_test",
            CANDIDATE_TEST,
            {"pkg/production.py": CANDIDATE_PRODUCTION},
            repo_root=self.repo,
        )
        self.assertEqual(self.production.read_bytes(), before)



class PackageFidelityTests(unittest.TestCase):
    """
    Proves the validation environment reproduces the real package, not a synthetic one.

    Empty __init__.py markers would fail here twice over: they discard the real package's
    exports, and they make the package directory point at the overlay so unstaged siblings
    disappear. Both would corrupt the very environment the candidate is validated inside.
    """

    def setUp(self):
        self.repo = pathlib.Path(tempfile.mkdtemp(prefix="fidelity_repo_"))
        package = self.repo / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("PACKAGE_VALUE = 42\n", encoding="utf-8")
        (package / "helper.py").write_text("HELPER_VALUE = 7\n", encoding="utf-8")
        self.production = package / "production.py"
        self.production.write_text(
            "from pkg import PACKAGE_VALUE\n"
            "from pkg.helper import HELPER_VALUE\n"
            "OLD_SYMBOL = 1\n",
            encoding="utf-8",
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.repo, ignore_errors=True)

    def test_candidate_leaf_sibling_and_package_semantics_all_hold(self):
        candidate = (
            "from pkg import PACKAGE_VALUE\n"
            "from pkg.helper import HELPER_VALUE\n"
            "OLD_SYMBOL = 1\n"
            "NEW_SYMBOL = 2\n"
        )
        test_source = "\n".join([
            "import unittest",
            "from pkg.production import NEW_SYMBOL, PACKAGE_VALUE, HELPER_VALUE",
            "",
            "",
            "class FidelityTests(unittest.TestCase):",
            "",
            "    def test_environment_fidelity(self):",
            "        self.assertEqual((NEW_SYMBOL, PACKAGE_VALUE, HELPER_VALUE), (2, 42, 7))",
            "",
        ])

        nodes = collect_test_node_ids_with_overlay(
            "fidelity_test", test_source,
            {"pkg/production.py": candidate},
            repo_root=self.repo,
        )
        self.assertEqual(nodes, ["FidelityTests.test_environment_fidelity"])
        self.assertEqual(
            self.production.read_text(encoding="utf-8").count("NEW_SYMBOL"), 0,
            "the real repository must not have been modified",
        )

if __name__ == "__main__":
    unittest.main()
