
"""
Gate A0 architectural test - S2.4: the production queue boundary requires a permit.

The production API cannot accept a permitless durable job, and the legacy/test seam must have zero
production callers. A scanner, not a convention: the point is that the old capability is not merely
discouraged, it is absent from production source.
"""

import ast
import pathlib
import unittest

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "ciph"
LEGACY_SEAM = "enqueue_legacy_job_for_test"


class ProductionQueueBoundaryTests(unittest.TestCase):

    def _production_sources(self):
        for path in sorted(PACKAGE_ROOT.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            yield path, path.read_text(encoding="utf-8")

    def test_no_production_caller_uses_the_legacy_seam(self):
        # `workers/ipc_queue.py` DEFINES the seam; the scan is for callers of it elsewhere.
        offenders = [
            str(path.relative_to(PACKAGE_ROOT))
            for path, text in self._production_sources()
            if LEGACY_SEAM in text and path.name != "ipc_queue.py"
        ]
        self.assertEqual(
            offenders, [],
            f"production code uses the legacy/test enqueue seam: {offenders}. That seam exists only "
            "for historical fixtures; production must go through enqueue_job(..., execution_permit=).",
        )

    def test_every_production_enqueue_passes_a_permit(self):
        """Structural: a production enqueue without a permit must not exist as source."""
        missing = []
        for path, text in self._production_sources():
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "enqueue_job"):
                    keywords = {k.arg for k in node.keywords if k.arg}
                    if "execution_permit" not in keywords:
                        missing.append(f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno}")
        self.assertEqual(
            missing, [],
            f"production enqueue call(s) without execution_permit: {missing}",
        )

    def test_the_production_api_structurally_requires_the_permit(self):
        """No default: omitting it is a TypeError, not a silently-legacy job."""
        source = (PACKAGE_ROOT / "workers/ipc_queue.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        sig = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "enqueue_job":
                sig = node
        self.assertIsNotNone(sig)
        kwonly = {a.arg for a in sig.args.kwonlyargs}
        self.assertIn("execution_permit", kwonly, "execution_permit must be keyword-only")
        required = [
            a.arg for a, default in zip(sig.args.kwonlyargs, sig.args.kw_defaults)
            if default is None
        ]
        self.assertIn("execution_permit", required, "execution_permit must have no default")
        positional = {a.arg for a in sig.args.args}
        self.assertNotIn("execution_permit", positional)

    def test_the_scanner_would_catch_a_legacy_production_call(self):
        sample = 'q.enqueue_legacy_job_for_test(capability="x", params={})\n'
        self.assertIn(LEGACY_SEAM, sample)
        tree = ast.parse('q.enqueue_job(capability="x", params={})\n')
        found = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "enqueue_job"
            and "execution_permit" not in {k.arg for k in n.keywords}
        ]
        self.assertEqual(len(found), 1)

    def test_the_legacy_seam_is_distinct_and_explicitly_named(self):
        source = (PACKAGE_ROOT / "workers/ipc_queue.py").read_text(encoding="utf-8")
        self.assertIn(f"def {LEGACY_SEAM}(", source)
        self.assertIn("LEGACY/TEST ONLY", source)


if __name__ == "__main__":
    unittest.main()
