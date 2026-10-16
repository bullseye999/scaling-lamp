
"""
Gate A0 architectural test - S2.5: legacy isolation and the backlog seal.

S2.4 made the production API require a permit. This pins the two ways that could quietly erode -
a direct `_enqueue_impl` bypass, or a live permitless backlog surviving into S3 - and records the
rule that no permitless row is ever upgraded from an ExecutionToken.
"""

import ast
import pathlib
import tempfile
import unittest

from ciph.workers.ipc_queue import IPCJobQueue

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "ciph"


def _production_sources():
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        yield path, path.read_text(encoding="utf-8")


class LegacyIsolationTests(unittest.TestCase):

    def test_no_production_caller_bypasses_to_the_impl(self):
        """A direct `_enqueue_impl` call would regain permitless production enqueue silently."""
        offenders = []
        for path, text in _production_sources():
            if path.name == "ipc_queue.py":
                continue
            for node in ast.walk(ast.parse(text)):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "_enqueue_impl"):
                    offenders.append(f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [], f"production bypasses the enqueue boundary: {offenders}")

    def test_the_bypass_scanner_would_catch_a_direct_call(self):
        tree = ast.parse("queue._enqueue_impl('cap', {}, 1)\n")
        found = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == "_enqueue_impl"]
        self.assertEqual(len(found), 1)

    def test_the_inventory_never_upgrades_a_row_from_the_token(self):
        """The docstring may describe the refusal; the CODE must not reach for the token."""
        import ast as _ast

        source = (PACKAGE_ROOT / "workers/ipc_queue.py").read_text(encoding="utf-8")
        tree = _ast.parse(source)
        node = next(
            n for n in _ast.walk(tree)
            if isinstance(n, _ast.FunctionDef) and n.name == "permitless_backlog_inventory"
        )
        code_only = "\n".join(
            _ast.get_source_segment(source, stmt) or ""
            for stmt in node.body
            if not (isinstance(stmt, _ast.Expr) and isinstance(stmt.value, _ast.Constant))
        )
        self.assertNotIn("ExecutionToken", code_only)
        self.assertNotIn("scope_payload_json", code_only)


class BacklogSealTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_backlog_")
        self.queue = IPCJobQueue(f"{self._dir}/jobs.db")

    def _enqueue(self, key, permit=None):
        if permit is None:
            return self.queue.enqueue_legacy_job_for_test(
                capability="cap.read", params={"k": "v"}, idempotency_key=key
            )
        return self.queue.enqueue_job(
            capability="cap.read", params={"k": "v"}, idempotency_key=key, execution_permit=permit
        )

    def test_a_live_permitless_row_blocks_the_s3_gate(self):
        self._enqueue("idem-live")
        inv = self.queue.permitless_backlog_inventory()
        self.assertEqual(inv["live_permitless"], 1)
        self.assertFalse(inv["s3_gate_satisfied"])

    def test_a_terminal_permitless_row_is_archival_only(self):
        job_id = self._enqueue("idem-terminal")
        with self.queue._get_connection() as conn:
            conn.execute("UPDATE ciph_ipc_jobs SET status = 'SUCCEEDED' WHERE job_id = ?;", (job_id,))
            conn.commit()
        inv = self.queue.permitless_backlog_inventory()
        self.assertEqual(inv["live_permitless"], 0)
        self.assertEqual(inv["historical_permitless"], 1)
        self.assertTrue(inv["s3_gate_satisfied"])

    def test_an_empty_backlog_satisfies_the_gate(self):
        inv = self.queue.permitless_backlog_inventory()
        self.assertEqual(inv["live_permitless"], 0)
        self.assertTrue(inv["s3_gate_satisfied"])


if __name__ == "__main__":
    unittest.main()
