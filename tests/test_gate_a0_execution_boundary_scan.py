"""
Gate A0 architectural test - only the execution boundary may touch raw capability execution.

Register items 0.5 and 0.15. Decision of record: D2.

WHY THIS TEST EXISTS IN ADDITION TO THE ROUTE TESTS
Route enumeration proves "every path I know today crosses the boundary". This scan proves
"a path I have not thought of yet cannot reach the primitive". Ciph 6.0 adding
`ciph/swarm/executor.py` with a direct `cap.execute(...)` is caught here without anybody
remembering to update a route list.

It is a static scan on purpose. A runtime test can only exercise call sites that exist.
"""

import pathlib
import re
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "ciph"

# The raw capability execution primitive. Anything matching this is executing a capability body.
RAW_EXECUTION_PATTERN = re.compile(r"\bcap(?:ability)?\.execute\s*\(")

# Files allowed to reference the primitive.
#
# execution_gateway.py  the boundary itself - this is where it belongs
#
# SHRUNK on the S3 daemon flip: `workers/daemon.py` was the last named bypass and is now removed.
# The daemon no longer reaches the primitive at all - it builds a governed request, deserializes the
# carried permit and runs the body through `GuardedExecutor`. Historically here:
#   capabilities/registry.py  - raw `cap.execute` in dispatch(), closed by the provenance cutover
#   workers/daemon.py         - the last named bypass, closed by the S3 daemon flip
ALLOWED_RAW_EXECUTION_FILES = {
    "kernel/execution_gateway.py",
}

# Files that must exist to give the boundary meaning at all.
REQUIRED_BOUNDARY_FILES = {
    "kernel/execution_gateway.py",
}


class ExecutionBoundaryScanTests(unittest.TestCase):

    def _scan(self):
        found = {}
        for path in PACKAGE_ROOT.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if RAW_EXECUTION_PATTERN.search(text):
                found[str(path.relative_to(PACKAGE_ROOT))] = True
        return found

    def test_no_new_file_may_reach_raw_capability_execution(self):
        """
        The enforceable property: adding a new execution path requires editing this allowlist,
        which is a deliberate, visible act rather than an accident.
        """
        found = set(self._scan())
        unexpected = sorted(found - ALLOWED_RAW_EXECUTION_FILES)
        self.assertEqual(
            unexpected, [],
            "New raw capability execution path(s) detected outside the execution boundary: "
            f"{unexpected}. Route them through ciph/kernel/execution_gateway.py, or if this is "
            "a deliberate exception, add the file to ALLOWED_RAW_EXECUTION_FILES and say why.",
        )

    def test_the_boundary_module_exists(self):
        missing = sorted(
            name for name in REQUIRED_BOUNDARY_FILES if not (PACKAGE_ROOT / name).exists()
        )
        self.assertEqual(missing, [], f"execution boundary module(s) missing: {missing}")

    def test_the_remaining_bypasses_are_named_and_bounded(self):
        """
        States the wiring status as testable fact rather than as prose.

        The pending-bypass era is OVER: the allowlist holds nothing but the boundary module itself,
        and this test now asserts that positively rather than reporting a count. If a future change
        reintroduces a raw execution site, `test_no_new_file_may_reach_raw_capability_execution`
        fails until somebody edits the allowlist on purpose - which is the point.
        """
        pending = sorted(
            name for name in ALLOWED_RAW_EXECUTION_FILES
            if name != "kernel/execution_gateway.py"
        )
        self.assertEqual(
            pending, [],
            "The allowlist must describe current reality: the daemon flip is closed, so no "
            f"pending bypass may remain. Found {pending}.",
        )
        found = set(self._scan())
        self.assertNotIn(
            "workers/daemon.py", found,
            "The worker daemon must reach capability execution only through the execution boundary. "
            "A raw primitive here reopens the bypass the S3 flip closed.",
        )

    def test_the_gateway_is_the_sanctioned_execution_point(self):
        """The boundary module must actually contain the guarded execution path."""
        gateway = PACKAGE_ROOT / "kernel/execution_gateway.py"
        text = gateway.read_text(encoding="utf-8")
        self.assertIn("class ExecutionGateway", text)
        self.assertIn("class GuardedExecutor", text)
        # One permit meaning: the signed artifact, minted and verified by the gateway.
        self.assertIn("SignedExecutionPermit", text)
        self.assertIn("ExecutionPermitVerifier", text)
        self.assertIn("DENY_PERMIT_MISSING", text)


if __name__ == "__main__":
    unittest.main()
