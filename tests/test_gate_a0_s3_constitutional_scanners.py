
"""
Gate A0 / S3 - the four constitutional invariants, enforced by static scan.

Nearly every S3 defect so far was a *call site* rather than a missing concept: the daemon reaching
the primitive directly, a producer minting a permit, an execution-affecting scope read from the
transport token, a second claim site. Each of those was fixed once; this suite exists so the next
one is a red test rather than a review finding.

    daemon raw cap.execute callers                 = 0
    worker/daemon permit issuers or private signers = 0
    token-derived execution-scope consumers         = 0
    PermitStore.claim outside GuardedExecutor       = 0
"""

import ast
import pathlib
import unittest

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1] / "ciph"
DAEMON = PACKAGE_ROOT / "workers" / "daemon.py"
WORKERS = PACKAGE_ROOT / "workers"
GATEWAY = PACKAGE_ROOT / "kernel" / "execution_gateway.py"


def _sources(root=PACKAGE_ROOT):
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        yield path, path.read_text(encoding="utf-8")


def _rel(path):
    return str(path.relative_to(PACKAGE_ROOT))


def _called_attrs(tree):
    """Every `X.method(...)` call as (method_name, receiver_source, lineno)."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            try:
                receiver = ast.unparse(node.func.value)
            except Exception:
                receiver = ""
            found.append((node.func.attr, receiver, node.lineno))
    return found


def _constructed_names(tree):
    """Every `Name(...)` constructor call as (name, lineno)."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            found.append((node.func.id, node.lineno))
    return found


class RawExecutionScannerTests(unittest.TestCase):

    def test_the_daemon_never_reaches_the_raw_execution_primitive(self):
        text = DAEMON.read_text(encoding="utf-8")
        offenders = [
            f"line {node.lineno}"
            for node in ast.walk(ast.parse(text))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and ast.unparse(node.func.value) in ("cap", "capability")
        ]
        self.assertEqual(offenders, [],
                         "the daemon must run capability bodies only through GuardedExecutor")
        self.assertIn("GuardedExecutor", text,
                      "the daemon must still reach execution through the guarded path")

    def test_the_scanner_would_catch_a_raw_execution_site(self):
        tree = ast.parse("def run():\n    return cap.execute({}, None)\n")
        found = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == "execute"
                 and ast.unparse(n.func.value) == "cap"]
        self.assertEqual(len(found), 1)


class WorkerIssuanceScannerTests(unittest.TestCase):

    # Constructing these is minting authority; asking for `.issue_permit` is delegating the mint to
    # whoever the worker points at. Parsing a permit the job already carries is NOT in this list.
    FORBIDDEN_CONSTRUCTORS = {
        "SignedExecutionPermit",
        "ExecutionAuthority",
        "ExecutionGateway",
    }
    FORBIDDEN_CALLS = {
        "issue_permit",
        "build_durable_permit_dependencies",
        "acquire_durable_permit",
    }
    FORBIDDEN_NAMES = {"EXECUTION_AUTHORITY_KEY_ID"}

    def _offenders(self):
        offenders = []
        for path, text in _sources(WORKERS):
            tree = ast.parse(text)
            for name, lineno in _constructed_names(tree):
                if name in self.FORBIDDEN_CONSTRUCTORS:
                    offenders.append(f"{_rel(path)}:{lineno}:{name}()")
            for attr, receiver, lineno in _called_attrs(tree):
                if attr in self.FORBIDDEN_CALLS:
                    offenders.append(f"{_rel(path)}:{lineno}:{receiver}.{attr}()")
            for name in self.FORBIDDEN_NAMES:
                if name in text:
                    offenders.append(f"{_rel(path)}:{name}")
        return offenders

    def test_no_worker_module_can_mint_or_sign_execution_authority(self):
        self.assertEqual(self._offenders(), [],
                         "the worker may carry authority; it may never create or sign it")

    def test_the_scanner_would_catch_a_minting_site(self):
        tree = ast.parse("p = SignedExecutionPermit(payload)\nq = gateway.issue_permit(req)\n")
        names = {n for n, _ in _constructed_names(tree)}
        attrs = {a for a, _, _ in _called_attrs(tree)}
        self.assertIn("SignedExecutionPermit", names)
        self.assertIn("issue_permit", attrs)


class TokenScopeScannerTests(unittest.TestCase):

    def test_the_daemon_reads_no_execution_scope_from_the_transport_token(self):
        text = DAEMON.read_text(encoding="utf-8")
        self.assertNotIn("scope_payload_json", text)
        self.assertNotIn("scope_obj", text)
        self.assertNotIn("ScopeGrant.from_dict", text)
        self.assertIn("ScopeGrantStore", text,
                      "execution scope must come from the canonical store, not nowhere")

    def test_the_scanner_would_catch_a_token_scope_read(self):
        text = "grant = ScopeGrant.from_dict(json.loads(token_obj.scope_payload_json))"
        self.assertIn("scope_payload_json", text)
        self.assertIn("ScopeGrant.from_dict", text)


class SingleClaimSiteScannerTests(unittest.TestCase):

    ALLOWED_FILES = {"kernel/execution_gateway.py"}

    def _claim_sites(self):
        sites = []
        for path, text in _sources():
            for attr, receiver, lineno in _called_attrs(ast.parse(text)):
                if attr != "claim":
                    continue
                if "permit_store" in receiver.lower():
                    sites.append(f"{_rel(path)}:{lineno}")
        return sites

    def test_the_only_permit_claim_site_is_inside_the_guarded_executor(self):
        sites = self._claim_sites()
        outside = [s for s in sites if s.split(":")[0] not in self.ALLOWED_FILES]
        self.assertEqual(outside, [],
                         "claiming a permit is the authority-spending transition; there is one site")
        self.assertTrue(
            any(s.startswith("kernel/execution_gateway.py") for s in sites),
            "the scanner must actually find the sanctioned claim site, or it proves nothing",
        )

    def test_the_scanner_would_catch_a_second_claim_site(self):
        tree = ast.parse("def f():\n    return self.permit_store.claim(pid, 'w')\n")
        found = [a for a, r, _ in _called_attrs(tree) if a == "claim" and "permit_store" in r]
        self.assertEqual(found, ["claim"])


class WorkerVerdictScannerTests(unittest.TestCase):

    def test_the_worker_hands_the_disposition_only_correlation_facts(self):
        tree = ast.parse(DAEMON.read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                 and node.func.attr == "retry_disposition"]
        self.assertTrue(calls, "the daemon must actually use the one disposition engine")
        for call in calls:
            keywords = {kw.arg for kw in call.keywords}
            self.assertLessEqual(
                keywords, {"job_id", "expected_permit_id"},
                f"the worker stated a retry verdict with {sorted(keywords)}; safety and budget are "
                "DERIVED centrally from canonical facts, never reported by the worker",
            )

    def test_the_scanner_would_catch_a_reported_verdict(self):
        tree = ast.parse("self.retry_disposition(job_id=j, retry_safe=True)\n")
        call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        self.assertIn("retry_safe", {kw.arg for kw in call.keywords})


if __name__ == "__main__":
    unittest.main()
