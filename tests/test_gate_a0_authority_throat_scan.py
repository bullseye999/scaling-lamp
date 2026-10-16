
"""
Gate A0 architectural test - the execution throat has ONE authority, and ONE mint.

Decision of record: D2 / A. `SignedExecutionPermit` is the sole execution-authority artifact for
the durable worker lane. `ExecutionToken` may survive only as non-authoritative transport,
session and replay state.

Closing the raw-execution throat while quietly opening five permit-minting throats would be a bad
trade, so permit issuance gets the same static treatment as raw execution: a scan, not a promise.
"""

import pathlib
import re
import unittest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "ciph"

# Constructing a signed permit is minting authority. It must happen in the canonical authority and
# its gateway, nowhere else.
PERMIT_CONSTRUCTION_PATTERN = re.compile(r"\bSignedExecutionPermit\s*\(")

# Asking something to issue a permit. Delegating to a canonical gateway/authority is allowed;
# minting from a producer, planner or worker is not.
PERMIT_ISSUANCE_PATTERN = re.compile(r"\.issue_permit\s*\(")

ALLOWED_PERMIT_CONSTRUCTION_FILES = {
    "kernel/execution_authority.py",   # the issuer itself
    "kernel/execution_gateway.py",     # the canonical signing boundary
}

# Constructing the authority or the gateway is building a permit universe. There must be exactly one
# canonical production configuration, so only the composition module may do it.
AUTHORITY_CONSTRUCTION_PATTERN = re.compile(r"\bExecutionAuthority\s*\(")
GATEWAY_CONSTRUCTION_PATTERN = re.compile(r"\bExecutionGateway\s*\(")
ALLOWED_AUTHORITY_CONSTRUCTION_FILES = {
    "kernel/execution_authority.py",   # the class and its own factory
    "kernel/permit_composition.py",    # the one canonical composition point
}
ALLOWED_GATEWAY_CONSTRUCTION_FILES = {
    "kernel/execution_gateway.py",     # the class itself
    "kernel/permit_composition.py",    # the one canonical composition point
}

ALLOWED_PERMIT_ISSUANCE_FILES = {
    "kernel/execution_authority.py",
    "kernel/execution_gateway.py",
    # The governed registry path delegates to `governed.gateway`; it does not mint. Removing this
    # line requires replacing the delegation with a refusal, not with a local issuer.
    "capabilities/registry.py",
    # S2.3: the canonical producer-side carriage helper delegates to an INJECTED gateway. It
    # constructs no permit and holds no key - it asks the boundary to mint and the store to
    # canonicalise. It is deliberately absent from ALLOWED_PERMIT_CONSTRUCTION_FILES.
    "kernel/permit_issuance.py",
    # S3: the atomic retry transition mints generation N+1. It holds no key and builds no permit -
    # it asks the INJECTED gateway to issue one, inside the same transaction that installs it, so
    # "generation > 0" is reachable only through the canonical classifier. Deliberately absent from
    # ALLOWED_PERMIT_CONSTRUCTION_FILES: it never constructs `SignedExecutionPermit` itself.
    "kernel/retry_transaction.py",
}


def _scan(pattern):
    found = set()
    for path in PACKAGE_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if pattern.search(text):
            found.add(str(path.relative_to(PACKAGE_ROOT)))
    return found


class PermitIssuanceScanTests(unittest.TestCase):

    def test_only_the_canonical_authority_constructs_signed_permits(self):
        unexpected = sorted(_scan(PERMIT_CONSTRUCTION_PATTERN) - ALLOWED_PERMIT_CONSTRUCTION_FILES)
        self.assertEqual(
            unexpected, [],
            "Signed permit construction outside the canonical authority: "
            f"{unexpected}. Producers must ask the gateway; they must never build a permit.",
        )

    def test_permit_issuance_is_confined_to_the_canonical_path(self):
        unexpected = sorted(_scan(PERMIT_ISSUANCE_PATTERN) - ALLOWED_PERMIT_ISSUANCE_FILES)
        self.assertEqual(
            unexpected, [],
            "New permit-issuing site(s) detected: "
            f"{unexpected}. Route issuance through ExecutionGateway / ExecutionAuthority, or if "
            "this is a deliberate change, edit the allowlist and say why.",
        )

    def test_the_scanner_would_catch_a_new_minting_site(self):
        """Guard against a scan that silently matches nothing."""
        sample = "def mint():\n    return SignedExecutionPermit(payload)\n"
        self.assertIsNotNone(PERMIT_CONSTRUCTION_PATTERN.search(sample))
        self.assertIsNotNone(PERMIT_ISSUANCE_PATTERN.search("p = gateway.issue_permit(request)\n"))

    def test_only_the_composition_point_builds_an_authority_or_a_gateway(self):
        for label, pattern, allowed in (
            ("ExecutionAuthority", AUTHORITY_CONSTRUCTION_PATTERN, ALLOWED_AUTHORITY_CONSTRUCTION_FILES),
            ("ExecutionGateway", GATEWAY_CONSTRUCTION_PATTERN, ALLOWED_GATEWAY_CONSTRUCTION_FILES),
        ):
            with self.subTest(pattern=label):
                unexpected = sorted(_scan(pattern) - allowed)
                self.assertEqual(
                    unexpected, [],
                    f"{label} constructed outside the canonical composition point: {unexpected}",
                )

    def test_the_boundary_and_the_authority_both_still_exist(self):
        for rel in ("kernel/execution_gateway.py", "kernel/execution_authority.py"):
            with self.subTest(module=rel):
                self.assertTrue((PACKAGE_ROOT / rel).exists(), f"missing {rel}")


if __name__ == "__main__":
    unittest.main()
