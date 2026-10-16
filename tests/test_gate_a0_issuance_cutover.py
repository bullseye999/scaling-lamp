
"""
Gate A0 closure test - post-cutover issuance.

After the certainty cutover every *new* production receipt must be issued through
ExecutionReceipt.issue() at the current schema with an explicit certainty statement. Historical
receipts stay readable and stay legacy. Nothing may keep emitting 4.1 as a stand-in for "this
production path has not been migrated yet", because that turns schema 4.1 into "issued before we
finished the migration" instead of "genuinely predates effect certainty".
"""

import ast
import pathlib
import unittest

from ciph.contracts.enums import EffectCertainty
from ciph.kernel.crypto_identity import Ed25519KeyManager
from ciph.kernel.performance_metric import (
    EXECUTION_SUCCESS_V1,
    ExclusionReason,
    observe_execution_success,
)
from ciph.workers.receipts import ExecutionReceipt

# Direct construction of an ExecutionReceipt is legitimate only when reconstructing an
# already-issued receipt: the internal signature/claim round-trips, and the historical vault
# parser. Every genuine new issuance must go through .issue().
RECONSTRUCTION_SITES = {
    ("ciph/workers/receipts.py", "attach_governed_claims"),
    ("ciph/workers/receipts.py", "sign"),
    ("ciph/capabilities/capability_ledger.py", "parse_raw_receipt"),
}


def _project_root():
    here = pathlib.Path(__file__).resolve().parents[1]
    if (here / "ciph").is_dir():
        return here
    cwd = pathlib.Path.cwd()
    if (cwd / "ciph").is_dir():
        return cwd
    raise RuntimeError("PROJECT_ROOT_NOT_FOUND")


def _enclosing(tree, lineno):
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= lineno <= (node.end_lineno or node.lineno):
                if best is None or node.lineno > best[0]:
                    best = (node.lineno, node.name)
    return best[1] if best else "<module>"


def _direct_issuance_sites():
    root = _project_root()
    found = []
    for path in sorted((root / "ciph").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = str(path.relative_to(root))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "ExecutionReceipt"):
                found.append((rel, _enclosing(tree, node.lineno), node.lineno))
    return found


def _payload(**overrides):
    base = dict(
        receipt_id="rcpt_cutover_1",
        job_id="JOB-CUT-LEDGER",
        capability="test.cutover",
        target="repo-A",
        started_at=1_700_000_000.0,
        completed_at=1_700_000_001.0,
        input_hash="ih",
        output_hash=ExecutionReceipt.hash_payload({"ok": True}),
        exit_code=0,
        outcome="SUCCESS",
        results={"ok": True},
        side_effects=[],
        idempotency_key="idem-cut",
        attempt_number=1,
        requested_network_policy="OFFLINE_ONLY",
        actual_transport_used="NONE",
        worker_id="worker-A",
    )
    base.update(overrides)
    return base


def _fields():
    from ciph.contracts.enums import NetworkPolicy, OutcomeCategory
    d = _payload()
    d["outcome"] = OutcomeCategory.SUCCESS
    d["requested_network_policy"] = NetworkPolicy.OFFLINE_ONLY
    return d


class IssuanceBoundaryScanTests(unittest.TestCase):

    def test_no_production_direct_issuance_outside_the_reconstruction_allowlist(self):
        offenders = [s for s in _direct_issuance_sites() if (s[0], s[1]) not in RECONSTRUCTION_SITES]
        self.assertEqual(offenders, [], f"direct ExecutionReceipt issuance remains: {offenders}")

    def test_the_scan_would_catch_a_direct_site(self):
        """Guard against a scan that silently matches nothing."""
        src = "def f():\n    return ExecutionReceipt(receipt_id='x')\n"
        tree = ast.parse(src)
        hits = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name) and n.func.id == "ExecutionReceipt"]
        self.assertEqual(len(hits), 1)

    def test_the_allowlisted_reconstruction_sites_still_construct(self):
        seen = {(rel, fn) for rel, fn, _ in _direct_issuance_sites()}
        missing = RECONSTRUCTION_SITES - seen
        self.assertEqual(missing, set(), f"allowlisted reconstruction sites vanished: {missing}")


class IssuanceTests(unittest.TestCase):

    def test_new_receipt_without_a_verifier_is_current_schema_and_unknown(self):
        receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN, **_fields())
        self.assertEqual(receipt.schema_version, "4.2")
        self.assertEqual(receipt.effect_certainty, "EFFECT_UNKNOWN")
        observation = observe_execution_success(receipt.outcome, receipt.effect_certainty)
        self.assertEqual(observation.metric_ref, EXECUTION_SUCCESS_V1)
        self.assertIsNone(observation.score)
        self.assertEqual(observation.exclusion_reason, ExclusionReason.EFFECT_UNKNOWN)

    def test_new_receipt_with_a_verifier_is_confirmed_and_eligible(self):
        receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_CONFIRMED, **_fields())
        self.assertEqual(receipt.schema_version, "4.2")
        observation = observe_execution_success(receipt.outcome, receipt.effect_certainty)
        self.assertEqual(observation.score, 1.0)

    def test_issue_normalises_enum_members_and_strings_alike(self):
        as_value = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value, **_fields())
        as_member = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN, **_fields())
        self.assertEqual(as_value.effect_certainty, "EFFECT_UNKNOWN")
        self.assertEqual(as_member.effect_certainty, "EFFECT_UNKNOWN")

    def test_a_new_receipt_is_signed_over_its_certainty(self):
        private_key, public_key = Ed25519KeyManager.generate_keypair()
        signed = ExecutionReceipt.issue(
            effect_certainty=EffectCertainty.EFFECT_UNKNOWN, **_fields()
        ).sign(private_key, worker_key_id="worker-A")
        self.assertTrue(signed.verify_signature(public_key))
        self.assertIn("effect_certainty", signed.compute_signature_payload())


class LedgerReadPathTests(unittest.TestCase):
    """The vault reader must round-trip newly-issued receipts, or the cutover breaks the ledger."""

    def _parser(self):
        from ciph.capabilities.capability_ledger import StrictHistoricalReceiptParser
        return StrictHistoricalReceiptParser

    def test_the_parser_accepts_the_current_schema(self):
        receipt = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN, **_fields())
        parsed, meta = self._parser().parse_raw_receipt(receipt.to_dict())
        self.assertIsNotNone(parsed, meta)
        self.assertEqual(parsed.schema_version, "4.2")
        self.assertEqual(parsed.effect_certainty, "EFFECT_UNKNOWN")

    def test_a_confirmed_receipt_round_trips_its_signature(self):
        private_key, public_key = Ed25519KeyManager.generate_keypair()
        signed = ExecutionReceipt.issue(
            effect_certainty=EffectCertainty.EFFECT_CONFIRMED, **_fields()
        ).sign(private_key, worker_key_id="worker-A")
        parsed, meta = self._parser().parse_raw_receipt(signed.to_dict())
        self.assertIsNotNone(parsed, meta)
        self.assertEqual(parsed.effect_certainty, "EFFECT_CONFIRMED")
        self.assertTrue(parsed.verify_signature(public_key))

    def test_the_parser_refuses_an_unknown_future_schema(self):
        body = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN, **_fields()).to_dict()
        body["schema_version"] = "4.3"
        parsed, meta = self._parser().parse_raw_receipt(body)
        self.assertIsNone(parsed)
        self.assertEqual(meta.get("error"), "UNSUPPORTED_SCHEMA_VERSION")

    def test_the_parser_refuses_a_current_schema_receipt_without_certainty(self):
        body = ExecutionReceipt.issue(effect_certainty=EffectCertainty.EFFECT_UNKNOWN, **_fields()).to_dict()
        body.pop("effect_certainty", None)
        parsed, meta = self._parser().parse_raw_receipt(body)
        self.assertIsNone(parsed)
        self.assertIn("EFFECT_CERTAINTY_REQUIRED", str(meta.get("error")))

    def test_a_historical_legacy_receipt_still_parses_as_legacy(self):
        parsed, meta = self._parser().parse_raw_receipt(_payload(schema_version="4.1"))
        self.assertIsNotNone(parsed, meta)
        self.assertEqual(parsed.schema_version, "4.1")
        self.assertIsNone(parsed.effect_certainty)


if __name__ == "__main__":
    unittest.main()
