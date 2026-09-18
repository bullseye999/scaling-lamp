#!/usr/bin/env python3
"""Regression tests for deterministic constitutional matrix execution."""

import os
import tempfile
import time
import unittest
from unittest.mock import patch

from ciph_matrix_audit import run_audit


class TestCiphMatrixAuditIsolation(unittest.TestCase):
    def test_matrix_audit_never_invokes_live_external_backends(self):
        report_file = tempfile.NamedTemporaryFile(prefix="ciph_matrix_report_", suffix=".json", delete=False)
        report_path = report_file.name
        report_file.close()
        try:
            started = time.monotonic()
            with patch(
                "bounty_hunter.BountyHunter.deep_scan",
                side_effect=AssertionError("matrix audit attempted live bounty scan"),
            ) as bounty_scan, patch(
                "ghost_transport.GhostTransport.request",
                side_effect=AssertionError("matrix audit attempted live Tor request"),
            ) as tor_request, patch(
                "code_staging.CodeStagingManager.apply",
                side_effect=AssertionError("matrix audit attempted production code promotion"),
            ) as code_promotion:
                result = run_audit(
                    verbose=False,
                    capability_timeout_seconds=5.0,
                    report_path=report_path,
                )

            self.assertEqual(result["compliant_count"], 16)
            self.assertEqual(result["total_canonical_capabilities"], 16)
            self.assertIn("operator.status", result["additional_capabilities_not_in_canonical_matrix"])
            self.assertNotIn("operator.status", result["results"])
            self.assertEqual(result["audit_mode"], "DETERMINISTIC_ISOLATED")
            self.assertIn("cybersecurity.bounty_scan", result["isolated_capabilities"])
            self.assertLess(time.monotonic() - started, 15.0)
            bounty_scan.assert_not_called()
            tor_request.assert_not_called()
            code_promotion.assert_not_called()
            self.assertIn("code.promote_upgrade", result["isolated_capabilities"])
            self.assertIn("not live capability", result["verification_scope"])
        finally:
            try:
                os.remove(report_path)
            except FileNotFoundError:
                pass

    def test_missing_canonical_capability_cannot_shrink_the_exit_gate(self):
        from ciph.runtime import CiphRuntime
        original = CiphRuntime.get_manifests
        def incomplete(runtime):
            return [m for m in original(runtime) if m.name != "memory.retrieve"]
        with patch.object(CiphRuntime, "get_manifests", incomplete):
            with self.assertRaisesRegex(RuntimeError, "MISSING_CANONICAL_CAPABILITIES.*memory.retrieve"):
                run_audit(verbose=False)

    def test_capability_deadline_reports_failure_instead_of_hanging(self):
        report_file = tempfile.NamedTemporaryFile(prefix="ciph_matrix_timeout_", suffix=".json", delete=False)
        report_path = report_file.name
        report_file.close()

        def never_finishes(_capability_name, _runtime):
            time.sleep(60)

        try:
            started = time.monotonic()
            with patch("ciph_matrix_audit.audit_capability", side_effect=never_finishes):
                result = run_audit(
                    verbose=False,
                    capability_timeout_seconds=0.05,
                    report_path=report_path,
                )

            self.assertEqual(result["compliant_count"], 0)
            self.assertEqual(result["total_canonical_capabilities"], 16)
            self.assertLess(time.monotonic() - started, 6.0)
            for capability_result in result["results"].values():
                self.assertIn("AUDIT_TIMEOUT", capability_result["error"])
        finally:
            try:
                os.remove(report_path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    unittest.main()
