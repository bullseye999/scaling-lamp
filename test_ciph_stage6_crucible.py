"""
test_ciph_stage6_crucible.py - Verification for Stage 6 The Iron Crucible & Adversarial Falsification.
"""

import os
import unittest

from ciph.runtime import CiphRuntime
from ciph.crucible.red_shadow import RedShadowCrucible


class TestCiphStage6Crucible(unittest.TestCase):
    TEST_DB = "test_stage6_crucible.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.auth_key = b"crucible_auth_secret_stage6_32b!"
        self.runtime = CiphRuntime(db_path=self.TEST_DB, auth_secret_key=self.auth_key)
        self.crucible = RedShadowCrucible()

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_adversarial_penetration_sweep(self):
        """Run penetration sweep across capabilities and verify 100% resilience."""
        # Fuzz target set including critical code promote and standard capabilities
        targets = ["code.promote_upgrade", "tor.check_status", "pentest.cvss_calculate"]
        report = self.crucible.run_penetration_sweep(self.runtime, target_capabilities=targets)

        self.assertGreater(report.total_probes, 0)
        self.assertEqual(report.probes_escaped, 0)
        self.assertEqual(len(report.quarantined_capabilities), 0)
        self.assertEqual(report.resilience_score, 1.0)


if __name__ == "__main__":
    unittest.main()
