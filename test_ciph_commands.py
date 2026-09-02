"""
test_ciph_commands.py - Unit and Integration Tests for CIPH 4.0 Declarative Command Registry (Phase 4).
"""

import os
import time
import unittest
from ciph.runtime import CiphRuntime
from ciph.capabilities.commands import CommandRegistry, CommandDefinition
from ciph.capabilities.registry import SportsPredictCapability
from ciph.workers.receipts import OutcomeCategory


class TestCiphCommands(unittest.TestCase):
    TEST_DB = "test_ciph_commands.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            os.remove(self.TEST_DB)
        self.runtime = CiphRuntime(db_path=self.TEST_DB)

        # Mock sports predictor adapter
        class MockSportsPredictor:
            def predict_match(self, home, away):
                return {"home": home, "away": away, "winner": home, "prob_home": 0.65}

        self.runtime.register_capability(SportsPredictCapability(MockSportsPredictor()))

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    def test_command_registry_parsing_and_aliases(self):
        reg = CommandRegistry()

        # 1. /sports vs parsing
        cmd, p1 = reg.parse("/sports Arsenal vs Chelsea")
        self.assertIsNotNone(cmd)
        self.assertEqual(cmd.command, "/sports")
        self.assertEqual(p1["home"], "Arsenal")
        self.assertEqual(p1["away"], "Chelsea")

        # 2. Alias /predict
        cmd_alias, p2 = reg.parse("/predict Liverpool vs Everton")
        self.assertIsNotNone(cmd_alias)
        self.assertEqual(cmd_alias.command, "/sports")
        self.assertEqual(p2["home"], "Liverpool")
        self.assertEqual(p2["away"], "Everton")

        # 3. /memory get
        cmd_mem, p3 = reg.parse("/memory get operator_secret")
        self.assertEqual(cmd_mem.command, "/memory")
        self.assertEqual(p3["key"], "operator_secret")

        # 4. /cvss
        cmd_cvss, p4 = reg.parse("/cvss AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(cmd_cvss.command, "/cvss")
        self.assertIn("AV:N", p4["vector"])

        # 5. Non-command input
        self.assertIsNone(reg.parse("Hello, how are you?"))
        self.assertIsNone(reg.parse("/nonexistent_command_xyz"))

    def test_dispatch_cvss_slash_command(self):
        """Test declarative /cvss execution through reference loop."""
        res = self.runtime.dispatch_slash_command("/cvss AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "SUCCESS")

        receipt = res["receipt"]
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.capability, "pentest.cvss_calculate")
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.results["base_score"], 9.8)
        self.assertEqual(receipt.results["severity"], "CRITICAL")

        # Verified in EventStore
        events = self.runtime.event_store.get_events(aggregate_id=receipt.receipt_id)
        self.assertEqual(len(events), 1)

    def test_dispatch_sports_slash_command(self):
        """Test declarative /sports execution through reference loop."""
        res = self.runtime.dispatch_slash_command("/sports RealMadrid vs Barcelona")
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "SUCCESS")
        receipt = res["receipt"]
        self.assertEqual(receipt.results["prediction"]["winner"], "RealMadrid")

    def test_dispatch_code_audit_slash_command(self):
        """Test declarative /code-audit on code_staging.py."""
        res = self.runtime.dispatch_slash_command("/code-audit code_staging.py")
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "SUCCESS")
        receipt = res["receipt"]
        self.assertEqual(receipt.results["missing_count"], 0)

    def test_missing_parameter_command_rejected_cleanly(self):
        """Missing required parameter produces INCOMPLETE_INTENT."""
        res = self.runtime.dispatch_slash_command("/bounty")
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "INCOMPLETE_INTENT")
        self.assertIn("target", res["missing_parameters"])

    def test_help_card_generation(self):
        help_card = self.runtime.command_registry.generate_help_card()
        self.assertIn("/sports", help_card)
        self.assertIn("/cvss", help_card)
        self.assertIn("/memory", help_card)
        self.assertIn("/tor", help_card)
        self.assertIn("/code-audit", help_card)


if __name__ == "__main__":
    unittest.main()
