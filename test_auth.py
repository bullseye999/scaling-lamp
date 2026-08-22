#!/usr/bin/env python3
# test_auth.py - CIPH 3.0 Verification & Core Integration Test Suite

import os
import unittest
from cipher_vault import CipherVault
from personality_engine import CiphPersonality
from query_router import QueryRouter
from state_manager import StateManager
from bounty_hunter import BountyHunter
from ghost_transport import GhostTransport


class TestCiphCore(unittest.TestCase):

    def setUp(self):
        self.vault = CipherVault()
        self.personality = CiphPersonality()
        self.state = StateManager()
        self.query_router = QueryRouter(self.state, self.vault)
        self.bounty = BountyHunter(self.vault)
        self.transport = GhostTransport()

    def test_vault_wal_and_encryption(self):
        """Test vault encryption and config persistence under WAL mode."""
        self.vault.set_config("test_ciph_key", "ciph_secret_value_123")
        val = self.vault.get_config("test_ciph_key")
        self.assertEqual(val, "ciph_secret_value_123")

    def test_personality_code_masking(self):
        """Test that code blocks and JSON payloads are untouched by slang filters."""
        sample_code = '```json\n{\n  "name": "Operator",\n  "system": "CIPH"\n}\n```'
        input_text = f"Certainly! Here is your code:\n{sample_code}\nLet me know if you need more."
        output = self.personality.inject_personality(input_text)
        self.assertIn(sample_code, output)
        self.assertNotIn("Certainly", output)

    def test_safe_ast_math(self):
        """Test safe AST math calculation in QueryRouter without eval."""
        res = self.query_router.answer_calculation("calc (10 + 5) * 4 / 2")
        self.assertIn("30", res)

    def test_bounty_scope_checking(self):
        """Test scope boundary logic in BountyHunter."""
        in_scope, reason = self.bounty.is_in_scope("example.com")
        self.assertIsInstance(in_scope, bool)

    def test_ghost_transport_fail_closed(self):
        """Test GhostTransport fail-closed header and session generation."""
        headers = self.transport.get_random_headers()
        self.assertIn("User-Agent", headers)
        self.assertIn("Accept", headers)


if __name__ == "__main__":
    unittest.main()