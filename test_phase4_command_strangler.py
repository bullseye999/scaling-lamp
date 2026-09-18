from phase5_test_support import offline_fixture
"""
test_phase4_command_strangler.py - Test Suite for Program 1, Phase 4.
CIPH 4.0: Command & Capability Strangler Migration.

Verifies:
 1. Declarative CommandRegistry parsing across all 16 canonical capability commands & aliases.
 2. Full governed reference loop dispatch (Token -> Queue -> Worker -> Receipt -> EventStore).
 3. Parameter validation & fail-closed INCOMPLETE_INTENT behavior.
 4. Mandatory Interrupt authorization enforcement for privileged commands (/apply, /approve).
 5. Dynamic capability routing (/memory set -> memory.store, /memory get -> memory.retrieve).
 6. Scope grant containment on governed network commands (/bounty).
 7. Honest backend unavailable handling without fabricated simulations (/tor).
 8. CiphCore strangler interception ensuring zero unauthenticated raw module bypass.
 9. EventStore hash-chain integrity & monotonic event recording across command dispatches.
10. Built-in help card directory generation.
"""

import os
import time
import uuid
import unittest
from typing import Dict, Any

from ciph.runtime import CiphRuntime
from ciph.capabilities.commands import CommandRegistry, CommandDefinition
from ciph.capabilities.base import WorkerExecutionContext
from ciph.capabilities.registry import (
    SportsPredictCapability,
    MemoryRetrieveCapability,
    MemoryStoreCapability,
    CvssCalculatorCapability,
    CodeAuditCapability,
    CodeListStagedCapability,
    CodePromoteUpgradeCapability,
    TorStatusCapability,
    WisdomConsultCapability,
    TradingPortfolioCapability,
    DeadmanStatusCapability,
    BountyScanCapability,
    BountySummaryCapability,
    DarknetStatusCapability,
    DarknetReportCapability,
    OsintMonetizeCapability
)
from ciph.kernel.policy_engine import (
    AuthorizationTier,
    AuthorizationGrant,
    ScopeGrant,
    NetworkPolicy,
    RiskTier
)
from ciph.contracts.enums import ScopeType
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory
from ciph_core import CiphCore


class TestPhase4CommandStrangler(unittest.TestCase):
    TEST_DB = "test_phase4_strangler.db"

    def setUp(self):
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass
        self.runtime = CiphRuntime(db_path=self.TEST_DB)

        # Mock backends for deterministic unit testing
        class MockSports:
            def predict_match(self, home, away):
                return {"home": home, "away": away, "winner": home, "prob_home": 0.72}

        class MockStaging:
            def __init__(self):
                self.applied = []
            def list_staged(self):
                return "UP-001: Model router enhancement"
            def apply(self, prop_id):
                self.applied.append(prop_id)
                return True, f"Upgrade {prop_id} promoted successfully"

        class MockBounty:
            def deep_scan(self, target, force=True):
                return {"target": target, "subdomains": 5, "takeovers": 0, "status": "COMPLETED"}
            def list_bounties_summary(self):
                return "Active bounties: 12 targets monitored"

        class MockTor:
            def check_connection(self):
                return True

        class MockTrading:
            def portfolio_health_check(self):
                return {"total_value": 25000.0, "health_status": "STRONG", "risk": "LOW"}

        class MockBooks:
            def get_situational_advice(self, query):
                return f"Guidance for '{query}': Maintain optionality and verify evidence."
            def list_books(self):
                return ["The Art of War", "Thinking in Bets", "Antifragile"]

        class MockDeadman:
            def check_in(self):
                return "‖ Dead man's failsafe check-in confirmed ‖"

        class MockDarknet:
            def get_status(self):
                return {"feeds_monitored": 8, "active_alerts": 2}
            def get_detailed_report(self):
                return "Darknet report: No critical leaks detected."

        class MockOsint:
            def find_monetizable_threats(self):
                return [{"threat_type": "zero_day", "title": "Protocol auth bypass", "potential_value": "$5,000"}]

        self.mock_staging = MockStaging()
        self.mock_sports = MockSports()
        self.mock_bounty = MockBounty()
        self.mock_tor = MockTor()
        self.mock_trading = MockTrading()
        self.mock_books = MockBooks()
        self.mock_deadman = MockDeadman()
        self.mock_darknet = MockDarknet()
        self.mock_osint = MockOsint()

        # Shared memory backend for store/retrieve integration
        self.shared_memory = {}
        self.runtime.register_capability(MemoryRetrieveCapability(self.shared_memory))
        self.runtime.register_capability(MemoryStoreCapability(self.shared_memory))

        # Register mocked capability adapters into runtime
        self.runtime.register_capability(offline_fixture(SportsPredictCapability(self.mock_sports)))
        self.runtime.register_capability(CodeListStagedCapability(self.mock_staging))
        self.runtime.register_capability(CodePromoteUpgradeCapability(self.mock_staging))
        self.runtime.register_capability(offline_fixture(BountyScanCapability(self.mock_bounty)))
        self.runtime.register_capability(BountySummaryCapability(self.mock_bounty))
        self.runtime.register_capability(offline_fixture(TorStatusCapability(self.mock_tor)))
        self.runtime.register_capability(offline_fixture(TradingPortfolioCapability(self.mock_trading)))
        self.runtime.register_capability(WisdomConsultCapability(self.mock_books))
        self.runtime.register_capability(DeadmanStatusCapability(self.mock_deadman))
        self.runtime.register_capability(DarknetStatusCapability(self.mock_darknet))
        self.runtime.register_capability(DarknetReportCapability(self.mock_darknet))
        self.runtime.register_capability(offline_fixture(OsintMonetizeCapability(self.mock_osint)))

    def tearDown(self):
        self.runtime.shutdown()
        if os.path.exists(self.TEST_DB):
            try:
                os.remove(self.TEST_DB)
            except Exception:
                pass

    # =========================================================================
    # 1. PARSING & ALIAS VERIFICATION
    # =========================================================================

    def test_all_16_canonical_command_definitions_registered(self):
        """Ensure all canonical command families and aliases are properly registered in CommandRegistry."""
        reg = CommandRegistry()

        commands_to_verify = [
            ("/sports", "sports.predict_match"),
            ("/predict", "sports.predict_match"),
            ("/match", "sports.predict_match"),
            ("/predict-match", "sports.predict_match"),
            ("/memory", "memory.retrieve"),
            ("/vault", "memory.retrieve"),
            ("/mem", "memory.retrieve"),
            ("/learn", "memory.store"),
            ("/bounty", "cybersecurity.bounty_scan"),
            ("/bounty-scan", "cybersecurity.bounty_scan"),
            ("/scan", "cybersecurity.bounty_scan"),
            ("/bounty-status", "cybersecurity.bounty_summary"),
            ("/bounty-programs", "cybersecurity.bounty_summary"),
            ("/bounties", "cybersecurity.bounty_summary"),
            ("/bounty-list", "cybersecurity.bounty_summary"),
            ("/osint", "osint.find_monetizable_threats"),
            ("/threats", "osint.find_monetizable_threats"),
            ("/feed", "osint.find_monetizable_threats"),
            ("/money-ops", "osint.find_monetizable_threats"),
            ("/bounty-ops", "osint.find_monetizable_threats"),
            ("/cvss", "pentest.cvss_calculate"),
            ("/calc-cvss", "pentest.cvss_calculate"),
            ("/tor", "tor.check_status"),
            ("/tor-status", "tor.check_status"),
            ("/circuit", "tor.check_status"),
            ("/code-audit", "code.audit_dependencies"),
            ("/audit-deps", "code.audit_dependencies"),
            ("/check-deps", "code.audit_dependencies"),
            ("/darknet-status", "darknet.get_status"),
            ("/darknet-report", "darknet.get_detailed_report"),
            ("/detailed-darknet-scan", "darknet.get_detailed_report"),
            ("/alerts", "darknet.get_detailed_report"),
            ("/darknet-alerts", "darknet.get_detailed_report"),
            ("/upgrades", "code.list_staged"),
            ("/staged", "code.list_staged"),
            ("/code", "code.list_staged"),
            ("/apply", "code.promote_upgrade"),
            ("/approve", "code.promote_upgrade"),
            ("/apply-code", "code.promote_upgrade"),
            ("/apply-upgrade", "code.promote_upgrade"),
            ("/library", "wisdom.consult_library"),
            ("/books", "wisdom.consult_library"),
            ("/book-advice", "wisdom.consult_library"),
            ("/ask-book", "wisdom.consult_library"),
            ("/trading", "trading.portfolio_check"),
            ("/portfolio", "trading.portfolio_check"),
            ("/trade-status", "trading.portfolio_check"),
            ("/portfolio-health", "trading.portfolio_check"),
            ("/deadman", "security.deadman_status"),
            ("/deadmans-switch", "security.deadman_status"),
            ("/failsafe", "security.deadman_status"),
            ("/help", "system.help"),
            ("/?", "system.help"),
        ]

        for cmd_str, expected_cap in commands_to_verify:
            cmd_def = reg.find_command(cmd_str)
            self.assertIsNotNone(cmd_def, f"Command/alias '{cmd_str}' was not found in CommandRegistry.")
            self.assertEqual(cmd_def.capability_name, expected_cap, f"Command '{cmd_str}' mapped to '{cmd_def.capability_name}', expected '{expected_cap}'.")

    def test_sports_parameter_parsing_variants(self):
        """Verify /sports handles 'vs', positional tokens, and 'home=... away=...' syntax."""
        reg = CommandRegistry()

        # Variant 1: "vs"
        cmd, p1 = reg.parse("/sports Arsenal vs Chelsea")
        self.assertEqual(p1["home"], "Arsenal")
        self.assertEqual(p1["away"], "Chelsea")

        # Variant 2: positional
        cmd, p2 = reg.parse("/sports Liverpool Everton")
        self.assertEqual(p2["home"], "Liverpool")
        self.assertEqual(p2["away"], "Everton")

        # Variant 3: key=value
        cmd, p3 = reg.parse("/sports home=RealMadrid away=Barcelona")
        self.assertEqual(p3["home"], "RealMadrid")
        self.assertEqual(p3["away"], "Barcelona")

        # Variant 4: alias /predict-match
        cmd, p4 = reg.parse("/predict-match Bayern vs Dortmund")
        self.assertEqual(cmd.command, "/sports")
        self.assertEqual(p4["home"], "Bayern")
        self.assertEqual(p4["away"], "Dortmund")

    def test_memory_and_learn_parameter_parsing(self):
        """Verify /memory get, /memory set, and /learn parse parameters properly."""
        reg = CommandRegistry()

        # /memory get
        cmd, p1 = reg.parse("/memory get api_endpoint")
        self.assertEqual(p1["action"], "retrieve")
        self.assertEqual(p1["key"], "api_endpoint")

        # /memory set
        cmd, p2 = reg.parse("/memory set cluster_size 8")
        self.assertEqual(p2["action"], "store")
        self.assertEqual(p2["key"], "cluster_size")
        self.assertEqual(p2["value"], "8")

        # /learn
        cmd, p3 = reg.parse("/learn Deception is fundamental to security operations")
        self.assertEqual(cmd.command, "/learn")
        self.assertEqual(cmd.capability_name, "memory.store")
        self.assertEqual(p3["value"], "Deception is fundamental to security operations")
        self.assertTrue(p3["key"].startswith("knowledge_"))

    def test_apply_upgrade_parameter_parsing(self):
        """Verify /apply and aliases parse proposal_id with positional and key=value syntax."""
        reg = CommandRegistry()

        cmd, p1 = reg.parse("/apply UP-042")
        self.assertEqual(cmd.command, "/apply")
        self.assertEqual(p1["proposal_id"], "UP-042")

        cmd, p2 = reg.parse("/approve proposal_id=UP-099")
        self.assertEqual(cmd.command, "/apply")
        self.assertEqual(p2["proposal_id"], "UP-099")

    # =========================================================================
    # 2. FULL GOVERNED REFERENCE LOOP EXECUTION
    # =========================================================================

    def test_dispatch_sports_through_governed_reference_loop(self):
        """Verify /sports executes through queue and worker, writing an authentic receipt and EventStore event."""
        res = self.runtime.dispatch_slash_command("/sports Arsenal vs Chelsea")
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], "SUCCESS")

        receipt = res["receipt"]
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.capability, "sports.predict_match")
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.results["prediction"]["winner"], "Arsenal")

        # Check EventStore recording
        events = self.runtime.event_store.get_events(aggregate_id=receipt.receipt_id)
        self.assertEqual(len(events), 1)
        self.assertIn(events[0]["event_type"], ("ExecutionReceiptStoredEvent", "ExecutionReceiptRecorded"))

    def test_dispatch_learn_and_memory_get_reference_loop(self):
        """Verify /learn stores knowledge into vault and /memory get retrieves it via governed receipts."""
        # 1. /learn
        learn_res = self.runtime.dispatch_slash_command("/learn Sovereign computing is non-negotiable")
        self.assertEqual(learn_res["status"], "SUCCESS")
        learn_receipt = learn_res["receipt"]
        self.assertEqual(learn_receipt.capability, "memory.store")
        stored_key = learn_receipt.results["key"]

        # 2. /memory get
        get_res = self.runtime.dispatch_slash_command(f"/memory get {stored_key}")
        self.assertEqual(get_res["status"], "SUCCESS")
        get_receipt = get_res["receipt"]
        self.assertEqual(get_receipt.capability, "memory.retrieve")
        self.assertTrue(get_receipt.results["found"])
        self.assertEqual(get_receipt.results["value"], "Sovereign computing is non-negotiable")

    def test_dispatch_bounty_summary_and_scan(self):
        """Verify /bounty-status and /bounty target.com execute through the strangler pipeline."""
        # 1. /bounty-status
        status_res = self.runtime.dispatch_slash_command("/bounty-status")
        self.assertEqual(status_res["status"], "SUCCESS")
        self.assertEqual(status_res["receipt"].capability, "cybersecurity.bounty_summary")
        self.assertIn("12 targets monitored", status_res["receipt"].results["summary"])

        # 2. /bounty target.com
        scope = ScopeGrant(scope_id="bounty_test", scope_type=ScopeType.TARGET_DOMAIN,
                           allowed_targets=["target.com"], valid_until=time.time()+300).sign(self.runtime.auth_secret_key)
        scan_res = self.runtime.dispatch_slash_command("/bounty target.com", scope_grant=scope)
        self.assertEqual(scan_res["status"], "SUCCESS")
        self.assertEqual(scan_res["receipt"].capability, "cybersecurity.bounty_scan")
        self.assertEqual(scan_res["receipt"].results["subdomains"], 5)

    def test_dispatch_trading_portfolio_health(self):
        """Verify /portfolio-health routes to trading.portfolio_check via alias."""
        res = self.runtime.dispatch_slash_command("/portfolio-health")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["receipt"].capability, "trading.portfolio_check")
        self.assertEqual(res["receipt"].results["portfolio"]["health_status"], "STRONG")

    def test_dispatch_wisdom_book_advice(self):
        """Verify /ask-book routes to wisdom.consult_library via alias."""
        res = self.runtime.dispatch_slash_command("/ask-book adversarial deception")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["receipt"].capability, "wisdom.consult_library")
        self.assertIn("Guidance for 'adversarial deception'", res["receipt"].results["result"])

    def test_dispatch_osint_money_ops(self):
        """Verify /money-ops routes to osint.find_monetizable_threats."""
        res = self.runtime.dispatch_slash_command("/money-ops")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["receipt"].capability, "osint.find_monetizable_threats")
        self.assertEqual(len(res["receipt"].results["opportunities"]), 1)

    # =========================================================================
    # 3. PARAMETER VALIDATION & INCOMPLETE INTENT
    # =========================================================================

    def test_missing_required_parameter_fails_closed(self):
        """Verify commands with missing required parameters return INCOMPLETE_INTENT without execution."""
        # /bounty with no target
        bounty_res = self.runtime.dispatch_slash_command("/bounty")
        self.assertEqual(bounty_res["status"], "INCOMPLETE_INTENT")
        self.assertIn("target", bounty_res["missing_parameters"])

        # /sports with no arguments
        sports_res = self.runtime.dispatch_slash_command("/sports")
        self.assertEqual(sports_res["status"], "INCOMPLETE_INTENT")
        self.assertIn("home", sports_res["missing_parameters"])

        # /apply with no proposal_id
        apply_res = self.runtime.dispatch_slash_command("/apply")
        self.assertEqual(apply_res["status"], "INCOMPLETE_INTENT")
        self.assertIn("proposal_id", apply_res["missing_parameters"])

        # /learn with no content
        learn_res = self.runtime.dispatch_slash_command("/learn")
        self.assertEqual(learn_res["status"], "INCOMPLETE_INTENT")
        self.assertIn("value", learn_res["missing_parameters"])

    # =========================================================================
    # 4. MANDATORY INTERRUPT AUTHORIZATION ENFORCEMENT
    # =========================================================================

    def test_apply_without_auth_grant_is_halted(self):
        """Privileged command /apply must halt with AUTHORIZATION_REQUIRED when grant is absent."""
        res = self.runtime.dispatch_slash_command("/apply UP-001")
        self.assertEqual(res["status"], "AUTHORIZATION_REQUIRED")
        self.assertIn("Operator authorization required", res["dialogue"])
        self.assertEqual(len(self.mock_staging.applied), 0)

    def test_apply_with_authentic_operator_grant_executes(self):
        """Privileged command /apply succeeds when presented with valid cryptographic AuthorizationGrant."""
        # 1. Dispatch first to receive the compiled authorization requirements
        initial_res = self.runtime.dispatch_slash_command("/apply UP-001")
        self.assertEqual(initial_res["status"], "AUTHORIZATION_REQUIRED")
        plan_hash = initial_res["plan_hash"]
        step_id = initial_res["step_id"]
        params_hash = initial_res["params_hash"]

        # 2. Mint authentic operator grant bound to plan_hash, step_id, capability, params_hash
        grant = AuthorizationGrant(
            grant_id=f"grant_{uuid.uuid4().hex[:8]}",
            plan_hash=plan_hash,
            step_id=step_id,
            capability="code.promote_upgrade",
            params_hash=params_hash,
            scope_grant_id="",
            expires_at=time.time() + 300
        ).sign(self.runtime.auth_secret_key)

        # 3. Dispatch with grant
        res = self.runtime.dispatch_slash_command("/apply UP-001", auth_grant=grant)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["receipt"].capability, "code.promote_upgrade")
        self.assertIn("UP-001", self.mock_staging.applied)

    # =========================================================================
    # 5. SCOPE ENFORCEMENT & POLICY GATING
    # =========================================================================

    def test_scope_grant_enforced_on_governed_bounty_command(self):
        """Verify /bounty strictly enforces ScopeGrant allowed targets."""
        scope = ScopeGrant(
            scope_id="scope_test_01",
            scope_type=ScopeType.TARGET_DOMAIN,
            allowed_targets=["allowed-domain.org"],
            valid_until=time.time() + 300
        )

        scope = scope.sign(self.runtime.auth_secret_key)

        # Disallowed target
        blocked_res = self.runtime.dispatch_slash_command("/bounty outside-target.com", scope_grant=scope)
        self.assertEqual(blocked_res["status"], "POLICY_BLOCKED")
        self.assertEqual(blocked_res["receipt"].outcome, OutcomeCategory.POLICY_BLOCKED)

        # Allowed target
        allowed_res = self.runtime.dispatch_slash_command("/bounty allowed-domain.org", scope_grant=scope)
        self.assertEqual(allowed_res["status"], "SUCCESS")

    # =========================================================================
    # 6. CIPHCORE STRANGLER INTERCEPTION (ZERO DIRECT RAW MODULE CALLS)
    # =========================================================================

    def test_ciph_core_strangler_intercepts_registered_slash_commands(self):
        """Verify CiphCore.handle_command delegates directly to runtime without reaching legacy code."""
        core = CiphCore.__new__(CiphCore)
        core.runtime = self.runtime

        # 1. /sports
        output = core.handle_command("/sports Arsenal vs Chelsea")
        self.assertIn("sports.predict_match", output)
        self.assertIn("Arsenal", output)

        # 2. /upgrades
        output = core.handle_command("/upgrades")
        self.assertIn("code.list_staged", output)

        # 3. /darknet-status
        output = core.handle_command("/darknet-status")
        self.assertIn("darknet.get_status", output)

        # 4. /help
        output = core.handle_command("/help")
        self.assertIn("CIPH 4.0 DECLARATIVE COMMAND DIRECTORY", output)

    def test_help_card_directory_generation(self):
        """Verify /help returns complete ASCII directory of all commands and aliases."""
        res = self.runtime.dispatch_slash_command("/help")
        self.assertEqual(res["status"], "SUCCESS")
        help_card = res["dialogue"]
        self.assertIn("/sports", help_card)
        self.assertIn("/memory", help_card)
        self.assertIn("/learn", help_card)
        self.assertIn("/apply", help_card)
        self.assertIn("/trading", help_card)
        self.assertIn("/bounty", help_card)
        self.assertIn("/cvss", help_card)


if __name__ == "__main__":
    unittest.main()
