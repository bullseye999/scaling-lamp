"""
test_phase9_step3_empirical_self_knowledge.py - Phase 9 Step 3 Verification Suite.
Validates Empirical Self-Knowledge, Operator Briefings & Cognitive Grounding
satisfying Phase 9 exit gate: "CIPH accurately reports its abilities based purely
on verified execution history."

Probes:
- Probe 1: Exact Section 19 card body line-by-line derivation
- Probe 2: Prompt assembly audit (no hardcoded capability lists, three-state ledger block)
- Probe 3: Degraded/failing error disclosure under [WARNING]
- Probe 4: Freshness decay to HISTORICAL_ONLY
- Probe 5: LLM bypass proof (monkeypatch LLM to raise; assert zero LLM calls on capability queries)
- Probe 6: Governed /capabilities command (presentation-only, single-capability card vs summary)
- Probe 7: Epistemic card grammar & anti-spoofing (whitelist precedence over bullets)
- Probe 8: Cold-start full compilation and stale cache disclosure header
- Probe 9: Multi-turn deterministic repeatability on capability verdict lines
- Probe 10: Baseline regression immunity (command registry compatibility)
"""

import os
import sys
import time
import uuid
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ciph.capabilities.capability_ledger import (
    CapabilityLedger,
    EmpiricalCapabilityProfile,
    CapabilityHealthStatus,
    CapabilityEvidenceState,
    ExecutionEvidenceAnchor,
    OutcomeCategory,
    NetworkPolicy,
    ExecutionToken,
    ExecutionReceipt,
    LedgerScanCheckpoint,
)
from ciph.operator.dialogue_formatter import DialogueFormatter
from ciph.capabilities.commands import CommandRegistry, CommandDefinition
from ciph.capabilities.local_commands import LOCAL_COMMANDS
from ciph.runtime import CiphRuntime
from ciph.kernel.crypto_identity import Ed25519KeyManager, KeyRole, TrustRegistry
from ciph.memory.event_store import EventStore
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.workers.receipts import generate_environment_fingerprint
from query_router import QueryRouter
from enhanced_conversation import CiphConversation
from ciph_router import CiphRouter
from cipher_vault import CipherVault
from state_manager import StateManager
from smart_memory import SmartMemory


class TestPhase9Step3EmpiricalSelfKnowledge(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ciph_step3_test_")
        self.db_path = os.path.join(self.test_dir, "test_vault.db")

        # Initialize crypto identities
        self.trust_registry = TrustRegistry(self.db_path)
        self.op_priv, self.op_pub = self.trust_registry.get_or_create_keypair("operator_root", KeyRole.OPERATOR)
        self.worker_priv, self.worker_pub = self.trust_registry.get_or_create_keypair("worker_primary", KeyRole.WORKER)
        self.kernel_priv, self.kernel_pub = self.trust_registry.get_or_create_keypair("kernel_primary", KeyRole.KERNEL)
        self.env_fingerprint = generate_environment_fingerprint()

        # Initialize event store and queue
        self.event_store = EventStore(self.db_path)
        self.queue = IPCJobQueue(self.db_path, trust_registry=self.trust_registry)

    def tearDown(self):
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_sample_profile(
        self,
        capability_name: str = "cybersecurity.bounty_scan",
        health_status: CapabilityHealthStatus = CapabilityHealthStatus.VERIFIED_ACTIVE,
        attempts: int = 5,
        clean_successes: int = 4,
        partial: int = 1,
        defect_failures: int = 0,
        operational_failures: int = 0,
        policy_blocked: int = 0,
        last_success_at: float = 1773000000.0,
        manifest_version: str = "1.0.0",
        targets=("target.test", "scan.example.com"),
        transports=("TOR_SOCKS5",),
        receipt_ids=("rcpt_001", "rcpt_002"),
    ) -> EmpiricalCapabilityProfile:
        anchors = tuple(
            ExecutionEvidenceAnchor(
                receipt_id=rid,
                event_id=idx + 1,
                job_id=f"job_{idx}",
                attempt_number=1,
                executed_at=last_success_at,
                outcome=OutcomeCategory.SUCCESS,
                exit_code=0,
                latency_ms=45.0,
                output_hash="hash_abc",
                worker_id="worker_primary",
                environment_fingerprint=self.env_fingerprint,
                bound_manifest_version=manifest_version,
                observed_transport=transports[0] if transports else "OFFLINE_LOCAL",
                tested_target=targets[0] if targets else "local"
            )
            for idx, rid in enumerate(receipt_ids)
        )

        return EmpiricalCapabilityProfile(
            capability_name=capability_name,
            registered_in_manifest=True,
            current_manifest_version=manifest_version,
            evidence_state=CapabilityEvidenceState.CURRENT_VERSION_PROVEN,
            health_status=health_status,
            current_version_attempts=attempts,
            current_version_clean_successes=clean_successes,
            current_version_defect_failures=defect_failures,
            current_version_operational_failures=operational_failures,
            current_version_policy_blocked=policy_blocked,
            current_version_partial=partial,
            defect_failure_rate=0.0 if clean_successes + defect_failures > 0 else None,
            operational_failure_rate=0.0 if clean_successes + operational_failures > 0 else None,
            overall_success_rate=clean_successes / attempts if attempts > 0 else None,
            last_qualifying_success_at=last_success_at,
            last_attempt_at=last_success_at,
            clean_success_latency_p50_ms=45.0,
            clean_success_latency_p95_ms=50.0,
            clean_success_latency_avg_ms=47.5,
            lifetime_total_attempts=attempts,
            lifetime_reconciled_jobs=0,
            declared_network_policy="TOR_ONLY",
            observed_transports=tuple(transports),
            tested_targets=tuple(targets),
            recent_evidence_anchors=anchors,
            conflict_reasons=()
        )

    # =========================================================================
    # Probe 1: Exact Section 19 Card Body Line-by-Line Derivation
    # =========================================================================
    def test_probe1_exact_section19_card_derivation(self):
        profile = self._create_sample_profile()
        manifest_hash = "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"

        card_body = CapabilityLedger.format_capability_card(profile, manifest_hash=manifest_hash)
        lines = card_body.splitlines()

        # Must have exactly 15 authoritative Section 19 lines
        self.assertEqual(len(lines), 15, f"Expected exactly 15 lines, got {len(lines)}:\n{card_body}")

        expected_labels = [
            "Capability:",
            "Registered:",
            "Available now:",
            "Provider version:",
            "Manifest hash:",
            "Last verified:",
            "Recent attempts:",
            "Successful:",
            "Partial:",
            "Execution failures:",
            "Policy-blocked:",
            "Tested targets:",
            "Verified transport:",
            "Environment:",
            "Evidence receipts:",
        ]
        for idx, (line, label) in enumerate(zip(lines, expected_labels)):
            self.assertTrue(
                line.startswith(label),
                f"Line {idx} expected to start with '{label}', got: '{line}'"
            )

        # Value assertions
        self.assertIn("cybersecurity.bounty_scan", lines[0])
        self.assertEqual(lines[1], "Registered: yes")
        self.assertEqual(lines[2], "Available now: yes (VERIFIED_ACTIVE)")
        self.assertEqual(lines[3], "Provider version: 1.0.0")
        self.assertEqual(lines[4], f"Manifest hash: {manifest_hash}")
        self.assertIn("UTC", lines[5])
        self.assertEqual(lines[6], "Recent attempts: 5")
        self.assertEqual(lines[7], "Successful: 4")
        self.assertEqual(lines[8], "Partial: 1")
        self.assertEqual(lines[9], "Execution failures: 0")
        self.assertEqual(lines[10], "Policy-blocked: 0")
        self.assertIn("scan.example.com", lines[11])
        self.assertEqual(lines[12], "Verified transport: TOR_SOCKS5")
        self.assertEqual(lines[13], f"Environment: {self.env_fingerprint}")
        self.assertEqual(lines[14], "Evidence receipts: [rcpt_001, rcpt_002]")

        # Formatter block header and indentation verification
        formatted_card = DialogueFormatter.format_single_capability_card(profile, manifest_hash=manifest_hash)
        formatted_lines = formatted_card.splitlines()
        self.assertEqual(formatted_lines[0], "[FACT] CAPABILITY PROFILE: cybersecurity.bounty_scan")
        for bline in formatted_lines[1:]:
            self.assertTrue(bline.startswith("  "), f"Line in card body must be indented by 2 spaces: '{bline}'")

    # =========================================================================
    # Probe 2: Prompt Assembly Audit (Prompt Laundering Eradication)
    # =========================================================================
    def test_probe2_prompt_assembly_audit(self):
        vault = CipherVault(self.db_path)
        mem = SmartMemory(vault)

        # 1. Inspect real memory pins initialized by CiphCore
        from ciph_core import CiphCore
        core = CiphCore.__new__(CiphCore)
        core.vault = vault
        core.smart_memory = mem
        core._init_memory_pins()

        # Verify the real pins initialized by CiphCore
        cap_pin = core.smart_memory.get_pinned('capability_awareness')
        self.assertIsNotNone(cap_pin)
        self.assertIn("strictly determined by the empirical capability ledger", cap_pin)

        resp_pin = core.smart_memory.get_pinned('response_style')
        self.assertIsNotNone(resp_pin)
        self.assertIn("empirically verified capabilities from the capability ledger", resp_pin)

        # Assert the forbidden hardcoded capability laundry list is NOT in pins
        forbidden_phrases = [
            "darknet threat intel via Tor, bug bounty",
            "darknet threat intel via tor, bug bounty vulnerability scanning",
            "port scanning, web vulnerability detection",
        ]
        all_pins_text = " ".join(
            item.get('value', '') if isinstance(item, dict) else str(item)
            for item in core.smart_memory.pinned_facts.values()
        ).lower()
        for phrase in forbidden_phrases:
            self.assertNotIn(phrase.lower(), all_pins_text, f"Forbidden capability laundry string '{phrase}' found in memory pins!")

        # Source code audit of ciph_core.py directly
        ciph_core_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ciph_core.py")
        with open(ciph_core_path, "r", encoding="utf-8") as f:
            ciph_core_src = f.read().lower()
        for phrase in forbidden_phrases:
            self.assertNotIn(phrase.lower(), ciph_core_src, f"Forbidden capability laundry string '{phrase}' found in ciph_core.py source!")

        # 2. Inspect enhanced_conversation prompt assembly
        rt = CiphRuntime(db_path=self.db_path)
        conv = CiphConversation(vault, runtime=rt)
        prompt = conv._build_system_prompt()

        # Prompt must contain the empirical three-state grounding block
        self.assertIn("[EMPIRICAL CAPABILITY STATUS (DERIVED STRICTLY FROM RECEIPT LEDGER)]", prompt)
        self.assertIn("CAPABILITY GROUNDING RULES:", prompt)

        # Assert no phantom capabilities mentioned as active without verification
        for phrase in forbidden_phrases:
            self.assertNotIn(phrase.lower(), prompt.lower(), f"Forbidden capability laundry string '{phrase}' found in assembled system prompt!")
        rt.close()

    # =========================================================================
    # Probe 3: Degraded/Failing Error Disclosure under [WARNING]
    # =========================================================================
    def test_probe3_degraded_failing_error_disclosure(self):
        # Create a FAILING capability profile
        failing_profile = self._create_sample_profile(
            capability_name="osint.gather_intel",
            health_status=CapabilityHealthStatus.FAILING,
            attempts=3,
            clean_successes=0,
            defect_failures=3,
            operational_failures=0,
            partial=0,
            last_success_at=None,
            receipt_ids=()
        )

        card = DialogueFormatter.format_single_capability_card(failing_profile)
        self.assertTrue(card.startswith("[WARNING] CAPABILITY PROFILE: osint.gather_intel"))
        self.assertIn("Available now: no (FAILING)", card)
        self.assertIn("Execution failures: 3", card)
        self.assertIn("Last verified: N/A", card)

        # Formatter integrity check on card
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(card))

        # Create a briefing report dict containing this degraded capability
        report_dict = {
            "summary": {
                "total_capabilities_tracked": 3,
                "verified_active_count": 1,
                "untested_count": 1,
                "historical_only_count": 0,
                "degraded_count": 1,
                "conflicted_count": 0,
                "verified_active_capabilities": ["cybersecurity.bounty_scan"],
                "untested_capabilities": ["math.compute"],
                "degraded_capabilities": ["osint.gather_intel"],
            },
            "checkpoint": {"scan_timestamp": time.time()}
        }
        briefing = DialogueFormatter.format_capability_briefing(report_dict)
        self.assertIn("[WARNING] UNVERIFIED / DEGRADED / UNAVAILABLE CAPABILITIES", briefing)
        self.assertIn("• osint.gather_intel (DEGRADED)", briefing)
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(briefing))

    # =========================================================================
    # Probe 4: Freshness Decay to HISTORICAL_ONLY
    # =========================================================================
    def test_probe4_freshness_decay_to_historical_only(self):
        expired_profile = self._create_sample_profile(
            capability_name="trading.portfolio_check",
            health_status=CapabilityHealthStatus.HISTORICAL_ONLY,
            attempts=10,
            clean_successes=10,
            last_success_at=time.time() - (20 * 86400.0),  # 20 days ago (TTL is 14 days)
        )

        card = DialogueFormatter.format_single_capability_card(expired_profile)
        self.assertTrue(card.startswith("[WARNING] CAPABILITY PROFILE: trading.portfolio_check"))
        self.assertIn("Available now: no (HISTORICAL_ONLY - verified evidence expired)", card)
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(card))

        report_dict = {
            "summary": {
                "total_capabilities_tracked": 1,
                "verified_active_count": 0,
                "untested_count": 0,
                "historical_only_count": 1,
                "degraded_count": 0,
                "conflicted_count": 0,
                "historical_only_capabilities": ["trading.portfolio_check"],
            },
            "checkpoint": {"scan_timestamp": time.time()}
        }
        briefing = DialogueFormatter.format_capability_briefing(report_dict)
        self.assertIn("[WARNING] UNVERIFIED / DEGRADED / UNAVAILABLE CAPABILITIES", briefing)
        self.assertIn("• trading.portfolio_check (HISTORICAL_ONLY)", briefing)
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(briefing))

    # =========================================================================
    # Probe 5: LLM Bypass Proof
    # =========================================================================
    def test_probe5_llm_bypass_proof(self):
        rt = CiphRuntime(db_path=self.db_path)
        vault = CipherVault(self.db_path)
        state = StateManager()
        mem = SmartMemory(vault)

        # Wire query router and conversation
        qrouter = QueryRouter(state, vault, runtime=rt)
        mock_brain = MagicMock()
        mock_brain.route.side_effect = AssertionError("LLM BrainRouter/CiphRouter.route MUST NOT BE CALLED on capability queries")
        mock_brain.think.side_effect = AssertionError("LLM CiphRouter.think MUST NOT BE CALLED on capability queries")

        conv = CiphConversation(vault, router=mock_brain, smart_memory=mem, runtime=rt)

        test_queries = [
            "what can you do",
            "what are your capabilities",
            "ciph capabilities",
            "show capabilities",
            "list capabilities",
            "what can ciph do",
            "what do you do",
            "what are you capable of",
        ]

        # 1. Test QueryRouter directly
        for q in test_queries:
            self.assertTrue(qrouter.can_handle(q), f"QueryRouter should recognize '{q}'")
            ans = qrouter.answer(q)
            self.assertIn("🏛️ EMPIRICAL CAPABILITY BRIEFING", ans)
            self.assertTrue(DialogueFormatter.verify_epistemic_integrity(ans))

        # 2. Test Conversation layer interception
        for q in test_queries:
            ans = conv.process_input(q)
            self.assertIn("🏛️ EMPIRICAL CAPABILITY BRIEFING", ans)
            self.assertTrue(DialogueFormatter.verify_epistemic_integrity(ans))

        # 3. Test direct single capability query
        ans_single = rt.answer_capability_query("cybersecurity.bounty_scan")
        self.assertIn("CAPABILITY PROFILE: cybersecurity.bounty_scan", ans_single)
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(ans_single))

        # Assert no calls reached the mock LLM
        mock_brain.route.assert_not_called()
        mock_brain.think.assert_not_called()
        rt.close()

    # =========================================================================
    # Probe 6: Governed /capabilities Command
    # =========================================================================
    def test_probe6_governed_capabilities_command(self):
        registry = CommandRegistry()

        # Assert /capabilities and alias /self-knowledge exist in registry
        cmd_def = registry.find_command("/capabilities")
        self.assertIsNotNone(cmd_def)
        self.assertEqual(cmd_def.command, "/capabilities")
        self.assertIn("/self-knowledge", cmd_def.aliases)

        # Assert alias lookup returns same command definition
        alias_def = registry.find_command("/self-knowledge")
        self.assertEqual(alias_def, cmd_def)

        # CRITICAL CONSTRAINT: Must NOT be in LOCAL_COMMANDS
        self.assertNotIn(
            "/capabilities",
            LOCAL_COMMANDS,
            "/capabilities must NOT be in LOCAL_COMMANDS to prevent breaking receipt expectations"
        )
        self.assertNotIn(
            "/self-knowledge",
            LOCAL_COMMANDS,
            "/self-knowledge must NOT be in LOCAL_COMMANDS"
        )

        rt = CiphRuntime(db_path=self.db_path)

        # 1. Summary briefing dispatch
        res1 = registry.dispatch("/capabilities", rt)
        self.assertEqual(res1["status"], "SUCCESS")
        self.assertIsNone(res1["receipt"], "Presentation-only command must have receipt: None")
        self.assertIn("🏛️ EMPIRICAL CAPABILITY BRIEFING", res1["dialogue"])
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(res1["dialogue"]))

        # 2. Single capability inspection dispatch
        res2 = registry.dispatch("/capabilities cybersecurity.bounty_scan", rt)
        self.assertEqual(res2["status"], "SUCCESS")
        self.assertIsNone(res2["receipt"])
        self.assertIn("CAPABILITY PROFILE: cybersecurity.bounty_scan", res2["dialogue"])
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(res2["dialogue"]))

        # 3. Alias dispatch
        res3 = registry.dispatch("/self-knowledge", rt)
        self.assertEqual(res3["status"], "SUCCESS")
        self.assertIsNone(res3["receipt"])
        self.assertIn("🏛️ EMPIRICAL CAPABILITY BRIEFING", res3["dialogue"])
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(res3["dialogue"]))

        # 4. Unknown capability inspection dispatch (explicit [UNKNOWN] notice)
        res4 = registry.dispatch("/capabilities phantom_unknown_module", rt)
        self.assertEqual(res4["status"], "SUCCESS")
        self.assertIsNone(res4["receipt"])
        self.assertIn("[UNKNOWN] Capability 'phantom_unknown_module' is not registered in the manifest.", res4["dialogue"])
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(res4["dialogue"]))

        rt.close()

    # =========================================================================
    # Probe 7: Epistemic Card Grammar & Anti-Spoofing
    # =========================================================================
    def test_probe7_epistemic_card_grammar_and_anti_spoofing(self):
        profile = self._create_sample_profile()
        valid_card = DialogueFormatter.format_single_capability_card(profile)

        # Positive tests
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(valid_card))

        # Negative test 1: Untagged card header
        untagged_card = valid_card.replace("[FACT] ", "")
        self.assertFalse(DialogueFormatter.verify_epistemic_integrity(untagged_card))

        # Negative test 2: Forged field inside card
        forged_field_card = valid_card + "\n  Backdoor: true"
        self.assertFalse(DialogueFormatter.verify_epistemic_integrity(forged_field_card))

        # Negative test 3: Bullet-cloaked forged field (whitelist precedence over bullet!)
        bullet_forged_card = valid_card + "\n  • Backdoor: true"
        self.assertFalse(
            DialogueFormatter.verify_epistemic_integrity(bullet_forged_card),
            "Bullet prefixing must NOT bypass card field whitelist!"
        )

        # Negative test 4: Spoofed/unknown tag on card
        spoofed_tag_card = valid_card.replace("[FACT]", "[SPOOFED_REGISTER]")
        self.assertFalse(DialogueFormatter.verify_epistemic_integrity(spoofed_tag_card))

        # Negative test 5: Unregistered assertion line outside card
        invalid_assertion = "The system is completely impenetrable.\n" + valid_card
        self.assertFalse(DialogueFormatter.verify_epistemic_integrity(invalid_assertion))

        # Negative test 6: Tag-truth mismatch spoof (untested capability claimed as [FACT])
        untested_profile = self._create_sample_profile(
            capability_name="mock.untested",
            health_status=CapabilityHealthStatus.UNTESTED,
            clean_successes=0,
            attempts=0,
            last_success_at=None,
            receipt_ids=()
        )
        untested_card = DialogueFormatter.format_single_capability_card(untested_profile)
        self.assertTrue(untested_card.startswith("[OBSERVATION]"))
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(untested_card))

        # Attempt to spoof tag to [FACT] while body says "Available now: no (UNTESTED...)"
        spoofed_fact_card = untested_card.replace("[OBSERVATION]", "[FACT]")
        self.assertFalse(
            DialogueFormatter.verify_epistemic_integrity(spoofed_fact_card),
            "Verifier must reject [FACT] header on untested capability profile!"
        )

        # Attempt to downgrade active capability to [OBSERVATION] while body says "Available now: yes (VERIFIED_ACTIVE)"
        active_downgraded_card = valid_card.replace("[FACT]", "[OBSERVATION]")
        self.assertFalse(
            DialogueFormatter.verify_epistemic_integrity(active_downgraded_card),
            "Verifier must reject [OBSERVATION] header on active capability profile!"
        )

    # =========================================================================
    # Probe 8: Cold-Start Full Compilation and Stale Cache Disclosure Header
    # =========================================================================
    def test_probe8_cold_start_full_compilation_and_stale_cache_disclosure(self):
        rt = CiphRuntime(db_path=self.db_path)

        # Verify cold cache is initially None
        self.assertIsNone(rt.idle_maintenance_engine.compiled_ledger_cache)

        # First call triggers cold-start full compilation with genesis verification
        briefing = rt.generate_capability_briefing()
        self.assertIn("🏛️ EMPIRICAL CAPABILITY BRIEFING", briefing)
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(briefing))

        # Verify cache is now populated with full verification
        cached = rt.get_cached_capability_ledger()
        self.assertIsNotNone(cached)
        profiles, checkpoint = cached
        self.assertIn(checkpoint.verification_status, ("VERIFIED_EMPTY", "VERIFIED_COMPLETE"))
        self.assertEqual(checkpoint.last_verified_event_hash, "GENESIS_BLOCK_CIPH_4.0")

        # Verify empty/untested state is handled honestly: 0 verified active
        self.assertEqual(len([p for p in profiles.values() if p.health_status == CapabilityHealthStatus.VERIFIED_ACTIVE]), 0)

        # Simulate stale cache: artificially set checkpoint timestamp 4000s in the past (> 3600s TTL)
        stale_cp = LedgerScanCheckpoint(
            attempted_barrier_id=checkpoint.attempted_barrier_id,
            attempted_barrier_hash=checkpoint.attempted_barrier_hash,
            last_verified_event_id=checkpoint.last_verified_event_id,
            last_verified_event_hash=checkpoint.last_verified_event_hash,
            verification_status=checkpoint.verification_status,
            is_complete=checkpoint.is_complete,
            total_events_scanned=checkpoint.total_events_scanned,
            qualifying_receipts_count=checkpoint.qualifying_receipts_count,
            duplicate_replays_count=checkpoint.duplicate_replays_count,
            conflicting_receipts_count=checkpoint.conflicting_receipts_count,
            reconciliation_events_count=checkpoint.reconciliation_events_count,
            reconciled_jobs_count=checkpoint.reconciled_jobs_count,
            unverifiable_receipts_count=checkpoint.unverifiable_receipts_count,
            scan_timestamp=time.time() - 4000.0,
            unresolved_reconciled_jobs_count=0
        )
        rt.idle_maintenance_engine.compiled_ledger_cache = (profiles, stale_cp)

        stale_briefing = rt.generate_capability_briefing()
        self.assertIn("STALE CACHE", stale_briefing)
        self.assertIn("Idle maintenance recommended", stale_briefing)
        self.assertTrue(DialogueFormatter.verify_epistemic_integrity(stale_briefing))

        rt.close()

    # =========================================================================
    # Probe 9: Multi-Turn Deterministic Repeatability
    # =========================================================================
    def test_probe9_multiturn_deterministic_repeatability(self):
        rt = CiphRuntime(db_path=self.db_path)

        # 1. Briefing repeatability across 10 turns
        first_briefing = rt.answer_capability_query("what can you do")
        for turn in range(10):
            next_briefing = rt.answer_capability_query("what can you do")
            self.assertEqual(
                first_briefing,
                next_briefing,
                f"Non-deterministic briefing output at turn {turn}"
            )

        # 2. Single capability card repeatability across 10 turns
        first_card = rt.answer_capability_query("cybersecurity.bounty_scan")
        for turn in range(10):
            next_card = rt.answer_capability_query("cybersecurity.bounty_scan")
            self.assertEqual(
                first_card,
                next_card,
                f"Non-deterministic card output at turn {turn}"
            )

        rt.close()

    # =========================================================================
    # Probe 10: Baseline Regression Immunity
    # =========================================================================
    def test_probe10_baseline_regression_immunity(self):
        # Verify that all LOCAL_COMMANDS remain pure and untouched by presentation commands
        registry = CommandRegistry()
        for lc in LOCAL_COMMANDS:
            cd = registry.find_command(lc.command)
            self.assertIsNotNone(cd, f"LOCAL_COMMAND {lc.command} missing from registry")
            self.assertNotEqual(cd.command, "/capabilities")
            self.assertNotEqual(cd.command, "/self-knowledge")

        rt = CiphRuntime(db_path=self.db_path)
        try:
            # Verify command argument checking is unaffected for normal commands
            res_missing = registry.dispatch("/bounty", rt)
            self.assertEqual(res_missing["status"], "INCOMPLETE_INTENT")
            self.assertIn("target", res_missing.get("missing_parameters", []))

            # Verify /capabilities presents briefing without requiring arguments
            res_caps = registry.dispatch("/capabilities", rt)
            self.assertEqual(res_caps["status"], "SUCCESS")
            self.assertIsNone(res_caps["receipt"])
        finally:
            rt.close()


    def test_probe11_briefing_categorizes_every_health_status(self):
        """Every health status must land in exactly one briefing section; nothing may be dropped."""
        from types import SimpleNamespace
        from ciph.runtime import CiphRuntime

        rt = CiphRuntime(db_path=self.db_path)
        try:
            statuses = [
                "VERIFIED_ACTIVE", "UNTESTED", "LEGACY_UNVERIFIED", "UNREGISTERED", "HISTORICAL_ONLY",
                "DEPENDENCY_UNVERIFIED", "DEPENDENCY_FAILED", "POLICY_RESTRICTED_ONLY",
                "PARTIAL_ONLY", "FAILING", "INCONCLUSIVE_SAMPLE", "DEGRADED",
                "OPERATIONAL_DEGRADED", "INTEGRITY_CONFLICT", "UNAVAILABLE",
            ]
            profiles = {}
            for status in statuses:
                name = f"probe.{status.lower()}"
                profiles[name] = self._create_sample_profile(
                    capability_name=name,
                    health_status=CapabilityHealthStatus(status),
                )

            checkpoint = SimpleNamespace(
                verification_status="VERIFIED_COMPLETE", is_complete=True,
                total_events_scanned=len(statuses), duplicate_replays_count=0,
                conflicting_receipts_count=0, reconciled_jobs_count=0,
                unverifiable_receipts_count=0, scan_timestamp=time.time(),
            )
            report = rt._build_report_dict_from_profiles(profiles, checkpoint)
            summary = report["summary"]

            listed = (
                set(summary["verified_active_capabilities"])
                | set(summary["untested_capabilities"])
                | set(summary["warning_capabilities"])
            )
            self.assertEqual(listed, set(profiles), "Every tracked capability must be listed")
            self.assertEqual(summary["total_capabilities_tracked"], len(profiles))
            self.assertEqual(
                summary["total_capabilities_tracked"],
                len(summary["verified_active_capabilities"])
                + len(summary["untested_capabilities"])
                + len(summary["warning_capabilities"]),
                "Section counts must sum to the tracked total",
            )

            # A status the previous five-bucket builder dropped is now surfaced with its real label.
            self.assertIn("probe.dependency_unverified", summary["warning_capabilities"])
            self.assertEqual(
                summary["warning_status_by_name"]["probe.dependency_unverified"],
                "DEPENDENCY_UNVERIFIED",
            )

            text = DialogueFormatter.format_capability_briefing(
                report, scan_timestamp=checkpoint.scan_timestamp
            )
            self.assertNotIn("were not", text, "Briefing must not report uncategorized capabilities")
            self.assertIn("probe.dependency_unverified (DEPENDENCY_UNVERIFIED)", text)
            self.assertTrue(DialogueFormatter.verify_epistemic_integrity(text))
        finally:
            rt.shutdown()

    def test_probe12_live_card_manifest_hash_and_unknown_name(self):
        """The live card carries the real manifest hash, and unknown names are answered honestly."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import (
            AuthorizationTier, CapabilityManifest, NetworkPolicy, ReversibilityClass, RiskTier,
        )

        class HashCap(BaseCapability):
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="probe.hash", description="manifest hash probe",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                return {"ok": True}

        rt = CiphRuntime(db_path=self.db_path)
        try:
            rt.register_capability(HashCap())
            card = rt.answer_capability_query("probe.hash")
            self.assertIn("Manifest hash: ", card)
            self.assertNotIn("Manifest hash: N/A", card, "Registered capability must expose its manifest hash")

            unknown = rt.answer_capability_query("not.a.real.capability")
            self.assertTrue(unknown.startswith("[UNKNOWN]"), unknown)
            self.assertIn("not registered", unknown)
        finally:
            rt.shutdown()

    def test_probe13_legacy_receipt_verification_and_labeling(self):
        """Era-correct legacy hash verification for integrity display only; grants no credit and labels LEGACY_UNVERIFIED."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import (
            AuthorizationTier, CapabilityManifest, NetworkPolicy, ReversibilityClass, RiskTier,
        )
        import hashlib
        import json

        class LegacyProbeCap(BaseCapability):
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="probe.legacy_cap", description="legacy probe",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO,
                )

            def run(self, params, context=None):
                return {"ok": True}

        rt = CiphRuntime(db_path=self.db_path)
        try:
            rt.register_capability(LegacyProbeCap())

            # Legacy receipts produced with json.dumps(results)
            results_payload = {"status": "ok"}
            legacy_hash = hashlib.sha256(json.dumps(results_payload).encode('utf-8')).hexdigest()
            canonical_hash = hashlib.sha256(json.dumps(results_payload, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
            self.assertNotEqual(legacy_hash, canonical_hash)

            receipt_payload = {
                "capability": "probe.legacy_cap",
                "receipt_id": "rcpt_legacy_001",
                "job_id": "job_legacy_001",
                "started_at": 100.0,
                "completed_at": 110.0,
                "attempt_number": 1,
                "exit_code": 0,
                "schema_version": "4.0",
                "results": results_payload,
                "output_hash": legacy_hash,
            }

            rt.event_store.append_event(
                event_type="ExecutionReceiptStoredEvent",
                aggregate_id="rcpt_legacy_001",
                payload=receipt_payload
            )

            profiles, checkpoint = rt.capability_ledger.compile_empirical_ledger()
            self.assertEqual(checkpoint.legacy_verified_receipts_count, 1)
            self.assertEqual(checkpoint.unverifiable_receipts_count, 1)

            prof = profiles.get("probe.legacy_cap")
            self.assertIsNotNone(prof)
            # Proves old receipts weren't altered, grants no credit:
            self.assertEqual(prof.health_status, CapabilityHealthStatus.LEGACY_UNVERIFIED)
            self.assertEqual(prof.current_version_clean_successes, 0)

            # Card formatting
            card = DialogueFormatter.format_single_capability_card(prof)
            self.assertIn("Available now: no (LEGACY_UNVERIFIED - historical receipts unverified under current canonical rules)", card)
            self.assertTrue(card.startswith("[WARNING] CAPABILITY PROFILE: probe.legacy_cap"))
            self.assertTrue(DialogueFormatter.verify_epistemic_integrity(card))

            # Briefing formatting
            report = rt.capability_ledger.generate_self_knowledge_report()
            briefing = DialogueFormatter.format_capability_briefing(report)
            self.assertIn("Historical receipts: 1 unverified under current canonical rules", briefing)
            self.assertIn("(1 verified against era-correct legacy hashes; confer no capability credit)", briefing)
            self.assertIn("• probe.legacy_cap (LEGACY_UNVERIFIED)", briefing)
            self.assertTrue(DialogueFormatter.verify_epistemic_integrity(briefing))
        finally:
            rt.shutdown()


if __name__ == "__main__":
    unittest.main()
