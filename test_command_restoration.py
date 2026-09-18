"""Restored commands exercise actual governed execution and durable test stores."""
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from cipher_vault import CipherVault
from ciph.runtime import CiphRuntime
from ciph.capabilities.local_commands import LOCAL_COMMANDS, RECORDS
from ciph.capabilities.command_retirement import coverage
from ciph.contracts.grants import AuthorizationGrant
from ciph_core import CiphCore


class TestRestoredCommands(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-command-test-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.vault = CipherVault(str(root/"vault.db"), str(root/"key"), str(root/"salt"))
        self.runtime = CiphRuntime(vault=self.vault, db_path=self.vault.db_path)
        self.addCleanup(self.runtime.shutdown)

    def run_command(self, command):
        result = self.runtime.dispatch_slash_command(command)
        self.assertEqual(result["status"], "SUCCESS", result)
        self.assertTrue(result["receipt"].verify_signature(trust_registry=self.runtime.trust_registry))
        self.assertEqual(result["claim"].epistemic_state.value, "OBSERVED")
        self.assertLessEqual(result["claim"].freshness_deadline, result["receipt"].completed_at+300)
        return result

    def test_every_argument_free_reader_has_real_receipt_and_display(self):
        for spec in LOCAL_COMMANDS:
            if not spec.argument:
                with self.subTest(command=spec.command):
                    result = self.run_command(spec.command)
                    self.assertIn("report_data", result["receipt"].results)
                    self.assertIn("Local record snapshot", result["dialogue"])
                    self.assertEqual(result["receipt"].actual_transport_used, "OFFLINE_ONLY")

    def test_aliases_resolve_to_same_capability_and_reject_extra_arguments(self):
        for spec in LOCAL_COMMANDS:
            for name in (spec.command, *spec.aliases):
                with self.subTest(name=name):
                    self.assertEqual(self.runtime.command_registry.find_command(name).capability_name, spec.capability)
                    self.assertEqual(self.runtime.dispatch_slash_command(name+" secret=ignored")["status"], "INVALID_ARGUMENTS")

    def test_parameters_validated_even_without_command_parser(self):
        from ciph.planner.schemas import IntentProposal
        result = self.runtime.execute_reference_loop(IntentProposal(proposal_id="invalid-operator", objective="inspect", proposed_capability="operator.status", provided_parameters={"method": "resume_curiosity"}))
        self.assertNotEqual(result["status"], "SUCCESS")
        self.assertIsNone(result.get("claim"))

    def test_direct_execute_still_requires_worker_context(self):
        cap = self.runtime.registry.get("operator.status")
        receipt = cap.execute({})
        self.assertNotEqual(receipt.exit_code, 0)
        self.assertIn("GATE_ZERO_VIOLATION", receipt.error_message)

    def test_jobs_hide_inputs_tokens_and_secrets(self):
        created = self.runtime.dispatch_slash_command('/memory set fixture "CANARY_PRIVATE_INPUT"')
        for command in ("/jobs", "/job-status "+created["job_id"], "/what-changed", "/auth-status"):
            data = self.run_command(command)["receipt"].results
            encoded = json.dumps(data)
            self.assertNotIn("CANARY_PRIVATE_INPUT", encoded)
            self.assertNotIn("execution_token", encoded)
            self.assertNotIn(self.runtime.worker_secret_key.hex(), encoded)

    def test_result_and_inspect_bind_existing_evidence(self):
        created = self.runtime.dispatch_slash_command('/memory set fixture value')
        value = self.run_command("/result "+created["job_id"])["receipt"].results["report_data"]
        self.assertEqual(value["result"], created["receipt"].results)
        data = self.run_command("/inspect "+created["claim"].claim_id)["receipt"].results["report_data"]
        self.assertTrue(data["usable"])
        self.assertEqual(data["claim"]["claim_id"], created["claim"].claim_id)

    def test_missing_ids_return_explicit_absence(self):
        for cmd in ("/job-status missing", "/result missing", "/inspect missing"):
            self.assertFalse(self.run_command(cmd)["receipt"].results["report_data"]["found"])

    def test_result_rejects_tampered_receipt(self):
        created = self.runtime.dispatch_slash_command('/memory set fixture value')
        with self.runtime.event_store._get_connection() as conn:
            conn.execute("UPDATE ciph_event_store SET payload='{}' WHERE aggregate_id=?", (created["receipt"].receipt_id,))
        result = self.runtime.dispatch_slash_command("/result "+created["job_id"])
        self.assertNotEqual(result["status"], "SUCCESS")
        self.assertIsNone(result.get("claim"))

    def test_profile_is_stored_assertion_not_domain_truth(self):
        self.vault.store_profile_fact("P1", "operator", "name", "Fixture", 0.9)
        data = self.run_command("/profile")["receipt"].results["report_data"]
        self.assertEqual(data["records"][0]["value"], "Fixture")

    def test_corrupt_records_are_errors_not_empty_success(self):
        self.vault.store_profile_fact("P1", "operator", "name", "Fixture")
        conn = self.vault._get_connection()
        try:
            conn.execute("UPDATE operator_profile SET value_enc='corrupt'")
            conn.commit()
        finally:
            conn.close()
        result = self.runtime.dispatch_slash_command("/profile")
        self.assertNotEqual(result["status"], "SUCCESS")
        self.assertIsNone(result.get("claim"))

    def test_missing_table_is_error_not_healthy_empty_report(self):
        conn = self.vault._get_connection()
        try:
            conn.execute("DROP TABLE cognitive_blueprints")
            conn.commit()
        finally:
            conn.close()
        result = self.runtime.dispatch_slash_command("/blueprints")
        self.assertNotEqual(result["status"], "SUCCESS")

    def test_record_list_is_bounded_and_marks_truncation(self):
        for index in range(30):
            self.vault.store_profile_fact(str(index), "operator", str(index), "value")
        data = self.run_command("/profile")["receipt"].results["report_data"]
        self.assertEqual(len(data["records"]), 25)
        self.assertTrue(data["truncated"])

    def test_recon_diff_compares_actual_stored_snapshots(self):
        first = self.run_command("/recon-diff example.test")
        self.assertEqual(first["receipt"].results["report_data"]["comparison"], "INSUFFICIENT_HISTORY")
        self.vault.store_recon_snapshot("example.test", {"subdomains": ["a"], "old": True})
        self.vault.store_recon_snapshot("example.test", {"subdomains": ["a", "b"]})
        data = self.run_command("/recon-diff example.test")["receipt"].results["report_data"]
        self.assertEqual(data["changes"]["subdomains"]["previous"], ["a"])
        self.assertEqual(data["changes"]["subdomains"]["current"], ["a", "b"])
        self.assertFalse(data["changes"]["old"]["current_present"])

    def grant(self, challenge):
        return AuthorizationGrant(grant_id="test_"+challenge["plan_hash"], plan_hash=challenge["plan_hash"],
            step_id=challenge["step_id"], capability=challenge["capability"], params_hash=challenge["params_hash"],
            scope_grant_id="", expires_at=time.time()+120).sign(self.runtime.auth_secret_key)

    def test_curiosity_controls_require_grants_and_do_not_launch_thread(self):
        r = self.runtime
        for cmd in ('/curiosity-off "maintenance"', '/curiosity-on "maintenance completed"'):
            before = r.question_dag.store.state()
            challenge = r.dispatch_slash_command(cmd)
            self.assertEqual(challenge["status"], "AUTHORIZATION_REQUIRED")
            self.assertEqual(r.question_dag.store.state(), before)
            grant = self.grant(challenge)
            done = r.dispatch_slash_command(cmd, auth_grant=grant)
            self.assertEqual(done["status"], "SUCCESS", done)
            self.assertFalse(r.curiosity_daemon.running)
            self.assertEqual(r.question_dag.store.state()["paused"], "-off" in cmd)
            replay = r.dispatch_slash_command(cmd, auth_grant=grant)
            self.assertEqual(replay["receipt"].receipt_id, done["receipt"].receipt_id)

    def test_control_grant_cannot_be_retargeted(self):
        challenge = self.runtime.dispatch_slash_command('/curiosity-off reason')
        grant = self.grant(challenge)
        result = self.runtime.dispatch_slash_command('/curiosity-on reason', auth_grant=grant)
        self.assertNotEqual(result["status"], "SUCCESS")
        self.assertFalse(self.runtime.question_dag.store.state()["paused"])

    def test_pause_survives_restart(self):
        cmd = '/curiosity-off restart'
        challenge = self.runtime.dispatch_slash_command(cmd)
        self.runtime.dispatch_slash_command(cmd, auth_grant=self.grant(challenge))
        self.runtime.shutdown()
        other = CiphRuntime(vault=self.vault, db_path=self.vault.db_path)
        self.addCleanup(other.shutdown)
        self.assertTrue(other.question_dag.store.state()["paused"])

    def test_failed_job_result_preserves_failure_without_claiming_success(self):
        created = self.runtime.dispatch_slash_command('/code-audit definitely_missing_fixture.py')
        self.assertNotEqual(created["status"], "SUCCESS")
        self.assertIsNotNone(created.get("receipt"))
        data = self.run_command("/result "+created["job_id"])["receipt"].results["report_data"]
        self.assertNotEqual(data["outcome"], "SUCCESS")

    def test_resume_preserves_spent_attempts(self):
        store = self.runtime.question_dag.store
        with store.transaction() as conn:
            store.put(conn, "attempt", "spent", {"attempt_id": "spent", "cost": 12, "reserved_at": time.time(), "status": "ANSWERED"}, "TEST_SPENT")
        store.pause("BUDGET_EXHAUSTED")
        command = '/curiosity-on "operator reassessment"'
        challenge = self.runtime.dispatch_slash_command(command)
        result = self.runtime.dispatch_slash_command(command, auth_grant=self.grant(challenge))
        self.assertEqual(result["status"], "SUCCESS")
        with store.transaction() as conn:
            self.assertEqual(store.get(conn, "attempt", "spent")["cost"], 12)

    def test_core_displays_actual_report(self):
        core = CiphCore.__new__(CiphCore)
        core.runtime = self.runtime
        text = core.handle_command("/status")
        self.assertIn("uptime_seconds", text)
        self.assertEqual(core.last_command_result["status"], "SUCCESS")

    def test_asset_inventory_is_not_mislabeled_as_credential_configuration(self):
        """Asset inspection is now governed; it must never be classified as credential configuration."""
        from ciph.capabilities.command_retirement import disposition
        result = self.runtime.dispatch_slash_command("/asset-inventory")
        self.assertEqual(result["status"], "SUCCESS")
        self.assertIsNotNone(result["receipt"])
        # The legacy classifier must not bucket asset inspection as secret configuration.
        self.assertNotEqual(disposition("/asset-inventory")[0], "SECRET_CONFIGURATION_RETIRED")
        self.assertNotEqual(disposition("/assets")[0], "SECRET_CONFIGURATION_RETIRED")

    def test_result_rejects_receipt_from_different_attempt(self):
        created = self.runtime.dispatch_slash_command('/memory set fixture value')
        with self.runtime.queue._get_connection() as conn:
            conn.execute("UPDATE ciph_ipc_jobs SET attempt_number=attempt_number+1 WHERE job_id=?", (created["job_id"],))
        result = self.runtime.dispatch_slash_command("/result "+created["job_id"])
        self.assertNotEqual(result["status"], "SUCCESS")
        self.assertIsNone(result.get("claim"))

    def test_oversized_record_is_rejected_and_terminal_control_bytes_are_escaped(self):
        self.vault.store_profile_fact("P1", "operator", "name", "\x1b[31mred")
        result = self.run_command("/profile")
        self.assertNotIn("\x1b", result["dialogue"])
        self.assertIn("\\u001b", result["dialogue"])
        self.vault.store_profile_fact("P1", "operator", "name", "x"*70000)
        result = self.runtime.dispatch_slash_command("/profile")
        self.assertNotEqual(result["status"], "SUCCESS")
        self.assertIn("REPORT_TOO_LARGE", result["receipt"].error_message)

    def test_batch2_restored_commands_inspection(self):
        """Batch 2 restorations: /alignment-check, /convo-summary, /changelog, /predictions."""
        # 1. /alignment-check
        self.vault.store_evolution_audit(
            "AUDIT-T1", "2026-09-18", 10, 2, 98.5,
            "Memory leak in worker pool", "Audit lease expiration"
        )
        res_align = self.run_command("/alignment-check")
        records_align = res_align["receipt"].results["report_data"]["records"]
        self.assertGreaterEqual(len(records_align), 1)
        self.assertEqual(records_align[0]["id"], "AUDIT-T1")
        self.assertEqual(records_align[0]["alignment_score"], 98.5)
        self.assertEqual(records_align[0]["blind_spots"], "Memory leak in worker pool")
        self.assertEqual(records_align[0]["next_day_agenda"], "Audit lease expiration")

        # Alias /interrogation-audit returns identical report
        res_alias = self.run_command("/interrogation-audit")
        self.assertEqual(res_alias["receipt"].results["report_data"]["records"][0]["id"], "AUDIT-T1")

        # 2. /convo-summary
        self.vault.store_conversation("Hello operator", "Operational status optimal", context_tag="briefing")
        res_convo = self.run_command("/convo-summary")
        records_convo = res_convo["receipt"].results["report_data"]["records"]
        self.assertGreaterEqual(len(records_convo), 1)
        self.assertEqual(records_convo[0]["context_tag"], "briefing")
        self.assertNotIn("Hello operator", json.dumps(records_convo))

        # 3. /changelog
        res_change = self.run_command("/changelog")
        self.assertIn("records", res_change["receipt"].results["report_data"])

        # 4. /predictions
        res_pred = self.run_command("/predictions")
        self.assertIn("records", res_pred["receipt"].results["report_data"])

    def test_command_coverage_is_inventory_derived(self):
        data = coverage(self.runtime.command_registry)
        self.assertEqual(data["registered_legacy_names"]+data["unavailable_legacy_names"], data["legacy_total"])
        self.assertGreater(data["registered_legacy_names"], 28)
        with mock.patch.object(self.runtime, "execute_reference_loop", side_effect=AssertionError("unexpected dispatch")):
            for row in data["unavailable"]:
                result = self.runtime.dispatch_slash_command(row["command"])
                self.assertEqual(result["status"], "COMMAND_UNAVAILABLE")
                self.assertEqual(result["reason_code"], row["reason"])
                self.assertIsNone(result["receipt"])


from phase5_test_support import EpistemicTestCase


class TestRestoredEvidenceInspection(EpistemicTestCase):
    def test_disputed_claims_are_visible_in_hypotheses_but_not_active_worldview(self):
        self.seed("old")
        self.seed("conflict", value="OFFLINE")
        result = self.runtime.dispatch_slash_command("/hypotheses")
        self.assertEqual(result["status"], "SUCCESS", result)
        data = result["receipt"].results["report_data"]
        self.assertEqual({c["claim_id"] for c in data}, {"old", "conflict"})
        self.assertTrue(all(c["state"] == "DISPUTED" for c in data))
        active = self.runtime.dispatch_slash_command("/reality-check")
        self.assertEqual(active["receipt"].results["report_data"], [])


if __name__ == "__main__":
    unittest.main()
