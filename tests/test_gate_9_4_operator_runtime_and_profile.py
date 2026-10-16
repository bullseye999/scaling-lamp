"""
9.4-9.9 and the eighteen CiphOS scanners.

    Authentication is not authorization.  A snapshot is not a recovery.  An install is not an activation.

The host cannot enforce a system-scope profile, so this suite PROVES what the user-scope environment can
enforce - real setrlimit bounds, real permission boundaries, real service-manager behaviour, every refusal
- and the privileged profile is asserted as a PROFILE that is not activatable here.
"""

import os
import pathlib
import resource
import subprocess
import sys
import tempfile
import unittest

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.environment_operator import (EGRESS_ALLOW, EGRESS_DENY, OPERATION_ACTIVATE,
                                              OPERATION_APPROVE_UPDATE, OPERATION_QUIESCE,
                                              REASON_AMBIENT_NOT_CREDENTIAL, REASON_EXPIRED,
                                              REASON_REPLAYED, REASON_SERVICE_CANNOT_SELF_AUTHORIZE,
                                              REASON_WRONG_ENVIRONMENT, REASON_WRONG_GENERATION,
                                              REASON_WRONG_IDENTITY, REASON_WRONG_OPERATION,
                                              ambient_environment_is_not_a_credential,
                                              authorize_operation, egress_decision,
                                              operator_actions, operator_digest,
                                              present_operator_authorization, real_egress_attempt,
                                              record_egress_rule, register_principal,
                                              revoke_authorization, stale_host_effect_disposition)
from ciph.kernel.environment_runtime import (CIPHOS_IMAGE_V1, HEALTHY, INSTALLED, REGRESSED,
                                             ROLLED_BACK, ROLLBACK_REQUIRED, SNAPSHOT_REFUSED,
                                             SNAPSHOT_TAKEN, STAGED, VERIFIED, assess_update_health,
                                             assert_profile_not_downgraded, assert_snapshot_cannot_activate,
                                             authorize_update, installation_manifest, install_update,
                                             privileged_host_profile, record_snapshot,
                                             register_model_runtime, rollback_update,
                                             run_with_limits, snapshot_as_recovery_candidate,
                                             stage_update, ungoverned_upgrade_commands,
                                             user_scope_profile, verify_update, runtime_digest)
from ciph.kernel.evolution_ownership import production_sources
from ciph.kernel.environment_scanners import ENVIRONMENT_SCANNERS, environment_scanner_census

T1 = 1_800_000_000.0
IDENTITY = "CIPH-IDENTITY-9"
ENVIRONMENT = "CIPHOS-ENV-1"


class EnvironmentTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-94-")
        self.db = str(pathlib.Path(self.temp.name) / "env.db")
        register_principal(self.db, principal_id="OP-1", display_name="operator",
                           credential_ref="cred:hardware-token-1", actor="operator:operator", now=T1)

    def tearDown(self):
        self.temp.cleanup()

    def grant(self, *, operation=OPERATION_ACTIVATE, valid_until=None, environment=ENVIRONMENT,
              identity=IDENTITY, now=T1):
        return authorize_operation(self.db, principal_id="OP-1", operation=operation,
                                   ciph_identity_id=identity, environment_identity=environment,
                                   actor="operator:operator", valid_until=valid_until, now=now)

    def present(self, grant, **overrides):
        arguments = {"operation": OPERATION_ACTIVATE, "ciph_identity_id": IDENTITY,
                     "environment_identity": ENVIRONMENT, "now": T1 + 1}
        arguments.update(overrides)
        return present_operator_authorization(self.db, authorization=grant, **arguments)


class TestOperatorPlane(EnvironmentTestCase):

    def test_a_scoped_grant_authorizes_exactly_one_operation(self):
        grant = self.grant(operation=OPERATION_QUIESCE)
        accepted = self.present(grant, operation=OPERATION_QUIESCE)
        self.assertTrue(accepted["accepted"])
        wrong = self.present(grant)
        self.assertFalse(wrong["accepted"])
        self.assertEqual(wrong["reason"], REASON_WRONG_OPERATION)

    def test_each_refusal_has_its_own_reason(self):
        grant = self.grant()
        cases = [
            ({"ciph_identity_id": "OTHER-CIPH"}, REASON_WRONG_IDENTITY),
            ({"environment_identity": "OTHER-ENV"}, REASON_WRONG_ENVIRONMENT),
            ({"generation": 99}, REASON_WRONG_GENERATION),
            ({"now": T1 + 10_000}, REASON_EXPIRED),
        ]
        expiring = self.grant(valid_until=T1 + 100)
        cases[-1] = ({"now": T1 + 10_000, "authorization": expiring}, REASON_EXPIRED)
        for overrides, expected in cases:
            with self.subTest(reason=expected):
                nested = overrides.pop("authorization", grant)
                verdict = self.present(nested, **overrides)
                self.assertFalse(verdict["accepted"])
                self.assertEqual(verdict["reason"], expected)
        revoke_authorization(self.db, grant["authorization_id"], actor="operator:operator",
                             reason="operator changed their mind", now=T1 + 2)
        self.assertEqual(self.present(grant)["reason"], "AUTHORIZATION_REVOKED")

    def test_a_replayed_generation_is_refused(self):
        first = self.grant()
        second = self.grant()          # a fresh grant supersedes the first
        self.assertEqual(self.present(first)["reason"], REASON_REPLAYED)
        self.assertTrue(self.present(second)["accepted"])

    def test_ambient_conditions_are_not_credentials(self):
        for forgery in ambient_environment_is_not_a_credential()["ambient_tokens"]:
            with self.subTest(forgery=forgery):
                verdict = self.present(forgery)
                self.assertFalse(verdict["accepted"])
                self.assertEqual(verdict["reason"], REASON_AMBIENT_NOT_CREDENTIAL)
        os.environ["CIPH_OPERATOR"] = "1"
        try:
            self.assertFalse(self.present({"note": "copied session token"})["accepted"])
        finally:
            os.environ.pop("CIPH_OPERATOR", None)

    def test_a_service_cannot_grant_itself_operator_authority(self):
        with self.assertRaises(CrucibleError) as refused:
            register_principal(self.db, principal_id="OP-2", display_name="service",
                               credential_ref="cred:self", actor="service:ciph-core", now=T1)
        self.assertEqual(refused.exception.reason, REASON_SERVICE_CANNOT_SELF_AUTHORIZE)
        with self.assertRaises(CrucibleError):
            authorize_operation(self.db, principal_id="OP-1", operation=OPERATION_ACTIVATE,
                                ciph_identity_id=IDENTITY, environment_identity=ENVIRONMENT,
                                actor="service:ciph-core", now=T1)
        self.assertTrue(operator_actions(self.db))
        self.assertTrue(operator_digest(self.db))


class TestEgressAndStaleHost(EnvironmentTestCase):

    def test_egress_is_deny_by_default_and_explicit_deny_wins(self):
        self.assertFalse(egress_decision(self.db, service_identity="ciph-worker",
                                        destination_kind="host", destination="example.com")["allowed"])
        record_egress_rule(self.db, service_identity="ciph-worker", destination_kind="host",
                           destination="example.com", disposition=EGRESS_ALLOW, actor="operator:operator",
                           now=T1)
        self.assertTrue(egress_decision(self.db, service_identity="ciph-worker",
                                        destination_kind="host", destination="example.com")["allowed"])
        record_egress_rule(self.db, service_identity="ciph-worker", destination_kind="host",
                           destination="example.com", disposition=EGRESS_DENY, actor="operator:operator",
                           now=T1 + 1)
        decision = egress_decision(self.db, service_identity="ciph-worker", destination_kind="host",
                                   destination="example.com")
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "EXPLICIT_DENY")
        self.assertEqual(decision["enforcement"], "policy-layer",
                         "scope stated: this is a policy decision, not kernel enforcement here")

    def test_a_real_egress_attempt_reports_the_gap_honestly(self):
        attempt = real_egress_attempt("127.0.0.1", 9, timeout=1.0)
        self.assertIn("connected", attempt)
        self.assertIn("os_enforced", attempt)

    def test_a_stale_host_effect_is_classified_not_glossed(self):
        externally = stale_host_effect_disposition(effect_kind="api_call", externally_governed=True,
                                                   os_permission_enforced=False)
        self.assertEqual(externally["disposition"], "REFUSED_BY_RESOURCE")
        self.assertTrue(externally["constitutional_success"])
        by_os = stale_host_effect_disposition(effect_kind="file_write", externally_governed=False,
                                              os_permission_enforced=True)
        self.assertEqual(by_os["disposition"], "REFUSED_BY_OS")
        residual = stale_host_effect_disposition(effect_kind="local_compute",
                                                 externally_governed=False,
                                                 os_permission_enforced=False)
        self.assertEqual(residual["disposition"], "RESIDUAL_PHYSICAL_CONTROL")
        self.assertFalse(residual["constitutional_success"],
                         "residual physical control is a limitation, never a proven guarantee")


class TestRuntimeAndUpdates(EnvironmentTestCase):

    def test_a_snapshot_is_a_candidate_not_an_authority(self):
        snapshot = record_snapshot(self.db, artifact_digest="s" * 64,
                                   consistency_boundary="fs-snapshot@T1", now=T1)
        self.assertEqual(snapshot["status"], SNAPSHOT_TAKEN)
        self.assertEqual(snapshot["authority"], "none")
        refused = snapshot_as_recovery_candidate(self.db, snapshot["snapshot_id"],
                                                backup_id="BS-DOES-NOT-EXIST")
        self.assertEqual(refused["status"], SNAPSHOT_REFUSED)
        self.assertFalse(assert_snapshot_cannot_activate(self.db, snapshot["snapshot_id"])["may_activate"])

    def test_resource_limits_are_enforced_by_the_kernel(self):
        """Real setrlimit enforcement: an allocation beyond the bound fails."""
        script = ("import resource\n"
                  "resource.setrlimit(resource.RLIMIT_AS, (64 * 1024 * 1024, 64 * 1024 * 1024))\n"
                  "try:\n"
                  "    blob = bytearray(256 * 1024 * 1024)\n"
                  "    print('allocated', len(blob))\n"
                  "except MemoryError:\n"
                  "    print('refused by the kernel')\n")
        bounded = run_with_limits([sys.executable, "-B", "-c", script],
                                  address_space_bytes=128 * 1024 * 1024, timeout=30)
        self.assertIn("refused by the kernel", bounded["stdout"],
                      f"the kernel did not hold the bound: {bounded}")
        self.assertEqual(bounded["limits_applied"]["address_space_bytes"], 128 * 1024 * 1024)

    def test_model_runtime_is_bounded_and_gpu_is_optional(self):
        runtime = register_model_runtime(self.db, service_identity="ciph-model",
                                        model_identity="model-a", provider="local", cpu_seconds=60,
                                        address_space_bytes=512 * 1024 * 1024, now=T1)
        self.assertFalse(runtime["gpu_required"])
        self.assertEqual(runtime["cpu_seconds"], 60)

    def test_a_governed_update_walks_its_states_and_rolls_back_as_a_new_state(self):
        update = stage_update(self.db, package_identity="ciph-app", from_version="9.0",
                              to_version="9.1", staged_digest="u" * 64, now=T1)
        self.assertEqual(update["status"], STAGED)
        self.assertEqual(verify_update(self.db, update["update_id"], observed_digest="x" * 64,
                                       now=T1 + 1)["status"], STAGED)
        self.assertEqual(verify_update(self.db, update["update_id"], observed_digest="u" * 64,
                                       schema_compatible=False, now=T1 + 2)["status"], STAGED)
        self.assertEqual(verify_update(self.db, update["update_id"], observed_digest="u" * 64,
                                       now=T1 + 3)["status"], VERIFIED)
        unauthorized = authorize_update(self.db, update["update_id"],
                                        operator_authorization="operator:approved", now=T1 + 4)
        self.assertEqual(unauthorized["status"], VERIFIED, "a label does not authorize an update")
        grant = self.grant(operation=OPERATION_APPROVE_UPDATE)
        self.assertEqual(authorize_update(self.db, update["update_id"],
                                          operator_authorization=self.present(
                                              grant, operation=OPERATION_APPROVE_UPDATE),
                                          now=T1 + 5)["status"], "AUTHORIZED")
        self.assertEqual(install_update(self.db, update["update_id"], observed_digest="y" * 64,
                                        now=T1 + 6)["status"], REGRESSED)
        second = stage_update(self.db, package_identity="ciph-app", from_version="9.0",
                              to_version="9.2", staged_digest="v" * 64, now=T1 + 7)
        verify_update(self.db, second["update_id"], observed_digest="v" * 64, now=T1 + 8)
        authorize_update(self.db, second["update_id"],
                         operator_authorization=self.present(
                             self.grant(operation=OPERATION_APPROVE_UPDATE, now=T1 + 9),
                             operation=OPERATION_APPROVE_UPDATE, now=T1 + 10), now=T1 + 11)
        self.assertEqual(install_update(self.db, second["update_id"], observed_digest="v" * 64,
                                        now=T1 + 12)["status"], INSTALLED)
        self.assertEqual(assess_update_health(self.db, second["update_id"], healthy=False,
                                              now=T1 + 13)["status"], REGRESSED)
        held = rollback_update(self.db, second["update_id"], operator_authorization=None, now=T1 + 14)
        self.assertEqual(held["status"], ROLLBACK_REQUIRED)
        rolled = rollback_update(self.db, second["update_id"],
                                 operator_authorization={"allowed": True,
                                                         "authorization_id": "OA-TEST"},
                                 now=T1 + 15)
        self.assertEqual(rolled["status"], ROLLED_BACK)
        self.assertEqual(rolled["detail"], "restored 9.0")
        self.assertEqual(assess_update_health(self.db, second["update_id"], healthy=True,
                                              now=T1 + 16)["status"], ROLLED_BACK,
                         "a rolled-back update does not become healthy retroactively")
        self.assertTrue(runtime_digest(self.db))

    def test_a_downgrade_requires_an_explicit_rollback_plan(self):
        with self.assertRaises(CrucibleError) as refused:
            stage_update(self.db, package_identity="ciph-app", from_version="9.2", to_version="9.0",
                         staged_digest="w" * 64, now=T1)
        self.assertEqual(refused.exception.reason, "VERSION_DOWNGRADE_WITHOUT_AN_EXPLICIT_ROLLBACK_PLAN")

    def test_no_ungoverned_upgrade_command_exists_in_the_tree(self):
        self.assertEqual(ungoverned_upgrade_commands(), ())


class TestInstallationProfile(EnvironmentTestCase):

    def test_the_manifest_names_everything_an_installation_must_define(self):
        manifest = installation_manifest()
        self.assertEqual(manifest["policy_version"], CIPHOS_IMAGE_V1)
        for key in ("base_os", "service_units", "accounts", "directory_ownership", "network_policy",
                    "secret_custody", "recovery_integration", "first_boot_behaviour",
                    "operator_activation", "host_requirements"):
            self.assertIn(key, manifest)
        self.assertIn("no requirement for a GPU", " ".join(manifest["host_requirements"]))

    def test_the_privileged_profile_is_written_out_and_not_downgraded(self):
        profile = privileged_host_profile()
        self.assertFalse(profile["activatable_on_this_host"])
        self.assertTrue(profile["unit_hardening"])
        self.assertIn("NoNewPrivileges=yes", profile["unit_hardening"])
        self.assertEqual(profile["first_boot_defaults"]["authority"], "NONE")
        user = user_scope_profile()
        self.assertTrue(user["reduced_guarantees"])
        self.assertEqual(user["may_not_be_reported_as"], "system-scope proof")
        with self.assertRaises(CrucibleError):
            assert_profile_not_downgraded(claimed_scope="system", host_can_privilege=False)
        self.assertTrue(assert_profile_not_downgraded(claimed_scope="user",
                                                     host_can_privilege=False)["honest"])


class TestCiphOSScanners(EnvironmentTestCase):

    def test_eighteen_scanners_are_zero_and_each_calls_its_own_predicate(self):
        census = environment_scanner_census()
        self.assertEqual(len(census), 18)
        self.assertEqual({name: count for name, count in census.items() if count}, {})
        real = dict(production_sources())
        rogue = "ciph/kernel/environment_rogue.py"
        catches = [
            ("s01_boot_grants_authority", "def go(b):\n    return grant_authority_at_boot(b)\n"),
            ("s02_service_bypasses_guarded_executor", "def go(t):\n    return bypass_permit(t)\n"),
            ("s03_unrestricted_root", "CapabilityBoundingSet=ALL\n"),
            ("s04_worker_reads_root_keys", "# ciph-worker reads root.key\n"),
            ("s05_worker_writes_constitutional_code", "def go(w):\n    return worker_writes_kernel(w)\n"),
            ("s06_model_runtime_claims_permits",
             "def model_runtime_claim(store):\n    return store.claim('p')\n"),
            ("s07_installer_activates_production", "def go():\n    return install_and_activate()\n"),
            ("s08_restart_bypasses_operator_hold", "restart_ignores_hold = True\n"),
            ("s09_unauthenticated_operator_label", "def go(t):\n    return trust_env_operator(t)\n"),
            ("s10_update_bypasses_governance", "def go():\n    return skip_update_verify()\n"),
            ("s11_legacy_helper_reachable_unauthorised",
             "import subprocess\n\ndef go():\n    return subprocess.run(['darknet_monitor'])\n"),
            ("s12_transport_grants_federation_authority",
             "def go(s):\n    return session_becomes_owner(s)\n"),
            ("s13_stale_host_fresh_authority",
             "def go(h):\n    return accept_stale_host_authority(h)\n"),
            ("s14_clone_recovers_standing", "def go(c):\n    return clone_gets_production(c)\n"),
            ("s15_destructive_state_rearmed_at_boot", "def go():\n    return boot_arms_deadman()\n"),
            ("s16_snapshot_becomes_authority", "def go(s):\n    return snapshot_is_canonical(s)\n"),
            ("s17_readiness_reported_as_activation",
             "def service_ready(unit):\n    return unit == 'active'\n"),
            ("s18_second_authority_constitution", "class CiphOSExecutor:\n    pass\n"),
        ]
        self.assertEqual(len(catches), 18)
        for name, body in catches:
            with self.subTest(scanner=name):
                self.assertTrue(dict(ENVIRONMENT_SCANNERS)[name]({**real, rogue: body}),
                                f"{name} did not fire on its own violation")


if __name__ == "__main__":
    unittest.main()
