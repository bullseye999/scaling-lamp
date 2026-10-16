"""
9.0-9.3 - the CiphOS boot constitution, service identity, and the boundaries this environment can
ACTUALLY enforce.

    Boot != activation.  Process running != authorized.  Root privileges != constitutional permission.

Everything here is measured in the environment the suite ran in, and `environment_capabilities` reports
what that environment does NOT provide so a seal cannot borrow against it.
"""

import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.environment_boot import (ACTIVATION_REFUSED, AWAITING_OPERATOR_AUTHORIZATION,
                                          BOOT_INTEGRITY_FAILED, CONSTITUTIONALLY_ACTIVATED,
                                          ENVIRONMENT_ATTESTATION_FAILED, ENVIRONMENT_VERIFIED,
                                          KEY_CUSTODY_UNAVAILABLE, RUNNING, advance_boot, begin_boot,
                                          boot_digest, boot_summary, can_read, env_capabilities_ok,
                                          environment_capabilities, install_user_unit,
                                          privileged_operation_reachable, register_service,
                                          assert_within_scope, scrubbed_environment, secure_file,
                                          stop_user_unit, unit_status, user_unit_available)

T1 = 1_800_000_000.0


class BootTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-90-")
        self.db = str(pathlib.Path(self.temp.name) / "boot.db")

    def tearDown(self):
        self.temp.cleanup()

    def boot(self, installation_id="INST-1", *, now=None):
        # A boot identity is derived from the installation and the moment, so a fixture that wants a
        # SECOND boot in the same datastore must say so - otherwise it silently continues the first.
        return begin_boot(self.db, installation_id=installation_id, software_revision="9.0-ciphos",
                          artifact_digest="a" * 64, service_config_digest="s" * 64,
                          environment_identity="ENV-1", now=T1 if now is None else now)

    def to_awaiting(self, installation_id="INST-1", *, now=None):
        moment = T1 if now is None else now
        boot = self.boot(installation_id, now=moment)
        advance_boot(self.db, boot.boot_id, "BOOTSTRAPPING", now=moment + 1)
        advance_boot(self.db, boot.boot_id, ENVIRONMENT_VERIFIED,
                     evidence={"capabilities": {"user_scoped_systemd": True}, "integrity_ok": True,
                               "key_custody_available": True}, now=moment + 2)
        return advance_boot(self.db, boot.boot_id, AWAITING_OPERATOR_AUTHORIZATION, now=moment + 3)


class TestBootConstitution(BootTestCase):

    def test_boot_reaches_awaiting_authorization_and_grants_nothing(self):
        awaiting = self.to_awaiting()
        self.assertEqual(awaiting.state, AWAITING_OPERATOR_AUTHORIZATION)
        summary = boot_summary(self.db, awaiting.boot_id)
        self.assertEqual(summary["authority_granted"], "none")
        self.assertFalse(summary["sovereign_execution_enabled"])
        for field in ("new_execution_permits", "autonomous_missions_started", "production_deployments",
                      "recovery_activations", "historical_permits_replayed",
                      "destructive_timers_armed", "workers_authoritative",
                      "federation_domains_assumed"):
            self.assertEqual(summary[field], 0, field)
        self.assertTrue(summary["diagnostics_running"],
                        "diagnostics may run; authority may not be assumed")

    def test_a_started_service_cannot_authorize_activation(self):
        """
        THE mandatory specimen: reboot without operator authorization - and in particular, a service
        manager having started the process is NOT an operator.
        """
        # Each forged attempt gets its OWN boot: a refusal is terminal for that boot's path, which is
        # itself part of the law - a refused activation does not leave the machine half-activated.
        for index, forged in enumerate(("systemd:started-us", "service:ciphcore", "boot:complete",
                                        "AUTOSTART")):
            with self.subTest(forged=forged):
                awaiting = self.to_awaiting(installation_id=f"INST-{index + 10}",
                                            now=T1 + 100 + index * 10)
                outcome = advance_boot(self.db, awaiting.boot_id, CONSTITUTIONALLY_ACTIVATED,
                                       evidence={"operator_authorization": forged},
                                       now=T1 + 100 + index * 10 + 4)
                self.assertEqual(outcome.state, ACTIVATION_REFUSED)
                with self.assertRaises(CrucibleError):
                    advance_boot(self.db, awaiting.boot_id, RUNNING,
                                 now=T1 + 100 + index * 10 + 5)

    def test_a_real_operator_authorization_activates_and_only_from_awaiting(self):
        awaiting = self.to_awaiting()
        activated = advance_boot(self.db, awaiting.boot_id, CONSTITUTIONALLY_ACTIVATED,
                                 evidence={"operator_authorization": "operator:operator"}, now=T1 + 6)
        self.assertEqual(activated.state, CONSTITUTIONALLY_ACTIVATED)
        running = advance_boot(self.db, awaiting.boot_id, RUNNING, now=T1 + 7)
        self.assertEqual(running.state, RUNNING)
        self.assertTrue(boot_summary(self.db, running.boot_id)["sovereign_execution_enabled"])
        self.assertTrue(boot_digest(self.db))

    def test_boot_failure_states_are_explicit_and_terminal_for_that_boot(self):
        boot = self.boot()
        advance_boot(self.db, boot.boot_id, "BOOTSTRAPPING", now=T1 + 1)
        failed = advance_boot(self.db, boot.boot_id, ENVIRONMENT_VERIFIED,
                              evidence={"capabilities": {"user_scoped_systemd": True},
                                        "key_custody_available": False}, now=T1 + 2)
        self.assertEqual(failed.state, KEY_CUSTODY_UNAVAILABLE)
        divergent = self.boot(installation_id="INST-2")
        advance_boot(self.db, divergent.boot_id, "BOOTSTRAPPING", now=T1 + 3)
        self.assertEqual(advance_boot(self.db, divergent.boot_id, ENVIRONMENT_VERIFIED,
                                      evidence={"capabilities": {}, "integrity_ok": False},
                                      now=T1 + 4).state, BOOT_INTEGRITY_FAILED)
        with self.assertRaises(CrucibleError):
            advance_boot(self.db, failed.boot_id, AWAITING_OPERATOR_AUTHORIZATION, now=T1 + 5)

    def test_an_environment_may_not_verify_a_capability_this_one_lacks(self):
        caps = environment_capabilities()
        self.assertTrue(caps["unavailable"])
        for claim in ("namespace_isolation", "hardware_backed_attestation"):
            self.assertIn(claim, caps["unavailable"])
        for unsupported in ("clean VM install", "measured boot"):
            self.assertIn(unsupported, caps["unsupported_claims"])
        self.assertFalse(env_capabilities_ok({"namespace_isolation": True})["ok"])
        self.assertTrue(env_capabilities_ok({"user_scoped_systemd": True})["ok"])


class TestRealBoundaries(BootTestCase):
    """Measured enforcement, not configuration prose."""

    def test_a_mode_zero_secret_is_refused_to_its_own_owner(self):
        secret = secure_file(str(pathlib.Path(self.temp.name) / "root.key"))
        self.assertFalse(can_read(secret),
                         "the OS refused a mode-000 file to its owner: custody is enforced by the kernel")
        os.chmod(secret, 0o600)
        self.assertTrue(can_read(secret))

    def test_a_service_may_not_reach_a_forbidden_scope_by_symlink(self):
        root = pathlib.Path(self.temp.name)
        allowed = root / "allowed"
        forbidden = root / "vault"
        allowed.mkdir()
        forbidden.mkdir()
        (forbidden / "ciph_vault.db").write_text("secrets", encoding="utf-8")
        escape = allowed / "escape"
        try:
            escape.symlink_to(forbidden)
        except OSError:
            self.skipTest("symlinks unavailable in this environment")
        service = register_service(self.db, name="worker", service_identity="ciph-worker",
                                   writable_scopes=[str(allowed)],
                                   forbidden_scopes=[str(forbidden)], now=T1)
        with self.assertRaises(CrucibleError) as refused:
            assert_within_scope(service, target=str(escape / "ciph_vault.db"))
        self.assertEqual(refused.exception.reason, "SERVICE_SCOPE_FORBIDDEN")

    def test_a_worker_environment_is_scrubbed_not_inherited(self):
        os.environ["CIPH_TEST_SECRET"] = "must-not-leak"
        try:
            observed = scrubbed_environment({"ONLY_THIS": "1"},
                                           command=[sys.executable, "-B", "-c",
                                                    "import os,json;print(json.dumps(sorted(os.environ)))"])
        finally:
            os.environ.pop("CIPH_TEST_SECRET", None)
        self.assertIn("ONLY_THIS", observed["stdout"])
        self.assertNotIn("CIPH_TEST_SECRET", observed["stdout"])
        self.assertEqual(observed["environment_variables"], ["ONLY_THIS"])

    def test_privileged_host_operations_are_not_reachable_by_inheritance(self):
        """The R13 sudo finding, measured rather than assumed."""
        outcome = privileged_operation_reachable()
        self.assertFalse(outcome["reachable"],
                         f"unprivileged escalation must not be reachable: {outcome['detail']}")

    def test_a_real_user_scoped_service_starts_and_is_restarted_by_the_manager(self):
        """
        REAL service management, with the scope stated: `systemd --user`, because a system unit needs
        root this environment does not have. What it proves is that the manager starts the process,
        applies a restart policy, and that none of it produces authority.
        """
        manager = user_unit_available()
        if not manager["available"]:
            self.skipTest(f"no user service manager: {manager['state']}")
        marker = pathlib.Path(self.temp.name) / "heartbeat.log"
        unit = f"ciphos-test-{os.getpid()}"
        script = (f"import time,pathlib,sys\n"
                  f"p = pathlib.Path({str(marker)!r})\n"
                  f"p.write_text(p.read_text() + 'beat\\n' if p.exists() else 'beat\\n')\n"
                  f"time.sleep(120)\n")
        try:
            installed = install_user_unit(unit,
                                          exec_start=f"{sys.executable} -c {script!r}",
                                          description="CiphOS boot specimen", restart="always")
            self.assertEqual(installed["start_returncode"], 0, installed["start_detail"])
            self.assertEqual(installed["authority_granted"], "none")
            for _ in range(40):
                if marker.exists():
                    break
                time.sleep(0.25)
            self.assertTrue(marker.exists(), "the service manager did not start the process")
            status = unit_status(unit)
            self.assertEqual(status.get("ActiveState"), "active")
            first_pid = status.get("MainPID")
            os.kill(int(first_pid), signal.SIGKILL)
            for _ in range(60):
                time.sleep(0.25)
                status = unit_status(unit)
                if status.get("ActiveState") == "active" and status.get("MainPID") not in (first_pid, "0"):
                    break
            self.assertEqual(status.get("ActiveState"), "active",
                             "the restart policy did not bring the service back")
            self.assertNotEqual(status.get("MainPID"), first_pid, "PID reuse must not preserve identity")
        finally:
            stop_user_unit(unit)
            unit_path = pathlib.Path(os.environ.get("XDG_CONFIG_HOME", str(pathlib.Path.home() / ".config")))
            try:
                (unit_path / "systemd" / "user" / f"{unit}.service").unlink()
            except OSError:
                pass
            subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
