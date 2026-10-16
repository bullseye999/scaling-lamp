"""
Gate A0 closure tests - register items 0.7, 0.8 and 0.10.

0.7  compile_empirical_ledger dependency-map footgun
0.8  daemon liveness (LOOP1_V2_SPEC section 3.8)
0.10 experimental organ docstrings must not claim what the code does not implement

Each test states what it can and cannot establish. These are closure tests, so a passing
result is evidence about the item, not about the surrounding system.
"""

import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace

import ciph.silicon
import ciph.zk
from ciph.capabilities.capability_ledger import CapabilityLedger, DependencyCheckResult
from ciph.perception.curiosity_daemon import CuriosityDaemon


def _wait_until(predicate, timeout=5.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class _Manifest:
    def __init__(self, name, declared_modules):
        self.name = name
        self.declared_modules = declared_modules


class _Registry:
    def __init__(self, manifests):
        self._manifests = manifests

    def list_manifests(self):
        return list(self._manifests)


class _ExplodingRegistry:
    def list_manifests(self):
        raise RuntimeError("registry unavailable")


class Item07DependencyMapTests(unittest.TestCase):
    """
    Scope note: these exercise the static-evidence resolver directly. They do not run a full
    compile against a live vault, so they establish that the default is measured rather than
    UNKNOWN, not that every downstream health classification is unchanged.
    """

    def _resolve(self, registry):
        return CapabilityLedger.build_static_dependency_evidence_map(
            SimpleNamespace(registry=registry)
        )

    def test_importable_module_resolves_to_pass(self):
        result = self._resolve(_Registry([_Manifest("cap.good", ("json",))]))
        evidence = result["cap.good"]
        self.assertEqual(evidence.status, DependencyCheckResult.PASS)
        self.assertEqual(list(evidence.missing_modules), [])

    def test_missing_module_resolves_to_fail_with_evidence(self):
        result = self._resolve(
            _Registry([_Manifest("cap.bad", ("ciph_dependency_that_must_not_exist_7f3c8d",))])
        )
        evidence = result["cap.bad"]
        self.assertEqual(evidence.status, DependencyCheckResult.FAIL)
        self.assertIn("ciph_dependency_that_must_not_exist_7f3c8d", list(evidence.missing_modules))

    def test_the_default_is_measured_not_unknown(self):
        """
        The defect was that omitting the map produced DEPENDENCY_UNVERIFIED for everything.
        A capability with a satisfied manifest must no longer be reported that way.
        """
        result = self._resolve(_Registry([_Manifest("cap.good", ("json",))]))
        self.assertNotEqual(result["cap.good"].status, DependencyCheckResult.UNKNOWN)

    def test_unavailable_registry_fails_closed_to_empty(self):
        """No registry means no evidence, never a fabricated pass."""
        self.assertEqual(self._resolve(_ExplodingRegistry()), {})


class Item08DaemonLivenessTests(unittest.TestCase):

    def setUp(self):
        self.daemon = None

    def tearDown(self):
        if self.daemon is not None:
            try:
                self.daemon.stop()
            except Exception:
                pass

    def _daemon(self, **kwargs):
        kwargs.setdefault("inquiry_interval_seconds", 0.05)
        kwargs.setdefault("cycle_timeout_seconds", 0.25)
        self.daemon = CuriosityDaemon(**kwargs)
        return self.daemon

    def test_invalid_cycle_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            CuriosityDaemon(cycle_timeout_seconds=0)

    def test_a_hanging_cycle_is_recorded_and_stops_the_worker(self):
        """
        The observed production failure was a hang, which never reaches an `except`. This is
        the test that would have caught it: the cycle never returns, and the daemon must still
        report the condition instead of sitting there looking healthy.
        """
        daemon = self._daemon()
        daemon.run_inquiry_cycle = lambda runtime: time.sleep(5)
        daemon.start(runtime=object())

        observed = _wait_until(
            lambda: daemon.get_liveness()["cycle_timeout_count"] >= 1, timeout=5.0
        )
        self.assertTrue(observed, "timeout was never recorded")

        liveness = daemon.get_liveness()
        self.assertEqual(liveness["health"], "HUNG")
        self.assertFalse(liveness["healthy"])
        self.assertIn("CYCLE_TIMEOUT", liveness["last_error"])

    def test_exception_records_type_and_message(self):
        daemon = self._daemon()

        def _boom(runtime):
            raise ValueError("synthetic cycle failure")

        daemon.run_inquiry_cycle = _boom
        daemon.start(runtime=object())

        observed = _wait_until(
            lambda: daemon.get_liveness()["consecutive_failures"] >= 1, timeout=5.0
        )
        self.assertTrue(observed, "failure was never recorded")
        liveness = daemon.get_liveness()
        self.assertIn("ValueError", liveness["last_error"])
        self.assertIn("synthetic cycle failure", liveness["last_error"])
        self.assertEqual(liveness["health"], "DEGRADED")

    def test_successful_cycle_is_healthy_and_counted(self):
        daemon = self._daemon()
        daemon.run_inquiry_cycle = lambda runtime: None
        daemon.start(runtime=object())

        observed = _wait_until(
            lambda: daemon.get_liveness()["cycle_count"] >= 2, timeout=5.0
        )
        self.assertTrue(observed, "cycles never completed")
        liveness = daemon.get_liveness()
        self.assertEqual(liveness["health"], "HEALTHY")
        self.assertEqual(liveness["consecutive_failures"], 0)
        self.assertTrue(liveness["healthy"])

    def test_heartbeat_is_written_to_disk(self):
        handle, path = tempfile.mkstemp(prefix="ciph_heartbeat_", suffix=".json")
        os.close(handle)
        try:
            daemon = self._daemon(heartbeat_path=path)
            daemon.run_inquiry_cycle = lambda runtime: None
            daemon.start(runtime=object())

            observed = _wait_until(
                lambda: daemon.get_liveness()["cycle_count"] >= 1, timeout=5.0
            )
            self.assertTrue(observed, "no cycle completed")
            self.assertTrue(
                _wait_until(lambda: os.path.getsize(path) > 0, timeout=5.0),
                "heartbeat file stayed empty",
            )

            with open(path, "r", encoding="utf-8") as handle_in:
                heartbeat = json.load(handle_in)
            self.assertGreaterEqual(heartbeat["cycle_count"], 1)
            self.assertIsNotNone(heartbeat["last_cycle_completed_at"])
        finally:
            for suffix in ("", ".tmp"):
                try:
                    os.remove(path + suffix)
                except OSError:
                    pass

    def test_watchdog_restarts_a_dead_worker(self):
        daemon = self._daemon()
        daemon.run_inquiry_cycle = lambda runtime: None
        # Never started, so liveness cannot be satisfied.
        self.assertFalse(daemon.is_healthy())
        restarted = daemon.ensure_running(runtime=object())
        self.assertTrue(restarted)
        self.assertEqual(daemon.get_liveness()["restart_count"], 1)
        self.assertTrue(
            _wait_until(lambda: daemon.get_liveness()["cycle_count"] >= 1, timeout=5.0),
            "restarted worker never ran a cycle",
        )

    def test_restart_limit_is_respected(self):
        """An unrestartable engine must become visibly unrestartable, not loop forever."""
        daemon = self._daemon(max_restarts=0)
        daemon.run_inquiry_cycle = lambda runtime: None
        self.assertFalse(daemon.ensure_running(runtime=object()))
        self.assertEqual(daemon.get_liveness()["health"], "RESTART_LIMIT_EXCEEDED")

    def test_healthy_worker_is_not_restarted(self):
        daemon = self._daemon()
        daemon.run_inquiry_cycle = lambda runtime: None
        daemon.start(runtime=object())
        self.assertTrue(
            _wait_until(lambda: daemon.is_healthy(), timeout=5.0),
            "worker never became healthy",
        )
        self.assertFalse(daemon.ensure_running(runtime=object()))
        self.assertEqual(daemon.get_liveness()["restart_count"], 0)


class Item10DocstringHonestyTests(unittest.TestCase):

    def test_zk_does_not_claim_zero_knowledge_proofs(self):
        doc = ciph.zk.__doc__ or ""
        self.assertIn("NOT IMPLEMENTED", doc)
        self.assertNotIn("Cryptographically proves", doc)

    def test_silicon_does_not_claim_hardware_or_post_quantum(self):
        doc = ciph.silicon.__doc__ or ""
        self.assertIn("NOT IMPLEMENTED", doc)
        self.assertNotIn("ML-DSA", doc)
        self.assertNotIn("Hardware Security Module (HSM) enclave key isolation", doc)

    def test_placeholders_are_labelled_as_placeholders(self):
        self.assertIn("PLACEHOLDER", ciph.zk.__doc__ or "")
        self.assertIn("PLACEHOLDER", ciph.silicon.__doc__ or "")


if __name__ == "__main__":
    unittest.main()
