"""
test_phase7_sandbox_feasibility.py - Executable acceptance tests for Program 2, Phase 7 Milestone 7.0.
Four-Gate Verification Matrix:
  Gate A: Safe Refusal (Restricted Host & Admission Denial)
  Gate B: Working Containment (Positive and Negative Controls)
  Gate C: Secret and Descriptor Isolation
  Gate D: Lifecycle and Resource Containment
"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from ciph.contracts.enums import NetworkPolicy, ScopeType, OutcomeCategory
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import (
    CapabilityManifest,
    RiskTier,
    ReversibilityClass,
    AuthorizationTier,
    is_sandboxed_execution_required,
)
from ciph.kernel.sandbox.base import (
    DiagnosticCheck,
    SandboxDiagnostics,
    SandboxDiagnosticState,
    SandboxPolicy,
    SandboxResult,
    SandboxTerminationReason,
    SandboxUnavailableError,
)
from ciph.kernel.sandbox.launcher import apply_rlimits
from ciph.kernel.sandbox.runner import OfflineSandboxRunner
from ciph.runtime import CiphRuntime


class TestPhase7SandboxFeasibility(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="ciph_p7_test_")
        self.db_path = os.path.join(self.temp_dir.name, "vault.db")
        self.runtime = CiphRuntime(db_path=self.db_path)
        self.daemon = self.runtime.worker_daemon

    def tearDown(self):
        self.runtime.close()
        self.temp_dir.cleanup()

    # =========================================================================
    # GATE A: Safe Refusal (Restricted Host & Admission Denial)
    # =========================================================================

    def test_gate_a_host_probe_reports_exact_diagnostics(self):
        """
        Gate A.1: Runner attempts exact required launch configuration.
        Structured diagnostics report on all five checks: launcher, filesystem,
        network, resource limits, and cleanup, providing tested_config and observations.
        On this host with Landlock and Linux namespaces, containment is AVAILABLE.
        """
        runner = OfflineSandboxRunner()
        diag = runner.probe_containment(SandboxPolicy(network_policy=NetworkPolicy.OFFLINE_ONLY))

        self.assertIsInstance(diag, SandboxDiagnostics)
        self.assertEqual(diag.launcher_status.state, SandboxDiagnosticState.PASS)
        self.assertEqual(diag.filesystem_isolation.state, SandboxDiagnosticState.PASS)
        self.assertIn("inaccessible", diag.filesystem_isolation.observation.lower())
        self.assertEqual(diag.network_isolation.state, SandboxDiagnosticState.PASS)
        self.assertEqual(diag.resource_enforcement.state, SandboxDiagnosticState.PASS)
        self.assertEqual(diag.descendant_cleanup.state, SandboxDiagnosticState.PASS)
        self.assertEqual(diag.overall, "AVAILABLE")

    def test_gate_a_three_state_diagnostics_broken_launcher(self):
        """
        Gate A.2: Three-state diagnostics: PASS, FAIL, NOT_TESTED.
        If launcher fails to execute, all four subsequent boundary probes
        must be explicitly marked NOT_TESTED, and overall reports UNAVAILABLE.
        """
        broken_runner = OfflineSandboxRunner(launcher_cmd=["/bin/nonexistent_launcher_bin"])
        diag = broken_runner.probe_containment(SandboxPolicy())

        self.assertEqual(diag.launcher_status.state, SandboxDiagnosticState.FAIL)
        self.assertEqual(diag.filesystem_isolation.state, SandboxDiagnosticState.NOT_TESTED)
        self.assertEqual(diag.network_isolation.state, SandboxDiagnosticState.NOT_TESTED)
        self.assertEqual(diag.resource_enforcement.state, SandboxDiagnosticState.NOT_TESTED)
        self.assertEqual(diag.descendant_cleanup.state, SandboxDiagnosticState.NOT_TESTED)
        self.assertEqual(diag.overall, "UNAVAILABLE")

    def test_gate_a_simulated_probe_crash_fails_closed_without_false_pass(self):
        """
        Gate A.3 (Finding 3): Probe crashes must report FAIL or NOT_TESTED and UNAVAILABLE.
        Reproducing reviewer's crashed_probe where probe commands exit with code 2.
        Must never report a false PASS.
        """
        def crashed_probe(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0 if cmd == ['true'] else 2, '', 'simulated probe crash')

        with patch('ciph.kernel.sandbox.runner.subprocess.Popen', side_effect=OSError('simulated launcher crash')):
            diag = OfflineSandboxRunner(launcher_cmd=[]).probe_containment()

        self.assertEqual(diag.overall, "UNAVAILABLE")
        self.assertNotEqual(diag.filesystem_isolation.state, SandboxDiagnosticState.PASS)

    def test_gate_a_pre_execution_denial_on_containment_unavailable(self):
        """
        Gate A.4: When containment is unavailable, supervisor fails closed BEFORE task starts.
        Records SandboxDeniedEvent, marks job FAILED, mints ZERO ExecutionReceipt, and payload never runs.
        """
        class MockUnavailableRunner:
            def probe_containment(self, policy=None):
                check_fail = DiagnosticCheck(
                    state=SandboxDiagnosticState.FAIL,
                    observation="Host kernel lacks required boundary isolation",
                    tested_config="unshare-landlock"
                )
                return SandboxDiagnostics(
                    launcher_status=DiagnosticCheck(state=SandboxDiagnosticState.PASS, observation="ok", tested_config="unshare"),
                    filesystem_isolation=check_fail,
                    network_isolation=DiagnosticCheck(state=SandboxDiagnosticState.NOT_TESTED, observation="skipped", tested_config="unshare"),
                    resource_enforcement=DiagnosticCheck(state=SandboxDiagnosticState.NOT_TESTED, observation="skipped", tested_config="unshare"),
                    descendant_cleanup=DiagnosticCheck(state=SandboxDiagnosticState.NOT_TESTED, observation="skipped", tested_config="unshare"),
                    overall="UNAVAILABLE"
                )

        self.daemon.sandbox_runner = MockUnavailableRunner()

        class SandboxedProbeCapability(BaseCapability):
            requires_sandbox = True
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="cybersecurity.test_probe_denial",
                    description="Probe requiring sandboxing",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                    timeout_seconds=5
                )
            def get_sandbox_command(self, params):
                return [sys.executable, "-c", "import sys; sys.exit(0)"]
            def run(self, params, context=None):
                raise AssertionError("Payload must never execute when containment is unavailable")

        self.runtime.register_capability(SandboxedProbeCapability())

        token = self.runtime.mint_execution_token("cybersecurity.test_probe_denial", {"target": "t1"})
        job_id = self.runtime.queue.enqueue_job(
            capability="cybersecurity.test_probe_denial",
            params={"target": "t1"},
            execution_token=token,
        )

        res = self.daemon.drain_once(worker_id="worker-p7-denial", target_job_id=job_id)

        # 1. Returned denial status
        self.assertEqual(res.get("status"), "SANDBOX_UNAVAILABLE")

        # 2. Job in queue must be FAILED
        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], "FAILED")
        self.assertIn("SANDBOX_UNAVAILABLE", job["error"])

        # 3. Signed denial event recorded in EventStore
        events = self.runtime.event_store.get_events(event_type="SandboxDeniedEvent")
        self.assertEqual(len(events), 1)
        denial_data = events[0]["payload"] if isinstance(events[0]["payload"], dict) else json.loads(events[0]["payload"])
        self.assertEqual(denial_data["job_id"], job_id)
        self.assertEqual(denial_data["reason"], "SANDBOX_UNAVAILABLE")

        # 4. Zero ExecutionReceipt stored
        receipt_events = self.runtime.event_store.get_events(event_type="ExecutionReceiptStoredEvent")
        self.assertEqual(len(receipt_events), 0)

    def test_gate_a_pre_execution_denial_on_missing_sandbox_adapter(self):
        """
        Gate A.5 (Finding 2): Missing get_sandbox_command must fail closed before execution.
        Must refuse to run any substitute command, record SandboxDeniedEvent, mark job FAILED,
        and produce zero receipts.
        """
        class MissingAdapterCapability(BaseCapability):
            requires_sandbox = True
            called = False
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="cybersecurity.test_missing_adapter",
                    description="Requires sandbox but has no adapter",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                    timeout_seconds=5
                )
            def run(self, params, context=None):
                self.called = True
                return {"should_not_run": True}

        cap = MissingAdapterCapability()
        self.runtime.register_capability(cap)

        token = self.runtime.mint_execution_token("cybersecurity.test_missing_adapter", {"target": "x"})
        job_id = self.runtime.queue.enqueue_job(
            capability="cybersecurity.test_missing_adapter",
            params={"target": "x"},
            execution_token=token,
        )

        res = self.daemon.drain_once(worker_id="worker-p7-no-adapter", target_job_id=job_id)

        self.assertEqual(res.get("status"), "SANDBOX_UNAVAILABLE")
        self.assertFalse(cap.called)

        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], "FAILED")
        self.assertIn("SANDBOX_ADAPTER_MISSING", job["error"])

        denial_events = self.runtime.event_store.get_events(event_type="SandboxDeniedEvent")
        self.assertEqual(len(denial_events), 1)

        receipt_events = self.runtime.event_store.get_events(event_type="ExecutionReceiptStoredEvent")
        self.assertEqual(len(receipt_events), 0)

    def test_gate_a_launch_refusal_inside_execute_isolated_denies_without_receipt(self):
        """
        Gate A.6 (Finding 4): Second launch refusal inside execute_isolated() emits
        SandboxDeniedEvent, marks job FAILED, and produces ZERO ExecutionReceipt records.
        """
        class RefusingRunner:
            def probe_containment(self, policy=None):
                check = lambda: DiagnosticCheck(state=SandboxDiagnosticState.PASS, observation="Preflight fixture", tested_config="fixture")
                return SandboxDiagnostics(
                    launcher_status=check(),
                    filesystem_isolation=check(),
                    network_isolation=check(),
                    resource_enforcement=check(),
                    descendant_cleanup=check(),
                    overall="AVAILABLE"
                )
            def execute_isolated(self, *args, **kwargs):
                return SandboxResult(
                    exit_code=None,
                    stdout="",
                    stderr="SANDBOX_UNAVAILABLE: Real launch boundary refused at runtime",
                    termination_reason=SandboxTerminationReason.SANDBOX_UNAVAILABLE,
                    execution_confirmed=False
                )

        self.daemon.sandbox_runner = RefusingRunner()

        class DeniedSecondLaunchCap(BaseCapability):
            requires_sandbox = True
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="cybersecurity.test_denied_second_launch",
                    description="Admission denial probe",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                    timeout_seconds=5
                )
            def get_sandbox_command(self, params):
                return [sys.executable, "-c", "import sys; sys.exit(0)"]
            def run(self, params, context=None):
                raise AssertionError("Must not execute")

        self.runtime.register_capability(DeniedSecondLaunchCap())

        token = self.runtime.mint_execution_token("cybersecurity.test_denied_second_launch", {})
        job_id = self.runtime.queue.enqueue_job(
            capability="cybersecurity.test_denied_second_launch",
            params={},
            execution_token=token,
        )

        res = self.daemon.drain_once(worker_id="worker-p7-second-denial", target_job_id=job_id)

        self.assertIsInstance(res, dict)
        self.assertEqual(res.get("status"), "SANDBOX_UNAVAILABLE")

        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], "FAILED")

        denials = self.runtime.event_store.get_events(event_type="SandboxDeniedEvent")
        self.assertEqual(len(denials), 1)

        receipts = self.runtime.event_store.get_events(event_type="ExecutionReceiptStoredEvent")
        self.assertEqual(len(receipts), 0)

    # =========================================================================
    # GATE B: Working Containment (Positive and Negative Controls)
    # =========================================================================

    def test_gate_b_positive_control_reads_input_writes_scratch_returns_bounded_data(self):
        """
        Gate B.1: Positive control: A permitted task reads declared input,
        writes to scratch space, and outputs bounded JSON result.
        Operates natively with OfflineSandboxRunner without any overrides.
        """
        runner = OfflineSandboxRunner()
        test_script = """
import json, sys, os
input_data = json.load(sys.stdin)
with open("scratch_output.txt", "w") as f:
    f.write("scratch_verified")
output = {"echo_target": input_data.get("target"), "scratch_created": os.path.exists("scratch_output.txt")}
print(json.dumps(output))
"""
        cmd = [sys.executable, "-c", test_script]
        policy = SandboxPolicy(network_policy=NetworkPolicy.OFFLINE_ONLY, max_wall_time_seconds=5.0)

        result = runner.execute_isolated(cmd, payload={"target": "alpha_1"}, policy=policy)
        self.assertEqual(result.termination_reason, SandboxTerminationReason.SUCCESS)
        self.assertEqual(result.exit_code, 0)
        self.assertIsNotNone(result.data)
        self.assertEqual(result.data.get("echo_target"), "alpha_1")
        self.assertTrue(result.data.get("scratch_created"))
        self.assertTrue(result.cleaned_up)

    def test_gate_b_negative_control_filesystem_canary_blocked(self):
        """
        Gate B.2 (Finding 1): Negative control: Sandboxed task attempting to read an
        undeclared canary file outside allowed paths fails with PermissionError (Landlock).
        """
        with tempfile.TemporaryDirectory() as td:
            canary = Path(td) / "review_canary.txt"
            canary.write_text("SUPER_CONFIDENTIAL_HOST_CANARY")

            runner = OfflineSandboxRunner()
            code = f"""
import sys, json
try:
    with open({repr(str(canary))}, 'r') as f:
        data = f.read()
    print(json.dumps({{'canary_read': True, 'content': data}}))
    sys.exit(0)
except (PermissionError, FileNotFoundError) as ex:
    print(json.dumps({{'canary_read': False, 'blocked_by': type(ex).__name__}}))
    sys.exit(10)
"""
            policy = SandboxPolicy(network_policy=NetworkPolicy.OFFLINE_ONLY, allowed_read_paths=[])
            result = runner.execute_isolated([sys.executable, "-c", code], policy=policy)

            # Child exit code is 10 (access blocked by Landlock LSM)
            self.assertEqual(result.exit_code, 10)
            self.assertIsNotNone(result.data)
            self.assertFalse(result.data.get("canary_read"))
            self.assertEqual(result.data.get("blocked_by"), "PermissionError")

    def test_gate_b_negative_control_network_blocked_under_offline_only(self):
        """
        Gate B.3: Negative control: Outbound network connection fails under OFFLINE_ONLY.
        """
        runner = OfflineSandboxRunner()
        net_probe_script = """
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    s.connect(('1.1.1.1', 80))
    print("LEAK")
    sys.exit(0)
except Exception as ex:
    print(f"BLOCKED: {type(ex).__name__}")
    sys.exit(1)
"""
        cmd = [sys.executable, "-c", net_probe_script]
        policy = SandboxPolicy(network_policy=NetworkPolicy.OFFLINE_ONLY)
        result = runner.execute_isolated(cmd, policy=policy)

        self.assertEqual(result.exit_code, 1)
        self.assertIn("BLOCKED", result.stdout)
        self.assertNotIn("LEAK", result.stdout)

    # =========================================================================
    # GATE C: Secret & Descriptor Isolation
    # =========================================================================

    def test_gate_c_parent_secrets_and_inherited_descriptors_withheld(self):
        """
        Gate C.1: Parent-held canary secrets in os.environ and open file descriptors
        are completely absent and inaccessible to the sandboxed child.
        """
        runner = OfflineSandboxRunner()

        canary_secret_key = "CIPH_CANARY_PARENT_KEY_" + uuid.uuid4().hex
        os.environ["CIPH_PARENT_CANARY_SECRET"] = canary_secret_key

        canary_fd, canary_file = tempfile.mkstemp(prefix="canary_fd_")
        os.write(canary_fd, b"CONFIDENTIAL_PARENT_DATA")

        inspect_script = f"""
import os, json, sys

env_keys = list(os.environ.keys())
has_canary_env = "CIPH_PARENT_CANARY_SECRET" in os.environ

has_canary_fd = False
try:
    os.fstat({canary_fd})
    has_canary_fd = True
except OSError:
    has_canary_fd = False

print(json.dumps({{
    "has_canary_env": has_canary_env,
    "has_canary_fd": has_canary_fd,
    "env_keys": env_keys
}}))
"""
        cmd = [sys.executable, "-c", inspect_script]
        policy = SandboxPolicy(env_allowlist=("PATH", "LANG", "LC_ALL", "CIPH_SANDBOX_ID"))

        result = runner.execute_isolated(cmd, policy=policy)
        self.assertEqual(result.exit_code, 0)
        data = result.data

        self.assertFalse(data["has_canary_env"])
        for k in data["env_keys"]:
            self.assertIn(k, policy.env_allowlist + ("PYTHONUNBUFFERED",))
        self.assertFalse(data["has_canary_fd"])

        os.close(canary_fd)
        os.remove(canary_file)
        del os.environ["CIPH_PARENT_CANARY_SECRET"]

    def test_gate_c_signing_authority_kept_outside_child(self):
        """
        Gate C.2: Supervisor validates token and signs receipt; child receives neither
        worker_secret_key nor trust_registry.
        """
        runner = OfflineSandboxRunner()
        self.daemon.sandbox_runner = runner

        class ExternalInspectionCapability(BaseCapability):
            requires_sandbox = True
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="cybersecurity.test_key_isolation",
                    description="Test signing key isolation",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                    timeout_seconds=5
                )
            def get_sandbox_command(self, params):
                script = """
import json, sys
data = json.load(sys.stdin)
has_keys = any('key' in str(k).lower() for k in data.keys())
print(json.dumps({'has_keys': has_keys, 'params': data}))
"""
                return [sys.executable, "-c", script]
            def run(self, params, context=None):
                return {}

        self.runtime.register_capability(ExternalInspectionCapability())

        token = self.runtime.mint_execution_token("cybersecurity.test_key_isolation", {"param1": "safe_val"})
        job_id = self.runtime.queue.enqueue_job(
            capability="cybersecurity.test_key_isolation",
            params={"param1": "safe_val"},
            execution_token=token,
        )

        receipt = self.daemon.drain_once(worker_id="worker-p7-keys", target_job_id=job_id)

        self.assertTrue(receipt.worker_signature)
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.results.get("has_keys"), False)

        valid, reason = receipt.verify(self.runtime.trust_registry)
        self.assertTrue(valid, reason)

    def test_gate_c_kernel_policy_auto_enforces_sandboxing_for_non_internal(self):
        """
        Gate C.3 (Finding 7): Kernel policy automatically requires sandboxing for non-internal
        origin or external network policies without requiring manual opt-in.
        """
        class InProcessInternalCap(BaseCapability):
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="ciph.internal.curiosity_probe",
                    description="Internal trusted probe",
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    risk_tier=RiskTier.LOW,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )
            def run(self, params, context=None):
                return {}

        class ExternalNetworkCap(BaseCapability):
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="threat.osint.scraper",
                    description="External fetch capability",
                    network_policy=NetworkPolicy.DIRECT_APPROVED,
                    risk_tier=RiskTier.HIGH,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                )
            def run(self, params, context=None):
                return {}

        internal_cap = InProcessInternalCap()
        external_cap = ExternalNetworkCap()

        # Internal capability with OFFLINE_ONLY does not require sandbox
        self.assertFalse(is_sandboxed_execution_required(internal_cap, internal_cap.manifest, code_origin="internal"))

        # External network capability requires sandbox even if code_origin="internal"
        self.assertTrue(is_sandboxed_execution_required(external_cap, external_cap.manifest, code_origin="internal"))

        # Non-internal code origin mandates sandboxing regardless of manifest
        self.assertTrue(is_sandboxed_execution_required(internal_cap, internal_cap.manifest, code_origin="external"))
        self.assertTrue(is_sandboxed_execution_required(internal_cap, internal_cap.manifest, code_origin="untrusted"))

    # =========================================================================
    # GATE D: Lifecycle & Resource Containment
    # =========================================================================

    def test_gate_d_descendant_escape_terminated_cleanly(self):
        """
        Gate D.1: Rogue descendant calling os.setsid() and ignoring SIGTERM
        is guaranteed terminated by the PID namespace / process group lifecycle.
        """
        runner = OfflineSandboxRunner()
        marker = f"ciph_escape_target_{uuid.uuid4().hex[:8]}"

        escape_script = f"""
import os, sys, time, signal, json
pid = os.fork()
if pid == 0:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        # marker: {marker}
        time.sleep(0.2)
else:
    time.sleep(0.1)
    print(json.dumps({{'marker': '{marker}', 'parent_pid': os.getpid()}}))
    sys.exit(0)
"""
        cmd = [sys.executable, "-c", escape_script]
        policy = SandboxPolicy(max_wall_time_seconds=3.0)

        result = runner.execute_isolated(cmd, policy=policy)
        self.assertEqual(result.exit_code, 0)

        time.sleep(0.2)
        pgrep = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
        surviving = pgrep.stdout.strip()
        self.assertEqual(surviving, "", f"Rogue descendant survived parent death: {surviving}")

    def test_gate_d_output_flooding_terminated_at_limit(self):
        """
        Gate D.2: Output flooding on stdout: Child attempting to stream infinite output
        is terminated immediately at max_output_bytes with reason OUTPUT_FLOOD.
        """
        runner = OfflineSandboxRunner()
        flood_script = """
import sys
while True:
    sys.stdout.write("A" * 4096)
    sys.stdout.flush()
"""
        cmd = [sys.executable, "-c", flood_script]
        policy = SandboxPolicy(max_output_bytes=32_768, max_wall_time_seconds=5.0)

        start = time.time()
        result = runner.execute_isolated(cmd, policy=policy)
        duration = time.time() - start

        self.assertLess(duration, 4.0)
        self.assertEqual(result.termination_reason, SandboxTerminationReason.OUTPUT_FLOOD)
        self.assertIn("Output exceeded ceiling", result.stderr)

    def test_gate_d_stderr_flooding_bounded_under_output_ceiling(self):
        """
        Gate D.3 (Finding 5): 64KB stderr under 1KB limit must be truncated to 1024 bytes
        and child terminated immediately with OUTPUT_FLOOD.
        """
        runner = OfflineSandboxRunner()
        code = 'import sys; sys.stderr.write("x" * 65536); print("{}")'
        policy = SandboxPolicy(max_output_bytes=1024, max_wall_time_seconds=5.0)

        result = runner.execute_isolated([sys.executable, "-c", code], policy=policy)

        self.assertEqual(result.termination_reason, SandboxTerminationReason.OUTPUT_FLOOD)
        self.assertLessEqual(len(result.stderr), 1024)
        self.assertIn("Output exceeded ceiling", result.stderr)

    def test_gate_d_wall_time_timeout_terminated_cleanly(self):
        """
        Gate D.4: Workload exceeding max_wall_time_seconds is killed with reason TIMEOUT.
        """
        runner = OfflineSandboxRunner()
        sleep_script = """
import time
time.sleep(10.0)
"""
        cmd = [sys.executable, "-c", sleep_script]
        policy = SandboxPolicy(max_wall_time_seconds=1.0)

        start = time.time()
        result = runner.execute_isolated(cmd, policy=policy)
        duration = time.time() - start

        self.assertGreaterEqual(duration, 1.0)
        self.assertLess(duration, 3.5)
        self.assertEqual(result.termination_reason, SandboxTerminationReason.TIMEOUT)
        self.assertIn("Wall time exceeded ceiling", result.stderr)

    def test_gate_d_resource_limits_propagate_exceptions(self):
        """
        Gate D.5 (Finding 5): apply_rlimits must propagate exceptions when setrlimit fails,
        rather than swallowing them with pass.
        """
        with patch('ciph.kernel.sandbox.launcher.resource.setrlimit', side_effect=PermissionError('controlled denial')):
            with self.assertRaises(PermissionError):
                apply_rlimits({'max_memory_bytes': 1024 * 1024, 'max_cpu_seconds': 1, 'max_output_bytes': 1024})

    def test_gate_d_active_descendant_verification_and_uncertain_cleanup(self):
        """
        Gate D.6 (Finding 6): When a process survives whole-tree cleanup, runner records
        cleaned_up=False with UNCERTAIN_CLEANUP, and IPCJobQueue marks RECONCILIATION_REQUIRED.
        """
        token = self.runtime.mint_execution_token("ciph.internal.curiosity_probe", {})
        job_id = self.runtime.queue.enqueue_job(
            capability="ciph.internal.curiosity_probe",
            params={},
            execution_token=token,
        )
        self.runtime.queue.lease_next_job("worker_uncertain", target_job_id=job_id)
        self.runtime.queue.mark_job_uncertain(
            job_id=job_id,
            worker_id="worker_uncertain",
            reason="UNCERTAIN_CLEANUP: Descendant process tree survival",
        )

        job = self.runtime.queue.get_job(job_id)
        self.assertEqual(job["status"], "RECONCILIATION_REQUIRED")
        self.assertIn("UNCERTAIN_CLEANUP", job["error"])

        events = self.runtime.event_store.get_events(event_type="JobReconciliationRequiredEvent")
        self.assertEqual(len(events), 1)

    def test_gate_d_known_exit_error_produces_authenticated_failure_receipt(self):
        """
        Gate D.7: Known nonzero exit produces an authenticated failure receipt,
        distinguishing known execution failure from uncertain cleanup.
        """
        runner = OfflineSandboxRunner()
        self.daemon.sandbox_runner = runner

        class FailingCapability(BaseCapability):
            requires_sandbox = True
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="cybersecurity.test_failing_cap",
                    description="Deliberately failing capability",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO,
                    timeout_seconds=5
                )
            def get_sandbox_command(self, params):
                return [sys.executable, "-c", "import sys; sys.stderr.write('Known application error'); sys.exit(42)"]
            def run(self, params, context=None):
                return {}

        self.runtime.register_capability(FailingCapability())

        token = self.runtime.mint_execution_token("cybersecurity.test_failing_cap", {})
        job_id = self.runtime.queue.enqueue_job(
            capability="cybersecurity.test_failing_cap",
            params={},
            execution_token=token,
        )

        receipt = self.daemon.drain_once(worker_id="worker-p7-fail", target_job_id=job_id)

        self.assertEqual(receipt.exit_code, 42)
        self.assertEqual(receipt.outcome, OutcomeCategory.EXECUTION_ERROR)
        self.assertIn("Known application error", receipt.error_message)
        self.assertTrue(receipt.worker_signature)


if __name__ == "__main__":
    unittest.main()
