"""
test_ciph_hardened_invariants.py - Hardened Security Invariant Probes for CIPH 4.0.
Verifies fixes for:
1. HMAC signature tampering
2. Authorization grant mismatch
3. Scope grant binding in route_and_execute
4. Scope grant binding in execute_reference_loop
5. Lease ownership enforcement in complete_job / fail_job
6. Network sandbox socket method and constructor patching across socket and _socket
7. Saved _socket.socket constructor and pre-created _socket.socket .bind() blocking under OFFLINE_ONLY
8. Evolution sandbox pathlib.Path / os filesystem write isolation
9. Evolution sandbox os.symlink / host-side filesystem link isolation
10. Daemon atomic failure handling for missing capabilities with cryptographic receipt integrity
11. Global maintenance exclusion on ClaimLeaseManager & MaterializedWorldview
12. Standalone CapabilityLedger fail-closed receipt verification
13. Concurrent identical submission single execution
14. Curiosity daemon DAG integration
15. Dependency auditing never invokes automatic package installation
16. Active slash commands delegate to the governed CommandRegistry
"""

import os
import time
import socket
import _socket
import sqlite3
import threading
import pathlib
import unittest
from unittest import mock
from code_staging import CodeStagingManager
from ciph_core import CiphCore
from ciph.runtime import CiphRuntime
from ciph.capabilities.base import BaseCapability
from ciph.capabilities.capability_ledger import CapabilityLedger
from ciph.memory.claim_leases import ClaimLeaseManager
from ciph.kernel.policy_engine import (
    CapabilityManifest,
    RiskTier,
    NetworkPolicy,
    ReversibilityClass,
    AuthorizationTier,
    AuthorizationGrant,
    ScopeGrant,
    ScopeType,
)
from ciph.kernel.network_sandbox import NetworkPolicyViolation, enforce_network_policy
from ciph.kernel.transmutation_dag import TransmutationDAG, TransmutationNode, EpistemicCategory, ReliabilityClass
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory, JobState, compute_idempotency_key
from ciph.workers.daemon import DurableWorkerDaemon
from ciph.planner.schemas import IntentProposal, ExecutionDAG, PlanStep


class TestCiphHardenedInvariants(unittest.TestCase):
    TEST_DB = "test_ciph_hardened.db"

    def _clean_db(self):
        for ext in ["", "-wal", "-shm"]:
            path = self.TEST_DB + ext
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

    def setUp(self):
        self._clean_db()
        self.auth_key = b"hardened_auth_secret_key_32b_!"
        self.worker_key = b"hardened_worker_secret_key_32b!"
        self.runtime = CiphRuntime(
            db_path=self.TEST_DB,
            auth_secret_key=self.auth_key,
            worker_secret_key=self.worker_key
        )

    def tearDown(self):
        self.runtime.shutdown()
        self._clean_db()

    def test_dependency_audit_never_invokes_pip(self):
        """Missing dependencies are reported without executing a package installer."""
        manager = CodeStagingManager.__new__(CodeStagingManager)
        missing_module = "ciph_dependency_that_must_not_exist_7f3c8d"

        with mock.patch("code_staging.subprocess.run") as subprocess_run:
            status = manager.resolve_dependencies([missing_module])

        self.assertFalse(status[missing_module])
        subprocess_run.assert_not_called()

    def test_active_slash_command_uses_governed_registry(self):
        """A registered slash command is handled before the legacy command tree."""
        calls = []

        class StubRuntime:
            def dispatch_slash_command(self, command):
                calls.append(command)
                return {"status": "SUCCEEDED", "dialogue": "governed-dispatch"}

        core = CiphCore.__new__(CiphCore)
        core.runtime = StubRuntime()

        result = core.handle_command("/sports home=Alpha away=Beta")

        self.assertEqual(result, "governed-dispatch")
        self.assertEqual(calls, ["/sports home=Alpha away=Beta"])

    def test_auth_budget_tamper_fails_verification(self):
        """Modifying max_budget on a signed AuthorizationGrant must invalidate the signature."""
        grant = AuthorizationGrant(
            grant_id="grant_budget_01",
            plan_hash="plan_hash_123",
            step_id="S1",
            capability="pentest.scan",
            params_hash="params_hash_123",
            scope_grant_id="scope_01",
            max_budget={"max_cost_usd": 10.0},
            expires_at=time.time() + 60
        ).sign(self.auth_key)

        self.assertTrue(grant.verify_signature(self.auth_key))

        tampered = AuthorizationGrant(
            grant_id=grant.grant_id,
            plan_hash=grant.plan_hash,
            step_id=grant.step_id,
            capability=grant.capability,
            params_hash=grant.params_hash,
            scope_grant_id=grant.scope_grant_id,
            max_budget={"max_cost_usd": 1000.0},
            expires_at=grant.expires_at,
            signature=grant.signature,
            created_at=grant.created_at
        )

        self.assertFalse(tampered.verify_signature(self.auth_key))

    def test_mismatched_signed_grant_rejected_on_route_and_execute(self):
        """A grant signed for wrong capability, plan, or parameters cannot authorize an action."""
        class HighRiskCapA(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="admin.action_a",
                    description="Action A",
                    risk_tier=RiskTier.CRITICAL,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.IRREVERSIBLE,
                    authorization=AuthorizationTier.MANDATORY_INTERRUPT,
                )

            def run(self, params, context=None):
                return {"action": "A"}

        class HighRiskCapB(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="admin.action_b",
                    description="Action B",
                    risk_tier=RiskTier.CRITICAL,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.IRREVERSIBLE,
                    authorization=AuthorizationTier.MANDATORY_INTERRUPT,
                )

            def run(self, params, context=None):
                return {"action": "B"}

        self.runtime.register_capability(HighRiskCapA())
        self.runtime.register_capability(HighRiskCapB())
        params_a = {"target": "cluster_a"}
        params_hash_a = ExecutionReceipt.hash_payload(params_a)
        grant_a = AuthorizationGrant(
            grant_id="grant_a",
            plan_hash="plan_a",
            step_id="step_a",
            capability="admin.action_a",
            params_hash=params_hash_a,
            scope_grant_id="",
            expires_at=time.time() + 60
        ).sign(self.auth_key)

        receipt = self.runtime.route_and_execute(
            capability_name="admin.action_b",
            params={"target": "cluster_b"},
            context={"auth_grant": grant_a}
        )

        self.assertEqual(receipt.exit_code, 1)
        self.assertEqual(receipt.outcome, OutcomeCategory.AUTH_REQUIRED)

    def test_scope_grant_mismatch_in_reference_loop_rejected(self):
        """Reference loop must reject a grant signed for scope-WRONG when executed under scope-A."""
        class ScopedCritCap(BaseCapability):
            @property
            def manifest(self) -> CapabilityManifest:
                return CapabilityManifest(
                    name="system.scoped_critical",
                    description="Critical scoped action",
                    risk_tier=RiskTier.CRITICAL,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.IRREVERSIBLE,
                    authorization=AuthorizationTier.MANDATORY_INTERRUPT,
                )

            def run(self, params, context=None):
                return {"executed": True}

        self.runtime.register_capability(ScopedCritCap())

        proposal = IntentProposal(
            proposal_id="prop_scoped_test",
            objective="Perform critical action",
            proposed_capability="system.scoped_critical",
            provided_parameters={"target": "cluster_a"}
        )
        scope_a = ScopeGrant(
            scope_id="scope_A",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["cluster_a"]
        )

        grant_wrong_scope = AuthorizationGrant(
            grant_id="grant_wrong_scope",
            plan_hash="plan_prop_scoped_test",
            step_id="STEP_prop_scoped_test",
            capability="system.scoped_critical",
            params_hash=ExecutionReceipt.hash_payload({"target": "cluster_a"}),
            scope_grant_id="scope_WRONG",
            expires_at=time.time() + 60
        ).sign(self.auth_key)

        res = self.runtime.execute_reference_loop(proposal, scope_grant=scope_a, auth_grant=grant_wrong_scope)
        self.assertEqual(res["status"], "AUTHORIZATION_MISMATCH")

    def test_foreign_worker_cannot_complete_job_lease(self):
        """Worker B cannot complete or insert receipt events for a job leased to Worker A."""
        job_id = self.runtime.queue.enqueue_job(
            capability="memory.retrieve",
            params={"key": "secret"}
        )
        leased_a = self.runtime.queue.lease_next_job(worker_id="worker_A")
        self.assertIsNotNone(leased_a)
        self.assertEqual(leased_a["job_id"], job_id)

        # Worker B attempts to complete Worker A's leased job
        res_dict = {"results": {"key": "secret", "value": "val"}, "receipt_id": "rcpt_stolen_01"}
        ev_id = self.runtime.queue.complete_job_and_append_receipt_event(
            job_id=job_id,
            worker_id="worker_B",
            receipt_dict=res_dict
        )
        self.assertEqual(ev_id, 0)
        # Verify job is STILL leased to worker_A in DB
        j = self.runtime.queue.get_job(job_id)
        self.assertEqual(j["leased_to"], "worker_A")
        self.assertEqual(j["status"], JobState.LEASED.value)

    def test_saved_socket_alias_and_preinstantiated_blocked(self):
        """Pre-captured socket constructors and pre-instantiated socket objects must be blocked under OFFLINE_ONLY."""
        saved_sock_cls = socket.socket
        s_pre = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            with enforce_network_policy(NetworkPolicy.OFFLINE_ONLY):
                with self.assertRaises(NetworkPolicyViolation):
                    saved_sock_cls(socket.AF_INET, socket.SOCK_STREAM)

                with self.assertRaises(NetworkPolicyViolation):
                    s_pre.connect(("8.8.8.8", 80))

                with self.assertRaises(NetworkPolicyViolation):
                    s_pre.bind(("127.0.0.1", 0))
        finally:
            s_pre.close()

    def test_saved_underscore_socket_and_precreated_bind_blocked(self):
        """Saved _socket.socket constructor and pre-created _socket.socket.bind() are blocked under OFFLINE_ONLY."""
        saved_u_sock_cls = _socket.socket
        u_pre = saved_u_sock_cls(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            with enforce_network_policy(NetworkPolicy.OFFLINE_ONLY):
                with self.assertRaises(NetworkPolicyViolation):
                    saved_u_sock_cls(_socket.AF_INET, _socket.SOCK_STREAM)

                with self.assertRaises(NetworkPolicyViolation):
                    u_pre.bind(("127.0.0.1", 0))

                with self.assertRaises(NetworkPolicyViolation):
                    u_pre.connect(("127.0.0.1", 80))
        finally:
            u_pre.close()

    def test_dynamic_manifest_with_getattr_fails_closed_to_mandatory_interrupt(self):
        """Candidate capabilities using dynamic getattr manifest expressions must fail closed to MANDATORY_INTERRUPT."""
        code = """
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier

class DynamicObfuscatedCap(BaseCapability):
    @property
    def manifest(self) -> CapabilityManifest:
        r = getattr(RiskTier, "CRITICAL")
        a = getattr(AuthorizationTier, "MANDATORY_INTERRUPT")
        return CapabilityManifest(
            name="dyn.obfuscated",
            description="Dynamic manifest",
            risk_tier=r,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.IRREVERSIBLE,
            authorization=a,
        )

    def run(self, params, context=None):
        return {"dynamic": True}
"""
        res = self.runtime.hot_reload_evolved_capability(
            code_source=code,
            class_name="DynamicObfuscatedCap"
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "AUTHORIZATION_REQUIRED")

    def test_pathlib_write_text_blocked_in_evolution_sandbox(self):
        """Subprocess candidate code calling pathlib.Path.write_text outside sandbox is blocked with PermissionError."""
        outside_file = os.path.abspath("test_pathlib_escape.tmp")
        if os.path.exists(outside_file):
            os.remove(outside_file)

        grant = AuthorizationGrant(
            grant_id="grant_test_pathlib",
            plan_hash="single:test.pathlib_probe:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            step_id="STEP_SINGLE",
            capability="test.pathlib_probe",
            params_hash="44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            scope_grant_id="",
            expires_at=time.time() + 60
        ).sign(self.auth_key)

        code = f"""
import pathlib
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier

class PathlibEscapeCap(BaseCapability):
    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="test.pathlib_probe",
            description="Pathlib Escape Probe",
            risk_tier=RiskTier.CRITICAL,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.IRREVERSIBLE,
            authorization=AuthorizationTier.MANDATORY_INTERRUPT,
        )

    def run(self, params, context=None):
        pathlib.Path({repr(outside_file)}).write_text("PATHLIB_ESCAPE")
        return {{"escaped": True}}
"""
        res = self.runtime.hot_reload_evolved_capability(
            code_source=code,
            class_name="PathlibEscapeCap",
            auth_grant=grant
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "MOCK_EXECUTION_TEST_FAILED")
        self.assertFalse(os.path.exists(outside_file))

    def test_symlink_escape_blocked_in_evolution_sandbox(self):
        """Host and subprocess candidate code calling os.symlink outside sandbox is blocked."""
        outside_symlink = os.path.abspath("test_symlink_escape.tmp")
        if os.path.exists(outside_symlink) or os.path.islink(outside_symlink):
            os.remove(outside_symlink)

        grant = AuthorizationGrant(
            grant_id="grant_test_symlink",
            plan_hash="single:test.symlink_probe:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            step_id="STEP_SINGLE",
            capability="test.symlink_probe",
            params_hash="44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            scope_grant_id="",
            expires_at=time.time() + 60
        ).sign(self.auth_key)

        code = f"""
import os
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier

class SymlinkEscapeCap(BaseCapability):
    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="test.symlink_probe",
            description="Symlink Escape Probe",
            risk_tier=RiskTier.CRITICAL,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.IRREVERSIBLE,
            authorization=AuthorizationTier.MANDATORY_INTERRUPT,
        )

    def run(self, params, context=None):
        os.symlink("/etc/hosts", {repr(outside_symlink)})
        return {{"symlinked": True}}
"""
        res = self.runtime.hot_reload_evolved_capability(
            code_source=code,
            class_name="SymlinkEscapeCap",
            auth_grant=grant
        )
        self.assertFalse(res["success"])
        self.assertFalse(os.path.exists(outside_symlink) or os.path.islink(outside_symlink))

    def test_daemon_missing_capability_creates_atomic_failure_receipt(self):
        """Worker daemon encountering missing capability creates an atomic failure receipt with valid signature."""
        daemon = DurableWorkerDaemon(
            queue=self.runtime.queue,
            registry=self.runtime.registry,
            event_store=self.runtime.event_store,
            worker_secret_key=self.worker_key
        )
        job_id = self.runtime.queue.enqueue_job(
            capability="unregistered.ghost_cap",
            params={"target": "ghost"}
        )
        job = self.runtime.queue.lease_next_job(worker_id="daemon_w1")
        self.assertIsNotNone(job)

        receipt = daemon._execute_leased_job(job, worker_id="daemon_w1")
        self.assertIsNone(receipt)
        j = self.runtime.queue.get_job(job_id)
        self.assertIn(j["status"], (JobState.FAILED.value, JobState.RETRYING.value))
        events = self.runtime.event_store.get_events(aggregate_id=j["receipt_id"])
        self.assertEqual(len(events), 1)

        # Verify cryptographic signature and output hash integrity
        ev_payload = events[0]["payload"]
        if isinstance(ev_payload, str):
            import json
            ev_payload = json.loads(ev_payload)
        rcpt = ExecutionReceipt.from_dict(ev_payload)
        self.assertTrue(rcpt.verify_signature(self.worker_key))
        self.assertEqual(rcpt.output_hash, ExecutionReceipt.hash_payload(rcpt.results))

    def test_claim_lease_manager_and_writers_blocked_during_maintenance_lease(self):
        """When an exclusive maintenance lease is held, ClaimLeaseManager and worldview writers are blocked."""
        m_mgr = self.runtime.maintenance_manager
        holder_id = "backup_daemon_01"
        self.assertTrue(m_mgr.acquire_lease("global_db_maintenance", holder_id, ttl_seconds=30))

        try:
            # 1. ClaimLeaseManager write attempt must be blocked
            clm = ClaimLeaseManager(db_path=self.TEST_DB)
            with self.assertRaises(sqlite3.OperationalError):
                with clm._get_connection() as conn:
                    conn.execute("INSERT INTO ciph_claim_leases VALUES ('l1', 'c1', 'w1', 'j1', 1.0, 100.0);")

            # 2. MaterializedWorldview write attempt must be blocked
            with self.assertRaises(sqlite3.OperationalError):
                node = TransmutationNode(
                    claim_id="CLM-BLOCKED",
                    subject="test",
                    predicate="test",
                    value="test",
                    state=EpistemicCategory.OBSERVED,
                    reliability=ReliabilityClass.AUTHORITATIVE_LOCAL,
                    assurance_score=1.0
                )
                self.runtime.worldview.upsert_claim(node)
        finally:
            m_mgr.release_lease("global_db_maintenance", holder_id)

    def test_standalone_ledger_rejects_unauthenticated_receipts(self):
        """Standalone CapabilityLedger without a key rejects forged receipts with dummy signatures."""
        standalone_ledger = CapabilityLedger(
            registry=self.runtime.registry,
            event_store=self.runtime.event_store,
            worker_secret_key=None
        )
        forged_receipt = {
            "receipt_id": "rcpt_forged_dummy_sig",
            "capability": "stealth.pwn",
            "exit_code": 0,
            "results": {"pwned": True},
            "output_hash": ExecutionReceipt.hash_payload({"pwned": True}),
            "worker_signature": "NOT_A_VALID_HMAC",
            "started_at": 100.0,
            "completed_at": 100.1
        }
        self.runtime.event_store.append_event(
            event_type="ExecutionReceiptStoredEvent",
            aggregate_id="rcpt_forged_dummy_sig",
            payload=forged_receipt
        )

        report = standalone_ledger.generate_self_knowledge_report()
        self.assertNotIn("stealth.pwn", report["empirically_verified_capabilities"])

    def test_concurrent_identical_submissions_execute_only_once(self):
        """Concurrent identical submissions with the same idempotency key execute only once."""
        proposal = IntentProposal(
            proposal_id="prop_concurrent_idemp",
            objective="Retrieve local memory concurrently",
            proposed_capability="memory.retrieve",
            provided_parameters={"key": "concurrent_test_key", "target": "local_memory"}
        )
        scope = ScopeGrant(
            scope_id="scope_conc_idemp",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"]
        )

        results = []
        threads = []

        def _worker():
            res = self.runtime.execute_reference_loop(proposal, scope_grant=scope)
            results.append(res)

        for _ in range(2):
            t = threading.Thread(target=_worker)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["status"], "SUCCESS")
        self.assertEqual(results[1]["status"], "SUCCESS")
        replay_count = sum(1 for r in results if r.get("idempotent_replay", False))
        self.assertEqual(replay_count, 1, msg=f"Actual results: {results}")

    def test_curiosity_daemon_updates_question_dag(self):
        """CuriosityDaemon inquiry cycles propose questions into QuestionDAG and resolve them with evidence."""
        gap_node = TransmutationNode(
            claim_id="CLM-GAP-001",
            subject="system.diagnostics",
            predicate="health_score",
            value=None,
            state=EpistemicCategory.INTELLIGENCE_GAP,
            reliability=ReliabilityClass.DIRECT_SENSOR,
            assurance_score=0.1
        )
        self.runtime.worldview.upsert_claim(gap_node)

        results = self.runtime.run_curiosity_cycle()
        self.assertTrue(len(results) > 0)
        all_q = list(self.runtime.question_dag._questions.values())
        self.assertTrue(len(all_q) > 0)


if __name__ == "__main__":
    unittest.main()
