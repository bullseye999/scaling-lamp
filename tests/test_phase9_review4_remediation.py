"""Review 4 regressions: genuine activation, retries, attribution and receipt schema."""
import hashlib
import json
import sqlite3
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import test_phase9_capability_ledger as ledger_fixtures
import test_phase3_adversarial_recovery as worker_fixtures
from ciph.capabilities.capability_ledger import CapabilityLedger, DependencyHealthEvidence, DependencyCheckResult
from ciph.kernel.crypto_identity import ExecutionToken, Ed25519KeyManager
from ciph.workers.receipts import generate_environment_fingerprint


class TestReview4Evidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.t = ledger_fixtures.TestPhase9CapabilityLedger()
        self.t.TEST_DB = str(Path(self.temp.name) / 'ledger.db')
        self.t.setUp()

    def tearDown(self):
        self.t.tearDown()
        self.temp.cleanup()

    def token(self):
        t = self.t
        receipt = t._create_signed_receipt()
        p = receipt.provenance
        token = ExecutionToken(token_id=p['token_id'], nonce='nonce_JOB-1',
            plan_hash=p['plan_hash'], step_id=p['step_id'], capability=receipt.capability,
            manifest_hash=p['manifest_hash'], manifest_version=p['manifest_version'],
            parameters_hash=p['parameters_hash'], scope_grant_id=None, authorization_grant_id=None,
            execution_lane='OFFLINE', authorized_worker_class='ALL',
            issued_at=receipt.started_at-5, expires_at=receipt.completed_at+60,
            max_attempts=3, kernel_key_id='kernel_primary').sign(t.kernel_priv)
        return receipt, token

    def append(self, receipt):
        self.t.event_store.append_event('ExecutionReceiptStoredEvent', receipt.receipt_id, receipt.to_dict())

    def unsigned_attempt(self, receipt, token):
        self.t.event_store.append_event('ExecutionAttemptStartedEvent',
            f'attempt:{receipt.job_id}:{receipt.attempt_number}', {
                'job_id': receipt.job_id, 'attempt_number': receipt.attempt_number,
                'capability': receipt.capability, 'worker_id': receipt.worker_id,
                'token_id': token.token_id, 'token_hash': token.token_hash(),
                'manifest_version': token.manifest_version, 'manifest_hash': token.manifest_hash,
                'token': token.to_dict()})

    def reconcile(self, job_id):
        result = {}; notes = 'Operator reviewed uncertain execution'
        digest = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
        signature = Ed25519KeyManager.sign(self.t.op_priv,
            f'RECONCILE:{job_id}:FAILED:{digest}:{notes}'.encode())
        self.t.event_store.append_event('JobReconciledEvent', job_id, {
            'job_id': job_id, 'target_state': 'FAILED', 'resolution_notes': notes,
            'operator_id': 'operator_root', 'operator_signature': signature, 'result': result})

    def scan(self, **kwargs):
        dep = DependencyHealthEvidence(capability_name='math.compute', status=DependencyCheckResult.PASS,
            checked_at=time.time(), source='TEST', declared_modules=(), missing_modules=(),
            environment_fingerprint=self.t.env_fingerprint)
        profiles, checkpoint = CapabilityLedger(self.t.event_store, self.t.registry,
            trust_registry=self.t.trust_registry, **kwargs).compile_empirical_ledger(
                dependency_evidence_map={'math.compute': dep})
        self.assertTrue(checkpoint.is_complete)
        return profiles['math.compute'], checkpoint

    def test_signed_fixtures_without_consumption_cannot_activate(self):
        r, token = self.token()
        self.unsigned_attempt(r, token); self.append(r)
        p, _ = self.scan()
        self.assertEqual(p.current_version_clean_successes, 0)
        self.assertEqual(p.evidence_state.value, 'HISTORICAL_UNBOUND')

    def test_one_consumed_token_cannot_credit_three_attempts(self):
        r, token = self.token()
        self.t._activate(r, token); self.append(r)
        for n in (2, 3):
            changed = replace(r, attempt_number=n, receipt_id=f'reused_{n}').sign(self.t.worker_priv)
            self.unsigned_attempt(changed, token); self.append(changed)
        p, _ = self.scan()
        self.assertEqual(p.current_version_attempts, 1)
        self.assertEqual(p.current_version_clean_successes, 1)

    def test_malformed_side_effects_fail_both_verifiers(self):
        r, _ = self.token()
        self.assertTrue(r.verify(self.t.trust_registry)[0])
        for value in ({'deleted_files': ['/example/important-file']}, {}, None, 'file', [1], [{}], ('file',), {'file'}):
            with self.subTest(value=value):
                changed = replace(r, side_effects=value)
                self.assertEqual(changed.verify(self.t.trust_registry), (False, 'INVALID_SIDE_EFFECTS'))
                self.assertFalse(changed.verify_signature(self.t.worker_priv))
                with self.assertRaises(ValueError): changed.compute_signature_payload()
        valid = replace(r, side_effects=['b', 'a']).sign(self.t.worker_priv)
        self.assertTrue(valid.verify(self.t.trust_registry)[0])
        self.assertTrue(replace(valid, side_effects=['a', 'b']).verify(self.t.trust_registry)[0])
        self.assertFalse(replace(valid, side_effects=['a', 'deleted']).verify(self.t.trust_registry)[0])

    def test_unsigned_attempt_cannot_attribute_reconciliation(self):
        r, token = self.token()
        self.unsigned_attempt(r, token); self.reconcile(r.job_id)
        p, c = self.scan()
        self.assertEqual((p.lifetime_reconciled_jobs, c.unresolved_reconciled_jobs_count), (0, 1))

    def test_attempt_token_capability_contradiction_remains_a_conflict(self):
        r, token = self.token()
        token = replace(token, capability='other.capability').sign(self.t.kernel_priv)
        self.unsigned_attempt(r, token); self.reconcile(r.job_id)
        p, c = self.scan()
        self.assertEqual(p.health_status.value, 'INTEGRITY_CONFLICT')
        self.assertGreater(c.conflicting_receipts_count, 0)
        self.assertEqual(c.unresolved_reconciled_jobs_count, 1)

    def test_unenrolled_receipt_cannot_attribute_reconciliation(self):
        r, _ = self.token(); private, _ = Ed25519KeyManager.generate_keypair()
        r = replace(r, worker_key_id='unenrolled').sign(private, worker_key_id='unenrolled')
        self.append(r); self.reconcile(r.job_id)
        p, c = self.scan(worker_secret_key=private)
        self.assertEqual((p.lifetime_reconciled_jobs, c.unresolved_reconciled_jobs_count), (0, 1))

    def test_reconciliation_before_genuine_activation_is_resolved_postscan(self):
        r, token = self.token(); self.reconcile(r.job_id); self.t._activate(r, token)
        p, c = self.scan()
        self.assertEqual((p.lifetime_reconciled_jobs, c.unresolved_reconciled_jobs_count), (1, 0))
        self.assertEqual(p.current_version_clean_successes, 0)

    def test_consumption_removal_disqualifies_execution_and_attribution(self):
        r, token = self.token(); self.t._activate(r, token); self.append(r); self.reconcile(r.job_id)
        with sqlite3.connect(self.t.TEST_DB) as conn: conn.execute('DELETE FROM ciph_consumed_tokens')
        p, c = self.scan()
        self.assertEqual(p.current_version_clean_successes, 0)
        self.assertEqual(c.unresolved_reconciled_jobs_count, 1)

    def test_altered_signed_activation_with_rehashed_chain_is_rejected(self):
        r, token = self.token(); self.t._activate(r, token)
        with sqlite3.connect(self.t.TEST_DB) as conn:
            row = conn.execute('SELECT event_id,event_type,aggregate_id,payload,timestamp,previous_hash FROM ciph_event_store').fetchone()
            payload = json.loads(row[3]); payload['plan_id'] = 'forged_plan'
            raw = json.dumps(payload, sort_keys=True)
            digest = hashlib.sha256(f'{row[5]}|{row[1]}|{row[2]}|{raw}|{row[4]}'.encode()).hexdigest()
            conn.execute('UPDATE ciph_event_store SET payload=?,event_hash=? WHERE event_id=?', (raw,digest,row[0]))
            conn.execute('UPDATE ciph_ipc_jobs SET plan_id=?', ('forged_plan',))
        self.append(r); self.reconcile(r.job_id)
        p, c = self.scan()
        self.assertEqual(p.current_version_clean_successes, 0)
        self.assertEqual(c.unresolved_reconciled_jobs_count, 1)

    def test_missing_signing_authority_rolls_back_consumption(self):
        r, token = self.token()
        with patch('time.time', return_value=r.started_at):
            self.t.queue.enqueue_job(r.capability, {'x':1}, job_id=r.job_id, execution_token=token)
            self.t.queue.lease_next_job(r.worker_id, target_job_id=r.job_id)
            with patch.object(self.t.trust_registry, 'get_keypair', return_value=None):
                ok, _ = self.t.queue.mark_executing_and_consume_token(r.job_id, r.worker_id, token.token_id, token.nonce, token.expires_at)
        self.assertFalse(ok)
        with sqlite3.connect(self.t.TEST_DB) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM ciph_consumed_tokens').fetchone()[0], 0)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM ciph_event_store').fetchone()[0], 0)
        self.assertEqual(self.t.queue.get_job(r.job_id)['status'], 'LEASED')


class TestReview4RealRetries(unittest.TestCase):
    def setUp(self):
        self.t = worker_fixtures.TestPhase3AdversarialRecovery(); self.t.setUp()

    def tearDown(self): self.t.tearDown()

    def scan(self):
        p, c = self.t.runtime.capability_ledger.compile_empirical_ledger()
        self.assertTrue(c.is_complete)
        return p[self.t.cap.manifest.name], c

    def execute_retry(self, crash=False):
        t = self.t; t.cap.should_fail = True
        job, _ = t.enqueue(attempts=3)
        first = t.execute(job); self.assertNotEqual(first.exit_code, 0)
        if crash:
            t.queue.lease_next_job('dead', .01, target_job_id=job)
            time.sleep(.03); t.queue.reclaim_expired_leases()
        t.cap.should_fail = False
        second = t.execute(job); self.assertEqual(second.exit_code, 0)
        self.assertNotEqual(first.provenance['execution_token_hash'], second.provenance['execution_token_hash'])
        return job

    def test_activation_event_failure_rolls_back_before_invocation(self):
        job, _ = self.t.enqueue()
        with sqlite3.connect(self.t.db) as conn:
            conn.execute("CREATE TRIGGER reject_activation BEFORE INSERT ON ciph_event_store BEGIN SELECT RAISE(ABORT, 'activation failure'); END")
        result = self.t.execute(job)
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(self.t.cap.execution_count, 0)
        self.assertEqual(self.t.queue.get_job(job)['status'], 'LEASED')
        with sqlite3.connect(self.t.db) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM ciph_consumed_tokens').fetchone()[0], 0)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM ciph_event_store').fetchone()[0], 0)

    def test_real_retry_credits_both_authenticated_attempts(self):
        self.execute_retry()
        p, c = self.scan()
        self.assertEqual((p.current_version_attempts, p.current_version_clean_successes), (2, 1))
        self.assertEqual(c.conflicting_receipts_count, 0)

    def test_preexecution_crash_preserves_unused_retry_authority(self):
        self.execute_retry(crash=True)
        p, _ = self.scan()
        self.assertEqual((p.current_version_attempts, p.current_version_clean_successes), (2, 1))

    def test_missing_retry_lineage_removes_retry_credit(self):
        self.execute_retry()
        with sqlite3.connect(self.t.db) as conn: conn.execute('DELETE FROM ciph_retry_tokens')
        p, _ = self.scan()
        self.assertEqual((p.current_version_attempts, p.current_version_clean_successes), (1, 0))

class TestReview5DelayedStartup(unittest.TestCase):
    """Review 5 regressions: startup latency must not discard authenticated evidence."""

    def setUp(self):
        self.t = worker_fixtures.TestPhase3AdversarialRecovery(); self.t.setUp()

    def tearDown(self): self.t.tearDown()

    def scan(self):
        from ciph.workers.receipts import generate_environment_fingerprint
        dep = DependencyHealthEvidence(capability_name=self.t.cap.manifest.name,
            status=DependencyCheckResult.PASS, checked_at=time.time(), source='TEST',
            declared_modules=(), missing_modules=(),
            environment_fingerprint=generate_environment_fingerprint())
        p, c = self.t.runtime.capability_ledger.compile_empirical_ledger(
            dependency_evidence_map={self.t.cap.manifest.name: dep})
        self.assertTrue(c.is_complete)
        return p[self.t.cap.manifest.name], c

    def _execute_with_delay(self, delay, fail=False):
        from ciph.capabilities.base import WorkerExecutionContext
        self.t.cap.should_fail = fail
        job, token = self.t.enqueue(attempts=3)
        original = WorkerExecutionContext.create
        def delayed(*a, **kw):
            time.sleep(delay)
            return original(*a, **kw)
        with patch.object(WorkerExecutionContext, 'create', side_effect=delayed):
            receipt = self.t.execute(job)
        self.assertIsNotNone(receipt)
        self.assertTrue(receipt.verify(self.t.runtime.trust_registry)[0])
        return job, receipt

    def test_delayed_genuine_success_earns_current_version_credit(self):
        """A 1.2s startup delay must not discard a valid successful execution."""
        _, receipt = self._execute_with_delay(1.2, fail=False)
        self.assertEqual(receipt.exit_code, 0)
        p, c = self.scan()
        self.assertEqual(p.current_version_attempts, 1)
        self.assertEqual(p.current_version_clean_successes, 1)
        self.assertEqual(p.health_status.value, 'VERIFIED_ACTIVE')
        self.assertEqual(c.conflicting_receipts_count, 0)

    def test_delayed_failure_after_success_appears_in_defect_metrics(self):
        """A delayed failure must stay in current-version metrics and change health."""
        # First: immediate success
        job1, r1 = self._execute_with_delay(0, fail=False)
        self.assertEqual(r1.exit_code, 0)
        # Second: delayed failure
        job2, r2 = self._execute_with_delay(1.2, fail=True)
        self.assertNotEqual(r2.exit_code, 0)
        p, c = self.scan()
        self.assertEqual(p.current_version_attempts, 2)
        self.assertEqual(p.current_version_clean_successes, 1)
        self.assertEqual(p.current_version_defect_failures, 1)
        # Health must NOT be VERIFIED_ACTIVE with a defect present
        self.assertNotEqual(p.health_status.value, 'VERIFIED_ACTIVE')
        self.assertEqual(c.conflicting_receipts_count, 0)

    def test_retry_after_delayed_parent_failure_credits_both_attempts(self):
        """A retry whose failed parent had startup delay must credit both attempts."""
        self.t.cap.should_fail = True
        from ciph.capabilities.base import WorkerExecutionContext
        job, _ = self.t.enqueue(attempts=3)
        # First attempt: delayed failure
        original = WorkerExecutionContext.create
        def delayed(*a, **kw):
            time.sleep(1.2)
            return original(*a, **kw)
        with patch.object(WorkerExecutionContext, 'create', side_effect=delayed):
            first = self.t.execute(job)
        self.assertNotEqual(first.exit_code, 0)
        # Second attempt: immediate success (retry)
        self.t.cap.should_fail = False
        second = self.t.execute(job)
        self.assertEqual(second.exit_code, 0)
        self.assertNotEqual(first.provenance['execution_token_hash'],
                            second.provenance['execution_token_hash'])
        p, c = self.scan()
        self.assertEqual(p.current_version_attempts, 2)
        self.assertEqual(p.current_version_clean_successes, 1)
        self.assertEqual(c.conflicting_receipts_count, 0)



class TestReview6SandboxAndEvolutionExecution(unittest.TestCase):
    """Review 6 regressions: Sandbox and Evolution paths must be admitted by the capability ledger."""

    def test_real_sandbox_success_establishes_verified_active(self):
        """Real sandboxed execution with exit 0 earns current-version credit and VERIFIED_ACTIVE."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier
        import sys

        class SandboxedSuccess(BaseCapability):
            requires_sandbox = True
            @property
            def manifest(self):
                return CapabilityManifest(name="test.sandbox.success", description="Sandbox success",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO)
            def get_sandbox_command(self, params):
                return [sys.executable, "-c", "import json, sys; print(json.dumps({'result': 42})); sys.exit(0)"]
            def run(self, params, context=None):
                raise AssertionError("Must run in sandbox")

        with tempfile.TemporaryDirectory(prefix="review6-sbx-succ-") as td:
            rt = CiphRuntime(db_path=str(Path(td) / "jobs.db"))
            try:
                cap = SandboxedSuccess()
                rt.register_capability(cap)
                params = {"x": 1}
                token = rt.mint_execution_token(cap.manifest.name, params, max_attempts=1)
                job = rt.queue.enqueue_job(cap.manifest.name, params, max_retries=1, execution_token=token,
                                           idempotency_key="sbx-succ-idemp")
                receipt = rt.worker_daemon.drain_once(worker_id="worker_sbx", target_job_id=job)
                self.assertIsNotNone(receipt)
                self.assertEqual(receipt.exit_code, 0)
                self.assertTrue(receipt.verify(rt.trust_registry)[0])

                dep = DependencyHealthEvidence(capability_name=cap.manifest.name, status=DependencyCheckResult.PASS,
                    checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
                    environment_fingerprint=generate_environment_fingerprint())
                profiles, checkpoint = rt.capability_ledger.compile_empirical_ledger(
                    dependency_evidence_map={cap.manifest.name: dep})
                p = profiles[cap.manifest.name]
                self.assertEqual(p.current_version_attempts, 1)
                self.assertEqual(p.current_version_clean_successes, 1)
                self.assertEqual(p.current_version_defect_failures, 0)
                self.assertEqual(p.health_status.value, "VERIFIED_ACTIVE")
                self.assertTrue(checkpoint.is_complete)
                self.assertEqual(checkpoint.conflicting_receipts_count, 0)
            finally:
                rt.shutdown()

    def test_real_sandbox_failure_records_defect_and_failing_health(self):
        """Real sandboxed execution with nonzero exit records a defect and FAILING health."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier
        import sys

        class SandboxedFailure(BaseCapability):
            requires_sandbox = True
            @property
            def manifest(self):
                return CapabilityManifest(name="test.sandbox.failure", description="Sandbox failure",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO)
            def get_sandbox_command(self, params):
                return [sys.executable, "-c", "import json, sys; print(json.dumps({'error': 'boom'})); sys.exit(42)"]
            def run(self, params, context=None):
                raise AssertionError("Must run in sandbox")

        with tempfile.TemporaryDirectory(prefix="review6-sbx-fail-") as td:
            rt = CiphRuntime(db_path=str(Path(td) / "jobs.db"))
            try:
                cap = SandboxedFailure()
                rt.register_capability(cap)
                params = {"x": 1}
                token = rt.mint_execution_token(cap.manifest.name, params, max_attempts=1)
                job = rt.queue.enqueue_job(cap.manifest.name, params, max_retries=1, execution_token=token,
                                           idempotency_key="sbx-fail-idemp")
                receipt = rt.worker_daemon.drain_once(worker_id="worker_sbx", target_job_id=job)
                self.assertIsNotNone(receipt)
                self.assertEqual(receipt.exit_code, 42)
                self.assertTrue(receipt.verify(rt.trust_registry)[0])

                dep = DependencyHealthEvidence(capability_name=cap.manifest.name, status=DependencyCheckResult.PASS,
                    checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
                    environment_fingerprint=generate_environment_fingerprint())
                profiles, checkpoint = rt.capability_ledger.compile_empirical_ledger(
                    dependency_evidence_map={cap.manifest.name: dep})
                p = profiles[cap.manifest.name]
                self.assertEqual(p.current_version_attempts, 1)
                self.assertEqual(p.current_version_clean_successes, 0)
                self.assertEqual(p.current_version_defect_failures, 1)
                self.assertEqual(p.health_status.value, "FAILING")
                self.assertTrue(checkpoint.is_complete)
                self.assertEqual(checkpoint.conflicting_receipts_count, 0)
            finally:
                rt.shutdown()

    def test_real_promoted_evolution_success_establishes_verified_active(self):
        """Real promoted evolution execution in sandbox establishes VERIFIED_ACTIVE in ledger."""
        from phase8_test_support import Phase8Case
        from ciph.evolution.workflow import EvolutionCoordinator

        t = Phase8Case()
        t.setUp()
        try:
            service = EvolutionCoordinator(t.runtime, t.staging)
            grant = t.deployment()
            ok, message, cid = service.deploy(grant)
            self.assertTrue(ok, message)
            self.assertEqual(service.run_canary(cid, {"x": 2, "y": 3})["status"], "ACTIVE")
            self.assertEqual(service.run_canary(cid, {"x": 2, "y": 3})["status"], "PROMOTED")

            receipt = t.runtime.route_and_execute("math.compute", {"x": 8, "y": 5})
            self.assertEqual(receipt.exit_code, 0)
            self.assertEqual(receipt.results["result"], 13)
            self.assertTrue(receipt.verify(t.runtime.trust_registry)[0])

            dep = DependencyHealthEvidence(capability_name="math.compute", status=DependencyCheckResult.PASS,
                checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
                environment_fingerprint=generate_environment_fingerprint())
            profiles, checkpoint = t.runtime.capability_ledger.compile_empirical_ledger(
                dependency_evidence_map={"math.compute": dep})
            p = profiles["math.compute"]
            self.assertEqual(p.current_version_attempts, 1)
            self.assertEqual(p.current_version_clean_successes, 1)
            self.assertEqual(p.current_version_defect_failures, 0)
            self.assertEqual(p.health_status.value, "VERIFIED_ACTIVE")
            self.assertTrue(checkpoint.is_complete)
            self.assertEqual(checkpoint.conflicting_receipts_count, 0)
        finally:
            t.tearDown()

    def test_sandbox_retry_following_authenticated_failure_credits_both_attempts(self):
        """A sandboxed capability failing attempt 1 and retrying successfully on attempt 2 credits both attempts."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier
        import sys

        class FlakySandbox(BaseCapability):
            requires_sandbox = True
            def __init__(self):
                super().__init__()
                self.calls = 0
            @property
            def manifest(self):
                return CapabilityManifest(name="test.sandbox.retry", description="Flaky sandbox",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO)
            def get_sandbox_command(self, params):
                self.calls += 1
                exit_code = 42 if self.calls == 1 else 0
                return [sys.executable, "-c", f"import json, sys; print(json.dumps({{'attempt': {self.calls}}})); sys.exit({exit_code})"]
            def run(self, params, context=None):
                raise AssertionError("Must run in sandbox")

        with tempfile.TemporaryDirectory(prefix="review6-sbx-retry-") as td:
            rt = CiphRuntime(db_path=str(Path(td) / "jobs.db"))
            try:
                cap = FlakySandbox()
                rt.register_capability(cap)
                params = {"val": 10}
                token = rt.mint_execution_token(cap.manifest.name, params, max_attempts=3)
                job_id = rt.queue.enqueue_job(cap.manifest.name, params, max_retries=3, execution_token=token,
                                              idempotency_key="sbx-retry-idemp")
                # Attempt 1 -> fails with exit 42
                r1 = rt.worker_daemon.drain_once(worker_id="worker_sbx", target_job_id=job_id)
                self.assertIsNotNone(r1)
                self.assertEqual(r1.exit_code, 42)
                # Attempt 2 (retry) -> succeeds with exit 0
                r2 = rt.worker_daemon.drain_once(worker_id="worker_sbx", target_job_id=job_id)
                self.assertIsNotNone(r2)
                self.assertEqual(r2.exit_code, 0)
                self.assertNotEqual(r1.provenance["execution_token_hash"], r2.provenance["execution_token_hash"])

                dep = DependencyHealthEvidence(capability_name=cap.manifest.name, status=DependencyCheckResult.PASS,
                    checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
                    environment_fingerprint=generate_environment_fingerprint())
                profiles, checkpoint = rt.capability_ledger.compile_empirical_ledger(
                    dependency_evidence_map={cap.manifest.name: dep})
                p = profiles[cap.manifest.name]
                self.assertEqual(p.current_version_attempts, 2)
                self.assertEqual(p.current_version_clean_successes, 1)
                self.assertEqual(p.current_version_defect_failures, 1)
                self.assertEqual(p.health_status.value, "INCONCLUSIVE_SAMPLE")
                self.assertTrue(checkpoint.is_complete)
                self.assertEqual(checkpoint.conflicting_receipts_count, 0)
            finally:
                rt.shutdown()



class TestReview7IdempotencyKeyConsistency(unittest.TestCase):
    """Review 7 regressions: Omitted optional idempotency keys must be preserved across jobs, activations, and receipts."""

    def test_sandbox_success_with_omitted_idempotency_key(self):
        """Sandbox execution without idempotency_key preserves None and earns VERIFIED_ACTIVE."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier
        import sys

        class Sbx(BaseCapability):
            requires_sandbox = True
            @property
            def manifest(self):
                return CapabilityManifest(name="test.sbx.noidemp", description="Omitted key test",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO)
            def get_sandbox_command(self, params):
                return [sys.executable, "-c", "import json, sys; print(json.dumps({'res': 1})); sys.exit(0)"]
            def run(self, params, context=None):
                raise AssertionError("Must run in sandbox")

        with tempfile.TemporaryDirectory(prefix="review7-sbx-succ-") as td:
            rt = CiphRuntime(db_path=str(Path(td) / "jobs.db"))
            try:
                cap = Sbx()
                rt.register_capability(cap)
                params = {"x": 1}
                token = rt.mint_execution_token(cap.manifest.name, params, max_attempts=1)
                job = rt.queue.enqueue_job(cap.manifest.name, params, max_retries=1, execution_token=token)
                receipt = rt.worker_daemon.drain_once(worker_id="worker_sbx", target_job_id=job)
                self.assertIsNotNone(receipt)
                self.assertIsNone(receipt.idempotency_key)
                self.assertEqual(receipt.exit_code, 0)
                self.assertTrue(receipt.verify(rt.trust_registry)[0])

                dep = DependencyHealthEvidence(capability_name=cap.manifest.name, status=DependencyCheckResult.PASS,
                    checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
                    environment_fingerprint=generate_environment_fingerprint())
                profiles, checkpoint = rt.capability_ledger.compile_empirical_ledger(
                    dependency_evidence_map={cap.manifest.name: dep})
                p = profiles[cap.manifest.name]
                self.assertEqual(p.current_version_attempts, 1)
                self.assertEqual(p.current_version_clean_successes, 1)
                self.assertEqual(p.health_status.value, "VERIFIED_ACTIVE")
                self.assertEqual(checkpoint.conflicting_receipts_count, 0)
            finally:
                rt.shutdown()

    def test_sandbox_failure_and_retry_with_omitted_idempotency_key(self):
        """Sandbox retry with omitted idempotency_key credits both attempts."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier
        import sys

        class FlakySbx(BaseCapability):
            requires_sandbox = True
            def __init__(self):
                super().__init__()
                self.calls = 0
            @property
            def manifest(self):
                return CapabilityManifest(name="test.sbx.flaky.noidemp", description="Omitted key retry",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO)
            def get_sandbox_command(self, params):
                self.calls += 1
                return [sys.executable, "-c", f"import json, sys; print(json.dumps({{'c': {self.calls}}})); sys.exit({42 if self.calls == 1 else 0})"]
            def run(self, params, context=None):
                raise AssertionError("Must run in sandbox")

        with tempfile.TemporaryDirectory(prefix="review7-sbx-retry-") as td:
            rt = CiphRuntime(db_path=str(Path(td) / "jobs.db"))
            try:
                cap = FlakySbx()
                rt.register_capability(cap)
                params = {"x": 1}
                token = rt.mint_execution_token(cap.manifest.name, params, max_attempts=2)
                job = rt.queue.enqueue_job(cap.manifest.name, params, max_retries=2, execution_token=token)
                r1 = rt.worker_daemon.drain_once(worker_id="worker_sbx", target_job_id=job)
                self.assertIsNotNone(r1)
                self.assertIsNone(r1.idempotency_key)
                self.assertEqual(r1.exit_code, 42)
                r2 = rt.worker_daemon.drain_once(worker_id="worker_sbx", target_job_id=job)
                self.assertIsNotNone(r2)
                self.assertIsNone(r2.idempotency_key)
                self.assertEqual(r2.exit_code, 0)

                dep = DependencyHealthEvidence(capability_name=cap.manifest.name, status=DependencyCheckResult.PASS,
                    checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
                    environment_fingerprint=generate_environment_fingerprint())
                profiles, checkpoint = rt.capability_ledger.compile_empirical_ledger(
                    dependency_evidence_map={cap.manifest.name: dep})
                p = profiles[cap.manifest.name]
                self.assertEqual(p.current_version_attempts, 2)
                self.assertEqual(p.current_version_clean_successes, 1)
                self.assertEqual(p.current_version_defect_failures, 1)
                self.assertEqual(p.health_status.value, "INCONCLUSIVE_SAMPLE")
                self.assertEqual(checkpoint.conflicting_receipts_count, 0)
            finally:
                rt.shutdown()

    def test_promoted_evolution_with_omitted_idempotency_key(self):
        """Promoted evolution execution without idempotency_key preserves None and earns VERIFIED_ACTIVE."""
        from phase8_test_support import Phase8Case
        from ciph.evolution.workflow import EvolutionCoordinator

        t = Phase8Case()
        t.setUp()
        try:
            service = EvolutionCoordinator(t.runtime, t.staging)
            grant = t.deployment()
            ok, message, cid = service.deploy(grant)
            self.assertTrue(ok, message)
            self.assertEqual(service.run_canary(cid, {"x": 2, "y": 3})["status"], "ACTIVE")
            self.assertEqual(service.run_canary(cid, {"x": 2, "y": 3})["status"], "PROMOTED")

            params = {"x": 10, "y": 20}
            token = t.runtime.mint_execution_token("math.compute", params, max_attempts=1)
            job = t.runtime.queue.enqueue_job("math.compute", params, execution_token=token)
            receipt = t.runtime.worker_daemon.drain_once(worker_id="worker_evo", target_job_id=job)
            self.assertIsNotNone(receipt)
            self.assertIsNone(receipt.idempotency_key)
            self.assertEqual(receipt.exit_code, 0)
            self.assertEqual(receipt.results["result"], 30)
            self.assertTrue(receipt.verify(t.runtime.trust_registry)[0])

            dep = DependencyHealthEvidence(capability_name="math.compute", status=DependencyCheckResult.PASS,
                checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
                environment_fingerprint=generate_environment_fingerprint())
            profiles, checkpoint = t.runtime.capability_ledger.compile_empirical_ledger(
                dependency_evidence_map={"math.compute": dep})
            p = profiles["math.compute"]
            self.assertEqual(p.current_version_attempts, 1)
            self.assertEqual(p.current_version_clean_successes, 1)
            self.assertEqual(p.health_status.value, "VERIFIED_ACTIVE")
            self.assertEqual(checkpoint.conflicting_receipts_count, 0)
        finally:
            t.tearDown()

    def test_idempotency_key_mismatch_between_activation_and_receipt_is_rejected(self):
        """A receipt whose idempotency_key does not match the signed activation row is rejected as HISTORICAL_UNBOUND."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier
        from dataclasses import replace

        class MismatchCap(BaseCapability):
            @property
            def manifest(self):
                return CapabilityManifest(name="test.idemp.mismatch", description="Mismatch test",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO)
            def run(self, params, context=None):
                return {"ok": True}
            def execute(self, params, context=None):
                r = super().execute(params, context=context)
                return replace(r, idempotency_key="mismatched-key")

        with tempfile.TemporaryDirectory(prefix="review7-mismatch-") as td:
            rt = CiphRuntime(db_path=str(Path(td) / "jobs.db"))
            try:
                cap = MismatchCap()
                rt.register_capability(cap)
                params = {"x": 1}
                token = rt.mint_execution_token(cap.manifest.name, params, max_attempts=1)
                job = rt.queue.enqueue_job(cap.manifest.name, params, execution_token=token, idempotency_key="expected-idemp")
                receipt = rt.worker_daemon.drain_once(worker_id="worker_local", target_job_id=job)
                self.assertIsNotNone(receipt)
                self.assertEqual(receipt.idempotency_key, "mismatched-key")

                dep = DependencyHealthEvidence(capability_name=cap.manifest.name, status=DependencyCheckResult.PASS,
                    checked_at=time.time(), source="TEST", declared_modules=(), missing_modules=(),
                    environment_fingerprint=generate_environment_fingerprint())
                profiles, checkpoint = rt.capability_ledger.compile_empirical_ledger(
                    dependency_evidence_map={cap.manifest.name: dep})
                p = profiles[cap.manifest.name]
                self.assertEqual(p.current_version_attempts, 0)
                self.assertNotEqual(p.health_status.value, "VERIFIED_ACTIVE")
            finally:
                rt.shutdown()

    def test_omitted_idempotency_key_ingress_rejects_divergent_key(self):
        """Queue ingress rejects a receipt carrying an idempotency key when the job had None."""
        from ciph.runtime import CiphRuntime
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier

        class OmittedCap(BaseCapability):
            @property
            def manifest(self):
                return CapabilityManifest(name="test.idemp.omitted.ingress", description="Omitted ingress test",
                    risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO)
            def run(self, params, context=None):
                return {"ok": True}

        with tempfile.TemporaryDirectory(prefix="review7-ingress-") as td:
            rt = CiphRuntime(db_path=str(Path(td) / "jobs.db"))
            try:
                cap = OmittedCap()
                rt.register_capability(cap)
                params = {"x": 1}
                token = rt.mint_execution_token(cap.manifest.name, params, max_attempts=1)
                job_id = rt.queue.enqueue_job(cap.manifest.name, params, execution_token=token, idempotency_key=None)

                worker_id = "worker_local"
                leased = rt.queue.lease_next_job(worker_id=worker_id, target_job_id=job_id)
                self.assertIsNotNone(leased)

                now = time.time()
                from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory
                secret_key = rt.worker_daemon.worker_secret_key
                key_id = rt.worker_daemon.worker_key_id

                bad_receipt = ExecutionReceipt(
                    receipt_id="rcpt_bad_idemp",
                    job_id=job_id,
                    capability=cap.manifest.name,
                    target=None,
                    started_at=now - 0.1,
                    completed_at=now,
                    input_hash=ExecutionReceipt.hash_payload(params),
                    output_hash=ExecutionReceipt.hash_payload({"ok": True}),
                    exit_code=0,
                    outcome=OutcomeCategory.SUCCESS,
                    results={"ok": True},
                    side_effects=[],
                    idempotency_key="injected-divergent-key",
                    attempt_number=1,
                    requested_network_policy=cap.manifest.network_policy,
                    actual_transport_used="LOCAL_SOCKET",
                    worker_id=worker_id,
                    worker_key_id=key_id,
                    provenance={
                        "execution_token_hash": ExecutionReceipt.hash_payload(token.to_dict()),
                        "manifest_version": cap.manifest.version,
                        "manifest_hash": cap.manifest.compute_manifest_hash(),
                    },
                ).sign(secret_key, worker_key_id=key_id)

                committed = rt.queue.complete_job_and_append_receipt_event(
                    job_id=job_id,
                    worker_id=worker_id,
                    receipt_dict=bad_receipt.to_dict()
                )
                self.assertEqual(committed, 0, "Ingress must fail closed when receipt has key but job had None")

                good_receipt = ExecutionReceipt(
                    receipt_id="rcpt_good_idemp",
                    job_id=job_id,
                    capability=cap.manifest.name,
                    target=None,
                    started_at=now - 0.1,
                    completed_at=now,
                    input_hash=ExecutionReceipt.hash_payload(params),
                    output_hash=ExecutionReceipt.hash_payload({"ok": True}),
                    exit_code=0,
                    outcome=OutcomeCategory.SUCCESS,
                    results={"ok": True},
                    side_effects=[],
                    idempotency_key=None,
                    attempt_number=1,
                    requested_network_policy=cap.manifest.network_policy,
                    actual_transport_used="LOCAL_SOCKET",
                    worker_id=worker_id,
                    worker_key_id=key_id,
                    provenance={
                        "execution_token_hash": ExecutionReceipt.hash_payload(token.to_dict()),
                        "manifest_version": cap.manifest.version,
                        "manifest_hash": cap.manifest.compute_manifest_hash(),
                    },
                ).sign(secret_key, worker_key_id=key_id)
                committed_good = rt.queue.complete_job_and_append_receipt_event(
                    job_id=job_id,
                    worker_id=worker_id,
                    receipt_dict=good_receipt.to_dict()
                )
                self.assertEqual(committed_good, 1, "Ingress must succeed when both job and receipt have None")
            finally:
                rt.shutdown()

    def test_preactivation_denial_with_omitted_idempotency_key_commits_receipt(self):
        """Pre-activation denial on an omitted-key job transitions out of LEASED and commits denial receipt."""
        from ciph.runtime import CiphRuntime
        with tempfile.TemporaryDirectory(prefix="review7-denial-") as td:
            rt = CiphRuntime(db_path=str(Path(td) / "jobs.db"))
            try:
                # Enqueue a job for an unregistered capability with idempotency_key=None
                job_id = rt.queue.enqueue_job(
                    capability="unregistered.test.capability",
                    params={"a": 1},
                    idempotency_key=None
                )

                # Daemon drains the job: it hits the pre-activation denial (unregistered capability)
                receipt = rt.worker_daemon.drain_once(worker_id="worker_local", target_job_id=job_id)
                self.assertIsNone(receipt)  # drain_once returns None on unregistered capability denial

                # The job must have transitioned out of LEASED into FAILED
                job_row = rt.queue.get_job(job_id)
                self.assertIsNotNone(job_row)
                self.assertNotEqual(job_row["status"], "LEASED", "Job must not remain stuck in LEASED")
                self.assertEqual(job_row["status"], "FAILED", "Unregistered capability denial must transition job to FAILED")
                self.assertIsNotNone(job_row["receipt_id"], "Denial receipt_id must be recorded on job")

                # Denial event must be committed to the event store
                events = rt.event_store.get_events(aggregate_id=job_row["receipt_id"])
                self.assertTrue(len(events) > 0, "ExecutionReceiptStoredEvent must be committed for pre-activation denial")
                self.assertEqual(events[0]["event_type"], "ExecutionReceiptStoredEvent")
                self.assertIsNone(events[0]["payload"].get("idempotency_key"), "Event payload must preserve idempotency_key=None")
            finally:
                rt.shutdown()


if __name__ == '__main__': unittest.main()
