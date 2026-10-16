"""Phase 3 authority, durable evidence, concurrency and real process-crash regressions.

MIGRATED TO THE S3 CONSTITUTION.

Every governed fixture here goes through the SAME canonical pipeline production uses
(`permit_test_support.enqueue_permit_bearing_job`), because a fixture may bypass product UX but may
not bypass the execution constitution. The scenarios were kept; where the new retry law genuinely
changed the correct outcome, the expectation changed with it rather than the law being bent:

    authority never spent (permit ISSUED)
        -> operational redelivery: same permit, same generation, no execution retry budget

    authority spent (permit CLAIMED) with no independent retry-safety proof
        -> RECONCILIATION_REQUIRED, non-runnable, NO next generation

    authority spent with an explicit retry-safety proof
        -> NEXT_GENERATION: fresh single-use permit, same logical action, transport renewed

    retry budget exhausted
        -> TERMINAL, no further authority
"""
import concurrent.futures
from ciph.kernel.policy_engine import ScopeGrant
from ciph.contracts.enums import ReplaySemantics, ScopeType
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from ciph.runtime import CiphRuntime
from ciph.kernel.crypto_identity import ExecutionToken, mint_attempt_token
from ciph.kernel.execution_authority import SignedExecutionPermit
from ciph.kernel.network_sandbox import enforce_network_policy, NetworkPolicyViolation
from ciph.kernel.policy_engine import NetworkPolicy, ReversibilityClass
from ciph.memory.event_store import EventStore
from ciph.planner.schemas import IntentProposal
from ciph.workers.daemon import DurableWorkerDaemon
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory
from permit_test_support import enqueue_permit_bearing_job, central_retry_disposition
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability


class TestPhase3AdversarialRecovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-phase3-regression-')
        self.db = str(Path(self.temp.name) / 'jobs.db')
        self.runtime = CiphRuntime(db_path=self.db)
        self.queue = self.runtime.queue
        self.worker = self.runtime.worker_daemon
        self.cap = SimpleComputeCapability(name='review.compute')
        self.runtime.register_capability(self.cap)
        self.params = {'value': 1}

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def enqueue(self, cap=None, params=None, attempts=3, token=None, plan_id=None, step_id=None):
        """Enqueue through the canonical permit pipeline (transport token included)."""
        cap = cap or self.cap
        params = self.params if params is None else params
        fixture = enqueue_permit_bearing_job(
            self.runtime,
            capability=cap.manifest.name,
            params=params,
            execution_token=token,
            plan_id=plan_id,
            step_id=step_id,
            max_retries=attempts,
        )
        return fixture.job_id, (token if token is not None else fixture.execution_token)

    def idempotent_cap(self, name='review.compute_idempotent', **kwargs):
        """A capability that DECLARES its effect is identified by the action.

        Retry safety is never a test flag now: it is this declaration, and the central transition
        re-validates it against the exact attempt's attested manifest identity.
        """
        class IdempotentCompute(SimpleComputeCapability):
            @property
            def manifest(self):
                return replace(super().manifest, replay_semantics=ReplaySemantics.IDEMPOTENT)
        cap = IdempotentCompute(name, **kwargs)
        self.runtime.register_capability(cap)
        return cap

    def carried_permit(self, job_id):
        """The canonical permit artifact the durable row currently carries."""
        raw = self.queue.get_job(job_id)['execution_permit']
        return SignedExecutionPermit.from_dict(json.loads(raw) if isinstance(raw, str) else raw)

    def execute(self, job_id, worker='review_worker', ttl=30):
        job = self.queue.lease_next_job(worker, ttl, target_job_id=job_id)
        return self.worker._execute_leased_job(job, worker) if job else None

    def wait_for(self, condition, timeout=5):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if condition():
                return
            time.sleep(.01)
        self.fail('Timed out waiting for the expected state')

    def restarted_daemon(self):
        """A daemon built the way production builds one: bound to the ONE disposition engine."""
        return DurableWorkerDaemon(
            queue=self.queue,
            registry=self.runtime.registry,
            event_store=self.runtime.event_store,
            db_path=self.db,
            trust_registry=self.runtime.trust_registry,
            worker_secret_key=self.runtime.worker_secret_key,
            worker_key_id=self.runtime.worker_key_id,
            retry_disposition=self.runtime.retry_disposition,
        )

    # ------------------------------------------------------------------ transport & signing gates
    def test_tampered_retry_parent_is_never_resigned(self):
        jid, token = self.enqueue()
        self.queue.lease_next_job('dead', .01, target_job_id=jid)
        time.sleep(.03)
        self.queue.reclaim_expired_leases()
        changed = token.to_dict()
        changed['parameters_hash'] = ExecutionReceipt.hash_payload({'value': 999})
        with sqlite3.connect(self.db) as conn:
            conn.execute('UPDATE ciph_ipc_jobs SET params = ?, execution_token = ? WHERE job_id = ?',
                         (json.dumps({'value': 999}), json.dumps(changed), jid))
        receipt = self.execute(jid)
        self.assertEqual(receipt.outcome, OutcomeCategory.POLICY_BLOCKED)
        self.assertEqual(self.cap.execution_count, 0)
        self.assertFalse(ExecutionToken.from_dict(json.loads(self.queue.get_job(jid)['execution_token'])).verify(self.runtime.trust_registry)[0])

    def test_public_retry_signer_requires_coordinator_authority(self):
        _, token = self.enqueue()
        for base in (token, replace(token, parameters_hash='tampered')):
            with self.subTest(tampered=base is not token), self.assertRaises(PermissionError):
                mint_attempt_token(base, trust_registry=self.runtime.trust_registry)
        with self.assertRaises(PermissionError):
            mint_attempt_token(replace(token, parameters_hash='tampered'), self.runtime.kernel_priv_bytes,
                               self.runtime.trust_registry, job_id='forged', attempt_number=2)

    def test_consumed_token_cannot_be_renewed_for_other_jobs(self):
        plan_id, step_id = 'plan_replay_p3', 'step_replay_p3'
        token = self.runtime.mint_execution_token(
            self.cap.manifest.name, self.params, plan_id=plan_id, step_id=step_id, max_attempts=2)
        first, _ = self.enqueue(attempts=2, token=token, plan_id=plan_id, step_id=step_id)
        self.assertEqual(self.execute(first).exit_code, 0)
        for _ in range(3):
            other, _ = self.enqueue(attempts=2, token=token, plan_id=plan_id, step_id=step_id)
            self.assertEqual(self.execute(other).outcome, OutcomeCategory.POLICY_BLOCKED)
            self.assertIsNone(self.execute(other))
        self.assertEqual(self.cap.execution_count, 1)

    def test_retired_kernel_cannot_issue_new_attempt_authority(self):
        jid, token = self.enqueue()
        with sqlite3.connect(self.db) as conn:
            conn.execute('UPDATE ciph_trust_registry SET valid_until = ? WHERE key_id = ?',
                         (time.time() - .001, token.kernel_key_id))
        with self.assertRaises(PermissionError):
            mint_attempt_token(token, self.runtime.kernel_priv_bytes, self.runtime.trust_registry,
                               job_id=jid, attempt_number=2)

    # ------------------------------------------------------------------ the retry law, end to end
    def test_claimed_failure_without_retry_safety_reconciles_and_survives_restart(self):
        """A claimed failure is NOT retried: no independent retry-safety proof exists, so the
        logical action reconciles and a daemon restart must not resurrect its authority."""
        self.cap.should_fail = True
        jid, _ = self.enqueue(attempts=3)
        receipt = self.execute(jid)
        self.assertNotEqual(receipt.exit_code, 0)
        self.assertEqual(self.queue.get_job(jid)['status'], 'RECONCILIATION_REQUIRED')
        self.assertEqual(self.cap.execution_count, 1)

        self.worker = self.restarted_daemon()
        self.assertIsNone(self.execute(jid))
        self.assertEqual(self.cap.execution_count, 1)
        # The permit is spent and stays spent; no successor generation was minted.
        permit = self.carried_permit(jid)
        self.assertEqual(int(permit.payload.authorization_generation or 0), 0)
        with sqlite3.connect(self.db) as conn:
            generations = [row[0] for row in conn.execute(
                'SELECT authorization_generation FROM execution_permits WHERE logical_action_id = ?',
                (permit.payload.logical_action_id,)).fetchall()]
        self.assertEqual(sorted(generations), [0])
        self.assertTrue(self.runtime.event_store.verify_integrity()[0])

    def test_next_generation_is_bound_to_the_original_logical_action(self):
        """A declared-safe claimed failure is retried by the CENTRAL path, not by the worker.

        The capability's replay declaration is the only input: no caller states a verdict, and no
        worker flag exists. The disposition installs exactly one fresh generation, bound to the same
        logical action.
        """
        cap = self.idempotent_cap(should_fail=True)
        jid, _ = self.enqueue(cap=cap, attempts=3)
        permit0 = self.carried_permit(jid)

        first = self.execute(jid)
        self.assertNotEqual(first.exit_code, 0)

        # The disposition already advanced the generation during that failure.
        self.assertEqual(self.queue.get_job(jid)['status'], 'RETRYING')
        permit1 = self.carried_permit(jid)
        self.assertEqual(permit1.payload.logical_action_id, permit0.payload.logical_action_id)
        self.assertNotEqual(permit1.payload.permit_id, permit0.payload.permit_id)
        self.assertNotEqual(permit1.permit_digest(), permit0.permit_digest())
        self.assertEqual(int(permit1.payload.authorization_generation or 0), 1)
        self.assertEqual(permit1.payload.action_fingerprint, permit0.payload.action_fingerprint)
        self.assertEqual(permit1.payload.capability_id, permit0.payload.capability_id)

        # The failure receipt is still canonical evidence, recorded once.
        self.assertEqual(len(self.runtime.event_store.get_events(aggregate_id=first.receipt_id)), 1)

        # An unrelated logical action is untouched by this retry.
        other, _ = self.enqueue(attempts=3)
        self.assertNotEqual(self.carried_permit(other).payload.logical_action_id,
                            permit1.payload.logical_action_id)

        # The renewed authority is actually spendable: transport was renewed with it.
        cap.should_fail = False
        self.assertEqual(self.execute(jid).exit_code, 0)
        self.assertEqual(cap.execution_count, 2)
        self.assertEqual(self.queue.get_job(jid)['status'], 'SUCCEEDED')

    def test_central_retry_is_refused_without_a_capability_declaration(self):
        """The same failure, the same call, no declaration: uncertainty must reconcile."""
        self.cap.should_fail = True
        jid, _ = self.enqueue(attempts=3)
        permit0 = self.carried_permit(jid)
        self.execute(jid)

        # The automatic disposition already reconciled it; repeating the call changes nothing,
        # which is the idempotence a duplicate report must have.
        self.assertEqual(self.queue.get_job(jid)['status'], 'RECONCILIATION_REQUIRED')
        result = self.runtime.retry_disposition(
            job_id=jid, expected_permit_id=permit0.payload.permit_id,
        )

        self.assertEqual(result.outcome, 'RECONCILIATION_REQUIRED')
        self.assertIsNone(result.permit_id)
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM execution_permits WHERE authorization_generation > 0'
            ).fetchone()[0], 0)

    def test_stale_retry_report_never_advances_twice(self):
        """A duplicate report naming generation N must not mint N+2 after N+1 is installed."""
        cap = self.idempotent_cap(should_fail=True, name='review.compute_stale')
        jid, _ = self.enqueue(cap=cap, attempts=3)
        permit0 = self.carried_permit(jid)
        self.execute(jid)  # automatic: P0 -> P1
        permit1 = self.carried_permit(jid)
        self.assertEqual(int(permit1.payload.authorization_generation or 0), 1)

        stale = self.runtime.retry_disposition(
            job_id=jid, expected_permit_id=permit0.payload.permit_id,
        )
        self.assertFalse(stale.applied)
        self.assertEqual(stale.reason, 'STALE_CORRELATION')
        self.assertEqual(self.carried_permit(jid).payload.permit_id, permit1.payload.permit_id)
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM execution_permits WHERE authorization_generation > 1'
            ).fetchone()[0], 0, "a duplicate report must never mint N+2")

    def test_retry_budget_exhaustion_terminates_the_logical_action(self):
        """`max_retries` is the total EXECUTED-attempt budget, so one attempt means no retry.

        The budget is derived from the job row and the authorization generation - never reported by
        the worker - so a declared-safe capability still cannot exceed it.
        """
        cap = self.idempotent_cap(should_fail=True, name='review.compute_budget')
        jid, _ = self.enqueue(cap=cap, attempts=1)
        permit0 = self.carried_permit(jid)
        self.execute(jid)
        self.assertEqual(self.queue.get_job(jid)['status'], 'FAILED')
        self.assertIsNone(self.execute(jid))
        self.assertEqual(cap.execution_count, 1)
        with sqlite3.connect(self.db) as conn:
            generations = [row[0] for row in conn.execute(
                'SELECT authorization_generation FROM execution_permits WHERE logical_action_id = ?',
                (permit0.payload.logical_action_id,)).fetchall()]
        self.assertEqual(sorted(generations), [0])

    def test_lost_lease_before_claim_redelivers_the_same_permit(self):
        """A delivery retry is not an execution retry: authority was never spent."""
        jid, token = self.enqueue(attempts=3)
        permit0 = self.carried_permit(jid)
        self.queue.lease_next_job('dead', .01, target_job_id=jid)
        time.sleep(.03)
        self.queue.reclaim_expired_leases()

        job = self.queue.get_job(jid)
        self.assertEqual(job['status'], 'RETRYING')
        permit1 = self.carried_permit(jid)
        self.assertEqual(permit1.payload.permit_id, permit0.payload.permit_id)
        self.assertEqual(permit1.permit_digest(), permit0.permit_digest())
        self.assertEqual(int(permit1.payload.authorization_generation or 0), 0)
        # The transport artifact is untouched because it was never consumed - no renewal needed.
        self.assertEqual(ExecutionToken.from_dict(json.loads(job['execution_token'])).to_dict(),
                         token.to_dict())
        with sqlite3.connect(self.db) as conn:
            generations = [row[0] for row in conn.execute(
                'SELECT authorization_generation FROM execution_permits WHERE logical_action_id = ?',
                (permit0.payload.logical_action_id,)).fetchall()]
        self.assertEqual(sorted(generations), [0])

        self.assertEqual(self.execute(jid).exit_code, 0)
        self.assertEqual(self.cap.execution_count, 1)

    def test_missing_canonical_permit_lineage_fails_closed(self):
        """No canonical permit row -> authorize refuses before the body runs."""
        jid, _ = self.enqueue()
        with sqlite3.connect(self.db) as conn:
            conn.execute('DELETE FROM execution_permits')
        receipt = self.execute(jid)
        # Fail closed: the attempt is refused before the body runs, and no successor authority is
        # minted from a lineage that does not exist.
        self.assertNotEqual(receipt.exit_code, 0)
        self.assertEqual(self.cap.execution_count, 0)
        self.assertIsNone(self.execute(jid))
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM execution_permits WHERE authorization_generation > 0').fetchone()[0], 0)

    def test_transport_and_authority_domains_never_fuse(self):
        """The retry renews a PERMIT and a TRANSPORT TOKEN for different reasons.

        Each case gets its own logical action, so the three combinations cannot contaminate each
        other: (P1,T0) must be refused by the TRANSPORT domain, (P0,T1) by the AUTHORITY domain, and
        only (P1,T1) may execute.
        """
        cap = self.idempotent_cap(should_fail=True, name='review.compute_domains')
        before = cap.execution_count

        def generation_one_of_one_job():
            # This logical action's FIRST attempt must fail, so the disposition retries it and
            # renews BOTH artifacts. The body then succeeds for the substitution cases below.
            cap.should_fail = True
            jid, token0 = self.enqueue(cap=cap, attempts=3)
            permit0 = self.carried_permit(jid)
            self.execute(jid)
            cap.should_fail = False
            self.assertEqual(self.queue.get_job(jid)['status'], 'RETRYING')
            permit1 = self.carried_permit(jid)
            token1 = ExecutionToken.from_dict(json.loads(self.queue.get_job(jid)['execution_token']))
            self.assertEqual(int(permit1.payload.authorization_generation or 0), 1)
            self.assertNotEqual(permit1.payload.permit_id, permit0.payload.permit_id)
            self.assertNotEqual(token1.token_id, token0.token_id)
            return jid, token0, permit0, permit1, token1

        def requeue(jid, permit, token):
            with sqlite3.connect(self.db) as conn:
                conn.execute(
                    'UPDATE ciph_ipc_jobs SET status = ?, leased_to = NULL, lease_expires_at = NULL, '
                    'execution_permit = ?, execution_token = ? WHERE job_id = ?',
                    ('QUEUED', json.dumps(permit.to_dict(), sort_keys=True),
                     json.dumps(token.to_dict()), jid))

        cap.should_fail = False

        # old transport + new authority -> the TRANSPORT domain refuses
        jid, token0, _p0, permit1, _t1 = generation_one_of_one_job()
        requeue(jid, permit1, token0)
        refused = self.execute(jid)
        self.assertNotEqual(refused.exit_code, 0)
        self.assertEqual(cap.execution_count, before + 1,
                         "the body must not run without its own transport")

        # new transport + old (already claimed) authority -> the AUTHORITY domain refuses
        jid, _t0, permit0, _p1, token1 = generation_one_of_one_job()
        requeue(jid, permit0, token1)
        refused = self.execute(jid)
        self.assertNotEqual(refused.exit_code, 0)
        self.assertIn('CLAIMED', str(refused.error_message) + str(refused.results))
        self.assertEqual(cap.execution_count, before + 2,
                         "authority may not be re-spent by a fresh session")

        # the coherent pair is the only combination that executes
        jid, _t0, _p0, permit1, token1 = generation_one_of_one_job()
        requeue(jid, permit1, token1)
        self.assertEqual(self.execute(jid).exit_code, 0)
        self.assertEqual(cap.execution_count, before + 4)

    # ------------------------------------------------------------------ durable evidence gates
    def capture_execution(self, jid):
        captured = []
        def reject(**kwargs):
            captured.append(kwargs['receipt_dict'])
            raise sqlite3.OperationalError('injected completion failure')
        with patch.object(self.queue, 'complete_job_and_append_receipt_event', side_effect=reject):
            receipt = self.execute(jid)
        return receipt, captured[0]

    def test_store_failure_preserves_full_signed_evidence_without_success(self):
        jid, _ = self.enqueue()
        denied, original = self.capture_execution(jid)
        self.assertNotEqual(denied.exit_code, 0)
        self.assertEqual(self.worker.get_pool_status()['total_processed'], 0)
        self.assertEqual(self.queue.get_job(jid)['status'], 'RECONCILIATION_REQUIRED')
        self.assertIsNone(self.execute(jid))
        event = self.runtime.event_store.get_events(aggregate_id=jid)[0]
        self.assertEqual(event['payload']['receipt'], original)
        self.assertTrue(ExecutionReceipt.from_dict(event['payload']['receipt']).verify(self.runtime.trust_registry)[0])
        with sqlite3.connect(self.db) as conn:
            pending = conn.execute('SELECT pending_receipt FROM ciph_ipc_jobs WHERE job_id = ?', (jid,)).fetchone()[0]
        self.assertEqual(json.loads(pending), original)
        self.assertTrue(self.runtime.event_store.verify_integrity()[0])

    def test_reference_loop_never_publishes_uncommitted_success(self):
        proposal = IntentProposal(proposal_id='storage_failure', objective='read memory',
            proposed_capability='memory.retrieve', provided_parameters={'key': 'x', 'target': 'local_memory'})
        with patch.object(self.queue, 'complete_job_and_append_receipt_event', side_effect=sqlite3.OperationalError('disk error')):
            # The loop is target-bearing: the caller must present the authority it assumes.
            result = self.runtime.execute_reference_loop(
                proposal,
                scope_grant=ScopeGrant(
                    scope_id="scope_phase3_recovery",
                    scope_type=ScopeType.LOCAL_SYSTEM,
                    allowed_targets=["local_memory"],
                ).sign(self.runtime.kernel_priv_bytes, signing_key_id=self.runtime.kernel_key_id),
            )
        self.assertEqual(result['status'], 'RECONCILIATION_REQUIRED')
        self.assertIsNone(result['claim'])
        self.assertIsNone(result['event_id'])
        self.assertEqual(self.runtime.worldview.query_active_claims(subject='local_memory'), [])

    def test_reconciliation_rejects_foreign_terminal_and_forged_receipts(self):
        jid, _ = self.enqueue()
        completed = self.execute(jid)
        original = self.queue.get_job(jid)
        self.assertFalse(self.queue.mark_reconciliation_required(jid, 'stranger', 'fake', completed.to_dict()))
        self.assertFalse(self.queue.mark_reconciliation_required(jid, completed.worker_id, 'late', completed.to_dict()))
        self.assertEqual(self.queue.get_job(jid), original)
        active, _ = self.enqueue()
        captured = []
        with patch.object(self.queue, 'complete_job_and_append_receipt_event', side_effect=lambda **kw: captured.append(kw['receipt_dict']) or 0):
            self.execute(active)
        forged = dict(captured[0], worker_signature='invalid')
        self.assertFalse(self.queue.mark_reconciliation_required(active, 'review_worker', 'fake', forged))
        self.assertFalse(self.queue.mark_reconciliation_required(active, 'review_worker', 'missing'))
        self.assertEqual(self.queue.get_job(active)['status'], 'EXECUTING')

    def test_reconciliation_lease_clock_is_sampled_after_write_lock(self):
        jid, _ = self.enqueue()
        captured = []
        with patch.object(self.queue, 'complete_job_and_append_receipt_event', side_effect=lambda **kw: captured.append(kw['receipt_dict']) or 0):
            self.execute(jid)
        with sqlite3.connect(self.db) as conn:
            conn.execute('UPDATE ciph_ipc_jobs SET lease_expires_at = ? WHERE job_id = ?', (time.time() + .02, jid))
        real = self.queue._get_connection
        class Delayed:
            def __init__(self): self.conn = real()
            def execute(self, sql, *args):
                if sql == 'BEGIN IMMEDIATE': time.sleep(.05)
                return self.conn.execute(sql, *args)
            def __enter__(self): return self
            def __exit__(self, *args): return self.conn.__exit__(*args)
            def commit(self): return self.conn.commit()
        with patch.object(self.queue, '_get_connection', side_effect=Delayed):
            self.assertFalse(self.queue.mark_reconciliation_required(jid, 'review_worker', 'late', captured[0]))
        self.assertEqual(self.queue.get_job(jid)['status'], 'EXECUTING')

    def test_retry_and_receipt_transaction_rolls_back_on_event_failure(self):
        """Even when the receipt cannot be stored, a claimed failure is still settled into a
        non-runnable reconciliation state and mints no successor authority."""
        self.cap.should_fail = True
        jid, original = self.enqueue()
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TRIGGER reject_receipt BEFORE INSERT ON ciph_event_store WHEN NEW.event_type = 'ExecutionReceiptStoredEvent' BEGIN SELECT RAISE(ABORT, 'injected event failure'); END")
        receipt = self.execute(jid)
        self.assertNotEqual(receipt.exit_code, 0)
        self.assertEqual(self.queue.get_job(jid)['status'], 'RECONCILIATION_REQUIRED')
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM ciph_retry_tokens').fetchone()[0], 0)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM execution_permits WHERE authorization_generation > 0').fetchone()[0], 0)
        self.assertEqual(ExecutionToken.from_dict(json.loads(self.queue.get_job(jid)['execution_token'])).to_dict(), original.to_dict())

    def test_reconciliation_event_and_state_rollback_together(self):
        jid, _ = self.enqueue()
        with sqlite3.connect(self.db) as conn:
            # Let the durable activation commit; fail receipt/reconciliation writes
            # so this exercises uncertainty after actual capability invocation.
            conn.execute("CREATE TRIGGER reject_completion_events BEFORE INSERT ON ciph_event_store WHEN NEW.event_type != 'ExecutionAttemptStartedEvent' BEGIN SELECT RAISE(ABORT, 'injected event failure'); END")
        result = self.execute(jid)
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(self.queue.get_job(jid)['status'], 'EXECUTING')
        self.assertEqual(self.cap.execution_count, 1)
        with sqlite3.connect(self.db) as conn:
            conn.execute('UPDATE ciph_ipc_jobs SET lease_expires_at = ? WHERE job_id = ?', (time.time() - 1, jid))
        self.queue.reclaim_expired_leases()
        self.assertEqual(self.queue.get_job(jid)['status'], 'RECONCILIATION_REQUIRED')
        self.assertIsNone(self.execute(jid))

    def test_legacy_fail_cannot_bypass_governed_receipt_gate(self):
        jid, _ = self.enqueue()
        self.queue.lease_next_job('owner', target_job_id=jid)
        self.assertFalse(self.queue.fail_job(jid, 'owner', 'unsigned failure'))
        self.assertEqual(self.queue.get_job(jid)['status'], 'LEASED')

    def test_one_activation_per_lease_even_without_token(self):
        jid = self.queue.enqueue_legacy_job_for_test('test.legacy', {})
        self.queue.lease_next_job('owner', target_job_id=jid)
        self.assertTrue(self.queue.mark_executing_and_consume_token(jid, 'owner')[0])
        self.assertFalse(self.queue.mark_executing_and_consume_token(jid, 'owner')[0])

    def test_post_execution_exception_is_never_retried(self):
        jid, _ = self.enqueue()
        with patch.object(self.cap, 'execute', side_effect=RuntimeError('exception after external effect')):
            receipt = self.execute(jid)
        self.assertNotEqual(receipt.exit_code, 0)
        self.assertEqual(self.queue.get_job(jid)['status'], 'RECONCILIATION_REQUIRED')
        self.assertIsNone(self.execute(jid))

    def test_mutating_failure_requires_reconciliation(self):
        class Mutating(SimpleComputeCapability):
            @property
            def manifest(self):
                return replace(super().manifest, reversibility=ReversibilityClass.REVERSIBLE)
        cap = Mutating('review.mutation', should_fail=True)
        self.runtime.register_capability(cap)
        jid, _ = self.enqueue(cap=cap)
        self.execute(jid)
        self.assertEqual(cap.execution_count, 1)
        self.assertEqual(self.queue.get_job(jid)['status'], 'RECONCILIATION_REQUIRED')
        self.assertIsNone(self.execute(jid))

    # ------------------------------------------------------------------ network policy containment
    @staticmethod
    def socket_allowed():
        try:
            sock = socket.socket()
            sock.close()
            return True
        except NetworkPolicyViolation:
            return False

    def test_helper_threads_inherit_policy_and_cannot_downgrade_it(self):
        result = []
        def child():
            with enforce_network_policy(NetworkPolicy.LOCAL_ONLY):
                result.append(self.socket_allowed())
        with enforce_network_policy(NetworkPolicy.OFFLINE_ONLY):
            thread = threading.Thread(target=child)
            thread.start()
            thread.join(timeout=2)
        self.assertEqual(result, [False])
        self.assertTrue(self.socket_allowed())

    def test_helper_retains_policy_after_parent_exits(self):
        release = threading.Event()
        result = []
        def child():
            release.wait(2)
            result.append(self.socket_allowed())
        with enforce_network_policy(NetworkPolicy.OFFLINE_ONLY):
            thread = threading.Thread(target=child)
            thread.start()
        release.set()
        thread.join(timeout=2)
        self.assertEqual(result, [False])

    def test_reused_and_lazily_started_executor_workers_do_not_leak_policy(self):
        for warm in (False, True):
            with self.subTest(warm=warm), concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                if warm: self.assertTrue(pool.submit(self.socket_allowed).result())
                with enforce_network_policy(NetworkPolicy.OFFLINE_ONLY):
                    self.assertFalse(pool.submit(self.socket_allowed).result())
                self.assertTrue(pool.submit(self.socket_allowed).result())

    def test_lowlevel_thread_inherits_policy(self):
        import _thread
        done = threading.Event()
        result = []
        def child():
            result.append(self.socket_allowed())
            done.set()
        with enforce_network_policy(NetworkPolicy.OFFLINE_ONLY):
            _thread.start_new_thread(child, ())
            self.assertTrue(done.wait(2))
        self.assertEqual(result, [False])

    # ------------------------------------------------------------------ concurrency & supervisor
    def test_concurrent_event_writers_keep_one_hash_chain(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(self.runtime.event_store.append_event, 'ReviewEvent', str(i), {'n': i}) for i in range(80)]
            event_ids = [future.result() for future in futures]
        self.assertEqual(len(set(event_ids)), 80)
        self.assertTrue(self.runtime.event_store.verify_integrity()[0])

    def test_start_is_idempotent_for_running_pool(self):
        self.worker.start()
        threads = list(self.worker.workers)
        try:
            self.worker.start()
            self.assertEqual(self.worker.workers, threads)
        finally:
            self.worker.stop()

    def test_concurrent_governed_generations_preserve_receipts_and_event_chain(self):
        """The pool must not double-execute, and the ONE disposition engine - not the worker -
        advances each logical action to generation 1."""
        class Flaky(SimpleComputeCapability):
            @property
            def manifest(self):
                # Declaring IDEMPOTENT is what makes the claimed failure retryable at all.
                return replace(super().manifest, replay_semantics=ReplaySemantics.IDEMPOTENT)

            def __init__(self):
                super().__init__('review.concurrent_retry')
                self.calls = {}
            def run(self, params, context=None):
                with self._lock:
                    value = params['value']
                    self.calls[value] = self.calls.get(value, 0) + 1
                    first = self.calls[value] == 1
                return {'success': not first, 'value': value, 'error': 'transient' if first else None}
        cap = Flaky()
        self.runtime.register_capability(cap)
        jobs = [self.enqueue(cap=cap, params={'value': value}, attempts=2)[0] for value in range(12)]
        permits = {jid: self.carried_permit(jid) for jid in jobs}

        # NOTHING in this loop authorizes a retry: the pool's own disposition derives the proof from
        # the capability declaration and advances each job exactly once.
        self.worker.num_workers = 4
        self.worker.supervised = True
        self.worker.enable_watchdog = True
        self.worker.start()
        try:
            self.wait_for(lambda: all(self.queue.get_job(jid)['status'] == 'SUCCEEDED' for jid in jobs), timeout=30)
        finally:
            self.worker.stop(timeout=3)

        self.assertEqual(cap.calls, {value: 2 for value in range(12)})
        for jid in jobs:
            job = self.queue.get_job(jid)
            permit = self.carried_permit(jid)
            self.assertEqual(int(permit.payload.authorization_generation or 0), 1)
            self.assertEqual(permit.payload.logical_action_id, permits[jid].payload.logical_action_id)
            self.assertNotEqual(permit.payload.permit_id, permits[jid].payload.permit_id)
            event = self.runtime.event_store.get_events(aggregate_id=job['receipt_id'])[0]
            receipt = ExecutionReceipt.from_dict(event['payload'])
            self.assertTrue(receipt.verify(self.runtime.trust_registry)[0])
        self.assertTrue(self.runtime.event_store.verify_integrity()[0])

    def test_legacy_dispatch_selects_own_job_and_replays_one_receipt(self):
        older, _ = self.enqueue()
        context = {'idempotency_key': 'route_once'}
        receipt = self.runtime.route_and_execute(self.cap.manifest.name, {'value': 7}, context=context)
        self.assertEqual(receipt.exit_code, 0)
        self.assertEqual(receipt.results['doubled'], 14)
        self.assertEqual(self.queue.get_job(older)['status'], 'QUEUED')
        self.assertEqual(len(self.runtime.event_store.get_events(aggregate_id=receipt.receipt_id)), 1)
        replay = self.runtime.route_and_execute(self.cap.manifest.name, {'value': 7}, context=context)
        self.assertEqual(replay, receipt)
        self.assertEqual(self.cap.execution_count, 1)
        self.assertEqual(len(self.runtime.event_store.get_events(aggregate_id=receipt.receipt_id)), 1)

    def test_dag_step_does_not_lease_older_unrelated_job(self):
        from ciph.planner.schemas import ExecutionDAG, PlanStep
        older, _ = self.enqueue()
        dag = ExecutionDAG(plan_id='review_dag', objective='double seven', steps=[
            PlanStep(step_id='compute', capability=self.cap.manifest.name, parameters={'value': 7})])
        result = self.runtime.execute_dag_plan(dag)
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(self.queue.get_job(older)['status'], 'QUEUED')
        self.assertEqual(self.cap.execution_count, 1)

    def test_reference_publication_uses_canonical_domain_target(self):
        proposal = IntentProposal(proposal_id='domain_target', objective='offline math',
            proposed_capability=self.cap.manifest.name, provided_parameters={'value': 7, 'domain': 'local.example'})
        result = self.runtime.execute_reference_loop(proposal)
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertEqual(result['receipt'].target, 'local.example')
        replay = self.runtime.execute_reference_loop(proposal)
        self.assertEqual(replay['status'], 'SUCCESS')

    def test_supervisor_recovers_from_uncaught_worker_exit(self):
        jid, _ = self.enqueue()
        permit0 = self.carried_permit(jid)
        original_execute = self.worker._execute_leased_job
        original_lease = self.queue.lease_next_job
        dead = []
        def crash_once(job, worker_id):
            if not dead:
                dead.append(threading.current_thread())
                raise SystemExit('simulated abrupt thread exit')
            return original_execute(job, worker_id)
        leased = []
        def short_lease(worker_id, lease_ttl_seconds=30, target_job_id=None):
            # Only the CRASHING delivery gets the short lease. The recovered delivery must not race
            # its own lease: an expiry during a healthy execution would (correctly) become
            # reconciliation, and the specimen would be measuring scheduling jitter instead of
            # supervisor recovery.
            job = original_lease(worker_id, .2 if not leased else 30, target_job_id)
            if job is not None and not leased:
                leased.append(True)
            return job
        self.worker.num_workers = 1
        self.worker.supervised = True
        self.worker.enable_watchdog = True
        self.worker.watchdog_interval = .05
        with patch.object(self.worker, '_execute_leased_job', side_effect=crash_once), patch.object(self.queue, 'lease_next_job', side_effect=short_lease):
            self.worker.start()
            try:
                self.wait_for(lambda: self.queue.get_job(jid)['status'] == 'SUCCEEDED')
                self.assertEqual(self.worker.active_workers_count(), 1)
            finally:
                self.worker.stop()
        self.assertEqual(len(dead), 1)
        self.assertFalse(dead[0].is_alive())
        self.assertEqual(self.cap.execution_count, 1)
        self.assertEqual(self.queue.get_job(jid)['attempt_number'], 2)
        # A lost lease is a DELIVERY retry: the execution authority was never spent.
        permit1 = self.carried_permit(jid)
        self.assertEqual(permit1.payload.permit_id, permit0.payload.permit_id)
        self.assertEqual(int(permit1.payload.authorization_generation or 0), 0)

    def test_real_process_kills_preserve_preexecution_and_inflight_safety(self):
        # No subprocess accesses anything except this test's database and marker.
        source = '''
import sys, time
from pathlib import Path
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.workers.daemon import DurableWorkerDaemon
from ciph.capabilities.registry import CapabilityRegistry
from ciph.memory.event_store import EventStore
from ciph.kernel.crypto_identity import TrustRegistry
from permit_test_support import central_retry_disposition
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability
path, jid, marker, phase, key, operator_hex = sys.argv[1:]
class CrashCap(SimpleComputeCapability):
    def run(self, params, context=None):
        Path(marker).write_text('effect applied')
        while True: time.sleep(.1)
queue = IPCJobQueue(path)
registry = CapabilityRegistry()
registry.register(CrashCap('review.compute'), code_origin="internal")
trust = TrustRegistry(path)
store = EventStore(path)
worker = DurableWorkerDaemon(
    queue=queue, registry=registry, event_store=store, db_path=path, worker_key_id=key,
    trust_registry=trust,
    retry_disposition=central_retry_disposition(
        db_path=path, queue=queue, event_store=store, trust_registry=trust,
        operator_private_key=bytes.fromhex(operator_hex),
    ),
)
job = queue.lease_next_job('killed_process', .3, target_job_id=jid)
if phase == 'LEASED':
    Path(marker).write_text('leased')
    while True: time.sleep(.1)
worker._execute_leased_job(job, 'killed_process')
'''
        for phase in ('LEASED', 'EXECUTING'):
            with self.subTest(phase=phase):
                jid, _ = self.enqueue()
                marker = str(Path(self.temp.name) / (phase + '.marker'))
                process = subprocess.Popen(
                    [sys.executable, '-B', '-c', source, self.db, jid, marker, phase,
                     self.runtime.worker_key_id, self.runtime.operator_priv_bytes.hex()],
                    cwd=self.temp.name, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1]) + os.pathsep + str(Path(__file__).resolve().parents[1] / 'tests')})
                expected_marker = 'leased' if phase == 'LEASED' else 'effect applied'
                try:
                    # Wait for the CONTENT, not the file. `write_text` truncates before it writes, so
                    # "the file exists" is true for a window in which the marker is still empty - and
                    # killing inside that window would assert on a half-written marker rather than on
                    # the crash behaviour under test.
                    self.wait_for(
                        lambda: (Path(marker).exists() and Path(marker).read_text() == expected_marker)
                        or process.poll() is not None,
                        timeout=15,
                    )
                    self.assertIsNone(process.poll(), process.communicate() if process.poll() is not None else None)
                    process.kill()
                    process.communicate(timeout=3)
                    self.assertLess(process.returncode, 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=3)
                expected = 'RETRYING' if phase == 'LEASED' else 'RECONCILIATION_REQUIRED'
                self.worker.enable_watchdog = True
                self.worker.watchdog_interval = .05
                self.worker.num_workers = 0
                self.worker.start()
                try:
                    self.wait_for(lambda: self.queue.get_job(jid)['status'] == expected, timeout=15)
                finally:
                    self.worker.stop()
                before = self.cap.execution_count
                receipt = self.execute(jid)
                if phase == 'LEASED':
                    self.assertEqual(receipt.exit_code, 0)
                    self.assertEqual(self.cap.execution_count, before + 1)
                else:
                    self.assertIsNone(receipt)
                    self.assertEqual(self.cap.execution_count, before)
                    self.assertEqual(Path(marker).read_text(), 'effect applied')
                self.assertTrue(self.runtime.event_store.verify_integrity()[0])


if __name__ == '__main__':
    unittest.main()
