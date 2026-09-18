"""Phase 6 acceptance and adversarial tests against real signed offline execution."""
import copy
import json
import math
import socket
import sqlite3
import subprocess
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from phase5_test_support import EpistemicTestCase, memory_claim, claim, EvidenceFixture
from ciph.contracts.base import ContractValidationError
from ciph.contracts.enums import NetworkPolicy
from ciph.kernel.network_sandbox import NetworkPolicyViolation, enforce_network_policy
from ciph.perception.curiosity_question import CuriosityQuestion, CuriosityQuestionDAG, QuestionStatus
from ciph.perception.curiosity_daemon import CuriosityDaemon
from ciph.planner.schemas import IntentProposal
from ciph.runtime import CiphRuntime


class TestPhase6InternalCuriosity(EpistemicTestCase):
    def question(self, key='phase6-record', predicate='retrieval_report', **kw):
        return self.runtime.question_dag.propose_question('local_memory', predicate,
            'Read this local record', capability='memory.retrieve',
            parameters={'target': 'local_memory', 'key': key}, **kw)

    def test_existing_evidence_resolves_with_zero_dispatch_and_same_age(self):
        original = memory_claim(self.runtime)
        q = self.question()
        before = self.runtime.event_store.get_events(event_type='ExecutionReceiptStoredEvent')
        with patch.object(self.runtime, 'execute_reference_loop', side_effect=AssertionError('dispatch forbidden')):
            result = self.runtime.run_curiosity_cycle()
        self.assertEqual(result[0]['status'], 'ANSWERED_INTERNAL')
        answer = self.runtime.question_dag.get_question(q.question_id)
        self.assertEqual(answer.answer_claim_id, original.claim_id)
        self.assertEqual(self.worldview.get_canonical_claim(original.claim_id).freshness_deadline, original.freshness_deadline)
        self.assertEqual(before, self.runtime.event_store.get_events(event_type='ExecutionReceiptStoredEvent'))
        with self.runtime.question_dag.store.transaction() as conn:
            self.assertEqual(self.runtime.question_dag.store.all(conn, 'attempt'), [])

    def test_missing_evidence_dispatches_once_and_admits_once(self):
        q = self.question()
        with patch.object(self.worldview, 'admit_claim', wraps=self.worldview.admit_claim) as admit:
            result = self.runtime.run_curiosity_cycle()
        self.assertTrue(result[0]['answered'], result)
        self.assertEqual(admit.call_count, 1)
        self.assertEqual(self.runtime.question_dag.get_question(q.question_id).status, QuestionStatus.ANSWERED)
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            self.runtime.run_curiosity_cycle()
        execute.assert_not_called()

    def test_receipt_committed_before_projection_is_recovered_without_execution(self):
        params = {'target': 'local_memory', 'key': 'phase6-record'}
        from ciph.kernel.policy_engine import ScopeGrant, ScopeType
        proof = self.runtime.route_and_execute('memory.retrieve', params, context={'scope_grant': ScopeGrant(
            scope_id='scope_curiosity_ro', scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=['local_memory'], valid_until=time.time()+60)})
        self.assertEqual(proof.exit_code, 0)
        for i in range(101):
            self.runtime.event_store.append_event('ExecutionReceiptStoredEvent', 'unrelated-'+str(i),
                {'capability': 'unrelated', 'input_hash': 'unrelated'})
        self.question()
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            result = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertEqual(result[0]['status'], 'ANSWERED_INTERNAL')

    def test_forged_answers_and_question_state_are_rejected(self):
        q = self.question()
        with self.assertRaises(ContractValidationError):
            self.runtime.question_dag.resolve_question_with_evidence(q.question_id, 'TRUE', ['invented'])
        with self.assertRaises(ContractValidationError):
            self.question('forged', status='ANSWERED')
        with self.assertRaises(ContractValidationError):
            self.question('skip-search', search_internal_first=False)
        snapshot = self.runtime.question_dag._questions
        snapshot[q.question_id].status = QuestionStatus.ANSWERED
        self.assertEqual(self.runtime.question_dag.get_question(q.question_id).status, QuestionStatus.OPEN)

    def test_unrelated_input_and_forged_value_do_not_answer(self):
        original = memory_claim(self.runtime, key='different')
        q = self.question()
        self.assertFalse(self.runtime.question_dag.resolve_question_with_evidence(q.question_id, claim_id=original.claim_id))
        matching = self.question('different')
        with self.assertRaises(ContractValidationError):
            self.runtime.question_dag.resolve_question_with_evidence(matching.question_id, 'invented', claim_id=original.claim_id)

    def test_missing_memory_value_is_unresolved_not_domain_truth(self):
        q = self.question(predicate='value')
        result = self.runtime.run_curiosity_cycle()
        self.assertFalse(result[0]['answered'])
        self.assertEqual(self.runtime.question_dag.get_question(q.question_id).status, QuestionStatus.UNRESOLVED)

    def test_external_probe_blocked_even_if_caller_allowlists_it(self):
        self.runtime.curiosity_daemon = CuriosityDaemon(allowed_capabilities=['tor.check_status'])
        self.runtime.question_dag.propose_question('tor.check_status', 'execution_report', 'Inspect Tor',
            capability='tor.check_status', parameters={})
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            result = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertEqual(result[0]['status'], 'SAFETY_BLOCKED_REQUIRES_OPERATOR')

    def test_empty_allowlist_disables_all_execution(self):
        self.runtime.curiosity_daemon = CuriosityDaemon(allowed_capabilities=[])
        self.question()
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            self.runtime.run_curiosity_cycle()
        execute.assert_not_called()

    def test_socket_dns_and_process_escape_are_blocked(self):
        operations = [lambda: socket.socket(), lambda: socket.getaddrinfo('example.invalid', 80),
                      lambda: subprocess.run(['/bin/true'], check=True)]
        for operation in operations:
            with self.subTest(operation=operation), enforce_network_policy(NetworkPolicy.OFFLINE_ONLY):
                with self.assertRaises(NetworkPolicyViolation):
                    operation()
        with enforce_network_policy(NetworkPolicy.OFFLINE_ONLY), ThreadPoolExecutor(1) as pool:
            with self.assertRaises(NetworkPolicyViolation):
                pool.submit(lambda: socket.socket()).result()

    def test_socket_attempt_inside_real_capability_cannot_escape(self):
        self.question()
        cap = self.runtime.registry.get('memory.retrieve')
        with patch.object(cap, 'run', side_effect=lambda *a, **k: socket.getaddrinfo('example.invalid', 80)):
            result = self.runtime.run_curiosity_cycle()
        self.assertFalse(result[0]['answered'])
        self.assertNotEqual(result[0]['status'], 'SUCCESS')

    def test_expired_evidence_is_not_reprojected_to_reset_its_clock(self):
        old = memory_claim(self.runtime, deadline=time.time()-1)
        self.question()
        result = self.runtime.run_curiosity_cycle()
        self.assertTrue(any(r['dispatched'] and r['answered'] for r in result), result)
        self.assertEqual(self.worldview.get_claim(old.claim_id).lifecycle_state.value, 'DORMANT')
        self.assertEqual(self.worldview.get_canonical_claim(old.claim_id).freshness_deadline, old.freshness_deadline)

    def test_priority_uses_all_four_dimensions_and_validates_scores(self):
        base = dict(question_id='q', target_subject='s', target_predicate='p', question_text='why')
        q = CuriosityQuestion(**base, impact_score=8, relevance_score=.5, estimated_cost_score=2, risk_score=1)
        self.assertEqual(q.compute_priority_score(), 1)
        for key, value in [('relevance_score', math.nan), ('risk_score', math.inf),
                           ('estimated_cost_score', 0), ('impact_score', -1)]:
            with self.subTest(key=key), self.assertRaises(ContractValidationError):
                CuriosityQuestion(**base, **{key: value})
        low = self.question('low', impact_score=1)
        high = self.question('high', impact_score=8, relevance_score=.8, risk_score=.2)
        self.assertEqual(self.runtime.question_dag.get_ready_unanswered_questions()[0].question_id, high.question_id)

    def test_restart_deduplication_preserves_answers_and_budget(self):
        q = self.question()
        self.runtime.run_curiosity_cycle()
        db = self.runtime.db_path
        self.runtime.close()
        self.runtime = CiphRuntime(db_path=db)
        self.worldview = self.runtime.worldview
        self.assertIsNone(self.question())
        self.assertEqual(self.runtime.question_dag.get_question(q.question_id).status, QuestionStatus.ANSWERED)
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        with self.runtime.question_dag.store.transaction() as conn:
            self.assertEqual(len(self.runtime.question_dag.store.all(conn, 'attempt')), 1)

    def test_atomic_quota_reservation_across_concurrent_schedulers(self):
        q1, q2 = self.question('one'), self.question('two')
        store = self.runtime.question_dag.store
        barrier = threading.Barrier(2)
        def reserve(q):
            barrier.wait()
            return store.reserve(q.question_id, 1, 1)
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(reserve, [q1, q2]))
        self.assertEqual(sum(r is not None for r in results), 1)
        self.assertTrue(store.state()['paused'])
        self.assertEqual(store.state()['reason'], 'BUDGET_EXHAUSTED')
        store.resume('Operator reviewed quota')
        self.assertIsNone(store.reserve(q2.question_id if results[0] else q1.question_id, 1, 1))

    def test_same_question_reserves_only_once(self):
        q = self.question()
        store = self.runtime.question_dag.store
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: store.reserve(q.question_id, 12, 12), range(2)))
        self.assertEqual(sum(r is not None for r in results), 1)

    def test_failure_streak_pauses_and_restart_does_not_clear_it(self):
        for i in range(4): self.question(str(i), predicate='value')
        self.runtime.run_curiosity_cycle()
        state = self.runtime.question_dag.store.state()
        self.assertEqual(state['failure_streak'], 3)
        self.assertEqual(state['reason'], 'CONSECUTIVE_FAILURES')
        self.runtime.question_dag.store.replay()
        self.assertEqual(state, self.runtime.question_dag.store.state())
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.runtime.resume_curiosity('Investigated missing records')
        self.assertFalse(self.runtime.question_dag.store.state()['paused'])

    def test_interrupted_reservation_is_not_blindly_retried(self):
        q = self.question()
        self.runtime.question_dag.store.reserve(q.question_id, 12, 12)
        self.runtime.question_dag.store.replay()
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            result = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertEqual(result[0]['status'], 'RECONCILIATION_REQUIRED')

    def test_exception_is_durable_and_requires_reconciliation(self):
        q = self.question()
        with patch.object(self.runtime, 'execute_reference_loop', side_effect=RuntimeError('interrupted')):
            self.runtime.run_curiosity_cycle()
        state = self.runtime.question_dag.store.state()
        self.assertEqual(state['reason'], 'RECONCILIATION_REQUIRED')
        self.runtime.resume_curiosity('Investigate interruption')
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            self.runtime.run_curiosity_cycle()
        execute.assert_not_called()

    def test_replay_restores_identical_questions_edges_attempts_and_budget(self):
        parent = self.question('parent')
        self.question('child', depends_on=[parent.question_id])
        self.runtime.run_curiosity_cycle()
        store = self.runtime.question_dag.store
        def snapshot():
            with store.transaction() as conn:
                return {kind: store.all(conn, kind) for kind in store.TABLES}
        before = snapshot()
        store.replay()
        self.assertEqual(before, snapshot())
        self.assertTrue(self.runtime.event_store.verify_integrity()[0])

    def test_question_and_budget_tampering_fail_closed(self):
        q = self.question()
        store = self.runtime.question_dag.store
        store.pause('test persisted state')
        store.resume('test resume')
        with store.transaction() as conn:
            conn.execute("UPDATE ciph_curiosity_budget SET payload='{}'")
        with self.assertRaises(ContractValidationError): store.state()
        store.replay()
        store.reserve(q.question_id, 12, 12)
        with store.transaction() as conn:
            conn.execute('DELETE FROM ciph_curiosity_attempts')
        q2 = self.question('other')
        with self.assertRaises(ContractValidationError): store.reserve(q2.question_id, 12, 12)

    def test_dependencies_require_current_evidence(self):
        original = memory_claim(self.runtime)
        parent = self.question()
        child = self.question('child', depends_on=[parent.question_id])
        self.runtime.question_dag.resolve_question_with_evidence(parent.question_id, claim_id=original.claim_id)
        self.assertIn(child.question_id, [q.question_id for q in self.runtime.question_dag.get_ready_unanswered_questions()])
        self.worldview.bury_in_graveyard(original.subject, original.predicate, 'premise withdrawn', claim_id=original.claim_id)
        self.assertNotIn(child.question_id, [q.question_id for q in self.runtime.question_dag.get_ready_unanswered_questions()])

    def test_graph_bounds_and_missing_parents_fail_closed(self):
        dag = CuriosityQuestionDAG()
        with self.assertRaises(ValueError): dag.propose_question('s', 'p', 'q', depends_on=['missing'])
        parent = dag.propose_question('s', 'p0', 'q')
        for i in range(1, 17):
            parent = dag.propose_question('s', 'p'+str(i), 'q', depends_on=[parent.question_id])
        with self.assertRaises(ValueError): dag.propose_question('s', 'too-deep', 'q', depends_on=[parent.question_id])
        dag = CuriosityQuestionDAG()
        parent = dag.propose_question('s', 'root', 'q')
        for i in range(256): dag.propose_question('s', str(i), 'q', depends_on=[parent.question_id])
        with self.assertRaises(ValueError): dag.propose_question('s', 'too-wide', 'q', depends_on=[parent.question_id])

    def test_old_closed_loop_cannot_bypass_offline_scheduler(self):
        claim(self.runtime, 'external', subject='darknet.feeds', deadline=time.time()-1)
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            report = self.runtime.run_epistemic_cycle(force_refresh_all=True)
        execute.assert_not_called()
        self.assertEqual(report.inquiries_dispatched, 0)
        self.assertTrue(report.errors)

    def test_context_mismatch_cannot_reuse_a_receipt(self):
        original = memory_claim(self.runtime)
        q = self.question(normalized_context_hash='wrong-context')
        self.assertFalse(self.runtime.question_dag.resolve_question_with_evidence(q.question_id, claim_id=original.claim_id))

    def test_pausing_execution_does_not_prevent_internal_evidence_resolution(self):
        q = self.question()
        self.runtime.question_dag.store.pause('OPERATOR_PAUSED')
        original = memory_claim(self.runtime)
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            results = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertEqual(results[0]['status'], 'ANSWERED_INTERNAL')
        self.assertTrue(self.runtime.question_dag.store.state()['paused'])

    def test_crash_after_receipt_commit_recovers_reserved_question(self):
        q = self.question()
        attempt = self.runtime.question_dag.store.reserve(q.question_id, 12, 12)
        self.runtime.execute_reference_loop(IntentProposal(proposal_id=attempt['proposal_id'],
            objective=q.question_text, proposed_capability=q.capability, provided_parameters=q.parameters))
        self.runtime.question_dag.store.replay()
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            results = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertTrue(results[0]['answered'])
        with self.runtime.question_dag.store.transaction() as conn:
            saved = self.runtime.question_dag.store.get(conn, 'attempt', attempt['attempt_id'])
        self.assertEqual(saved['status'], 'ANSWERED')
        self.assertTrue(saved['receipt_id'])

    def test_atomic_reservation_rechecks_parent_evidence(self):
        original = memory_claim(self.runtime)
        parent = self.question()
        child = self.question('child', depends_on=[parent.question_id])
        self.runtime.question_dag.resolve_question_with_evidence(parent.question_id, claim_id=original.claim_id)
        self.runtime.question_dag.get_ready_unanswered_questions()
        self.worldview.bury_in_graveyard(original.subject, original.predicate, 'withdrawn', claim_id=original.claim_id)
        self.assertIsNone(self.runtime.question_dag.store.reserve(child.question_id, 12, 12))

    def test_authenticated_observation_answers_only_attributed_question(self):
        from phase5_test_support import receipt
        proof = receipt(self.runtime, {'observation': {'source': 'sensor-feed', 'subject': 'server',
            'predicate': 'compromised', 'value': True}}, capability='test.collect')
        observation = self.worldview.ingest_observation(proof.receipt_id)
        candidate = self.projector.project_from_observation(observation)
        self.worldview.admit_claim(candidate)
        context = self.worldview.get_claim(candidate.claim_id).normalized_context_hash
        q = self.runtime.question_dag.propose_question(candidate.subject, candidate.predicate,
            'What did this source report?', normalized_context_hash=context)
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            results = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertTrue(results[0]['answered'])
        self.assertEqual(self.runtime.question_dag.get_question(q.question_id).evidence_found, [observation.observation_id])
        wrong = self.runtime.question_dag.propose_question('server', 'compromised', 'Is it compromised?', normalized_context_hash=context)
        self.assertFalse(self.runtime.question_dag.resolve_question_with_evidence(wrong.question_id, claim_id=candidate.claim_id))

    def test_question_dependency_variations_cannot_duplicate_same_inquiry(self):
        parent = self.question('parent')
        q = self.question()
        with self.assertRaises(ContractValidationError):
            self.question(depends_on=[parent.question_id])
        self.assertEqual(len(self.runtime.question_dag._questions), 2)

    def test_sub_unit_estimates_cannot_evade_execution_cost_floor(self):
        q = self.question(estimated_cost_score=.01)
        attempt = self.runtime.question_dag.store.reserve(q.question_id, 12, 1)
        self.assertEqual(attempt['cost'], 1)
        self.assertEqual(self.runtime.question_dag.store.state()['reason'], 'BUDGET_EXHAUSTED')


    def test_existing_question_edges_cannot_be_rewritten_into_a_cycle(self):
        parent = self.question('parent')
        child = self.question('child', depends_on=[parent.question_id])
        with self.assertRaises(ValueError):
            self.question('parent', depends_on=[child.question_id])
        self.assertEqual(self.runtime.question_dag.get_question(parent.question_id).depends_on, [])

    def test_allowed_name_cannot_override_privileged_manifest(self):
        from ciph.capabilities.base import BaseCapability
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, ReversibilityClass, AuthorizationTier
        class Privileged(BaseCapability):
            @property
            def manifest(self):
                return CapabilityManifest(name='memory.retrieve', description='Requires approval',
                    network_policy=NetworkPolicy.OFFLINE_ONLY, risk_tier=RiskTier.HIGH,
                    reversibility=ReversibilityClass.REVERSIBLE, authorization=AuthorizationTier.MANDATORY_INTERRUPT)
            def run(self, params, context=None):
                raise AssertionError('must not run')
        self.runtime.register_capability(Privileged())
        self.question()
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            results = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertEqual(results[0]['status'], 'SAFETY_BLOCKED_REQUIRES_OPERATOR')


    def test_fresh_receipt_can_answer_another_registered_predicate_without_execution(self):
        original = memory_claim(self.runtime)
        q = self.question(predicate='found')
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            result = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertTrue(result[0]['answered'])
        resolved = self.runtime.question_dag.get_question(q.question_id)
        candidate = self.worldview.get_canonical_claim(resolved.answer_claim_id)
        self.assertIn(original.claim_id, candidate.parent_claim_ids)
        self.assertLessEqual(candidate.freshness_deadline, original.freshness_deadline)

    def test_expired_question_ancestor_blocks_descendants(self):
        first = memory_claim(self.runtime, 'first', key='first', deadline=time.time()+30)
        second = memory_claim(self.runtime, 'second', key='second')
        parent = self.question('first')
        child = self.question('second', depends_on=[parent.question_id])
        grandchild = self.question('third', depends_on=[child.question_id])
        dag = self.runtime.question_dag
        self.assertTrue(dag.resolve_question_with_evidence(parent.question_id, claim_id=first.claim_id))
        self.assertTrue(dag.resolve_question_with_evidence(child.question_id, claim_id=second.claim_id))
        self.worldview.reap_expired_claims(current_time=time.time()+31)
        ready = dag.get_ready_unanswered_questions()
        self.assertNotIn(grandchild.question_id, [q.question_id for q in ready])


    def test_unrelated_job_answer_does_not_reconcile_reserved_execution(self):
        q = self.question()
        attempt = self.runtime.question_dag.store.reserve(q.question_id, 12, 12)
        original = memory_claim(self.runtime)
        with patch.object(self.runtime, 'execute_reference_loop') as execute:
            results = self.runtime.run_curiosity_cycle()
        execute.assert_not_called()
        self.assertTrue(results[0]['answered'])
        with self.runtime.question_dag.store.transaction() as conn:
            saved = self.runtime.question_dag.store.get(conn, 'attempt', attempt['attempt_id'])
        self.assertEqual(saved['status'], 'RESERVED')
        self.assertIsNone(saved['receipt_id'])
        self.assertIsNone(saved['job_id'])
        self.worldview.reap_expired_claims(current_time=time.time()+8*86400)
        self.runtime.question_dag.get_ready_unanswered_questions()
        self.assertIsNone(self.runtime.question_dag.store.reserve(q.question_id, 12, 12))



if __name__ == '__main__':
    unittest.main()
