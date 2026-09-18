"""Independent verification and durable canary lifecycle acceptance tests."""
import time
from dataclasses import replace
from unittest.mock import patch
from phase8_test_support import Phase8Case,BASE,CANDIDATE,BROKEN,sha
from ciph.evolution.canary_manager import CanaryDeploymentManager
from ciph.contracts.evolution import CanaryCriteria
SAMPLE_BASELINE_CODE=BASE
SAMPLE_CANDIDATE_CODE=CANDIDATE
SAMPLE_BROKEN_CANDIDATE_CODE=BROKEN

class TestPhase82(Phase8Case):
    def test_independent_benchmark_and_signed_evidence(self):
        ok,report,receipt=self.benchmark();self.assertTrue(ok,report.notes)
        data=self.manager.store.verify(report.verification_evidence_hash,'BENCHMARK_VERIFIED')
        self.assertTrue(data['passed']);self.assertEqual(data['candidate_hash'],sha(CANDIDATE));self.assertGreater(data['baseline_avg_ms'],0)
    def test_candidate_cannot_forge_parent_assertions(self):
        forgery=BROKEN+'''\nimport json
original_dump=json.dump
def forged_dump(value,output,**kwargs):
    value['success']=True
    original_dump(value,output,**kwargs)
json.dump=forged_dump
'''
        ok,report,receipt=self.benchmark(forgery)
        self.assertFalse(ok);self.assertIsNone(receipt);self.assertIn('independent expected output mismatch',report.notes)
    def test_empty_tests_or_empty_oracle_rejected(self):
        for cases in ([],[{'params':{},'expected':{}}]):self.assertFalse(self.benchmark(cases=cases)[0])
    def test_ast_dynamic_execution_rejected(self):
        ok,report,_=self.benchmark(CANDIDATE+'\neval("1")\n');self.assertFalse(ok);self.assertIn('AST security veto',report.notes)
    def test_fake_benchmark_reference_cannot_activate(self):
        grant=self.deployment(evidence=sha('invented'))
        a=self.staging.stage_code('test','test',str(self.target),CANDIDATE)
        self.assertFalse(self.manager.activate_canary(grant,a['id'])[0]);self.assertEqual(self.target.read_text(),BASE)
    def test_evaluation_grant_cannot_be_replayed(self):
        grant=self.evaluation();self.assertTrue(self.benchmark(grant=grant)[0]);self.assertFalse(self.benchmark(grant=grant)[0])
    def test_evaluation_run_budget_enforced(self):
        grant=self.evaluation(max_resource_budget={'max_runs':1})
        ok,report,_=self.benchmark(grant=grant);self.assertFalse(ok);self.assertIn('BUDGET_EXCEEDED',report.notes)
    def test_canary_activation_preserves_production(self):
        _,cid,_=self.activate();self.assertEqual(self.target.read_text(),BASE)
        self.assertEqual(self.manager.get_canary(cid).status.value,'ACTIVE')
    def test_success_boolean_and_unbound_observation_rejected(self):
        _,cid,_=self.activate()
        for kw in ({'success':True},{'receipt_id':sha('fake')}):self.assertFalse(self.manager.record_canary_observation(cid,**kw)['success'])
        self.assertEqual(self.manager.get_canary(cid).samples_evaluated,0)
    def test_real_canary_samples_promote(self):
        _,cid,_=self.activate();self.assertEqual(self.finish(cid)['status'],'PROMOTED')
        self.assertEqual(self.target.read_text(),CANDIDATE)
    def test_unknown_input_does_not_count_as_success(self):
        _,cid,_=self.activate();result=self.manager.execute_canary(cid,{'x':100})
        self.assertEqual(result['status'],'ROLLED_BACK');self.assertEqual(self.target.read_text(),BASE)
    def test_no_auto_promotion_without_explicit_permission(self):
        grant=self.deployment(allow_auto_promotion=False);_,cid,_=self.activate(grant=grant)
        self.assertEqual(self.finish(cid)['status'],'AWAITING_OPERATOR');self.assertEqual(self.target.read_text(),BASE)
    def test_restart_uses_signed_state_not_mutable_projection(self):
        _,cid,_=self.activate()
        with self.store._get_connection() as conn:conn.execute('DELETE FROM ciph_phase8_canary_state')
        restarted=CanaryDeploymentManager(staging_manager=self.staging,trust_registry=self.trust)
        self.assertEqual(restarted.get_canary(cid).status.value,'ACTIVE')
    def test_crash_inflight_is_not_retried_or_claimed_rolled_back(self):
        _,cid,_=self.activate();state=self.manager._load(cid);state['in_flight']='interrupted';self.manager._save(state)
        result=self.manager.recover_in_flight_canaries()[0]
        self.assertEqual(result['status'],'RECONCILIATION_REQUIRED');self.assertEqual(self.target.read_text(),BASE)
    def test_expired_canary_stops_and_preserves_baseline(self):
        _,cid,_=self.activate();state=self.manager._load(cid);state['deadline_at']=time.time()-1;self.manager._save(state)
        self.assertEqual(self.manager.recover_in_flight_canaries()[0]['status'],'ROLLED_BACK');self.assertEqual(self.target.read_text(),BASE)
    def test_interrupted_replace_is_recovered_even_after_deadline(self):
        grant,cid,_=self.activate();self.finish(cid)
        state=self.manager._load(cid);state['status']='RECONCILIATION_REQUIRED';state['deadline_at']=time.time()-1;self.manager._save(state)
        self.assertEqual(self.manager.recover_in_flight_canaries()[0]['status'],'ROLLED_BACK');self.assertEqual(self.target.read_text(),BASE)
    def test_rollback_failure_is_not_reported_success(self):
        _,cid,_=self.activate();self.finish(cid);self.target.write_text('newer')
        state=self.manager._load(cid);state['status']='RECONCILIATION_REQUIRED';self.manager._save(state)
        self.assertEqual(self.manager.recover_in_flight_canaries()[0]['status'],'RECONCILIATION_REQUIRED')
    def test_canary_grant_cannot_be_reused(self):
        grant,cid,a=self.activate();self.assertFalse(self.manager.activate_canary(grant,a['id'])[0])
