"""Acceptance coverage for every connected Phase 8 pipeline stage."""
import json,time,uuid
from pathlib import Path
from dataclasses import replace
from phase8_test_support import Phase8Case,BASE,CANDIDATE,sha
from ciph.evolution.workflow import EvolutionCoordinator
from ciph.contracts.evolution import CanaryCriteria

class TestCompleteEvolution(Phase8Case):
    def coordinator(self):
        return EvolutionCoordinator(self.runtime,self.staging)
    def test_complete_chain_and_live_worker_routing(self):
        service=self.coordinator()
        ok,report,_=self.benchmark();self.assertTrue(ok,report.notes)
        proposal=service.operator_proposal(report.verification_evidence_hash,str(self.target))
        self.assertIn('diff',proposal);self.assertIn('hypothesis',proposal)
        grant=self.deployment(evidence=report.verification_evidence_hash)
        ok,message,cid=service.deploy(grant);self.assertTrue(ok,message)
        self.assertEqual(self.target.read_text(),BASE)
        self.assertEqual(service.run_canary(cid,{'x':2,'y':3})['status'],'ACTIVE')
        self.assertEqual(service.run_canary(cid,{'x':2,'y':3})['status'],'PROMOTED')
        receipt=self.runtime.route_and_execute('math.compute',{'x':2,'y':3})
        self.assertEqual(receipt.exit_code,0,receipt.error_message)
        self.assertEqual(receipt.results['result'],5)
        self.assertTrue(receipt.verify_signature(trust_registry=self.trust))
        kinds=[e['payload'].get('kind') for e in self.store.get_events(event_type='EvolutionEvidenceEvent',limit=1000)]
        for kind in ('EVOLUTION_INSPECTED','ENGINEERING_HYPOTHESIS','EVOLUTION_DESIGN','EVOLUTION_STAGED','EVOLUTION_OPERATOR_PROPOSAL','EVOLUTION_OPERATOR_DECISION','SHADOW_VERIFIED','CANARY_ACCEPTED','ACTIVATED','EVOLUTION_ROUTING_ACTIVATED','EVOLUTION_PRODUCTION_OBSERVATION'):
            self.assertIn(kind,kinds)
    def test_dependency_and_manifest_changes_require_exact_approval(self):
        code='import math\n'+CANDIDATE.replace('description="Arithmetic fixture"','description="Reviewed arithmetic revision"')
        ok,report,_=self.benchmark(code);self.assertTrue(ok,report.notes)
        data=self.manager.store.verify(report.verification_evidence_hash,'BENCHMARK_VERIFIED')
        self.assertEqual(data['change_review']['dependency_changes'],['+math'])
        wrong=self.deployment(code,evidence=report.verification_evidence_hash)
        with self.assertRaisesRegex(Exception,'UNAPPROVED'):self.manager.store.validate_deployment(wrong)
        grant=self.deployment(code,evidence=report.verification_evidence_hash,
            dependency_changes=('+math',),manifest_changes=data['change_review']['manifest_changes'])
        _,cid,_=self.activate(code,grant=grant)
        self.assertEqual(self.finish(cid)['status'],'PROMOTED')
    def test_forbidden_dependency_never_installed(self):
        ok,report,_=self.benchmark('import requests\n'+CANDIDATE)
        self.assertFalse(ok);self.assertIn('DEPENDENCY_NOT_APPROVED',report.notes)
    def test_shadow_permission_is_mandatory(self):
        grant=self.deployment(permitted_stages=('CANARY','PRODUCTION'))
        artifact=self.staging.stage_code('x','x',str(self.target),CANDIDATE)
        self.assertFalse(self.manager.activate_canary(grant,artifact['id'])[0])
    def test_resource_metrics_are_from_trusted_launcher(self):
        ok,report,_=self.benchmark();self.assertTrue(ok,report.notes)
        data=self.manager.store.verify(report.verification_evidence_hash,'BENCHMARK_VERIFIED')
        for measurement in data['resource_measurements']:
            self.assertGreater(measurement['peak_memory_bytes'],0)
            self.assertGreaterEqual(measurement['cpu_seconds'],0)
    def test_resource_threshold_rejects_shadow(self):
        grant=self.deployment(canary_criteria=CanaryCriteria(2,0,{'max_peak_memory_bytes':1},300,('RESOURCE_REGRESSION',)))
        a=self.staging.stage_code('x','x',str(self.target),CANDIDATE)
        ok,message,cid=self.manager.activate_canary(grant,a['id'])
        self.assertFalse(ok);self.assertIn('MEMORY_REGRESSION',message);self.assertEqual(self.target.read_text(),BASE)
    def test_second_operator_signature_promotes_canary_only_grant(self):
        grant=self.deployment(permitted_stages=('SHADOW','CANARY'),allow_auto_promotion=False)
        _,cid,_=self.activate(grant=grant);self.assertEqual(self.finish(cid)['status'],'AWAITING_OPERATOR')
        production=replace(grant,grant_id='PROD-'+uuid.uuid4().hex,permitted_stages=('PRODUCTION',)).sign(self.op_priv)
        result=self.coordinator().approve_production(cid,production)
        self.assertEqual(result['status'],'PROMOTED',result);self.assertEqual(self.target.read_text(),CANDIDATE)
    def test_live_regression_restores_baseline(self):
        code=CANDIDATE.replace('params.get("x",0)+params.get("y",0)','(999 if params.get("x")==100 else params.get("x",0)+params.get("y",0))')
        service=self.coordinator();grant=self.deployment(code)
        ok,message,cid=service.deploy(grant);self.assertTrue(ok,message)
        service.run_canary(cid,{'x':2,'y':3});service.run_canary(cid,{'x':2,'y':3})
        result=self.runtime.route_and_execute('math.compute',{'x':100,'y':3})
        self.assertNotEqual(result.exit_code,0)
        self.assertEqual(self.target.read_text(),BASE)
        self.assertEqual(service.canaries.get_canary(cid).status.value,'ROLLED_BACK')
    def test_restart_recovers_production_routing(self):
        service=self.coordinator();grant=self.deployment();ok,message,cid=service.deploy(grant);self.assertTrue(ok,message)
        service.run_canary(cid,{'x':2,'y':3});service.run_canary(cid,{'x':2,'y':3})
        from ciph.runtime import CiphRuntime
        restarted=CiphRuntime(db_path=self.trust.db_path)
        try:
            receipt=restarted.route_and_execute('math.compute',{'x':7,'y':3})
            self.assertEqual(receipt.exit_code,0,receipt.error_message);self.assertEqual(receipt.results['result'],10)
        finally:restarted.shutdown()
    def test_discovery_no_relevance_is_durable(self):
        service=self.coordinator();self.assertEqual(service.discover(),[])
        self.assertTrue(any(e['payload'].get('kind')=='NO_RELEVANCE_FOUND' for e in self.store.get_events(event_type='EvolutionEvidenceEvent')))
    def test_missing_behavior_gap_requires_repeated_authentic_oracle_failure(self):
        from ciph.contracts.enums import OutcomeCategory
        receipts=[self.receipt(outcome=OutcomeCategory.SUCCESS,results={'result':-1}) for _ in range(2)]
        gap=self.detector.detect_behavior_gap('math.compute',receipts,{'result':5})
        self.assertEqual(gap.category.value,'MISSING_BEHAVIOR')
        self.assertEqual(gap.measured_impact['reproduction_rate'],1.0)
        with self.assertRaises(Exception):self.detector.detect_behavior_gap('math.compute',[receipts[0]]*2,{'result':5})
    def test_incremental_discovery_progresses_across_restarts(self):
        self.receipt();self.receipt()
        one=self.coordinator();self.assertEqual(one.discover(limit=1),[])
        two=self.coordinator();self.assertEqual(len(two.discover(limit=1)),1)
        self.assertEqual(two.discover(limit=1),[])
    def test_legacy_keyword_blueprint_cannot_create_engineering_hypothesis(self):
        from evolution_bridge import SelfRelevanceAnalyzer
        class Vault:
            db_path=self.trust.db_path
        result=SelfRelevanceAnalyzer(Vault(),str(self.root)).evaluate_blueprint({'blueprint_id':'legacy','topic':'verify integrity concurrency'})
        self.assertIsNone(result)
        self.assertTrue(self.store.get_events(event_type='NoRelevanceFoundEvent'))
    def test_evolution_receipt_records_final_promotion(self):
        _,cid,_=self.activate();self.finish(cid)
        proof=self.manager.evolution_receipt(cid)
        self.assertIsNotNone(proof);self.assertEqual(proof.outcome,'PROMOTED')
