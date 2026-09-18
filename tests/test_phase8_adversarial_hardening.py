"""Additional Phase 8 regressions for signed budget and recovery boundaries."""
from pathlib import Path
from unittest.mock import patch
from phase8_test_support import Phase8Case,CANDIDATE,BASE,sha
from ciph.contracts.base import ContractValidationError
from ciph.kernel.sandbox.base import SandboxResult,SandboxTerminationReason
from ciph.evolution.isolated_execution import CandidateExecutionError,execute_candidate

class TestPhase8Adversarial(Phase8Case):
    def test_signed_frozen_budget_roundtrip(self):
        grant=self.evaluation(max_resource_budget={'max_runs':8,'timeout':2})
        self.assertTrue(grant.verify_signature(self.trust)[0])
        self.assertEqual(grant.max_resource_budget['max_runs'],8)
    def test_bad_resource_limits_rejected(self):
        for budget in ({'timeout':float('nan')},{'max_runs':True},{'max_processes':1.5},{'unknown':1}):
            with self.assertRaises(ContractValidationError):self.evaluation(max_resource_budget=budget)
    def test_candidate_change_invalidates_evaluation(self):
        grant=self.evaluation();ok,report,_=self.benchmark(CANDIDATE+'# changed',grant=grant)
        self.assertFalse(ok);self.assertIn('BINDING_MISMATCH',report.notes)
    def test_interface_regression_rejected(self):
        changed=CANDIDATE.replace('def run(self,params,context=None):','def run(self,params,context=None,extra=None):')
        ok,report,_=self.benchmark(changed);self.assertFalse(ok);self.assertIn('INTERFACE_REGRESSION',report.notes)
    def test_legacy_import_benchmark_cannot_execute(self):
        from ciph_benchmark import CiphBenchmark
        marker=self.root/'executed';code=self.root/'malicious.py'
        code.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")')
        self.assertFalse(CiphBenchmark().measure_import_speed(str(code))['success']);self.assertFalse(marker.exists())
    def test_dependency_check_does_not_import_parent_package(self):
        with patch('code_staging.importlib.import_module',side_effect=AssertionError('unexpected import')):
            self.assertEqual(self.staging.resolve_dependencies(['untrusted.child']),{'untrusted.child':False})
    def test_rollback_permissions_are_bound_to_checkpoint(self):
        grant,cid,_=self.activate();self.assertEqual(self.finish(cid)['status'],'PROMOTED')
        with self.store._get_connection() as conn:conn.execute('UPDATE ciph_file_activations SET mode=? WHERE grant_id=?',(0o777,grant.grant_id))
        ok,reason=self.staging.rollback(str(self.target),grant.candidate_hash,deployment_grant=grant,trust_registry=self.trust)
        self.assertFalse(ok);self.assertIn('TAMPERED',reason);self.assertEqual(self.target.read_text(),CANDIDATE)
    def test_denial_does_not_mint_execution_observation(self):
        # State-machine fault injection; actual isolation is tested separately.
        _,cid,_=self.activate()
        result=SandboxResult(None,'','unavailable',SandboxTerminationReason.SANDBOX_UNAVAILABLE)
        with patch('ciph.evolution.isolated_execution.execute_candidate',side_effect=CandidateExecutionError(result)):
            self.assertEqual(self.manager.execute_canary(cid,{'x':2,'y':3})['status'],'ROLLED_BACK')
        kinds=[e['payload'].get('kind') for e in self.store.get_events(event_type='EvolutionEvidenceEvent')]
        self.assertIn('CANARY_DENIED',kinds);self.assertNotIn('CANARY_OBSERVATION',kinds)
    def test_timeout_remains_reconciliation_required(self):
        _,cid,_=self.activate()
        result=SandboxResult(None,'','timeout',SandboxTerminationReason.TIMEOUT,execution_confirmed=True)
        with patch('ciph.evolution.isolated_execution.execute_candidate',side_effect=CandidateExecutionError(result)):
            self.assertEqual(self.manager.execute_canary(cid,{'x':2,'y':3})['status'],'RECONCILIATION_REQUIRED')
        self.assertEqual(self.target.read_text(),BASE)
    def test_output_flood_is_bounded_by_real_runner(self):
        code=CANDIDATE+'\nprint("x"*100000)\n'
        with self.assertRaisesRegex(CandidateExecutionError,'OUTPUT_FLOOD'):
            execute_candidate(code,'MathComputeCapability',{},'DISPOSABLE_PROCESS',{'max_output_bytes':4096})
    def test_manifest_migration_cannot_hide_in_source(self):
        changed=CANDIDATE.replace('risk_tier=RiskTier.LOW','risk_tier=RiskTier.NONE')
        ok,report,_=self.benchmark(changed);self.assertTrue(ok,report.notes)
        grant=self.deployment(changed,evidence=report.verification_evidence_hash)
        with self.assertRaisesRegex(ContractValidationError,'UNAPPROVED'):
            self.manager.store.validate_deployment(grant)
    def test_rejected_artifact_cannot_continue_canary(self):
        _,cid,a=self.activate();self.staging.reject(a['id'],'operator withdrew candidate')
        self.assertEqual(self.manager.execute_canary(cid,{'x':2,'y':3})['status'],'ROLLED_BACK')
        self.assertEqual(self.target.read_text(),BASE)
    def test_unsigned_failure_group_projection_cannot_retarget_evidence(self):
        one=self.receipt(env='different');self.detector.ingest_receipt(one)
        two=self.receipt();self.detector.ingest_receipt(two)
        with self.store._get_connection() as conn:
            sig=conn.execute('SELECT signature FROM ciph_gap_failure_inputs WHERE receipt_id=?',(two.receipt_id,)).fetchone()[0]
            conn.execute('UPDATE ciph_gap_failure_inputs SET signature=? WHERE receipt_id=?',(sig,one.receipt_id))
        with self.assertRaisesRegex(ContractValidationError,'GROUP_TAMPERED'):self.detector.ingest_receipt(self.receipt())
