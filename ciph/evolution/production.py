"""Trusted production proxy. Candidate code only enters the Phase 7 OS runner."""
import hashlib
from dataclasses import replace
from ciph.capabilities.base import BaseCapability
from ciph.capabilities.evolution import HotReloadEngine
from ciph.contracts.base import canonical_json
from ciph.evolution.isolated_execution import execute_candidate, CandidateExecutionError
from ciph.kernel.sandbox.base import SandboxResult, SandboxTerminationReason as Reason
from ciph.evolution.file_activation import locked_target,read_at


class EvolutionRevisionCapability(BaseCapability):
    def __init__(self,manager,canary_id):
        self.manager=manager
        self.canary_id=canary_id
        state=manager._load(canary_id)
        if not state or state['status'] not in ('PROMOTED','ROLLED_BACK'):raise ValueError('VERIFIED_PRODUCTION_REQUIRED')
        report=manager.store.verify(manager._grant(state).verification_evidence_hashes[0],'BENCHMARK_VERIFIED')
        self._manifest=replace(HotReloadEngine().build_manifest_from_static_info(report['change_review']['candidate_manifest']),version='evo-'+state['candidate_hash'])

    @property
    def manifest(self):return self._manifest

    def run(self,params,context=None):
        raise PermissionError('SUPERVISED_EVOLUTION_DISPATCH_REQUIRED')

    def execute_supervised(self,params,token):
        state=self.manager._load(self.canary_id)
        if not token or not token.verify(self.manager.trust_registry,expected_manifest_hash=self.manifest.compute_manifest_hash())[0]:
            raise PermissionError('EXECUTION_TOKEN_REQUIRED')
        if token.capability!=self.manifest.name or token.parameters_hash!=hashlib.sha256(canonical_json(params).encode()).hexdigest():
            raise PermissionError('EVOLUTION_EXECUTION_BINDING_MISMATCH')
        if state['status']=='RECONCILIATION_REQUIRED':
            return SandboxResult(None,'','EVOLUTION_RECONCILIATION_REQUIRED',Reason.UNCERTAIN_CLEANUP)
        if state['status'] not in ('PROMOTED','ROLLED_BACK'):
            raise PermissionError('PRODUCTION_REVISION_NOT_ACTIVE')
        if state['status']=='PROMOTED':
            key=self.manager.trust_registry.get_key(self.manager._grant(state).operator_id)
            if not key or key['status']!='ACTIVE':
                self.manager.rollback_production(self.canary_id,'AUTHORITY_REVOKED')
                return SandboxResult(None,'','AUTHORITY_REVOKED',Reason.SANDBOX_UNAVAILABLE)
        source=state['candidate_source'] if state['status']=='PROMOTED' else state['baseline_source']
        with locked_target(state['target_file_path']) as (parent,name):current,_=read_at(parent,name)
        if hashlib.sha256(current).hexdigest()!=hashlib.sha256(source.encode()).hexdigest():
            return SandboxResult(None,'','ACTIVE_REVISION_MISMATCH',Reason.SANDBOX_UNAVAILABLE)
        metrics={}
        try:
            output,duration=execute_candidate(source,state['class_name'],params,state['isolation_tier'],state['budget'],measurements=metrics)
            if state['status']=='PROMOTED':
                cases=[case for case in state['test_cases'] if canonical_json(case['params'])==canonical_json(params)]
                if cases:
                    valid=all(all(k in output and canonical_json(output[k])==canonical_json(v) for k,v in case['expected'].items()) for case in cases)
                else:
                    baseline,_=execute_candidate(state['baseline_source'],state['class_name'],params,state['isolation_tier'],state['budget'])
                    valid=canonical_json(output)==canonical_json(baseline)
                from ciph.evolution.review import resource_regression
                regression=resource_regression(self.manager._grant(state).canary_criteria,metrics,state['benchmark'])
                if not valid or regression:raise ValueError(regression or 'PRODUCTION_REGRESSION')
            self.manager.store.record('EVOLUTION_PRODUCTION_OBSERVATION',{'canary_id':self.canary_id,'candidate_hash':state['candidate_hash'],
                'input_hash':token.parameters_hash,'output_hash':hashlib.sha256(canonical_json(output).encode()).hexdigest(),'resources':metrics,'revision_status':state['status']})
            return SandboxResult(0,canonical_json(output),'',Reason.SUCCESS,execution_confirmed=True,data=output,
                duration_seconds=duration,peak_memory_bytes=metrics['peak_memory_bytes'],cpu_seconds=metrics['cpu_seconds'])
        except CandidateExecutionError as exc:
            if not exc.result.execution_confirmed:return exc.result
            if exc.result.termination_reason in (Reason.TIMEOUT,Reason.UNCERTAIN_CLEANUP):
                self.manager.rollback_production(self.canary_id,'UNCERTAIN_PRODUCTION_EXECUTION')
                return replace(exc.result,termination_reason=Reason.UNCERTAIN_CLEANUP)
            error=str(exc)
        except Exception as exc:error=str(exc)
        restored=self.manager.rollback_production(self.canary_id,error)
        if not restored['success']:
            return SandboxResult(None,'',restored['reason'],Reason.UNCERTAIN_CLEANUP,execution_confirmed=True)
        # The failed candidate is recorded as a failure. The next governed request
        # uses the restored baseline; no ambiguous work is retried in this call.
        return SandboxResult(1,'',error,Reason.EXIT_ERROR,execution_confirmed=True,data={'error':error,'rolled_back':True})
