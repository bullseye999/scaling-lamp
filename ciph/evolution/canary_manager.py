"""Durable canary evaluation with supervisor-owned evidence and revision-safe recovery.

Canaries execute approved offline test inputs in isolated workers. Production
files change only after accepted samples and explicit deployment authorization.
"""

import os
import json
import time
import uuid
import sqlite3
import hashlib
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from ciph.contracts.evolution import (
    EvolutionDeploymentGrant,
    EvolutionReceipt,
    DeploymentStage,
    CanaryCriteria,
)
from ciph.contracts.base import ContractValidationError
from ciph.kernel.crypto_identity import TrustRegistry, KeyRole, KeyStatus
from code_staging import CodeStagingManager


class CanaryState(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    PROMOTED = "PROMOTED"
    ROLLED_BACK = "ROLLED_BACK"
    AWAITING_OPERATOR = "AWAITING_OPERATOR"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"


@dataclass(frozen=True)
class CanaryRecord:
    canary_id: str
    grant_id: str
    gap_id: str
    candidate_hash: str
    target_capability: str
    target_file_path: str
    stage: str
    status: CanaryState
    sample_size: int
    samples_evaluated: int
    error_threshold: float
    errors_detected: int
    started_at: float
    deadline_at: float
    allow_auto_promotion: bool
    rollback_reason: Optional[str]
    receipt_id: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "grant_id": self.grant_id,
            "gap_id": self.gap_id,
            "candidate_hash": self.candidate_hash,
            "target_capability": self.target_capability,
            "target_file_path": self.target_file_path,
            "stage": self.stage,
            "status": self.status.value,
            "sample_size": self.sample_size,
            "samples_evaluated": self.samples_evaluated,
            "error_threshold": self.error_threshold,
            "errors_detected": self.errors_detected,
            "started_at": self.started_at,
            "deadline_at": self.deadline_at,
            "allow_auto_promotion": self.allow_auto_promotion,
            "rollback_reason": self.rollback_reason,
            "receipt_id": self.receipt_id,
        }


class CanaryDeploymentManager:
    """Canary execution stays isolated; production files change only after acceptance.

    Signed events are authoritative. Projection rows are rebuilt from those events.
    A file lock serializes deployment transitions across supervisor processes.
    """
    def __init__(self, db_path=None, staging_manager=None, trust_registry=None):
        from ciph.evolution.evidence import EvolutionEvidenceStore
        self.trust_registry=trust_registry
        self.store=EvolutionEvidenceStore(trust_registry)
        self.db_path=trust_registry.db_path
        if db_path and os.path.abspath(db_path)!=os.path.abspath(self.db_path):
            raise ValueError('CANARY_AND_EVIDENCE_STORE_MUST_MATCH')
        self.staging_manager=staging_manager or CodeStagingManager()
        with self.store.events._get_connection() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_canary_acceptance (grant_id TEXT PRIMARY KEY, evidence_hash TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_phase8_canary_state (canary_id TEXT PRIMARY KEY, payload TEXT NOT NULL, evidence_hash TEXT NOT NULL)')

    def _get_connection(self):
        return self.store.events._get_connection()

    def _lock(self):
        from contextlib import contextmanager
        import fcntl
        @contextmanager
        def locked():
            fd=os.open(self.db_path+'.canary.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX)
                yield
            finally:os.close(fd)
        return locked()

    @staticmethod
    def _grant(state):
        data=dict(state['grant']);data.pop('grant_type',None)
        return EvolutionDeploymentGrant(**data)

    def _save(self,state):
        identity=self.store.record('CANARY_STATE',state)
        with self._get_connection() as conn:
            conn.execute('INSERT OR REPLACE INTO ciph_phase8_canary_state VALUES (?,?,?)',
                         (state['canary_id'],json.dumps(state,sort_keys=True),identity))

    def _load(self,canary_id):
        with self._get_connection() as conn:
            row=conn.execute("SELECT aggregate_id FROM ciph_event_store WHERE event_type='EvolutionEvidenceEvent' AND json_extract(payload,'$.kind')='CANARY_STATE' AND json_extract(payload,'$.data.canary_id')=? ORDER BY event_id DESC LIMIT 1",(canary_id,)).fetchone()
        return self.store.verify(row[0],'CANARY_STATE') if row else None

    def activate_canary(self,deployment_grant,staging_identifier):
        # Exclusive maintenance lease check: canary activation fails closed
        with self._get_connection() as conn:
            try:
                row = conn.execute("SELECT holder_id FROM ciph_maintenance_leases WHERE expires_at > ? LIMIT 1;", (time.time(),)).fetchone()
                if row:
                    from ciph.maintenance.exclusion import MaintenanceInProgressError
                    raise MaintenanceInProgressError(f"Cannot activate canary: Active exclusive maintenance lease held by '{row[0]}'.")
            except sqlite3.OperationalError as ex:
                if "no such table" not in str(ex):
                    raise ex

        try:
            if not isinstance(deployment_grant,EvolutionDeploymentGrant):raise ValueError('AUTHORIZATION_REQUIRED')
            self.store.validate_deployment(deployment_grant)
            if 'CANARY' not in deployment_grant.permitted_stages or not deployment_grant.canary_criteria:
                raise ValueError('CANARY_PERMISSION_AND_CRITERIA_REQUIRED')
            from ciph.evolution.review import validate_criteria
            validate_criteria(deployment_grant.canary_criteria)
            if 'SHADOW' not in deployment_grant.permitted_stages:
                raise ValueError('SHADOW_PERMISSION_REQUIRED')
            artifact=self.staging_manager.find_artifact(staging_identifier)
            if not artifact:raise ValueError('STAGED_ARTIFACT_NOT_FOUND')
            if artifact.get('status')!='PENDING':raise ValueError('STAGED_ARTIFACT_NOT_PENDING')
            from ciph.evolution.file_activation import locked_target,read_at,sha
            if os.path.abspath(artifact['target_file'])!=os.path.abspath(deployment_grant.target_file_path):raise ValueError('TARGET_PATH_MISMATCH')
            with locked_target(artifact['staged_file']) as (parent,name):candidate,_=read_at(parent,name)
            with locked_target(artifact['target_file']) as (parent,name):baseline,_=read_at(parent,name)
            if sha(candidate)!=deployment_grant.candidate_hash or sha(baseline)!=deployment_grant.base_file_hash:
                raise ValueError('CANDIDATE_OR_BASE_HASH_MISMATCH')
            verification=self.store.verify(deployment_grant.verification_evidence_hashes[0],'BENCHMARK_VERIFIED')
            with self._lock():
                with self._get_connection() as conn:
                    used=conn.execute("SELECT 1 FROM ciph_event_store WHERE event_type='EvolutionEvidenceEvent' AND json_extract(payload,'$.kind')='CANARY_STATE' AND json_extract(payload,'$.data.grant_id')=? LIMIT 1",(deployment_grant.grant_id,)).fetchone()
                if used:raise ValueError('DEPLOYMENT_GRANT_ALREADY_CONSUMED')
                now=time.time();criteria=deployment_grant.canary_criteria
                grant=json.loads(deployment_grant.compute_canonical_payload());grant['operator_signature']=deployment_grant.operator_signature
                state={'canary_id':'CANARY-'+uuid.uuid4().hex,'grant_id':deployment_grant.grant_id,
                    'gap_id':deployment_grant.gap_id,'candidate_hash':deployment_grant.candidate_hash,
                    'target_capability':deployment_grant.target_capability,'target_file_path':deployment_grant.target_file_path,
                    'stage':'CANARY','status':'ACTIVE','sample_size':criteria.sample_size,'samples_evaluated':0,
                    'error_threshold':criteria.error_threshold,'errors_detected':0,'started_at':now,
                    'deadline_at':min(now+criteria.deadline_seconds,deployment_grant.expires_at),
                    'allow_auto_promotion':deployment_grant.allow_auto_promotion,'rollback_reason':None,'receipt_id':None,
                    'grant':grant,'candidate_source':candidate.decode(),'baseline_source':baseline.decode(),
                    'benchmark':verification,'shadow_evidence':None,'class_name':verification['class_name'],
                    'isolation_tier':verification['isolation_tier'],'budget':verification['max_resource_budget'],
                    'test_cases':verification['test_cases'],'observations':[],'staging_identifier':staging_identifier,'in_flight':None}
                self.store.record('EVOLUTION_OPERATOR_DECISION',{'decision':'APPROVED','grant':grant,'review_id':verification['operator_review_id']})
                self._save(state)
                shadow=self._run_shadow(state)
                if not shadow['success']:return False,shadow.get('reason',shadow['status']),state['canary_id']
                return True,'Canary active in isolated workers; production file unchanged',state['canary_id']
        except Exception as exc:return False,str(exc),None

    def _run_shadow(self,state):
        """Paired isolated runs; neither candidate nor baseline can mutate live state."""
        from ciph.evolution.isolated_execution import execute_candidate, CandidateExecutionError
        from ciph.contracts.base import canonical_json
        from ciph.evolution.review import resource_regression
        state['stage']='SHADOW';state['in_flight']='SHADOW';self._save(state)
        comparisons=[]
        try:
            for case in state['test_cases']:
                grant=self._grant(state)
                if time.time()>=state['deadline_at'] or not grant.verify_signature(self.trust_registry)[0]:
                    raise ValueError('SHADOW_AUTHORITY_OR_DEADLINE_EXPIRED')
                base_metrics={};candidate_metrics={}
                baseline,_=execute_candidate(state['baseline_source'],state['class_name'],case['params'],state['isolation_tier'],state['budget'],measurements=base_metrics)
                candidate,_=execute_candidate(state['candidate_source'],state['class_name'],case['params'],state['isolation_tier'],state['budget'],measurements=candidate_metrics)
                if any(k not in candidate or canonical_json(candidate[k])!=canonical_json(v) for k,v in case['expected'].items()):
                    raise ValueError('SHADOW_ASSERTION_FAILED')
                regression=resource_regression(grant.canary_criteria,candidate_metrics,state['benchmark'])
                if regression:raise ValueError(regression)
                comparisons.append({'input_hash':hashlib.sha256(canonical_json(case['params']).encode()).hexdigest(),
                    'baseline_hash':hashlib.sha256(canonical_json(baseline).encode()).hexdigest(),
                    'candidate_hash':hashlib.sha256(canonical_json(candidate).encode()).hexdigest(),
                    'baseline_resources':base_metrics,'candidate_resources':candidate_metrics})
            state['shadow_evidence']=self.store.record('SHADOW_VERIFIED',{'canary_id':state['canary_id'],
                'candidate_hash':state['candidate_hash'],'comparisons':comparisons})
            state['stage']='CANARY';state['in_flight']=None;self._save(state)
            return {'success':True,'status':'SHADOW_VERIFIED'}
        except Exception as exc:
            ambiguous=isinstance(exc,CandidateExecutionError) and exc.result.execution_confirmed and exc.result.termination_reason.value in ('TIMEOUT','UNCERTAIN_CLEANUP')
            if not ambiguous:state['in_flight']=None
            return self._stop(state,str(exc))

    def execute_canary(self,canary_id,params):
        """Actual isolated runs supply samples; no caller success flag is accepted."""
        # Exclusive maintenance lease check: canary execution fails closed
        with self._get_connection() as conn:
            try:
                row = conn.execute("SELECT holder_id FROM ciph_maintenance_leases WHERE expires_at > ? LIMIT 1;", (time.time(),)).fetchone()
                if row:
                    from ciph.maintenance.exclusion import MaintenanceInProgressError
                    raise MaintenanceInProgressError(f"Cannot execute canary: Active exclusive maintenance lease held by '{row[0]}'.")
            except sqlite3.OperationalError as ex:
                if "no such table" not in str(ex):
                    raise ex

        from ciph.evolution.isolated_execution import execute_candidate
        with self._lock():
            state=self._load(canary_id)
            if not state or state['status']!='ACTIVE':return {'success':False,'status':'CANARY_NOT_ACTIVE'}
            if time.time()>=state['deadline_at'] or not self._grant(state).verify_signature(self.trust_registry)[0]:
                return self._stop(state,'CANARY_DEADLINE_OR_GRANT_EXPIRED')
            artifact=self.staging_manager.find_artifact(state['staging_identifier'])
            if not artifact or artifact.get('status')!='PENDING':
                return self._stop(state,'STAGED_ARTIFACT_WITHDRAWN')
            state['in_flight']='RUN-'+uuid.uuid4().hex;self._save(state)
            started=time.time()
            try:
                measurement={}
                output,duration=execute_candidate(state['candidate_source'],state['class_name'],params,state['isolation_tier'],state['budget'],measurements=measurement)
                from ciph.contracts.base import canonical_json
                cases=[c for c in state['test_cases'] if canonical_json(c['params'])==canonical_json(params)]
                if not cases:raise ValueError('CANARY_INPUT_WITHOUT_INDEPENDENT_ORACLE')
                success=all(all(k in output and canonical_json(output[k])==canonical_json(v) for k,v in c['expected'].items()) for c in cases)
                from ciph.evolution.review import resource_regression
                regression=resource_regression(self._grant(state).canary_criteria,measurement,state['benchmark'])
                success=success and not regression
                error=regression or ('' if success else 'CANARY_ASSERTION_FAILED')
            except Exception as exc:
                output={};duration=time.time()-started;success=False;error=str(exc)
                from ciph.evolution.isolated_execution import CandidateExecutionError
                if isinstance(exc,CandidateExecutionError) and not exc.result.execution_confirmed:
                    self.store.record('CANARY_DENIED',{'canary_id':canary_id,'reason':error})
                    state['in_flight']=None
                    return self._stop(state,error)
                if any(term in error for term in ('TIMEOUT','UNCERTAIN','CLEANUP_FAILED')):
                    return self._stop(state,'UNCERTAIN_EXECUTION: '+error)
            identity=self.store.record('CANARY_OBSERVATION',{'canary_id':canary_id,'run_id':state['in_flight'],
                'candidate_hash':state['candidate_hash'],'success':success,'error':error,'started_at':started,
                'completed_at':time.time(),'duration_seconds':duration,'output_hash':hashlib.sha256(json.dumps(output,sort_keys=True).encode()).hexdigest()})
            return self._observe(state,identity)

    def record_canary_observation(self,canary_id,success=None,error_message='',current_time=None,*,receipt_id=None):
        if success is not None or current_time is not None or not receipt_id:
            return {'success':False,'status':'AUTHENTICATED_CANARY_OBSERVATION_REQUIRED'}
        with self._lock():
            state=self._load(canary_id)
            if not state:return {'success':False,'status':'CANARY_NOT_FOUND'}
            return self._observe(state,receipt_id)

    def _observe(self,state,identity):
        try:
            if state['status']!='ACTIVE':raise ValueError('CANARY_NOT_ACTIVE')
            data=self.store.verify(identity,'CANARY_OBSERVATION')
            if identity in state['observations']:raise ValueError('DUPLICATE_CANARY_OBSERVATION')
            if (data['canary_id']!=state['canary_id'] or data['candidate_hash']!=state['candidate_hash']
                    or data['run_id']!=state['in_flight'] or data['started_at']<state['started_at']):
                raise ValueError('CANARY_OBSERVATION_BINDING_MISMATCH')
            if time.time()>=state['deadline_at'] or data['completed_at']>=state['deadline_at']:
                return self._stop(state,'CANARY_DEADLINE_EXPIRED')
            grant=self._grant(state)
            if not grant.verify_signature(self.trust_registry)[0]:return self._stop(state,'GRANT_EXPIRED_OR_REVOKED')
            state['observations'].append(identity);state['samples_evaluated']+=1
            state['errors_detected']+=int(data['success'] is not True);state['in_flight']=None
            rate=state['errors_detected']/state['samples_evaluated']
            if (rate>state['error_threshold'] or ('ANY_ERROR' in grant.canary_criteria.rollback_conditions and data['success'] is not True)):return self._stop(state,'Canary error threshold breached')
            if state['samples_evaluated']>=state['sample_size']:
                accepted=self.store.record('CANARY_ACCEPTED',{'grant_hash':hashlib.sha256(grant.compute_canonical_payload()).hexdigest(),
                    'candidate_hash':grant.candidate_hash,'canary_id':state['canary_id'],'observations':state['observations'],'shadow_evidence':state['shadow_evidence']})
                with self._get_connection() as conn:
                    conn.execute('INSERT OR REPLACE INTO ciph_canary_acceptance VALUES (?,?)',(grant.grant_id,accepted))
                if grant.allow_auto_promotion and 'PRODUCTION' in grant.permitted_stages:
                    state['status']='RECONCILIATION_REQUIRED';self._save(state)
                    applied,msg=self.staging_manager.apply(state['staging_identifier'],grant,self.trust_registry)
                    if not applied:
                        state['rollback_reason']=msg;self._save(state)
                        return {'success':False,'status':state['status'],'reason':msg}
                    state['status']='PROMOTED';state['stage']='PRODUCTION'
                    state['receipt_id']=self.store.record('EVOLUTION_OUTCOME',{'canary_id':state['canary_id'],'outcome':'PROMOTED','timestamp':time.time()})
                else:state['status']='AWAITING_OPERATOR'
            self._save(state)
            return {'success':True,'status':state['status'],'samples':state['samples_evaluated'],'error_rate':rate}
        except Exception as exc:return {'success':False,'status':'OBSERVATION_REJECTED','error':str(exc)}

    def _stop(self,state,reason):
        # Canary workers never replaced production files. Stopping this isolated
        # routing session therefore leaves the known-good production revision intact.
        state['status']='RECONCILIATION_REQUIRED' if state['in_flight'] else 'ROLLED_BACK'
        state['rollback_reason']=reason
        state['receipt_id']=self.store.record('EVOLUTION_OUTCOME',{'canary_id':state['canary_id'],'outcome':state['status'],'reason':reason})
        self._save(state)
        return {'success':False,'status':state['status'],'reason':reason}

    def recover_in_flight_canaries(self,current_time=None):
        if current_time is not None and abs(current_time-time.time())>5:
            raise ValueError('CALLER_CONTROLLED_RECOVERY_CLOCK_REJECTED')
        results=[]
        with self._lock():
            with self._get_connection() as conn:
                rows=conn.execute("SELECT DISTINCT json_extract(payload,'$.data.canary_id') FROM ciph_event_store WHERE event_type='EvolutionEvidenceEvent' AND json_extract(payload,'$.kind')='CANARY_STATE'").fetchall()
            for row in rows:
                state=self._load(row[0])
                if state['status'] not in ('ACTIVE','AWAITING_OPERATOR','RECONCILIATION_REQUIRED'):continue
                if state['status']=='RECONCILIATION_REQUIRED' and not state['in_flight']:
                    grant=self._grant(state)
                    ok,msg=self.staging_manager.rollback(grant.target_file_path,grant.candidate_hash,deployment_grant=grant,trust_registry=self.trust_registry)
                    state['status']='ROLLED_BACK' if ok else 'RECONCILIATION_REQUIRED';state['rollback_reason']=msg;self._save(state)
                    result={'success':ok,'status':state['status'],'reason':msg}
                elif state['in_flight'] or time.time()>=state['deadline_at'] or not self._grant(state).verify_signature(self.trust_registry)[0]:
                    result=self._stop(state,'RECOVERY_REQUIRES_RECONCILIATION' if state['in_flight'] else 'DEADLINE_EXPIRED')
                else:result={'success':True,'status':state['status']}
                results.append({'canary_id':state['canary_id'],**result})
        return results

    def get_canary(self,canary_id):
        state=self._load(canary_id)
        if not state:return None
        fields={key:state[key] for key in CanaryRecord.__dataclass_fields__}
        fields['status']=CanaryState(fields['status'])
        return CanaryRecord(**fields)

    def approve_production(self,canary_id,grant):
        """A second operator signature can authorize production after a canary-only grant."""
        with self._lock():
            state=self._load(canary_id)
            if not state or state['status']!='AWAITING_OPERATOR':
                return {'success':False,'status':'CANARY_NOT_ACCEPTED'}
            try:
                self.store.validate_deployment(grant)
                previous=self._grant(state)
                for field in ('candidate_hash','base_file_hash','gap_id','target_capability','target_file_path','verification_evidence_hashes','canary_criteria'):
                    if getattr(grant,field)!=getattr(previous,field):raise ValueError('PRODUCTION_APPROVAL_BINDING_MISMATCH')
                if 'PRODUCTION' not in grant.permitted_stages:raise ValueError('PRODUCTION_STAGE_NOT_AUTHORIZED')
                approval=self.store.record('CANARY_ACCEPTED',{'grant_hash':hashlib.sha256(grant.compute_canonical_payload()).hexdigest(),
                    'candidate_hash':grant.candidate_hash,'canary_id':canary_id,'observations':state['observations'],'shadow_evidence':state['shadow_evidence']})
                with self._get_connection() as conn:
                    conn.execute('INSERT OR REPLACE INTO ciph_canary_acceptance VALUES (?,?)',(grant.grant_id,approval))
                data=json.loads(grant.compute_canonical_payload());data['operator_signature']=grant.operator_signature
                state['grant']=data;state['grant_id']=grant.grant_id
                state['status']='RECONCILIATION_REQUIRED';self._save(state)
                ok,message=self.staging_manager.apply(state['staging_identifier'],grant,self.trust_registry)
                state['status']='PROMOTED' if ok else 'RECONCILIATION_REQUIRED'
                if ok:state['stage']='PRODUCTION'
                state['receipt_id']=self.store.record('EVOLUTION_OUTCOME',{'canary_id':canary_id,'outcome':state['status'],'reason':message})
                self._save(state)
                return {'success':ok,'status':state['status'],'reason':message}
            except Exception as exc:return {'success':False,'status':'PRODUCTION_APPROVAL_REJECTED','reason':str(exc)}

    def rollback_production(self,canary_id,reason):
        """Automatic regression rollback uses the already approved baseline checkpoint."""
        with self._lock():
            state=self._load(canary_id)
            if not state or state['status'] not in ('PROMOTED','RECONCILIATION_REQUIRED'):
                return {'success':False,'status':'PRODUCTION_NOT_ACTIVE'}
            grant=self._grant(state)
            state['status']='RECONCILIATION_REQUIRED';self._save(state)
            ok,message=self.staging_manager.rollback(grant.target_file_path,grant.candidate_hash,deployment_grant=grant,trust_registry=self.trust_registry)
            state['status']='ROLLED_BACK' if ok else 'RECONCILIATION_REQUIRED'
            state['rollback_reason']=reason+': '+message
            state['receipt_id']=self.store.record('EVOLUTION_OUTCOME',{'canary_id':canary_id,'outcome':state['status'],'reason':state['rollback_reason']})
            self._save(state)
            return {'success':ok,'status':state['status'],'reason':message}

    def evolution_receipt(self,canary_id):
        state=self._load(canary_id)
        if not state or not state['receipt_id']:return None
        proof=self.store.verify(state['receipt_id'],'EVOLUTION_OUTCOME')
        return EvolutionReceipt(state['receipt_id'],state['grant_id'],state['candidate_hash'],proof['outcome'],proof,proof.get('timestamp',state['started_at']))
