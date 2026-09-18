"""Durable evidence-backed hypothesis, design, staging and operator review chain.

All records are signed by the trusted supervisor. This module never executes
candidate source and never treats a model suggestion as an engineering gap.
"""
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
from ciph.contracts.base import ContractValidationError, canonical_json
from ciph.evolution.evidence import EvolutionEvidenceStore
from ciph.evolution.file_activation import locked_target, read_at, replace_at


def prepare_evaluation(store, gap, baseline, candidate, grant, class_name, review):
    binding = {'gap_id':gap.gap_id, 'candidate_hash':grant.candidate_hash,
               'base_file_hash':grant.base_file_hash, 'grant_id':grant.grant_id}
    inspection = {'classes':[n.name for n in ast.walk(ast.parse(baseline)) if isinstance(n,ast.ClassDef)],
                  'functions':[n.name for n in ast.walk(ast.parse(baseline)) if isinstance(n,ast.FunctionDef)],
                  'source_hash':hashlib.sha256(baseline.encode()).hexdigest()}
    inspected = store.record('EVOLUTION_INSPECTED', {**binding,'inspection':inspection,
        'receipt_hashes':list(gap.failure_evidence_hashes),'source_questions':list(gap.source_question_ids)})
    hypothesis = store.record('ENGINEERING_HYPOTHESIS', {**binding,'inspection_id':inspected,
        'statement':gap.testable_improvement_criterion,'reproducible_conditions':dict(gap.reproducible_conditions),
        'measured_impact':dict(gap.measured_impact),'proposed_owner':gap.proposed_owner,'risk':gap.risk_tier.value})
    design = store.record('EVOLUTION_DESIGN', {**binding,'hypothesis_id':hypothesis,'class_name':class_name,
        'review':review,'diff':''.join(difflib.unified_diff(baseline.splitlines(True),candidate.splitlines(True),fromfile='baseline',tofile='candidate'))})
    directory = Path(store.trust.db_path).absolute().parent/'ciph_evolution_staging'
    directory.mkdir(mode=0o700,exist_ok=True)
    target = directory/(grant.candidate_hash+'.py')
    with locked_target(target) as (parent,name):
        try:
            existing,_=read_at(parent,name)
        except FileNotFoundError:
            replace_at(parent,name,candidate.encode(),0o600)
        else:
            if existing != candidate.encode():raise ContractValidationError('STAGED_CONTENT_TAMPERED')
    return store.record('EVOLUTION_STAGED',{**binding,'design_id':design,'staged_path':str(target)})


def validate_chain(store, benchmark):
    stage=store.verify(benchmark['workflow_id'],'EVOLUTION_STAGED')
    design=store.verify(stage['design_id'],'EVOLUTION_DESIGN')
    hypothesis=store.verify(design['hypothesis_id'],'ENGINEERING_HYPOTHESIS')
    inspection=store.verify(hypothesis['inspection_id'],'EVOLUTION_INSPECTED')
    for record in (stage,design,hypothesis,inspection):
        for field in ('gap_id','candidate_hash','base_file_hash'):
            if record[field]!=benchmark[field]:raise ContractValidationError('EVOLUTION_CHAIN_BINDING_MISMATCH')
    if design['review']!=benchmark['change_review']:
        raise ContractValidationError('EVOLUTION_REVIEW_BINDING_MISMATCH')
    return stage,design,hypothesis


class EvolutionCoordinator:
    """Runtime entrypoint connecting gap discovery to review and governed deployment."""
    def __init__(self,runtime,staging_manager=None):
        from ciph.evolution.gap_detector import EngineeringGapDetector
        from ciph.evolution.canary_manager import CanaryDeploymentManager
        from code_staging import CodeStagingManager
        self.runtime=runtime
        self.store=EvolutionEvidenceStore(runtime.trust_registry)
        self.detector=EngineeringGapDetector(runtime.db_path,trust_registry=runtime.trust_registry)
        self.staging=staging_manager or CodeStagingManager(runtime.vault)
        self.canaries=CanaryDeploymentManager(staging_manager=self.staging,trust_registry=runtime.trust_registry)

    def discover(self,limit=100):
        from ciph.workers.receipts import ExecutionReceipt
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=1000:
            raise ValueError('INVALID_EVOLUTION_DISCOVERY_BUDGET')
        gaps=[]
        with self.store.events._get_connection() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_evolution_discovery (name TEXT PRIMARY KEY, event_id INTEGER NOT NULL)')
            row=conn.execute("SELECT event_id FROM ciph_evolution_discovery WHERE name='receipts'").fetchone()
            cursor=row[0] if row else 0
            events=conn.execute("SELECT event_id,payload FROM ciph_event_store WHERE event_type='ExecutionReceiptStoredEvent' AND event_id>? ORDER BY event_id LIMIT ?",(cursor,limit)).fetchall()
        for event in events:
            receipt=ExecutionReceipt.from_dict(json.loads(event['payload']))
            gap=self.detector.ingest_receipt(receipt)
            if gap:gaps.append(gap)
            with self.store.events._get_connection() as conn:
                conn.execute("INSERT INTO ciph_evolution_discovery VALUES ('receipts',?) ON CONFLICT(name) DO UPDATE SET event_id=MAX(event_id,excluded.event_id)",(event['event_id'],))
        if not gaps:self.store.record('NO_RELEVANCE_FOUND',{'reason':'No new repeated engineering defect','examined_receipts':len(events)})
        return gaps

    def evaluate(self,baseline,candidate,class_name,grant,test_cases,benchmark_iterations=3):
        from ciph.evolution.benchmark_harness import IndependentBenchmarkHarness
        return IndependentBenchmarkHarness().evaluate_candidate_against_baseline(
            baseline,candidate,class_name,grant,self.runtime.trust_registry,test_cases,benchmark_iterations)

    def operator_proposal(self,evidence_hash,target_file):
        report=self.store.verify(evidence_hash,'BENCHMARK_VERIFIED')
        stage,design,hypothesis=validate_chain(self.store,report)
        with locked_target(target_file) as (parent,name):baseline,_=read_at(parent,name)
        if hashlib.sha256(baseline).hexdigest()!=report['base_file_hash']:
            raise ValueError('CONCURRENT_MODIFICATION_DETECTED')
        proposal={'gap_id':report['gap_id'],'target_file':os.path.abspath(target_file),
            'candidate_hash':report['candidate_hash'],'base_file_hash':report['base_file_hash'],
            'verification_evidence_hash':evidence_hash,'hypothesis':hypothesis,'diff':design['diff'],
            'change_review':report['change_review'],'benchmark':report,'status':'AWAITING_OPERATOR'}
        identity=self.store.record('EVOLUTION_OPERATOR_REVIEW',proposal)
        return {**proposal,'proposal_id':identity}

    def deploy(self,grant):
        self.store.validate_deployment(grant)
        report=self.store.verify(grant.verification_evidence_hashes[0],'BENCHMARK_VERIFIED')
        stage,_,_=validate_chain(self.store,report)
        self.operator_proposal(grant.verification_evidence_hashes[0],grant.target_file_path)
        with locked_target(stage['staged_path']) as (parent,name):source,_=read_at(parent,name)
        if hashlib.sha256(source).hexdigest()!=grant.candidate_hash:raise ValueError('STAGED_CONTENT_TAMPERED')
        artifact=self.staging.stage_code('Verified evolution '+grant.gap_id,'Operator-approved candidate',grant.target_file_path,source.decode())
        return self.canaries.activate_canary(grant,artifact['id'])

    def run_canary(self,canary_id,params):
        result=self.canaries.execute_canary(canary_id,params)
        if result.get('status')=='PROMOTED':self._install(canary_id)
        return result

    def approve_production(self,canary_id,grant):
        result=self.canaries.approve_production(canary_id,grant)
        if result.get('status')=='PROMOTED':self._install(canary_id)
        return result

    def _install(self,canary_id):
        from ciph.evolution.production import EvolutionRevisionCapability
        proxy=EvolutionRevisionCapability(self.canaries,canary_id)
        self.runtime.registry.register(proxy,code_origin='external')
        self.store.record('EVOLUTION_ROUTING_ACTIVATED',{'canary_id':canary_id,'manifest_hash':proxy.manifest.compute_manifest_hash()})

    def recover(self):
        results=self.canaries.recover_in_flight_canaries()
        with self.store.events._get_connection() as conn:
            rows=conn.execute("SELECT DISTINCT json_extract(payload,'$.data.canary_id') FROM ciph_event_store WHERE event_type='EvolutionEvidenceEvent' AND json_extract(payload,'$.kind')='CANARY_STATE'").fetchall()
        # Sequence order, not UUID order, determines the latest approved revision.
        states=[self.canaries._load(row[0]) for row in rows]
        for state in sorted(states,key=lambda value:value['started_at']):
            if state['status'] in ('PROMOTED','ROLLED_BACK'):
                with locked_target(state['target_file_path']) as (parent,name):current,_=read_at(parent,name)
                expected=state['candidate_hash'] if state['status']=='PROMOTED' else self.canaries._grant(state).base_file_hash
                if hashlib.sha256(current).hexdigest()==expected:self._install(state['canary_id'])
        return results
