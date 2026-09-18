"""Disposable signed evidence fixtures; real sandbox runs are never mocked here.

receipt() builds terminal ledger fixtures for unit tests. A separate integration
probe verifies admission of receipts produced by the actual runtime worker.
"""
import hashlib,json,os,tempfile,time,unittest,uuid
from pathlib import Path
from ciph.runtime import CiphRuntime
from ciph.contracts.evolution import EvolutionEvaluationGrant,EvolutionDeploymentGrant,CanaryCriteria
from ciph.contracts.enums import OutcomeCategory,NetworkPolicy
from ciph.workers.receipts import ExecutionReceipt
from ciph.evolution.gap_detector import EngineeringGapDetector
from ciph.evolution.benchmark_harness import IndependentBenchmarkHarness
from ciph.evolution.canary_manager import CanaryDeploymentManager
from code_staging import CodeStagingManager

BASE='''from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest,RiskTier,NetworkPolicy,ReversibilityClass,AuthorizationTier
class MathComputeCapability(BaseCapability):
    @property
    def manifest(self):
        return CapabilityManifest(name="math.compute",description="Arithmetic fixture",risk_tier=RiskTier.LOW,network_policy=NetworkPolicy.OFFLINE_ONLY,reversibility=ReversibilityClass.READ_ONLY,authorization=AuthorizationTier.AUTO)
    def run(self,params,context=None):
        return {"result":params.get("x",0)+params.get("y",0),"status":"ok"}
'''
CANDIDATE=BASE+'\n# Candidate revision\n'
BROKEN=CANDIDATE.replace('params.get("x",0)+params.get("y",0)','-999')
def sha(s):return hashlib.sha256(s.encode() if isinstance(s,str) else s).hexdigest()

class Phase8Case(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='phase8-test-');self.root=Path(self.temp.name)
        self.runtime=CiphRuntime(db_path=str(self.root/'vault.db'))
        self.trust=self.runtime.trust_registry
        self.op_id='operator_root';self.op_priv=self.trust.get_keypair(self.op_id)[0]
        self.store=self.runtime.event_store
        self.detector=EngineeringGapDetector(self.trust.db_path,trust_registry=self.trust)
        class Staging(CodeStagingManager):
            STAGING_DIR=str(self.root/'staging');BACKUPS_DIR=str(self.root/'backups');PROPOSALS_DIR=str(self.root/'proposals')
            INDEX_FILE=str(self.root/'staging/index.json');CHANGELOG_FILE=str(self.root/'changes.json')
        self.staging=Staging();self.target=self.root/'target.py';self.target.write_text(BASE)
        self.manager=CanaryDeploymentManager(staging_manager=self.staging,trust_registry=self.trust)
        self.harness=IndependentBenchmarkHarness()
    def tearDown(self):self.runtime.shutdown();self.temp.cleanup()
    def receipt(self,*,capability='math.compute',results=None,outcome=OutcomeCategory.EXECUTION_ERROR,error_class='ValueError',revision=None,env='fixture-environment',signed=True,committed=True):
        now=time.time();params={'x':2,'y':3};results={} if results is None else results
        r=ExecutionReceipt(receipt_id='rcpt_'+uuid.uuid4().hex,job_id='JOB-'+uuid.uuid4().hex,capability=capability,target=None,
            started_at=now,completed_at=now,input_hash=ExecutionReceipt.hash_payload(params),output_hash=ExecutionReceipt.hash_payload(results),
            exit_code=0 if outcome==OutcomeCategory.SUCCESS else 1,outcome=outcome,results=results,side_effects=[],
            idempotency_key=uuid.uuid4().hex,attempt_number=1,requested_network_policy=NetworkPolicy.OFFLINE_ONLY,actual_transport_used='NONE',
            worker_id='worker_primary',environment_fingerprint=env,error_class=error_class,error_message='fixture internal invariant failed',
            provenance={'source_revision':revision or sha(BASE)})
        if signed:r=r.sign(self.trust.get_keypair('worker_primary')[0])
        if committed:
            self.store.append_event('ExecutionReceiptStoredEvent',r.receipt_id,r.to_dict())
            with self.store._get_connection() as conn:
                conn.execute('INSERT INTO ciph_ipc_jobs (job_id,capability,params,status,attempt_number,receipt_id,worker_signature,created_at) VALUES (?,?,?,?,?,?,?,?)',
                    (r.job_id,r.capability,json.dumps(params),'SUCCEEDED' if r.exit_code==0 else 'FAILED',1,r.receipt_id,r.worker_signature,now))
        return r
    def gap(self):
        existing=self.detector.list_gaps()
        if existing:return existing[0]
        self.detector.ingest_receipt(self.receipt());return self.detector.ingest_receipt(self.receipt())
    def evaluation(self,code=CANDIDATE,**changes):
        args=dict(grant_id='EVAL-'+uuid.uuid4().hex,gap_id=self.gap().gap_id,candidate_hash=sha(code),target_capability='math.compute',
            base_commit_id=sha(BASE),base_file_hash=sha(BASE),allowed_isolation_tier='DISPOSABLE_PROCESS',max_resource_budget={'max_runs':16},
            expires_at=time.time()+600,operator_id=self.op_id)
        args.update(changes);return EvolutionEvaluationGrant(**args).sign(self.op_priv)
    def benchmark(self,code=CANDIDATE,grant=None,cases=None,baseline=BASE):
        return self.harness.evaluate_candidate_against_baseline(baseline,code,'MathComputeCapability',grant or self.evaluation(code),self.trust,
            cases if cases is not None else [{'params':{'x':2,'y':3},'expected':{'result':5,'status':'ok'}}],benchmark_iterations=1)
    def deployment(self,code=CANDIDATE,evidence=None,**changes):
        if evidence is None:
            ok,report,_=self.benchmark(code);self.assertTrue(ok,report.notes);evidence=report.verification_evidence_hash
        args=dict(grant_id='DEPLOY-'+uuid.uuid4().hex,gap_id=self.gap().gap_id,candidate_hash=sha(code),target_capability='math.compute',target_file_path=str(self.target),
            base_commit_id=sha(BASE),base_file_hash=sha(BASE),dependency_changes=(),manifest_changes={},verification_evidence_hashes=(evidence,),
            permitted_stages=('SHADOW','CANARY','PRODUCTION'),expires_at=time.time()+600,operator_id=self.op_id,
            canary_criteria=CanaryCriteria(2,0,{},300),allow_auto_promotion=True)
        args.update(changes);return EvolutionDeploymentGrant(**args).sign(self.op_priv)
    def activate(self,code=CANDIDATE,grant=None):
        grant=grant or self.deployment(code)
        a=self.staging.stage_code('fixture','local test',str(self.target),code)
        ok,msg,cid=self.manager.activate_canary(grant,a['id']);self.assertTrue(ok,msg)
        return grant,cid,a
    def finish(self,cid):
        self.manager.execute_canary(cid,{'x':2,'y':3});return self.manager.execute_canary(cid,{'x':2,'y':3})
