"""Phase 8 authorization, exact-byte activation, and real isolation acceptance."""
import os,sys,time
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch
from phase8_test_support import Phase8Case,BASE,CANDIDATE,BROKEN,sha
from ciph.contracts.evolution import CanaryCriteria,EvolutionDeploymentGrant
from ciph.contracts.base import ContractValidationError
from ciph.capabilities.evolution import HotReloadEngine
from ciph.evolution.isolated_execution import execute_candidate

class TestPhase80(Phase8Case):
    def test_grantless_apply_cannot_write(self):
        a=self.staging.stage_code('test','inert staging',str(self.target),CANDIDATE)
        self.assertFalse(self.staging.apply(a['id'])[0]);self.assertEqual(self.target.read_text(),BASE)
        self.assertEqual(Path(a['staged_file']).read_text(),CANDIDATE)
        self.assertFalse(a['sandbox_passed'])
    def test_detached_hot_reload_cannot_activate(self):
        grant=self.deployment(evidence=sha('invented'))
        result=self.runtime.hot_reload_evolved_capability(CANDIDATE,'MathComputeCapability',auth_grant=grant)
        self.assertFalse(result['success']);self.assertEqual(result['status'],'GOVERNED_CANARY_REQUIRED')
        self.assertIsNone(self.runtime.registry.get('math.compute'))
    def test_evaluation_grant_cannot_deploy(self):
        a=self.staging.stage_code('test','test',str(self.target),CANDIDATE)
        self.assertFalse(self.staging.apply(a['id'],self.evaluation(),self.trust)[0])
    def test_wrong_signer_and_expired_or_future_grants(self):
        from ciph.kernel.crypto_identity import Ed25519KeyManager
        grant=self.evaluation()
        for changed in (replace(grant,expires_at=time.time()-1),replace(grant,created_at=time.time()+100),replace(grant,expires_at=float('nan'))):
            self.assertFalse(changed.verify_signature(self.trust)[0])
        self.assertFalse(grant.sign(Ed25519KeyManager.generate_keypair()[0]).verify_signature(self.trust)[0])
        self.assertFalse(grant.sign(self.trust.get_keypair('worker_primary')[0]).verify_signature(self.trust)[0])
    def test_invalid_criteria_and_evidence_digests(self):
        for size in (0,True,1.5):
            with self.assertRaises(ContractValidationError):CanaryCriteria(size,0,{},60)
        with self.assertRaises(ContractValidationError):self.deployment(evidence='invented')
        with self.assertRaises(ContractValidationError):self.deployment(evidence=sha('fake'),permitted_stages=('CANARY',),allow_auto_promotion=True)
    def test_candidate_never_mutates_supervisor_memory(self):
        code=CANDIDATE+'\nimport sys\nsys._phase8_pollution=True\n'
        out,_=execute_candidate(code,'MathComputeCapability',{'x':2,'y':3},'DISPOSABLE_PROCESS',{})
        self.assertEqual(out['result'],5);self.assertFalse(hasattr(sys,'_phase8_pollution'))
    def test_actual_filesystem_network_and_secret_boundary(self):
        canary=self.root/'private-canary';canary.write_text('disposable-secret')
        os.environ['PHASE8_CANARY_SECRET']='do-not-inherit'
        code=CANDIDATE.replace('return {"result":params.get("x",0)+params.get("y",0),"status":"ok"}', '''import os,socket
        blocked=False
        try:open(params['path']).read()
        except (PermissionError,FileNotFoundError):blocked=True
        net=False
        try:socket.socket()
        except OSError:net=True
        return {"blocked":blocked,"net":net,"secret":os.environ.get('PHASE8_CANARY_SECRET')}''')
        try:
            output,_=execute_candidate(code,'MathComputeCapability',{'path':str(canary)},'DISPOSABLE_PROCESS',{})
            self.assertEqual(output,{'blocked':True,'net':True,'secret':None})
        finally:os.environ.pop('PHASE8_CANARY_SECRET',None)
    def test_unsupported_isolation_never_falls_back(self):
        with self.assertRaisesRegex(ValueError,'SANDBOX_UNAVAILABLE'):execute_candidate(CANDIDATE,'MathComputeCapability',{},'UNKNOWN',{})
    def test_production_replace_and_exact_rollback(self):
        grant,cid,_=self.activate();result=self.finish(cid)
        self.assertEqual(result['status'],'PROMOTED',result);self.assertEqual(self.target.read_bytes(),CANDIDATE.encode())
        self.assertTrue(self.staging.rollback(str(self.target),grant.candidate_hash,deployment_grant=grant,trust_registry=self.trust)[0])
        self.assertEqual(self.target.read_bytes(),BASE.encode())
    def test_concurrent_change_is_preserved(self):
        grant,cid,_=self.activate();self.target.write_text('newer revision\n');result=self.finish(cid)
        self.assertEqual(result['status'],'RECONCILIATION_REQUIRED',result);self.assertEqual(self.target.read_text(),'newer revision\n')
    def test_rollback_cannot_clobber_newer_revision(self):
        grant,cid,_=self.activate();self.finish(cid);self.target.write_text('newer revision\n')
        self.assertFalse(self.staging.rollback(str(self.target),grant.candidate_hash,deployment_grant=grant,trust_registry=self.trust)[0])
        self.assertEqual(self.target.read_text(),'newer revision\n')
    def test_symlink_target_rejected(self):
        grant=self.deployment();a=self.staging.stage_code('test','test',str(self.target),CANDIDATE)
        other=self.root/'other.py';other.write_text(BASE);self.target.unlink();self.target.symlink_to(other)
        self.assertFalse(self.manager.activate_canary(grant,a['id'])[0]);self.assertEqual(other.read_text(),BASE)
