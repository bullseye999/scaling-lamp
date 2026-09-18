"""Offline test evidence collected through the real token, queue and worker path."""
import time
import uuid
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier, ScopeGrant, ScopeType
from ciph.contracts.epistemic import Claim
from ciph.contracts.enums import DecayProfile

class EvidenceFixture(BaseCapability):
    def __init__(self,name,payload): self.name=name;self.payload=payload
    @property
    def manifest(self):
        return CapabilityManifest(name=self.name,description='Offline evidence fixture',risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,reversibility=ReversibilityClass.READ_ONLY,authorization=AuthorizationTier.AUTO)
    def run(self,params,context=None): return self.payload

def receipt(runtime,payload=None,capability='tor.check_status',subject=None):
    runtime.register_capability(EvidenceFixture(capability, payload if payload is not None else {'status':'ONLINE'}))
    params={'target':subject} if subject else {}
    context={}
    if subject:context['scope_grant']=ScopeGrant(scope_id='fixture-scope',scope_type=ScopeType.LOCAL_SYSTEM,allowed_targets=[subject],valid_until=time.time()+60)
    result=runtime.route_and_execute(capability,params,context=context)
    if result.exit_code:raise AssertionError(result.error_message or result.results)
    return result

def claim(runtime,claim_id=None,*,parents=(),deadline=None,value='ONLINE',subject=None,capability='tor.check_status',predicate='status',decay_profile=DecayProfile.LIVE_NETWORK_STATE,admit=True):
    proof=receipt(runtime,{predicate:value},capability,subject)
    candidate=runtime.claim_projector.project_claim(proof,claim_id=claim_id or 'TEST-'+uuid.uuid4().hex,predicate=predicate,parent_claim_ids=parents,decay_profile=decay_profile)
    if deadline is not None:
        # Validated constructor preserves the cryptographic binding while shortening TTL.
        d=candidate.to_dict();d['freshness_deadline']=deadline
        candidate=Claim(**d,receipt=proof,_receipt_verifier=runtime.claim_projector._ClaimProjector__receipt_verifier)
    if admit:runtime.worldview.admit_claim(candidate)
    return candidate

import tempfile
import unittest
from ciph.runtime import CiphRuntime

class EpistemicTestCase(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.runtime=CiphRuntime(db_path=self.temp.name+'/vault.db')
        self.worldview=self.runtime.worldview
        self.projector=self.runtime.claim_projector
    def tearDown(self):
        self.runtime.close()
        self.temp.cleanup()
    def seed(self,claim_id=None,**kwargs): return claim(self.runtime,claim_id,**kwargs)

def memory_claim(runtime, claim_id='local-record', *, deadline=None, key='phase6-record'):
    """A genuine offline retrieval report, suitable for governed refresh tests."""
    params = {'target': 'local_memory', 'key': key}
    scope = ScopeGrant(scope_id='scope_curiosity_ro', scope_type=ScopeType.LOCAL_SYSTEM,
                       allowed_targets=['local_memory'], valid_until=time.time()+60)
    proof = runtime.route_and_execute('memory.retrieve', params, context={'scope_grant': scope})
    if proof.exit_code:
        raise AssertionError(proof.results)
    candidate = runtime.claim_projector.project_claim(proof, claim_id=claim_id)
    if deadline is not None:
        data = candidate.to_dict(); data['freshness_deadline'] = deadline
        candidate = Claim(**data, receipt=proof)
    runtime.worldview.admit_claim(candidate)
    return candidate


def offline_fixture(capability):
    """Offline command-result fixture for synthetic backend tests only.

    Production manifests stay intact. Live transport requires Phase 7 verification.
    """
    from dataclasses import replace
    class OfflineAdapter(BaseCapability):
        @property
        def manifest(self):
            return replace(capability.manifest, network_policy=NetworkPolicy.OFFLINE_ONLY)
        def run(self, params, context=None):
            return capability.run(params, context)
    return OfflineAdapter()
