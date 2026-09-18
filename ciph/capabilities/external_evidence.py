"""External evidence capability: source policy is fixed by trusted registration."""
import sys
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest
from ciph.contracts.enums import NetworkPolicy, RiskTier, ReversibilityClass, AuthorizationTier
from ciph.perception.external_sources import ExternalSource

class ExternalEvidenceCapability(BaseCapability):
    def __init__(self, source: ExternalSource):
        if not isinstance(source, ExternalSource): raise TypeError('EXTERNAL_SOURCE_REQUIRED')
        self.source = source

    @property
    def manifest(self):
        return CapabilityManifest(name='external.observe.'+self.source.source_id,
            description='Collect attributed external HTTP evidence via the trusted Tor broker',
            risk_tier=RiskTier.LOW, network_policy=NetworkPolicy.TOR_MANDATORY,
            reversibility=ReversibilityClass.READ_ONLY, authorization=AuthorizationTier.AUTO,
            timeout_seconds=self.source.timeout_seconds + 5)

    def get_sandbox_command(self, params):
        return [sys.executable, '-I', '-S', '-c',
                'import json,sys; d=json.load(sys.stdin); print(json.dumps(d)); sys.exit(0 if d.get("success") else 1)']

    def run(self, params, context=None):
        raise PermissionError('EXTERNAL_EVIDENCE_REQUIRES_BROKER_AND_SANDBOX')
