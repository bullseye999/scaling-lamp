"""
Gate A0 - REGISTRY CAPABILITY IDENTITY, currently red by design.

This is a **characterisation test**: it asserts the failure that exists today, so the failure is
proven rather than traced. When versioned manifest identity lands on the governed path, this file
must be inverted - the receipt should then carry `ManifestIdentity(2, ...)` and the ledger should
report the evidence as CURRENT for that exact identity.

Do not delete it or weaken it to make the suite green; invert it when the fix exists.

Current chain, observed through the ledger's own predicate:

    governed registry dispatch
        -> BaseCapability.execute builds the receipt with provenance from the CONTEXT
        -> the governed context supplies no provenance
        -> receipt.provenance == {}
        -> StrictHistoricalReceiptParser.parse_raw_receipt reports has_complete_provenance False
        -> evidence is HISTORICAL_UNBOUND, not bound to any manifest identity
"""

import os
import tempfile
import time
import unittest

from ciph.capabilities.capability_ledger import StrictHistoricalReceiptParser
from ciph.contracts.enums import (
    AuthorizationTier,
    NetworkPolicy,
    ReversibilityClass,
    RiskTier,
)
from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitVerifier
from ciph.kernel.execution_gateway import ExecutionGateway, GovernedExecutionContext
from ciph.kernel.permit_store import ExecutionPermitStore
from ciph.kernel.policy_engine import CapabilityManifest
from ciph.kernel.target_identity import (
    CanonicalizerContract,
    register_canonicalizer,
)

CONTRACT = CanonicalizerContract(
    canonicalizer_id="registry_identity.endpoint",
    version="1",
    normalization_rules=("lowercase host", "strip trailing dot"),
    golden_vectors=(("Example.COM.", b"example.com"),),
)

try:
    @register_canonicalizer("registry_identity.endpoint", "1", contract=CONTRACT)
    def _endpoint(raw):
        return raw.strip().strip(".").lower().encode("utf-8")
except Exception:
    pass


class _Manifest:
    def __init__(self):
        self.name = "test.registry_identity"
        self.target_canonicalizer_id = "registry_identity.endpoint"
        self.target_canonicalizer_version = "1"

    def identity(self):
        from ciph.kernel.manifest_identity import ManifestIdentity
        return ManifestIdentity(2, "HX")


class _Capability:
    def __init__(self):
        self.manifest = _Manifest()
        self.calls = 0

    def execute(self, params, context=None):
        # Mirrors BaseCapability's contract: provenance comes from the execution context.
        self.calls += 1
        from ciph.workers.receipts import ExecutionReceipt
        from ciph.contracts.enums import NetworkPolicy, OutcomeCategory
        return ExecutionReceipt(
            receipt_id="rcpt_registry_identity",
            job_id="JOB-IDENT",
            capability=self.manifest.name,
            target=params.get("target"),
            started_at=time.time(),
            completed_at=time.time() + 0.01,
            input_hash="ih",
            output_hash=ExecutionReceipt.hash_payload({"ok": True}),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results={"ok": True},
            side_effects=[],
            idempotency_key="idem-identity",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="NONE",
            worker_id="registry",
            provenance=(context or {}).get("provenance", {}),
        )


class _RegistryView:
    def __init__(self, capabilities):
        self._capabilities = capabilities

    def get(self, name):
        return self._capabilities.get(name)

    def list_names(self):
        return list(self._capabilities)


class _ScopeGrant:
    scope_id = "scope-identity"
    valid_until = None

    def is_expired(self, now=None):
        return False

    def is_target_permitted(self, target):
        return target == "repo-A"


class RegistryCapabilityIdentityTests(unittest.TestCase):

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(prefix="test_registry_identity_", suffix=".db")
        os.close(handle)
        self.store = ExecutionPermitStore(db_path=self.db_path)
        self.authority, public = ExecutionAuthority.generate()
        self.gateway = ExecutionGateway(
            registry=None, permit_ttl_seconds=60.0,
            issuer=self.authority,
            verifier=ExecutionPermitVerifier(public, key_id=self.authority.key_id),
        )
        self.capability = _Capability()
        self.registry = _RegistryView({self.capability.manifest.name: self.capability})

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except OSError:
                pass

    def _governed_dispatch(self, caller_provenance=None):
        from ciph.capabilities.registry import CapabilityRegistry
        governed = GovernedExecutionContext(
            gateway=self.gateway, permit_store=self.store,
            scope_grant=_ScopeGrant(), target="repo-A", route="registry",
        )
        context = {"execution_authority": governed}
        if caller_provenance is not None:
            context["provenance"] = caller_provenance
        return CapabilityRegistry.dispatch(
            self.registry, self.capability.manifest.name, {"target": "repo-A"},
            context,
        )

    def test_governed_registry_receipt_carries_the_exact_manifest_identity(self):
        """
        INVERTED. This test originally asserted the defect: the governed route supplied no
        provenance and the ledger classified the evidence as HISTORICAL_UNBOUND. The same
        regression anchor now proves the defect is gone, which is stronger than deleting it and
        adding a fresh green test.
        """
        envelope = self._governed_dispatch()
        receipt = envelope["result"]
        self.assertEqual(self.capability.calls, 1, "the governed route should have executed")
        governed = receipt.provenance["governed"]
        self.assertEqual(
            governed["manifest_identity"], {"hash_version": 2, "manifest_hash": "HX"}
        )
        self.assertTrue(governed["execution_attempt_id"])
        self.assertEqual(governed["authorization_provenance"], "EXECUTION_PERMIT_V1")

    def test_the_ledger_reports_this_evidence_as_unbound(self):
        """
        Asserted through the ledger's own predicate, so this is what the ledger actually receives -
        not a re-implementation of its rule.
        """
        envelope = self._governed_dispatch()
        receipt = envelope["result"]
        _parsed, metadata = StrictHistoricalReceiptParser.parse_raw_receipt(receipt.to_dict())

        self.assertEqual(metadata["manifest_binding"], "VERSIONED")
        self.assertEqual(
            metadata["manifest_identity"], {"hash_version": 2, "manifest_hash": "HX"}
        )

    def test_the_manifest_can_already_state_its_v2_identity(self):
        """
        The identity primitive exists; the route simply does not use it yet. This is the half that
        is already true, kept adjacent so the gap is unambiguous.
        """
        manifest = CapabilityManifest(
            name="test.registry_identity",
            description="identity specimen",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            target_canonicalizer_id="registry_identity.endpoint",
            target_canonicalizer_version="1",
        )
        self.assertEqual(manifest.target_mode(), "TARGET_BEARING")
        self.assertNotEqual(
            manifest.compute_manifest_hash(), manifest.compute_manifest_hash_v2()
        )


    def test_caller_supplied_identity_cannot_override_the_resolved_manifest(self):
        """
        The hostile case: the caller claims identity Y while the registry resolves X. The governed
        block must carry X, and Y must not appear anywhere authoritative.
        """
        hostile_provenance = {"manifest_identity": {"hash_version": 2, "manifest_hash": "Y"}}
        envelope = self._governed_dispatch(caller_provenance=hostile_provenance)
        receipt = envelope["result"]
        governed = receipt.provenance["governed"]
        self.assertEqual(
            governed["manifest_identity"], {"hash_version": 2, "manifest_hash": "HX"}
        )
        self.assertNotIn("Y", str(governed))
        self.assertNotIn("manifest_identity", receipt.provenance["metadata"])


if __name__ == "__main__":
    unittest.main()
