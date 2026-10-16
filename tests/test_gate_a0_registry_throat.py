"""
Gate A0 closure test - Steps C and D: the registry path through the throat.

REGISTRY PROVENANCE CUTOVER. Decision of record: registry hard cutover, global epoch still pending.

THE DISTINCTION THIS FILE PROTECTS
Registry execution has exactly two outcomes:
    authority present -> permit -> claim -> execution
    authority absent  -> REFUSED, body never runs

There is deliberately no third path. No compatibility bypass, and no "execute anyway then label
it legacy", because a label applied after the effect is auditing rather than enforcement.

The registry's `dispatch` is exercised unbound against a stand-in registry so the real production
logic runs without constructing the full manifest machinery; that limitation is stated rather than
implied.
"""

import os
import tempfile
import time
import unittest

from ciph.capabilities.registry import CapabilityRegistry
from ciph.kernel.execution_authority import (
    ExecutionAuthority,
    ExecutionPermitVerifier,
)
from ciph.kernel.execution_gateway import ExecutionGateway, GovernedExecutionContext
from ciph.kernel.permit_store import ExecutionPermitStore, PermitStoreError, STATE_CLAIMED, STATE_CONSUMED


class _Manifest:
    def __init__(self, name, canonicalizer_id="test.endpoint.v1", canonicalizer_version="1"):
        self.name = name
        self.target_canonicalizer_id = canonicalizer_id
        self.target_canonicalizer_version = canonicalizer_version

    def identity(self):
        from ciph.kernel.manifest_identity import ManifestIdentity
        return ManifestIdentity(2, "FIXTURE")


def identity(self):
        from ciph.kernel.manifest_identity import ManifestIdentity
        return ManifestIdentity(2, "FIXTURE")


class _Capability:
    def __init__(self, name="test.capability", canonicalizer=True):
        self.manifest = _Manifest(name) if canonicalizer else _Manifest(name, None, None)
        self.calls = 0

    def execute(self, params, context=None):
        self.calls += 1
        return {"ok": True}


class _ScopeGrant:
    def __init__(self, targets=("repo-A",), expired=False):
        self.scope_id = "scope-1"
        self.allowed_targets = list(targets)
        self.valid_until = None
        self._expired = expired

    def is_expired(self, now=None):
        return self._expired

    def is_target_permitted(self, target):
        return target in self.allowed_targets


class _RegistryView:
    """Minimal stand-in with the surface `dispatch` actually uses."""

    def __init__(self, capabilities):
        self._capabilities = capabilities

    def get(self, name):
        return self._capabilities.get(name)

    def list_names(self):
        return list(self._capabilities)


def _register_test_canonicalizer():
    from ciph.kernel.target_identity import register_canonicalizer
    try:
        @register_canonicalizer("test.endpoint.v1", "1")
        def _canonical(raw):
            return raw.strip().lower().encode("utf-8")
    except Exception:
        pass


class RegistryThroatTests(unittest.TestCase):

    def setUp(self):
        _register_test_canonicalizer()
        handle, self.db_path = tempfile.mkstemp(prefix="test_registry_throat_", suffix=".db")
        os.close(handle)
        self.store = ExecutionPermitStore(db_path=self.db_path)
        self.authority, self.authority_public = ExecutionAuthority.generate()
        self.verifier = ExecutionPermitVerifier(
            self.authority_public, key_id=self.authority.key_id
        )
        self.gateway = ExecutionGateway(
            registry=None, permit_ttl_seconds=60.0,
            issuer=self.authority, verifier=self.verifier,
        )
        self.capability = _Capability()
        self.registry = _RegistryView({self.capability.manifest.name: self.capability})

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except OSError:
                pass

    def _context(self, target="repo-A", scope_grant=None, capability=None):
        return {
            "execution_authority": GovernedExecutionContext(
                gateway=self.gateway,
                issuer=None,
                permit_store=self.store,
                scope_grant=scope_grant if scope_grant is not None else _ScopeGrant(),
                target=target,
                route="registry",
            )
        }

    def _dispatch(self, context, name="test.capability", params=None):
        return CapabilityRegistry.dispatch(
            self.registry, name, params or {"target": "repo-A"}, context
        )

    # ------------------------------------------------------------- hard cutover

    def test_dispatch_without_authority_is_refused_and_the_body_never_runs(self):
        with self.assertRaises(PermissionError) as caught:
            self._dispatch(context=None)
        self.assertIn("AUTHORITY_REQUIRED", str(caught.exception))
        self.assertEqual(self.capability.calls, 0)

    def test_dispatch_with_an_empty_context_is_refused(self):
        with self.assertRaises(PermissionError):
            self._dispatch(context={})
        self.assertEqual(self.capability.calls, 0)

    def test_the_registry_never_mints_legacy_provenance(self):
        """
        During the migration window the daemon is still a named bypass, so the global legacy lane
        exists. The registry-local cutover must still forbid it here.
        """
        source = (pathlib.Path(__file__).resolve().parents[1]
                  / "ciph/capabilities/registry.py").read_text(encoding="utf-8")
        self.assertNotIn("LEGACY_PRE_PERMIT", source)
        with self.assertRaises(PermissionError):
            self._dispatch(context=None)

    # --------------------------------------------------------- canonicalizer rule

    def test_target_bearing_capability_without_a_canonicalizer_is_refused(self):
        bare = _Capability(name="test.bare", canonicalizer=False)
        registry = _RegistryView({bare.manifest.name: bare})
        with self.assertRaises(PermissionError) as caught:
            CapabilityRegistry.dispatch(
                registry, "test.bare", {"target": "repo-A"}, self._context()
            )
        self.assertIn("CANONICALIZER_REQUIRED", str(caught.exception))
        self.assertEqual(bare.calls, 0)

    # ------------------------------------------------------------- governed path

    def test_valid_authority_executes_and_claims_the_permit(self):
        result = self._dispatch(self._context())
        self.assertEqual(result["status"], "EXECUTED")
        self.assertEqual(self.capability.calls, 1)
        permit = result["permit"]
        claim = result["claim"]
        self.assertIsNotNone(claim)
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CLAIMED)
        self.assertEqual(claim.claimant, "registry")

    def test_scope_is_evaluated_before_authority_is_minted(self):
        with self.assertRaises(Exception):
            self._dispatch(self._context(scope_grant=_ScopeGrant(targets=("repo-B",))))
        self.assertEqual(self.capability.calls, 0)

    def test_no_scope_grant_is_refused_rather_than_assumed(self):
        governed = GovernedExecutionContext(
            gateway=self.gateway, issuer=None, permit_store=self.store,
            scope_grant=None, target="repo-A", route="registry",
        )
        with self.assertRaises(Exception):
            self._dispatch({"execution_authority": governed})
        self.assertEqual(self.capability.calls, 0)

    # --------------------------------------------------- receipt before CONSUMED

    def test_terminal_receipt_is_persisted_before_the_permit_is_consumed(self):
        from ciph.kernel.execution_gateway import GuardedExecutor
        result = self._dispatch(self._context())
        permit, claim = result["permit"], result["claim"]
        executor = GuardedExecutor(self.gateway, permit_store=self.store)
        persisted = []

        receipt = executor.terminalize(
            permit, claim,
            receipt_factory=lambda c: {"attempt": c.execution_attempt_id},
            receipt_sink=persisted.append,
        )
        self.assertEqual(len(persisted), 1)
        self.assertEqual(receipt["attempt"], claim.execution_attempt_id)
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CONSUMED)

    def test_failed_receipt_persistence_leaves_the_permit_claimed_not_consumed(self):
        """
        Raw return must never justify CONSUMED. If terminal evidence cannot be made durable, the
        attempt stays CLAIMED with no receipt, which is the reconciliation signal.
        """
        from ciph.kernel.execution_gateway import GuardedExecutor
        result = self._dispatch(self._context())
        permit, claim = result["permit"], result["claim"]
        executor = GuardedExecutor(self.gateway, permit_store=self.store)

        def _failing_sink(receipt):
            raise IOError("receipt store unavailable")

        with self.assertRaises(IOError):
            executor.terminalize(
                permit, claim,
                receipt_factory=lambda c: {"attempt": c.execution_attempt_id},
                receipt_sink=_failing_sink,
            )
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CLAIMED)
        # And the permit still cannot be re-claimed: it is not reusable authority.
        with self.assertRaises(PermitStoreError):
            self.store.claim(permit.payload.permit_id, "someone-else")

    def test_a_signed_permit_without_a_durable_row_is_not_executable(self):
        """
        A signed blob alone is never usable authority. The permit here is minted and never
        registered, so it is cryptographically sound and operationally unusable - which is the
        intended asymmetry: mint, register durably, then use.
        """
        from ciph.kernel.execution_gateway import GuardedExecutor, ExecutionRequest
        request = ExecutionRequest(
            capability="test.capability", params={"target": "repo-A"},
            target="repo-A", scope_grant=_ScopeGrant(), route="registry",
        )
        permit = self.gateway.issue_permit(request)
        executor = GuardedExecutor(self.gateway, permit_store=self.store)
        with self.assertRaises(PermitStoreError):
            executor.execute(request, self.capability, None, permit, claimant="registry")
        self.assertEqual(self.capability.calls, 0)


import pathlib  # noqa: E402  (used by the source-scan assertion above)

if __name__ == "__main__":
    unittest.main()
