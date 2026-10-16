"""
Gate A0 - the executor's provenance hook.

The enabling piece for registry wiring: `execution_attempt_id` does not exist until the claim
succeeds, so the executor takes a builder and invokes it *after* claiming, then hands the completed
provenance to the capability. These tests pin that ordering, because getting it wrong would either
invent an attempt id before it exists or hand the capability provenance without one.
"""

import os
import tempfile
import unittest

from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitVerifier
from ciph.kernel.execution_gateway import (
    ExecutionGateway,
    ExecutionRequest,
    GuardedExecutor,
)
from ciph.kernel.permit_store import ExecutionPermitStore, STATE_CLAIMED


class _ScopeGrant:
    scope_id = "scope-hook"
    valid_until = None

    def is_expired(self, now=None):
        return False

    def is_target_permitted(self, target):
        return True


class _Capability:
    """Records the context it was handed, so the test can assert what execution saw."""

    def __init__(self):
        self.received_context = None

    def execute(self, params, context=None):
        self.received_context = context
        return {"ok": True}


class ExecutorProvenanceHookTests(unittest.TestCase):

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(prefix="test_hook_", suffix=".db")
        os.close(handle)
        self.store = ExecutionPermitStore(db_path=self.db_path)
        self.authority, public = ExecutionAuthority.generate()
        self.gateway = ExecutionGateway(
            registry=None, permit_ttl_seconds=60.0,
            issuer=self.authority,
            verifier=ExecutionPermitVerifier(public, key_id=self.authority.key_id),
        )
        self.executor = GuardedExecutor(self.gateway, permit_store=self.store)
        self.capability = _Capability()

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except OSError:
                pass

    def _request(self, registered=True):
        request = ExecutionRequest(
            capability="test.hook", params={"target": "repo-A"},
            target="repo-A", scope_grant=_ScopeGrant(), route="registry",
        )
        permit = self.gateway.issue_permit(request)
        if registered:
            self.store.register(
                permit_id=permit.payload.permit_id,
                digest=permit.permit_digest(),
                issued_at=permit.payload.issued_at_us / 1_000_000,
                expires_at=permit.payload.expires_at_us / 1_000_000,
            )
        return request, permit

    def test_the_builder_receives_the_claim_so_the_attempt_id_can_exist(self):
        request, permit = self._request()
        seen = {}

        def builder(claim):
            seen["attempt"] = claim.execution_attempt_id
            return {"governed": {"execution_attempt_id": claim.execution_attempt_id}}

        _result, claim = self.executor.execute(
            request, self.capability, {}, permit, provenance_builder=builder
        )
        self.assertEqual(seen["attempt"], claim.execution_attempt_id)
        self.assertTrue(claim.execution_attempt_id)

    def test_the_capability_receives_the_completed_provenance(self):
        request, permit = self._request()
        _result, claim = self.executor.execute(
            request, self.capability, {},
            permit,
            provenance_builder=lambda c: {"governed": {"execution_attempt_id": c.execution_attempt_id}},
        )
        self.assertEqual(
            self.capability.received_context["provenance"]["governed"]["execution_attempt_id"],
            claim.execution_attempt_id,
        )

    def test_the_callers_context_mapping_is_not_mutated(self):
        request, permit = self._request()
        caller_context = {"execution_authority": object()}
        self.executor.execute(
            request, self.capability, caller_context, permit,
            provenance_builder=lambda c: {"governed": {}},
        )
        self.assertNotIn(
            "provenance", caller_context,
            "the executor must not write provenance into the caller's own mapping",
        )

    def test_without_a_builder_the_capability_sees_the_original_context(self):
        request, permit = self._request()
        caller_context = {"note": "unchanged"}
        self.executor.execute(request, self.capability, caller_context, permit)
        self.assertIs(self.capability.received_context, caller_context)
        self.assertNotIn("provenance", self.capability.received_context)

    def test_a_failing_builder_leaves_the_permit_claimed_not_consumed(self):
        """
        The attempt owns the permit and never executed. That is a reconciliation case, not a
        success, so the permit must not be consumed and the capability must not run.
        """
        request, permit = self._request()

        def _explode(claim):
            raise RuntimeError("provenance assembly failed")

        with self.assertRaises(RuntimeError):
            self.executor.execute(
                request, self.capability, {}, permit, provenance_builder=_explode
            )
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CLAIMED)
        self.assertIsNone(self.capability.received_context)


if __name__ == "__main__":
    unittest.main()
