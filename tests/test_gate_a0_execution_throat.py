"""
Gate A0 closure test - register items 0.5 and 0.15: the single execution throat.

Class: HARD BLOCKER (0.15) / CONDITIONAL BLOCKER under D2 (0.5). Decisions: D2, D3.

WHAT IS BEING PROVEN
Not "all known routes cross the boundary" - that is route enumeration, and it is tested here too -
but "a route added tomorrow still cannot execute unless it crosses the boundary". That is what the
permit requirement buys, and it is why the executor refuses without one.

THE TWO DENIAL POINTS ARE DIFFERENT AND BOTH ARE TESTED
  issuance   the gateway refuses to mint a permit (missing, expired, non-covering scope)
  execution  a permit exists but cannot authorise this exact operation (reuse, mutation,
             capability mismatch, expiry, revocation)
A test that blurs them proves nothing about either.
"""

import unittest

from ciph.kernel.execution_authority import (
    ExecutionAuthority,
    ExecutionPermitVerifier,
)
from ciph.kernel.execution_gateway import (
    GovernedPreExecutionRefusal,
    DENY_CAPABILITY_MISMATCH,
    DENY_PERMIT_ALREADY_USED,
    DENY_PERMIT_EXPIRED,
    DENY_PERMIT_MISSING,
    DENY_REQUEST_MUTATED,
    DENY_SCOPE_EXPIRED,
    DENY_SCOPE_REQUIRED,
    DENY_SCOPE_REVOKED,
    DENY_TARGET_NOT_PERMITTED,
    DENY_UNKNOWN_CAPABILITY,
    ExecutionDenied,
    ExecutionGateway,
    ExecutionRequest,
    GuardedExecutor,
)


class FakeScopeGrant:
    def __init__(self, scope_id="scope-1", targets=("repo-A",), valid_until=None, expired=False):
        self.scope_id = scope_id
        self.allowed_targets = list(targets)
        self.valid_until = valid_until
        self._expired = expired

    def is_expired(self, now=None):
        return self._expired

    def is_target_permitted(self, target):
        return target in self.allowed_targets


class FakeCapability:
    """Counts executions, so a denial can prove the body never ran."""

    def __init__(self, name="capability.read"):
        self.name = name
        self.calls = 0

    def execute(self, params, context=None):
        self.calls += 1
        return {"ok": True, "params": dict(params)}


class FakeRegistry:
    def __init__(self, names):
        self._names = set(names)

    def get(self, name):
        return FakeCapability(name) if name in self._names else None


class ExecutionThroatTests(unittest.TestCase):

    def setUp(self):
        self.registry = FakeRegistry({"capability.read", "capability.write"})
        # One permit meaning: the gateway mints and verifies the signed artifact itself.
        self.authority, self.authority_public = ExecutionAuthority.generate()
        self.verifier = ExecutionPermitVerifier(
            self.authority_public, key_id=self.authority.key_id
        )
        self.gateway = ExecutionGateway(
            registry=self.registry, permit_ttl_seconds=30.0,
            issuer=self.authority, verifier=self.verifier,
        )
        self.executor = GuardedExecutor(self.gateway)
        self.capability = FakeCapability()

    def _request(self, **overrides):
        base = dict(
            capability="capability.read",
            params={"target": "repo-A"},
            target="repo-A",
            scope_grant=FakeScopeGrant(),
            route="interactive_command",
        )
        base.update(overrides)
        return ExecutionRequest(**base)

    def _expect_issuance_denied(self, reason, request, gateway=None):
        """No permit may be minted, so nothing can execute."""
        target_gateway = gateway or self.gateway
        with self.assertRaises(ExecutionDenied) as caught:
            target_gateway.issue_permit(request)
        self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def _expect_execution_denied(self, reason, request, permit, executor=None):
        """A permit exists but must not authorise this operation, and the body must not run.

        The refusal SURFACES as `GovernedPreExecutionRefusal`: the executor translates the
        authority's denial at the boundary, which is what makes "refused before the claim" a
        structural phase rather than a property of who happened to raise what. The underlying
        `ExecutionDenied` is the `__cause__`, and the reason is carried through verbatim.
        """
        target_executor = executor or self.executor
        capability = FakeCapability()
        with self.assertRaises(GovernedPreExecutionRefusal) as caught:
            target_executor.execute(request, capability, None, permit)
        self.assertEqual(caught.exception.reason, reason)
        self.assertIsInstance(caught.exception.__cause__, ExecutionDenied)
        self.assertEqual(getattr(caught.exception.__cause__, "reason", None), reason)
        self.assertEqual(capability.calls, 0, f"capability body ran despite {reason}")
        return caught.exception

    def test_no_scope_grant_is_refused(self):
        """0.5: the fail-open path is gone. No grant is a refusal, not a skipped check."""
        self._expect_issuance_denied(
            DENY_SCOPE_REQUIRED, self._request(scope_grant=None, target="repo-A")
        )

    def test_grant_that_excludes_the_target_is_refused(self):
        grant = FakeScopeGrant(targets=("repo-B",))
        self._expect_issuance_denied(
            DENY_TARGET_NOT_PERMITTED, self._request(scope_grant=grant, target="repo-A")
        )

    def test_expired_grant_is_refused(self):
        self._expect_issuance_denied(
            DENY_SCOPE_EXPIRED, self._request(scope_grant=FakeScopeGrant(expired=True))
        )

    def test_unknown_capability_is_refused(self):
        self._expect_issuance_denied(
            DENY_UNKNOWN_CAPABILITY, self._request(capability="capability.nonexistent")
        )

    def test_capability_without_a_target_needs_no_scope(self):
        """Deny-by-default applies to target-bearing work, not to every innocent read."""
        request = self._request(target=None, scope_grant=None, params={})
        permit = self.gateway.issue_permit(request)
        result, claim = self.executor.execute(request, self.capability, None, permit)
        self.assertTrue(result["ok"])
        self.assertEqual(self.capability.calls, 1)

    def test_valid_authority_produces_a_permit_and_runs(self):
        request = self._request()
        permit = self.gateway.issue_permit(request)
        result, claim = self.executor.execute(request, self.capability, None, permit)
        self.assertTrue(result["ok"])
        self.assertEqual(self.capability.calls, 1)

    def test_direct_execution_without_a_permit_is_refused(self):
        """
        The law rather than the convention: a future route that reaches the executor directly,
        having forgotten the gateway entirely, is refused instead of executing.
        """
        self._expect_execution_denied(DENY_PERMIT_MISSING, self._request(), None)

    def test_request_modified_after_issuance_is_refused(self):
        request = self._request()
        permit = self.gateway.issue_permit(request)
        mutated = self._request(params={"target": "repo-A", "extra": "smuggled"})
        self._expect_execution_denied(DENY_REQUEST_MUTATED, mutated, permit)

    def test_permit_for_one_capability_presented_to_another_is_refused(self):
        permit = self.gateway.issue_permit(self._request(capability="capability.read"))
        other = self._request(capability="capability.write")
        self._expect_execution_denied(DENY_CAPABILITY_MISMATCH, other, permit)

    def test_permit_cannot_be_reused(self):
        request = self._request()
        permit = self.gateway.issue_permit(request)
        self.executor.execute(request, self.capability, None, permit)
        self.assertEqual(self.capability.calls, 1)
        self._expect_execution_denied(DENY_PERMIT_ALREADY_USED, request, permit)
        self.assertEqual(self.capability.calls, 1, "a reused permit executed a second time")

    def test_expired_permit_is_refused(self):
        gateway = ExecutionGateway(
            registry=self.registry, permit_ttl_seconds=0.01,
            issuer=self.authority, verifier=self.verifier,
        )
        request = self._request()
        permit = gateway.issue_permit(request)
        with self.assertRaises(ExecutionDenied) as caught:
            gateway.authorize(permit, request, now=(permit.payload.expires_at_us / 1_000_000) + 1)
        self.assertEqual(caught.exception.reason, DENY_PERMIT_EXPIRED)

    def test_revocation_after_issuance_invalidates_an_unused_permit(self):
        """
        grant valid -> permit issued -> grant revoked -> the permit must not execute anyway.
        Decision of record: yes, revocation invalidates issued-but-unused permits.
        """
        revoked = {"value": False}
        gateway = ExecutionGateway(
            registry=self.registry,
            issuer=self.authority,
            verifier=self.verifier,
            authorization_state_provider=lambda permit: not revoked["value"],
        )
        executor = GuardedExecutor(gateway)
        request = self._request()
        permit = gateway.issue_permit(request)

        revoked["value"] = True
        self._expect_execution_denied(DENY_SCOPE_REVOKED, request, permit, executor=executor)

    def test_every_route_faces_the_same_boundary(self):
        """
        Route enumeration: proof that every path known today crosses the boundary. The permit
        requirement is what covers the paths nobody has written yet.
        """
        routes = [
            "interactive_command",
            "durable_worker",
            "mission_execution",
            "recovery_replay",
            "replanning",
            "ghost_mesh",
            "red_shadow",
            "direct_executor_invocation",
        ]
        for route in routes:
            with self.subTest(route=route):
                self._expect_issuance_denied(
                    DENY_SCOPE_REQUIRED,
                    self._request(route=route, scope_grant=None),
                )
                granted = self._request(route=route)
                permit = self.gateway.issue_permit(granted)
                capability = FakeCapability()
                self.executor.execute(granted, capability, None, permit)
                self.assertEqual(capability.calls, 1)

    def test_denials_are_counted_per_reason(self):
        """Operators need refusals surfaced, not inferred from absence of activity."""
        self._expect_issuance_denied(DENY_SCOPE_REQUIRED, self._request(scope_grant=None))
        self._expect_issuance_denied(DENY_SCOPE_REQUIRED, self._request(scope_grant=None))
        self.assertEqual(self.gateway.denials.get(DENY_SCOPE_REQUIRED), 2)


if __name__ == "__main__":
    unittest.main()
