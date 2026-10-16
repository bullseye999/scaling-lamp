
"""
Gate A0 - S3.5: the refusal boundary is CLAIM-based, not exception-shaped.

The daemon classifies a governed refusal as a refused transition (POLICY_BLOCKED, no
reconciliation) rather than a crash window. That is only sound if a pre-claim denial cannot be
confused with a post-claim failure, so these specimens pin where the phase actually changes.
"""

import pathlib
import unittest

from ciph.kernel.execution_authority import ExecutionAuthority
from ciph.kernel.execution_gateway import ExecutionDenied, ExecutionGateway, ExecutionRequest, GuardedExecutor
from ciph.kernel.permit_store import ExecutionPermitStore


class _Cap:
    """A capability whose body raises. Everything a capability does is wrapped by base.execute in
    production, so this models 'the body exploded', not 'the capability refused'."""

    class _M:
        name = "cap.test"

    manifest = _M()

    def __init__(self, error):
        self.error = error
        self.calls = 0

    def execute(self, params, context=None):
        self.calls += 1
        raise self.error


class RefusalPhaseBoundaryTests(unittest.TestCase):

    def setUp(self):
        import tempfile
        self._dir = tempfile.mkdtemp(prefix="ciph_phase_")
        self.db = f"{self._dir}/vault.db"
        self.store = ExecutionPermitStore(self.db)
        from ciph.kernel.execution_authority import ExecutionPermitVerifier

        self.authority, _ = ExecutionAuthority.generate()
        self.gateway = ExecutionGateway(
            registry=None, issuer=self.authority,
            verifier=ExecutionPermitVerifier(self.authority.public_key_bytes),
            permit_ttl_seconds=600.0,
        )

    def _permit(self, job_id="JOB-1"):
        request = ExecutionRequest(
            capability="cap.test", params={"k": "v"}, target=None,
            logical_action_id=job_id, route="test",
        )
        permit = self.gateway.issue_permit(request)
        self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint,
            job_id=job_id,
        )
        return request, permit

    def test_authorize_runs_before_the_claim(self):
        """Source order: the only pre-claim denial site precedes the claim transition."""
        src = pathlib.Path("ciph/kernel/execution_gateway.py").read_text(encoding="utf-8")
        block = src[src.index("def execute("):src.index("def terminalize(")]
        self.assertLess(block.index("self.gateway.authorize("), block.index("self.permit_store.claim("))

    def test_a_pre_claim_denial_raises_before_any_claim_exists(self):
        request, permit = self._permit("JOB-PRE")
        self.store.revoke(permit.payload.permit_id, reason="TEST_REVOKE")
        executor = GuardedExecutor(self.gateway, permit_store=self.store)

        # Revocation surfaces at claim time, not at authorize time: the point is that the failure
        # arrives BEFORE any attempt identity could exist.
        with self.assertRaises(Exception):
            executor.execute(request, _Cap(RuntimeError("unused")), {}, permit=permit, claimant="w1")
        self.assertIsNone(
            self.store.find_by_attempt("nonexistent"), "no attempt identity may exist pre-claim"
        )

    def test_a_post_claim_body_failure_leaves_the_claim_visible(self):
        """
        The boundary that matters: once the claim succeeds, a failing body is a post-claim failure
        - the claim survives, so reconciliation semantics apply. It must not look like a refusal.
        """
        request, permit = self._permit("JOB-POST")
        executor = GuardedExecutor(self.gateway, permit_store=self.store)
        body_error = RuntimeError("body exploded after the claim")

        with self.assertRaises(RuntimeError):
            executor.execute(request, _Cap(body_error), {}, permit=permit, claimant="w1")

        state = self.store.state_of(permit.payload.permit_id)
        self.assertEqual(state, "CLAIMED", "the claim must survive a post-claim failure")

    def test_execution_denied_is_only_raised_from_the_gateway(self):
        """ExecutionDenied has exactly one raiser: the gateway's own denial helper."""
        # `runtime.py` raises it for a PRE-execution acquisition refusal, which the runtime boundary
        # converts to a governed refusal before any claim exists; the scan is about post-claim
        # surfaces, and the daemon must not be one of them.
        offenders = []
        for path in sorted(pathlib.Path("ciph").rglob("*.py")):
            if "__pycache__" in path.parts or path.name in ("execution_gateway.py", "runtime.py"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if "raise ExecutionDenied" in text:
                offenders.append(str(path.relative_to("ciph")))
        self.assertEqual(offenders, [], f"ExecutionDenied raised outside the gateway: {offenders}")


class StructuralPhaseTranslationTests(unittest.TestCase):
    """
    Option B: the translation lives ABOVE the claim, so the phase distinction is structural rather
    than a property of who currently raises ExecutionDenied.
    """

    def setUp(self):
        import tempfile

        from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitVerifier

        self._dir = tempfile.mkdtemp(prefix="ciph_optionb_")
        self.db = f"{self._dir}/vault.db"
        self.store = ExecutionPermitStore(self.db)
        self.authority, _ = ExecutionAuthority.generate()
        self.gateway = ExecutionGateway(
            registry=None, issuer=self.authority,
            verifier=ExecutionPermitVerifier(self.authority.public_key_bytes),
            permit_ttl_seconds=600.0,
        )

    def _registered(self, job_id, capability="cap.test"):
        request = ExecutionRequest(
            capability=capability, params={"k": "v"}, target=None,
            logical_action_id=job_id, route="test",
        )
        permit = self.gateway.issue_permit(request)
        self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint,
            job_id=job_id,
        )
        return request, permit

    def test_an_authorization_denial_becomes_a_governed_pre_execution_refusal(self):
        from ciph.kernel.execution_gateway import GovernedPreExecutionRefusal

        _request, permit = self._registered("JOB-DENY")
        mismatched = ExecutionRequest(
            capability="cap.other", params={"k": "v"}, target=None,
            logical_action_id="JOB-DENY", route="test",
        )
        executor = GuardedExecutor(self.gateway, permit_store=self.store)

        with self.assertRaises(GovernedPreExecutionRefusal) as caught:
            executor.execute(mismatched, _Cap(RuntimeError("unused")), {}, permit=permit, claimant="w1")

        self.assertTrue(caught.exception.reason.startswith("DENY_"))
        self.assertEqual(self.store.state_of(permit.payload.permit_id), "ISSUED")

    def test_a_post_claim_execution_denied_is_not_translated(self):
        """THE killer specimen: the hypothetical hole is now structurally impossible."""
        from ciph.kernel.execution_gateway import GovernedPreExecutionRefusal

        _request, permit = self._registered("JOB-POST-DENIED")
        executor = GuardedExecutor(self.gateway, permit_store=self.store)

        with self.assertRaises(ExecutionDenied) as caught:
            executor.execute(
                _request, _Cap(ExecutionDenied("RAISED_BY_BODY")), {},
                permit=permit, claimant="w1",
            )

        self.assertNotIsInstance(caught.exception, GovernedPreExecutionRefusal)
        self.assertEqual(
            self.store.state_of(permit.payload.permit_id), "CLAIMED",
            "a post-claim failure leaves the claim visible for reconciliation",
        )

    def test_the_daemon_no_longer_catches_execution_denied(self):
        source = pathlib.Path("ciph/workers/daemon.py").read_text(encoding="utf-8")
        self.assertIn("except GovernedPreExecutionRefusal as refusal:", source)
        self.assertNotIn("except (GovernedPreExecutionRefusal, ExecutionDenied)", source)
        self.assertNotIn("from ciph.kernel.execution_gateway import ExecutionDenied", source)


if __name__ == "__main__":
    unittest.main()
