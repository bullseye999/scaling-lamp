
"""
Gate A0 - attempt-attributable evidence.

Post-claim evidence must state which attempt produced it. These specimens run a real job through the
daemon and pin that the receipt carries the genuine PermitClaim identity.

A governed job still needs its transport token (session/replay), so the fixture supplies both: the
token admits the job, the permit authorizes execution.
"""

import tempfile
import unittest

from ciph.contracts.enums import ScopeType
from ciph.kernel.policy_engine import ScopeGrant
from ciph.runtime import CiphRuntime
from permit_test_support import enqueue_permit_bearing_job


class ClaimBoundEvidenceTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_claimprov_")
        self.runtime = CiphRuntime(db_path=f"{self._dir}/vault.db")

    def _scope(self, scope_id):
        return ScopeGrant(
            scope_id=scope_id, scope_type=ScopeType.LOCAL_SYSTEM, allowed_targets=["local_memory"]
        ).sign(self.runtime.kernel_priv_bytes, signing_key_id=self.runtime.kernel_key_id)

    def _run(self, scope_id):
        params = {"key": "k", "target": "local_memory"}
        plan_id, step_id = f"plan_{scope_id}", "s1"
        token = self.runtime.mint_execution_token(
            capability="memory.retrieve", params=params,
            plan_id=plan_id, step_id=step_id, scope_grant=self._scope(scope_id),
        )
        fixture = enqueue_permit_bearing_job(
            self.runtime, capability="memory.retrieve", params=params,
            scope_targets=["local_memory"], scope_id=scope_id,
            plan_id=plan_id, step_id=step_id, execution_token=token,
        )
        receipt = self.runtime.worker_daemon.drain_once(
            worker_id="w1", target_job_id=fixture.job_id
        )
        return fixture, receipt

    def test_a_claimed_execution_records_the_real_attempt_identity(self):
        fixture, receipt = self._run("scope_claim_1")
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt.outcome.value, "SUCCESS", receipt.error_message)

        block = (receipt.provenance or {}).get("governed_authorization")
        self.assertIsNotNone(block, "post-claim evidence must state which attempt produced it")
        self.assertEqual(block["execution_permit_id"], fixture.permit_id)
        self.assertEqual(block["execution_permit_digest"], fixture.permit.permit_digest())
        self.assertEqual(block["authorization_generation"], 0)
        self.assertTrue(block["execution_attempt_id"])

        canonical = self.runtime.durable_permit_dependencies().permit_store.find_by_attempt(
            block["execution_attempt_id"]
        )
        self.assertIsNotNone(canonical, "the attempt on the evidence must be the canonical claim")
        self.assertEqual(canonical["permit_id"], fixture.permit_id)

    def test_the_pre_existing_trajectory_is_preserved_alongside_the_claim(self):
        _fixture, receipt = self._run("scope_claim_2")
        provenance = receipt.provenance or {}
        self.assertIn("governed_authorization", provenance)
        self.assertIn("reversibility", provenance)


class PostClaimAttributionTests(unittest.TestCase):
    """
    Every post-claim path must name the attempt, including the ones that explode.

    The binding is installed before enrichment and before the body runs, so attribution does not
    depend on either succeeding.
    """

    def setUp(self):
        import tempfile
        from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitVerifier
        from ciph.kernel.execution_gateway import ExecutionGateway
        from ciph.kernel.permit_store import ExecutionPermitStore

        self._dir = tempfile.mkdtemp(prefix="ciph_binding_")
        self.db = f"{self._dir}/vault.db"
        self.store = ExecutionPermitStore(self.db)
        self.authority, _ = ExecutionAuthority.generate()
        self.gateway = ExecutionGateway(
            registry=None, issuer=self.authority,
            verifier=ExecutionPermitVerifier(self.authority.public_key_bytes),
            permit_ttl_seconds=600.0,
        )

    def _registered(self, job_id):
        from ciph.kernel.execution_gateway import ExecutionRequest
        request = ExecutionRequest(capability="cap.test", params={"k": "v"}, target=None,
                                   logical_action_id=job_id, route="test")
        permit = self.gateway.issue_permit(request)
        self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint, job_id=job_id,
        )
        return request, permit

    def test_a_failing_body_still_leaves_the_attempt_binding(self):
        from ciph.kernel.execution_gateway import ClaimBindingSlot, GuardedExecutor

        request, permit = self._registered("JOB-BIND-1")
        slot = ClaimBindingSlot()

        class _Boom:
            class _M: name = "cap.test"
            manifest = _M()

            def execute(self, params, context=None):
                raise RuntimeError("body exploded after the claim")

        with self.assertRaises(RuntimeError):
            GuardedExecutor(self.gateway, permit_store=self.store).execute(
                request, _Boom(), {"claim_binding_slot": slot}, permit=permit, claimant="w1",
            )

        self.assertIsNotNone(slot.binding, "a post-claim failure must still name the attempt")
        self.assertEqual(slot.binding.permit_id, permit.payload.permit_id)
        self.assertEqual(slot.binding.permit_digest, permit.permit_digest())
        self.assertTrue(slot.binding.execution_attempt_id)
        self.assertEqual(self.store.state_of(permit.payload.permit_id), "CLAIMED")

    def test_a_pre_claim_refusal_leaves_no_binding(self):
        from ciph.kernel.execution_gateway import ClaimBindingSlot, GuardedExecutor, GovernedPreExecutionRefusal

        _request, permit = self._registered("JOB-BIND-2")
        from ciph.kernel.execution_gateway import ExecutionRequest
        mismatched = ExecutionRequest(capability="cap.other", params={}, target=None,
                                      logical_action_id="JOB-BIND-2", route="test")
        slot = ClaimBindingSlot()

        class _Never:
            class _M: name = "cap.other"
            manifest = _M()

            def execute(self, params, context=None):
                raise AssertionError("must not run")

        with self.assertRaises(GovernedPreExecutionRefusal):
            GuardedExecutor(self.gateway, permit_store=self.store).execute(
                mismatched, _Never(), {"claim_binding_slot": slot}, permit=permit, claimant="w1",
            )
        self.assertIsNone(slot.binding, "a pre-claim refusal must fabricate no attribution")


class ClaimBindingSlotReuseTests(unittest.TestCase):
    """
    A stale binding must be impossible to mistake for the current execution.

    The guard runs BEFORE authorization, so a reused slot cannot even produce a refusal whose
    handler might read the previous execution's attribution.
    """

    def setUp(self):
        import tempfile
        from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitVerifier
        from ciph.kernel.execution_gateway import ExecutionGateway
        from ciph.kernel.permit_store import ExecutionPermitStore

        self._dir = tempfile.mkdtemp(prefix="ciph_reuse_")
        self.db = f"{self._dir}/vault.db"
        self.store = ExecutionPermitStore(self.db)
        self.authority, _ = ExecutionAuthority.generate()
        self.gateway = ExecutionGateway(
            registry=None, issuer=self.authority,
            verifier=ExecutionPermitVerifier(self.authority.public_key_bytes),
            permit_ttl_seconds=600.0,
        )

    def _registered(self, job_id, capability="cap.test"):
        from ciph.kernel.execution_gateway import ExecutionRequest
        request = ExecutionRequest(capability=capability, params={"k": "v"}, target=None,
                                   logical_action_id=job_id, route="test")
        permit = self.gateway.issue_permit(request)
        self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint, job_id=job_id,
        )
        return request, permit

    class _Cap:
        class _M: name = "cap.test"
        manifest = _M()

        def execute(self, params, context=None):
            return {"ok": True}

    class _Other:
        class _M: name = "cap.other"
        manifest = _M()

        def execute(self, params, context=None):
            raise AssertionError("must not run")

    def test_a_reused_slot_is_refused_before_anything_else_happens(self):
        from ciph.kernel.execution_gateway import ClaimBindingSlot, GuardedExecutor

        request, permit = self._registered("JOB-REUSE-1")
        slot = ClaimBindingSlot()
        executor = GuardedExecutor(self.gateway, permit_store=self.store)
        executor.execute(request, self._Cap(), {"claim_binding_slot": slot},
                         permit=permit, claimant="w1")
        first = slot.binding
        self.assertIsNotNone(first)

        with self.assertRaises(RuntimeError) as caught:
            executor.execute(request, self._Cap(), {"claim_binding_slot": slot},
                             permit=permit, claimant="w2")

        self.assertIn("ALREADY_ASSIGNED", str(caught.exception))
        self.assertIs(slot.binding, first, "the previous attribution must remain untouched")

    def test_a_reused_slot_cannot_launder_a_pre_claim_refusal(self):
        """The pathological case: B refuses pre-claim, and the handler must not read A's binding."""
        from ciph.kernel.execution_gateway import (
            ClaimBindingSlot, ExecutionRequest, GuardedExecutor,
        )

        request_a, permit_a = self._registered("JOB-REUSE-A")
        slot = ClaimBindingSlot()
        executor = GuardedExecutor(self.gateway, permit_store=self.store)
        executor.execute(request_a, self._Cap(), {"claim_binding_slot": slot},
                         permit=permit_a, claimant="w1")
        stale = slot.binding

        mismatched = ExecutionRequest(capability="cap.other", params={}, target=None,
                                      logical_action_id="JOB-REUSE-A", route="test")
        with self.assertRaises(RuntimeError):
            executor.execute(mismatched, self._Other(), {"claim_binding_slot": slot},
                             permit=permit_a, claimant="w2")

        self.assertIs(slot.binding, stale)
        self.assertEqual(slot.binding.permit_id, permit_a.payload.permit_id)


class CanonicalClaimProvenanceTests(unittest.TestCase):
    """
    ONE helper produces the governed block; every post-claim handler consumes it.

    Corroboration is by IDENTITY, never by lifecycle state - a consumed permit still produced its
    attempt.
    """

    def setUp(self):
        import tempfile
        from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitVerifier
        from ciph.kernel.execution_gateway import ExecutionGateway
        from ciph.kernel.permit_store import ExecutionPermitStore

        self._dir = tempfile.mkdtemp(prefix="ciph_canon_")
        self.db = f"{self._dir}/vault.db"
        self.store = ExecutionPermitStore(self.db)
        self.authority, _ = ExecutionAuthority.generate()
        self.gateway = ExecutionGateway(
            registry=None, issuer=self.authority,
            verifier=ExecutionPermitVerifier(self.authority.public_key_bytes),
            permit_ttl_seconds=600.0,
        )

    class _Cap:
        class _M: name = "cap.test"
        manifest = _M()

        def execute(self, params, context=None):
            return {"ok": True}

    def _execute(self, job_id):
        from ciph.kernel.execution_gateway import (
            ClaimBindingSlot, ExecutionRequest, GuardedExecutor,
        )
        request = ExecutionRequest(capability="cap.test", params={"k": "v"}, target=None,
                                   logical_action_id=job_id, route="test")
        permit = self.gateway.issue_permit(request)
        self.store.register(
            permit_id=permit.payload.permit_id, digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint, job_id=job_id,
        )
        slot = ClaimBindingSlot()
        GuardedExecutor(self.gateway, permit_store=self.store).execute(
            request, self._Cap(), {"claim_binding_slot": slot}, permit=permit, claimant="w1",
        )
        return slot, permit

    def test_a_claimed_execution_yields_one_corroborated_block(self):
        from ciph.kernel.retry_authority import canonical_claim_provenance
        slot, permit = self._execute("JOB-CANON-1")

        block = canonical_claim_provenance(slot, self.store)

        self.assertEqual(block["execution_permit_id"], permit.payload.permit_id)
        self.assertEqual(block["authorization_generation"], 0)
        self.assertEqual(block["logical_action_id"], "JOB-CANON-1")
        self.assertTrue(block["execution_attempt_id"])

    def test_no_binding_means_no_attribution_expected(self):
        from ciph.kernel.execution_gateway import ClaimBindingSlot
        from ciph.kernel.retry_authority import canonical_claim_provenance

        self.assertIsNone(canonical_claim_provenance(ClaimBindingSlot(), self.store))

    def test_a_consumed_permit_still_corroborates_its_attempt(self):
        """Identity, not lifecycle: terminalization consuming the permit must not orphan the claim."""
        from ciph.kernel.retry_authority import canonical_claim_provenance
        slot, permit = self._execute("JOB-CANON-2")
        self.store.consume(permit.payload.permit_id, "w1")

        block = canonical_claim_provenance(slot, self.store)

        self.assertIsNotNone(block)
        self.assertEqual(block["execution_attempt_id"], slot.binding.execution_attempt_id)

    def test_a_disagreeing_binding_is_an_integrity_conflict(self):
        from ciph.kernel.execution_gateway import ClaimBinding, ClaimBindingSlot
        from ciph.kernel.retry_authority import ClaimProvenanceConflict, canonical_claim_provenance
        slot, permit = self._execute("JOB-CANON-3")
        tampered = ClaimBindingSlot()
        tampered.binding = ClaimBinding(
            execution_attempt_id=slot.binding.execution_attempt_id,
            permit_id="permit_someone_else", permit_digest=slot.binding.permit_digest,
            authorization_generation=0, logical_action_id=slot.binding.logical_action_id,
        )

        with self.assertRaises(ClaimProvenanceConflict):
            canonical_claim_provenance(tampered, self.store)

    def test_an_uncorroboratable_binding_is_unavailable_not_invented(self):
        from ciph.kernel.execution_gateway import ClaimBinding, ClaimBindingSlot
        from ciph.kernel.retry_authority import ClaimProvenanceUnavailable, canonical_claim_provenance
        orphan = ClaimBindingSlot()
        orphan.binding = ClaimBinding(
            execution_attempt_id="attempt_not_in_store", permit_id="p", permit_digest="d",
            authorization_generation=0, logical_action_id="L",
        )

        with self.assertRaises(ClaimProvenanceUnavailable):
            canonical_claim_provenance(orphan, self.store)


class SlotIsExecutionLocalTests(unittest.TestCase):
    """
    Fresh slot per execution is not enough: the REFERENCE to it must be execution-local too.

    This daemon runs several worker threads, so a slot stored on the instance would let job A's
    failure handler read job B's binding. Frame-local is per-invocation by construction.
    """

    def test_the_daemon_never_stores_the_active_slot_on_itself(self):
        import pathlib
        source = pathlib.Path("ciph/workers/daemon.py").read_text(encoding="utf-8")
        self.assertNotIn(
            "self._claim_binding_slot", source,
            "a shared slot pointer would let one job's failure be attributed to another",
        )
        self.assertIn("claim_binding_slot = ClaimBindingSlot()", source)

    def test_the_daemon_is_not_single_flight(self):
        """Evidence that execution-locality was the correct choice, not merely the tidier one."""
        import pathlib
        source = pathlib.Path("ciph/workers/daemon.py").read_text(encoding="utf-8")
        self.assertIn("self.num_workers", source)
        self.assertIn("def _worker_loop(", source)


if __name__ == "__main__":
    unittest.main()
