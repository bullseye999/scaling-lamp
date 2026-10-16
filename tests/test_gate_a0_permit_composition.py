
"""
Gate A0 closure test - S2.3b composition: the durable permit lane becomes real infrastructure.

Three properties this suite pins:

  ONE CANONICAL CONFIGURATION   the same environment resolves the same signing lineage and the same
                                permit-store namespace; a second construction is not a second
                                execution identity.

  COMPOSITION, NOT AUTHORITY    the runtime and the planner build nothing; authority semantics stay
                                inside the canonical gateway/store.

  BOUNDED DURABLE HORIZON       a durable permit may not outlive the authority behind it, nor the
                                frozen V1 maximum. A horizon beyond that is refused, never extended
                                and never refreshed by a worker.
"""

import pathlib
import tempfile
import time
import unittest

from ciph.kernel.execution_gateway import ExecutionRequest
from ciph.kernel.permit_composition import (
    V1_MAX_PERMIT_LIFETIME_SECONDS,
    DurableHorizonRefused,
    acquire_durable_permit,
    build_durable_permit_dependencies,
    durable_claim_horizon_from_deadline,
    durable_claim_horizon_seconds,
)
from ciph.kernel.permit_issuance import register_or_adopt


class DurablePermitCompositionTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_compose_")
        self.db = f"{self._dir}/vault.db"

    # ---------------------------------------------------------------- lineage

    def test_the_composition_resolves_persistent_lineage_across_builds(self):
        first = build_durable_permit_dependencies(self.db)
        second = build_durable_permit_dependencies(self.db)

        self.assertEqual(
            first.public_key_bytes, second.public_key_bytes
        )
        self.assertEqual(first.key_id, second.key_id)

    def test_a_second_runtime_does_not_create_a_new_execution_identity(self):
        from ciph.runtime import CiphRuntime

        first = CiphRuntime(db_path=self.db).durable_permit_dependencies()
        second = CiphRuntime(db_path=self.db).durable_permit_dependencies()

        self.assertEqual(
            first.public_key_bytes, second.public_key_bytes
        )

    def test_constructing_a_runtime_creates_no_authority_state_until_used(self):
        from ciph.runtime import CiphRuntime

        runtime = CiphRuntime(db_path=self.db)
        self.assertIsNone(runtime._durable_permit_dependencies)
        self.assertIsNone(runtime.trust_registry.get_key("execution_authority_primary"))

        runtime.durable_permit_dependencies()

        self.assertIsNotNone(runtime.trust_registry.get_key("execution_authority_primary"))

    # ---------------------------------------------------------------- composition

    def test_the_runtime_and_planner_construct_no_authority_objects(self):
        for rel in ("ciph/runtime.py", "ciph/planner/dag_planner.py"):
            with self.subTest(module=rel):
                source = pathlib.Path(rel).read_text(encoding="utf-8")
                for forbidden in ("ExecutionGateway(", "ExecutionAuthority(", "SignedExecutionPermit("):
                    self.assertNotIn(forbidden, source)

    # ---------------------------------------------------------------- horizon

    def test_a_horizon_beyond_the_v1_max_is_refused(self):
        with self.assertRaises(DurableHorizonRefused) as caught:
            durable_claim_horizon_seconds(V1_MAX_PERMIT_LIFETIME_SECONDS + 1.0)
        self.assertEqual(caught.exception.reason, "CLAIM_HORIZON_EXCEEDS_V1_MAX")

    def test_the_horizon_is_bounded_by_the_authorization_grant(self):
        now = time.time()
        horizon = durable_claim_horizon_seconds(
            600.0, now=now, authorization_grant_expires_at=now + 120.0
        )
        self.assertAlmostEqual(horizon, 120.0, places=1)

        with self.assertRaises(DurableHorizonRefused) as caught:
            durable_claim_horizon_seconds(
                600.0, now=now, authorization_grant_expires_at=now - 1.0
            )
        self.assertEqual(caught.exception.reason, "DURABLE_HORIZON_EXHAUSTED")

    def test_a_durable_permit_is_claimable_beyond_the_interactive_ttl(self):
        """Queue residence must not consume a TTL designed for near-immediate dispatch."""
        deps = build_durable_permit_dependencies(self.db)
        request = ExecutionRequest(
            capability="cap.read", params={"k": "v"}, target=None,
            logical_action_id="L-DURABLE", action_fingerprint="A", route="TEST",
        )
        permit = deps.gateway.issue_permit(request)
        self.assertTrue(register_or_adopt(deps.permit_store, permit).registered)

        # 120 seconds in: well past the old 30-60s interactive assumption, still inside the
        # durable horizon, and still ISSUED rather than EXPIRED.
        later = time.time() + 120.0
        self.assertEqual(deps.permit_store.state_of(permit.payload.permit_id, now=later), "ISSUED")


class DurablePermitAcquisitionTests(unittest.TestCase):
    """The single entry point the four production producers will call."""

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_acquire_")
        self.db = f"{self._dir}/vault.db"
        self.deps = build_durable_permit_dependencies(self.db)

    def _provider(self):
        return self.deps

    def _request(self, logical_action_id="L-ACQ", fingerprint="A"):
        return ExecutionRequest(
            capability="cap.read", params={"k": "v"}, target=None,
            logical_action_id=logical_action_id, action_fingerprint=fingerprint, route="TEST",
        )

    def test_the_bundle_exposes_verification_material_not_the_signer(self):
        self.assertFalse(hasattr(self.deps, "authority"))
        self.assertTrue(self.deps.public_key_bytes)
        # A producer must be able to verify, never to sign.
        self.assertFalse(hasattr(self.deps, "issue_permit"))

    def test_acquire_applies_the_bounded_horizon_to_the_permit_expiry(self):
        deadline = time.time() + 120.0
        carriage = acquire_durable_permit(
            self._provider, self._request(), "JOB-ACQ-1", claim_deadline=deadline
        )
        payload = carriage.permit.payload
        # The permit never outlives the declared claim deadline.
        self.assertLessEqual(payload.expires_at_us, int(deadline * 1_000_000) + 1)
        self.assertLessEqual(payload.expires_at_us - payload.issued_at_us, 120 * 1_000_000)

    def test_an_oversized_horizon_refuses_before_any_permit_exists(self):
        with self.assertRaises(DurableHorizonRefused):
            acquire_durable_permit(
                self._provider, self._request("L-ACQ-2"), "JOB-ACQ-2",
                claim_deadline=time.time() + V1_MAX_PERMIT_LIFETIME_SECONDS + 60.0,
            )
        self.assertIsNone(self.deps.permit_store._blocking_permit_row("L-ACQ-2"))

    def test_acquire_returns_the_canonical_permit_for_a_new_action(self):
        carriage = acquire_durable_permit(
            self._provider, self._request("L-ACQ-3"), "JOB-ACQ-3",
            claim_deadline=time.time() + 300.0
        )
        self.assertTrue(carriage.accepted)
        self.assertEqual(carriage.reason, "REGISTERED_NEW")
        self.assertIsNotNone(carriage.permit)
        self.assertEqual(carriage.issuance.owning_job_id, "JOB-ACQ-3")

    def test_acquire_adopts_the_owning_job_without_carrying_a_candidate(self):
        acquire_durable_permit(
            self._provider, self._request("L-ACQ-4"), "JOB-ACQ-4",
            claim_deadline=time.time() + 300.0
        )
        retry = acquire_durable_permit(
            self._provider, self._request("L-ACQ-4"), "JOB-ACQ-OTHER",
            claim_deadline=time.time() + 300.0
        )
        self.assertTrue(retry.accepted)
        self.assertIsNone(retry.permit)                       # the losing candidate is never carried
        self.assertEqual(retry.adopt_job_id, "JOB-ACQ-4")


class ClaimDeadlineLawTests(unittest.TestCase):
    """The producer states a timing fact; the authority layer derives the horizon."""

    def _now(self):
        return time.time()

    def test_a_grant_expiring_before_the_deadline_bounds_the_horizon(self):
        now = self._now()
        horizon = durable_claim_horizon_from_deadline(
            now + 600.0, now=now, authorization_grant_expires_at=now + 90.0
        )
        self.assertAlmostEqual(horizon, 90.0, places=1)

    def test_a_deadline_in_the_past_is_refused(self):
        with self.assertRaises(DurableHorizonRefused) as caught:
            durable_claim_horizon_from_deadline(self._now() - 1.0)
        self.assertEqual(caught.exception.reason, "CLAIM_DEADLINE_ALREADY_PASSED")

    def test_a_missing_deadline_is_refused(self):
        with self.assertRaises(DurableHorizonRefused) as caught:
            durable_claim_horizon_from_deadline(None)
        self.assertEqual(caught.exception.reason, "CLAIM_DEADLINE_REQUIRED")

    def test_a_deadline_beyond_the_v1_max_is_refused(self):
        with self.assertRaises(DurableHorizonRefused) as caught:
            durable_claim_horizon_from_deadline(
                self._now() + V1_MAX_PERMIT_LIFETIME_SECONDS + 60.0
            )
        self.assertEqual(caught.exception.reason, "CLAIM_HORIZON_EXCEEDS_V1_MAX")


if __name__ == "__main__":
    unittest.main()
