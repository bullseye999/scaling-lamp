
"""
Gate A0 closure test - S2.1: the logical action is the canonical issuance unit.

Two invariants, both enforced inside the store's write transaction:

  LOGICAL ACTION IDENTITY
      once logical_action_id L has been observed with fingerprint A, L may never later bind to
      fingerprint B - in any state, including REVOKED and EXPIRED.

  BLOCKING PERMIT UNIQUENESS
      for L, at most one ISSUANCE_BLOCKING permit (ISSUED / CLAIMED / CONSUMED) exists.

The point is that an ordinary retry is not an authority event: it either adopts the permit that
already exists or is refused, and it can never manufacture a second spendable artifact.
"""

import concurrent.futures
import hashlib
import tempfile
import unittest

from ciph.kernel.execution_authority import ExecutionAuthority
from ciph.kernel.permit_store import (
    DENY_LOGICAL_ACTION_CONFLICT,
    DENY_LOGICAL_ACTION_REQUIRES_FINGERPRINT,
    ISSUANCE_ALREADY_ISSUED,
    PermitStoreError,
    ExecutionPermitStore,
    STATE_CLAIMED,
    STATE_CONSUMED,
    STATE_EXPIRED,
    STATE_ISSUED,
)
from ciph.kernel.execution_authority import ExecutionPermitPayload, time_us


class LogicalActionIssuanceLawTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_logical_action_")
        self.store = ExecutionPermitStore(f"{self._dir}/permits.db")
        self.authority, _ = ExecutionAuthority.generate()

    # ------------------------------------------------------------------ helpers

    def _permit(self, logical_action_id, fingerprint, ttl=600.0):
        payload = ExecutionPermitPayload.build(
            capability_id="cap.read",
            request_digest="rd",
            action_fingerprint=fingerprint,
            issued_at_us=time_us(),
            ttl_seconds=ttl,
            logical_action_id=logical_action_id,
        )
        return self.authority.issue_permit(payload)

    def _register(self, permit, job_id=None, expires_at=None):
        return self.store.register(
            permit_id=permit.payload.permit_id,
            digest=permit.permit_digest(),
            issued_at=permit.payload.issued_at_us / 1_000_000,
            expires_at=expires_at if expires_at is not None
            else permit.payload.expires_at_us / 1_000_000,
            logical_action_id=permit.payload.logical_action_id,
            action_fingerprint=permit.payload.action_fingerprint,
            job_id=job_id,
        )

    def _rows_for(self, logical_action_id):
        with self.store._connect() as conn:
            return conn.execute(
                "SELECT permit_id, state, job_id FROM execution_permits "
                "WHERE logical_action_id = ? ORDER BY permit_id;",
                (logical_action_id,),
            ).fetchall()

    # ------------------------------------------------------------------ specimens

    def test_1_sequential_reissue_of_the_same_action_returns_already_issued(self):
        first = self._permit("L1", "A")
        self.assertTrue(self._register(first, job_id="JOB-1").registered)
        second = self._permit("L1", "A")

        result = self._register(second)

        self.assertFalse(result.registered)
        self.assertTrue(result.already_issued)
        self.assertEqual(result.reason, ISSUANCE_ALREADY_ISSUED)
        self.assertEqual(result.permit_id, first.payload.permit_id)
        self.assertEqual(result.owning_job_id, "JOB-1")
        self.assertEqual(len(self._rows_for("L1")), 1)

    def test_2_concurrent_issuance_of_the_same_action_yields_one_identity(self):
        def attempt(_):
            return self._register(self._permit("L2", "A"))

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))

        registered = [r for r in results if r.registered]
        already = [r for r in results if r.already_issued]
        self.assertEqual(len(registered), 1)
        self.assertEqual(len(already), 1)
        self.assertEqual(already[0].permit_id, registered[0].permit_id)
        self.assertEqual(len(self._rows_for("L2")), 1)

    def test_3_concurrent_different_fingerprints_for_one_action_conflict(self):
        def attempt(fingerprint):
            try:
                return self._register(self._permit("L3", fingerprint))
            except PermitStoreError as error:
                return error

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, ("A", "B")))

        winners = [r for r in results if not isinstance(r, PermitStoreError) and r.registered]
        losers = [r for r in results if isinstance(r, PermitStoreError)]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 1)
        self.assertEqual(losers[0].reason, DENY_LOGICAL_ACTION_CONFLICT)
        self.assertEqual(len(self._rows_for("L3")), 1)

    def test_4_a_claimed_action_cannot_be_reissued(self):
        permit = self._permit("L4", "A")
        self._register(permit)
        self.store.claim(permit.payload.permit_id, "worker-A", digest=permit.permit_digest())

        result = self._register(self._permit("L4", "A"))

        self.assertTrue(result.already_issued)
        self.assertEqual(result.state, STATE_CLAIMED)
        self.assertEqual(len(self._rows_for("L4")), 1)

    def test_5_a_consumed_action_is_permanently_blocked(self):
        permit = self._permit("L5", "A")
        self._register(permit)
        self.store.claim(permit.payload.permit_id, "worker-A", digest=permit.permit_digest())
        self.store.consume(permit.payload.permit_id, "worker-A")

        result = self._register(self._permit("L5", "A"))

        self.assertTrue(result.already_issued)
        self.assertEqual(result.state, STATE_CONSUMED)
        self.assertEqual(len(self._rows_for("L5")), 1)

    def test_6_a_revoked_action_may_be_replaced_with_the_same_fingerprint(self):
        first = self._permit("L6", "A")
        self._register(first)
        self.assertTrue(self.store.revoke(first.payload.permit_id, reason="ENQUEUE_FAILED"))

        replacement = self._register(self._permit("L6", "A"))

        self.assertTrue(replacement.registered)
        self.assertEqual(len(self._rows_for("L6")), 2)

    def test_7_an_expired_action_may_be_replaced_with_the_same_fingerprint(self):
        # Deterministic expiry: register with an already-past expiry rather than sleeping. Expiry is
        # derived, so the stored row remains ISSUED until a transition materialises it.
        first = self._permit("L7", "A")
        self._register(first, expires_at=0.0)

        replacement = self._register(self._permit("L7", "A"))

        self.assertTrue(replacement.registered)
        rows = self._rows_for("L7")
        self.assertEqual(len(rows), 2)
        states = {row["permit_id"]: row["state"] for row in rows}
        self.assertEqual(states[first.payload.permit_id], STATE_EXPIRED)
        self.assertEqual(states[replacement.permit_id], STATE_ISSUED)

    def test_8_replacement_with_a_different_fingerprint_is_a_hard_conflict(self):
        """The identity invariant survives revocation: L is bound to A forever."""
        first = self._permit("L8", "A")
        self._register(first)
        self.store.revoke(first.payload.permit_id, reason="ENQUEUE_FAILED")

        with self.assertRaises(PermitStoreError) as caught:
            self._register(self._permit("L8", "B"))

        self.assertEqual(caught.exception.reason, DENY_LOGICAL_ACTION_CONFLICT)
        self.assertEqual(len(self._rows_for("L8")), 1)

    def test_9_a_loser_cannot_mint_authority_when_the_owning_job_is_unretrievable(self):
        """
        Crash between registration and queue persistence. The retry sees ALREADY_ISSUED with no job
        to adopt, and must refuse - temporary liveness loss beats a second spendable permit.
        """
        self._register(self._permit("L9", "A"))

        result = self._register(self._permit("L9", "A"))

        self.assertTrue(result.already_issued)
        self.assertIsNone(result.owning_job_id)
        self.assertEqual(len(self._rows_for("L9")), 1)

    def test_a_logical_action_without_a_fingerprint_is_refused(self):
        """A logical action with no fingerprint is not a well-formed issuance unit."""
        permit = self._permit("L10", "A")
        with self.assertRaises(PermitStoreError) as caught:
            self.store.register(
                permit_id=permit.payload.permit_id,
                digest=permit.permit_digest(),
                issued_at=permit.payload.issued_at_us / 1_000_000,
                expires_at=permit.payload.expires_at_us / 1_000_000,
                logical_action_id="L10",
            )
        self.assertEqual(
            caught.exception.reason, DENY_LOGICAL_ACTION_REQUIRES_FINGERPRINT
        )


if __name__ == "__main__":
    unittest.main()
