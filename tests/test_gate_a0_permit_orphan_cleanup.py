
"""
Gate A0 closure test - S2.2 producer-side orphan hygiene.

S2.1 is safety; this is cleanliness. The specimens pin the two ways S2.2 could accidentally undo
S2.1: revoking authority that belongs to a prior attempt, and revoking on an ambiguous outcome.
"""

import tempfile
import unittest

from ciph.kernel.execution_authority import ExecutionAuthority, ExecutionPermitPayload, time_us
from ciph.kernel.permit_issuance import (
    OrphanCleanupFailed,
    handle_enqueue_failure,
    register_or_adopt,
    revoke_orphan,
)
from ciph.kernel.permit_store import ExecutionPermitStore, STATE_ISSUED, STATE_REVOKED


class OrphanCleanupTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_orphan_")
        self.store = ExecutionPermitStore(f"{self._dir}/permits.db")
        self.authority, _ = ExecutionAuthority.generate()

    def _permit(self, logical_action_id="L", fingerprint="A"):
        payload = ExecutionPermitPayload.build(
            capability_id="cap.read",
            request_digest="rd",
            action_fingerprint=fingerprint,
            issued_at_us=time_us(),
            ttl_seconds=600.0,
            logical_action_id=logical_action_id,
        )
        return self.authority.issue_permit(payload)

    def _state(self, permit):
        return self.store.state_of(permit.payload.permit_id)

    def test_1_new_permit_with_a_known_enqueue_failure_is_revoked(self):
        permit = self._permit()
        issuance = register_or_adopt(self.store, permit)

        cleaned = handle_enqueue_failure(self.store, issuance, known_rejection=True)

        self.assertTrue(cleaned)
        self.assertEqual(self._state(permit), STATE_REVOKED)

    def test_2_new_permit_with_a_successful_enqueue_stays_issued(self):
        permit = self._permit()
        register_or_adopt(self.store, permit, job_id="JOB-1")

        # A successful enqueue takes no cleanup path at all.
        self.assertEqual(self._state(permit), STATE_ISSUED)

    def test_3_already_issued_permit_is_never_revoked_by_a_retry(self):
        """The retry adopts canonical authority; it must not kill the original job's permit."""
        original = self._permit()
        register_or_adopt(self.store, original, job_id="JOB-ORIGINAL")
        retry = self._permit()

        adoption = register_or_adopt(self.store, retry)
        cleaned = handle_enqueue_failure(self.store, adoption, known_rejection=True)

        self.assertFalse(adoption.registered)
        self.assertFalse(cleaned)
        self.assertEqual(self._state(original), STATE_ISSUED)

    def test_4_an_ambiguous_outcome_never_revokes(self):
        """
        The producer lost the acknowledgement. The job may exist and carry this permit, so the
        permit must survive for the retry to adopt.
        """
        permit = self._permit()
        issuance = register_or_adopt(self.store, permit)

        cleaned = handle_enqueue_failure(self.store, issuance, known_rejection=False)

        self.assertFalse(cleaned)
        self.assertEqual(self._state(permit), STATE_ISSUED)

    def test_5_a_failed_cleanup_is_surfaced_not_swallowed(self):
        permit = self._permit()
        issuance = register_or_adopt(self.store, permit)
        # The permit moved on (claimed then consumed) before cleanup ran, so revoke must not take.
        self.store.claim(permit.payload.permit_id, "worker-A", digest=permit.permit_digest())
        self.store.consume(permit.payload.permit_id, "worker-A")

        with self.assertRaises(OrphanCleanupFailed):
            revoke_orphan(self.store, issuance)

    def test_6_a_revoked_orphan_permits_a_canonical_replacement(self):
        permit = self._permit("L6", "A")
        issuance = register_or_adopt(self.store, permit)
        handle_enqueue_failure(self.store, issuance, known_rejection=True)

        replacement = register_or_adopt(self.store, self._permit("L6", "A"))

        self.assertTrue(replacement.registered)

    def test_7_cleanup_only_speaks_for_the_attempt_that_registered(self):
        original = self._permit("L7", "A")
        register_or_adopt(self.store, original)
        adoption = register_or_adopt(self.store, self._permit("L7", "A"))

        self.assertFalse(revoke_orphan(self.store, adoption))
        self.assertEqual(self._state(original), STATE_ISSUED)


if __name__ == "__main__":
    unittest.main()
