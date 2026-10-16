"""
Gate A0 closure test - register item 0.14: claim leases contend on the epistemic domain.

Class: HARD BLOCKER. Decisions of record: D3 (taxonomy), D2 (dispatch scope).

THE DEFECT THIS TEST EXISTS TO CATCH

Revisions 0-2 leased claims by `claim_id`. Two claims that disagree about the same
(subject, scope, predicate), which is precisely the case the contradiction rule exists for,
carry different claim ids, so both leased cleanly and both workers proceeded. The old torture
test would pass if its fixture happened to map the two claims onto one resource, while the
general model stayed unsound.

WHAT THIS TEST DOES DIFFERENTLY

The two contradictory claims are constructed independently, as separate real Claim objects.
Each domain is derived from that claim's own fields. Nothing in this file asserts that the two
claims share a resource; the implementation must derive that, or the test fails.
"""

import os
import tempfile
import unittest

from ciph.contracts.enums import EpistemicState
from ciph.contracts.epistemic import Claim
from ciph.memory.claim_leases import ClaimLeaseManager, EpistemicDomainConflict


def _claim(claim_id, subject, predicate, value, scope_id="environment-X"):
    """A real Claim, not a stand-in, so the domain is derived from the real contract."""
    return Claim(
        claim_id=claim_id,
        subject=subject,
        predicate=predicate,
        value=value,
        epistemic_state=EpistemicState.HYPOTHESIZED,
        scope_id=scope_id,
    )


class EpistemicDomainLeaseTests(unittest.TestCase):

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(prefix="test_gate_a0_domain_", suffix=".db")
        os.close(handle)
        self.manager = ClaimLeaseManager(db_path=self.db_path)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except OSError:
                pass

    # ------------------------------------------------------------ domain derivation

    def test_contradictory_claims_share_one_domain(self):
        """Independently created, genuinely contradictory claims resolve to one domain."""
        older = _claim("claim_91", "server-A", "version", "1.4")
        newer = _claim("claim_117", "server-A", "version", "1.5")

        self.assertNotEqual(older.claim_id, newer.claim_id)
        self.assertNotEqual(older.value, newer.value)

        self.assertEqual(
            ClaimLeaseManager.domain_of_claim(older),
            ClaimLeaseManager.domain_of_claim(newer),
        )

    def test_different_predicate_is_a_different_domain(self):
        version_claim = _claim("c_v", "server-A", "version", "1.4")
        patch_claim = _claim("c_p", "server-A", "patchlevel", "7")
        self.assertNotEqual(
            ClaimLeaseManager.domain_of_claim(version_claim),
            ClaimLeaseManager.domain_of_claim(patch_claim),
        )

    def test_different_scope_is_a_different_domain(self):
        here = _claim("c_here", "server-A", "version", "1.4", scope_id="environment-X")
        there = _claim("c_there", "server-A", "version", "1.4", scope_id="environment-Y")
        self.assertNotEqual(
            ClaimLeaseManager.domain_of_claim(here),
            ClaimLeaseManager.domain_of_claim(there),
        )

    def test_domain_ignores_case_and_surrounding_space(self):
        plain = _claim("c_1", "server-A", "version", "1.4")
        noisy = _claim("c_2", "  SERVER-A  ", " Version ", "1.4")
        self.assertEqual(
            ClaimLeaseManager.domain_of_claim(plain),
            ClaimLeaseManager.domain_of_claim(noisy),
        )

    # -------------------------------------------------------------------- the invariant

    def test_second_worker_cannot_lease_a_contradictory_domain(self):
        """The point of 0.14: two workers may not act on contradictory knowledge."""
        worker_a_claim = _claim("claim_91", "server-A", "version", "1.4")
        worker_b_claim = _claim("claim_117", "server-A", "version", "1.5")

        domain_a = ClaimLeaseManager.domain_of_claim(worker_a_claim)
        domain_b = ClaimLeaseManager.domain_of_claim(worker_b_claim)

        self.manager.acquire_claim_leases(
            [worker_a_claim.claim_id], "worker-A", "job-1",
            claim_domains={worker_a_claim.claim_id: domain_a},
        )

        with self.assertRaises(EpistemicDomainConflict):
            self.manager.acquire_claim_leases(
                [worker_b_claim.claim_id], "worker-B", "job-2",
                claim_domains={worker_b_claim.claim_id: domain_b},
            )

        holders = {row["worker_id"] for row in self.manager.get_domain_pinners(domain_a)}
        self.assertEqual(holders, {"worker-A"})
        self.assertFalse(self.manager.is_claim_pinned(worker_b_claim.claim_id))

    def test_unrelated_domain_is_not_blocked(self):
        """The repair must not degenerate into a global lock."""
        version_claim = _claim("claim_91", "server-A", "version", "1.4")
        unrelated = _claim("claim_200", "server-B", "uptime", "42")

        domain_version = ClaimLeaseManager.domain_of_claim(version_claim)
        domain_unrelated = ClaimLeaseManager.domain_of_claim(unrelated)

        self.manager.acquire_claim_leases(
            [version_claim.claim_id], "worker-A", "job-1",
            claim_domains={version_claim.claim_id: domain_version},
        )

        lease = self.manager.acquire_claim_leases(
            [unrelated.claim_id], "worker-B", "job-2",
            claim_domains={unrelated.claim_id: domain_unrelated},
        )
        self.assertTrue(lease)
        self.assertTrue(self.manager.is_domain_pinned(domain_unrelated))

    # ------------------------------------------------------------- release and expiry

    def test_release_returns_the_domain(self):
        """Release must actually free the resource, or the lock is a leak."""
        held = _claim("claim_91", "server-A", "version", "1.4")
        blocked = _claim("claim_117", "server-A", "version", "1.5")
        domain = ClaimLeaseManager.domain_of_claim(held)

        lease_id = self.manager.acquire_claim_leases(
            [held.claim_id], "worker-A", "job-1",
            claim_domains={held.claim_id: domain},
        )
        self.manager.release_lease(lease_id)
        self.assertFalse(self.manager.is_domain_pinned(domain))

        second = self.manager.acquire_claim_leases(
            [blocked.claim_id], "worker-B", "job-2",
            claim_domains={blocked.claim_id: domain},
        )
        self.assertTrue(second)

    def test_expiry_returns_the_domain(self):
        """An expired lease must not hold a domain forever."""
        held = _claim("claim_91", "server-A", "version", "1.4")
        later = _claim("claim_117", "server-A", "version", "1.5")
        domain = ClaimLeaseManager.domain_of_claim(held)

        self.manager.acquire_claim_leases(
            [held.claim_id], "worker-A", "job-1",
            ttl_seconds=-1,
            claim_domains={held.claim_id: domain},
        )
        self.manager.cleanup_expired_leases()
        self.assertFalse(self.manager.is_domain_pinned(domain))

        lease = self.manager.acquire_claim_leases(
            [later.claim_id], "worker-B", "job-2",
            claim_domains={later.claim_id: domain},
        )
        self.assertTrue(lease)

    def test_same_worker_may_reacquire_its_own_domain(self):
        """Renewal and multi-job operation by one worker must not deadlock against itself."""
        claim = _claim("claim_91", "server-A", "version", "1.4")
        domain = ClaimLeaseManager.domain_of_claim(claim)

        self.manager.acquire_claim_leases(
            [claim.claim_id], "worker-A", "job-1",
            claim_domains={claim.claim_id: domain},
        )
        second = self.manager.acquire_claim_leases(
            [claim.claim_id], "worker-A", "job-2",
            claim_domains={claim.claim_id: domain},
        )
        self.assertTrue(second)

    # ------------------------------------------------- compatibility boundary, stated plainly

    def test_legacy_callers_remain_unprotected(self):
        """
        A caller that omits claim_domains keeps the pre-0.14 behaviour and is NOT protected
        against contradiction. That is deliberate for backward compatibility, and it is exactly
        why wiring the worker checkout path is the remaining half of register item 0.2: this
        test proves the mechanism is sound, not that every caller uses it.
        """
        first = _claim("claim_91", "server-A", "version", "1.4")
        second = _claim("claim_117", "server-A", "version", "1.5")

        self.manager.acquire_claim_leases([first.claim_id], "worker-A", "job-1")
        self.manager.acquire_claim_leases([second.claim_id], "worker-B", "job-2")

        self.assertTrue(self.manager.is_claim_pinned(first.claim_id))
        self.assertTrue(self.manager.is_claim_pinned(second.claim_id))


if __name__ == "__main__":
    unittest.main()
