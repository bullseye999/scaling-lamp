"""
Gate A0 closure test - register item 0.2: worker checkout acquires epistemic domain leases.

Class: HARD BLOCKER. Decisions of record: D2, D3.

THE DEFECT
Revisions 0-2 left the worker checkout path with no claim relationship at all: a worker could
take a job whose dependencies rested on knowledge another worker was simultaneously contradicting.
0.14 built the domain-lease mechanism; this test covers its adoption at the checkout boundary.

THE TORTURE LIST (from the 4.0 closure plan)
  worker crash after lease acquisition
  worker crash during execution
  lease expiry
  duplicate worker checkout
  two jobs with partially overlapping epistemic domains
  three-way contradiction rather than only pairwise

Domains are derived from real Claim objects, never mapped by hand, so the fixture cannot encode
the answer.
"""

import os
import tempfile
import time
import unittest

from ciph.contracts.enums import EpistemicState
from ciph.contracts.epistemic import Claim
from ciph.memory.claim_leases import ClaimLeaseManager, domain_lease_conflicts
from ciph.workers.ipc_queue import IPCJobQueue


def _domain(subject, predicate, value, claim_id, scope_id="environment-X"):
    claim = Claim(
        claim_id=claim_id,
        subject=subject,
        predicate=predicate,
        value=value,
        epistemic_state=EpistemicState.HYPOTHESIZED,
        scope_id=scope_id,
    )
    return ClaimLeaseManager.domain_of_claim(claim)


class WorkerDomainEnforcementTests(unittest.TestCase):

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(prefix="test_gate_a0_worker_", suffix=".db")
        os.close(handle)
        self.queue = IPCJobQueue(db_path=self.db_path)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except OSError:
                pass

    def _enqueue(self, name, domains=None, deps=None, **kwargs):
        return self.queue.enqueue_legacy_job_for_test(
            capability="memory.retrieve",
            params={"target": name},
            job_id=name,
            epistemic_domains=domains,
            epistemic_dependencies=deps,
            **kwargs
        )

    def _status(self, job_id):
        with self.queue._get_connection() as conn:
            row = conn.execute(
                "SELECT status, dependency_block_reason FROM ciph_ipc_jobs WHERE job_id = ?;",
                (job_id,),
            ).fetchone()
        return row["status"], row["dependency_block_reason"]

    def _held_by_anyone(self, domain_ids):
        with self.queue._get_connection() as conn:
            return domain_lease_conflicts(conn, domain_ids, "nobody", time.time())

    def test_job_without_declared_domains_is_unaffected(self):
        """Declaration is opt-in: existing callers keep working exactly as before."""
        self._enqueue("job-plain")
        leased = self.queue.lease_next_job("worker-A")
        self.assertIsNotNone(leased)
        self.assertEqual(leased["job_id"], "job-plain")

    def test_worker_cannot_lease_a_job_on_a_domain_another_worker_holds(self):
        domain = _domain("server-A", "version", "1.4", "claim_91")
        contradiction = _domain("server-A", "version", "1.5", "claim_117")
        self.assertEqual(domain, contradiction)

        self._enqueue("job-first", domains=[domain], deps=["claim_91"])
        self._enqueue("job-second", domains=[contradiction], deps=["claim_117"])

        first = self.queue.lease_next_job("worker-A")
        self.assertEqual(first["job_id"], "job-first")

        second = self.queue.lease_next_job("worker-B")
        self.assertIsNone(second, "worker-B leased work resting on a contradicted claim")

        status, reason = self._status("job-second")
        self.assertEqual(status, "QUEUED")
        self.assertIn("EPISTEMIC_DOMAIN_CONFLICT", reason or "")

    def test_lease_set_is_all_or_nothing(self):
        """
        Partially overlapping dependency sets must not leave a half-acquired state behind.
        job-first holds d1 and d2; job-second wants d2 and d3, so it must acquire nothing.
        """
        d1 = _domain("server-A", "version", "1.4", "c1")
        d2 = _domain("server-A", "patchlevel", "7", "c2")
        d3 = _domain("server-B", "uptime", "42", "c3")
        self.assertEqual(len({d1, d2, d3}), 3)

        self._enqueue("job-first", domains=[d1, d2])
        self._enqueue("job-second", domains=[d2, d3])

        self.assertEqual(self.queue.lease_next_job("worker-A")["job_id"], "job-first")
        self.assertIsNone(self.queue.lease_next_job("worker-B"))

        self.assertEqual(self._held_by_anyone([d3]), [])
        self.assertEqual(self._held_by_anyone([d2]), [d2])

    def test_three_way_contradiction_admits_exactly_one_holder(self):
        shared = _domain("server-A", "version", "1.4", "c_a")
        self.assertEqual(_domain("server-A", "version", "1.5", "c_b"), shared)
        self.assertEqual(_domain("server-A", "version", "1.6", "c_c"), shared)

        for name in ("job-a", "job-b", "job-c"):
            self._enqueue(name, domains=[shared])

        leased = []
        for worker in ("worker-A", "worker-B", "worker-C"):
            result = self.queue.lease_next_job(worker)
            if result:
                leased.append(result["job_id"])

        self.assertEqual(len(leased), 1, f"more than one holder for one domain: {leased}")

    def test_duplicate_checkout_of_a_leased_job_is_refused(self):
        domain = _domain("server-A", "version", "1.4", "c1")
        self._enqueue("job-first", domains=[domain])
        self.assertIsNotNone(self.queue.lease_next_job("worker-A"))
        self.assertIsNone(self.queue.lease_next_job("worker-B", target_job_id="job-first"))

    def test_completion_releases_the_domain(self):
        domain = _domain("server-A", "version", "1.4", "c1")
        other = _domain("server-A", "version", "1.5", "c2")
        self._enqueue("job-first", domains=[domain])
        self._enqueue("job-second", domains=[other])

        self.queue.lease_next_job("worker-A")
        self.assertTrue(self.queue.complete_job("job-first", "worker-A", result={"ok": True}))

        self.assertIsNotNone(
            self.queue.lease_next_job("worker-B"),
            "the domain stayed locked after a successful completion",
        )

    def test_crash_after_acquisition_expires_the_domain(self):
        """Worker dies holding the lease: the domain must come back on reclaim."""
        domain = _domain("server-A", "version", "1.4", "c1")
        self._enqueue("job-first", domains=[domain], max_retries=3)

        self.assertIsNotNone(self.queue.lease_next_job("worker-A", lease_ttl_seconds=-1))
        self.queue.reclaim_expired_leases()

        status, _ = self._status("job-first")
        self.assertEqual(status, "RETRYING")
        self.assertEqual(self._held_by_anyone([domain]), [])
        self.assertIsNotNone(self.queue.lease_next_job("worker-B"))

    def test_crash_during_execution_requires_reconciliation_and_releases_the_domain(self):
        domain = _domain("server-A", "version", "1.4", "c1")
        self._enqueue("job-first", domains=[domain])

        leased = self.queue.lease_next_job("worker-A")
        self.assertIsNotNone(leased)
        self.assertTrue(self.queue.mark_executing("job-first", "worker-A"))
        # The worker dies mid-execution: the lease lapses while status is EXECUTING.
        with self.queue._get_connection() as conn:
            conn.execute(
                "UPDATE ciph_ipc_jobs SET lease_expires_at = ? WHERE job_id = ?;",
                (time.time() - 1, "job-first"),
            )
            conn.commit()
        self.queue.reclaim_expired_leases()

        status, _ = self._status("job-first")
        self.assertEqual(status, "RECONCILIATION_REQUIRED")
        self.assertEqual(
            self._held_by_anyone([domain]), [],
            "an uncertain crashed job kept holding its epistemic domain",
        )

    def test_lease_expiry_alone_frees_a_blocked_candidate(self):
        """A short TTL must not permanently block a contradicting worker."""
        domain = _domain("server-A", "version", "1.4", "c1")
        other = _domain("server-A", "version", "1.5", "c2")
        self._enqueue("job-first", domains=[domain])
        self._enqueue("job-second", domains=[other])

        self.assertIsNotNone(self.queue.lease_next_job("worker-A", lease_ttl_seconds=1))
        self.assertIsNone(self.queue.lease_next_job("worker-B"))

        with self.queue._get_connection() as conn:
            conn.execute(
                "UPDATE ciph_epistemic_domain_leases SET expires_at = ?;", (time.time() - 1,)
            )
            conn.commit()

        self.assertIsNotNone(self.queue.lease_next_job("worker-B"))


if __name__ == "__main__":
    unittest.main()
