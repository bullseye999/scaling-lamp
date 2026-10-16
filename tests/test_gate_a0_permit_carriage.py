
"""
Gate A0 closure test - S2.3 carriage: only canonical authority reaches the queue.

A signed candidate permit is not necessarily the canonical permit. S2.1 canonicalises one permit per
logical action; this suite proves the integration consequence - the losing candidate is never
carried, the owning job is adopted rather than duplicated, and an unretrievable owner fails closed.

Nothing here consumes the permit. The durable lane is still token-authorized until S3.
"""

import concurrent.futures
import pathlib
import tempfile
import unittest

from ciph.kernel.execution_authority import (
    ExecutionAuthority,
    ExecutionPermitPayload,
    SignedExecutionPermit,
    time_us,
)
from ciph.kernel.execution_gateway import ExecutionGateway, ExecutionRequest
from ciph.kernel.permit_issuance import obtain_canonical_permit
from ciph.kernel.permit_store import ExecutionPermitStore
from ciph.workers.ipc_queue import IPCJobQueue


class PermitCarriageTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_carriage_")
        self.store = ExecutionPermitStore(f"{self._dir}/permits.db")
        self.queue = IPCJobQueue(f"{self._dir}/jobs.db")
        self.authority, _ = ExecutionAuthority.generate()
        self.gateway = ExecutionGateway(registry=None, issuer=self.authority, permit_ttl_seconds=600.0)

    def _request(self, logical_action_id="L1", fingerprint="A", capability="cap.read"):
        return ExecutionRequest(
            capability=capability,
            params={"k": "v"},
            target=None,
            logical_action_id=logical_action_id,
            action_fingerprint=fingerprint,
            route="TEST",
        )

    # ---------------------------------------------------------------- carriage

    def test_registered_new_carries_the_canonical_permit(self):
        carriage = obtain_canonical_permit(self.gateway, self.store, self._request())

        self.assertTrue(carriage.accepted)
        self.assertEqual(carriage.reason, "REGISTERED_NEW")
        self.assertIsNotNone(carriage.permit)
        self.assertIsNone(carriage.adopt_job_id)

    def test_already_issued_with_an_owning_job_adopts_that_job(self):
        first = obtain_canonical_permit(self.gateway, self.store, self._request(), job_id="JOB-1")
        self.queue.enqueue_job(
            capability="cap.read", params={"k": "v"}, idempotency_key="idem-1",
            execution_permit=first.permit, job_id="JOB-1",
        )

        retry = obtain_canonical_permit(self.gateway, self.store, self._request())

        self.assertTrue(retry.accepted)
        self.assertIsNone(retry.permit)              # the losing candidate is NOT carried
        self.assertEqual(retry.reason, "ADOPT_EXISTING_JOB")
        self.assertEqual(retry.adopt_job_id, "JOB-1")

    def test_already_issued_without_an_owning_job_fails_closed(self):
        obtain_canonical_permit(self.gateway, self.store, self._request())

        retry = obtain_canonical_permit(self.gateway, self.store, self._request())

        self.assertFalse(retry.accepted)
        self.assertEqual(retry.reason, "OWNING_JOB_UNAVAILABLE")
        self.assertIsNone(retry.permit)
        self.assertIsNone(retry.adopt_job_id)

    def test_the_losing_signed_candidate_is_never_usable(self):
        first = obtain_canonical_permit(self.gateway, self.store, self._request(), job_id="JOB-1")
        retry = obtain_canonical_permit(self.gateway, self.store, self._request())

        # The retry's own candidate is NOT carried - nothing hands it to a caller or a queue.
        self.assertIsNone(retry.permit)
        # Canonical authority is still exactly the first permit, and only one row exists.
        canonical = self.store._blocking_permit_row("L1")
        self.assertEqual(canonical["permit_id"], first.permit.payload.permit_id)
        with self.store._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS n FROM execution_permits WHERE logical_action_id = 'L1';"
            ).fetchone()["n"]
        self.assertEqual(count, 1)

    def test_concurrent_producers_yield_one_canonical_permit(self):
        def attempt(index):
            return obtain_canonical_permit(
                self.gateway, self.store, self._request("L-CONC"), job_id=f"JOB-{index}"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))

        registered = [r for r in results if r.reason == "REGISTERED_NEW"]
        adopted = [r for r in results if r.reason == "ADOPT_EXISTING_JOB"]
        self.assertEqual(len(registered), 1)
        self.assertEqual(len(adopted), 1)
        # The loser adopts the winner's job; it never carries its own candidate.
        self.assertIsNone(adopted[0].permit)
        self.assertEqual(adopted[0].adopt_job_id, registered[0].issuance.owning_job_id)

    # ---------------------------------------------------------------- queue

    def test_the_queue_round_trips_the_exact_signed_permit(self):
        carriage = obtain_canonical_permit(self.gateway, self.store, self._request("L-Q1"))
        job_id = self.queue.enqueue_job(
            capability="cap.read", params={"k": "v"}, idempotency_key="idem-q1",
            execution_permit=carriage.permit,
        )

        stored = self.queue.get_job(job_id)["execution_permit"]

        self.assertIsNotNone(stored)
        rebuilt = SignedExecutionPermit.from_dict(stored)
        self.assertEqual(rebuilt.permit_digest(), carriage.permit.permit_digest())
        self.assertEqual(rebuilt.signature, carriage.permit.signature)

    def test_a_job_without_a_permit_stays_backward_compatible(self):
        job_id = self.queue.enqueue_legacy_job_for_test(
            capability="cap.read", params={"k": "v"}, idempotency_key="idem-q2"
        )
        self.assertIsNone(self.queue.get_job(job_id)["execution_permit"])

    # ---------------------------------------------------------------- S2 boundary

if __name__ == "__main__":
    unittest.main()
