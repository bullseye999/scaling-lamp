
"""
Gate A0 - canonical permit-bearing fixture setup.

The builder exists so fixtures can set up worker/queue scenarios without bypassing the execution
constitution. These specimens pin that it produces a genuinely canonical job, not a decorated one.
"""

import tempfile
import unittest

from ciph.kernel.execution_authority import SignedExecutionPermit
from ciph.runtime import CiphRuntime
from permit_test_support import canonical_permit_for, enqueue_permit_bearing_job


class PermitTestSupportTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_support_")
        self.runtime = CiphRuntime(db_path=f"{self._dir}/vault.db")

    def test_the_builder_produces_a_canonically_registered_permit(self):
        _, permit = canonical_permit_for(
            self.runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_support_1",
        )

        store = self.runtime.durable_permit_dependencies().permit_store
        row = store._blocking_permit_row(permit.payload.logical_action_id)
        self.assertIsNotNone(row, "the canonical store must own the permit, not just the caller")
        self.assertEqual(row["permit_id"], permit.payload.permit_id)
        self.assertEqual(row["permit_digest"], permit.permit_digest())

    def test_the_scope_reference_resolves_canonically(self):
        _, permit = canonical_permit_for(
            self.runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_support_2",
        )
        resolved = self.runtime.scope_grant_store().resolve(permit.payload.scope_grant_id)
        self.assertTrue(resolved.resolvable)

    def test_the_builder_enqueues_a_permit_bearing_job(self):
        fixture = enqueue_permit_bearing_job(
            self.runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_support_3",
        )
        stored = self.runtime.queue.get_job(fixture.job_id)["execution_permit"]
        self.assertIsNotNone(stored, "a permitted fixture job must carry its canonical permit")
        self.assertTrue(SignedExecutionPermit.from_dict(stored).permit_digest())

    def test_the_builder_never_recycles_an_existing_canonical_job(self):
        """A fresh fixture uses a fresh logical action; recycling authority would be a silent reuse."""
        first_id, first = canonical_permit_for(
            self.runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_support_4",
        )
        second_id, second = canonical_permit_for(
            self.runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_support_5",
        )
        self.assertNotEqual(first.payload.logical_action_id, second.payload.logical_action_id)


class AcquireHandlesHasNoQueueSideEffectsTests(unittest.TestCase):
    """
    "Acquire handles" and "enqueue a job" are materially different operations.

    `canonical_permit_for` drifted once into enqueuing through the fixture pipeline, which would make
    recovery tests impossible to reason about. This is a permanent guard, not a one-off fix.
    """

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_noside_")
        self.runtime = CiphRuntime(db_path=f"{self._dir}/vault.db")

    def _job_count(self):
        with self.runtime.queue._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM ciph_ipc_jobs;").fetchone()[0]

    def test_canonical_permit_for_does_not_enqueue(self):
        before = self._job_count()
        job_id, permit = canonical_permit_for(
            self.runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_noside_1",
        )
        self.assertEqual(self._job_count(), before, "acquiring handles must not create a job")
        self.assertTrue(permit.permit_id if hasattr(permit, "permit_id") else permit.payload.permit_id)
        self.assertTrue(job_id)

    def test_enqueue_permit_bearing_job_does_enqueue(self):
        before = self._job_count()
        fixture = enqueue_permit_bearing_job(
            self.runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_noside_2",
        )
        self.assertEqual(self._job_count(), before + 1)
        self.assertTrue(self.runtime.queue.get_job(fixture.job_id))


if __name__ == "__main__":
    unittest.main()
