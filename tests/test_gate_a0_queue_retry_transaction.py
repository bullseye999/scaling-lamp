
"""
Gate A0 - the queue half of the retry transaction: one snapshot, one owner.

The central retry transition must read and update the job inside the SAME authoritative view as the
permit rows and effect evidence. This pins the ownership law and the stale-report check.
"""

import json
import sqlite3
import tempfile
import unittest

from ciph.workers.ipc_queue import IPCJobQueue
from permit_test_support import canonical_permit_for
from ciph.runtime import CiphRuntime


class QueueRetryTransactionTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_qtxn_")
        self.db = f"{self._dir}/vault.db"
        self.queue = IPCJobQueue(self.db)
        self.runtime = CiphRuntime(db_path=self.db)

    def _permit_bearing_job(self):
        job_id, permit = canonical_permit_for(
            self.runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_qtxn_1",
        )
        self.queue.enqueue_job(
            capability="memory.retrieve", params={"key": "k", "target": "local_memory"},
            job_id=job_id, idempotency_key=job_id, execution_permit=permit,
        )
        return job_id, permit

    def _conn(self):
        conn = sqlite3.connect(self.db, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _status(self, job_id):
        return (self.queue.get_job_for_retry(job_id) or {}).get("status")

    def test_a_caller_rollback_leaves_the_job_unchanged(self):
        job_id, permit = self._permit_bearing_job()
        before = self._status(job_id)

        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self.assertTrue(self.queue.apply_retry_transition(
                job_id=job_id, status="RETRYING", expected_permit_id=permit.payload.permit_id,
                conn=conn,
            ))
            conn.execute("ROLLBACK")
        finally:
            conn.close()

        self.assertEqual(self._status(job_id), before, "the queue must not commit on its own")

    def test_a_caller_commit_applies_the_transition(self):
        job_id, permit = self._permit_bearing_job()

        conn = self._conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self.assertTrue(self.queue.apply_retry_transition(
                job_id=job_id, status="RETRYING", expected_permit_id=permit.payload.permit_id,
                conn=conn,
            ))
            conn.execute("COMMIT")
        finally:
            conn.close()

        self.assertEqual(self._status(job_id), "RETRYING")

    def test_a_stale_report_for_an_already_advanced_job_is_refused(self):
        """A duplicate worker report must not advance a job someone else already moved."""
        job_id, permit = self._permit_bearing_job()
        # Someone else already advanced the job to a different carried permit.
        self.queue.apply_retry_transition(
            job_id=job_id, status="RETRYING", carried_permit=json.dumps({
                "permit_id": "permit_already_advanced", "logical_action_id": "L",
                "action_fingerprint": "A", "capability_id": "memory.retrieve",
            }),
            expected_permit_id=permit.payload.permit_id,
        )
        before = self.queue.get_job_for_retry(job_id)["execution_permit"]

        applied = self.queue.apply_retry_transition(
            job_id=job_id, status="RETRYING", carried_permit="{}",
            expected_permit_id=permit.payload.permit_id,
        )

        self.assertFalse(applied, "a stale report must be detected by the correlation fact")
        self.assertEqual(
            self.queue.get_job_for_retry(job_id)["execution_permit"], before,
            "the stale report must not overwrite what is currently carried",
        )


if __name__ == "__main__":
    unittest.main()
