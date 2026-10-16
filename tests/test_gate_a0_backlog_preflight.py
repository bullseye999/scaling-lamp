
"""
Gate A0 - S3.0 read-only backlog preflight.

The S3 gate is "zero live permitless rows in the real durable queue". Establishing that must not
write to the production database, so the preflight opens it read-only and never constructs the
queue object (whose constructor runs migrations).
"""

import os
import sqlite3
import tempfile
import unittest

from ciph.workers.ipc_queue import IPCJobQueue, inspect_permitless_backlog_readonly


class ReadOnlyPreflightTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_s30_")
        self.db = f"{self._dir}/jobs.db"
        self.queue = IPCJobQueue(self.db)

    def test_a_live_permitless_row_blocks_the_gate(self):
        self.queue.enqueue_legacy_job_for_test(
            capability="cap.read", params={"k": "v"}, idempotency_key="idem-live"
        )
        report = inspect_permitless_backlog_readonly(self.db)
        self.assertTrue(report["available"])
        self.assertEqual(report["live_permitless"], 1)
        self.assertFalse(report["s3_gate_satisfied"])

    def test_a_terminal_permitless_row_is_archival_only(self):
        job_id = self.queue.enqueue_legacy_job_for_test(
            capability="cap.read", params={"k": "v"}, idempotency_key="idem-term"
        )
        with self.queue._get_connection() as conn:
            conn.execute("UPDATE ciph_ipc_jobs SET status='SUCCEEDED' WHERE job_id=?;", (job_id,))
            conn.commit()
        report = inspect_permitless_backlog_readonly(self.db)
        self.assertEqual(report["live_permitless"], 0)
        self.assertEqual(report["historical_permitless"], 1)
        self.assertTrue(report["s3_gate_satisfied"])

    def test_the_preflight_does_not_run_migrations(self):
        """Read-only: a database whose schema is current must be byte-unchanged by the preflight."""
        before = os.path.getsize(self.db)
        inspect_permitless_backlog_readonly(self.db)
        self.assertEqual(os.path.getsize(self.db), before)
        # And the connection really is read-only: it refuses a write.
        conn = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("CREATE TABLE should_not_exist (x INTEGER);")
        finally:
            conn.close()

    def test_a_missing_database_is_reported_not_created(self):
        missing = f"{self._dir}/absent.db"
        report = inspect_permitless_backlog_readonly(missing)
        self.assertFalse(report["available"])
        self.assertEqual(report["reason"], "DATABASE_NOT_FOUND")
        self.assertFalse(os.path.exists(missing), "the preflight must not create a database")


if __name__ == "__main__":
    unittest.main()
