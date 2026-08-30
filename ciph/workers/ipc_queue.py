"""
ciph.workers.ipc_queue - Persistent SQLite IPC Job Queue with Leases & Heartbeats.
Survives CLI crashes, client disconnects, and worker terminations.
"""

import time
import json
import uuid
import sqlite3
from typing import Dict, Any, List, Optional
from ciph.workers.receipts import JobState


class IPCJobQueue:
    """
    Persistent Job Queue backed by SQLite WAL mode.
    Guarantees that background tasks survive UI and terminal process lifetimes.
    """

    def __init__(self, db_path: str = "ciph_vault.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_ipc_jobs (
                    job_id TEXT PRIMARY KEY,
                    capability TEXT NOT NULL,
                    params TEXT NOT NULL,
                    status TEXT NOT NULL,
                    leased_to TEXT,
                    lease_expires_at REAL,
                    attempt_number INTEGER DEFAULT 0,
                    max_retries INTEGER DEFAULT 1,
                    result TEXT,
                    error TEXT,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    completed_at REAL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ipc_status ON ciph_ipc_jobs(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ipc_lease_exp ON ciph_ipc_jobs(lease_expires_at);")
            conn.commit()

    def enqueue_job(
        self,
        capability: str,
        params: Dict[str, Any],
        max_retries: int = 1,
        job_id: Optional[str] = None
    ) -> str:
        """Enqueue a new persistent job."""
        jid = job_id or f"JOB-{uuid.uuid4().hex[:8].upper()}"
        now = time.time()
        params_str = json.dumps(params, sort_keys=True, default=str)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO ciph_ipc_jobs (
                    job_id, capability, params, status, attempt_number,
                    max_retries, created_at
                ) VALUES (?, ?, ?, ?, 0, ?, ?);
            """, (jid, capability, params_str, JobState.QUEUED.value, max_retries, now))
            conn.commit()
        return jid

    def lease_next_job(self, worker_id: str, lease_ttl_seconds: int = 60) -> Optional[Dict[str, Any]]:
        """
        Atomically leases the next available QUEUED job or TIMED_OUT job for this worker.
        """
        self.reclaim_expired_leases()
        now = time.time()
        expires_at = now + lease_ttl_seconds

        with self._get_connection() as conn:
            # Find next eligible job
            cursor = conn.execute("""
                SELECT job_id, capability, params, attempt_number 
                FROM ciph_ipc_jobs 
                WHERE status IN ('QUEUED', 'RETRYING') 
                ORDER BY created_at ASC LIMIT 1;
            """)
            row = cursor.fetchone()
            if not row:
                return None

            job_id = row['job_id']
            new_attempt = row['attempt_number'] + 1

            # Atomic lease update
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, leased_to = ?, lease_expires_at = ?, 
                    started_at = ?, attempt_number = ?
                WHERE job_id = ? AND status IN ('QUEUED', 'RETRYING');
            """, (JobState.LEASED.value, worker_id, expires_at, now, new_attempt, job_id))
            conn.commit()

            if cursor.rowcount == 0:
                return None  # Leased by another worker concurrently

            return {
                "job_id": job_id,
                "capability": row['capability'],
                "params": json.loads(row['params']),
                "attempt_number": new_attempt,
                "lease_expires_at": expires_at
            }

    def renew_lease(self, job_id: str, worker_id: str, lease_ttl_seconds: int = 60) -> bool:
        """Worker heartbeat extending lease expiration."""
        now = time.time()
        new_expires = now + lease_ttl_seconds
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET lease_expires_at = ? 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING');
            """, (new_expires, job_id, worker_id))
            conn.commit()
            return cursor.rowcount > 0

    def mark_executing(self, job_id: str, worker_id: str) -> bool:
        """Update job state to EXECUTING once payload starts running."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ? 
                WHERE job_id = ? AND leased_to = ?;
            """, (JobState.EXECUTING.value, job_id, worker_id))
            conn.commit()
            return cursor.rowcount > 0

    def complete_job(self, job_id: str, worker_id: str, result: Dict[str, Any]) -> None:
        """Mark job as successfully completed."""
        now = time.time()
        res_str = json.dumps(result, sort_keys=True, default=str)
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, result = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ?;
            """, (JobState.SUCCEEDED.value, res_str, now, job_id, worker_id))
            conn.commit()

    def fail_job(self, job_id: str, worker_id: str, error: str) -> None:
        """Mark job as failed, auto-queuing for retry if within max_retries."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT attempt_number, max_retries FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            row = cursor.fetchone()
            if not row:
                return

            if row['attempt_number'] < row['max_retries']:
                next_status = JobState.RETRYING.value
            else:
                next_status = JobState.FAILED.value

            conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, error = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ?;
            """, (next_status, error, now, job_id))
            conn.commit()

    def quarantine_job(self, job_id: str, worker_id: str, reason: str) -> None:
        """Quarantine a job to halt execution safety loops."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, error = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ?;
            """, (JobState.QUARANTINED.value, f"QUARANTINED: {reason}", now, job_id))
            conn.commit()

    def reclaim_expired_leases(self) -> int:
        """Watchdog: Reclaims jobs whose worker lease expired without a completion/heartbeat."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = 'RETRYING', leased_to = NULL, lease_expires_at = NULL 
                WHERE status IN ('LEASED', 'EXECUTING') AND lease_expires_at < ? AND attempt_number < max_retries;
            """, (now,))
            reclaimed_retries = cursor.rowcount

            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = 'TIMED_OUT', leased_to = NULL, lease_expires_at = NULL 
                WHERE status IN ('LEASED', 'EXECUTING') AND lease_expires_at < ? AND attempt_number >= max_retries;
            """, (now,))
            timed_out = cursor.rowcount

            conn.commit()
            return reclaimed_retries + timed_out

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full status of a job."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            res = json.loads(row['result']) if row['result'] else None
            params = json.loads(row['params']) if row['params'] else {}
            return {
                "job_id": row['job_id'],
                "capability": row['capability'],
                "params": params,
                "status": row['status'],
                "leased_to": row['leased_to'],
                "attempt_number": row['attempt_number'],
                "max_retries": row['max_retries'],
                "result": res,
                "error": row['error'],
                "created_at": row['created_at'],
                "started_at": row['started_at'],
                "completed_at": row['completed_at']
            }
