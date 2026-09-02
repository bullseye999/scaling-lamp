"""
ciph.workers.ipc_queue - Persistent SQLite IPC Job Queue (CIPH 4.0).
Guarantees at-least-once delivery, concurrency-safe unique idempotency, lease expirations,
dead-letter quarantine, atomic single-transaction cross-store commits, and global maintenance exclusion.
"""

import time
import json
import uuid
import sqlite3
from typing import Optional, Dict, Any, List
from ciph.workers.receipts import JobState, ExecutionReceipt


class IPCJobQueue:
    """
    Durable, crash-resilient IPC queue backed by SQLite in WAL mode.
    Enforces atomic transitions, heartbeat lease renewals, and crash recovery.
    """

    def __init__(self, db_path: str = "ciph_vault.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA busy_timeout = 10000;")
        conn.row_factory = sqlite3.Row
        conn.isolation_level = "IMMEDIATE"  # Enforces BEGIN IMMEDIATE atomicity on all transactions

        # Global exclusive maintenance lease check
        try:
            now = time.time()
            cursor = conn.execute("SELECT holder_id FROM ciph_maintenance_leases WHERE expires_at > ? LIMIT 1;", (now,))
            lease_row = cursor.fetchone()
            if lease_row:
                conn.close()
                raise sqlite3.OperationalError(f"Database locked: Active exclusive maintenance lease held by '{lease_row[0]}'.")
        except sqlite3.OperationalError as ex:
            if "no such table" not in str(ex):
                raise ex

        return conn

    def _init_db(self):
        # Direct connection to avoid bootstrap chicken-egg with maintenance leases
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 10000;")
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
                    idempotency_key TEXT,
                    receipt_id TEXT,
                    plan_id TEXT,
                    step_id TEXT,
                    worker_signature TEXT,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    completed_at REAL
                );
            """)
            # Auto-migrate columns if table already existed without new fields
            cursor = conn.execute("PRAGMA table_info(ciph_ipc_jobs);")
            existing_cols = {row[1] for row in cursor.fetchall()}
            for col in ['idempotency_key', 'receipt_id', 'plan_id', 'step_id', 'worker_signature']:
                if col not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE ciph_ipc_jobs ADD COLUMN {col} TEXT;")
                    except Exception:
                        pass

            conn.execute("CREATE INDEX IF NOT EXISTS idx_ipc_status ON ciph_ipc_jobs(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ipc_lease_exp ON ciph_ipc_jobs(lease_expires_at);")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ipc_idemp_unique ON ciph_ipc_jobs(idempotency_key);")
            conn.commit()

    def enqueue_job(
        self,
        capability: str,
        params: Dict[str, Any],
        max_retries: int = 1,
        job_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        plan_id: Optional[str] = None,
        step_id: Optional[str] = None
    ) -> str:
        """
        Enqueue a new persistent job with concurrency-safe atomic idempotency.
        If an idempotency_key already exists, returns the existing job_id without creating duplicate jobs.
        """
        now = time.time()
        params_str = json.dumps(params, sort_keys=True, default=str)
        jid = job_id or f"JOB-{uuid.uuid4().hex[:8].upper()}"

        with self._get_connection() as conn:
            if idempotency_key:
                # Atomically insert with unique conflict protection
                cursor = conn.execute("""
                    INSERT INTO ciph_ipc_jobs (
                        job_id, capability, params, status, attempt_number,
                        max_retries, idempotency_key, plan_id, step_id, created_at
                    ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?)
                    ON CONFLICT(idempotency_key) DO NOTHING;
                """, (jid, capability, params_str, JobState.QUEUED.value, max_retries, idempotency_key, plan_id, step_id, now))
                
                if cursor.rowcount == 0:
                    # Conflict hit: Fetch existing job_id
                    cur = conn.execute("SELECT job_id FROM ciph_ipc_jobs WHERE idempotency_key = ? LIMIT 1;", (idempotency_key,))
                    existing = cur.fetchone()
                    if existing:
                        return existing['job_id']
                conn.commit()
                return jid

            conn.execute("""
                INSERT INTO ciph_ipc_jobs (
                    job_id, capability, params, status, attempt_number,
                    max_retries, idempotency_key, plan_id, step_id, created_at
                ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?);
            """, (jid, capability, params_str, JobState.QUEUED.value, max_retries, idempotency_key, plan_id, step_id, now))
            conn.commit()
            return jid

    def get_job_by_idempotency_key(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve latest job with matching idempotency key."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM ciph_ipc_jobs WHERE idempotency_key = ? ORDER BY created_at DESC LIMIT 1;",
                (idempotency_key,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "job_id": row['job_id'],
                "capability": row['capability'],
                "status": row['status'],
                "result": json.loads(row['result']) if row['result'] else None,
                "receipt_id": row['receipt_id'],
                "worker_signature": row['worker_signature'],
                "completed_at": row['completed_at']
            }

    def lease_next_job(self, worker_id: str, lease_ttl_seconds: int = 60) -> Optional[Dict[str, Any]]:
        """
        Atomically lease the next available job (QUEUED or RETRYING) to a worker thread using CAS.
        Sets status to LEASED and establishes lease expiration deadline in a single atomic statement.
        """
        now = time.time()
        lease_exp = now + lease_ttl_seconds
        
        with self._get_connection() as conn:
            # Single atomic UPDATE ... RETURNING with CAS status check
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, leased_to = ?, lease_expires_at = ?, attempt_number = attempt_number + 1, started_at = ? 
                WHERE job_id = (
                    SELECT job_id FROM ciph_ipc_jobs 
                    WHERE status IN ('QUEUED', 'RETRYING') 
                    ORDER BY created_at ASC 
                    LIMIT 1
                ) AND status IN ('QUEUED', 'RETRYING')
                RETURNING job_id, capability, params, attempt_number, max_retries, idempotency_key, plan_id, step_id;
            """, (JobState.LEASED.value, worker_id, lease_exp, now))
            row = cursor.fetchone()
            if not row:
                return None
            conn.commit()

            return {
                "job_id": row['job_id'],
                "capability": row['capability'],
                "params": json.loads(row['params']),
                "attempt_number": row['attempt_number'],
                "max_retries": row['max_retries'],
                "idempotency_key": row['idempotency_key'],
                "plan_id": row['plan_id'],
                "step_id": row['step_id']
            }

    def renew_lease(self, job_id: str, worker_id: str, extension_seconds: int = 30) -> bool:
        """Worker heartbeat: Renews lease deadline while long-running task is active."""
        now = time.time()
        new_exp = now + extension_seconds
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET lease_expires_at = ? 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING');
            """, (new_exp, job_id, worker_id))
            conn.commit()
            return cursor.rowcount > 0

    def mark_executing(self, job_id: str, worker_id: str) -> bool:
        """Mark job as actively executing on worker."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ? 
                WHERE job_id = ? AND leased_to = ?;
            """, (JobState.EXECUTING.value, job_id, worker_id))
            conn.commit()
            return cursor.rowcount > 0

    def complete_job_and_append_receipt_event(
        self,
        job_id: str,
        worker_id: str,
        receipt_dict: Dict[str, Any]
    ) -> int:
        """
        Atomically mark job SUCCEEDED and insert ExecutionReceiptStoredEvent into EventStore
        within a SINGLE SQLite IMMEDIATE transaction boundary with CAS lease guard.
        """
        import hashlib
        now = time.time()
        res_str = json.dumps(receipt_dict.get("results", {}), sort_keys=True, default=str)
        payload_str = json.dumps(receipt_dict, sort_keys=True, default=str)
        receipt_id = receipt_dict.get("receipt_id", f"rcpt_{uuid.uuid4().hex[:12]}")
        worker_signature = receipt_dict.get("worker_signature")

        with self._get_connection() as conn:
            # 1. Update job status with CAS guard (only active lease holder can complete)
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, result = ?, receipt_id = ?, worker_signature = ?,
                    completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING');
            """, (JobState.SUCCEEDED.value, res_str, receipt_id, worker_signature, now, job_id, worker_id))

            if cursor.rowcount == 0:
                conn.commit()
                return 0

            # 2. Append to EventStore table within the same atomic transaction
            cursor = conn.execute("SELECT event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1;")
            row = cursor.fetchone()
            prev_hash = row['event_hash'] if row else "GENESIS_BLOCK_CIPH_4.0"
            
            hash_input = f"{prev_hash}|ExecutionReceiptStoredEvent|{receipt_id}|{payload_str}|{now}"
            event_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

            cur = conn.execute("""
                INSERT INTO ciph_event_store 
                (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash)
                VALUES ('ExecutionReceiptStoredEvent', ?, ?, ?, ?, ?);
            """, (receipt_id, payload_str, now, prev_hash, event_hash))
            conn.commit()
            return cur.lastrowid

    def fail_job_and_append_receipt_event(
        self,
        job_id: str,
        worker_id: str,
        error: str,
        receipt_dict: Dict[str, Any]
    ) -> int:
        """
        Atomically mark job FAILED/RETRYING and insert ExecutionReceiptStoredEvent into EventStore
        within a SINGLE SQLite IMMEDIATE transaction boundary with CAS lease guard.
        """
        import hashlib
        now = time.time()
        payload_str = json.dumps(receipt_dict, sort_keys=True, default=str)
        receipt_id = receipt_dict.get("receipt_id", f"rcpt_{uuid.uuid4().hex[:12]}")
        worker_signature = receipt_dict.get("worker_signature")

        with self._get_connection() as conn:
            cursor = conn.execute("SELECT attempt_number, max_retries FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            row = cursor.fetchone()
            next_status = JobState.FAILED.value
            if row and row['attempt_number'] < row['max_retries']:
                next_status = JobState.RETRYING.value

            # 1. Update job status with CAS guard (enforce leased_to = worker_id)
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, error = ?, receipt_id = ?, worker_signature = ?,
                    completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING');
            """, (next_status, error, receipt_id, worker_signature, now, job_id, worker_id))

            if cursor.rowcount == 0:
                conn.commit()
                return 0

            # 2. Append to EventStore table within the same atomic transaction
            cursor = conn.execute("SELECT event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1;")
            row = cursor.fetchone()
            prev_hash = row['event_hash'] if row else "GENESIS_BLOCK_CIPH_4.0"
            
            hash_input = f"{prev_hash}|ExecutionReceiptStoredEvent|{receipt_id}|{payload_str}|{now}"
            event_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

            cur = conn.execute("""
                INSERT INTO ciph_event_store 
                (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash)
                VALUES ('ExecutionReceiptStoredEvent', ?, ?, ?, ?, ?);
            """, (receipt_id, payload_str, now, prev_hash, event_hash))
            conn.commit()
            return cur.lastrowid

    def complete_job(
        self,
        job_id: str,
        worker_id: str,
        result: Optional[Dict[str, Any]] = None,
        receipt_id: Optional[str] = None,
        worker_signature: Optional[str] = None
    ) -> bool:
        """Mark job successfully completed and clear lease with CAS ownership guard."""
        now = time.time()
        res_str = json.dumps(result, sort_keys=True, default=str) if result else None
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, result = ?, receipt_id = ?, worker_signature = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING');
            """, (JobState.SUCCEEDED.value, res_str, receipt_id, worker_signature, now, job_id, worker_id))
            conn.commit()
            return cursor.rowcount > 0

    def fail_job(
        self,
        job_id: str,
        worker_id: str,
        error: str
    ) -> bool:
        """Mark job failed or increment attempt for retry with CAS ownership guard."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT attempt_number, max_retries FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            row = cursor.fetchone()
            if not row:
                return False

            if row['attempt_number'] < row['max_retries']:
                next_status = JobState.RETRYING.value
            else:
                next_status = JobState.FAILED.value

            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, error = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING');
            """, (next_status, error, now, job_id, worker_id))
            conn.commit()
            return cursor.rowcount > 0

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
            conn.commit()
            return cursor.rowcount

    def dead_letter_unrecoverable_jobs(self) -> int:
        """Watchdog: Quarantines jobs that have exceeded max_retries after lease expiration."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = 'DEAD_LETTER', leased_to = NULL, lease_expires_at = NULL, error = 'Max retries exhausted upon lease expiry' 
                WHERE status IN ('LEASED', 'EXECUTING', 'RETRYING') AND lease_expires_at < ? AND attempt_number >= max_retries;
            """, (now,))
            conn.commit()
            return cursor.rowcount

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Inspect persistent job state by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "job_id": row['job_id'],
                "capability": row['capability'],
                "params": json.loads(row['params']),
                "status": row['status'],
                "leased_to": row['leased_to'],
                "lease_expires_at": row['lease_expires_at'],
                "attempt_number": row['attempt_number'],
                "max_retries": row['max_retries'],
                "result": json.loads(row['result']) if row['result'] else None,
                "error": row['error'],
                "idempotency_key": row['idempotency_key'],
                "receipt_id": row['receipt_id'],
                "worker_signature": row['worker_signature'],
                "created_at": row['created_at'],
                "started_at": row['started_at'],
                "completed_at": row['completed_at']
            }
