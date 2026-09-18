"""
ciph.workers.ipc_queue - Persistent SQLite IPC Job Queue (CIPH 4.0).
Guarantees at-least-once delivery, concurrency-safe unique idempotency, lease expirations,
dead-letter quarantine, atomic single-transaction cross-store commits, and global maintenance exclusion.
"""

import time
import json
import uuid
import sqlite3
import hashlib
import hmac
from typing import Optional, Dict, Any, List, Union, Tuple
from collections.abc import Mapping
from ciph.workers.receipts import JobState, ExecutionReceipt


class IPCJobQueue:
    """
    Durable, crash-resilient IPC queue backed by SQLite in WAL mode.
    Enforces atomic transitions, heartbeat lease renewals, and crash recovery.
    """

    def __init__(
        self,
        db_path: str = "ciph_vault.db",
        trust_registry: Optional[Any] = None,
        worker_secret_key: Optional[bytes] = None
    ):
        self.db_path = db_path
        self.trust_registry = trust_registry
        self.worker_secret_key = worker_secret_key
        if self.trust_registry is None and db_path:
            try:
                from ciph.kernel.crypto_identity import TrustRegistry
                self.trust_registry = TrustRegistry(db_path)
            except Exception:
                self.trust_registry = None
        self._init_db()

    def _get_connection(self, calling_holder_id: Optional[str] = None) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA busy_timeout = 10000;")
        conn.row_factory = sqlite3.Row
        conn.isolation_level = "IMMEDIATE"  # Enforces BEGIN IMMEDIATE atomicity on all transactions

        from ciph.maintenance.exclusion import ExcludedConnection
        return ExcludedConnection(conn, calling_holder_id=calling_holder_id, db_path=self.db_path)

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
                    execution_token TEXT,
                    created_at REAL NOT NULL,
                    started_at REAL,
                    completed_at REAL
                );
            """)
            # Auto-migrate columns if table already existed without new fields
            cursor = conn.execute("PRAGMA table_info(ciph_ipc_jobs);")
            existing_cols = {row[1] for row in cursor.fetchall()}
            for col in ['idempotency_key', 'receipt_id', 'plan_id', 'step_id', 'worker_signature', 'execution_token', 'pending_receipt']:
                if col not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE ciph_ipc_jobs ADD COLUMN {col} TEXT;")
                    except Exception:
                        pass

            conn.execute("CREATE INDEX IF NOT EXISTS idx_ipc_status ON ciph_ipc_jobs(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ipc_lease_exp ON ciph_ipc_jobs(lease_expires_at);")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ipc_idemp_unique ON ciph_ipc_jobs(idempotency_key);")

            # Persistent Replay Store: Tokens & Nonces persisted atomically in SQLite
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_consumed_tokens (
                    token_id TEXT PRIMARY KEY,
                    nonce TEXT UNIQUE,
                    job_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    consumed_at REAL NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_consumed_nonce ON ciph_consumed_tokens(nonce);")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_retry_tokens (
                    token_id TEXT PRIMARY KEY, parent_token_id TEXT UNIQUE NOT NULL,
                    job_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
                    parent_token TEXT NOT NULL, token TEXT NOT NULL
                );
            """)

            # Verified Authorization Grants Store
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_authorization_grants (
                    grant_id TEXT PRIMARY KEY,
                    plan_hash TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    params_hash TEXT NOT NULL,
                    scope_grant_id TEXT,
                    signature TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_grant_cap ON ciph_authorization_grants(capability);")

            # EventStore Table (for atomic single-transaction commits and audit events)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_event_store (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_aggregate ON ciph_event_store(aggregate_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON ciph_event_store(event_type);")
            conn.commit()

    def enqueue_job(
        self,
        capability: str,
        params: Dict[str, Any],
        max_retries: int = 1,
        job_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        plan_id: Optional[str] = None,
        step_id: Optional[str] = None,
        execution_token: Optional[Any] = None
    ) -> str:
        """
        Enqueue a new persistent job with concurrency-safe atomic idempotency.
        If an idempotency_key already exists, returns the existing job_id without creating duplicate jobs.
        Stores signed ExecutionToken when provided.
        """
        now = time.time()
        params_data = params.to_dict() if hasattr(params, "to_dict") else (dict(params) if isinstance(params, Mapping) else params)
        params_str = json.dumps(params_data, sort_keys=True, default=str)
        jid = job_id or f"JOB-{uuid.uuid4().hex[:8].upper()}"

        token_str = None
        if execution_token is not None:
            t_data = None
            if isinstance(execution_token, str):
                token_str = execution_token
                try:
                    from ciph.kernel.crypto_identity import ExecutionToken
                    t_data = json.loads(execution_token)
                    t_obj = ExecutionToken.from_dict(t_data)
                    if self.trust_registry:
                        v, r = t_obj.verify(self.trust_registry)
                        if not v:
                            raise ValueError(f"Invalid ExecutionToken: {r}")
                except Exception as ex:
                    if isinstance(ex, ValueError):
                        raise ex
            elif hasattr(execution_token, 'to_dict'):
                if self.trust_registry:
                    v, r = execution_token.verify(self.trust_registry)
                    if not v:
                        raise ValueError(f"Invalid ExecutionToken: {r}")
                t_data = execution_token.to_dict()
                token_str = json.dumps(t_data)
            elif isinstance(execution_token, dict):
                from ciph.kernel.crypto_identity import ExecutionToken
                t_data = execution_token
                t_obj = ExecutionToken.from_dict(execution_token)
                if self.trust_registry:
                    v, r = t_obj.verify(self.trust_registry)
                    if not v:
                        raise ValueError(f"Invalid ExecutionToken: {r}")
                token_str = json.dumps(t_obj.to_dict())

            if t_data and isinstance(t_data, dict):
                if step_id is None and "step_id" in t_data:
                    step_id = t_data["step_id"]
                if plan_id is None:
                    plan_id = t_data.get("plan_id", "PLAN_STANDALONE")

        # Exclusive maintenance lease check: enqueue fails closed
        with sqlite3.connect(self.db_path, timeout=5.0) as check_conn:
            try:
                row = check_conn.execute("SELECT holder_id FROM ciph_maintenance_leases WHERE expires_at > ? LIMIT 1;", (now,)).fetchone()
                if row:
                    from ciph.maintenance.exclusion import MaintenanceInProgressError
                    raise MaintenanceInProgressError(f"Cannot enqueue job: Active exclusive maintenance lease held by '{row[0]}'.")
            except sqlite3.OperationalError:
                pass

        with self._get_connection() as conn:
            if idempotency_key:
                # Atomically insert with unique conflict protection
                cursor = conn.execute("""
                    INSERT INTO ciph_ipc_jobs (
                        job_id, capability, params, status, attempt_number,
                        max_retries, idempotency_key, plan_id, step_id, execution_token, created_at
                    ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(idempotency_key) DO NOTHING;
                """, (jid, capability, params_str, JobState.QUEUED.value, max_retries, idempotency_key, plan_id, step_id, token_str, now))
                
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
                    max_retries, idempotency_key, plan_id, step_id, execution_token, created_at
                ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?);
            """, (jid, capability, params_str, JobState.QUEUED.value, max_retries, idempotency_key, plan_id, step_id, token_str, now))
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
                "params": json.loads(row['params']),
                "status": row['status'],
                "attempt_number": row['attempt_number'],
                "result": json.loads(row['result']) if row['result'] else None,
                "error": row['error'],
                "idempotency_key": row['idempotency_key'],
                "plan_id": row['plan_id'],
                "step_id": row['step_id'],
                "receipt_id": row['receipt_id'],
                "worker_signature": row['worker_signature'],
                "execution_token": row['execution_token'] if 'execution_token' in row.keys() else None,
                "pending_receipt": json.loads(row["pending_receipt"]) if row["pending_receipt"] else None,
                "created_at": row['created_at'],
                "completed_at": row['completed_at']
            }

    def lease_next_job(
        self,
        worker_id: str,
        lease_ttl_seconds: int = 60,
        target_job_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Atomically lease the next available job (QUEUED or RETRYING) to a worker thread using CAS.
        If target_job_id is provided, specifically leases that job if available.
        Sets status to LEASED and establishes lease expiration deadline in a single atomic statement.
        """
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            lease_exp = now + lease_ttl_seconds
            # Single atomic UPDATE ... RETURNING with CAS status check
            if target_job_id:
                cursor = conn.execute("""
                    UPDATE ciph_ipc_jobs 
                    SET status = ?, leased_to = ?, lease_expires_at = ?, attempt_number = attempt_number + 1,
                        started_at = ?, completed_at = NULL, result = NULL, error = NULL,
                        receipt_id = NULL, worker_signature = NULL, pending_receipt = NULL
                    WHERE job_id = ? AND status IN ('QUEUED', 'RETRYING')
                    RETURNING job_id, capability, params, attempt_number, max_retries, idempotency_key, plan_id, step_id, execution_token, lease_expires_at, started_at;
                """, (JobState.LEASED.value, worker_id, lease_exp, now, target_job_id))
            else:
                cursor = conn.execute("""
                    UPDATE ciph_ipc_jobs 
                    SET status = ?, leased_to = ?, lease_expires_at = ?, attempt_number = attempt_number + 1,
                        started_at = ?, completed_at = NULL, result = NULL, error = NULL,
                        receipt_id = NULL, worker_signature = NULL, pending_receipt = NULL
                    WHERE job_id = (
                        SELECT job_id FROM ciph_ipc_jobs 
                        WHERE status IN ('QUEUED', 'RETRYING') 
                        ORDER BY created_at ASC 
                        LIMIT 1
                    ) AND status IN ('QUEUED', 'RETRYING')
                    RETURNING job_id, capability, params, attempt_number, max_retries, idempotency_key, plan_id, step_id, execution_token, lease_expires_at, started_at;
                """, (JobState.LEASED.value, worker_id, lease_exp, now))
            row = cursor.fetchone()
            if not row:
                return None

            exec_token_raw = row['execution_token']
            conn.commit()

            return {
                "job_id": row['job_id'],
                "capability": row['capability'],
                "params": json.loads(row['params']),
                "attempt_number": row['attempt_number'],
                "max_retries": row['max_retries'],
                "idempotency_key": row['idempotency_key'],
                "plan_id": row['plan_id'],
                "step_id": row['step_id'],
                "execution_token": exec_token_raw,
                "lease_expires_at": row['lease_expires_at'],
                "started_at": row['started_at'],
            }

    def get_job_attempt(self, job_id: str) -> Optional[Any]:
        """Retrieve the immutable JobAttempt contract for an active job lease."""
        from ciph.contracts.execution import JobAttempt
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT job_id, capability, attempt_number, max_retries, leased_to, started_at, lease_expires_at, idempotency_key, plan_id, step_id, execution_token FROM ciph_ipc_jobs WHERE job_id = ?;",
                (job_id,)
            )
            row = cursor.fetchone()
            if not row or not row['leased_to']:
                return None
            tok_hash = None
            if row['execution_token']:
                tok_hash = hashlib.sha256(row['execution_token'].encode('utf-8')).hexdigest()
            return JobAttempt(
                job_id=row['job_id'],
                capability=row['capability'],
                attempt_number=row['attempt_number'] or 1,
                max_retries=row['max_retries'] or 1,
                worker_id=row['leased_to'],
                leased_at=row['started_at'] or time.time(),
                lease_expires_at=row['lease_expires_at'] or time.time(),
                idempotency_key=row['idempotency_key'] or "",
                execution_token_hash=tok_hash,
                plan_id=row['plan_id'],
                step_id=row['step_id'],
            )

    def renew_lease(self, job_id: str, worker_id: str, extension_seconds: int = 30, lease_ttl_seconds: Optional[int] = None) -> bool:
        """Worker heartbeat: Renews lease deadline while long-running task is active."""
        ext = lease_ttl_seconds if lease_ttl_seconds is not None else extension_seconds
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            new_exp = now + ext
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET lease_expires_at = ? 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (new_exp, job_id, worker_id, now))
            conn.commit()
            return cursor.rowcount > 0

    def mark_executing(self, job_id: str, worker_id: str) -> bool:
        """Mark job as actively executing on worker with status and lease expiration verification."""
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ? 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (JobState.EXECUTING.value, job_id, worker_id, now))
            conn.commit()
            return cursor.rowcount > 0

    def mark_executing_and_consume_token(
        self,
        job_id: str,
        worker_id: str,
        token_id: Optional[str] = None,
        nonce: Optional[str] = None,
        token_expires_at: Optional[float] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Atomically validate unexpired lease ownership, recheck token expiry, transition job to EXECUTING,
        and record consumed token within a single SQLite IMMEDIATE transaction boundary.
        Returns: (success: bool, error_reason: Optional[str])
        """
        try:
            with self._get_connection() as conn:
                # Acquiring the write lock is part of the security boundary: expiry
                # is only authoritative when sampled after this succeeds. Never
                # continue under a deferred/autocommit transaction if it fails.
                conn.execute("BEGIN IMMEDIATE")

                # Sample time AFTER acquiring transaction write lock
                now = time.time()

                # 1. Immediate token expiry re-check right at activation boundary inside write lock
                if token_expires_at and token_expires_at > 0 and now > token_expires_at:
                    if hasattr(conn, "rollback"):
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                    return False, "TOKEN_EXPIRED"

                job_row = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?", (job_id,)).fetchone()
                if job_row and job_row["execution_token"]:
                    from ciph.kernel.crypto_identity import ExecutionToken, retry_nonce
                    stored = ExecutionToken.from_dict(json.loads(job_row["execution_token"]))
                    if (stored.token_id, stored.nonce) != (token_id, nonce):
                        return False, "TOKEN_REPLAYED"
                    if stored.token_id.startswith("tok_retry_"):
                        lineage = conn.execute("SELECT * FROM ciph_retry_tokens WHERE token_id = ?", (token_id,)).fetchone()
                        if not lineage:
                            return False, "TOKEN_REPLAYED"
                        parent = ExecutionToken.from_dict(json.loads(lineage["parent_token"]))
                        if (lineage["job_id"] != job_id
                            or not lineage["attempt_number"] <= job_row["attempt_number"] <= stored.max_attempts
                            or stored.nonce != retry_nonce(parent, job_id, lineage["attempt_number"])
                            or stored.to_dict() != json.loads(lineage["token"])):
                            return False, "TOKEN_REPLAYED"

                # 2. Check and transition lease ownership to EXECUTING
                cursor = conn.execute("""
                    UPDATE ciph_ipc_jobs 
                    SET status = ? 
                    WHERE job_id = ? AND leased_to = ? AND status = 'LEASED' AND lease_expires_at > ?;
                """, (JobState.EXECUTING.value, job_id, worker_id, now))
                if cursor.rowcount == 0:
                    if hasattr(conn, "rollback"):
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                    return False, "LEASE_LOST"

                # 3. Transactionally record consumed token & nonce if present
                if token_id and nonce:
                    try:
                        conn.execute("""
                            INSERT INTO ciph_consumed_tokens (token_id, nonce, job_id, worker_id, consumed_at)
                            VALUES (?, ?, ?, ?, ?)
                        """, (token_id, nonce, job_id, worker_id, now))
                    except sqlite3.IntegrityError:
                        if hasattr(conn, "rollback"):
                            try:
                                conn.rollback()
                            except Exception:
                                pass
                        return False, "TOKEN_REPLAYED"
                    except Exception as ex:
                        if hasattr(conn, "rollback"):
                            try:
                                conn.rollback()
                            except Exception:
                                pass
                        return False, f"STORAGE_FAILURE: {ex}"

                # 3.5. Atomically record ExecutionAttemptStartedEvent in ciph_event_store
                try:
                    if job_row:
                        cap = str(job_row["capability"])
                        att_num = int(job_row["attempt_number"])
                        t_id = token_id or (stored.token_id if 'stored' in locals() and stored else "")
                        t_hash = stored.token_hash() if 'stored' in locals() and stored else ""
                        m_ver = stored.manifest_version if 'stored' in locals() and stored else ""
                        m_hash = stored.manifest_hash if 'stored' in locals() and stored else ""
                        p_hash = stored.parameters_hash if 'stored' in locals() and stored else ""
                        plan_hash = stored.plan_hash if 'stored' in locals() and stored else ""
                        step_id = stored.step_id if 'stored' in locals() and stored else ""

                        attempt_payload = {
                            "job_id": job_id,
                            "attempt_number": att_num,
                            "capability": cap,
                            "worker_id": worker_id,
                            "token_id": t_id,
                            "token_hash": t_hash,
                            "manifest_version": m_ver,
                            "manifest_hash": m_hash,
                            "parameters_hash": p_hash,
                            "plan_hash": plan_hash,
                            "step_id": step_id,
                            "started_at": now
                        }
                        if 'stored' in locals() and stored:
                            from ciph.workers.activation_evidence import activation_message
                            from ciph.kernel.crypto_identity import Ed25519KeyManager
                            pair = self.trust_registry.get_keypair(stored.kernel_key_id) if self.trust_registry else None
                            if pair is None:
                                raise PermissionError("ACTIVATION_SIGNING_AUTHORITY_UNAVAILABLE")
                            attempt_payload.update({
                                "token": stored.to_dict(),
                                "activation_key_id": stored.kernel_key_id,
                                "idempotency_key": job_row["idempotency_key"],
                                "plan_id": job_row["plan_id"],
                                "lease_expires_at": job_row["lease_expires_at"],
                            })
                            attempt_payload["activation_signature"] = Ed25519KeyManager.sign(
                                pair[0], activation_message(attempt_payload)
                            )

                        attempt_payload_str = json.dumps(attempt_payload, sort_keys=True)
                        aggregate_id = f"attempt:{job_id}:{att_num}"

                        prev_cursor = conn.execute("SELECT event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1;")
                        prev_row = prev_cursor.fetchone()
                        prev_hash = prev_row[0] if prev_row else "GENESIS_BLOCK_CIPH_4.0"

                        hash_input = f"{prev_hash}|ExecutionAttemptStartedEvent|{aggregate_id}|{attempt_payload_str}|{now}"
                        ev_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

                        conn.execute("""
                            INSERT INTO ciph_event_store
                            (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash)
                            VALUES ('ExecutionAttemptStartedEvent', ?, ?, ?, ?, ?);
                        """, (aggregate_id, attempt_payload_str, now, prev_hash, ev_hash))
                except Exception as ex:
                    if hasattr(conn, "rollback"):
                        try:
                            conn.rollback()
                        except Exception:
                            pass
                    return False, f"STORAGE_FAILURE: {ex}"

                # 4. Atomically commit transaction - fail closed if commit fails
                if hasattr(conn, "commit"):
                    conn.commit()
                return True, None
        except Exception as outer_ex:
            return False, f"STORAGE_FAILURE: {outer_ex}"

    def _verify_receipt_ingress(
        self,
        job_id: str,
        worker_id: str,
        receipt_dict: Dict[str, Any],
        job_row: sqlite3.Row,
        now: float
    ) -> bool:
        """
        Cryptographically verify receipt ingress and bind every signed field to the committed job record.
        Applied symmetrically to both success and failure receipts.
        Ingress verifies ONLY through the public TrustRegistry when present, rejecting registry failure
        without private-key/HMAC fallback.
        """
        worker_signature = receipt_dict.get("worker_signature")
        if not worker_signature:
            return False

        # 1. Cryptographic signature verification
        # Malformed or unsupported receipt evidence is a definitive rejection. Storage faults
        # (sqlite3.Error and other non-evidence failures) deliberately propagate: a transient
        # database failure under load must never be indistinguishable from a security rejection.
        try:
            receipt_obj = ExecutionReceipt.from_dict(receipt_dict)
            if self.trust_registry is not None or self.worker_secret_key is not None:
                is_valid = receipt_obj.verify_signature(
                    secret_key=self.worker_secret_key,
                    trust_registry=self.trust_registry,
                    current_time=now
                )
                if not is_valid:
                    return False
            else:
                return False
        except (KeyError, TypeError, ValueError):
            return False

        # 2. Output hash payload verification
        computed_output_hash = ExecutionReceipt.hash_payload(receipt_dict.get("results", {}))
        if receipt_dict.get("output_hash") != computed_output_hash:
            return False

        # 3. Context binding to committed job record
        if receipt_dict.get("job_id") != job_id:
            return False
        if receipt_dict.get("capability") != job_row["capability"]:
            return False
        if receipt_dict.get("worker_id") != worker_id or receipt_dict.get("worker_id") != job_row["leased_to"]:
            return False
        if receipt_dict.get("attempt_number") != job_row["attempt_number"]:
            return False
        if receipt_dict.get("input_hash") != ExecutionReceipt.hash_payload(json.loads(job_row["params"])):
            return False
        if receipt_dict.get("idempotency_key") != job_row["idempotency_key"]:
            return False

        plan_id = job_row["plan_id"]
        if plan_id and receipt_dict.get("plan_id") and receipt_dict.get("plan_id") != plan_id:
            return False

        step_id = job_row["step_id"]
        if step_id and receipt_dict.get("step_id") and receipt_dict.get("step_id") != step_id:
            return False

        # 4. Token parameters and capability binding
        if job_row["execution_token"]:
            try:
                tok_data = json.loads(job_row["execution_token"])
                expected_params_hash = tok_data.get("parameters_hash")
                receipt_input_hash = receipt_dict.get("input_hash")
                if expected_params_hash and receipt_input_hash and expected_params_hash != receipt_input_hash:
                    return False
                if tok_data.get("capability") and tok_data.get("capability") != job_row["capability"]:
                    return False
            except (TypeError, ValueError):
                return False

        # 5. Timing boundaries: cannot be completed in the future or before the job was created
        created_at = job_row["created_at"]
        completed_at = receipt_dict.get("completed_at")
        if completed_at is not None:
            if completed_at > now + 5.0 or (created_at and completed_at < created_at - 1.0):
                return False

        return True

    def complete_job_and_append_receipt_event(
        self,
        job_id: str,
        worker_id: str,
        receipt_dict: Dict[str, Any]
    ) -> int:
        """
        Atomically mark job SUCCEEDED and insert ExecutionReceiptStoredEvent into EventStore
        within a SINGLE SQLite IMMEDIATE transaction boundary with CAS lease guard and ingress verification.
        """
        if receipt_dict.get("exit_code") != 0 or receipt_dict.get("outcome") != "SUCCESS":
            return 0
        import hashlib
        res_str = json.dumps(receipt_dict.get("results", {}), sort_keys=True, default=str)
        payload_str = json.dumps(receipt_dict, sort_keys=True, default=str)
        receipt_id = receipt_dict.get("receipt_id", f"rcpt_{uuid.uuid4().hex[:12]}")
        worker_signature = receipt_dict.get("worker_signature")

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            cur = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            job_row = cur.fetchone()
            if not job_row or job_row['status'] not in ('LEASED', 'EXECUTING') or job_row['leased_to'] != worker_id or (job_row['lease_expires_at'] and job_row['lease_expires_at'] < now):
                return 0

            # Cryptographic & Job Binding Ingress Gate
            if not self._verify_receipt_ingress(job_id, worker_id, receipt_dict, job_row, now):
                return 0

            # 1. Update job status with CAS guard (only active unexpired lease holder can complete)
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, result = ?, receipt_id = ?, worker_signature = ?,
                    completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (JobState.SUCCEEDED.value, res_str, receipt_id, worker_signature, now, job_id, worker_id, now))

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

    def _prepare_retry_token(self, conn, job, receipt, now):
        """Renew only consumed authority for this authenticated failed execution."""
        from ciph.kernel.crypto_identity import ExecutionToken, mint_attempt_token
        parent = ExecutionToken.from_dict(json.loads(job["execution_token"]))
        consumed = conn.execute(
            "SELECT * FROM ciph_consumed_tokens WHERE token_id = ? AND nonce = ?",
            (parent.token_id, parent.nonce),
        ).fetchone()
        if (not consumed or consumed["job_id"] != job["job_id"]
            or consumed["worker_id"] != job["leased_to"]
            or receipt.get("provenance", {}).get("execution_token_hash") != parent.token_hash()
            or parent.execution_lane not in ("LANE_1_READ_ONLY", "LANE_2_LOCAL_MATH", "LANE_3_OBSERVATION")
            or job["attempt_number"] >= parent.max_attempts):
            raise PermissionError("RETRY_EVIDENCE_MISSING_OR_EXHAUSTED")
        pair = self.trust_registry.get_keypair(parent.kernel_key_id)
        if pair is None:
            raise PermissionError("RETRY_SIGNING_AUTHORITY_UNAVAILABLE")
        fresh = mint_attempt_token(
            parent, kernel_private_key_bytes=pair[0], trust_registry=self.trust_registry,
            current_time=now, job_id=job["job_id"], attempt_number=job["attempt_number"] + 1,
        )
        serialized = json.dumps(fresh.to_dict())
        conn.execute("""
            INSERT INTO ciph_retry_tokens
            (token_id, parent_token_id, job_id, attempt_number, parent_token, token)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (fresh.token_id, parent.token_id, job["job_id"], job["attempt_number"] + 1,
              json.dumps(parent.to_dict()), serialized))
        return serialized

    def fail_job_and_append_receipt_event(
        self,
        job_id: str,
        worker_id: str,
        error: str,
        receipt_dict: Dict[str, Any]
    ) -> int:
        """
        Atomically mark job FAILED/RETRYING and insert ExecutionReceiptStoredEvent into EventStore
        within a SINGLE SQLite IMMEDIATE transaction boundary with CAS lease guard and ingress verification.
        """
        import hashlib
        payload_str = json.dumps(receipt_dict, sort_keys=True, default=str)
        receipt_id = receipt_dict.get("receipt_id", f"rcpt_{uuid.uuid4().hex[:12]}")
        worker_signature = receipt_dict.get("worker_signature")

        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            cur = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            job_row = cur.fetchone()
            if not job_row or job_row['status'] not in ('LEASED', 'EXECUTING') or job_row['leased_to'] != worker_id or (job_row['lease_expires_at'] and job_row['lease_expires_at'] < now):
                return 0

            # Cryptographic & Job Binding Ingress Gate (exact same gate applied to failure)
            if not self._verify_receipt_ingress(job_id, worker_id, receipt_dict, job_row, now):
                return 0

            next_status = JobState.FAILED.value
            next_token = job_row["execution_token"]
            if (receipt_dict.get("exit_code", 0) == 0
                or receipt_dict.get("outcome") == "SUCCESS"):
                return 0
            if (job_row['attempt_number'] < job_row['max_retries']
                and receipt_dict.get("outcome") == "EXECUTION_ERROR"
                and not receipt_dict.get("side_effects")
                and receipt_dict.get("provenance", {}).get("reversibility") == "READ_ONLY"):
                if next_token:
                    try:
                        next_token = self._prepare_retry_token(conn, job_row, receipt_dict, now)
                        next_status = JobState.RETRYING.value
                    except PermissionError:
                        next_status = JobState.FAILED.value
                else:
                    next_status = JobState.RETRYING.value

            # 1. Update job status with CAS guard (enforce leased_to = worker_id and active lease)
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, error = ?, receipt_id = ?, worker_signature = ?, execution_token = ?,
                    completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (next_status, error, receipt_id, worker_signature, next_token, now, job_id, worker_id, now))

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
        worker_signature: Optional[str] = None,
        receipt_dict: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Mark job successfully completed with CAS ownership guard and cryptographic verification."""
        res_str = json.dumps(result, sort_keys=True, default=str) if result else None
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            cursor = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            job_row = cursor.fetchone()
            if not job_row:
                return False
            if job_row["leased_to"] != worker_id or job_row["status"] not in (JobState.LEASED.value, JobState.EXECUTING.value) or (job_row["lease_expires_at"] and job_row["lease_expires_at"] < now):
                return False

            # If worker_signature or receipt_dict is provided, strictly verify it!
            if receipt_dict is not None:
                if not self._verify_receipt_ingress(job_id, worker_id, receipt_dict, job_row, now):
                    return False
            elif worker_signature is not None:
                # Cryptographically verify the worker signature
                payload = f"COMPLETE:{job_id}:{job_row['capability']}:{worker_id}:{receipt_id}:{res_str}".encode('utf-8')
                is_valid = False
                if self.trust_registry:
                    is_valid, _ = self.trust_registry.verify_signature_at_time(worker_id, payload, worker_signature, now)
                    if not is_valid and self.trust_registry.get_key("worker_primary"):
                        is_valid, _ = self.trust_registry.verify_signature_at_time("worker_primary", payload, worker_signature, now)
                if not is_valid and self.worker_secret_key:
                    try:
                        from ciph.kernel.crypto_identity import Ed25519KeyManager
                        is_valid = Ed25519KeyManager.verify(self.worker_secret_key, payload, worker_signature)
                    except Exception:
                        pass
                    if not is_valid:
                        expected = hmac.new(self.worker_secret_key, payload, hashlib.sha256).hexdigest()
                        is_valid = hmac.compare_digest(worker_signature, expected)
                if not is_valid:
                    return False
            elif job_row["execution_token"] is not None:
                # Jobs under governed execution token strictly require cryptographic receipt verification
                return False

            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, result = ?, receipt_id = ?, worker_signature = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (JobState.SUCCEEDED.value, res_str, receipt_id, worker_signature, now, job_id, worker_id, now))
            conn.commit()
            return cursor.rowcount > 0

    def fail_job(
        self,
        job_id: str,
        worker_id: str,
        error: str,
        worker_signature: Optional[str] = None,
        receipt_dict: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Mark job failed or increment attempt for retry with CAS ownership guard and cryptographic check."""
        if receipt_dict is not None:
            return bool(self.fail_job_and_append_receipt_event(job_id, worker_id, error, receipt_dict))
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            cursor = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            job_row = cursor.fetchone()
            if not job_row or job_row["execution_token"] is not None or job_row["status"] == "EXECUTING":
                return False
            if job_row["leased_to"] != worker_id or job_row["status"] not in (JobState.LEASED.value, JobState.EXECUTING.value) or (job_row["lease_expires_at"] and job_row["lease_expires_at"] < now):
                return False

            if receipt_dict is not None:
                if not self._verify_receipt_ingress(job_id, worker_id, receipt_dict, job_row, now):
                    return False
            elif worker_signature is not None:
                payload = f"FAIL:{job_id}:{job_row['capability']}:{worker_id}:{error}".encode('utf-8')
                is_valid = False
                if self.trust_registry:
                    is_valid, _ = self.trust_registry.verify_signature_at_time(worker_id, payload, worker_signature, now)
                if not is_valid and self.worker_secret_key:
                    try:
                        from ciph.kernel.crypto_identity import Ed25519KeyManager
                        is_valid = Ed25519KeyManager.verify(self.worker_secret_key, payload, worker_signature)
                    except Exception:
                        pass
                    if not is_valid:
                        expected = hmac.new(self.worker_secret_key, payload, hashlib.sha256).hexdigest()
                        is_valid = hmac.compare_digest(worker_signature, expected)
                if not is_valid:
                    return False

            if job_row['attempt_number'] < job_row['max_retries']:
                next_status = JobState.RETRYING.value
            else:
                next_status = JobState.FAILED.value

            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, error = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (next_status, error, now, job_id, worker_id, now))
            conn.commit()
            return cursor.rowcount > 0

    def fail_job_containment_denied(
        self,
        job_id: str,
        worker_id: str,
        error: str,
        denial_payload: Dict[str, Any]
    ) -> bool:
        """
        Atomically mark a leased/executing job FAILED due to containment unavailability
        and append SandboxDeniedEvent into EventStore within a single atomic transaction,
        without manufacturing or requiring an ExecutionReceipt.
        """
        payload_str = json.dumps(denial_payload, sort_keys=True, default=str)
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            cursor = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            job_row = cursor.fetchone()
            if not job_row or job_row["leased_to"] != worker_id or job_row["status"] not in (JobState.LEASED.value, JobState.EXECUTING.value) or (job_row["lease_expires_at"] and job_row["lease_expires_at"] < now):
                return False

            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, error = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (JobState.FAILED.value, error, now, job_id, worker_id, now))
            if cursor.rowcount == 0:
                conn.commit()
                return False

            cursor = conn.execute("SELECT event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1;")
            row = cursor.fetchone()
            prev_hash = row['event_hash'] if row else "GENESIS_BLOCK_CIPH_4.0"

            hash_input = f"{prev_hash}|SandboxDeniedEvent|sandbox:denial:{job_id}|{payload_str}|{now}"
            event_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

            conn.execute("""
                INSERT INTO ciph_event_store 
                (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash)
                VALUES ('SandboxDeniedEvent', ?, ?, ?, ?, ?);
            """, (f"sandbox:denial:{job_id}", payload_str, now, prev_hash, event_hash))
            conn.commit()
            return True

    def mark_job_uncertain(
        self,
        job_id: str,
        worker_id: str,
        reason: str,
        receipt_dict: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Atomically mark job RECONCILIATION_REQUIRED when execution outcome or cleanup
        is uncertain, appending JobReconciliationRequiredEvent into EventStore.
        """
        payload = {
            "job_id": job_id,
            "worker_id": worker_id,
            "reason": reason,
            "receipt": receipt_dict,
        }
        payload_str = json.dumps(payload, sort_keys=True, default=str)
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            cursor = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            job_row = cursor.fetchone()
            if not job_row or job_row["leased_to"] != worker_id or job_row["status"] not in (JobState.LEASED.value, JobState.EXECUTING.value) or (job_row["lease_expires_at"] and job_row["lease_expires_at"] < now):
                return False

            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = 'RECONCILIATION_REQUIRED', error = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ? AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (f"UNCERTAIN: {reason}", now, job_id, worker_id, now))
            if cursor.rowcount == 0:
                conn.commit()
                return False

            cursor = conn.execute("SELECT event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1;")
            row = cursor.fetchone()
            prev_hash = row['event_hash'] if row else "GENESIS_BLOCK_CIPH_4.0"

            hash_input = f"{prev_hash}|JobReconciliationRequiredEvent|reconciliation:{job_id}|{payload_str}|{now}"
            event_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

            conn.execute("""
                INSERT INTO ciph_event_store 
                (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash)
                VALUES ('JobReconciliationRequiredEvent', ?, ?, ?, ?, ?);
            """, (f"reconciliation:{job_id}", payload_str, now, prev_hash, event_hash))
            conn.commit()
            return True

    def quarantine_job(self, job_id: str, worker_id: str, reason: str) -> bool:
        """Quarantine only an ungoverned job held by its active lease owner."""
        if not isinstance(reason, str) or not reason.strip():
            return False
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            row = conn.execute(
                "SELECT execution_token FROM ciph_ipc_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            # Governed jobs can only reach QUARANTINED through signed operator
            # reconciliation, which also emits JobReconciledEvent evidence.
            if not row or row["execution_token"] is not None:
                return False
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = ?, error = ?, completed_at = ?, leased_to = NULL, lease_expires_at = NULL 
                WHERE job_id = ? AND leased_to = ?
                  AND status IN ('LEASED', 'EXECUTING') AND lease_expires_at > ?;
            """, (
                JobState.QUARANTINED.value,
                f"QUARANTINED: {reason.strip()}",
                now,
                job_id,
                worker_id,
                now,
            ))
            conn.commit()
            return cursor.rowcount > 0

    def mark_reconciliation_required(
        self, job_id: str, worker_id: str, error: str,
        receipt_dict: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Preserve authenticated in-flight evidence atomically without retrying it."""
        if not receipt_dict or not error:
            return False
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            job = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if (not job or job["status"] != "EXECUTING" or job["leased_to"] != worker_id
                or not job["lease_expires_at"] or job["lease_expires_at"] <= now
                or not self._verify_receipt_ingress(job_id, worker_id, receipt_dict, job, now)):
                return False
            receipt_json = json.dumps(receipt_dict, sort_keys=True, default=str)
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs
                SET status = 'RECONCILIATION_REQUIRED', error = ?, result = ?,
                    receipt_id = ?, worker_signature = ?, pending_receipt = ?, completed_at = ?,
                    leased_to = NULL, lease_expires_at = NULL
                WHERE job_id = ? AND status = 'EXECUTING' AND leased_to = ? AND lease_expires_at > ?
            """, (error, json.dumps(receipt_dict["results"], sort_keys=True, default=str),
                  receipt_dict["receipt_id"], receipt_dict["worker_signature"], receipt_json,
                  now, job_id, worker_id, now))
            payload = json.dumps({"job_id": job_id, "worker_id": worker_id, "error": error,
                                  "receipt": receipt_dict}, sort_keys=True, default=str)
            previous = conn.execute("SELECT event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1").fetchone()
            previous_hash = previous["event_hash"] if previous else "GENESIS_BLOCK_CIPH_4.0"
            digest = hashlib.sha256(f"{previous_hash}|ReconciliationRequiredEvent|{job_id}|{payload}|{now}".encode()).hexdigest()
            conn.execute("""INSERT INTO ciph_event_store
                (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash)
                VALUES ('ReconciliationRequiredEvent', ?, ?, ?, ?, ?)""",
                (job_id, payload, now, previous_hash, digest))
            conn.commit()
            return cursor.rowcount > 0

    def reclaim_expired_leases(self, calling_holder_id: Optional[str] = None) -> int:
        """
        Watchdog: Reclaims jobs whose worker lease expired without a completion/heartbeat.
        - Jobs expired in LEASED state (prior to execution) safely transition to RETRYING if attempt_number < max_retries.
        - Jobs expired in LEASED state with exhausted retries transition to FAILED.
        - Jobs expired in EXECUTING state (execution was in-flight with potential external side effects)
          transition to RECONCILIATION_REQUIRED to prevent blind automatic retries.
        """
        now = time.time()
        with self._get_connection(calling_holder_id=calling_holder_id) as conn:
            # 1a. Pre-execution lease expiry with retries remaining -> RETRYING
            c1 = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = 'RETRYING', leased_to = NULL, lease_expires_at = NULL 
                WHERE status = 'LEASED' AND lease_expires_at < ? AND attempt_number < max_retries;
            """, (now,))

            # 1b. Pre-execution lease expiry with retries exhausted -> FAILED
            c_fail = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = 'FAILED', leased_to = NULL, lease_expires_at = NULL,
                    error = 'Max retries exhausted upon pre-execution lease expiry' 
                WHERE status = 'LEASED' AND lease_expires_at < ? AND attempt_number >= max_retries;
            """, (now,))

            # 2. In-flight execution lease expiry -> RECONCILIATION_REQUIRED (constitutional crash recovery)
            c2 = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = 'RECONCILIATION_REQUIRED', leased_to = NULL, lease_expires_at = NULL,
                    error = 'Worker lease expired while EXECUTING (uncertain side effects) - reconciliation required'
                WHERE status = 'EXECUTING' AND lease_expires_at < ?;
            """, (now,))

            conn.commit()
            return c1.rowcount + c_fail.rowcount + c2.rowcount

    def _resolve_active_operator_public_key(self, operator_id: str) -> bytes:
        """Resolve reconciliation authority exclusively through the public registry."""
        if self.trust_registry is None:
            raise PermissionError("Reconciliation failed: No authoritative TrustRegistry is available.")

        from ciph.kernel.crypto_identity import KeyRole

        key_rec = self.trust_registry.get_key(operator_id)
        if key_rec is None:
            raise PermissionError(
                f"Reconciliation failed: Identity '{operator_id}' is not enrolled in the authoritative TrustRegistry."
            )
        if str(key_rec.get("status", "")).upper() != "ACTIVE":
            raise PermissionError(
                f"Reconciliation failed: Operator key '{operator_id}' is revoked or inactive in trust registry "
                f"(status: '{key_rec.get('status')}')."
            )
        if str(key_rec.get("role", "")).upper() != KeyRole.OPERATOR.value:
            raise PermissionError(
                f"Reconciliation failed: Identity '{operator_id}' is not an authorized OPERATOR "
                f"(role: '{key_rec.get('role')}')."
            )

        public_key_hex = str(key_rec.get("public_key_hex", "")).lower()
        pinned_hex = getattr(self.trust_registry, "pinned_operator_pub_hex", None)
        if operator_id == "operator_root" and pinned_hex and public_key_hex != str(pinned_hex).lower():
            raise PermissionError("Reconciliation failed: operator_root does not match the durable root pin.")
        try:
            public_key = bytes.fromhex(public_key_hex)
        except (TypeError, ValueError):
            raise PermissionError(
                f"Reconciliation failed: Operator key '{operator_id}' has malformed public-key material."
            )
        if len(public_key) != 32:
            raise PermissionError(
                f"Reconciliation failed: Operator key '{operator_id}' has malformed public-key material."
            )
        return public_key

    def verify_reconciliation_event(
        self,
        job: Dict[str, Any],
        event: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Verify a stored reconciliation event and all terminal-job bindings."""
        try:
            if not isinstance(job, dict) or not isinstance(event, dict):
                return False, "MALFORMED_RECONCILIATION_EVIDENCE"
            job_id = job.get("job_id")
            if event.get("event_type") != "JobReconciledEvent" or event.get("aggregate_id") != job_id:
                return False, "RECONCILIATION_EVENT_CONTEXT_MISMATCH"

            payload = event.get("payload")
            if isinstance(payload, str):
                payload = json.loads(payload)
            if not isinstance(payload, dict):
                return False, "MALFORMED_RECONCILIATION_PAYLOAD"

            state = str(payload.get("target_state", ""))
            allowed_states = {
                JobState.SUCCEEDED.value,
                JobState.COMPLETED.value,
                JobState.FAILED.value,
                JobState.QUARANTINED.value,
            }
            if payload.get("job_id") != job_id or state not in allowed_states or state != job.get("status"):
                return False, "RECONCILIATION_JOB_STATE_MISMATCH"

            notes = payload.get("resolution_notes")
            result = payload.get("result")
            operator_id = payload.get("operator_id")
            signature = payload.get("operator_signature")
            if not isinstance(notes, str) or len(notes.strip()) < 10:
                return False, "INVALID_RECONCILIATION_NOTES"
            if not isinstance(result, dict):
                return False, "INVALID_RECONCILIATION_RESULT"
            if not isinstance(operator_id, str) or not operator_id.strip():
                return False, "INVALID_RECONCILIATION_OPERATOR"
            if not isinstance(signature, str) or not signature.strip():
                return False, "INVALID_RECONCILIATION_SIGNATURE"

            # The event payload, terminal row, and audit annotation must describe
            # exactly the same operator decision. Never prefer mutable row data.
            if job.get("result") != result:
                return False, "RECONCILIATION_RESULT_MISMATCH"
            if job.get("error") != f"Reconciled ({operator_id}): {notes.strip()}":
                return False, "RECONCILIATION_AUDIT_MISMATCH"

            reconciled_at = float(payload.get("reconciled_at"))
            event_time = float(event.get("timestamp"))
            completed_at = float(job.get("completed_at"))
            created_at = float(job.get("created_at"))
            if abs(reconciled_at - event_time) > 1e-6 or abs(completed_at - reconciled_at) > 1e-6:
                return False, "RECONCILIATION_TIMESTAMP_MISMATCH"
            if reconciled_at < created_at:
                return False, "RECONCILIATION_PRECEDES_JOB"

            result_digest = hashlib.sha256(
                json.dumps(result, sort_keys=True).encode("utf-8")
            ).hexdigest()
            message = f"RECONCILE:{job_id}:{state}:{result_digest}:{notes.strip()}".encode("utf-8")
            public_key = self._resolve_active_operator_public_key(operator_id)

            from ciph.kernel.crypto_identity import Ed25519KeyManager
            if not Ed25519KeyManager.verify(public_key, message, signature):
                return False, "INVALID_RECONCILIATION_SIGNATURE"
            return True, "VALID"
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return False, f"MALFORMED_RECONCILIATION_EVIDENCE: {exc}"
        except PermissionError as exc:
            return False, str(exc)

    def reconcile_job(
        self,
        job_id: str,
        target_state: Union[JobState, str],
        resolution_notes: str,
        result: Optional[Dict[str, Any]] = None,
        operator_id: str = "operator_root",
        operator_signature: Optional[str] = None
    ) -> bool:
        """
        Governed reconciliation transition: resolves a RECONCILIATION_REQUIRED job
        after deterministic verification and operator authorization.
        - Whitelists allowed terminal target states: SUCCEEDED, COMPLETED, FAILED, QUARANTINED.
        - Rejects transitioning back to active or unexecuted states (QUEUED, LEASED, EXECUTING, RETRYING).
        - Enforces non-empty resolution_notes of at least 10 characters.
        - Validates operator identity and verifies cryptographic operator signature when provided.
        - Atomically inserts a JobReconciledEvent into ciph_event_store within the same transaction.
        """
        # 1. Target state validation: strictly whitelist terminal states
        allowed_states = {
            JobState.SUCCEEDED.value,
            JobState.COMPLETED.value,
            JobState.FAILED.value,
            JobState.QUARANTINED.value
        }
        state_val = target_state.value if hasattr(target_state, "value") else str(target_state)
        if state_val not in allowed_states:
            raise ValueError(
                f"Invalid reconciliation target_state '{state_val}'. "
                f"Reconciliation cannot transition to active/unexecuted states (QUEUED, LEASED, EXECUTING, RETRYING). "
                f"Allowed states: {sorted(list(allowed_states))}."
            )

        # 2. Resolution notes validation
        if not resolution_notes or not isinstance(resolution_notes, str) or len(resolution_notes.strip()) < 10:
            raise ValueError("Reconciliation requires detailed resolution_notes (minimum 10 non-whitespace characters).")

        # 3. Operator identity & signature validation
        if not operator_id or not isinstance(operator_id, str) or not operator_id.strip():
            raise ValueError("Reconciliation requires non-empty operator_id.")

        if not operator_signature or not isinstance(operator_signature, str) or not operator_signature.strip():
            raise PermissionError(f"Reconciliation requires a valid cryptographic operator signature for operator '{operator_id}'.")

        res_dict = result or {}
        res_str = json.dumps(res_dict, sort_keys=True)
        res_digest = hashlib.sha256(res_str.encode('utf-8')).hexdigest()
        recon_payload_msg = f"RECONCILE:{job_id}:{state_val}:{res_digest}:{resolution_notes.strip()}".encode('utf-8')

        from ciph.kernel.crypto_identity import Ed25519KeyManager
        op_pub_bytes = self._resolve_active_operator_public_key(operator_id)

        sig_verified = False
        try:
            sig_verified = Ed25519KeyManager.verify(op_pub_bytes, recon_payload_msg, operator_signature)
        except Exception:
            sig_verified = False

        if not sig_verified:
            raise PermissionError(f"Reconciliation failed: Invalid operator signature for operator '{operator_id}'.")

        now = time.time()

        with self._get_connection() as conn:
            cur = conn.execute("SELECT * FROM ciph_ipc_jobs WHERE job_id = ?;", (job_id,))
            job_row = cur.fetchone()
            if not job_row or job_row['status'] != JobState.RECONCILIATION_REQUIRED.value:
                return False

            err_text = f"Reconciled ({operator_id}): {resolution_notes.strip()}"
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs
                SET status = ?, error = ?, result = ?, completed_at = ?,
                    receipt_id = NULL, worker_signature = NULL
                WHERE job_id = ? AND status = 'RECONCILIATION_REQUIRED';
            """, (state_val, err_text, res_str, now, job_id))

            if cursor.rowcount == 0:
                conn.commit()
                return False

            # Append JobReconciledEvent to EventStore in the exact same transaction
            cursor = conn.execute("SELECT event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1;")
            row = cursor.fetchone()
            prev_hash = row['event_hash'] if row else "GENESIS_BLOCK_CIPH_4.0"

            event_payload = {
                "job_id": job_id,
                "target_state": state_val,
                "resolution_notes": resolution_notes.strip(),
                "result": res_dict,
                "operator_id": operator_id,
                "operator_signature": operator_signature,
                "reconciled_at": now
            }
            payload_str = json.dumps(event_payload, sort_keys=True, default=str)
            hash_input = f"{prev_hash}|JobReconciledEvent|{job_id}|{payload_str}|{now}"
            event_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

            conn.execute("""
                INSERT INTO ciph_event_store 
                (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash)
                VALUES ('JobReconciledEvent', ?, ?, ?, ?, ?);
            """, (job_id, payload_str, now, prev_hash, event_hash))

            conn.commit()
            return True

    def dead_letter_unrecoverable_jobs(self) -> int:
        """Dead-letter only pre-execution work; in-flight work requires reconciliation."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_ipc_jobs 
                SET status = 'DEAD_LETTER', leased_to = NULL, lease_expires_at = NULL, error = 'Max retries exhausted upon lease expiry' 
                WHERE status IN ('LEASED', 'RETRYING') AND lease_expires_at < ? AND attempt_number >= max_retries;
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
                "execution_token": row['execution_token'] if 'execution_token' in row.keys() else None,
                "pending_receipt": json.loads(row["pending_receipt"]) if row["pending_receipt"] else None,
                "created_at": row['created_at'],
                "started_at": row['started_at'],
                "completed_at": row['completed_at']
            }
