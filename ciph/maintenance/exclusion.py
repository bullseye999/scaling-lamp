"""
ciph.maintenance.exclusion - Phase 9 Shared Exclusion Coordinator & Maintenance Lock.
Provides atomic CAS lease acquisition, Ed25519 OPERATOR authorization, idempotent
schema migration, and transparent write-only exclusion connection wrappers.
"""

import os
import time
import uuid
import json
import sqlite3
from typing import Optional, Tuple, Dict, Any

from ciph.kernel.crypto_identity import Ed25519KeyManager, KeyRole


class MaintenanceInProgressError(Exception):
    """Raised when an operation is rejected because exclusive maintenance is in progress."""
    pass


WRITE_ACTION_CODES = {
    sqlite3.SQLITE_INSERT,
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_ALTER_TABLE,
    sqlite3.SQLITE_DROP_TABLE,
    sqlite3.SQLITE_CREATE_TABLE,
    sqlite3.SQLITE_CREATE_INDEX,
    sqlite3.SQLITE_DROP_INDEX,
    sqlite3.SQLITE_ATTACH,
    sqlite3.SQLITE_DETACH,
}


WRITE_COMMANDS = (
    "INSERT", "UPDATE", "DELETE", "REPLACE",
    "BEGIN IMMEDIATE", "BEGIN EXCLUSIVE",
    "CREATE", "DROP", "ALTER", "VACUUM", "PRAGMA WAL_CHECKPOINT"
)


def check_write_exclusion(conn: sqlite3.Connection, calling_holder_id: Optional[str] = None, db_path: Optional[str] = None):
    """
    Checks if an exclusive maintenance lease is currently held on the database.
    Allows the write if calling_holder_id matches the active lease holder.
    Otherwise raises sqlite3.OperationalError.
    """
    now = time.time()
    # Fast in-memory check
    if db_path and SharedExclusionCoordinator.is_maintenance_active(db_path, calling_holder_id):
        active_holder = SharedExclusionCoordinator.get_active_holder(db_path) or "unknown"
        raise sqlite3.OperationalError(
            f"Database locked: Active exclusive maintenance lease held by '{active_holder}'."
        )

    # Durable database check
    try:
        cur = conn.execute("SELECT holder_id, expires_at FROM ciph_maintenance_leases WHERE expires_at > ? LIMIT 1;", (now,))
        row = cur.fetchone()
        if row:
            active_holder = row[0]
            if calling_holder_id != active_holder:
                raise sqlite3.OperationalError(
                    f"Database locked: Active exclusive maintenance lease held by '{active_holder}'."
                )
    except sqlite3.OperationalError as ex:
        if "no such table" not in str(ex):
            raise ex


class ExcludedCursor:
    """Cursor wrapper enforcing write-only maintenance exclusion."""

    def __init__(self, raw_cursor: sqlite3.Cursor, conn: sqlite3.Connection, calling_holder_id: Optional[str] = None, db_path: Optional[str] = None):
        self._cursor = raw_cursor
        self._conn = conn
        self._calling_holder_id = calling_holder_id
        self._db_path = db_path

    def execute(self, sql: str, params: tuple = ()):
        sql_clean = sql.strip().upper()
        if any(sql_clean.startswith(cmd) for cmd in WRITE_COMMANDS):
            check_write_exclusion(self._conn, self._calling_holder_id, self._db_path)
        return self._cursor.execute(sql, params)

    def executemany(self, sql: str, seq_of_params):
        sql_clean = sql.strip().upper()
        if any(sql_clean.startswith(cmd) for cmd in WRITE_COMMANDS):
            check_write_exclusion(self._conn, self._calling_holder_id, self._db_path)
        return self._cursor.executemany(sql, seq_of_params)

    def executescript(self, script: str):
        check_write_exclusion(self._conn, self._calling_holder_id, self._db_path)
        return self._cursor.executescript(script)

    def __getattr__(self, name: str):
        return getattr(self._cursor, name)

    def __iter__(self):
        return iter(self._cursor)


class ExcludedConnection:
    """
    Transparent SQLite connection wrapper enforcing write-only maintenance exclusion.
    Permits all read queries unhindered.
    Intercepts write commands, failing closed with sqlite3.OperationalError or sqlite3.DatabaseError
    unless calling_holder_id matches the active unexpired maintenance lease.
    """

    def __init__(self, raw_conn: sqlite3.Connection, calling_holder_id: Optional[str] = None, db_path: str = "ciph_vault.db"):
        self._conn = raw_conn
        self._calling_holder_id = calling_holder_id
        self._db_path = db_path

        # Install SQLite-layer authorizer covering all write paths (execute, executemany, cursor, executescript)
        def _authorizer(action_code, param1, param2, db_name, trigger_or_view):
            if action_code in WRITE_ACTION_CODES:
                if SharedExclusionCoordinator.is_maintenance_active(self._db_path, self._calling_holder_id):
                    return sqlite3.SQLITE_DENY
            elif action_code == sqlite3.SQLITE_PRAGMA:
                if param1 and str(param1).lower() in ("wal_checkpoint", "journal_mode", "synchronous", "auto_vacuum"):
                    if SharedExclusionCoordinator.is_maintenance_active(self._db_path, self._calling_holder_id):
                        return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self._conn.set_authorizer(_authorizer)

    def execute(self, sql: str, params: tuple = ()):
        sql_clean = sql.strip().upper()
        if any(sql_clean.startswith(cmd) for cmd in WRITE_COMMANDS):
            check_write_exclusion(self._conn, self._calling_holder_id, self._db_path)
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, seq_of_params):
        sql_clean = sql.strip().upper()
        if any(sql_clean.startswith(cmd) for cmd in WRITE_COMMANDS):
            check_write_exclusion(self._conn, self._calling_holder_id, self._db_path)
        return self._conn.executemany(sql, seq_of_params)

    def executescript(self, script: str):
        check_write_exclusion(self._conn, self._calling_holder_id, self._db_path)
        return self._conn.executescript(script)

    def cursor(self) -> ExcludedCursor:
        raw_cur = self._conn.cursor()
        return ExcludedCursor(raw_cur, self._conn, self._calling_holder_id, self._db_path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._conn.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, name: str):
        return getattr(self._conn, name)


class SharedExclusionCoordinator:
    """
    Phase 9 Shared Exclusion Coordinator.
    Manages atomic CAS acquisition, Ed25519 OPERATOR authentication, heartbeat renewal,
    and release of exclusive maintenance leases.
    """

    DEFAULT_LEASE_NAME = "global_db_maintenance"
    _active_leases: Dict[str, Tuple[str, float]] = {}

    @classmethod
    def _norm(cls, path: str) -> str:
        return os.path.abspath(path) if path else ""

    @classmethod
    def is_maintenance_active(cls, db_path: str, calling_holder_id: Optional[str] = None) -> bool:
        norm = cls._norm(db_path)
        rec = cls._active_leases.get(norm)
        if not rec:
            return False
        holder, expires = rec
        if time.time() > expires:
            cls._active_leases.pop(norm, None)
            return False
        return calling_holder_id != holder

    @classmethod
    def get_active_holder(cls, db_path: str) -> Optional[str]:
        norm = cls._norm(db_path)
        rec = cls._active_leases.get(norm)
        if rec and time.time() <= rec[1]:
            return rec[0]
        return None

    def __init__(self, db_path: str = "ciph_vault.db", trust_registry: Optional[Any] = None):
        self.db_path = db_path
        self.trust_registry = trust_registry
        self._init_db()

    def _init_db(self):
        """Idempotently ensures ciph_maintenance_leases exists and migrates older 4-column schemas."""
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_maintenance_leases (
                    lease_name TEXT PRIMARY KEY,
                    holder_id TEXT NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
            """)
            cur = conn.execute("PRAGMA table_info(ciph_maintenance_leases);")
            existing_cols = {row[1] for row in cur.fetchall()}

            col_definitions = [
                ("cycle_id", "TEXT NOT NULL DEFAULT ''"),
                ("task_name", "TEXT DEFAULT 'INIT'"),
                ("heartbeat_at", "REAL NOT NULL DEFAULT 0.0"),
                ("holder_signature", "TEXT NOT NULL DEFAULT ''")
            ]
            for col_name, col_type in col_definitions:
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE ciph_maintenance_leases ADD COLUMN {col_name} {col_type};")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_maint_expires ON ciph_maintenance_leases(expires_at);")
            conn.commit()

    @staticmethod
    def compute_statement(lease_name: str, holder_id: str, cycle_id: str, acquired_at: float, expires_at: float) -> bytes:
        """Constructs domain-separated canonical statement for Ed25519 signing."""
        return f"CIPH_MAINTENANCE_LEASE_V1:{lease_name}:{holder_id}:{cycle_id}:{acquired_at}:{expires_at}".encode('utf-8')

    def _verify_operator_authority(self, holder_id: str, signature: str, statement_bytes: bytes, timestamp: float):
        """Validates that holder_id resolves strictly to an active OPERATOR key in TrustRegistry."""
        if not self.trust_registry:
            raise PermissionError("MAINTENANCE_TRUST_REGISTRY_REQUIRED: Cannot verify operator authority without a configured TrustRegistry.")

        key_rec = self.trust_registry.get_key(holder_id)
        if not key_rec:
            raise PermissionError(f"MAINTENANCE_UNENROLLED_KEY: Key '{holder_id}' not found in TrustRegistry.")

        role = getattr(key_rec.get("role"), "value", key_rec.get("role"))
        if str(role).upper() != "OPERATOR":
            raise PermissionError(f"MAINTENANCE_UNAUTHORIZED_ROLE: Signer '{holder_id}' has role '{role}', expected 'OPERATOR'.")

        valid, reason = self.trust_registry.verify_signature_at_time(holder_id, statement_bytes, signature, timestamp)
        if not valid:
            raise PermissionError(f"MAINTENANCE_SIGNATURE_INVALID: {reason}")

    def acquire_lease(
        self,
        lease_name: str = DEFAULT_LEASE_NAME,
        holder_id: str = "operator_primary",
        operator_secret_key: Optional[bytes] = None,
        ttl_seconds: int = 30,
        cycle_id: Optional[str] = None,
        bypass_idle_checks: bool = False,
        quiescence_window_seconds: float = 10.0
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Atomically acquires exclusive maintenance lease under BEGIN IMMEDIATE.
        Verifies zero active jobs, zero searching curiosity questions, zero in-flight canaries,
        and durable quiescence window before inserting the signed lease.
        """
        cid = cycle_id or f"cycle_{uuid.uuid4().hex[:12]}"
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()  # Clock strictly sampled AFTER write lock is acquired

            # 1. Clear expired leases
            conn.execute("DELETE FROM ciph_maintenance_leases WHERE lease_name = ? AND expires_at < ?;", (lease_name, now))

            # 2. Check for active unexpired lease
            cur = conn.execute("SELECT holder_id FROM ciph_maintenance_leases WHERE lease_name = ?;", (lease_name,))
            if cur.fetchone():
                conn.rollback()
                return False, "LEASE_ALREADY_HELD", None

            # 3. In-transaction idle verification
            if not bypass_idle_checks:
                # 3a. Active jobs check
                try:
                    cur = conn.execute("SELECT COUNT(*) FROM ciph_ipc_jobs WHERE status = 'QUEUED' OR status = 'EXECUTING' OR (status = 'LEASED' AND (lease_expires_at IS NULL OR lease_expires_at >= ?));", (now,))
                    if cur.fetchone()[0] > 0:
                        conn.rollback()
                        return False, "ACTIVE_WORK_IN_PROGRESS", None
                except sqlite3.OperationalError as ex:
                    if "no such table" not in str(ex):
                        conn.rollback()
                        return False, f"STORAGE_ERROR_{type(ex).__name__}", None

                # 3b. Curiosity searching check
                try:
                    cur = conn.execute("SELECT COUNT(*) FROM ciph_curiosity_questions WHERE json_extract(payload, '$.status') = 'SEARCHING';")
                    if cur.fetchone()[0] > 0:
                        conn.rollback()
                        return False, "CURIOSITY_ACTIVE", None
                except sqlite3.OperationalError as ex:
                    if "no such table" not in str(ex):
                        conn.rollback()
                        return False, f"STORAGE_ERROR_{type(ex).__name__}", None

                # 3c. Curiosity reserved attempts check
                try:
                    cur = conn.execute("SELECT COUNT(*) FROM ciph_curiosity_attempts WHERE json_extract(payload, '$.status') = 'RESERVED';")
                    if cur.fetchone()[0] > 0:
                        conn.rollback()
                        return False, "CURIOSITY_RESERVED", None
                except sqlite3.OperationalError as ex:
                    if "no such table" not in str(ex):
                        conn.rollback()
                        return False, f"STORAGE_ERROR_{type(ex).__name__}", None

                # 3d. Canary in-flight check
                try:
                    cur = conn.execute("SELECT COUNT(*) FROM ciph_phase8_canary_state WHERE json_extract(payload, '$.in_flight') IS NOT NULL;")
                    if cur.fetchone()[0] > 0:
                        conn.rollback()
                        return False, "CANARY_IN_FLIGHT", None
                except sqlite3.OperationalError as ex:
                    if "no such table" not in str(ex):
                        conn.rollback()
                        return False, f"STORAGE_ERROR_{type(ex).__name__}", None

                # 3e. Durable quiescence window check (>= 10.0s elapsed since last completed work)
                try:
                    cur = conn.execute("""
                        SELECT COALESCE(MAX(ts), 0.0) FROM (
                            SELECT MAX(completed_at) AS ts FROM ciph_ipc_jobs
                            UNION ALL
                            SELECT MAX(timestamp) AS ts FROM ciph_event_store
                        );
                    """)
                    max_ts = cur.fetchone()[0] or 0.0
                    if max_ts > 0.0 and (now - max_ts) < quiescence_window_seconds:
                        conn.rollback()
                        return False, "QUIESCENCE_WINDOW_ACTIVE", None
                except sqlite3.OperationalError as ex:
                    if "no such table" not in str(ex):
                        conn.rollback()
                        return False, f"STORAGE_ERROR_{type(ex).__name__}", None

            # 4. Canonical statement & cryptographic authority verification
            statement = self.compute_statement(lease_name, holder_id, cid, now, now + ttl_seconds)
            sig = ""
            if operator_secret_key:
                sig = Ed25519KeyManager.sign(operator_secret_key, statement)

            self._verify_operator_authority(holder_id, sig, statement, now)

            # 5. Insert exclusive lease row
            conn.execute("""
                INSERT INTO ciph_maintenance_leases
                (lease_name, holder_id, cycle_id, acquired_at, expires_at, task_name, heartbeat_at, holder_signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (lease_name, holder_id, cid, now, now + ttl_seconds, "INIT", now, sig))
            conn.commit()
            SharedExclusionCoordinator._active_leases[self._norm(self.db_path)] = (holder_id, now + ttl_seconds)
            return True, "ACQUIRED", cid

    def renew_lease(
        self,
        lease_name: str = DEFAULT_LEASE_NAME,
        holder_id: str = "operator_primary",
        operator_secret_key: Optional[bytes] = None,
        cycle_id: str = "",
        extension_seconds: int = 30,
        task_name: str = "RUNNING"
    ) -> bool:
        """Extends an active lease under write lock with a fresh Ed25519 signature."""
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()  # Clock strictly sampled AFTER write lock
            cur = conn.execute("SELECT expires_at, cycle_id FROM ciph_maintenance_leases WHERE lease_name = ? AND holder_id = ?;", (lease_name, holder_id))
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return False

            if row[0] < now or (cycle_id and row[1] != cycle_id):
                conn.rollback()
                return False

            new_expires = now + extension_seconds
            statement = self.compute_statement(lease_name, holder_id, cycle_id or row[1], now, new_expires)
            sig = ""
            if operator_secret_key:
                sig = Ed25519KeyManager.sign(operator_secret_key, statement)

            self._verify_operator_authority(holder_id, sig, statement, now)

            conn.execute("""
                UPDATE ciph_maintenance_leases
                SET expires_at = ?, heartbeat_at = ?, task_name = ?, holder_signature = ?
                WHERE lease_name = ? AND holder_id = ?;
            """, (new_expires, now, task_name, sig, lease_name, holder_id))
            conn.commit()
            SharedExclusionCoordinator._active_leases[self._norm(self.db_path)] = (holder_id, new_expires)
            return True

    def release_lease(self, lease_name: str = DEFAULT_LEASE_NAME, holder_id: str = "operator_primary", cycle_id: Optional[str] = None) -> bool:
        """Releases an active maintenance lease."""
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            if cycle_id:
                cur = conn.execute("DELETE FROM ciph_maintenance_leases WHERE lease_name = ? AND holder_id = ? AND cycle_id = ?;", (lease_name, holder_id, cycle_id))
            else:
                cur = conn.execute("DELETE FROM ciph_maintenance_leases WHERE lease_name = ? AND holder_id = ?;", (lease_name, holder_id))
            conn.commit()
            SharedExclusionCoordinator._active_leases.pop(self._norm(self.db_path), None)
            return cur.rowcount > 0

    def get_active_lease(self, lease_name: str = DEFAULT_LEASE_NAME) -> Optional[Dict[str, Any]]:
        """Retrieves active unexpired lease metadata if present."""
        now = time.time()
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT * FROM ciph_maintenance_leases WHERE lease_name = ? AND expires_at > ?;", (lease_name, now))
            row = cur.fetchone()
            return dict(row) if row else None

    def wrap_connection(self, raw_conn: sqlite3.Connection, calling_holder_id: Optional[str] = None) -> ExcludedConnection:
        """Wraps a raw connection in an ExcludedConnection proxy enforcing write-only exclusion."""
        return ExcludedConnection(raw_conn, calling_holder_id=calling_holder_id, db_path=self.db_path)
