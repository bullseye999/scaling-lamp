"""
ciph.memory.claim_leases - Epistemic Claim Pinning & Worker Lease Locks (Anti-TOCTOU).
Prevents race conditions between active workers and Active Forgetting supersessions.
"""

import time
import uuid
import sqlite3
from typing import List, Dict, Any, Optional


class ClaimLeaseManager:
    """
    Manages concurrency leases on epistemic claims.
    When an out-of-process worker executes a job depending on claims C1..Cn,
    it pins those claims. If Active Forgetting attempts to mutate a pinned claim,
    it detects the collision and safely quarantines the job.
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
                CREATE TABLE IF NOT EXISTS ciph_claim_leases (
                    lease_id TEXT NOT NULL,
                    claim_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (lease_id, claim_id)
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_claim ON ciph_claim_leases(claim_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_leases_expires ON ciph_claim_leases(expires_at);")
            conn.commit()

    def cleanup_expired_leases(self) -> int:
        """Purge leases whose TTL has lapsed."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM ciph_claim_leases WHERE expires_at < ?;", (now,))
            conn.commit()
            return cursor.rowcount

    def acquire_claim_leases(
        self,
        claim_ids: List[str],
        worker_id: str,
        job_id: str,
        ttl_seconds: int = 60
    ) -> str:
        """
        Pins a list of claim IDs for a worker. Returns a shared lease_id.
        Composite primary key (lease_id, claim_id) allows multi-claim atomic locking.
        """
        self.cleanup_expired_leases()
        lease_id = f"lease_{uuid.uuid4().hex[:12]}"
        now = time.time()
        expires_at = now + ttl_seconds
        
        with self._get_connection() as conn:
            for cid in set(claim_ids):
                conn.execute("""
                    INSERT OR REPLACE INTO ciph_claim_leases 
                    (lease_id, claim_id, worker_id, job_id, acquired_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?);
                """, (lease_id, cid, worker_id, job_id, now, expires_at))
            conn.commit()
        return lease_id

    def renew_lease(self, lease_id: str, ttl_seconds: int = 60) -> bool:
        """Heartbeat to extend the expiration of an active lease across all pinned claims."""
        now = time.time()
        new_expires = now + ttl_seconds
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_claim_leases 
                SET expires_at = ? 
                WHERE lease_id = ? AND expires_at >= ?;
            """, (new_expires, lease_id, now))
            conn.commit()
            return cursor.rowcount > 0

    def release_lease(self, lease_id: str) -> None:
        """Release all claim locks held by a lease ID upon job completion."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM ciph_claim_leases WHERE lease_id = ?;", (lease_id,))
            conn.commit()

    def is_claim_pinned(self, claim_id: str) -> bool:
        """Check if a claim currently has an active, non-expired worker lease lock."""
        self.cleanup_expired_leases()
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT 1 FROM ciph_claim_leases 
                WHERE claim_id = ? AND expires_at >= ? LIMIT 1;
            """, (claim_id, now))
            return cursor.fetchone() is not None

    def get_pinning_workers(self, claim_id: str) -> List[Dict[str, Any]]:
        """Return details of workers actively pinning this claim."""
        self.cleanup_expired_leases()
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT lease_id, worker_id, job_id, expires_at 
                FROM ciph_claim_leases 
                WHERE claim_id = ? AND expires_at >= ?;
            """, (claim_id, now))
            return [dict(r) for r in cursor.fetchall()]
