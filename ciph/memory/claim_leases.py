"""
ciph.memory.claim_leases - Epistemic Claim Pinning & Worker Lease Locks (Anti-TOCTOU).
Prevents race conditions between active workers and Active Forgetting supersessions.
"""

import hashlib
import time
import uuid
import sqlite3
from typing import List, Dict, Any, Optional


DOMAIN_LEASE_TABLE = "ciph_epistemic_domain_leases"


def ensure_domain_lease_schema(conn) -> None:
    """
    Register item 0.2. Domain leases are the resource a set of jobs contends for when their
    declared dependencies rest on contradictory claims. They live in their own table so the
    set can be acquired all-or-nothing inside a caller's existing write transaction.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ciph_epistemic_domain_leases ("
        "  lease_id TEXT NOT NULL,"
        "  domain_id TEXT NOT NULL,"
        "  worker_id TEXT NOT NULL,"
        "  job_id TEXT NOT NULL,"
        "  acquired_at REAL NOT NULL,"
        "  expires_at REAL NOT NULL,"
        "  PRIMARY KEY (lease_id, domain_id)"
        ");"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_leases_domain "
                 "ON ciph_epistemic_domain_leases(domain_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_leases_job "
                 "ON ciph_epistemic_domain_leases(job_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_domain_leases_expires "
                 "ON ciph_epistemic_domain_leases(expires_at);")


def domain_lease_conflicts(conn, domain_ids, worker_id, now) -> list:
    """
    Domains already held by a *different* worker. Reads only; safe to call inside a
    caller-owned transaction, which is what makes the acquire-or-refuse decision atomic.
    """
    ids = sorted({d for d in (domain_ids or []) if d})
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT domain_id, worker_id FROM {DOMAIN_LEASE_TABLE} "
        f"WHERE domain_id IN ({placeholders}) AND expires_at >= ?;",
        (*ids, now),
    ).fetchall()
    return sorted({row[0] for row in rows if row[1] != worker_id})


def insert_domain_leases(conn, domain_ids, worker_id, job_id, expires_at, acquired_at) -> str:
    """Insert the whole domain set under one lease id. Caller owns the transaction."""
    lease_id = f"dlease_{uuid.uuid4().hex[:12]}"
    for domain_id in sorted({d for d in (domain_ids or []) if d}):
        conn.execute(
            f"INSERT OR REPLACE INTO {DOMAIN_LEASE_TABLE} "
            "(lease_id, domain_id, worker_id, job_id, acquired_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            (lease_id, domain_id, worker_id, job_id, acquired_at, expires_at),
        )
    return lease_id


def release_domain_leases_for_job(conn, job_id) -> int:
    """Free every domain a job holds. Used on completion, failure, retry and reclaim."""
    return conn.execute(
        f"DELETE FROM {DOMAIN_LEASE_TABLE} WHERE job_id = ?;", (job_id,)
    ).rowcount


class EpistemicDomainConflict(Exception):
    """
    Raised when a worker tries to lease a claim whose epistemic domain is already held
    by a different worker or job.

    The domain - (subject, scope, predicate) - is the resource two contradictory claims
    contend for. Keying leases on claim_id alone cannot see that contention: two claims
    disagreeing about server-A.version have two different claim ids and therefore two
    independent locks, so both workers proceed and the contradiction is never blocked.
    """


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

    def _get_connection(self, calling_holder_id: Optional[str] = None) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.row_factory = sqlite3.Row

        from ciph.maintenance.exclusion import ExcludedConnection
        return ExcludedConnection(conn, calling_holder_id=calling_holder_id, db_path=self.db_path)

    def _init_db(self):
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
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

            # Register item 0.14: leases must contend on the epistemic domain, not only on
            # claim_id. Additive and nullable, so pre-existing databases migrate in place and
            # legacy rows keep working unchanged.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(ciph_claim_leases);")}
            if "epistemic_domain" not in columns:
                conn.execute(
                    "ALTER TABLE ciph_claim_leases ADD COLUMN epistemic_domain TEXT;"
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_leases_domain "
                "ON ciph_claim_leases(epistemic_domain);"
            )
            ensure_domain_lease_schema(conn)
            conn.commit()

    def cleanup_expired_leases(self, calling_holder_id: Optional[str] = None) -> int:
        """Purge leases whose TTL has lapsed."""
        now = time.time()
        with self._get_connection(calling_holder_id=calling_holder_id) as conn:
            cursor = conn.execute("DELETE FROM ciph_claim_leases WHERE expires_at < ?;", (now,))
            conn.commit()
            return cursor.rowcount

    @staticmethod
    def epistemic_domain_id(
        subject: Optional[str],
        predicate: Optional[str],
        scope_id: Optional[str] = None
    ) -> str:
        """
        The epistemic resource a claim speaks about.

        Two claims that disagree about the same (subject, scope, predicate) address the SAME
        domain even though they carry different claim ids. Leasing the domain is what turns a
        contradiction into a contended resource instead of two independent locks.
        """
        key = "||".join([
            (subject or "").strip().lower(),
            (scope_id or "").strip().lower(),
            (predicate or "").strip().lower(),
        ])
        return "dom_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def domain_of_claim(cls, claim: Any) -> str:
        """
        Derive the domain from a claim's own fields - never from a caller-supplied mapping.
        Accepts a Claim instance or a mapping.
        """
        def _get(name: str) -> Optional[str]:
            if isinstance(claim, dict):
                return claim.get(name)
            return getattr(claim, name, None)

        return cls.epistemic_domain_id(
            _get("subject"), _get("predicate"), _get("scope_id")
        )

    def get_domain_pinners(
        self,
        domain_id: str,
        excluding_worker: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Active, non-expired leases holding this epistemic domain."""
        self.cleanup_expired_leases()
        now = time.time()
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT lease_id, claim_id, worker_id, job_id, expires_at
                FROM ciph_claim_leases
                WHERE epistemic_domain = ? AND expires_at >= ?;
            """, (domain_id, now)).fetchall()
        return [
            dict(r) for r in rows
            if not (excluding_worker is not None and r["worker_id"] == excluding_worker)
        ]

    def is_domain_pinned(
        self,
        domain_id: str,
        excluding_worker: Optional[str] = None
    ) -> bool:
        """True when another worker currently holds this epistemic domain."""
        return len(self.get_domain_pinners(domain_id, excluding_worker=excluding_worker)) > 0

    def acquire_domain_lease_set(
        self,
        domain_ids: List[str],
        worker_id: str,
        job_id: str,
        ttl_seconds: int = 60
    ) -> str:
        """
        Acquire a whole dependency set atomically, or nothing at all.

        Either the worker owns every domain it needs, or it owns none. There is no
        intermediate state where A and B are held and C failed.
        """
        ids = sorted({d for d in (domain_ids or []) if d})
        if not ids:
            raise ValueError("EMPTY_DOMAIN_LEASE_SET")
        with self._get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            conn.execute(
                f"DELETE FROM {DOMAIN_LEASE_TABLE} WHERE expires_at < ?;", (now,)
            )
            conflicts = domain_lease_conflicts(conn, ids, worker_id, now)
            if conflicts:
                conn.rollback()
                raise EpistemicDomainConflict(
                    f"EPISTEMIC_DOMAIN_CONFLICT: worker '{worker_id}' cannot lease "
                    f"domain(s) {conflicts}; another worker holds a contradictory claim "
                    "about the same (subject, scope, predicate)."
                )
            lease_id = insert_domain_leases(
                conn, ids, worker_id=worker_id, job_id=job_id,
                expires_at=now + ttl_seconds, acquired_at=now
            )
            conn.commit()
            return lease_id

    def acquire_claim_leases(
        self,
        claim_ids: List[str],
        worker_id: str,
        job_id: str,
        ttl_seconds: int = 60,
        claim_domains: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Pins a list of claim IDs for a worker. Returns a shared lease_id.
        Composite primary key (lease_id, claim_id) allows multi-claim atomic locking.

        `claim_domains` optionally maps claim_id -> epistemic_domain_id. When supplied, the
        caller states the epistemic resource each claim addresses, and acquisition fails
        closed if any of those domains is already held by another worker or job.

        The same worker may re-acquire its own domain (renewal and multi-job operation), and
        callers that omit `claim_domains` retain the legacy claim-id-only behaviour.
        """
        self.cleanup_expired_leases()
        lease_id = f"lease_{uuid.uuid4().hex[:12]}"
        now = time.time()
        expires_at = now + ttl_seconds

        if claim_domains:
            conflicts: List[str] = []
            for domain_id in sorted(set(claim_domains.values())):
                if self.is_domain_pinned(domain_id, excluding_worker=worker_id):
                    conflicts.append(domain_id)
            if conflicts:
                raise EpistemicDomainConflict(
                    "EPISTEMIC_DOMAIN_CONFLICT: worker "
                    f"'{worker_id}' cannot lease domain(s) {conflicts}: another worker holds a "
                    "contradictory claim about the same (subject, scope, predicate)."
                )

        with self._get_connection() as conn:
            for cid in set(claim_ids):
                conn.execute("""
                    INSERT OR REPLACE INTO ciph_claim_leases 
                    (lease_id, claim_id, worker_id, job_id, acquired_at, expires_at, epistemic_domain)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                """, (
                    lease_id, cid, worker_id, job_id, now, expires_at,
                    (claim_domains or {}).get(cid)
                ))
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
