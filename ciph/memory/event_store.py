"""
ciph.memory.event_store - Append-Only Cryptographic Event Store.
Guarantees memory immutability, auditability, and SHA-256 tamper-evident hash chaining.
"""

import time
import json
from dataclasses import dataclass
from enum import Enum
from typing import Tuple
import sqlite3
import hashlib
from typing import Dict, Any, List, Optional, Tuple


def governed_authorization_block(event) -> Dict[str, Any]:
    """
    The ONE reader for an event's governed-authorization block.

    A governed block has two legitimate homes depending on the event's shape:

      * a synthetic evidence event carries it at the payload root;
      * a signed `ExecutionReceipt` carries it inside `provenance`, because the receipt schema is
        frozen and the block rides in the already-signed provenance dict.

    Both are the same block. Reading only one shape is what let a real daemon attempt look like
    NO_ATTRIBUTABLE_EVIDENCE while its signed receipt sat in the store.
    """
    payload = (event or {}).get("payload") or {}
    if not isinstance(payload, dict):
        return {}
    block = payload.get("governed_authorization")
    if isinstance(block, dict):
        return block
    provenance = payload.get("provenance")
    if isinstance(provenance, dict):
        block = provenance.get("governed_authorization")
        if isinstance(block, dict):
            return block
    return {}


class AttemptEvidenceOutcome(str, Enum):
    """The three answers an exact-attempt read may give. Deliberately no "best match"."""

    ATTRIBUTABLE = "ATTRIBUTABLE"
    NO_ATTRIBUTABLE_EVIDENCE = "NO_ATTRIBUTABLE_EVIDENCE"
    INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"


@dataclass(frozen=True)
class AttemptEvidence:
    outcome: AttemptEvidenceOutcome
    events: Tuple[Dict[str, Any], ...] = ()


class EventStore:
    """
    Append-only event log backed by SQLite in WAL mode.
    Every state change is recorded as an immutable event with cryptographic hash chaining.
    """

    def __init__(self, db_path: str = "ciph_vault.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self, calling_holder_id: Optional[str] = None) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.row_factory = sqlite3.Row

        from ciph.maintenance.exclusion import ExcludedConnection
        return ExcludedConnection(conn, calling_holder_id=calling_holder_id, db_path=self.db_path)

    def _init_db(self):
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
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

    def _get_latest_hash(self, conn: sqlite3.Connection) -> str:
        cursor = conn.execute("SELECT event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1;")
        row = cursor.fetchone()
        return row['event_hash'] if row else "GENESIS_BLOCK_CIPH_4.0"

    def append_event(self, event_type: str, aggregate_id: str, payload: Dict[str, Any], calling_holder_id: Optional[str] = None) -> int:
        """
        Append an immutable event to the event store with SHA-256 hash chaining.
        Returns the new event_id.
        """
        payload_str = json.dumps(payload, sort_keys=True, default=str)
        
        with self._get_connection(calling_holder_id=calling_holder_id) as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            prev_hash = self._get_latest_hash(conn)
            
            # Compute hash = SHA256(prev_hash + event_type + aggregate_id + payload_str + str(now))
            hash_input = f"{prev_hash}|{event_type}|{aggregate_id}|{payload_str}|{now}"
            event_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
            
            cursor = conn.execute("""
                INSERT INTO ciph_event_store 
                (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (event_type, aggregate_id, payload_str, now, prev_hash, event_hash))
            conn.commit()
            return cursor.lastrowid

    def get_attempt_evidence(
        self,
        *,
        execution_attempt_id: str,
        permit_id: str,
        permit_digest: str,
        authorization_generation: int,
        event_types: Optional[Tuple[str, ...]] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> "AttemptEvidence":
        """
        Retry-relevant canonical evidence for ONE exact attempt.

        Every supplied identity must agree. A partial match is not a match: an event that mentions the
        attempt but disagrees on the permit, the digest or the generation is an integrity conflict,
        never evidence. Events without claim provenance are not attributable and are never attached by
        inference from timestamp, capability or target.
        """
        wanted = {
            "execution_attempt_id": str(execution_attempt_id),
            "execution_permit_id": str(permit_id),
            "execution_permit_digest": str(permit_digest),
            "authorization_generation": int(authorization_generation or 0),
        }
        events = self.get_events(limit=100000, conn=conn)
        attributable: list = []
        mentioned = False
        for event in events:
            if event_types is not None and event.get("event_type") not in event_types:
                continue
            block = governed_authorization_block(event)
            if not block:
                continue
            same_attempt = str(block.get("execution_attempt_id")) == wanted["execution_attempt_id"]
            same_permit = str(block.get("execution_permit_id")) == wanted["execution_permit_id"]
            if not (same_attempt or same_permit):
                continue
            mentioned = True
            agrees = (
                same_attempt
                and same_permit
                and str(block.get("execution_permit_digest")) == wanted["execution_permit_digest"]
                and int(block.get("authorization_generation") or 0) == wanted["authorization_generation"]
            )
            if agrees:
                attributable.append(event)
            else:
                return AttemptEvidence(AttemptEvidenceOutcome.INTEGRITY_CONFLICT, (event,))

        if attributable:
            return AttemptEvidence(AttemptEvidenceOutcome.ATTRIBUTABLE, tuple(attributable))
        if mentioned:
            return AttemptEvidence(AttemptEvidenceOutcome.INTEGRITY_CONFLICT)
        return AttemptEvidence(AttemptEvidenceOutcome.NO_ATTRIBUTABLE_EVIDENCE)


    def get_events(
        self,
        aggregate_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        order_desc: bool = False,
        conn: Optional[sqlite3.Connection] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve events matching filter criteria.

        With `conn` supplied the read runs inside the CALLER's transaction, so canonical events and
        the caller's other reads share one snapshot. This is what lets a retry decision read the
        exact attempt's evidence in the same authoritative view as the job and permit rows. The
        caller owns the transaction; this method never begins, commits or rolls back.
        """
        query = "SELECT * FROM ciph_event_store WHERE 1=1"
        params: List[Any] = []
        
        if aggregate_id:
            query += " AND aggregate_id = ?"
            params.append(aggregate_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
            
        order_dir = "DESC" if order_desc else "ASC"
        query += f" ORDER BY event_id {order_dir} LIMIT ?"
        params.append(limit)
        
        def _rows_of(active):
            rows = active.execute(query, params).fetchall()
            return [
                {
                    "event_id": row["event_id"],
                    "event_type": row["event_type"],
                    "aggregate_id": row["aggregate_id"],
                    "payload": json.loads(row["payload"]),
                    "timestamp": row["timestamp"],
                    "previous_hash": row["previous_hash"],
                    "event_hash": row["event_hash"],
                }
                for row in rows
            ]

        if conn is not None:
            return _rows_of(conn)
        with self._get_connection() as owned:
            return _rows_of(owned)

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Walks the entire cryptographic hash chain to ensure no historical events were tampered with.
        Returns (is_valid, corrupted_event_id).
        """
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM ciph_event_store ORDER BY event_id ASC;")
            
            prev_hash = "GENESIS_BLOCK_CIPH_4.0"
            for row in cursor:
                if row['previous_hash'] != prev_hash:
                    return False, row['event_id']
                
                payload_str = row['payload']
                hash_input = f"{prev_hash}|{row['event_type']}|{row['aggregate_id']}|{payload_str}|{row['timestamp']}"
                expected_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
                
                if row['event_hash'] != expected_hash:
                    return False, row['event_id']
                
                prev_hash = row['event_hash']
                
            return True, None
