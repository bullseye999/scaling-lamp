"""
ciph.memory.event_store - Append-Only Cryptographic Event Store.
Guarantees memory immutability, auditability, and SHA-256 tamper-evident hash chaining.
"""

import time
import json
import sqlite3
import hashlib
from typing import Dict, Any, List, Optional, Tuple


class EventStore:
    """
    Append-only event log backed by SQLite in WAL mode.
    Every state change is recorded as an immutable event with cryptographic hash chaining.
    """

    def __init__(self, db_path: str = "ciph_vault.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
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

    def append_event(self, event_type: str, aggregate_id: str, payload: Dict[str, Any]) -> int:
        """
        Append an immutable event to the event store with SHA-256 hash chaining.
        Returns the new event_id.
        """
        now = time.time()
        payload_str = json.dumps(payload, sort_keys=True, default=str)
        
        with self._get_connection() as conn:
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

    def get_events(
        self,
        aggregate_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Retrieve events matching filter criteria."""
        query = "SELECT * FROM ciph_event_store WHERE 1=1"
        params: List[Any] = []
        
        if aggregate_id:
            query += " AND aggregate_id = ?"
            params.append(aggregate_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
            
        query += " ORDER BY event_id ASC LIMIT ?"
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            results = []
            for row in cursor.fetchall():
                results.append({
                    "event_id": row['event_id'],
                    "event_type": row['event_type'],
                    "aggregate_id": row['aggregate_id'],
                    "payload": json.loads(row['payload']),
                    "timestamp": row['timestamp'],
                    "previous_hash": row['previous_hash'],
                    "event_hash": row['event_hash'],
                })
            return results

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Walks the entire cryptographic hash chain to ensure no historical events were tampered with.
        Returns (is_valid, corrupted_event_id).
        """
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM ciph_event_store ORDER BY event_id ASC;")
            rows = cursor.fetchall()
            
            prev_hash = "GENESIS_BLOCK_CIPH_4.0"
            for row in rows:
                if row['previous_hash'] != prev_hash:
                    return False, row['event_id']
                
                payload_str = row['payload']
                hash_input = f"{prev_hash}|{row['event_type']}|{row['aggregate_id']}|{payload_str}|{row['timestamp']}"
                expected_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
                
                if row['event_hash'] != expected_hash:
                    return False, row['event_id']
                
                prev_hash = row['event_hash']
                
            return True, None
