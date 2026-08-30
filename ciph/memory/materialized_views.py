"""
ciph.memory.materialized_views - Materialized Projections of Active Worldview Claims.
Allows O(1) query performance while preserving append-only event sourcing truth.
"""

import time
import json
import sqlite3
from typing import List, Dict, Any, Optional
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.perception.observation import ReliabilityClass


class MaterializedWorldview:
    """
    Maintains high-performance materialized views of active claims in SQLite WAL.
    Updated strictly via append-only events and verified state transitions.
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
                CREATE TABLE IF NOT EXISTS ciph_active_claims (
                    claim_id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    value TEXT NOT NULL,
                    condition TEXT,
                    state TEXT NOT NULL,
                    reliability TEXT NOT NULL,
                    assurance_score REAL NOT NULL,
                    evidence_receipt_ids TEXT NOT NULL,
                    parent_claim_ids TEXT NOT NULL,
                    superseded_by TEXT,
                    freshness_deadline REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_subject ON ciph_active_claims(subject);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_state ON ciph_active_claims(state);")
            conn.commit()

    def upsert_claim(self, node: TransmutationNode) -> None:
        """Upsert a transmutation node into the active materialized view."""
        val_str = json.dumps(node.value) if isinstance(node.value, (dict, list)) else str(node.value)
        ev_str = json.dumps(node.evidence_receipt_ids)
        parents_str = json.dumps(node.parent_claim_ids)
        
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO ciph_active_claims (
                    claim_id, subject, predicate, value, condition, state, reliability,
                    assurance_score, evidence_receipt_ids, parent_claim_ids,
                    superseded_by, freshness_deadline, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(claim_id) DO UPDATE SET
                    subject = excluded.subject,
                    predicate = excluded.predicate,
                    value = excluded.value,
                    condition = excluded.condition,
                    state = excluded.state,
                    reliability = excluded.reliability,
                    assurance_score = excluded.assurance_score,
                    evidence_receipt_ids = excluded.evidence_receipt_ids,
                    parent_claim_ids = excluded.parent_claim_ids,
                    superseded_by = excluded.superseded_by,
                    freshness_deadline = excluded.freshness_deadline,
                    updated_at = excluded.updated_at;
            """, (
                node.claim_id, node.subject, node.predicate, val_str, node.condition,
                node.state.value if isinstance(node.state, EpistemicCategory) else str(node.state),
                node.reliability.value if isinstance(node.reliability, ReliabilityClass) else str(node.reliability),
                node.assurance_score, ev_str, parents_str, node.superseded_by,
                node.freshness_deadline, node.created_at, node.updated_at
            ))
            conn.commit()

    def get_claim(self, claim_id: str) -> Optional[TransmutationNode]:
        """Retrieve a specific transmutation node by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM ciph_active_claims WHERE claim_id = ?;", (claim_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_node(row)

    def query_active_claims(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        states: Optional[List[str]] = None,
        limit: int = 50
    ) -> List[TransmutationNode]:
        """
        Retrieve active, non-superseded claims matching criteria.
        Defaults to [SUPPORTED, OBSERVED] claims with valid freshness TTL.
        """
        now = time.time()
        query = "SELECT * FROM ciph_active_claims WHERE (superseded_by IS NULL OR superseded_by = '')"
        params: List[Any] = []
        
        if subject:
            query += " AND subject = ?"
            params.append(subject)
        if predicate:
            query += " AND predicate = ?"
            params.append(predicate)
        if states:
            placeholders = ",".join("?" for _ in states)
            query += f" AND state IN ({placeholders})"
            params.extend(states)
        else:
            query += " AND state IN ('SUPPORTED', 'OBSERVED')"

        # Freshness filter: deadline is null OR deadline > now
        query += " AND (freshness_deadline IS NULL OR freshness_deadline > ?)"
        params.append(now)

        query += " ORDER BY assurance_score DESC, updated_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_node(r) for r in cursor.fetchall()]

    def get_downstream_dependents(self, claim_id: str) -> List[str]:
        """Find all active claims that declare claim_id as a parent dependency."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT claim_id, parent_claim_ids FROM ciph_active_claims WHERE superseded_by IS NULL;")
            dependents = []
            for row in cursor.fetchall():
                try:
                    parents = json.loads(row['parent_claim_ids'])
                    if claim_id in parents:
                        dependents.append(row['claim_id'])
                except Exception:
                    pass
            return dependents

    def _row_to_node(self, row: sqlite3.Row) -> TransmutationNode:
        try:
            val = json.loads(row['value'])
        except Exception:
            val = row['value']
            
        try:
            evidence = json.loads(row['evidence_receipt_ids'])
        except Exception:
            evidence = []
            
        try:
            parents = json.loads(row['parent_claim_ids'])
        except Exception:
            parents = []

        return TransmutationNode(
            claim_id=row['claim_id'],
            subject=row['subject'],
            predicate=row['predicate'],
            value=val,
            condition=row['condition'],
            state=EpistemicCategory(row['state']) if row['state'] in EpistemicCategory.__members__ else EpistemicCategory.OBSERVED,
            reliability=ReliabilityClass(row['reliability']) if row['reliability'] in ReliabilityClass.__members__ else ReliabilityClass.DIRECT_SENSOR,
            assurance_score=row['assurance_score'],
            evidence_receipt_ids=evidence,
            parent_claim_ids=parents,
            superseded_by=row['superseded_by'],
            freshness_deadline=row['freshness_deadline'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )
