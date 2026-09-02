"""
ciph.memory.materialized_views - Materialized Projections of Active Worldview Claims.
Allows O(1) query performance while preserving append-only event sourcing truth.
"""

import time
import json
import sqlite3
from enum import Enum
from typing import List, Dict, Any, Optional
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.perception.observation import ReliabilityClass


class DecayProfile(str, Enum):
    LIVE_NETWORK_STATE   = "LIVE_NETWORK_STATE"    # 5 minutes
    OPERATIONAL_ANOMALY  = "OPERATIONAL_ANOMALY"   # 24 hours
    SOFTWARE_BEHAVIOR    = "SOFTWARE_BEHAVIOR"     # 7 days
    STRATEGIC_HYPOTHESIS = "STRATEGIC_HYPOTHESIS"  # 30 days
    MATHEMATICAL_FACT    = "MATHEMATICAL_FACT"     # Never decays


DECAY_DURATIONS_SECONDS: Dict[DecayProfile, Optional[float]] = {
    DecayProfile.LIVE_NETWORK_STATE: 300.0,
    DecayProfile.OPERATIONAL_ANOMALY: 86400.0,
    DecayProfile.SOFTWARE_BEHAVIOR: 604800.0,
    DecayProfile.STRATEGIC_HYPOTHESIS: 2592000.0,
    DecayProfile.MATHEMATICAL_FACT: None,
}


class MaterializedWorldview:
    """
    Maintains high-performance materialized views of active claims in SQLite WAL.
    Updated strictly via append-only events and verified state transitions.
    Includes the Tabu Graveyard for permanently refuted or quarantined hypotheses.
    """

    def __init__(self, db_path: str = "ciph_vault.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.row_factory = sqlite3.Row

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
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
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

            # Tabu Graveyard Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_tabu_graveyard (
                    grave_id TEXT PRIMARY KEY,
                    claim_id TEXT,
                    subject TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    refuted_value TEXT,
                    reason TEXT NOT NULL,
                    negative_evidence TEXT,
                    buried_at REAL NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graveyard_subj ON ciph_tabu_graveyard(subject, predicate);")
            conn.commit()

    @staticmethod
    def get_decay_deadline(profile: DecayProfile, from_time: Optional[float] = None) -> Optional[float]:
        """Compute absolute epoch expiration timestamp based on decay profile."""
        duration = DECAY_DURATIONS_SECONDS.get(profile)
        if duration is None:
            return None
        now = from_time if from_time is not None else time.time()
        return now + duration

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
        include_expired: bool = False,
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
            if not include_expired and all(s in ('SUPPORTED', 'OBSERVED') for s in states):
                query += " AND (freshness_deadline IS NULL OR freshness_deadline > ?)"
                params.append(now)
        else:
            query += " AND state IN ('SUPPORTED', 'OBSERVED')"
            if not include_expired:
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

    def bury_in_graveyard(
        self,
        subject: str,
        predicate: str,
        reason: str,
        claim_id: Optional[str] = None,
        refuted_value: Any = None,
        negative_evidence: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Quarantine and bury a refuted claim or failed hypothesis in the Tabu Graveyard.
        Prevents redundant re-probing and hallucinations.
        """
        import uuid
        grave_id = f"GRV-{uuid.uuid4().hex[:8].upper()}"
        now = time.time()
        val_str = json.dumps(refuted_value) if isinstance(refuted_value, (dict, list)) else str(refuted_value or "")
        ev_str = json.dumps(negative_evidence or {})

        with self._get_connection() as conn:
            # If active claim exists, mark it REFUTED in worldview
            if claim_id:
                conn.execute(
                    "UPDATE ciph_active_claims SET state = 'REFUTED', updated_at = ? WHERE claim_id = ?;",
                    (now, claim_id)
                )

            conn.execute("""
                INSERT INTO ciph_tabu_graveyard (
                    grave_id, claim_id, subject, predicate, refuted_value,
                    reason, negative_evidence, buried_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (grave_id, claim_id, subject, predicate, val_str, reason, ev_str, now))
            conn.commit()

        return grave_id

    def is_in_graveyard(self, subject: str, predicate: str) -> bool:
        """Check if an inquiry has already been permanently refuted in the Tabu Graveyard."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) AS cnt FROM ciph_tabu_graveyard WHERE subject = ? AND predicate = ?;",
                (subject, predicate)
            )
            row = cursor.fetchone()
            return row['cnt'] > 0 if row else False

    def query_graveyard(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent graves from the Tabu Graveyard."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM ciph_tabu_graveyard ORDER BY buried_at DESC LIMIT ?;", (limit,))
            graves = []
            for row in cursor.fetchall():
                graves.append({
                    "grave_id": row['grave_id'],
                    "claim_id": row['claim_id'],
                    "subject": row['subject'],
                    "predicate": row['predicate'],
                    "refuted_value": row['refuted_value'],
                    "reason": row['reason'],
                    "buried_at": row['buried_at']
                })
            return graves

    def reap_expired_claims(self, current_time: Optional[float] = None) -> int:
        """
        Transition claims whose freshness TTL has passed to STALE without false refutation.
        """
        now = current_time if current_time is not None else time.time()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE ciph_active_claims 
                SET state = 'STALE', updated_at = ? 
                WHERE (superseded_by IS NULL OR superseded_by = '') 
                  AND state IN ('SUPPORTED', 'OBSERVED') 
                  AND freshness_deadline IS NOT NULL 
                  AND freshness_deadline <= ?;
            """, (now, now))
            conn.commit()
            return cursor.rowcount

    def detect_and_handle_contradiction(self, new_node: TransmutationNode) -> Dict[str, Any]:
        """
        Check for existing high-assurance claims on the same subject & predicate.
        If values conflict, marks existing claim as DISPUTED and sets new claim as DISPUTED.
        """
        existing = self.query_active_claims(
            subject=new_node.subject,
            predicate=new_node.predicate,
            states=["SUPPORTED", "OBSERVED"]
        )

        conflicts = []
        for old in existing:
            if old.claim_id != new_node.claim_id and old.value != new_node.value:
                # Value contradiction detected!
                old.state = EpistemicCategory.DISPUTED
                old.updated_at = time.time()
                self.upsert_claim(old)
                conflicts.append(old.claim_id)

        if conflicts:
            new_node.state = EpistemicCategory.DISPUTED
            new_node.updated_at = time.time()
            self.upsert_claim(new_node)
            return {
                "contradiction_detected": True,
                "disputed_claim_ids": conflicts + [new_node.claim_id]
            }

        self.upsert_claim(new_node)
        return {
            "contradiction_detected": False,
            "claim_id": new_node.claim_id
        }

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
