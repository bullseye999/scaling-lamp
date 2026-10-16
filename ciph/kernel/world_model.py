"""
ciph.kernel.world_model - what Ciph models as existing, related or unknown.

4.3 Gate Zero. The world model is a PROJECTION over epistemic state. It is not another source of truth,
and nothing in it may create evidence simply because the model represents it.

    Entity              a stable identity (entity_id derived from a canonical key)
    WorldFactProjection entity . relation . value @ temporal scope, plus where it came from and how
                        firmly the epistemics behind it stand

The statuses here are WORLD-MODEL projections, deliberately not 4.2 belief statuses:

    PRESENT      the proposition's claim holds in the world
    ABSENT       it does not hold  (this is NOT "no evidence" - that is UNKNOWN)
    UNCERTAIN    evidence exists but has not converged
    CONTESTED    epistemically contested, so the world state is not definite
    STALE        the evidence is too old to be current
    UNKNOWN      nothing epistemic bears on it at all

LAWS (each has a specimen in `test_gate_4_3_world_state.py`)

 1. WORLD STATE != EVIDENCE.
 2. Every modeled relation traces to epistemic propositions.
 3. CONTESTED epistemics cannot become definite world state.
 4. UNKNOWN survives projection as UNKNOWN.
 5. Time is part of state identity.
 6. Historical world states are immutable snapshots.
 7. Model output cannot directly insert a world fact.
 8. Removing support does not rewrite historical state.
 9. Same epistemic basis -> same world-state digest.
10. World-state reconstruction survives restart and model replacement.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.epistemic_convergence import (
    STATUS_CONTESTED as CONV_CONTESTED,
    STATUS_CONVERGED_REFUTED,
    STATUS_CONVERGED_SUPPORTED,
    STATUS_INTEGRITY_BLOCKED,
    STATUS_STALE as CONV_STALE,
    STATUS_UNRESOLVED as CONV_UNRESOLVED,
    project_convergence,
)
from ciph.kernel.epistemic_ledger import canonical_proposition, reconstruct as reconstruct_beliefs

WORLD_PRESENT = "PRESENT"
WORLD_ABSENT = "ABSENT"
WORLD_UNCERTAIN = "UNCERTAIN"
WORLD_CONTESTED = "CONTESTED"
WORLD_STALE = "STALE"
WORLD_UNKNOWN = "UNKNOWN"
VALID_WORLD_STATUSES = (WORLD_PRESENT, WORLD_ABSENT, WORLD_UNCERTAIN, WORLD_CONTESTED, WORLD_STALE,
                        WORLD_UNKNOWN)

REASON_NO_EPISTEMIC_BASIS = "NO_EPISTEMIC_BASIS"
REASON_NOT_CONVERGED = "NOT_CONVERGED"
REASON_INTEGRITY_BLOCKED = "INTEGRITY_BLOCKED"

_SCOPE_AT = "AT"
_SCOPE_INTERVAL = "INTERVAL"
_SCOPE_UNORDERABLE = "UNORDERABLE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_entities (
        entity_id TEXT PRIMARY KEY,
        canonical_key TEXT NOT NULL,
        kind TEXT,
        first_recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_world_snapshots (
        fact_id TEXT NOT NULL,
        snapshot_version INTEGER NOT NULL,
        entity_id TEXT NOT NULL,
        relation TEXT NOT NULL,
        modeled_value TEXT,
        temporal_scope TEXT,
        world_status TEXT NOT NULL,
        epistemic_status TEXT,
        confidence REAL,
        reason_codes_json TEXT,
        evidence_basis_digest TEXT NOT NULL,
        recorded_at REAL,
        PRIMARY KEY (fact_id, snapshot_version)
    );
    """,
)


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            pass
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def canonical_scope(value: Any) -> Optional[str]:
    """
    The canonical temporal-scope string for an instant or a window.

    `None` stays `None` rather than becoming the string "None": an untimed relation is a real state of
    affairs, and inventing a scope for it would give two different questions the same fact id.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return f"{_SCOPE_AT}:{float(value)}"
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return f"{_SCOPE_INTERVAL}:{float(value[0])}:{float(value[1])}"
    return str(value)


def parse_scope(scope: Optional[str]) -> Tuple[str, Optional[float], Optional[float]]:
    """
    Read a canonical scope. Anything else is UNORDERABLE rather than guessed at: a model that cannot
    place a fact in time must say so, because ordering is what dynamics are built on.
    """
    if not scope:
        return _SCOPE_UNORDERABLE, None, None
    text = str(scope)
    if text.startswith(f"{_SCOPE_AT}:"):
        try:
            moment = float(text.split(":", 1)[1])
        except ValueError:
            return _SCOPE_UNORDERABLE, None, None
        return _SCOPE_AT, moment, moment
    if text.startswith(f"{_SCOPE_INTERVAL}:"):
        try:
            _, low, high = text.split(":")
            return _SCOPE_INTERVAL, float(low), float(high)
        except ValueError:
            return _SCOPE_UNORDERABLE, None, None
    return _SCOPE_UNORDERABLE, None, None


@dataclass(frozen=True)
class Entity:
    entity_id: str
    canonical_key: str
    kind: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"entity_id": self.entity_id, "canonical_key": self.canonical_key, "kind": self.kind}


@dataclass(frozen=True)
class WorldFactProjection:
    fact_id: str
    entity: Entity
    relation: str
    modeled_value: Optional[str]
    temporal_scope: Optional[str]
    world_status: str
    epistemic_status: Optional[str]
    confidence: Optional[float]
    source_proposition_id: Optional[str]
    reason_codes: Tuple[str, ...]
    evidence_basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"fact_id": self.fact_id, "entity": self.entity.as_dict(), "relation": self.relation,
                "modeled_value": self.modeled_value, "temporal_scope": self.temporal_scope,
                "world_status": self.world_status, "epistemic_status": self.epistemic_status,
                "confidence": None if self.confidence is None else round(self.confidence, 12),
                "source_proposition_id": self.source_proposition_id,
                "reason_codes": list(self.reason_codes),
                "evidence_basis_digest": self.evidence_basis_digest}

    def canonical_digest(self) -> str:
        return _digest(self.as_dict())


def entity_for(canonical_key: str, *, kind: Optional[str] = None) -> Entity:
    key = str(canonical_key).strip()
    if not key:
        raise ValueError("ENTITY_REQUIRES_A_CANONICAL_KEY")
    return Entity(entity_id="ENT-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12].upper(),
                  canonical_key=key, kind=kind)


def fact_id_for(entity: Entity, relation: str, value: Any, scope: Any) -> str:
    payload = {"entity": entity.canonical_key, "relation": str(relation),
               "value": None if value is None else str(value), "scope": canonical_scope(scope)}
    return "WF-" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:12].upper()


def _world_status(convergence_status: Optional[str], *, has_basis: bool) -> Tuple[str, Tuple[str, ...]]:
    """
    The ONE mapping from epistemic convergence to world state. Frozen, and deliberately not the
    epistemic status itself: a world-model projection says what the world looks like, not how the
    epistemics stand.
    """
    if not has_basis or convergence_status is None:
        return WORLD_UNKNOWN, (REASON_NO_EPISTEMIC_BASIS,)
    if convergence_status == STATUS_CONVERGED_SUPPORTED:
        return WORLD_PRESENT, ()
    if convergence_status == STATUS_CONVERGED_REFUTED:
        return WORLD_ABSENT, ()
    if convergence_status == CONV_CONTESTED:
        return WORLD_CONTESTED, ()
    if convergence_status == CONV_STALE:
        return WORLD_STALE, ()
    if convergence_status == STATUS_INTEGRITY_BLOCKED:
        return WORLD_UNCERTAIN, (REASON_INTEGRITY_BLOCKED,)
    return WORLD_UNCERTAIN, (REASON_NOT_CONVERGED,)


def project_fact(db_path: str, *, entity: Entity, relation: str, value: Any = None,
                 scope: Any = None, now: Optional[float] = None,
                 stale_after: Optional[float] = None) -> WorldFactProjection:
    """
    Derive ONE world fact from the epistemic ledger, and register the entity it is about.

    Nothing is asserted here: if no proposition bears on the fact, this returns UNKNOWN and says why.
    """
    moment = time.time() if now is None else float(now)
    scope_text = canonical_scope(scope)
    proposition = canonical_proposition(entity.canonical_key, relation, value,
                                        temporal_scope=scope_text)
    cognitive = reconstruct_beliefs(db_path, now=moment, stale_after=stale_after)
    belief = cognitive.belief_for(proposition.proposition_id)
    convergence = project_convergence(db_path, proposition.proposition_id, now=moment,
                                      stale_after=stale_after)
    has_basis = belief is not None
    status, reasons = _world_status(convergence.status if has_basis else None, has_basis=has_basis)

    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute("INSERT OR IGNORE INTO ciph_entities (entity_id, canonical_key, kind, "
                     "first_recorded_at) VALUES (?,?,?,?);",
                     (entity.entity_id, entity.canonical_key, entity.kind, moment))
        conn.commit()
    finally:
        conn.close()

    basis = _digest({"proposition": proposition.proposition_id,
                     "belief": belief.derivation_digest if belief else None,
                     "convergence": convergence.basis_digest})
    return WorldFactProjection(
        fact_id=fact_id_for(entity, relation, value, scope), entity=entity, relation=relation,
        modeled_value=None if value is None else str(value), temporal_scope=scope_text,
        world_status=status, epistemic_status=(belief.status if belief else None),
        confidence=(belief.confidence if belief else None),
        source_proposition_id=(proposition.proposition_id if has_basis else None),
        reason_codes=reasons, evidence_basis_digest=basis)


def project_entities(db_path: str, *, now: Optional[float] = None,
                     stale_after: Optional[float] = None) -> Tuple[WorldFactProjection, ...]:
    """
    Every world fact the ledger implies: each proposition it holds becomes exactly one fact.

    This is the projection direction that must never reverse - the ledger is read, never written.
    """
    moment = time.time() if now is None else float(now)
    cognitive = reconstruct_beliefs(db_path, now=moment, stale_after=stale_after)
    facts: List[WorldFactProjection] = []
    for proposition in cognitive.propositions:
        entity = entity_for(proposition.subject)
        facts.append(project_fact(db_path, entity=entity, relation=proposition.predicate,
                                  value=proposition.object_value,
                                  scope=proposition.temporal_scope, now=moment,
                                  stale_after=stale_after))
    return tuple(sorted(facts, key=lambda f: f.fact_id))


def record_world_snapshot(db_path: str, *, now: Optional[float] = None,
                          stale_after: Optional[float] = None) -> int:
    """
    Append the current world state as an immutable snapshot (law 6).

    A snapshot is only appended when the DERIVED state actually changed, so history is a record of
    what the world looked like at each point rather than a log of when we happened to look.
    """
    moment = time.time() if now is None else float(now)
    facts = project_entities(db_path, now=moment, stale_after=stale_after)
    conn = _connect(db_path)
    appended = 0
    try:
        init_schema(conn)
        for fact in facts:
            latest = conn.execute(
                "SELECT * FROM ciph_world_snapshots WHERE fact_id = ? "
                "ORDER BY snapshot_version DESC LIMIT 1;", (fact.fact_id,)).fetchone()
            if latest is not None and latest["evidence_basis_digest"] == fact.evidence_basis_digest:
                continue
            version = (int(latest["snapshot_version"]) + 1) if latest else 1
            conn.execute(
                "INSERT INTO ciph_world_snapshots (fact_id, snapshot_version, entity_id, relation, "
                "modeled_value, temporal_scope, world_status, epistemic_status, confidence, "
                "reason_codes_json, evidence_basis_digest, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
                (fact.fact_id, version, fact.entity.entity_id, fact.relation, fact.modeled_value,
                 fact.temporal_scope, fact.world_status, fact.epistemic_status, fact.confidence,
                 json.dumps(list(fact.reason_codes)), fact.evidence_basis_digest, moment),
            )
            appended += 1
        conn.commit()
    finally:
        conn.close()
    return appended


def world_history(db_path: str, fact_id: str) -> List[Dict[str, Any]]:
    """Every historical snapshot of one fact, oldest first. Nothing here is ever rewritten."""
    conn = _connect(db_path, read_only=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_world_snapshots WHERE fact_id = ? ORDER BY snapshot_version;",
            (fact_id,))]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def world_digest(db_path: str, *, now: Optional[float] = None,
                 stale_after: Optional[float] = None) -> str:
    """The deterministic identity of the world model (laws 9 and 10)."""
    return _digest([f.as_dict() for f in project_entities(db_path, now=now, stale_after=stale_after)])
