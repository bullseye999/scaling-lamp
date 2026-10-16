"""
ciph.kernel.epistemic_ledger - durable observation, evidence and belief projection.

4.2 Gate Zero. The principle it exists to enforce:

    EVIDENCE IS DURABLE. BELIEFS ARE PROJECTIONS OVER EVIDENCE.
    CONFIDENCE IS A PROPERTY OF THE PROJECTION, NEVER EVIDENCE ITSELF.

Five things that are routinely confused are kept strictly apart here:

    Observation   the raw thing Ciph received or measured
    Claim         a proposition asserted by an observation/source
    Evidence      a durable SUPPORTS / CONTRADICTS / CONTEXT_ONLY link between the two
    Belief        Ciph's CURRENT projection over the evidence for one canonical proposition
    Confidence    how strongly the current evidence supports that belief

A model's output is recorded as a MODEL OUTPUT, which is explicitly not evidence.

THE LAWS (each has a specimen in `test_gate_4_2_epistemic_ledger.py`)

 1. OBSERVATION != CLAIM.       Receiving text does not make its contents true.
 2. CLAIM != BELIEF.            A source asserting P does not force Ciph to believe P.
 3. BELIEF != FACT.             Confidence 0.999 does not promote P into canonical truth.
 4. MODEL REPETITION ADDS ZERO EVIDENCE. Restating P is not confirming P.
 5. EVIDENCE IS APPEND-ONLY.    New contradiction never deletes earlier support.
 6. BELIEF STATE IS RECONSTRUCTIBLE. Delete the projection; replay evidence; same state, same digest.
 7. CONTRADICTION IS FIRST-CLASS. Support + contradiction -> CONTESTED, not last-one-wins.
 8. ABSENCE OF SUPPORT != REFUTATION. No evidence for P is UNRESOLVED, never REFUTED.
 9. STALENESS IS TEMPORAL, NOT FALSEHOOD. Old support stops being current; it was not wrong.
10. CONFIDENCE CANNOT CREATE EVIDENCE.    No API updates a score without a link behind it.
11. UNKNOWN IS VALID.          A proposition may stay UNRESOLVED indefinitely.
12. HISTORY IS NEVER REWRITTEN. Current belief changes; previous projections remain historical.

DELIBERATELY OUT OF SCOPE (Gate One and later): whether two sources are actually independent, whether
an inference is sound, whether a prediction was calibrated. Gate Zero records WHO said this, WHERE it
came from, WHICH proposition it bears on, and WHETHER it supports or contradicts - and derives belief
from exactly that, mechanically.
"""

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

RELATION_SUPPORTS = "SUPPORTS"
RELATION_CONTRADICTS = "CONTRADICTS"
RELATION_CONTEXT_ONLY = "CONTEXT_ONLY"
VALID_RELATIONS = (RELATION_SUPPORTS, RELATION_CONTRADICTS, RELATION_CONTEXT_ONLY)

PROPOSITION_VERSION = 1

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_propositions (
        proposition_id TEXT PRIMARY KEY,
        proposition_version INTEGER NOT NULL,
        canonical_form TEXT NOT NULL,
        subject TEXT NOT NULL,
        predicate TEXT NOT NULL,
        object_value TEXT,
        temporal_scope TEXT,
        first_recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_observations (
        observation_id TEXT PRIMARY KEY,
        source_ref TEXT,
        observed_at REAL,
        received_at REAL,
        content_digest TEXT,
        raw_text TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_evidence (
        evidence_id TEXT PRIMARY KEY,
        proposition_id TEXT NOT NULL,
        relation TEXT NOT NULL,
        source_ref TEXT,
        observation_ref TEXT,
        evidence_time REAL,
        recorded_at REAL,
        note TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_model_outputs (
        output_id TEXT PRIMARY KEY,
        proposition_id TEXT,
        model_ref TEXT,
        output_digest TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_belief_projections (
        proposition_id TEXT NOT NULL,
        projection_version INTEGER NOT NULL,
        status TEXT NOT NULL,
        confidence REAL NOT NULL,
        supporting_refs TEXT,
        contradicting_refs TEXT,
        context_refs TEXT,
        stale_refs TEXT,
        derivation_digest TEXT NOT NULL,
        first_observed_at REAL,
        last_evidence_at REAL,
        projected_at REAL,
        PRIMARY KEY (proposition_id, projection_version)
    );
    """,
)


class EpistemicError(Exception):
    """An epistemic operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class BeliefStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    CONTESTED = "CONTESTED"
    UNRESOLVED = "UNRESOLVED"
    REFUTED = "REFUTED"
    STALE = "STALE"


@dataclass(frozen=True)
class Proposition:
    """A canonical proposition: identity comes from meaning, and temporal scope is part of meaning."""

    proposition_id: str
    subject: str
    predicate: str
    object_value: Optional[str]
    temporal_scope: Optional[str]
    canonical_form: str
    proposition_version: int = PROPOSITION_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "proposition_id": self.proposition_id,
            "proposition_version": self.proposition_version,
            "canonical_form": self.canonical_form,
            "subject": self.subject,
            "predicate": self.predicate,
            "object_value": self.object_value,
            "temporal_scope": self.temporal_scope,
        }


@dataclass(frozen=True)
class BeliefRecord:
    """The current epistemic projection for one proposition. Derived, never declared."""

    proposition_id: str
    status: str
    confidence: float
    supporting_evidence: Tuple[str, ...]
    contradicting_evidence: Tuple[str, ...]
    context_evidence: Tuple[str, ...]
    stale_evidence: Tuple[str, ...]
    projection_version: int
    first_observed_at: Optional[float]
    last_evidence_at: Optional[float]
    derivation_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "proposition_id": self.proposition_id,
            "status": self.status,
            "confidence": round(self.confidence, 12),
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "context_evidence": list(self.context_evidence),
            "stale_evidence": list(self.stale_evidence),
            "projection_version": self.projection_version,
            "first_observed_at": self.first_observed_at,
            "last_evidence_at": self.last_evidence_at,
            "derivation_digest": self.derivation_digest,
        }


@dataclass(frozen=True)
class EpistemicState:
    """Every proposition and its current belief, reconstructed from evidence alone."""

    propositions: Tuple[Proposition, ...] = ()
    beliefs: Tuple[BeliefRecord, ...] = ()
    evidence_count: int = 0

    def belief_for(self, proposition_id: str) -> Optional[BeliefRecord]:
        for belief in self.beliefs:
            if belief.proposition_id == proposition_id:
                return belief
        return None

    def as_dict(self) -> Dict[str, Any]:
        return {"propositions": [p.as_dict() for p in self.propositions],
                "beliefs": [b.as_dict() for b in self.beliefs],
                "evidence_count": self.evidence_count}

    def canonical_digest(self) -> str:
        blob = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


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


# ---------------------------------------------------------------------------- propositions
def canonical_proposition(subject: str, predicate: str, object_value: Any = None,
                          temporal_scope: Optional[str] = None) -> Proposition:
    """
    Build a proposition whose identity comes from MEANING, including temporal scope.

    "Server X is online" and "Server X was online at 14:03" are different propositions, and so are
    "BTC > 100k today" and "BTC > 100k this year". If identity were fuzzy, everything downstream -
    evidence linkage, contradiction, confidence, staleness - would be mush.
    """
    subject = str(subject).strip()
    predicate = str(predicate).strip()
    if not subject or not predicate:
        raise EpistemicError("PROPOSITION_REQUIRES_SUBJECT_AND_PREDICATE", f"{subject!r}/{predicate!r}")
    value = None if object_value is None else str(object_value).strip()
    scope = None if temporal_scope is None else str(temporal_scope).strip()
    body = json.dumps(
        {"proposition_version": PROPOSITION_VERSION, "subject": subject, "predicate": predicate,
         "object_value": value, "temporal_scope": scope},
        sort_keys=True, separators=(",", ":"),
    )
    return Proposition(
        proposition_id="PROP-" + hashlib.sha256(body.encode("utf-8")).hexdigest()[:16].upper(),
        subject=subject, predicate=predicate, object_value=value, temporal_scope=scope,
        canonical_form=body,
    )


def _ensure_proposition(conn: sqlite3.Connection, proposition: Proposition, now: float) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO ciph_propositions (proposition_id, proposition_version, "
        "canonical_form, subject, predicate, object_value, temporal_scope, first_recorded_at) "
        "VALUES (?,?,?,?,?,?,?,?);",
        (proposition.proposition_id, proposition.proposition_version, proposition.canonical_form,
         proposition.subject, proposition.predicate, proposition.object_value,
         proposition.temporal_scope, now),
    )


# ---------------------------------------------------------------------------- durable facts
def record_observation(db_path: str, *, source_ref: Optional[str] = None,
                       raw_text: Optional[str] = None, content_digest: Optional[str] = None,
                       observed_at: Optional[float] = None,
                       now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record something that was RECEIVED. This is not a claim about the world and asserts nothing:
    observation is the bottom of the stack precisely because receiving text does not make it true.
    """
    moment = time.time() if now is None else float(now)
    digest = content_digest or (
        hashlib.sha256(str(raw_text or "").encode("utf-8")).hexdigest() if raw_text is not None else None
    )
    observation_id = f"OBS-{uuid.uuid4().hex[:12].upper()}"
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute(
            "INSERT INTO ciph_observations (observation_id, source_ref, observed_at, received_at, "
            "content_digest, raw_text) VALUES (?,?,?,?,?,?);",
            (observation_id, source_ref, observed_at if observed_at is not None else moment,
             moment, digest, raw_text),
        )
        conn.commit()
        return {"observation_id": observation_id, "source_ref": source_ref,
                "content_digest": digest, "observed_at": observed_at or moment}
    finally:
        conn.close()


def record_evidence(db_path: str, proposition: Proposition, *, relation: str,
                    source_ref: Optional[str] = None, observation_ref: Optional[str] = None,
                    evidence_time: Optional[float] = None, note: Optional[str] = None,
                    now: Optional[float] = None) -> str:
    """
    Append ONE durable evidence link for a proposition. There is no update and no delete path.

    `relation` is recorded explicitly rather than inferred from a status label later: support and
    contradiction are FACTS about the link, and reconstruction must be mechanical, not interpretive.
    """
    if relation not in VALID_RELATIONS:
        raise EpistemicError("INVALID_EVIDENCE_RELATION", str(relation))
    moment = time.time() if now is None else float(now)
    evidence_id = f"EVD-{uuid.uuid4().hex[:12].upper()}"
    conn = _connect(db_path)
    try:
        init_schema(conn)
        _ensure_proposition(conn, proposition, moment)
        conn.execute(
            "INSERT INTO ciph_evidence (evidence_id, proposition_id, relation, source_ref, "
            "observation_ref, evidence_time, recorded_at, note) VALUES (?,?,?,?,?,?,?,?);",
            (evidence_id, proposition.proposition_id, relation, source_ref, observation_ref,
             evidence_time if evidence_time is not None else moment, moment, note),
        )
        conn.commit()
        return evidence_id
    finally:
        conn.close()


def record_model_output(db_path: str, *, model_ref: str, output_text: str,
                        proposition: Optional[Proposition] = None,
                        now: Optional[float] = None) -> str:
    """
    Record that a MODEL said something (law 4).

    This writes an audit fact and creates NO evidence. Ten restatements of P are ten model outputs and
    zero confirmations - otherwise Ciph could build an epistemic echo chamber entirely inside itself.
    """
    moment = time.time() if now is None else float(now)
    output_id = f"MDL-{uuid.uuid4().hex[:12].upper()}"
    conn = _connect(db_path)
    try:
        init_schema(conn)
        if proposition is not None:
            _ensure_proposition(conn, proposition, moment)
        conn.execute(
            "INSERT INTO ciph_model_outputs (output_id, proposition_id, model_ref, output_digest, "
            "recorded_at) VALUES (?,?,?,?,?);",
            (output_id, proposition.proposition_id if proposition else None, model_ref,
             hashlib.sha256(str(output_text).encode("utf-8")).hexdigest(), moment),
        )
        conn.commit()
        return output_id
    finally:
        conn.close()


# ---------------------------------------------------------------------------- projection
def _derive_belief(proposition_id: str, links: Sequence[Mapping[str, Any]], *,
                   now: float, stale_after: Optional[float],
                   first_recorded_at: Optional[float]) -> BeliefRecord:
    """
    The ONE derivation from evidence to belief. Mechanical by construction.

    Evidence is grouped by the RELATION it recorded - never by a status label inferred later - and
    freshness is applied only to the DERIVATION. A stale support link is still support; it has simply
    stopped being current, which is why it appears in `stale_evidence` and not in `context_evidence`.
    """
    support: List[Mapping[str, Any]] = []
    contradict: List[Mapping[str, Any]] = []
    context: List[Mapping[str, Any]] = []
    stale: List[Mapping[str, Any]] = []
    newest: Optional[float] = None
    cutoff = None if stale_after is None else now - float(stale_after)

    def fresh(link: Mapping[str, Any]) -> bool:
        if cutoff is None:
            return True
        return float(link["evidence_time"] or 0.0) >= cutoff

    for link in sorted(links, key=lambda item: str(item["evidence_id"])):
        relation = str(link["relation"])
        newest = max(newest or 0.0, float(link["evidence_time"] or 0.0))
        if relation == RELATION_SUPPORTS:
            support.append(link)
            if not fresh(link):
                stale.append(link)
        elif relation == RELATION_CONTRADICTS:
            contradict.append(link)
            if not fresh(link):
                stale.append(link)
        else:
            context.append(link)

    support_ids = sorted(str(l["evidence_id"]) for l in support)
    contradict_ids = sorted(str(l["evidence_id"]) for l in contradict)
    stale_ids = sorted(str(l["evidence_id"]) for l in stale)
    context_ids = sorted(str(l["evidence_id"]) for l in context)

    fresh_support = sum(1 for l in support if fresh(l))
    fresh_contradict = sum(1 for l in contradict if fresh(l))

    if fresh_support and fresh_contradict:
        status = BeliefStatus.CONTESTED
    elif fresh_support:
        status = BeliefStatus.SUPPORTED
    elif fresh_contradict:
        status = BeliefStatus.REFUTED
    elif stale:
        # Law 9: too old to be current support is NOT the same as being wrong.
        status = BeliefStatus.STALE
    else:
        # Law 8 + 11: no support is not refutation, and UNRESOLVED is a valid answer to keep.
        status = BeliefStatus.UNRESOLVED

    total = fresh_support + fresh_contradict
    confidence = round(fresh_support / total, 12) if total else 0.0

    payload = {
        "proposition_id": proposition_id,
        "status": status.value,
        "confidence": confidence,
        "supporting": support_ids,
        "contradicting": contradict_ids,
        "stale": stale_ids,
        "context": context_ids,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    return BeliefRecord(
        proposition_id=proposition_id,
        status=status.value,
        confidence=confidence,
        supporting_evidence=tuple(support_ids),
        contradicting_evidence=tuple(contradict_ids),
        context_evidence=tuple(context_ids),
        stale_evidence=tuple(stale_ids),
        projection_version=0,
        first_observed_at=first_recorded_at,
        last_evidence_at=newest,
        derivation_digest=digest,
    )


def reconstruct(db_path: str, *, now: Optional[float] = None,
                stale_after: Optional[float] = None,
                conn: Optional[sqlite3.Connection] = None) -> EpistemicState:
    """
    Rebuild every belief from the durable evidence. Reads only; the stored projections are NOT an
    input - delete them and this returns the same state and the same digest (law 6).
    """
    moment = time.time() if now is None else float(now)
    owned = conn is None
    conn = _connect(db_path, read_only=True) if owned else conn
    try:
        propositions = [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_propositions ORDER BY proposition_id;")]
        links = [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_evidence ORDER BY evidence_id;")]
    except sqlite3.Error:
        propositions, links = [], []
    finally:
        if owned:
            conn.close()

    by_proposition: Dict[str, List[Dict[str, Any]]] = {}
    for link in links:
        by_proposition.setdefault(str(link["proposition_id"]), []).append(link)

    beliefs: List[BeliefRecord] = []
    for row in propositions:
        proposition_id = str(row["proposition_id"])
        beliefs.append(_derive_belief(proposition_id, by_proposition.get(proposition_id, []),
                                      now=moment, stale_after=stale_after,
                                      first_recorded_at=row["first_recorded_at"]))
    return EpistemicState(
        propositions=tuple(Proposition(
            proposition_id=str(r["proposition_id"]),
            subject=r["subject"], predicate=r["predicate"], object_value=r["object_value"],
            temporal_scope=r["temporal_scope"], canonical_form=r["canonical_form"],
            proposition_version=int(r["proposition_version"]),
        ) for r in propositions),
        beliefs=tuple(sorted(beliefs, key=lambda b: b.proposition_id)),
        evidence_count=len(links),
    )


def project_beliefs(db_path: str, *, now: Optional[float] = None,
                    stale_after: Optional[float] = None) -> Dict[str, Any]:
    """
    Persist the CURRENT projection as a new immutable version per proposition.

    A version is only appended when the derived projection actually changed, so history stays
    meaningful. Previous versions are never rewritten (law 12), and the projection is never an INPUT
    to derivation (law 6).
    """
    moment = time.time() if now is None else float(now)
    state = reconstruct(db_path, now=moment, stale_after=stale_after)
    conn = _connect(db_path)
    appended = 0
    try:
        init_schema(conn)
        for belief in state.beliefs:
            latest = conn.execute(
                "SELECT * FROM ciph_belief_projections WHERE proposition_id = ? "
                "ORDER BY projection_version DESC LIMIT 1;", (belief.proposition_id,)).fetchone()
            if latest is not None and latest["derivation_digest"] == belief.derivation_digest:
                continue
            version = (int(latest["projection_version"]) + 1) if latest else 1
            conn.execute(
                "INSERT INTO ciph_belief_projections (proposition_id, projection_version, status, "
                "confidence, supporting_refs, contradicting_refs, context_refs, stale_refs, "
                "derivation_digest, first_observed_at, last_evidence_at, projected_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
                (belief.proposition_id, version, belief.status, belief.confidence,
                 json.dumps(list(belief.supporting_evidence)), json.dumps(list(belief.contradicting_evidence)),
                 json.dumps(list(belief.context_evidence)), json.dumps(list(belief.stale_evidence)),
                 belief.derivation_digest,
                 belief.first_observed_at, belief.last_evidence_at, moment),
            )
            appended += 1
        conn.commit()
    finally:
        conn.close()
    return {"projected_at": moment, "projections_appended": appended,
            "state_digest": state.canonical_digest(), "propositions": len(state.propositions)}


def projection_history(db_path: str, proposition_id: str) -> List[Dict[str, Any]]:
    """Every historical projection for one proposition, oldest first. Nothing here is rewritten."""
    conn = _connect(db_path, read_only=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_belief_projections WHERE proposition_id = ? "
            "ORDER BY projection_version;", (proposition_id,))]
    except sqlite3.Error:
        return []
    finally:
        conn.close()
