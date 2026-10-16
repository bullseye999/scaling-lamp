"""
ciph.kernel.world_dynamics - what CHANGES from one state to another.

4.3 Gate One. A transition records that the world moved between two observed states. It does not say
why, and it does not fill the space between the observations:

    T1  service OFFLINE
    T3  service ONLINE
    -> OFFLINE -> ONLINE happened somewhere in (T1, T3]

and NOT "it came online at T2", because nothing observed T2.

LAWS (each has a specimen in `test_gate_4_3_dynamics.py`)

 1. State difference != causal explanation. A transition carries no cause and has no API for one.
 2. A transition records change, not why it changed.
 3. Missing intermediate observations remain UNKNOWN.
 4. Temporal ordering must be evidence-backed: an unorderable scope forms no transition.
 5. Transition history is append-only.
 6. Later evidence may REFINE a window; it may never fabricate an exact time.
 7. Repeated observations of the same transition do not duplicate it.
 8. World dynamics reconstruct deterministically.

Only a PRESENT world fact establishes a world STATE. An ABSENT fact is knowledge that a claim did NOT
hold, which is a different thing from a state value: "not healthy" is not the token "degraded", so
using a refutation as a state can narrate a change that never happened - and where two claims bear on
one scope it can even pin an exact moment to it. A refutation is therefore NOT used as a state value
here: a state that matters is asserted as its own PRESENT proposition. Where that leaves a relation
under-described, dynamics UNDER-reports rather than inventing a transition, which is the same
direction the rest of the constitution resolves uncertainty. Contested and unknown states likewise
cannot produce a definite change.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.world_model import (
    WORLD_PRESENT,
    WorldFactProjection,
    parse_scope,
    project_entities,
)

TRANSITION_STATE_CHANGE = "STATE_CHANGE"

REASON_NOT_DEFINITE_STATE = "SOURCE_FACT_NOT_DEFINITE"
REASON_UNORDERABLE_SCOPE = "UNORDERABLE_SCOPE"
REASON_NO_INTERMEDIATE_OBSERVATION = "NO_INTERMEDIATE_OBSERVATION"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_world_transitions (
        transition_id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL,
        relation TEXT NOT NULL,
        from_fact_id TEXT NOT NULL,
        to_fact_id TEXT NOT NULL,
        from_value TEXT,
        to_value TEXT,
        window_lower REAL,
        window_upper REAL,
        exact_at REAL,
        transition_type TEXT NOT NULL,
        evidence_basis_digest TEXT NOT NULL,
        recorded_at REAL
    );
    """,
)


class DynamicsError(Exception):
    """A dynamics operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class TransitionRecord:
    transition_id: str
    entity_id: str
    relation: str
    from_fact_id: str
    to_fact_id: str
    from_value: Optional[str]
    to_value: Optional[str]
    window_lower: Optional[float]
    window_upper: Optional[float]
    exact_at: Optional[float]
    transition_type: str
    evidence_basis_digest: str
    intermediate_observations: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {"transition_id": self.transition_id, "entity_id": self.entity_id,
                "relation": self.relation, "from_fact_id": self.from_fact_id,
                "to_fact_id": self.to_fact_id, "from_value": self.from_value,
                "to_value": self.to_value, "window_lower": self.window_lower,
                "window_upper": self.window_upper, "exact_at": self.exact_at,
                "transition_type": self.transition_type,
                "evidence_basis_digest": self.evidence_basis_digest,
                "intermediate_observations": self.intermediate_observations}

    def canonical_digest(self) -> str:
        return _digest(self.as_dict())

    def describe_window(self) -> str:
        """How the change should be spoken about: a window, never an invented instant."""
        if self.exact_at is not None:
            return f"at {self.exact_at}"
        if self.window_lower is None or self.window_upper is None:
            return "at an unknown time"
        return f"somewhere in ({self.window_lower}, {self.window_upper}]"

    def require_exact_time(self) -> float:
        """
        Law 6, as a guard: a caller that needs a precise moment is REFUSED rather than handed a guess.
        """
        if self.exact_at is None:
            raise DynamicsError(
                "TRANSITION_TIME_NOT_OBSERVED",
                f"{self.transition_id} is only bounded: {self.describe_window()}",
            )
        return self.exact_at


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


def _transition_id(entity_id: str, relation: str, from_fact: str, to_fact: str) -> str:
    return "TRN-" + hashlib.sha256(f"{entity_id}:{relation}:{from_fact}:{to_fact}".encode("utf-8")
                                   ).hexdigest()[:12].upper()


def derive_transitions(db_path: str, *, now: Optional[float] = None,
                       stale_after: Optional[float] = None) -> Tuple[TransitionRecord, ...]:
    """
    Derive every observed state change, from definite world facts only.

    Nothing is inferred between observations: a pair of facts yields a WINDOW, and the count of facts
    strictly inside that window is reported so "we did not look" stays visible.
    """
    moment = time.time() if now is None else float(now)
    facts = project_entities(db_path, now=moment, stale_after=stale_after)

    grouped: Dict[Tuple[str, str], List[Tuple[float, float, WorldFactProjection]]] = {}
    for fact in facts:
        # A refutation is not a state value (see the module header): only a PRESENT fact says which
        # state the world is in.
        if fact.world_status != WORLD_PRESENT:
            continue
        kind, lower, upper = parse_scope(fact.temporal_scope)
        if kind == "UNORDERABLE" or lower is None:
            continue
        grouped.setdefault((fact.entity.entity_id, fact.relation), []).append((lower, upper, fact))

    transitions: List[TransitionRecord] = []
    for (entity_id, relation), series in sorted(grouped.items()):
        ordered = sorted(series, key=lambda item: (item[0], item[1]))
        for (lower_a, upper_a, first), (lower_b, upper_b, second) in zip(ordered, ordered[1:]):
            if first.modeled_value == second.modeled_value:
                continue
            window_lower, window_upper = upper_a, lower_b
            if window_upper < window_lower:
                window_lower, window_upper = window_upper, window_lower
            intermediates = sum(1 for low, _high, _f in ordered if window_lower < low < window_upper)
            # An exact instant is only available when the evidence itself pins one, which a CHANGE
            # never does: something moved, so the two observations are at different times.
            exact_at = window_lower if window_lower == window_upper else None
            transitions.append(TransitionRecord(
                transition_id=_transition_id(entity_id, relation, first.fact_id, second.fact_id),
                entity_id=entity_id, relation=relation, from_fact_id=first.fact_id,
                to_fact_id=second.fact_id, from_value=first.modeled_value,
                to_value=second.modeled_value, window_lower=window_lower, window_upper=window_upper,
                exact_at=exact_at, transition_type=TRANSITION_STATE_CHANGE,
                evidence_basis_digest=_digest({"from": first.evidence_basis_digest,
                                               "to": second.evidence_basis_digest}),
                intermediate_observations=intermediates))
    return tuple(sorted(transitions, key=lambda t: t.transition_id))


def record_transitions(db_path: str, *, now: Optional[float] = None,
                       stale_after: Optional[float] = None) -> int:
    """
    Append the currently derived transitions (law 5/7).

    Identity is `(entity, relation, from_fact, to_fact)`, so re-observing the same change does not
    duplicate it; a REFINED window derives a different one, and the earlier record stays as history.
    """
    moment = time.time() if now is None else float(now)
    transitions = derive_transitions(db_path, now=moment, stale_after=stale_after)
    conn = _connect(db_path)
    appended = 0
    try:
        init_schema(conn)
        for transition in transitions:
            existing = conn.execute("SELECT 1 FROM ciph_world_transitions WHERE transition_id = ?;",
                                    (transition.transition_id,)).fetchone()
            if existing is not None:
                continue
            conn.execute(
                "INSERT INTO ciph_world_transitions (transition_id, entity_id, relation, from_fact_id, "
                "to_fact_id, from_value, to_value, window_lower, window_upper, exact_at, "
                "transition_type, evidence_basis_digest, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
                (transition.transition_id, transition.entity_id, transition.relation,
                 transition.from_fact_id, transition.to_fact_id, transition.from_value,
                 transition.to_value, transition.window_lower, transition.window_upper,
                 transition.exact_at, transition.transition_type,
                 transition.evidence_basis_digest, moment),
            )
            appended += 1
        conn.commit()
    finally:
        conn.close()
    return appended


def transition_history(db_path: str, entity_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = _connect(db_path, read_only=True)
    conn.row_factory = sqlite3.Row
    try:
        if entity_id is None:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM ciph_world_transitions ORDER BY transition_id;")]
        else:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM ciph_world_transitions WHERE entity_id = ? ORDER BY transition_id;",
                (entity_id,))]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return rows


def dynamics_digest(db_path: str, *, now: Optional[float] = None,
                    stale_after: Optional[float] = None) -> str:
    """The deterministic identity of the derived dynamics (law 8)."""
    return _digest([t.as_dict() for t in derive_transitions(db_path, now=now, stale_after=stale_after)])
