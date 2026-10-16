"""
ciph.kernel.causal_model - what MIGHT explain observed transitions.

4.3 Gate Two. Dynamics record that the world MOVED; a causal hypothesis records a CANDIDATE
explanation for that movement. It is a hypothesis and it stays one until FALSIFIABLE predictions are
tested against the world:

    H1  the deployment caused the latency rise
    H2  the upstream provider caused the latency rise
    -> both PROPOSED, zero empirical credit, and they coexist

ABSOLUTE LAW
    correlation / temporal order != causation. "A preceded B" is not "A caused B".

LAWS (each has a specimen in `test_gate_4_3_causality.py`)

 1. Causes are never inferred merely because A preceded B.
 2. Causal hypotheses are not evidence: nothing here writes the epistemic ledger.
 3. Model-generated causal stories add zero support - proposing NEVER yields SUPPORTED.
 4. Competing causal hypotheses may coexist.
 5. A hypothesis must generate falsifiable predictions before gaining any empirical credit.
 6. Prediction outcomes flow through 4.2 Gate Three, so a hypothesis moves only on canonical,
    resolved prediction evidence - never on a model's say-so.
 7. Failed predictions weaken (CONTESTED) or refute (REFUTED) the hypothesis.
 8. Successful predictions SUPPORT but never prove causality absolutely.
 9. Historical hypotheses are immutable: status is DERIVED, never written onto the record.
10. Same evidence/prediction history -> same causal projection.

The status is not a column. It is recomputed from the linked predictions each time it is asked for,
so there is no way to write "SUPPORTED" onto a story that no test has touched.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.belief_revision import INFERENCE_STALE, inference_status
from ciph.kernel.predictions import (
    OUTCOME_FALSE,
    OUTCOME_TRUE,
    STATUS_RESOLVED,
    get_prediction,
)

HYPOTHESIS_PROPOSED = "PROPOSED"
HYPOTHESIS_SUPPORTED = "SUPPORTED"
HYPOTHESIS_CONTESTED = "CONTESTED"
HYPOTHESIS_REFUTED = "REFUTED"
HYPOTHESIS_STALE = "STALE"
VALID_HYPOTHESIS_STATUSES = (HYPOTHESIS_PROPOSED, HYPOTHESIS_SUPPORTED, HYPOTHESIS_CONTESTED,
                             HYPOTHESIS_REFUTED, HYPOTHESIS_STALE)

REASON_NO_FALSIFIABLE_PREDICTION = "NO_FALSIFIABLE_PREDICTION"
REASON_PREDICTIONS_PENDING = "PREDICTIONS_PENDING"
REASON_PREDICTIONS_SUPPORT = "PREDICTIONS_SUPPORT"
REASON_PREDICTIONS_REFUTE = "PREDICTIONS_REFUTE"
REASON_PREDICTIONS_CONFLICT = "PREDICTIONS_CONFLICT"
REASON_INFERENCE_STALE = "INFERENCE_BASIS_STALE"
REASON_EXPLICITLY_INVALIDATED = "EXPLICITLY_INVALIDATED"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_causal_hypotheses (
        hypothesis_id TEXT PRIMARY KEY,
        cause TEXT NOT NULL,
        effect TEXT NOT NULL,
        evidence_refs_json TEXT,
        inference_refs_json TEXT,
        transition_refs_json TEXT,
        note TEXT,
        basis_digest TEXT NOT NULL,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_causal_prediction_links (
        link_id TEXT PRIMARY KEY,
        hypothesis_id TEXT NOT NULL,
        prediction_id TEXT NOT NULL,
        expect TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_causal_invalidations (
        invalidation_id TEXT PRIMARY KEY,
        hypothesis_id TEXT NOT NULL,
        reason TEXT,
        recorded_at REAL
    );
    """,
)


class CausalModelError(Exception):
    """A causal-model operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class CausalHypothesis:
    hypothesis_id: str
    cause: str
    effect: str
    evidence_refs: Tuple[str, ...]
    inference_refs: Tuple[str, ...]
    transition_refs: Tuple[str, ...]
    basis_digest: str
    created_at: Optional[float] = None
    note: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "cause": self.cause, "effect": self.effect,
                "evidence_refs": list(self.evidence_refs), "inference_refs": list(self.inference_refs),
                "transition_refs": list(self.transition_refs), "basis_digest": self.basis_digest,
                "note": self.note}

    def canonical_digest(self) -> str:
        return _digest(self.as_dict())


@dataclass(frozen=True)
class CausalAssessment:
    """The DERIVED standing of a hypothesis. Nothing here is written onto the hypothesis."""

    hypothesis_id: str
    status: str
    reason_codes: Tuple[str, ...]
    linked_predictions: Tuple[str, ...]
    resolved_true: Tuple[str, ...]
    resolved_false: Tuple[str, ...]
    unresolved: Tuple[str, ...]
    stale_inferences: Tuple[str, ...]
    basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "status": self.status,
                "reason_codes": list(self.reason_codes),
                "linked_predictions": list(self.linked_predictions),
                "resolved_true": list(self.resolved_true),
                "resolved_false": list(self.resolved_false),
                "unresolved": list(self.unresolved),
                "stale_inferences": list(self.stale_inferences),
                "basis_digest": self.basis_digest}

    def canonical_digest(self) -> str:
        return _digest(self.as_dict())


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


def _hypothesis_id(cause: str, effect: str) -> str:
    return "HY-" + hashlib.sha256(f"{cause}\x00{effect}".encode("utf-8")).hexdigest()[:12].upper()


def _row_to_hypothesis(row: Mapping[str, Any]) -> CausalHypothesis:
    return CausalHypothesis(
        hypothesis_id=str(row["hypothesis_id"]), cause=str(row["cause"]), effect=str(row["effect"]),
        evidence_refs=tuple(json.loads(row["evidence_refs_json"] or "[]")),
        inference_refs=tuple(json.loads(row["inference_refs_json"] or "[]")),
        transition_refs=tuple(json.loads(row["transition_refs_json"] or "[]")),
        basis_digest=str(row["basis_digest"]), created_at=row["created_at"], note=row["note"])


def propose_hypothesis(db_path: str, *, cause: str, effect: str,
                       evidence_refs: Sequence[str] = (), inference_refs: Sequence[str] = (),
                       transition_refs: Sequence[str] = (), note: Optional[str] = None,
                       now: Optional[float] = None) -> CausalHypothesis:
    """
    Propose ONE candidate explanation. It is a PROPOSAL and nothing else.

    There is deliberately no parameter for a status, a confidence or a verdict: proposing can never
    hand a story empirical credit (law 3). Credit only ever arrives through linked 4.2 Gate Three
    predictions that real evidence resolved.
    """
    cause_text = str(cause).strip()
    effect_text = str(effect).strip()
    if not cause_text or not effect_text:
        raise CausalModelError("HYPOTHESIS_REQUIRES_CAUSE_AND_EFFECT", f"{cause!r}/{effect!r}")
    moment = time.time() if now is None else float(now)
    evidence = sorted(str(ref) for ref in evidence_refs)
    inferences = sorted(str(ref) for ref in inference_refs)
    transitions = sorted(str(ref) for ref in transition_refs)
    hypothesis_id = _hypothesis_id(cause_text, effect_text)
    basis = _digest({"cause": cause_text, "effect": effect_text, "evidence": evidence,
                     "inferences": inferences, "transitions": transitions})

    conn = _connect(db_path)
    try:
        init_schema(conn)
        existing = conn.execute("SELECT * FROM ciph_causal_hypotheses WHERE hypothesis_id = ?;",
                                (hypothesis_id,)).fetchone()
        if existing is not None:
            return _row_to_hypothesis(existing)
        conn.execute(
            "INSERT INTO ciph_causal_hypotheses (hypothesis_id, cause, effect, evidence_refs_json, "
            "inference_refs_json, transition_refs_json, note, basis_digest, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?);",
            (hypothesis_id, cause_text, effect_text, json.dumps(evidence), json.dumps(inferences),
             json.dumps(transitions), note, basis, moment),
        )
        conn.commit()
    finally:
        conn.close()
    return CausalHypothesis(hypothesis_id=hypothesis_id, cause=cause_text, effect=effect_text,
                            evidence_refs=tuple(evidence), inference_refs=tuple(inferences),
                            transition_refs=tuple(transitions), basis_digest=basis,
                            created_at=moment, note=note)


def link_prediction(db_path: str, *, hypothesis_id: str, prediction_id: str,
                    expect: Optional[str] = None, now: Optional[float] = None) -> str:
    """
    Bind one FALSIFIABLE 4.2 Gate Three prediction to the hypothesis (law 5).

    `expect` is a human label ("rollback should restore health"), never authority: it does not enter
    the assessment. The ONLY thing that moves the hypothesis is how the prediction resolved against
    canonical evidence.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        if conn.execute("SELECT 1 FROM ciph_causal_hypotheses WHERE hypothesis_id = ?;",
                        (hypothesis_id,)).fetchone() is None:
            raise CausalModelError("UNKNOWN_HYPOTHESIS", hypothesis_id)
    finally:
        conn.close()
    get_prediction(db_path, prediction_id, now=moment)  # refuses an unknown prediction
    conn = _connect(db_path)
    try:
        init_schema(conn)
        existing = conn.execute(
            "SELECT link_id FROM ciph_causal_prediction_links WHERE hypothesis_id = ? "
            "AND prediction_id = ?;", (hypothesis_id, prediction_id)).fetchone()
        if existing is not None:
            return str(existing["link_id"])
        link_id = "CL-" + hashlib.sha256(
            f"{hypothesis_id}:{prediction_id}".encode("utf-8")).hexdigest()[:12].upper()
        conn.execute("INSERT INTO ciph_causal_prediction_links (link_id, hypothesis_id, "
                     "prediction_id, expect, recorded_at) VALUES (?,?,?,?,?);",
                     (link_id, hypothesis_id, prediction_id, expect, moment))
        conn.commit()
        return link_id
    finally:
        conn.close()


def invalidate_hypothesis(db_path: str, hypothesis_id: str, *, reason: str = "",
                          now: Optional[float] = None) -> str:
    """Append an explicit refutation. The hypothesis record itself is never edited (law 9)."""
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        if conn.execute("SELECT 1 FROM ciph_causal_hypotheses WHERE hypothesis_id = ?;",
                        (hypothesis_id,)).fetchone() is None:
            raise CausalModelError("UNKNOWN_HYPOTHESIS", hypothesis_id)
        invalidation_id = "CINV-" + hashlib.sha256(
            f"{hypothesis_id}:{reason}:{moment}".encode("utf-8")).hexdigest()[:12].upper()
        conn.execute("INSERT OR IGNORE INTO ciph_causal_invalidations (invalidation_id, "
                     "hypothesis_id, reason, recorded_at) VALUES (?,?,?,?);",
                     (invalidation_id, hypothesis_id, reason, moment))
        conn.commit()
        return invalidation_id
    finally:
        conn.close()


def _hypothesis_row(db_path: str, hypothesis_id: str) -> Mapping[str, Any]:
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute("SELECT * FROM ciph_causal_hypotheses WHERE hypothesis_id = ?;",
                           (hypothesis_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    if row is None:
        raise CausalModelError("UNKNOWN_HYPOTHESIS", hypothesis_id)
    return dict(row)


def hypothesis(db_path: str, hypothesis_id: str) -> CausalHypothesis:
    return _row_to_hypothesis(_hypothesis_row(db_path, hypothesis_id))


def _linked_prediction_ids(db_path: str, hypothesis_id: str) -> Tuple[str, ...]:
    conn = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT prediction_id FROM ciph_causal_prediction_links WHERE hypothesis_id = ? "
            "ORDER BY link_id;", (hypothesis_id,))]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return tuple(str(r["prediction_id"]) for r in rows)


def _is_invalidated(db_path: str, hypothesis_id: str) -> bool:
    conn = _connect(db_path, read_only=True)
    try:
        return conn.execute("SELECT 1 FROM ciph_causal_invalidations WHERE hypothesis_id = ? "
                            "LIMIT 1;", (hypothesis_id,)).fetchone() is not None
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def _safe_inference_status(db_path: str, inference_id: str, *, now: float) -> str:
    """A referenced inference we cannot read is treated as unusable, which is the safe direction."""
    try:
        return inference_status(db_path, inference_id, now=now)
    except Exception:
        return INFERENCE_STALE


def _assess_hypothesis(*, invalidated: bool, stale_inferences: Sequence[str],
                       prediction_count: int, resolved_true: Sequence[str],
                       resolved_false: Sequence[str]) -> Tuple[str, Tuple[str, ...]]:
    """
    THE status function. Frozen, and the ONLY place a hypothesis status comes from.

    A hypothesis earns SUPPORTED only from predictions that canonical evidence actually resolved -
    never from how plausible its story sounds, and never from a model repeating it.
    """
    if invalidated:
        return HYPOTHESIS_REFUTED, (REASON_EXPLICITLY_INVALIDATED,)
    if stale_inferences:
        return HYPOTHESIS_STALE, (REASON_INFERENCE_STALE,)
    if prediction_count == 0:
        return HYPOTHESIS_PROPOSED, (REASON_NO_FALSIFIABLE_PREDICTION,)
    if not resolved_true and not resolved_false:
        return HYPOTHESIS_PROPOSED, (REASON_PREDICTIONS_PENDING,)
    if resolved_true and resolved_false:
        return HYPOTHESIS_CONTESTED, (REASON_PREDICTIONS_CONFLICT,)
    if resolved_false:
        return HYPOTHESIS_REFUTED, (REASON_PREDICTIONS_REFUTE,)
    return HYPOTHESIS_SUPPORTED, (REASON_PREDICTIONS_SUPPORT,)


def hypothesis_assessment(db_path: str, hypothesis_id: str, *,
                          now: Optional[float] = None) -> CausalAssessment:
    """Derive the hypothesis's standing from its linked, canonically-resolved predictions (laws 6-8)."""
    moment = time.time() if now is None else float(now)
    row = _hypothesis_row(db_path, hypothesis_id)
    linked = _linked_prediction_ids(db_path, hypothesis_id)

    resolved_true: List[str] = []
    resolved_false: List[str] = []
    unresolved: List[str] = []
    for prediction_id in linked:
        record = get_prediction(db_path, prediction_id, now=moment)
        if record.status == STATUS_RESOLVED and record.outcome == OUTCOME_TRUE:
            resolved_true.append(prediction_id)
        elif record.status == STATUS_RESOLVED and record.outcome == OUTCOME_FALSE:
            resolved_false.append(prediction_id)
        else:
            unresolved.append(prediction_id)

    inference_refs = json.loads(row["inference_refs_json"] or "[]")
    stale = tuple(ref for ref in inference_refs
                  if _safe_inference_status(db_path, str(ref), now=moment) == INFERENCE_STALE)

    status, reasons = _assess_hypothesis(
        invalidated=_is_invalidated(db_path, hypothesis_id), stale_inferences=stale,
        prediction_count=len(linked), resolved_true=resolved_true, resolved_false=resolved_false)

    basis = _digest({"hypothesis": str(row["basis_digest"]), "status": status,
                     "true": sorted(resolved_true), "false": sorted(resolved_false),
                     "unresolved": sorted(unresolved), "stale_inferences": sorted(stale),
                     "reasons": list(reasons)})
    return CausalAssessment(hypothesis_id=hypothesis_id, status=status, reason_codes=tuple(reasons),
                            linked_predictions=tuple(linked), resolved_true=tuple(resolved_true),
                            resolved_false=tuple(resolved_false), unresolved=tuple(unresolved),
                            stale_inferences=stale, basis_digest=basis)


def assert_empirically_supported(db_path: str, hypothesis_id: str, *,
                                 now: Optional[float] = None) -> str:
    """
    Refuse to treat a hypothesis as a cause unless tests actually supported it (laws 1, 3, 8).

    Even when it passes, the caller holds a SUPPORTED hypothesis - never a proven cause.
    """
    assessment = hypothesis_assessment(db_path, hypothesis_id, now=now)
    if assessment.status != HYPOTHESIS_SUPPORTED:
        raise CausalModelError("HYPOTHESIS_NOT_SUPPORTED", f"{hypothesis_id}:{assessment.status}")
    return assessment.status


def hypothesis_history(db_path: str) -> List[Dict[str, Any]]:
    """Every hypothesis ever proposed, oldest first. Nothing here is ever rewritten."""
    conn = _connect(db_path, read_only=True)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_causal_hypotheses ORDER BY created_at, hypothesis_id;")]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def causal_digest(db_path: str, *, now: Optional[float] = None) -> str:
    """The deterministic identity of the causal model (law 10)."""
    payload = []
    for row in hypothesis_history(db_path):
        hypothesis_id = str(row["hypothesis_id"])
        payload.append({"hypothesis": _row_to_hypothesis(row).as_dict(),
                        "assessment": hypothesis_assessment(db_path, hypothesis_id,
                                                            now=now).as_dict()})
    return _digest(payload)
