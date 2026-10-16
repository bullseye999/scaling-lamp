"""
ciph.kernel.predictions - what Ciph expected, how sure it was BEFORE seeing the answer, and whether it
was right.

4.2 Gate Three, V1: BINARY ONLY. No numeric forecasting, no distributions, no markets. The gate exists
to make confidence ACCOUNTABLE, and a binary prediction with a frozen probability is enough to do that.

    PredictionRecord      a forecast, bound to the epistemic state that existed when it was issued
    PredictionResolution  an immutable resolution, from canonical admissible evidence only

Two anti-cheat properties are structural:

  * PROBABILITY IS FROZEN AT ISSUANCE. Later beliefs do not rewrite it, so a lucky later state cannot
    turn a 0.8 forecast into a 0.95 one.
  * THE FINGERPRINT IS CANONICAL. Issuing the same forecast fifty times yields ONE prediction, so
    calibration statistics cannot be inflated by repetition.

LAWS (each has a specimen in `test_gate_4_2_predictions_calibration.py`)

 1. Prediction probability is immutable after issuance.
 2. A prediction binds to the epistemic state that existed when it was issued.
 3. Future belief changes do not rewrite the old prediction.
 4. Model output cannot resolve its own prediction.
 5. Resolution uses canonical admissible evidence only.
 6. UNRESOLVED is not FALSE.
 7. Missing resolution evidence never becomes failure automatically.
 8. Predictions cannot be backdated (nor resolved before their resolution window opens).
 9. Duplicate forecasts cannot inflate calibration statistics.
10. Prediction resolution is append-only.
11. Calibration uses only RESOLVED predictions.
12. Same prediction/resolution history -> same calibration projection after restart.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.epistemic_ledger import Proposition, reconstruct as reconstruct_beliefs
from ciph.kernel.source_dependence import project_source_dependence

PREDICTION_CALIBRATION_V1 = "PREDICTION_CALIBRATION_V1"

STATUS_OPEN = "OPEN"
STATUS_RESOLVED = "RESOLVED"
STATUS_EXPIRED_UNRESOLVED = "EXPIRED_UNRESOLVED"
STATUS_INVALIDATED = "INVALIDATED"

OUTCOME_TRUE = "TRUE"
OUTCOME_FALSE = "FALSE"
OUTCOME_UNRESOLVED = "UNRESOLVED"
VALID_OUTCOMES = (OUTCOME_TRUE, OUTCOME_FALSE, OUTCOME_UNRESOLVED)

# The fixed reliability bins, so binning cannot become a tunable authority.
RELIABILITY_BINS = tuple((round(i / 10, 1), round((i + 1) / 10, 1)) for i in range(10))

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_predictions (
        prediction_id TEXT PRIMARY KEY,
        prediction_fingerprint TEXT NOT NULL UNIQUE,
        predictor_id TEXT NOT NULL,
        proposition_id TEXT NOT NULL,
        probability REAL NOT NULL,
        epistemic_basis_digest TEXT NOT NULL,
        belief_projection_ref TEXT,
        source_dependence_ref TEXT,
        resolution_rule_id TEXT NOT NULL,
        window_key TEXT NOT NULL,
        issued_at REAL NOT NULL,
        resolution_not_before REAL,
        resolution_deadline REAL NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_prediction_resolutions (
        resolution_id TEXT PRIMARY KEY,
        prediction_id TEXT NOT NULL,
        outcome TEXT NOT NULL,
        evidence_refs_json TEXT,
        resolved_at REAL NOT NULL,
        resolution_digest TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_prediction_invalidations (
        invalidation_id TEXT PRIMARY KEY,
        prediction_id TEXT NOT NULL,
        reason TEXT,
        recorded_at REAL
    );
    """,
)


class PredictionError(Exception):
    """A prediction operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class PredictionRecord:
    prediction_id: str
    prediction_fingerprint: str
    predictor_id: str
    proposition_id: str
    probability: float
    epistemic_basis_digest: str
    belief_projection_ref: Optional[str]
    source_dependence_ref: Optional[str]
    resolution_rule_id: str
    issued_at: float
    resolution_not_before: Optional[float]
    resolution_deadline: float
    status: str
    outcome: Optional[str] = None
    created: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {"prediction_id": self.prediction_id,
                "prediction_fingerprint": self.prediction_fingerprint,
                "predictor_id": self.predictor_id, "proposition_id": self.proposition_id,
                "probability": round(self.probability, 12),
                "epistemic_basis_digest": self.epistemic_basis_digest,
                "belief_projection_ref": self.belief_projection_ref,
                "source_dependence_ref": self.source_dependence_ref,
                "resolution_rule_id": self.resolution_rule_id,
                "issued_at": self.issued_at,
                "resolution_not_before": self.resolution_not_before,
                "resolution_deadline": self.resolution_deadline,
                "status": self.status, "outcome": self.outcome}


@dataclass(frozen=True)
class PredictionResolution:
    resolution_id: str
    prediction_id: str
    outcome: str
    evidence_refs: Tuple[str, ...]
    resolved_at: float
    resolution_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"resolution_id": self.resolution_id, "prediction_id": self.prediction_id,
                "outcome": self.outcome, "evidence_refs": list(self.evidence_refs),
                "resolved_at": self.resolved_at, "resolution_digest": self.resolution_digest}


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


# ---------------------------------------------------------------------------- issuance
def issue_prediction(db_path: str, *, predictor_id: str, proposition: Proposition,
                     probability: float, resolution_deadline: float,
                     resolution_rule_id: str, resolution_not_before: Optional[float] = None,
                     window_key: Optional[str] = None, now: Optional[float] = None) -> PredictionRecord:
    """
    Issue ONE binary prediction, bound to the epistemic state right now.

    The fingerprint is canonical: the same predictor making the same forecast on the same basis over
    the same window and rule is ONE prediction, however many times it is issued (law 9).
    """
    moment = time.time() if now is None else float(now)
    if not (0.0 <= float(probability) <= 1.0):
        raise PredictionError("PROBABILITY_OUT_OF_RANGE", str(probability))
    if resolution_deadline <= moment:
        raise PredictionError("RESOLUTION_DEADLINE_IN_THE_PAST", str(resolution_deadline))
    if resolution_not_before is not None and resolution_not_before < moment:
        raise PredictionError("RESOLUTION_WINDOW_STARTS_IN_THE_PAST", str(resolution_not_before))

    belief = reconstruct_beliefs(db_path, now=moment).belief_for(proposition.proposition_id)
    dependence = project_source_dependence(db_path, proposition.proposition_id, now=moment)
    basis_digest = _digest({
        "belief": belief.derivation_digest if belief else None,
        "provenance": dependence.provenance_digest,
        "metric": dependence.metric_id,
    })
    window = window_key or f"{resolution_not_before or moment}:{resolution_deadline}"
    fingerprint = _digest({"predictor": predictor_id, "proposition": proposition.proposition_id,
                           "basis": basis_digest, "window": window, "rule": resolution_rule_id})

    conn = _connect(db_path)
    try:
        init_schema(conn)
        existing = conn.execute("SELECT * FROM ciph_predictions WHERE prediction_fingerprint = ?;",
                                (fingerprint,)).fetchone()
        if existing is not None:
            # The SAME forecast: canonical, not a new scoring opportunity.
            return _record_from_row(db_path, dict(existing), now=moment, created=False,
                                    belief_ref=belief.derivation_digest if belief else None)
        prediction_id = f"PRD-{uuid.uuid4().hex[:12].upper()}"
        conn.execute(
            "INSERT INTO ciph_predictions (prediction_id, prediction_fingerprint, predictor_id, "
            "proposition_id, probability, epistemic_basis_digest, belief_projection_ref, "
            "source_dependence_ref, resolution_rule_id, window_key, issued_at, resolution_not_before, "
            "resolution_deadline) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (prediction_id, fingerprint, predictor_id, proposition.proposition_id, float(probability),
             basis_digest, belief.derivation_digest if belief else None,
             dependence.provenance_digest, resolution_rule_id, window, moment, resolution_not_before,
             resolution_deadline),
        )
        conn.commit()
        return PredictionRecord(
            prediction_id=prediction_id, prediction_fingerprint=fingerprint,
            predictor_id=predictor_id, proposition_id=proposition.proposition_id,
            probability=float(probability), epistemic_basis_digest=basis_digest,
            belief_projection_ref=belief.derivation_digest if belief else None,
            source_dependence_ref=dependence.provenance_digest,
            resolution_rule_id=resolution_rule_id, issued_at=moment,
            resolution_not_before=resolution_not_before, resolution_deadline=resolution_deadline,
            status=STATUS_OPEN, created=True)
    finally:
        conn.close()


def _resolution_for(conn: sqlite3.Connection, prediction_id: str) -> Optional[Dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM ciph_prediction_resolutions WHERE prediction_id = ? ORDER BY resolved_at LIMIT 1;",
        (prediction_id,)).fetchone()
    return dict(row) if row else None


def _invalidated(conn: sqlite3.Connection, prediction_id: str) -> bool:
    try:
        return conn.execute("SELECT 1 FROM ciph_prediction_invalidations WHERE prediction_id = ? LIMIT 1;",
                            (prediction_id,)).fetchone() is not None
    except sqlite3.Error:
        return False


def prediction_status(db_path: str, prediction_id: str, *, now: Optional[float] = None) -> str:
    """
    Derive the status. An overdue prediction with no resolution is EXPIRED_UNRESOLVED - never FALSE
    (laws 6 and 7): the deadline passing is not evidence about the world.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute("SELECT * FROM ciph_predictions WHERE prediction_id = ?;",
                           (prediction_id,)).fetchone()
        if row is None:
            raise PredictionError("UNKNOWN_PREDICTION", prediction_id)
        # An invalidation is an explicit statement that the prediction is void, so it wins - and it
        # can only exist while the prediction was still open, so it can never erase a known outcome.
        if _invalidated(conn, prediction_id):
            return STATUS_INVALIDATED
        resolution = _resolution_for(conn, prediction_id)
        if resolution is not None:
            return STATUS_RESOLVED if resolution["outcome"] != OUTCOME_UNRESOLVED \
                else STATUS_EXPIRED_UNRESOLVED
        if moment > float(row["resolution_deadline"]):
            return STATUS_EXPIRED_UNRESOLVED
        return STATUS_OPEN
    finally:
        conn.close()


def _record_from_row(db_path: str, row: Mapping[str, Any], *, now: Optional[float],
                     created: bool = False, belief_ref: Optional[str] = None) -> PredictionRecord:
    status = prediction_status(db_path, str(row["prediction_id"]), now=now)
    conn = _connect(db_path, read_only=True)
    try:
        resolution = _resolution_for(conn, str(row["prediction_id"]))
    finally:
        conn.close()
    return PredictionRecord(
        prediction_id=str(row["prediction_id"]),
        prediction_fingerprint=str(row["prediction_fingerprint"]),
        predictor_id=str(row["predictor_id"]), proposition_id=str(row["proposition_id"]),
        probability=float(row["probability"]),
        epistemic_basis_digest=str(row["epistemic_basis_digest"]),
        belief_projection_ref=belief_ref if belief_ref is not None else row["belief_projection_ref"],
        source_dependence_ref=row["source_dependence_ref"],
        resolution_rule_id=str(row["resolution_rule_id"]), issued_at=float(row["issued_at"]),
        resolution_not_before=row["resolution_not_before"],
        resolution_deadline=float(row["resolution_deadline"]),
        status=status, outcome=(resolution["outcome"] if resolution else None), created=created)


def get_prediction(db_path: str, prediction_id: str, *, now: Optional[float] = None) -> PredictionRecord:
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute("SELECT * FROM ciph_predictions WHERE prediction_id = ?;",
                           (prediction_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise PredictionError("UNKNOWN_PREDICTION", prediction_id)
    return _record_from_row(db_path, dict(row), now=now)


# ---------------------------------------------------------------------------- resolution
def resolve_prediction(db_path: str, prediction_id: str, *, outcome: str,
                       evidence_refs: Sequence[str] = (), now: Optional[float] = None,
                       note: Optional[str] = None) -> PredictionResolution:
    """
    Resolve a prediction from CANONICAL ADMISSIBLE EVIDENCE, or leave it UNRESOLVED.

    TRUE requires supporting evidence that exists in Gate Zero for this proposition; FALSE requires
    contradicting evidence. A model's assertion is not evidence, so it can never resolve anything
    (law 4) - and UNRESOLVED asserts nothing, so it needs no evidence and is never counted as wrong.
    """
    if outcome not in VALID_OUTCOMES:
        raise PredictionError("INVALID_OUTCOME", str(outcome))
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        row = conn.execute("SELECT * FROM ciph_predictions WHERE prediction_id = ?;",
                           (prediction_id,)).fetchone()
        if row is None:
            raise PredictionError("UNKNOWN_PREDICTION", prediction_id)
        existing = _resolution_for(conn, prediction_id)
        if existing is not None:
            if existing["outcome"] == outcome:
                return PredictionResolution(
                    resolution_id=str(existing["resolution_id"]), prediction_id=prediction_id,
                    outcome=str(existing["outcome"]),
                    evidence_refs=tuple(json.loads(existing["evidence_refs_json"] or "[]")),
                    resolved_at=float(existing["resolved_at"]),
                    resolution_digest=str(existing["resolution_digest"]))
            raise PredictionError("PREDICTION_ALREADY_RESOLVED", f"{existing['outcome']}!={outcome}")

        not_before = row["resolution_not_before"]
        if not_before is not None and moment < float(not_before):
            raise PredictionError("RESOLUTION_TOO_EARLY",
                                  f"window opens at {not_before}, now {moment}")
        if moment < float(row["issued_at"]):
            raise PredictionError("RESOLUTION_BACKDATED", str(moment))

        proposition_id = str(row["proposition_id"])
        refs = [str(r) for r in evidence_refs]
        if outcome in (OUTCOME_TRUE, OUTCOME_FALSE):
            if not refs:
                raise PredictionError("RESOLUTION_REQUIRES_CANONICAL_EVIDENCE", proposition_id)
            expected = "SUPPORTS" if outcome == OUTCOME_TRUE else "CONTRADICTS"
            with sqlite3.connect(db_path) as witness:
                found = {str(r[0]): str(r[1]) for r in witness.execute(
                    "SELECT evidence_id, relation FROM ciph_evidence WHERE proposition_id = ?;",
                    (proposition_id,))}
            for ref in refs:
                if ref not in found:
                    raise PredictionError("RESOLUTION_EVIDENCE_NOT_CANONICAL", ref)
                if found[ref] != expected:
                    raise PredictionError("RESOLUTION_EVIDENCE_MISMATCH",
                                          f"{ref}:{found[ref]}!={expected}")

        digest = _digest({"prediction_id": prediction_id, "outcome": outcome, "evidence": sorted(refs)})
        resolution_id = f"RSL-{uuid.uuid4().hex[:12].upper()}"
        conn.execute(
            "INSERT INTO ciph_prediction_resolutions (resolution_id, prediction_id, outcome, "
            "evidence_refs_json, resolved_at, resolution_digest) VALUES (?,?,?,?,?,?);",
            (resolution_id, prediction_id, outcome, json.dumps(sorted(refs)), moment, digest),
        )
        conn.commit()
        return PredictionResolution(resolution_id=resolution_id, prediction_id=prediction_id,
                                    outcome=outcome, evidence_refs=tuple(sorted(refs)),
                                    resolved_at=moment, resolution_digest=digest)
    finally:
        conn.close()


def invalidate_prediction(db_path: str, prediction_id: str, *, reason: str = "",
                          now: Optional[float] = None) -> str:
    """
    Void a prediction that has NOT been resolved (law 10: nothing is edited, an append is added).

    Refused once a resolution exists, deliberately: letting a prediction be invalidated after its
    outcome is known would let hindsight remove an inconvenient data point from calibration. If a
    forecast must be excluded, it has to be excluded while it is still open.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        if conn.execute("SELECT 1 FROM ciph_predictions WHERE prediction_id = ?;",
                        (prediction_id,)).fetchone() is None:
            raise PredictionError("UNKNOWN_PREDICTION", prediction_id)
        if _resolution_for(conn, prediction_id) is not None:
            raise PredictionError("CANNOT_INVALIDATE_RESOLVED_PREDICTION", prediction_id)
        invalidation_id = f"PIN-{uuid.uuid4().hex[:12].upper()}"
        conn.execute("INSERT INTO ciph_prediction_invalidations (invalidation_id, prediction_id, "
                     "reason, recorded_at) VALUES (?,?,?,?);",
                     (invalidation_id, prediction_id, reason, moment))
        conn.commit()
        return invalidation_id
    finally:
        conn.close()


# ---------------------------------------------------------------------------- calibration
def calibrate(db_path: str, *, predictor_id: Optional[str] = None,
              now: Optional[float] = None) -> Dict[str, Any]:
    """
    The frozen V1 calibration projection: Brier over RESOLVED predictions only (law 11).

    UNRESOLVED and EXPIRED_UNRESOLVED are counted and excluded, never scored as wrong (laws 6 and 7).
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path, read_only=True)
    try:
        query = "SELECT * FROM ciph_predictions"
        params: Tuple[Any, ...] = ()
        if predictor_id is not None:
            query += " WHERE predictor_id = ?"
            params = (predictor_id,)
        rows = [dict(r) for r in conn.execute(query + " ORDER BY prediction_id;", params)]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()

    scored: List[Dict[str, Any]] = []
    unresolved = 0
    invalidated = 0
    open_count = 0
    for row in rows:
        record = _record_from_row(db_path, row, now=moment)
        if record.status == STATUS_RESOLVED and record.outcome in (OUTCOME_TRUE, OUTCOME_FALSE):
            y = 1.0 if record.outcome == OUTCOME_TRUE else 0.0
            scored.append({"prediction_id": record.prediction_id, "probability": record.probability,
                           "outcome": record.outcome, "y": y,
                           "brier": (record.probability - y) ** 2})
        elif record.status == STATUS_EXPIRED_UNRESOLVED:
            unresolved += 1
        elif record.status == STATUS_INVALIDATED:
            invalidated += 1
        else:
            open_count += 1

    resolved_count = len(scored)
    brier = round(sum(s["brier"] for s in scored) / resolved_count, 12) if resolved_count else None
    mean_probability = (round(sum(s["probability"] for s in scored) / resolved_count, 12)
                        if resolved_count else None)
    observed_frequency = (round(sum(s["y"] for s in scored) / resolved_count, 12)
                          if resolved_count else None)

    bins = []
    for low, high in RELIABILITY_BINS:
        in_bin = [s for s in scored if low <= s["probability"] < high or (high == 1.0 and s["probability"] == 1.0)]
        if not in_bin:
            continue
        bins.append({"low": low, "high": high, "count": len(in_bin),
                     "mean_probability": round(sum(s["probability"] for s in in_bin) / len(in_bin), 12),
                     "observed_frequency": round(sum(s["y"] for s in in_bin) / len(in_bin), 12)})

    payload = {"metric_id": PREDICTION_CALIBRATION_V1, "predictor_id": predictor_id,
               "resolved_count": resolved_count, "unresolved_count": unresolved,
               "invalidated_count": invalidated, "open_count": open_count,
               "mean_probability": mean_probability, "observed_frequency": observed_frequency,
               "brier_score": brier, "bins": bins,
               "predictions": [s["prediction_id"] for s in scored]}
    payload["calibration_digest"] = _digest(payload)
    return payload


def prediction_history(db_path: str, proposition_id: Optional[str] = None) -> Tuple[PredictionRecord, ...]:
    conn = _connect(db_path, read_only=True)
    try:
        if proposition_id is None:
            rows = [dict(r) for r in conn.execute("SELECT * FROM ciph_predictions ORDER BY prediction_id;")]
        else:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM ciph_predictions WHERE proposition_id = ? ORDER BY prediction_id;",
                (proposition_id,))]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return tuple(_record_from_row(db_path, row, now=None) for row in rows)


def resolution_history(db_path: str, prediction_id: str) -> Tuple[PredictionResolution, ...]:
    conn = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_prediction_resolutions WHERE prediction_id = ? ORDER BY resolved_at;",
            (prediction_id,))]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return tuple(PredictionResolution(
        resolution_id=str(r["resolution_id"]), prediction_id=str(r["prediction_id"]),
        outcome=str(r["outcome"]), evidence_refs=tuple(json.loads(r["evidence_refs_json"] or "[]")),
        resolved_at=float(r["resolved_at"]), resolution_digest=str(r["resolution_digest"]))
        for r in rows)
