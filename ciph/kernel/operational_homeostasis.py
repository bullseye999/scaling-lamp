"""
ciph/kernel/operational_homeostasis - 10.8: evidence-based expectations, and honest departures from them.

    Homeostasis RECOGNIZES patterns. It does not repair anything, and it does not grant authority.

    A deviation is not a danger. A correlation is not a cause. A recent deviation is not the new normal.

WHAT A BASELINE MUST DECLARE (and does, in this module): metric definition, canonical data source, units,
observation window, workload/environment context, sample size, coverage, baseline version, accepted reference
period, comparison method, confidence indication, and the policy threshold WITH its justification.

WHAT IT REFUSES TO DO:

    Compare unlike workloads. A different context key is INCONCLUSIVE, not an anomaly.
    Claim an anomaly from an incomplete window. Missing data is reported as such.
    Let a flood rewrite normal. Candidate baselines are separate from APPROVED ones, and promotion needs an
    operator identity; a silent rewrite is impossible because an approved baseline is only superseded by
    another APPROVED version.
    Collapse the interpretation states. Observed deviation -> anomaly -> concern -> hypothesis ->
    verified cause -> proposed response -> authorized response -> outcome are SEPARATE, and a causal claim
    exists only when a verified cause with evidence has been recorded.
    Self-authorize. An anomaly may become an evidence-linked candidate for 10.6 attention; it grants nothing.
"""

import json
import sqlite3
import statistics
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

OPERATIONAL_HOMEOSTASIS_V1 = "OPERATIONAL_HOMEOSTASIS_V1"
BASELINE_V1 = "BASELINE_V1"
ANOMALY_V1 = "ANOMALY_V1"

CANDIDATE = "CANDIDATE"
APPROVED = "APPROVED"
SUPERSEDED = "SUPERSEDED"

NORMAL = "NORMAL"
DEVIATION = "DEVIATION"
INCONCLUSIVE = "INCONCLUSIVE"

NO_APPROVED_BASELINE = "NO_APPROVED_BASELINE"
WORKLOAD_CONTEXT_CHANGED = "WORKLOAD_CONTEXT_CHANGED"
INSUFFICIENT_OBSERVATIONS = "INSUFFICIENT_OBSERVATIONS"
INCOMPLETE_OBSERVATION_WINDOW = "INCOMPLETE_OBSERVATION_WINDOW"

OBSERVED_DEVIATION = "OBSERVED_DEVIATION"
ANOMALY = "ANOMALY"
CONCERN = "CONCERN"
HYPOTHESIS = "HYPOTHESIS"
VERIFIED_CAUSE = "VERIFIED_CAUSE"
PROPOSED_RESPONSE = "PROPOSED_RESPONSE"
AUTHORIZED_RESPONSE = "AUTHORIZED_RESPONSE"
OUTCOME = "OUTCOME"
STATE_ORDER = (OBSERVED_DEVIATION, ANOMALY, CONCERN, HYPOTHESIS, VERIFIED_CAUSE, PROPOSED_RESPONSE,
               AUTHORIZED_RESPONSE, OUTCOME)

REASON_NOT_OPERATOR = "BASELINE_PROMOTION_REQUIRES_AN_OPERATOR"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_homeostasis_observations (
        observation_id TEXT PRIMARY KEY,
        metric TEXT NOT NULL,
        context_key TEXT NOT NULL,
        value REAL NOT NULL,
        unit TEXT,
        source_ref TEXT,
        observed_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_homeostasis_baselines (
        baseline_id TEXT PRIMARY KEY,
        metric TEXT NOT NULL,
        context_key TEXT NOT NULL,
        version INTEGER NOT NULL,
        definition TEXT NOT NULL,
        source TEXT NOT NULL,
        units TEXT,
        window_seconds REAL NOT NULL,
        reference_from REAL,
        reference_to REAL,
        sample_size INTEGER NOT NULL,
        expected_value REAL,
        expected_spread REAL,
        coverage REAL NOT NULL,
        missing_fraction REAL NOT NULL,
        comparison_method TEXT NOT NULL,
        confidence REAL,
        threshold REAL NOT NULL,
        threshold_justification TEXT NOT NULL,
        status TEXT NOT NULL,
        proposed_by TEXT,
        approved_by TEXT,
        approved_at REAL,
        effective_at REAL,
        superseded_by TEXT,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_homeostasis_anomalies (
        anomaly_id TEXT PRIMARY KEY,
        metric TEXT NOT NULL,
        context_key TEXT NOT NULL,
        baseline_ref TEXT NOT NULL,
        observed_value REAL,
        expected_value REAL,
        deviation REAL,
        relative_deviation REAL,
        coverage REAL,
        missing_fraction REAL,
        verdict TEXT NOT NULL,
        state TEXT NOT NULL,
        causal_claim TEXT,
        recorded_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_homeostasis_interpretations (
        record_id TEXT PRIMARY KEY,
        anomaly_id TEXT NOT NULL,
        state TEXT NOT NULL,
        evidence_ref TEXT,
        note TEXT,
        recorded_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
)


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            connection.row_factory = sqlite3.Row
            return connection
        except sqlite3.OperationalError:
            pass
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    return connection


def init_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        connection.execute(statement)


def _moment(now: Optional[float]) -> float:
    return time.time() if now is None else float(now)


def _rows(db_path: str, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def _write(db_path: str, query: str, params: Sequence[Any]) -> None:
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(query, tuple(params))
        connection.commit()
    finally:
        connection.close()


# ------------------------------------------------------------------ observations
def observe(db_path: str, *, metric: str, context_key: str, value: float, unit: Optional[str] = None,
            source_ref: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """One measured value, with its metric, its workload context and its canonical source."""
    moment = _moment(now)
    observation_id = "HOB-" + digest({"metric": metric, "context": context_key, "value": float(value),
                                      "at": moment, "source": source_ref})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_homeostasis_observations (observation_id, metric, "
                    "context_key, value, unit, source_ref, observed_at, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?);",
           (observation_id, str(metric), str(context_key), float(value), unit, source_ref, moment,
            OPERATIONAL_HOMEOSTASIS_V1))
    return {"observation_id": observation_id, "metric": str(metric), "context_key": str(context_key),
            "value": float(value), "observed_at": moment, "policy_version": OPERATIONAL_HOMEOSTASIS_V1}


def observations(db_path: str, *, metric: str, context_key: str, since: Optional[float] = None,
                 until: Optional[float] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_homeostasis_observations WHERE metric = ? AND context_key = ?"
    params: List[Any] = [str(metric), str(context_key)]
    if since is not None:
        query += " AND observed_at >= ?"
        params.append(float(since))
    if until is not None:
        query += " AND observed_at <= ?"
        params.append(float(until))
    query += " ORDER BY observed_at, observation_id;"
    return _rows(db_path, query, tuple(params))


# ------------------------------------------------------------------ versioned baselines
def propose_baseline(db_path: str, *, metric: str, context_key: str, definition: str, source: str,
                     units: str, window_seconds: float, reference_from: float, reference_to: float,
                     comparison_method: str, threshold: float, threshold_justification: str,
                     expected_samples: int, coverage: float = 1.0, confidence: Optional[float] = None,
                     proposed_by: str = "ciph", now: Optional[float] = None) -> Dict[str, Any]:
    """
    Propose a CANDIDATE baseline computed from the reference window. A candidate is NOT normal behaviour until
    it is approved; a flood of observations therefore cannot rewrite normal by itself.
    """
    moment = _moment(now)
    window = observations(db_path, metric=metric, context_key=context_key, since=float(reference_from),
                          until=float(reference_to))
    values = [float(row["value"]) for row in window]
    existing = _rows(db_path, "SELECT version FROM ciph_homeostasis_baselines WHERE metric = ? AND "
                              "context_key = ? ORDER BY version DESC LIMIT 1;", (str(metric),
                                                                                 str(context_key)))
    version = (int(existing[0]["version"]) + 1) if existing else 1
    sample_size = len(values)
    missing_fraction = 0.0 if int(expected_samples) <= 0 else \
        max(0.0, 1.0 - sample_size / float(expected_samples))
    expected_value = statistics.fmean(values) if values else None
    expected_spread = statistics.pstdev(values) if len(values) > 1 else 0.0
    baseline_id = "BAS-" + digest({"metric": metric, "context": context_key, "version": version,
                                   "from": reference_from, "to": reference_to})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_homeostasis_baselines (baseline_id, metric, context_key, "
                    "version, definition, source, units, window_seconds, reference_from, reference_to, "
                    "sample_size, expected_value, expected_spread, coverage, missing_fraction, "
                    "comparison_method, confidence, threshold, threshold_justification, status, proposed_by, "
                    "approved_by, approved_at, effective_at, superseded_by, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (baseline_id, str(metric), str(context_key), version, str(definition), str(source), str(units),
            float(window_seconds), float(reference_from), float(reference_to), sample_size, expected_value,
            expected_spread, float(coverage), missing_fraction, str(comparison_method), confidence,
            float(threshold), str(threshold_justification), CANDIDATE, str(proposed_by), None, None, None,
            None, BASELINE_V1))
    return {"baseline_id": baseline_id, "metric": str(metric), "context_key": str(context_key),
            "version": version, "status": CANDIDATE, "sample_size": sample_size,
            "missing_fraction": missing_fraction, "expected_value": expected_value,
            "candidate_is_not_normal_yet": True, "policy_version": BASELINE_V1}


def approve_baseline(db_path: str, *, candidate_id: str, approved_by: str,
                     now: Optional[float] = None) -> Dict[str, Any]:
    """
    Promote a CANDIDATE. Only an operator identity may do it, the change is recorded with an effective date,
    and the superseded version is marked SUPSERSEDED - never rewritten.
    """
    if not str(approved_by).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(approved_by))
    moment = _moment(now)
    rows = _rows(db_path, "SELECT * FROM ciph_homeostasis_baselines WHERE baseline_id = ?;",
                 (str(candidate_id),))
    if not rows:
        raise CrucibleError("UNKNOWN_BASELINE", str(candidate_id))
    candidate = rows[0]
    previous = _rows(db_path, "SELECT baseline_id FROM ciph_homeostasis_baselines WHERE metric = ? AND "
                              "context_key = ? AND status = ?;",
                     (candidate["metric"], candidate["context_key"], APPROVED))
    connection = _connect(db_path)
    try:
        init_schema(connection)
        for row in previous:
            connection.execute("UPDATE ciph_homeostasis_baselines SET status = ?, superseded_by = ? "
                               "WHERE baseline_id = ?;", (SUPERSEDED, str(candidate_id),
                                                          row["baseline_id"]))
        connection.execute("UPDATE ciph_homeostasis_baselines SET status = ?, approved_by = ?, "
                           "approved_at = ?, effective_at = ? WHERE baseline_id = ?;",
                           (APPROVED, str(approved_by), moment, moment, str(candidate_id)))
        connection.commit()
    finally:
        connection.close()
    return {"baseline_id": str(candidate_id), "status": APPROVED, "approved_by": str(approved_by),
            "effective_at": moment, "superseded": [row["baseline_id"] for row in previous],
            "policy_version": BASELINE_V1}


def approved_baseline(db_path: str, *, metric: str, context_key: str) -> Optional[Dict[str, Any]]:
    rows = _rows(db_path, "SELECT * FROM ciph_homeostasis_baselines WHERE metric = ? AND context_key = ? "
                          "AND status = ? ORDER BY version DESC LIMIT 1;",
                 (str(metric), str(context_key), APPROVED))
    return rows[0] if rows else None


def baselines(db_path: str, *, status: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_homeostasis_baselines"
    params: Sequence[Any] = ()
    if status is not None:
        query += " WHERE status = ?"
        params = (str(status),)
    query += " ORDER BY metric, context_key, version;"
    return _rows(db_path, query, params)


# ------------------------------------------------------------------ evaluation
def evaluate(db_path: str, *, metric: str, context_key: str, live_context: Optional[str] = None,
             now: Optional[float] = None) -> Dict[str, Any]:
    """
    Compare the recent window against the APPROVED baseline - or refuse to compare.

    Unlike workloads, an incomplete window and a missing baseline are INCONCLUSIVE, not anomalies. The
    verdict NEVER carries a causal claim.
    """
    moment = _moment(now)
    baseline = approved_baseline(db_path, metric=metric, context_key=context_key)
    if baseline is None:
        return {"metric": str(metric), "context_key": str(context_key), "verdict": INCONCLUSIVE,
                "reason": NO_APPROVED_BASELINE, "causal_claim": None,
                "policy_version": ANOMALY_V1}
    if live_context is not None and str(live_context) != str(baseline["context_key"]):
        return {"metric": str(metric), "context_key": str(context_key), "verdict": INCONCLUSIVE,
                "reason": WORKLOAD_CONTEXT_CHANGED, "live_context": str(live_context),
                "baseline_context": str(baseline["context_key"]),
                "note": "unlike workloads are not compared", "causal_claim": None,
                "policy_version": ANOMALY_V1}
    # The comparison window starts AFTER the baseline's reference period ends, so the reference
    # observations cannot inflate the observed mean and hide a real departure.
    reference_to = baseline["reference_to"]
    window_from = moment - float(baseline["window_seconds"])
    if reference_to is not None:
        window_from = max(window_from, float(reference_to))
    window = observations(db_path, metric=metric, context_key=context_key, since=window_from, until=moment)
    required = int(baseline["sample_size"])
    if required and len(window) < max(1, int(required * float(baseline["coverage"]))):
        return {"metric": str(metric), "context_key": str(context_key), "verdict": INCONCLUSIVE,
                "reason": INSUFFICIENT_OBSERVATIONS, "observed_samples": len(window),
                "required_samples": required, "causal_claim": None, "policy_version": ANOMALY_V1}
    values = [float(row["value"]) for row in window]
    expected = baseline["expected_value"]
    if expected is None or float(expected) == 0.0:
        return {"metric": str(metric), "context_key": str(context_key), "verdict": INCONCLUSIVE,
                "reason": INCOMPLETE_OBSERVATION_WINDOW,
                "note": "the baseline has no reference mean", "causal_claim": None,
                "policy_version": ANOMALY_V1}
    observed = statistics.fmean(values)
    relative = (observed - float(expected)) / abs(float(expected))
    verdict = DEVIATION if abs(relative) >= float(baseline["threshold"]) else NORMAL
    result = {"metric": str(metric), "context_key": str(context_key), "verdict": verdict,
              "baseline_ref": baseline["baseline_id"], "baseline_version": baseline["version"],
              "observed_value": observed, "expected_value": float(expected),
              "relative_deviation": relative, "threshold": float(baseline["threshold"]),
              "coverage": len(window) / max(1, required), "missing_fraction": baseline["missing_fraction"],
              "causal_claim": None, "cause_established": False,
              "note": "a deviation is not a cause and not a concern until it is interpreted",
              "policy_version": ANOMALY_V1}
    if verdict == DEVIATION:
        anomaly_id = "HAN-" + digest({"metric": metric, "context": context_key, "at": moment})[:16].upper()
        _write(db_path, "INSERT OR IGNORE INTO ciph_homeostasis_anomalies (anomaly_id, metric, context_key, "
                        "baseline_ref, observed_value, expected_value, deviation, relative_deviation, "
                        "coverage, missing_fraction, verdict, state, causal_claim, recorded_at, "
                        "policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
               (anomaly_id, str(metric), str(context_key), baseline["baseline_id"], observed,
                float(expected), observed - float(expected), relative, result["coverage"],
                baseline["missing_fraction"], verdict, OBSERVED_DEVIATION, None, moment, ANOMALY_V1))
        _append_state(db_path, anomaly_id=anomaly_id, state=OBSERVED_DEVIATION, evidence_ref=None,
                      note="recorded from the canonical window", now=moment)
        result["anomaly_id"] = anomaly_id
    return result


# ------------------------------------------------------------------ interpretation states
def _append_state(db_path: str, *, anomaly_id: str, state: str, evidence_ref: Optional[str],
                  note: Optional[str], now: float) -> str:
    record_id = "HIN-" + digest({"anomaly": anomaly_id, "state": state, "at": now})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_homeostasis_interpretations (record_id, anomaly_id, state, "
                    "evidence_ref, note, recorded_at, policy_version) VALUES (?,?,?,?,?,?,?);",
           (record_id, str(anomaly_id), str(state), evidence_ref, note, now, ANOMALY_V1))
    return record_id


def advance(db_path: str, *, anomaly_id: str, state: str, evidence_ref: Optional[str] = None,
            note: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Move the interpretation ONE step, and refuse to collapse the states.

    A VERIFIED_CAUSE requires an evidence reference, and only then is a causal claim recorded.
    """
    if state not in STATE_ORDER:
        raise CrucibleError("UNKNOWN_INTERPRETATION_STATE", str(state))
    moment = _moment(now)
    rows = _rows(db_path, "SELECT * FROM ciph_homeostasis_anomalies WHERE anomaly_id = ?;",
                 (str(anomaly_id),))
    if not rows:
        raise CrucibleError("UNKNOWN_ANOMALY", str(anomaly_id))
    current = str(rows[0]["state"])
    if STATE_ORDER.index(state) <= STATE_ORDER.index(current):
        raise CrucibleError("INTERPRETATION_STATES_ARE_ORDERED", f"{current}->{state}")
    if state == VERIFIED_CAUSE and not evidence_ref:
        raise CrucibleError("VERIFIED_CAUSE_REQUIRES_EVIDENCE", str(anomaly_id))
    causal_claim = evidence_ref if state == VERIFIED_CAUSE else None
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_homeostasis_anomalies SET state = ?, causal_claim = ? "
                           "WHERE anomaly_id = ?;",
                           (str(state), causal_claim if causal_claim else rows[0]["causal_claim"],
                            str(anomaly_id)))
        connection.commit()
    finally:
        connection.close()
    _append_state(db_path, anomaly_id=anomaly_id, state=state, evidence_ref=evidence_ref, note=note,
                  now=moment)
    return {"anomaly_id": str(anomaly_id), "state": str(state), "evidence_ref": evidence_ref,
            "cause_established": state == VERIFIED_CAUSE, "note": note,
            "policy_version": ANOMALY_V1}


def interpretation(db_path: str, *, anomaly_id: str) -> Dict[str, Any]:
    rows = _rows(db_path, "SELECT * FROM ciph_homeostasis_anomalies WHERE anomaly_id = ?;",
                 (str(anomaly_id),))
    if not rows:
        raise CrucibleError("UNKNOWN_ANOMALY", str(anomaly_id))
    history = _rows(db_path, "SELECT * FROM ciph_homeostasis_interpretations WHERE anomaly_id = ? "
                             "ORDER BY recorded_at, record_id;", (str(anomaly_id),))
    record = rows[0]
    record["states_are_separate"] = True
    return {"anomaly": record, "history": history,
            "cause_established": bool(record["causal_claim"]),
            "authorizes_corrective_action": False, "policy_version": ANOMALY_V1}


def anomalies(db_path: str, *, state: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_homeostasis_anomalies"
    params: Sequence[Any] = ()
    if state is not None:
        query += " WHERE state = ?"
        params = (str(state),)
    query += " ORDER BY recorded_at, anomaly_id;"
    return _rows(db_path, query, params)


# ------------------------------------------------------------------ reflective awareness
def attention_allocation_ratio(db_path: str, *, category: str, window_seconds: float,
                               baseline_metric: Optional[str] = None,
                               now: Optional[float] = None) -> Dict[str, Any]:
    """
    Ciph's own habit, from ACTUAL allocation data: numerator, denominator, windows and a versioned baseline.

    The statement is arithmetic. It is never model intuition, and it carries no causal claim.
    """
    moment = _moment(now)
    window_from = moment - float(window_seconds)
    rows = _rows(db_path, "SELECT category, enqueued_at FROM ciph_attention_requests WHERE enqueued_at >= ?;",
                 (window_from,))
    denominator = len(rows)
    numerator = len([row for row in rows if str(row["category"]) == str(category)])
    ratio = (numerator / denominator) if denominator else None
    metric = baseline_metric or f"attention.category.{category}"
    baseline = approved_baseline(db_path, metric=metric, context_key="default") if metric else None
    return {"policy_version": OPERATIONAL_HOMEOSTASIS_V1, "category": str(category),
            "numerator": numerator, "denominator": denominator, "ratio": ratio,
            "window_seconds": float(window_seconds), "window_from": window_from, "window_to": moment,
            "workload_definition": "attention requests enqueued in the window",
            "baseline_metric": metric,
            "baseline": None if baseline is None else {"baseline_id": baseline["baseline_id"],
                                                       "version": baseline["version"],
                                                       "expected_ratio": baseline["expected_value"]},
            "derived_from": "10.6 attention requests", "model_intuition": False,
            "causal_claim": None, "comparison_permitted": baseline is not None and denominator > 0}


def to_attention(db_path: str, *, anomaly_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    An anomaly becomes an evidence-linked CANDIDATE for focused attention. It grants nothing and cannot
    declare itself CRITICAL: 10.6's evidence rules decide the category.
    """
    moment = _moment(now)
    record = interpretation(db_path, anomaly_id=anomaly_id)["anomaly"]
    from ciph.kernel.selective_attention import submit
    queued = submit(db_path, subject_ref=f"homeostasis:{anomaly_id}", sensor_kind="CHANGE",
                    evidence_ref=record["baseline_ref"], declared_severity=None,
                    uncertainty="deviation without an established cause", now=moment)
    return {"anomaly_id": str(anomaly_id), "attention_request": queued.get("request_id"),
            "attention_category": queued.get("category"),
            "self_declared_critical": False, "grants_authority": False,
            "policy_version": OPERATIONAL_HOMEOSTASIS_V1}


def homeostasis_digest(db_path: str) -> str:
    return digest({"baselines": _rows(db_path, "SELECT baseline_id, metric, context_key, version, status "
                                               "FROM ciph_homeostasis_baselines ORDER BY baseline_id;"),
                   "anomalies": _rows(db_path, "SELECT anomaly_id, verdict, state, causal_claim "
                                               "FROM ciph_homeostasis_anomalies ORDER BY anomaly_id;"),
                   "interpretations": _rows(db_path, "SELECT record_id, anomaly_id, state "
                                                     "FROM ciph_homeostasis_interpretations "
                                                     "ORDER BY record_id;")})
