"""
ciph.kernel.curiosity_learning - did an investigation actually REDUCE uncertainty?

4.4 Gate Four. The result is DERIVED by comparing immutable before/after canonical projections. The
model does not score its own success, and it cannot reward itself for producing more questions.

    before: canonical state when the investigation started (immutable reference)
    after:  canonical state when it closed            (immutable reference)
    result: RESOLVED | REDUCED | UNCHANGED | WORSENED | INCONCLUSIVE
    information_gain: how much CANONICAL state actually moved

LAWS (each has a specimen in `test_gate_4_4_curiosity_learning.py`)

 1. Curiosity success is measured by canonical state change, not by whether the result "interesting".
 2. An investigation can succeed operationally yet yield zero information.
 3. An investigation can fail operationally and remain epistemically inconclusive.
 4. Model commentary cannot mark an investigation RESOLVED.
 5. The before-state and after-state are immutable references.
 6. Information gain cannot be retroactively rewritten.
 7. Repeated low-value investigation lowers future priority (see `outcome_penalty`).
 8. Curiosity cannot reward itself for generating more uncertainty.
 9. Closing one uncertainty may expose another, but that new uncertainty enters Gate Zero on its own.
10. Same before/after canonical history -> same outcome digest.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.causal_model import hypothesis_assessment
from ciph.kernel.epistemic_convergence import (
    STATUS_CONVERGED_REFUTED,
    STATUS_CONVERGED_SUPPORTED,
    project_convergence,
)
from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs
from ciph.kernel.predictions import calibrate
from ciph.kernel.self_model import project_capability
from ciph.kernel.source_dependence import project_source_dependence
from ciph.kernel.uncertainty_registry import (
    KIND_CALIBRATION_WEAKNESS,
    KIND_DYNAMICS_GAP,
    KIND_EPISTEMIC_CONTESTED,
    KIND_EPISTEMIC_UNRESOLVED,
    KIND_SELF_MODEL_UNKNOWN,
    KIND_WEAK_CAUSAL_HYPOTHESIS,
    uncertainty,
)

CURIOSITY_INFORMATION_GAIN_V1 = "CURIOSITY_INFORMATION_GAIN_V1"

RESULT_RESOLVED = "RESOLVED"
RESULT_REDUCED = "REDUCED"
RESULT_UNCHANGED = "UNCHANGED"
RESULT_WORSENED = "WORSENED"
RESULT_INCONCLUSIVE = "INCONCLUSIVE"
VALID_RESULTS = (RESULT_RESOLVED, RESULT_REDUCED, RESULT_UNCHANGED, RESULT_WORSENED,
                 RESULT_INCONCLUSIVE)

# What the MACHINERY did, kept separate from what the EPISTEMICS did (laws 2 and 3). An operation
# that failed before producing admissible evidence is INCONCLUSIVE, never a worse epistemic picture.
OPERATIONAL_COMPLETED = "COMPLETED"
OPERATIONAL_FAILED = "FAILED"
OPERATIONAL_NOT_ATTEMPTED = "NOT_ATTEMPTED"
VALID_OPERATIONAL_STATUSES = (OPERATIONAL_COMPLETED, OPERATIONAL_FAILED,
                              OPERATIONAL_NOT_ATTEMPTED)

# The FROZEN barren-investigation penalty: each closed investigation that moved no canonical state
# costs future priority for the SAME uncertainty (law 7). It is a small, fixed number rather than a
# learned weight, so "curiosity about its own curiosity" cannot drift.
BARREN_OUTCOME_PENALTY = 0.5
BARREN_RESULTS = (RESULT_UNCHANGED, RESULT_INCONCLUSIVE)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_curiosity_investigations (
        outcome_id TEXT PRIMARY KEY,
        uncertainty_id TEXT NOT NULL,
        proposal_id TEXT,
        investigation_ref TEXT,
        before_basis_digest TEXT NOT NULL,
        before_state_json TEXT NOT NULL,
        started_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_curiosity_outcomes (
        outcome_id TEXT PRIMARY KEY,
        after_basis_digest TEXT NOT NULL,
        after_state_json TEXT NOT NULL,
        result TEXT NOT NULL,
        information_gain INTEGER NOT NULL,
        reason_code TEXT NOT NULL,
        operational_status TEXT,
        cost_actual REAL,
        risk_actual REAL,
        outcome_digest TEXT NOT NULL,
        closed_at REAL
    );
    """,
)


class CuriosityLearningError(Exception):
    """A curiosity-learning operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class CuriosityOutcome:
    outcome_id: str
    uncertainty_id: str
    proposal_id: Optional[str]
    investigation_ref: Optional[str]
    before_basis_digest: str
    before_state: Dict[str, Any]
    after_basis_digest: Optional[str]
    after_state: Optional[Dict[str, Any]]
    result: Optional[str]
    information_gain: Optional[int]
    reason_code: Optional[str]
    operational_status: Optional[str] = None
    closed_at: Optional[float] = None
    outcome_digest: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"outcome_id": self.outcome_id, "uncertainty_id": self.uncertainty_id,
                "proposal_id": self.proposal_id, "investigation_ref": self.investigation_ref,
                "before_basis_digest": self.before_basis_digest, "before_state": self.before_state,
                "after_basis_digest": self.after_basis_digest, "after_state": self.after_state,
                "result": self.result, "information_gain": self.information_gain,
                "reason_code": self.reason_code, "operational_status": self.operational_status,
                "outcome_digest": self.outcome_digest}

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


def curiosity_state_probe(db_path: str, uncertainty_id: str, *,
                          now: Optional[float] = None) -> Dict[str, Any]:
    """
    The canonical measurement of ONE uncertainty. Everything here is read from 4.2/4.3 state, so the
    same history always produces the same probe (law 10).
    """
    moment = time.time() if now is None else float(now)
    record = uncertainty(db_path, uncertainty_id, now=moment)
    probe: Dict[str, Any] = {
        "present": record is not None,
        "source_kind": record.source_kind if record is not None else None,
        "source_ref": record.source_ref if record is not None else None,
        "reducibility": record.reducibility if record is not None else None,
        "evidence_count": reconstruct_beliefs(db_path, now=moment).evidence_count,
        "convergence_status": None,
        "support_interval_width": None,
        "contradict_interval_width": None,
        "hypothesis_status": None,
        "claim_level": None,
        "calibration_digest": None,
        "transition_digest": None,
    }
    if record is None:
        return probe
    if record.source_kind in (KIND_EPISTEMIC_UNRESOLVED, KIND_EPISTEMIC_CONTESTED):
        dependence = project_source_dependence(db_path, record.source_ref, now=moment)
        convergence = project_convergence(db_path, record.source_ref, now=moment)
        probe["convergence_status"] = convergence.status
        probe["support_interval_width"] = (dependence.independent_support_max
                                           - dependence.independent_support_min)
        probe["contradict_interval_width"] = (dependence.independent_contradict_max
                                              - dependence.independent_contradict_min)
    elif record.source_kind == KIND_WEAK_CAUSAL_HYPOTHESIS:
        probe["hypothesis_status"] = hypothesis_assessment(db_path, record.source_ref,
                                                           now=moment).status
    elif record.source_kind == KIND_SELF_MODEL_UNKNOWN:
        probe["claim_level"] = project_capability(db_path, capability_id=record.source_ref,
                                                  now=moment).claim_level
    elif record.source_kind == KIND_CALIBRATION_WEAKNESS:
        probe["calibration_digest"] = str(calibrate(db_path, now=moment)["calibration_digest"])
    elif record.source_kind == KIND_DYNAMICS_GAP:
        probe["transition_digest"] = record.basis_digest
    return probe


def _narrowed(before: Dict[str, Any], after: Dict[str, Any]) -> bool:
    for key in ("support_interval_width", "contradict_interval_width"):
        if before[key] is not None and after[key] is not None and after[key] < before[key]:
            return True
    return False


def _widened(before: Dict[str, Any], after: Dict[str, Any]) -> bool:
    for key in ("support_interval_width", "contradict_interval_width"):
        if before[key] is not None and after[key] is not None and after[key] > before[key]:
            return True
    return False


def information_gain(before: Dict[str, Any], after: Dict[str, Any]) -> int:
    """
    How much CANONICAL state moved. Model prose cannot move any of these terms, which is exactly why
    ten generated questions score zero (laws 1 and 8).
    """
    gain = max(0, int(after["evidence_count"]) - int(before["evidence_count"]))
    for key in ("convergence_status", "hypothesis_status", "claim_level", "calibration_digest"):
        if after[key] is not None and before[key] != after[key]:
            gain += 1
    return gain


def derive_result(before: Dict[str, Any], after: Dict[str, Any], *, attempted: bool,
                  operational_status: str = OPERATIONAL_COMPLETED) -> Tuple[str, str]:
    """THE frozen result function. Nothing about the model's opinion enters it."""
    if before["present"] and not after["present"]:
        return RESULT_RESOLVED, "UNCERTAINTY_CLOSED"
    if before["convergence_status"] != after["convergence_status"] and after[
            "convergence_status"] in (STATUS_CONVERGED_SUPPORTED, STATUS_CONVERGED_REFUTED):
        return RESULT_RESOLVED, "CONVERGENCE_REACHED"
    if information_gain(before, after) > 0 or _narrowed(before, after):
        return RESULT_REDUCED, "CANONICAL_STATE_MOVED"
    if _widened(before, after):
        return RESULT_WORSENED, "SUPPORT_INTERVAL_WIDENED"
    if attempted and operational_status == OPERATIONAL_COMPLETED:
        return RESULT_UNCHANGED, "NO_CANONICAL_MOVEMENT"
    # A failed or never-attempted operation taught nothing. It is not evidence of anything, and it is
    # emphatically not WORSENED - the epistemic picture is simply unmoved (law 3).
    return RESULT_INCONCLUSIVE, f"OPERATION_{operational_status}"


def begin_investigation(db_path: str, *, uncertainty_id: str, proposal_id: Optional[str] = None,
                        investigation_ref: Optional[str] = None,
                        now: Optional[float] = None) -> str:
    """
    Freeze the BEFORE state (law 5). Two open investigations of one uncertainty are refused, because
    a second "before" for the same question would make the measurement meaningless.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        open_row = conn.execute(
            "SELECT outcome_id FROM ciph_curiosity_investigations i WHERE i.uncertainty_id = ? "
            "AND NOT EXISTS (SELECT 1 FROM ciph_curiosity_outcomes o "
            "WHERE o.outcome_id = i.outcome_id);", (uncertainty_id,)).fetchone()
        if open_row is not None:
            raise CuriosityLearningError("INVESTIGATION_ALREADY_OPEN",
                                         f"{uncertainty_id}:{open_row['outcome_id']}")
        probe = curiosity_state_probe(db_path, uncertainty_id, now=moment)
        if not probe["present"]:
            raise CuriosityLearningError("UNKNOWN_UNCERTAINTY", uncertainty_id)
        basis = _digest(probe)
        # A repeat investigation of the SAME uncertainty on the SAME basis is a NEW measurement - that
        # is exactly the "repeated low-value investigation" law 7 describes. History, not wall-clock
        # time, decides the sequence number, so a restart reproduces the same ids.
        sequence = int(conn.execute(
            "SELECT COUNT(*) FROM ciph_curiosity_investigations WHERE uncertainty_id = ?;",
            (uncertainty_id,)).fetchone()[0]) + 1
        outcome_id = "CI-" + hashlib.sha256(
            f"{uncertainty_id}:{basis}:{sequence}".encode("utf-8")).hexdigest()[:12].upper()
        conn.execute(
            "INSERT INTO ciph_curiosity_investigations (outcome_id, uncertainty_id, proposal_id, "
            "investigation_ref, before_basis_digest, before_state_json, started_at) "
            "VALUES (?,?,?,?,?,?,?);",
            (outcome_id, uncertainty_id, proposal_id, investigation_ref, basis,
             json.dumps(probe, sort_keys=True), moment),
        )
        conn.commit()
        return outcome_id
    finally:
        conn.close()


def _row_to_outcome(open_row: Dict[str, Any],
                    closed_row: Optional[Dict[str, Any]]) -> CuriosityOutcome:
    closed_row = closed_row or {}
    return CuriosityOutcome(
        outcome_id=str(open_row["outcome_id"]), uncertainty_id=str(open_row["uncertainty_id"]),
        proposal_id=open_row["proposal_id"], investigation_ref=open_row["investigation_ref"],
        before_basis_digest=str(open_row["before_basis_digest"]),
        before_state=json.loads(open_row["before_state_json"]),
        after_basis_digest=closed_row.get("after_basis_digest"),
        after_state=(json.loads(closed_row["after_state_json"])
                     if closed_row.get("after_state_json") else None),
        result=closed_row.get("result"), information_gain=closed_row.get("information_gain"),
        reason_code=closed_row.get("reason_code"),
        operational_status=closed_row.get("operational_status"),
        closed_at=closed_row.get("closed_at"),
        outcome_digest=closed_row.get("outcome_digest"))


def get_outcome(db_path: str, outcome_id: str) -> CuriosityOutcome:
    conn = _connect(db_path, read_only=True)
    try:
        open_row = conn.execute("SELECT * FROM ciph_curiosity_investigations WHERE outcome_id = ?;",
                                (outcome_id,)).fetchone()
        closed_row = conn.execute("SELECT * FROM ciph_curiosity_outcomes WHERE outcome_id = ?;",
                                  (outcome_id,)).fetchone()
    except sqlite3.Error:
        open_row, closed_row = None, None
    finally:
        conn.close()
    if open_row is None:
        raise CuriosityLearningError("UNKNOWN_OUTCOME", outcome_id)
    return _row_to_outcome(dict(open_row), dict(closed_row) if closed_row is not None else None)


def close_investigation(db_path: str, outcome_id: str, *, attempted: bool = True,
                        operational_status: str = OPERATIONAL_COMPLETED,
                        cost_actual: Optional[float] = None, risk_actual: Optional[float] = None,
                        now: Optional[float] = None) -> CuriosityOutcome:
    """
    Measure the AFTER state and close. Closing is a ONE-WAY transition: the record is immutable
    afterwards, so information gain cannot be retroactively rewritten (law 6).
    """
    moment = time.time() if now is None else float(now)
    existing = get_outcome(db_path, outcome_id)
    if existing.result is not None:
        raise CuriosityLearningError("OUTCOME_ALREADY_CLOSED", f"{outcome_id}:{existing.result}")
    if operational_status not in VALID_OPERATIONAL_STATUSES:
        raise CuriosityLearningError("INVALID_OPERATIONAL_STATUS", str(operational_status))
    after = curiosity_state_probe(db_path, existing.uncertainty_id, now=moment)
    result, reason = derive_result(existing.before_state, after, attempted=attempted,
                                   operational_status=operational_status)
    gain = information_gain(existing.before_state, after)
    after_basis = _digest(after)
    digest = _digest({"outcome_id": outcome_id, "uncertainty_id": existing.uncertainty_id,
                      "before": existing.before_basis_digest, "after": after_basis,
                      "result": result, "gain": gain, "operational_status": operational_status,
                      "metric": CURIOSITY_INFORMATION_GAIN_V1})
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute(
            "INSERT INTO ciph_curiosity_outcomes (outcome_id, after_basis_digest, "
            "after_state_json, result, information_gain, reason_code, operational_status, "
            "cost_actual, risk_actual, outcome_digest, closed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (outcome_id, after_basis, json.dumps(after, sort_keys=True), result, gain, reason,
             operational_status, cost_actual, risk_actual, digest, moment),
        )
        conn.commit()
    finally:
        conn.close()
    return get_outcome(db_path, outcome_id)


def outcome_history(db_path: str, uncertainty_id: Optional[str] = None) -> List[CuriosityOutcome]:
    """Every closed investigation, oldest first. Historical records are never rewritten (law 5)."""
    conn = _connect(db_path, read_only=True)
    try:
        query = ("SELECT i.*, o.result, o.information_gain, o.reason_code, o.operational_status, o.closed_at, "
                 "o.after_basis_digest, o.after_state_json, o.outcome_digest "
                 "FROM ciph_curiosity_investigations i JOIN ciph_curiosity_outcomes o "
                 "ON o.outcome_id = i.outcome_id")
        params: Tuple[Any, ...] = ()
        if uncertainty_id is not None:
            query += " WHERE i.uncertainty_id = ?"
            params = (uncertainty_id,)
        rows = [dict(r) for r in conn.execute(query + " ORDER BY o.closed_at, i.outcome_id;", params)]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return [_row_to_outcome(row, row) for row in rows]


def outcome_penalty(db_path: str, uncertainty_id: str) -> float:
    """
    Law 7, as a number Gate One can read: repeated barren investigations of the SAME uncertainty
    lower its future priority. Fixed weight, no learning loop.
    """
    barren = sum(1 for outcome in outcome_history(db_path, uncertainty_id)
                 if outcome.result in BARREN_RESULTS)
    return round(barren * BARREN_OUTCOME_PENALTY, 12)


def learning_digest(db_path: str) -> str:
    """The deterministic identity of the learning record (law 10)."""
    return _digest([outcome.as_dict() for outcome in outcome_history(db_path)])
