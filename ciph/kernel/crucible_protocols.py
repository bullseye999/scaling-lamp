"""
ciph/kernel/crucible_protocols - 4.5 Gate One: how will the candidate be judged, decided BEFORE it runs?

An evaluation protocol is frozen before any result exists. It names the development cases, the SEALED
held-out cases, the metric definitions with their versions and directions, the environment, the
repetition count and the hard invariants. Changing any of that does not edit an evaluation - it
creates a different one.

LAWS
 1. The protocol is frozen before candidate results.
 2. A candidate cannot edit the evaluator, the metrics or the test corpus.
 3. Candidate and baseline face the same protocol.
 4. The evaluation environment identity is recorded.
 5. Metric versions are explicit.
 6. Changing metrics after seeing results creates a NEW evaluation.
 7. Development performance is not held-out performance.
 8. Benchmark success is evidence only for the evaluated domain.
 9. Hard constitutional invariants override performance gains.
10. Missing evaluation evidence is INSUFFICIENT_EVIDENCE, never PASS.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import (
    CRUCIBLE_PROTOCOL_V1,
    CrucibleError,
    DIRECTION_HIGHER_BETTER,
    DIRECTION_LOWER_BETTER,
    VALID_DIRECTIONS,
    VALID_KINDS,
    digest,
)

# The constitutional invariants that can never be traded for performance. They are named here so a
# protocol can declare them and a comparison can refuse to trade them.
HARD_INVARIANTS = ("NO_AUTHORITY_BYPASS", "NO_FABRICATED_EVIDENCE", "NO_HISTORY_MUTATION",
                   "NO_UNAUTHORIZED_EXECUTION", "NO_EVALUATOR_OR_BENCHMARK_MUTATION")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_protocols (
        protocol_id TEXT PRIMARY KEY,
        protocol_version TEXT NOT NULL,
        candidate_kind TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        development_cases_json TEXT,
        heldout_cases_json TEXT,
        metric_definitions_json TEXT,
        environment_identity TEXT,
        repetition_count INTEGER NOT NULL,
        seed_policy TEXT,
        resource_budget REAL,
        hard_invariants_json TEXT,
        minimum_evidence INTEGER NOT NULL,
        created_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetricDefinition:
    metric_id: str
    metric_version: str
    direction: str
    minimum_meaningful_delta: float = 0.0
    tolerance: float = 0.0
    hard: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {"metric_id": self.metric_id, "metric_version": self.metric_version,
                "direction": self.direction,
                "minimum_meaningful_delta": self.minimum_meaningful_delta,
                "tolerance": self.tolerance, "hard": self.hard}


@dataclass(frozen=True)
class EvaluationProtocol:
    protocol_id: str
    protocol_version: str
    candidate_kind: str
    development_cases: Tuple[str, ...]
    heldout_cases: Tuple[str, ...]
    metric_definitions: Tuple[MetricDefinition, ...]
    environment_identity: Optional[str]
    repetition_count: int
    seed_policy: Optional[str]
    resource_budget: Optional[float]
    hard_invariants: Tuple[str, ...]
    minimum_evidence: int
    created_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"protocol_id": self.protocol_id, "protocol_version": self.protocol_version,
                "candidate_kind": self.candidate_kind,
                "development_cases": list(self.development_cases),
                "heldout_cases": list(self.heldout_cases),
                "metric_definitions": [metric.as_dict() for metric in self.metric_definitions],
                "environment_identity": self.environment_identity,
                "repetition_count": self.repetition_count, "seed_policy": self.seed_policy,
                "resource_budget": self.resource_budget,
                "hard_invariants": list(self.hard_invariants),
                "minimum_evidence": self.minimum_evidence}

    def metric(self, metric_id: str) -> Optional[MetricDefinition]:
        for metric in self.metric_definitions:
            if metric.metric_id == metric_id:
                return metric
        return None


def protocol_payload(*, candidate_kind: str, development_cases: Sequence[str],
                     heldout_cases: Sequence[str], metric_definitions: Sequence[MetricDefinition],
                     environment_identity: Optional[str], repetition_count: int, seed_policy,
                     resource_budget, hard_invariants: Sequence[str],
                     minimum_evidence: int) -> Dict[str, Any]:
    """THE frozen identity payload. Any change here is a different evaluation, by construction."""
    return {"protocol_version": CRUCIBLE_PROTOCOL_V1, "candidate_kind": candidate_kind,
            "development_cases": sorted(str(case) for case in development_cases),
            "heldout_cases": sorted(str(case) for case in heldout_cases),
            "metric_definitions": sorted((metric.as_dict() for metric in metric_definitions),
                                         key=lambda item: item["metric_id"]),
            "environment_identity": environment_identity,
            "repetition_count": int(repetition_count), "seed_policy": seed_policy,
            "resource_budget": resource_budget,
            "hard_invariants": sorted(str(item) for item in hard_invariants),
            "minimum_evidence": int(minimum_evidence)}


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


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def freeze_protocol(db_path: str, *, candidate_kind: str, development_cases: Sequence[str],
                    heldout_cases: Sequence[str],
                    metric_definitions: Sequence[MetricDefinition],
                    environment_identity: Optional[str] = None, repetition_count: int = 1,
                    seed_policy: Optional[str] = None, resource_budget: Optional[float] = None,
                    hard_invariants: Sequence[str] = (),
                    minimum_evidence: int = 1, now: Optional[float] = None) -> EvaluationProtocol:
    """
    Freeze ONE evaluation protocol. Idempotent by payload: the same judgement plan is the same plan.

    There is no update path anywhere in this module. A changed metric, corpus or environment produces a
    different protocol_id, which is exactly how "we changed the goalposts after seeing the results"
    becomes visible instead of silent.
    """
    if candidate_kind not in VALID_KINDS:
        raise CrucibleError("INVALID_CANDIDATE_KIND", str(candidate_kind))
    if not metric_definitions:
        raise CrucibleError("PROTOCOL_REQUIRES_METRICS", "no metric definitions")
    for metric in metric_definitions:
        if metric.direction not in VALID_DIRECTIONS:
            raise CrucibleError("INVALID_METRIC_DIRECTION", f"{metric.metric_id}:{metric.direction}")
        if not metric.metric_version:
            raise CrucibleError("METRIC_REQUIRES_VERSION", metric.metric_id)
    development = [str(case) for case in development_cases]
    heldout = [str(case) for case in heldout_cases]
    overlap = sorted(set(development) & set(heldout))
    if overlap:
        raise CrucibleError("DEVELOPMENT_CASES_OVERLAP_HELDOUT", ",".join(overlap[:3]))
    if int(repetition_count) < 1:
        raise CrucibleError("REPETITION_COUNT_MUST_BE_POSITIVE", str(repetition_count))
    if int(minimum_evidence) < 1:
        raise CrucibleError("MINIMUM_EVIDENCE_MUST_BE_POSITIVE", str(minimum_evidence))
    invariants = [str(item) for item in hard_invariants]
    unknown = sorted(set(invariants) - set(HARD_INVARIANTS))
    if unknown:
        raise CrucibleError("UNKNOWN_HARD_INVARIANT", ",".join(unknown))

    moment = time.time() if now is None else float(now)
    payload = protocol_payload(
        candidate_kind=candidate_kind, development_cases=development, heldout_cases=heldout,
        metric_definitions=metric_definitions, environment_identity=environment_identity,
        repetition_count=repetition_count, seed_policy=seed_policy, resource_budget=resource_budget,
        hard_invariants=invariants, minimum_evidence=minimum_evidence)
    protocol_id = "CP-" + digest(payload)[:16].upper()

    connection = _connect(db_path)
    try:
        init_schema(connection)
        existing = connection.execute("SELECT 1 FROM ciph_crucible_protocols WHERE protocol_id = ?;",
                                      (protocol_id,)).fetchone()
        if existing is None:
            connection.execute(
                "INSERT INTO ciph_crucible_protocols (protocol_id, protocol_version, "
                "candidate_kind, payload_json, development_cases_json, heldout_cases_json, "
                "metric_definitions_json, environment_identity, repetition_count, seed_policy, "
                "resource_budget, hard_invariants_json, minimum_evidence, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
                (protocol_id, CRUCIBLE_PROTOCOL_V1, candidate_kind,
                 json.dumps(payload, sort_keys=True), json.dumps(sorted(development)),
                 json.dumps(sorted(heldout)),
                 json.dumps([metric.as_dict() for metric in metric_definitions]),
                 environment_identity, int(repetition_count), seed_policy, resource_budget,
                 json.dumps(sorted(invariants)), int(minimum_evidence), moment))
            connection.commit()
    finally:
        connection.close()
    return get_protocol(db_path, protocol_id)


def get_protocol(db_path: str, protocol_id: str) -> EvaluationProtocol:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_crucible_protocols WHERE protocol_id = ?;",
                                 (protocol_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_PROTOCOL", protocol_id)
    return _protocol_from_row(dict(row))


def _protocol_from_row(row: Dict[str, Any]) -> EvaluationProtocol:
    payload = _json(row["payload_json"]) or {}
    metrics = tuple(MetricDefinition(
        metric_id=str(item["metric_id"]), metric_version=str(item["metric_version"]),
        direction=str(item["direction"]),
        minimum_meaningful_delta=float(item.get("minimum_meaningful_delta", 0.0)),
        tolerance=float(item.get("tolerance", 0.0)), hard=bool(item.get("hard", False)))
        for item in (_json(row["metric_definitions_json"]) or []))
    return EvaluationProtocol(
        protocol_id=str(row["protocol_id"]), protocol_version=str(row["protocol_version"]),
        candidate_kind=str(row["candidate_kind"]),
        development_cases=tuple(_json(row["development_cases_json"]) or []),
        heldout_cases=tuple(_json(row["heldout_cases_json"]) or []),
        metric_definitions=metrics, environment_identity=row["environment_identity"],
        repetition_count=int(row["repetition_count"]), seed_policy=row["seed_policy"],
        resource_budget=row["resource_budget"],
        hard_invariants=tuple(_json(row["hard_invariants_json"]) or []),
        minimum_evidence=int(row["minimum_evidence"]), created_at=row["created_at"])


def _json(value: Any) -> Any:
    """Strict JSON only: a payload that cannot be parsed is corruption, not something to guess at."""
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(str(value))
    except Exception:
        return None


def assert_protocol_integrity(db_path: str, protocol_id: str) -> str:
    """
    Law 2, as a guard: the stored protocol must still BE the protocol its id names.

    Recomputes the identity from the stored payload and compares. An out-of-band edit to a metric, a
    threshold, a case list or the environment is therefore detected rather than silently believed.
    """
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_crucible_protocols WHERE protocol_id = ?;",
                                 (protocol_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_PROTOCOL", protocol_id)
    row = dict(row)
    stored = _json(row["payload_json"])
    if stored is None:
        raise CrucibleError("PROTOCOL_INTEGRITY_VIOLATION", f"{protocol_id}: unreadable payload")
    if "CP-" + digest(stored)[:16].upper() != protocol_id:
        raise CrucibleError("PROTOCOL_INTEGRITY_VIOLATION",
                            f"{protocol_id}: the stored payload does not hash to its own id")
    protocol = _protocol_from_row(row)
    expected_payload = protocol_payload(
        candidate_kind=protocol.candidate_kind, development_cases=protocol.development_cases,
        heldout_cases=protocol.heldout_cases, metric_definitions=protocol.metric_definitions,
        environment_identity=protocol.environment_identity,
        repetition_count=protocol.repetition_count, seed_policy=protocol.seed_policy,
        resource_budget=protocol.resource_budget, hard_invariants=protocol.hard_invariants,
        minimum_evidence=protocol.minimum_evidence)
    if expected_payload != stored:
        raise CrucibleError("PROTOCOL_INTEGRITY_VIOLATION",
                            f"{protocol_id}: stored columns disagree with the frozen payload")
    return protocol_id


def protocol_history(db_path: str) -> List[EvaluationProtocol]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in connection.execute(
            "SELECT * FROM ciph_crucible_protocols ORDER BY created_at, protocol_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [_protocol_from_row(row) for row in rows]


def protocol_digest(db_path: str) -> str:
    return digest([protocol.as_dict() for protocol in protocol_history(db_path)])
