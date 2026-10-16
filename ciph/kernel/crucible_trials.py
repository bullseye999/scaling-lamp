"""
ciph/kernel/crucible_trials - 4.5 Gate Two: can baseline and candidate be tested under equivalent,
controlled conditions?

A trial is one evaluation of one subject (baseline or candidate) under one frozen protocol. Its identity
is derived from (protocol, subject, role, seed, environment), so a restart resumes the SAME trial rather
than quietly starting a second one.

LAWS
 1. The Crucible has no private execution signer.
 2. The Crucible has no direct PermitStore.claim path.
 3. Trials cannot modify production candidate pointers.
 4. A candidate cannot modify evaluator state.
 5. A candidate cannot modify benchmark answers.
 6. Trial failure is recorded, not hidden.
 7. Crash/restart resumes or reconstructs the SAME trial.
 8. Retrying follows the normal execution-generation law.
 9. The trial environment identity is part of the evidence.
10. A candidate receives only the permissions the evaluation protocol declares.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.crucible_candidates import get_candidate
from ciph.kernel.crucible_protocols import assert_protocol_integrity, get_protocol
from ciph.kernel.crucible_types import CrucibleError, digest

STATUS_PENDING = "PENDING"
STATUS_RUNNING = "RUNNING"
STATUS_COMPLETE = "COMPLETE"
STATUS_FAILED = "FAILED"
STATUS_INVALID = "INVALID"
VALID_TRIAL_STATUSES = (STATUS_PENDING, STATUS_RUNNING, STATUS_COMPLETE, STATUS_FAILED,
                        STATUS_INVALID)

ROLE_BASELINE = "BASELINE"
ROLE_CANDIDATE = "CANDIDATE"
VALID_ROLES = (ROLE_BASELINE, ROLE_CANDIDATE)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_trials (
        trial_id TEXT PRIMARY KEY,
        protocol_id TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        role TEXT NOT NULL,
        environment_identity TEXT,
        dataset_digest TEXT,
        seed TEXT,
        status TEXT NOT NULL,
        observations_json TEXT,
        result_refs_json TEXT,
        execution_receipt_refs_json TEXT,
        epistemic_refs_json TEXT,
        invalid_reason TEXT,
        started_at REAL,
        completed_at REAL
    );
    """,
)


@dataclass(frozen=True)
class TrialRun:
    trial_id: str
    protocol_id: str
    subject_id: str
    role: str
    environment_identity: Optional[str]
    dataset_digest: Optional[str]
    seed: Optional[str]
    status: str
    observations: Mapping[str, Any]
    result_refs: Tuple[str, ...]
    execution_receipt_refs: Tuple[str, ...]
    epistemic_refs: Tuple[str, ...]
    invalid_reason: Optional[str]
    started_at: Optional[float]
    completed_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"trial_id": self.trial_id, "protocol_id": self.protocol_id,
                "subject_id": self.subject_id, "role": self.role,
                "environment_identity": self.environment_identity,
                "dataset_digest": self.dataset_digest, "seed": self.seed, "status": self.status,
                "observations": {key: self.observations[key]
                                 for key in sorted(self.observations or {})},
                "result_refs": list(self.result_refs),
                "execution_receipt_refs": list(self.execution_receipt_refs),
                "epistemic_refs": list(self.epistemic_refs),
                "invalid_reason": self.invalid_reason}


def trial_id_for(*, protocol_id: str, subject_id: str, role: str, seed: Optional[str],
                 environment_identity: Optional[str]) -> str:
    return "CT-" + digest({"protocol": protocol_id, "subject": subject_id, "role": role,
                           "seed": seed, "environment": environment_identity})[:16].upper()


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


def start_trial(db_path: str, *, protocol_id: str, subject_id: str, role: str,
                environment_identity: Optional[str] = None, dataset_digest: Optional[str] = None,
                seed: Optional[str] = None, now: Optional[float] = None) -> TrialRun:
    """
    Open ONE trial. Idempotent by derived identity (law 7): re-opening the same trial after a restart
    returns the SAME trial, so a crash cannot manufacture a second attempt at the same measurement.
    """
    if role not in VALID_ROLES:
        raise CrucibleError("INVALID_TRIAL_ROLE", str(role))
    assert_protocol_integrity(db_path, protocol_id)
    protocol = get_protocol(db_path, protocol_id)
    get_candidate(db_path, subject_id)
    if environment_identity != protocol.environment_identity:
        raise CrucibleError("TRIAL_ENVIRONMENT_MISMATCH",
                            f"{environment_identity!r} != {protocol.environment_identity!r}")
    moment = time.time() if now is None else float(now)
    trial_id = trial_id_for(protocol_id=protocol_id, subject_id=subject_id, role=role, seed=seed,
                            environment_identity=environment_identity)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        existing = connection.execute("SELECT 1 FROM ciph_crucible_trials WHERE trial_id = ?;",
                                      (trial_id,)).fetchone()
        if existing is None:
            connection.execute(
                "INSERT INTO ciph_crucible_trials (trial_id, protocol_id, subject_id, role, "
                "environment_identity, dataset_digest, seed, status, observations_json, "
                "result_refs_json, execution_receipt_refs_json, epistemic_refs_json, "
                "invalid_reason, started_at, completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
                (trial_id, protocol_id, subject_id, role, environment_identity, dataset_digest, seed,
                 STATUS_RUNNING, json.dumps({}), json.dumps([]), json.dumps([]), json.dumps([]),
                 None, moment, None))
            connection.commit()
    finally:
        connection.close()
    return get_trial(db_path, trial_id)


def _finish(db_path: str, trial_id: str, *, status: str, observations=None, result_refs=(),
            execution_receipt_refs=(), epistemic_refs=(), invalid_reason=None,
            now: Optional[float] = None) -> TrialRun:
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        row = connection.execute("SELECT * FROM ciph_crucible_trials WHERE trial_id = ?;",
                                 (trial_id,)).fetchone()
        if row is None:
            raise CrucibleError("UNKNOWN_TRIAL", trial_id)
        if row["status"] in (STATUS_COMPLETE, STATUS_FAILED, STATUS_INVALID):
            raise CrucibleError("TRIAL_ALREADY_CLOSED", f"{trial_id}:{row['status']}")
        # Law 4: a trial cannot be completed against an evaluator that has moved underneath it.
        assert_protocol_integrity(db_path, str(row["protocol_id"]))
        connection.execute(
            "UPDATE ciph_crucible_trials SET status = ?, observations_json = ?, result_refs_json = ?, "
            "execution_receipt_refs_json = ?, epistemic_refs_json = ?, invalid_reason = ?, "
            "completed_at = ? WHERE trial_id = ?;",
            (status, json.dumps(dict(observations or {})), json.dumps(sorted(result_refs)),
             json.dumps(sorted(execution_receipt_refs)), json.dumps(sorted(epistemic_refs)),
             invalid_reason, moment, trial_id))
        connection.commit()
    finally:
        connection.close()
    return get_trial(db_path, trial_id)


def complete_trial(db_path: str, trial_id: str, *, observations: Mapping[str, Any],
                   result_refs: Sequence[str] = (), execution_receipt_refs: Sequence[str] = (),
                   epistemic_refs: Sequence[str] = (), now: Optional[float] = None) -> TrialRun:
    """Record a finished trial. Failure is a recorded outcome too, never a silent absence (law 6)."""
    return _finish(db_path, trial_id, status=STATUS_COMPLETE, observations=observations,
                   result_refs=result_refs, execution_receipt_refs=execution_receipt_refs,
                   epistemic_refs=epistemic_refs, now=now)


def fail_trial(db_path: str, trial_id: str, *, reason: str,
               now: Optional[float] = None) -> TrialRun:
    return _finish(db_path, trial_id, status=STATUS_FAILED, invalid_reason=reason, now=now)


def invalidate_trial(db_path: str, trial_id: str, *, reason: str,
                     now: Optional[float] = None) -> TrialRun:
    """
    Mark a trial INVALID - used when a candidate tried to edit the evaluator, the benchmark, or its own
    results. The score it might have earned is irrelevant (Gate Three refuses it outright).
    """
    return _finish(db_path, trial_id, status=STATUS_INVALID, invalid_reason=reason, now=now)


def get_trial(db_path: str, trial_id: str) -> TrialRun:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_crucible_trials WHERE trial_id = ?;",
                                 (trial_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_TRIAL", trial_id)
    return _trial_from_row(dict(row))


def _trial_from_row(row: Dict[str, Any]) -> TrialRun:
    return TrialRun(
        trial_id=str(row["trial_id"]), protocol_id=str(row["protocol_id"]),
        subject_id=str(row["subject_id"]), role=str(row["role"]),
        environment_identity=row["environment_identity"], dataset_digest=row["dataset_digest"],
        seed=row["seed"], status=str(row["status"]),
        observations=json.loads(row["observations_json"] or "{}"),
        result_refs=tuple(json.loads(row["result_refs_json"] or "[]")),
        execution_receipt_refs=tuple(json.loads(row["execution_receipt_refs_json"] or "[]")),
        epistemic_refs=tuple(json.loads(row["epistemic_refs_json"] or "[]")),
        invalid_reason=row["invalid_reason"], started_at=row["started_at"],
        completed_at=row["completed_at"])


def trials_for(db_path: str, *, protocol_id: Optional[str] = None,
               subject_id: Optional[str] = None) -> List[TrialRun]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_crucible_trials"
    clauses, params = [], []
    if protocol_id is not None:
        clauses.append("protocol_id = ?")
        params.append(protocol_id)
    if subject_id is not None:
        clauses.append("subject_id = ?")
        params.append(subject_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    try:
        rows = [dict(r) for r in connection.execute(query + " ORDER BY trial_id;", tuple(params))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [_trial_from_row(row) for row in rows]


def trial_digest(db_path: str) -> str:
    return digest([trial.as_dict() for trial in trials_for(db_path)])
