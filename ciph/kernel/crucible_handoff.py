"""
ciph/kernel/crucible_handoff - 4.6 Gate Four: hand the candidate over and become a spectator.

This gate is intentionally boring. After handoff, 4.6 may consume the result; it may not touch the
protocol, the held-out cases, the metrics, the candidate, the comparison or the promotion.

The held-out firewall is the part that matters: a generator that can read the sealed answers is not
being evaluated, it is studying for the exam it wrote.

LAWS
 1. 4.6 never evaluates its own candidate.
 2. 4.6 cannot modify a frozen protocol.
 3. 4.6 cannot inspect sealed held-out answers.
 4. The candidate is immutable during an evaluation.
 5. Handoff creates no promotion.
 6. Handoff creates no deployment authority.
 7. The Crucible verdict is canonical even if the generator disagrees.
 8. INCOMPARABLE is a valid outcome.
 9. INSUFFICIENT_EVIDENCE is a valid outcome.
10. A rejected candidate remains historical.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.candidate_safety import VERDICT_ADMISSIBLE, is_admissible
from ciph.kernel.crucible_candidates import get_candidate
from ciph.kernel.crucible_protocols import assert_protocol_integrity, get_protocol
from ciph.kernel.crucible_types import CrucibleError, digest

CRUCIBLE_HANDOFF_V1 = "CRUCIBLE_HANDOFF_V1"

REASON_NOT_ADMISSIBLE = "CANDIDATE_NOT_ADMISSIBLE"
REASON_UNKNOWN_HYPOTHESIS = "UNKNOWN_HYPOTHESIS"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_crucible_handoffs (
        handoff_id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        role TEXT NOT NULL,
        artifact_digest TEXT NOT NULL,
        creates_authority INTEGER NOT NULL,
        handed_off_at REAL
    );
    """,
)


@dataclass(frozen=True)
class HandoffRecord:
    handoff_id: str
    candidate_id: str
    hypothesis_id: str
    protocol_id: str
    role: str
    artifact_digest: str
    creates_authority: bool

    def as_dict(self) -> Dict[str, Any]:
        return {"handoff_id": self.handoff_id, "candidate_id": self.candidate_id,
                "hypothesis_id": self.hypothesis_id, "protocol_id": self.protocol_id,
                "role": self.role, "artifact_digest": self.artifact_digest,
                "creates_authority": self.creates_authority}


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


def generator_visible_view(db_path: str, protocol_id: str) -> Dict[str, Any]:
    """
    Everything a candidate generator is allowed to know about an evaluation.

    Development cases and metric definitions only. The sealed held-out list is deliberately ABSENT
    rather than filtered out later - there is no code path from here to a held-out answer (law 3).
    """
    protocol = get_protocol(db_path, protocol_id)
    return {"protocol_id": protocol.protocol_id,
            "development_cases": list(protocol.development_cases),
            "metrics": [{"metric_id": metric.metric_id, "metric_version": metric.metric_version,
                         "direction": metric.direction} for metric in protocol.metric_definitions],
            "environment_identity": protocol.environment_identity,
            "sealed_case_count": len(protocol.heldout_cases)}


def hand_off(db_path: str, *, candidate_id: str, hypothesis_id: str, protocol_id: str, role: str,
             now: Optional[float] = None) -> HandoffRecord:
    """
    Declare that a candidate is ready to face the Crucible (laws 1, 5, 6).

    Every path out of here leads to the 4.5 evaluator. Nothing here creates a trial, a promotion or a
    deployment, and `creates_authority` is recorded as False so the absence is auditable.
    """
    if not is_admissible(db_path, candidate_id):
        raise CrucibleError(REASON_NOT_ADMISSIBLE, candidate_id)
    assert_protocol_integrity(db_path, protocol_id)
    candidate = get_candidate(db_path, candidate_id)
    moment = time.time() if now is None else float(now)
    handoff_id = "CHO-" + digest({"candidate": candidate_id, "hypothesis": hypothesis_id,
                                  "protocol": protocol_id, "role": role})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_crucible_handoffs (handoff_id, candidate_id, hypothesis_id, "
            "protocol_id, role, artifact_digest, creates_authority, handed_off_at) "
            "VALUES (?,?,?,?,?,?,?,?);",
            (handoff_id, candidate_id, hypothesis_id, protocol_id, role, candidate.artifact_digest,
             0, moment))
        connection.commit()
    finally:
        connection.close()
    return get_handoff(db_path, handoff_id)


def get_handoff(db_path: str, handoff_id: str) -> HandoffRecord:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_crucible_handoffs WHERE handoff_id = ?;",
                                 (handoff_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_HANDOFF", handoff_id)
    row = dict(row)
    return HandoffRecord(handoff_id=str(row["handoff_id"]), candidate_id=str(row["candidate_id"]),
                         hypothesis_id=str(row["hypothesis_id"]),
                         protocol_id=str(row["protocol_id"]), role=str(row["role"]),
                         artifact_digest=str(row["artifact_digest"]),
                         creates_authority=bool(row["creates_authority"]))


def handoff_history(db_path: str) -> List[HandoffRecord]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["handoff_id"]) for row in connection.execute(
            "SELECT handoff_id FROM ciph_crucible_handoffs ORDER BY handed_off_at, handoff_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_handoff(db_path, handoff_id) for handoff_id in ids]


def handoff_digest(db_path: str) -> str:
    return digest({"version": CRUCIBLE_HANDOFF_V1,
                   "handoffs": [item.as_dict() for item in handoff_history(db_path)]})
