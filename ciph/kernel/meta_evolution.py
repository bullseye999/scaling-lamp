"""
ciph/kernel/meta_evolution - 4.6 Gate Six: the stop sign.

Ordinary self-improvement may not improve the machinery that generates or judges improvements. Not
because that is forever forbidden, but because the ordinary path has no way to notice that it is
grading its own homework.

    ordinary:  candidate improves a CAPABILITY
    meta:      candidate improves the GENERATOR, the REVIEWER, the CRUCIBLE or the CONSTITUTION

LAWS
 1. The candidate generator cannot ordinarily modify itself.
 2. The safety reviewer cannot ordinarily modify itself.
 3. The Crucible cannot be an ordinary candidate target.
 4. The execution constitution cannot be an ordinary candidate target.
 5. Meta-evolution requires explicit architecture-level authorization.
 6. A meta proposal creates zero promotion or deployment authority.
 7. A meta candidate, if later allowed, faces a stronger external protocol.
 8. Ordinary candidates cannot smuggle meta changes inside unrelated diffs.
 9. Dependency changes reaching protected components count as meta-touching.
10. Recursive candidate generation is disabled in 4.6.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.candidate_safety import GENERATOR_SURFACES, PROTECTED_SURFACES
from ciph.kernel.crucible_types import CrucibleError, digest

META_EVOLUTION_BOUNDARY_V1 = "META_EVOLUTION_BOUNDARY_V1"

REVIEW_OPERATOR_ARCHITECTURE = "OPERATOR_ARCHITECTURE_REVIEW"

REASON_META_TARGET = "META_EVOLUTION_REQUIRES_ARCHITECTURE_REVIEW"
REASON_RECURSIVE_DISABLED = "RECURSIVE_CANDIDATE_GENERATION_DISABLED"

META_TARGETS: Tuple[str, ...] = tuple(PROTECTED_SURFACES) + tuple(GENERATOR_SURFACES) + (
    "ciph/kernel/evolution_ownership.py", "ciph/kernel/evolution_adapters.py",
    "ciph/kernel/crucible_types.py", "code_staging.py", "evolution_bridge.py",
)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_evolution_requests (
        request_id TEXT PRIMARY KEY,
        target_component TEXT NOT NULL,
        proposed_change TEXT NOT NULL,
        reason TEXT,
        evidence_refs_json TEXT,
        required_review_class TEXT NOT NULL,
        creates_authority INTEGER NOT NULL,
        requested_by TEXT,
        requested_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetaEvolutionRequest:
    request_id: str
    target_component: str
    proposed_change: str
    reason: Optional[str]
    evidence_refs: Tuple[str, ...]
    required_review_class: str
    creates_authority: bool

    def as_dict(self) -> Dict[str, Any]:
        return {"request_id": self.request_id, "target_component": self.target_component,
                "proposed_change": self.proposed_change, "reason": self.reason,
                "evidence_refs": list(self.evidence_refs),
                "required_review_class": self.required_review_class,
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


def is_meta_target(paths: Sequence[str]) -> Tuple[bool, Tuple[str, ...]]:
    """Which of these paths belong to the machinery rather than to a capability (laws 1-4, 9)."""
    touched = []
    for path in paths:
        normalised = str(path).replace("\\", "/").lstrip("./")
        for target in META_TARGETS:
            if normalised == target or normalised.endswith(target) or target.endswith(normalised):
                touched.append(normalised)
                break
    return (bool(touched), tuple(sorted(set(touched))))


def assert_ordinary_candidate_scope(db_path: str, *, changed_files: Sequence[str],
                                    new_dependencies: Sequence[str] = ()) -> None:
    """
    Law 8: a candidate may not smuggle a meta change inside an unrelated diff.

    The check looks at the ACTUAL files and dependencies, so a description claiming to optimize a
    planner cannot carry a modification to the evaluator past this point.
    """
    meta, touched = is_meta_target(list(changed_files) + list(new_dependencies))
    if meta:
        raise CrucibleError(REASON_META_TARGET, ",".join(touched))


def request_meta_evolution(db_path: str, *, target_component: str, proposed_change: str,
                           reason: Optional[str] = None, evidence_refs: Sequence[str] = (),
                           requested_by: Optional[str] = None,
                           now: Optional[float] = None) -> MetaEvolutionRequest:
    """
    Record a meta-evolution request (laws 5-7).

    It is a REQUEST for architecture review, and it carries no authority: no candidate is registered,
    no comparison is run, no promotion is possible.
    """
    moment = time.time() if now is None else float(now)
    refs = tuple(sorted(str(ref) for ref in evidence_refs))
    request_id = "MER-" + digest({"target": target_component, "change": proposed_change,
                                  "refs": list(refs)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_evolution_requests (request_id, target_component, "
            "proposed_change, reason, evidence_refs_json, required_review_class, creates_authority, "
            "requested_by, requested_at) VALUES (?,?,?,?,?,?,?,?,?);",
            (request_id, target_component, proposed_change, reason, json.dumps(list(refs)),
             REVIEW_OPERATOR_ARCHITECTURE, 0, requested_by, moment))
        connection.commit()
    finally:
        connection.close()
    return get_meta_request(db_path, request_id)


def get_meta_request(db_path: str, request_id: str) -> MetaEvolutionRequest:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_evolution_requests WHERE request_id = ?;",
                                 (request_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_META_REQUEST", request_id)
    row = dict(row)
    return MetaEvolutionRequest(
        request_id=str(row["request_id"]), target_component=str(row["target_component"]),
        proposed_change=str(row["proposed_change"]), reason=row["reason"],
        evidence_refs=tuple(json.loads(row["evidence_refs_json"] or "[]")),
        required_review_class=str(row["required_review_class"]),
        creates_authority=bool(row["creates_authority"]))


def meta_request_history(db_path: str) -> List[MetaEvolutionRequest]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["request_id"]) for row in connection.execute(
            "SELECT request_id FROM ciph_meta_evolution_requests ORDER BY requested_at, request_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_meta_request(db_path, request_id) for request_id in ids]


def recursive_generation_enabled() -> bool:
    """Law 10: disabled in 4.6, as a property rather than a convention."""
    return False


def meta_boundary_digest(db_path: str) -> str:
    return digest({"version": META_EVOLUTION_BOUNDARY_V1,
                   "requests": [item.as_dict() for item in meta_request_history(db_path)],
                   "recursive": recursive_generation_enabled()})
