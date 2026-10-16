"""
ciph/kernel/meta_opportunities - 4.7 Gate One: what evidence says the IMPROVEMENT MACHINERY is weak.

"I want a smarter candidate generator" is not a weakness. Neither is one bad candidate, nor the model's
opinion of itself. A meta opportunity needs historical evidence, at a versioned reproducibility
threshold, pinned to the EXACT component identity it accuses - so a new generator version does not
inherit its predecessor's accusation.

LAWS
 1. Meta weakness requires historical evidence.
 2. Self-criticism is not evidence.
 3. Candidate quantity is not candidate quality.
 4. A low DOMINATES rate alone is not a defect: some problem domains are genuinely hard.
 5. Production regression evidence counts separately from benchmark outcomes.
 6. An opportunity is bound to an exact machinery version.
 7. A new machinery version does not inherit an old weakness.
 8. History is append-only.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest
from ciph.kernel.meta_targets import RING_CONSTITUTIONAL_ROOT, classify_target

META_OPPORTUNITY_V1 = "META_OPPORTUNITY_V1"
META_OPPORTUNITY_REPRODUCIBILITY_V1 = "META_OPPORTUNITY_REPRODUCIBILITY_V1"
REQUIRED_META_REPRODUCTIONS_V1 = 2

KIND_LOW_YIELD = "LOW_USEFUL_CANDIDATE_YIELD"
KIND_HIGH_INVALID = "HIGH_INVALID_RATE"
KIND_HIGH_REGRESSION = "HIGH_REGRESSION_RATE"
KIND_EXCESSIVE_COST = "EXCESSIVE_GENERATION_COST"
KIND_REVIEW_FALSE_POSITIVE = "REVIEW_FALSE_POSITIVE"
KIND_REVIEW_FALSE_NEGATIVE = "REVIEW_FALSE_NEGATIVE"
KIND_EVALUATOR_INSTABILITY = "EVALUATOR_INSTABILITY"
KIND_SEARCH_COLLAPSE = "SEARCH_MODE_COLLAPSE"
KIND_OPERATOR_REQUEST = "OPERATOR_REQUEST"
VALID_WEAKNESS_KINDS = (KIND_LOW_YIELD, KIND_HIGH_INVALID, KIND_HIGH_REGRESSION, KIND_EXCESSIVE_COST,
                        KIND_REVIEW_FALSE_POSITIVE, KIND_REVIEW_FALSE_NEGATIVE,
                        KIND_EVALUATOR_INSTABILITY, KIND_SEARCH_COLLAPSE, KIND_OPERATOR_REQUEST)

STATUS_OPEN = "OPEN"
STATUS_STALE = "STALE"
STATUS_SATISFIED = "SATISFIED"
STATUS_INVALID = "INVALID"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_opportunities (
        opportunity_id TEXT PRIMARY KEY,
        target_component TEXT NOT NULL,
        target_ring TEXT NOT NULL,
        exact_component_identity TEXT NOT NULL,
        weakness_kind TEXT NOT NULL,
        crucible_history_refs_json TEXT,
        production_refs_json TEXT,
        policy_version TEXT NOT NULL,
        required_reproductions INTEGER NOT NULL,
        basis_digest TEXT NOT NULL,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_opportunity_evidence (
        opportunity_id TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        recorded_at REAL,
        PRIMARY KEY (opportunity_id, evidence_ref)
    );
    """,
)


@dataclass(frozen=True)
class MetaOpportunity:
    opportunity_id: str
    target_component: str
    target_ring: str
    exact_component_identity: str
    weakness_kind: str
    evidence_refs: Tuple[str, ...]
    crucible_history_refs: Tuple[str, ...]
    production_refs: Tuple[str, ...]
    policy_version: str
    required_reproductions: int
    basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"opportunity_id": self.opportunity_id, "target_component": self.target_component,
                "target_ring": self.target_ring,
                "exact_component_identity": self.exact_component_identity,
                "weakness_kind": self.weakness_kind, "evidence_refs": list(self.evidence_refs),
                "crucible_history_refs": list(self.crucible_history_refs),
                "production_refs": list(self.production_refs),
                "policy_version": self.policy_version,
                "required_reproductions": self.required_reproductions,
                "basis_digest": self.basis_digest}


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


def meta_weakness_basis(*, weakness_kind: str, target_component: str,
                        exact_component_identity: str) -> Dict[str, Any]:
    """Identity is the WEAKNESS AT A VERSION (laws 6, 7). Evidence is not part of it."""
    return {"version": META_OPPORTUNITY_V1, "weakness_kind": weakness_kind,
            "target_component": target_component,
            "exact_component_identity": exact_component_identity}


def record_meta_opportunity(db_path: str, *, target_component: str, weakness_kind: str,
                            exact_component_identity: str, evidence_refs: Sequence[str],
                            crucible_history_refs: Sequence[str] = (),
                            production_refs: Sequence[str] = (),
                            required_reproductions: int = REQUIRED_META_REPRODUCTIONS_V1,
                            now: Optional[float] = None) -> MetaOpportunity:
    if weakness_kind not in VALID_WEAKNESS_KINDS:
        raise CrucibleError("INVALID_META_WEAKNESS_KIND", str(weakness_kind))
    if not exact_component_identity:
        raise CrucibleError("META_OPPORTUNITY_REQUIRES_A_COMPONENT_IDENTITY", str(target_component))
    evidence = sorted({str(ref) for ref in evidence_refs} | {str(ref) for ref in production_refs})
    if not evidence:
        # Law 2: dissatisfaction, however strongly felt, is not evidence.
        raise CrucibleError("META_OPPORTUNITY_REQUIRES_EVIDENCE", str(target_component))
    classification = classify_target(db_path, changed_files=[target_component], now=now)
    rationale = sorted({str(ref) for ref in crucible_history_refs} | set(evidence))
    basis = meta_weakness_basis(weakness_kind=weakness_kind, target_component=target_component,
                                exact_component_identity=exact_component_identity)
    opportunity_id = "MO-" + digest(basis)[:16].upper()
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        for ref in rationale:
            connection.execute("INSERT OR IGNORE INTO ciph_meta_opportunity_evidence "
                               "(opportunity_id, evidence_ref, recorded_at) VALUES (?,?,?);",
                               (opportunity_id, ref, moment))
        accumulated = {str(row["evidence_ref"]) for row in connection.execute(
            "SELECT evidence_ref FROM ciph_meta_opportunity_evidence WHERE opportunity_id = ?;",
            (opportunity_id,))}
        if len(accumulated) < int(required_reproductions):
            connection.rollback()
            raise CrucibleError("META_OPPORTUNITY_NOT_REPRODUCIBLE",
                                f"{len(accumulated)}<{required_reproductions}")
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_opportunities (opportunity_id, target_component, "
            "target_ring, exact_component_identity, weakness_kind, crucible_history_refs_json, "
            "production_refs_json, policy_version, required_reproductions, basis_digest, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (opportunity_id, target_component, classification.target_ring,
             exact_component_identity, weakness_kind,
             json.dumps(sorted(str(ref) for ref in crucible_history_refs)),
             json.dumps(sorted(str(ref) for ref in production_refs)),
             META_OPPORTUNITY_REPRODUCIBILITY_V1, int(required_reproductions),
             json.dumps(basis, sort_keys=True), moment))
        connection.commit()
    finally:
        connection.close()
    return get_meta_opportunity(db_path, opportunity_id)


def _accumulated(db_path: str, opportunity_id: str) -> List[str]:
    connection = _connect(db_path, read_only=True)
    try:
        return sorted(str(row["evidence_ref"]) for row in connection.execute(
            "SELECT evidence_ref FROM ciph_meta_opportunity_evidence WHERE opportunity_id = ?;",
            (opportunity_id,)))
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def get_meta_opportunity(db_path: str, opportunity_id: str) -> MetaOpportunity:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_opportunities WHERE opportunity_id = ?;",
                                 (opportunity_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_META_OPPORTUNITY", opportunity_id)
    row = dict(row)
    return MetaOpportunity(
        opportunity_id=str(row["opportunity_id"]), target_component=str(row["target_component"]),
        target_ring=str(row["target_ring"]),
        exact_component_identity=str(row["exact_component_identity"]),
        weakness_kind=str(row["weakness_kind"]),
        evidence_refs=tuple(_accumulated(db_path, opportunity_id)),
        crucible_history_refs=tuple(json.loads(row["crucible_history_refs_json"] or "[]")),
        production_refs=tuple(json.loads(row["production_refs_json"] or "[]")),
        policy_version=str(row["policy_version"]),
        required_reproductions=int(row["required_reproductions"]),
        basis_digest=str(row["basis_digest"]))


def meta_opportunity_status(db_path: str, opportunity_id: str, *,
                            current_component_identity: Optional[str] = None,
                            weakness_present: Optional[bool] = None) -> str:
    try:
        opportunity = get_meta_opportunity(db_path, opportunity_id)
    except CrucibleError:
        return STATUS_INVALID
    if weakness_present is False:
        return STATUS_SATISFIED
    if current_component_identity is not None:
        if str(current_component_identity) != opportunity.exact_component_identity:
            # Law 7: a different version is a different question, not an inherited accusation.
            return STATUS_STALE
    return STATUS_OPEN


def meta_opportunity_history(db_path: str) -> List[MetaOpportunity]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["opportunity_id"]) for row in connection.execute(
            "SELECT opportunity_id FROM ciph_meta_opportunities ORDER BY created_at, opportunity_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_meta_opportunity(db_path, opportunity_id) for opportunity_id in ids]


def meta_opportunity_digest(db_path: str) -> str:
    return digest({"version": META_OPPORTUNITY_V1,
                   "opportunities": [item.as_dict() for item in meta_opportunity_history(db_path)]})


def assert_meta_automatic_path_allowed(opportunity: MetaOpportunity) -> None:
    """Ring 0 is never reachable through the automatic recursive loop."""
    if opportunity.target_ring == RING_CONSTITUTIONAL_ROOT:
        raise CrucibleError("META_RING_0_FORBIDDEN", opportunity.target_component)
