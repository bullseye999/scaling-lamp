"""
ciph/kernel/improvement_opportunities - 4.6 Gate Zero: what measured weakness exists?

`ciph/evolution/gap_detector.py` already finds repeated engineering defects and it stays exactly where
it is. What it does not get to do is declare one. Its output is a DETECTOR RESULT, and this module is
the only way that result becomes a canonical opportunity - with the evidence, the reproduction count and
the affected revision that make it more than a story about a bad afternoon.

LAWS
 1. Detector output is not a confirmed weakness.
 2. Every opportunity traces to canonical evidence.
 3. Model dissatisfaction is not evidence of weakness.
 4. One anomalous failure does not establish a reproducible weakness.
 5. Reproducibility requirements are explicit and versioned.
 6. An opportunity is bound to the component, revision and environment where it was observed.
 7. When the weakness disappears the opportunity becomes SATISFIED or STALE - never deleted.
 8. Multiple symptoms may map to one canonical opportunity.
 9. Same canonical weakness basis -> same opportunity identity.
10. Restart reproduces the same registry and digest.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

IMPROVEMENT_OPPORTUNITY_V1 = "IMPROVEMENT_OPPORTUNITY_V1"
OPPORTUNITY_REPRODUCIBILITY_V1 = "OPPORTUNITY_REPRODUCIBILITY_V1"

# The reproducibility requirement is a VERSIONED POLICY, not a piece of metaphysics. Changing it means
# a new policy id, so an opportunity that qualified under V1 stays qualified historically.
REQUIRED_REPRODUCTIONS_V1 = 2

SOURCE_REPEATED_FAILURE = "REPEATED_FAILURE"
SOURCE_CRUCIBLE_REGRESSION = "CRUCIBLE_REGRESSION"
SOURCE_CALIBRATION_WEAKNESS = "CALIBRATION_WEAKNESS"
SOURCE_SELF_MODEL_LIMITATION = "SELF_MODEL_LIMITATION"
SOURCE_RESOURCE_REGRESSION = "RESOURCE_REGRESSION"
SOURCE_MISSING_CAPABILITY = "MISSING_CAPABILITY"
SOURCE_OPERATOR_REQUEST = "OPERATOR_REQUEST"
VALID_SOURCE_KINDS = (SOURCE_REPEATED_FAILURE, SOURCE_CRUCIBLE_REGRESSION,
                      SOURCE_CALIBRATION_WEAKNESS, SOURCE_SELF_MODEL_LIMITATION,
                      SOURCE_RESOURCE_REGRESSION, SOURCE_MISSING_CAPABILITY,
                      SOURCE_OPERATOR_REQUEST)

# The legacy GapCategory vocabulary, mapped rather than re-invented.
GAP_CATEGORY_MAP = {"DEFECT": SOURCE_REPEATED_FAILURE,
                    "MISSING_TELEMETRY": SOURCE_CALIBRATION_WEAKNESS,
                    "MISSING_BEHAVIOR": SOURCE_REPEATED_FAILURE,
                    "OPERATIONAL_INEFFICIENCY": SOURCE_RESOURCE_REGRESSION}

STATUS_OPEN = "OPEN"
STATUS_STALE = "STALE"
STATUS_SATISFIED = "SATISFIED"
STATUS_INVALID = "INVALID"
VALID_STATUSES = (STATUS_OPEN, STATUS_STALE, STATUS_SATISFIED, STATUS_INVALID)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_improvement_opportunity_evidence (
        opportunity_id TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        recorded_at REAL,
        PRIMARY KEY (opportunity_id, evidence_ref)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_improvement_opportunities (
        opportunity_id TEXT PRIMARY KEY,
        source_kind TEXT NOT NULL,
        affected_component TEXT NOT NULL,
        affected_revision TEXT,
        environment_identity TEXT,
        weakness_description TEXT,
        evidence_refs_json TEXT NOT NULL,
        reproduction_refs_json TEXT NOT NULL,
        measurable_impact_json TEXT,
        improvement_criterion TEXT,
        policy_version TEXT NOT NULL,
        required_reproductions INTEGER NOT NULL,
        source_detector TEXT,
        basis_digest TEXT NOT NULL,
        created_at REAL
    );
    """,
)


@dataclass(frozen=True)
class ImprovementOpportunity:
    opportunity_id: str
    source_kind: str
    affected_component: str
    affected_revision: Optional[str]
    environment_identity: Optional[str]
    weakness_description: Optional[str]
    evidence_refs: Tuple[str, ...]
    reproduction_refs: Tuple[str, ...]
    measurable_impact: Optional[Dict[str, Any]]
    improvement_criterion: Optional[str]
    policy_version: str
    required_reproductions: int
    source_detector: Optional[str]
    basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"opportunity_id": self.opportunity_id, "source_kind": self.source_kind,
                "affected_component": self.affected_component,
                "affected_revision": self.affected_revision,
                "environment_identity": self.environment_identity,
                "weakness_description": self.weakness_description,
                "evidence_refs": list(self.evidence_refs),
                "reproduction_refs": list(self.reproduction_refs),
                "measurable_impact": self.measurable_impact,
                "improvement_criterion": self.improvement_criterion,
                "policy_version": self.policy_version,
                "required_reproductions": self.required_reproductions,
                "source_detector": self.source_detector, "basis_digest": self.basis_digest}


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


def _field(gap: Any, name: str, default: Any = None) -> Any:
    if isinstance(gap, Mapping):
        return gap.get(name, default)
    return getattr(gap, name, default)


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [str(value)]
    try:
        return [str(item) for item in value]
    except TypeError:
        return [str(value)]


def weakness_basis(*, source_kind: str, affected_component: str, affected_revision: Optional[str],
                   environment_identity: Optional[str], symptom_signature: Optional[str],
                   policy_version: str = OPPORTUNITY_REPRODUCIBILITY_V1) -> Dict[str, Any]:
    """
    THE identity basis (law 9). It is the WEAKNESS, not the pile of evidence for it.

    Two symptoms of the same defect in the same revision under the same environment are ONE
    opportunity (law 8). If evidence refs were part of the basis, a third observation would mint a
    third opportunity and the registry would fill with duplicates of one problem.
    """
    return {"policy_version": policy_version, "source_kind": source_kind,
            "affected_component": affected_component,
            "affected_revision": affected_revision,
            "environment_identity": environment_identity,
            "symptom_signature": symptom_signature}


def opportunity_id_for(basis: Mapping[str, Any]) -> str:
    return "OPP-" + digest(basis)[:16].upper()


def adopt_gap(db_path: str, gap: Any, *, environment_identity: Optional[str] = None,
              source_detector: Optional[str] = "ciph/evolution/gap_detector.py",
              required_reproductions: int = REQUIRED_REPRODUCTIONS_V1,
              now: Optional[float] = None) -> ImprovementOpportunity:
    """
    Constitutionalize ONE detector result.

    The legacy `EngineeringGapCandidate` is accepted as data (mapping or object); nothing here imports
    its class, so the detector keeps its own model and this module keeps the canonical one.
    """
    moment = time.time() if now is None else float(now)
    evidence = _as_list(_field(gap, "failure_evidence_hashes"))
    reproductions = _as_list(_field(gap, "reproduction_refs")) or evidence
    category = str(_field(gap, "category", "DEFECT"))
    source_kind = GAP_CATEGORY_MAP.get(category.upper(), SOURCE_REPEATED_FAILURE)
    component = str(_field(gap, "target_capability", "")).strip()
    revision = _field(gap, "affected_revision")

    if not component:
        raise CrucibleError("OPPORTUNITY_REQUIRES_A_COMPONENT", repr(component))
    if not evidence:
        # Law 2: a detector result with no evidence is a story, not a weakness.
        raise CrucibleError("OPPORTUNITY_REQUIRES_EVIDENCE", str(_field(gap, "gap_id", "")))
    if len(set(reproductions) | set(evidence)) < int(required_reproductions):
        # Law 4: one anomalous failure is not a reproducible weakness. The threshold is judged on the
        # ACCUMULATED evidence, so an opportunity already on record is not re-refused for being re-seen.
        already = _accumulated_evidence(db_path, opportunity_id_for(weakness_basis(
            source_kind=source_kind, affected_component=component, affected_revision=revision,
            environment_identity=environment_identity,
            symptom_signature=(None if _field(gap, "testable_improvement_criterion") is None
                               else str(_field(gap, "testable_improvement_criterion"))))))
        if len(set(reproductions) | set(evidence) | set(already)) < int(required_reproductions):
            raise CrucibleError("OPPORTUNITY_NOT_REPRODUCIBLE",
                                f"{len(set(reproductions) | set(evidence))}<{required_reproductions}")

    symptom = _field(gap, "testable_improvement_criterion")
    basis = weakness_basis(source_kind=source_kind, affected_component=component,
                           affected_revision=revision, environment_identity=environment_identity,
                           symptom_signature=(None if symptom is None else str(symptom)))
    opportunity_id = opportunity_id_for(basis)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        for ref in sorted(set(reproductions) | set(evidence)):
            connection.execute("INSERT OR IGNORE INTO ciph_improvement_opportunity_evidence "
                               "(opportunity_id, evidence_ref, recorded_at) VALUES (?,?,?);",
                               (opportunity_id, str(ref), moment))
        existing = connection.execute(
            "SELECT 1 FROM ciph_improvement_opportunities WHERE opportunity_id = ?;",
            (opportunity_id,)).fetchone()
        if existing is None:
            connection.execute(
                "INSERT INTO ciph_improvement_opportunities (opportunity_id, source_kind, "
                "affected_component, affected_revision, environment_identity, weakness_description, "
                "evidence_refs_json, reproduction_refs_json, measurable_impact_json, "
                "improvement_criterion, policy_version, required_reproductions, source_detector, "
                "basis_digest, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
                (opportunity_id, source_kind, component, revision, environment_identity,
                 _field(gap, "weakness_description"), json.dumps(sorted(evidence)),
                 json.dumps(sorted(reproductions)),
                 json.dumps(_field(gap, "measured_impact") or {}, sort_keys=True, default=str),
                 _field(gap, "testable_improvement_criterion"),
                 OPPORTUNITY_REPRODUCIBILITY_V1, int(required_reproductions), source_detector,
                 json.dumps(basis, sort_keys=True), moment))
        # The COMMIT is outside the branch on purpose: a second observation of a known weakness adds
        # evidence without a new opportunity, and that evidence must still be durable.
        connection.commit()
    finally:
        connection.close()
    return get_opportunity(db_path, opportunity_id)


def record_operator_request(db_path: str, *, affected_component: str, weakness_description: str,
                            evidence_refs: Sequence[str], affected_revision: Optional[str] = None,
                            environment_identity: Optional[str] = None,
                            improvement_criterion: Optional[str] = None,
                            now: Optional[float] = None) -> ImprovementOpportunity:
    """
    An operator may raise a weakness too - and it still has to cite evidence (law 3).

    There is no function that accepts a model's opinion of itself as the basis for an opportunity;
    dissatisfaction is not evidence.
    """
    refs = _as_list(evidence_refs)
    if not refs:
        raise CrucibleError("OPPORTUNITY_REQUIRES_EVIDENCE", "operator request cited nothing")
    return adopt_gap(db_path, {"gap_id": f"OPS-{digest([affected_component, sorted(refs)])[:12]}",
                               "category": "OPERATIONAL_INEFFICIENCY",
                               "target_capability": affected_component,
                               "affected_revision": affected_revision,
                               "failure_evidence_hashes": refs,
                               "weakness_description": weakness_description,
                               "testable_improvement_criterion": improvement_criterion},
                     environment_identity=environment_identity,
                     source_detector="operator", required_reproductions=1, now=now)


def _accumulated_evidence(db_path: str, opportunity_id: str) -> List[str]:
    connection = _connect(db_path, read_only=True)
    try:
        return sorted(str(row["evidence_ref"]) for row in connection.execute(
            "SELECT evidence_ref FROM ciph_improvement_opportunity_evidence "
            "WHERE opportunity_id = ?;", (opportunity_id,)))
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def opportunity_evidence(db_path: str, opportunity_id: str) -> List[str]:
    """Every observation ever attached to one weakness, oldest-compatible order."""
    return _accumulated_evidence(db_path, opportunity_id)


def get_opportunity(db_path: str, opportunity_id: str) -> ImprovementOpportunity:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_improvement_opportunities WHERE "
                                 "opportunity_id = ?;", (opportunity_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_OPPORTUNITY", opportunity_id)
    row = dict(row)
    return ImprovementOpportunity(
        opportunity_id=str(row["opportunity_id"]), source_kind=str(row["source_kind"]),
        affected_component=str(row["affected_component"]), affected_revision=row["affected_revision"],
        environment_identity=row["environment_identity"],
        weakness_description=row["weakness_description"],
        evidence_refs=tuple(sorted(_accumulated_evidence(db_path, str(row["opportunity_id"]))
                                   or json.loads(row["evidence_refs_json"] or "[]"))),
        reproduction_refs=tuple(json.loads(row["reproduction_refs_json"] or "[]")),
        measurable_impact=json.loads(row["measurable_impact_json"] or "{}"),
        improvement_criterion=row["improvement_criterion"], policy_version=str(row["policy_version"]),
        required_reproductions=int(row["required_reproductions"]),
        source_detector=row["source_detector"], basis_digest=str(row["basis_digest"]))


def opportunity_status(db_path: str, opportunity_id: str, *, current_revision: Optional[str] = None,
                       weakness_present: Optional[bool] = None) -> str:
    """
    DERIVED status (law 7). A weakness that stopped reproducing is SATISFIED, not erased: the record of
    having had the weakness is what makes the later improvement meaningful.
    """
    try:
        opportunity = get_opportunity(db_path, opportunity_id)
    except CrucibleError:
        return STATUS_INVALID
    if weakness_present is False:
        return STATUS_SATISFIED
    if current_revision is not None and opportunity.affected_revision is not None:
        if str(current_revision) != str(opportunity.affected_revision):
            return STATUS_STALE if weakness_present is None else STATUS_SATISFIED
    return STATUS_OPEN


def opportunity_history(db_path: str) -> List[ImprovementOpportunity]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["opportunity_id"]) for row in connection.execute(
            "SELECT opportunity_id FROM ciph_improvement_opportunities "
            "ORDER BY created_at, opportunity_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_opportunity(db_path, opportunity_id) for opportunity_id in ids]


def opportunity_digest(db_path: str) -> str:
    return digest({"version": IMPROVEMENT_OPPORTUNITY_V1,
                   "opportunities": [item.as_dict() for item in opportunity_history(db_path)]})
