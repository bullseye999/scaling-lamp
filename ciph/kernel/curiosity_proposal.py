"""
ciph.kernel.curiosity_proposal - HOW an uncertainty could be reduced, as a PROPOSAL only.

4.4 Gate Two.

ABSOLUTE LAW
    A curiosity proposal grants ZERO execution authority.

A proposal is a statement of intent. Accepting it records a governance decision and still creates no
job, no permit and no action; only the 4.0 execution throat can do that, and only when a caller walks
the normal mission/action/permit path (see `governed_investigation`).

    investigation_type
        QUERY_EXISTING_EVIDENCE   re-read what is already durable
        OBSERVE                   take a new observation through governed execution
        COMPARE                   contrast two existing states
        RESEARCH                  consult an external source
        TEST_HYPOTHESIS           run the falsification a causal hypothesis needs
        RUN_SIMULATION            a counterfactual only - it can never become evidence
        REQUEST_OPERATOR_INPUT    ask a human
        DO_NOTHING                the honest recommendation that this is not worth reducing

LAWS (each has a specimen in `test_gate_4_4_curiosity_proposal.py`)

 1. Curiosity proposal != action.
 2. Proposal != permit.
 3. A proposal cannot fabricate a logical action identity.
 4. A proposal binds to the uncertainty basis it was generated from.
 5. If the uncertainty changes before acceptance -> STALE_CURIOSITY_PROPOSAL.
 6. A proposal cannot broaden capability or scope (it may only REQUEST capabilities).
 7. Simulation-only investigations remain simulations.
 8. External observation must cross the normal mission/action/permit boundary.
 9. A proposal may recommend "do nothing".
10. A rejected curiosity remains historical.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.uncertainty_registry import uncertainty

TYPE_QUERY_EXISTING_EVIDENCE = "QUERY_EXISTING_EVIDENCE"
TYPE_OBSERVE = "OBSERVE"
TYPE_COMPARE = "COMPARE"
TYPE_RESEARCH = "RESEARCH"
TYPE_TEST_HYPOTHESIS = "TEST_HYPOTHESIS"
TYPE_RUN_SIMULATION = "RUN_SIMULATION"
TYPE_REQUEST_OPERATOR_INPUT = "REQUEST_OPERATOR_INPUT"
TYPE_DO_NOTHING = "DO_NOTHING"
VALID_INVESTIGATION_TYPES = (TYPE_QUERY_EXISTING_EVIDENCE, TYPE_OBSERVE, TYPE_COMPARE, TYPE_RESEARCH,
                             TYPE_TEST_HYPOTHESIS, TYPE_RUN_SIMULATION, TYPE_REQUEST_OPERATOR_INPUT,
                             TYPE_DO_NOTHING)

# Types whose whole point is to touch the world. Naming the set makes law 8 checkable rather than
# implicit: these are the ones that MUST cross the execution boundary before anything happens.
EXTERNAL_TYPES = (TYPE_OBSERVE, TYPE_RESEARCH, TYPE_TEST_HYPOTHESIS)

STATUS_PROPOSED = "PROPOSED"
STATUS_ACCEPTED = "ACCEPTED"
STATUS_REJECTED = "REJECTED"
STATUS_STALE = "STALE"
VALID_PROPOSAL_STATUSES = (STATUS_PROPOSED, STATUS_ACCEPTED, STATUS_REJECTED, STATUS_STALE)

REASON_BASIS_MOVED = "STALE_CURIOSITY_PROPOSAL"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_curiosity_proposals (
        proposal_id TEXT PRIMARY KEY,
        uncertainty_id TEXT NOT NULL,
        investigation_type TEXT NOT NULL,
        basis_digest TEXT NOT NULL,
        expected_resolution_conditions_json TEXT,
        required_capabilities_json TEXT,
        estimated_cost REAL,
        estimated_risk REAL,
        rationale TEXT,
        proposed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_curiosity_proposal_decisions (
        decision_id TEXT PRIMARY KEY,
        proposal_id TEXT NOT NULL,
        decision TEXT NOT NULL,
        actor TEXT,
        reason TEXT,
        decided_at REAL
    );
    """,
)


class CuriosityProposalError(Exception):
    """A proposal operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class CuriosityProposal:
    proposal_id: str
    uncertainty_id: str
    investigation_type: str
    basis_digest: str
    expected_resolution_conditions: Tuple[str, ...]
    required_capabilities: Tuple[str, ...]
    estimated_cost: Optional[float]
    estimated_risk: Optional[float]
    rationale: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"proposal_id": self.proposal_id, "uncertainty_id": self.uncertainty_id,
                "investigation_type": self.investigation_type, "basis_digest": self.basis_digest,
                "expected_resolution_conditions": list(self.expected_resolution_conditions),
                "required_capabilities": list(self.required_capabilities),
                "estimated_cost": self.estimated_cost, "estimated_risk": self.estimated_risk,
                "rationale": self.rationale}

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


def propose_investigation(db_path: str, *, uncertainty_id: str, investigation_type: str,
                          expected_resolution_conditions: Sequence[str] = (),
                          required_capabilities: Sequence[str] = (),
                          estimated_cost: Optional[float] = None,
                          estimated_risk: Optional[float] = None,
                          rationale: Optional[str] = None,
                          now: Optional[float] = None) -> CuriosityProposal:
    """
    Record ONE proposal, bound to the uncertainty's CURRENT basis (law 4).

    Identity is canonical: the same investigation of the same uncertainty on the same basis is one
    proposal, so re-phrasing generates no second attempt (and no second scoring opportunity).
    """
    if investigation_type not in VALID_INVESTIGATION_TYPES:
        raise CuriosityProposalError("INVALID_INVESTIGATION_TYPE", str(investigation_type))
    moment = time.time() if now is None else float(now)
    record = uncertainty(db_path, uncertainty_id, now=moment)
    if record is None:
        raise CuriosityProposalError("UNKNOWN_UNCERTAINTY", uncertainty_id)

    conditions = sorted(str(item) for item in expected_resolution_conditions)
    capabilities = sorted(str(item) for item in required_capabilities)
    basis = record.basis_digest
    proposal_id = "CP-" + hashlib.sha256(
        json.dumps({"uncertainty": uncertainty_id, "type": investigation_type, "basis": basis,
                    "conditions": conditions, "capabilities": capabilities},
                   sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:12].upper()
    conn = _connect(db_path)
    try:
        init_schema(conn)
        existing = conn.execute("SELECT 1 FROM ciph_curiosity_proposals WHERE proposal_id = ?;",
                                (proposal_id,)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO ciph_curiosity_proposals (proposal_id, uncertainty_id, "
                "investigation_type, basis_digest, expected_resolution_conditions_json, "
                "required_capabilities_json, estimated_cost, estimated_risk, rationale, proposed_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?);",
                (proposal_id, uncertainty_id, investigation_type, basis, json.dumps(conditions),
                 json.dumps(capabilities), estimated_cost, estimated_risk, rationale, moment),
            )
            conn.commit()
    finally:
        conn.close()
    return CuriosityProposal(proposal_id=proposal_id, uncertainty_id=uncertainty_id,
                             investigation_type=investigation_type, basis_digest=basis,
                             expected_resolution_conditions=tuple(conditions),
                             required_capabilities=tuple(capabilities),
                             estimated_cost=estimated_cost, estimated_risk=estimated_risk,
                             rationale=rationale)


def recommend_do_nothing(db_path: str, *, uncertainty_id: str, rationale: str = "",
                         now: Optional[float] = None) -> CuriosityProposal:
    """Law 9: "this is not worth reducing" is a legitimate, recordable conclusion."""
    return propose_investigation(db_path, uncertainty_id=uncertainty_id,
                                 investigation_type=TYPE_DO_NOTHING, rationale=rationale, now=now)


def _row_to_proposal(row: Dict[str, Any]) -> CuriosityProposal:
    return CuriosityProposal(
        proposal_id=str(row["proposal_id"]), uncertainty_id=str(row["uncertainty_id"]),
        investigation_type=str(row["investigation_type"]), basis_digest=str(row["basis_digest"]),
        expected_resolution_conditions=tuple(json.loads(
            row["expected_resolution_conditions_json"] or "[]")),
        required_capabilities=tuple(json.loads(row["required_capabilities_json"] or "[]")),
        estimated_cost=row["estimated_cost"], estimated_risk=row["estimated_risk"],
        rationale=row["rationale"])


def get_proposal(db_path: str, proposal_id: str) -> CuriosityProposal:
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute("SELECT * FROM ciph_curiosity_proposals WHERE proposal_id = ?;",
                           (proposal_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    if row is None:
        raise CuriosityProposalError("UNKNOWN_PROPOSAL", proposal_id)
    return _row_to_proposal(dict(row))


def _decision(db_path: str, proposal_id: str) -> Optional[Dict[str, Any]]:
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute("SELECT * FROM ciph_curiosity_proposal_decisions WHERE proposal_id = ? "
                           "ORDER BY decided_at, decision_id LIMIT 1;", (proposal_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    return dict(row) if row is not None else None


def proposal_status(db_path: str, proposal_id: str, *, now: Optional[float] = None) -> str:
    """
    DERIVED. A proposal generated against a state that has since moved is STALE, not valid (law 5) -
    the same optimistic-concurrency rule the planner boundary uses.
    """
    moment = time.time() if now is None else float(now)
    proposal = get_proposal(db_path, proposal_id)
    decision = _decision(db_path, proposal_id)
    if decision is not None:
        return str(decision["decision"])
    current = uncertainty(db_path, proposal.uncertainty_id, now=moment)
    if current is None or current.basis_digest != proposal.basis_digest:
        return STATUS_STALE
    return STATUS_PROPOSED


def _record_decision(db_path: str, proposal_id: str, decision: str, *, actor: Optional[str],
                     reason: str, now: Optional[float]) -> str:
    moment = time.time() if now is None else float(now)
    status = proposal_status(db_path, proposal_id, now=moment)
    if status in (STATUS_ACCEPTED, STATUS_REJECTED):
        raise CuriosityProposalError("PROPOSAL_ALREADY_DECIDED", f"{proposal_id}:{status}")
    if status == STATUS_STALE:
        raise CuriosityProposalError(REASON_BASIS_MOVED, proposal_id)
    decision_id = "CD-" + hashlib.sha256(
        f"{proposal_id}:{decision}:{actor}:{moment}".encode("utf-8")).hexdigest()[:12].upper()
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute("INSERT OR IGNORE INTO ciph_curiosity_proposal_decisions (decision_id, "
                     "proposal_id, decision, actor, reason, decided_at) VALUES (?,?,?,?,?,?);",
                     (decision_id, proposal_id, decision, actor, reason, moment))
        conn.commit()
    finally:
        conn.close()
    return decision_id


def accept_proposal(db_path: str, proposal_id: str, *, actor: Optional[str] = None,
                    reason: str = "", now: Optional[float] = None) -> str:
    """
    Record a governance decision. ACCEPTED still authorises nothing: it is a permission to *prepare*
    an investigation through the normal mission/action/permit path, never an execution (laws 1, 2).
    """
    return _record_decision(db_path, proposal_id, STATUS_ACCEPTED, actor=actor, reason=reason,
                            now=now)


def reject_proposal(db_path: str, proposal_id: str, *, actor: Optional[str] = None,
                    reason: str = "", now: Optional[float] = None) -> str:
    """A rejection is history, not a deletion (law 10)."""
    return _record_decision(db_path, proposal_id, STATUS_REJECTED, actor=actor, reason=reason,
                            now=now)


def proposal_history(db_path: str) -> List[Dict[str, Any]]:
    """Every proposal ever made, oldest first, with its decision if any."""
    conn = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT p.*, d.decision, d.actor, d.reason, d.decided_at FROM ciph_curiosity_proposals p "
            "LEFT JOIN ciph_curiosity_proposal_decisions d ON d.proposal_id = p.proposal_id "
            "ORDER BY p.proposed_at, p.proposal_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return rows


def proposal_digest(db_path: str) -> str:
    return _digest(proposal_history(db_path))
