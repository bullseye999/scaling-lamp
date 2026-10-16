"""
ciph/kernel/mission_stewardship - 5.1: long-horizon mission stewardship.

A mission that persists for weeks is a mission that can DRIFT. The law this module exists to enforce:

    persistence of a mission does not permit reinterpretation of its purpose.

Ciph may change PLANS freely - a plan is strategy. Ciph may not change what the mission is FOR. So the
charter is written once, by an operator, and a replan is checked against the charter's purpose digest
before it reaches 4.1. A replan that quietly restates the objective is MISSION_PURPOSE_DRIFT, not a
replan.

The other half is HONEST ENDINGS. A mission may be satisfied, blocked, or abandoned, and each of those
is a recorded decision with evidence - never a mission that simply stops appearing in the plan.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

MISSION_STEWARDSHIP_V1 = "MISSION_STEWARDSHIP_V1"
MISSION_CHARTER_V1 = "MISSION_CHARTER_V1"
MISSION_HEALTH_V1 = "MISSION_HEALTH_V1"
MISSION_MILESTONE_V1 = "MISSION_MILESTONE_V1"

REASON_CHARTER_REQUIRES_OPERATOR = "MISSION_CHARTER_REQUIRES_AN_OPERATOR"
REASON_PURPOSE_DRIFT = "MISSION_PURPOSE_DRIFT"
REASON_NO_CHARTER = "MISSION_HAS_NO_CHARTER"
REASON_MILESTONE_REQUIRES_EVIDENCE = "MILESTONE_SATISFACTION_REQUIRES_EVIDENCE"
REASON_ABANDONMENT_REQUIRES_OPERATOR = "MISSION_ABANDONMENT_REQUIRES_AN_OPERATOR"
REASON_UNKNOWN_CHARTER = "UNKNOWN_MISSION_CHARTER"
REASON_UNKNOWN_MILESTONE = "UNKNOWN_MILESTONE"

# Default staleness horizon for the health projection. A mission with no member action attached and no
# plan after this long is STALLED - a fact about the record, not an opinion about the work.
STALL_AFTER_SECONDS = 7 * 86_400.0

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_mission_charters (
        charter_id TEXT PRIMARY KEY,
        mission_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        purpose_digest TEXT NOT NULL,
        success_criteria_json TEXT,
        constraints_json TEXT,
        opened_by TEXT NOT NULL,
        opened_at REAL,
        superseded_by TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_mission_milestones (
        milestone_id TEXT PRIMARY KEY,
        charter_id TEXT NOT NULL,
        mission_id TEXT NOT NULL,
        label TEXT NOT NULL,
        declared_at REAL,
        satisfied_at REAL,
        evidence_ref TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_mission_abandonment_proposals (
        proposal_id TEXT PRIMARY KEY,
        mission_id TEXT NOT NULL,
        rationale TEXT NOT NULL,
        proposed_at REAL,
        status TEXT NOT NULL
    );
    """,
)

PROPOSAL_OPEN = "OPEN"
PROPOSAL_ACCEPTED = "ACCEPTED"
PROPOSAL_WITHDRAWN = "WITHDRAWN"


def purpose_digest(purpose: str) -> str:
    """The canonical identity of a mission's PURPOSE. Whitespace is not meaning; wording is."""
    normalised = " ".join(str(purpose).split())
    return digest({"charter": MISSION_CHARTER_V1, "purpose": normalised})


@dataclass(frozen=True)
class MissionCharter:
    charter_id: str
    mission_id: str
    purpose: str
    purpose_digest: str
    success_criteria: Tuple[str, ...]
    constraints: Tuple[str, ...]
    opened_by: str

    def as_dict(self) -> Dict[str, Any]:
        return {"charter_id": self.charter_id, "mission_id": self.mission_id,
                "purpose": self.purpose, "purpose_digest": self.purpose_digest,
                "success_criteria": list(self.success_criteria),
                "constraints": list(self.constraints), "opened_by": self.opened_by,
                "policy_version": MISSION_CHARTER_V1}


@dataclass(frozen=True)
class Milestone:
    milestone_id: str
    charter_id: str
    mission_id: str
    label: str
    satisfied_at: Optional[float]
    evidence_ref: Optional[str]

    @property
    def satisfied(self) -> bool:
        return self.satisfied_at is not None

    def as_dict(self) -> Dict[str, Any]:
        return {"milestone_id": self.milestone_id, "charter_id": self.charter_id,
                "mission_id": self.mission_id, "label": self.label,
                "satisfied_at": self.satisfied_at, "evidence_ref": self.evidence_ref,
                "policy_version": MISSION_MILESTONE_V1}


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


def open_charter(db_path: str, *, mission_id: str, purpose: str, actor: str,
                 success_criteria: Sequence[str] = (), constraints: Sequence[str] = (),
                 now: Optional[float] = None) -> MissionCharter:
    """
    Write the ONE charter a mission's purpose is measured against.

    Only an operator identity may state what a mission is for. A daemon that writes its own charter can
    always be correct by its own definition, which is the whole failure mode this program exists to
    prevent - so the gate is here rather than in a caller's good manners.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_CHARTER_REQUIRES_OPERATOR, str(actor))
    if not str(purpose).strip():
        raise CrucibleError("MISSION_CHARTER_REQUIRES_A_PURPOSE", str(mission_id))
    moment = time.time() if now is None else float(now)
    charter_id = "MCH-" + digest({"mission": mission_id, "purpose": purpose_digest(purpose),
                                  "opened_by": actor})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        previous = connection.execute(
            "SELECT charter_id FROM ciph_mission_charters WHERE mission_id = ? "
            "AND superseded_by IS NULL ORDER BY opened_at DESC LIMIT 1;", (mission_id,)).fetchone()
        connection.execute(
            "INSERT OR IGNORE INTO ciph_mission_charters (charter_id, mission_id, purpose, "
            "purpose_digest, success_criteria_json, constraints_json, opened_by, opened_at, "
            "superseded_by) VALUES (?,?,?,?,?,?,?,?,?);",
            (charter_id, mission_id, str(purpose), purpose_digest(purpose),
             json.dumps(sorted(str(item) for item in success_criteria)),
             json.dumps(sorted(str(item) for item in constraints)), str(actor), moment, None))
        if previous is not None and str(previous["charter_id"]) != charter_id:
            connection.execute("UPDATE ciph_mission_charters SET superseded_by = ? WHERE charter_id = ?;",
                               (charter_id, str(previous["charter_id"])))
        connection.commit()
    finally:
        connection.close()
    return get_charter(db_path, charter_id)


def get_charter(db_path: str, charter_id: str) -> MissionCharter:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_mission_charters WHERE charter_id = ?;",
                                 (charter_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_CHARTER, charter_id)
    row = dict(row)
    return MissionCharter(charter_id=str(row["charter_id"]), mission_id=str(row["mission_id"]),
                          purpose=str(row["purpose"]), purpose_digest=str(row["purpose_digest"]),
                          success_criteria=tuple(json.loads(row["success_criteria_json"] or "[]")),
                          constraints=tuple(json.loads(row["constraints_json"] or "[]")),
                          opened_by=str(row["opened_by"]))


def charter_for(db_path: str, mission_id: str) -> Optional[MissionCharter]:
    """The current charter for a mission, or None. A mission without one cannot be revised."""
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute(
            "SELECT charter_id FROM ciph_mission_charters WHERE mission_id = ? "
            "AND superseded_by IS NULL ORDER BY opened_at, charter_id;", (mission_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return get_charter(db_path, str(row["charter_id"])) if row is not None else None


def assert_purpose_unchanged(db_path: str, *, mission_id: str, proposed_objective: str) -> str:
    """
    THE drift gate. A revision may restate strategy; it may not restate purpose.

    Returns the charter id it was checked against. Raises when the purpose moved, and refuses when
    there is no charter at all - an unchartered mission is revised only after its purpose is written
    down, because "we never wrote it down" is exactly how a mission drifts without anyone noticing.
    """
    charter = charter_for(db_path, mission_id)
    if charter is None:
        raise CrucibleError(REASON_NO_CHARTER, str(mission_id))
    if purpose_digest(proposed_objective) != charter.purpose_digest:
        raise CrucibleError(REASON_PURPOSE_DRIFT,
                            f"{str(mission_id)}: proposed purpose differs from {charter.charter_id}")
    return charter.charter_id


def authorize_plan_revision(db_path: str, *, mission_id: str, plan_id: str,
                            logical_action_ids: Sequence[str],
                            objective: Optional[str] = None, version: Optional[int] = None,
                            coverage: str = "COMPLETE", now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record a plan revision through 4.1, after checking it against the charter.

    Strategy is Ciph's. Purpose is not. The check happens BEFORE the projection is written, so a
    drifting revision leaves no trace in the canonical plan history.
    """
    from ciph.kernel.missions import record_plan
    if objective is not None:
        assert_purpose_unchanged(db_path, mission_id=mission_id, proposed_objective=objective)
    else:
        charter = charter_for(db_path, mission_id)
        if charter is None:
            raise CrucibleError(REASON_NO_CHARTER, str(mission_id))
    return record_plan(db_path, mission_id=mission_id, plan_id=plan_id,
                       logical_action_ids=list(logical_action_ids), objective=objective,
                       version=version, coverage=coverage, now=now)


def declare_milestone(db_path: str, *, mission_id: str, label: str,
                      now: Optional[float] = None) -> Milestone:
    charter = charter_for(db_path, mission_id)
    if charter is None:
        raise CrucibleError(REASON_NO_CHARTER, str(mission_id))
    moment = time.time() if now is None else float(now)
    milestone_id = "MMS-" + digest({"charter": charter.charter_id, "label": label})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_mission_milestones (milestone_id, charter_id, mission_id, "
            "label, declared_at, satisfied_at, evidence_ref) VALUES (?,?,?,?,?,?,?);",
            (milestone_id, charter.charter_id, mission_id, str(label), moment, None, None))
        connection.commit()
    finally:
        connection.close()
    return get_milestone(db_path, milestone_id)


def get_milestone(db_path: str, milestone_id: str) -> Milestone:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_mission_milestones WHERE milestone_id = ?;",
                                 (milestone_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_MILESTONE, milestone_id)
    row = dict(row)
    return Milestone(milestone_id=str(row["milestone_id"]), charter_id=str(row["charter_id"]),
                     mission_id=str(row["mission_id"]), label=str(row["label"]),
                     satisfied_at=row["satisfied_at"], evidence_ref=row["evidence_ref"])


def milestones_for(db_path: str, mission_id: str) -> List[Milestone]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["milestone_id"]) for row in connection.execute(
            "SELECT milestone_id FROM ciph_mission_milestones WHERE mission_id = ? "
            "ORDER BY declared_at, milestone_id;", (mission_id,))]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_milestone(db_path, milestone_id) for milestone_id in ids]


def satisfy_milestone(db_path: str, milestone_id: str, *, evidence_ref: str,
                      now: Optional[float] = None) -> Milestone:
    """A milestone is satisfied by EVIDENCE, not by the claim that it is satisfied."""
    if not str(evidence_ref).strip():
        raise CrucibleError(REASON_MILESTONE_REQUIRES_EVIDENCE, str(milestone_id))
    moment = time.time() if now is None else float(now)
    get_milestone(db_path, milestone_id)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "UPDATE ciph_mission_milestones SET satisfied_at = COALESCE(satisfied_at, ?), "
            "evidence_ref = COALESCE(evidence_ref, ?) WHERE milestone_id = ?;",
            (moment, str(evidence_ref), milestone_id))
        connection.commit()
    finally:
        connection.close()
    return get_milestone(db_path, milestone_id)


def detect_purpose_drift(db_path: str, mission_id: str) -> Tuple[str, ...]:
    """
    The SECOND line: which recorded plans no longer match the charter.

    The gate above refuses a drifting revision, but a plan can also reach 4.1 directly. So drift is
    MEASURED against the canonical plan history rather than assumed to be impossible because the front
    door is guarded.
    """
    charter = charter_for(db_path, mission_id)
    if charter is None:
        return ()
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT plan_id, objective FROM ciph_mission_plans WHERE mission_id = ? "
            "ORDER BY version, plan_id;", (mission_id,))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    drifted = []
    for row in rows:
        objective = row["objective"]
        if objective is None:
            continue
        if purpose_digest(str(objective)) != charter.purpose_digest:
            drifted.append(str(row["plan_id"]))
    return tuple(drifted)


def propose_abandonment(db_path: str, *, mission_id: str, rationale: str,
                        now: Optional[float] = None) -> str:
    """Ciph may SAY a mission should end. Saying it confers nothing (see `abandon_mission`)."""
    moment = time.time() if now is None else float(now)
    proposal_id = "MAP-" + digest({"mission": mission_id, "rationale": str(rationale)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_mission_abandonment_proposals (proposal_id, mission_id, "
            "rationale, proposed_at, status) VALUES (?,?,?,?,?);",
            (proposal_id, mission_id, str(rationale), moment, PROPOSAL_OPEN))
        connection.commit()
    finally:
        connection.close()
    return proposal_id


def abandonment_proposals(db_path: str, mission_id: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_mission_abandonment_proposals"
    params: Tuple[Any, ...] = ()
    if mission_id is not None:
        query += " WHERE mission_id = ?"
        params = (mission_id,)
    try:
        return [dict(row) for row in connection.execute(query + " ORDER BY proposed_at, proposal_id;",
                                                        params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def abandon_mission(db_path: str, *, mission_id: str, rationale: str, actor: str,
                    now: Optional[float] = None) -> bool:
    """
    End a mission's life deliberately, and let the canonical row say so.

    Only an operator may do this here. The status write itself belongs to 4.1 - stewardship supplies the
    AUTHORISATION and 4.1 supplies the row, so there is still exactly one writer of mission state.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_ABANDONMENT_REQUIRES_OPERATOR, str(actor))
    from ciph.kernel.missions import abandon_mission as abandon_row
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "UPDATE ciph_mission_abandonment_proposals SET status = ? WHERE mission_id = ? "
            "AND status = ?;", (PROPOSAL_ACCEPTED, mission_id, PROPOSAL_OPEN))
        connection.commit()
    finally:
        connection.close()
    return abandon_row(db_path, mission_id=mission_id, reason=str(rationale), now=moment)


def detect_mission_conflicts(db_path: str) -> List[Dict[str, Any]]:
    """
    Two live missions that claim the same EXCLUSIVE resource.

    The result is a REPORT, not a winner: arbitration between two operator missions is an operator act,
    and picking one silently would be this module substituting its own priority for the operator's.
    """
    from ciph.kernel.missions import MISSION_ACTIVE, reconstruct_missions
    reconstructed = reconstruct_missions(db_path)
    claimed: Dict[str, List[str]] = {}
    for mission in reconstructed.missions:
        if mission.status != MISSION_ACTIVE:
            continue
        charter = charter_for(db_path, mission.mission_id)
        if charter is None:
            continue
        for constraint in charter.constraints:
            text = str(constraint)
            if not text.startswith("exclusive:"):
                continue
            claimed.setdefault(text.split(":", 1)[1], []).append(mission.mission_id)
    return [{"resource": resource, "missions": sorted(mission_ids)}
            for resource, mission_ids in sorted(claimed.items()) if len(mission_ids) > 1]


def mission_health(db_path: str, mission_id: str, *, now: Optional[float] = None,
                   stall_after: float = STALL_AFTER_SECONDS) -> Dict[str, Any]:
    """One projection: is this mission alive, blocked, stalled, drifting, or finished?"""
    from ciph.kernel.missions import reconstruct_missions
    moment = time.time() if now is None else float(now)
    state = reconstruct_missions(db_path, now=moment).state_of(mission_id)
    if state is None:
        raise CrucibleError("UNKNOWN_MISSION", str(mission_id))
    charter = charter_for(db_path, mission_id)
    milestones = milestones_for(db_path, mission_id)
    drifted = detect_purpose_drift(db_path, mission_id)
    age = (moment - float(state.opened_at)) if state.opened_at is not None else 0.0
    blocked = bool(state.obligations) and state.current_plan_id is None
    stalled = (state.status == "ACTIVE" and not state.actions and age > float(stall_after))
    return {"policy_version": MISSION_HEALTH_V1, "mission_id": mission_id, "status": state.status,
            "charter_id": charter.charter_id if charter else None,
            "purpose_digest": charter.purpose_digest if charter else None,
            "milestones": len(milestones),
            "milestones_open": len([item for item in milestones if not item.satisfied]),
            "plan_id": state.current_plan_id, "plan_coverage": state.plan_coverage,
            "actions": len(state.actions), "open_obligations": list(state.obligations),
            "completion_eligible": state.completion_eligible,
            "needs_replanning": state.needs_replanning,
            "drifted_plan_ids": list(drifted),
            "abandonment_proposed": any(item["status"] == PROPOSAL_OPEN
                                        for item in abandonment_proposals(db_path, mission_id)),
            "age_seconds": age, "blocked": blocked, "stalled": stalled,
            "healthy": not blocked and not stalled and not drifted}


def stewardship_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        charters = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_mission_charters ORDER BY opened_at, charter_id;")]
        milestones = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_mission_milestones ORDER BY declared_at, milestone_id;")]
        proposals = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_mission_abandonment_proposals "
            "ORDER BY proposed_at, proposal_id;")]
    except sqlite3.Error:
        charters, milestones, proposals = [], [], []
    finally:
        connection.close()
    return digest({"version": MISSION_STEWARDSHIP_V1, "charters": charters,
                   "milestones": milestones, "abandonment_proposals": proposals})
