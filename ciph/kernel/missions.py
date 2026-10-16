"""
ciph.kernel.missions - durable mission identity, immutable plan projections, completion.

4.1 Gate One (missions) and Gate Two (plans). Gate Zero answers *what is true*; a mission answers
*what unfinished purpose those truths belong to*; a plan answers *how that purpose might proceed* -
and nothing more than that.

    Mission M            durable identity and intent          survives everything below
        ↓
    logical actions      durable identity of work             survives replanning
        ↓
    attempts / evidence  what actually happened               Gate Zero reconstructs it
        ↓
    plans                IMMUTABLE projections over actions   append-only; never authority
        ↓
    scheduler            a mechanism for advancing work       never a source of truth
        ↓
    permits              authority for one execution          central mint only

GATE ONE LAWS (missions)
 1. MISSION IDENTITY.            One stable identity across restart and replanning.
 2. NO AUTHORITY BY EXISTENCE.   A mission existing authorises nothing.
 3. ACTIONS OUTLIVE PLANS.       Membership is independent of any plan version.
 4. PLAN != TRUTH.               A projection cannot erase history.
 5. RESTART != REPLAN.           Reconstruction comes first; `needs_replanning` is derived.
 6. UNRESOLVED WORK SURVIVES.    Obligations stay attached to the mission.
 7. TERMINAL WORK STAYS DEAD.    A new plan mentioning it does not revive it.
 8. NO DUPLICATED ACTION IDENTITY. Reuse is explicit; a plan cannot rename an old action as new.
 9. COMPLETION IS EVIDENCE-BASED.  Unresolved work and live unattempted authority block closure.

GATE TWO LAWS (plans)
10. PLAN IS NOT AUTHORITY.        Creating or selecting a plan issues no permits and enables nothing.
11. PLAN IS NOT HISTORY.          A plan cannot alter outcomes, claims, obligations or evidence.
12. PLAN VERSION IS IMMUTABLE.    Once recorded, a projection's references and rationale never change.
13. OLD PLANS REMAIN HISTORICAL.  Superseding is a pointer move, never a delete or an edit.
14. ACTION IDENTITY SURVIVES REPLANNING. Reuse is by explicit id; similarity is never enough.
15. SAME ACTION CANNOT CHANGE SEMANTICS. A reference whose canonical fingerprint disagrees is a HARD
    CONFLICT - if the work changed semantically it is a new action, not a mutated one.
16. NEW SEMANTIC WORK -> NEW ACTION.
17. REPLANNING CANNOT RESURRECT TERMINAL WORK.
18. REPLANNING CANNOT ERASE UNCERTAINTY.
19. PLAN OMISSION != CANCELLATION. Dropping an action from a plan revokes nothing and cancels
    nothing; cancellation/revocation is an explicit governed transition.
20. CURRENT-PLAN POINTER IS A PROJECTION. Losing it loses no mission truth.
21. DETERMINISTIC RECONSTRUCTION. Same history -> same projection and digest.

DIRECTION OF INFERENCE, ALWAYS:
    truth -> plan projection
never
    plan says A is done -> therefore A is done
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.continuity import ActionContinuity, ContinuityState, reconstruct

MISSION_ACTIVE = "ACTIVE"
MISSION_COMPLETED = "COMPLETED"
MISSION_ABANDONED = "ABANDONED"

# COVERAGE. A projection states whether it is an EXHAUSTIVE strategy or an ADDITIVE patch.
#   COMPLETE -> absence means "not scheduled now" (omitted, never cancelled)
#   PATCH    -> absence means NOTHING, because a truncated or partial planner response must never be
#               able to pause work by failing to mention it
PLAN_COVERAGE_COMPLETE = "COMPLETE"
PLAN_COVERAGE_PATCH = "PATCH"
VALID_COVERAGE = (PLAN_COVERAGE_COMPLETE, PLAN_COVERAGE_PATCH)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_missions (
        mission_id TEXT PRIMARY KEY,
        objective TEXT,
        opened_at REAL,
        status TEXT NOT NULL,
        closed_at REAL,
        close_reason TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_mission_actions (
        mission_id TEXT NOT NULL,
        logical_action_id TEXT NOT NULL,
        attached_at REAL,
        origin_plan_id TEXT,
        PRIMARY KEY (mission_id, logical_action_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_mission_plans (
        plan_id TEXT PRIMARY KEY,
        mission_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        objective TEXT,
        created_at REAL,
        superseded_by TEXT,
        coverage TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_plan_actions (
        plan_id TEXT NOT NULL,
        logical_action_id TEXT NOT NULL,
        semantic_fingerprint TEXT,
        PRIMARY KEY (plan_id, logical_action_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_mission_current_plan (
        mission_id TEXT PRIMARY KEY,
        plan_id TEXT NOT NULL,
        updated_at REAL
    );
    """,
)

_ADDITIVE_COLUMNS = (
    ("ciph_plan_actions", "semantic_fingerprint", "TEXT"),
    ("ciph_mission_plans", "coverage", "TEXT"),
)


class MissionError(Exception):
    """A mission or plan operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class PlanProjection:
    """One immutable plan projection: what a strategy proposed, and what it believed about it."""

    plan_id: str
    mission_id: str
    version: int
    objective: Optional[str]
    created_at: Optional[float]
    action_ids: Tuple[str, ...]
    action_fingerprints: Tuple[Tuple[str, Optional[str]], ...]
    coverage: str
    is_current: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "mission_id": self.mission_id,
            "version": self.version,
            "objective": self.objective,
            "created_at": self.created_at,
            "action_ids": list(self.action_ids),
            "action_fingerprints": {k: v for k, v in self.action_fingerprints},
            "coverage": self.coverage,
            "is_current": self.is_current,
        }


@dataclass(frozen=True)
class NewActionProposal:
    """
    Semantic work the planner wants to exist, WITHOUT an identity.

    The planner does not choose the durable logical action id; the canonical mission layer allocates
    it when the proposal is accepted. That is deliberate: an LLM that could name identities could
    accidentally (or conveniently) re-use one, and identity reuse is the thing D4 protects.
    """

    capability: str
    parameters: Mapping[str, Any] = None
    target: Optional[str] = None
    label: Optional[str] = None


@dataclass(frozen=True)
class PlanProposal:
    """
    What a planner proposes, bound to the state it planned against.

    `basis_continuity_digest` is optimistic concurrency for cognition: the proposal is only valid
    against the mission state whose digest it was generated from. A planner need not be deterministic;
    it only must not be able to commit a projection generated against stale truth.
    """

    mission_id: str
    basis_continuity_digest: str
    plan_id: Optional[str] = None
    objective: Optional[str] = None
    existing_action_refs: Tuple[Tuple[str, Optional[str]], ...] = ()
    new_action_proposals: Tuple[NewActionProposal, ...] = ()
    coverage: str = PLAN_COVERAGE_COMPLETE
    rationale: Optional[str] = None
    planner_metadata: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class MissionState:
    """One mission, as the durable record proves it right now."""

    mission_id: str
    objective: Optional[str]
    status: str
    opened_at: Optional[float]
    actions: Tuple[ActionContinuity, ...]
    current_plan_id: Optional[str]
    plan_coverage: Optional[str]
    plan_action_ids: Tuple[str, ...]
    omitted_action_ids: Tuple[str, ...]
    unauthorised_action_ids: Tuple[str, ...]
    plan_history: Tuple[PlanProjection, ...]
    obligations: Tuple[str, ...]
    unresolved_attempts: Tuple[str, ...]
    completion_obligations: Tuple[str, ...]
    remaining_authorized_work: Tuple[str, ...]
    completion_eligible: bool
    needs_replanning: bool

    @property
    def plan_ids(self) -> Tuple[str, ...]:
        """The current projection, if the pointer resolves. Kept for the Gate One surface."""
        return (self.current_plan_id,) if self.current_plan_id else ()

    @property
    def historical_plan_ids(self) -> Tuple[str, ...]:
        return tuple(p.plan_id for p in self.plan_history)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "objective": self.objective,
            "status": self.status,
            "actions": [a.as_dict() for a in self.actions],
            "current_plan_id": self.current_plan_id,
            "plan_coverage": self.plan_coverage,
            "plan_action_ids": list(self.plan_action_ids),
            "omitted_action_ids": list(self.omitted_action_ids),
            "unauthorised_action_ids": list(self.unauthorised_action_ids),
            "plan_history": [p.as_dict() for p in self.plan_history],
            "obligations": list(self.obligations),
            "unresolved_attempts": list(self.unresolved_attempts),
            "completion_obligations": list(self.completion_obligations),
            "remaining_authorized_work": list(self.remaining_authorized_work),
            "completion_eligible": self.completion_eligible,
            "needs_replanning": self.needs_replanning,
        }

    def canonical_digest(self) -> str:
        blob = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MissionContinuity:
    """Every mission, reconstructed from canonical evidence."""

    missions: Tuple[MissionState, ...] = ()
    contested_actions: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {"missions": [m.as_dict() for m in self.missions],
                "contested_actions": list(self.contested_actions)}

    def canonical_digest(self) -> str:
        blob = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def state_of(self, mission_id: str) -> Optional[MissionState]:
        for mission in self.missions:
            if mission.mission_id == mission_id:
                return mission
        return None


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


def init_mission_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)
    for table, column, kind in _ADDITIVE_COLUMNS:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind};")
        except sqlite3.Error:
            pass   # already present


# ---------------------------------------------------------------------------- writes (explicit)
def open_mission(db_path: str, *, objective: str, mission_id: Optional[str] = None,
                 now: Optional[float] = None) -> str:
    """Create a mission identity. This grants NO authority - see law 2."""
    moment = time.time() if now is None else float(now)
    identity = mission_id or f"MSN-{uuid.uuid4().hex[:12].upper()}"
    conn = _connect(db_path)
    try:
        init_mission_schema(conn)
        conn.execute(
            "INSERT INTO ciph_missions (mission_id, objective, opened_at, status) "
            "VALUES (?, ?, ?, ?);",
            (identity, objective, moment, MISSION_ACTIVE),
        )
        conn.commit()
    finally:
        conn.close()
    return identity


def attach_action(db_path: str, *, mission_id: str, logical_action_id: str,
                  origin_plan_id: Optional[str] = None, now: Optional[float] = None) -> bool:
    """
    Attach a logical action to a mission. Idempotent by (mission, action): attaching twice neither
    duplicates the action nor advances anything. Returns True when this call created the membership.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_mission_schema(conn)
        existing = conn.execute(
            "SELECT 1 FROM ciph_mission_actions WHERE mission_id = ? AND logical_action_id = ?;",
            (mission_id, logical_action_id),
        ).fetchone()
        if existing:
            return False
        conn.execute(
            "INSERT INTO ciph_mission_actions (mission_id, logical_action_id, attached_at, origin_plan_id) "
            "VALUES (?, ?, ?, ?);",
            (mission_id, logical_action_id, moment, origin_plan_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def _canonical_fingerprint(conn: sqlite3.Connection, logical_action_id: str) -> Optional[str]:
    """
    The action's canonical semantic fingerprint, taken from the AUTHORITY record - never from a plan.

    `execution_permits.action_fingerprint` is what the central authority bound when it authorised this
    logical action, so it is the honest answer to "what work is this?". A plan that disagrees with it
    is proposing different work under an old name.
    """
    try:
        row = conn.execute(
            "SELECT action_fingerprint FROM execution_permits "
            "WHERE logical_action_id = ? AND action_fingerprint IS NOT NULL LIMIT 1;",
            (logical_action_id,),
        ).fetchone()
    except sqlite3.Error:
        return None
    return row["action_fingerprint"] if row else None


def _recorded_fingerprint(conn: sqlite3.Connection, mission_id: str,
                          logical_action_id: str) -> Optional[str]:
    """What a previous projection in this mission recorded for this action, if anything."""
    row = conn.execute(
        "SELECT pa.semantic_fingerprint AS fp FROM ciph_plan_actions pa "
        "JOIN ciph_mission_plans p ON p.plan_id = pa.plan_id "
        "WHERE p.mission_id = ? AND pa.logical_action_id = ? AND pa.semantic_fingerprint IS NOT NULL "
        "LIMIT 1;",
        (mission_id, logical_action_id),
    ).fetchone()
    return row["fp"] if row else None


def _allocate_action_id() -> str:
    """A canonical identity for newly proposed work. The planner never chooses one."""
    return f"ACT-{uuid.uuid4().hex[:12].upper()}"


def _proposed_action_fingerprint(proposal: "NewActionProposal") -> str:
    """
    The semantic fingerprint of proposed work, computed by the KERNEL's own function.

    The planner states capability/parameters/target; the canonical layer derives the meaning. Note
    the fail-closed sharp edge: the kernel's fingerprint includes whether a scope grant is present,
    so if a later enqueue authorises this work WITH a scope, the canonical fingerprint will differ
    from the plan-time proposal and a later plan reference will report a conflict rather than
    silently accept the drift. Scope-ness is part of the kernel's notion of semantic identity, so
    surfacing the disagreement is the honest direction.
    """
    from ciph.kernel.execution_gateway import ExecutionRequest
    request = ExecutionRequest(
        capability=proposal.capability,
        params=dict(proposal.parameters or {}),
        target=proposal.target,
        logical_action_id="PLAN_PROPOSAL",
    )
    return request.compute_action_fingerprint()


def _record_projection(conn, *, mission_id: str, plan_id: str, objective: Optional[str],
                       version: Optional[int], coverage: str,
                       references: Sequence[Tuple[str, Optional[str]]],
                       now: float) -> Dict[str, Any]:
    """
    Validate and stage ONE immutable projection on the CALLER's connection. Never commits.

    Every conflict is detected before anything is written, so a rejected projection leaves no trace.
    """
    if coverage not in VALID_COVERAGE:
        raise MissionError("INVALID_COVERAGE", str(coverage))
    if conn.execute("SELECT 1 FROM ciph_mission_plans WHERE plan_id = ?;", (plan_id,)).fetchone():
        raise MissionError("PLAN_ALREADY_EXISTS", plan_id)

    prior = conn.execute(
        "SELECT COALESCE(MAX(version), 0) AS v FROM ciph_mission_plans WHERE mission_id = ?;",
        (mission_id,),
    ).fetchone()["v"]
    plan_version = int(version) if version is not None else int(prior) + 1

    already_known, newly_attached, recorded = [], [], []
    for action_id, declared in references:
        canonical = _canonical_fingerprint(conn, action_id)
        previous = _recorded_fingerprint(conn, mission_id, action_id)
        for label, a, b in (("declared_vs_canonical", declared, canonical),
                            ("declared_vs_recorded", declared, previous),
                            ("canonical_vs_recorded", canonical, previous)):
            if a and b and a != b:
                raise MissionError("PLAN_SEMANTIC_CONFLICT", f"{action_id}:{label}:{a}!={b}")
        recorded.append((action_id, canonical or declared or previous))

    for action_id, _fingerprint in recorded:
        known = conn.execute(
            "SELECT 1 FROM ciph_mission_actions WHERE mission_id = ? AND logical_action_id = ?;",
            (mission_id, action_id),
        ).fetchone()
        if known:
            already_known.append(action_id)
        else:
            conn.execute(
                "INSERT INTO ciph_mission_actions "
                "(mission_id, logical_action_id, attached_at, origin_plan_id) VALUES (?, ?, ?, ?);",
                (mission_id, action_id, now, plan_id),
            )
            newly_attached.append(action_id)

    conn.execute(
        "INSERT INTO ciph_mission_plans "
        "(plan_id, mission_id, version, objective, created_at, coverage) VALUES (?, ?, ?, ?, ?, ?);",
        (plan_id, mission_id, plan_version, objective, now, coverage),
    )
    for action_id, fingerprint in recorded:
        conn.execute(
            "INSERT INTO ciph_plan_actions (plan_id, logical_action_id, semantic_fingerprint) "
            "VALUES (?, ?, ?);",
            (plan_id, action_id, fingerprint),
        )
    # The pointer moves; every previous projection is untouched (law 13/20).
    conn.execute(
        "INSERT INTO ciph_mission_current_plan (mission_id, plan_id, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(mission_id) DO UPDATE SET plan_id = excluded.plan_id, "
        "updated_at = excluded.updated_at;",
        (mission_id, plan_id, now),
    )
    return {"plan_id": plan_id, "version": plan_version, "coverage": coverage,
            "already_known": tuple(already_known), "newly_attached": tuple(newly_attached),
            "fingerprints": dict(recorded)}


def record_plan(db_path: str, *, mission_id: str, plan_id: str, logical_action_ids: Sequence[str],
                objective: Optional[str] = None, version: Optional[int] = None,
                action_fingerprints: Optional[Dict[str, str]] = None,
                coverage: str = PLAN_COVERAGE_COMPLETE,
                now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record an IMMUTABLE plan projection and make it current.

    Recording grants no authority (law 10), edits no history (law 11), and refuses to change an
    existing action's meaning (law 15). Re-recording the same plan id is refused: a projection is
    append-only, so a changed strategy is a NEW projection (law 12/13). `coverage` states whether
    absence in this projection means "not scheduled" (COMPLETE) or nothing at all (PATCH).
    """
    moment = time.time() if now is None else float(now)
    declared = dict(action_fingerprints or {})
    references = [(str(action_id), declared.get(str(action_id))) for action_id in logical_action_ids]
    conn = _connect(db_path)
    try:
        init_mission_schema(conn)
        result = _record_projection(
            conn, mission_id=mission_id, plan_id=plan_id, objective=objective, version=version,
            coverage=coverage, references=references, now=moment,
        )
        conn.commit()
        return result
    finally:
        conn.close()


def propose_plan_from_dag(*, mission_id: str, basis_continuity_digest: str, dag,
                          reuse: Optional[Mapping[str, str]] = None,
                          coverage: str = PLAN_COVERAGE_COMPLETE,
                          rationale: Optional[str] = None,
                          objective: Optional[str] = None) -> PlanProposal:
    """
    The bridge from the REAL planner's output to a proposal.

    A planner step that is explicitly mapped to an existing logical action becomes an identity
    REFERENCE (`reuse={step_id: logical_action_id}`); every other step becomes proposed NEW work whose
    identity the canonical layer will allocate. Identity reuse therefore cannot travel by similarity:
    the planner either names an id, or it is proposing something new.
    """
    mapping = dict(reuse or {})
    references: List[Tuple[str, Optional[str]]] = []
    new_work: List[NewActionProposal] = []
    for step in (getattr(dag, "steps", ()) or ()):
        existing = mapping.get(getattr(step, "step_id", None))
        if existing:
            references.append((str(existing), None))
            continue
        parameters = dict(getattr(step, "parameters", None) or {})
        new_work.append(NewActionProposal(
            capability=getattr(step, "capability", None),
            parameters=parameters,
            target=parameters.get("target"),
            label=getattr(step, "step_id", None),
        ))
    return PlanProposal(
        mission_id=mission_id,
        basis_continuity_digest=basis_continuity_digest,
        plan_id=getattr(dag, "plan_id", None),
        objective=objective if objective is not None else getattr(dag, "objective", None),
        existing_action_refs=tuple(references),
        new_action_proposals=tuple(new_work),
        coverage=coverage,
        rationale=rationale,
    )


def apply_plan_proposal(db_path: str, proposal: PlanProposal, *,
                        now: Optional[float] = None) -> Dict[str, Any]:
    """
    Validate a planner's proposal against the CURRENT mission state and, only then, record it.

    ONE `BEGIN IMMEDIATE` covers the freshness check and the write, so no writer can slip between
    "the basis was fresh" and "the projection was recorded". A rejected proposal leaves ZERO durable
    side effects: no projection, no pointer move, no new action, no authority. Nothing here mints a
    permit - planning is a proposal about work, never a grant to perform it.
    """
    moment = time.time() if now is None else float(now)
    if proposal.coverage not in VALID_COVERAGE:
        raise MissionError("INVALID_COVERAGE", str(proposal.coverage))

    conn = _connect(db_path)
    try:
        init_mission_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        current = reconstruct_missions(db_path, now=moment, conn=conn).state_of(proposal.mission_id)
        if current is None:
            conn.execute("ROLLBACK")
            raise MissionError("UNKNOWN_MISSION", proposal.mission_id)

        current_digest = current.canonical_digest()
        if str(proposal.basis_continuity_digest) != current_digest:
            conn.execute("ROLLBACK")
            raise MissionError(
                "STALE_PLAN_PROPOSAL",
                f"basis={str(proposal.basis_continuity_digest)[:12]} current={current_digest[:12]}",
            )

        known_actions = {action.logical_action_id for action in current.actions}
        references: List[Tuple[str, Optional[str]]] = []
        for action_id, fingerprint in proposal.existing_action_refs:
            if str(action_id) not in known_actions:
                conn.execute("ROLLBACK")
                raise MissionError("UNKNOWN_ACTION",
                                   f"{action_id} is not an action of {proposal.mission_id}")
            references.append((str(action_id), fingerprint))

        allocated: List[Tuple[str, str, Optional[str]]] = []
        for proposed in proposal.new_action_proposals:
            action_id = _allocate_action_id()
            fingerprint = _proposed_action_fingerprint(proposed)
            allocated.append((action_id, fingerprint, proposed.label))
            references.append((action_id, fingerprint))

        plan_id = proposal.plan_id or f"PLAN-{uuid.uuid4().hex[:10].upper()}"
        result = _record_projection(
            conn, mission_id=proposal.mission_id, plan_id=plan_id, objective=proposal.objective,
            version=None, coverage=proposal.coverage, references=references, now=moment,
        )
        conn.execute("COMMIT")
        return {**result, "new_actions": tuple(allocated),
                "existing_action_refs": tuple(r[0] for r in proposal.existing_action_refs)}
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def supersede_plan(db_path: str, *, plan_id: str, superseded_by: str,
                   now: Optional[float] = None) -> bool:
    """
    Point the mission's CURRENT projection at a different existing projection.

    Nothing about the old projection changes - supersession is a pointer move. Kept for the Gate One
    surface; `record_plan` already makes a newly recorded projection current.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_mission_schema(conn)
        target = conn.execute("SELECT * FROM ciph_mission_plans WHERE plan_id = ?;",
                              (superseded_by,)).fetchone()
        if target is None:
            raise MissionError("UNKNOWN_PLAN", superseded_by)
        old = conn.execute("SELECT * FROM ciph_mission_plans WHERE plan_id = ?;",
                           (plan_id,)).fetchone()
        if old is not None and old["mission_id"] != target["mission_id"]:
            raise MissionError("PLAN_MISSION_MISMATCH", f"{plan_id}->{superseded_by}")
        conn.execute(
            "INSERT INTO ciph_mission_current_plan (mission_id, plan_id, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(mission_id) DO UPDATE SET plan_id = excluded.plan_id, "
            "updated_at = excluded.updated_at;",
            (target["mission_id"], superseded_by, moment),
        )
        conn.commit()
        return True
    finally:
        conn.close()


# ---------------------------------------------------------------------------- reconstruction
def reconstruct_missions(db_path: str, *, now: Optional[float] = None,
                         conn: Optional[sqlite3.Connection] = None) -> MissionContinuity:
    """
    Rebuild every mission from its durable rows PLUS Gate Zero's reconstruction of the truth.

    Read-only, with no fallback to in-memory state: a mission, a plan or a strategy that only exists
    in a scheduler's memory does not exist. Plans are read as projections; they never decide anything.
    """
    moment = time.time() if now is None else float(now)
    truth: ContinuityState = reconstruct(db_path, now=moment, read_only=True, conn=conn)
    by_action = {a.logical_action_id: a for a in truth.actions}

    owned = conn is None
    conn = _connect(db_path, read_only=True) if owned else conn
    try:
        missions = [dict(r) for r in conn.execute("SELECT * FROM ciph_missions ORDER BY mission_id")]
        memberships = [dict(r) for r in conn.execute("SELECT * FROM ciph_mission_actions")]
        plans = [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_mission_plans ORDER BY mission_id, version, plan_id")]
        plan_actions = [dict(r) for r in conn.execute("SELECT * FROM ciph_plan_actions")]
        pointers = {r["mission_id"]: r["plan_id"] for r in
                    conn.execute("SELECT * FROM ciph_mission_current_plan")}
    except sqlite3.Error:
        missions, memberships, plans, plan_actions, pointers = [], [], [], [], {}
    finally:
        if owned:
            conn.close()

    actions_by_mission: Dict[str, List[str]] = {}
    for row in memberships:
        actions_by_mission.setdefault(row["mission_id"], []).append(row["logical_action_id"])
    actions_by_plan: Dict[str, List[Dict[str, Any]]] = {}
    for row in plan_actions:
        actions_by_plan.setdefault(row["plan_id"], []).append(row)
    plans_by_mission: Dict[str, List[Dict[str, Any]]] = {}
    for row in plans:
        plans_by_mission.setdefault(row["mission_id"], []).append(row)

    states: List[MissionState] = []
    for mission in missions:
        mission_id = mission["mission_id"]
        action_ids = sorted(actions_by_mission.get(mission_id, []))
        action_states = tuple(by_action[a] for a in action_ids if a in by_action)

        obligations = tuple(a.logical_action_id for a in action_states
                            if a.attempt_outcome in ("UNRESOLVED", "UNKNOWN") or a.consumption_pending)
        unresolved = tuple(a.execution_attempt_id for a in action_states
                           if a.attempt_outcome in ("UNRESOLVED", "UNKNOWN") and a.execution_attempt_id)
        completions = tuple(a.permit_id for a in action_states if a.consumption_pending and a.permit_id)
        authorized = tuple(a.logical_action_id for a in action_states
                           if a.authorization_alive and a.job_status in ("QUEUED", "RETRYING"))
        terminal = [a for a in action_states
                    if a.attempt_outcome in ("TERMINAL", "RESOLVED_BY_OPERATOR")]

        history: List[PlanProjection] = []
        known_plan_ids = {p["plan_id"] for p in plans_by_mission.get(mission_id, [])}
        pointer = pointers.get(mission_id)
        if pointer and pointer not in known_plan_ids:
            # Dangling pointer: the projection is gone, mission truth is not (law 20).
            pointer = None
        for plan in plans_by_mission.get(mission_id, []):
            refs = sorted(actions_by_plan.get(plan["plan_id"], []),
                          key=lambda r: r["logical_action_id"])
            history.append(PlanProjection(
                plan_id=plan["plan_id"],
                mission_id=mission_id,
                version=int(plan["version"] or 0),
                objective=plan.get("objective"),
                created_at=plan.get("created_at"),
                action_ids=tuple(r["logical_action_id"] for r in refs),
                action_fingerprints=tuple(
                    (r["logical_action_id"], r.get("semantic_fingerprint")) for r in refs),
                coverage=(plan.get("coverage") or PLAN_COVERAGE_COMPLETE),
                is_current=(plan["plan_id"] == pointer),
            ))

        current = next((p for p in history if p.is_current), None)
        coverage = current.coverage if current else None
        # Planned work that has no canonical authority yet. It is REAL work the mission intends to do,
        # but Gate Zero cannot describe it because Gate Zero speaks only about attempts and authority.
        # It is reported here so nothing has to guess, and it is never dispatchable.
        unauthorised = tuple(a for a in action_ids if a not in by_action)
        if current is None:
            plan_action_ids: Tuple[str, ...] = ()
        elif coverage == PLAN_COVERAGE_COMPLETE:
            plan_action_ids = current.action_ids
        else:
            # A PATCH cannot remove anything: it layers onto the last exhaustive strategy, so absence
            # in a partial planner response can never pause work (law 19, second half).
            base = None
            for candidate in history:
                if (candidate.coverage == PLAN_COVERAGE_COMPLETE and not candidate.is_current
                        and (base is None or candidate.version > base.version)):
                    base = candidate
            plan_action_ids = tuple(sorted(set(current.action_ids)
                                           | (set(base.action_ids) if base else set())))
        # Law 19: an action a COMPLETE plan does not mention is OMITTED, not cancelled. Absence in a
        # PATCH means nothing at all.
        omitted = (tuple(a for a in action_ids if a not in set(plan_action_ids))
                   if coverage == PLAN_COVERAGE_COMPLETE else ())

        completion_eligible = ((not obligations) and (not completions) and (not authorized)
                               and bool(terminal))
        needs_replanning = (bool(obligations or unresolved)
                            or (current is None and not completion_eligible)
                            or (coverage == PLAN_COVERAGE_PATCH and not completion_eligible))

        states.append(MissionState(
            mission_id=mission_id,
            objective=mission.get("objective"),
            status=mission.get("status"),
            opened_at=mission.get("opened_at"),
            actions=action_states,
            current_plan_id=pointer,
            plan_coverage=coverage,
            plan_action_ids=plan_action_ids,
            omitted_action_ids=omitted,
            unauthorised_action_ids=unauthorised,
            plan_history=tuple(history),
            obligations=obligations,
            unresolved_attempts=unresolved,
            completion_obligations=completions,
            remaining_authorized_work=authorized,
            completion_eligible=completion_eligible,
            needs_replanning=needs_replanning,
        ))

    return MissionContinuity(missions=tuple(states), contested_actions=())


def complete_mission(db_path: str, *, mission_id: str, reason: str,
                     now: Optional[float] = None) -> bool:
    """
    Law 9: completion is EVIDENCE-based. Refuses while any obligation remains, and says which.

    Refusing here is the whole point: a mission that closed while an attempt was unresolved would be
    the mission-level version of "resolved-but-claimed".
    """
    moment = time.time() if now is None else float(now)
    state = reconstruct_missions(db_path, now=moment).state_of(mission_id)
    if state is None:
        raise MissionError("UNKNOWN_MISSION", mission_id)
    if state.status != MISSION_ACTIVE:
        raise MissionError("MISSION_NOT_ACTIVE", f"{mission_id}={state.status}")
    blockers = (tuple(state.obligations) + tuple(state.completion_obligations)
                + tuple(state.remaining_authorized_work))
    if blockers:
        raise MissionError("MISSION_HAS_OPEN_OBLIGATIONS", ",".join(sorted(set(blockers))))
    conn = _connect(db_path)
    try:
        init_mission_schema(conn)
        conn.execute(
            "UPDATE ciph_missions SET status = ?, closed_at = ?, close_reason = ? WHERE mission_id = ?;",
            (MISSION_COMPLETED, moment, reason, mission_id),
        )
        conn.commit()
    finally:
        conn.close()
    return True


def abandon_mission(db_path: str, *, mission_id: str, reason: str,
                    now: Optional[float] = None) -> bool:
    """
    Law 9's sibling: an ending that is DELIBERATE rather than earned.

    Completion is refused while obligations remain, and that is right - but a mission that has become
    pointless must be able to END, in the record, on purpose. Abandonment is therefore a recorded
    decision (this row) rather than an inference from silence, and the write stays here so that exactly
    one module owns mission state. Who is ALLOWED to make that decision is 5.1's business, not this
    function's; the function only refuses to act on a mission that is already closed.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_mission_schema(conn)
        cursor = conn.execute(
            "UPDATE ciph_missions SET status = ?, closed_at = ?, close_reason = ? "
            "WHERE mission_id = ? AND status = ?;",
            (MISSION_ABANDONED, moment, reason, mission_id, MISSION_ACTIVE),
        )
        conn.commit()
        if cursor.rowcount == 0:
            raise MissionError("MISSION_NOT_ACTIVE", mission_id)
        return True
    finally:
        conn.close()
