"""
ciph/kernel/swarm_worker - 6.0 (worker identity), 6.10 (membership lifecycle),
6.7 (health and quarantine) and 6.8 (the capability ladder).

    A worker is a subordinate computational carrier operating under Ciph's EXISTING authority.
    Multiplicity grants capacity, not authority.

Four things are deliberately separated here, because collapsing them is how swarms sprout sovereignty:

    IDENTITY      a worker_id is a ROLE. A process is an INSTANCE. Restarting W3 produces generation
                  N+1 of the same role - never a continuation of the old runtime, and never a second
                  identity root.
    MEMBERSHIP    an append-only event history. A disappeared process does not delete its history, and
                  a new process wearing an old label is not an old worker.
    HEALTH        measured, never self-reported. A worker cannot declare itself healthy, and cannot
                  leave quarantine by assertion: re-entry is re-attestation.
    CAPABILITY    a LADDER, not a claim: INSTALLED -> AVAILABLE -> AUTHORIZED -> VERIFIED. A worker may
                  install a name; only measurement and governance move it up.

Nothing in this module grants execution authority. Registration is not permission; a READY worker is
ready to be CONSIDERED, and the delegation layer still decides.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SWARM_WORKER_IDENTITY_V1 = "SWARM_WORKER_IDENTITY_V1"
SWARM_MEMBERSHIP_V1 = "SWARM_MEMBERSHIP_V1"
SWARM_TOPOLOGY_V1 = "SWARM_TOPOLOGY_V1"
SWARM_HEALTH_V1 = "SWARM_HEALTH_V1"
SWARM_ROUTING_V1 = "SWARM_ROUTING_V1"

# Membership status: what the swarm knows about a worker instance right now.
JOINING = "JOINING"
READY = "READY"
BUSY = "BUSY"
QUIESCING = "QUIESCING"
DRAINED = "DRAINED"
QUARANTINED = "QUARANTINED"
DEAD = "DEAD"
VALID_STATUSES = (JOINING, READY, BUSY, QUIESCING, DRAINED, QUARANTINED, DEAD)
ACTIVE_STATUSES = (READY, BUSY)

# Health: a SEPARATE axis from membership, because a healthy worker can be draining and a dead worker
# cannot be unhealthy.
HEALTHY = "HEALTHY"
DEGRADED = "DEGRADED"
SUSPECT = "SUSPECT"
HEALTH_QUARANTINE = "QUARANTINED"
HEALTH_DEAD = "DEAD"
VALID_HEALTH = (HEALTHY, DEGRADED, SUSPECT, HEALTH_QUARANTINE, HEALTH_DEAD)

# The capability ladder (4.3's shape, applied to a worker).
INSTALLED = "INSTALLED"
AVAILABLE = "AVAILABLE"
AUTHORIZED = "AUTHORIZED"
VERIFIED = "VERIFIED"
CAPABILITY_LADDER = (INSTALLED, AVAILABLE, AUTHORIZED, VERIFIED)

REASON_NOT_OPERATOR = "SWARM_ACTION_REQUIRES_AN_OPERATOR"
REASON_UNKNOWN_WORKER = "UNKNOWN_SWARM_WORKER"
REASON_UNKNOWN_HEALTH = "UNKNOWN_HEALTH_STATUS"
REASON_UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY_LEVEL"
REASON_ILLEGAL_TRANSITION = "ILLEGAL_WORKER_TRANSITION"
REASON_NOT_ATTESTED = "WORKER_NOT_ATTESTED"
REASON_ATTESTATION_MISMATCH = "WORKER_ATTESTATION_MISMATCH"
REASON_SELF_HEALTH = "WORKER_CANNOT_ASSESS_ITSELF"
REASON_SELF_CAPABILITY = "WORKER_CANNOT_RAISE_ITS_OWN_CAPABILITY"
REASON_STALE_GENERATION = "STALE_WORKER_GENERATION"
REASON_QUARANTINE_NEEDS_OPERATOR = "QUARANTINE_RELEASE_REQUIRES_AN_OPERATOR"

# Membership transitions. `+` means the target needs an operator identity, because it is a grant.
# JOINING -> READY is deliberately ABSENT: attestation is the only path out of JOINING, so a worker
# can never be READY without a measurement on the record. The operator's route back from quarantine is
# QUARANTINED -> JOINING -> attestation, which is slower on purpose.
_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    JOINING: (QUARANTINED, DEAD),
    READY: (BUSY, QUIESCING, DRAINED, QUARANTINED, DEAD),
    BUSY: (READY, QUIESCING, QUARANTINED, DEAD),
    QUIESCING: (DRAINED, READY, QUARANTINED, DEAD),
    DRAINED: (READY, QUARANTINED, DEAD),
    QUARANTINED: (JOINING, DEAD),
    DEAD: (),
}
# Transitions that are GRANTS rather than reports. Only reachable pairs are listed: a quarantined
# worker has no path to READY at all (it must be returned to JOINING and measured again), and DEAD is
# terminal, so neither appears here.
_REQUIRES_OPERATOR = ((QUARANTINED, JOINING), (DRAINED, READY))

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_workers (
        worker_id TEXT NOT NULL,
        instance_generation INTEGER NOT NULL,
        process_identity TEXT,
        code_digest TEXT NOT NULL,
        environment_digest TEXT NOT NULL,
        capability_manifest_digest TEXT,
        model_identity TEXT,
        worker_role TEXT,
        status TEXT NOT NULL,
        attested_at REAL,
        joined_at REAL,
        PRIMARY KEY (worker_id, instance_generation)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_membership (
        membership_id TEXT PRIMARY KEY,
        worker_id TEXT NOT NULL,
        instance_generation INTEGER NOT NULL,
        event TEXT NOT NULL,
        detail TEXT,
        actor TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_health (
        assessment_id TEXT PRIMARY KEY,
        worker_id TEXT NOT NULL,
        instance_generation INTEGER NOT NULL,
        status TEXT NOT NULL,
        evidence_refs_json TEXT,
        assessor TEXT NOT NULL,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_swarm_capabilities (
        capability_id TEXT PRIMARY KEY,
        worker_id TEXT NOT NULL,
        instance_generation INTEGER NOT NULL,
        capability TEXT NOT NULL,
        level TEXT NOT NULL,
        evidence_ref TEXT,
        recorded_at REAL
    );
    """,
)


def _operator(actor: str) -> bool:
    return str(actor).startswith("operator:")


def _worker_actor(worker_id: str) -> str:
    return f"worker:{worker_id}"


@dataclass(frozen=True)
class WorkerIdentity:
    worker_id: str
    instance_generation: int
    process_identity: Optional[str]
    code_digest: str
    environment_digest: str
    capability_manifest_digest: Optional[str]
    model_identity: Optional[str]
    worker_role: Optional[str]
    status: str
    attested_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"worker_id": self.worker_id, "instance_generation": self.instance_generation,
                "process_identity": self.process_identity, "code_digest": self.code_digest,
                "environment_digest": self.environment_digest,
                "capability_manifest_digest": self.capability_manifest_digest,
                "model_identity": self.model_identity, "worker_role": self.worker_role,
                "status": self.status, "attested_at": self.attested_at,
                "policy_version": SWARM_WORKER_IDENTITY_V1}


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=15.0)
            connection.row_factory = sqlite3.Row
            return connection
        except sqlite3.OperationalError:
            pass
    connection = sqlite3.connect(db_path, timeout=15.0)
    connection.row_factory = sqlite3.Row
    return connection


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _record_event(conn: sqlite3.Connection, *, worker_id: str, generation: int, event: str,
                  detail: Optional[str], actor: Optional[str], now: float) -> str:
    event_id = "SM-" + digest({"worker": worker_id, "gen": int(generation), "event": event,
                               "detail": detail, "at": now})[:16].upper()
    conn.execute("INSERT OR IGNORE INTO ciph_swarm_membership (membership_id, worker_id, "
                 "instance_generation, event, detail, actor, recorded_at) VALUES (?,?,?,?,?,?,?);",
                 (event_id, worker_id, int(generation), event, detail, actor, now))
    return event_id


def register_worker(db_path: str, *, worker_id: str, process_identity: Optional[str],
                    code_digest: str, environment_digest: str,
                    capability_manifest_digest: Optional[str] = None,
                    model_identity: Optional[str] = None, worker_role: Optional[str] = None,
                    now: Optional[float] = None) -> WorkerIdentity:
    """
    Announce one runtime INSTANCE of a worker role.

    The generation is allocated by the swarm, never chosen by the worker: a process that could pick its
    own generation could pick a current one after being superseded. Registration grants nothing at all -
    the worker exists in JOINING and stays there until it is attested.
    """
    if not str(worker_id).strip():
        raise CrucibleError("WORKER_REQUIRES_AN_ID", str(worker_id))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        row = connection.execute("SELECT MAX(instance_generation) AS latest FROM ciph_swarm_workers "
                                 "WHERE worker_id = ?;", (str(worker_id),)).fetchone()
        generation = int(row["latest"] or 0) + 1
        connection.execute(
            "INSERT INTO ciph_swarm_workers (worker_id, instance_generation, process_identity, "
            "code_digest, environment_digest, capability_manifest_digest, model_identity, "
            "worker_role, status, attested_at, joined_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (str(worker_id), generation, process_identity, str(code_digest),
             str(environment_digest), capability_manifest_digest, model_identity, worker_role,
             JOINING, None, moment))
        _record_event(connection, worker_id=str(worker_id), generation=generation, event="JOIN",
                      detail=None, actor=_worker_actor(worker_id), now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_worker(db_path, str(worker_id), generation)


def get_worker(db_path: str, worker_id: str, generation: Optional[int] = None) -> WorkerIdentity:
    connection = _connect(db_path, read_only=True)
    try:
        if generation is None:
            row = connection.execute(
                "SELECT * FROM ciph_swarm_workers WHERE worker_id = ? "
                "ORDER BY instance_generation DESC LIMIT 1;", (str(worker_id),)).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM ciph_swarm_workers WHERE worker_id = ? AND instance_generation = ?;",
                (str(worker_id), int(generation))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_WORKER, f"{worker_id}:{generation}")
    row = dict(row)
    return WorkerIdentity(worker_id=str(row["worker_id"]),
                          instance_generation=int(row["instance_generation"]),
                          process_identity=row["process_identity"],
                          code_digest=str(row["code_digest"]),
                          environment_digest=str(row["environment_digest"]),
                          capability_manifest_digest=row["capability_manifest_digest"],
                          model_identity=row["model_identity"], worker_role=row["worker_role"],
                          status=str(row["status"]), attested_at=row["attested_at"])


def worker_generation(db_path: str, worker_id: str) -> int:
    return get_worker(db_path, worker_id).instance_generation


def is_current_generation(db_path: str, worker_id: str, generation: int) -> bool:
    try:
        return get_worker(db_path, worker_id).instance_generation == int(generation)
    except CrucibleError:
        return False


def attest_worker(db_path: str, worker_id: str, generation: int, *, observed_code_digest: str,
                  observed_environment_digest: str, capability_manifest_digest: Optional[str] = None,
                  actor: Optional[str] = None, now: Optional[float] = None) -> WorkerIdentity:
    """
    Move JOINING -> READY against MEASURED facts, supplied by the host that can see the process.

    The measurement is the caller's, not the worker's self-description: a worker that could attest
    itself could claim any code digest it liked. A mismatch leaves the worker in JOINING and records
    why - it does not quietly become READY with a wrong environment.
    """
    if not _operator(actor or "") and actor is not None and str(actor).startswith("worker:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    identity = get_worker(db_path, worker_id, generation)
    if identity.status != JOINING:
        raise CrucibleError(REASON_ILLEGAL_TRANSITION, f"{identity.status}->{READY}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        if str(observed_code_digest) != identity.code_digest or \
                str(observed_environment_digest) != identity.environment_digest:
            _record_event(connection, worker_id=worker_id, generation=generation,
                          event="ATTEST_MISMATCH",
                          detail=f"code={observed_code_digest[:12]} env={observed_environment_digest[:12]}",
                          actor=actor, now=moment)
            connection.commit()
            raise CrucibleError(REASON_ATTESTATION_MISMATCH, str(worker_id))
        connection.execute(
            "UPDATE ciph_swarm_workers SET status = ?, attested_at = ?, "
            "capability_manifest_digest = COALESCE(?, capability_manifest_digest) "
            "WHERE worker_id = ? AND instance_generation = ?;",
            (READY, moment, capability_manifest_digest, str(worker_id), int(generation)))
        _record_event(connection, worker_id=worker_id, generation=generation, event="ATTEST",
                      detail=None, actor=actor, now=moment)
        _record_event(connection, worker_id=worker_id, generation=generation, event="READY",
                      detail=None, actor=actor, now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_worker(db_path, worker_id, generation)


def set_worker_status(db_path: str, worker_id: str, generation: int, *, status: str, actor: str,
                      reason: Optional[str] = None, now: Optional[float] = None) -> WorkerIdentity:
    """
    Move a worker along the membership lifecycle.

    Two refusals carry the law. A worker may not take itself out of quarantine - re-entry is a
    re-attestation, and a quarantined worker that could READY itself would make quarantine decorative.
    And a worker may not move itself to READY from DEAD or DRAINED, because those transitions are
    grants, and grants are the operator's.
    """
    if status not in VALID_STATUSES:
        raise CrucibleError("UNKNOWN_WORKER_STATUS", str(status))
    moment = time.time() if now is None else float(now)
    if status == BUSY:
        # A frozen swarm admits no new work state. A worker that could mark itself BUSY during a
        # quiescence barrier would be starting work in the one window where nobody is watching it.
        from ciph.kernel.swarm_quiescence import swarm_is_frozen
        if swarm_is_frozen(db_path):
            raise CrucibleError("SWARM_IS_QUIESCING", f"{worker_id} cannot become BUSY")
    identity = get_worker(db_path, worker_id, generation)
    if not is_current_generation(db_path, worker_id, generation):
        raise CrucibleError(REASON_STALE_GENERATION, f"{worker_id}:{generation}")
    if status not in _TRANSITIONS[identity.status]:
        raise CrucibleError(REASON_ILLEGAL_TRANSITION, f"{identity.status}->{status}")
    if (identity.status, status) in _REQUIRES_OPERATOR and not _operator(actor):
        raise CrucibleError(REASON_QUARANTINE_NEEDS_OPERATOR, f"{identity.status}->{status}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_swarm_workers SET status = ? WHERE worker_id = ? "
                           "AND instance_generation = ?;", (status, str(worker_id), int(generation)))
        _record_event(connection, worker_id=worker_id, generation=generation, event=status,
                      detail=reason, actor=actor, now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_worker(db_path, worker_id, generation)


def mark_dead(db_path: str, worker_id: str, *, reason: str, actor: str,
              now: Optional[float] = None) -> WorkerIdentity:
    """A disappearance is an event with a reason, not a row that stops being mentioned."""
    identity = get_worker(db_path, worker_id)
    return set_worker_status(db_path, worker_id, identity.instance_generation, status=DEAD,
                             actor=actor, reason=reason, now=now)


def members(db_path: str, *, statuses: Sequence[str] = ACTIVE_STATUSES) -> List[WorkerIdentity]:
    connection = _connect(db_path, read_only=True)
    allowed = tuple(str(item) for item in statuses)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT worker_id, instance_generation FROM ciph_swarm_workers "
            "ORDER BY worker_id, instance_generation;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    identities = [get_worker(db_path, str(row["worker_id"]), int(row["instance_generation"]))
                  for row in rows]
    if not allowed:
        return identities
    # Only the CURRENT generation of a worker can be an active member.
    latest: Dict[str, int] = {}
    for identity in identities:
        latest[identity.worker_id] = max(latest.get(identity.worker_id, 0),
                                         identity.instance_generation)
    return [identity for identity in identities
            if identity.status in allowed and identity.instance_generation == latest[identity.worker_id]]


def membership_history(db_path: str, worker_id: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_swarm_membership"
    params: Tuple[Any, ...] = ()
    if worker_id is not None:
        query += " WHERE worker_id = ?"
        params = (str(worker_id),)
    try:
        return [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, membership_id;", params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


# ---------------------------------------------------------------------------- 6.7 health
def assess_health(db_path: str, worker_id: str, generation: int, *, status: str,
                  evidence_refs: Sequence[str], assessor: str,
                  now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record a health assessment against EVIDENCE, by an actor that is not the worker.

    One wrong answer is not a malicious worker, so DEGRADED needs one piece of evidence and SUSPECT or
    QUARANTINED needs the caller to supply at least one as well - the module's job is to refuse a
    self-report and to keep the evidence attached, not to pretend it can read intent.
    """
    if status not in VALID_HEALTH:
        raise CrucibleError(REASON_UNKNOWN_HEALTH, str(status))
    if str(assessor) == _worker_actor(worker_id):
        raise CrucibleError(REASON_SELF_HEALTH, str(worker_id))
    refs = sorted(str(ref) for ref in evidence_refs)
    if status in (DEGRADED, SUSPECT, HEALTH_QUARANTINE) and not refs:
        raise CrucibleError("HEALTH_ASSESSMENT_REQUIRES_EVIDENCE", str(status))
    moment = time.time() if now is None else float(now)
    assessment_id = "SHA-" + digest({"worker": worker_id, "gen": int(generation),
                                     "status": status, "evidence": refs,
                                     "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_swarm_health (assessment_id, worker_id, "
            "instance_generation, status, evidence_refs_json, assessor, recorded_at) "
            "VALUES (?,?,?,?,?,?,?);",
            (assessment_id, str(worker_id), int(generation), status, json.dumps(refs),
             str(assessor), moment))
        if status in (HEALTH_QUARANTINE, HEALTH_DEAD) and is_current_generation(db_path, worker_id,
                                                                              generation):
            connection.execute("UPDATE ciph_swarm_workers SET status = ? WHERE worker_id = ? "
                               "AND instance_generation = ?;", (QUARANTINED, str(worker_id),
                                                                int(generation)))
            _record_event(connection, worker_id=worker_id, generation=generation,
                          event="QUARANTINE", detail=status, actor=assessor, now=moment)
        connection.commit()
    finally:
        connection.close()
    return health_of(db_path, worker_id, generation)


def health_of(db_path: str, worker_id: str, generation: Optional[int] = None) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        if generation is None:
            row = connection.execute("SELECT * FROM ciph_swarm_health WHERE worker_id = ? "
                                     "ORDER BY recorded_at DESC, assessment_id DESC LIMIT 1;",
                                     (str(worker_id),)).fetchone()
        else:
            row = connection.execute("SELECT * FROM ciph_swarm_health WHERE worker_id = ? "
                                     "AND instance_generation = ? "
                                     "ORDER BY recorded_at DESC, assessment_id DESC LIMIT 1;",
                                     (str(worker_id), int(generation))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        return {"worker_id": worker_id, "instance_generation": generation, "status": None,
                "evidence_refs": [], "assessor": None, "policy_version": SWARM_HEALTH_V1}
    row = dict(row)
    return {"worker_id": str(row["worker_id"]), "instance_generation": int(row["instance_generation"]),
            "status": str(row["status"]),
            "evidence_refs": json.loads(row["evidence_refs_json"] or "[]"),
            "assessor": str(row["assessor"]), "policy_version": SWARM_HEALTH_V1}


# ---------------------------------------------------------------------------- 6.8 capability ladder
def record_capability(db_path: str, worker_id: str, generation: int, *, capability: str, level: str,
                      actor: str, evidence_ref: Optional[str] = None,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """
    Move a capability up the ladder - but a worker may only ever reach INSTALLED by itself.

    INSTALLED means "this worker's manifest names it". Everything above is measurement or governance:
    an environment attestation, an authorization, or a verified use with evidence.
    """
    if level not in CAPABILITY_LADDER:
        raise CrucibleError(REASON_UNKNOWN_CAPABILITY, str(level))
    if str(actor) == _worker_actor(worker_id) and CAPABILITY_LADDER.index(level) > 0:
        raise CrucibleError(REASON_SELF_CAPABILITY, f"{worker_id}:{capability}:{level}")
    if CAPABILITY_LADDER.index(level) >= CAPABILITY_LADDER.index(AUTHORIZED) and not evidence_ref \
            and not _operator(actor):
        raise CrucibleError("CAPABILITY_ABOVE_AVAILABLE_REQUIRES_EVIDENCE_OR_AUTHORITY",
                            f"{capability}:{level}")
    moment = time.time() if now is None else float(now)
    # Keyed WITHOUT the level: a capability has one current level, and the ladder is the value, not a
    # second row. Keying by level would leave "coding:INSTALLED" and "coding:VERIFIED" coexisting, and
    # a reader would have to guess which one is true.
    capability_id = "SWC-" + digest({"worker": worker_id, "gen": int(generation),
                                     "capability": capability})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        current = connection.execute(
            "SELECT level FROM ciph_swarm_capabilities WHERE capability_id = ?;",
            (capability_id,)).fetchone()
        if current is None:
            connection.execute(
                "INSERT INTO ciph_swarm_capabilities (capability_id, worker_id, "
                "instance_generation, capability, level, evidence_ref, recorded_at) "
                "VALUES (?,?,?,?,?,?,?);",
                (capability_id, str(worker_id), int(generation), str(capability), level,
                 evidence_ref, moment))
        elif CAPABILITY_LADDER.index(level) > CAPABILITY_LADDER.index(str(current["level"])):
            connection.execute("UPDATE ciph_swarm_capabilities SET level = ?, evidence_ref = ? "
                               "WHERE capability_id = ?;", (level, evidence_ref, capability_id))
        connection.commit()
    finally:
        connection.close()
    return {"worker_id": str(worker_id), "capability": str(capability),
            "level": capability_level(db_path, worker_id, generation, capability),
            "policy_version": SWARM_ROUTING_V1}


def capability_level(db_path: str, worker_id: str, generation: int, capability: str) -> Optional[str]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute(
            "SELECT level FROM ciph_swarm_capabilities WHERE worker_id = ? "
            "AND instance_generation = ? AND capability = ?;",
            (str(worker_id), int(generation), str(capability))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return str(row["level"]) if row is not None else None


def route(db_path: str, *, required_capabilities: Sequence[str], work_class: str,
          required_level: str = VERIFIED, now: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    Which workers may be assigned this work, deterministically ordered.

    The ladder is read, not trusted: a worker whose manifest merely names a capability is INSTALLED and
    does not route. Membership must be current and active, and a barrier freezes routing entirely.
    """
    from ciph.kernel.swarm_quiescence import swarm_is_frozen
    moment = time.time() if now is None else float(now)
    if swarm_is_frozen(db_path):
        return []
    floor = CAPABILITY_LADDER.index(required_level) if required_level in CAPABILITY_LADDER else len(
        CAPABILITY_LADDER) - 1
    eligible = []
    for identity in members(db_path):
        levels = []
        ok = True
        for capability in required_capabilities:
            level = capability_level(db_path, identity.worker_id, identity.instance_generation,
                                     capability)
            level = level or INSTALLED
            levels.append({"capability": str(capability), "level": level})
            if CAPABILITY_LADDER.index(level) < floor:
                ok = False
        health = health_of(db_path, identity.worker_id, identity.instance_generation).get("status")
        if health in (HEALTH_QUARANTINE, HEALTH_DEAD):
            ok = False
        if ok:
            eligible.append({"worker_id": identity.worker_id,
                             "instance_generation": identity.instance_generation,
                             "worker_role": identity.worker_role,
                             "model_identity": identity.model_identity,
                             "capabilities": levels, "work_class": str(work_class),
                             "policy_version": SWARM_ROUTING_V1})
    return sorted(eligible, key=lambda item: (item["worker_id"], item["instance_generation"]))


def topology_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        workers = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_workers ORDER BY worker_id, instance_generation;")]
        capabilities = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_capabilities ORDER BY capability_id;")]
        health = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_swarm_health ORDER BY assessment_id;")]
    except sqlite3.Error:
        workers, capabilities, health = [], [], []
    finally:
        connection.close()
    return digest({"version": SWARM_TOPOLOGY_V1, "workers": workers,
                   "capabilities": capabilities, "health": health,
                   "membership": membership_history(db_path)})
