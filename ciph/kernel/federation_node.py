"""
ciph/kernel/federation_node - 7.0 (node identity and generation), 7.1 (membership and trust),
                                7.10 (health and quarantine) and 7.11 (rejoin and retirement).

    node != Ciph.  A node is a durable HOST-LEVEL participant, not a subordinate runtime.

That distinction is the whole reason this module exists separately from 6.x's worker identity: a worker
is machinery Ciph starts, while a node is a machine Ciph trusts with durable state. Four facts are kept
apart on purpose, because collapsing any of them is how a federation grows a second sovereign:

    IDENTITY      `node_id` is a logical participant. It is NOT a hostname, NOT an IP, NOT a PID, NOT a
                  VPS instance, NOT a swarm worker id. A machine that changes address is the same node;
                  a machine that restarts gets an explicit new GENERATION.
    MEMBERSHIP    granted, revocable and auditable. A handshake is not membership and a known public
                  key is not authority - a node cannot enroll itself by introducing itself.
    HEALTH        measured. UNREACHABLE is its own status and is never DEAD and never malicious: not
                  hearing from a node is information about the LINK, not about the node.
    REJOIN        a node returning with stale data and valid old credentials must not push stale
                  authority back into the federation. Identity, generation, membership, authority epoch
                  and re-attestation are checked in that order, and the check is recorded either way.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

FEDERATION_NODE_IDENTITY_V1 = "FEDERATION_NODE_IDENTITY_V1"
FEDERATION_MEMBERSHIP_V1 = "FEDERATION_MEMBERSHIP_V1"
FEDERATION_HEALTH_V1 = "FEDERATION_HEALTH_V1"
FEDERATION_REJOIN_V1 = "FEDERATION_REJOIN_V1"

CANDIDATE = "CANDIDATE"
TRUSTED = "TRUSTED"
DEGRADED = "DEGRADED"
QUARANTINED = "QUARANTINED"
RETIRED = "RETIRED"
VALID_MEMBERSHIP = (CANDIDATE, TRUSTED, DEGRADED, QUARANTINED, RETIRED)
ACTIVE_MEMBERSHIP = (TRUSTED, DEGRADED)

HEALTHY = "HEALTHY"
HEALTH_DEGRADED = "DEGRADED"
SUSPECT = "SUSPECT"
HEALTH_QUARANTINE = "QUARANTINED"
UNREACHABLE = "UNREACHABLE"
HEALTH_RETIRED = "RETIRED"
VALID_HEALTH = (HEALTHY, HEALTH_DEGRADED, SUSPECT, HEALTH_QUARANTINE, UNREACHABLE, HEALTH_RETIRED)

REJOIN_ACCEPTED = "ACCEPTED"
REJOIN_REATTEST = "REQUIRES_REATTESTATION"
REJOIN_STALE_GENERATION = "STALE_GENERATION"
REJOIN_UNKNOWN = "UNKNOWN_IDENTITY"
REJOIN_RETIRED = "RETIRED_GENERATION"
REJOIN_STALE_EPOCH = "STALE_AUTHORITY_EPOCH"
REJOIN_NOT_TRUSTED = "NOT_TRUSTED"
VALID_REJOIN = (REJOIN_ACCEPTED, REJOIN_REATTEST, REJOIN_STALE_GENERATION, REJOIN_UNKNOWN,
                REJOIN_RETIRED, REJOIN_STALE_EPOCH, REJOIN_NOT_TRUSTED)

REASON_NOT_OPERATOR = "FEDERATION_ACTION_REQUIRES_AN_OPERATOR"
REASON_UNKNOWN_NODE = "UNKNOWN_FEDERATION_NODE"
REASON_ATTESTATION_MISMATCH = "NODE_ATTESTATION_MISMATCH"
REASON_ILLEGAL_TRANSITION = "ILLEGAL_MEMBERSHIP_TRANSITION"
REASON_SELF_HEALTH = "NODE_CANNOT_ASSESS_ITSELF"
REASON_WORKER_IDENTITY = "WORKER_IDENTITY_IS_NOT_NODE_IDENTITY"
REASON_RETIRED = "RETIRED_GENERATION_CANNOT_REJOIN"
REASON_UNKNOWN_HEALTH = "UNKNOWN_NODE_HEALTH_STATUS"

# CANDIDATE -> TRUSTED is reached by ATTESTATION only, so it is deliberately absent here.
_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    CANDIDATE: (QUARANTINED, RETIRED),
    TRUSTED: (DEGRADED, QUARANTINED, RETIRED),
    DEGRADED: (TRUSTED, QUARANTINED, RETIRED),
    QUARANTINED: (CANDIDATE, RETIRED),
    RETIRED: (),
}
# Grants, not reports: leaving quarantine means re-attestation, and un-degrading is an operator act.
_REQUIRES_OPERATOR = ((DEGRADED, TRUSTED), (QUARANTINED, CANDIDATE), (QUARANTINED, RETIRED))

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_nodes (
        node_id TEXT NOT NULL,
        node_generation INTEGER NOT NULL,
        public_key_ref TEXT NOT NULL,
        code_digest TEXT NOT NULL,
        environment_digest TEXT NOT NULL,
        attestation_digest TEXT,
        host_label TEXT,
        endpoint TEXT,
        membership TEXT NOT NULL,
        attested_at REAL,
        joined_at REAL,
        PRIMARY KEY (node_id, node_generation)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_membership (
        membership_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        node_generation INTEGER NOT NULL,
        event TEXT NOT NULL,
        detail TEXT,
        actor TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_health (
        assessment_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        node_generation INTEGER NOT NULL,
        status TEXT NOT NULL,
        evidence_refs_json TEXT,
        assessor TEXT NOT NULL,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_rejoins (
        rejoin_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        node_generation INTEGER,
        disposition TEXT NOT NULL,
        presented_epoch INTEGER,
        current_epoch INTEGER,
        detail TEXT,
        recorded_at REAL
    );
    """,
)


def _operator(actor: str) -> bool:
    return str(actor).startswith("operator:")


@dataclass(frozen=True)
class FederationNode:
    node_id: str
    node_generation: int
    public_key_ref: str
    code_digest: str
    environment_digest: str
    attestation_digest: Optional[str]
    host_label: Optional[str]
    endpoint: Optional[str]
    membership: str
    attested_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"node_id": self.node_id, "node_generation": self.node_generation,
                "public_key_ref": self.public_key_ref, "code_digest": self.code_digest,
                "environment_digest": self.environment_digest,
                "attestation_digest": self.attestation_digest, "host_label": self.host_label,
                "endpoint": self.endpoint, "membership": self.membership,
                "attested_at": self.attested_at, "policy_version": FEDERATION_NODE_IDENTITY_V1}


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


def _event(conn: sqlite3.Connection, *, node_id: str, generation: int, event: str,
           detail: Optional[str], actor: Optional[str], now: float) -> str:
    event_id = "FM-" + digest({"node": node_id, "gen": int(generation), "event": event,
                               "detail": detail, "at": now})[:16].upper()
    conn.execute("INSERT OR IGNORE INTO ciph_federation_membership (membership_id, node_id, "
                 "node_generation, event, detail, actor, recorded_at) VALUES (?,?,?,?,?,?,?);",
                 (event_id, node_id, int(generation), event, detail, actor, now))
    return event_id


def _was_a_worker(db_path: str, node_id: str) -> bool:
    """A swarm worker id is not a federation node id, and enrolment is where that is refused."""
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT 1 FROM ciph_swarm_workers WHERE worker_id = ? LIMIT 1;",
                                 (str(node_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return row is not None


def register_node(db_path: str, *, node_id: str, public_key_ref: str, code_digest: str,
                  environment_digest: str, endpoint: Optional[str] = None,
                  host_label: Optional[str] = None, actor: str,
                  now: Optional[float] = None) -> FederationNode:
    """
    Announce a runtime instance of a node. The GENERATION is allocated here, never chosen by the node.

    A node that could pick its own generation could pick a current one after being superseded, so the
    allocation is the federation's. Registration confers CANDIDATE and nothing else: it is an
    introduction, not a trust decision.
    """
    if not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    if not str(node_id).strip():
        raise CrucibleError("NODE_REQUIRES_AN_ID", str(node_id))
    if _was_a_worker(db_path, node_id):
        raise CrucibleError(REASON_WORKER_IDENTITY, str(node_id))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        row = connection.execute("SELECT MAX(node_generation) AS latest FROM ciph_federation_nodes "
                                 "WHERE node_id = ?;", (str(node_id),)).fetchone()
        generation = int(row["latest"] or 0) + 1
        connection.execute(
            "INSERT INTO ciph_federation_nodes (node_id, node_generation, public_key_ref, code_digest, "
            "environment_digest, attestation_digest, host_label, endpoint, membership, attested_at, "
            "joined_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (str(node_id), generation, str(public_key_ref), str(code_digest),
             str(environment_digest), None, host_label, endpoint, CANDIDATE, None, moment))
        _event(connection, node_id=str(node_id), generation=generation, event="REGISTER",
               detail=None, actor=str(actor), now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_node(db_path, str(node_id), generation)


def get_node(db_path: str, node_id: str, generation: Optional[int] = None) -> FederationNode:
    connection = _connect(db_path, read_only=True)
    try:
        if generation is None:
            row = connection.execute("SELECT * FROM ciph_federation_nodes WHERE node_id = ? "
                                     "ORDER BY node_generation DESC LIMIT 1;",
                                     (str(node_id),)).fetchone()
        else:
            row = connection.execute("SELECT * FROM ciph_federation_nodes WHERE node_id = ? "
                                     "AND node_generation = ?;",
                                     (str(node_id), int(generation))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_NODE, f"{node_id}:{generation}")
    row = dict(row)
    return FederationNode(node_id=str(row["node_id"]),
                          node_generation=int(row["node_generation"]),
                          public_key_ref=str(row["public_key_ref"]),
                          code_digest=str(row["code_digest"]),
                          environment_digest=str(row["environment_digest"]),
                          attestation_digest=row["attestation_digest"],
                          host_label=row["host_label"], endpoint=row["endpoint"],
                          membership=str(row["membership"]), attested_at=row["attested_at"])


def current_generation(db_path: str, node_id: str) -> int:
    return get_node(db_path, node_id).node_generation


def is_current_generation(db_path: str, node_id: str, generation: int) -> bool:
    try:
        return get_node(db_path, node_id).node_generation == int(generation)
    except CrucibleError:
        return False


def attest_node(db_path: str, node_id: str, generation: int, *, observed_code_digest: str,
                observed_environment_digest: str, observed_public_key_ref: str,
                attestation_digest: Optional[str] = None, actor: str = "operator:operator",
                now: Optional[float] = None) -> FederationNode:
    """
    CANDIDATE -> TRUSTED, against MEASURED facts, by an operator.

    A node cannot attest itself: the observation is the federation's. A mismatch leaves the node a
    CANDIDATE and records why - it does not quietly become trusted with the wrong code on it.
    """
    moment = time.time() if now is None else float(now)
    node = get_node(db_path, node_id, generation)
    if node.membership != CANDIDATE:
        raise CrucibleError(REASON_ILLEGAL_TRANSITION, f"{node.membership}->{TRUSTED}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        if (str(observed_code_digest) != node.code_digest
                or str(observed_environment_digest) != node.environment_digest
                or str(observed_public_key_ref) != node.public_key_ref):
            _event(connection, node_id=node_id, generation=generation, event="ATTEST_MISMATCH",
                   detail=f"code={observed_code_digest[:12]} env={observed_environment_digest[:12]}",
                   actor=actor, now=moment)
            connection.commit()
            raise CrucibleError(REASON_ATTESTATION_MISMATCH, str(node_id))
        connection.execute("UPDATE ciph_federation_nodes SET membership = ?, attested_at = ?, "
                           "attestation_digest = ? WHERE node_id = ? AND node_generation = ?;",
                           (TRUSTED, moment, attestation_digest, str(node_id), int(generation)))
        _event(connection, node_id=node_id, generation=generation, event="ATTEST", detail=None,
               actor=actor, now=moment)
        _event(connection, node_id=node_id, generation=generation, event=TRUSTED, detail=None,
               actor=actor, now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_node(db_path, node_id, generation)


def set_membership(db_path: str, node_id: str, generation: int, *, membership: str, actor: str,
                   reason: Optional[str] = None, now: Optional[float] = None) -> FederationNode:
    """
    Move a node along the membership lifecycle.

    RETIRED is terminal for a GENERATION: the only way back is a new generation, which is a governed
    act. Leaving quarantine goes to CANDIDATE and requires an operator, because re-entry is
    re-attestation rather than a status change.
    """
    if membership not in VALID_MEMBERSHIP:
        raise CrucibleError("UNKNOWN_MEMBERSHIP_STATE", str(membership))
    moment = time.time() if now is None else float(now)
    node = get_node(db_path, node_id, generation)
    if not is_current_generation(db_path, node_id, generation):
        raise CrucibleError("STALE_NODE_GENERATION", f"{node_id}:{generation}")
    if node.membership == RETIRED:
        raise CrucibleError(REASON_RETIRED, f"{node_id}:{generation}")
    if membership not in _TRANSITIONS[node.membership]:
        raise CrucibleError(REASON_ILLEGAL_TRANSITION, f"{node.membership}->{membership}")
    if (node.membership, membership) in _REQUIRES_OPERATOR and not _operator(actor):
        raise CrucibleError(REASON_NOT_OPERATOR, f"{node.membership}->{membership}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_nodes SET membership = ? WHERE node_id = ? "
                           "AND node_generation = ?;", (membership, str(node_id), int(generation)))
        _event(connection, node_id=node_id, generation=generation, event=membership, detail=reason,
               actor=actor, now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_node(db_path, node_id, generation)


def update_endpoint(db_path: str, node_id: str, generation: int, *, endpoint: str, actor: str,
                    now: Optional[float] = None) -> FederationNode:
    """An address change is METADATA about the same node, never a new identity."""
    moment = time.time() if now is None else float(now)
    node = get_node(db_path, node_id, generation)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_nodes SET endpoint = ? WHERE node_id = ? "
                           "AND node_generation = ?;", (str(endpoint), str(node_id),
                                                        int(generation)))
        _event(connection, node_id=node_id, generation=generation, event="ENDPOINT_CHANGED",
               detail=f"{node.endpoint}->{endpoint}", actor=actor, now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_node(db_path, node_id, generation)


def nodes(db_path: str, *, memberships: Sequence[str] = ()) -> List[FederationNode]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT node_id, node_generation FROM ciph_federation_nodes "
            "ORDER BY node_id, node_generation;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    identities = [get_node(db_path, str(row["node_id"]), int(row["node_generation"]))
                  for row in rows]
    latest: Dict[str, int] = {}
    for identity in identities:
        latest[identity.node_id] = max(latest.get(identity.node_id, 0), identity.node_generation)
    wanted = tuple(str(item) for item in memberships)
    return [identity for identity in identities
            if identity.node_generation == latest[identity.node_id]
            and (not wanted or identity.membership in wanted)]


def membership_history(db_path: str, node_id: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_federation_membership"
    params: Tuple[Any, ...] = ()
    if node_id is not None:
        query += " WHERE node_id = ?"
        params = (str(node_id),)
    try:
        return [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, membership_id;", params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def assess_node_health(db_path: str, node_id: str, *, status: str, assessor: str,
                       evidence_refs: Sequence[str] = (), generation: Optional[int] = None,
                       now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record what the federation OBSERVED, not what the node said.

    UNREACHABLE is a first-class status and needs no other evidence: failing to reach a node is a fact
    about the link, and it must not be filed as DEAD or as malignancy. DEGRADED/SUSPECT/QUARANTINED do
    require evidence, because those are claims about the node itself.
    """
    if status not in VALID_HEALTH:
        raise CrucibleError(REASON_UNKNOWN_HEALTH, str(status))
    if str(assessor) == f"node:{node_id}":
        raise CrucibleError(REASON_SELF_HEALTH, str(node_id))
    refs = sorted(str(ref) for ref in evidence_refs)
    if status in (HEALTH_DEGRADED, SUSPECT, HEALTH_QUARANTINE) and not refs:
        raise CrucibleError("NODE_HEALTH_ASSESSMENT_REQUIRES_EVIDENCE", str(status))
    moment = time.time() if now is None else float(now)
    generation = int(generation) if generation is not None else (
        current_generation(db_path, node_id) if _known(db_path, node_id) else 0)
    assessment_id = "FH-" + digest({"node": node_id, "gen": int(generation), "status": status,
                                    "evidence": refs, "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_health (assessment_id, node_id, node_generation, "
            "status, evidence_refs_json, assessor, recorded_at) VALUES (?,?,?,?,?,?,?);",
            (assessment_id, str(node_id), int(generation), str(status), json.dumps(refs),
             str(assessor), moment))
        if status in (HEALTH_QUARANTINE,) and _known(db_path, node_id):
            connection.execute("UPDATE ciph_federation_nodes SET membership = ? WHERE node_id = ? "
                               "AND node_generation = ?;", (QUARANTINED, str(node_id),
                                                            int(generation)))
            _event(connection, node_id=str(node_id), generation=int(generation), event=QUARANTINED,
                   detail=status, actor=str(assessor), now=moment)
        connection.commit()
    finally:
        connection.close()
    return health_of(db_path, node_id, generation)


def _known(db_path: str, node_id: str) -> bool:
    try:
        get_node(db_path, node_id)
        return True
    except CrucibleError:
        return False


def health_of(db_path: str, node_id: str, generation: Optional[int] = None) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        if generation is None:
            row = connection.execute("SELECT * FROM ciph_federation_health WHERE node_id = ? "
                                     "ORDER BY recorded_at DESC, assessment_id DESC LIMIT 1;",
                                     (str(node_id),)).fetchone()
        else:
            row = connection.execute("SELECT * FROM ciph_federation_health WHERE node_id = ? "
                                     "AND node_generation = ? ORDER BY recorded_at DESC, "
                                     "assessment_id DESC LIMIT 1;",
                                     (str(node_id), int(generation))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        return {"node_id": node_id, "node_generation": generation, "status": None,
                "evidence_refs": [], "assessor": None, "policy_version": FEDERATION_HEALTH_V1,
                "is_death": False}
    row = dict(row)
    return {"node_id": str(row["node_id"]), "node_generation": int(row["node_generation"]),
            "status": str(row["status"]),
            "evidence_refs": json.loads(row["evidence_refs_json"] or "[]"),
            "assessor": str(row["assessor"]), "policy_version": FEDERATION_HEALTH_V1,
            "is_death": False}


def retire_node(db_path: str, node_id: str, *, reason: str, actor: str,
                now: Optional[float] = None) -> FederationNode:
    return set_membership(db_path, node_id, current_generation(db_path, node_id), membership=RETIRED,
                          actor=actor, reason=reason, now=now)


def evaluate_rejoin(db_path: str, *, node_id: str, generation: Optional[int],
                    presented_epoch: Optional[int], current_epoch: Optional[int], actor: str,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    THE stale-rejoin gate. A node returning with valid old credentials must not revive old authority.

    The order is deliberate and each refusal is recorded: identity, then generation, then membership,
    then authority epoch. Step four is the one that matters for federation - a node can be perfectly
    itself, on its current generation, trusted, and still be holding a world that has moved twelve
    epochs past it.
    """
    moment = time.time() if now is None else float(now)
    disposition, detail = REJOIN_ACCEPTED, None
    if not _known(db_path, node_id):
        disposition = REJOIN_UNKNOWN
    else:
        node = get_node(db_path, node_id)
        if generation is None or int(generation) != node.node_generation:
            disposition = REJOIN_STALE_GENERATION
        elif node.membership == RETIRED:
            disposition = REJOIN_RETIRED
        elif node.membership == QUARANTINED:
            disposition = REJOIN_REATTEST
        elif node.membership == CANDIDATE:
            disposition = REJOIN_REATTEST
        elif node.membership == DEGRADED:
            disposition = REJOIN_REATTEST
        elif presented_epoch is None or current_epoch is None \
                or int(presented_epoch) != int(current_epoch):
            disposition = REJOIN_STALE_EPOCH
            detail = f"presented {presented_epoch}, current {current_epoch}"
        else:
            detail = "epoch current"
    rejoin_id = "FRJ-" + digest({"node": node_id, "gen": generation, "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_rejoins (rejoin_id, node_id, node_generation, "
            "disposition, presented_epoch, current_epoch, detail, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?);",
            (rejoin_id, str(node_id), generation, disposition, presented_epoch, current_epoch,
             detail, moment))
        if disposition in (REJOIN_STALE_GENERATION, REJOIN_RETIRED, REJOIN_STALE_EPOCH):
            # A refused rejoin makes the node a CANDIDATE again: it must be re-attested before it is
            # trusted with anything, and its own opinion is not part of that decision.
            _event(connection, node_id=str(node_id), generation=int(generation or 0),
                   event="REJOIN_REFUSED", detail=f"{disposition}:{detail}", actor=str(actor),
                   now=moment)
        connection.commit()
    finally:
        connection.close()
    return {"policy_version": FEDERATION_REJOIN_V1, "rejoin_id": rejoin_id, "node_id": str(node_id),
            "node_generation": generation, "disposition": disposition, "detail": detail,
            "authority_revived": False, "recorded_at": moment}


def rejoin_history(db_path: str, node_id: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_federation_rejoins"
    params: Tuple[Any, ...] = ()
    if node_id is not None:
        query += " WHERE node_id = ?"
        params = (str(node_id),)
    try:
        return [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, rejoin_id;", params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def node_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        table = lambda name: [dict(row) for row in connection.execute(  # noqa: E731
            f"SELECT * FROM {name} ORDER BY rowid;")]
        payload = {"nodes": table("ciph_federation_nodes"),
                   "membership": table("ciph_federation_membership"),
                   "health": table("ciph_federation_health"),
                   "rejoins": table("ciph_federation_rejoins")}
    except sqlite3.Error:
        payload = {"nodes": [], "membership": [], "health": [], "rejoins": []}
    finally:
        connection.close()
    return digest({"version": FEDERATION_NODE_IDENTITY_V1, **payload})
