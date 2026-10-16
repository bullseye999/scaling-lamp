"""
ciph/kernel/federation_authority - 7.3 (distributed authority ownership) and 7.5 (partition semantics).

    Only the current canonical authority lineage may perform authoritative transitions for its domain.
    Loss of communication does not manufacture authority.

The federation does NOT use quorum to move authority. It uses explicit DOMAIN OWNERSHIP: a scope is owned
by one node at one generation at one EPOCH, and a transition is a governed event that increments the
epoch - operator-authorized, evidenced, recorded, and visible to everyone afterwards.

Three refusals carry the phase, and all three are executable functions rather than prose:

    assert_authoritative      a node that is not the owner cannot perform the transition
    evaluate_quorum_claim     B+C agreeing about A's domain has NO standing - the anchor specimen
    safe_mode_for             when the owner goes silent, the answer is SAFE MODE (read and local work
                              continue), never an automatic replacement owner

Partition views are per-OBSERVER. `record_partition_view` says what one node could reach, not what is
true of the world, because "unreachable from here" is exactly the observation that must not be promoted
into "gone".
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

FEDERATION_AUTHORITY_V1 = "FEDERATION_AUTHORITY_V1"
FEDERATION_PARTITION_V1 = "FEDERATION_PARTITION_V1"

DOMAIN_ACTIVE = "ACTIVE"
DOMAIN_FROZEN = "FROZEN"
DOMAIN_RETIRED = "RETIRED"
VALID_DOMAIN_STATUS = (DOMAIN_ACTIVE, DOMAIN_FROZEN, DOMAIN_RETIRED)

MODE_NORMAL = "NORMAL"
MODE_SAFE = "SAFE_MODE"
MODE_FROZEN = "FROZEN"

QUORUM_REFUSED = "REFUSED_NO_STANDING"
INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"
CLAIM_OK = "CLAIM_MATCHES_LINEAGE"

REASON_UNKNOWN_DOMAIN = "UNKNOWN_AUTHORITY_DOMAIN"
REASON_NOT_OWNER = "NOT_THE_AUTHORITY_OWNER"
REASON_STALE_EPOCH = "STALE_AUTHORITY_EPOCH"
REASON_NOT_OPERATOR = "AUTHORITY_TRANSFER_REQUIRES_AN_OPERATOR"
REASON_DOMAIN_NOT_ACTIVE = "AUTHORITY_DOMAIN_NOT_ACTIVE"
REASON_TRANSFER_INCOMPLETE = "AUTHORITY_TRANSFER_REQUIRES_EVIDENCE_AND_TARGET_TRUST"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_authority_domains (
        domain_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        owner_node_id TEXT NOT NULL,
        owner_generation INTEGER NOT NULL,
        authority_epoch INTEGER NOT NULL,
        status TEXT NOT NULL,
        permitted_transitions_json TEXT,
        created_at REAL,
        updated_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_authority_events (
        event_id TEXT PRIMARY KEY,
        domain_id TEXT NOT NULL,
        event TEXT NOT NULL,
        from_owner TEXT,
        to_owner TEXT,
        epoch_before INTEGER,
        epoch_after INTEGER,
        actor TEXT,
        evidence_refs_json TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_partitions (
        partition_id TEXT PRIMARY KEY,
        observed_by TEXT NOT NULL,
        reachable_json TEXT NOT NULL,
        unreachable_json TEXT NOT NULL,
        mode TEXT NOT NULL,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class AuthorityDomain:
    domain_id: str
    scope: str
    owner_node_id: str
    owner_generation: int
    authority_epoch: int
    status: str

    def as_dict(self) -> Dict[str, Any]:
        return {"domain_id": self.domain_id, "scope": self.scope,
                "owner_node_id": self.owner_node_id, "owner_generation": self.owner_generation,
                "authority_epoch": self.authority_epoch, "status": self.status,
                "policy_version": FEDERATION_AUTHORITY_V1}


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


def _event(conn: sqlite3.Connection, *, domain_id: str, event: str, from_owner: Optional[str],
           to_owner: Optional[str], epoch_before: Optional[int], epoch_after: Optional[int],
           actor: Optional[str], evidence: Sequence[str], now: float) -> str:
    event_id = "FAE-" + digest({"domain": domain_id, "event": event, "to": to_owner,
                                "epoch": epoch_after, "at": now})[:16].upper()
    conn.execute("INSERT OR IGNORE INTO ciph_federation_authority_events (event_id, domain_id, event, "
                 "from_owner, to_owner, epoch_before, epoch_after, actor, evidence_refs_json, "
                 "recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
                 (event_id, domain_id, event, from_owner, to_owner, epoch_before, epoch_after, actor,
                  json.dumps(sorted(str(ref) for ref in evidence)), now))
    return event_id


def open_domain(db_path: str, *, domain_id: str, scope: str, owner_node_id: str,
                owner_generation: Optional[int] = None, permitted_transitions: Sequence[str] = (),
                actor: str, now: Optional[float] = None) -> AuthorityDomain:
    """
    Create a domain with an explicit owner. Operator-only: ownership is a grant, never a claim.

    The owner must already be a TRUSTED node - a domain cannot be handed to a stranger, and it cannot be
    handed to a CANDIDATE that has not been measured yet.
    """
    from ciph.kernel.federation_node import TRUSTED, current_generation, get_node
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    owner = get_node(db_path, owner_node_id)
    if owner.membership != TRUSTED:
        raise CrucibleError(REASON_TRANSFER_INCOMPLETE,
                            f"{owner_node_id} is {owner.membership}, not {TRUSTED}")
    generation = int(owner_generation) if owner_generation is not None else current_generation(
        db_path, owner_node_id)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_authority_domains (domain_id, scope, owner_node_id, "
            "owner_generation, authority_epoch, status, permitted_transitions_json, created_at, "
            "updated_at) VALUES (?,?,?,?,?,?,?,?,?);",
            (str(domain_id), str(scope), str(owner_node_id), generation, 1, DOMAIN_ACTIVE,
             json.dumps(sorted(str(item) for item in permitted_transitions)), moment, moment))
        _event(connection, domain_id=str(domain_id), event="OPEN", from_owner=None,
               to_owner=str(owner_node_id), epoch_before=None, epoch_after=1, actor=str(actor),
               evidence=(), now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_domain(db_path, str(domain_id))


def get_domain(db_path: str, domain_id: str) -> AuthorityDomain:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_federation_authority_domains WHERE domain_id = ?;",
                                 (str(domain_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_DOMAIN, str(domain_id))
    row = dict(row)
    return AuthorityDomain(domain_id=str(row["domain_id"]), scope=str(row["scope"]),
                           owner_node_id=str(row["owner_node_id"]),
                           owner_generation=int(row["owner_generation"]),
                           authority_epoch=int(row["authority_epoch"]),
                           status=str(row["status"]))


def domains(db_path: str) -> List[AuthorityDomain]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["domain_id"]) for row in connection.execute(
            "SELECT domain_id FROM ciph_federation_authority_domains ORDER BY domain_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_domain(db_path, domain_id) for domain_id in ids]


def assert_authoritative(db_path: str, domain_id: str, *, node_id: str, generation: int,
                         epoch: Optional[int] = None) -> AuthorityDomain:
    """
    THE mutation gate for distributed authority. Four refusals, in the order that matters:

    unknown domain; domain not ACTIVE; wrong node or wrong GENERATION (a restarted node is not the
    owner its predecessor was); stale EPOCH (a node holding an old world is not the owner of the new
    one). Nothing here consults a vote, a clock or a network view - only the lineage.
    """
    domain = get_domain(db_path, domain_id)
    if domain.status != DOMAIN_ACTIVE:
        raise CrucibleError(REASON_DOMAIN_NOT_ACTIVE, f"{domain_id}:{domain.status}")
    if str(node_id) != domain.owner_node_id or int(generation) != domain.owner_generation:
        raise CrucibleError(REASON_NOT_OWNER,
                            f"{domain_id}:owner={domain.owner_node_id}/{domain.owner_generation}")
    if epoch is not None and int(epoch) != domain.authority_epoch:
        raise CrucibleError(REASON_STALE_EPOCH, f"{domain_id}:{epoch}!={domain.authority_epoch}")
    return domain


def transfer_domain(db_path: str, domain_id: str, *, to_node_id: str, to_generation: Optional[int],
                    actor: str, evidence_ref: str, expected_epoch: int,
                    now: Optional[float] = None) -> AuthorityDomain:
    """
    Move ownership deliberately, by operator act, with evidence and an expected epoch.

    Two things are load-bearing. `expected_epoch` makes the transfer compare-and-swap: if the domain
    moved while the operator was deciding, the transfer is refused rather than applied to a world that
    changed underneath it. And the target must be TRUSTED on its CURRENT generation, so a transfer can
    never quietly hand a domain to a superseded runtime.
    """
    from ciph.kernel.federation_node import TRUSTED, current_generation, get_node
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    if not str(evidence_ref).strip():
        raise CrucibleError(REASON_TRANSFER_INCOMPLETE, "evidence required")
    moment = time.time() if now is None else float(now)
    domain = get_domain(db_path, domain_id)
    if int(expected_epoch) != domain.authority_epoch:
        raise CrucibleError(REASON_STALE_EPOCH,
                            f"{domain_id}:expected {expected_epoch}, at {domain.authority_epoch}")
    target = get_node(db_path, to_node_id)
    if target.membership != TRUSTED:
        raise CrucibleError(REASON_TRANSFER_INCOMPLETE, f"{to_node_id}:{target.membership}")
    generation = int(to_generation) if to_generation is not None else current_generation(
        db_path, to_node_id)
    if generation != target.node_generation:
        raise CrucibleError("STALE_NODE_GENERATION", f"{to_node_id}:{generation}")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_authority_domains SET owner_node_id = ?, "
                           "owner_generation = ?, authority_epoch = ?, updated_at = ? "
                           "WHERE domain_id = ?;",
                           (str(to_node_id), generation, domain.authority_epoch + 1, moment,
                            str(domain_id)))
        _event(connection, domain_id=str(domain_id), event="TRANSFER",
               from_owner=f"{domain.owner_node_id}@{domain.owner_generation}",
               to_owner=f"{to_node_id}@{generation}", epoch_before=domain.authority_epoch,
               epoch_after=domain.authority_epoch + 1, actor=str(actor),
               evidence=[str(evidence_ref)], now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_domain(db_path, str(domain_id))


def reconcile_authority_claim(db_path: str, *, domain_id: str, node_id: str, generation: int,
                              epoch: int, now: Optional[float] = None) -> Dict[str, Any]:
    """
    What to do when another node asserts ownership of a domain.

    A claim that matches the lineage is confirmation. A claim for an epoch the lineage already settled
    with a DIFFERENT owner is INTEGRITY_CONFLICT - two valid-looking histories, surfaced rather than
    resolved by whichever arrived last. There is no timestamp tiebreak here, deliberately.
    """
    moment = time.time() if now is None else float(now)
    try:
        domain = get_domain(db_path, domain_id)
    except CrucibleError:
        return {"domain_id": str(domain_id), "status": REASON_UNKNOWN_DOMAIN, "adopted": False,
                "recorded_at": moment}
    matches = (domain.owner_node_id == str(node_id)
               and domain.owner_generation == int(generation)
               and domain.authority_epoch == int(epoch))
    if matches:
        return {"domain_id": str(domain_id), "status": CLAIM_OK, "adopted": False,
                "authority": "unchanged", "recorded_at": moment}
    connection = _connect(db_path)
    try:
        init_schema(connection)
        _event(connection, domain_id=str(domain_id), event="CONFLICTING_CLAIM",
               from_owner=f"{domain.owner_node_id}@{domain.owner_generation}",
               to_owner=f"{node_id}@{generation}", epoch_before=int(epoch),
               epoch_after=domain.authority_epoch, actor=None,
               evidence=[f"claimed-epoch:{epoch}"], now=moment)
        connection.commit()
    finally:
        connection.close()
    return {"domain_id": str(domain_id), "status": INTEGRITY_CONFLICT, "adopted": False,
            "authority": "unchanged", "claimed_owner": f"{node_id}@{generation}@{epoch}",
            "lineage_owner": f"{domain.owner_node_id}@{domain.owner_generation}"
                             f"@{domain.authority_epoch}",
            "resolution": "surfaced, not adopted; no timestamp tiebreak", "recorded_at": moment}


def evaluate_quorum_claim(db_path: str, *, domain_id: str, voters: Sequence[str],
                          claimed_epoch: Optional[int] = None,
                          now: Optional[float] = None) -> Dict[str, Any]:
    """
    THE anchor specimen of 7.x: a majority agreeing about somebody else's domain.

    B+C (or 5/7) can be unanimous, well-intentioned and genuinely able to reach each other. The answer is
    still no, because counting agreement is not a constitutional transition. This function exists so the
    refusal has a name and an executable form rather than living in a design document.
    """
    moment = time.time() if now is None else float(now)
    try:
        domain = get_domain(db_path, domain_id)
    except CrucibleError:
        return {"domain_id": str(domain_id), "disposition": QUORUM_REFUSED, "votes_for": len(voters),
                "authority_effect": "none", "reason": REASON_UNKNOWN_DOMAIN, "recorded_at": moment}
    voters = [str(voter) for voter in voters]
    is_owner_among = any(voter == domain.owner_node_id for voter in voters)
    return {"domain_id": str(domain_id), "disposition": QUORUM_REFUSED, "votes_for": len(voters),
            "voters": sorted(voters), "owner_among_voters": is_owner_among,
            "claimed_epoch": claimed_epoch, "current_epoch": domain.authority_epoch,
            "authority_effect": "none", "owner_unchanged": domain.owner_node_id,
            "reason": ("counting agreement is not a transition; a domain moves only by a governed "
                       "transfer"),
            "recorded_at": moment}


def record_partition_view(db_path: str, *, observed_by: str, reachable: Sequence[str],
                          unreachable: Sequence[str], now: Optional[float] = None) -> Dict[str, Any]:
    """
    One node's VIEW of who it can reach - an observation, not a fact about the world.

    The distinction is the whole point: `unreachable` here means "not from here, not right now", which is
    why nothing downstream may read it as death or as a vacancy.
    """
    moment = time.time() if now is None else float(now)
    partition_id = "FPV-" + digest({"by": observed_by, "reachable": sorted(map(str, reachable)),
                                   "unreachable": sorted(map(str, unreachable)),
                                   "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_partitions (partition_id, observed_by, "
            "reachable_json, unreachable_json, mode, recorded_at) VALUES (?,?,?,?,?,?);",
            (partition_id, str(observed_by), json.dumps(sorted(str(item) for item in reachable)),
             json.dumps(sorted(str(item) for item in unreachable)), "OBSERVED", moment))
        connection.commit()
    finally:
        connection.close()
    return {"partition_id": partition_id, "observed_by": str(observed_by),
            "reachable": sorted(str(item) for item in reachable),
            "unreachable": sorted(str(item) for item in unreachable),
            "is_a_fact_about_the_world": False, "implies_death": False, "policy_version":
                FEDERATION_PARTITION_V1, "recorded_at": moment}


def safe_mode_for(db_path: str, domain_id: str, *, view: Dict[str, Any]) -> Dict[str, Any]:
    """
    What a node may do while the owner is not reachable.

    The owner reachable: NORMAL. The owner not reachable FROM HERE: SAFE MODE - read-only and local work
    continue, and no replacement owner appears. Availability is allowed to fall before safety does; that
    is the choice, made explicitly, rather than the accident that creates split brain.
    """
    domain = get_domain(db_path, domain_id)
    unreachable = set(view.get("unreachable") or ())
    owner_reachable = domain.owner_node_id not in unreachable
    return {"domain_id": domain_id, "mode": MODE_NORMAL if owner_reachable else MODE_SAFE,
            "owner": f"{domain.owner_node_id}@{domain.owner_generation}",
            "epoch": domain.authority_epoch,
            "can_perform_authoritative_transitions": owner_reachable,
            "may_read": True, "may_do_local_work": True,
            "creates_replacement_owner": False,
            "note": ("loss of communication does not manufacture authority"), "policy_version":
                FEDERATION_PARTITION_V1}


def set_domain_status(db_path: str, domain_id: str, *, status: str, actor: str,
                      now: Optional[float] = None) -> AuthorityDomain:
    if status not in VALID_DOMAIN_STATUS:
        raise CrucibleError("UNKNOWN_DOMAIN_STATUS", str(status))
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    domain = get_domain(db_path, domain_id)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_federation_authority_domains SET status = ?, updated_at = ? "
                           "WHERE domain_id = ?;", (str(status), moment, str(domain_id)))
        _event(connection, domain_id=str(domain_id), event=f"STATUS_{status}", from_owner=None,
               to_owner=None, epoch_before=domain.authority_epoch, epoch_after=domain.authority_epoch,
               actor=str(actor), evidence=(), now=moment)
        connection.commit()
    finally:
        connection.close()
    return get_domain(db_path, str(domain_id))


def authority_events(db_path: str, domain_id: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_federation_authority_events"
    params: Tuple[Any, ...] = ()
    if domain_id is not None:
        query += " WHERE domain_id = ?"
        params = (str(domain_id),)
    try:
        return [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, event_id;", params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def authority_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        partitions = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_federation_partitions ORDER BY partition_id;")]
    except sqlite3.Error:
        partitions = []
    finally:
        connection.close()
    return digest({"version": FEDERATION_AUTHORITY_V1,
                   "domains": [domain.as_dict() for domain in domains(db_path)],
                   "events": authority_events(db_path), "partition_views": partitions})
