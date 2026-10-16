"""
ciph/kernel/federation_replication - 7.8 (reconciliation and divergence) and 7.7 (clock law).

    last-write-wins is not the universal answer.
    timestamp order != constitutional order.

Every family reconciles by its OWN law (7.2's classification decides which), and the laws are:

    REPLICATED_EVIDENCE   append-only union, deduplicated by canonical identity AND digest. Two nodes
                          that observed the same thing merge into one standing record; two nodes that
                          observed different things both survive, because evidence is not a contest.
    DERIVED_PROJECTION    discarded and rebuilt from canonical history. Shipping a projection is
                          shipping a conclusion, and conclusions are re-derived.
    NODE_LOCAL            stays local. A process id is not federation truth.
    SECRET_LOCAL          refused outright: it never enters ordinary replication at all.
    EPHEMERAL             refused; caches are cheaper to rebuild than to reconcile.
    GLOBAL_CANONICAL      the authority LINEAGE decides. A replicated copy may confirm the lineage; a
                          copy that contradicts it is an INTEGRITY CONFLICT - surfaced, never adopted,
                          and never resolved by whichever arrived last.

Wall time crosses one boundary and stops: it is metadata for humans, scheduling and expiry windows. It
never establishes constitutional order, and `authority_winner_by_wall_clock` exists to be a refusal.
"""

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest
from ciph.kernel.federation_state import (DERIVED_PROJECTION, EPHEMERAL, GLOBAL_CANONICAL, NODE_LOCAL,
                                         REPLICATED_EVIDENCE, SECRET_LOCAL, classify, state_class,
                                         travels_in_ordinary_replication)

FEDERATION_RECONCILIATION_V1 = "FEDERATION_RECONCILIATION_V1"
FEDERATION_CLOCK_LAW_V1 = "FEDERATION_CLOCK_LAW_V1"

MERGED = "MERGED"
DUPLICATE = "DUPLICATE"
REBUILT = "REBUILT"
REFUSED_CLASS = "REFUSED_CLASS"
REFUSED_CORRUPT = "REFUSED_CORRUPT"
REFUSED_NOT_OWNER = "REFUSED_NOT_OWNER"
AUTHORITY_CONFIRMED = "AUTHORITY_CONFIRMED"
INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"
KEPT_LOCAL = "KEPT_LOCAL"
VALID_DISPOSITIONS = (MERGED, DUPLICATE, REBUILT, REFUSED_CLASS, REFUSED_CORRUPT, REFUSED_NOT_OWNER,
                      AUTHORITY_CONFIRMED, INTEGRITY_CONFLICT, KEPT_LOCAL)

REASON_BAD_DIGEST = "REPLICATED_RECORD_DIGEST_INVALID"
REASON_WALL_CLOCK = "WALL_CLOCK_CANNOT_DECIDE_CONSTITUTIONAL_ORDER"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_replicated_records (
        record_id TEXT PRIMARY KEY,
        family TEXT NOT NULL,
        state_class TEXT NOT NULL,
        origin_node TEXT NOT NULL,
        origin_generation INTEGER,
        domain_id TEXT,
        canonical_id TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        authority_epoch INTEGER,
        sequence INTEGER NOT NULL,
        wall_time REAL,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_reconciliations (
        reconciliation_id TEXT PRIMARY KEY,
        family TEXT NOT NULL,
        disposition TEXT NOT NULL,
        detail TEXT,
        record_refs_json TEXT,
        recorded_at REAL
    );
    """,
)

# THE CLOCK LAW. Frozen, and stated as permissions and prohibitions rather than as a preference.
CLOCK_LAW: Dict[str, Any] = {
    "policy_version": FEDERATION_CLOCK_LAW_V1,
    "wall_time_may_support": ["scheduling", "expiry windows", "human-readable audit", "timeouts as "
                              "observations"],
    "wall_time_must_not_establish": ["constitutional event order", "authority ownership",
                                     "winner in conflicting histories", "node identity generation",
                                     "quiescence acknowledgement"],
    "constitutional_order": "authority_epoch then durable sequence",
    "skew_policy": "a node whose clock disagrees with its peers gains governed caution, never precedence",
}


@dataclass(frozen=True)
class ReplicatedRecord:
    record_id: str
    family: str
    state_class: str
    origin_node: str
    origin_generation: Optional[int]
    domain_id: Optional[str]
    canonical_id: str
    payload_digest: str
    authority_epoch: Optional[int]
    sequence: int
    wall_time: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"record_id": self.record_id, "family": self.family, "state_class": self.state_class,
                "origin_node": self.origin_node, "origin_generation": self.origin_generation,
                "domain_id": self.domain_id, "canonical_id": self.canonical_id,
                "payload_digest": self.payload_digest, "authority_epoch": self.authority_epoch,
                "sequence": self.sequence, "wall_time": self.wall_time,
                "policy_version": FEDERATION_RECONCILIATION_V1}


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


def _record(db_path: str, record_id: str) -> ReplicatedRecord:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_federation_replicated_records "
                                 "WHERE record_id = ?;", (str(record_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_REPLICATED_RECORD", str(record_id))
    row = dict(row)
    return ReplicatedRecord(record_id=str(row["record_id"]), family=str(row["family"]),
                            state_class=str(row["state_class"]), origin_node=str(row["origin_node"]),
                            origin_generation=row["origin_generation"], domain_id=row["domain_id"],
                            canonical_id=str(row["canonical_id"]),
                            payload_digest=str(row["payload_digest"]),
                            authority_epoch=row["authority_epoch"], sequence=int(row["sequence"]),
                            wall_time=row["wall_time"])


def _note(db_path: str, *, family: str, disposition: str, detail: Optional[str],
          refs: Sequence[str], now: float) -> str:
    reconciliation_id = "FRE-" + digest({"family": family, "disposition": disposition,
                                         "refs": sorted(str(ref) for ref in refs),
                                         "at": now})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_reconciliations (reconciliation_id, family, "
            "disposition, detail, record_refs_json, recorded_at) VALUES (?,?,?,?,?,?);",
            (reconciliation_id, str(family), str(disposition), detail,
             json.dumps(sorted(str(ref) for ref in refs)), now))
        connection.commit()
    finally:
        connection.close()
    return reconciliation_id


def offer_record(db_path: str, *, family: str, origin_node: str, canonical_id: str,
                 payload_digest: str, origin_generation: Optional[int] = None,
                 domain_id: Optional[str] = None, authority_epoch: Optional[int] = None,
                 sequence: int = 0, wall_time: Optional[float] = None,
                 node_id: Optional[str] = None, generation: Optional[int] = None,
                 now: Optional[float] = None) -> Dict[str, Any]:
    """
    Offer one record for replication and get back what may happen to it - decided by its FAMILY.

    The authority branch is the important one: a GLOBAL_CANONICAL record is accepted only if the node
    offering it is the current owner lineage for that domain at that epoch. Otherwise it is either a
    harmless confirmation, a refusal, or an integrity conflict - and never an adoption.
    """
    moment = time.time() if now is None else float(now)
    klass = state_class(family)
    if not _DIGEST.match(str(payload_digest)):
        return {"family": family, "disposition": REFUSED_CORRUPT, "reason": REASON_BAD_DIGEST,
                "stored": False, "recorded_at": moment}
    if klass in (SECRET_LOCAL, NODE_LOCAL, EPHEMERAL, DERIVED_PROJECTION):
        disposition = REBUILT if klass == DERIVED_PROJECTION else (
            KEPT_LOCAL if klass == NODE_LOCAL else REFUSED_CLASS)
        detail = {"state_class": klass, "travels": travels_in_ordinary_replication(family)}
        _note(db_path, family=family, disposition=disposition, detail=json.dumps(detail),
              refs=[canonical_id], now=moment)
        return {"family": family, "disposition": disposition, "stored": False,
                "state_class": klass, "recorded_at": moment}
    if klass == REPLICATED_EVIDENCE:
        connection = _connect(db_path)
        try:
            init_schema(connection)
            existing = connection.execute(
                "SELECT record_id FROM ciph_federation_replicated_records WHERE family = ? "
                "AND canonical_id = ? AND payload_digest = ? LIMIT 1;",
                (str(family), str(canonical_id), str(payload_digest))).fetchone()
            if existing is not None:
                _note(db_path, family=family, disposition=DUPLICATE,
                      detail="same canonical identity and digest", refs=[canonical_id], now=moment)
                return {"family": family, "disposition": DUPLICATE, "stored": False,
                        "duplicate_of": str(existing["record_id"]), "recorded_at": moment}
            record_id = _insert(connection, family=family, state_class=klass,
                                origin_node=origin_node, origin_generation=origin_generation,
                                domain_id=None, canonical_id=canonical_id,
                                payload_digest=payload_digest, authority_epoch=authority_epoch,
                                sequence=sequence, wall_time=wall_time, now=moment)
            connection.commit()
        finally:
            connection.close()
        _note(db_path, family=family, disposition=MERGED, detail="append-only union",
              refs=[record_id], now=moment)
        return {"family": family, "disposition": MERGED, "stored": True, "record_id": record_id,
                "standing_gained": False, "recorded_at": moment}
    # GLOBAL_CANONICAL: the lineage decides, and nothing else does.
    from ciph.kernel.federation_authority import assert_authoritative, evaluate_quorum_claim, get_domain
    if domain_id is None or node_id is None or generation is None or authority_epoch is None:
        _note(db_path, family=family, disposition=REFUSED_NOT_OWNER,
              detail="canonical record without a domain lineage", refs=[canonical_id], now=moment)
        return {"family": family, "disposition": REFUSED_NOT_OWNER,
                "reason": "a canonical record must name the domain lineage it belongs to",
                "stored": False, "recorded_at": moment}
    try:
        assert_authoritative(db_path, str(domain_id), node_id=str(node_id),
                             generation=int(generation), epoch=int(authority_epoch))
    except CrucibleError as refused:
        domain = None
        try:
            domain = get_domain(db_path, str(domain_id))
        except CrucibleError:
            domain = None
        disposition = INTEGRITY_CONFLICT if domain is not None and (
            domain.authority_epoch == int(authority_epoch)) else REFUSED_NOT_OWNER
        _note(db_path, family=family, disposition=disposition, detail=str(refused.reason),
              refs=[canonical_id], now=moment)
        return {"family": family, "disposition": disposition, "stored": False,
                "reason": str(refused.reason), "adopted": False,
                "quorum_claim": evaluate_quorum_claim(db_path, domain_id=str(domain_id),
                                                      voters=[str(node_id)]),
                "recorded_at": moment}
    connection = _connect(db_path)
    try:
        init_schema(connection)
        record_id = _insert(connection, family=family, state_class=klass, origin_node=origin_node,
                            origin_generation=origin_generation, domain_id=str(domain_id),
                            canonical_id=canonical_id, payload_digest=payload_digest,
                            authority_epoch=int(authority_epoch), sequence=sequence,
                            wall_time=wall_time, now=moment)
        connection.commit()
    finally:
        connection.close()
    _note(db_path, family=family, disposition=AUTHORITY_CONFIRMED, detail="lineage confirmed",
          refs=[record_id], now=moment)
    return {"family": family, "disposition": AUTHORITY_CONFIRMED, "stored": True,
            "record_id": record_id, "authority": "confirmed, not created", "recorded_at": moment}


def _insert(connection: sqlite3.Connection, *, family: str, state_class: str, origin_node: str,
            origin_generation: Optional[int], domain_id: Optional[str], canonical_id: str,
            payload_digest: str, authority_epoch: Optional[int], sequence: int,
            wall_time: Optional[float], now: float) -> str:
    record_id = "FRR-" + digest({"family": family, "origin": origin_node, "canonical": canonical_id,
                                "digest": payload_digest})[:16].upper()
    connection.execute(
        "INSERT OR IGNORE INTO ciph_federation_replicated_records (record_id, family, state_class, "
        "origin_node, origin_generation, domain_id, canonical_id, payload_digest, authority_epoch, "
        "sequence, wall_time, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
        (record_id, str(family), str(state_class), str(origin_node), origin_generation, domain_id,
         str(canonical_id), str(payload_digest), authority_epoch, int(sequence), wall_time, now))
    return record_id


def records_for(db_path: str, family: Optional[str] = None) -> List[ReplicatedRecord]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT record_id FROM ciph_federation_replicated_records"
    params: Tuple[Any, ...] = ()
    if family is not None:
        query += " WHERE family = ?"
        params = (str(family),)
    try:
        ids = [str(row["record_id"]) for row in connection.execute(
            query + " ORDER BY rowid;", params)]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [_record(db_path, record_id) for record_id in ids]


def causal_order(records: Sequence[ReplicatedRecord]) -> List[ReplicatedRecord]:
    """
    Constitutional order: (authority_epoch, durable sequence). Wall time is not in the key.

    A node whose clock is an hour fast cannot move ahead of a node whose clock is slow, because the
    ordering simply does not consult clocks.
    """
    return sorted(records, key=lambda item: (item.authority_epoch if item.authority_epoch is not None
                                             else 0, item.sequence, item.record_id))


def authority_winner_by_wall_clock(*, candidates: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """
    The refusal, made executable: there is no winner by timestamp, so this never returns one.
    """
    raise CrucibleError(REASON_WALL_CLOCK,
                        f"{len(candidates)} candidates cannot be ordered by wall clock")


def clock_law() -> Dict[str, Any]:
    return dict(CLOCK_LAW)


def reconcile(db_path: str, *, family: str, records: Sequence[ReplicatedRecord]) -> Dict[str, Any]:
    """
    Reconcile a SET of records under the family's law - the function a healing partition calls.

    Note what is missing: any branch that picks a winner by arrival time. The canonical branch either
    agrees with the lineage or reports a conflict.
    """
    moment = time.time()
    family_meta = classify(family)
    klass = family_meta.state_class
    ordered = causal_order(records)
    if klass == REPLICATED_EVIDENCE:
        seen, merged, duplicates = set(), [], []
        for record in ordered:
            key = (record.canonical_id, record.payload_digest)
            (duplicates if key in seen else merged).append(record.record_id)
            seen.add(key)
        disposition, detail = MERGED, {"merged": merged, "duplicates": duplicates}
    elif klass == DERIVED_PROJECTION:
        disposition, detail = REBUILT, {"discarded": [record.record_id for record in ordered]}
    elif klass in (NODE_LOCAL, EPHEMERAL):
        disposition, detail = KEPT_LOCAL, {"kept_local": [record.record_id for record in ordered]}
    elif klass == SECRET_LOCAL:
        disposition, detail = REFUSED_CLASS, {"refused": [record.record_id for record in ordered]}
    else:
        epochs: Dict[int, set] = {}
        for record in ordered:
            if record.authority_epoch is None:
                continue
            epochs.setdefault(int(record.authority_epoch), set()).add(
                (record.origin_node, record.origin_generation))
        conflicts = {epoch: sorted(str(owner) for owner in owners)
                     for epoch, owners in epochs.items() if len(owners) > 1}
        if conflicts:
            disposition, detail = INTEGRITY_CONFLICT, {"epochs_with_two_owners": conflicts}
        else:
            disposition, detail = AUTHORITY_CONFIRMED, {"epochs": sorted(epochs)}
    _note(db_path, family=family, disposition=disposition, detail=json.dumps(detail),
          refs=[record.record_id for record in ordered], now=moment)
    return {"family": family, "state_class": klass, "disposition": disposition, "detail": detail,
            "order": [record.record_id for record in ordered],
            "ordered_by": "authority_epoch, sequence", "wall_clock_used": False,
            "policy_version": FEDERATION_RECONCILIATION_V1, "recorded_at": moment}


def reconciliation_history(db_path: str, family: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_federation_reconciliations"
    params: Tuple[Any, ...] = ()
    if family is not None:
        query += " WHERE family = ?"
        params = (str(family),)
    try:
        return [dict(row) for row in connection.execute(
            query + " ORDER BY recorded_at, reconciliation_id;", params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def replication_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_federation_replicated_records ORDER BY record_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return digest({"version": FEDERATION_RECONCILIATION_V1, "records": rows,
                   "reconciliations": reconciliation_history(db_path), "clock_law": CLOCK_LAW})
