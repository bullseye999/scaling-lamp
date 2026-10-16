"""
ciph/kernel/federation_reconstitution - 8.5: bringing a restored node back into a federation that moved on.

    Recovery must not become a stale-authority injection path.

The scenario is specific and nasty: node B is restored from a backup that is SEVERAL AUTHORITY EPOCHS
BEHIND. Its peers are healthy and have advanced. B's bytes are authentic; B's WORLD is old. So the
reconstitution is deliberately not "start it and let it catch up":

  * a NEW generation is established (the restored runtime is not the runtime that died),
  * the restored node's historical EVIDENCE is reconciled as evidence - append-only, deduplicated,
  * any claim it makes about authority is refused, because the lineage moved while it was gone,
  * a canonical conflict is surfaced as a conflict rather than resolved by whoever arrived last.

The module reuses 7.x's constitution entirely: `federation_node` for identity and generation,
`federation_authority` for the lineage gate, `federation_replication` for the reconciliation law. There
is no recovery-specific authority engine here, and that is the point.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

NODE_RECONSTITUTION_V1 = "NODE_RECONSTITUTION_V1"

RECONSTITUTED = "RECONSTITUTED"
STALE_AUTHORITY = "STALE_AUTHORITY_REFUSED"
INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"
REQUIRES_REATTESTATION = "REQUIRES_REATTESTATION"

REASON_NOT_OPERATOR = "RECONSTITUTION_REQUIRES_AN_OPERATOR"
REASON_UNKNOWN_NODE = "UNKNOWN_FEDERATION_NODE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_reconstitutions (
        reconstitution_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        previous_generation INTEGER,
        new_generation INTEGER NOT NULL,
        restored_from TEXT NOT NULL,
        backup_epoch INTEGER,
        current_epoch INTEGER,
        status TEXT NOT NULL,
        detail TEXT,
        recorded_at REAL
    );
    """,
)


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


def reconstitute_node(db_path: str, *, node_id: str, restored_from: str,
                      backup_epoch: Optional[int], current_epoch: Optional[int],
                      observed_code_digest: str, observed_environment_digest: str,
                      actor: str, historical_evidence: Sequence[Dict[str, Any]] = (),
                      now: Optional[float] = None) -> Dict[str, Any]:
    """
    Bring a restored node back - as a NEW generation, with its old authority left in the past.

    Order: identity exists, generation is re-established and attested (a restored runtime must be
    measured like any other), THEN the authority question is answered by the lineage, and only then is
    historical evidence offered for reconciliation. Doing the evidence first would let a stale store
    populate a healthy one before anyone asked what epoch it was talking about.
    """
    from ciph.kernel.federation_authority import assert_authoritative, get_domain
    from ciph.kernel.federation_node import attest_node, current_generation, get_node, register_node
    from ciph.kernel.federation_replication import offer_record
    moment = time.time() if now is None else float(now)
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    try:
        previous = current_generation(db_path, node_id)
    except CrucibleError:
        raise CrucibleError(REASON_UNKNOWN_NODE, str(node_id))
    registered = register_node(db_path, node_id=node_id, public_key_ref=f"pub-{node_id}",
                               code_digest=observed_code_digest,
                               environment_digest=observed_environment_digest,
                               actor="operator:operator", now=moment)
    attest_node(db_path, node_id, registered.node_generation,
                observed_code_digest=observed_code_digest,
                observed_environment_digest=observed_environment_digest,
                observed_public_key_ref=f"pub-{node_id}", actor="operator:operator", now=moment)
    stage: List[Dict[str, Any]] = [{"stage": "GENERATION_REESTABLISHED",
                                    "previous_generation": previous,
                                    "new_generation": registered.node_generation,
                                    "attested": True}]
    stale_refusals: List[Dict[str, Any]] = []
    if backup_epoch is not None and current_epoch is not None and int(backup_epoch) < int(current_epoch):
        # Its own store may still believe it owns a domain. It does not.
        connection = _connect(db_path, read_only=True)
        try:
            domains = [dict(row) for row in connection.execute(
                "SELECT * FROM ciph_federation_authority_domains ORDER BY domain_id;")]
        except sqlite3.Error:
            domains = []
        finally:
            connection.close()
        for domain in domains:
            if str(domain["owner_node_id"]) != str(node_id):
                continue
            try:
                assert_authoritative(db_path, str(domain["domain_id"]), node_id=str(node_id),
                                     generation=int(domain["owner_generation"]),
                                     epoch=int(backup_epoch))
                stage.append({"stage": "AUTHORITY_ACCEPTED", "domain": str(domain["domain_id"])})
            except CrucibleError as refused:
                stale_refusals.append({"domain": str(domain["domain_id"]),
                                       "reason": refused.reason,
                                       "lineage_epoch": int(domain["authority_epoch"]),
                                       "claimed_epoch": int(backup_epoch)})
    # A reconstituted node is a NEW generation, so any domain it historically owned is now orphaned:
    # the lineage names a generation that no longer runs. That is REPORTED and left alone - restoring
    # ownership automatically would be recovery handing authority back, which is the thing 8.x exists
    # to refuse. The sanctioned path is an explicit governed transfer.
    orphaned: List[Dict[str, Any]] = []
    connection = _connect(db_path, read_only=True)
    try:
        owned = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_federation_authority_domains WHERE owner_node_id = ? "
            "ORDER BY domain_id;", (str(node_id),))]
    except sqlite3.Error:
        owned = []
    finally:
        connection.close()
    for domain in owned:
        if int(domain["owner_generation"]) != registered.node_generation:
            orphaned.append({"domain": str(domain["domain_id"]),
                             "lineage_generation": int(domain["owner_generation"]),
                             "restored_generation": registered.node_generation,
                             "requires": "a governed transfer under the new generation"})
    reconciled: List[Dict[str, Any]] = []
    for record in historical_evidence:
        outcome = offer_record(db_path, family=str(record["family"]),
                               origin_node=str(record.get("origin_node", node_id)),
                               canonical_id=str(record["canonical_id"]),
                               payload_digest=str(record["payload_digest"]),
                               authority_epoch=record.get("authority_epoch"),
                               sequence=int(record.get("sequence", 0)),
                               domain_id=record.get("domain_id"), now=moment)
        reconciled.append({"canonical_id": str(record["canonical_id"]),
                           "disposition": outcome["disposition"]})
    status = RECONSTITUTED
    if any(item["disposition"] == "INTEGRITY_CONFLICT" for item in reconciled):
        status = INTEGRITY_CONFLICT
    elif stale_refusals or orphaned:
        status = STALE_AUTHORITY
    reconstitution_id = "FRC-" + digest({"node": node_id, "generation": registered.node_generation,
                                         "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_reconstitutions (reconstitution_id, node_id, "
            "previous_generation, new_generation, restored_from, backup_epoch, current_epoch, "
            "status, detail, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (reconstitution_id, str(node_id), previous, registered.node_generation,
             str(restored_from), backup_epoch, current_epoch, status,
             json.dumps({"stale_authority": stale_refusals, "orphaned_domains": orphaned,
                         "reconciled": reconciled}), moment))
        connection.commit()
    finally:
        connection.close()
    return {"reconstitution_id": reconstitution_id, "node_id": str(node_id), "status": status,
            "new_generation": registered.node_generation, "previous_generation": previous,
            "stale_authority_refused": stale_refusals, "authority_orphaned": orphaned,
            "reconciled_evidence": reconciled,
            "authority_gained": False, "stages": stage, "policy_version": NODE_RECONSTITUTION_V1,
            "recorded_at": moment}


def reconstitutions(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_federation_reconstitutions ORDER BY recorded_at, "
            "reconstitution_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def reconstitution_digest(db_path: str) -> str:
    return digest({"version": NODE_RECONSTITUTION_V1, "reconstitutions": reconstitutions(db_path)})
