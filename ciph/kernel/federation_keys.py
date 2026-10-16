"""
ciph/kernel/federation_keys - 7.9: key and secret custody.

    Ciph root identity -> authorized node identities -> node-specific credentials.

The architecture question this answers is: what does a compromised node cost? If the answer is "the whole
Ciph identity", the federation is not a federation, it is a copy of one secret on several disks. So:

    * the ROOT stays with the operator. Root custody is not distributed in V1, and that is stated as a
      limit rather than dressed up as distributed key management.
    * a NODE has its own credential, registered against its generation, rotatable and revocable.
    * membership therefore does NOT imply root authority. `node_holds_root_authority` returns False with
      the reason attached, so the boundary has somewhere to live besides a diagram.
    * rotation and revocation are append-only events: the history of which credential was valid when is
      never rewritten, because that history is what a rejoin challenge is checked against.
"""

import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

FEDERATION_KEY_CUSTODY_V1 = "FEDERATION_KEY_CUSTODY_V1"

KEY_ACTIVE = "ACTIVE"
KEY_ROTATED = "ROTATED"
KEY_REVOKED = "REVOKED"
VALID_KEY_STATES = (KEY_ACTIVE, KEY_ROTATED, KEY_REVOKED)

REASON_NOT_OPERATOR = "KEY_CUSTODY_CHANGE_REQUIRES_AN_OPERATOR"
REASON_NO_ACTIVE_KEY = "NODE_HAS_NO_ACTIVE_CREDENTIAL_FOR_THIS_GENERATION"
REASON_REVOKED = "NODE_CREDENTIAL_REVOKED"
REASON_UNKNOWN_KEY = "UNKNOWN_NODE_KEY"

_ROOT_LAW = ("Ciph root custody remains with the operator (offline). Node membership grants a node its "
             "OWN credential and never the root identity; distributing root custody is explicitly NOT "
             "solved here and is recorded as a stated limit rather than implied.")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_federation_node_keys (
        key_id TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        node_generation INTEGER NOT NULL,
        public_key_ref TEXT NOT NULL,
        key_state TEXT NOT NULL,
        rotated_from TEXT,
        reason TEXT,
        created_at REAL,
        closed_at REAL
    );
    """,
)


@dataclass(frozen=True)
class NodeKey:
    key_id: str
    node_id: str
    node_generation: int
    public_key_ref: str
    key_state: str
    rotated_from: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"key_id": self.key_id, "node_id": self.node_id,
                "node_generation": self.node_generation, "public_key_ref": self.public_key_ref,
                "key_state": self.key_state, "rotated_from": self.rotated_from,
                "policy_version": FEDERATION_KEY_CUSTODY_V1}


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


def _from_row(row: Any) -> NodeKey:
    row = dict(row)
    return NodeKey(key_id=str(row["key_id"]), node_id=str(row["node_id"]),
                   node_generation=int(row["node_generation"]),
                   public_key_ref=str(row["public_key_ref"]), key_state=str(row["key_state"]),
                   rotated_from=row["rotated_from"])


def register_node_key(db_path: str, *, node_id: str, node_generation: int, public_key_ref: str,
                      actor: str, now: Optional[float] = None) -> NodeKey:
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    key_id = "FNK-" + digest({"node": node_id, "gen": int(node_generation),
                              "ref": public_key_ref})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_node_keys (key_id, node_id, node_generation, "
            "public_key_ref, key_state, rotated_from, reason, created_at, closed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?);",
            (key_id, str(node_id), int(node_generation), str(public_key_ref), KEY_ACTIVE, None, None,
             moment, None))
        connection.commit()
    finally:
        connection.close()
    return get_key(db_path, key_id)


def get_key(db_path: str, key_id: str) -> NodeKey:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_federation_node_keys WHERE key_id = ?;",
                                 (str(key_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_KEY, str(key_id))
    return _from_row(row)


def active_key(db_path: str, node_id: str, generation: Optional[int] = None) -> Optional[NodeKey]:
    from ciph.kernel.federation_node import current_generation
    resolved = int(generation) if generation is not None else current_generation(db_path, node_id)
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_federation_node_keys WHERE node_id = ? "
                                 "AND node_generation = ? AND key_state = ? "
                                 "ORDER BY created_at DESC LIMIT 1;",
                                 (str(node_id), resolved, KEY_ACTIVE)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return _from_row(row) if row is not None else None


def rotate_node_key(db_path: str, *, node_id: str, node_generation: int, new_public_key_ref: str,
                    actor: str, evidence_ref: str, now: Optional[float] = None) -> NodeKey:
    """
    Replace a node's credential, keeping the record of what was valid before.

    A rotation is not an edit: the old key becomes ROTATED and the new one ACTIVE, so a challenge can
    always ask "was this credential the node's at the time?" and get a truthful answer.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    if not str(evidence_ref).strip():
        raise CrucibleError("KEY_ROTATION_REQUIRES_EVIDENCE", str(node_id))
    moment = time.time() if now is None else float(now)
    previous = active_key(db_path, node_id, node_generation)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        if previous is not None:
            connection.execute("UPDATE ciph_federation_node_keys SET key_state = ?, closed_at = ?, "
                               "reason = ? WHERE key_id = ?;",
                               (KEY_ROTATED, moment, f"rotated:{evidence_ref}", previous.key_id))
        connection.commit()
    finally:
        connection.close()
    key_id = "FNK-" + digest({"node": node_id, "gen": int(node_generation),
                              "ref": new_public_key_ref})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_federation_node_keys (key_id, node_id, node_generation, "
            "public_key_ref, key_state, rotated_from, reason, created_at, closed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?);",
            (key_id, str(node_id), int(node_generation), str(new_public_key_ref), KEY_ACTIVE,
             previous.key_id if previous else None, f"rotation:{evidence_ref}", moment, None))
        connection.commit()
    finally:
        connection.close()
    return get_key(db_path, key_id)


def revoke_node_key(db_path: str, *, node_id: str, node_generation: Optional[int] = None,
                    actor: str, reason: str, now: Optional[float] = None) -> List[str]:
    """Revoke every active credential for a node generation. Revoked means revoked, for good."""
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        if node_generation is None:
            cursor = connection.execute("UPDATE ciph_federation_node_keys SET key_state = ?, "
                                        "closed_at = ?, reason = ? WHERE node_id = ? AND "
                                        "key_state = ?;",
                                        (KEY_REVOKED, moment, str(reason), str(node_id), KEY_ACTIVE))
        else:
            cursor = connection.execute("UPDATE ciph_federation_node_keys SET key_state = ?, "
                                        "closed_at = ?, reason = ? WHERE node_id = ? "
                                        "AND node_generation = ? AND key_state = ?;",
                                        (KEY_REVOKED, moment, str(reason), str(node_id),
                                         int(node_generation), KEY_ACTIVE))
        connection.commit()
        revoked = int(cursor.rowcount)
    finally:
        connection.close()
    return [f"{node_id}:revoked:{revoked}"]


def assert_node_key_boundary(db_path: str, *, node_id: str, generation: int) -> NodeKey:
    """
    A node presenting old credentials is refused at the boundary - not reconciled afterwards.

    The check is against the CURRENT generation: a retired or superseded credential does not
    authenticate, which is what stops a stale node from walking back in on the strength of a key that
    used to be valid.
    """
    from ciph.kernel.federation_node import is_current_generation
    if not is_current_generation(db_path, node_id, generation):
        raise CrucibleError("STALE_NODE_GENERATION", f"{node_id}:{generation}")
    key = active_key(db_path, node_id, generation)
    if key is None:
        raise CrucibleError(REASON_NO_ACTIVE_KEY, f"{node_id}:{generation}")
    return key


def node_holds_root_authority(node_id: str) -> Dict[str, Any]:
    """The boundary, executable: no node holds the root, whatever its membership says."""
    return {"node_id": str(node_id), "holds_root_authority": False,
            "root_custody": "operator", "reason": _ROOT_LAW,
            "policy_version": FEDERATION_KEY_CUSTODY_V1}


def root_custody_law() -> Dict[str, Any]:
    return {"policy_version": FEDERATION_KEY_CUSTODY_V1, "root_custody": "operator-held, offline",
            "stated_limit": _ROOT_LAW,
            "compromise_scope": "a node credential compromise does not imply root compromise"}


def key_history(db_path: str, node_id: Optional[str] = None) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_federation_node_keys"
    params: Tuple[Any, ...] = ()
    if node_id is not None:
        query += " WHERE node_id = ?"
        params = (str(node_id),)
    try:
        return [dict(row) for row in connection.execute(
            query + " ORDER BY created_at, key_id;", params)]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def key_digest(db_path: str) -> str:
    return digest({"version": FEDERATION_KEY_CUSTODY_V1, "keys": key_history(db_path),
                   "root_law": root_custody_law()})
