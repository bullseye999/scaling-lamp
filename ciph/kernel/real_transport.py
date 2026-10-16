"""
ciph/kernel/real_transport - 8.0: authenticated transport beneath the 7.x constitution.

    A successful authenticated connection grants no additional federation authority.

7.x proved the partition laws with explicit deliveries and said so. 8.0 replaces the carrier and changes
NOTHING about the law: sessions authenticate a PEER, envelopes carry MESSAGE identity, and both are kept
away from what a node is allowed to DO.

    TLS/mTLS success          != federation membership
    federation membership     != authority-domain ownership
    transport identity        == who is speaking, and nothing else

The design decisions that matter:

  * MESSAGE IDENTITY, not connection identity, is what makes retries boring. An envelope carries a
    `message_id` and a `payload_digest`; a redelivery of the same pair is a REPLAY and has no effect, and
    the same id with a different digest is an INTEGRITY_CONFLICT - there is no third possibility and no
    "probably the new one".
  * SECRETS ARE NOT IN THE DATABASE. The store holds key REFERENCES and their states; the actual secret
    material is supplied by the caller (operator custody). A transport that could dump its own keys would
    be another place for root-adjacent material to leak.
  * EVERY SESSION RE-CHECKS LAW. Membership, generation currency and key state are checked at open AND
    at every envelope, because a peer can be revoked mid-session and a stale runtime can keep talking
    happily on a connection it already has.
"""

import hashlib
import hmac
import json
import socket
import sqlite3
import struct
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

REAL_TRANSPORT_SESSION_V1 = "REAL_TRANSPORT_SESSION_V1"
FEDERATION_ENVELOPE_V1 = "FEDERATION_ENVELOPE_V1"

PROTOCOL_V1 = "CIPH-TRANSPORT-V1"
SUPPORTED_PROTOCOLS = (PROTOCOL_V1,)

SESSION_OPEN = "OPEN"
SESSION_CLOSED = "CLOSED"
SESSION_RESUMED = "RESUMED"
VALID_SESSION_STATES = (SESSION_OPEN, SESSION_CLOSED, SESSION_RESUMED)

DELIVERED = "DELIVERED"
REPLAY = "REPLAY"
INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"
REFUSED = "REFUSED"

KEY_ACTIVE = "ACTIVE"
KEY_REVOKED = "REVOKED"

REASON_NOT_MEMBER = "TRANSPORT_PEER_IS_NOT_A_FEDERATION_MEMBER"
REASON_STALE_GENERATION = "STALE_NODE_GENERATION"
REASON_KEY_REVOKED = "PEER_KEY_REVOKED"
REASON_KEY_UNKNOWN = "UNKNOWN_PEER_KEY"
REASON_PROTOCOL = "UNSUPPORTED_PROTOCOL_VERSION"
REASON_AUTH = "ENVELOPE_AUTHENTICATION_FAILED"
REASON_SESSION = "UNKNOWN_TRANSPORT_SESSION"
REASON_SENDER = "ENVELOPE_SENDER_MISMATCH"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_transport_keys (
        key_ref TEXT PRIMARY KEY,
        node_id TEXT NOT NULL,
        node_generation INTEGER NOT NULL,
        key_state TEXT NOT NULL,
        created_at REAL,
        closed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_transport_sessions (
        session_id TEXT PRIMARY KEY,
        local_node TEXT NOT NULL,
        local_generation INTEGER,
        remote_node TEXT NOT NULL,
        remote_generation INTEGER,
        peer_key_ref TEXT NOT NULL,
        protocol_version TEXT NOT NULL,
        status TEXT NOT NULL,
        opened_at REAL,
        resumed_from TEXT,
        closed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_transport_envelopes (
        envelope_id TEXT PRIMARY KEY,
        message_id TEXT NOT NULL,
        sender_node TEXT NOT NULL,
        sender_generation INTEGER,
        payload_digest TEXT NOT NULL,
        protocol_version TEXT NOT NULL,
        disposition TEXT NOT NULL,
        received_at REAL
    );
    """,
)


@dataclass(frozen=True)
class TransportSession:
    session_id: str
    local_node: str
    local_generation: Optional[int]
    remote_node: str
    remote_generation: Optional[int]
    peer_key_ref: str
    protocol_version: str
    status: str
    resumed_from: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"session_id": self.session_id, "local_node": self.local_node,
                "local_generation": self.local_generation, "remote_node": self.remote_node,
                "remote_generation": self.remote_generation, "peer_key_ref": self.peer_key_ref,
                "protocol_version": self.protocol_version, "status": self.status,
                "resumed_from": self.resumed_from, "policy_version": REAL_TRANSPORT_SESSION_V1}


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


def register_transport_key(db_path: str, *, node_id: str, node_generation: int, key_ref: str,
                           actor: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Register the REFERENCE to a peer key. The secret itself lives with its custodian, not here."""
    if not str(actor).startswith("operator:"):
        raise CrucibleError("TRANSPORT_KEY_REGISTRATION_REQUIRES_AN_OPERATOR", str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_transport_keys (key_ref, node_id, node_generation, key_state, "
            "created_at, closed_at) VALUES (?,?,?,?,?,?);",
            (str(key_ref), str(node_id), int(node_generation), KEY_ACTIVE, moment, None))
        connection.commit()
    finally:
        connection.close()
    return {"key_ref": str(key_ref), "node_id": str(node_id), "node_generation":
            int(node_generation), "key_state": KEY_ACTIVE}


def revoke_transport_key(db_path: str, key_ref: str, *, actor: str, reason: str,
                         now: Optional[float] = None) -> Dict[str, Any]:
    if not str(actor).startswith("operator:"):
        raise CrucibleError("TRANSPORT_KEY_REVOCATION_REQUIRES_AN_OPERATOR", str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_transport_keys SET key_state = ?, closed_at = ? "
                           "WHERE key_ref = ?;", (KEY_REVOKED, moment, str(key_ref)))
        connection.commit()
    finally:
        connection.close()
    return {"key_ref": str(key_ref), "key_state": KEY_REVOKED, "reason": str(reason)}


def key_state(db_path: str, key_ref: str) -> Optional[str]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT key_state FROM ciph_transport_keys WHERE key_ref = ?;",
                                 (str(key_ref),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return str(row["key_state"]) if row is not None else None


def key_owner(db_path: str, key_ref: str) -> Optional[Tuple[str, int]]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT node_id, node_generation FROM ciph_transport_keys "
                                 "WHERE key_ref = ?;", (str(key_ref),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return (str(row["node_id"]), int(row["node_generation"])) if row is not None else None


def open_session(db_path: str, *, local_node: str, remote_node: str, peer_key_ref: str,
                 protocol_version: str = PROTOCOL_V1, local_generation: Optional[int] = None,
                 remote_generation: Optional[int] = None, resumed_from: Optional[str] = None,
                 now: Optional[float] = None) -> TransportSession:
    """
    Authenticate a peer - and stop there.

    Three refusals before a session exists: the protocol must be one we speak, the peer must be a
    TRUSTED federation member on its CURRENT generation, and the key must be ACTIVE and belong to that
    node generation. Note what is NOT checked and NOT granted: nothing here looks at authority domains,
    because a peer being able to talk is not a peer being able to act.
    """
    from ciph.kernel.federation_node import TRUSTED, current_generation, get_node, is_current_generation
    moment = time.time() if now is None else float(now)
    if str(protocol_version) not in SUPPORTED_PROTOCOLS:
        raise CrucibleError(REASON_PROTOCOL, str(protocol_version))
    node = get_node(db_path, str(remote_node))
    if node.membership != TRUSTED:
        raise CrucibleError(REASON_NOT_MEMBER, f"{remote_node}:{node.membership}")
    generation = int(remote_generation) if remote_generation is not None else current_generation(
        db_path, str(remote_node))
    if not is_current_generation(db_path, str(remote_node), generation):
        raise CrucibleError(REASON_STALE_GENERATION, f"{remote_node}:{generation}")
    state = key_state(db_path, str(peer_key_ref))
    if state is None:
        raise CrucibleError(REASON_KEY_UNKNOWN, str(peer_key_ref))
    if state != KEY_ACTIVE:
        raise CrucibleError(REASON_KEY_REVOKED, str(peer_key_ref))
    owner = key_owner(db_path, str(peer_key_ref))
    if owner != (str(remote_node), generation):
        raise CrucibleError(REASON_KEY_UNKNOWN,
                            f"{peer_key_ref} does not belong to {remote_node}@{generation}")
    session_id = "TS-" + digest({"local": str(local_node), "remote": str(remote_node),
                                 "key": str(peer_key_ref), "protocol": str(protocol_version),
                                 "resumed_from": resumed_from})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_transport_sessions (session_id, local_node, "
            "local_generation, remote_node, remote_generation, peer_key_ref, protocol_version, "
            "status, opened_at, resumed_from, closed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (session_id, str(local_node), local_generation, str(remote_node), generation,
             str(peer_key_ref), str(protocol_version),
             SESSION_RESUMED if resumed_from else SESSION_OPEN, moment, resumed_from, None))
        connection.commit()
    finally:
        connection.close()
    return get_session(db_path, session_id)


def get_session(db_path: str, session_id: str) -> TransportSession:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_transport_sessions WHERE session_id = ?;",
                                 (str(session_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_SESSION, str(session_id))
    row = dict(row)
    return TransportSession(session_id=str(row["session_id"]), local_node=str(row["local_node"]),
                            local_generation=row["local_generation"],
                            remote_node=str(row["remote_node"]),
                            remote_generation=row["remote_generation"],
                            peer_key_ref=str(row["peer_key_ref"]),
                            protocol_version=str(row["protocol_version"]),
                            status=str(row["status"]), resumed_from=row["resumed_from"])


def close_session(db_path: str, session_id: str, *, now: Optional[float] = None) -> TransportSession:
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_transport_sessions SET status = ?, closed_at = ? "
                           "WHERE session_id = ?;", (SESSION_CLOSED, moment, str(session_id)))
        connection.commit()
    finally:
        connection.close()
    return get_session(db_path, session_id)


def sessions(db_path: str) -> List[TransportSession]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["session_id"]) for row in connection.execute(
            "SELECT session_id FROM ciph_transport_sessions ORDER BY opened_at, session_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_session(db_path, session_id) for session_id in ids]


# ---------------------------------------------------------------------------- envelopes
def _canonical_bytes(envelope: Dict[str, Any]) -> bytes:
    body = {key: value for key, value in envelope.items() if key != "authentication"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_envelope(*, message_id: str, sender_node: str, sender_generation: Optional[int],
                  causal_ref: str, payload_digest: str, secret: bytes,
                  protocol_version: str = PROTOCOL_V1) -> Dict[str, Any]:
    envelope = {"message_id": str(message_id), "sender_node": str(sender_node),
                "sender_generation": sender_generation, "causal_ref": str(causal_ref),
                "payload_digest": str(payload_digest), "protocol_version": str(protocol_version),
                "policy_version": FEDERATION_ENVELOPE_V1}
    envelope["authentication"] = hmac.new(secret, _canonical_bytes(envelope),
                                          hashlib.sha256).hexdigest()
    return envelope


def verify_envelope(envelope: Dict[str, Any], secret: bytes) -> bool:
    authentication = envelope.get("authentication")
    if not authentication:
        return False
    expected = hmac.new(secret, _canonical_bytes(envelope), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(authentication), expected)


def accept_envelope(db_path: str, session_id: str, envelope: Dict[str, Any], *, secret: bytes,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    Accept or refuse one message, and record what happened either way.

    The order is deliberate: authenticity, then LAW (membership, generation, key state re-checked at
    arrival), then identity (replay or conflict). A message that arrives on a live connection from a peer
    whose membership was revoked mid-session is refused even though the socket is fine - which is the
    whole point of re-checking law per envelope instead of trusting the session.
    """
    from ciph.kernel.federation_node import TRUSTED, get_node, is_current_generation
    moment = time.time() if now is None else float(now)
    session = get_session(db_path, session_id)
    if session.status == SESSION_CLOSED:
        return _record_envelope(db_path, envelope=envelope, disposition=REFUSED, reason=REASON_SESSION,
                                moment=moment)
    if not verify_envelope(envelope, secret):
        return _record_envelope(db_path, envelope=envelope, disposition=REFUSED, reason=REASON_AUTH,
                                moment=moment)
    if str(envelope.get("sender_node")) != session.remote_node:
        return _record_envelope(db_path, envelope=envelope, disposition=REFUSED, reason=REASON_SENDER,
                                moment=moment)
    node = get_node(db_path, session.remote_node)
    if node.membership != TRUSTED:
        return _record_envelope(db_path, envelope=envelope, disposition=REFUSED,
                                reason=REASON_NOT_MEMBER, moment=moment)
    if not is_current_generation(db_path, session.remote_node,
                                 int(envelope.get("sender_generation") or 0)):
        return _record_envelope(db_path, envelope=envelope, disposition=REFUSED,
                                reason=REASON_STALE_GENERATION, moment=moment)
    if key_state(db_path, session.peer_key_ref) != KEY_ACTIVE:
        return _record_envelope(db_path, envelope=envelope, disposition=REFUSED,
                                reason=REASON_KEY_REVOKED, moment=moment)
    message_id = str(envelope.get("message_id"))
    payload_digest = str(envelope.get("payload_digest"))
    if not message_id or not payload_digest:
        return _record_envelope(db_path, envelope=envelope, disposition=REFUSED,
                                reason="ENVELOPE_REQUIRES_IDENTITY", moment=moment)
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT payload_digest, disposition FROM ciph_transport_envelopes "
                                 "WHERE message_id = ?;", (message_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is not None:
        if str(row["payload_digest"]) == payload_digest:
            return _record_envelope(db_path, envelope=envelope, disposition=REPLAY,
                                    reason="same message identity and digest", moment=moment)
        return _record_envelope(db_path, envelope=envelope, disposition=INTEGRITY_CONFLICT,
                                reason="same message identity, different payload", moment=moment)
    return _record_envelope(db_path, envelope=envelope, disposition=DELIVERED, reason=None,
                            moment=moment)


def _record_envelope(db_path: str, *, envelope: Dict[str, Any], disposition: str,
                     reason: Optional[str], moment: float) -> Dict[str, Any]:
    message_id = str(envelope.get("message_id"))
    payload_digest = str(envelope.get("payload_digest"))
    envelope_id = "TE-" + digest({"message_id": message_id, "digest": payload_digest})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_transport_envelopes (envelope_id, message_id, sender_node, "
            "sender_generation, payload_digest, protocol_version, disposition, received_at) "
            "VALUES (?,?,?,?,?,?,?,?);",
            (envelope_id, message_id, str(envelope.get("sender_node")),
             envelope.get("sender_generation"), payload_digest,
             str(envelope.get("protocol_version")), disposition, moment))
        connection.commit()
    finally:
        connection.close()
    return {"envelope_id": envelope_id, "message_id": message_id, "disposition": disposition,
            "reason": reason, "authority_effect": "none",
            "policy_version": FEDERATION_ENVELOPE_V1, "received_at": moment}


def envelopes(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_transport_envelopes ORDER BY received_at, envelope_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


# ---------------------------------------------------------------------------- the wire
_FRAME = struct.Struct("!I")


def send_envelope(sock: socket.socket, envelope: Dict[str, Any]) -> int:
    """Length-prefixed JSON frame. The transport moves BYTES; identity is in the envelope."""
    payload = json.dumps(envelope, sort_keys=True).encode("utf-8")
    sock.sendall(_FRAME.pack(len(payload)) + payload)
    return len(payload)


def receive_envelope(sock: socket.socket) -> Dict[str, Any]:
    header = _read_exactly(sock, _FRAME.size)
    (length,) = _FRAME.unpack(header)
    return json.loads(_read_exactly(sock, length).decode("utf-8"))


def _read_exactly(sock: socket.socket, size: int) -> bytes:
    chunks = b""
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("transport closed before the frame completed")
        chunks += chunk
    return chunks


def transport_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        keys = [dict(row) for row in connection.execute(
            "SELECT key_ref, node_id, node_generation, key_state FROM ciph_transport_keys "
            "ORDER BY key_ref;")]
    except sqlite3.Error:
        keys = []
    finally:
        connection.close()
    return digest({"version": REAL_TRANSPORT_SESSION_V1, "keys": keys,
                   "sessions": [session.as_dict() for session in sessions(db_path)],
                   "envelopes": envelopes(db_path)})
