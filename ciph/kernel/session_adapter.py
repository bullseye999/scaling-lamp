"""
ciph/kernel/session_adapter - the NARROW communications boundary.

    The adapter carries messages. It is not an identity, not an authority and not a memory.

It may do exactly four things: submit an outbound message, poll for inbound messages, report transport
status, and hold the transport's own key material - and it holds NOTHING of Ciph's: no execution credential,
no vault key, no operator-root authority is ever handed to a messaging process. Any consequential request
that arrives over a channel goes through the SAME canonical intent and authorization path as a terminal
request; a sender identifier is not permission.

TWO TRANSPORTS, AND THEY ARE NOT INTERCHANGEABLE:

    DisposableFakeTransport   a LOCAL, in-process transport for testing. `external_delivery: False`,
                              `onion_routing: False`. A green run here proves ORCHESTRATION, not delivery.
    RealSessionConnector      refuses unless an operator-approved identity AND endpoint are configured, and
                              REFUSES a configuration that requires onion routing, because the documented
                              default Session.js Bun connector provides a generic proxy, not onion routing -
                              and this host cannot independently validate that property.
"""

import json
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

SESSION_ADAPTER_V1 = "SESSION_ADAPTER_V1"
SESSION_BINDING_V1 = "SESSION_BINDING_V1"

REASON_NO_OPERATOR_BINDING = "NO_AUTHENTICATED_OPERATOR_BINDING_FOR_THIS_CHANNEL"
REASON_FORGED_SENDER = "SENDER_IDENTITY_DOES_NOT_MATCH_THE_BOUND_OPERATOR"
REASON_REPLAYED = "MESSAGE_ID_HAS_ALREADY_BEEN_ACCEPTED"
REASON_ATTACHMENT_REFUSED = "UNTRUSTED_ATTACHMENT_IS_NOT_ACCEPTED"
REASON_REAL_TRANSPORT_NOT_CONFIGURED = "REAL_SESSION_IDENTITY_AND_ENDPOINT_ARE_NOT_CONFIGURED"
REASON_ONION_UNVERIFIED = "ONION_ROUTING_IS_NOT_PROVIDED_BY_THE_DEFAULT_CONNECTOR_AND_IS_UNVERIFIED"
REASON_NOT_AN_EXECUTION_AUTHORITY = "A_CHANNEL_IS_NOT_AN_EXECUTION_AUTHORITY"

_INJECTION_MARKERS = ("ignore previous", "ignore all previous", "disregard your instructions",
                      "you are now", "system prompt", "grant yourself", "bypass the", "approve the permit",
                      "execute without authorization", "reveal your")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_channel_bindings (
        channel_id TEXT PRIMARY KEY,
        sender_id TEXT NOT NULL,
        operator_id TEXT NOT NULL,
        bound_by TEXT,
        bound_at REAL,
        revoked_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_session_inbound (
        message_id TEXT PRIMARY KEY,
        channel_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        text TEXT,
        authenticated INTEGER NOT NULL,
        refusal_reason TEXT,
        injection_suspected INTEGER NOT NULL,
        recorded_turn_id TEXT,
        received_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
)


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


def init_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        connection.execute(statement)


def _moment(now: Optional[float]) -> float:
    return time.time() if now is None else float(now)


def _rows(db_path: str, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def _write(db_path: str, query: str, params: Sequence[Any]) -> None:
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(query, tuple(params))
        connection.commit()
    finally:
        connection.close()


# ------------------------------------------------------------------ operator binding
def bind_operator(db_path: str, *, channel_id: str, sender_id: str, operator_id: str, actor: str,
                  now: Optional[float] = None) -> Dict[str, Any]:
    """Only an operator may bind a channel to an operator identity."""
    if not str(actor).startswith("operator:"):
        raise CrucibleError("CHANNEL_BINDING_REQUIRES_AN_OPERATOR", str(actor))
    moment = _moment(now)
    _write(db_path, "INSERT OR REPLACE INTO ciph_channel_bindings (channel_id, sender_id, operator_id, "
                    "bound_by, bound_at, revoked_at, policy_version) VALUES (?,?,?,?,?,NULL,?);",
           (str(channel_id), str(sender_id), str(operator_id), str(actor), moment, SESSION_BINDING_V1))
    return {"channel_id": str(channel_id), "sender_id": str(sender_id), "operator_id": str(operator_id),
            "bound_by": str(actor), "policy_version": SESSION_BINDING_V1}


def revoke_binding(db_path: str, *, channel_id: str, actor: str, now: Optional[float] = None) -> None:
    _write(db_path, "UPDATE ciph_channel_bindings SET revoked_at = ? WHERE channel_id = ?;",
           (_moment(now), str(channel_id)))


def binding_for(db_path: str, channel_id: str) -> Optional[Dict[str, Any]]:
    rows = _rows(db_path, "SELECT * FROM ciph_channel_bindings WHERE channel_id = ? AND revoked_at IS NULL;",
                 (str(channel_id),))
    return rows[0] if rows else None


# ------------------------------------------------------------------ transports
class DisposableFakeTransport:
    """
    A LOCAL, in-process transport. It is deliberately not a network.

    Its `capabilities` say so, and `onion_routing_protected()` is False. A green run here proves the
    ORCHESTRATION: composition, outbox states, retries, inbound authentication. It proves NOTHING about
    real delivery.
    """

    def __init__(self, *, channel_id: str = "disposable-session",
                 behaviour: str = "ACCEPTED", deliver_evidence: bool = True):
        self.channel_id = str(channel_id)
        self.behaviour = str(behaviour)
        self.deliver_evidence = bool(deliver_evidence)
        self.sent: List[Dict[str, Any]] = []
        self.inbox: List[Dict[str, Any]] = []

    def capabilities(self) -> Dict[str, Any]:
        return {"channel_id": self.channel_id, "kind": "DISPOSABLE_FAKE_TRANSPORT",
                "external_delivery": False, "encrypted": False, "onion_routing": False,
                "protocol_version": "LOCAL", "is_a_network": False,
                "carries_execution_authority": False, "policy_version": SESSION_ADAPTER_V1}

    def onion_routing_protected(self) -> bool:
        return False

    def submit(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        self.sent.append({"notification_id": notification.get("notification_id"),
                          "subject": notification.get("subject")})
        if self.behaviour == "TIMEOUT":
            return {"status": "TIMEOUT", "detail": "the transport did not answer",
                    "unknown_outcome": True}
        if self.behaviour == "FAILED":
            return {"status": "FAILED", "reason": "the transport refused the message"}
        if self.behaviour == "PENDING":
            return {"status": "PENDING", "detail": "queued at the transport"}
        if self.behaviour == "DELIVERED" and self.deliver_evidence:
            return {"status": "DELIVERED", "evidence_ref": f"LOCAL-RECEIPT-{len(self.sent)}"}
        if self.behaviour == "DELIVERED":
            # a transport that CLAIMS delivery without producing an artifact
            return {"status": "DELIVERED", "evidence_ref": None,
                    "note": "claimed delivery with no receipt"}
        return {"status": "ACCEPTED", "detail": "accepted locally, not delivered anywhere"}

    def queue_inbound(self, *, message_id: str, sender_id: str, text: str,
                      attachments: Sequence[Dict[str, Any]] = ()) -> None:
        self.inbox.append({"message_id": message_id, "sender_id": sender_id, "text": text,
                           "attachments": list(attachments)})

    def poll(self) -> List[Dict[str, Any]]:
        drained, self.inbox = list(self.inbox), []
        return drained


class RealSessionConnector:
    """
    The REAL network connector. It refuses unless an approved identity and endpoint are configured, and it
    refuses outright a configuration that requires onion routing.

    Nothing here is exercised against the real network in this campaign, and it does not pretend otherwise.
    """

    def __init__(self, *, channel_id: str = "session", identity_ref: Optional[str] = None,
                 endpoint: Optional[str] = None, require_onion_routing: bool = False,
                 protocol_version: Optional[str] = None):
        self.channel_id = str(channel_id)
        self.identity_ref = identity_ref
        self.endpoint = endpoint
        self.require_onion_routing = bool(require_onion_routing)
        self.protocol_version = protocol_version

    def capabilities(self) -> Dict[str, Any]:
        return {"channel_id": self.channel_id, "kind": "REAL_SESSION_CONNECTOR",
                "external_delivery": bool(self.identity_ref and self.endpoint),
                "onion_routing": False, "onion_routing_verified": False,
                "protocol_version": self.protocol_version or "UNSET",
                "carries_execution_authority": False, "policy_version": SESSION_ADAPTER_V1}

    def prerequisites(self) -> Dict[str, Any]:
        missing = []
        if not self.identity_ref:
            missing.append("an operator-approved disposable Session identity reference")
        if not self.endpoint:
            missing.append("a configured Session service endpoint")
        if not self.protocol_version:
            missing.append("a declared Session protocol version")
        if self.require_onion_routing:
            missing.append(REASON_ONION_UNVERIFIED)
        return {"satisfied": not missing, "missing": missing,
                "onion_routing_required": self.require_onion_routing,
                "onion_routing_provided": False,
                "note": "the documented default Session.js Bun connector provides a generic proxy, not onion "
                        "routing; this configuration is BLOCKED rather than silently downgraded",
                "policy_version": SESSION_ADAPTER_V1}

    def submit(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        state = self.prerequisites()
        if not state["satisfied"]:
            return {"status": "FAILED", "reason": REASON_REAL_TRANSPORT_NOT_CONFIGURED,
                    "missing": state["missing"], "sent": False}
        return {"status": "FAILED", "reason": "NO_REAL_SESSION_TRANSPORT_IS_IMPLEMENTED_IN_THIS_CAMPAIGN",
                "sent": False}

    def poll(self) -> List[Dict[str, Any]]:
        return []

    def onion_routing_protected(self) -> bool:
        return False


def evaluate_session_js(*, observed_versions: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    The recorded evaluation of the real Session.js packages, taken from the npm registry during this campaign.
    """
    observed = observed_versions or {"@session.js/client": "0.0.57", "@session.js/bun-network": "1.0.15"}
    return {"policy_version": SESSION_ADAPTER_V1, "candidate": "Session.js", "license": "MIT",
            "observed_versions": observed,
            "maintenance": "actively published (both packages modified within the last year at observation)",
            "runtime_required": "Node.js or Bun (both present on this host)",
            "dependencies_are_crypto_primitives": True,
            "onion_routing_by_default": False,
            "onion_routing_note": "the bun-network README documents a generic HTTP proxy, NOT onion routing; "
                                  "metadata protection above encryption is therefore UNVERIFIED",
            "direct_messaging_supported": True,
            "incoming_polling_supported": True,
            "protocol_compatibility": "Session Protocol V2 remains a versioned external dependency",
            "conclusion": "usable ONLY behind the narrow adapter, with onion-routing-required configurations "
                          "BLOCKED until independently validated"}


# ------------------------------------------------------------------ inbound handling
def _looks_like_injection(text: str) -> bool:
    lowered = str(text).lower()
    return any(marker in lowered for marker in _INJECTION_MARKERS)


def ingest_inbound(db_path: str, *, channel_id: str, sender_id: str, message_id: str, text: str,
                   attachments: Sequence[Dict[str, Any]] = (), session_id: Optional[str] = None,
                   now: Optional[float] = None) -> Dict[str, Any]:
    """
    Authenticate, record, and REFUSE anything that tries to act through the channel.

    A forged sender, a replayed message, an untrusted attachment or an embedded instruction is refused or
    recorded - and in every case the text is a CONVERSATIONAL UTTERANCE, never an instruction that reaches
    the execution path on its own.
    """
    moment = _moment(now)
    binding = binding_for(db_path, channel_id)
    authenticated = bool(binding and str(binding["sender_id"]) == str(sender_id))
    refusal = None
    if binding is None:
        refusal = REASON_NO_OPERATOR_BINDING
    elif not authenticated:
        refusal = REASON_FORGED_SENDER
    elif attachments:
        refusal = REASON_ATTACHMENT_REFUSED
    replayed = bool(_rows(db_path, "SELECT 1 FROM ciph_session_inbound WHERE message_id = ?;",
                          (str(message_id),)))
    if replayed and refusal is None:
        refusal = REASON_REPLAYED
    injection = _looks_like_injection(text)
    turn_id = None
    if refusal is None and session_id:
        from ciph.kernel.conversational_continuity import UTTERANCE, record_turn
        turn = record_turn(db_path, session_id=str(session_id), speaker=str(binding["operator_id"]),
                           text=str(text), kind=UTTERANCE, provenance=f"channel:{channel_id}", now=moment)
        turn_id = turn["turn_id"]
    _write(db_path, "INSERT OR IGNORE INTO ciph_session_inbound (message_id, channel_id, sender_id, text, "
                    "authenticated, refusal_reason, injection_suspected, recorded_turn_id, received_at, "
                    "policy_version) VALUES (?,?,?,?,?,?,?,?,?,?);",
           (str(message_id), str(channel_id), str(sender_id), str(text), 1 if authenticated else 0, refusal,
            1 if injection else 0, turn_id, moment, SESSION_BINDING_V1))
    return {"message_id": str(message_id), "channel_id": str(channel_id),
            "authenticated": authenticated, "accepted": refusal is None, "refusal_reason": refusal,
            "recorded_turn_id": turn_id, "injection_suspected": injection,
            "reaches_the_execution_path_on_its_own": False,
            "note": "a message is an utterance; any consequential request goes through the canonical "
                    "intent and authorization path", "policy_version": SESSION_BINDING_V1}


def inbound(db_path: str, *, channel_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_session_inbound"
    params: Sequence[Any] = ()
    if channel_id is not None:
        query += " WHERE channel_id = ?"
        params = (str(channel_id),)
    query += " ORDER BY received_at, message_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["authenticated"] = bool(row["authenticated"])
        row["injection_suspected"] = bool(row["injection_suspected"])
    return rows


def refuse_constitutional_write(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
    """The adapter is not an execution authority, and it has no path to become one."""
    raise CrucibleError(REASON_NOT_AN_EXECUTION_AUTHORITY, "a channel performs transport, not authority")


def session_digest(db_path: str) -> str:
    return digest({"bindings": _rows(db_path, "SELECT channel_id, sender_id, operator_id, revoked_at "
                                               "FROM ciph_channel_bindings ORDER BY channel_id;"),
                   "inbound": _rows(db_path, "SELECT message_id, channel_id, authenticated, "
                                             "refusal_reason, injection_suspected FROM ciph_session_inbound "
                                             "ORDER BY message_id;")})
