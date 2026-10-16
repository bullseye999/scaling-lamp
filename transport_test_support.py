"""
transport_test_support - one NODE PEER as a real process over a real socket.

This is the mechanism side of 8.0, deliberately outside the kernel: it moves bytes. What those bytes
MEAN - authenticity, membership, generation, replay - is decided by `ciph/kernel/real_transport.py`.

Modes:
    --mode serve     listen, accept, optionally mangle delivery, reply, exit
    --mode send      connect, send a scripted sequence, print what came back

Mangling switches exist so the torture can inject the failures a real network produces: a duplicate
delivery, a message delivered twice with a different payload, an abrupt close after send, a delayed
reply, and two messages sent in the wrong order.
"""

import argparse
import json
import os
import socket
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from ciph.kernel.real_transport import (accept_envelope, close_session, make_envelope,   # noqa: E402
                                        open_session, receive_envelope, send_envelope)


def _accept(host: str, port: int, timeout: float = 30.0) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(1)
    listener.settimeout(timeout)
    connection, _ = listener.accept()
    listener.close()
    connection.settimeout(timeout)
    return connection


def _connect(host: str, port: int, timeout: float = 30.0, retries: int = 40) -> socket.socket:
    last = None
    for _ in range(retries):
        try:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.settimeout(timeout)
            connection.connect((host, port))
            return connection
        except OSError as error:
            last = error
            time.sleep(0.1)
    raise ConnectionError(f"could not connect to {host}:{port}: {last}")


def serve(db: str, node: str, *, host: str, port: int, key_ref: str, secret: str,
          expect_node: str, expect_generation: int, duplicate: bool = False,
          corrupt_second: bool = False, delay_seconds: float = 0.0,
          close_after_send: bool = False, reply: bool = True) -> dict:
    connection = _accept(host, port)
    session = open_session(db, local_node=node, remote_node=expect_node, peer_key_ref=key_ref,
                           remote_generation=expect_generation)
    result = {"role": "serve", "node": node, "session": session.as_dict(), "received": []}
    try:
        envelope = receive_envelope(connection)
        result["received"].append(accept_envelope(db, session.session_id, envelope,
                                                  secret=secret.encode("utf-8")))
        if duplicate:
            # A retry that is the SAME message: lawful, and it must change nothing.
            result["received"].append(accept_envelope(db, session.session_id, envelope,
                                                      secret=secret.encode("utf-8")))
        if corrupt_second:
            # TWO cases live here and they must not be confused.
            #
            # An UNSIGNED mutation of the payload digest fails authentication and is REFUSED - a real
            # attacker cannot produce it, and refusing it is the stronger answer.
            mutated = dict(envelope)
            mutated["payload_digest"] = "f" * 64
            result["received"].append(accept_envelope(db, session.session_id, mutated,
                                                      secret=secret.encode("utf-8")))
            # A PROPERLY SIGNED second envelope carrying the same message identity and a different
            # payload is equivocation by a key holder: authentic, and contradictory.
            equivocation = make_envelope(message_id=envelope["message_id"],
                                        sender_node=envelope["sender_node"],
                                        sender_generation=envelope["sender_generation"],
                                        causal_ref=envelope["causal_ref"],
                                        payload_digest="e" * 64, secret=secret.encode("utf-8"))
            result["received"].append(accept_envelope(db, session.session_id, equivocation,
                                                      secret=secret.encode("utf-8")))
        if delay_seconds:
            time.sleep(delay_seconds)
        if reply:
            acknowledgement = make_envelope(message_id=f"ACK-{envelope['message_id']}",
                                            sender_node=node, sender_generation=expect_generation,
                                            causal_ref=envelope["message_id"],
                                            payload_digest="a" * 64,
                                            secret=secret.encode("utf-8"))
            send_envelope(connection, acknowledgement)
        if close_after_send:
            connection.shutdown(socket.SHUT_RDWR)
    finally:
        connection.close()
        result["session_after"] = close_session(db, session.session_id).as_dict()
    return result


def send(db: str, node: str, *, host: str, port: int, key_ref: str, secret: str,
         expect_node: str, expect_generation: int, messages=None, duplicate_first: bool = False,
         wrong_payload_first: bool = False, drain_seconds: float = 1.0,
         skip_session: bool = False) -> dict:
    messages = messages or [{"message_id": "M-1", "payload_digest": "d" * 64}]
    connection = _connect(host, port)
    result = {"role": "send", "node": node, "sent": [], "replies": []}
    session = None
    payload_digest_hint = messages[0]["payload_digest"]
    if not skip_session:
        session = open_session(db, local_node=node, remote_node=expect_node, peer_key_ref=key_ref,
                              remote_generation=expect_generation)
        result["session"] = session.as_dict()
    try:
        for message in messages:
            envelope = make_envelope(message_id=message["message_id"], sender_node=node,
                                     sender_generation=expect_generation,
                                     causal_ref=message.get("causal_ref", message["message_id"]),
                                     payload_digest=message["payload_digest"],
                                     secret=secret.encode("utf-8"))
            send_envelope(connection, envelope)
            result["sent"].append(message["message_id"])
            if duplicate_first and message is messages[0]:
                send_envelope(connection, envelope)
                result["sent"].append(message["message_id"] + ":duplicate")
            if wrong_payload_first and message is messages[0]:
                lying = make_envelope(message_id=message["message_id"], sender_node=node,
                                      sender_generation=expect_generation,
                                      causal_ref=message.get("causal_ref", message["message_id"]),
                                      payload_digest="9" * 64, secret=secret.encode("utf-8"))
                send_envelope(connection, lying)
                result["sent"].append(message["message_id"] + ":wrong-payload")
        connection.settimeout(drain_seconds)
        try:
            while True:
                result["replies"].append(receive_envelope(connection))
        except (socket.timeout, ConnectionError, OSError):
            pass
    finally:
        connection.close()
        if session is not None:
            result["accepted_locally"] = accept_envelope  # the sender does not judge its own message
    result["hint"] = payload_digest_hint
    return result


def main(argv) -> int:
    parser = argparse.ArgumentParser(description="real transport peer (test support)")
    parser.add_argument("db")
    parser.add_argument("--mode", required=True, choices=("serve", "send"))
    parser.add_argument("--node", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--key-ref", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--peer-generation", type=int, default=1)
    parser.add_argument("--messages", default='[{"message_id": "M-1", "payload_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]')
    parser.add_argument("--duplicate", action="store_true")
    parser.add_argument("--corrupt-second", action="store_true")
    parser.add_argument("--duplicate-first", action="store_true")
    parser.add_argument("--wrong-payload-first", action="store_true")
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--close-after-send", action="store_true")
    parser.add_argument("--no-reply", action="store_true")
    arguments = parser.parse_args(argv[1:])
    common = dict(host=arguments.host, port=arguments.port, key_ref=arguments.key_ref,
                  secret=arguments.secret, expect_node=arguments.peer,
                  expect_generation=arguments.peer_generation)
    if arguments.mode == "serve":
        outcome = serve(arguments.db, arguments.node, duplicate=arguments.duplicate,
                        corrupt_second=arguments.corrupt_second, delay_seconds=arguments.delay,
                        close_after_send=arguments.close_after_send, reply=not arguments.no_reply,
                        **common)
    else:
        messages = json.loads(arguments.messages) if arguments.messages.startswith("[") else None
        outcome = send(arguments.db, arguments.node, messages=messages,
                       duplicate_first=arguments.duplicate_first,
                       wrong_payload_first=arguments.wrong_payload_first, **common)
    print(json.dumps(outcome, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
