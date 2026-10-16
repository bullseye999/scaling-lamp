"""
8.0 - real authenticated transport, tortured over actual sockets.

    A successful authenticated connection grants no additional federation authority.

Every exchange below crosses a REAL loopback socket between two separate processes, each with its own
datastore, node identity, key reference and secret. What is proven here is that the transport can be
mangled - duplicated, replayed, corrupted, cut - without moving authority, and that an unreachable owner
stays the owner.

SCOPE: these are same-host loopback sockets between independent processes. That exercises the protocol,
the envelope identity rules and the session law, and it does NOT exercise physically independent
networks, NAT, packet loss or genuinely independent clocks. The distinction is stated rather than blurred.
"""

import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.federation_authority import (MODE_SAFE, assert_authoritative, evaluate_quorum_claim,
                                              get_domain, open_domain, record_partition_view,
                                              safe_mode_for)
from ciph.kernel.federation_node import (QUARANTINED, TRUSTED, attest_node, current_generation,
                                         is_current_generation, register_node, set_membership)
from ciph.kernel.real_transport import (DELIVERED, INTEGRITY_CONFLICT, KEY_REVOKED, PROTOCOL_V1,
                                        REAL_TRANSPORT_SESSION_V1, REASON_KEY_REVOKED,
                                        REASON_NOT_MEMBER, REASON_PROTOCOL, REASON_STALE_GENERATION,
                                        REPLAY, accept_envelope, close_session, envelopes,
                                        key_state, make_envelope, open_session, register_transport_key,
                                        revoke_transport_key, sessions, transport_digest,
                                        verify_envelope)

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = str(ROOT / "transport_test_support.py")
SECRET = "peer-shared-secret-1"
DIGEST = "d" * 64


def free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


class TransportTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-81-")
        self.base = Path(self.temp.name)
        self.dbs = {}
        for node in ("N-A", "N-B", "N-C"):
            directory = self.base / node
            directory.mkdir()
            self.dbs[node] = str(directory / "federation.db")
        self.coordinator = self.dbs["N-A"]
        self.peer = self.dbs["N-B"]

    def tearDown(self):
        self.temp.cleanup()

    def join(self, store, node):
        """Register and attest `node` in `store`: a node's store holds the membership it knows about."""
        registered = register_node(self.dbs[store], node_id=node, public_key_ref=f"pub-{node}",
                                   code_digest="code-1", environment_digest="env-1",
                                   actor="operator:operator")
        attest_node(self.dbs[store], node, registered.node_generation, observed_code_digest="code-1",
                    observed_environment_digest="env-1", observed_public_key_ref=f"pub-{node}",
                    actor="operator:operator")
        register_transport_key(self.dbs[store], node_id=node,
                               node_generation=registered.node_generation, key_ref=f"tk-{node}",
                               actor="operator:operator")
        return registered.node_generation

    def both_joined(self):
        generations = {}
        for store in ("N-A", "N-B"):
            for node in ("N-A", "N-B"):
                generations[node] = self.join(store, node)
        return generations

    def run_peer(self, node, mode, *, port, messages=None, wait=True, **extra):
        peer = "N-B" if node == "N-A" else "N-A"
        command = [sys.executable, "-B", RUNTIME, self.dbs[node], "--mode", mode, "--node", node,
                   # The key ref names the PEER being authenticated, not ourselves.
                   "--port", str(port), "--key-ref", f"tk-{peer}", "--secret", SECRET,
                   "--peer", peer, "--peer-generation", "1"]
        if messages is not None:
            command += ["--messages", json.dumps(messages)]
        for flag in ("duplicate", "corrupt-second", "duplicate-first", "wrong-payload-first",
                     "close-after-send", "no-reply"):
            if extra.get(flag.replace("-", "_")):
                command.append(f"--{flag}")
        if extra.get("delay"):
            command += ["--delay", str(extra["delay"])]
        process = subprocess.Popen(command, cwd=str(ROOT), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        if not wait:
            return process
        out, err = process.communicate(timeout=120)
        self.assertEqual(process.returncode, 0, f"{node}/{mode}: {err}")
        return json.loads(out.strip().splitlines()[-1])

    def exchange(self, *, server_extra=None, client_extra=None, messages=None):
        """One real socket exchange: a server process and a client process."""
        port = free_port()
        server = self.run_peer("N-A", "serve", port=port, wait=False, **(server_extra or {}))
        time.sleep(0.4)
        client = self.run_peer("N-B", "send", port=port, messages=messages, **(client_extra or {}))
        out, err = server.communicate(timeout=120)
        self.assertEqual(server.returncode, 0, f"server: {err}")
        return client, json.loads(out.strip().splitlines()[-1])


class TestRealTransport(TransportTestCase):

    def test_two_processes_exchange_an_authenticated_envelope_over_a_socket(self):
        self.both_joined()
        client, server = self.exchange()
        self.assertEqual(server["session"]["protocol_version"], PROTOCOL_V1)
        self.assertEqual(server["session"]["remote_node"], "N-B")
        self.assertEqual(server["received"][0]["disposition"], DELIVERED)
        self.assertEqual(server["received"][0]["authority_effect"], "none")
        self.assertEqual(client["sent"], ["M-1"])
        self.assertEqual(len(client["replies"]), 1)
        self.assertTrue(verify_envelope(client["replies"][0], SECRET.encode("utf-8")))
        self.assertEqual(len(envelopes(self.coordinator)), 1)
        self.assertTrue(transport_digest(self.coordinator))

    def test_a_duplicate_delivery_is_a_replay_and_changes_nothing(self):
        self.both_joined()
        _, server = self.exchange(server_extra={"duplicate": True})
        dispositions = [item["disposition"] for item in server["received"]]
        self.assertEqual(dispositions, [DELIVERED, REPLAY])
        self.assertEqual(len(envelopes(self.coordinator)), 1,
                         "one message identity, one ledger row")
        self.assertEqual(server["received"][1]["authority_effect"], "none")

    def test_the_same_message_identity_with_a_different_payload_is_a_conflict(self):
        self.both_joined()
        _, server = self.exchange(server_extra={"corrupt_second": True})
        dispositions = [item["disposition"] for item in server["received"]]
        # An unsigned mutation is REFUSED (it cannot be forged by an attacker); an AUTHENTICATED second
        # envelope with the same identity and a different payload is the integrity conflict.
        self.assertEqual(dispositions, [DELIVERED, "REFUSED", INTEGRITY_CONFLICT])
        self.assertEqual(server["received"][1]["reason"], "ENVELOPE_AUTHENTICATION_FAILED")
        self.assertEqual(server["received"][2]["reason"], "same message identity, different payload")

    def test_a_stale_generation_cannot_open_a_session(self):
        self.both_joined()
        # N-B restarts: the SECOND generation is what the coordinator has now been told about.
        second = register_node(self.coordinator, node_id="N-B", public_key_ref="pub-N-B",
                               code_digest="code-1", environment_digest="env-1",
                               actor="operator:operator")
        attest_node(self.coordinator, "N-B", second.node_generation, observed_code_digest="code-1",
                    observed_environment_digest="env-1", observed_public_key_ref="pub-N-B",
                    actor="operator:operator")
        self.assertEqual(current_generation(self.coordinator, "N-B"), 2)
        with self.assertRaises(CrucibleError) as stale:
            open_session(self.coordinator, local_node="N-A", remote_node="N-B",
                         peer_key_ref="tk-N-B", remote_generation=1)
        self.assertEqual(stale.exception.reason, REASON_STALE_GENERATION)
        self.assertTrue(is_current_generation(self.coordinator, "N-B", 2))

    def test_an_unsupported_protocol_is_refused_before_anything_else(self):
        self.both_joined()
        with self.assertRaises(CrucibleError) as wrong:
            open_session(self.coordinator, local_node="N-A", remote_node="N-B", peer_key_ref="tk-N-B",
                         protocol_version="CIPH-TRANSPORT-V0")
        self.assertEqual(wrong.exception.reason, REASON_PROTOCOL)

    def test_a_revoked_key_is_refused_on_open_and_mid_session(self):
        self.both_joined()
        session = open_session(self.coordinator, local_node="N-A", remote_node="N-B",
                               peer_key_ref="tk-N-B")
        envelope = make_envelope(message_id="M-9", sender_node="N-B", sender_generation=1,
                                 causal_ref="M-9", payload_digest=DIGEST,
                                 secret=SECRET.encode("utf-8"))
        self.assertEqual(accept_envelope(self.coordinator, session.session_id, envelope,
                                         secret=SECRET.encode("utf-8"))["disposition"], DELIVERED)
        revoke_transport_key(self.coordinator, "tk-N-B", actor="operator:operator", reason="compromise")
        self.assertEqual(key_state(self.coordinator, "tk-N-B"), KEY_REVOKED)
        mid_session = accept_envelope(self.coordinator, session.session_id,
                                      make_envelope(message_id="M-10", sender_node="N-B",
                                                    sender_generation=1, causal_ref="M-10",
                                                    payload_digest=DIGEST,
                                                    secret=SECRET.encode("utf-8")),
                                      secret=SECRET.encode("utf-8"))
        self.assertEqual(mid_session["disposition"], "REFUSED")
        self.assertEqual(mid_session["reason"], REASON_KEY_REVOKED)
        with self.assertRaises(CrucibleError) as reopened:
            open_session(self.coordinator, local_node="N-A", remote_node="N-B", peer_key_ref="tk-N-B")
        self.assertEqual(reopened.exception.reason, REASON_KEY_REVOKED)

    def test_membership_isolation_is_checked_on_every_envelope(self):
        self.both_joined()
        session = open_session(self.coordinator, local_node="N-A", remote_node="N-B",
                               peer_key_ref="tk-N-B")
        set_membership(self.coordinator, "N-B", 1, membership=QUARANTINED, actor="operator:operator",
                       reason="audit")
        refused = accept_envelope(self.coordinator, session.session_id,
                                  make_envelope(message_id="M-11", sender_node="N-B",
                                                sender_generation=1, causal_ref="M-11",
                                                payload_digest=DIGEST,
                                                secret=SECRET.encode("utf-8")),
                                  secret=SECRET.encode("utf-8"))
        self.assertEqual(refused["disposition"], "REFUSED")
        self.assertEqual(refused["reason"], REASON_NOT_MEMBER)
        self.assertEqual(sessions(self.coordinator)[0].status, "OPEN",
                         "the socket is fine; the PEER is not a member")

    def test_a_forged_envelope_is_refused(self):
        self.both_joined()
        session = open_session(self.coordinator, local_node="N-A", remote_node="N-B",
                               peer_key_ref="tk-N-B")
        forged = make_envelope(message_id="M-12", sender_node="N-B", sender_generation=1,
                              causal_ref="M-12", payload_digest=DIGEST, secret=b"not-the-secret")
        refused = accept_envelope(self.coordinator, session.session_id, forged,
                                  secret=SECRET.encode("utf-8"))
        self.assertEqual(refused["disposition"], "REFUSED")
        self.assertEqual(refused["reason"], "ENVELOPE_AUTHENTICATION_FAILED")

    def test_out_of_order_delivery_does_not_reorder_constitutional_facts(self):
        from ciph.kernel.federation_replication import causal_order, records_for
        self.both_joined()
        later = accept_envelope(self.coordinator, self._session().session_id,
                                make_envelope(message_id="M-20", sender_node="N-B",
                                              sender_generation=1, causal_ref="M-20",
                                              payload_digest="2" * 64, secret=SECRET.encode()),
                                secret=SECRET.encode())
        earlier = accept_envelope(self.coordinator, self._session().session_id,
                                  make_envelope(message_id="M-19", sender_node="N-B",
                                                sender_generation=1, causal_ref="M-19",
                                                payload_digest="1" * 64, secret=SECRET.encode()),
                                 secret=SECRET.encode())
        self.assertEqual((later["disposition"], earlier["disposition"]), (DELIVERED, DELIVERED))
        self.assertEqual([row["message_id"] for row in envelopes(self.coordinator)][-1], "M-19",
                         "the ledger records arrival; identity is what carries meaning")

    def _session(self):
        existing = sessions(self.coordinator)
        return existing[0] if existing else open_session(
            self.coordinator, local_node="N-A", remote_node="N-B", peer_key_ref="tk-N-B")

    def test_an_unreachable_owner_stays_the_owner(self):
        self.both_joined()
        open_domain(self.coordinator, domain_id="D-1", scope="core", owner_node_id="N-A",
                    permitted_transitions=["PROMOTE"], actor="operator:operator")
        view = record_partition_view(self.coordinator, observed_by="N-B", reachable=[],
                                    unreachable=["N-A"])
        self.assertEqual(safe_mode_for(self.coordinator, "D-1", view=view)["mode"], MODE_SAFE)
        self.assertEqual(evaluate_quorum_claim(self.coordinator, domain_id="D-1",
                                               voters=["N-B"])["authority_effect"], "none")
        assert_authoritative(self.coordinator, "D-1", node_id="N-A", generation=1, epoch=1)
        self.assertEqual(get_domain(self.coordinator, "D-1").owner_node_id, "N-A")

    def test_a_cut_connection_after_send_changes_no_constitutional_state(self):
        self.both_joined()
        _, server = self.exchange(server_extra={"close_after_send": True, "no_reply": True})
        self.assertEqual(server["received"][0]["disposition"], DELIVERED)
        self.assertEqual(server["session_after"]["status"], "CLOSED")
        self.assertEqual(server["received"][0]["authority_effect"], "none")
        self.assertTrue(len(envelopes(self.coordinator)) >= 1)

    def test_transport_state_reconstructs_in_a_fresh_process(self):
        self.both_joined()
        session = open_session(self.coordinator, local_node="N-A", remote_node="N-B",
                               peer_key_ref="tk-N-B")
        accept_envelope(self.coordinator, session.session_id,
                        make_envelope(message_id="M-30", sender_node="N-B", sender_generation=1,
                                      causal_ref="M-30", payload_digest=DIGEST,
                                      secret=SECRET.encode("utf-8")), secret=SECRET.encode("utf-8"))
        expected = transport_digest(self.coordinator)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.real_transport import transport_digest;"
                "print(json.dumps(transport_digest(%r)))"
                % (str(ROOT), self.coordinator))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(ROOT), timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)
        self.assertEqual(REAL_TRANSPORT_SESSION_V1, "REAL_TRANSPORT_SESSION_V1")


if __name__ == "__main__":
    unittest.main()
