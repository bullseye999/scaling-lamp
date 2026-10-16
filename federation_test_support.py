"""
federation_test_support - one NODE as a real process, for the three-node torture.

Each node gets its own datastore, its own node identity and key, and its own runtime directory - the
local stand-in for three hosts. This module is deliberately NOT a kernel module: it is the mechanism side
of a node, while `ciph/kernel/federation_*` decides what any of it MEANS.

Message passing between nodes is explicit: the harness reads a record from one node's store and offers it
to another's, which is what a replication path does. There is no shared database pretending to be a
network, and no action here grants authority - the nodes attempt transitions and are refused by their own
local copy of the lineage.

Actions:
    join            register + attest this node in its OWN store
    domain          open an authority domain (operator act, in this node's store)
    attempt         try an authoritative transition as this node (expected: refused unless it owns it)
    claim           assert ownership of a domain epoch (expected: conflict unless it matches)
    offer           offer a replicated record (family/origin/digest/epoch/sequence/wall offset)
    quorum          have a set of nodes vote to own a domain (expected: standing = 0)
    ack / unreach   acknowledge a federation barrier, or record that a peer did not answer
    health          assess a node's health from this node's observation
    keys            register / rotate / revoke this node's credential
    digest          print this node's canonical digests
"""

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from ciph.kernel.crucible_types import CrucibleError                                    # noqa: E402
from ciph.kernel.federation_authority import (assert_authoritative, evaluate_quorum_claim,  # noqa: E402
                                              get_domain, open_domain, reconcile_authority_claim)
from ciph.kernel.federation_keys import (register_node_key, revoke_node_key, rotate_node_key)  # noqa: E402
from ciph.kernel.federation_node import (assess_node_health, attest_node, evaluate_rejoin,  # noqa: E402
                                         node_digest, register_node)
from ciph.kernel.federation_quiescence import (acknowledge, observe_unreachable, open_barrier,  # noqa: E402
                                               quiescence_digest)
from ciph.kernel.federation_replication import offer_record, replication_digest  # noqa: E402


def _offset_clock(seconds: float) -> float:
    return time.time() + float(seconds)


def run(db: str, action: str, *, node_id: str, arguments: dict) -> dict:
    result = {"node": node_id, "action": action, "db": os.path.basename(db)}
    if action == "join":
        registered = register_node(db, node_id=node_id, public_key_ref=f"pub-{node_id}",
                                   code_digest=arguments.get("code", "code-1"),
                                   environment_digest="env-1", endpoint=arguments.get("endpoint"),
                                   actor="operator:operator")
        attest_node(db, node_id, registered.node_generation, observed_code_digest="code-1",
                    observed_environment_digest="env-1",
                    observed_public_key_ref=f"pub-{node_id}", actor="operator:operator")
        register_node_key(db, node_id=node_id, node_generation=registered.node_generation,
                          public_key_ref=f"pub-{node_id}", actor="operator:operator")
        result.update({"generation": registered.node_generation, "membership": "TRUSTED"})
    elif action == "domain":
        domain = open_domain(db, domain_id=arguments["domain"], scope=arguments.get("scope", "core"),
                             owner_node_id=arguments["owner"], actor="operator:operator")
        result.update({"domain": domain.domain_id, "owner": domain.owner_node_id,
                       "epoch": domain.authority_epoch})
    elif action == "attempt":
        try:
            domain = assert_authoritative(db, arguments["domain"], node_id=node_id,
                                          generation=int(arguments["generation"]),
                                          epoch=int(arguments["epoch"]))
            result.update({"allowed": True, "owner": domain.owner_node_id})
        except CrucibleError as refused:
            result.update({"allowed": False, "reason": refused.reason})
    elif action == "claim":
        result.update(reconcile_authority_claim(db, domain_id=arguments["domain"], node_id=node_id,
                                                generation=int(arguments["generation"]),
                                                epoch=int(arguments["epoch"])))
    elif action == "quorum":
        result.update(evaluate_quorum_claim(db, domain_id=arguments["domain"],
                                            voters=arguments["voters"],
                                            claimed_epoch=int(arguments["epoch"])))
    elif action == "offer":
        result.update(offer_record(db, family=arguments["family"], origin_node=node_id,
                                   canonical_id=arguments["canonical_id"],
                                   payload_digest=arguments["digest"],
                                   authority_epoch=arguments.get("epoch"),
                                   sequence=int(arguments.get("sequence", 0)),
                                   domain_id=arguments.get("domain"),
                                   node_id=node_id if arguments.get("epoch") else None,
                                   generation=int(arguments.get("generation", 0)) or None,
                                   wall_time=_offset_clock(float(arguments.get("clock_skew", 0.0)))))
    elif action == "ack":
        # `subject` lets this process act FOR another node - which is what delivering a peer's
        # acknowledgement means: the message arrives, and the coordinator records it.
        barrier = acknowledge(db, arguments["barrier"],
                              node_id=arguments.get("subject", node_id),
                              generation=int(arguments["generation"]),
                              outcome=arguments.get("outcome", "ACKNOWLEDGED_QUIESCENT"),
                              actor="operator:operator")
        result.update({"status": barrier.status, "unresolved": list(barrier.unresolved)})
    elif action == "unreach":
        barrier = observe_unreachable(db, arguments["barrier"], node_id=arguments["peer"],
                                      generation=int(arguments.get("peer_generation", 1)),
                                      observed_by=node_id)
        result.update({"status": barrier.status, "unresolved": list(barrier.unresolved)})
    elif action == "barrier":
        barrier = open_barrier(db, actor="operator:operator", snapshot=arguments.get("snapshot"))
        result.update(barrier.as_dict())
    elif action == "rejoin":
        result.update(evaluate_rejoin(db, node_id=node_id, generation=arguments.get("generation"),
                                      presented_epoch=arguments.get("presented_epoch"),
                                      current_epoch=arguments.get("current_epoch"),
                                      actor="operator:operator"))
    elif action == "health":
        result.update(assess_node_health(db, arguments["peer"], status=arguments["status"],
                                        assessor=f"node:{node_id}",
                                        evidence_refs=arguments.get("evidence", []),
                                        generation=arguments.get("peer_generation")))
    elif action == "keys":
        if arguments["op"] == "register":
            key = register_node_key(db, node_id=node_id, node_generation=int(arguments["generation"]),
                                    public_key_ref=arguments["ref"], actor="operator:operator")
            result.update({"key": key.key_id, "state": key.key_state})
        elif arguments["op"] == "rotate":
            key = rotate_node_key(db, node_id=node_id, node_generation=int(arguments["generation"]),
                                  new_public_key_ref=arguments["ref"], actor="operator:operator",
                                  evidence_ref="ROT-1")
            result.update({"key": key.key_id, "state": key.key_state})
        else:
            result.update({"revoked": revoke_node_key(db, node_id=node_id,
                                                      node_generation=int(arguments["generation"]),
                                                      actor="operator:operator", reason="torture")})
    elif action == "digest":
        result.update({"node": node_digest(db), "replication": replication_digest(db),
                       "quiescence": quiescence_digest(db)})
    else:
        raise SystemExit(f"unknown action {action}")
    return result


def main(argv) -> int:
    parser = argparse.ArgumentParser(description="federation node runtime (test support)")
    parser.add_argument("db")
    parser.add_argument("--node", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--args", default="{}")
    arguments = parser.parse_args(argv[1:])
    payload = json.loads(arguments.args)
    print(json.dumps(run(arguments.db, arguments.action, node_id=arguments.node,
                         arguments=payload), sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
