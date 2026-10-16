"""
federation_clone_assertion - a fresh vault must expose ZERO prior federation state.

Run inside a sanitized clone or against any datastore that has never held federation work. It proves:

  1. no federation nodes, memberships, keys, health records, rejoin attempts, authority domains,
     authority events, partition views, replicated records, reconciliations, barriers, delegations,
     placements or placement attempts exist;
  2. the federation is OPEN because nothing asserted a freeze, and no authority domain exists to be
     owned - so the "no sovereign node" property is the absence of the mechanism, not a flag;
  3. R11 is clean ON THIS TREE: zero violations, zero retained-machinery missing, zero production
     consumers of the ghost-mesh/consensus/sovereignty authority symbols, and zero swarm-federation
     bypasses;
  4. the sixteen federation scanners are zero here too;
  5. every federation digest is computable on an empty datastore.

Exit code 0 means all five hold. Usage: python3 tools/federation_clone_assertion.py [db_path]
"""

import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciph.kernel.federation_authority import authority_digest, domains                    # noqa: E402
from ciph.kernel.federation_delegation import delegation_digest, federation_learning       # noqa: E402
from ciph.kernel.federation_keys import key_digest, key_history                            # noqa: E402
from ciph.kernel.federation_node import membership_history, node_digest, nodes             # noqa: E402
from ciph.kernel.federation_ownership import (assert_ownership_clean,                       # noqa: E402
                                              authority_shaped_consumers, federation_bypasses,
                                              ownership_digest, retained_machinery_missing,
                                              second_federation_authority)
from ciph.kernel.federation_quiescence import (federation_is_frozen, quiescence_digest)     # noqa: E402
from ciph.kernel.federation_replication import (reconciliation_history, records_for,        # noqa: E402
                                                replication_digest)
from ciph.kernel.federation_scanners import federation_scanner_census                       # noqa: E402
from ciph.kernel.federation_state import classification_digest                              # noqa: E402


def _count(db_path: str, table: str) -> int:
    connection = sqlite3.connect(db_path)
    try:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0])
    except sqlite3.Error:
        return 0
    finally:
        connection.close()


def main(argv) -> int:
    temporary = None
    if len(argv) > 1:
        db_path = argv[1]
    else:
        temporary = tempfile.TemporaryDirectory(prefix="ciph-federation-fresh-")
        db_path = str(pathlib.Path(temporary.name) / "fresh.db")

    findings = {
        "nodes": _count(db_path, "ciph_federation_nodes"),
        "memberships": len(membership_history(db_path)),
        "node_keys": len(key_history(db_path)),
        "health": _count(db_path, "ciph_federation_health"),
        "rejoins": _count(db_path, "ciph_federation_rejoins"),
        "authority_domains": len(domains(db_path)),
        "authority_events": _count(db_path, "ciph_federation_authority_events"),
        "partition_views": _count(db_path, "ciph_federation_partitions"),
        "replicated_records": len(records_for(db_path)),
        "reconciliations": len(reconciliation_history(db_path)),
        "barriers": _count(db_path, "ciph_federation_barriers"),
        "live_nodes": len(nodes(db_path, memberships=())),
        "delegations": _count(db_path, "ciph_federation_delegations"),
        "placements": _count(db_path, "ciph_federation_placements"),
        "placement_attempts": _count(db_path, "ciph_federation_placement_attempts"),
    }
    non_empty = {name: count for name, count in findings.items() if count}
    if non_empty:
        print("FRESH_FEDERATION_STATE_NOT_EMPTY:", non_empty)
        return 1
    if federation_is_frozen(db_path):
        print("FRESH_FEDERATION_STATE_IS_FROZEN")
        return 1
    for digest_callable in (node_digest, authority_digest, replication_digest, quiescence_digest,
                            key_digest, delegation_digest, ownership_digest):
        if not digest_callable(db_path):
            print("EMPTY_DIGEST_UNAVAILABLE:", digest_callable.__name__)
            return 1
    if not classification_digest():
        print("CLASSIFICATION_DIGEST_UNAVAILABLE")
        return 1
    report = assert_ownership_clean()
    consumers = {name: list(values) for name, values in authority_shaped_consumers().items()
                 if values}
    if consumers or second_federation_authority() or federation_bypasses() \
            or retained_machinery_missing():
        print("R11_NOT_CLEAN:", {**report, "consumers": consumers})
        return 1
    census = federation_scanner_census()
    if any(census.values()):
        print("FEDERATION_SCANNER_NOT_ZERO:", {k: v for k, v in census.items() if v})
        return 1
    if federation_learning(db_path)["attempts"] != 0:
        print("FRESH_FEDERATION_STATE_HAS_LEARNING")
        return 1
    if temporary is not None:
        temporary.cleanup()
    print("FRESH_FEDERATION_STATE_CLEAN: zero nodes, zero domains, zero history, "
          "R11 clean, 16 scanners zero")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
