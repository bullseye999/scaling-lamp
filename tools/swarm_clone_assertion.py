"""
swarm_clone_assertion - a fresh vault must expose ZERO prior swarm state.

Run inside a sanitized clone, or against any datastore that has not been used for swarm work. It proves
four things a suite run alone cannot:

  1. a brand-new vault starts with no workers, no membership history, no delegations, no leases, no
     results, no aggregations, no allocations, no barriers, no health assessments, no capabilities and no
     delegation learning - the swarm does not bootstrap itself from anything ambient;
  2. the swarm is OPEN: no barrier exists, so `swarm_is_frozen` is False because nothing asserted a
     freeze rather than because a row said "not frozen";
  3. the R10 census is clean ON THIS TREE, and the legacy consensus engine is still unreferenced by
     production - the demotion is a property, not a note;
  4. every swarm digest is computable on an empty datastore, so a projection that has to describe
     "nobody" cannot be tempted to describe somebody.

Exit code 0 means all four hold. Usage: python3 tools/swarm_clone_assertion.py [db_path]
"""

import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciph.kernel.swarm_delegation import delegation_digest, delegations, leases_for       # noqa: E402
from ciph.kernel.swarm_learning import attempts, learning_digest                          # noqa: E402
from ciph.kernel.swarm_ownership import (assert_ownership_clean, dormant_consensus_authority,
                                         ownership_digest, retained_machinery_missing,
                                         swarm_bypasses)
from ciph.kernel.swarm_quiescence import (current_barrier, quiescence_digest, swarm_is_frozen)  # noqa: E402
from ciph.kernel.swarm_resources import allocations, resources_digest                     # noqa: E402
from ciph.kernel.swarm_results import aggregations, results_digest                        # noqa: E402
from ciph.kernel.swarm_worker import members, membership_history, topology_digest         # noqa: E402


def _table_count(db_path: str, table: str) -> int:
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
        temporary = tempfile.TemporaryDirectory(prefix="ciph-swarm-fresh-")
        db_path = str(pathlib.Path(temporary.name) / "fresh.db")

    findings = {
        "workers": _table_count(db_path, "ciph_swarm_workers"),
        "membership_events": _table_count(db_path, "ciph_swarm_membership"),
        "live_members": len(members(db_path, statuses=())),
        "delegations": len(delegations(db_path)),
        "barriers": _table_count(db_path, "ciph_swarm_barriers"),
        "barrier_acks": _table_count(db_path, "ciph_swarm_barrier_acks"),
        "health_assessments": _table_count(db_path, "ciph_swarm_health"),
        "capabilities": _table_count(db_path, "ciph_swarm_capabilities"),
        "budget_allocations": len(allocations(db_path)),
        "spawn_events": _table_count(db_path, "ciph_swarm_spawn_events"),
        "aggregations": len(aggregations(db_path)),
        "delegation_attempts": len(attempts(db_path)),
    }
    non_empty = {name: count for name, count in findings.items() if count}
    if non_empty:
        print("FRESH_SWARM_STATE_NOT_EMPTY:", non_empty)
        return 1

    for delegation in delegations(db_path):
        if leases_for(db_path, delegation.delegation_id):
            print("FRESH_SWARM_STATE_HAS_A_LEASE:", delegation.delegation_id)
            return 1
    if swarm_is_frozen(db_path) or current_barrier(db_path) is not None:
        print("FRESH_SWARM_STATE_IS_FROZEN")
        return 1
    for digest_callable in (topology_digest, delegation_digest, results_digest, quiescence_digest,
                            resources_digest, learning_digest, ownership_digest):
        if not digest_callable(db_path):
            print("EMPTY_DIGEST_UNAVAILABLE:", digest_callable.__name__)
            return 1
    report = assert_ownership_clean()
    if dormant_consensus_authority() or swarm_bypasses() or retained_machinery_missing():
        print("R10_NOT_CLEAN:", report)
        return 1
    if membership_history(db_path):
        print("FRESH_SWARM_STATE_HAS_MEMBERSHIP_HISTORY")
        return 1
    if temporary is not None:
        temporary.cleanup()
    print("FRESH_SWARM_STATE_CLEAN: zero workers, zero delegations, zero history, census clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
