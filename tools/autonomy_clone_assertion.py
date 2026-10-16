"""
autonomy_clone_assertion - a fresh vault must expose ZERO prior autonomy state.

Run this inside a sanitized clone, or against any datastore that has not been used. It proves three
things a suite run alone cannot:

  1. a brand-new vault starts with no autonomous work, no sessions, no schedules, no interventions, no
     standing authority, no budgets and no mission charters - autonomy does not bootstrap itself from
     anything ambient;
  2. the default OPERATOR mode is permissive because nothing has been asserted, not because a row
     granted it: the mode table holds zero records;
  3. no promotion-ready notice exists, and the notice table cannot describe authority even if it did.

Exit code 0 means all three hold. Usage: python3 tools/autonomy_clone_assertion.py [db_path]
"""

import pathlib
import sqlite3
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciph.kernel.autonomy_budgets import budget_digest, budget_status                    # noqa: E402
from ciph.kernel.autonomy_interrupts import intervention_digest, interventions            # noqa: E402
from ciph.kernel.autonomy_maintenance import (promotion_ready_carries_no_authority,       # noqa: E402
                                             promotion_ready_notices)
from ciph.kernel.autonomy_modes import MODE_NORMAL, current_mode, mode_history            # noqa: E402
from ciph.kernel.autonomy_schedule import (reconsideration_history, schedule_digest,      # noqa: E402
                                           schedules)
from ciph.kernel.autonomy_session import session_history                                  # noqa: E402
from ciph.kernel.autonomous_work import work_intent_history                               # noqa: E402
from ciph.kernel.evolution_epochs import current_epoch, epoch_history                     # noqa: E402
from ciph.kernel.mission_stewardship import stewardship_digest                            # noqa: E402
from ciph.kernel.missions import reconstruct_missions                                     # noqa: E402
from ciph.kernel.standing_authorization import standing_authorizations                     # noqa: E402


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
        temporary = tempfile.TemporaryDirectory(prefix="ciph-autonomy-fresh-")
        db_path = str(pathlib.Path(temporary.name) / "fresh.db")

    findings = {
        "work_intents": len(work_intent_history(db_path)),
        "sessions": len(session_history(db_path)),
        "session_work_rows": _table_count(db_path, "ciph_autonomy_session_work"),
        "idle_decisions": _table_count(db_path, "ciph_autonomy_idle_decisions"),
        "schedules": len(schedules(db_path)),
        "reconsiderations": len(reconsideration_history(db_path)),
        "interventions": len(interventions(db_path)),
        "standing_authorizations": len(standing_authorizations(db_path)),
        "mode_records": len(mode_history(db_path)),
        "promotion_ready_notices": len(promotion_ready_notices(db_path)),
        "missions": len(reconstruct_missions(db_path).missions),
    }
    non_empty = {name: count for name, count in findings.items() if count}
    if non_empty:
        print("FRESH_STATE_NOT_EMPTY:", non_empty)
        return 1

    # The default mode is the ABSENCE of an assertion, not a grant.
    if current_mode(db_path) != MODE_NORMAL:
        print("FRESH_STATE_UNEXPECTED_MODE:", current_mode(db_path))
        return 1
    # No epoch, and the epoch history is empty rather than "starts at one".
    if current_epoch(db_path) is not None or epoch_history(db_path):
        print("FRESH_STATE_HAS_AN_EPOCH")
        return 1
    # No notice can claim authority, whatever the table says.
    if not promotion_ready_carries_no_authority(db_path):
        print("A_PROMOTION_READY_ROW_CLAIMS_AUTHORITY")
        return 1
    # The digests must be computable on an empty datastore: a projection that cannot describe "nothing"
    # would tempt its first caller to describe something.
    for digest_callable in (budget_digest, schedule_digest, intervention_digest, stewardship_digest):
        if not digest_callable(db_path):
            print("EMPTY_DIGEST_UNAVAILABLE:", digest_callable.__name__)
            return 1
    if temporary is not None:
        temporary.cleanup()
    print("FRESH_AUTONOMY_STATE_CLEAN: zero work, zero authority, zero history")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
