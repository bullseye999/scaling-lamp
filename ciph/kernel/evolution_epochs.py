"""
ciph/kernel/evolution_epochs - 4.7 Gate Six and Seven: which rules were in force when?

An epoch names the generator, evaluator, safety policy and Crucible policy that were authoritative
together. A judgment is recorded UNDER an epoch, so a later generation of the evaluator cannot rewrite
what an earlier one concluded - it can only reach a different conclusion under its own epoch.

    C17 DOMINATED B4 under Epoch 7     stays true under Epoch 9

LAWS
 1. Epoch transitions are explicit and append-only.
 2. Historical evaluations retain the epoch they were made under.
 3. A new evaluator cannot rewrite a prior judgment.
 4. Re-evaluating a candidate produces a NEW judgment under a NEW protocol - never a mutation.
 5. A meta rollback restores a component without deleting the era it belonged to.
 6. Restart reproduces epochs and judgments exactly.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_metrics import VALID_COMPARISON_STATUSES
from ciph.kernel.crucible_types import CrucibleError, digest

EVOLUTION_EPOCH_V1 = "EVOLUTION_EPOCH_V1"
META_ROLLBACK_V1 = "META_ROLLBACK_V1"

REASON_CROSS_EPOCH_REWRITE = "EPOCH_HISTORY_IS_APPEND_ONLY"
REASON_UNKNOWN_EPOCH = "UNKNOWN_EPOCH"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_evolution_epochs (
        epoch_id TEXT PRIMARY KEY,
        generator_identity TEXT NOT NULL,
        evaluator_identity TEXT NOT NULL,
        safety_policy_identity TEXT,
        crucible_policy_identity TEXT,
        predecessor_epoch TEXT,
        rollback_of TEXT,
        restored_identity_from TEXT,
        authority_ref TEXT NOT NULL,
        began_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_epoch_judgments (
        judgment_id TEXT PRIMARY KEY,
        epoch_id TEXT NOT NULL,
        candidate_id TEXT NOT NULL,
        comparison_status TEXT NOT NULL,
        protocol_id TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_rollbacks (
        rollback_id TEXT PRIMARY KEY,
        bad_epoch TEXT NOT NULL,
        restored_epoch TEXT NOT NULL,
        restored_component TEXT NOT NULL,
        evidence_refs_json TEXT,
        rolled_back_at REAL
    );
    """,
)


@dataclass(frozen=True)
class EvolutionEpoch:
    epoch_id: str
    generator_identity: str
    evaluator_identity: str
    safety_policy_identity: Optional[str]
    crucible_policy_identity: Optional[str]
    predecessor_epoch: Optional[str]
    authority_ref: str
    rollback_of: Optional[str] = None
    restored_identity_from: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"epoch_id": self.epoch_id, "generator_identity": self.generator_identity,
                "evaluator_identity": self.evaluator_identity,
                "safety_policy_identity": self.safety_policy_identity,
                "crucible_policy_identity": self.crucible_policy_identity,
                "predecessor_epoch": self.predecessor_epoch, "authority_ref": self.authority_ref,
                "rollback_of": self.rollback_of,
                "restored_identity_from": self.restored_identity_from}


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


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)
    # A vault created before the rollback columns existed still has to work: restoration is a NEW
    # epoch, so the columns it names must exist.
    existing = {str(row[1]) for row in conn.execute("PRAGMA table_info(ciph_evolution_epochs);")}
    for column in ("rollback_of", "restored_identity_from"):
        if column not in existing:
            conn.execute(f"ALTER TABLE ciph_evolution_epochs ADD COLUMN {column} TEXT;")


def open_epoch(db_path: str, *, generator_identity: str, evaluator_identity: str,
               authority_ref: str, safety_policy_identity: Optional[str] = None,
               crucible_policy_identity: Optional[str] = None, now: Optional[float] = None
               ) -> EvolutionEpoch:
    """Open the FIRST epoch. Every later one is a transition (law 1)."""
    existing = current_epoch(db_path)
    if existing is not None:
        raise CrucibleError("EPOCH_ALREADY_OPEN", existing.epoch_id)
    return _insert_epoch(db_path, generator_identity=generator_identity,
                         evaluator_identity=evaluator_identity,
                         safety_policy_identity=safety_policy_identity,
                         crucible_policy_identity=crucible_policy_identity,
                         predecessor_epoch=None, authority_ref=authority_ref, now=now)


def transition_epoch(db_path: str, *, generator_identity: Optional[str] = None,
                     evaluator_identity: Optional[str] = None,
                     safety_policy_identity: Optional[str] = None,
                     crucible_policy_identity: Optional[str] = None,
                     authority_ref: str, now: Optional[float] = None) -> EvolutionEpoch:
    """
    Move to a new epoch (laws 1, 2). Components not named are inherited, so an epoch records the whole
    authoritative configuration rather than just what changed.
    """
    previous = current_epoch(db_path)
    if previous is None:
        raise CrucibleError("NO_CURRENT_EPOCH", 'open one first')
    return _insert_epoch(
        db_path,
        generator_identity=generator_identity or previous.generator_identity,
        evaluator_identity=evaluator_identity or previous.evaluator_identity,
        safety_policy_identity=safety_policy_identity or previous.safety_policy_identity,
        crucible_policy_identity=crucible_policy_identity or previous.crucible_policy_identity,
        predecessor_epoch=previous.epoch_id, authority_ref=authority_ref, now=now)


def _insert_epoch(db_path: str, *, generator_identity: str, evaluator_identity: str,
                  safety_policy_identity: Optional[str], crucible_policy_identity: Optional[str],
                  predecessor_epoch: Optional[str], authority_ref: str,
                  rollback_of: Optional[str] = None,
                  restored_identity_from: Optional[str] = None,
                  now: Optional[float] = None) -> EvolutionEpoch:
    moment = time.time() if now is None else float(now)
    epoch_id = "EP-" + digest({"generator": generator_identity, "evaluator": evaluator_identity,
                               "safety": safety_policy_identity,
                               "crucible": crucible_policy_identity,
                               "predecessor": predecessor_epoch, "rollback_of": rollback_of,
                               "restored_from": restored_identity_from,
                               "authority": authority_ref})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_evolution_epochs (epoch_id, generator_identity, "
            "evaluator_identity, safety_policy_identity, crucible_policy_identity, "
            "predecessor_epoch, rollback_of, restored_identity_from, authority_ref, began_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?);",
            (epoch_id, generator_identity, evaluator_identity, safety_policy_identity,
             crucible_policy_identity, predecessor_epoch, rollback_of, restored_identity_from,
             authority_ref, moment))
        connection.commit()
    finally:
        connection.close()
    return get_epoch(db_path, epoch_id)


def record_judgment(db_path: str, *, epoch_id: str, candidate_id: str, comparison_status: str,
                    protocol_id: Optional[str] = None, now: Optional[float] = None) -> str:
    """
    Record what the Crucible said about a candidate UNDER an epoch (law 2).

    There is no update path: a later evaluator reaches a new judgment under a new epoch, and both stay
    readable (laws 3, 4).
    """
    if comparison_status not in VALID_COMPARISON_STATUSES:
        raise CrucibleError("INVALID_COMPARISON_STATUS", str(comparison_status))
    get_epoch(db_path, epoch_id)
    moment = time.time() if now is None else float(now)
    judgment_id = "EJG-" + digest({"epoch": epoch_id, "candidate": candidate_id,
                                   "status": comparison_status, "protocol": protocol_id
                                   })[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_epoch_judgments (judgment_id, epoch_id, candidate_id, "
            "comparison_status, protocol_id, recorded_at) VALUES (?,?,?,?,?,?);",
            (judgment_id, epoch_id, candidate_id, comparison_status, protocol_id, moment))
        connection.commit()
    finally:
        connection.close()
    return judgment_id


def judgments_for(db_path: str, candidate_id: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_epoch_judgments WHERE candidate_id = ? ORDER BY rowid;",
            (candidate_id,))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def assert_history_not_rewritten(db_path: str, candidate_id: str, *, epoch_id: str,
                                 comparison_status: str) -> None:
    """
    LAW 3, as a guard: a judgment recorded under another epoch may not be replaced.

    Re-evaluation is legal and produces a second judgment; overwriting the first is not.
    """
    for judgment in judgments_for(db_path, candidate_id):
        if judgment["epoch_id"] != epoch_id and judgment["comparison_status"] != comparison_status:
            continue
        if judgment["epoch_id"] == epoch_id and judgment["comparison_status"] != comparison_status:
            raise CrucibleError(REASON_CROSS_EPOCH_REWRITE,
                                f"{candidate_id} already judged {judgment['comparison_status']} "
                                f"under {epoch_id}")


def rollback_epoch(db_path: str, *, bad_epoch: str, restored_epoch: str,
                   restored_component: str, evidence_refs: Sequence[str] = (),
                   authority_ref: str, now: Optional[float] = None) -> str:
    """Returns the NEW epoch id. The bad epoch is retained: it happened."""
    """
    Restore a component by moving to a new epoch that inherits the earlier configuration (law 5).

    The bad epoch is NOT deleted: "G2 shadow success, production regression, rolled back" is three
    historical facts, not one.
    """
    bad = get_epoch(db_path, bad_epoch)
    if bad.predecessor_epoch is None:
        raise CrucibleError("NO_PREDECESSOR_EPOCH", bad_epoch)
    restored = get_epoch(db_path, restored_epoch)
    history = [epoch.epoch_id for epoch in epoch_history(db_path)]
    if restored.epoch_id not in history or bad.epoch_id not in history or (
            history.index(restored.epoch_id) >= history.index(bad.epoch_id)):
        # Restoration reaches BACKWARD only: a rollback may restore an earlier configuration, never
        # promote the era it is undoing.
        raise CrucibleError("ROLLBACK_MUST_RESTORE_AN_EARLIER_EPOCH",
                            f"{restored_epoch} !< {bad_epoch}")
    moment = time.time() if now is None else float(now)
    rollback_id = "MRB-" + digest({"bad": bad_epoch, "restored": restored_epoch,
                                   "component": restored_component,
                                   "authority": authority_ref})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_rollbacks (rollback_id, bad_epoch, restored_epoch, "
            "restored_component, evidence_refs_json, rolled_back_at) VALUES (?,?,?,?,?,?);",
            (rollback_id, bad_epoch, restored_epoch, restored_component,
             json.dumps(sorted(str(ref) for ref in evidence_refs)), moment))
        connection.commit()
    finally:
        connection.close()
    # RESTORATION IS A NEW EPOCH, NOT TIME TRAVEL (operator's rule). Epoch 7 stays a historical period;
    # the rollback opens a new one that inherits Epoch 7's configuration and says what it undid.
    return _insert_epoch(db_path, generator_identity=restored.generator_identity,
                         evaluator_identity=restored.evaluator_identity,
                         safety_policy_identity=restored.safety_policy_identity,
                         crucible_policy_identity=restored.crucible_policy_identity,
                         predecessor_epoch=bad.epoch_id, authority_ref=authority_ref,
                         rollback_of=bad.epoch_id, restored_identity_from=restored.epoch_id,
                         now=moment).epoch_id


def get_epoch(db_path: str, epoch_id: str) -> EvolutionEpoch:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_evolution_epochs WHERE epoch_id = ?;",
                                 (epoch_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_EPOCH, epoch_id)
    row = dict(row)
    return EvolutionEpoch(
        epoch_id=str(row["epoch_id"]), generator_identity=str(row["generator_identity"]),
        evaluator_identity=str(row["evaluator_identity"]),
        safety_policy_identity=row["safety_policy_identity"],
        crucible_policy_identity=row["crucible_policy_identity"],
        predecessor_epoch=row["predecessor_epoch"], authority_ref=str(row["authority_ref"]),
        rollback_of=row["rollback_of"], restored_identity_from=row["restored_identity_from"])


def current_epoch(db_path: str) -> Optional[EvolutionEpoch]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT epoch_id FROM ciph_evolution_epochs "
                                 "ORDER BY rowid DESC LIMIT 1;").fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return None if row is None else get_epoch(db_path, str(row["epoch_id"]))


def epoch_history(db_path: str) -> List[EvolutionEpoch]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["epoch_id"]) for row in connection.execute(
            "SELECT epoch_id FROM ciph_evolution_epochs ORDER BY rowid;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_epoch(db_path, epoch_id) for epoch_id in ids]


def rollback_history(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_meta_rollbacks ORDER BY rolled_back_at, rollback_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def epoch_digest(db_path: str) -> str:
    return digest({"version": EVOLUTION_EPOCH_V1,
                   "epochs": [item.as_dict() for item in epoch_history(db_path)],
                   "rollbacks": [str(row["rollback_id"]) for row in rollback_history(db_path)]})
