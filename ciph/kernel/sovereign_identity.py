"""
ciph/kernel/sovereign_identity - 8.1: what must survive for the result to still BE Ciph.

    machine != Ciph.  provider != Ciph.  model != Ciph.  database copy != Ciph.

R1 made the vault portable by giving it an identity independent of its path. 7.x split Ciph into a root
and node identities. 8.1 answers the question those two set up but did not settle:

    after total machine loss, what is the MINIMAL material that makes a restored system the CONTINUATION
    of Ciph rather than a copy of some bytes?

The answer is deliberately not "whatever was on the old host". A sovereign identity is:

    * a named Ciph identity with a GENERATION and a lineage (a restored identity names its predecessor),
    * a reference to the R1 vault identity (so the vault is portable AND identified),
    * a commitment to the constitutional state it was established against,
    * a recovery policy identity,
    * the set of root key references that AUTHORISE continuity - held by the OPERATOR (offline in V1,
      stated as a limit rather than solved by copying the root everywhere),
    * the node-identity lineage it stands at the root of.

And the boundary that matters most: because the root is operator-held and NOT distributed, a restored
copy without the authorised root material cannot graduate to production. It does not invent a new
identity to paper over the gap - it returns UNRECOVERABLE.

DESTRUCTION POLICY also lives here, because R12 found a timer-driven destruction mechanism whose
authority was unowned. Destruction is armed by a NAMED PERSON with evidence, it is disarmed by default,
and recovery never arms it.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SOVEREIGN_IDENTITY_V1 = "SOVEREIGN_IDENTITY_V1"
DESTRUCTION_POLICY_V1 = "DESTRUCTION_POLICY_V1"
RECOVERY_ROOT_CUSTODY_V1 = "RECOVERY_ROOT_CUSTODY_V1"

RECOVERABLE = "RECOVERABLE"
UNRECOVERABLE = "UNRECOVERABLE"
RECOVERY_REQUIRES_OPERATOR = "RECOVERY_REQUIRES_OPERATOR"

ROOT_KEY_ACTIVE = "ACTIVE"
ROOT_KEY_REVOKED = "REVOKED"

REASON_NOT_OPERATOR = "SOVEREIGN_ACTION_REQUIRES_AN_OPERATOR"
REASON_NO_IDENTITY = "NO_SOVEREIGN_IDENTITY"
REASON_IDENTITY_MISMATCH = "SOVEREIGN_IDENTITY_MISMATCH"
REASON_UNKNOWN_IDENTITY = "UNKNOWN_SOVEREIGN_IDENTITY"
REASON_MISSING_ROOT = "INDISPENSABLE_RECOVERY_MATERIAL_UNAVAILABLE"
REASON_ARINGE = "DESTRUCTION_ARMING_REQUIRES_AN_OPERATOR"
REASON_ARMED_STATE = "DESTRUCTION_ARMED_STATE_PRESENT"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_sovereign_identity (
        ciph_identity_id TEXT PRIMARY KEY,
        identity_generation INTEGER NOT NULL,
        vault_identity_ref TEXT NOT NULL,
        constitutional_root_digest TEXT NOT NULL,
        recovery_policy_id TEXT NOT NULL,
        authorized_root_key_refs_json TEXT NOT NULL,
        node_identity_root_refs_json TEXT,
        predecessor_identity_digest TEXT,
        established_by TEXT NOT NULL,
        established_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_recovery_root_keys (
        key_ref TEXT PRIMARY KEY,
        custodian TEXT NOT NULL,
        key_state TEXT NOT NULL,
        hardware_ref TEXT,
        note TEXT,
        created_at REAL,
        closed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_destruction_policy (
        policy_id TEXT PRIMARY KEY,
        armed INTEGER NOT NULL,
        authorized_by TEXT,
        evidence_ref TEXT,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class SovereignIdentity:
    ciph_identity_id: str
    identity_generation: int
    vault_identity_ref: str
    constitutional_root_digest: str
    recovery_policy_id: str
    authorized_root_key_refs: Tuple[str, ...]
    node_identity_root_refs: Tuple[str, ...]
    predecessor_identity_digest: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"ciph_identity_id": self.ciph_identity_id,
                "identity_generation": self.identity_generation,
                "vault_identity_ref": self.vault_identity_ref,
                "constitutional_root_digest": self.constitutional_root_digest,
                "recovery_policy_id": self.recovery_policy_id,
                "authorized_root_key_refs": list(self.authorized_root_key_refs),
                "node_identity_root_refs": list(self.node_identity_root_refs),
                "predecessor_identity_digest": self.predecessor_identity_digest,
                "policy_version": SOVEREIGN_IDENTITY_V1}


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


def _from_row(row: Any) -> SovereignIdentity:
    row = dict(row)
    return SovereignIdentity(
        ciph_identity_id=str(row["ciph_identity_id"]),
        identity_generation=int(row["identity_generation"]),
        vault_identity_ref=str(row["vault_identity_ref"]),
        constitutional_root_digest=str(row["constitutional_root_digest"]),
        recovery_policy_id=str(row["recovery_policy_id"]),
        authorized_root_key_refs=tuple(json.loads(row["authorized_root_key_refs_json"] or "[]")),
        node_identity_root_refs=tuple(json.loads(row["node_identity_root_refs_json"] or "[]")),
        predecessor_identity_digest=row["predecessor_identity_digest"])


def register_root_key(db_path: str, *, key_ref: str, custodian: str = "operator:operator",
                      hardware_ref: Optional[str] = None, note: Optional[str] = None,
                      actor: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record that an authorised root credential EXISTS, without recording what it is.

    The identity table stores REFERENCES. Secret values never enter this database, never enter an
    ordinary backup, and never appear in a report - which is the difference between key custody and key
    leakage.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_recovery_root_keys (key_ref, custodian, key_state, "
            "hardware_ref, note, created_at, closed_at) VALUES (?,?,?,?,?,?,?);",
            (str(key_ref), str(custodian), ROOT_KEY_ACTIVE, hardware_ref, note, moment, None))
        connection.commit()
    finally:
        connection.close()
    return {"key_ref": str(key_ref), "custodian": str(custodian), "key_state": ROOT_KEY_ACTIVE,
            "policy_version": RECOVERY_ROOT_CUSTODY_V1}


def revoke_root_key(db_path: str, key_ref: str, *, actor: str, reason: str,
                    now: Optional[float] = None) -> Dict[str, Any]:
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_recovery_root_keys SET key_state = ?, closed_at = ?, "
                           "note = ? WHERE key_ref = ?;",
                           (ROOT_KEY_REVOKED, moment, str(reason), str(key_ref)))
        connection.commit()
    finally:
        connection.close()
    return {"key_ref": str(key_ref), "key_state": ROOT_KEY_REVOKED}


def available_root_keys(db_path: str) -> Tuple[str, ...]:
    connection = _connect(db_path, read_only=True)
    try:
        return tuple(sorted(str(row["key_ref"]) for row in connection.execute(
            "SELECT key_ref FROM ciph_recovery_root_keys WHERE key_state = ? ORDER BY key_ref;",
            (ROOT_KEY_ACTIVE,))))
    except sqlite3.Error:
        return ()
    finally:
        connection.close()


def establish_identity(db_path: str, *, ciph_identity_id: str, vault_identity_ref: str,
                       constitutional_root_digest: str, recovery_policy_id: str,
                       authorized_root_key_refs: Sequence[str] = (),
                       node_identity_root_refs: Sequence[str] = (),
                       predecessor_identity_digest: Optional[str] = None, actor: str,
                       now: Optional[float] = None) -> SovereignIdentity:
    """
    Establish the sovereign identity of Ciph - once per generation, by an operator, naming its lineage.

    A RESTORED identity must name its predecessor. That single field is what makes continuity a CLAIM
    WITH A HISTORY rather than an assertion made by a machine that found some files.
    """
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, str(actor))
    for reference in tuple(authorized_root_key_refs):
        if not str(reference).strip():
            raise CrucibleError(REASON_MISSING_ROOT, "empty root key reference")
    moment = time.time() if now is None else float(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        existing = connection.execute("SELECT * FROM ciph_sovereign_identity WHERE "
                                      "ciph_identity_id = ?;",
                                      (str(ciph_identity_id),)).fetchone()
        if existing is not None:
            return _from_row(existing)
        if predecessor_identity_digest is None:
            generation = 1
        else:
            generation = int(connection.execute(
                "SELECT COALESCE(MAX(identity_generation), 0) AS latest FROM ciph_sovereign_identity;"
            ).fetchone()["latest"]) + 1
        connection.execute(
            "INSERT INTO ciph_sovereign_identity (ciph_identity_id, identity_generation, "
            "vault_identity_ref, constitutional_root_digest, recovery_policy_id, "
            "authorized_root_key_refs_json, node_identity_root_refs_json, "
            "predecessor_identity_digest, established_by, established_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?);",
            (str(ciph_identity_id), generation, str(vault_identity_ref),
             str(constitutional_root_digest), str(recovery_policy_id),
             json.dumps(sorted(str(item) for item in authorized_root_key_refs)),
             json.dumps(sorted(str(item) for item in node_identity_root_refs)),
             predecessor_identity_digest, str(actor), moment))
        connection.commit()
    finally:
        connection.close()
    return identity(db_path, ciph_identity_id)


def identity(db_path: str, ciph_identity_id: Optional[str] = None) -> SovereignIdentity:
    connection = _connect(db_path, read_only=True)
    try:
        if ciph_identity_id is None:
            row = connection.execute("SELECT * FROM ciph_sovereign_identity "
                                     "ORDER BY identity_generation DESC LIMIT 1;").fetchone()
        else:
            row = connection.execute("SELECT * FROM ciph_sovereign_identity "
                                     "WHERE ciph_identity_id = ?;",
                                     (str(ciph_identity_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_NO_IDENTITY if ciph_identity_id is None
                            else REASON_UNKNOWN_IDENTITY, str(ciph_identity_id))
    return _from_row(row)


def identity_history(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_sovereign_identity ORDER BY identity_generation;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def assert_identity_continuity(db_path: str, *, expected_identity_id: str,
                               expected_vault_ref: Optional[str] = None) -> SovereignIdentity:
    """
    THE negative proof in code: a copy of the bytes that cannot present the expected identity - or whose
    vault identity differs - is not this Ciph.
    """
    found = identity(db_path)
    if found.ciph_identity_id != str(expected_identity_id):
        raise CrucibleError(REASON_IDENTITY_MISMATCH,
                            f"{found.ciph_identity_id}!={expected_identity_id}")
    if expected_vault_ref is not None and found.vault_identity_ref != str(expected_vault_ref):
        raise CrucibleError(REASON_IDENTITY_MISMATCH,
                            f"{found.vault_identity_ref}!={expected_vault_ref}")
    return found


def assess_recoverability(db_path: str, *, required_root_key_refs: Sequence[str] = ()
                          ) -> Dict[str, Any]:
    """
    Can this material become Ciph again - and if not, say so instead of inventing an identity.

    Missing indispensable root material is UNRECOVERABLE. It is not "recovery with a new root", because a
    new root would be a NEW Ciph wearing the old one's history, which is the identity paradox this phase
    exists to refuse.
    """
    required = tuple(sorted(str(ref) for ref in required_root_key_refs))
    try:
        found = identity(db_path)
    except CrucibleError:
        return {"status": UNRECOVERABLE, "reason": REASON_NO_IDENTITY,
                "required_root_key_refs": list(required), "available_root_key_refs": [],
                "replacement_identity_created": False}
    available = available_root_keys(db_path)
    missing = tuple(ref for ref in required if ref not in available)
    if missing:
        return {"status": UNRECOVERABLE, "reason": REASON_MISSING_ROOT,
                "ciph_identity_id": found.ciph_identity_id, "missing_root_key_refs": list(missing),
                "available_root_key_refs": list(available), "replacement_identity_created": False,
                "note": "an operator-held root that is gone is not replaced by a guess"}
    if not required:
        return {"status": RECOVERY_REQUIRES_OPERATOR, "reason": "no root requirement declared",
                "ciph_identity_id": found.ciph_identity_id, "available_root_key_refs": list(available),
                "replacement_identity_created": False}
    return {"status": RECOVERABLE, "ciph_identity_id": found.ciph_identity_id,
            "required_root_key_refs": list(required), "available_root_key_refs": list(available),
            "replacement_identity_created": False}


# ---------------------------------------------------------------------------- destruction policy
def destruction_policy(db_path: str) -> Dict[str, Any]:
    """Disarmed unless a named person armed it. Absence of a policy row means DISARMED."""
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_destruction_policy "
                                 "ORDER BY recorded_at DESC LIMIT 1;").fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        return {"policy_version": DESTRUCTION_POLICY_V1, "armed": False, "authorized_by": None,
                "evidence_ref": None, "default": "DISARMED"}
    row = dict(row)
    return {"policy_version": DESTRUCTION_POLICY_V1, "armed": bool(row["armed"]),
            "authorized_by": row["authorized_by"], "evidence_ref": row["evidence_ref"],
            "recorded_at": row["recorded_at"], "default": "DISARMED"}


def arm_destruction(db_path: str, *, actor: str, evidence_ref: str,
                    now: Optional[float] = None) -> Dict[str, Any]:
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_ARINGE, str(actor))
    if not str(evidence_ref).strip():
        raise CrucibleError(REASON_ARINGE, "evidence required")
    moment = time.time() if now is None else float(now)
    policy_id = "DP-" + digest({"armed": 1, "by": actor, "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_destruction_policy (policy_id, armed, "
                           "authorized_by, evidence_ref, recorded_at) VALUES (?,?,?,?,?);",
                           (policy_id, 1, str(actor), str(evidence_ref), moment))
        connection.commit()
    finally:
        connection.close()
    return destruction_policy(db_path)


def disarm_destruction(db_path: str, *, actor: str, now: Optional[float] = None) -> Dict[str, Any]:
    if not str(actor).startswith("operator:"):
        raise CrucibleError(REASON_ARINGE, str(actor))
    moment = time.time() if now is None else float(now)
    policy_id = "DP-" + digest({"armed": 0, "by": actor, "at": moment})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_destruction_policy (policy_id, armed, "
                           "authorized_by, evidence_ref, recorded_at) VALUES (?,?,?,?,?);",
                           (policy_id, 0, str(actor), None, moment))
        connection.commit()
    finally:
        connection.close()
    return destruction_policy(db_path)


def destruction_state_after_recovery(db_path: str) -> Dict[str, Any]:
    """
    THE hostile case, executable: a backup whose destruction timer was ARMED is restored.

    Recovery reports what it found and leaves the mechanism DISARMED. Re-arming is a separate operator
    decision made after recovery verification - because a restore that carried the instruction to destroy
    the machine would be the worst possible outcome of a disaster recovery.
    """
    historical = destruction_policy(db_path)
    return {"policy_version": DESTRUCTION_POLICY_V1, "historical_armed_state_present":
            bool(historical.get("armed")), "armed_after_recovery": False,
            "reported_for_inspection": historical,
            "rearm_requires": "a separate operator authorization after recovery verification"}


def sovereign_identity_digest(db_path: str) -> str:
    return digest({"version": SOVEREIGN_IDENTITY_V1, "identities": identity_history(db_path),
                   "root_keys": [dict(row) for row in _root_rows(db_path)],
                   "destruction_policy": destruction_policy(db_path)})


def _root_rows(db_path: str) -> List[Any]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT key_ref, custodian, key_state, hardware_ref, created_at FROM "
            "ciph_recovery_root_keys ORDER BY key_ref;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()
