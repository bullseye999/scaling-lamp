"""
ciph/kernel/sensory_fabric - 10.3: the lightweight, continuous observation subsystem.

    The LLM may rest. Ciph's operational continuity does not.

WHAT THIS OWNS, AND WHAT IT REFUSES TO OWN.

A SENSOR reports OBSERVATIONS. It does not certify constitutional truth, approve its own output, or mint
execution authority. This module owns one thing - the sensor registry and the bounded transport of
observations - and it deliberately owns NO canonical facts. Epistemic observations stay with 4.2
(`epistemic_ledger`), the empirical capability ladder with 4.3 (`self_model`), architectural views with 10.4
(`architectural_proprioception`), findings with 10.0 (`referential_continuity`), worker state with 6.x and
federation state with 7.x. A sensor event is a REPORT; it becomes evidence only when its canonical owner
accepts it, and this module never writes those owners' tables itself.

FOUR PROPERTIES THAT MAKE IT HONEST RATHER THAN LIVELY.

    IT RUNS WITHOUT THE MODEL.  Ingestion, deduplication, retention, status, gap recording and restart
    reconstruction are all pure bookkeeping. Nothing here calls an LLM, and nothing here classifies a
    routine heartbeat with one. Later reasoning reads `context_for_reasoning`.

    DEDUPLICATION DISTINGUISHES A RETRY FROM A REPEAT.  Event identity is derived from
    (sensor, contract version, sequence, payload digest, generation). Re-delivering the SAME event is
    idempotent; two DISTINCT events that happen to carry identical payloads have different sequences and are
    both kept - collapsing them would silently delete a real second occurrence.

    LOSS IS ALWAYS INDICATED.  Retention expiry and queue overflow are recorded as explicit loss/gap rows,
    never as silence. Under pressure ROUTINE events are dropped WITH a marker; ANOMALY events bypass the
    ordinary bound and, past a hard cap, the ingest FAILS CLOSED rather than pretending nothing was lost.

    SILENCE IS NOT A VERDICT.  A sensor that stops is STALE or UNKNOWN according to the evidence available;
    that says nothing about whether its subject failed. Missing witness data stays missing.

The observer cannot independently certify its own integrity; that rule lives in 10.4 and is NOT reimplemented
here. A sensor claiming ANOMALY gets attention routed to it, never authority to act.
"""

import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SENSORY_FABRIC_V1 = "SENSORY_FABRIC_V1"
SENSOR_CONTRACT_V1 = "SENSOR_CONTRACT_V1"
SENSOR_EVENT_V1 = "SENSOR_EVENT_V1"
SENSOR_STATUS_V1 = "SENSOR_STATUS_V1"
SENSORY_GAP_V1 = "SENSORY_GAP_V1"

# A coarse KIND, deliberately not a universal urgency score. It says what sort of thing was seen, and it is
# the only priority vocabulary the fabric has: later attention work will use the canonical priorities.
ROUTINE = "ROUTINE"
CHANGE = "CHANGE"
ANOMALY = "ANOMALY"
EVENT_KINDS = (ROUTINE, CHANGE, ANOMALY)

# Sensor status. Nothing here is a verdict about the SUBJECT of the sensor.
REGISTERED = "REGISTERED"
LIVE = "LIVE"
STALE = "STALE"
UNKNOWN = "UNKNOWN"
STOPPED = "STOPPED"
FAILED = "FAILED"

ACCEPTED = "ACCEPTED"
DUPLICATE = "DUPLICATE"
OUT_OF_ORDER = "OUT_OF_ORDER"
OVERFLOWED = "OVERFLOWED"
REFUSED_STALE_GENERATION = "REFUSED_STALE_GENERATION"
# The SAME event identity carrying a DIFFERENT payload. A sequence slot is unique, so this is neither a
# retry nor a new event: it is equivocation, and it is raised as an integrity conflict.
EQUIVOCATION = "EQUIVOCATION"

GAP_OBSERVATION = "OBSERVATION_GAP"
GAP_OVERFLOW = "OVERFLOW"
GAP_SENSOR_DOWN = "SENSOR_DOWN"
GAP_STALE_GENERATION = "STALE_GENERATION"

REASON_UNKNOWN_SENSOR = "SENSOR_NOT_REGISTERED"
REASON_CONTRACT_CHANGED = "SENSOR_CONTRACT_CHANGED_WITHOUT_A_VERSION"
REASON_INVALID_KIND = "INVALID_EVENT_KIND"
REASON_HARD_CAP = "SENSOR_HARD_CAP_EXCEEDED"
REASON_FABRIC_WRITES_CANONICAL = "SENSOR_FABRIC_MAY_NOT_WRITE_CANONICAL_TABLES"

_HEX = 16
_HARD_CAP_MULTIPLIER = 10

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_sensors (
        sensor_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        capability TEXT NOT NULL,
        scope TEXT,
        canonical_owner TEXT NOT NULL,
        evidence_source TEXT,
        collection_method TEXT NOT NULL,
        ordering TEXT NOT NULL,
        freshness_ttl REAL NOT NULL,
        retention_seconds REAL NOT NULL,
        max_queue INTEGER NOT NULL,
        failure_behavior TEXT NOT NULL,
        restart_behavior TEXT NOT NULL,
        contract_digest TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        registered_at REAL,
        PRIMARY KEY (sensor_id, version)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_sensor_events (
        event_id TEXT PRIMARY KEY,
        sensor_id TEXT NOT NULL,
        sensor_version INTEGER NOT NULL,
        kind TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        payload_digest TEXT NOT NULL,
        payload_json TEXT,
        dedup_key TEXT,
        evidence_ref TEXT,
        canonical_owner TEXT,
        runtime_generation TEXT,
        observed_at REAL NOT NULL,
        ingested_at REAL NOT NULL,
        retained_until REAL NOT NULL,
        disposition TEXT NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_sensor_status (
        sensor_id TEXT PRIMARY KEY,
        last_sequence INTEGER NOT NULL,
        last_event_at REAL,
        last_generation TEXT,
        status TEXT NOT NULL,
        duplicate_count INTEGER NOT NULL,
        overflow_count INTEGER NOT NULL,
        expired_count INTEGER NOT NULL,
        refused_count INTEGER NOT NULL,
        updated_at REAL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_sensor_generations (
        sensor_id TEXT NOT NULL,
        generation TEXT NOT NULL,
        first_seen_at REAL,
        superseded_at REAL,
        PRIMARY KEY (sensor_id, generation)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_sensor_conflicts (
        conflict_id TEXT PRIMARY KEY,
        sensor_id TEXT NOT NULL,
        sensor_version INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        runtime_generation TEXT,
        first_payload_digest TEXT NOT NULL,
        conflicting_payload_digest TEXT NOT NULL,
        conflicting_payload_json TEXT,
        recorded_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_sensor_gaps (
        gap_id TEXT PRIMARY KEY,
        sensor_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        missing_from REAL,
        missing_to REAL,
        reason TEXT,
        recorded_at REAL NOT NULL,
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


# ------------------------------------------------------------------ the sensor contract
def _contract_digest(fields: Dict[str, Any]) -> str:
    return digest({key: fields[key] for key in sorted(fields)})


def register_sensor(db_path: str, *, sensor_id: str, capability: str, canonical_owner: str,
                    collection_method: str, version: int = 1, scope: Optional[str] = None,
                    evidence_source: Optional[str] = None, ordering: str = "WALLCLOCK",
                    freshness_ttl: float = 300.0, retention_seconds: float = 86400.0,
                    max_queue: int = 1000, failure_behavior: str = "STALE_ON_SILENCE",
                    restart_behavior: str = "RECONSTRUCT_DURABLE_AND_MARK_GAPS",
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    Declare a sensor's contract. Re-declaring the IDENTICAL contract is idempotent; changing a contract
    without bumping its version is refused, because a silent contract change is a silent behaviour change.
    """
    key = str(sensor_id).strip()
    if not key:
        raise CrucibleError("SENSOR_REQUIRES_AN_ID", repr(sensor_id))
    moment = _moment(now)
    fields = {"capability": str(capability), "scope": None if scope is None else str(scope),
              "canonical_owner": str(canonical_owner),
              "evidence_source": None if evidence_source is None else str(evidence_source),
              "collection_method": str(collection_method), "ordering": str(ordering).upper(),
              "freshness_ttl": float(freshness_ttl), "retention_seconds": float(retention_seconds),
              "max_queue": int(max_queue), "failure_behavior": str(failure_behavior),
              "restart_behavior": str(restart_behavior)}
    contract_digest = _contract_digest(fields)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        row = connection.execute("SELECT contract_digest FROM ciph_sensors WHERE sensor_id = ? "
                                 "AND version = ?;", (key, int(version))).fetchone()
        if row is not None and str(row["contract_digest"]) != contract_digest:
            raise CrucibleError(REASON_CONTRACT_CHANGED, f"{key}:v{version}")
        connection.execute(
            "INSERT OR IGNORE INTO ciph_sensors (sensor_id, version, capability, scope, canonical_owner, "
            "evidence_source, collection_method, ordering, freshness_ttl, retention_seconds, max_queue, "
            "failure_behavior, restart_behavior, contract_digest, policy_version, registered_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (key, int(version), fields["capability"], fields["scope"], fields["canonical_owner"],
             fields["evidence_source"], fields["collection_method"], fields["ordering"],
             fields["freshness_ttl"], fields["retention_seconds"], fields["max_queue"],
             fields["failure_behavior"], fields["restart_behavior"], contract_digest, SENSOR_CONTRACT_V1,
             moment))
        connection.execute(
            "INSERT OR IGNORE INTO ciph_sensor_status (sensor_id, last_sequence, last_event_at, "
            "last_generation, status, duplicate_count, overflow_count, expired_count, refused_count, "
            "updated_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (key, 0, None, None, REGISTERED, 0, 0, 0, 0, moment, SENSOR_STATUS_V1))
        connection.commit()
    finally:
        connection.close()
    return {"sensor_id": key, "version": int(version), "contract_digest": contract_digest,
            "policy_version": SENSOR_CONTRACT_V1, **fields}


def sensor_contract(db_path: str, sensor_id: str, version: Optional[int] = None) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        if version is None:
            row = connection.execute("SELECT * FROM ciph_sensors WHERE sensor_id = ? "
                                     "ORDER BY version DESC LIMIT 1;", (str(sensor_id),)).fetchone()
        else:
            row = connection.execute("SELECT * FROM ciph_sensors WHERE sensor_id = ? AND version = ?;",
                                     (str(sensor_id), int(version))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_SENSOR, str(sensor_id))
    return dict(row)


def sensors(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_sensors ORDER BY sensor_id, version;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return rows


# ------------------------------------------------------------------ status bookkeeping
def _status_row(db_path: str, sensor_id: str) -> Optional[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_sensor_status WHERE sensor_id = ?;",
                                 (str(sensor_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return None if row is None else dict(row)


def _bump(db_path: str, sensor_id: str, *, column: str, amount: int = 1,
          now: Optional[float] = None) -> None:
    if column not in ("duplicate_count", "overflow_count", "expired_count", "refused_count"):
        raise CrucibleError("UNKNOWN_COUNTER", column)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(f"UPDATE ciph_sensor_status SET {column} = {column} + ?, updated_at = ? "
                           "WHERE sensor_id = ?;", (int(amount), _moment(now), str(sensor_id)))
        connection.commit()
    finally:
        connection.close()


def _record_gap(db_path: str, *, sensor_id: str, kind: str, missing_from: Optional[float],
                missing_to: Optional[float], reason: str, now: Optional[float] = None) -> Dict[str, Any]:
    moment = _moment(now)
    gap_id = "SGP-" + digest({"sensor": sensor_id, "kind": kind, "from": missing_from, "to": missing_to,
                              "reason": reason})[:_HEX].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_sensor_gaps (gap_id, sensor_id, kind, missing_from, missing_to, "
            "reason, recorded_at, policy_version) VALUES (?,?,?,?,?,?,?,?);",
            (gap_id, str(sensor_id), str(kind), missing_from, missing_to, str(reason), moment,
             SENSORY_GAP_V1))
        connection.commit()
    finally:
        connection.close()
    return {"gap_id": gap_id, "sensor_id": str(sensor_id), "kind": str(kind),
            "missing_from": missing_from, "missing_to": missing_to, "reason": str(reason),
            "invented_activity": False, "policy_version": SENSORY_GAP_V1}


def _record_conflict(db_path: str, *, sensor_id: str, version: int, sequence: int,
                     generation: Optional[str], first_payload_digest: str,
                     conflicting_payload_digest: str, conflicting_payload_json: str,
                     now: Optional[float] = None) -> Dict[str, Any]:
    """Retain BOTH contents of an equivocation. The evidence a conflict is BETWEEN is not discarded."""
    moment = _moment(now)
    conflict_id = "SCF-" + digest({"sensor": str(sensor_id), "sequence": int(sequence),
                                   "generation": generation, "first": first_payload_digest,
                                   "conflicting": conflicting_payload_digest})[:_HEX].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_sensor_conflicts (conflict_id, sensor_id, sensor_version, "
            "sequence, runtime_generation, first_payload_digest, conflicting_payload_digest, "
            "conflicting_payload_json, recorded_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (conflict_id, str(sensor_id), int(version), int(sequence), generation,
             str(first_payload_digest), str(conflicting_payload_digest), str(conflicting_payload_json),
             moment, SENSOR_EVENT_V1))
        connection.commit()
    finally:
        connection.close()
    return {"conflict_id": conflict_id, "sensor_id": str(sensor_id), "sequence": int(sequence),
            "runtime_generation": generation, "first_payload_digest": str(first_payload_digest),
            "conflicting_payload_digest": str(conflicting_payload_digest),
            "both_contents_retained": True, "policy_version": SENSOR_EVENT_V1}


def conflicts(db_path: str, *, sensor_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_sensor_conflicts"
    params: Tuple[Any, ...] = ()
    if sensor_id is not None:
        query += " WHERE sensor_id = ?"
        params = (str(sensor_id),)
    query += " ORDER BY recorded_at, conflict_id;"
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(query, params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return rows


def record_observation_gap(db_path: str, *, sensor_id: str, missing_from: float, missing_to: float,
                           reason: str, kind: str = GAP_OBSERVATION,
                           now: Optional[float] = None) -> Dict[str, Any]:
    """An interval with no observer is a GAP. Nothing is filled in and no activity is invented."""
    sensor_contract(db_path, sensor_id)
    return _record_gap(db_path, sensor_id=sensor_id, kind=kind, missing_from=missing_from,
                       missing_to=missing_to, reason=reason, now=now)


def gaps(db_path: str, *, sensor_id: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_sensor_gaps"
    params: Tuple[Any, ...] = ()
    if sensor_id is not None:
        query += " WHERE sensor_id = ?"
        params = (str(sensor_id),)
    query += " ORDER BY recorded_at, gap_id;"
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(query, params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    for row in rows:
        row["invented_activity"] = False
    return rows


# ------------------------------------------------------------------ ingestion
def _generation_state(db_path: str, sensor_id: str) -> Tuple[Optional[str], set]:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_sensor_generations WHERE sensor_id = ?;", (str(sensor_id),))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    current = None
    superseded = set()
    for row in rows:
        if row["superseded_at"] is None:
            current = str(row["generation"])
        else:
            superseded.add(str(row["generation"]))
    return current, superseded


def _advance_generation(db_path: str, sensor_id: str, generation: str, *, now: float) -> None:
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_sensor_generations SET superseded_at = ? WHERE sensor_id = ? "
                           "AND superseded_at IS NULL;", (now, str(sensor_id)))
        connection.execute("INSERT OR IGNORE INTO ciph_sensor_generations (sensor_id, generation, "
                           "first_seen_at, superseded_at) VALUES (?,?,?,NULL);",
                           (str(sensor_id), str(generation), now))
        connection.commit()
    finally:
        connection.close()


def _live_queue_length(connection: sqlite3.Connection, sensor_id: str, now: float) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM ciph_sensor_events WHERE sensor_id = ? AND "
                                  "retained_until > ?;", (str(sensor_id), now)).fetchone()[0])


def ingest(db_path: str, *, sensor_id: str, payload: Any, kind: str = ROUTINE,
           sequence: Optional[int] = None, observed_at: Optional[float] = None,
           runtime_generation: Optional[str] = None, evidence_ref: Optional[str] = None,
           canonical_owner: Optional[str] = None, dedup_key: Optional[str] = None,
           now: Optional[float] = None) -> Dict[str, Any]:
    """
    Deliver ONE observation. Bounded, idempotent, generation-aware, and honest about loss.

    The return value always carries a `disposition`, and every non-ACCEPTED disposition that means data was
    not kept also leaves a durable marker - so a caller can never mistake "dropped" for "nothing happened".
    """
    contract = sensor_contract(db_path, sensor_id)
    if kind not in EVENT_KINDS:
        raise CrucibleError(REASON_INVALID_KIND, str(kind))
    moment = _moment(now)
    observed = moment if observed_at is None else float(observed_at)
    body = payload if isinstance(payload, dict) else {"value": payload}
    payload_json = json.dumps(body, sort_keys=True, default=str)
    payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    version = int(contract["version"])
    status = _status_row(db_path, sensor_id) or {}
    last_sequence = int(status.get("last_sequence") or 0)
    sequence = last_sequence + 1 if sequence is None else int(sequence)
    # A SEQUENCE SLOT IS UNIQUE. Identity deliberately excludes the payload digest: if it included it, a
    # second, DIFFERENT payload under the same sequence would look like a new event and the equivocation
    # would be invisible.
    event_id = "SEN-" + digest({"sensor": str(sensor_id), "version": version, "sequence": sequence,
                                "generation": runtime_generation})[:_HEX].upper()

    # GENERATION GUARD. A superseded generation may not overwrite newer state; it is recorded as a refusal,
    # not silently accepted (and not silently dropped either - a marker is left).
    if runtime_generation is not None:
        current_generation, superseded = _generation_state(db_path, sensor_id)
        if str(runtime_generation) in superseded:
            _bump(db_path, sensor_id, column="refused_count", now=moment)
            _record_gap(db_path, sensor_id=sensor_id, kind=GAP_STALE_GENERATION, missing_from=observed,
                        missing_to=observed, reason=f"generation {runtime_generation} is superseded",
                        now=moment)
            return {"event_id": event_id, "disposition": REFUSED_STALE_GENERATION, "stored": False,
                    "loss_indicated": True, "sensor_id": str(sensor_id), "sequence": sequence,
                    "policy_version": SENSOR_EVENT_V1}
        if current_generation is None or str(runtime_generation) != current_generation:
            _advance_generation(db_path, sensor_id, str(runtime_generation), now=moment)

    retained_until = moment + float(contract["retention_seconds"])
    connection = _connect(db_path)
    try:
        init_schema(connection)
        existing = connection.execute("SELECT disposition, payload_digest FROM ciph_sensor_events "
                                      "WHERE event_id = ?;", (event_id,)).fetchone()
        if existing is not None:
            if str(existing["payload_digest"]) == payload_digest:
                # A RE-DELIVERY of the same event identity. Idempotent: no second row, no state move.
                _bump(db_path, sensor_id, column="duplicate_count", now=moment)
                return {"event_id": event_id, "disposition": DUPLICATE, "stored": False,
                        "distinct_event": False, "loss_indicated": False, "sensor_id": str(sensor_id),
                        "sequence": sequence, "policy_version": SENSOR_EVENT_V1}
            # EQUIVOCATION: the SAME identity now carries a DIFFERENT payload. This is not a retry (the
            # content changed) and not a new event (the slot is taken). Both contents are RETAINED, the
            # conflict is raised, and neither is silently preferred.
            connection.commit()
            conflict = _record_conflict(db_path, sensor_id=sensor_id, version=version, sequence=sequence,
                                        generation=runtime_generation,
                                        first_payload_digest=str(existing["payload_digest"]),
                                        conflicting_payload_digest=payload_digest,
                                        conflicting_payload_json=payload_json, now=moment)
            return {"event_id": event_id, "disposition": EQUIVOCATION, "stored": False,
                    "distinct_event": False, "loss_indicated": False, "integrity_conflict": True,
                    "conflict": conflict, "sensor_id": str(sensor_id), "sequence": sequence,
                    "policy_version": SENSOR_EVENT_V1}
        if dedup_key is not None:
            seen = connection.execute("SELECT 1 FROM ciph_sensor_events WHERE sensor_id = ? AND "
                                      "dedup_key = ?;", (str(sensor_id), str(dedup_key))).fetchone()
            if seen is not None:
                _bump(db_path, sensor_id, column="duplicate_count", now=moment)
                return {"event_id": event_id, "disposition": DUPLICATE, "stored": False,
                        "distinct_event": False, "loss_indicated": False, "sensor_id": str(sensor_id),
                        "sequence": sequence, "policy_version": SENSOR_EVENT_V1}

        max_queue = int(contract["max_queue"])
        live = _live_queue_length(connection, sensor_id, moment)
        disposition = ACCEPTED
        out_of_order = sequence <= last_sequence
        if out_of_order:
            disposition = OUT_OF_ORDER
        if live >= max_queue and kind != ANOMALY:
            # BACKPRESSURE. The event is dropped, and the drop is INDICATED rather than silent.
            connection.commit()
            _bump(db_path, sensor_id, column="overflow_count", now=moment)
            _record_gap(db_path, sensor_id=sensor_id, kind=GAP_OVERFLOW, missing_from=observed,
                        missing_to=observed, reason=f"queue at {live}/{max_queue}", now=moment)
            return {"event_id": event_id, "disposition": OVERFLOWED, "stored": False,
                    "loss_indicated": True, "queue_length": live, "max_queue": max_queue,
                    "sensor_id": str(sensor_id), "sequence": sequence, "policy_version": SENSOR_EVENT_V1}
        if kind == ANOMALY and live >= max_queue * _HARD_CAP_MULTIPLIER:
            # FAIL CLOSED. Past the hard cap the fabric refuses to accept a critical observation rather than
            # keep losing them quietly - an explicit failure beats a silent one.
            connection.commit()
            raise CrucibleError(REASON_HARD_CAP, f"{sensor_id}:{live}")

        connection.execute(
            "INSERT INTO ciph_sensor_events (event_id, sensor_id, sensor_version, kind, sequence, "
            "payload_digest, payload_json, dedup_key, evidence_ref, canonical_owner, runtime_generation, "
            "observed_at, ingested_at, retained_until, disposition, policy_version) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            (event_id, str(sensor_id), version, str(kind), sequence, payload_digest, payload_json,
             None if dedup_key is None else str(dedup_key), evidence_ref,
             canonical_owner or contract["canonical_owner"], runtime_generation, observed, moment,
             retained_until, disposition, SENSOR_EVENT_V1))
        connection.execute(
            "UPDATE ciph_sensor_status SET last_sequence = ?, last_event_at = ?, last_generation = ?, "
            "status = ?, updated_at = ? WHERE sensor_id = ?;",
            (max(last_sequence, sequence), moment,
             runtime_generation if runtime_generation is not None else status.get("last_generation"),
             LIVE, moment, str(sensor_id)))
        connection.commit()
    finally:
        connection.close()
    return {"event_id": event_id, "disposition": disposition, "stored": True, "distinct_event": True,
            "kind": str(kind), "sensor_id": str(sensor_id), "sequence": sequence,
            "payload_digest": payload_digest, "observed_at": observed, "retained_until": retained_until,
            "loss_indicated": False, "canonical_owner": canonical_owner or contract["canonical_owner"],
            "policy_version": SENSOR_EVENT_V1}


def expire(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """Retention expiry: bounded events are dropped, and the drop is COUNTED, never silent."""
    moment = _moment(now)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        rows = connection.execute("SELECT sensor_id, COUNT(*) AS n FROM ciph_sensor_events WHERE "
                                  "retained_until <= ? GROUP BY sensor_id;", (moment,)).fetchall()
        counts = {str(row["sensor_id"]): int(row["n"]) for row in rows}
        connection.execute("DELETE FROM ciph_sensor_events WHERE retained_until <= ?;", (moment,))
        connection.commit()
    finally:
        connection.close()
    for sensor_id, count in counts.items():
        _bump(db_path, sensor_id, column="expired_count", amount=count, now=moment)
    return {"expired": counts, "total": sum(counts.values()), "policy_version": SENSORY_FABRIC_V1}


def events(db_path: str, *, sensor_id: Optional[str] = None, kind: Optional[str] = None,
           since: Optional[float] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_sensor_events"
    clauses: List[str] = []
    params: List[Any] = []
    if sensor_id is not None:
        clauses.append("sensor_id = ?")
        params.append(str(sensor_id))
    if kind is not None:
        clauses.append("kind = ?")
        params.append(str(kind))
    if since is not None:
        clauses.append("observed_at >= ?")
        params.append(float(since))
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY sensor_id, sequence, observed_at;"
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return rows


# ------------------------------------------------------------------ status, gaps, restart
def sensor_status(db_path: str, sensor_id: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """
    The status of the SENSOR, never a verdict about its subject.

    Silence past the freshness TTL is STALE; a sensor that never reported is UNKNOWN. Neither says the
    underlying component failed.
    """
    contract = sensor_contract(db_path, sensor_id)
    status = _status_row(db_path, sensor_id) or {"status": REGISTERED, "last_event_at": None}
    moment = _moment(now)
    last = status.get("last_event_at")
    if str(status.get("status")) in (STOPPED, FAILED):
        state = str(status["status"])
    elif last is None:
        state = UNKNOWN
    elif moment - float(last) > float(contract["freshness_ttl"]):
        state = STALE
    else:
        state = LIVE
    age = None if last is None else moment - float(last)
    return {"sensor_id": str(sensor_id), "status": state, "last_event_at": last, "age_seconds": age,
            "freshness_ttl": float(contract["freshness_ttl"]),
            "is_a_verdict_about_the_subject": False, "policy_version": SENSOR_STATUS_V1}


def sensors_status(db_path: str, *, now: Optional[float] = None) -> Dict[str, Dict[str, Any]]:
    return {record["sensor_id"]: sensor_status(db_path, record["sensor_id"], now=now)
            for record in sensors(db_path)}


def mark_unavailable(db_path: str, *, sensor_id: str, reason: str, status: str = STOPPED,
                     now: Optional[float] = None) -> Dict[str, Any]:
    """The sensor itself stopped or failed. Its subject is NOT thereby declared failed."""
    if status not in (STOPPED, FAILED, UNKNOWN):
        raise CrucibleError("INVALID_SENSOR_STATUS", str(status))
    contract = sensor_contract(db_path, sensor_id)
    moment = _moment(now)
    status_row = _status_row(db_path, sensor_id) or {}
    last = status_row.get("last_event_at")
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_sensor_status SET status = ?, updated_at = ? WHERE sensor_id = ?;",
                           (str(status), moment, str(sensor_id)))
        connection.commit()
    finally:
        connection.close()
    gap = _record_gap(db_path, sensor_id=sensor_id, kind=GAP_SENSOR_DOWN, missing_from=last,
                      missing_to=moment, reason=reason, now=moment)
    return {"sensor_id": str(sensor_id), "status": str(status), "gap": gap,
            "subject_failed": False, "policy_version": SENSOR_STATUS_V1,
            "canonical_owner": contract["canonical_owner"]}


def restart(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Reconstruct sensor state after a restart WITHOUT inventing activity during the downtime.

    A sensor whose last event predates the freshness TTL becomes STALE and gets an EXPLICIT gap from its last
    observation to now. A sensor that never reported stays UNKNOWN. Nothing is back-filled.
    """
    moment = _moment(now)
    report: Dict[str, Any] = {}
    for record in sensors(db_path):
        sensor_id = record["sensor_id"]
        status = _status_row(db_path, sensor_id) or {}
        last = status.get("last_event_at")
        previous_status = str(status.get("status") or REGISTERED)
        if last is None:
            state = UNKNOWN if previous_status == REGISTERED else previous_status
        elif moment - float(last) > float(record["freshness_ttl"]):
            state = STALE
            _record_gap(db_path, sensor_id=sensor_id, kind=GAP_OBSERVATION, missing_from=float(last),
                        missing_to=moment,
                        reason="no observation between the last event and this restart", now=moment)
        else:
            state = LIVE
        connection = _connect(db_path)
        try:
            init_schema(connection)
            connection.execute("UPDATE ciph_sensor_status SET status = ?, updated_at = ? "
                               "WHERE sensor_id = ?;", (state, moment, sensor_id))
            connection.commit()
        finally:
            connection.close()
        report[sensor_id] = {"status": state, "last_event_at": last, "invented_activity": False}
    return {"restarted_at": moment, "sensors": report, "policy_version": SENSORY_FABRIC_V1}


# ------------------------------------------------------------------ reconstruction and context
def reconstruct(db_path: str, *, since: Optional[float] = None, now: Optional[float] = None
                ) -> Dict[str, Any]:
    """What was actually observed, with freshness and loss, ready to be explained to reasoning later."""
    moment = _moment(now)
    observed = events(db_path, since=since)
    return {"policy_version": SENSORY_FABRIC_V1, "sensors": sensors_status(db_path, now=moment),
            "events": observed, "event_count": len(observed),
            "gaps": gaps(db_path), "conflicts": conflicts(db_path),
            "counters": {record["sensor_id"]: _status_row(db_path, record["sensor_id"])
                         for record in sensors(db_path)},
            "invented_activity": False}


def context_for_reasoning(db_path: str, *, since: Optional[float] = None, limit: int = 50,
                          now: Optional[float] = None) -> Dict[str, Any]:
    """
    Evidence-linked event references for a LATER attention mechanism. No urgency score is computed here:
    this provides the KIND and the evidence, and the canonical priorities decide what matters.
    """
    moment = _moment(now)
    observed = events(db_path, since=since)[-int(limit):]
    references = [{"event_id": row["event_id"], "sensor_id": row["sensor_id"], "kind": row["kind"],
                   "observed_at": row["observed_at"], "evidence_ref": row["evidence_ref"],
                   "payload_digest": row["payload_digest"], "canonical_owner": row["canonical_owner"],
                   "freshness": "FRESH" if moment - float(row["observed_at"]) <= 300 else "STALE"}
                  for row in observed]
    counts = {kind: sum(1 for row in observed if row["kind"] == kind) for kind in EVENT_KINDS}
    return {"policy_version": SENSORY_FABRIC_V1, "references": references, "counts": counts,
            "urgency_score": None, "note": "kind counts only; a sensor does not set a universal priority "
                                           "and a sensor claiming ANOMALY gains no authority to act"}


def sensory_digest(db_path: str) -> str:
    """
    A digest over DURABLE fabric state only.

    The derived status (`age_seconds`) depends on the wall clock, so it is deliberately NOT part of the
    digest: a digest that moves just because time passed could not be compared across two processes.
    """
    status_rows = [_status_row(db_path, record["sensor_id"]) or {} for record in sensors(db_path)]
    payload = {"sensors": sensors(db_path), "status": status_rows, "events": events(db_path),
               "gaps": gaps(db_path), "conflicts": conflicts(db_path)}
    return digest(payload)


# ------------------------------------------------------------------ resources (stdlib, kernel-sourced)
def process_resource_usage() -> Dict[str, Any]:
    """This process's own CPU/RSS from the kernel - the honest measure for a resource-constrained VPS."""
    import resource
    usage = resource.getrusage(resource.RUSAGE_SELF)
    rss_kb: Optional[int] = None
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
    except OSError:
        rss_kb = None
    return {"cpu_user_seconds": round(usage.ru_utime, 6), "cpu_system_seconds": round(usage.ru_stime, 6),
            "max_rss_kb": int(usage.ru_maxrss), "rss_kb": rss_kb, "source": "getrusage+/proc"}
