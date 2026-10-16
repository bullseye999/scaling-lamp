"""
ciph/kernel/sensory_adapters - the nine low-cost adapters over EXISTING owners (10.3).

    An adapter READS an owner and reports what it finds. It is not a second observer of Ciph's architecture.

The architectural adapters call 10.4 (`architectural_proprioception`) directly, so a change on disk lands in
10.4's SOURCE view and can NEVER silently become a claim about LOADED or EXECUTED code. Execution is read
from the 4.3 empirical record; swarm state from 6.x; federation state from 7.x; findings and announcements
from 10.0. No adapter writes a canonical table, and none of them invokes the model.

Every adapter is EVENT-DRIVEN (it reads what the owner already recorded) except the resource adapter, which
is a BOUNDED POLL of this process's own kernel counters, and reconciliation, which exists to catch an event
that a subscription would have missed.
"""

import json
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.architectural_proprioception import (SOURCE, integrity_claim, observe_source,
                                                      witness_change, witness_loaded)
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.sensory_fabric import (ANOMALY, CHANGE, ROUTINE, ingest, process_resource_usage,
                                        register_sensor)

SENSORY_ADAPTERS_V1 = "SENSORY_ADAPTERS_V1"

_ARCH = "ciph/kernel/architectural_proprioception.py"
_SELF_MODEL = "ciph/kernel/self_model.py"
_REFERENTIAL = "ciph/kernel/referential_continuity.py"
_SWARM = "ciph/kernel/swarm_worker.py"
_SWARM_RESULTS = "ciph/kernel/swarm_results.py"
_FEDERATION = "ciph/kernel/federation_node.py"
_AUTONOMY = "ciph/kernel/autonomy_session.py"
_INTEGRITY = "ciph/kernel/sovereignty_monitoring.py"

# The 10.4 view each adapter feeds. This is the whole point of the catalogue: architectural observations all
# land in the SAME four-view model instead of in nine private interpretations of Ciph.
VIEW_BY_ADAPTER: Dict[str, str] = {
    "architecture_source": "SOURCE",
    "architecture_installed": "INSTALLED",
    "runtime": "LOADED",
    "execution": "EXECUTED",
}

DEFAULT_RESOURCE_BUDGET = {"max_rss_kb": 524288, "max_events_per_cycle": 200}

ADAPTER_SPECS: Tuple[Dict[str, Any], ...] = (
    {"sensor_id": "architecture.source", "capability": "observe source-tree artifacts", "view": "SOURCE",
     "canonical_owner": _ARCH, "collection_method": "EVENT_DRIVEN_RECONCILED", "evidence_source": "filesystem"},
    {"sensor_id": "architecture.installed", "capability": "observe installed artifacts", "view": "INSTALLED",
     "canonical_owner": _ARCH, "collection_method": "EVENT_DRIVEN", "evidence_source": "filesystem"},
    {"sensor_id": "runtime.loaded", "capability": "witness the loaded implementation", "view": "LOADED",
     "canonical_owner": _ARCH, "collection_method": "LOAD_TIME_WITNESS", "evidence_source": "process"},
    {"sensor_id": "execution.history", "capability": "observe governed executions", "view": "EXECUTED",
     "canonical_owner": _SELF_MODEL, "collection_method": "EVENT_DRIVEN", "evidence_source": "4.3 record"},
    {"sensor_id": "swarm.state", "capability": "observe delegation and worker state", "view": None,
     "canonical_owner": _SWARM, "collection_method": "EVENT_DRIVEN", "evidence_source": "6.x state"},
    {"sensor_id": "federation.state", "capability": "observe federation membership and reachability",
     "view": None, "canonical_owner": _FEDERATION, "collection_method": "EVENT_DRIVEN",
     "evidence_source": "7.x state"},
    {"sensor_id": "investigation.activity", "capability": "observe investigations and findings", "view": None,
     "canonical_owner": _REFERENTIAL, "collection_method": "EVENT_DRIVEN", "evidence_source": "10.0 state"},
    {"sensor_id": "resource.consumption", "capability": "observe this process's own resources", "view": None,
     "canonical_owner": "ciph/kernel/sensory_fabric.py", "collection_method": "BOUNDED_POLL",
     "evidence_source": "getrusage+/proc"},
    {"sensor_id": "integrity.observation", "capability": "observe architectural integrity disposition",
     "view": "SOURCE", "canonical_owner": _ARCH, "collection_method": "DELEGATED_TO_10_4",
     "evidence_source": "10.4 integrity_claim"},
    {"sensor_id": "communications.state", "capability": "observe announcement delivery state", "view": None,
     "canonical_owner": _REFERENTIAL, "collection_method": "EVENT_DRIVEN", "evidence_source": "10.0 state"},
)


def ensure_registered(db_path: str, sensor_id: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    for spec in ADAPTER_SPECS:
        if spec["sensor_id"] == sensor_id:
            return register_sensor(db_path, sensor_id=sensor_id, capability=spec["capability"],
                                   canonical_owner=spec["canonical_owner"],
                                   collection_method=spec["collection_method"],
                                   evidence_source=spec["evidence_source"], now=now)
    raise CrucibleError("UNKNOWN_ADAPTER_SENSOR", str(sensor_id))


# ------------------------------------------------------------------ architectural adapters (into 10.4)
def observe_architecture(db_path: str, *, component_id: str, source_path: Optional[str] = None,
                         now: Optional[float] = None) -> Dict[str, Any]:
    """Record the SOURCE view through 10.4 and report the observation into the fabric."""
    ensure_registered(db_path, "architecture.source", now=now)
    previous = _last_digest(db_path, "architecture.source", component_id)
    observation = observe_source(db_path, component_id=component_id, path=source_path, now=now)
    current = observation["digest"]
    kind = CHANGE if (previous is not None and previous != current) else ROUTINE
    if kind == CHANGE:
        # The change is witnessed by 10.4 as an observation, with NO authorization inferred: the fabric does
        # not know who changed the file, and it will not pretend to.
        witness_change(db_path, component_id=component_id, view=SOURCE, previous_digest=previous,
                       current_digest=current, affected=[], now=now)
    delivered = ingest(db_path, sensor_id="architecture.source",
                       payload={"component": component_id, "view": "SOURCE", "digest": current},
                       kind=kind, evidence_ref=observation["arch_observation_id"], now=now)
    return {"adapter": "architecture.source", "view": "SOURCE", "observation": observation,
            "delivery": delivered, "previous_digest": previous, "kind": kind}


def observe_installed(db_path: str, *, component_id: str, artifact_path: str,
                      now: Optional[float] = None) -> Dict[str, Any]:
    from ciph.kernel.architectural_proprioception import observe_installed as record_installed
    ensure_registered(db_path, "architecture.installed", now=now)
    previous = _last_digest(db_path, "architecture.installed", component_id)
    observation = record_installed(db_path, component_id=component_id, artifact_path=artifact_path, now=now)
    current = observation["digest"]
    kind = CHANGE if (previous is not None and previous != current) else ROUTINE
    delivered = ingest(db_path, sensor_id="architecture.installed",
                       payload={"component": component_id, "view": "INSTALLED", "digest": current},
                       kind=kind, evidence_ref=observation["arch_observation_id"], now=now)
    return {"adapter": "architecture.installed", "view": "INSTALLED", "observation": observation,
            "delivery": delivered, "previous_digest": previous, "kind": kind}


def witness_runtime(db_path: str, *, component_id: str, digest: str, runtime_generation: str,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """
    Record the LOADED view through 10.4's load-time witness.

    An on-disk change is NOT promoted here: this adapter reports what a process LOADED, and the fabric event
    references that witness. The SOURCE view is untouched by this call.
    """
    ensure_registered(db_path, "runtime.loaded", now=now)
    observation = witness_loaded(db_path, component_id=component_id, digest=digest,
                                 runtime_generation=runtime_generation, now=now)
    delivered = ingest(db_path, sensor_id="runtime.loaded",
                       payload={"component": component_id, "view": "LOADED", "digest": digest,
                                "generation": runtime_generation},
                       kind=CHANGE, evidence_ref=observation["arch_observation_id"],
                       runtime_generation=runtime_generation, now=now)
    return {"adapter": "runtime.loaded", "view": "LOADED", "observation": observation,
            "delivery": delivered, "kind": CHANGE}


# ------------------------------------------------------------------ owner-reading adapters
def observe_execution(db_path: str, *, limit: int = 100, now: Optional[float] = None) -> Dict[str, Any]:
    """Report the 4.3 execution record. Reporting is READING: no execution evidence is created here."""
    ensure_registered(db_path, "execution.history", now=now)
    rows = _rows(db_path, "SELECT * FROM ciph_self_executions ORDER BY recorded_at DESC LIMIT ?;", (int(limit),))
    delivered = []
    for row in rows:
        delivered.append(ingest(db_path, sensor_id="execution.history",
                                payload={"capability": row["capability_id"],
                                         "succeeded": bool(row["succeeded"]),
                                         "receipt_ref": row["receipt_ref"]},
                                kind=ROUTINE, evidence_ref=str(row["record_id"]),
                                dedup_key=f"execution:{row['record_id']}", now=now))
    return {"adapter": "execution.history", "view": "EXECUTED", "observed": len(rows),
            "deliveries": delivered}


def observe_swarm(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Report 6.x worker and delegation state. A worker that is not ACTIVE is STALE/UNKNOWN, never "failed":
    the fabric has evidence about the worker's last report, not about its subject.
    """
    ensure_registered(db_path, "swarm.state", now=now)
    from ciph.kernel.swarm_worker import (BUSY, DEAD, DRAINED, JOINING, QUARANTINED, QUIESCING, READY,
                                          members)
    all_statuses = (JOINING, READY, BUSY, QUIESCING, DRAINED, QUARANTINED, DEAD)
    active = {READY, BUSY}
    delivered, observed, unreachable = [], [], []
    for worker in members(db_path, statuses=all_statuses):
        reachable = worker.status in active
        if not reachable:
            unreachable.append(worker.worker_id)
        payload = {"worker_id": worker.worker_id, "generation": worker.instance_generation,
                   "status": worker.status, "attested_at": worker.attested_at,
                   "reachability": "CURRENT" if reachable else "UNKNOWN"}
        observed.append(payload)
        delivered.append(ingest(db_path, sensor_id="swarm.state", payload=payload,
                                kind=ROUTINE if reachable else CHANGE,
                                evidence_ref=f"worker:{worker.worker_id}:{worker.instance_generation}",
                                runtime_generation=str(worker.instance_generation),
                                dedup_key=f"worker:{worker.worker_id}:{worker.instance_generation}:"
                                          f"{worker.status}", now=now))
    return {"adapter": "swarm.state", "observed": observed, "deliveries": delivered,
            "unreachable_as_stale": unreachable, "declared_failed": []}


def observe_federation(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """Report 7.x membership/reachability. A disconnected node is STALE/UNKNOWN, never DEAD."""
    ensure_registered(db_path, "federation.state", now=now)
    from ciph.kernel.federation_node import nodes
    delivered, observed = [], []
    for node in nodes(db_path):
        payload = {"node_id": node.node_id, "generation": node.node_generation,
                   "membership": node.membership, "attested_at": node.attested_at}
        observed.append(payload)
        delivered.append(ingest(db_path, sensor_id="federation.state", payload=payload, kind=ROUTINE,
                                evidence_ref=f"node:{node.node_id}:{node.node_generation}",
                                runtime_generation=str(node.node_generation),
                                dedup_key=f"node:{node.node_id}:{node.node_generation}:{node.membership}",
                                now=now))
    return {"adapter": "federation.state", "observed": observed, "deliveries": delivered,
            "disconnected_as_stale": [node["node_id"] for node in observed if node["attested_at"] is None],
            "declared_dead": []}


def observe_investigations(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """Report 10.0 result sets. The findings stay durable and retrievable through 10.0 itself."""
    from ciph.kernel.referential_continuity import result_sets
    ensure_registered(db_path, "investigation.activity", now=now)
    delivered = []
    sets = result_sets(db_path)
    for record in sets:
        delivered.append(ingest(db_path, sensor_id="investigation.activity",
                                payload={"result_set_id": record["result_set_id"],
                                         "investigation_ref": record["investigation_ref"],
                                         "revision": record["current_revision"]},
                                kind=ROUTINE, evidence_ref=record["result_set_id"],
                                dedup_key=f"result-set:{record['result_set_id']}:"
                                          f"{record['current_revision']}", now=now))
    return {"adapter": "investigation.activity", "observed": len(sets), "deliveries": delivered}


def observe_communications(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """Report 10.0 announcements and their delivery status. A queued message is not a delivered one."""
    from ciph.kernel.referential_continuity import announcements
    ensure_registered(db_path, "communications.state", now=now)
    delivered = []
    records = announcements(db_path)
    for record in records:
        delivered.append(ingest(db_path, sensor_id="communications.state",
                                payload={"announcement_id": record["announcement_id"],
                                         "status": record["status"],
                                         "verified_count": record.get("verified_count")},
                                kind=ROUTINE, evidence_ref=record["announcement_id"],
                                dedup_key=f"announcement:{record['announcement_id']}:{record['status']}",
                                now=now))
    return {"adapter": "communications.state", "observed": len(records), "deliveries": delivered}


def observe_resources(db_path: str, *, budget: Optional[Dict[str, Any]] = None,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """A BOUNDED POLL of this process's own kernel counters. No model, no subprocess, no network."""
    ensure_registered(db_path, "resource.consumption", now=now)
    limits = dict(DEFAULT_RESOURCE_BUDGET)
    limits.update(budget or {})
    usage = process_resource_usage()
    rss = usage.get("rss_kb")
    over = rss is not None and rss > int(limits["max_rss_kb"])
    kind = ANOMALY if over else ROUTINE
    delivered = ingest(db_path, sensor_id="resource.consumption", payload=usage, kind=kind,
                       evidence_ref=None, now=now)
    return {"adapter": "resource.consumption", "usage": usage, "kind": kind, "over_budget": over,
            "budget": limits, "delivery": delivered}


def observe_integrity(db_path: str, *, component_id: str, view: str = SOURCE,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """
    Report the 10.4 integrity DISPOSITION for a component.

    This adapter never certifies anything: it reads `integrity_claim`, which refuses a self-certification and
    reports DISPUTED when independent witnesses disagree, and passes that disposition on verbatim.
    """
    ensure_registered(db_path, "integrity.observation", now=now)
    claim = integrity_claim(db_path, component_id=component_id, view=view, now=now)
    delivered = ingest(db_path, sensor_id="integrity.observation",
                       payload={"component": component_id, "view": view, "status": claim["status"]},
                       kind=CHANGE if claim["status"] != "CORROBORATED" else ROUTINE,
                       evidence_ref=None, canonical_owner=_ARCH, now=now)
    return {"adapter": "integrity.observation", "claim": claim, "delivery": delivered,
            "self_certified": False}


# ------------------------------------------------------------------ the bounded cycle
ADAPTERS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "architecture_source": observe_architecture,
    "architecture_installed": observe_installed,
    "runtime": witness_runtime,
    "execution": observe_execution,
    "swarm": observe_swarm,
    "federation": observe_federation,
    "investigations": observe_investigations,
    "communications": observe_communications,
    "resources": observe_resources,
    "integrity": observe_integrity,
}


def run_cycle(db_path: str, *, calls: Sequence[Tuple[str, Dict[str, Any]]],
              now: Optional[float] = None) -> Dict[str, Any]:
    """Run one bounded observation cycle. No model is invoked: this is bookkeeping, not reasoning."""
    results: Dict[str, Any] = {}
    for name, kwargs in calls:
        if name not in ADAPTERS:
            raise CrucibleError("UNKNOWN_ADAPTER", str(name))
        results[name] = ADAPTERS[name](db_path, now=now, **dict(kwargs))
    return {"policy_version": SENSORY_ADAPTERS_V1, "adapters": results, "invoked_the_model": False,
            "created_execution_authority": False}


def _last_digest(db_path: str, sensor_id: str, component_id: str) -> Optional[str]:
    from ciph.kernel.sensory_fabric import events
    for row in reversed(events(db_path, sensor_id=sensor_id)):
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except ValueError:
            continue
        if payload.get("component") == component_id:
            return payload.get("digest")
    return None


def _rows(db_path: str, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    import sqlite3
    from ciph.kernel.sensory_fabric import _connect
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()
