"""
ciph/kernel/operational_presence - 10.2: what Ciph is doing, from the AUTHORITATIVE work owner.

    Persistent presence does not require constant activity.

THE LAW THIS MODULE ENFORCES:

    Progress comes from the authoritative work owner. If an investigation was paused yesterday, it did NOT
    progress overnight merely because time passed. If a worker completed an operation, the completion must
    resolve to a canonical result. If a node was disconnected, its historical observations are not live
    progress. If no authorized work occurred while operator was away, Ciph says so.

    A CONVERSATIONAL INTENTION IS NOT AUTHORIZATION. A commitment records a promise; whether the referenced
    permission still permits work is decided by the owner that granted it (5.x standing authorization, 4.0
    permits, 4.1 remaining authorized work). A vague wish may be preserved and turned into a PROPOSAL, and it
    authorizes nothing.

It writes NOTHING: it is a projection over 10.0 findings and follow-ups, 10.1 conversations and commitments,
10.5 relationships, 4.1 remaining authorized work, 4.4 investigation identity, 5.x sessions and 6.x results.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

OPERATIONAL_PRESENCE_V1 = "OPERATIONAL_PRESENCE_V1"

ACTIVE = "ACTIVE"
PAUSED = "PAUSED"
AWAITING_DECISION = "AWAITING_DECISION"
UNKNOWN = "UNKNOWN"

# How a unit of delegated work stands with respect to RESUMING it. "Not COMPLETED" is not resumable.
TERMINAL = "TERMINAL"
IN_PROGRESS = "IN_PROGRESS"
AWAITING_CLAIM = "AWAITING_CLAIM"
ORPHANED = "ORPHANED"
REFUSED_OR_EXPIRED = "REFUSED_OR_EXPIRED"

# Observation completeness for an absence claim. A global "nothing happened" needs COMPLETE.
COMPLETE = "COMPLETE"
PARTIAL = "PARTIAL"
COVERAGE_UNKNOWN = "UNKNOWN"

REASON_NO_AUTHORIZATION_ATTACHED = "NO_AUTHORIZATION_ATTACHED"
REASON_AUTHORIZATION_DOES_NOT_RESOLVE = "AUTHORIZATION_REFERENCE_DOES_NOT_RESOLVE"
REASON_AUTHORIZATION_NOT_ACTIVE = "AUTHORIZATION_IS_NOT_ACTIVE"
REASON_CONVERSATIONAL_INTENT = "CONVERSATIONAL_INTENT_IS_NOT_AUTHORIZATION"

_INTENT_MARKERS = ("i'd love", "i would love", "it would be nice", "maybe someday", "i wish",
                   "someday", "i wonder if")


def _moment(now: Optional[float]) -> float:
    return time.time() if now is None else float(now)


def _rows(db_path: str, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


# ------------------------------------------------------------------ the authorization boundary
def commitment_authorization(db_path: str, *, commitment_turn_id: str,
                             now: Optional[float] = None) -> Dict[str, Any]:
    """
    Resolve a commitment's authorization POINTER against the owner that grants it.

    A commitment is a promise. This function never grants anything: it reports whether a referenced grant is
    still active, and refuses to treat a promise as permission.
    """
    moment = _moment(now)
    rows = _rows(db_path, "SELECT * FROM ciph_conv_turns WHERE turn_id = ? AND kind = 'COMMITMENT';",
                 (str(commitment_turn_id),))
    if not rows:
        raise CrucibleError("UNKNOWN_COMMITMENT", str(commitment_turn_id))
    reference = rows[0].get("authorization_ref")
    if not reference:
        return {"commitment_turn_id": str(commitment_turn_id), "authorized": False,
                "reason": REASON_NO_AUTHORIZATION_ATTACHED,
                "note": "a promise is not permission", "policy_version": OPERATIONAL_PRESENCE_V1}
    from ciph.kernel.standing_authorization import STATUS_ACTIVE, authorization_status
    status = authorization_status(db_path, str(reference), now=moment)
    if status == "UNKNOWN":
        return {"commitment_turn_id": str(commitment_turn_id), "authorized": False,
                "authorization_ref": str(reference), "reason": REASON_AUTHORIZATION_DOES_NOT_RESOLVE,
                "note": "a promise is not permission", "policy_version": OPERATIONAL_PRESENCE_V1}
    return {"commitment_turn_id": str(commitment_turn_id), "authorization_ref": str(reference),
            "authorization_status": status, "authorized": status == STATUS_ACTIVE,
            "reason": None if status == STATUS_ACTIVE else REASON_AUTHORIZATION_NOT_ACTIVE,
            "note": "the granting owner decides; the promise does not",
            "policy_version": OPERATIONAL_PRESENCE_V1}


def initiative_boundary(db_path: str, *, statement_ref: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    A conversational wish is preserved and may become a PROPOSAL. It authorizes nothing.

    "I'd love Ciph to investigate cybersecurity research independently" does not grant arbitrary scanning.
    """
    moment = _moment(now)
    rows = _rows(db_path, "SELECT * FROM ciph_conv_turns WHERE turn_id = ?;", (str(statement_ref),))
    if not rows:
        raise CrucibleError("UNKNOWN_STATEMENT", str(statement_ref))
    text = str(rows[0].get("text") or "")
    lowered = text.lower()
    looks_like_intent = any(marker in lowered for marker in _INTENT_MARKERS)
    return {"statement_ref": str(statement_ref), "text": text, "looks_like_intent": looks_like_intent,
            "authorization_granted": False, "proposal_allowed": True,
            "reason": REASON_CONVERSATIONAL_INTENT,
            "enforcement_owner": "5.x standing authorizations / 4.0 permits / 4.1 remaining work",
            "as_of": moment,
            "note": "a preference may be preserved and proposed; only the granting owner permits work",
            "policy_version": OPERATIONAL_PRESENCE_V1}


# ------------------------------------------------------------------ honest progress
def delegation_disposition(db_path: str, delegation_id: str, *, now: Optional[float] = None
                           ) -> Dict[str, Any]:
    """
    Whether a unit of work is RESUMABLE, decided by the OWNING subsystem's lifecycle - not by "it is not
    COMPLETED".

    The real lifecycle is PROPOSED/ELIGIBLE -> ASSIGNED -> COMPLETED, with CANCELLED and STALE as terminal
    refusals, and leases ACTIVE -> RELEASED/EXPIRED/INTERRUPTED. A completed or cancelled delegation is
    TERMINAL (a re-run is a NEW delegation); an ASSIGNED delegation whose lease expired or was interrupted is
    ORPHANED and may only be continued through the lease reclamation path, never silently.
    """
    moment = _moment(now)
    rows = _rows(db_path, "SELECT * FROM ciph_swarm_delegations WHERE delegation_id = ?;",
                 (str(delegation_id),))
    if not rows:
        return {"delegation_id": str(delegation_id), "status": UNKNOWN, "disposition": UNKNOWN,
                "resumable": False, "reason": "UNKNOWN_DELEGATION",
                "policy_version": OPERATIONAL_PRESENCE_V1}
    status = str(rows[0]["status"])
    if status == "COMPLETED":
        return {"delegation_id": str(delegation_id), "status": status, "disposition": TERMINAL,
                "resumable": False, "reason": "a completed delegation is not resumed; a re-run is a NEW "
                                              "delegation", "policy_version": OPERATIONAL_PRESENCE_V1}
    if status in ("CANCELLED", "STALE"):
        return {"delegation_id": str(delegation_id), "status": status,
                "disposition": REFUSED_OR_EXPIRED, "resumable": False,
                "reason": f"{status} is terminal; it needs a new authorized delegation",
                "policy_version": OPERATIONAL_PRESENCE_V1}
    if status in ("PROPOSED", "ELIGIBLE"):
        return {"delegation_id": str(delegation_id), "status": status,
                "disposition": AWAITING_CLAIM, "resumable": True,
                "reason": "awaiting an eligible claim under current authority",
                "policy_version": OPERATIONAL_PRESENCE_V1}
    if status == "ASSIGNED":
        lease = _rows(db_path, "SELECT status, expires_at FROM ciph_swarm_leases WHERE delegation_id = ? "
                               "ORDER BY claimed_at DESC, lease_id DESC LIMIT 1;", (str(delegation_id),))
        if not lease:
            return {"delegation_id": str(delegation_id), "status": status, "disposition": ORPHANED,
                    "resumable": True, "reason": "assigned with no lease record; reclaim required",
                    "policy_version": OPERATIONAL_PRESENCE_V1}
        lease_status, expires_at = str(lease[0]["status"]), lease[0]["expires_at"]
        if lease_status == "ACTIVE" and expires_at is not None and moment <= float(expires_at):
            return {"delegation_id": str(delegation_id), "status": status, "disposition": IN_PROGRESS,
                    "resumable": True, "reason": "an active unexpired lease is in progress",
                    "policy_version": OPERATIONAL_PRESENCE_V1}
        return {"delegation_id": str(delegation_id), "status": status, "disposition": ORPHANED,
                "resumable": True, "reason": f"lease is {lease_status}; continue only via the lease "
                                             f"reclamation path", "policy_version":
                OPERATIONAL_PRESENCE_V1}
    return {"delegation_id": str(delegation_id), "status": status, "disposition": UNKNOWN,
            "resumable": False, "reason": "unrecognised lifecycle state",
            "policy_version": OPERATIONAL_PRESENCE_V1}


def observation_coverage(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """
    What an absence claim is actually COVERED by.

    Work sources (delegations, results, announcements) are canonical and always readable. The SENSORY
    dimension is only covered when a sensor has reported inside its own freshness window, and FEDERATION is
    only covered when every known node has a fresh witness. An uncovered source makes a global "nothing
    happened" claim impermissible.
    """
    moment = _moment(now)
    sources = [{"source": "swarm.delegations", "covered": True, "note": "canonical work record"},
               {"source": "swarm.results", "covered": True, "note": "canonical work record"},
               {"source": "announcements", "covered": True, "note": "canonical record"}]
    # sensory coverage
    try:
        from ciph.kernel.sensory_fabric import sensors, sensor_status
        registered = sensors(db_path)
        if not registered:
            sources.append({"source": "sensory.fabric", "covered": False,
                            "note": "no sensor is registered, so nothing is observing"})
        else:
            stale = [record["sensor_id"] for record in registered
                     if sensor_status(db_path, record["sensor_id"], now=moment)["status"]
                     not in ("LIVE", "REGISTERED")]
            sources.append({"source": "sensory.fabric", "covered": not stale,
                            "note": "all sensors fresh" if not stale else f"stale/unknown: {sorted(stale)}"})
    except Exception:
        sources.append({"source": "sensory.fabric", "covered": False, "note": "sensor state unavailable"})
    # federation coverage
    try:
        nodes = _rows(db_path, "SELECT node_id, attested_at FROM ciph_federation_nodes;")
        disconnected = [row["node_id"] for row in nodes if row["attested_at"] is None]
        sources.append({"source": "federation.nodes", "covered": not disconnected,
                        "note": "no disconnected node" if not disconnected
                                else f"disconnected: {sorted(disconnected)}"})
    except Exception:
        sources.append({"source": "federation.nodes", "covered": False, "note": "node state unavailable"})
    completeness = COMPLETE if all(item["covered"] for item in sources) else (
        PARTIAL if any(item["covered"] for item in sources) else COVERAGE_UNKNOWN)
    return {"sources": sources, "completeness": completeness,
            "global_claim_permitted": completeness == COMPLETE, "checked_at": moment,
            "policy_version": OPERATIONAL_PRESENCE_V1}


def honest_progress(db_path: str, *, subject_ref: str, since: float,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """Progress from the AUTHORITATIVE work owner only. Elapsed time is not progress."""
    moment = _moment(now)
    results = _rows(db_path, "SELECT result_id, delegation_id, worker_id, output_digest, result_status, "
                             "recorded_at FROM ciph_swarm_results WHERE recorded_at > ? "
                             "ORDER BY recorded_at;", (float(since),))
    completed = [row for row in results if str(row["result_status"]) == "CURRENT"]
    return {"policy_version": OPERATIONAL_PRESENCE_V1, "subject_ref": str(subject_ref),
            "since": float(since), "checked_at": moment,
            "canonical_results": completed, "all_arrivals": results,
            "progressed": bool(completed),
            "nothing_authorized_happened": not completed,
            "elapsed_time_is_not_progress": True}


def absence_report(db_path: str, *, since: float, now: Optional[float] = None) -> Dict[str, Any]:
    """
    The honest answer to "what happened while I was away?" - and it may be "nothing authorized".

    It STATES its interval and its covered sources, and it refuses a global claim when a source is unknown:
    with an unobserved sensor or a disconnected node, the most Ciph may say is what the canonical work
    records contain - not that nothing happened.
    """
    moment = _moment(now)
    results = _rows(db_path, "SELECT result_id, delegation_id, worker_id, output_digest, result_status, "
                             "recorded_at FROM ciph_swarm_results WHERE recorded_at > ? "
                             "ORDER BY recorded_at;", (float(since),))
    completed = [row for row in results if str(row["result_status"]) == "CURRENT"]
    announcements = _rows(db_path, "SELECT announcement_id, status, created_at FROM ciph_announcements "
                                   "WHERE created_at > ? ORDER BY created_at;", (float(since),))
    # OUTSTANDING means "not terminal", decided by the owning lifecycle - and each outstanding unit carries
    # whether it is actually resumable and why.
    dispositions = [delegation_disposition(db_path, row["delegation_id"], now=moment)
                    for row in _rows(db_path, "SELECT delegation_id FROM ciph_swarm_delegations;")]
    paused = [item for item in dispositions
              if item["disposition"] in (IN_PROGRESS, AWAITING_CLAIM, ORPHANED)]
    coverage = observation_coverage(db_path, now=moment)
    any_observed = bool(completed or announcements)
    permitted = coverage["global_claim_permitted"]
    return {"policy_version": OPERATIONAL_PRESENCE_V1, "since": float(since), "as_of": moment,
            "interval": {"from": float(since), "to": moment},
            "covered_sources": coverage["sources"], "observation_completeness": coverage["completeness"],
            "global_claim_permitted": permitted,
            "completed_work": completed, "announcements": announcements, "outstanding_work": paused,
            "unverified_work": [row for row in results if str(row["result_status"]) != "CURRENT"],
            "nothing_authorized_happened": (not any_observed) if permitted else None,
            "qualified": not permitted,
            "qualification": None if permitted else
            "some sources were not observed, so Ciph can report only what the canonical work records contain",
            "note": "a paused investigation did not progress merely because time passed",
            "invented_activity": False}


# ------------------------------------------------------------------ recovery and resumption
def resume_plan(db_path: str, *, subject_ref: str, now: Optional[float] = None) -> Dict[str, Any]:
    """
    Reconstruct an interrupted subject's identity, authorization context, outstanding work and last verified
    state - and REFUSE to restart consequential work under a permission that is no longer active.
    """
    moment = _moment(now)
    from ciph.kernel.continuity import reconstruct
    state = reconstruct(db_path, now=moment)
    remaining = list(getattr(state, "remaining_authorized_work", ()))
    dead = list(getattr(state, "dead_authority", ()))
    unresolved = list(getattr(state, "unresolved_attempts", ()))
    from ciph.kernel import operational_awareness as awareness
    state_of_subject = awareness.subject_state(db_path, ref=str(subject_ref), now=moment)
    may_resume = bool(remaining) and not dead
    return {"policy_version": OPERATIONAL_PRESENCE_V1, "subject_ref": str(subject_ref),
            "last_verified_state": state_of_subject,
            "remaining_authorized_work": remaining, "dead_authority": dead,
            "unresolved_attempts": unresolved, "may_resume": may_resume,
            "refusal_reason": None if may_resume else
            ("expired or revoked authority" if dead else "no remaining authorized work"),
            "may_resume_under_expired_permission": False, "keeps_original_identity": True}


# ------------------------------------------------------------------ the presence projection
def presence(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """One coherent, read-only view of what Ciph is doing, from the authoritative owners."""
    moment = _moment(now)
    from ciph.kernel import operational_awareness as awareness
    projection = awareness.build_projection(db_path, now=moment)
    from ciph.kernel.referential_continuity import followups, result_sets
    investigations = [{"result_set_id": record["result_set_id"],
                       "investigation_ref": record["investigation_ref"],
                       "revision": record["current_revision"], "state": ACTIVE,
                       "owner": "referential_continuity"} for record in result_sets(db_path)]
    from ciph.kernel.conversational_continuity import commitments, outstanding_questions
    commitment_records = [{"turn_id": record["turn_id"],
                           "authorization": commitment_authorization(
                               db_path, commitment_turn_id=record["turn_id"], now=moment)}
                          for record in commitments(db_path)]
    awaiting = _rows(db_path, "SELECT delegation_id, status FROM ciph_swarm_delegations "
                              "WHERE status = 'ELIGIBLE';")
    return {"policy_version": OPERATIONAL_PRESENCE_V1, "as_of": moment, "read_only": True,
            "investigations": investigations, "tasks": projection.get("tasks", []),
            "worker_generations": projection.get("worker_generations", []),
            "node_generations": projection.get("node_generations", []),
            "contradictions": projection.get("contradictions", []),
            "commitments": commitment_records, "open_followups": followups(db_path),
            "outstanding_questions": outstanding_questions(db_path), "awaiting_decision": awaiting,
            "mints_authority": False}


def presence_digest(db_path: str) -> str:
    """Durable rows only: no wall-clock field, so two processes agree."""
    return digest({
        "investigations": _rows(db_path, "SELECT result_set_id, investigation_ref, current_revision "
                                         "FROM ciph_result_sets ORDER BY result_set_id;"),
        "delegations": _rows(db_path, "SELECT delegation_id, status FROM ciph_swarm_delegations "
                                      "ORDER BY delegation_id;"),
        "results": _rows(db_path, "SELECT result_id, result_status FROM ciph_swarm_results "
                                  "ORDER BY result_id;"),
        "commitments": _rows(db_path, "SELECT turn_id, authorization_ref FROM ciph_conv_turns "
                                      "WHERE kind = 'COMMITMENT' ORDER BY turn_id;"),
        "followups": _rows(db_path, "SELECT followup_id, status FROM ciph_followups ORDER BY followup_id;"),
        "questions": _rows(db_path, "SELECT question_id, status FROM ciph_conv_questions "
                                    "ORDER BY question_id;"),
    })
