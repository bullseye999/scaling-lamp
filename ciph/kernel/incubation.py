"""
ciph/kernel/incubation - 10.10: revisiting existing evidence, and an honest view of what Ciph is doing.

    Incubation revisits what is ALREADY KNOWN. It does not invent objectives, and it does not reason when
    there is no model to reason with.

WHAT IT OWNS: the hypothesis LINEAGE (what was proposed, from which evidence, by whom, with what support and
what contradiction, and at what epistemic status) and a PROJECTION of the current operating condition. It owns
no objective generator, no second curiosity priority, no autonomy mode authority and no scheduler.

THREE RULES IT ENFORCES:

    A HYPOTHESIS IS NOT A RESULT. `generate_hypothesis` records status HYPOTHESIS and never a verified
    finding. If no model participated it says `model_participated: False`; if one did, the generation is
    recorded as the MODEL'S OUTPUT and never as independent validation.

    NO FALSE NOVELTY. A proposal that merely re-words an existing hypothesis is reported as a paraphrase of
    it (normalised, order-independent), while a genuinely distinct investigation with identical final
    evidence keeps its own identity.

    MODES ARE A PROJECTION, NOT AN AUTHORITY. `operating_modes` reads 5.x (`autonomy_modes`,
    `standing_authorization`, quiescence), 10.3 (sensor freshness), 10.6 (attention and model availability)
    and the expedition/delegation state, and reports which descriptive states are ACTIVE. Several may hold at
    once, and the projection never grants anything - 5.x remains the only thing that can stop or permit work.
"""

import json
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

INCUBATION_V1 = "INCUBATION_V1"
HYPOTHESIS_LINEAGE_V1 = "HYPOTHESIS_LINEAGE_V1"
OPERATING_MODES_V1 = "OPERATING_MODES_V1"

HYPOTHESIS = "HYPOTHESIS"
SUPPORTED = "SUPPORTED"
REFUTED = "REFUTED"
INCONCLUSIVE = "INCONCLUSIVE"
SUPERSEDED = "SUPERSEDED"
HYPOTHESIS_STATUSES = (HYPOTHESIS, SUPPORTED, REFUTED, INCONCLUSIVE, SUPERSEDED)

OBSERVING = "OBSERVING"
DELIBERATING = "DELIBERATING"
INVESTIGATING = "INVESTIGATING"
INCUBATING = "INCUBATING"
GOVERNED_HOLD = "GOVERNED_HOLD"
DESCRIPTIVE_STATES = (OBSERVING, DELIBERATING, INVESTIGATING, INCUBATING, GOVERNED_HOLD)

REASON_VERIFIED_STATUS_REQUIRES_TEN_ZERO = "A_VERIFIED_FINDING_IS_COMMITTED_TO_10_0_NOT_CLAIMED_HERE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_incubation_hypotheses (
        hypothesis_id TEXT PRIMARY KEY,
        source_question_ref TEXT,
        origin_evidence_json TEXT,
        reason TEXT,
        model_participated INTEGER NOT NULL,
        model_identity TEXT,
        supporting_evidence_json TEXT,
        contradictory_evidence_json TEXT,
        epistemic_status TEXT NOT NULL,
        proposed_verification TEXT,
        authorization_status TEXT,
        resource_estimate_json TEXT,
        novelty_key TEXT NOT NULL,
        created_at REAL NOT NULL,
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


def _rows(db_path: str, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def _write(db_path: str, query: str, params: Sequence[Any]) -> None:
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(query, tuple(params))
        connection.commit()
    finally:
        connection.close()


def _novelty_key(text: str) -> str:
    """Order-independent, so re-wording the same question does not look like a new idea."""
    words = sorted(re.findall(r"[a-z0-9]+", str(text).lower()))
    return digest({"tokens": words})


# ------------------------------------------------------------------ hypothesis lineage
def generate_hypothesis(db_path: str, *, source_question_ref: str, origin_evidence_refs: Sequence[str],
                        reason: str, model_participated: bool = False,
                        model_identity: Optional[str] = None,
                        supporting_evidence_refs: Sequence[str] = (),
                        contradictory_evidence_refs: Sequence[str] = (),
                        proposed_verification: Optional[str] = None,
                        authorization_status: Optional[str] = None,
                        resource_estimate: Optional[Dict[str, Any]] = None,
                        now: Optional[float] = None) -> Dict[str, Any]:
    """Record a HYPOTHESIS with its full lineage. It is never a result, and it carries no authority."""
    moment = _moment(now)
    novelty_key = _novelty_key(f"{source_question_ref} {reason}")
    hypothesis_id = "HYP-" + digest({"question": source_question_ref, "key": novelty_key,
                                     "at": moment})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_incubation_hypotheses (hypothesis_id, source_question_ref, "
                    "origin_evidence_json, reason, model_participated, model_identity, "
                    "supporting_evidence_json, contradictory_evidence_json, epistemic_status, "
                    "proposed_verification, authorization_status, resource_estimate_json, novelty_key, "
                    "created_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (hypothesis_id, str(source_question_ref), json.dumps(sorted(map(str, origin_evidence_refs))),
            str(reason), 1 if model_participated else 0, model_identity,
            json.dumps(sorted(map(str, supporting_evidence_refs))),
            json.dumps(sorted(map(str, contradictory_evidence_refs))), HYPOTHESIS, proposed_verification,
            authorization_status, json.dumps(resource_estimate or {}, sort_keys=True), novelty_key, moment,
            HYPOTHESIS_LINEAGE_V1))
    return get_hypothesis(db_path, hypothesis_id)


def get_hypothesis(db_path: str, hypothesis_id: str) -> Dict[str, Any]:
    rows = _rows(db_path, "SELECT * FROM ciph_incubation_hypotheses WHERE hypothesis_id = ?;",
                 (str(hypothesis_id),))
    if not rows:
        raise CrucibleError("UNKNOWN_HYPOTHESIS", str(hypothesis_id))
    record = rows[0]
    record["origin_evidence"] = json.loads(record.pop("origin_evidence_json") or "[]")
    record["supporting_evidence"] = json.loads(record.pop("supporting_evidence_json") or "[]")
    record["contradictory_evidence"] = json.loads(record.pop("contradictory_evidence_json") or "[]")
    record["resource_estimate"] = json.loads(record.pop("resource_estimate_json") or "{}")
    record["model_participated"] = bool(record["model_participated"])
    record["is_a_result"] = False
    return record


def hypotheses(db_path: str, *, status: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT hypothesis_id FROM ciph_incubation_hypotheses"
    params: Sequence[Any] = ()
    if status is not None:
        query += " WHERE epistemic_status = ?"
        params = (str(status),)
    query += " ORDER BY created_at, hypothesis_id;"
    return [get_hypothesis(db_path, row["hypothesis_id"]) for row in _rows(db_path, query, params)]


def novelty(db_path: str, *, source_question_ref: str, reason: str) -> Dict[str, Any]:
    """
    Is this a NEW question, or a re-wording of one already recorded?

    Wording changes do not create novelty, and a paraphrase is REPORTED rather than suppressed.
    """
    key = _novelty_key(f"{source_question_ref} {reason}")
    matches = _rows(db_path, "SELECT hypothesis_id FROM ciph_incubation_hypotheses WHERE novelty_key = ? "
                             "ORDER BY hypothesis_id;", (key,))
    return {"novelty_key": key, "is_novel": not matches,
            "paraphrase_of": [row["hypothesis_id"] for row in matches],
            "wording_alone_is_not_novelty": True, "policy_version": INCUBATION_V1}


def set_status(db_path: str, *, hypothesis_id: str, status: str, evidence_ref: Optional[str] = None,
               now: Optional[float] = None) -> Dict[str, Any]:
    """
    Advance a hypothesis's EPISTEMIC status with evidence. A verified finding is NOT a status here - it is
    committed to 10.0, and this refuses to claim it.
    """
    if str(status).upper() in ("VERIFIED", "CONFIRMED", "TRUE"):
        raise CrucibleError(REASON_VERIFIED_STATUS_REQUIRES_TEN_ZERO, str(status))
    if status not in HYPOTHESIS_STATUSES:
        raise CrucibleError("UNKNOWN_HYPOTHESIS_STATUS", str(status))
    if status in (SUPPORTED, REFUTED) and not evidence_ref:
        raise CrucibleError("EVIDENCE_REQUIRED_FOR_A_STATUS_CHANGE", str(hypothesis_id))
    record = get_hypothesis(db_path, hypothesis_id)
    if status == SUPPORTED:
        updated = sorted(set(record["supporting_evidence"]) | {str(evidence_ref)})
        _write(db_path, "UPDATE ciph_incubation_hypotheses SET supporting_evidence_json = ? "
                        "WHERE hypothesis_id = ?;", (json.dumps(updated), str(hypothesis_id)))
    elif status == REFUTED:
        updated = sorted(set(record["contradictory_evidence"]) | {str(evidence_ref)})
        _write(db_path, "UPDATE ciph_incubation_hypotheses SET contradictory_evidence_json = ? "
                        "WHERE hypothesis_id = ?;", (json.dumps(updated), str(hypothesis_id)))
    _write(db_path, "UPDATE ciph_incubation_hypotheses SET epistemic_status = ? WHERE hypothesis_id = ?;",
           (str(status), str(hypothesis_id)))
    refreshed = get_hypothesis(db_path, hypothesis_id)
    refreshed["is_a_result"] = False
    refreshed["verified_findings_live_in_10_0"] = True
    return refreshed


def review_sources(db_path: str, *, now: Optional[float] = None, limit: int = 20) -> List[Dict[str, Any]]:
    """What incubation may revisit: existing evidence, unresolved questions and unexplained anomalies."""
    moment = _moment(now)
    sources: List[Dict[str, Any]] = []
    try:
        from ciph.kernel.uncertainty_registry import derive_uncertainties
        for record in derive_uncertainties(db_path, now=moment):
            sources.append({"kind": "UNRESOLVED_QUESTION", "ref": record.uncertainty_id,
                            "reducibility": record.reducibility})
    except Exception:
        pass
    try:
        from ciph.kernel.operational_homeostasis import anomalies
        for anomaly in anomalies(db_path):
            sources.append({"kind": "UNEXPLAINED_ANOMALY", "ref": anomaly["anomaly_id"],
                            "state": anomaly["state"], "cause": anomaly["causal_claim"]})
    except Exception:
        pass
    try:
        from ciph.kernel.curiosity_learning import outcome_history
        for outcome in outcome_history(db_path):
            status = str(getattr(outcome, "outcome_status", "") or getattr(outcome, "result", ""))
            if status.upper() not in ("RESOLVED", "CLOSED"):
                sources.append({"kind": "INCONCLUSIVE_EXPERIMENT",
                                "ref": getattr(outcome, "outcome_id", None), "status": status})
    except Exception:
        pass
    for source in sources:
        source["executes_nothing"] = True
    return sources[: int(limit)]


# ------------------------------------------------------------------ the operating condition
def operating_modes(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """
    A PROJECTION of the actual operating condition. It grants nothing and stops nothing.

    Several states may be active simultaneously - background observation and an authorized investigation
    genuinely coexist - so the projection is a SET with evidence per member, never one exclusive label.
    """
    moment = _moment(now)
    active: Dict[str, List[Dict[str, Any]]] = {state: [] for state in DESCRIPTIVE_STATES}

    try:
        from ciph.kernel.sensory_fabric import sensor_status, sensors
        live = [record["sensor_id"] for record in sensors(db_path)
                if sensor_status(db_path, record["sensor_id"], now=moment)["status"] == "LIVE"]
        if live:
            active[OBSERVING].append({"source": "10.3 sensory fabric", "live_sensors": len(live)})
    except Exception:
        pass

    from ciph.kernel.selective_attention import (BACKGROUND, PENDING, _get_state,
                                                 invocations_this_window, requests)
    model_available = str(_get_state(db_path, "model_available", "true")).lower() == "true"
    pending = requests(db_path, status=PENDING)
    if model_available and pending:
        active[DELIBERATING].append({"source": "10.6 attention", "pending_requests": len(pending),
                                     "invocations_this_window": invocations_this_window(db_path,
                                                                                        now=moment)})

    try:
        from ciph.kernel.independent_expeditions import ACTIVE, expeditions
        running = [record["expedition_id"] for record in expeditions(db_path, status=ACTIVE)]
        if running:
            active[INVESTIGATING].append({"source": "10.9 expeditions", "active": running})
    except Exception:
        pass
    try:
        from ciph.kernel.swarm_delegation import delegations
        assigned = [record.delegation_id for record in delegations(db_path)
                    if str(record.status) == "ASSIGNED"]
        if assigned:
            active[INVESTIGATING].append({"source": "6.x delegations", "assigned": len(assigned)})
    except Exception:
        pass

    background = [row for row in requests(db_path) if row["category"] == BACKGROUND]
    sources = review_sources(db_path, now=moment, limit=50)
    if sources and model_available:
        active[INCUBATING].append({"source": "10.10 incubation", "reviewable_sources": len(sources),
                                   "background_requests": len(background)})

    blocking: List[Dict[str, Any]] = []
    try:
        from ciph.kernel.autonomy_modes import MODE_NORMAL, current_mode
        mode = current_mode(db_path)
        if mode != MODE_NORMAL:
            blocking.append({"source": "5.x autonomy mode", "mode": mode})
    except Exception:
        pass
    try:
        from ciph.kernel.swarm_quiescence import swarm_is_frozen
        if swarm_is_frozen(db_path):
            blocking.append({"source": "6.x quiescence", "frozen": True})
    except Exception:
        pass
    if blocking:
        active[GOVERNED_HOLD].extend(blocking)

    return {"policy_version": OPERATING_MODES_V1, "as_of": moment,
            "modes": sorted(state for state, evidence in active.items() if evidence),
            "evidence": {state: evidence for state, evidence in active.items() if evidence},
            "mutually_exclusive": False, "is_an_authority": False, "model_available": model_available,
            "grants_permission": False, "blocking_conditions": blocking}


def can_start_consequential_work(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """A convenience READ of the projection. 5.x remains the only thing that can actually stop work."""
    projection = operating_modes(db_path, now=now)
    return {"allowed": GOVERNED_HOLD not in projection["modes"],
            "blocking_conditions": projection["blocking_conditions"], "is_an_authority": False}


def resource_envelope(db_path: str, *, expedition_id: Optional[str] = None,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """Measured consumption, with the UNMEASURABLE limits named rather than fabricated."""
    moment = _moment(now)
    from ciph.kernel.independent_expeditions import ACTIVE, expeditions
    from ciph.kernel.selective_attention import invocations_this_window, requests
    envelope: Dict[str, Any] = {
        "policy_version": INCUBATION_V1,
        "inference_calls_this_window": invocations_this_window(db_path, now=moment),
        "queued_attention_requests": len(requests(db_path, status="PENDING")),
        "attention_requests_total": len(requests(db_path)),
        "concurrent_expeditions": len([row for row in expeditions(db_path) if row["status"] == ACTIVE]),
        "model_invocations_are_measured": True,
        "unmeasurable_metrics": ["token consumption (no provider accounting is wired)",
                                 "network usage (no governed egress accounting on this host)"],
    }
    try:
        from ciph.kernel.swarm_worker import members
        envelope["live_workers"] = len(members(db_path))
        envelope["worker_count_is_measured"] = True
    except Exception:
        envelope["live_workers"] = None
        envelope["worker_count_is_measured"] = False
    if expedition_id is not None:
        from ciph.kernel.independent_expeditions import get_expedition
        record = get_expedition(db_path, expedition_id)
        used = invocations_this_window(db_path, now=moment)
        envelope["expedition"] = {"inference_budget": record["inference_budget"],
                                  "tool_call_budget": record["tool_call_budget"],
                                  "permitted_tools": record["permitted_tools"],
                                  "inference_budget_exhausted": (record["inference_budget"] > 0 and
                                                                 used >= record["inference_budget"])}
    return envelope


def model_outage_behavior(db_path: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """What Ciph may still do with no model - and the one thing it may not: claim new reasoning."""
    return {"policy_version": INCUBATION_V1,
            "may_continue": ["observation through 10.3", "recording durable events and findings",
                             "maintaining existing commitments", "authorized deterministic work",
                             "constitutional guards and reflexes", "queueing questions for later reasoning"],
            "may_not": ["claim to have generated model-based reasoning",
                        "present a hypothesis as a verified result",
                        "start work that needs deliberation"],
            "may_claim_new_reasoning": False, "checked_at": _moment(now), "grants_permission": False}


def incubation_digest(db_path: str) -> str:
    return digest({"hypotheses": _rows(db_path, "SELECT hypothesis_id, epistemic_status, novelty_key, "
                                                 "model_participated FROM ciph_incubation_hypotheses "
                                                 "ORDER BY hypothesis_id;")})
