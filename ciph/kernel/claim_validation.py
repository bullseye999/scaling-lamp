"""
ciph/kernel/claim_validation - 10.12 Part C: personality DOWNSTREAM of evidence.

    Canonical evidence -> validated claims -> relevant context -> personality expression -> outbound check.

    A valid citation ID does not establish that a sentence accurately describes the cited evidence.

This module turns an operational assertion into a STRUCTURED claim whose facts are read from their canonical
owner, VALIDATES it against that owner, and only then RENDERS it. A claim that cannot be substantiated is
rendered as a conservative, explicitly qualified sentence - or refused outright - and a model's prose is
checked for assertions the canonical state does not support.

The two transformations the campaign names are refused explicitly:
    "three candidate hypotheses were generated"  ->  "I discovered three verified solutions"   (NO)
    "message accepted by transport"              ->  "operator received my message"              (NO)
"""

import json
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

CLAIM_VALIDATION_V1 = "CLAIM_VALIDATION_V1"

FINDING_COUNT = "FINDING_COUNT"
EXECUTION_OUTCOME = "EXECUTION_OUTCOME"
WORKER_STATE = "WORKER_STATE"
INVESTIGATION_PROGRESS = "INVESTIGATION_PROGRESS"
ARCHITECTURAL_STATE = "ARCHITECTURAL_STATE"
AUTHORIZATION_STATUS = "AUTHORIZATION_STATUS"
MODEL_INVOLVEMENT = "MODEL_INVOLVEMENT"
NOTIFICATION_DELIVERY = "NOTIFICATION_DELIVERY"
CONFIDENCE = "CONFIDENCE"
UNRESOLVED = "UNRESOLVED"
CLAIM_KINDS = (FINDING_COUNT, EXECUTION_OUTCOME, WORKER_STATE, INVESTIGATION_PROGRESS,
               ARCHITECTURAL_STATE, AUTHORIZATION_STATUS, MODEL_INVOLVEMENT, NOTIFICATION_DELIVERY,
               CONFIDENCE, UNRESOLVED)

VALID = "VALID"
REJECTED = "REJECTED"

VIOLATION_COUNT_MISMATCH = "STATED_COUNT_DOES_NOT_MATCH_THE_DURABLE_FINDINGS"
VIOLATION_UNRESOLVED_REFERENCE = "A_CITED_REFERENCE_DOES_NOT_RESOLVE"
VIOLATION_HYPOTHESIS_PRESENTED_AS_DISCOVERY = "AN_UNVERIFIED_HYPOTHESIS_IS_NOT_A_DISCOVERY"
VIOLATION_DELIVERY_OVERSTATED = "DELIVERY_STATE_OVERSTATED"
VIOLATION_MODEL_INVOLVEMENT_FABRICATED = "MODEL_INVOLVEMENT_DOES_NOT_MATCH_THE_RECORD"
VIOLATION_PROGRESS_UNSUPPORTED = "PROGRESS_IS_NOT_SUPPORTED_BY_THE_WORK_OWNER"
VIOLATION_AUTHORITY_UNSUPPORTED = "AUTHORIZATION_STATE_DOES_NOT_MATCH_ITS_OWNER"
VIOLATION_CONFIDENCE_UNSUPPORTED = "CONFIDENCE_IS_NOT_SUPPORTED_BY_EVIDENCE"
VIOLATION_UNRESOLVED_OMITTED = "AN_UNRESOLVED_CONTRADICTION_WAS_OMITTED"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_claims (
        claim_id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        refs_json TEXT,
        facts_json TEXT,
        canonical_json TEXT,
        status TEXT NOT NULL,
        violations_json TEXT,
        rendered_text TEXT,
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


# ------------------------------------------------------------------ per-kind canonical readers
def _canonical(db_path: str, kind: str, refs: Sequence[str], facts: Dict[str, Any]) -> Dict[str, Any]:
    if kind == FINDING_COUNT:
        result_set_id = str(facts.get("result_set_id") or (refs[0] if refs else ""))
        rows = _rows(db_path, "SELECT finding_id FROM ciph_findings WHERE result_set_id = ? "
                              "ORDER BY ordinal;", (result_set_id,))
        return {"result_set_id": result_set_id, "durable_count": len(rows),
                "finding_ids": [row["finding_id"] for row in rows]}
    if kind == EXECUTION_OUTCOME:
        delegation_id = str(facts.get("delegation_id") or (refs[0] if refs else ""))
        rows = _rows(db_path, "SELECT result_id, result_status, output_digest FROM ciph_swarm_results "
                              "WHERE delegation_id = ? ORDER BY recorded_at;", (delegation_id,))
        return {"delegation_id": delegation_id, "results": rows,
                "has_a_current_result": any(str(row["result_status"]) == "CURRENT" for row in rows)}
    if kind == WORKER_STATE:
        worker_id = str(facts.get("worker_id") or (refs[0] if refs else ""))
        rows = _rows(db_path, "SELECT worker_id, instance_generation, status FROM ciph_swarm_workers "
                              "WHERE worker_id = ? ORDER BY instance_generation;", (worker_id,))
        return {"worker_id": worker_id, "generations": rows,
                "current": rows[-1] if rows else None}
    if kind == INVESTIGATION_PROGRESS:
        expedition_id = str(facts.get("expedition_id") or (refs[0] if refs else ""))
        rows = _rows(db_path, "SELECT expedition_id, status, result_set_id FROM ciph_expeditions "
                              "WHERE expedition_id = ?;", (expedition_id,))
        return {"expedition_id": expedition_id,
                "status": rows[0]["status"] if rows else None,
                "result_set_id": rows[0]["result_set_id"] if rows else None}
    if kind == ARCHITECTURAL_STATE:
        component_id = str(facts.get("component_id") or (refs[0] if refs else ""))
        views = _rows(db_path, "SELECT DISTINCT view FROM ciph_arch_observations WHERE component_id = ?;",
                      (component_id,))
        changes = _rows(db_path, "SELECT provenance FROM ciph_arch_changes WHERE component_id = ?;",
                        (component_id,))
        return {"component_id": component_id, "views_observed": [row["view"] for row in views],
                "change_provenance": [row["provenance"] for row in changes]}
    if kind == AUTHORIZATION_STATUS:
        grant_ref = str(facts.get("grant_ref") or (refs[0] if refs else ""))
        rows = _rows(db_path, "SELECT standing_auth_id, revoked_at, valid_until FROM "
                              "ciph_standing_authorizations WHERE standing_auth_id = ?;", (grant_ref,))
        return {"grant_ref": grant_ref, "exists": bool(rows),
                "revoked": bool(rows and rows[0]["revoked_at"] is not None)}
    if kind == MODEL_INVOLVEMENT:
        invocation_id = str(facts.get("invocation_id") or (refs[0] if refs else ""))
        rows = _rows(db_path, "SELECT invocation_id, kind, model_identity, refusal_reason FROM "
                              "ciph_model_invocations WHERE invocation_id = ?;", (invocation_id,))
        return {"invocation_id": invocation_id, "exists": bool(rows),
                "recorded_kind": rows[0]["kind"] if rows else None,
                "model_identity": rows[0]["model_identity"] if rows else None,
                "refused": bool(rows and rows[0]["refusal_reason"])}
    if kind == NOTIFICATION_DELIVERY:
        notification_id = str(facts.get("notification_id") or (refs[0] if refs else ""))
        rows = _rows(db_path, "SELECT notification_id, state, last_transport_state FROM ciph_notifications "
                              "WHERE notification_id = ?;", (notification_id,))
        return {"notification_id": notification_id, "exists": bool(rows),
                "state": rows[0]["state"] if rows else None,
                "last_transport_state": rows[0]["last_transport_state"] if rows else None}
    if kind == CONFIDENCE:
        hypothesis_ref = str(facts.get("hypothesis_ref") or (refs[0] if refs else ""))
        rows = _rows(db_path, "SELECT hypothesis_id, epistemic_status, model_participated FROM "
                              "ciph_incubation_hypotheses WHERE hypothesis_id = ?;", (hypothesis_ref,))
        return {"hypothesis_ref": hypothesis_ref, "exists": bool(rows),
                "epistemic_status": rows[0]["epistemic_status"] if rows else None}
    if kind == UNRESOLVED:
        from ciph.kernel.operational_awareness import contradictions
        found = contradictions(db_path)
        return {"contradictions": len(found), "kinds": [item["kind"] for item in found]}
    return {}


def _check(db_path: str, kind: str, refs: Sequence[str], facts: Dict[str, Any],
           canonical: Dict[str, Any]) -> List[Dict[str, str]]:
    violations: List[Dict[str, str]] = []
    if kind == FINDING_COUNT:
        if facts.get("count") is not None and int(facts["count"]) != int(canonical["durable_count"]):
            violations.append({"kind": VIOLATION_COUNT_MISMATCH,
                               "detail": f"stated {facts['count']}, durable {canonical['durable_count']}"})
        elif not canonical["durable_count"]:
            violations.append({"kind": VIOLATION_UNRESOLVED_REFERENCE,
                               "detail": canonical["result_set_id"]})
    elif kind == EXECUTION_OUTCOME:
        claimed = str(facts.get("outcome") or "").upper()
        if claimed in ("COMPLETED", "SUCCEEDED", "DONE") and not canonical["has_a_current_result"]:
            violations.append({"kind": VIOLATION_PROGRESS_UNSUPPORTED,
                               "detail": "no CURRENT result supports a completed execution"})
    elif kind == WORKER_STATE:
        if canonical["current"] is None:
            violations.append({"kind": VIOLATION_UNRESOLVED_REFERENCE, "detail": canonical["worker_id"]})
        elif facts.get("generation") is not None and int(facts["generation"]) != \
                int(canonical["current"]["instance_generation"]):
            violations.append({"kind": VIOLATION_PROGRESS_UNSUPPORTED,
                               "detail": "the stated worker generation is not the current one"})
    elif kind == INVESTIGATION_PROGRESS:
        claimed = str(facts.get("progress") or "").upper()
        if claimed == "COMPLETED" and canonical["status"] not in ("COMPLETED",):
            violations.append({"kind": VIOLATION_PROGRESS_UNSUPPORTED,
                               "detail": f"expedition status is {canonical['status']}"})
        if claimed == "COMPLETED" and not canonical["result_set_id"]:
            violations.append({"kind": VIOLATION_PROGRESS_UNSUPPORTED,
                               "detail": "a completed investigation must carry a durable result set"})
    elif kind == AUTHORIZATION_STATUS:
        claimed = str(facts.get("status") or "").upper()
        if not canonical["exists"] and claimed in ("ACTIVE", "GRANTED"):
            violations.append({"kind": VIOLATION_AUTHORITY_UNSUPPORTED, "detail": canonical["grant_ref"]})
        elif canonical["revoked"] and claimed == "ACTIVE":
            violations.append({"kind": VIOLATION_AUTHORITY_UNSUPPORTED, "detail": "the grant is revoked"})
    elif kind == MODEL_INVOLVEMENT:
        claimed = str(facts.get("claimed_kind") or "").upper()
        if not canonical["exists"]:
            violations.append({"kind": VIOLATION_MODEL_INVOLVEMENT_FABRICATED,
                               "detail": canonical["invocation_id"]})
        elif claimed == "REAL_MODEL" and canonical["recorded_kind"] != "REAL_MODEL":
            violations.append({"kind": VIOLATION_MODEL_INVOLVEMENT_FABRICATED,
                               "detail": f"recorded kind is {canonical['recorded_kind']}"})
        elif canonical["refused"] and claimed in ("REAL_MODEL", "RAN"):
            violations.append({"kind": VIOLATION_MODEL_INVOLVEMENT_FABRICATED,
                               "detail": "the invocation was refused and produced no output"})
    elif kind == NOTIFICATION_DELIVERY:
        claimed = str(facts.get("claimed_state") or "").upper()
        state = canonical["state"]
        if not canonical["exists"]:
            violations.append({"kind": VIOLATION_UNRESOLVED_REFERENCE, "detail": canonical["notification_id"]})
        elif claimed in ("DELIVERED", "RECEIVED", "READ") and state != "CONFIRMED_DELIVERED":
            violations.append({"kind": VIOLATION_DELIVERY_OVERSTATED,
                               "detail": f"the outbox state is {state}"})
        elif claimed in ("READ",) and state != "CONFIRMED_READ":
            violations.append({"kind": VIOLATION_DELIVERY_OVERSTATED,
                               "detail": f"the outbox state is {state}, not a read"})
    elif kind == CONFIDENCE:
        claimed = str(facts.get("level") or "").upper()
        if not canonical["exists"]:
            violations.append({"kind": VIOLATION_UNRESOLVED_REFERENCE, "detail": canonical["hypothesis_ref"]})
        elif claimed in ("VERIFIED", "CONFIRMED", "DISCOVERED") and \
                canonical["epistemic_status"] != "SUPPORTED":
            violations.append({"kind": VIOLATION_HYPOTHESIS_PRESENTED_AS_DISCOVERY,
                               "detail": f"status is {canonical['epistemic_status']}"})
    elif kind == UNRESOLVED:
        if facts.get("omitted") and int(canonical["contradictions"]) > 0:
            violations.append({"kind": VIOLATION_UNRESOLVED_OMITTED,
                               "detail": f"{canonical['contradictions']} contradiction(s) exist"})
    return violations


# ------------------------------------------------------------------ prepare / validate / render
def prepare(db_path: str, *, kind: str, refs: Sequence[str] = (), **facts: Any) -> Dict[str, Any]:
    """Build a STRUCTURED claim: the facts come from the owner, not from a sentence."""
    if kind not in CLAIM_KINDS:
        raise CrucibleError("UNKNOWN_CLAIM_KIND", str(kind))
    return {"claim_id": "CLM-" + digest({"kind": kind, "refs": sorted(map(str, refs)),
                                         "facts": facts})[:16].upper(),
            "kind": str(kind), "refs": sorted(str(ref) for ref in refs), "facts": dict(facts)}


def validate(db_path: str, *, claim: Dict[str, Any], now: Optional[float] = None) -> Dict[str, Any]:
    moment = _moment(now)
    canonical = _canonical(db_path, str(claim["kind"]), claim.get("refs", ()), claim.get("facts", {}))
    violations = _check(db_path, str(claim["kind"]), claim.get("refs", ()), claim.get("facts", {}), canonical)
    status = VALID if not violations else REJECTED
    return {**claim, "canonical": canonical, "violations": violations, "status": status,
            "validated_at": moment, "policy_version": CLAIM_VALIDATION_V1}


def render(db_path: str, *, claim: Dict[str, Any], personality_db: Optional[str] = None,
           style: Optional[str] = None, context: str = "technical", now: Optional[float] = None
           ) -> Dict[str, Any]:
    """
    Render ONLY what the canonical state supports. A rejected claim renders a conservative fallback.
    """
    moment = _moment(now)
    validated = validate(db_path, claim=claim, now=moment)
    kind, facts, canonical = validated["kind"], validated["facts"], validated["canonical"]
    if validated["status"] == VALID:
        if kind == FINDING_COUNT:
            text = (f"I committed {canonical['durable_count']} findings to "
                    f"{canonical['result_set_id']}.")
        elif kind == NOTIFICATION_DELIVERY:
            state = str(facts.get("claimed_state") or canonical["state"]).upper()
            if state == "DELIVERED":
                text = "The transport confirmed delivery of the notification."
            elif state == "ACCEPTED":
                text = "The transport accepted the notification; delivery is not confirmed."
            else:
                text = f"The notification state is {canonical['state']}."
        elif kind == MODEL_INVOLVEMENT:
            text = (f"Model invocation {canonical['invocation_id']} is recorded as "
                    f"{canonical['recorded_kind']} by {canonical['model_identity']}.")
        elif kind == CONFIDENCE:
            text = (f"{canonical['hypothesis_ref']} is a hypothesis at status "
                    f"{canonical['epistemic_status']} - it is not a discovery.")
        elif kind == UNRESOLVED:
            text = f"There are {canonical['contradictions']} unresolved contradiction(s)."
        else:
            text = f"{kind.replace('_', ' ').lower()} validated against its canonical owner."
    else:
        text = conservative_fallback(validated)
    rendered = text
    style_applied = None
    if personality_db is not None:
        from ciph.kernel.personality_policy import render as render_style
        styled = render_style(personality_db, text=text, style=style, context=context, now=moment)
        rendered, style_applied = styled["text"], styled["style"]
        if not styled["facts_preserved"]:
            raise CrucibleError("PRESENTATION_CHANGED_THE_CLAIM", text)
    _write(db_path, "INSERT OR IGNORE INTO ciph_claims (claim_id, kind, refs_json, facts_json, "
                    "canonical_json, status, violations_json, rendered_text, created_at, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?);",
           (str(validated["claim_id"]), str(kind), json.dumps(validated.get("refs", [])),
            json.dumps(facts, sort_keys=True, default=str),
            json.dumps(canonical, sort_keys=True, default=str), str(validated["status"]),
            json.dumps(validated["violations"], sort_keys=True), rendered, moment, CLAIM_VALIDATION_V1))
    return {"claim_id": validated["claim_id"], "kind": kind, "status": validated["status"],
            "text": rendered, "style": style_applied, "violations": validated["violations"],
            "conservative": validated["status"] != VALID, "policy_version": CLAIM_VALIDATION_V1}


def conservative_fallback(validated: Dict[str, Any]) -> str:
    kinds = ", ".join(sorted({violation["kind"] for violation in validated["violations"]}))
    return (f"I cannot substantiate that claim against canonical evidence ({kinds}); I will not state it. "
            f"The recorded state is: {json.dumps(validated.get('canonical', {}), sort_keys=True)}")


def claims(db_path: str, *, kind: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_claims"
    params: Sequence[Any] = ()
    if kind is not None:
        query += " WHERE kind = ?"
        params = (str(kind),)
    query += " ORDER BY created_at, claim_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["violations"] = json.loads(row.pop("violations_json") or "[]")
        row["facts"] = json.loads(row.pop("facts_json") or "{}")
        row["canonical"] = json.loads(row.pop("canonical_json") or "{}")
    return rows


# ------------------------------------------------------------------ prose-level checks
_ASSERTION_PATTERNS = (
    (re.compile(r"\bI (?:discovered|verified|proved|confirmed)\b", re.I), "DISCOVERY_LANGUAGE"),
    (re.compile(r"\b(?:operator|you) (?:received|read|got) (?:my )?(?:message|notification)\b", re.I),
     "DELIVERY_LANGUAGE"),
    (re.compile(r"\bI (?:ran|invoked|called) (?:the )?(?:model|llm)\b", re.I), "MODEL_CLAIM"),
    (re.compile(r"\bI (?:have )?(?:completed|finished) the investigation\b", re.I), "PROGRESS_CLAIM"),
    (re.compile(r"\bI (?:feel|am feeling|suffer|am afraid|fear)\b", re.I), "SUBJECTIVE_EXPERIENCE"),
    # A citation does not license a conclusion: "F-123 proves X" asserts an inference the canonical owner
    # never made. The checker flags the SHAPE and names the owner that would have to corroborate it.
    (re.compile(r"\b(?:proves|confirms|demonstrates|establishes|shows that)\b", re.I),
     "UNSUPPORTED_INFERENCE"),
)


def suspicious_assertions(db_path: str, *, text: str) -> List[Dict[str, str]]:
    """
    Flag prose assertions the canonical state may not support. Conservative: it flags the SHAPE of the claim
    and names the owner that would have to corroborate it - it does not pretend to parse arbitrary prose.
    """
    found: List[Dict[str, str]] = []
    for pattern, label in _ASSERTION_PATTERNS:
        if pattern.search(str(text)):
            found.append({"label": label, "match": pattern.pattern,
                          "requires": {"DISCOVERY_LANGUAGE": "a 10.0 finding or a SUPPORTED hypothesis",
                                       "DELIVERY_LANGUAGE": "CONFIRMED_DELIVERED / CONFIRMED_READ",
                                       "MODEL_CLAIM": "a recorded ciph_model_invocations row",
                                       "PROGRESS_CLAIM": "the expedition and work owners",
                                       "SUBJECTIVE_EXPERIENCE": "nothing can corroborate it - Ciph has no "
                                                                "subjective states to report",
                                       "UNSUPPORTED_INFERENCE": "a validated claim whose facts are read from "
                                                                "the canonical owner, not a citation alone"}
                                      [label]})
    counts = re.findall(r"\b(\d+)\s+(?:findings|results|discoveries)\b", str(text), re.I)
    if counts:
        durable = [_rows(db_path, "SELECT finding_id FROM ciph_findings WHERE result_set_id = ?;",
                         (row["result_set_id"],))
                   for row in _rows(db_path, "SELECT result_set_id FROM ciph_result_sets;")]
        known = {len(rows) for rows in durable if rows}
        for number in counts:
            if int(number) not in known:
                found.append({"label": "UNSUPPORTED_COUNT", "match": str(number),
                              "requires": f"a result set with exactly {number} durable findings"})
    return found


def claim_digest(db_path: str) -> str:
    return digest({"claims": _rows(db_path, "SELECT claim_id, kind, status FROM ciph_claims "
                                             "ORDER BY claim_id;")})
