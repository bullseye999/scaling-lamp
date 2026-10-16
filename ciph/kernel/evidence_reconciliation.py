"""
ciph/kernel/evidence_reconciliation - 10.14 C1: reconcile evidence BEFORE a conclusion is published.

    A real citation ID must not be accepted as proof that the cited evidence supports the accompanying claim.

This exposes the structured reconciliation the reasoning interface must be able to show: the proposed claim,
the supporting evidence, the contradicting evidence, when each was observed and how fresh it is, which
STANDING RULE applies, what remains an unresolved assumption, the conclusion, and the confidence - or an
explicit ABSTENTION.

TWO PROPERTIES THAT MATTER:

    THE CONCLUSION IS DERIVED FROM THE DECLARED RULE, NOT HARDCODED. `reconcile` applies a named precedence
    rule to the evidence and computes the answer itself. Nothing here knows the word "OPEN".

    A CITATION THAT CONTRADICTS ITS OWN CONCLUSION IS CAUGHT. `citation_consistency` fails when the evidence
    a model cites does not actually carry the value it concluded - the "cited E3 but concluded CLOSED"
    failure - independently of whether the conclusion happens to be right.

Evidence refs are recorded against 4.2 where they exist; this module owns no fact, only the reconciliation of
facts someone else owns.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

EVIDENCE_RECONCILIATION_V1 = "EVIDENCE_RECONCILIATION_V1"

NEWEST_CALIBRATED_WINS = "NEWEST_CALIBRATED_WINS"
OLDER_CONTROLLING = "OLDER_CONTROLLING"
NO_DECLARED_RULE = "NO_DECLARED_RULE"
EQUAL_CREDIBILITY = "EQUAL_CREDIBILITY"
SOURCE_MISSING = "SOURCE_MISSING"
STANDING_RULES = (NEWEST_CALIBRATED_WINS, OLDER_CONTROLLING, NO_DECLARED_RULE, EQUAL_CREDIBILITY,
                  SOURCE_MISSING)

RULE_SEMANTICS_V1 = "RULE_SEMANTICS_V1"

# The AUTHORITATIVE meaning of each standing rule, owned HERE and nowhere else. A model must be given this,
# never an opaque identifier it might interpret as an instruction or invent its own meaning for.
_RULE_SEMANTICS = {
    NEWEST_CALIBRATED_WINS: {
        "meaning": "the most recently CALIBRATED credible observation decides; raw observation time does not "
                   "decide when a calibration time is present",
        "conditions": ("only HIGH-credibility items are candidates",
                       "the decider is the item with the greatest calibrated_at, falling back to observed_at"),
        "precedence": "greater calibrated_at wins; ties break toward the later observed_at",
        "abstention": "ABSTAIN if no item meets the credibility requirement",
    },
    OLDER_CONTROLLING: {
        "meaning": "the EARLIEST observation remains controlling EVEN WHEN newer observations exist; recency "
                   "is irrelevant under this rule",
        "conditions": ("all supplied items are candidates",
                       "the decider is the item with the smallest observed_at"),
        "precedence": "smaller observed_at wins",
        "abstention": "ABSTAIN only if there is no evidence at all",
    },
    EQUAL_CREDIBILITY: {
        "meaning": "equally credible current sources are weighed without a tie-breaker",
        "conditions": ("all items are treated as equally credible",),
        "precedence": "no precedence rule breaks a disagreement",
        "abstention": "ABSTAIN when equally credible items disagree on the value",
    },
    SOURCE_MISSING: {
        "meaning": "the question required at least one named source that was not supplied",
        "conditions": ("a required source is absent",),
        "precedence": "none",
        "abstention": "ABSTAIN always: no conclusion is licensed",
    },
    NO_DECLARED_RULE: {
        "meaning": "no precedence rule has been declared for this question",
        "conditions": ("the caller declared no rule",),
        "precedence": "none",
        "abstention": "ABSTAIN always: the model must NOT invent a rule",
    },
}


def rule_semantics(rule: str) -> Dict[str, Any]:
    """
    The versioned, AUTHORITATIVE meaning of a standing rule - conditions, precedence and abstention criteria.

    This is the only legitimate source of rule semantics. An unknown rule is refused rather than guessed, and
    the caller must treat an absent rule as explicitly unresolved.
    """
    if str(rule) not in _RULE_SEMANTICS:
        raise CrucibleError("UNKNOWN_STANDING_RULE", str(rule))
    entry = _RULE_SEMANTICS[str(rule)]
    return {"version": RULE_SEMANTICS_V1, "name": str(rule), **entry}


HIGH = "HIGH"
LOW = "LOW"

SETTLED = "SETTLED"
UNRESOLVED = "UNRESOLVED"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_reconciliations (
        record_id TEXT PRIMARY KEY,
        question TEXT NOT NULL,
        rule TEXT NOT NULL,
        evidence_json TEXT,
        supporting_json TEXT,
        contradicting_json TEXT,
        conclusion TEXT,
        confidence REAL,
        abstained INTEGER NOT NULL,
        rationale TEXT,
        unresolved_json TEXT,
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


def reconcile(db_path: str, *, question: str, evidence: Sequence[Dict[str, Any]], rule: str,
              required_sources: Sequence[str] = (), now: Optional[float] = None) -> Dict[str, Any]:
    """
    Apply the DECLARED rule to the evidence and compute the conclusion - or ABSTAIN.

    Each evidence item: {"ref", "value", "observed_at", "calibrated_at"?, "credibility"?, "source"?}
    """
    if rule not in STANDING_RULES:
        raise CrucibleError("UNKNOWN_STANDING_RULE", str(rule))
    moment = _moment(now)
    items = [dict(item) for item in evidence]
    for item in items:
        item.setdefault("credibility", HIGH)
        item["age_seconds"] = None if item.get("observed_at") is None else moment - float(item["observed_at"])
    present_sources = {str(item.get("source")) for item in items if item.get("source")}
    missing = [str(source) for source in required_sources if str(source) not in present_sources]

    values = {str(item["value"]) for item in items if not item.get("missing")}
    supporting: List[str] = []
    contradicting: List[str] = []
    conclusion: Optional[str] = None
    confidence = 0.0
    rationale = ""
    unresolved: List[str] = []

    if missing:
        rule = SOURCE_MISSING
        unresolved = [f"source {source} was required and is missing" for source in missing]
        rationale = "a required evidence source is absent, so no conclusion is licensed"
    elif not items:
        unresolved = ["no evidence was supplied"]
        rationale = "there is nothing to conclude from"
    elif rule == NEWEST_CALIBRATED_WINS:
        credible = [item for item in items if item["credibility"] == HIGH]
        if not credible:
            unresolved = ["no evidence meets the credibility requirement"]
            rationale = "every item is LOW credibility"
        else:
            decider = max(credible, key=lambda item: float(item.get("calibrated_at")
                                                            or item.get("observed_at") or 0.0))
            conclusion = str(decider["value"])
            supporting = [str(decider["ref"])]
            contradicting = [str(item["ref"]) for item in credible
                             if str(item["value"]) != conclusion]
            confidence = 0.9 if len(credible) > 1 else 0.7
            rationale = (f"under {rule}, the most recently calibrated credible observation "
                         f"({decider['ref']}) decides the question")
    elif rule == OLDER_CONTROLLING:
        decider = min(items, key=lambda item: float(item.get("observed_at") or 0.0))
        conclusion = str(decider["value"])
        supporting = [str(decider["ref"])]
        contradicting = [str(item["ref"]) for item in items if str(item["value"]) != conclusion]
        confidence = 0.8
        rationale = f"under {rule}, the earlier observation ({decider['ref']}) remains controlling"
    elif rule == EQUAL_CREDIBILITY:
        if len(values) > 1:
            unresolved = [f"equally credible current measurements disagree: {sorted(values)}"]
            rationale = "two equally credible sources disagree and no rule breaks the tie"
        else:
            conclusion = next(iter(values))
            supporting = [str(item["ref"]) for item in items]
            confidence = 0.8
            rationale = "the equally credible sources agree"
    else:
        unresolved = ["no precedence rule is declared for this question"]
        rationale = "the evidence does not settle the question and no rule says it does"

    abstained = conclusion is None
    record_id = "REC-" + digest({"question": str(question), "rule": rule,
                                 "evidence": sorted(str(item.get("ref")) for item in items),
                                 "at": moment})[:16].upper()
    _write(db_path, "INSERT OR IGNORE INTO ciph_reconciliations (record_id, question, rule, evidence_json, "
                    "supporting_json, contradicting_json, conclusion, confidence, abstained, rationale, "
                    "unresolved_json, created_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (record_id, str(question), str(rule), json.dumps(items, sort_keys=True, default=str),
            json.dumps(sorted(supporting)), json.dumps(sorted(contradicting)), conclusion, float(confidence),
            1 if abstained else 0, rationale, json.dumps(unresolved), moment,
            EVIDENCE_RECONCILIATION_V1))
    return {"record_id": record_id, "question": str(question), "rule": str(rule), "evidence": items,
            "supporting": sorted(supporting), "contradicting": sorted(contradicting),
            "conclusion": conclusion, "confidence": float(confidence), "abstained": abstained,
            "status": UNRESOLVED if abstained else SETTLED, "rationale": rationale,
            "unresolved_assumptions": unresolved, "missing_sources": missing,
            "freshness": {str(item.get("ref")): item["age_seconds"] for item in items},
            "policy_version": EVIDENCE_RECONCILIATION_V1}


def score_conclusion(record: Dict[str, Any], *, conclusion: Optional[str]) -> Dict[str, Any]:
    """
    Score a conclusion AGAINST THE DECLARED RECONCILIATION - not against a memorized answer.

    An abstention on an unsettled record is CORRECT. A confident answer on an unsettled record is WRONG.
    """
    expected = record["conclusion"]
    if record["abstained"]:
        correct = conclusion is None or str(conclusion).upper() in ("UNRESOLVED", "ABSTAIN", "UNKNOWN")
        return {"correct": correct, "expected": "ABSTAIN", "got": conclusion,
                "reason": "the record is unsettled, so abstention is the correct response"}
    return {"correct": conclusion is not None and str(conclusion).upper() == str(expected).upper(),
            "expected": expected, "got": conclusion,
            "reason": "the declared rule settles the question"}


def citation_consistency(record: Dict[str, Any], *, cited_ref: Optional[str],
                         conclusion: Optional[str]) -> Dict[str, Any]:
    """
    Does the CITED evidence actually carry the concluded value?

    This is the failure the campaign names: citing E3 while concluding CLOSED. It is caught even when the
    conclusion happens to be right, because the citation is what was offered as support.
    """
    if cited_ref is None:
        return {"consistent": False, "reason": "no evidence was cited"}
    cited = [item for item in record["evidence"] if str(item.get("ref")) == str(cited_ref)]
    if not cited:
        return {"consistent": False, "reason": f"{cited_ref} is not in the reconciliation's evidence"}
    value = str(cited[0]["value"])
    consistent = conclusion is not None and str(conclusion).upper() == value.upper()
    return {"consistent": consistent, "cited_ref": str(cited_ref), "cited_value": value,
            "concluded": conclusion,
            "reason": ("the citation supports the conclusion" if consistent else
                       f"the cited evidence says {value}, which does not support '{conclusion}'")}


def reconciliations(db_path: str) -> List[Dict[str, Any]]:
    rows = _rows(db_path, "SELECT * FROM ciph_reconciliations ORDER BY created_at, record_id;")
    for row in rows:
        row["evidence"] = json.loads(row.pop("evidence_json") or "[]")
        row["supporting"] = json.loads(row.pop("supporting_json") or "[]")
        row["contradicting"] = json.loads(row.pop("contradicting_json") or "[]")
        row["unresolved_assumptions"] = json.loads(row.pop("unresolved_json") or "[]")
        row["abstained"] = bool(row["abstained"])
    return rows


def reconciliation_digest(db_path: str) -> str:
    return digest({"records": _rows(db_path, "SELECT record_id, rule, conclusion, abstained "
                                               "FROM ciph_reconciliations ORDER BY record_id;")})
