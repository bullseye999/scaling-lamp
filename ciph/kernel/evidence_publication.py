"""
ciph/kernel/evidence_publication - 10.x-R B: nothing is published unless canonical evidence licenses it.

    A model citing a real observation while contradicting that observation must not pass merely because its
    citation resolves.

THE RULE-GOVERNED PATH, in order, for every consequential factual publication:

    1. retrieve the relevant canonical evidence (the caller supplies it, or it comes from 4.2/10.0 refs)
    2. resolve the applicable VERSIONED standing rule
    3. compute the rule-governed conclusion INDEPENDENTLY of any model
    4. identify the supporting and the contradictory evidence
    5. return an EXPLICIT unresolved outcome when the rule or the evidence cannot settle the question
    6. permit a model to explain ONLY a conclusion consistent with that validated outcome
    7. refuse or replace an unsupported model assertion BEFORE publication

WHERE NO RULE SETTLES THE QUESTION, this does not pretend to have established semantic truth: it publishes an
explicit abstention and refuses a confident model claim.

CREDIT IS ATTRIBUTED, NOT MERGED. Every publication names which component produced the published conclusion -
`RULE_DERIVED`, `MODEL_SUPPORTED`, `MODEL_CORRECTED` or `ABSTAINED` - and a rule-derived or corrected answer
carries `model_quality_credit: False`. A safe correction earns SYSTEM_EVIDENCE_RELIABILITY; it does NOT earn
REAL_MODEL_REASONING_QUALITY. That distinction is the point of this module.

OWNERSHIP. This module owns no fact and no truth: it delegates the reconciliation to
`ciph/kernel/evidence_reconciliation.py` (the 4.2/10.14 owner) and only records the PUBLICATION DECISION over
that owner's result. It is not a second source of truth.

PERSISTENCE. The decision row is written in ONE transaction (`with connection`), keyed by a deterministic
`publication_id`, so duplicate publish attempts are idempotent (`INSERT OR IGNORE`) and an interrupted write
commits nothing rather than a partial or fabricated success. The RAW model output is preserved verbatim for
audit, separately from the parsed verdict and the rule-derived conclusion.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import digest
from ciph.kernel.evidence_reconciliation import (reconcile, score_conclusion, citation_consistency)

EVIDENCE_PUBLICATION_V1 = "EVIDENCE_PUBLICATION_V1"

RULE_DERIVED = "RULE_DERIVED"
MODEL_SUPPORTED = "MODEL_SUPPORTED"
MODEL_CORRECTED = "MODEL_CORRECTED"
ABSTAINED = "ABSTAINED"

REASON_MODEL_CONTRADICTS_THE_RULE = "MODEL_CONCLUSION_CONTRADICTS_THE_RULE_DERIVED_OUTCOME"
REASON_MODEL_CITATION_CONTRADICTS_THE_MODEL = "MODEL_CITATION_DOES_NOT_SUPPORT_ITS_OWN_CONCLUSION"
REASON_CONFIDENT_CLAIM_ON_UNSETTLED_EVIDENCE = "CONFIDENT_CLAIM_ON_EVIDENCE_THAT_DOES_NOT_SETTLE"
REASON_NO_MODEL_CONTRIBUTION = "NO_MODEL_CONTRIBUTION"
# A model ABSTENTION on a settled question is NOT a factual assertion. It is under-commitment, and it must
# never be recorded as if the model asserted something contradictory.
REASON_MODEL_ABSTAINED_ON_SETTLED_EVIDENCE = "MODEL_ABSTAINED_ON_A_SETTLED_QUESTION"

_ABSTENTION_TOKENS = ("ABSTAIN", "UNRESOLVED", "UNKNOWN", "INSUFFICIENT", "CANNOT")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_publications (
        publication_id TEXT PRIMARY KEY,
        question TEXT NOT NULL,
        rule TEXT NOT NULL,
        reconciliation_ref TEXT,
        attribution TEXT NOT NULL,
        published_conclusion TEXT,
        model_conclusion TEXT,
        model_citation TEXT,
        model_raw_output TEXT,
        refused_assertion TEXT,
        refusal_reason TEXT,
        unresolved_json TEXT NOT NULL,
        model_quality_credit INTEGER NOT NULL,
        system_reliability_credit INTEGER NOT NULL,
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


def _write_publication(db_path: str, row: Sequence[Any]) -> None:
    """Write the decision row in ONE transaction; nothing partial is ever committed."""
    connection = _connect(db_path)
    try:
        with connection:  # commits on success, rolls back on any exception
            init_schema(connection)
            connection.execute(
                "INSERT OR IGNORE INTO ciph_publications (publication_id, question, rule, "
                "reconciliation_ref, attribution, published_conclusion, model_conclusion, model_citation, "
                "model_raw_output, refused_assertion, refusal_reason, unresolved_json, model_quality_credit, "
                "system_reliability_credit, created_at, policy_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
                tuple(row))
    finally:
        connection.close()


def _rows(db_path: str, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def publish(db_path: str, *, question: str, evidence: Sequence[Dict[str, Any]], rule: str,
            model_conclusion: Optional[str] = None, model_citation: Optional[str] = None,
            model_raw_output: Optional[str] = None, required_sources: Sequence[str] = (),
            now: Optional[float] = None) -> Dict[str, Any]:
    """
    Decide what may be PUBLISHED, and attribute the credit for it.

    The model may explain a conclusion the rule already licenses. It may not establish one.
    """
    moment = _moment(now)
    record = reconcile(db_path, question=question, evidence=evidence, rule=rule,
                       required_sources=required_sources, now=moment)
    refused: Optional[str] = None
    refusal_reason: Optional[str] = None
    attribution = RULE_DERIVED
    published = record["conclusion"]
    model_credit = False

    model_answer = None if model_conclusion is None else str(model_conclusion).strip().upper()
    # The published conclusion is the RULE outcome unless the rule abstained.
    if record["abstained"]:
        attribution = ABSTAINED
        published = None
        if model_answer and model_answer not in ("ABSTAIN", "UNRESOLVED", "UNKNOWN"):
            refused, refusal_reason = str(model_conclusion), REASON_CONFIDENT_CLAIM_ON_UNSETTLED_EVIDENCE
    elif model_answer is None or model_answer == "":
        # No model contribution at all: the rule decides, and NO model-quality credit is earned.
        attribution = RULE_DERIVED
        refusal_reason = REASON_NO_MODEL_CONTRIBUTION
    else:
        scored = score_conclusion(record, conclusion=model_answer)
        citation = citation_consistency(record, cited_ref=model_citation, conclusion=model_answer)
        if any(token in model_answer for token in _ABSTENTION_TOKENS):
            # The model ABSTAINED while the rule settles the question. That is under-commitment, NOT a
            # contradictory assertion: the rule decides, and NO model-quality credit is earned.
            attribution = RULE_DERIVED
            refusal_reason = REASON_MODEL_ABSTAINED_ON_SETTLED_EVIDENCE
            refused = str(model_conclusion)
        elif not scored["correct"]:
            refused, refusal_reason = str(model_conclusion), REASON_MODEL_CONTRADICTS_THE_RULE
            attribution = MODEL_CORRECTED
        elif not citation["consistent"]:
            # Right answer, unsupported citation: a correct GUESS is not sound reconciliation.
            refused, refusal_reason = str(model_conclusion), REASON_MODEL_CITATION_CONTRADICTS_THE_MODEL
            attribution = MODEL_CORRECTED
        else:
            attribution = MODEL_SUPPORTED
            model_credit = True

    publication_id = "PUB-" + digest({"question": str(question), "rule": rule,
                                      "reconciliation": record["record_id"], "at": moment})[:16].upper()
    _write_publication(db_path, (
        publication_id, str(question), str(rule), record["record_id"], attribution, published,
        model_conclusion, model_citation, model_raw_output, refused, refusal_reason,
        json.dumps(list(record["unresolved_assumptions"])), 1 if model_credit else 0,
        1 if (record["abstained"] or refused) else 0, moment, EVIDENCE_PUBLICATION_V1))
    return {"publication_id": publication_id, "question": str(question), "rule": str(rule),
            "reconciliation": record, "attribution": attribution,
            "published_conclusion": published, "abstained": record["abstained"],
            "model_conclusion": model_conclusion, "model_citation": model_citation,
            "model_raw_output": model_raw_output,
            "refused_assertion": refused, "refusal_reason": refusal_reason,
            "unresolved_assumptions": list(record["unresolved_assumptions"]),
            "model_quality_credit": model_credit,
            "system_reliability_credit": bool(record["abstained"] or refused),
            "publication_text": publication_text(record, published, attribution),
            "policy_version": EVIDENCE_PUBLICATION_V1}


def publication_text(record: Dict[str, Any], published: Optional[str],
                     attribution: str) -> str:
    """A conservative, evidence-grounded sentence. It never outruns the validated outcome."""
    if record["abstained"]:
        reasons = "; ".join(record["unresolved_assumptions"]) or "the evidence does not settle the question"
        return (f"I cannot settle this: {reasons}. I am not publishing a conclusion. "
                f"(rule {record['rule']}, evidence {[item['ref'] for item in record['evidence']]})")
    supporting = ", ".join(record["supporting"]) or "none"
    contradicting = ", ".join(record["contradicting"]) or "none"
    qualify = "" if attribution == MODEL_SUPPORTED else " (established by the declared rule, not by me)"
    return (f"{published}{qualify}. Supporting evidence: {supporting}. "
            f"Contradicting evidence: {contradicting}. Rule: {record['rule']}.")


def publications(db_path: str) -> List[Dict[str, Any]]:
    rows = _rows(db_path, "SELECT * FROM ciph_publications ORDER BY created_at, publication_id;")
    for row in rows:
        row["model_quality_credit"] = bool(row["model_quality_credit"])
        row["system_reliability_credit"] = bool(row["system_reliability_credit"])
        row["unresolved_assumptions"] = json.loads(row.pop("unresolved_json") or "[]")
    return rows


def publication_digest(db_path: str) -> str:
    return digest({"publications": _rows(db_path, "SELECT publication_id, attribution, "
                                                     "published_conclusion, refused_assertion "
                                                     "FROM ciph_publications ORDER BY publication_id;")})
