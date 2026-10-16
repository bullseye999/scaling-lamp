"""
ciph/kernel/meta_corpus - 4.7 Gate Four: how do you evaluate a replacement for the thing that evaluates,
without letting the replacement write the exam?

Two classes of case:

    GENERATOR_CASE   historical improvement opportunities, bounded weakness families
    EVALUATOR_CASE   candidate comparisons, hard-invariant situations, noisy/unresolvable ones

THE ACCESS BOUNDARY IS A FILE, NOT A CONVENTION. Public inputs live in one database; the sealed
answers, expected verdicts and adjudication notes live in a SEPARATE database file that the
candidate-facing handle is never given. A candidate-side process holding the public path cannot read an
answer even by opening the whole file. That is a real boundary, with a stated limit: a process with
filesystem access to BOTH paths could read the sealed DB, so the boundary is process-and-handle based,
not cryptographic.

The other half of the design: E0's historical answer is NOT automatically ground truth. Otherwise the
only way to beat the old evaluator would be to imitate it. Cases are classified:

    MECHANICAL   decidable from a constitutional invariant (fabricated evidence -> INVALID)
    OPERATOR     an independent adjudication was already recorded
    NONE         unresolvable - an evaluator disagreement is recorded and decides nothing

LAWS
 1. The protocol is frozen before the candidate sees held-out cases.
 2. A meta candidate cannot modify corpus membership.
 3. A meta candidate cannot read sealed answers.
 4. A meta candidate cannot select which failed cases count.
 5. The pre-change authoritative evaluator stays authoritative throughout.
 6. E1's opinion of E1 has zero standing.
 7. The corpus version is immutable.
 8. Changing the corpus or the protocol creates new identities.
 9. Unadjudicated evaluator disagreement remains disagreement.
10. Same corpus + protocol + candidate -> same evaluation identity after restart.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.crucible_metrics import (
    STATUS_DOMINATED,
    STATUS_DOMINATES,
    STATUS_INCOMPARABLE,
    STATUS_INSUFFICIENT,
    STATUS_INVALID,
)
from ciph.kernel.crucible_types import CrucibleError, digest

META_CORPUS_V1 = "META_CORPUS_V1"
META_CRUCIBLE_PROTOCOL_V1 = "META_CRUCIBLE_PROTOCOL_V1"

CASE_KIND_GENERATOR = "GENERATOR_CASE"
CASE_KIND_EVALUATOR = "EVALUATOR_CASE"
VALID_CASE_KINDS = (CASE_KIND_GENERATOR, CASE_KIND_EVALUATOR)

ADJUDICATION_MECHANICAL = "MECHANICAL"
ADJUDICATION_OPERATOR = "OPERATOR"
ADJUDICATION_NONE = "NONE"
VALID_ADJUDICATIONS = (ADJUDICATION_MECHANICAL, ADJUDICATION_OPERATOR, ADJUDICATION_NONE)

REASON_ACCESS_DENIED = "SEALED_CORPUS_ACCESS_DENIED"
REASON_NOT_AN_ADJUDICATOR = "ADJUDICATOR_AUTHORIZATION_REQUIRED"

CARRIES_NO_ANSWER = ("MECHANICAL", "OPERATOR")

_PUBLIC_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_corpus_cases (
        case_id TEXT PRIMARY KEY,
        corpus_version TEXT NOT NULL,
        case_kind TEXT NOT NULL,
        input_digest TEXT NOT NULL,
        environment_identity TEXT,
        expected_properties_json TEXT,
        adjudication_class TEXT NOT NULL,
        sealed_payload_ref TEXT NOT NULL,
        provenance_digest TEXT NOT NULL,
        registered_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_corpus_protocols (
        protocol_id TEXT PRIMARY KEY,
        corpus_version TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        metric_definitions_json TEXT,
        minimum_evidence INTEGER NOT NULL,
        required_case_kinds_json TEXT,
        authority_ref TEXT NOT NULL,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_evaluator_disagreements (
        disagreement_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        protocol_id TEXT NOT NULL,
        authoritative_evaluator_id TEXT NOT NULL,
        candidate_evaluator_id TEXT NOT NULL,
        authoritative_result TEXT,
        candidate_result TEXT,
        adjudicated_result TEXT,
        disagreement_class TEXT NOT NULL,
        recorded_at REAL
    );
    """,
)

_SEALED_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_corpus_sealed (
        case_id TEXT PRIMARY KEY,
        sealed_payload_json TEXT NOT NULL,
        expected_result TEXT,
        adjudicated_result TEXT,
        adjudication_notes TEXT,
        sealed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_sealed_access_log (
        access_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        adjudicator_ref TEXT NOT NULL,
        accessed_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetaCorpusCase:
    case_id: str
    corpus_version: str
    case_kind: str
    input_digest: str
    environment_identity: Optional[str]
    expected_properties: Tuple[Dict[str, Any], ...]
    adjudication_class: str
    sealed_payload_ref: str
    provenance_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"case_id": self.case_id, "corpus_version": self.corpus_version,
                "case_kind": self.case_kind, "input_digest": self.input_digest,
                "environment_identity": self.environment_identity,
                "expected_properties": [dict(item) for item in self.expected_properties],
                "adjudication_class": self.adjudication_class,
                "sealed_payload_ref": self.sealed_payload_ref,
                "provenance_digest": self.provenance_digest}


@dataclass(frozen=True)
class EvaluatorDisagreement:
    disagreement_id: str
    case_id: str
    protocol_id: str
    authoritative_evaluator_id: str
    candidate_evaluator_id: str
    authoritative_result: Optional[str]
    candidate_result: Optional[str]
    adjudicated_result: Optional[str]
    disagreement_class: str

    def as_dict(self) -> Dict[str, Any]:
        return {"disagreement_id": self.disagreement_id, "case_id": self.case_id,
                "protocol_id": self.protocol_id,
                "authoritative_evaluator_id": self.authoritative_evaluator_id,
                "candidate_evaluator_id": self.candidate_evaluator_id,
                "authoritative_result": self.authoritative_result,
                "candidate_result": self.candidate_result,
                "adjudicated_result": self.adjudicated_result,
                "disagreement_class": self.disagreement_class}


@dataclass(frozen=True)
class MetaEvaluationResult:
    protocol_id: str
    candidate_evaluator_id: str
    status: str
    cases_evaluated: int
    adjudicated_cases: int
    constitutional_misses: int
    adjudicated_errors: int
    agreements: int
    unadjudicated_disagreements: int
    basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"protocol_id": self.protocol_id, "candidate_evaluator_id": self.candidate_evaluator_id,
                "status": self.status, "cases_evaluated": self.cases_evaluated,
                "adjudicated_cases": self.adjudicated_cases,
                "constitutional_misses": self.constitutional_misses,
                "adjudicated_errors": self.adjudicated_errors, "agreements": self.agreements,
                "unadjudicated_disagreements": self.unadjudicated_disagreements,
                "basis_digest": self.basis_digest}


def _connect(path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10.0)
            connection.row_factory = sqlite3.Row
            return connection
        except sqlite3.OperationalError:
            pass
    connection = sqlite3.connect(path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    return connection


class CandidateFacingCorpus:
    """
    Everything a candidate generator or evaluator may see, and nothing else.

    It is constructed with the PUBLIC database only. There is no method that reaches a sealed answer,
    and - the point of the design - the sealed answers are not in this file at all.
    """

    def __init__(self, public_db_path: str):
        self._public = public_db_path

    def cases(self, corpus_version: str) -> List[Dict[str, Any]]:
        connection = _connect(self._public, read_only=True)
        try:
            rows = [dict(row) for row in connection.execute(
                "SELECT * FROM ciph_meta_corpus_cases WHERE corpus_version = ? ORDER BY case_id;",
                (corpus_version,))]
        except sqlite3.Error:
            rows = []
        finally:
            connection.close()
        return [{"case_id": row["case_id"], "case_kind": row["case_kind"],
                 "input_digest": row["input_digest"],
                 "expected_properties": json.loads(row["expected_properties_json"] or "[]"),
                 "environment_identity": row["environment_identity"]} for row in rows]

    def case_input(self, corpus_version: str, case_id: str) -> Dict[str, Any]:
        for case in self.cases(corpus_version):
            if case["case_id"] == case_id:
                return {"case_id": case["case_id"], "input_digest": case["input_digest"],
                        "expected_properties": case["expected_properties"]}
        raise CrucibleError("UNKNOWN_CASE", case_id)


class MetaCorpusVault:
    """
    The adjudication side: public metadata PLUS the sealed answers, in a separate database.

    Only this class can reveal a sealed payload, and only to a caller presenting a non-candidate
    adjudicator reference. Every reveal is audited.
    """

    def __init__(self, public_db_path: str, sealed_db_path: str):
        self._public = public_db_path
        self._sealed = sealed_db_path

    # ------------------------------------------------------------------ registration
    def register_case(self, *, corpus_version: str, case_kind: str, case_input: Mapping[str, Any],
                      expected_properties: Sequence[Mapping[str, Any]] = (),
                      adjudication_class: str = ADJUDICATION_NONE,
                      sealed_payload: Optional[Mapping[str, Any]] = None,
                      expected_result: Optional[str] = None,
                      adjudicated_result: Optional[str] = None,
                      adjudication_notes: Optional[str] = None,
                      environment_identity: Optional[str] = None,
                      now: Optional[float] = None) -> MetaCorpusCase:
        if case_kind not in VALID_CASE_KINDS:
            raise CrucibleError("INVALID_CASE_KIND", str(case_kind))
        if adjudication_class not in VALID_ADJUDICATIONS:
            raise CrucibleError("INVALID_ADJUDICATION_CLASS", str(adjudication_class))
        if adjudication_class in CARRIES_NO_ANSWER and adjudicated_result is None and (
                expected_result is None):
            raise CrucibleError("ADJUDICATED_CASE_REQUIRES_AN_OUTCOME", str(case_kind))
        moment = time.time() if now is None else float(now)
        input_digest = digest(dict(case_input))
        provenance = digest({"version": META_CORPUS_V1, "corpus": corpus_version,
                             "kind": case_kind, "input": input_digest,
                             "adjudication": adjudication_class,
                             "expected": expected_result})
        case_id = "MCC-" + provenance[:16].upper()
        reference = f"sealed://{corpus_version}/{case_id}"

        public = _connect(self._public)
        try:
            for statement in _PUBLIC_SCHEMA:
                public.execute(statement)
            public.execute(
                "INSERT OR IGNORE INTO ciph_meta_corpus_cases (case_id, corpus_version, case_kind, "
                "input_digest, environment_identity, expected_properties_json, adjudication_class, "
                "sealed_payload_ref, provenance_digest, registered_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
                (case_id, corpus_version, case_kind, input_digest, environment_identity,
                 json.dumps([dict(item) for item in expected_properties], sort_keys=True),
                 adjudication_class, reference, provenance, moment))
            public.commit()
        finally:
            public.close()

        sealed = _connect(self._sealed)
        try:
            for statement in _SEALED_SCHEMA:
                sealed.execute(statement)
            sealed.execute(
                "INSERT OR IGNORE INTO ciph_meta_corpus_sealed (case_id, sealed_payload_json, "
                "expected_result, adjudicated_result, adjudication_notes, sealed_at) "
                "VALUES (?,?,?,?,?,?);",
                (case_id, json.dumps(dict(sealed_payload or {}), sort_keys=True), expected_result,
                 adjudicated_result, adjudication_notes, moment))
            sealed.commit()
        finally:
            sealed.close()
        return self.case(case_id)

    # ------------------------------------------------------------------ reading
    def case(self, case_id: str) -> MetaCorpusCase:
        connection = _connect(self._public, read_only=True)
        try:
            row = connection.execute("SELECT * FROM ciph_meta_corpus_cases WHERE case_id = ?;",
                                     (case_id,)).fetchone()
        except sqlite3.Error:
            row = None
        finally:
            connection.close()
        if row is None:
            raise CrucibleError("UNKNOWN_CASE", case_id)
        row = dict(row)
        return MetaCorpusCase(
            case_id=str(row["case_id"]), corpus_version=str(row["corpus_version"]),
            case_kind=str(row["case_kind"]), input_digest=str(row["input_digest"]),
            environment_identity=row["environment_identity"],
            expected_properties=tuple(json.loads(row["expected_properties_json"] or "[]")),
            adjudication_class=str(row["adjudication_class"]),
            sealed_payload_ref=str(row["sealed_payload_ref"]),
            provenance_digest=str(row["provenance_digest"]))

    def cases(self, corpus_version: Optional[str] = None) -> List[MetaCorpusCase]:
        connection = _connect(self._public, read_only=True)
        query = "SELECT case_id FROM ciph_meta_corpus_cases"
        params: Tuple[Any, ...] = ()
        if corpus_version is not None:
            query += " WHERE corpus_version = ?"
            params = (corpus_version,)
        try:
            ids = [str(row["case_id"]) for row in connection.execute(
                query + " ORDER BY case_id;", params)]
        except sqlite3.Error:
            ids = []
        finally:
            connection.close()
        return [self.case(case_id) for case_id in ids]

    def reveal(self, case_id: str, *, adjudicator_ref: Optional[str]) -> Dict[str, Any]:
        """
        Law 3, as a real boundary: a sealed answer is only reachable with a non-candidate adjudicator
        reference, and every reveal is audited.
        """
        # Allow-list, not deny-list: a case id, a candidate id or any other identifier a candidate
        # could plausibly hold must not open the door, so the reference has to SAY what it is.
        reference = str(adjudicator_ref or "")
        if not any(reference.startswith(prefix) for prefix in
                   ("operator:", "protocol:", "adjudicator:")):
            raise CrucibleError(REASON_NOT_AN_ADJUDICATOR,
                                f"{adjudicator_ref!r} is not an adjudicator")
        exact = self.case(case_id)
        connection = _connect(self._sealed)
        try:
            row = connection.execute("SELECT * FROM ciph_meta_corpus_sealed WHERE case_id = ?;",
                                     (exact.case_id,)).fetchone()
            if row is None:
                raise CrucibleError(REASON_ACCESS_DENIED, case_id)
            row = dict(row)
            connection.execute(
                "INSERT OR IGNORE INTO ciph_meta_sealed_access_log (access_id, case_id, "
                "adjudicator_ref, accessed_at) VALUES (?,?,?,?);",
                ("SAL-" + digest({"case": case_id, "who": adjudicator_ref})[:16].upper(), case_id,
                 str(adjudicator_ref), time.time()))
            connection.commit()
        finally:
            connection.close()
        return {"case_id": exact.case_id, "adjudication_class": exact.adjudication_class,
                "expected_result": row["expected_result"],
                "adjudicated_result": row["adjudicated_result"],
                "sealed_payload": json.loads(row["sealed_payload_json"] or "{}")}

    def sealed_access_log(self) -> List[Dict[str, Any]]:
        connection = _connect(self._sealed, read_only=True)
        try:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM ciph_meta_sealed_access_log ORDER BY accessed_at, access_id;")]
        except sqlite3.Error:
            return []
        finally:
            connection.close()

    def corpus_digest(self, corpus_version: Optional[str] = None) -> str:
        return digest({"version": META_CORPUS_V1,
                       "cases": [case.as_dict() for case in self.cases(corpus_version)]})


# ---------------------------------------------------------------------------- protocol
def freeze_meta_protocol(db_path: str, *, corpus_version: str, authority_ref: str,
                         metric_definitions: Sequence[Mapping[str, Any]] = (),
                         minimum_evidence: int = 1,
                         required_case_kinds: Sequence[str] = (CASE_KIND_EVALUATOR,),
                         now: Optional[float] = None) -> str:
    """Freeze the judgement plan BEFORE any candidate sees a held-out case (law 1, 7, 8)."""
    if not authority_ref:
        raise CrucibleError("PROTOCOL_REQUIRES_AN_AUTHORITY", '')
    if int(minimum_evidence) < 1:
        raise CrucibleError("MINIMUM_EVIDENCE_MUST_BE_POSITIVE", str(minimum_evidence))
    for kind in required_case_kinds:
        if kind not in VALID_CASE_KINDS:
            raise CrucibleError("INVALID_CASE_KIND", str(kind))
    moment = time.time() if now is None else float(now)
    payload = {"version": META_CRUCIBLE_PROTOCOL_V1, "corpus_version": corpus_version,
               "metrics": sorted((dict(item) for item in metric_definitions),
                                 key=lambda item: str(item.get("metric_id"))),
               "minimum_evidence": int(minimum_evidence),
               "required_case_kinds": sorted(str(kind) for kind in required_case_kinds)}
    protocol_id = "MCP-" + digest(payload)[:16].upper()
    connection = _connect(db_path)
    try:
        for statement in _PUBLIC_SCHEMA:
            connection.execute(statement)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_corpus_protocols (protocol_id, corpus_version, "
            "payload_json, metric_definitions_json, minimum_evidence, required_case_kinds_json, "
            "authority_ref, created_at) VALUES (?,?,?,?,?,?,?,?);",
            (protocol_id, corpus_version, json.dumps(payload, sort_keys=True),
             json.dumps([dict(item) for item in metric_definitions]), int(minimum_evidence),
             json.dumps(sorted(str(kind) for kind in required_case_kinds)), authority_ref, moment))
        connection.commit()
    finally:
        connection.close()
    return protocol_id


def get_meta_protocol(db_path: str, protocol_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_corpus_protocols WHERE protocol_id = ?;",
                                 (protocol_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_META_PROTOCOL", protocol_id)
    row = dict(row)
    row["payload"] = json.loads(row["payload_json"] or "{}")
    return row


def assert_meta_protocol_integrity(db_path: str, protocol_id: str) -> str:
    """
    A tamper check that reads the COLUMNS, not just the payload blob.

    Hashing the payload alone would miss an out-of-band `UPDATE` of `minimum_evidence` or the corpus
    version - exactly the kind of quiet goalpost move this protocol exists to prevent.
    """
    protocol = get_meta_protocol(db_path, protocol_id)
    if "MCP-" + digest(protocol["payload"])[:16].upper() != protocol_id:
        raise CrucibleError("META_PROTOCOL_INTEGRITY_VIOLATION",
                            f"{protocol_id} does not hash to its own payload")
    recomputed = {"version": META_CRUCIBLE_PROTOCOL_V1,
                  "corpus_version": str(protocol["corpus_version"]),
                  "metrics": sorted((dict(item) for item in
                                     json.loads(protocol["metric_definitions_json"] or "[]")),
                                    key=lambda item: str(item.get("metric_id"))),
                  "minimum_evidence": int(protocol["minimum_evidence"]),
                  "required_case_kinds": sorted(json.loads(protocol["required_case_kinds_json"]
                                                          or "[]"))}
    if recomputed != protocol["payload"]:
        raise CrucibleError("META_PROTOCOL_INTEGRITY_VIOLATION",
                            f"{protocol_id} columns disagree with the frozen payload")
    return protocol_id


# ---------------------------------------------------------------------------- evaluation
def _result_of(callable_or_mapping: Any, case_input: Mapping[str, Any]) -> Optional[str]:
    if callable(callable_or_mapping):
        return callable_or_mapping(case_input)
    if isinstance(callable_or_mapping, Mapping):
        return callable_or_mapping.get(case_input.get("case_id"))
    return None


def run_meta_evaluation(db_path: str, vault: MetaCorpusVault, *, protocol_id: str,
                        candidate_evaluator_id: str, evaluator: Any, authoritative: Any,
                        case_ids: Sequence[str], now: Optional[float] = None
                        ) -> MetaEvaluationResult:
    """
    Measure a candidate evaluator against the authoritative one on a sealed corpus (laws 4, 5, 6, 9).

    Only adjudicated cases move the verdict. Where the two evaluators disagree and no independent
    adjudication exists, that stays an `EvaluatorDisagreement` - it is not a win for either side, and
    it is most certainly not a win for the candidate, which is the whole point.
    """
    assert_meta_protocol_integrity(db_path, protocol_id)
    protocol = get_meta_protocol(db_path, protocol_id)
    if str(candidate_evaluator_id).startswith("MC-"):
        raise CrucibleError("META_CANDIDATE_MAY_NOT_BE_THE_EVALUATOR", candidate_evaluator_id)

    moment = time.time() if now is None else float(now)
    misses = adjudicated_cases = errors = agreements = unadjudicated = 0
    connection = _connect(db_path)
    try:
        for statement in _PUBLIC_SCHEMA:
            connection.execute(statement)
        for case_id in case_ids:
            case = vault.case(case_id)
            if protocol["corpus_version"] != case.corpus_version:
                raise CrucibleError("CASE_OUTSIDE_PROTOCOL_CORPUS", case_id)
            case_input = vault.reveal(case_id, adjudicator_ref=f"protocol:{protocol_id}")
            if case_input["adjudication_class"] != ADJUDICATION_NONE:
                adjudicated_cases += 1
            authoritative_result = _result_of(authoritative, {"case_id": case_id})
            candidate_result = _result_of(evaluator, {"case_id": case_id})
            truth = case_input["expected_result"] or case_input["adjudicated_result"]
            if candidate_result != authoritative_result:
                connection.execute(
                    "INSERT OR IGNORE INTO ciph_meta_evaluator_disagreements (disagreement_id, "
                    "case_id, protocol_id, authoritative_evaluator_id, candidate_evaluator_id, "
                    "authoritative_result, candidate_result, adjudicated_result, disagreement_class, "
                    "recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
                    ("MED-" + digest({"case": case_id, "candidate": candidate_evaluator_id,
                                      "protocol": protocol_id})[:16].upper(),
                     case_id, protocol_id, str(authoritative if isinstance(authoritative, str)
                                               else "authoritative"),
                     candidate_evaluator_id, authoritative_result, candidate_result, truth,
                     "ADJUDICATED" if truth is not None else "UNRESOLVED", moment))
            # An UNRESOLVED disagreement is recorded too: it is evidence about the candidate
            # evaluator, and it decides nothing for either side (law 9).
            if truth is None:
                if candidate_result != authoritative_result:
                    unadjudicated += 1
                continue
            if candidate_result == truth:
                agreements += 1
            else:
                errors += 1
                if case_input["adjudication_class"] == ADJUDICATION_MECHANICAL:
                    # A constitutional invariant is not a metric: missing it is not a bad score.
                    misses += 1
        connection.commit()
    finally:
        connection.close()

    if misses:
        status = STATUS_INVALID
    elif adjudicated_cases < int(protocol["minimum_evidence"]):
        status = STATUS_INSUFFICIENT
    elif errors == 0:
        status = STATUS_DOMINATES
    elif errors == adjudicated_cases:
        status = STATUS_DOMINATED
    else:
        status = STATUS_INCOMPARABLE
    basis = digest({"protocol": protocol_id, "candidate": candidate_evaluator_id,
                    "misses": misses, "errors": errors, "agreements": agreements,
                    "unadjudicated": unadjudicated, "cases": sorted(str(c) for c in case_ids)})
    return MetaEvaluationResult(
        protocol_id=protocol_id, candidate_evaluator_id=candidate_evaluator_id, status=status,
        cases_evaluated=len(list(case_ids)), adjudicated_cases=adjudicated_cases,
        constitutional_misses=misses, adjudicated_errors=errors, agreements=agreements,
        unadjudicated_disagreements=unadjudicated, basis_digest=basis)


def disagreements(db_path: str, protocol_id: Optional[str] = None) -> List[EvaluatorDisagreement]:
    connection = _connect(db_path, read_only=True)
    query = "SELECT * FROM ciph_meta_evaluator_disagreements"
    params: Tuple[Any, ...] = ()
    if protocol_id is not None:
        query += " WHERE protocol_id = ?"
        params = (protocol_id,)
    try:
        rows = [dict(row) for row in connection.execute(query + " ORDER BY disagreement_id;",
                                                        params)]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return [EvaluatorDisagreement(
        disagreement_id=str(row["disagreement_id"]), case_id=str(row["case_id"]),
        protocol_id=str(row["protocol_id"]),
        authoritative_evaluator_id=str(row["authoritative_evaluator_id"]),
        candidate_evaluator_id=str(row["candidate_evaluator_id"]),
        authoritative_result=row["authoritative_result"], candidate_result=row["candidate_result"],
        adjudicated_result=row["adjudicated_result"],
        disagreement_class=str(row["disagreement_class"])) for row in rows]


def meta_corpus_digest(db_path: str) -> str:
    return digest({"version": META_CORPUS_V1,
                   "cases": [case.as_dict() for case in MetaCorpusVault(db_path, db_path).cases()]})
