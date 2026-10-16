"""
ciph/kernel/referential_continuity - 10.0: the evidence behind an announcement stays retrievable.

    "Sir, I found twenty alerts" must be a claim about a COMMITTED result set containing exactly twenty
    accessible finding identities - or it must not be said.

The failure this module exists to remove is structural, not stylistic: there was nowhere in the tree for a
result set to live, so "retrieve the seventh" could only be answered by running a NEW scan. That is the
substitution this program forbids, and it was not a bug in a summary - it was the absence of identity.

Design rules, each answering a way the old behaviour lied:

    IDENTITY IS DERIVED, NEVER CHOSEN.  A model cannot invent a `result_set_id`: it is a digest of the
    investigation reference and the committed findings, and a `finding_id` is derived from its set, its
    ordinal, its source and its evidence. Asking the model for an id would reintroduce the whole problem.

    ORDER IS PROVENANCE.  Ordinals are persisted, so "the seventh alert" resolves to the same finding
    forever - including after a restart, and after a later revision.

    ANNOUNCEMENT IS A CLAIM ABOUT COMMITTED BYTES.  `announce` recomputes the committed finding count at
    the referenced revision and REFUSES a claim that outruns it, recording the refusal. A notification
    cannot legitimately describe results that were never committed because the check is arithmetic.

    HISTORY IS APPEND-ONLY.  A revision adds a row; it never edits one. An announcement keeps pointing at
    the revision it was made against, so later evidence cannot silently rewrite what was announced.

    UNAVAILABILITY IS REPORTED.  A finding that is expired, redacted or missing its evidence says so. It is
    never quietly dropped and it is never replaced by a newer scan.

    THE LEDGER STAYS THE TRUTH OWNER.  A finding REFERENCES an epistemic observation or a worker result; it
    does not duplicate one. This module owns relationships, not facts.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

REFERENTIAL_CONTINUITY_V1 = "REFERENTIAL_CONTINUITY_V1"
RESULT_SET_V1 = "RESULT_SET_V1"
FINDING_V1 = "FINDING_V1"
ANNOUNCEMENT_V1 = "ANNOUNCEMENT_V1"
FOLLOWUP_V1 = "FOLLOWUP_V1"

AVAILABLE = "AVAILABLE"
EXPIRED = "EXPIRED"
REDACTED = "REDACTED"
MISSING_EVIDENCE = "MISSING_EVIDENCE"
VALID_AVAILABILITY = (AVAILABLE, EXPIRED, REDACTED, MISSING_EVIDENCE)

ANNOUNCED = "ANNOUNCED"
REFUSED = "REFUSED"
CORRECTED = "CORRECTED"

OPERATOR_ONLY = "OPERATOR_ONLY"
UNCLASSIFIED = "UNCLASSIFIED"

RESOLVED = "RESOLVED"
AMBIGUOUS = "AMBIGUOUS_REFERENCE"
NOT_FOUND = "NOT_FOUND"

REASON_COUNT_MISMATCH = "ANNOUNCEMENT_CLAIMS_MORE_FINDINGS_THAN_WERE_COMMITTED"
REASON_NO_REVISION = "ANNOUNCEMENT_REQUIRES_A_COMMITTED_REVISION"
REASON_UNKNOWN_SET = "UNKNOWN_RESULT_SET"
REASON_UNKNOWN_FINDING = "UNKNOWN_FINDING"
REASON_OUT_OF_RANGE = "ORDINAL_OUT_OF_RANGE"
REASON_NOT_OPERATOR = "PROTECTED_RESULT_SET_REQUIRES_AN_OPERATOR"
REASON_SNAPSHOT_MOVED = "RESULT_SET_SNAPSHOT_DOES_NOT_MATCH_THE_COMMIT"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_result_sets (
        result_set_id TEXT PRIMARY KEY,
        investigation_ref TEXT NOT NULL,
        execution_ref TEXT,
        session_ref TEXT,
        classification TEXT NOT NULL,
        current_revision INTEGER NOT NULL,
        first_committed_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_result_set_revisions (
        revision_id TEXT PRIMARY KEY,
        result_set_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        finding_ids_json TEXT NOT NULL,
        snapshot_digest TEXT NOT NULL,
        note TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_findings (
        finding_id TEXT PRIMARY KEY,
        result_set_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        ordinal INTEGER NOT NULL,
        source_ref TEXT,
        evidence_ref TEXT,
        observation_ref TEXT,
        summary TEXT,
        availability TEXT NOT NULL,
        availability_reason TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_announcements (
        announcement_id TEXT PRIMARY KEY,
        result_set_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        claimed_count INTEGER NOT NULL,
        verified_count INTEGER,
        statement TEXT,
        snapshot_digest TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT,
        announced_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_followups (
        followup_id TEXT PRIMARY KEY,
        announcement_ref TEXT,
        finding_ref TEXT,
        text TEXT,
        status TEXT NOT NULL,
        created_at REAL
    );
    """,
)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    result_set_id: str
    revision: int
    ordinal: int
    source_ref: Optional[str]
    evidence_ref: Optional[str]
    observation_ref: Optional[str]
    summary: Optional[str]
    availability: str

    def as_dict(self) -> Dict[str, Any]:
        return {"finding_id": self.finding_id, "result_set_id": self.result_set_id,
                "revision": self.revision, "ordinal": self.ordinal, "source_ref": self.source_ref,
                "evidence_ref": self.evidence_ref, "observation_ref": self.observation_ref,
                "summary": self.summary, "availability": self.availability,
                "policy_version": FINDING_V1}


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


def _revision_digest(result_set_id: str, revision: int, finding_ids: Sequence[str]) -> str:
    return digest({"result_set": result_set_id, "revision": int(revision),
                   "findings": list(finding_ids)})


def _finding_identity(result_set_id: str, ordinal: int, source_ref: Optional[str],
                      evidence_ref: Optional[str], observation_ref: Optional[str]) -> str:
    return "F-" + digest({"set": result_set_id, "ordinal": int(ordinal), "source": source_ref,
                          "evidence": evidence_ref, "observation": observation_ref})[:16].upper()


def commit_result_set(db_path: str, *, investigation_ref: str, findings: Sequence[Dict[str, Any]],
                      execution_ref: Optional[str] = None, session_ref: Optional[str] = None,
                      classification: str = OPERATOR_ONLY, note: Optional[str] = None,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """
    Commit a result set and its findings as ONE durable act.

    The identities are DERIVED. The caller supplies findings - source, evidence reference, optional
    observation reference from the 4.2 ledger, and a summary - and never an id. Ordinals are assigned in
    the order given and persisted, so "the seventh" means the seventh forever.
    """
    if not findings:
        raise CrucibleError("RESULT_SET_REQUIRES_FINDINGS", str(investigation_ref))
    moment = time.time() if now is None else float(now)
    prepared: List[Tuple[int, Dict[str, Any]]] = []
    for ordinal, finding in enumerate(findings, start=1):
        required = ("source_ref", "evidence_ref")
        for field in required:
            if not str(finding.get(field) or "").strip():
                # A finding with no source or no evidence is not a finding; it is an assertion, and the
                # whole point of this module is that assertions do not acquire identity by being listed.
                raise CrucibleError("FINDING_REQUIRES_SOURCE_AND_EVIDENCE", f"{ordinal}:{field}")
        prepared.append((ordinal, dict(finding)))
    identity_source = [{key: str(finding.get(key) or "") for key in
                        ("source_ref", "evidence_ref", "observation_ref")}
                       for _, finding in prepared]
    result_set_id = "RS-" + digest({"investigation": str(investigation_ref),
                                    "findings": identity_source})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        existing = connection.execute("SELECT * FROM ciph_result_sets WHERE result_set_id = ?;",
                                      (result_set_id,)).fetchone()
        # IDEMPOTENT FOR IDENTICAL CONTENT. A crash after the commit but before the notification means the
        # caller retries; a retry of the SAME findings must not manufacture a new revision out of nothing.
        if existing is not None:
            current = int(existing["current_revision"])
            previous_ids = [str(item) for item in json.loads(connection.execute(
                "SELECT finding_ids_json FROM ciph_result_set_revisions WHERE result_set_id = ? "
                "AND revision = ?;", (result_set_id, current)).fetchone()["finding_ids_json"] or "[]")]
            would_be = [_finding_identity(result_set_id, ordinal, finding.get("source_ref"),
                                          finding.get("evidence_ref"), finding.get("observation_ref"))
                        for ordinal, finding in prepared]
            if previous_ids == would_be:
                return {"result_set_id": result_set_id, "revision": current, "finding_ids": previous_ids,
                        "count": len(previous_ids), "investigation_ref": str(investigation_ref),
                        "snapshot_digest": _revision_digest(result_set_id, current, previous_ids),
                        "idempotent": True, "policy_version": RESULT_SET_V1,
                        "committed_at": moment}
        if existing is None:
            connection.execute(
                "INSERT INTO ciph_result_sets (result_set_id, investigation_ref, execution_ref, "
                "session_ref, classification, current_revision, first_committed_at) "
                "VALUES (?,?,?,?,?,?,?);",
                (result_set_id, str(investigation_ref), execution_ref, session_ref,
                 str(classification), 1, moment))
            revision = 1
        else:
            revision = int(existing["current_revision"]) + 1
            connection.execute("UPDATE ciph_result_sets SET current_revision = ? WHERE "
                               "result_set_id = ?;", (revision, result_set_id))
        ids: List[str] = []
        for ordinal, finding in prepared:
            finding_id = _finding_identity(result_set_id, ordinal, finding.get("source_ref"),
                                           finding.get("evidence_ref"),
                                           finding.get("observation_ref"))
            ids.append(finding_id)
            connection.execute(
                "INSERT OR REPLACE INTO ciph_findings (finding_id, result_set_id, revision, ordinal, "
                "source_ref, evidence_ref, observation_ref, summary, availability, "
                "availability_reason, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
                (finding_id, result_set_id, revision, ordinal, finding.get("source_ref"),
                 finding.get("evidence_ref"), finding.get("observation_ref"),
                 finding.get("summary"), AVAILABLE, None, moment))
        revision_digest = _revision_digest(result_set_id, revision, ids)
        connection.execute(
            "INSERT OR REPLACE INTO ciph_result_set_revisions (revision_id, result_set_id, revision, "
            "finding_ids_json, snapshot_digest, note, recorded_at) VALUES (?,?,?,?,?,?,?);",
            (f"RSR-{result_set_id}-{revision}", result_set_id, revision, json.dumps(ids),
             revision_digest, note, moment))
        connection.commit()
    finally:
        connection.close()
    return {"result_set_id": result_set_id, "revision": revision, "finding_ids": ids,
            "count": len(ids), "investigation_ref": str(investigation_ref),
            "snapshot_digest": revision_digest, "policy_version": RESULT_SET_V1,
            "committed_at": moment}


def _revision_finding_ids(db_path: str, result_set_id: str, revision: Optional[int]) -> List[str]:
    connection = _connect(db_path, read_only=True)
    try:
        if revision is None:
            row = connection.execute("SELECT finding_ids_json FROM ciph_result_set_revisions WHERE "
                                     "result_set_id = ? ORDER BY revision DESC LIMIT 1;",
                                     (str(result_set_id),)).fetchone()
        else:
            row = connection.execute("SELECT finding_ids_json FROM ciph_result_set_revisions WHERE "
                                     "result_set_id = ? AND revision = ?;",
                                     (str(result_set_id), int(revision))).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_NO_REVISION, f"{result_set_id}:{revision}")
    return list(json.loads(row["finding_ids_json"] or "[]"))


def get_finding(db_path: str, finding_id: str) -> Finding:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_findings WHERE finding_id = ?;",
                                 (str(finding_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_FINDING, str(finding_id))
    row = dict(row)
    return Finding(finding_id=str(row["finding_id"]), result_set_id=str(row["result_set_id"]),
                   revision=int(row["revision"]), ordinal=int(row["ordinal"]),
                   source_ref=row["source_ref"], evidence_ref=row["evidence_ref"],
                   observation_ref=row["observation_ref"], summary=row["summary"],
                   availability=str(row["availability"]))


def _require_access(db_path: str, result_set_id: str, actor: Optional[str]) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_result_sets WHERE result_set_id = ?;",
                                 (str(result_set_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_SET, str(result_set_id))
    record = dict(row)
    if record["classification"] == OPERATOR_ONLY and not str(actor or "").startswith("operator:"):
        raise CrucibleError(REASON_NOT_OPERATOR, f"{result_set_id}:{record['classification']}")
    return record


def retrieve_result_set(db_path: str, result_set_id: str, *, actor: Optional[str] = None,
                        revision: Optional[int] = None) -> Dict[str, Any]:
    """
    Retrieve a result set in its ORIGINAL order, reporting availability honestly.

    Nothing here re-runs anything: a finding whose availability is not AVAILABLE is still listed, with the
    reason. A caller that wants a fresh scan must ask for a fresh scan and receive a NEW result set id.
    """
    record = _require_access(db_path, result_set_id, actor)
    ids = _revision_finding_ids(db_path, result_set_id, revision)
    findings = [get_finding(db_path, finding_id).as_dict() for finding_id in ids]
    unavailable = [item for item in findings if item["availability"] != AVAILABLE]
    return {"result_set_id": str(result_set_id), "revision": int(record["current_revision"])
            if revision is None else int(revision),
            "investigation_ref": str(record["investigation_ref"]), "count": len(findings),
            "findings": findings, "ordered_by": "ordinal",
            "available_count": len(findings) - len(unavailable),
            "unavailable": [{"finding_id": item["finding_id"], "availability": item["availability"]}
                            for item in unavailable],
            "substituted_by_a_new_scan": False, "policy_version": REFERENTIAL_CONTINUITY_V1}


def retrieve_nth(db_path: str, result_set_id: str, ordinal: int, *, actor: Optional[str] = None,
                 revision: Optional[int] = None) -> Dict[str, Any]:
    """Resolve one ordinal to the SAME finding every time - the cross-restart guarantee."""
    if int(ordinal) < 1:
        raise CrucibleError(REASON_OUT_OF_RANGE, str(ordinal))
    result = retrieve_result_set(db_path, result_set_id, actor=actor, revision=revision)
    for finding in result["findings"]:
        if int(finding["ordinal"]) == int(ordinal):
            return {"result_set_id": str(result_set_id), "ordinal": int(ordinal),
                    "finding": finding, "count": result["count"],
                    "policy_version": REFERENTIAL_CONTINUITY_V1}
    raise CrucibleError(REASON_OUT_OF_RANGE, f"{result_set_id}:{ordinal} of {result['count']}")


def announce(db_path: str, *, result_set_id: str, statement: str,
             claimed_count: Optional[int] = None, actor: Optional[str] = None,
             now: Optional[float] = None) -> Dict[str, Any]:
    """
    Announce a result set - and REFUSE if the claim outruns what was committed.

    The check is arithmetic, not interpretive: the committed finding count at the referenced revision is
    recomputed from the revision snapshot and the findings themselves, so "twenty findings" backed by
    seventeen bytes is refused and the refusal is recorded. A refused announcement is not a valid
    announcement and cannot be retrieved as one.
    """
    moment = time.time() if now is None else float(now)
    record = _require_access(db_path, result_set_id, actor)
    revision = int(record["current_revision"])
    ids = _revision_finding_ids(db_path, result_set_id, revision)
    committed = len(ids)
    claimed = int(claimed_count) if claimed_count is not None else _count_from_statement(statement)
    recomputed = _revision_digest(result_set_id, revision, ids)
    connection = _connect(db_path, read_only=True)
    try:
        revision_row = connection.execute(
            "SELECT snapshot_digest FROM ciph_result_set_revisions WHERE result_set_id = ? "
            "AND revision = ?;", (str(result_set_id), revision)).fetchone()
    except sqlite3.Error:
        revision_row = None
    finally:
        connection.close()
    if revision_row is None or str(revision_row["snapshot_digest"]) != recomputed:
        return _record_announcement(db_path, result_set_id=result_set_id, revision=revision,
                                    claimed=claimed or 0, verified=None, statement=statement,
                                    status=REFUSED, detail=REASON_SNAPSHOT_MOVED, moment=moment)
    if claimed is None or claimed != committed:
        return _record_announcement(db_path, result_set_id=result_set_id, revision=revision,
                                    claimed=claimed or 0, verified=committed, statement=statement,
                                    status=REFUSED, detail=REASON_COUNT_MISMATCH, moment=moment)
    return _record_announcement(db_path, result_set_id=result_set_id, revision=revision, claimed=claimed,
                                verified=committed, statement=statement, status=ANNOUNCED,
                                detail=None, moment=moment)


def _count_from_statement(statement: str) -> Optional[int]:
    """The count the sentence actually claims, so an unstated count cannot hide behind a number in prose."""
    import re
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
             "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
             "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
             "twenty": 20}
    match = re.search(r"\b(\d+)\b", str(statement))
    if match:
        return int(match.group(1))
    for word, value in words.items():
        if re.search(rf"\b{word}\b", str(statement), re.IGNORECASE):
            return value
    return None


def _record_announcement(db_path: str, *, result_set_id: str, revision: int, claimed: int,
                         verified: Optional[int], statement: str, status: str,
                         detail: Optional[str], moment: float) -> Dict[str, Any]:
    # Identity is CONTENT-derived, not time-derived: a notification retried after a delivery failure is
    # the SAME announcement, not a second one. (The first draft included the moment and so produced two
    # rows for one claim, which the duplicate-delivery specimen caught.)
    announcement_id = "ANN-" + digest({"set": result_set_id, "revision": revision,
                                       "claimed": claimed, "statement": str(statement),
                                       "status": str(status)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_announcements (announcement_id, result_set_id, revision, "
            "claimed_count, verified_count, statement, snapshot_digest, status, detail, announced_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?);",
            (announcement_id, str(result_set_id), int(revision), int(claimed), verified,
             str(statement), _revision_fingerprint(db_path, result_set_id, revision), str(status),
             detail, moment))
        connection.commit()
    finally:
        connection.close()
    return {"announcement_id": announcement_id, "result_set_id": str(result_set_id),
            "revision": int(revision), "claimed_count": int(claimed), "verified_count": verified,
            "status": str(status), "detail": detail, "retrievable_as_announced": status == ANNOUNCED,
            "policy_version": ANNOUNCEMENT_V1, "announced_at": moment}


def _revision_fingerprint(db_path: str, result_set_id: str, revision: int) -> str:
    try:
        return _revision_digest(result_set_id, revision,
                                _revision_finding_ids(db_path, result_set_id, revision))
    except CrucibleError:
        return digest({"set": result_set_id, "revision": revision, "uncommitted": True})


def get_announcement(db_path: str, announcement_id: str) -> Dict[str, Any]:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_announcements WHERE announcement_id = ?;",
                                 (str(announcement_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_ANNOUNCEMENT", str(announcement_id))
    return dict(row)


def announcement_snapshot(db_path: str, announcement_id: str, *, actor: Optional[str] = None
                          ) -> Dict[str, Any]:
    """
    What the announcement POINTED AT, even after the result set moved on.

    The snapshot is resolved at the announcement's own revision, so later evidence cannot rewrite what was
    said. If that revision's findings have since become unavailable, that is reported - not back-filled.
    """
    announcement = get_announcement(db_path, announcement_id)
    if announcement["status"] != ANNOUNCED:
        return {"announcement_id": str(announcement_id), "status": announcement["status"],
                "detail": announcement["detail"], "retrievable": False,
                "note": "a refused announcement is not a record of findings"}
    result = retrieve_result_set(db_path, announcement["result_set_id"], actor=actor,
                                 revision=int(announcement["revision"]))
    return {"announcement_id": str(announcement_id), "status": ANNOUNCED,
            "result_set_id": result["result_set_id"], "revision": result["revision"],
            "count": result["count"], "findings": result["findings"],
            "unavailable": result["unavailable"], "retrievable": True,
            "policy_version": ANNOUNCEMENT_V1}


def revise_result_set(db_path: str, result_set_id: str, *, findings: Sequence[Dict[str, Any]],
                      note: str, actor: Optional[str] = None,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """
    APPEND findings to an existing set as a new revision.

    This is deliberately not a re-commit. Set identity is CONTENT-derived, so committing different content
    produces a different SET - which is right for a new scan and wrong for a revision. A revision therefore
    appends to a set that already exists (naming it is only possible because it exists), continues the
    ordinals, keeps every earlier finding exactly where it was, and leaves prior revisions untouched so an
    announcement made against revision 1 still resolves to revision 1.

    A revision is a WRITE, so it passes the same access check as reading and announcing.
    """
    _require_access(db_path, result_set_id, actor)
    moment = time.time() if now is None else float(now)
    prepared: List[Tuple[int, Dict[str, Any]]] = []
    for finding in findings:
        for field in ("source_ref", "evidence_ref"):
            if not str(finding.get(field) or "").strip():
                raise CrucibleError("FINDING_REQUIRES_SOURCE_AND_EVIDENCE", str(field))
        prepared.append((0, dict(finding)))
    connection = _connect(db_path)
    try:
        init_schema(connection)
        current = connection.execute("SELECT current_revision FROM ciph_result_sets WHERE "
                                     "result_set_id = ?;", (str(result_set_id),)).fetchone()
        if current is None:
            raise CrucibleError(REASON_UNKNOWN_SET, str(result_set_id))
        revision = int(current["current_revision"]) + 1
        highest = connection.execute("SELECT COALESCE(MAX(ordinal), 0) AS top FROM ciph_findings "
                                     "WHERE result_set_id = ?;", (str(result_set_id),)).fetchone()["top"]
        ordinal = int(highest)
        for _, finding in prepared:
            ordinal += 1
            finding_id = _finding_identity(result_set_id, ordinal, finding.get("source_ref"),
                                           finding.get("evidence_ref"), finding.get("observation_ref"))
            connection.execute(
                "INSERT OR REPLACE INTO ciph_findings (finding_id, result_set_id, revision, ordinal, "
                "source_ref, evidence_ref, observation_ref, summary, availability, "
                "availability_reason, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
                (finding_id, str(result_set_id), revision, ordinal, finding.get("source_ref"),
                 finding.get("evidence_ref"), finding.get("observation_ref"),
                 finding.get("summary"), AVAILABLE, None, moment))
        ids = [str(row["finding_id"]) for row in connection.execute(
            "SELECT finding_id FROM ciph_findings WHERE result_set_id = ? ORDER BY ordinal;",
            (str(result_set_id),))]
        revision_digest = _revision_digest(result_set_id, revision, ids)
        connection.execute("UPDATE ciph_result_sets SET current_revision = ? WHERE result_set_id = ?;",
                           (revision, str(result_set_id)))
        connection.execute(
            "INSERT OR REPLACE INTO ciph_result_set_revisions (revision_id, result_set_id, revision, "
            "finding_ids_json, snapshot_digest, note, recorded_at) VALUES (?,?,?,?,?,?,?);",
            (f"RSR-{result_set_id}-{revision}", str(result_set_id), revision, json.dumps(ids),
             revision_digest, note, moment))
        connection.commit()
    finally:
        connection.close()
    return {"result_set_id": str(result_set_id), "revision": revision, "finding_ids": ids,
            "count": len(ids), "added": len(prepared), "snapshot_digest": revision_digest,
            "policy_version": RESULT_SET_V1, "revised_at": moment}


def _investigation_of(db_path: str, result_set_id: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT investigation_ref FROM ciph_result_sets WHERE "
                                 "result_set_id = ?;", (str(result_set_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError(REASON_UNKNOWN_SET, str(result_set_id))
    return str(row["investigation_ref"])


def _classification_of(db_path: str, result_set_id: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT classification FROM ciph_result_sets WHERE result_set_id = ?;",
                                 (str(result_set_id),)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    return str(row["classification"]) if row is not None else OPERATOR_ONLY


def mark_finding_unavailable(db_path: str, finding_id: str, *, availability: str, reason: str,
                             now: Optional[float] = None) -> Finding:
    """Record that a finding can no longer be presented - reported, never silently dropped."""
    if str(availability) not in VALID_AVAILABILITY or str(availability) == AVAILABLE:
        raise CrucibleError("INVALID_AVAILABILITY", str(availability))
    moment = time.time() if now is None else float(now)
    get_finding(db_path, finding_id)
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("UPDATE ciph_findings SET availability = ?, availability_reason = ? "
                           "WHERE finding_id = ?;", (str(availability), str(reason),
                                                     str(finding_id)))
        connection.commit()
    finally:
        connection.close()
    return get_finding(db_path, finding_id)


def resolve_reference(db_path: str, *, candidates: Sequence[str], phrase: str,
                      actor: Optional[str] = None) -> Dict[str, Any]:
    """
    Resolve a natural reference against candidate result sets.

    One match resolves. Several matches are AMBIGUOUS and stay ambiguous: picking the newest would be the
    same class of error as re-running a scan - a silent substitution of one thing for another.
    """
    existing = []
    for candidate in candidates:
        try:
            record = _require_access(db_path, candidate, actor)
        except CrucibleError:
            continue
        existing.append({"result_set_id": str(candidate),
                         "investigation_ref": str(record["investigation_ref"]),
                         "revision": int(record["current_revision"])})
    existing.sort(key=lambda item: item["result_set_id"])
    if not existing:
        return {"phrase": str(phrase), "status": NOT_FOUND, "candidates": []}
    if len(existing) > 1:
        return {"phrase": str(phrase), "status": AMBIGUOUS, "candidates": existing,
                "note": "several result sets match; the ambiguity is reported rather than resolved by "
                        "recency"}
    return {"phrase": str(phrase), "status": RESOLVED, "result_set_id": existing[0]["result_set_id"],
            "candidates": existing}


def record_new_scan(db_path: str, *, investigation_ref: str, findings: Sequence[Dict[str, Any]],
                    previous_result_set: Optional[str] = None, now: Optional[float] = None
                    ) -> Dict[str, Any]:
    """
    Commit a NEW scan, explicitly distinguished from retrieving an old one.

    The new set gets its own identity, and the previous set is untouched - so a caller can never mistake
    "I looked again" for "here is what I found before".
    """
    committed = commit_result_set(db_path, investigation_ref=str(investigation_ref), findings=findings,
                                  now=now)
    return {**committed, "is_a_new_scan": True, "previous_result_set": previous_result_set,
            "retrieval_not_substituted": True,
            "note": "a new scan is a new result set; the previous one remains retrievable as itself"}


RETRIEVAL_RESULT_SET = "RETRIEVAL_RESULT_SET"
RETRIEVAL_ORDINAL = "RETRIEVAL_ORDINAL"
RETRIEVAL_FOLLOWUP = "RETRIEVAL_FOLLOWUP"
RETRIEVAL_NONE = "NO_RETRIEVAL_INTENT"

_ORDINAL_WORDS = {"first": 1, "second": 2, "third": 3, "fourth": 4, "fifth": 5, "sixth": 6,
                  "seventh": 7, "eighth": 8, "ninth": 9, "tenth": 10, "eleventh": 11, "twelfth": 12,
                  "thirteenth": 13, "fourteenth": 14, "fifteenth": 15, "sixteenth": 16,
                  "seventeenth": 17, "eighteenth": 18, "nineteenth": 19, "twentieth": 20}
# A NUMBER WORD only counts after an explicit ordinal cue ("number seven", "item three"), so "one of them"
# is not read as "the first one"; an ORDINAL WORD may stand alone ("the seventh alert").
_NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
                 "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
                 "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
                 "nineteen": 19, "twenty": 20}


def resolve_conversational_reference(db_path: str, text: str, *, actor: Optional[str] = None,
                                     candidates: Sequence[str] = (), now: Optional[float] = None
                                     ) -> Dict[str, Any]:
    """
    Turn a natural retrieval request into an ANSWER FROM DURABLE EVIDENCE - or into an honest nothing.

    What this function never does: run a scan. The old behaviour routed "show me the alerts" to a command
    that RE-RAN the tool, which is why a follow-up question could return a different twenty than the twenty
    that were announced. Here, retrieval is retrieval: the durable set is resolved, the ordinal is resolved
    against it, and if nothing is stored the answer says so instead of producing fresh findings and calling
    them the old ones.

    Ambiguity is returned as ambiguity. Picking the newest set would be the same class of error as
    re-running the scan - a silent substitution.
    """
    import re
    moment = time.time() if now is None else float(now)
    phrase = str(text or "")
    lowered = phrase.lower()
    retrieval_words = ("alert", "alerts", "finding", "findings", "result", "results", "idea", "ideas")

    # ORDINAL PARSING COMES FIRST. A reference like "explain number seven" or "the seventh alert" carries
    # no result noun at all, yet it is unambiguously a retrieval request; anchoring intent on the noun list
    # first is exactly what let "explain number seven" fall through to CONSULT.
    ordinals: List[int] = []
    for match in re.finditer(r"\b(?:number|item|num)\s*(\d+|[a-z]+)\b", lowered):
        token = match.group(1)
        if token.isdigit():
            ordinals.append(int(token))
        elif token in _NUMBER_WORDS:
            ordinals.append(_NUMBER_WORDS[token])
    for match in re.finditer(r"#\s*(\d+)\b", lowered):
        ordinals.append(int(match.group(1)))
    for word, value in _ORDINAL_WORDS.items():
        if re.search(rf"\b{word}\b", lowered):
            ordinals.append(value)

    wants_retrieval = any(word in lowered for word in retrieval_words) or bool(ordinals)
    if not wants_retrieval:
        return {"kind": RETRIEVAL_NONE, "text": phrase, "answered_from_evidence": False}

    available = [str(item) for item in candidates] if candidates else [
        str(record["result_set_id"]) for record in result_sets(db_path)]
    if not available:
        # Honest nothing: there is no stored set to retrieve, and this function will not manufacture one
        # by scanning. The caller may offer a NEW scan, but it must be a new scan, not a retrieval.
        return {"kind": RETRIEVAL_NONE, "text": phrase, "answered_from_evidence": False,
                "no_stored_result_set": True,
                "note": "no durable result set exists for this reference; a new scan would be a NEW "
                        "result set, not a retrieval of an old one"}

    # Several stored sets are ALWAYS ambiguous, ordinal or not. Picking one by recency - or by sort order,
    # which is the same sin wearing a different hat - would silently substitute one set for another.
    if len(available) > 1:
        resolution = resolve_reference(db_path, candidates=available, phrase=phrase, actor=actor)
        if resolution["status"] != RESOLVED:
            return {"kind": RETRIEVAL_NONE, "text": phrase, "answered_from_evidence": False,
                    "ambiguous": True, "candidates": resolution["candidates"],
                    "note": "several stored result sets match; name one rather than let recency decide"}
        available = [resolution["result_set_id"]]

    result_set_id = available[0]
    if ordinals:
        ordinal = ordinals[0]
        try:
            found = retrieve_nth(db_path, result_set_id, ordinal, actor=actor)
        except CrucibleError as refused:
            return {"kind": RETRIEVAL_NONE, "text": phrase, "answered_from_evidence": False,
                    "reason": refused.reason, "result_set_id": result_set_id}
        return {"kind": RETRIEVAL_ORDINAL, "text": phrase, "answered_from_evidence": True,
                "result_set_id": result_set_id, "ordinal": ordinal, "finding": found["finding"],
                "count": found["count"], "scanned_again": False,
                "policy_version": REFERENTIAL_CONTINUITY_V1, "resolved_at": moment}
    retrieved = retrieve_result_set(db_path, result_set_id, actor=actor)
    return {"kind": RETRIEVAL_RESULT_SET, "text": phrase, "answered_from_evidence": True,
            "result_set_id": retrieved["result_set_id"], "revision": retrieved["revision"],
            "count": retrieved["count"], "findings": retrieved["findings"],
            "unavailable": retrieved["unavailable"], "scanned_again": False,
            "policy_version": REFERENTIAL_CONTINUITY_V1, "resolved_at": moment}


def record_followup(db_path: str, *, text: str, announcement_ref: Optional[str] = None,
                    finding_ref: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """A commitment or follow-up that points at durable refs rather than at a remembered sentence."""
    if announcement_ref is None and finding_ref is None:
        raise CrucibleError("FOLLOWUP_REQUIRES_A_DURABLE_REFERENCE", str(text))
    moment = time.time() if now is None else float(now)
    followup_id = "FU-" + digest({"announcement": announcement_ref, "finding": finding_ref,
                                  "text": str(text)})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute("INSERT OR IGNORE INTO ciph_followups (followup_id, announcement_ref, "
                           "finding_ref, text, status, created_at) VALUES (?,?,?,?,?,?);",
                           (followup_id, announcement_ref, finding_ref, str(text), "OPEN", moment))
        connection.commit()
    finally:
        connection.close()
    return {"followup_id": followup_id, "announcement_ref": announcement_ref,
            "finding_ref": finding_ref, "status": "OPEN", "policy_version": FOLLOWUP_V1,
            "created_at": moment}


def result_sets(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_result_sets ORDER BY first_committed_at, result_set_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def announcements(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_announcements ORDER BY announced_at, announcement_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def followups(db_path: str) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_followups ORDER BY created_at, followup_id;")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def referential_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        table = lambda name: [dict(row) for row in connection.execute(  # noqa: E731
            f"SELECT * FROM {name} ORDER BY rowid;")]
        payload = {"result_sets": table("ciph_result_sets"),
                   "revisions": table("ciph_result_set_revisions"),
                   "findings": table("ciph_findings"),
                   "announcements": table("ciph_announcements"),
                   "followups": table("ciph_followups")}
    except sqlite3.Error:
        payload = {"result_sets": [], "revisions": [], "findings": [], "announcements": [],
                   "followups": []}
    finally:
        connection.close()
    return digest({"version": REFERENTIAL_CONTINUITY_V1, **payload})
