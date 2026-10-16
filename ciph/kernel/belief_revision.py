"""
ciph.kernel.belief_revision - how the epistemic position changed, and what reasoning produced it.

4.2 Gate Two. Two things are recorded here, and the first law is the reason they are separate:

    INFERENCE IS NOT EVIDENCE.

A model may reason from evidence. Its reasoning never becomes another observation, so an inference can
introduce a conclusion into the REASONING graph and can never raise Gate Zero's support counts.

    InferenceRecord    a conclusion, the EXACT premise belief versions/digests it was drawn from, the
                       rule, and the model (if any)
    BeliefRevision     append-only bookkeeping of how a proposition's epistemic basis changed

An inference is only as current as the premises it pinned: when a premise's belief materially changes,
the inference goes STALE and is NOT silently recomputed in place (laws 3, 4, 9).

LAWS (each has a specimen in `test_gate_4_2_belief_revision.py`)

 1. BELIEF REVISION IS APPEND-ONLY. New epistemic state never rewrites the old one.
 2. "THE MODEL CHANGED ITS MIND" is not a revision cause by itself.
 3. An inference must pin the exact premise projection versions/digests it reasoned from.
 4. If a premise changes materially the old inference becomes STALE - never silently recomputed.
 5. INFERENCE != EVIDENCE. An inference cannot move Gate Zero support/contradiction counts.
 6. Repeating the same inference adds zero evidence.
 7. Two contradictory inferences may coexist; one does not delete the other.
 8. A conclusion may enter the reasoning graph without becoming SUPPORTED in Gate Zero.
 9. A stale inference cannot be used as if it rested on the current epistemic state.
10. Revision requires an actual canonical basis change; identical re-evaluation adds no version.
11. Historical revisions remain reconstructible.
12. Same evidence + provenance + inference history -> same assessment and digest after restart.

REVISION CAUSES are DERIVED from what actually changed, never supplied by a caller. The precedence is
frozen below; a caller cannot say "I changed my mind" and produce a revision (law 2).
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.epistemic_ledger import Proposition, reconstruct as reconstruct_beliefs
from ciph.kernel.source_dependence import project_source_dependence

# Inference statuses.
INFERENCE_CURRENT = "CURRENT"
INFERENCE_STALE = "STALE"
INFERENCE_CONTESTED = "CONTESTED"
INFERENCE_INVALID = "INVALID"

# Belief-revision causes. Frozen; derived, never caller-supplied.
CAUSE_NEW_SUPPORT = "NEW_SUPPORT"
CAUSE_NEW_CONTRADICTION = "NEW_CONTRADICTION"
CAUSE_PROVENANCE_CHANGED = "PROVENANCE_CHANGED"
CAUSE_EVIDENCE_STALE = "EVIDENCE_STALE"
CAUSE_EVIDENCE_REFRESHED = "EVIDENCE_REFRESHED"
CAUSE_INFERENCE_ADDED = "INFERENCE_ADDED"
CAUSE_INFERENCE_INVALIDATED = "INFERENCE_INVALIDATED"
VALID_CAUSES = (CAUSE_NEW_SUPPORT, CAUSE_NEW_CONTRADICTION, CAUSE_PROVENANCE_CHANGED,
                CAUSE_EVIDENCE_STALE, CAUSE_EVIDENCE_REFRESHED, CAUSE_INFERENCE_ADDED,
                CAUSE_INFERENCE_INVALIDATED)

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_inferences (
        inference_id TEXT PRIMARY KEY,
        conclusion_proposition_id TEXT NOT NULL,
        conclusion_canonical_form TEXT,
        inference_rule_id TEXT NOT NULL,
        model_id TEXT,
        model_version TEXT,
        premises_json TEXT NOT NULL,
        premise_digests_json TEXT NOT NULL,
        basis_digest TEXT NOT NULL,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_inference_invalidations (
        invalidation_id TEXT PRIMARY KEY,
        inference_id TEXT NOT NULL,
        reason TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_belief_revisions (
        revision_id TEXT PRIMARY KEY,
        proposition_id TEXT NOT NULL,
        previous_projection_version INTEGER,
        new_projection_version INTEGER,
        previous_source_dependence_digest TEXT,
        new_source_dependence_digest TEXT,
        cause_refs_json TEXT,
        basis_digest TEXT NOT NULL,
        revision_reason TEXT NOT NULL,
        created_at REAL
    );
    """,
)


class BeliefRevisionError(Exception):
    """A revision or inference operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class PremiseRef:
    """The EXACT premise belief state an inference reasoned from (law 3)."""

    proposition_id: str
    belief_projection_version: int
    belief_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"proposition_id": self.proposition_id,
                "belief_projection_version": self.belief_projection_version,
                "belief_digest": self.belief_digest}


@dataclass(frozen=True)
class InferenceRecord:
    inference_id: str
    premise_refs: Tuple[PremiseRef, ...]
    conclusion_proposition_id: str
    inference_rule_id: str
    model_id: Optional[str]
    model_version: Optional[str]
    basis_digest: str
    status: str
    created_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"inference_id": self.inference_id,
                "premise_refs": [p.as_dict() for p in self.premise_refs],
                "conclusion_proposition_id": self.conclusion_proposition_id,
                "inference_rule_id": self.inference_rule_id,
                "model_id": self.model_id, "model_version": self.model_version,
                "basis_digest": self.basis_digest, "status": self.status,
                "created_at": self.created_at}


@dataclass(frozen=True)
class BeliefRevision:
    revision_id: str
    proposition_id: str
    previous_projection_version: Optional[int]
    new_projection_version: Optional[int]
    previous_source_dependence_digest: Optional[str]
    new_source_dependence_digest: Optional[str]
    cause_refs: Tuple[str, ...]
    basis_digest: str
    revision_reason: str
    created_at: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {"revision_id": self.revision_id, "proposition_id": self.proposition_id,
                "previous_projection_version": self.previous_projection_version,
                "new_projection_version": self.new_projection_version,
                "previous_source_dependence_digest": self.previous_source_dependence_digest,
                "new_source_dependence_digest": self.new_source_dependence_digest,
                "cause_refs": list(self.cause_refs), "basis_digest": self.basis_digest,
                "revision_reason": self.revision_reason, "created_at": self.created_at}


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            pass
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _latest_projection_version(conn: sqlite3.Connection, proposition_id: str) -> int:
    try:
        row = conn.execute(
            "SELECT COALESCE(MAX(projection_version), 0) AS v FROM ciph_belief_projections "
            "WHERE proposition_id = ?;", (proposition_id,)).fetchone()
    except sqlite3.Error:
        return 0
    return int(row["v"]) if row else 0


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _premise_ref(db_path: str, proposition_id: str, *, now: Optional[float],
                 conn: sqlite3.Connection) -> PremiseRef:
    state = reconstruct_beliefs(db_path, now=now)
    belief = state.belief_for(proposition_id)
    if belief is None:
        raise BeliefRevisionError("PREMISE_NOT_IN_THE_LEDGER", proposition_id)
    return PremiseRef(proposition_id=proposition_id,
                      belief_projection_version=_latest_projection_version(conn, proposition_id),
                      belief_digest=belief.derivation_digest)


# ---------------------------------------------------------------------------- inferences
def record_inference(db_path: str, *, premise_proposition_ids: Sequence[str],
                     conclusion: Proposition, inference_rule_id: str,
                     model_id: Optional[str] = None, model_version: Optional[str] = None,
                     now: Optional[float] = None) -> InferenceRecord:
    """
    Record ONE inference, pinning the exact premise belief digests it reasoned from.

    The conclusion enters the REASONING graph here. It does not enter the evidence ledger, it is not
    SUPPORTED, and nothing about Gate Zero changes: an inference is not evidence (laws 5 and 8).
    """
    if not premise_proposition_ids:
        raise BeliefRevisionError("INFERENCE_REQUIRES_PREMISES", str(conclusion.proposition_id))
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        refs = [_premise_ref(db_path, str(pid), now=moment, conn=conn)
                for pid in premise_proposition_ids]
        digest = _digest({
            "premises": [r.as_dict() for r in refs],
            "rule": inference_rule_id,
            "conclusion": conclusion.proposition_id,
            "model": model_id,
            "model_version": model_version,
        })
        inference_id = f"INF-{uuid.uuid4().hex[:12].upper()}"
        conn.execute(
            "INSERT INTO ciph_inferences (inference_id, conclusion_proposition_id, "
            "conclusion_canonical_form, inference_rule_id, model_id, model_version, premises_json, "
            "premise_digests_json, basis_digest, created_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
            (inference_id, conclusion.proposition_id, conclusion.canonical_form, inference_rule_id,
             model_id, model_version,
             json.dumps([p.proposition_id for p in refs]),
             json.dumps([p.as_dict() for p in refs]),
             digest, moment),
        )
        conn.commit()
        return InferenceRecord(inference_id=inference_id, premise_refs=tuple(refs),
                               conclusion_proposition_id=conclusion.proposition_id,
                               inference_rule_id=inference_rule_id, model_id=model_id,
                               model_version=model_version, basis_digest=digest,
                               status=INFERENCE_CURRENT, created_at=moment)
    finally:
        conn.close()


def _invalidated(conn: sqlite3.Connection, inference_id: str) -> bool:
    try:
        return conn.execute("SELECT 1 FROM ciph_inference_invalidations WHERE inference_id = ? LIMIT 1;",
                            (inference_id,)).fetchone() is not None
    except sqlite3.Error:
        return False


def inference_status(db_path: str, inference_id: str, *, now: Optional[float] = None) -> str:
    """
    Derive an inference's status from the CURRENT premise beliefs.

    STALE means a premise moved (laws 4 and 9). Nothing here rewrites the inference: the record keeps
    the versions it pinned, and the status is recomputed from canonical state.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute("SELECT * FROM ciph_inferences WHERE inference_id = ?;",
                           (inference_id,)).fetchone()
        if row is None:
            raise BeliefRevisionError("UNKNOWN_INFERENCE", inference_id)
        if _invalidated(conn, inference_id):
            return INFERENCE_INVALID
        pinned = json.loads(row["premise_digests_json"])
        state = reconstruct_beliefs(db_path, now=moment)
        contested = False
        for pinned_ref in pinned:
            belief = state.belief_for(str(pinned_ref["proposition_id"]))
            if belief is None or belief.derivation_digest != pinned_ref["belief_digest"]:
                return INFERENCE_STALE
            if belief.status == "CONTESTED":
                contested = True
        return INFERENCE_CONTESTED if contested else INFERENCE_CURRENT
    finally:
        conn.close()


def assert_usable(db_path: str, inference_id: str, *, now: Optional[float] = None) -> str:
    """
    Refuse to use an inference that no longer rests on the current epistemic state (law 9).

    This is the guard that prevents a silent premise upgrade: nothing here re-pins the premises, so a
    caller cannot quietly reason from newer beliefs while claiming the old reasoning.
    """
    status = inference_status(db_path, inference_id, now=now)
    if status != INFERENCE_CURRENT:
        raise BeliefRevisionError("STALE_INFERENCE_BASIS", f"{inference_id}:{status}")
    return status


def invalidate_inference(db_path: str, inference_id: str, *, reason: str = "",
                         now: Optional[float] = None) -> str:
    """Append an invalidation. The inference record itself is never edited (law 1)."""
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        if conn.execute("SELECT 1 FROM ciph_inferences WHERE inference_id = ?;",
                        (inference_id,)).fetchone() is None:
            raise BeliefRevisionError("UNKNOWN_INFERENCE", inference_id)
        invalidation_id = f"INV-{uuid.uuid4().hex[:12].upper()}"
        conn.execute(
            "INSERT INTO ciph_inference_invalidations (invalidation_id, inference_id, reason, "
            "recorded_at) VALUES (?,?,?,?);", (invalidation_id, inference_id, reason, moment))
        conn.commit()
        return invalidation_id
    finally:
        conn.close()


def inferences_for(db_path: str, conclusion_proposition_id: str, *,
                   now: Optional[float] = None) -> Tuple[InferenceRecord, ...]:
    conn = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_inferences WHERE conclusion_proposition_id = ? ORDER BY inference_id;",
            (conclusion_proposition_id,))]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return tuple(_inference_from_row(db_path, row, now) for row in rows)


def _inference_from_row(db_path: str, row: Mapping[str, Any],
                        now: Optional[float]) -> InferenceRecord:
    return InferenceRecord(
        inference_id=str(row["inference_id"]),
        premise_refs=tuple(PremiseRef(**ref) for ref in json.loads(row["premise_digests_json"])),
        conclusion_proposition_id=str(row["conclusion_proposition_id"]),
        inference_rule_id=str(row["inference_rule_id"]),
        model_id=row["model_id"], model_version=row["model_version"],
        basis_digest=str(row["basis_digest"]),
        status=inference_status(db_path, str(row["inference_id"]), now=now),
        created_at=row["created_at"],
    )


# ---------------------------------------------------------------------------- revisions
def _current_basis(db_path: str, proposition_id: str, *, now: Optional[float],
                   conn: sqlite3.Connection,
                   stale_after: Optional[float] = None) -> Dict[str, Any]:
    belief = reconstruct_beliefs(db_path, now=now, stale_after=stale_after).belief_for(proposition_id)
    dependence = project_source_dependence(db_path, proposition_id, now=now,
                                           stale_after=stale_after)
    support = list(belief.supporting_evidence) if belief else []
    contradict = list(belief.contradicting_evidence) if belief else []
    stale = bool(belief and belief.status == "STALE")
    stable = {"proposition_id": proposition_id, "version": _latest_projection_version(conn, proposition_id),
              "support": sorted(support), "contradict": sorted(contradict),
              "provenance": dependence.provenance_digest, "stale": stale}
    stable["digest"] = _digest({k: v for k, v in stable.items() if k != "version"})
    return stable


def _derive_cause(previous: Optional[Mapping[str, Any]], current: Mapping[str, Any],
                  inference_count: int, previous_inference_count: int) -> Optional[str]:
    """
    The FROZEN precedence for deriving a revision cause from what actually changed (law 2).

    A caller cannot supply a cause, so "the model changed its mind" produces no revision at all.
    """
    if previous is None:
        return CAUSE_NEW_SUPPORT if current["support"] else (
            CAUSE_NEW_CONTRADICTION if current["contradict"] else None)
    if bool(previous["stale"]) != bool(current["stale"]):
        return CAUSE_EVIDENCE_STALE if current["stale"] else CAUSE_EVIDENCE_REFRESHED
    if set(current["support"]) - set(previous["support"]):
        return CAUSE_NEW_SUPPORT
    if set(current["contradict"]) - set(previous["contradict"]):
        return CAUSE_NEW_CONTRADICTION
    if previous["provenance"] != current["provenance"]:
        return CAUSE_PROVENANCE_CHANGED
    if inference_count != previous_inference_count:
        return CAUSE_INFERENCE_INVALIDATED if inference_count < previous_inference_count \
            else CAUSE_INFERENCE_ADDED
    return None


def record_revisions(db_path: str, *, now: Optional[float] = None,
                     stale_after: Optional[float] = None) -> Tuple[BeliefRevision, ...]:
    """
    Append a revision for every proposition whose epistemic basis actually changed (law 10).

    Reads Gate Zero's belief, Gate One's provenance and the inference graph, and writes only when the
    derived basis digest differs from the last recorded one. Identical re-evaluation adds nothing.
    """
    moment = time.time() if now is None else float(now)
    state = reconstruct_beliefs(db_path, now=moment, stale_after=stale_after)
    conn = _connect(db_path)
    written: List[BeliefRevision] = []
    try:
        init_schema(conn)
        for proposition in state.propositions:
            proposition_id = proposition.proposition_id
            try:
                # Inferences that conclude this proposition OR depend on it as a premise: both can
                # move the revision picture.
                rows = [dict(r) for r in conn.execute(
                    "SELECT * FROM ciph_inferences WHERE conclusion_proposition_id = ? "
                    "OR premises_json LIKE ?;", (proposition_id, f'%"{proposition_id}"%'))]
            except sqlite3.Error:
                rows = []
            inferences = {str(r["inference_id"]) for r in rows}
            current_inference_count = sum(
                1 for inference_id in inferences
                if inference_status(db_path, inference_id, now=moment) == INFERENCE_CURRENT)

            last = conn.execute(
                "SELECT * FROM ciph_belief_revisions WHERE proposition_id = ? "
                "ORDER BY rowid DESC LIMIT 1;", (proposition_id,)).fetchone()
            last_basis = None
            if last is not None:
                last_basis = {
                    "support": sorted(json.loads(last["cause_refs_json"] or "{}").get("support", [])),
                    "contradict": sorted(json.loads(last["cause_refs_json"] or "{}").get("contradict", [])),
                    "provenance": last["new_source_dependence_digest"],
                    "stale": bool(json.loads(last["cause_refs_json"] or "{}").get("stale", False)),
                    "inferences": int(json.loads(last["cause_refs_json"] or "{}").get("inferences", 0)),
                }
                previous_inference_count = last_basis["inferences"]
            else:
                previous_inference_count = 0

            current = _current_basis(db_path, proposition_id, now=moment, conn=conn,
                                     stale_after=stale_after)
            comparison = None if last_basis is None else {
                "support": last_basis["support"], "contradict": last_basis["contradict"],
                "provenance": last_basis["provenance"], "stale": last_basis["stale"],
            }
            cause = _derive_cause(comparison, current, current_inference_count,
                                 previous_inference_count)
            if cause is None:
                continue
            basis_digest = current["digest"]
            # DETERMINISTIC identity: a revision is DERIVED bookkeeping, so replaying the same history
            # must produce the same revision ids - otherwise "same history, same digest" would hold for
            # the assessment and fail for the record of how it was reached.
            revision_identity = _digest({
                "proposition_id": proposition_id, "basis": basis_digest,
                "previous": last["revision_id"] if last else None,
            })
            revision = BeliefRevision(
                revision_id=f"REV-{revision_identity[:12].upper()}",
                proposition_id=proposition_id,
                previous_projection_version=last["new_projection_version"] if last else None,
                new_projection_version=current["version"],
                previous_source_dependence_digest=last["new_source_dependence_digest"] if last else None,
                new_source_dependence_digest=current["provenance"],
                cause_refs=tuple(sorted(set(current["support"]) ^ set(current["contradict"]))),
                basis_digest=basis_digest,
                revision_reason=cause,
                created_at=moment,
            )
            conn.execute(
                "INSERT INTO ciph_belief_revisions (revision_id, proposition_id, "
                "previous_projection_version, new_projection_version, "
                "previous_source_dependence_digest, new_source_dependence_digest, cause_refs_json, "
                "basis_digest, revision_reason, created_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
                (revision.revision_id, proposition_id, revision.previous_projection_version,
                 revision.new_projection_version, revision.previous_source_dependence_digest,
                 revision.new_source_dependence_digest,
                 json.dumps({"support": current["support"], "contradict": current["contradict"],
                             "provenance": current["provenance"], "stale": current["stale"],
                             "inferences": current_inference_count}),
                 basis_digest, cause, moment),
            )
            written.append(revision)
        conn.commit()
    finally:
        conn.close()
    return tuple(written)


def revision_history(db_path: str, proposition_id: str) -> Tuple[BeliefRevision, ...]:
    conn = _connect(db_path, read_only=True)
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_belief_revisions WHERE proposition_id = ? ORDER BY created_at, rowid;",
            (proposition_id,))]
    except sqlite3.Error:
        rows = []
    finally:
        conn.close()
    return tuple(BeliefRevision(
        revision_id=str(r["revision_id"]), proposition_id=str(r["proposition_id"]),
        previous_projection_version=r["previous_projection_version"],
        new_projection_version=r["new_projection_version"],
        previous_source_dependence_digest=r["previous_source_dependence_digest"],
        new_source_dependence_digest=r["new_source_dependence_digest"],
        cause_refs=tuple(json.loads(r["cause_refs_json"] or "{}").get("support", [])
                         + json.loads(r["cause_refs_json"] or "{}").get("contradict", [])),
        basis_digest=str(r["basis_digest"]), revision_reason=str(r["revision_reason"]),
        created_at=r["created_at"]) for r in rows)


def revision_digest(db_path: str, *, now: Optional[float] = None,
                    stale_after: Optional[float] = None) -> str:
    """The deterministic identity of the revision history (law 12)."""
    moment = time.time() if now is None else float(now)
    state = reconstruct_beliefs(db_path, now=moment, stale_after=stale_after)
    payload = []
    for proposition in state.propositions:
        history = revision_history(db_path, proposition.proposition_id)
        payload.append({"proposition_id": proposition.proposition_id,
                        "basis": _current_basis(db_path, proposition.proposition_id, now=moment,
                                                conn=_connect(db_path, read_only=True),
                                                stale_after=stale_after),
                        "revisions": [h.as_dict() for h in history]})
    return _digest(payload)
