"""
ciph/kernel/candidate_safety - 4.6 Gate Three: is this candidate admissible at all?

This is PRE-EVALUATION ADMISSIBILITY, not performance. A candidate that touches the execution
constitution, the vault, the epistemic ledger or the Crucible itself is not a better or worse candidate
- it is a different kind of act, and ordinary self-improvement is not allowed to perform it.

LAWS
 1. Safety review is not performance evaluation.
 2. Passing safety review does not mean the candidate is good.
 3. Failing safety review cannot be outweighed by expected performance.
 4. A candidate cannot modify its own safety policy.
 5. New privileges must be explicit.
 6. Hidden dependency growth is a review failure.
 7. A candidate cannot gain key or signer access indirectly.
 8. Constitutional touchpoints require stronger governance.
 9. The review uses the actual artifact/diff, never its description.
10. Same candidate plus same policy -> same review digest.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_candidates import get_candidate
from ciph.kernel.crucible_types import CrucibleError, digest

CANDIDATE_SAFETY_POLICY_V1 = "CANDIDATE_SAFETY_POLICY_V1"

VERDICT_ADMISSIBLE = "ADMISSIBLE"
VERDICT_ARCHITECTURE_REVIEW = "REQUIRES_ARCHITECTURE_REVIEW"
VERDICT_REJECTED = "REJECTED"
VALID_VERDICTS = (VERDICT_ADMISSIBLE, VERDICT_ARCHITECTURE_REVIEW, VERDICT_REJECTED)

# Ordinary self-improvement may not reach these. The list is policy, and it is versioned.
PROTECTED_SURFACES: Tuple[str, ...] = (
    "ciph/kernel/execution_authority.py", "ciph/kernel/execution_gateway.py",
    "ciph/kernel/permit_store.py", "ciph/kernel/permit_issuance.py",
    "ciph/kernel/permit_composition.py", "ciph/kernel/scope_grant_store.py",
    "ciph/kernel/vault_identity.py", "ciph/kernel/crypto_identity.py",
    "ciph/kernel/epistemic_ledger.py", "ciph/kernel/schema_ownership.py",
    "ciph/kernel/crucible_candidates.py", "ciph/kernel/crucible_protocols.py",
    "ciph/kernel/crucible_trials.py", "ciph/kernel/crucible_metrics.py",
    "ciph/kernel/crucible_promotion.py", "ciph/kernel/crucible_monitoring.py",
    "ciph/kernel/evolution_deployment.py", "ciph/kernel/candidate_safety.py",
    # Ring 0 and the meta machinery, added when 4.7 made them load-bearing. `meta_scanners.s08` checks
    # that this set covers every Ring-0 component, so the two cannot drift apart silently.
    "ciph/kernel/crucible_types.py", "ciph/kernel/crucible_handoff.py",
    "ciph/kernel/evolution_ownership.py", "ciph/kernel/production_choke_point.py",
    "ciph/kernel/evolution_epochs.py", "ciph/kernel/meta_targets.py",
    "ciph/kernel/meta_guard.py", "ciph/kernel/meta_scanners.py", "ciph/kernel/meta_corpus.py",
    "ciph/kernel/meta_corpus_isolation.py", "ciph/kernel/meta_shadow.py",
    "ciph/kernel/meta_promotion.py", "ciph/kernel/meta_hypotheses.py",
    "ciph/kernel/meta_opportunities.py", "ciph/kernel/meta_learning.py",
    "ciph/kernel/meta_comparison.py",
)

# Changing the machinery that GENERATES improvements is meta-evolution, handled by 4.6 Gate Six.
GENERATOR_SURFACES: Tuple[str, ...] = (
    "ciph/evolution/gap_detector.py", "ciph/kernel/candidate_construction.py",
    "ciph/kernel/improvement_opportunities.py", "ciph/kernel/improvement_hypotheses.py",
)

PRIVILEGE_KEYS = ("network", "filesystem", "subprocess", "signer", "key_material", "permit_authority")

REASON_DIFF_EMPTY = "NO_ARTIFACT_FACT_DIFF_PROVIDED"
REASON_PROTECTED_SURFACE = "TOUCHES_PROTECTED_SURFACE"
REASON_GENERATOR_SURFACE = "TOUCHES_GENERATOR_SURFACE"
REASON_DEPENDENCY_GROWTH = "DEPENDENCY_REACHES_PROTECTED_SURFACE"
REASON_PRIVILEGE_SURFACE = "PRIVILEGE_SURFACE_CHANGE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_candidate_safety_reviews (
        review_id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        changed_files_json TEXT NOT NULL,
        new_dependencies_json TEXT,
        removed_dependencies_json TEXT,
        privilege_delta_json TEXT,
        constitutional_touchpoints_json TEXT,
        verdict TEXT NOT NULL,
        reason_codes_json TEXT,
        diff_digest TEXT,
        reviewed_at REAL
    );
    """,
)


@dataclass(frozen=True)
class CandidateSafetyReview:
    review_id: str
    candidate_id: str
    policy_version: str
    changed_files: Tuple[str, ...]
    new_dependencies: Tuple[str, ...]
    verdict: str
    reason_codes: Tuple[str, ...]
    constitutional_touchpoints: Tuple[str, ...]
    diff_digest: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {"review_id": self.review_id, "candidate_id": self.candidate_id,
                "policy_version": self.policy_version, "changed_files": list(self.changed_files),
                "new_dependencies": list(self.new_dependencies), "verdict": self.verdict,
                "reason_codes": list(self.reason_codes),
                "constitutional_touchpoints": list(self.constitutional_touchpoints),
                "diff_digest": self.diff_digest}


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


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _normalise(paths: Sequence[str]) -> Tuple[str, ...]:
    return tuple(sorted({str(path).replace("\\", "/").lstrip("./") for path in paths}))


def _touches(paths: Sequence[str], surfaces: Sequence[str]) -> Tuple[str, ...]:
    hits = []
    for path in paths:
        for surface in surfaces:
            if path == surface or path.endswith(surface) or surface.endswith(path):
                hits.append(path)
                break
    return tuple(sorted(set(hits)))


def review_candidate(db_path: str, *, candidate_id: str, changed_files: Sequence[str],
                     new_dependencies: Sequence[str] = (), removed_dependencies: Sequence[str] = (),
                     privilege_delta: Optional[Dict[str, Any]] = None,
                     declared_description: Optional[str] = None,
                     artifact_digest: Optional[str] = None,
                     now: Optional[float] = None) -> CandidateSafetyReview:
    """
    Review the ACTUAL artifact facts (law 9).

    `declared_description` is accepted for the audit trail - and read by nothing. A candidate whose
    story is "optimize latency" while its diff edits the promotion layer is a protected-surface change,
    and the story does not save it.
    """
    candidate = get_candidate(db_path, candidate_id)
    files = _normalise(changed_files)
    dependencies = _normalise(new_dependencies)
    privileges = {str(key): value for key, value in (privilege_delta or {}).items()}

    reasons: List[str] = []
    if not files and not dependencies:
        verdict = VERDICT_REJECTED
        reasons.append(REASON_DIFF_EMPTY)
        touchpoints: Tuple[str, ...] = ()
    else:
        protected_hits = _touches(files, PROTECTED_SURFACES)
        generator_hits = _touches(files, GENERATOR_SURFACES)
        dependency_hits = _touches(dependencies, PROTECTED_SURFACES + GENERATOR_SURFACES)
        privilege_changes = tuple(sorted(key for key, value in privileges.items()
                                         if value and key in PRIVILEGE_KEYS))
        touchpoints = protected_hits + generator_hits
        if protected_hits:
            reasons.append(REASON_PROTECTED_SURFACE)
        if generator_hits:
            reasons.append(REASON_GENERATOR_SURFACE)
        if dependency_hits:
            reasons.append(REASON_DEPENDENCY_GROWTH)
        if privilege_changes:
            reasons.append(REASON_PRIVILEGE_SURFACE)
        verdict = (VERDICT_ARCHITECTURE_REVIEW
                   if (protected_hits or generator_hits or dependency_hits or privilege_changes)
                   else VERDICT_ADMISSIBLE)

    moment = time.time() if now is None else float(now)
    diff_digest = artifact_digest or candidate.artifact_digest
    review_id = "CSR-" + digest({"candidate_id": candidate_id, "policy": CANDIDATE_SAFETY_POLICY_V1,
                                 "files": list(files), "dependencies": list(dependencies),
                                 "privileges": privileges, "diff": diff_digest,
                                 "verdict": verdict})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_candidate_safety_reviews (review_id, candidate_id, "
            "policy_version, changed_files_json, new_dependencies_json, removed_dependencies_json, "
            "privilege_delta_json, constitutional_touchpoints_json, verdict, reason_codes_json, "
            "diff_digest, reviewed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
            (review_id, candidate_id, CANDIDATE_SAFETY_POLICY_V1, json.dumps(list(files)),
             json.dumps(list(dependencies)), json.dumps(list(_normalise(removed_dependencies))),
             json.dumps(privileges, sort_keys=True), json.dumps(list(touchpoints)), verdict,
             json.dumps(sorted(reasons)), diff_digest, moment))
        connection.commit()
    finally:
        connection.close()
    return get_review(db_path, review_id)


def get_review(db_path: str, review_id: str) -> CandidateSafetyReview:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_candidate_safety_reviews WHERE review_id = ?;",
                                 (review_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_SAFETY_REVIEW", review_id)
    row = dict(row)
    return CandidateSafetyReview(
        review_id=str(row["review_id"]), candidate_id=str(row["candidate_id"]),
        policy_version=str(row["policy_version"]),
        changed_files=tuple(json.loads(row["changed_files_json"] or "[]")),
        new_dependencies=tuple(json.loads(row["new_dependencies_json"] or "[]")),
        verdict=str(row["verdict"]),
        reason_codes=tuple(json.loads(row["reason_codes_json"] or "[]")),
        constitutional_touchpoints=tuple(json.loads(row["constitutional_touchpoints_json"] or "[]")),
        diff_digest=row["diff_digest"])


def reviews_for(db_path: str, candidate_id: str) -> List[CandidateSafetyReview]:
    connection = _connect(db_path, read_only=True)
    try:
        ids = [str(row["review_id"]) for row in connection.execute(
            # INSERTION order, not (timestamp, id): two reviews written inside the same clock tick
            # would otherwise have an arbitrary "latest" - and "latest" is the whole verdict.
            "SELECT review_id FROM ciph_candidate_safety_reviews WHERE candidate_id = ? "
            "ORDER BY rowid;", (candidate_id,))]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_review(db_path, review_id) for review_id in ids]


def is_admissible(db_path: str, candidate_id: str) -> bool:
    """Admissibility is the LATEST review, and only ADMISSIBLE passes (law 3)."""
    reviews = reviews_for(db_path, candidate_id)
    return bool(reviews) and reviews[-1].verdict == VERDICT_ADMISSIBLE


def safety_digest(db_path: str) -> str:
    connection = _connect(db_path, read_only=True)
    try:
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM ciph_candidate_safety_reviews ORDER BY review_id;")]
    except sqlite3.Error:
        rows = []
    finally:
        connection.close()
    return digest({"version": CANDIDATE_SAFETY_POLICY_V1, "reviews": rows})
