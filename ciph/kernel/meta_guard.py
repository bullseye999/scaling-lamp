"""
ciph/kernel/meta_guard - 4.7: new rules cannot ratify themselves.

This is the whole phase in one predicate. A meta candidate may GENERATE evidence; it may not be the
thing that decides whether it wins, and it may not become part of the authoritative evaluation path
while it is itself under evaluation.

LAWS
 1. A meta candidate starts SHADOW-ONLY.
 2. A meta candidate cannot judge anything while it is under evaluation.
 3. A candidate cannot be judged by itself.
 4. Two shadow meta candidates cannot judge each other (collusion).
 5. The judging evaluator is the PRE-CHANGE authoritative generation, not the candidate.
 6. Hard constitutional invariants remain non-tradeable, whatever the candidate's policy says.
 7. Ring-0 targets are impossible through this path; Ring-1 needs external authorization.
 8. Recursive generation is bounded: a shadow candidate may not generate another meta candidate.
 9. Meta promotion requires standing from the ordinary Crucible AND the meta protocol AND governance.
10. Nothing here deploys: deployment still crosses R7.
"""

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.meta_targets import (
    DISP_META_ALLOWED,
    DISP_META_FORBIDDEN,
    DISP_META_REQUIRES_EXTERNAL_REVIEW,
    RING_CONSTITUTIONAL_ROOT,
    RING_EVALUATION_CONSTITUTION,
    assert_ordinary_loop_may_proceed,
    classify_target,
    get_classification,
)
from ciph.kernel.crucible_types import CrucibleError, digest

META_CANDIDATE_V1 = "META_CANDIDATE_V1"
META_RECURSION_POLICY_V1 = "META_RECURSION_POLICY_V1"
META_PROMOTION_POLICY_V1 = "META_PROMOTION_POLICY_V1"
META_CRUCIBLE_PROTOCOL_V1 = "META_CRUCIBLE_PROTOCOL_V1"

MAX_META_GENERATION_DEPTH_V1 = 1

REASON_SELF_RATIFICATION = "META_SELF_RATIFICATION_REFUSED"
REASON_SHADOW_CANNOT_JUDGE = "META_SHADOW_CANNOT_JUDGE"
REASON_COLLUSION = "META_SHADOW_COLLUSION_REFUSED"
REASON_NOT_SHADOW = "META_CANDIDATE_MUST_START_SHADOW_ONLY"
REASON_DEPTH = "META_RECURSION_DEPTH_EXCEEDED"
REASON_HARD_INVARIANT = "META_CANDIDATE_INVALID_TRADES_A_HARD_INVARIANT"
REASON_PROMOTION = "META_PROMOTION_REFUSED"

# The invariants no candidate policy may make tradeable (law 6).
NON_TRADEABLE_INVARIANTS: Tuple[str, ...] = ("NO_AUTHORITY_BYPASS", "NO_FABRICATED_EVIDENCE",
                                             "NO_HISTORY_MUTATION", "NO_UNAUTHORIZED_EXECUTION",
                                             "NO_EVALUATOR_OR_BENCHMARK_MUTATION")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_candidates (
        meta_candidate_id TEXT PRIMARY KEY,
        target_ring TEXT NOT NULL,
        disposition TEXT NOT NULL,
        target_components_json TEXT NOT NULL,
        artifact_digest TEXT NOT NULL,
        configuration_digest TEXT NOT NULL,
        baseline_component_identity TEXT,
        shadow_only INTEGER NOT NULL,
        generation_depth INTEGER NOT NULL,
        proposed_by TEXT,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_judgments (
        meta_judgment_id TEXT PRIMARY KEY,
        meta_candidate_id TEXT NOT NULL,
        judge_identity TEXT NOT NULL,
        protocol_version TEXT NOT NULL,
        verdict TEXT NOT NULL,
        standing INTEGER NOT NULL,
        reason TEXT,
        recorded_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetaCandidate:
    meta_candidate_id: str
    target_ring: str
    disposition: str
    target_components: Tuple[str, ...]
    artifact_digest: str
    configuration_digest: str
    baseline_component_identity: Optional[str]
    shadow_only: bool
    generation_depth: int

    def as_dict(self) -> Dict[str, Any]:
        return {"meta_candidate_id": self.meta_candidate_id, "target_ring": self.target_ring,
                "disposition": self.disposition, "target_components": list(self.target_components),
                "artifact_digest": self.artifact_digest,
                "configuration_digest": self.configuration_digest,
                "baseline_component_identity": self.baseline_component_identity,
                "shadow_only": self.shadow_only, "generation_depth": self.generation_depth}


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


def assert_recursion_allowed(*, generation_depth: int) -> None:
    """Law 8: one meta layer at a time. A shadow candidate may not generate another."""
    if int(generation_depth) > MAX_META_GENERATION_DEPTH_V1:
        raise CrucibleError(REASON_DEPTH, f"depth {generation_depth} > "
                                          f"{MAX_META_GENERATION_DEPTH_V1}")


def assert_hard_invariants_preserved(proposed_policy: Dict[str, Any]) -> None:
    """
    Law 6: a candidate that would make a constitutional invariant tradeable is INVALID, whatever it
    gains. "Twenty percent faster but occasionally fabricates evidence" is not a Pareto improvement.
    """
    for invariant in NON_TRADEABLE_INVARIANTS:
        declaration = (proposed_policy or {}).get(invariant)
        if declaration is not None and declaration is not True:
            raise CrucibleError(REASON_HARD_INVARIANT, f"{invariant}={declaration!r}")
    tradeable = (proposed_policy or {}).get("tradeable")
    if tradeable:
        offenders = [str(item) for item in tradeable if str(item) in NON_TRADEABLE_INVARIANTS]
        if offenders:
            raise CrucibleError(REASON_HARD_INVARIANT, ",".join(offenders))


def register_meta_candidate(db_path: str, *, changed_files: Sequence[str],
                            artifact_digest: str, configuration_digest: str,
                            baseline_component_identity: Optional[str] = None,
                            dependencies: Sequence[str] = (),
                            generation_depth: int = 1, proposed_by: Optional[str] = None,
                            now: Optional[float] = None) -> MetaCandidate:
    """
    Register ONE meta candidate (laws 1, 7, 8).

    Ring 0 is refused outright; Ring 1 is refused through the ORDINARY loop and needs external
    authorization; Ring 2 is allowed. Every meta candidate starts shadow-only.
    """
    assert_recursion_allowed(generation_depth=generation_depth)
    classification = classify_target(db_path, changed_files=changed_files,
                                     dependencies=dependencies, now=now)
    assert_ordinary_loop_may_proceed(classification)
    moment = time.time() if now is None else float(now)
    meta_candidate_id = "MC-" + digest({"classification": classification.classification_id,
                                        "artifact": artifact_digest,
                                        "configuration": configuration_digest,
                                        "depth": generation_depth})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_candidates (meta_candidate_id, target_ring, "
            "disposition, target_components_json, artifact_digest, configuration_digest, "
            "baseline_component_identity, shadow_only, generation_depth, proposed_by, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (meta_candidate_id, classification.target_ring, classification.disposition,
             json.dumps(list(classification.affected_components)), artifact_digest,
             configuration_digest, baseline_component_identity, 1, int(generation_depth),
             proposed_by, moment))
        connection.commit()
    finally:
        connection.close()
    return get_meta_candidate(db_path, meta_candidate_id)


def get_meta_candidate(db_path: str, meta_candidate_id: str) -> MetaCandidate:
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_candidates WHERE meta_candidate_id = ?;",
                                 (meta_candidate_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_META_CANDIDATE", meta_candidate_id)
    row = dict(row)
    return MetaCandidate(
        meta_candidate_id=str(row["meta_candidate_id"]), target_ring=str(row["target_ring"]),
        disposition=str(row["disposition"]),
        target_components=tuple(json.loads(row["target_components_json"] or "[]")),
        artifact_digest=str(row["artifact_digest"]),
        configuration_digest=str(row["configuration_digest"]),
        baseline_component_identity=row["baseline_component_identity"],
        shadow_only=bool(row["shadow_only"]), generation_depth=int(row["generation_depth"]))


def assert_independent_judgment(db_path: str, *, meta_candidate_id: str,
                                judge_identity: str) -> None:
    """
    THE predicate (laws 2, 3, 4, 5).

        a candidate may not be judged by itself, by another shadow candidate, or by anything it replaces

    The judge must be the pre-change authoritative generation; a shadow implementation judges nothing.
    """
    candidate = get_meta_candidate(db_path, meta_candidate_id)
    if judge_identity == meta_candidate_id:
        raise CrucibleError(REASON_SELF_RATIFICATION,
                            f"{meta_candidate_id} cannot judge itself")
    if judge_identity in candidate.target_components:
        raise CrucibleError(REASON_SELF_RATIFICATION,
                            f"{judge_identity} is a component this candidate would replace")
    connection = _connect(db_path, read_only=True)
    try:
        row = connection.execute("SELECT * FROM ciph_meta_candidates WHERE meta_candidate_id = ?;",
                                 (judge_identity,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is not None:
        # The judge is itself a registered meta candidate. While it is under evaluation it has no
        # standing, and two candidates cannot give each other a pass. A PROMOTED candidate judges as
        # `AUTHORITATIVE:<epoch>`, never as its own candidate id - which is exactly why promotion is an
        # epoch transition and not a flag on the candidate.
        raise CrucibleError(REASON_COLLUSION if judge_identity != meta_candidate_id
                            else REASON_SELF_RATIFICATION,
                            f"{judge_identity} is itself under evaluation")
    if candidate.shadow_only and judge_identity.startswith("MC-"):
        raise CrucibleError(REASON_SHADOW_CANNOT_JUDGE,
                            f"{meta_candidate_id} is shadow-only and does not judge")


def record_meta_judgment(db_path: str, *, meta_candidate_id: str, judge_identity: str,
                         verdict: str, standing_ref: Optional[str] = None,
                         now: Optional[float] = None) -> str:
    """
    Record what the AUTHORITATIVE generation concluded (laws 3, 5).

    Standing is zero unless an independent judge produced it; a verdict with no valid judge is stored
    as evidence of a REFUSED attempt and confers nothing.
    """
    moment = time.time() if now is None else float(now)
    try:
        assert_independent_judgment(db_path, meta_candidate_id=meta_candidate_id,
                                    judge_identity=judge_identity)
        standing, reason = 1, None
    except CrucibleError as refused:
        standing, reason = 0, refused.reason
    meta_judgment_id = "MJ-" + digest({"candidate": meta_candidate_id, "judge": judge_identity,
                                       "verdict": verdict, "standing": standing})[:16].upper()
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_judgments (meta_judgment_id, meta_candidate_id, "
            "judge_identity, protocol_version, verdict, standing, reason, recorded_at) "
            "VALUES (?,?,?,?,?,?,?,?);",
            (meta_judgment_id, meta_candidate_id, judge_identity, META_CRUCIBLE_PROTOCOL_V1,
             verdict, standing, reason, moment))
        connection.commit()
    finally:
        connection.close()
    return meta_judgment_id


def meta_standing(db_path: str, meta_candidate_id: str) -> Tuple[int, ...]:
    connection = _connect(db_path, read_only=True)
    try:
        return tuple(int(row["standing"]) for row in connection.execute(
            "SELECT standing FROM ciph_meta_judgments WHERE meta_candidate_id = ? ORDER BY rowid;",
            (meta_candidate_id,)))
    except sqlite3.Error:
        return ()
    finally:
        connection.close()


def assert_meta_promotion_allowed(db_path: str, *, meta_candidate_id: str,
                                  ordinary_standing: str, meta_protocol_standing: str,
                                  authority_ref: Optional[str],
                                  constitutional_violations: int = 0) -> None:
    """
    Law 9: meta promotion needs the ordinary Crucible, the meta protocol AND governance.

    Ring 1 additionally requires an explicit external authorization, and Ring 0 never arrives here at
    all because it was refused at registration.
    """
    candidate = get_meta_candidate(db_path, meta_candidate_id)
    problems: List[str] = []
    if int(constitutional_violations) > 0:
        problems.append(f"CONSTITUTIONAL_VIOLATIONS:{constitutional_violations}")
    if ordinary_standing != "DOMINATES":
        problems.append(f"ORDINARY_STANDING:{ordinary_standing}")
    if meta_protocol_standing != "DOMINATES":
        problems.append(f"META_PROTOCOL_STANDING:{meta_protocol_standing}")
    if not any(standing == 1 for standing in meta_standing(db_path, meta_candidate_id)):
        problems.append("NO_INDEPENDENT_META_JUDGMENT")
    if candidate.target_ring in (RING_EVALUATION_CONSTITUTION, RING_CONSTITUTIONAL_ROOT):
        if not authority_ref:
            problems.append("EXTERNAL_AUTHORIZATION_REQUIRED")
    if candidate.target_ring == RING_CONSTITUTIONAL_ROOT:
        problems.append("RING_0_NEVER")
    if problems:
        raise CrucibleError(REASON_PROMOTION, ",".join(problems))


def recursive_generation_permitted(*, generation_depth: int) -> bool:
    """Law 8 as a property rather than a convention."""
    return int(generation_depth) <= MAX_META_GENERATION_DEPTH_V1
