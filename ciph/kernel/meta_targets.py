"""
ciph/kernel/meta_targets - 4.7 Gate Zero: what class of thing is being changed?

Not every "meta" change is equally dangerous, so the protected system is split into rings and the
classification is deterministic, dependency-aware and versioned.

    RING 3  ORDINARY                 planner, tools, prompts, capability implementations
    RING 2  IMPROVEMENT_MACHINERY    gap detector, candidate generator, review, benchmark, learning
    RING 1  EVALUATION_CONSTITUTION  metric semantics, Pareto policy, protocols, candidate identity,
                                     safety policy, held-out isolation, regression/rollback semantics
    RING 0  CONSTITUTIONAL_ROOT      execution authority, permits, vault identity, canonical evidence,
                                     promotion authority, meta-evolution authority itself

Disposition:

```
RING 3 -> ORDINARY_4_6                 handled by 4.6
RING 2 -> META_ALLOWED                 meta-evolution may run
RING 1 -> META_REQUIRES_EXTERNAL_REVIEW
RING 0 -> META_FORBIDDEN               not forever, but never by the ordinary recursive loop
```

Ring 0 stays outside the loop on purpose: an evolutionary system needs something analogous to a
trusted computing base, or it can eventually "improve" the definition of improvement until everything
passes.

LAWS
 1. Classification uses the actual dependency/diff surface, not the description.
 2. Indirect modification counts.
 3. Renaming a protected module does not evade classification.
 4. Dependency injection into a protected component counts as touching it.
 5. Unknown classification fails UPWARD, never downward.
 6. A Ring-0 change cannot be smuggled as a Ring-2 candidate.
 7. The classification policy is versioned.
 8. A candidate cannot choose its own ring.
 9. Same target graph -> same classification.
10. Restart reproduces the classification exactly.

STATED LIMIT (law 3, honestly bounded): the scanner classifies by path membership and by the
dependencies a change declares. A protected module COPIED to a new name that imports nothing from the
original is indistinguishable from an ordinary new file by this method - the Constitutional Root is
protected by the scanner plus explicit architecture review, not by path strings alone.
"""

import json
import pathlib
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

META_TARGET_POLICY_V1 = "META_TARGET_POLICY_V1"

RING_CONSTITUTIONAL_ROOT = "CONSTITUTIONAL_ROOT"
RING_EVALUATION_CONSTITUTION = "EVALUATION_CONSTITUTION"
RING_IMPROVEMENT_MACHINERY = "IMPROVEMENT_MACHINERY"
RING_ORDINARY = "ORDINARY"
RING_ORDER = (RING_ORDINARY, RING_IMPROVEMENT_MACHINERY, RING_EVALUATION_CONSTITUTION,
              RING_CONSTITUTIONAL_ROOT)

DISP_ORDINARY_4_6 = "ORDINARY_4_6"
DISP_META_ALLOWED = "META_ALLOWED"
DISP_META_REQUIRES_EXTERNAL_REVIEW = "META_REQUIRES_EXTERNAL_REVIEW"
DISP_META_FORBIDDEN = "META_FORBIDDEN"
VALID_DISPOSITIONS = (DISP_ORDINARY_4_6, DISP_META_ALLOWED, DISP_META_REQUIRES_EXTERNAL_REVIEW,
                      DISP_META_FORBIDDEN)

RING_0_COMPONENTS: Tuple[str, ...] = (
    "ciph/kernel/execution_authority.py", "ciph/kernel/execution_gateway.py",
    "ciph/kernel/permit_store.py", "ciph/kernel/permit_issuance.py",
    "ciph/kernel/permit_composition.py", "ciph/kernel/scope_grant_store.py",
    "ciph/kernel/vault_identity.py", "ciph/kernel/crypto_identity.py",
    "ciph/kernel/epistemic_ledger.py", "ciph/kernel/crucible_candidates.py",
    "ciph/kernel/crucible_promotion.py", "ciph/kernel/schema_ownership.py",
    "ciph/kernel/production_choke_point.py", "ciph/kernel/meta_targets.py",
    "ciph/kernel/meta_guard.py", "ciph/kernel/evolution_epochs.py",
)

RING_1_COMPONENTS: Tuple[str, ...] = (
    "ciph/kernel/crucible_metrics.py", "ciph/kernel/crucible_protocols.py",
    "ciph/kernel/crucible_trials.py", "ciph/kernel/crucible_monitoring.py",
    "ciph/kernel/candidate_safety.py", "ciph/kernel/crucible_handoff.py",
    "ciph/kernel/evolution_deployment.py", "ciph/kernel/evolution_ownership.py",
    "ciph/kernel/crucible_types.py",
)

RING_2_COMPONENTS: Tuple[str, ...] = (
    "ciph/evolution/gap_detector.py", "ciph/evolution/isolated_execution.py",
    "ciph/evolution/benchmark_harness.py", "ciph/evolution/review.py",
    "ciph/evolution/canary_manager.py", "ciph/evolution/workflow.py",
    "ciph/evolution/evidence.py", "ciph/evolution/file_activation.py",
    "ciph/kernel/improvement_opportunities.py", "ciph/kernel/improvement_hypotheses.py",
    "ciph/kernel/candidate_construction.py", "ciph/kernel/improvement_learning.py",
    "ciph/kernel/evolution_adapters.py",
)

# Namespaces where an UNCLASSIFIED file fails upward rather than being treated as ordinary.
_CONSTITUTIONAL_NAMESPACES = ("ciph/kernel/", "ciph/evolution/", "ciph/contracts/evolution.py")

_DISPOSITION_BY_RING = {
    RING_ORDINARY: DISP_ORDINARY_4_6,
    RING_IMPROVEMENT_MACHINERY: DISP_META_ALLOWED,
    RING_EVALUATION_CONSTITUTION: DISP_META_REQUIRES_EXTERNAL_REVIEW,
    RING_CONSTITUTIONAL_ROOT: DISP_META_FORBIDDEN,
}

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_meta_target_classifications (
        classification_id TEXT PRIMARY KEY,
        target_ring TEXT NOT NULL,
        disposition TEXT NOT NULL,
        changed_files_json TEXT NOT NULL,
        dependencies_json TEXT,
        affected_components_json TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        declared_description TEXT,
        carried_truth TEXT NOT NULL,
        classified_at REAL
    );
    """,
)


@dataclass(frozen=True)
class MetaTargetClassification:
    classification_id: str
    target_ring: str
    disposition: str
    changed_files: Tuple[str, ...]
    dependencies: Tuple[str, ...]
    affected_components: Tuple[str, ...]
    policy_version: str
    carried_truth: str

    def as_dict(self) -> Dict[str, Any]:
        return {"classification_id": self.classification_id, "target_ring": self.target_ring,
                "disposition": self.disposition, "changed_files": list(self.changed_files),
                "dependencies": list(self.dependencies),
                "affected_components": list(self.affected_components),
                "policy_version": self.policy_version, "carried_truth": self.carried_truth}


def ring_of(component: str) -> Optional[str]:
    """The ring a single path belongs to, or None when it is unclassified."""
    normalised = str(component).replace("\\", "/").lstrip("./")
    for ring, components in ((RING_CONSTITUTIONAL_ROOT, RING_0_COMPONENTS),
                             (RING_EVALUATION_CONSTITUTION, RING_1_COMPONENTS),
                             (RING_IMPROVEMENT_MACHINERY, RING_2_COMPONENTS)):
        for candidate in components:
            if normalised == candidate or normalised.endswith(candidate):
                return ring
    return None


def _effective_ring(component: str) -> str:
    """Law 5: an unclassified file inside a constitutional namespace fails UPWARD."""
    ring = ring_of(component)
    if ring is not None:
        return ring
    normalised = str(component).replace("\\", "/").lstrip("./")
    if any(normalised.startswith(namespace) for namespace in _CONSTITUTIONAL_NAMESPACES):
        return RING_EVALUATION_CONSTITUTION
    return RING_ORDINARY


def classify(*, changed_files: Sequence[str], dependencies: Sequence[str] = ()) -> Tuple[str, Tuple[str, ...]]:
    """
    The most protected ring touched, and the components that put it there (laws 1, 2, 4, 6, 8).

    Dependencies count like files, so injecting a protected component into an otherwise ordinary change
    is not a way around the classification.
    """
    touched: List[str] = []
    worst = RING_ORDINARY
    for component in list(changed_files) + list(dependencies):
        ring = _effective_ring(component)
        touched.append(str(component))
        if RING_ORDER.index(ring) > RING_ORDER.index(worst):
            worst = ring
    return worst, tuple(sorted(set(touched)))


def classification_id_for(*, target_ring: str, changed_files: Sequence[str],
                          dependencies: Sequence[str],
                          policy_version: str = META_TARGET_POLICY_V1) -> str:
    return "MTC-" + digest({"policy": policy_version, "ring": target_ring,
                            "files": sorted(str(item) for item in changed_files),
                            "dependencies": sorted(str(item) for item in dependencies)})[:16].upper()


def classify_target(db_path: str, *, changed_files: Sequence[str],
                    dependencies: Sequence[str] = (), declared_description: Optional[str] = None,
                    now: Optional[float] = None) -> MetaTargetClassification:
    """
    Classify ONE proposed change and record it (laws 7, 9, 10).

    `declared_description` is stored for the audit trail and read by nothing: the ring comes from the
    diff surface, so a change that claims to "improve gap_detector" while editing crucible_metrics.py
    is Ring 1 and needs external review.
    """
    if not changed_files and not dependencies:
        raise CrucibleError("CLASSIFICATION_REQUIRES_A_TARGET_SURFACE", 'nothing to classify')
    moment = time.time() if now is None else float(now)
    ring, touched = classify(changed_files=changed_files, dependencies=dependencies)
    disposition = _DISPOSITION_BY_RING[ring]
    classification_id = classification_id_for(target_ring=ring, changed_files=changed_files,
                                              dependencies=dependencies)
    if disposition == DISP_META_FORBIDDEN:
        carried = "RING_0_NEVER_BY_THE_ORDINARY_LOOP"
    elif disposition == DISP_META_REQUIRES_EXTERNAL_REVIEW:
        carried = "RING_1_EXTERNAL_REVIEW_REQUIRED"
    elif disposition == DISP_META_ALLOWED:
        carried = "RING_2_META_ALLOWED"
    else:
        carried = "RING_3_ORDINARY"
    connection = sqlite3.connect(db_path, timeout=10.0)
    try:
        for statement in _SCHEMA:
            connection.execute(statement)
        connection.execute(
            "INSERT OR IGNORE INTO ciph_meta_target_classifications (classification_id, target_ring, "
            "disposition, changed_files_json, dependencies_json, affected_components_json, "
            "policy_version, declared_description, carried_truth, classified_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?);",
            (classification_id, ring, disposition, json.dumps(sorted(str(f) for f in changed_files)),
             json.dumps(sorted(str(d) for d in dependencies)), json.dumps(list(touched)),
             META_TARGET_POLICY_V1, declared_description, carried, moment))
        connection.commit()
    finally:
        connection.close()
    return get_classification(db_path, classification_id)


def get_classification(db_path: str, classification_id: str) -> MetaTargetClassification:
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute("SELECT * FROM ciph_meta_target_classifications WHERE "
                                 "classification_id = ?;", (classification_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        connection.close()
    if row is None:
        raise CrucibleError("UNKNOWN_CLASSIFICATION", classification_id)
    row = dict(row)
    return MetaTargetClassification(
        classification_id=str(row["classification_id"]), target_ring=str(row["target_ring"]),
        disposition=str(row["disposition"]),
        changed_files=tuple(json.loads(row["changed_files_json"] or "[]")),
        dependencies=tuple(json.loads(row["dependencies_json"] or "[]")),
        affected_components=tuple(json.loads(row["affected_components_json"] or "[]")),
        policy_version=str(row["policy_version"]), carried_truth=str(row["carried_truth"]))


def assert_ordinary_loop_may_proceed(classification: MetaTargetClassification) -> None:
    """Laws 6 and 8: the ordinary recursive loop may not carry a Ring 0 or Ring 1 change."""
    if classification.disposition == DISP_META_FORBIDDEN:
        raise CrucibleError("META_RING_0_FORBIDDEN", ','.join(classification.affected_components))
    if classification.disposition == DISP_META_REQUIRES_EXTERNAL_REVIEW:
        raise CrucibleError("META_EXTERNAL_REVIEW_REQUIRED",
                            ','.join(classification.affected_components))


def classification_history(db_path: str) -> List[MetaTargetClassification]:
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    try:
        ids = [str(row["classification_id"]) for row in connection.execute(
            "SELECT classification_id FROM ciph_meta_target_classifications "
            "ORDER BY classified_at, classification_id;")]
    except sqlite3.Error:
        ids = []
    finally:
        connection.close()
    return [get_classification(db_path, classification_id) for classification_id in ids]


def classification_digest(db_path: str) -> str:
    return digest({"policy": META_TARGET_POLICY_V1,
                   "classifications": [item.as_dict() for item in classification_history(db_path)]})
