"""
ciph.kernel.manifest_lineage - manifest ancestry as history, never as authority.

Decision of record: D11, MANIFEST_HASH_V2.

PARENTAGE RULES (decided consciously, not by default)
    predecessor -> many successors      ALLOWED   two new versions may descend from one capability
    successor  <- multiple predecessors FORBIDDEN once a successor has two parents, "what did this
                                                  evolve from" becomes a semantic merge operation
                                                  with its own rules for conflicting predecessor
                                                  semantics, which evidence lineage is relevant,
                                                  whether either parent's credit may influence
                                                  evaluation, and how rollback ancestry works
    self-transition                     FORBIDDEN no identity change, so no lineage
    cycles                              FORBIDDEN ancestry would not terminate
    edge mutation                       FORBIDDEN transitions are append-only history

Merging is not forbidden forever; it is forbidden *here*. Combining lineages belongs in an explicit
evolutionary construct such as Crucible candidate composition, where conflicting semantics can be
handled deliberately. Silent merging inside ordinary manifest lineage is how a DAG becomes a graph
nobody can reason about.

THIS MODULE NEVER ANSWERS "WHICH CREDIT MAY BE SPENT". It answers where a capability came from.
Credit lookup by exact identity is a different question with a different API on purpose.
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from ciph.kernel.manifest_identity import ManifestIdentity

REASON_MANIFEST_HASH_V2_ADOPTION = "MANIFEST_HASH_V2_ADOPTION"
SEMANTIC_DELTA_TARGET_IDENTITY_BOUND = "TARGET_IDENTITY_BOUND_TO_MANIFEST"


class LineageError(Exception):
    """Raised when a transition would violate the lineage rules."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class ManifestTransition:
    """
    One lineage step. Frozen, because a transition is history and history is not editable.
    """

    predecessor: ManifestIdentity
    successor: ManifestIdentity
    reason: str
    transition_time: float
    semantic_delta: tuple = ()

    def __post_init__(self):
        if not isinstance(self.predecessor, ManifestIdentity) or not isinstance(
            self.successor, ManifestIdentity
        ):
            raise LineageError("TRANSITION_REQUIRES_MANIFEST_IDENTITIES")
        if self.predecessor == self.successor:
            # Not even a same-hash claim: identity includes the version, so this also catches an
            # attempt to record lineage without an actual identity change.
            raise LineageError("SELF_TRANSITION_FORBIDDEN", str(self.predecessor))
        if not self.reason:
            raise LineageError("TRANSITION_REASON_REQUIRED")


class ManifestLineage:
    """Append-only, single-parent-above ancestry for manifest identities."""

    def __init__(self):
        self._parent: Dict[ManifestIdentity, ManifestIdentity] = {}
        self._children: Dict[ManifestIdentity, List[ManifestIdentity]] = {}
        self._reasons: Dict[ManifestIdentity, str] = {}

    def record(
        self,
        predecessor: ManifestIdentity,
        successor: ManifestIdentity,
        reason: str,
        semantic_delta: tuple = (),
        transition_time: Optional[float] = None,
    ) -> ManifestTransition:
        transition = ManifestTransition(
            predecessor=predecessor,
            successor=successor,
            reason=reason,
            transition_time=transition_time if transition_time is not None else time.time(),
            semantic_delta=semantic_delta,
        )

        existing_parent = self._parent.get(successor)
        if existing_parent is not None:
            if existing_parent == predecessor:
                raise LineageError("TRANSITION_ALREADY_RECORDED", str(successor))
            # Merging. Refused here by decision; it belongs in an explicit evolutionary construct.
            raise LineageError(
                "MULTIPLE_PREDECESSORS_FORBIDDEN",
                f"{successor} already descends from {existing_parent}",
            )

        if self._is_ancestor(successor, predecessor):
            raise LineageError("CYCLE_FORBIDDEN", f"{successor} is an ancestor of {predecessor}")

        self._parent[successor] = predecessor
        self._children.setdefault(predecessor, []).append(successor)
        self._reasons[successor] = reason
        return transition

    def predecessor_of(self, identity: ManifestIdentity) -> Optional[ManifestIdentity]:
        return self._parent.get(identity)

    def successors_of(self, identity: ManifestIdentity) -> List[ManifestIdentity]:
        return list(self._children.get(identity, ()))

    def _is_ancestor(self, candidate: ManifestIdentity, of: ManifestIdentity) -> bool:
        """Walk upward with a revisit guard, so corrupted state cannot loop forever."""
        seen: Set[ManifestIdentity] = set()
        cursor: Optional[ManifestIdentity] = of
        while cursor is not None:
            if cursor == candidate:
                return True
            if cursor in seen:
                return False
            seen.add(cursor)
            cursor = self._parent.get(cursor)
        return False

    def ancestors_of(self, identity: ManifestIdentity) -> List[ManifestIdentity]:
        """
        Full ancestry, nearest first.

        The revisit guard is defence in depth: insertion already rejects cycles, but historical
        corruption or manual database damage must not turn lineage traversal into an infinite walk.
        """
        lineage: List[ManifestIdentity] = []
        seen: Set[ManifestIdentity] = {identity}
        cursor = self._parent.get(identity)
        while cursor is not None:
            if cursor in seen:
                break
            seen.add(cursor)
            lineage.append(cursor)
            cursor = self._parent.get(cursor)
        return lineage
