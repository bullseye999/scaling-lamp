"""
Gate A0 closure test - manifest lineage parentage rules.

Branching is allowed, merging is not, cycles are not, and edges are immutable. The traversal guard
is tested against deliberately corrupted state, because defence in depth that is never exercised is
just a comment.
"""

import unittest

from ciph.kernel.manifest_identity import ManifestIdentity
from ciph.kernel.manifest_lineage import (
    REASON_MANIFEST_HASH_V2_ADOPTION,
    LineageError,
    ManifestLineage,
)

A = ManifestIdentity(2, "HA")
B = ManifestIdentity(2, "HB")
C = ManifestIdentity(2, "HC")


class ManifestLineageTests(unittest.TestCase):

    def setUp(self):
        self.lineage = ManifestLineage()

    def _record(self, predecessor, successor, reason=REASON_MANIFEST_HASH_V2_ADOPTION):
        return self.lineage.record(predecessor, successor, reason)

    def test_self_transition_is_forbidden(self):
        with self.assertRaises(LineageError) as caught:
            self._record(A, A)
        self.assertEqual(caught.exception.reason, "SELF_TRANSITION_FORBIDDEN")

    def test_same_hash_different_version_is_not_a_self_transition(self):
        """Version is identity, so a V1 to V2 move with the same hash string is a real transition."""
        v1 = ManifestIdentity(1, "HSAME")
        v2 = ManifestIdentity(2, "HSAME")
        transition = self.lineage.record(v1, v2, REASON_MANIFEST_HASH_V2_ADOPTION)
        self.assertEqual(transition.predecessor, v1)
        self.assertEqual(transition.successor, v2)

    def test_branching_is_allowed(self):
        """Two successors may descend from one historical capability."""
        self._record(A, B)
        self._record(A, C)
        self.assertEqual(set(self.lineage.successors_of(A)), {B, C})

    def test_merging_is_forbidden(self):
        self._record(A, C)
        with self.assertRaises(LineageError) as caught:
            self._record(B, C)
        self.assertEqual(caught.exception.reason, "MULTIPLE_PREDECESSORS_FORBIDDEN")
        self.assertEqual(self.lineage.predecessor_of(C), A)

    def test_recording_the_same_edge_twice_is_refused(self):
        self._record(A, B)
        with self.assertRaises(LineageError) as caught:
            self._record(A, B)
        self.assertEqual(caught.exception.reason, "TRANSITION_ALREADY_RECORDED")

    def test_cycles_are_forbidden(self):
        self._record(A, B)
        with self.assertRaises(LineageError) as caught:
            self._record(B, A)
        self.assertEqual(caught.exception.reason, "CYCLE_FORBIDDEN")

    def test_longer_cycles_are_forbidden(self):
        self._record(A, B)
        self._record(B, C)
        with self.assertRaises(LineageError) as caught:
            self._record(C, A)
        self.assertEqual(caught.exception.reason, "CYCLE_FORBIDDEN")

    def test_ancestry_is_ordered_nearest_first(self):
        self._record(A, B)
        self._record(B, C)
        self.assertEqual(self.lineage.ancestors_of(C), [B, A])
        self.assertEqual(self.lineage.ancestors_of(A), [])

    def test_traversal_terminates_on_corrupted_cyclic_state(self):
        """
        Defence in depth. Insertion rejects cycles, but manually damaged state must not hang.
        """
        self._record(A, B)
        self._record(B, C)
        self.lineage._parent[A] = C          # inject a cycle the public API would refuse
        self.assertEqual(self.lineage.ancestors_of(C), [B, A])

    def test_transition_records_are_immutable(self):
        transition = self._record(A, B)
        with self.assertRaises(Exception):
            transition.successor = C


if __name__ == "__main__":
    unittest.main()
