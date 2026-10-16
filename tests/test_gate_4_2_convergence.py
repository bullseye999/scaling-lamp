
"""
4.2 Gate Four - epistemic convergence.

The last gate answers: given evidence, source dependence, revision history and unresolved
contradiction, has the proposition actually converged, or is the honest answer still "we do not know"?

There is no FACT status. Convergence is a projection with an explicit policy identity.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.epistemic_convergence import (
    CONVERGENCE_V1,
    REASON_POSSIBLE_CONTRADICTION_BLOCKS,
    STATUS_CONTESTED,
    STATUS_CONVERGED_REFUTED,
    STATUS_CONVERGED_SUPPORTED,
    STATUS_INTEGRITY_BLOCKED,
    STATUS_STALE,
    STATUS_UNRESOLVED,
    VALID_STATUSES,
    apply_policy,
    convergence_digest,
    convergence_history,
    project_convergence,
    record_convergence,
)
from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    canonical_proposition,
    record_evidence,
    record_model_output,
    record_observation,
)
from ciph.kernel.source_dependence import (
    RELATION_COPIED_FROM,
    RELATION_PRIMARY_OBSERVATION,
    RELATION_SYNDICATED_FROM,
    record_provenance,
)


class TestGate42Convergence(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-42-convergence-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.clock = 1_800_000_000.0
        self.p = canonical_proposition('reactor.unit-3', 'is_stable', True)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def link(self, relation=RELATION_SUPPORTS, source='source', when=None):
        moment = when or self.clock
        observation = record_observation(self.db, source_ref=source, raw_text='report', now=moment)
        return record_evidence(self.db, self.p, relation=relation, source_ref=source,
                               observation_ref=observation['observation_id'], evidence_time=moment,
                               now=moment)

    def reuters_family(self, descendants=4, relation=RELATION_SYNDICATED_FROM,
                       polarity=RELATION_SUPPORTS):
        origin = self.link(polarity, source='reuters.example')
        for index in range(descendants):
            child = self.link(polarity, source=f'mirror-{index}.example')
            record_provenance(self.db, from_evidence=child, relation=relation, to_evidence=origin,
                              now=self.clock)
        return origin

    def primary(self, relation=RELATION_SUPPORTS, source='firsthand.example'):
        evidence = self.link(relation, source=source)
        record_provenance(self.db, from_evidence=evidence, relation=RELATION_PRIMARY_OBSERVATION,
                          now=self.clock)
        return evidence

    def project(self, **kwargs):
        return project_convergence(self.db, self.p.proposition_id, now=kwargs.pop('now', self.clock),
                                   **kwargs)

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_convergence_then_reversal_without_rewriting_history(self):
        self.reuters_family()
        self.primary()

        projection = self.project()
        self.assertEqual(projection.status, STATUS_CONVERGED_SUPPORTED)
        self.assertEqual(projection.proven_support_origins, 2)
        self.assertEqual(projection.possible_contradict_origins, 0)
        record_convergence(self.db, self.p.proposition_id, now=self.clock)

        # An INDEPENDENT contradiction arrives.
        self.primary(RELATION_CONTRADICTS, source='independent-critic.example')
        after = self.project(now=self.clock + 60)
        self.assertEqual(after.proven_support_origins, 2)
        self.assertEqual(after.proven_contradict_origins, 1)
        self.assertEqual(after.status, STATUS_CONTESTED)
        record_convergence(self.db, self.p.proposition_id, now=self.clock + 60)

        history = convergence_history(self.db, self.p.proposition_id)
        self.assertEqual([h['status'] for h in history],
                         [STATUS_CONVERGED_SUPPORTED, STATUS_CONTESTED],
                         "the earlier judgement was correct given what was known then")
        self.assertTrue(all(h['policy_id'] == CONVERGENCE_V1 for h in history))

    # ------------------------------------------------------------------ the hostile specimen
    def test_hostile_mirrors_never_outvote_an_independent_contradiction(self):
        self.reuters_family(descendants=4)
        self.primary(RELATION_CONTRADICTS, source='independent-critic.example')

        projection = self.project()
        self.assertEqual(projection.proven_support_origins, 1)
        self.assertEqual(projection.proven_contradict_origins, 1)
        self.assertEqual(projection.status, STATUS_CONTESTED)
        self.assertNotEqual(projection.status, STATUS_CONVERGED_SUPPORTED,
                            "five dependent reports are not five witnesses")

    def test_dependent_copies_do_not_manufacture_convergence(self):
        self.reuters_family(descendants=9)
        projection = self.project()
        self.assertEqual(projection.proven_support_origins, 1)
        self.assertEqual(projection.status, STATUS_UNRESOLVED,
                         "one origin, however loud, is not convergence")
        self.assertIn('NO_PROVEN_ORIGINS', projection.reason_codes)

    # ------------------------------------------------------------------ unknown provenance blocks
    def test_unknown_provenance_blocks_convergence(self):
        self.primary(source='firsthand-a.example')
        self.primary(source='firsthand-b.example')
        self.assertEqual(self.project().status, STATUS_CONVERGED_SUPPORTED)

        # A contradiction whose provenance is unresolved: possible, unproven.
        self.link(RELATION_CONTRADICTS, source='opaque.example')
        blocked = self.project()
        self.assertEqual(blocked.proven_contradict_origins, 0)
        self.assertEqual(blocked.possible_contradict_origins, 1)
        self.assertEqual(blocked.status, STATUS_UNRESOLVED,
                         "an unproven contradiction still blocks a claim of convergence")
        self.assertIn(REASON_POSSIBLE_CONTRADICTION_BLOCKS, blocked.reason_codes)

    # ------------------------------------------------------------------ integrity
    def test_integrity_conflict_always_blocks(self):
        origin = self.link(source='origin.example')
        child = self.link(source='child.example')
        record_provenance(self.db, from_evidence=child, relation=RELATION_COPIED_FROM,
                          to_evidence=origin, now=self.clock)
        record_provenance(self.db, from_evidence=child, relation='INDEPENDENCE_PROVEN',
                          to_evidence=origin, now=self.clock)
        projection = self.project()
        self.assertEqual(projection.status, STATUS_INTEGRITY_BLOCKED)
        self.assertNotEqual(projection.status, STATUS_CONVERGED_SUPPORTED)
        self.assertTrue(projection.reason_codes)

    # ------------------------------------------------------------------ symmetry, staleness
    def test_support_and_contradiction_are_symmetric(self):
        self.primary(source='critic-a.example', relation=RELATION_CONTRADICTS)
        self.primary(source='critic-b.example', relation=RELATION_CONTRADICTS)
        projection = self.project()
        self.assertEqual(projection.proven_contradict_origins, 2)
        self.assertEqual(projection.status, STATUS_CONVERGED_REFUTED)

    def test_stale_is_not_refuted(self):
        self.link(source='old.example', when=self.clock - 10_000)
        projection = project_convergence(self.db, self.p.proposition_id, now=self.clock,
                                         stale_after=60)
        self.assertEqual(projection.status, STATUS_STALE)
        self.assertNotEqual(projection.status, STATUS_CONVERGED_REFUTED)
        self.assertIn('ALL_EVIDENCE_STALE', projection.reason_codes)

    # ------------------------------------------------------------------ laws 1, 2, 11
    def test_no_promotion_to_fact_exists(self):
        self.assertNotIn('FACT', VALID_STATUSES)
        import inspect
        from ciph.kernel import epistemic_convergence
        public = [name for name, _ in inspect.getmembers(epistemic_convergence, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('promote_to_fact', 'declare_fact', 'set_status', 'converge'):
            self.assertNotIn(forbidden, public)
        # Even the strongest policy outcome is a projection, not a truth claim.
        self.reuters_family()
        self.primary()
        self.assertEqual(self.project().status, STATUS_CONVERGED_SUPPORTED)
        self.assertEqual(self.project().policy_id, CONVERGENCE_V1)

    def test_law_2_raw_counts_do_not_determine_convergence(self):
        """Six raw supporting links, one proven origin: the policy must not be fooled by volume."""
        self.reuters_family(descendants=5)
        self.assertEqual(self.project().status, STATUS_UNRESOLVED)
        # Two independent origins, by contrast, do converge.
        self.primary()
        self.assertEqual(self.project().status, STATUS_CONVERGED_SUPPORTED)

    def test_law_11_model_confidence_cannot_force_convergence(self):
        self.reuters_family()
        before = self.project()
        for index in range(5):
            record_model_output(self.db, model_ref='reasoner',
                                output_text=f'I am confident P holds ({index})',
                                proposition=self.p, now=self.clock + index)
        after = self.project(now=self.clock + 10)
        self.assertEqual(after.status, before.status)
        self.assertEqual(after.proven_support_origins, before.proven_support_origins)
        self.assertEqual(after.basis_digest, before.basis_digest,
                         "model output is not evidence and cannot move the convergence basis")

    def test_the_policy_is_a_pure_function(self):
        """The frozen policy can be read and tested without any storage."""
        self.assertEqual(apply_policy(belief_status='SUPPORTED', integrity=False, proven_support=2,
                                      possible_support=2, proven_contradict=0, possible_contradict=0,
                                      evidence_count=2)[0], STATUS_CONVERGED_SUPPORTED)
        self.assertEqual(apply_policy(belief_status='SUPPORTED', integrity=False, proven_support=2,
                                      possible_support=2, proven_contradict=0, possible_contradict=1,
                                      evidence_count=3)[0], STATUS_UNRESOLVED)
        self.assertEqual(apply_policy(belief_status='CONTESTED', integrity=False, proven_support=2,
                                      possible_support=2, proven_contradict=1, possible_contradict=1,
                                      evidence_count=3)[0], STATUS_CONTESTED)
        self.assertEqual(apply_policy(belief_status='STALE', integrity=False, proven_support=9,
                                      possible_support=9, proven_contradict=0, possible_contradict=0,
                                      evidence_count=9)[0], STATUS_STALE)
        self.assertEqual(apply_policy(belief_status='SUPPORTED', integrity=True, proven_support=9,
                                      possible_support=9, proven_contradict=0, possible_contradict=0,
                                      evidence_count=9)[0], STATUS_INTEGRITY_BLOCKED)
        self.assertEqual(apply_policy(belief_status='UNRESOLVED', integrity=False, proven_support=0,
                                      possible_support=0, proven_contradict=0, possible_contradict=0,
                                      evidence_count=0)[0], STATUS_UNRESOLVED)

    # ------------------------------------------------------------------ determinism
    def test_law_12_convergence_digest_is_stable_across_restart_and_process(self):
        self.reuters_family()
        self.primary()
        self.primary(RELATION_CONTRADICTS, source='critic.example')
        expected = convergence_digest(self.db, now=self.clock)
        self.assertEqual(convergence_digest(self.db, now=self.clock), expected)

        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.epistemic_convergence import convergence_digest;"
                "print(convergence_digest(%r, now=%r))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.clock))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)

    def test_the_projection_is_not_an_input_to_itself(self):
        self.reuters_family()
        self.primary()
        first = self.project()
        record_convergence(self.db, self.p.proposition_id, now=self.clock)
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM ciph_convergence_projections")
        self.assertEqual(self.project().canonical_digest(), first.canonical_digest())
        self.assertTrue(json.dumps(first.as_dict()))


if __name__ == '__main__':
    unittest.main()
