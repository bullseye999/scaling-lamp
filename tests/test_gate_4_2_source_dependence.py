
"""
4.2 Gate One - source dependence.

The question is not "are these five different websites?" It is:

    how many epistemically independent observations are actually represented?

The founding specimen is the one that motivated the gate, and the hostile one is the reason it exists.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    BeliefStatus,
    canonical_proposition,
    reconstruct as reconstruct_beliefs,
    record_evidence,
    record_model_output,
    record_observation,
)
from ciph.kernel.source_dependence import (
    DEPENDENCE_PROVEN_DEPENDENT,
    DEPENDENCE_PROVEN_INDEPENDENT,
    DEPENDENCE_UNKNOWN,
    INTEGRITY_PROVENANCE_CYCLE,
    METRIC_ID,
    RELATION_COPIED_FROM,
    RELATION_QUOTES,
    RELATION_PRIMARY_OBSERVATION,
    RELATION_SYNDICATED_FROM,
    project_all,
    project_source_dependence,
    projection_history,
    record_projection,
    record_provenance,
    record_similarity_hypothesis,
)


class TestGate42SourceDependence(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-42-source-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.clock = 1_800_000_000.0
        self.proposition = canonical_proposition('reactor.unit-3', 'is_stable', True)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def link(self, relation=RELATION_SUPPORTS, source='source', raw='report'):
        observation = record_observation(self.db, source_ref=source, raw_text=raw, now=self.clock)
        return record_evidence(self.db, self.proposition, relation=relation, source_ref=source,
                               observation_ref=observation['observation_id'], evidence_time=self.clock,
                               now=self.clock)

    def depend(self, child, parent, relation=RELATION_SYNDICATED_FROM):
        return record_provenance(self.db, from_evidence=child, relation=relation,
                                 to_evidence=parent, now=self.clock)

    def project(self, proposition_id=None):
        return project_source_dependence(self.db, proposition_id or self.proposition.proposition_id,
                                         now=self.clock)

    def ledger_confidence(self):
        belief = reconstruct_beliefs(self.db, now=self.clock).belief_for(self.proposition.proposition_id)
        return belief

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_reuters_specimen(self):
        # Gate Zero's view: five supporting links, all real, none deleted.
        reuters = self.link(source='reuters.com', raw='Reuters: unit-3 stable')
        site_a = self.link(source='site-a.example', raw='A: unit-3 stable')
        site_b = self.link(source='site-b.example', raw='B: "unit-3 stable" — Reuters')
        site_c = self.link(source='site-c.example', raw='C: unit-3 stable')
        site_d = self.link(source='site-d.example', raw='D: unit-3 stable')

        # Gate One's view: A quotes Reuters, B quotes Reuters, C copied A, D syndicated Reuters.
        self.depend(site_a, reuters, RELATION_SYNDICATED_FROM)
        self.depend(site_b, reuters, RELATION_QUOTES)
        self.depend(site_c, site_a, RELATION_COPIED_FROM)
        self.depend(site_d, reuters, RELATION_SYNDICATED_FROM)

        gate_zero = self.ledger_confidence()
        self.assertEqual(len(gate_zero.supporting_evidence), 5,
                         "Gate Zero legitimately sees five supporting links")
        self.assertEqual(gate_zero.confidence, 1.0, "and Gate Zero's metric is untouched by Gate One")

        projection = self.project()
        self.assertEqual(len(projection.support_families), 1,
                         "five articles from one origin are ONE witness")
        self.assertEqual(projection.support_families[0].members,
                         tuple(sorted([reuters, site_a, site_b, site_c, site_d])),
                         "and every dependent link is still in the ledger")
        self.assertEqual((projection.independent_support_min, projection.independent_support_max), (1, 1))
        self.assertEqual(projection.dependence_status, DEPENDENCE_PROVEN_DEPENDENT)

        # An independent primary source: now there are two.
        primary = self.link(source='firsthand.example', raw='our own seismograph reading')
        record_provenance(self.db, from_evidence=primary, relation=RELATION_PRIMARY_OBSERVATION,
                          now=self.clock)
        two = self.project()
        self.assertEqual((two.independent_support_min, two.independent_support_max), (2, 2))
        self.assertEqual(two.dependence_status, DEPENDENCE_PROVEN_INDEPENDENT)

        # A blog with unresolved provenance: bounds widen to [2, 3], never silently to 3.
        unknown = self.link(source='blog.example', raw='a blog agrees')
        widened = self.project()
        self.assertEqual((widened.independent_support_min, widened.independent_support_max), (2, 3))
        self.assertEqual(widened.dependence_status, DEPENDENCE_UNKNOWN)
        # NOTE on the frozen formula: with support uncertainty on ONE side and no contradiction at
        # all, the ratio is 1.0 at both bounds - there is nothing on the other side to widen against.
        # The honest signal here is the BOUNDS (2..3), not the interval. Uncertainty shows up in the
        # interval the moment there is opposition, which is what the hostile specimen demonstrates.
        self.assertEqual(widened.interval(), (1.0, 1.0))
        self.assertEqual(len(widened.support_families), 3)
        self.assertEqual(widened.evidence_count, 7)

    # ------------------------------------------------------------------ the hostile case
    def test_hostile_five_mirrors_cannot_outvote_one_independent_contradiction(self):
        reuters = self.link(source='reuters.com')
        mirrors = [self.link(source=f'mirror-{i}.example') for i in range(4)]
        for mirror in mirrors:
            self.depend(mirror, reuters, RELATION_SYNDICATED_FROM)
        primary = self.link(RELATION_CONTRADICTS, source='firsthand.example')
        record_provenance(self.db, from_evidence=primary, relation=RELATION_PRIMARY_OBSERVATION,
                          now=self.clock)

        gate_zero = self.ledger_confidence()
        self.assertEqual(len(gate_zero.supporting_evidence), 5, "raw evidence is noisier but real")
        self.assertAlmostEqual(gate_zero.confidence, 5 / 6, places=12,
                              msg="Gate Zero's number is what it always was")

        projection = self.project()
        self.assertEqual(projection.independent_support_min, 1)
        self.assertEqual(projection.independent_support_max, 1)
        self.assertEqual(projection.independent_contradict_min, 1)
        self.assertEqual(projection.independent_contradict_max, 1)
        self.assertEqual(projection.interval(), (0.5, 0.5),
                         "one independent witness against one independent witness is genuinely contested")
        self.assertEqual(projection.dependence_status, DEPENDENCE_PROVEN_INDEPENDENT)

        # Now add a contradiction whose provenance is unresolved: the interval becomes an interval.
        self.link(RELATION_CONTRADICTS, source='opaque-critic.example')
        widened = self.project()
        self.assertEqual((widened.independent_contradict_min, widened.independent_contradict_max), (1, 2))
        lower, upper = widened.interval()
        self.assertLess(lower, upper,
                        "unresolved provenance becomes epistemic uncertainty rather than a point estimate")
        self.assertAlmostEqual(lower, 1 / 3, places=12)
        self.assertAlmostEqual(upper, 1 / 2, places=12)
        self.assertEqual(widened.dependence_status, DEPENDENCE_UNKNOWN)

    # ------------------------------------------------------------------ laws 1, 2, 3
    def test_law_1_different_domains_are_not_different_witnesses(self):
        parent = self.link(source='origin-one.example')
        children = [self.link(source=f'unrelated-domain-{i}.example') for i in range(4)]
        for child in children:
            self.depend(child, parent, RELATION_COPIED_FROM)
        projection = self.project()
        self.assertEqual(len(projection.support_families), 1,
                         "four unrelated domains, one origin, one witness")
        self.assertEqual(projection.independent_support_max, 1)

    def test_law_2_one_publisher_can_produce_independent_observations(self):
        first = self.link(source='same-publisher.example', raw='first measurement at 12:00')
        second = self.link(source='same-publisher.example', raw='second measurement at 18:00')
        record_provenance(self.db, from_evidence=first, relation='INDEPENDENCE_PROVEN',
                          to_evidence=second, now=self.clock)
        projection = self.project()
        self.assertEqual((projection.independent_support_min, projection.independent_support_max), (2, 2),
                         "same source identity, proven independent observations")
        self.assertEqual(len(projection.support_families), 2)

    def test_law_3_proven_relays_do_not_multiply_corroboration(self):
        chain = [self.link(source=f'relayer-{i}.example') for i in range(3)]
        self.depend(chain[1], chain[0], RELATION_QUOTES)
        self.depend(chain[2], chain[1], RELATION_QUOTES)
        projection = self.project()
        self.assertEqual(len(projection.support_families), 1)
        self.assertEqual((projection.independent_support_min, projection.independent_support_max), (1, 1),
                         "a relay chain preserves history and adds no witness")

    # ------------------------------------------------------------------ law 4
    def test_law_4_unknown_provenance_is_never_counted_as_independent(self):
        for index in range(5):
            self.link(source=f'opaque-{index}.example')
        projection = self.project()
        self.assertEqual(projection.independent_support_min, 0,
                         "nothing is proven independent, so the lower bound is zero")
        self.assertEqual(projection.independent_support_max, 5)
        self.assertEqual(projection.interval(), (0.0, 1.0))
        self.assertEqual(projection.dependence_status, DEPENDENCE_UNKNOWN)

    # ------------------------------------------------------------------ laws 5, 6
    def test_law_5_and_6_grouping_deletes_nothing_and_changes_no_polarity(self):
        parent = self.link(source='origin.example')
        child = self.link(source='child.example')
        self.depend(child, parent)
        before = reconstruct_beliefs(self.db, now=self.clock).canonical_digest()
        projection = self.project()

        self.assertEqual(projection.evidence_count, 2)
        self.assertTrue(all("SUPPORTS" in family.polarities for family in projection.support_families))
        self.assertEqual(projection.contradiction_families, ())
        after = reconstruct_beliefs(self.db, now=self.clock)
        self.assertEqual(after.canonical_digest(), before,
                         "recording provenance must not touch the Gate Zero ledger")
        belief = after.belief_for(self.proposition.proposition_id)
        self.assertEqual(belief.status, BeliefStatus.SUPPORTED.value)
        self.assertEqual(len(belief.supporting_evidence), 2,
                         "the dependent link is still a real evidence link")
        self.assertEqual(belief.confidence, 1.0)

    # ------------------------------------------------------------------ laws 7, 8
    def test_law_7_and_8_similarity_and_model_assertions_cannot_create_edges(self):
        first = self.link(source='a.example', raw='the reactor is stable today')
        second = self.link(source='b.example', raw='the reactor is stable today')
        no_provenance = self.project()
        self.assertEqual(no_provenance.independent_support_min, 0)

        record_similarity_hypothesis(self.db, evidence_a=first, evidence_b=second,
                                     claim='POSSIBLE_COMMON_ORIGIN', model_ref='similarity-model',
                                     now=self.clock)
        record_model_output(self.db, model_ref='reasoner', output_text='these look like the same story',
                            proposition=self.proposition, now=self.clock)

        after = self.project()
        self.assertEqual(after.hypothesis_count, 1, "the hypothesis is recorded")
        self.assertEqual(len(after.support_families), 2, "but it creates no provenance family link")
        self.assertEqual((after.independent_support_min, after.independent_support_max), (0, 2))
        self.assertEqual(after.provenance_only_digest(), no_provenance.provenance_only_digest(),
                         "a model's suspicion cannot move the PROVENANCE picture")
        # The full projection identity does move, because 'there is one thing to investigate' is part
        # of the record. That is a fact about our open questions, not about the world.
        self.assertNotEqual(after.canonical_digest(), no_provenance.canonical_digest())
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ciph_provenance_edges").fetchone()[0], 0,
                             "and it created no provenance edge")

    # ------------------------------------------------------------------ law 9
    def test_law_9_contradictions_are_grouped_symmetrically(self):
        origin = self.link(RELATION_CONTRADICTS, source='origin.example')
        mirrors = [self.link(RELATION_CONTRADICTS, source=f'mirror-{i}.example') for i in range(9)]
        for mirror in mirrors:
            self.depend(mirror, origin, RELATION_SYNDICATED_FROM)
        projection = self.project()
        self.assertEqual(len(projection.contradiction_families), 1,
                         "ten dependent contradictions are one contradiction")
        self.assertEqual(projection.independent_contradict_min, 1)
        self.assertEqual(projection.independent_contradict_max, 1)
        self.assertEqual(projection.support_families, ())
        self.assertEqual(projection.interval(), (0.0, 0.0))

    # ------------------------------------------------------------------ law 10
    def test_law_10_provenance_history_is_append_only(self):
        parent = self.link(source='origin.example')
        child = self.link(source='child.example')
        record_projection(self.db, self.project())
        self.assertEqual(self.project().independent_support_min, 0)

        self.depend(child, parent, RELATION_COPIED_FROM)
        updated = self.project()
        self.assertEqual(len(updated.support_families), 1)
        record_projection(self.db, updated)

        history = projection_history(self.db, self.proposition.proposition_id)
        self.assertEqual([h['projection_version'] for h in history], [1, 2])
        self.assertEqual(history[0]['independent_support_max'], 2,
                         "the earlier projection is history, not a mistake to be corrected")
        self.assertEqual(history[1]['independent_support_max'], 1)
        self.assertTrue(all(h['metric_id'] == METRIC_ID for h in history))
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ciph_provenance_edges").fetchone()[0], 1,
                             "no provenance fact was rewritten")

    # ------------------------------------------------------------------ law 11
    def test_law_11_a_cycle_is_one_component_and_an_integrity_condition(self):
        first = self.link(source='a.example')
        second = self.link(source='b.example')
        self.depend(first, second, RELATION_QUOTES)     # A cites B
        self.depend(second, first, RELATION_QUOTES)     # B cites A
        projection = self.project()
        self.assertEqual(len(projection.support_families), 1,
                         "mutual citation is one dependent component, not two witnesses")
        self.assertEqual((projection.independent_support_min, projection.independent_support_max), (1, 1))
        self.assertTrue(any(flag.startswith(INTEGRITY_PROVENANCE_CYCLE)
                            for flag in projection.integrity_flags), projection.integrity_flags)

    def test_a_claim_of_independence_against_proven_ancestry_is_flagged(self):
        parent = self.link(source='origin.example')
        child = self.link(source='child.example')
        self.depend(child, parent, RELATION_COPIED_FROM)
        record_provenance(self.db, from_evidence=child, relation='INDEPENDENCE_PROVEN',
                          to_evidence=parent, now=self.clock)
        projection = self.project()
        self.assertEqual(len(projection.support_families), 1,
                         "the conservative direction wins: proven ancestry keeps one family")
        self.assertTrue(any('PROVENANCE_CONFLICT' in flag for flag in projection.integrity_flags),
                        projection.integrity_flags)

    # ------------------------------------------------------------------ law 12
    def test_law_12_same_graph_same_bounds_same_digest(self):
        parent = self.link(source='origin.example')
        child = self.link(source='child.example')
        self.depend(child, parent)
        self.link(source='independent.example', raw='firsthand')
        self.link(source='opaque.example')
        expected = self.project().canonical_digest()

        again = self.project()
        self.assertEqual(again.canonical_digest(), expected)
        self.assertEqual(project_all(self.db, now=self.clock)[0].canonical_digest(), expected)

        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.source_dependence import project_source_dependence;"
                "print(project_source_dependence(%r, %r, now=%r).canonical_digest())"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.proposition.proposition_id,
                   self.clock))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected,
                         "a second process over the same provenance graph must agree exactly")

    def test_the_projection_is_not_an_input_to_itself(self):
        parent = self.link(source='origin.example')
        child = self.link(source='child.example')
        self.depend(child, parent)
        first = self.project()
        record_projection(self.db, first)
        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM ciph_source_dependence_projections")
        self.assertEqual(self.project().canonical_digest(), first.canonical_digest())

    def test_metric_identity_is_its_own(self):
        """Gate One's metric has its own id, so it can never be mistaken for Gate Zero's confidence."""
        self.link(source='origin.example')
        projection = self.project()
        self.assertEqual(projection.metric_id, METRIC_ID)
        self.assertNotEqual(projection.metric_id, 'BELIEF_CONFIDENCE_V1')
        payload = projection.as_dict()
        self.assertIn('confidence_lower', payload)
        self.assertIn('independent_support_min', payload)
        self.assertTrue(json.dumps(payload))  # serializable record of the projection


if __name__ == '__main__':
    unittest.main()
