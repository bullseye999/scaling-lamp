
"""
4.2 Gate Zero - the epistemic ledger.

    EVIDENCE IS DURABLE. BELIEFS ARE PROJECTIONS OVER EVIDENCE.
    CONFIDENCE IS A PROPERTY OF THE PROJECTION, NEVER EVIDENCE ITSELF.

The founding specimen and the anti-echo specimen come first, then one case per law.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.epistemic_ledger import (
    RELATION_CONTEXT_ONLY,
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    BeliefStatus,
    canonical_proposition,
    projection_history,
    project_beliefs,
    reconstruct,
    record_evidence,
    record_model_output,
    record_observation,
)


class TestGate42EpistemicLedger(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-42-epistemic-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.clock = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def proposition(self, subject='server.x', predicate='is_online', value=True, scope=None):
        return canonical_proposition(subject, predicate, value, temporal_scope=scope)

    def observe_and_bear(self, proposition, relation, *, source='source-a', when=None,
                         raw='report text'):
        observation = record_observation(self.db, source_ref=source, raw_text=raw, now=when or self.clock)
        return record_evidence(self.db, proposition, relation=relation, source_ref=source,
                               observation_ref=observation['observation_id'],
                               evidence_time=when or self.clock, now=when or self.clock)

    def belief(self, proposition, *, now=None, stale_after=None):
        return reconstruct(self.db, now=now or self.clock, stale_after=stale_after) \
            .belief_for(proposition.proposition_id)

    def evidence_rows(self):
        with sqlite3.connect(self.db) as conn:
            return conn.execute("SELECT evidence_id, relation FROM ciph_evidence ORDER BY evidence_id").fetchall()

    def digest(self, *, now=None, stale_after=None):
        return reconstruct(self.db, now=now or self.clock, stale_after=stale_after).canonical_digest()

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_specimen_support_then_contradiction(self):
        p = self.proposition()
        e1 = self.observe_and_bear(p, RELATION_SUPPORTS, source='source-a', raw='A says online')
        supported = self.belief(p)
        self.assertEqual(supported.status, BeliefStatus.SUPPORTED.value)
        self.assertEqual(supported.confidence, 1.0)
        self.assertEqual(supported.supporting_evidence, (e1,))

        e2 = self.observe_and_bear(p, RELATION_CONTRADICTS, source='source-b', raw='B says offline')
        contested = self.belief(p)
        self.assertEqual(contested.status, BeliefStatus.CONTESTED.value)
        self.assertEqual(contested.confidence, 0.5)
        self.assertEqual(contested.supporting_evidence, (e1,), "E1 is not deleted by a contradiction")
        self.assertEqual(contested.contradicting_evidence, (e2,), "E2 is not ignored either")

        # Restart: same proposition id, same evidence set, same status, same confidence, same digest.
        before = self.digest()
        fresh = reconstruct(self.db, now=self.clock)
        self.assertEqual(fresh.canonical_digest(), before)
        self.assertEqual(fresh.belief_for(p.proposition_id).status, BeliefStatus.CONTESTED.value)
        self.assertEqual(fresh.belief_for(p.proposition_id).confidence, 0.5)
        self.assertEqual(len(self.evidence_rows()), 2)

    def test_model_repetition_adds_zero_evidence(self):
        """The anti-echo-chamber specimen: restating P is not confirming P."""
        p = self.proposition()
        self.observe_and_bear(p, RELATION_SUPPORTS, source='source-a')
        baseline = self.belief(p)
        evidence_before = self.digest()

        for index in range(10):
            record_model_output(self.db, model_ref='model-primary', output_text=f'P is true ({index})',
                                proposition=p, now=self.clock)

        after = self.belief(p)
        self.assertEqual(after.supporting_evidence, baseline.supporting_evidence)
        self.assertEqual(after.confidence, baseline.confidence,
                         "no amount of restatement may raise confidence")
        self.assertEqual(after.status, baseline.status)
        self.assertEqual(self.digest(), evidence_before,
                         "model outputs are not evidence, so the epistemic state is unchanged")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ciph_model_outputs").fetchone()[0], 10,
                             "the outputs are still recorded, as audit facts")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ciph_evidence").fetchone()[0], 1)

    # ------------------------------------------------------------------ laws 1, 2, 3
    def test_law_1_receiving_text_is_not_a_claim(self):
        observation = record_observation(self.db, source_ref='feed-x', raw_text='the reactor is stable',
                                         now=self.clock)
        state = reconstruct(self.db, now=self.clock)
        self.assertEqual(state.evidence_count, 0)
        self.assertEqual(state.propositions, (), "an observation asserts nothing on its own")
        self.assertTrue(observation['content_digest'])

    def test_law_2_and_3_a_source_asserting_p_does_not_make_it_believed_or_true(self):
        p = self.proposition()
        self.observe_and_bear(p, RELATION_SUPPORTS, source='loud-source')
        belief = self.belief(p)
        self.assertEqual(belief.status, BeliefStatus.SUPPORTED.value)
        self.assertNotIn('FACT', belief.status, "there is no FACT status to promote into")
        self.assertLessEqual(belief.confidence, 1.0)
        # Confidence is a number about the projection, and the proposition is still only a projection.
        state = reconstruct(self.db, now=self.clock)
        self.assertEqual(len(state.propositions), 1)
        self.assertEqual(len(state.beliefs), 1)

    # ------------------------------------------------------------------ laws 5, 7
    def test_law_5_and_7_history_is_append_only_and_contradiction_is_first_class(self):
        p = self.proposition()
        e1 = self.observe_and_bear(p, RELATION_SUPPORTS, source='a')
        e2 = self.observe_and_bear(p, RELATION_CONTRADICTS, source='b')
        e3 = self.observe_and_bear(p, RELATION_CONTRADICTS, source='c')

        belief = self.belief(p)
        self.assertEqual(belief.status, BeliefStatus.CONTESTED.value)
        self.assertEqual(sorted(belief.supporting_evidence), [e1])
        self.assertEqual(sorted(belief.contradicting_evidence), sorted([e2, e3]))
        self.assertAlmostEqual(belief.confidence, 1 / 3, places=12)
        self.assertEqual(len(self.evidence_rows()), 3, "no evidence is ever removed")

        # Last-one-wins would have said REFUTED at 2 contradictions; the ledger says CONTESTED.
        self.assertNotEqual(belief.status, BeliefStatus.REFUTED.value)

    def test_law_5_context_evidence_is_not_support_or_contradiction(self):
        p = self.proposition()
        e_support = self.observe_and_bear(p, RELATION_SUPPORTS, source='a')
        e_context = self.observe_and_bear(p, RELATION_CONTEXT_ONLY, source='c', raw='background note')
        belief = self.belief(p)
        self.assertEqual(belief.supporting_evidence, (e_support,))
        self.assertEqual(belief.context_evidence, (e_context,))
        self.assertEqual(belief.contradicting_evidence, ())
        self.assertEqual(belief.confidence, 1.0, "context changes nothing about support")

    # ------------------------------------------------------------------ laws 6, 12
    def test_law_6_belief_state_is_reconstructible_without_the_projection(self):
        p = self.proposition()
        self.observe_and_bear(p, RELATION_SUPPORTS, source='a')
        self.observe_and_bear(p, RELATION_CONTRADICTS, source='b', when=self.clock + 1)
        project_beliefs(self.db, now=self.clock)
        with_projection = self.digest()

        with sqlite3.connect(self.db) as conn:
            conn.execute("DELETE FROM ciph_belief_projections")
        self.assertEqual(self.digest(), with_projection,
                         "beliefs are projections over evidence, so deleting them changes nothing")
        projection = project_beliefs(self.db, now=self.clock)
        self.assertEqual(projection['projections_appended'], 1, "the same projection is re-derived")
        self.assertEqual(self.digest(), with_projection)

    def test_law_12_previous_projections_remain_historical(self):
        p = self.proposition()
        self.observe_and_bear(p, RELATION_SUPPORTS, source='a')
        project_beliefs(self.db, now=self.clock)
        self.observe_and_bear(p, RELATION_CONTRADICTS, source='b', when=self.clock + 1)
        project_beliefs(self.db, now=self.clock + 1)

        history = projection_history(self.db, p.proposition_id)
        self.assertEqual([h['projection_version'] for h in history], [1, 2])
        self.assertEqual(history[0]['status'], BeliefStatus.SUPPORTED.value,
                         "the earlier epistemic state is history, not a mistake to be corrected")
        self.assertEqual(history[1]['status'], BeliefStatus.CONTESTED.value)
        self.assertEqual(history[0]['confidence'], 1.0)
        self.assertEqual(history[1]['confidence'], 0.5)

    # ------------------------------------------------------------------ laws 8, 9, 11
    def test_law_8_absence_of_support_is_not_refutation(self):
        p = self.proposition()
        record_model_output(self.db, model_ref='m', output_text='I do not know', proposition=p,
                            now=self.clock)
        belief = self.belief(p)
        self.assertEqual(belief.status, BeliefStatus.UNRESOLVED.value)
        self.assertEqual(belief.confidence, 0.0)
        self.assertEqual(belief.contradicting_evidence, ())

    def test_law_9_staleness_is_temporal_not_falsehood(self):
        p = self.proposition()
        e1 = self.observe_and_bear(p, RELATION_SUPPORTS, source='a', when=self.clock - 10_000)
        fresh = self.belief(p, now=self.clock, stale_after=60)
        self.assertEqual(fresh.status, BeliefStatus.STALE.value)
        self.assertEqual(fresh.confidence, 0.0, "stale support is not current support")
        self.assertEqual(fresh.supporting_evidence, (e1,),
                         "it is still support - it has simply stopped being current")
        self.assertEqual(fresh.stale_evidence, (e1,))
        # With no staleness window it is simply supported again: the evidence never changed.
        self.assertEqual(self.belief(p, now=self.clock).status, BeliefStatus.SUPPORTED.value)

    def test_law_9_stale_support_beside_fresh_contradiction(self):
        p = self.proposition()
        self.observe_and_bear(p, RELATION_SUPPORTS, source='a', when=self.clock - 10_000)
        self.observe_and_bear(p, RELATION_CONTRADICTS, source='b', when=self.clock)
        belief = self.belief(p, now=self.clock, stale_after=60)
        self.assertEqual(belief.status, BeliefStatus.REFUTED.value)
        self.assertEqual(belief.confidence, 0.0)

    def test_law_11_unresolved_is_a_valid_standing_answer(self):
        p = self.proposition()
        # The proposition is in the ledger because something referenced it - and then nothing more.
        record_model_output(self.db, model_ref='m', output_text='considering P', proposition=p,
                            now=self.clock)
        for _ in range(3):
            self.assertEqual(self.belief(p).status, BeliefStatus.UNRESOLVED.value)
            self.assertEqual(self.belief(p).confidence, 0.0)
        self.assertEqual(self.digest(), self.digest())

    # ------------------------------------------------------------------ law 10
    def test_law_10_confidence_cannot_create_evidence(self):
        """There is no API that writes a confidence: the only way to change one is to add a link."""
        import inspect
        from ciph.kernel import epistemic_ledger
        public = [name for name, _ in inspect.getmembers(epistemic_ledger, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('set_confidence', 'update_belief', 'adjust_confidence', 'promote_to_fact'):
            self.assertNotIn(forbidden, public)
        p = self.proposition()
        record_model_output(self.db, model_ref='m', output_text='considering P', proposition=p,
                            now=self.clock)
        before = self.belief(p)
        self.assertEqual(before.status, BeliefStatus.UNRESOLVED.value)
        self.assertEqual(before.confidence, 0.0)
        e1 = self.observe_and_bear(p, RELATION_SUPPORTS, source='a')
        after = self.belief(p)
        self.assertEqual(after.confidence, 1.0)
        self.assertEqual(after.supporting_evidence, (e1,),
                         "the only thing that moved the score is the link behind it")

    # ------------------------------------------------------------------ proposition identity
    def test_proposition_identity_includes_temporal_scope(self):
        now_p = self.proposition(scope='AT:2026-10-08T14:03Z')
        untimed = self.proposition(scope=None)
        later = self.proposition(scope='AT:2026-10-08T15:00Z')
        self.assertNotEqual(now_p.proposition_id, untimed.proposition_id)
        self.assertNotEqual(now_p.proposition_id, later.proposition_id)

        # And the same meaning is the same id, however it was built.
        rebuilt = canonical_proposition('server.x', 'is_online', True, temporal_scope='AT:2026-10-08T14:03Z')
        self.assertEqual(rebuilt.proposition_id, now_p.proposition_id)

        self.observe_and_bear(now_p, RELATION_SUPPORTS, source='a')
        self.observe_and_bear(later, RELATION_CONTRADICTS, source='b')
        state = reconstruct(self.db, now=self.clock)
        self.assertEqual(len(state.propositions), 2, "two propositions, not one merged one")
        self.assertEqual(state.belief_for(now_p.proposition_id).status, BeliefStatus.SUPPORTED.value)
        self.assertEqual(state.belief_for(later.proposition_id).status, BeliefStatus.REFUTED.value)

    # ------------------------------------------------------------------ the Gate Zero seal
    def test_the_seal_same_evidence_history_same_digest_across_restart_and_process(self):
        p = self.proposition()
        self.observe_and_bear(p, RELATION_SUPPORTS, source='a')
        self.observe_and_bear(p, RELATION_CONTRADICTS, source='b', when=self.clock + 5)
        self.observe_and_bear(p, RELATION_CONTEXT_ONLY, source='c', when=self.clock + 6)
        record_model_output(self.db, model_ref='m', output_text='P seems true', proposition=p,
                            now=self.clock + 7)
        expected = self.digest()
        self.assertEqual(reconstruct(self.db, now=self.clock).canonical_digest(), expected)

        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.epistemic_ledger import reconstruct;"
                "print(reconstruct(%r, now=%r).canonical_digest())"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.clock))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected,
                         "a second process over the same evidence must agree exactly")

        # And a different CLOCK is explicitly a different (honest) projection, not a leak of one.
        self.assertNotEqual(reconstruct(self.db, now=self.clock + 10_000, stale_after=60)
                            .canonical_digest(), expected)

    def test_projection_digest_changes_only_when_the_evidence_does(self):
        p = self.proposition()
        self.observe_and_bear(p, RELATION_SUPPORTS, source='a')
        project_beliefs(self.db, now=self.clock)
        digest = self.digest()
        for _ in range(5):
            project_beliefs(self.db, now=self.clock)
            self.assertEqual(self.digest(), digest)
        self.assertEqual(len(projection_history(self.db, p.proposition_id)), 1,
                         "an unchanged projection is not re-versioned")


if __name__ == '__main__':
    unittest.main()
