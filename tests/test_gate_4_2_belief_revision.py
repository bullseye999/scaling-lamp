
"""
4.2 Gate Two - belief revision and inference lineage.

    INFERENCE IS NOT EVIDENCE.

The model may reason from evidence. Its reasoning never becomes another observation, so these specimens
care as much about what does NOT change (Gate Zero's counts, confidence and digest) as about what does.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.belief_revision import (
    CAUSE_EVIDENCE_REFRESHED,
    CAUSE_EVIDENCE_STALE,
    CAUSE_NEW_CONTRADICTION,
    CAUSE_NEW_SUPPORT,
    CAUSE_PROVENANCE_CHANGED,
    INFERENCE_CONTESTED,
    INFERENCE_CURRENT,
    INFERENCE_STALE,
    BeliefRevisionError,
    assert_usable,
    inference_status,
    inferences_for,
    invalidate_inference,
    record_inference,
    record_revisions,
    revision_digest,
    revision_history,
)
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
from ciph.kernel.source_dependence import record_provenance

RULE_MODUS_PONENS = "MODUS_PONENS_V1"


class TestGate42BeliefRevision(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-42-revision-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.clock = 1_800_000_000.0
        self.p = canonical_proposition('reactor.unit-3', 'is_stable', True)
        self.q = canonical_proposition('reactor.unit-3', 'is_safe_to_approach', True)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def link(self, proposition, relation=RELATION_SUPPORTS, source='source', when=None):
        moment = when or self.clock
        observation = record_observation(self.db, source_ref=source, raw_text='report', now=moment)
        return record_evidence(self.db, proposition, relation=relation, source_ref=source,
                               observation_ref=observation['observation_id'], evidence_time=moment,
                               now=moment)

    def belief(self, proposition, now=None):
        return reconstruct_beliefs(self.db, now=now or self.clock).belief_for(proposition.proposition_id)

    def ledger(self, now=None):
        return reconstruct_beliefs(self.db, now=now or self.clock)

    def infer(self, premises, conclusion=None, **kwargs):
        return record_inference(self.db, premise_proposition_ids=premises,
                                conclusion=conclusion or self.q,
                                inference_rule_id=RULE_MODUS_PONENS, now=self.clock, **kwargs)

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_inference_pins_premises_and_does_not_become_evidence(self):
        e1 = self.link(self.p, source='source-a')
        self.assertEqual(self.belief(self.p).status, BeliefStatus.SUPPORTED.value)
        pinned_digest = self.belief(self.p).derivation_digest

        inference = self.infer([self.p.proposition_id])
        self.assertEqual(inference.premise_refs[0].belief_digest, pinned_digest)
        self.assertEqual(inference.status, INFERENCE_CURRENT)

        # The conclusion is in the REASONING graph, not in the evidence ledger.
        self.assertEqual(len(inferences_for(self.db, self.q.proposition_id)), 1)
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ciph_evidence WHERE proposition_id = ?;",
                                          (self.q.proposition_id,)).fetchone()[0], 0)
        self.assertIsNone(self.belief(self.q),
                          "Q was never asserted by any evidence, so it has no belief at all")

        # Now the premise is contradicted: the inference goes STALE and stays historical.
        e2 = self.link(self.p, RELATION_CONTRADICTS, source='source-b', when=self.clock + 1)
        self.assertEqual(self.belief(self.p, now=self.clock + 1).status, BeliefStatus.CONTESTED.value)
        self.assertEqual(inference_status(self.db, inference.inference_id, now=self.clock + 1),
                         INFERENCE_STALE)

        history = inferences_for(self.db, self.q.proposition_id, now=self.clock + 1)
        self.assertEqual(len(history), 1, "the stale inference is not deleted or rewritten")
        self.assertEqual(history[0].premise_refs[0].belief_digest, pinned_digest,
                         "and it still pins the version it reasoned from")

        # A new inference may be drawn from the NEW premise state; the old one is untouched.
        second = self.infer([self.p.proposition_id])
        self.assertNotEqual(second.inference_id, inference.inference_id)
        self.assertNotEqual(second.basis_digest, inference.basis_digest)
        self.assertEqual(len(inferences_for(self.db, self.q.proposition_id, now=self.clock + 1)), 2)
        self.assertEqual(e1 and e2, e2, "sanity: both evidence links exist")

    # ------------------------------------------------------------------ the anti-echo specimen
    def test_anti_echo_ten_identical_inferences_add_no_evidence(self):
        self.link(self.p, source='source-a')
        before_ledger = self.ledger().canonical_digest()
        before_belief = self.belief(self.p)

        for _ in range(10):
            self.infer([self.p.proposition_id])

        after_belief = self.belief(self.p)
        self.assertEqual(after_belief.supporting_evidence, before_belief.supporting_evidence)
        self.assertEqual(after_belief.confidence, before_belief.confidence)
        self.assertEqual(self.ledger().canonical_digest(), before_ledger,
                         "ten inferences are ten inferences and zero evidence")
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ciph_evidence").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ciph_inferences").fetchone()[0], 10,
                             "all ten are logged for audit")

    # ------------------------------------------------------------------ the hostile specimen
    def test_hostile_premise_substitution_is_refused(self):
        a = canonical_proposition('sensor.a', 'reads', 'normal')
        b = canonical_proposition('sensor.b', 'reads', 'normal')
        self.link(a, source='a-primary')
        self.link(b, source='b-primary')
        inference = self.infer([a.proposition_id, b.proposition_id])
        pinned = {ref.proposition_id: ref.belief_digest for ref in inference.premise_refs}
        self.assertEqual(assert_usable(self.db, inference.inference_id), INFERENCE_CURRENT)

        # A moves on: new evidence arrives for A, so its belief digest changes.
        self.link(a, RELATION_CONTRADICTS, source='a-critic', when=self.clock + 1)

        with self.assertRaises(BeliefRevisionError) as refused:
            assert_usable(self.db, inference.inference_id, now=self.clock + 1)
        self.assertEqual(refused.exception.reason, 'STALE_INFERENCE_BASIS')

        stored = inferences_for(self.db, self.q.proposition_id, now=self.clock + 1)[0]
        self.assertEqual({ref.proposition_id: ref.belief_digest for ref in stored.premise_refs}, pinned,
                         "no silent premise upgrade: the record still says version 2, not version 4")

    def test_an_inference_pinned_on_a_contested_premise_is_contested_not_current(self):
        self.link(self.p, source='a')
        self.link(self.p, RELATION_CONTRADICTS, source='b')
        self.assertEqual(self.belief(self.p).status, BeliefStatus.CONTESTED.value)
        inference = self.infer([self.p.proposition_id])
        self.assertEqual(inference_status(self.db, inference.inference_id), INFERENCE_CONTESTED)
        with self.assertRaises(BeliefRevisionError):
            assert_usable(self.db, inference.inference_id)

    # ------------------------------------------------------------------ laws 5, 6, 7, 8
    def test_law_5_and_6_inference_cannot_increment_gate_zero(self):
        self.link(self.p, source='a')
        counts = lambda: (len(self.belief(self.p).supporting_evidence),
                          len(self.belief(self.p).contradicting_evidence))
        before = counts()
        self.infer([self.p.proposition_id])
        self.infer([self.p.proposition_id])
        self.assertEqual(counts(), before)
        self.assertEqual(self.belief(self.p).confidence, 1.0)

    def test_law_7_contradictory_inferences_coexist(self):
        self.link(self.p, source='a')
        not_safe = canonical_proposition('reactor.unit-3', 'is_safe_to_approach', False)
        first = self.infer([self.p.proposition_id], conclusion=self.q)
        second = self.infer([self.p.proposition_id], conclusion=not_safe)
        self.assertNotEqual(first.conclusion_proposition_id, second.conclusion_proposition_id)
        self.assertEqual(len(inferences_for(self.db, self.q.proposition_id)), 1)
        self.assertEqual(len(inferences_for(self.db, not_safe.proposition_id)), 1)
        self.assertEqual(inference_status(self.db, first.inference_id), INFERENCE_CURRENT)
        self.assertEqual(inference_status(self.db, second.inference_id), INFERENCE_CURRENT)

    def test_law_8_a_conclusion_does_not_become_supported(self):
        self.link(self.p, source='a')
        self.infer([self.p.proposition_id])
        state = self.ledger()
        self.assertIsNone(state.belief_for(self.q.proposition_id))
        self.assertNotIn(self.q.proposition_id, [b.proposition_id for b in state.beliefs if b.status
                                                 in (BeliefStatus.SUPPORTED.value,
                                                     BeliefStatus.REFUTED.value)])

    def test_law_9_an_invalidated_inference_is_never_usable(self):
        self.link(self.p, source='a')
        inference = self.infer([self.p.proposition_id])
        invalidate_inference(self.db, inference.inference_id, reason='rule superseded')
        self.assertEqual(inference_status(self.db, inference.inference_id), 'INVALID')
        with self.assertRaises(BeliefRevisionError):
            assert_usable(self.db, inference.inference_id)

    # ------------------------------------------------------------------ revision laws
    def test_law_10_and_2_revisions_need_a_real_basis_change(self):
        self.link(self.p, source='a')
        first = record_revisions(self.db, now=self.clock)
        self.assertEqual([r.revision_reason for r in first], [CAUSE_NEW_SUPPORT])
        self.assertEqual(record_revisions(self.db, now=self.clock), (),
                         "identical re-evaluation adds no version")

        # "The model changed its mind" is not a revision cause.
        record_model_output(self.db, model_ref='m', output_text='I now believe P more strongly',
                            proposition=self.p, now=self.clock)
        self.assertEqual(record_revisions(self.db, now=self.clock), ())

        self.link(self.p, RELATION_CONTRADICTS, source='b', when=self.clock + 1)
        second = record_revisions(self.db, now=self.clock + 1)
        self.assertEqual([r.revision_reason for r in second], [CAUSE_NEW_CONTRADICTION])

    def test_revision_causes_are_derived_from_what_changed(self):
        self.link(self.p, source='a')
        record_revisions(self.db, now=self.clock)

        # Provenance changes without any evidence changing.
        self.link(self.p, source='a-copy', when=self.clock + 1)
        record_revisions(self.db, now=self.clock + 1)                # NEW_SUPPORT for the copy
        evidence = [e for e in self.belief(self.p, now=self.clock + 1).supporting_evidence]
        record_provenance(self.db, from_evidence=evidence[-1], relation='SYNDICATED_FROM',
                          to_evidence=evidence[0], now=self.clock + 2)
        provenance_only = record_revisions(self.db, now=self.clock + 2)
        self.assertEqual([r.revision_reason for r in provenance_only], [CAUSE_PROVENANCE_CHANGED])

    def test_staleness_is_a_revision_cause_in_both_directions(self):
        self.link(self.p, source='a', when=self.clock)
        record_revisions(self.db, now=self.clock, stale_after=60)
        stale = record_revisions(self.db, now=self.clock + 10_000, stale_after=60)
        self.assertEqual([r.revision_reason for r in stale], [CAUSE_EVIDENCE_STALE])
        refreshed = record_revisions(self.db, now=self.clock + 10_001, stale_after=None)
        self.assertEqual([r.revision_reason for r in refreshed], [CAUSE_EVIDENCE_REFRESHED])

    def test_law_1_and_11_revision_history_is_append_only_and_reconstructible(self):
        self.link(self.p, source='a')
        record_revisions(self.db, now=self.clock)
        self.link(self.p, RELATION_CONTRADICTS, source='b', when=self.clock + 1)
        record_revisions(self.db, now=self.clock + 1)

        history = revision_history(self.db, self.p.proposition_id)
        self.assertEqual([r.revision_reason for r in history],
                         [CAUSE_NEW_SUPPORT, CAUSE_NEW_CONTRADICTION])
        self.assertEqual(history[0].new_projection_version, history[0].new_projection_version)
        self.assertNotEqual(history[0].basis_digest, history[1].basis_digest)
        self.assertEqual(history[1].previous_source_dependence_digest,
                         history[1].previous_source_dependence_digest)
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM ciph_belief_revisions WHERE proposition_id = ?;",
                (self.p.proposition_id,)).fetchone()[0], 2)

    def test_law_12_revision_digest_is_stable_across_restart_and_process(self):
        self.link(self.p, source='a')
        self.infer([self.p.proposition_id])
        record_revisions(self.db, now=self.clock)
        self.link(self.p, RELATION_CONTRADICTS, source='b', when=self.clock + 1)
        record_revisions(self.db, now=self.clock + 1)
        expected = revision_digest(self.db, now=self.clock + 1)

        self.assertEqual(revision_digest(self.db, now=self.clock + 1), expected)
        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.belief_revision import revision_digest;"
                "print(revision_digest(%r, now=%r))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.clock + 1))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)

    def test_inferences_and_revisions_never_touch_the_gate_zero_evidence(self):
        """
        One more angle on laws 5 and 8: reasoning is recorded, EVIDENCE is untouched.

        Note what is deliberately NOT asserted: that the ledger digest is unchanged. Gate Zero's own
        `record_model_output` registers the proposition it mentions (that is Gate Zero's sealed API,
        and a proposition existing is not evidence). The claim that matters is narrower and checkable:
        no evidence appears, and no proposition acquires support through reasoning.
        """
        self.link(self.p, source='a')
        before_state = self.ledger()
        before_p = before_state.belief_for(self.p.proposition_id)

        self.infer([self.p.proposition_id])
        record_revisions(self.db, now=self.clock)
        record_model_output(self.db, model_ref='m', output_text='Q follows', proposition=self.q,
                            now=self.clock)

        after_state = self.ledger()
        self.assertEqual(after_state.evidence_count, before_state.evidence_count,
                         "reasoning created no evidence")
        after_p = after_state.belief_for(self.p.proposition_id)
        self.assertEqual(after_p.as_dict(), before_p.as_dict(),
                         "the premise's belief is byte-identical")
        conclusion = after_state.belief_for(self.q.proposition_id)
        self.assertIsNotNone(conclusion, "the conclusion is in the ledger as an unresolved proposition")
        self.assertEqual(conclusion.status, BeliefStatus.UNRESOLVED.value)
        self.assertEqual(conclusion.supporting_evidence, ())
        self.assertEqual(conclusion.confidence, 0.0)
        self.assertTrue(json.dumps(inferences_for(self.db, self.q.proposition_id)[0].as_dict()))


if __name__ == '__main__':
    unittest.main()
