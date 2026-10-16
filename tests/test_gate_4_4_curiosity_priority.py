"""
4.4 Gate One - curiosity priority.

    Which uncertainty would actually be USEFUL to reduce?

Novelty is not value and uncertainty is not value. Every specimen is written so a scorer that let the
model's interest in something raise its priority, or that let execution success inflate it, would fail.
"""

import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import curiosity_priority as priority_module
from ciph.kernel.curiosity_learning import (
    BARREN_OUTCOME_PENALTY,
    RESULT_UNCHANGED,
    begin_investigation,
    close_investigation,
    learning_digest,
    outcome_penalty,
)
from ciph.kernel.curiosity_priority import (
    CURIOSITY_PRIORITY_V1,
    COST_BY_KIND,
    RISK_BY_KIND,
    derive_priority,
    prioritise,
    priority_digest,
)
from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs, record_model_output
from ciph.kernel.missions import open_mission
from ciph.kernel.self_model import record_installation
from ciph.kernel.uncertainty_registry import KIND_SELF_MODEL_UNKNOWN, KIND_WORLD_STALE
from ciph.kernel.world_model import world_digest
from curiosity_test_support import converge

SUBJECT = 'service.c'
OTHER = 'service.zz'


class TestGate44CuriosityPriority(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-44-priority-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.late = self.t1 + 10_000_000
        self.stale_after = 1_000

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def seed_mysterious_and_cheap(self):
        """U1: an unverified capability (irrelevant, expensive). U2: a stale fact about SUBJECT."""
        record_installation(self.db, capability_id='osint.identify', module_ref='osint.py',
                            environment_ref='host:a', now=self.t1)
        converge(self.db, SUBJECT, 'health', 'HEALTHY', at=self.t1)
        converge(self.db, OTHER, 'health', 'HEALTHY', at=self.t1)

    def ranked(self, **kwargs):
        return prioritise(self.db, now=kwargs.pop('now', self.late),
                          stale_after=kwargs.pop('stale_after', self.stale_after), **kwargs)

    def by_kind(self, kind):
        return [p for p in self.ranked() if p.source_kind == kind]

    def score_of(self, uncertainty_id):
        return derive_priority(self.db, uncertainty_id, now=self.late,
                               stale_after=self.stale_after).score

    # ------------------------------------------------------------------ the hostile specimen
    def test_hostile_a_cheap_relevant_stale_fact_outranks_a_mysterious_irrelevant_one(self):
        self.seed_mysterious_and_cheap()
        mysterious = self.by_kind(KIND_SELF_MODEL_UNKNOWN)
        stale = self.by_kind(KIND_WORLD_STALE)
        self.assertEqual(len(mysterious), 1)
        self.assertTrue(stale)

        # Irrelevant first: the stale facts score on cost alone, and they already beat the mystery.
        for record in stale:
            self.assertGreater(record.score, mysterious[0].score)

        # Now make ONE of them mission-relevant; it must climb further, and the mystery must not move.
        before_mystery = mysterious[0].score
        target = [r for r in stale if r.uncertainty_id
                  and 'service.c' in (self.subject_of(r.uncertainty_id) or '')][0]
        open_mission(self.db, objective='keep service.c healthy', now=self.late)
        after = self.ranked()
        ranked_ids = [p.uncertainty_id for p in after]
        self.assertLess(ranked_ids.index(target.uncertainty_id),
                        ranked_ids.index(mysterious[0].uncertainty_id),
                        'the cheap, mission-relevant uncertainty must outrank the mystery')
        self.assertEqual(self.score_of(mysterious[0].uncertainty_id), before_mystery,
                         'another uncertainty becoming relevant must not move this one')

    def subject_of(self, uncertainty_id):
        for record in __import__('ciph.kernel.uncertainty_registry',
                                 fromlist=['x']).derive_uncertainties(
                self.db, now=self.late, stale_after=self.stale_after):
            if record.uncertainty_id == uncertainty_id:
                return record.subject
        return None

    # ------------------------------------------------------------------ laws 1 and 2
    def test_law_1_and_2_novelty_and_uncertainty_alone_give_no_priority(self):
        self.seed_mysterious_and_cheap()
        # Nothing in the metric's vocabulary is "novelty" or "interest".
        fields = set(prioritise(self.db, now=self.late, stale_after=self.stale_after)[0].as_dict())
        for forbidden in ('novelty', 'interesting', 'interest', 'curiosity_felt', 'mystery'):
            self.assertNotIn(forbidden, fields)
        parameters = set(inspect.signature(derive_priority).parameters)
        for forbidden in ('novelty', 'interest', 'interesting', 'mystery'):
            self.assertNotIn(forbidden, parameters)

        # A deep, high-mystery uncertainty with no relevance and high cost still ranks low: the
        # unresolved epistemic uncertainty is scored on cost/risk, not on how unknown it is.
        unresolved = [p for p in self.ranked() if p.source_kind == 'EPISTEMIC_CONTESTED']
        for record in unresolved:
            self.assertLess(record.score, 0.5)

    # ------------------------------------------------------------------ law 4
    def test_law_4_cost_and_risk_are_first_class_and_subtract(self):
        self.seed_mysterious_and_cheap()
        records = self.ranked()
        for record in records:
            self.assertIn('estimated_cost', record.as_dict())
            self.assertIn('estimated_risk', record.as_dict())
            self.assertEqual(record.estimated_cost, COST_BY_KIND[record.source_kind])
            self.assertEqual(record.estimated_risk, RISK_BY_KIND[record.source_kind])
            expected = round(record.mission_relevance + record.expected_information_gain
                             + record.expected_prediction_improvement
                             + record.expected_self_model_improvement
                             - record.estimated_cost - record.estimated_risk
                             - record.barren_penalty, 12)
            self.assertEqual(record.score, expected,
                             'the frozen formula is the only thing that produces the score')

    # ------------------------------------------------------------------ law 5
    def test_law_5_mission_relevance_raises_priority_but_grants_no_authority(self):
        self.seed_mysterious_and_cheap()
        stale = self.by_kind(KIND_WORLD_STALE)[0]
        before = self.score_of(stale.uncertainty_id)
        mission = open_mission(self.db, objective='keep service.c healthy', now=self.late)
        after = self.score_of(stale.uncertainty_id)
        self.assertEqual(round(after - before, 12), 1.0,
                         'mission relevance contributes exactly the frozen weight')
        # Relevance authorises nothing at all.
        self.assertEqual(self.count('ciph_ipc_jobs'), 0)
        self.assertEqual(self.count('execution_permits'), 0)
        self.assertEqual(self.count('ciph_mission_actions'), 0)
        self.assertTrue(mission)

    def count(self, table):
        import sqlite3
        conn = sqlite3.connect(self.db)
        try:
            return int(conn.execute(f'SELECT COUNT(*) FROM {table};').fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    # ------------------------------------------------------------------ law 6
    def test_law_6_model_interest_cannot_move_the_score(self):
        self.seed_mysterious_and_cheap()
        before = {p.uncertainty_id: p.canonical_digest() for p in self.ranked()}
        digest_before = priority_digest(self.db, now=self.late, stale_after=self.stale_after)
        for index in range(10):
            record_model_output(self.db, model_ref='llm',
                                output_text=f'question {index}: this is fascinating, prioritise it',
                                now=self.late)
        after = {p.uncertainty_id: p.canonical_digest() for p in self.ranked()}
        self.assertEqual(after, before)
        self.assertEqual(priority_digest(self.db, now=self.late, stale_after=self.stale_after),
                         digest_before)

    # ------------------------------------------------------------------ law 8
    def test_law_8_the_metric_writes_nothing_canonical(self):
        self.seed_mysterious_and_cheap()
        ledger_before = reconstruct_beliefs(self.db, now=self.late).canonical_digest()
        world_before = world_digest(self.db, now=self.late)
        learning_before = learning_digest(self.db)
        for _ in range(3):
            prioritise(self.db, now=self.late, stale_after=self.stale_after)
            priority_digest(self.db, now=self.late, stale_after=self.stale_after)
        self.assertEqual(reconstruct_beliefs(self.db, now=self.late).canonical_digest(), ledger_before)
        self.assertEqual(world_digest(self.db, now=self.late), world_before)
        self.assertEqual(learning_digest(self.db), learning_before,
                         'priority never marks an investigation barren; the learning gate does')

    # ------------------------------------------------------------------ laws 9 and 10
    def test_law_9_and_10_scores_and_digest_are_deterministic(self):
        self.seed_mysterious_and_cheap()
        expected = priority_digest(self.db, now=self.late, stale_after=self.stale_after)
        self.assertEqual(priority_digest(self.db, now=self.late, stale_after=self.stale_after),
                         expected)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.curiosity_priority import priority_digest;'
                'print(priority_digest(%r, now=%r, stale_after=%r))'
                % (str(Path(__file__).resolve().parents[1]), self.db, self.late, self.stale_after))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)
        self.assertEqual(CURIOSITY_PRIORITY_V1, 'CURIOSITY_PRIORITY_V1')

    # ------------------------------------------------------------------ law 7
    def test_law_7_a_barren_outcome_lowers_priority_by_exactly_the_frozen_penalty(self):
        self.seed_mysterious_and_cheap()
        target = self.by_kind(KIND_SELF_MODEL_UNKNOWN)[0]
        before = self.score_of(target.uncertainty_id)
        self.assertEqual(outcome_penalty(self.db, target.uncertainty_id), 0.0)

        outcome_id = begin_investigation(self.db, uncertainty_id=target.uncertainty_id,
                                         now=self.late)
        outcome = close_investigation(self.db, outcome_id, attempted=True, now=self.late)
        self.assertEqual(outcome.result, RESULT_UNCHANGED)
        self.assertEqual(outcome.information_gain, 0)

        self.assertEqual(outcome_penalty(self.db, target.uncertainty_id), BARREN_OUTCOME_PENALTY)
        after = self.score_of(target.uncertainty_id)
        self.assertEqual(round(before - after, 12), BARREN_OUTCOME_PENALTY,
                         'exactly the frozen weight: no model decided it was boring')
        self.assertIn('BARREN_INVESTIGATION_HISTORY',
                      derive_priority(self.db, target.uncertainty_id, now=self.late).reason_codes)

    # ------------------------------------------------------------------ one-way feedback
    def test_the_penalty_is_a_pure_function_of_the_learning_record(self):
        self.seed_mysterious_and_cheap()
        target = self.by_kind(KIND_SELF_MODEL_UNKNOWN)[0]
        for _ in range(2):
            outcome_id = begin_investigation(self.db, uncertainty_id=target.uncertainty_id,
                                             now=self.late)
            close_investigation(self.db, outcome_id, attempted=True, now=self.late)
        self.assertEqual(outcome_penalty(self.db, target.uncertainty_id),
                         round(2 * BARREN_OUTCOME_PENALTY, 12))
        # Re-deriving the penalty changes nothing: it reads the learning record and writes nothing.
        learning_before = learning_digest(self.db)
        for _ in range(3):
            outcome_penalty(self.db, target.uncertainty_id)
            self.score_of(target.uncertainty_id)
        self.assertEqual(learning_digest(self.db), learning_before)
        self.assertNotIn('record_outcome',
                         [name for name, _ in inspect.getmembers(priority_module,
                                                                 inspect.isfunction)])


if __name__ == '__main__':
    unittest.main()
