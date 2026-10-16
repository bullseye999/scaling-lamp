"""
4.7 Gate Four - the sealed meta evaluation corpus.

    How do you evaluate a replacement for the thing that evaluates, without letting the replacement
    write the exam?

The load-bearing specimen is the access boundary, and it is a FILE boundary rather than an API
convention: the candidate-facing handle is given the public database, and the answers are in another
file it is never handed.
"""

import inspect
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_metrics import (
    STATUS_DOMINATED,
    STATUS_DOMINATES,
    STATUS_INSUFFICIENT,
    STATUS_INVALID,
)
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.meta_corpus import (
    ADJUDICATION_MECHANICAL,
    ADJUDICATION_NONE,
    ADJUDICATION_OPERATOR,
    CASE_KIND_EVALUATOR,
    CASE_KIND_GENERATOR,
    META_CORPUS_V1,
    META_CRUCIBLE_PROTOCOL_V1,
    CandidateFacingCorpus,
    MetaCorpusVault,
    assert_meta_protocol_integrity,
    disagreements,
    freeze_meta_protocol,
    get_meta_protocol,
)

CORPUS = 'META-CORPUS-1'


class TestGate47MetaCorpus(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-47-corpus-')
        self.root = Path(self.temp.name)
        self.public = str(self.root / 'public.db')
        self.sealed = str(self.root / 'sealed-answers.db')
        self.t1 = 1_800_000_000.0
        self.vault = MetaCorpusVault(self.public, self.sealed)

    def tearDown(self):
        self.temp.cleanup()

    def register(self, *, kind=CASE_KIND_EVALUATOR, inputs=None, adjudication=ADJUDICATION_NONE,
                 expected=None, adjudicated=None, corpus=CORPUS):
        return self.vault.register_case(
            corpus_version=corpus, case_kind=kind, case_input=inputs or {'situation': 'x'},
            adjudication_class=adjudication, expected_result=expected,
            adjudicated_result=adjudicated, sealed_payload={'note': 'sealed'}, now=self.t1)

    def protocol(self, **overrides):
        settings = dict(corpus_version=CORPUS, authority_ref='operator:operator', minimum_evidence=1,
                        required_case_kinds=(CASE_KIND_EVALUATOR,), now=self.t1)
        settings.update(overrides)
        return freeze_meta_protocol(self.public, **settings)

    # ------------------------------------------------------------------ founding
    def test_founding_a_corpus_case_is_immutable_and_publicly_identified(self):
        first = self.register(inputs={'situation': 'fabricated evidence'})
        again = self.register(inputs={'situation': 'fabricated evidence'})
        self.assertEqual(first.case_id, again.case_id, 'the same case is one identity')
        self.assertEqual(first.corpus_version, CORPUS)
        self.assertTrue(first.case_id.startswith('MCC-'))
        self.assertEqual(first.sealed_payload_ref, f'sealed://{CORPUS}/{first.case_id}')
        self.assertEqual(len(self.vault.cases(CORPUS)), 1)
        other = self.register(inputs={'situation': 'something else'})
        self.assertNotEqual(other.case_id, first.case_id)
        self.assertTrue(self.vault.corpus_digest(CORPUS))

    # ------------------------------------------------------------------ the access boundary
    def test_the_candidate_cannot_reach_a_sealed_answer(self):
        case = self.register(adjudication=ADJUDICATION_MECHANICAL, expected='INVALID')
        candidate = CandidateFacingCorpus(self.public)
        visible = candidate.cases(CORPUS)
        self.assertEqual(len(visible), 1)
        for forbidden in ('expected_result', 'adjudicated_result', 'sealed_payload',
                          'adjudication_notes'):
            self.assertNotIn(forbidden, visible[0])
        self.assertFalse(hasattr(candidate, 'reveal'), 'the candidate handle has no reveal at all')

        # The boundary is a FILE boundary: the answers are not in the database the candidate holds.
        connection = sqlite3.connect(self.public)
        try:
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table';")}
        finally:
            connection.close()
        self.assertNotIn('ciph_meta_corpus_sealed', tables,
                         'sealed answers live in a different database file')
        sealed_connection = sqlite3.connect(self.sealed)
        try:
            sealed_tables = {row[0] for row in sealed_connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table';")}
        finally:
            sealed_connection.close()
        self.assertIn('ciph_meta_corpus_sealed', sealed_tables)

        # And revealing requires a real adjudicator, not a candidate reference.
        for bad in (None, '', case.case_id, 'CC-CANDIDATE-1', 'MC-META-1', 'CON-1'):
            with self.subTest(adjudicator=bad):
                with self.assertRaises(CrucibleError) as refused:
                    self.vault.reveal(case.case_id, adjudicator_ref=bad)
                self.assertEqual(refused.exception.reason, 'ADJUDICATOR_AUTHORIZATION_REQUIRED')
        revealed = self.vault.reveal(case.case_id, adjudicator_ref='operator:operator')
        self.assertEqual(revealed['expected_result'], 'INVALID')
        self.assertEqual(len(self.vault.sealed_access_log()), 1, 'every reveal is audited')

    # ------------------------------------------------------------------ hard invariants
    def test_an_evaluator_that_trades_a_hard_invariant_is_invalid_however_it_scores(self):
        case = self.register(adjudication=ADJUDICATION_MECHANICAL, expected='INVALID',
                             inputs={'situation': 'one fabricated evidence violation'})
        protocol_id = self.protocol()
        result = self.vault_run(protocol_id, case_id=case.case_id,
                                evaluator=lambda payload: 'DOMINATES',
                                authoritative=lambda payload: 'INVALID')
        self.assertEqual(result.status, STATUS_INVALID)
        self.assertEqual(result.constitutional_misses, 1)
        self.assertEqual(result.adjudicated_errors, 1)
        recorded = disagreements(self.public, protocol_id)
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0].disagreement_class, 'ADJUDICATED')

    def vault_run(self, protocol_id, *, case_id, evaluator, authoritative):
        from ciph.kernel.meta_corpus import run_meta_evaluation
        return run_meta_evaluation(self.public, self.vault, protocol_id=protocol_id,
                                   candidate_evaluator_id='CC-E1', evaluator=evaluator,
                                   authoritative=authoritative, case_ids=[case_id], now=self.t1)

    # ------------------------------------------------------------------ law 9
    def test_an_unadjudicated_disagreement_is_not_a_win_for_anyone(self):
        case = self.register(adjudication=ADJUDICATION_NONE)
        protocol_id = self.protocol()
        result = self.vault_run(protocol_id, case_id=case.case_id,
                                evaluator=lambda payload: 'DOMINATES',
                                authoritative=lambda payload: 'INCOMPARABLE')
        self.assertEqual(result.status, STATUS_INSUFFICIENT,
                         'no independent adjudication means no verdict, least of all a win')
        self.assertEqual(result.unadjudicated_disagreements, 1)
        self.assertEqual(result.constitutional_misses, 0)
        recorded = disagreements(self.public, protocol_id)
        self.assertEqual(recorded[0].disagreement_class, 'UNRESOLVED')
        self.assertIsNone(recorded[0].adjudicated_result)

    def test_adjudicated_cases_are_what_move_the_verdict(self):
        good = self.register(adjudication=ADJUDICATION_MECHANICAL, expected='INVALID',
                             inputs={'situation': 'fabrication'})
        operator = self.register(adjudication=ADJUDICATION_OPERATOR, adjudicated='DOMINATES',
                                 inputs={'situation': 'genuine improvement'})
        protocol_id = self.protocol(minimum_evidence=2)
        from ciph.kernel.meta_corpus import run_meta_evaluation
        result = run_meta_evaluation(
            self.public, self.vault, protocol_id=protocol_id, candidate_evaluator_id='CC-E1',
            evaluator={'MCC-NOPE': None} if False else (
                lambda payload: 'INVALID' if payload['case_id'] == good.case_id else 'DOMINATES'),
            authoritative=lambda payload: 'INVALID', case_ids=[good.case_id, operator.case_id],
            now=self.t1)
        self.assertEqual(result.adjudicated_cases, 2)
        self.assertEqual(result.agreements, 2)
        self.assertEqual(result.status, STATUS_DOMINATES)
        self.assertEqual(STATUS_DOMINATED, 'DOMINATED')

    # ------------------------------------------------------------------ the protocol
    def test_the_protocol_is_frozen_and_tamper_evident(self):
        protocol_id = self.protocol(metric_definitions=[{'metric_id': 'invalid_rate'}])
        self.assertTrue(protocol_id.startswith('MCP-'))
        self.assertEqual(assert_meta_protocol_integrity(self.public, protocol_id), protocol_id)
        self.assertEqual(self.protocol(metric_definitions=[{'metric_id': 'invalid_rate'}]),
                         protocol_id, 'the same judgement plan is the same protocol')
        self.assertNotEqual(self.protocol(metric_definitions=[{'metric_id': 'other'}]),
                            protocol_id)
        self.assertEqual(get_meta_protocol(self.public, protocol_id)['payload']['version'],
                         META_CRUCIBLE_PROTOCOL_V1)
        connection = sqlite3.connect(self.public)
        try:
            connection.execute("UPDATE ciph_meta_corpus_protocols SET minimum_evidence = 99 "
                               "WHERE protocol_id = ?;", (protocol_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(CrucibleError) as refused:
            assert_meta_protocol_integrity(self.public, protocol_id)
        self.assertEqual(refused.exception.reason, 'META_PROTOCOL_INTEGRITY_VIOLATION')

    def test_a_case_outside_the_protocol_corpus_is_refused(self):
        case = self.register(corpus='OTHER-CORPUS')
        protocol_id = self.protocol()
        with self.assertRaises(CrucibleError) as refused:
            self.vault_run(protocol_id, case_id=case.case_id,
                           evaluator=lambda payload: 'DOMINATES',
                           authoritative=lambda payload: 'DOMINATES')
        self.assertEqual(refused.exception.reason, 'CASE_OUTSIDE_PROTOCOL_CORPUS')
        self.assertEqual(META_CORPUS_V1, 'META_CORPUS_V1')
        self.assertTrue(inspect.getsource(__import__('ciph.kernel.meta_corpus', fromlist=['x'])))


if __name__ == '__main__':
    unittest.main()
