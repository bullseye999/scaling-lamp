"""
4.5 Gate One - frozen evaluation protocol.

    How will the candidate be judged, decided BEFORE it runs?

Every specimen is written so that a protocol that could be edited after the results arrived would fail.
"""

import inspect
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import crucible_protocols as protocols_module
from ciph.kernel.crucible_protocols import (
    HARD_INVARIANTS,
    EvaluationProtocol,
    MetricDefinition,
    assert_protocol_integrity,
    freeze_protocol,
    get_protocol,
    protocol_digest,
    protocol_history,
    protocol_payload,
)
from ciph.kernel.crucible_types import CRUCIBLE_PROTOCOL_V1, CrucibleError, digest

SUCCESS = MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02)
BRIER = MetricDefinition('prediction_brier', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=0.02)
LATENCY = MetricDefinition('latency', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=10.0)
INVARIANTS = ('NO_AUTHORITY_BYPASS', 'NO_FABRICATED_EVIDENCE', 'NO_HISTORY_MUTATION')


class TestGate45EvaluationProtocol(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-protocol-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.dev = [f'dev-{index}' for index in range(100)]
        self.held = [f'held-{index}' for index in range(50)]

    def tearDown(self):
        self.temp.cleanup()

    def freeze(self, *, metrics=None, development=None, heldout=None, invariants=INVARIANTS,
               environment='host:eval-alpha', repetition=3, minimum_evidence=5, now=None):
        return freeze_protocol(
            self.db, candidate_kind='PLANNER_STRATEGY',
            development_cases=self.dev if development is None else development,
            heldout_cases=self.held if heldout is None else heldout,
            metric_definitions=[SUCCESS, BRIER, LATENCY] if metrics is None else metrics,
            environment_identity=environment, repetition_count=repetition,
            seed_policy='FIXED_PER_REPETITION', resource_budget=100.0,
            hard_invariants=invariants, minimum_evidence=minimum_evidence,
            now=now or self.t1)

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_a_protocol_is_frozen_before_any_result_exists(self):
        protocol = self.freeze()
        self.assertEqual(protocol.protocol_version, CRUCIBLE_PROTOCOL_V1)
        self.assertEqual(len(protocol.development_cases), 100)
        self.assertEqual(len(protocol.heldout_cases), 50)
        self.assertEqual(protocol.environment_identity, 'host:eval-alpha')
        self.assertEqual(protocol.repetition_count, 3)
        self.assertEqual(protocol.minimum_evidence, 5)
        self.assertEqual({metric.metric_id for metric in protocol.metric_definitions},
                         {'task_success', 'prediction_brier', 'latency'})
        for metric in protocol.metric_definitions:
            self.assertTrue(metric.metric_version)
        self.assertEqual(self.freeze().protocol_id, protocol.protocol_id,
                         'the same judgement plan is the same protocol')
        self.assertEqual(get_protocol(self.db, protocol.protocol_id).as_dict(),
                         protocol.as_dict())

    # ------------------------------------------------------------------ the hostile specimen
    def test_nobody_can_move_the_goalposts_after_the_results_arrive(self):
        original = self.freeze()
        # "C1 performed badly on eight cases" - so someone tries three edits.
        weakened = [MetricDefinition('task_success', 'v1', 'HIGHER_BETTER',
                                    minimum_meaningful_delta=0.4), BRIER, LATENCY]
        edited_threshold = [SUCCESS, BRIER,
                            MetricDefinition('latency', 'v1', 'LOWER_BETTER',
                                             minimum_meaningful_delta=500.0)]
        pruned = [case for case in self.held if case not in {'held-0', 'held-1', 'held-2'}]

        changed_metric = self.freeze(metrics=weakened)
        changed_threshold = self.freeze(metrics=edited_threshold)
        changed_corpus = self.freeze(heldout=pruned)
        for edited in (changed_metric, changed_threshold, changed_corpus):
            self.assertNotEqual(edited.protocol_id, original.protocol_id,
                                'a changed judgement plan is a NEW evaluation')

        # ...and the original is untouched, still integral, and still names all fifty cases.
        self.assertEqual(get_protocol(self.db, original.protocol_id).as_dict(), original.as_dict())
        self.assertEqual(assert_protocol_integrity(self.db, original.protocol_id),
                         original.protocol_id)
        self.assertEqual(len(get_protocol(self.db, original.protocol_id).heldout_cases), 50)
        self.assertEqual([p.protocol_id for p in protocol_history(self.db)],
                         sorted([p.protocol_id for p in protocol_history(self.db)]))

    # ------------------------------------------------------------------ law 7
    def test_law_7_development_and_held_out_cases_must_be_disjoint(self):
        with self.assertRaises(CrucibleError) as overlap:
            self.freeze(development=self.dev[:10] + ['held-0'], heldout=self.held)
        self.assertEqual(overlap.exception.reason, 'DEVELOPMENT_CASES_OVERLAP_HELDOUT')
        self.assertEqual(protocol_history(self.db), [], 'a refused protocol is not recorded')

    # ------------------------------------------------------------------ law 2
    def test_law_2_an_out_of_band_edit_to_the_evaluation_is_detected(self):
        protocol = self.freeze()
        self.assertEqual(assert_protocol_integrity(self.db, protocol.protocol_id),
                         protocol.protocol_id)
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE ciph_crucible_protocols SET minimum_evidence = 1, "
                               "heldout_cases_json = ? WHERE protocol_id = ?;",
                               ('["held-0"]', protocol.protocol_id))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(CrucibleError) as tampered:
            assert_protocol_integrity(self.db, protocol.protocol_id)
        self.assertEqual(tampered.exception.reason, 'PROTOCOL_INTEGRITY_VIOLATION')

    # ------------------------------------------------------------------ laws 2, 5, 9
    def test_law_5_and_9_metric_versions_and_invariants_are_explicit(self):
        with self.assertRaises(CrucibleError) as no_version:
            self.freeze(metrics=[MetricDefinition('task_success', '', 'HIGHER_BETTER')])
        self.assertEqual(no_version.exception.reason, 'METRIC_REQUIRES_VERSION')
        with self.assertRaises(CrucibleError) as bad_direction:
            self.freeze(metrics=[MetricDefinition('task_success', 'v1', 'SIDEWAYS')])
        self.assertEqual(bad_direction.exception.reason, 'INVALID_METRIC_DIRECTION')
        with self.assertRaises(CrucibleError) as invented:
            self.freeze(invariants=('NO_AUTHORITY_BYPASS', 'SPEED_IS_ALL_THAT_MATTERS'))
        self.assertEqual(invented.exception.reason, 'UNKNOWN_HARD_INVARIANT')
        with self.assertRaises(CrucibleError) as no_metrics:
            self.freeze(metrics=[])
        self.assertEqual(no_metrics.exception.reason, 'PROTOCOL_REQUIRES_METRICS')
        self.assertIn('NO_FABRICATED_EVIDENCE', HARD_INVARIANTS)

    def test_the_protocol_module_offers_no_mutation_surface(self):
        public = [name for name, _ in inspect.getmembers(protocols_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('update_protocol', 'edit_protocol', 'set_metric', 'add_case',
                          'delete_case', 'remove_heldout', 'relax_threshold', 'patch_protocol'):
            self.assertNotIn(forbidden, public)

    # ------------------------------------------------------------------ determinism
    def test_protocol_digest_and_identity_are_deterministic_across_restart(self):
        self.freeze()
        expected = protocol_digest(self.db)
        self.assertEqual(protocol_digest(self.db), expected)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.crucible_protocols import protocol_digest;'
                'print(protocol_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)

        # The identity is a pure function of the payload, so it is reproducible from the payload alone.
        payload = protocol_payload(
            candidate_kind='PLANNER_STRATEGY', development_cases=self.dev, heldout_cases=self.held,
            metric_definitions=[SUCCESS, BRIER, LATENCY], environment_identity='host:eval-alpha',
            repetition_count=3, seed_policy='FIXED_PER_REPETITION', resource_budget=100.0,
            hard_invariants=INVARIANTS, minimum_evidence=5)
        self.assertEqual('CP-' + digest(payload)[:16].upper(),
                         self.freeze().protocol_id)


if __name__ == '__main__':
    unittest.main()
