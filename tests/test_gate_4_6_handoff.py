"""
4.6 Gate Four - Crucible handoff.

    After handoff, 4.6 is a spectator.

The load-bearing specimen is the held-out firewall: there is no code path from the generator's view to
a sealed answer.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.candidate_safety import review_candidate
from ciph.kernel.crucible_candidates import register_candidate
from ciph.kernel.crucible_handoff import (
    CRUCIBLE_HANDOFF_V1,
    generator_visible_view,
    hand_off,
    handoff_history,
)
from ciph.kernel.crucible_metrics import STATUS_DOMINATED
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_types import KIND_CAPABILITY_IMPLEMENTATION, CrucibleError

ORDINARY = ['ciph/capabilities/planner.py']


class TestGate46Handoff(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-46-handoff-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_CAPABILITY_IMPLEMENTATION,
            development_cases=['dev-1', 'dev-2'],
            heldout_cases=['sealed-1', 'sealed-2', 'sealed-3'],
            metric_definitions=[MetricDefinition('task_success', 'v1', 'HIGHER_BETTER')],
            environment_identity='host:eval', minimum_evidence=1, now=self.t1)
        self.candidate = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                            artifact_digest='H1', configuration_digest='C1',
                                            now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def admit(self):
        return review_candidate(self.db, candidate_id=self.candidate.candidate_id,
                                changed_files=ORDINARY, now=self.t1)

    def count(self, table):
        connection = sqlite3.connect(self.db)
        try:
            return connection.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0]
        except sqlite3.Error:
            return 0
        finally:
            connection.close()

    # ------------------------------------------------------------------ law 3
    def test_law_3_the_generator_cannot_see_the_sealed_cases(self):
        view = generator_visible_view(self.db, self.protocol.protocol_id)
        self.assertEqual(view['development_cases'], ['dev-1', 'dev-2'])
        self.assertEqual(view['sealed_case_count'], 3)
        self.assertNotIn('heldout_cases', view)
        self.assertNotIn('sealed-1', str(view))
        self.assertEqual([metric['metric_id'] for metric in view['metrics']], ['task_success'])
        self.assertEqual([metric['direction'] for metric in view['metrics']], ['HIGHER_BETTER'])

    # ------------------------------------------------------------------ laws 1, 5, 6
    def test_handoff_creates_no_authority_and_requires_admissibility(self):
        with self.assertRaises(CrucibleError) as refused:
            hand_off(self.db, candidate_id=self.candidate.candidate_id, hypothesis_id='IH-1',
                     protocol_id=self.protocol.protocol_id, role='CANDIDATE', now=self.t1)
        self.assertEqual(refused.exception.reason, 'CANDIDATE_NOT_ADMISSIBLE')

        self.admit()
        record = hand_off(self.db, candidate_id=self.candidate.candidate_id, hypothesis_id='IH-1',
                          protocol_id=self.protocol.protocol_id, role='CANDIDATE', now=self.t1)
        self.assertFalse(record.creates_authority)
        self.assertEqual(record.artifact_digest, 'H1')
        self.assertEqual(len(handoff_history(self.db)), 1)
        self.assertEqual(self.count('execution_permits'), 0)
        self.assertEqual(self.count('ciph_crucible_promotions'), 0)
        self.assertEqual(self.count('ciph_crucible_deployments'), 0)
        self.assertEqual(self.count('ciph_crucible_handoffs'), 1)
        self.assertEqual(CRUCIBLE_HANDOFF_V1, 'CRUCIBLE_HANDOFF_V1')
        self.assertEqual(STATUS_DOMINATED, 'DOMINATED')


if __name__ == '__main__':
    unittest.main()
