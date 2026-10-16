
"""
4.3 Gate Zero - world state.

    The world model is a projection over epistemic state. It is not another source of truth.

Every specimen here is written so that a world model which quietly became an evidence source, or which
promoted contested epistemics into definite world state, would fail.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.belief_revision import record_revisions
from ciph.kernel.epistemic_convergence import project_convergence
from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    canonical_proposition,
    reconstruct as reconstruct_beliefs,
    record_evidence,
    record_model_output,
    record_observation,
)
from ciph.kernel.source_dependence import RELATION_PRIMARY_OBSERVATION, record_provenance
from ciph.kernel.world_model import (
    REASON_NO_EPISTEMIC_BASIS,
    WORLD_ABSENT,
    WORLD_CONTESTED,
    WORLD_PRESENT,
    WORLD_STALE,
    WORLD_UNKNOWN,
    canonical_scope,
    entity_for,
    project_entities,
    project_fact,
    record_world_snapshot,
    world_digest,
    world_history,
)


class TestGate43WorldState(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-43-world-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.t2 = self.t1 + 3_600
        self.service = entity_for('service.x', kind='service')

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def converge(self, *, relation='is_online', value=True, scope=None, sources=2, relation_kind=RELATION_SUPPORTS):
        # The proposition's scope must be the CANONICAL string, or its fact id will not line up with
        # the one the projection derives from it.
        proposition = canonical_proposition('service.x', relation, value,
                                            temporal_scope=canonical_scope(scope))
        for index in range(sources):
            observation = record_observation(self.db, source_ref=f'source-{index}', raw_text='report',
                                             now=self.t1)
            evidence = record_evidence(self.db, proposition, relation=relation_kind,
                                       source_ref=f'source-{index}',
                                       observation_ref=observation['observation_id'],
                                       evidence_time=self.t1, now=self.t1)
            record_provenance(self.db, from_evidence=evidence, relation=RELATION_PRIMARY_OBSERVATION,
                              now=self.t1)
        return proposition

    def fact(self, *, value=True, scope=None, **kwargs):
        return project_fact(self.db, entity=self.service, relation='is_online', value=value,
                            scope=scope, now=kwargs.pop('now', self.t1), **kwargs)

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_temporal_scopes_do_not_contradict(self):
        self.converge(value=True, scope=self.t1)
        first = self.fact(value=True, scope=self.t1)
        self.assertEqual(first.world_status, WORLD_PRESENT)
        record_world_snapshot(self.db, now=self.t1)

        # Later, independent evidence says the service is down AT T2. A different temporal scope means
        # a different fact, so this is not a contradiction of the first one.
        later = canonical_proposition('service.x', 'is_online', False,
                                      temporal_scope=canonical_scope(self.t2))
        for index in range(2):
            observation = record_observation(self.db, source_ref=f'later-{index}', raw_text='down',
                                             now=self.t2)
            evidence = record_evidence(self.db, later, relation=RELATION_SUPPORTS,
                                       source_ref=f'later-{index}',
                                       observation_ref=observation['observation_id'],
                                       evidence_time=self.t2, now=self.t2)
            record_provenance(self.db, from_evidence=evidence, relation=RELATION_PRIMARY_OBSERVATION,
                              now=self.t2)
        second = project_fact(self.db, entity=self.service, relation='is_online', value=False,
                              scope=self.t2, now=self.t2)
        self.assertEqual(second.world_status, WORLD_PRESENT,
                         "the claim 'not online at T2' is itself present at T2")
        self.assertEqual(second.modeled_value, 'False')
        self.assertNotEqual(first.fact_id, second.fact_id, "time is part of state identity")
        record_world_snapshot(self.db, now=self.t2)

        # The FIRST fact is untouched by the later one, and its history still says PRESENT.
        self.assertEqual(self.fact(value=True, scope=self.t1).world_status, WORLD_PRESENT)
        self.assertEqual([h['world_status'] for h in world_history(self.db, first.fact_id)],
                         [WORLD_PRESENT])

    # ------------------------------------------------------------------ laws 1, 7
    def test_law_1_and_7_the_world_model_never_writes_evidence(self):
        self.converge(value=True, scope=self.t1)
        before = reconstruct_beliefs(self.db, now=self.t1).canonical_digest()
        self.fact()
        project_entities(self.db, now=self.t1)
        record_world_snapshot(self.db, now=self.t1)
        record_model_output(self.db, model_ref='model', output_text='service X is definitely online',
                            proposition=canonical_proposition(
                                'service.x', 'is_online', True,
                                temporal_scope=canonical_scope(self.t1)),
                            now=self.t1)
        after = reconstruct_beliefs(self.db, now=self.t1)
        self.assertEqual(after.canonical_digest(), before,
                         "projecting the world must not touch the epistemic ledger")
        self.assertEqual(after.evidence_count, 2)
        self.assertEqual(project_convergence(self.db, canonical_proposition(
            'service.x', 'is_online', True, temporal_scope=canonical_scope(self.t1)).proposition_id,
            now=self.t1).status, 'CONVERGED_SUPPORTED')

    # ------------------------------------------------------------------ laws 2, 3, 4
    def test_law_2_every_fact_traces_to_a_proposition(self):
        self.converge()
        traced = self.fact()
        self.assertIsNotNone(traced.source_proposition_id)
        untraced = project_fact(self.db, entity=self.service, relation='has_uptime', value='99%',
                                scope=self.t1, now=self.t1)
        self.assertEqual(untraced.world_status, WORLD_UNKNOWN)
        self.assertIn(REASON_NO_EPISTEMIC_BASIS, untraced.reason_codes)
        self.assertIsNone(untraced.source_proposition_id,
                          "with no epistemic basis there is nothing to trace to, and nothing asserted")

    def test_law_3_contested_epistemics_cannot_become_world_state(self):
        self.converge(value=True, scope=self.t1)
        self.assertEqual(self.fact(value=True, scope=self.t1).world_status, WORLD_PRESENT)

        contradiction = record_observation(self.db, source_ref='critic', raw_text='it is down',
                                           now=self.t1 + 1)
        # A contradiction has to be PROVEN independent to contest the state; an unattributable one
        # only makes the world UNCERTAIN, which is the conservative direction.
        counter_evidence = record_evidence(
            self.db, canonical_proposition('service.x', 'is_online', True,
                                           temporal_scope=canonical_scope(self.t1)),
            relation=RELATION_CONTRADICTS, source_ref='critic',
            observation_ref=contradiction['observation_id'], evidence_time=self.t1 + 1,
            now=self.t1 + 1)
        record_provenance(self.db, from_evidence=counter_evidence,
                          relation=RELATION_PRIMARY_OBSERVATION, now=self.t1 + 1)
        contested = self.fact(value=True, scope=self.t1, now=self.t1 + 2)
        self.assertEqual(contested.world_status, WORLD_CONTESTED)
        self.assertNotIn(contested.world_status, (WORLD_PRESENT, WORLD_ABSENT),
                         "contested epistemics are not definite world state")

    def test_law_4_unknown_survives_projection(self):
        unknown = self.fact(value='maybe', scope=self.t1)
        self.assertEqual(unknown.world_status, WORLD_UNKNOWN)
        self.assertIsNone(unknown.confidence)
        self.assertIsNone(unknown.epistemic_status)

    def test_absent_is_not_unknown(self):
        """A refuted claim is ABSENT; no evidence at all is UNKNOWN. They must not collapse."""
        self.converge(value=True, scope=self.t1, relation_kind=RELATION_CONTRADICTS)
        refuted = self.fact(value=True, scope=self.t1)
        self.assertEqual(refuted.world_status, WORLD_ABSENT)
        self.assertNotEqual(refuted.world_status, WORLD_UNKNOWN)

    # ------------------------------------------------------------------ laws 6, 8
    def test_law_6_and_8_history_is_an_immutable_snapshot_series(self):
        proposition = self.converge(value=True, scope=self.t1)
        self.fact(value=True, scope=self.t1)
        record_world_snapshot(self.db, now=self.t1)

        contradiction = record_observation(self.db, source_ref='critic', raw_text='down',
                                           now=self.t1 + 1)
        counter_evidence = record_evidence(
            self.db, proposition, relation=RELATION_CONTRADICTS, source_ref='critic',
            observation_ref=contradiction['observation_id'], evidence_time=self.t1 + 1,
            now=self.t1 + 1)
        record_provenance(self.db, from_evidence=counter_evidence,
                          relation=RELATION_PRIMARY_OBSERVATION, now=self.t1 + 1)
        self.fact(value=True, scope=self.t1, now=self.t1 + 2)
        record_world_snapshot(self.db, now=self.t1 + 2)

        history = world_history(self.db, self.fact(value=True, scope=self.t1, now=self.t1 + 2).fact_id)
        self.assertEqual([h['world_status'] for h in history], [WORLD_PRESENT, WORLD_CONTESTED],
                         "removing support does not rewrite the state that was modelled before")
        self.assertEqual(record_world_snapshot(self.db, now=self.t1 + 3), 0,
                         "an unchanged world state adds no snapshot")

    # ------------------------------------------------------------------ laws 9, 10
    def test_law_9_and_10_world_digest_is_stable_across_restart_and_process(self):
        self.converge(value=True, scope=self.t1)
        self.converge(value=True, scope=self.t1)      # idempotent: same propositions
        expected = world_digest(self.db, now=self.t1)
        self.assertEqual(world_digest(self.db, now=self.t1), expected)

        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.world_model import world_digest;"
                "print(world_digest(%r, now=%r))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.t1))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected,
                         "a second process models the same world identically")

    def test_the_world_model_is_not_an_input_to_the_epistemic_layer(self):
        self.converge(value=True, scope=self.t1)
        before = reconstruct_beliefs(self.db, now=self.t1).canonical_digest()
        for _ in range(3):
            project_entities(self.db, now=self.t1)
            record_world_snapshot(self.db, now=self.t1)
            record_revisions(self.db, now=self.t1)
        self.assertEqual(reconstruct_beliefs(self.db, now=self.t1).canonical_digest(), before)
        self.assertTrue(json.dumps([f.as_dict() for f in project_entities(self.db, now=self.t1)]))


if __name__ == '__main__':
    unittest.main()
