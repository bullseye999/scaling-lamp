
"""
4.3 Gate One - world dynamics.

    A transition records that the world moved between two observed states. It does not say why, and it
    does not fill the space between the observations.

The hostile specimen is the point of the gate: T1 and T3 are observed, T2 is not, and the model must
stay silent about T2 rather than narrate a moment it never saw.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    canonical_proposition,
    record_evidence,
    record_observation,
)
from ciph.kernel.source_dependence import RELATION_PRIMARY_OBSERVATION, record_provenance
from ciph.kernel.world_dynamics import (
    DynamicsError,
    derive_transitions,
    dynamics_digest,
    record_transitions,
    transition_history,
)
from ciph.kernel.world_model import canonical_scope, entity_for, project_fact, world_digest


class TestGate43Dynamics(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-43-dynamics-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t0 = 1_800_000_000.0
        self.t1 = self.t0 + 100
        self.t2 = self.t0 + 200
        self.t3 = self.t0 + 300
        self.service = entity_for('service.x', kind='service')

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def observe(self, *, online, at, scope=None, sources=2):
        """
        Two independent primary observations of one state, LEARNED at `at`.

        `scope` is the time the FACT is about and defaults to `at`. They are separate axes: a fact can
        be learned at a real moment while referring to a scope the model cannot place in time.
        """
        scope_value = at if scope is None else scope
        proposition = canonical_proposition('service.x', 'is_online', online,
                                            temporal_scope=canonical_scope(scope_value))
        for index in range(sources):
            observation = record_observation(self.db, source_ref=f's-{index}-{at}', raw_text='x',
                                             now=at)
            evidence = record_evidence(self.db, proposition, relation=RELATION_SUPPORTS,
                                       source_ref=f's-{index}-{at}',
                                       observation_ref=observation['observation_id'],
                                       evidence_time=at, now=at)
            record_provenance(self.db, from_evidence=evidence, relation=RELATION_PRIMARY_OBSERVATION,
                              now=at)
        return project_fact(self.db, entity=self.service, relation='is_online', value=online,
                            scope=scope_value, now=at)

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_state_change_becomes_one_transition(self):
        offline = self.observe(online=False, at=self.t1)
        online = self.observe(online=True, at=self.t3)
        self.assertEqual((offline.world_status, online.world_status), ('PRESENT', 'PRESENT'))

        transitions = derive_transitions(self.db, now=self.t3)
        self.assertEqual(len(transitions), 1)
        transition = transitions[0]
        self.assertEqual(transition.from_value, 'False')
        self.assertEqual(transition.to_value, 'True')
        self.assertEqual((transition.window_lower, transition.window_upper), (self.t1, self.t3))
        self.assertEqual(transition.intermediate_observations, 0)

    # ------------------------------------------------------------------ the hostile specimen
    def test_hostile_no_observation_between_means_no_invented_time(self):
        self.observe(online=False, at=self.t1)
        self.observe(online=True, at=self.t3)
        transition = derive_transitions(self.db, now=self.t3)[0]

        self.assertIsNone(transition.exact_at, "nothing observed T2, so there is no exact moment")
        self.assertEqual(transition.describe_window(), f'somewhere in ({self.t1}, {self.t3}]')
        with self.assertRaises(DynamicsError) as refused:
            transition.require_exact_time()
        self.assertEqual(refused.exception.reason, 'TRANSITION_TIME_NOT_OBSERVED')
        self.assertNotIn('T2', transition.describe_window())

    def test_an_intermediate_observation_narrows_the_window_without_inventing_a_time(self):
        self.observe(online=False, at=self.t1)
        self.observe(online=True, at=self.t3)
        wide = derive_transitions(self.db, now=self.t3)[0]
        record_transitions(self.db, now=self.t3)

        # Now something IS observed at T2: still offline. The change is squeezed into (T2, T3].
        self.observe(online=False, at=self.t2)
        narrowed = [t for t in derive_transitions(self.db, now=self.t3)
                    if t.from_fact_id != wide.from_fact_id or t.to_fact_id != wide.to_fact_id]
        self.assertEqual(len(narrowed), 1)
        self.assertEqual((narrowed[0].window_lower, narrowed[0].window_upper), (self.t2, self.t3))
        self.assertEqual(narrowed[0].intermediate_observations, 0)
        self.assertIsNone(narrowed[0].exact_at)

        # The narrowed window is a NEW transition id, so it appends; the wider one stays as history.
        self.assertEqual(record_transitions(self.db, now=self.t3), 1,
                         "the refined window derives a new id and is appended")
        history = transition_history(self.db, self.service.entity_id)
        self.assertEqual(len(history), 2,
                         "the wide window and the narrowed window both remain as history")
        self.assertEqual(record_transitions(self.db, now=self.t3), 0, "nothing new to append")

    # ------------------------------------------------------------------ laws 1, 2, 5, 7
    def test_law_1_and_2_no_cause_is_recorded_anywhere(self):
        self.observe(online=False, at=self.t1)
        self.observe(online=True, at=self.t3)
        transition = derive_transitions(self.db, now=self.t3)[0]
        payload = transition.as_dict()
        for forbidden in ('cause', 'caused_by', 'reason', 'explanation', 'because'):
            self.assertNotIn(forbidden, payload)

        import inspect
        from ciph.kernel import world_dynamics
        public = [name for name, _ in inspect.getmembers(world_dynamics, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('explain_cause', 'attribute_cause', 'set_cause'):
            self.assertNotIn(forbidden, public)

    def test_law_5_and_7_transition_records_are_append_only_and_deduplicated(self):
        self.observe(online=False, at=self.t1)
        self.observe(online=True, at=self.t3)
        self.assertEqual(record_transitions(self.db, now=self.t3), 1)
        self.assertEqual(record_transitions(self.db, now=self.t3), 0,
                         "re-observing the same change adds no duplicate")
        self.assertEqual(len(transition_history(self.db)), 1)
        self.assertTrue(json.dumps(transition_history(self.db)[0]))

    def test_law_3_missing_intermediates_are_reported_not_filled(self):
        self.observe(online=False, at=self.t1)
        self.observe(online=True, at=self.t3)
        self.assertEqual(derive_transitions(self.db, now=self.t3)[0].intermediate_observations, 0)
        # With one observation in between the count reflects that we DID look.
        self.observe(online=False, at=self.t2)
        transitions = derive_transitions(self.db, now=self.t3)
        self.assertTrue(all(t.intermediate_observations == 0 for t in transitions))

    # ------------------------------------------------------------------ law 4
    def test_law_4_unorderable_scopes_form_no_transition(self):
        self.observe(online=False, at=self.t1, scope='SOMETIME_TUESDAY')
        self.observe(online=True, at=self.t3)
        self.assertEqual(derive_transitions(self.db, now=self.t3), (),
                         "ordering must be evidence-backed, so an unreadable scope forms no transition")

    def test_only_definite_states_produce_transitions(self):
        """A contested state is not a state the world can be said to have moved FROM."""
        self.observe(online=False, at=self.t1)
        self.observe(online=True, at=self.t3)
        self.assertEqual(len(derive_transitions(self.db, now=self.t3)), 1)

        # Contest the T3 state with a proven independent contradiction.
        proposition = canonical_proposition('service.x', 'is_online', True,
                                            temporal_scope=canonical_scope(self.t3))
        observation = record_observation(self.db, source_ref='critic', raw_text='still down',
                                         now=self.t3 + 1)
        evidence = record_evidence(self.db, proposition, relation='CONTRADICTS', source_ref='critic',
                                   observation_ref=observation['observation_id'],
                                   evidence_time=self.t3 + 1, now=self.t3 + 1)
        record_provenance(self.db, from_evidence=evidence, relation=RELATION_PRIMARY_OBSERVATION,
                          now=self.t3 + 1)
        self.assertEqual(derive_transitions(self.db, now=self.t3 + 2), (),
                         "a contested state cannot be the endpoint of a definite change")

    # ------------------------------------------------------------------ refutations are not states
    def test_a_refutation_is_not_a_state_value(self):
        """An ABSENT fact is knowledge that a claim failed, not the world taking another state."""
        self.observe(online=True, at=self.t1)
        self.observe(online=False, at=self.t2)

        # At T3 the claim "online again" is REFUTED, so the world is still offline at T3. Reading
        # that refutation as a state would narrate a recovery the evidence denies.
        proposition = canonical_proposition('service.x', 'is_online', True,
                                            temporal_scope=canonical_scope(self.t3))
        for index in range(2):
            observation = record_observation(self.db, source_ref=f'critic-{index}',
                                             raw_text='still down', now=self.t3)
            evidence = record_evidence(self.db, proposition, relation=RELATION_CONTRADICTS,
                                       source_ref=f'critic-{index}',
                                       observation_ref=observation['observation_id'],
                                       evidence_time=self.t3, now=self.t3)
            record_provenance(self.db, from_evidence=evidence,
                              relation=RELATION_PRIMARY_OBSERVATION, now=self.t3)
        self.assertEqual(project_fact(self.db, entity=self.service, relation='is_online',
                                      value=True, scope=self.t3, now=self.t3).world_status,
                         'ABSENT')

        transitions = derive_transitions(self.db, now=self.t3)
        self.assertEqual([(t.from_value, t.to_value) for t in transitions], [('True', 'False')],
                         "a refutation must not fabricate a recovery the evidence denies")

    def test_a_refutation_never_produces_an_exact_time_flip(self):
        """A same-scope refutation of the complement must not add a second, instant-pinned change."""
        self.observe(online=True, at=self.t1)
        self.observe(online=False, at=self.t2)
        self.observe(online=True, at=self.t3)

        # A model also claims, at T3, that the service is still down; evidence refutes that claim.
        proposition = canonical_proposition('service.x', 'is_online', False,
                                            temporal_scope=canonical_scope(self.t3))
        for index in range(2):
            observation = record_observation(self.db, source_ref=f'critic-{index}',
                                             raw_text='still down', now=self.t3)
            evidence = record_evidence(self.db, proposition, relation=RELATION_CONTRADICTS,
                                       source_ref=f'critic-{index}',
                                       observation_ref=observation['observation_id'],
                                       evidence_time=self.t3, now=self.t3)
            record_provenance(self.db, from_evidence=evidence,
                              relation=RELATION_PRIMARY_OBSERVATION, now=self.t3)

        transitions = derive_transitions(self.db, now=self.t3)
        self.assertEqual(sorted((t.from_value, t.to_value) for t in transitions),
                         [('False', 'True'), ('True', 'False')])
        self.assertTrue(all(t.exact_at is None for t in transitions),
                        "nothing observed an instant, so none may be invented")

    # ------------------------------------------------------------------ law 8
    def test_law_8_dynamics_are_deterministic_across_restart_and_process(self):
        self.observe(online=False, at=self.t1)
        self.observe(online=True, at=self.t3)
        expected = dynamics_digest(self.db, now=self.t3)
        self.assertEqual(dynamics_digest(self.db, now=self.t3), expected)
        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.world_dynamics import dynamics_digest;"
                "print(dynamics_digest(%r, now=%r))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.t3))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)

    def test_dynamics_never_write_the_world_model_or_the_ledger(self):
        self.observe(online=False, at=self.t1)
        self.observe(online=True, at=self.t3)
        from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs
        ledger_before = reconstruct_beliefs(self.db, now=self.t3).canonical_digest()
        world_before = world_digest(self.db, now=self.t3)
        record_transitions(self.db, now=self.t3)
        derive_transitions(self.db, now=self.t3)
        self.assertEqual(reconstruct_beliefs(self.db, now=self.t3).canonical_digest(), ledger_before)
        self.assertEqual(world_digest(self.db, now=self.t3), world_before)


if __name__ == '__main__':
    unittest.main()
