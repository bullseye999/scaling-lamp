"""
4.3 Gate Four - counterfactuals.

    A simulation projects what MIGHT happen under an intervention. It is never an observation, never
    evidence, never a world fact, and never authority.

Every specimen is written so a counterfactual layer that let an imagined outcome leak into canonical
state, evidence, predictions, or authority would fail.
"""

import inspect
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph import kernel
from ciph.kernel.counterfactuals import (
    MODEL_VERSION_V1,
    SIMULATION_KIND,
    CounterfactualError,
    as_evidence_ref,
    attach_outcome,
    get_simulation,
    outcome_history,
    run_simulation,
    simulation_digest,
    simulation_history,
)
from ciph.kernel.epistemic_ledger import (
    RELATION_SUPPORTS,
    canonical_proposition,
    reconstruct as reconstruct_beliefs,
    record_evidence,
    record_observation,
)
from ciph.kernel.source_dependence import RELATION_PRIMARY_OBSERVATION, record_provenance
from ciph.kernel.world_model import canonical_scope, entity_for, project_entities, world_digest


class TestGate43Counterfactuals(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-43-cf-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    def seed_degraded_service(self):
        """A small converged world state: service.x is degraded at T1."""
        proposition = canonical_proposition('service.x', 'is_degraded', True,
                                            temporal_scope=canonical_scope(self.t1))
        for index in range(2):
            observation = record_observation(self.db, source_ref=f'src-{index}', raw_text='degraded',
                                             now=self.t1)
            evidence = record_evidence(self.db, proposition, relation=RELATION_SUPPORTS,
                                       source_ref=f'src-{index}',
                                       observation_ref=observation['observation_id'],
                                       evidence_time=self.t1, now=self.t1)
            record_provenance(self.db, from_evidence=evidence,
                              relation=RELATION_PRIMARY_OBSERVATION, now=self.t1)
        return proposition

    def count(self, table):
        conn = sqlite3.connect(self.db)
        try:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    # ------------------------------------------------------------------ founding specimen
    def test_founding_a_simulation_records_basis_assumptions_and_interventions(self):
        self.seed_degraded_service()
        simulation = run_simulation(
            self.db, assumptions=[{'statement': 'degradation is reversible'},
                                  {'statement': 'no traffic spike'}],
            interventions=[{'action': 'restart service X'}],
            projected_outcomes=[{'outcome': 'recovery', 'probability': '0.7'}], now=self.t1)
        self.assertEqual(simulation.epistemic_kind, SIMULATION_KIND)
        self.assertEqual(simulation.model_version, MODEL_VERSION_V1)
        self.assertEqual(simulation.world_basis_digest, world_digest(self.db, now=self.t1),
                         "the simulation is explicitly bound to the world state it started from")
        self.assertEqual(simulation.interventions, ({'action': 'restart service X'},))
        self.assertEqual(len(simulation.assumptions), 2)

    # ------------------------------------------------------------------ laws 4, 5, 6
    def test_law_4_simulation_changes_nothing_canonical(self):
        self.seed_degraded_service()
        ledger_before = reconstruct_beliefs(self.db, now=self.t1).canonical_digest()
        world_before = world_digest(self.db, now=self.t1)
        facts_before = len(project_entities(self.db, now=self.t1))

        run_simulation(self.db, interventions=[{'action': 'restart service X'}],
                       projected_outcomes=[{'outcome': 'recovery'}], now=self.t1)
        run_simulation(self.db, interventions=[{'action': 'do nothing'}],
                       projected_outcomes=[{'outcome': 'stays degraded'}], now=self.t1)

        self.assertEqual(reconstruct_beliefs(self.db, now=self.t1).canonical_digest(), ledger_before,
                         "a simulation cannot create evidence")
        self.assertEqual(world_digest(self.db, now=self.t1), world_before,
                         "a simulation cannot modify the canonical world state")
        self.assertEqual(len(project_entities(self.db, now=self.t1)), facts_before)

    def test_law_5_a_simulation_is_never_evidence(self):
        simulation = run_simulation(self.db, interventions=[{'action': 'restart'}],
                                    projected_outcomes=[{'outcome': 'recovery'}], now=self.t1)
        with self.assertRaises(CounterfactualError) as refused:
            as_evidence_ref(simulation.simulation_id)
        self.assertEqual(refused.exception.reason, 'SIMULATION_IS_NOT_EVIDENCE')
        self.assertEqual(self.count('ciph_evidence'), 0)

    def test_law_6_the_module_cannot_issue_authority(self):
        source = inspect.getsource(kernel.counterfactuals)
        for forbidden in ('permit', 'execution_authority', 'execution_gateway', 'permit_store',
                          'guarded'):
            self.assertNotIn(f'import {forbidden}', source.lower())
        public = [name for name, _ in inspect.getmembers(kernel.counterfactuals, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('execute', 'issue_permit', 'dispatch'):
            self.assertNotIn(forbidden, public)
        self.assertEqual(self.count('ciph_predictions'), 0)

    # ------------------------------------------------------------------ law 7
    def test_law_7_competing_counterfactuals_coexist(self):
        self.seed_degraded_service()
        restart = run_simulation(self.db, interventions=[{'action': 'restart service X'}],
                                 projected_outcomes=[{'outcome': 'recovery'}], now=self.t1)
        nothing = run_simulation(self.db, interventions=[{'action': 'do nothing'}],
                                 projected_outcomes=[{'outcome': 'stays degraded'}], now=self.t1)
        self.assertNotEqual(restart.simulation_id, nothing.simulation_id)
        self.assertEqual(len(simulation_history(self.db)), 2)

    # ------------------------------------------------------------------ law 9
    def test_law_9_a_simulation_creates_no_prediction(self):
        self.seed_degraded_service()
        run_simulation(self.db, interventions=[{'action': 'restart'}],
                       projected_outcomes=[{'outcome': 'recovery', 'probability': '0.7'}],
                       now=self.t1)
        self.assertEqual(self.count('ciph_predictions'), 0,
                         "a projection becomes a real prediction only through Gate 4.2's own boundary")

    # ------------------------------------------------------------------ law 11
    def test_law_11_same_basis_and_model_give_one_deterministic_simulation(self):
        self.seed_degraded_service()
        first = run_simulation(self.db, assumptions=['a'], interventions=['i'],
                               projected_outcomes=['o'], now=self.t1)
        same = run_simulation(self.db, assumptions=['a'], interventions=['i'],
                              projected_outcomes=['o'], now=self.t1 + 60)
        other = run_simulation(self.db, assumptions=['a', 'different'], interventions=['i'],
                               projected_outcomes=['o'], now=self.t1 + 60)
        self.assertEqual(first.simulation_id, same.simulation_id,
                         "the same counterfactual is one simulation")
        self.assertEqual(len(simulation_history(self.db)), 2)
        self.assertNotEqual(first.simulation_id, other.simulation_id)

        expected = simulation_digest(self.db)
        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.counterfactuals import run_simulation, simulation_digest;"
                "print(simulation_digest(%r))" % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)

    # ------------------------------------------------------------------ laws 10, 12
    def test_law_10_and_12_scoring_never_rewrites_what_was_projected(self):
        self.seed_degraded_service()
        simulation = run_simulation(self.db, assumptions=['reversible'],
                                    interventions=[{'action': 'restart service X'}],
                                    projected_outcomes=[{'outcome': 'recovery', 'probability': '0.7'}],
                                    now=self.t1)
        snapshot = get_simulation(self.db, simulation.simulation_id).canonical_digest()
        attach_outcome(self.db, simulation.simulation_id, observed_outcome='degraded',
                       matched=False, evidence_ref='OBS-REAL', now=self.t1 + 100)
        self.assertEqual(get_simulation(self.db, simulation.simulation_id).canonical_digest(),
                         snapshot, "reality scoring the projection must not rewrite the projection")
        self.assertEqual(len(outcome_history(self.db, simulation.simulation_id)), 1)

    # ------------------------------------------------------------------ law 8
    def test_law_8_unknown_dynamics_stay_unknown(self):
        self.seed_degraded_service()
        simulation = run_simulation(self.db, assumptions=['model cannot say'],
                                    interventions=[{'action': 'unknown effect'}],
                                    projected_outcomes=[{'outcome': 'UNKNOWN'}], now=self.t1)
        # The unknown is preserved as unknown, not filled with a confident verdict or a world fact.
        self.assertEqual(simulation.projected_outcomes, ({'outcome': 'UNKNOWN'},))
        self.assertEqual(self.count('ciph_evidence'), 2, "only the seeded support, nothing added")
        self.assertEqual(world_digest(self.db, now=self.t1),
                         simulation.world_basis_digest)

    # ------------------------------------------------------------------ law 1
    def test_law_1_an_explicit_basis_overrides_the_derived_one(self):
        self.seed_degraded_service()
        simulation = run_simulation(self.db, interventions=['i'], projected_outcomes=['o'],
                                    world_basis_digest='BASIS-EXPLICIT', now=self.t1)
        self.assertEqual(simulation.world_basis_digest, 'BASIS-EXPLICIT')
        self.assertNotEqual(simulation.world_basis_digest, world_digest(self.db, now=self.t1))


if __name__ == '__main__':
    unittest.main()
