"""
4.3 cross-gate torture - one phenomenon through the WHOLE ladder, with a restart at a boundary.

One story, told once, end to end:

    4.2    independent evidence: service.x is degraded at T2 -> CONVERGED_SUPPORTED
    4.3/0  world state: DEGRADED
    4.3/1  history: HEALTHY -> DEGRADED somewhere in (T1, T2]
    4.3/2  H1 deployment caused it; H2 upstream dependency caused it -> two predictions
    4.3/4  simulate a rollback -> projects recovery, changes NOTHING canonical
    REAL   rollback happens; new observation arrives
    4.2    the predictions resolve; H1 SUPPORTED, H2 REFUTED
    4.3/0  a new world state is derived from the real evidence
    4.3/3  the self model records that the diagnostics were actually executed

The ladder is only proven if it COMPOSES, so the digest of every layer is captured before the
rollback and again after, and a second process must reproduce both, exactly.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.causal_model import (
    HYPOTHESIS_PROPOSED,
    HYPOTHESIS_REFUTED,
    HYPOTHESIS_SUPPORTED,
    causal_digest,
    hypothesis_assessment,
    link_prediction,
    propose_hypothesis,
)
from ciph.kernel.counterfactuals import run_simulation, simulation_digest, simulation_history
from ciph.kernel.epistemic_convergence import (
    STATUS_CONVERGED_SUPPORTED,
    convergence_digest,
    project_convergence,
)
from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    canonical_proposition,
    reconstruct as reconstruct_beliefs,
    record_evidence,
    record_model_output,
    record_observation,
)
from ciph.kernel.manifest_identity import ManifestIdentity
from ciph.kernel.predictions import (
    OUTCOME_FALSE,
    OUTCOME_TRUE,
    calibrate,
    get_prediction,
    issue_prediction,
    resolve_prediction,
)
from ciph.kernel.self_model import (
    LEVEL_VERIFIED,
    project_capability,
    record_authorization,
    record_execution_evidence,
    record_installation,
    self_model_digest,
)
from ciph.kernel.source_dependence import RELATION_PRIMARY_OBSERVATION, record_provenance
from ciph.kernel.world_dynamics import derive_transitions, dynamics_digest, record_transitions
from ciph.kernel.world_model import (
    WORLD_PRESENT,
    canonical_scope,
    entity_for,
    project_fact,
    record_world_snapshot,
    world_digest,
    world_history,
)

ENV = 'host:alpha'
MANIFEST = ManifestIdentity(hash_version=1, manifest_hash='c' * 16)
T0 = 1_800_000_000.0
T1 = T0 + 100
T2 = T0 + 200
T3 = T0 + 300
T_END = T0 + 400
DEADLINE = T0 + 10_000_000


def digest_bundle(db, now, environment_ref=ENV, manifest_identity=MANIFEST):
    """Every layer's deterministic identity, so a restart can be checked layer by layer."""
    return {
        "ledger": reconstruct_beliefs(db, now=now).canonical_digest(),
        "world": world_digest(db, now=now),
        "dynamics": dynamics_digest(db, now=now),
        "convergence": convergence_digest(db, now=now),
        "causal": causal_digest(db, now=now),
        "self": self_model_digest(db, environment_ref=environment_ref,
                                  manifest_identity=manifest_identity),
        "counterfactual": simulation_digest(db),
    }


class TestGate43CrossGateTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-43-torture-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.service = entity_for('service.x', kind='service')

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def observe_state(self, relation, value, *, at, relation_kind=RELATION_SUPPORTS, sources=2):
        proposition = canonical_proposition('service.x', relation, value,
                                            temporal_scope=canonical_scope(at))
        evidence_ids = []
        for index in range(sources):
            observation = record_observation(self.db, source_ref=f'{relation}-{value}-{index}',
                                             raw_text='report', now=at)
            evidence = record_evidence(self.db, proposition, relation=relation_kind,
                                       source_ref=f'{relation}-{value}-{index}',
                                       observation_ref=observation['observation_id'],
                                       evidence_time=at, now=at)
            record_provenance(self.db, from_evidence=evidence,
                              relation=RELATION_PRIMARY_OBSERVATION, now=at)
            evidence_ids.append(evidence)
        return proposition, tuple(evidence_ids)

    def fact(self, relation, value, *, at):
        return project_fact(self.db, entity=self.service, relation=relation, value=value, scope=at,
                            now=at)

    def assert_restart_reproduces(self, expected, now):
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from test_gate_4_3_cross_gate_torture import digest_bundle, MANIFEST;"
                "print(json.dumps(digest_bundle(%r, %r, %r, MANIFEST), sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, now, ENV))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected,
                         "a fresh process must reconstruct every layer identically")

    # ------------------------------------------------------------------ the torture
    def test_the_whole_ladder_composes_and_survives_a_restart(self):
        # -- 4.2 + 4.3/0: two converged world states, one transition between them ----------------
        self.observe_state('health', 'HEALTHY', at=T1)
        self.observe_state('health', 'DEGRADED', at=T2)

        degraded = self.fact('health', 'DEGRADED', at=T2)
        self.assertEqual(degraded.world_status, WORLD_PRESENT)
        self.assertEqual(degraded.modeled_value, 'DEGRADED')
        degraded_proposition = canonical_proposition('service.x', 'health', 'DEGRADED',
                                                     temporal_scope=canonical_scope(T2))
        self.assertEqual(project_convergence(self.db, degraded_proposition.proposition_id,
                                             now=T2).status, STATUS_CONVERGED_SUPPORTED)
        record_world_snapshot(self.db, now=T2)

        # -- 4.3/1: the change is bounded, and no instant between the observations is invented ---
        transitions = derive_transitions(self.db, now=T2)
        self.assertEqual(len(transitions), 1)
        self.assertEqual((transitions[0].from_value, transitions[0].to_value),
                         ('HEALTHY', 'DEGRADED'))
        self.assertEqual((transitions[0].window_lower, transitions[0].window_upper), (T1, T2))
        self.assertIsNone(transitions[0].exact_at)
        record_transitions(self.db, now=T2)

        # -- 4.3/2: two competing hypotheses, each with a falsifiable prediction -----------------
        deployment = propose_hypothesis(self.db, cause='deployment D', effect='service degraded',
                                        now=T2, transition_refs=[transitions[0].transition_id])
        upstream = propose_hypothesis(self.db, cause='upstream dependency degradation',
                                      effect='service degraded', now=T2)
        self.assertEqual(hypothesis_assessment(self.db, deployment.hypothesis_id,
                                               now=T2).status, HYPOTHESIS_PROPOSED)

        health_t3 = canonical_proposition('service.x', 'health', 'HEALTHY',
                                          temporal_scope=canonical_scope(T3))
        latency_t3 = canonical_proposition('service.x', 'latency_elevated', True,
                                           temporal_scope=canonical_scope(T3))
        rollback_helps = issue_prediction(self.db, predictor_id='ciph', proposition=health_t3,
                                          probability=0.70, resolution_deadline=DEADLINE,
                                          resolution_rule_id='ROLLBACK_RESTORES_HEALTH', now=T2)
        rollback_useless = issue_prediction(self.db, predictor_id='ciph', proposition=latency_t3,
                                            probability=0.80, resolution_deadline=DEADLINE,
                                            resolution_rule_id='ROLLBACK_DOES_NOT_HELP', now=T2)
        link_prediction(self.db, hypothesis_id=deployment.hypothesis_id,
                        prediction_id=rollback_helps.prediction_id,
                        expect='rollback restores health', now=T2)
        link_prediction(self.db, hypothesis_id=upstream.hypothesis_id,
                        prediction_id=rollback_useless.prediction_id,
                        expect='latency stays elevated', now=T2)

        # -- 4.3/4: the counterfactual changes nothing canonical ---------------------------------
        world_before_simulation = world_digest(self.db, now=T2)
        ledger_before_simulation = reconstruct_beliefs(self.db, now=T2).canonical_digest()
        simulation = run_simulation(
            self.db, assumptions=[{'statement': 'degradation is reversible'}],
            interventions=[{'action': 'rollback deployment D'}],
            projected_outcomes=[{'outcome': 'health restored', 'probability': '0.7'}], now=T2)
        self.assertEqual(world_digest(self.db, now=T2), world_before_simulation)
        self.assertEqual(reconstruct_beliefs(self.db, now=T2).canonical_digest(),
                         ledger_before_simulation)

        # -- RESTART AT THE BOUNDARY: every layer reconstructs identically in a fresh process ----
        midway = digest_bundle(self.db, T2)
        self.assert_restart_reproduces(midway, T2)

        # -- REAL rollback: new observations arrive, and only now do predictions resolve ---------
        _, health_refs = self.observe_state('health', 'HEALTHY', at=T3)
        _, latency_refs = self.observe_state('latency_elevated', True, at=T3,
                                             relation_kind=RELATION_CONTRADICTS)
        resolve_prediction(self.db, rollback_helps.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=list(health_refs), now=T3)
        resolve_prediction(self.db, rollback_useless.prediction_id, outcome=OUTCOME_FALSE,
                           evidence_refs=list(latency_refs), now=T3)

        self.assertEqual(hypothesis_assessment(self.db, deployment.hypothesis_id,
                                               now=T3).status, HYPOTHESIS_SUPPORTED)
        self.assertEqual(hypothesis_assessment(self.db, upstream.hypothesis_id,
                                               now=T3).status, HYPOTHESIS_REFUTED)

        # -- 4.2: the forecast probability is FROZEN at the value it was issued with -------------
        frozen = get_prediction(self.db, rollback_helps.prediction_id, now=T3)
        self.assertEqual(frozen.probability, 0.70)
        calibration = calibrate(self.db, predictor_id='ciph', now=T3)
        self.assertEqual(calibration['resolved_count'], 2)
        self.assertAlmostEqual(calibration['brier_score'], (0.09 + 0.64) / 2, places=9)

        # -- 4.3/0: the world model now shows the restored state, and keeps the degraded history -
        restored = self.fact('health', 'HEALTHY', at=T3)
        self.assertEqual(restored.world_status, WORLD_PRESENT)
        record_world_snapshot(self.db, now=T3)
        self.assertEqual([h['world_status'] for h in world_history(self.db, degraded.fact_id)],
                         [WORLD_PRESENT], "the earlier degraded state is not rewritten by recovery")
        transitions_after = derive_transitions(self.db, now=T3)
        # Ordered by deterministic transition id, so compare as a set of observed changes.
        self.assertEqual(sorted((t.from_value, t.to_value) for t in transitions_after),
                         [('DEGRADED', 'HEALTHY'), ('HEALTHY', 'DEGRADED')])

        # -- 4.3/3: the self model records that the diagnostics were ACTUALLY executed -----------
        record_installation(self.db, capability_id='diagnose.service_health',
                            module_ref='diagnostics.py', environment_ref=ENV,
                            manifest_identity=MANIFEST, now=T0)
        record_authorization(self.db, capability_id='diagnose.service_health',
                             environment_ref=ENV, manifest_identity=MANIFEST, now=T0)
        record_model_output(self.db, model_ref='llm', output_text='I am excellent at diagnosis',
                            now=T3)
        before_execution = project_capability(self.db, capability_id='diagnose.service_health',
                                              environment_ref=ENV, manifest_identity=MANIFEST,
                                              now=T3)
        self.assertNotEqual(before_execution.claim_level, LEVEL_VERIFIED,
                            "prose and permission are not execution")
        record_execution_evidence(self.db, capability_id='diagnose.service_health', succeeded=True,
                                  attempt_ref='ATT-DIAG-1', receipt_ref='RCP-DIAG-1',
                                  environment_ref=ENV, manifest_identity=MANIFEST, now=T3)
        after_execution = project_capability(self.db, capability_id='diagnose.service_health',
                                             environment_ref=ENV, manifest_identity=MANIFEST,
                                             now=T3)
        self.assertEqual(after_execution.claim_level, LEVEL_VERIFIED)
        self.assertIsNotNone(after_execution.performance_ref,
                             "performance is governed execution evidence, not self-assessment")

        # -- the simulation is still exactly what it projected, and nothing new was fabricated ---
        self.assertEqual(len(simulation_history(self.db)), 1)
        self.assertEqual(simulation.projected_outcomes,
                         ({'outcome': 'health restored', 'probability': '0.7'},))

        # -- RESTART AT THE END: every layer reconstructs identically, again ----------------------
        final = digest_bundle(self.db, T_END)
        self.assert_restart_reproduces(final, T_END)
        self.assertNotEqual(final['world'], midway['world'])
        self.assertNotEqual(final['causal'], midway['causal'])
        self.assertEqual(final['counterfactual'], midway['counterfactual'],
                         "the counterfactual layer is unchanged by everything that happened after")


if __name__ == '__main__':
    unittest.main()
