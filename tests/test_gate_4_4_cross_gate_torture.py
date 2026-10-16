"""
4.4 cross-gate torture - one real epistemic problem through 4.2, 4.3 and all of 4.4, plus the
hostile twin where the operator never authorises.

The constitutional thesis under test:

    curiosity can desire information without acquiring authority to obtain it.

The ladder runs end to end: epistemic uncertainty -> derived uncertainty -> priority -> proposal ->
governance decision -> canonical action -> permit -> GuardedExecutor -> observation -> evidence ->
prediction resolution -> causal assessment -> measured information gain, with a restart at the end
that must reproduce every digest exactly. The hostile twin stops after the proposal and proves that
NOTHING moved.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ciph.kernel.causal_model import (
    HYPOTHESIS_SUPPORTED,
    HYPOTHESIS_REFUTED,
    causal_digest,
    hypothesis_assessment,
    link_prediction,
    propose_hypothesis,
)
from ciph.kernel.continuity import reconstruct
from ciph.kernel.curiosity_learning import (
    RESULT_RESOLVED,
    begin_investigation,
    close_investigation,
    learning_digest,
)
from ciph.kernel.curiosity_priority import CURIOSITY_PRIORITY_V1, derive_priority, priority_digest
from ciph.kernel.curiosity_proposal import (
    STATUS_ACCEPTED,
    TYPE_OBSERVE,
    accept_proposal,
    propose_investigation,
    proposal_digest,
    proposal_history,
    proposal_status,
)
from ciph.kernel.epistemic_convergence import convergence_digest
from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    canonical_proposition,
    reconstruct as reconstruct_beliefs,
)
from ciph.kernel.governed_investigation import (
    authorize_and_enqueue,
    investigation_digest,
    prepare_investigation,
    record_investigation_observation,
)
from ciph.kernel.missions import open_mission
from ciph.kernel.predictions import OUTCOME_FALSE, OUTCOME_TRUE, issue_prediction, resolve_prediction
from ciph.kernel.uncertainty_registry import (
    KIND_WEAK_CAUSAL_HYPOTHESIS,
    STATUS_SATISFIED,
    derive_uncertainties,
    record_uncertainty_snapshots,
    uncertainty_digest,
    uncertainty_id_for,
    uncertainty_status,
)
from ciph.kernel.world_dynamics import derive_transitions, dynamics_digest
from ciph.kernel.world_model import canonical_scope, world_digest
from ciph.runtime import CiphRuntime
from curiosity_test_support import converge
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability

CAPABILITY = 'investigation.probe'
WORKER = 'curiosity_worker'
SUBJECT = 'service.c'
EFFECT = 'service.c degraded'


def digest_bundle(db, now):
    """Every 4.2 / 4.3 / 4.4 layer identity, so a restart can be checked layer by layer."""
    return {
        'ledger': reconstruct_beliefs(db, now=now).canonical_digest(),
        'world': world_digest(db, now=now),
        'dynamics': dynamics_digest(db, now=now),
        'convergence': convergence_digest(db, now=now),
        'causal': causal_digest(db, now=now),
        'uncertainty': uncertainty_digest(db, now=now),
        'priority': priority_digest(db, now=now),
        'learning': learning_digest(db),
        'proposal': proposal_digest(db),
        'investigation': investigation_digest(db),
    }


class TestGate44CrossGateTorture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-44-torture-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = time.time() - 60.0
        self.t2 = self.t1 + 10
        self.t3 = self.t1 + 20
        self.t4 = self.t1 + 30
        self.deadline = time.time() + 10_000_000.0
        self.runtime = CiphRuntime(db_path=self.db)
        self.runtime.register_capability(SimpleComputeCapability(name=CAPABILITY))

    def tearDown(self):
        self.runtime.shutdown()
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def count(self, table):
        conn = sqlite3.connect(self.db)
        try:
            return int(conn.execute(f'SELECT COUNT(*) FROM {table};').fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    def seed_problem(self):
        """4.2 + 4.3: a degraded service with two competing causal explanations."""
        converge(self.db, SUBJECT, 'health', 'HEALTHY', at=self.t1)
        converge(self.db, SUBJECT, 'health', 'DEGRADED', at=self.t2)
        deployment = propose_hypothesis(self.db, cause='deployment D', effect=EFFECT, now=self.t2)
        upstream = propose_hypothesis(self.db, cause='upstream degradation', effect=EFFECT,
                                      now=self.t2)
        health_t3 = canonical_proposition(SUBJECT, 'health', 'HEALTHY',
                                          temporal_scope=canonical_scope(self.t3))
        latency_t3 = canonical_proposition(SUBJECT, 'latency_elevated', True,
                                           temporal_scope=canonical_scope(self.t3))
        helps = issue_prediction(self.db, predictor_id='ciph', proposition=health_t3,
                                 probability=0.70, resolution_deadline=self.deadline,
                                 resolution_rule_id='ROLLBACK_RESTORES_HEALTH', now=self.t2)
        useless = issue_prediction(self.db, predictor_id='ciph', proposition=latency_t3,
                                   probability=0.80, resolution_deadline=self.deadline,
                                   resolution_rule_id='ROLLBACK_DOES_NOT_HELP', now=self.t2)
        link_prediction(self.db, hypothesis_id=deployment.hypothesis_id,
                        prediction_id=helps.prediction_id, expect='rollback restores health',
                        now=self.t2)
        link_prediction(self.db, hypothesis_id=upstream.hypothesis_id,
                        prediction_id=useless.prediction_id, expect='latency stays elevated',
                        now=self.t2)
        return deployment, upstream, helps, useless

    def assert_restart_reproduces(self, expected, now):
        code = ('import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from test_gate_4_4_cross_gate_torture import digest_bundle;'
                'print(json.dumps(digest_bundle(%r, %r), sort_keys=True))'
                % (str(Path(__file__).resolve().parents[1]), self.db, now))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected,
                         'a fresh process must reconstruct every layer identically')

    # ------------------------------------------------------------------ the ladder
    def test_the_whole_curiosity_ladder_composes_and_survives_a_restart(self):
        deployment, upstream, helps, useless = self.seed_problem()
        self.assertEqual(len(derive_transitions(self.db, now=self.t2)), 1)

        # --- 4.4 Gate Zero: the uncertainty is DERIVED, not invented --------------------------
        record_uncertainty_snapshots(self.db, now=self.t3)
        weak = [u for u in derive_uncertainties(self.db, now=self.t3)
                if u.source_kind == KIND_WEAK_CAUSAL_HYPOTHESIS]
        self.assertEqual(len(weak), 2, 'both explanations are unresolved questions')
        target = uncertainty_id_for(KIND_WEAK_CAUSAL_HYPOTHESIS, deployment.hypothesis_id)
        self.assertIn(target, {u.uncertainty_id for u in weak})

        # --- 4.4 Gate One: a mission makes it valuable; relevance authorises nothing ----------
        open_mission(self.db, objective=f'investigate {EFFECT}', now=self.t3)
        priority = derive_priority(self.db, target, now=self.t3)
        self.assertEqual(priority.metric_id, CURIOSITY_PRIORITY_V1)
        self.assertGreater(priority.score, 0.0)
        self.assertIn('MISSION_RELEVANT', priority.reason_codes)

        # --- 4.4 Gate Two: a proposal, and STILL zero authority -------------------------------
        proposal = propose_investigation(self.db, uncertainty_id=target,
                                         investigation_type=TYPE_OBSERVE,
                                         required_capabilities=[CAPABILITY],
                                         expected_resolution_conditions=[
                                             'health observed after rollback'], now=self.t3)
        self.assertEqual(self.count('ciph_ipc_jobs'), 0)
        self.assertEqual(self.count('execution_permits'), 0)
        self.assertEqual(self.count('ciph_mission_actions'), 0)
        accept_proposal(self.db, proposal.proposal_id, actor='operator', now=self.t3)
        self.assertEqual(proposal_status(self.db, proposal.proposal_id, now=self.t3), STATUS_ACCEPTED)
        self.assertEqual(self.count('ciph_ipc_jobs'), 0, 'acceptance is not authority')
        self.assertEqual(self.count('execution_permits'), 0)

        # --- 4.4 Gate Four: freeze the BEFORE state ------------------------------------------
        outcome_id = begin_investigation(self.db, uncertainty_id=target,
                                         proposal_id=proposal.proposal_id, now=self.t3)

        # --- 4.4 Gate Three: the one execution throat -----------------------------------------
        prepared = prepare_investigation(self.db, proposal_id=proposal.proposal_id,
                                         capability=CAPABILITY, params={'value': 1},
                                         objective=f'investigate {EFFECT}', now=self.t3)
        self.assertEqual(self.count('ciph_ipc_jobs'), 0)
        self.assertEqual(self.count('execution_permits'), 0)
        result = authorize_and_enqueue(self.runtime, proposal_id=proposal.proposal_id, now=self.t4)
        self.assertEqual(result['logical_action_id'], prepared.logical_action_id)
        job = self.runtime.queue.lease_next_job(WORKER, 30, target_job_id=result['job_id'])
        receipt = self.runtime.worker_daemon._execute_leased_job(job, WORKER)
        self.assertEqual(receipt.exit_code, 0)
        observation_id = record_investigation_observation(
            self.db, source_ref='rollback.observation',
            raw_text='service.c healthy after rollback', now=self.t4)
        self.assertTrue(observation_id.startswith('OBS-'))

        # --- 4.2: evidence admitted, and only then do the predictions resolve -----------------
        health_ids = list(converge(self.db, SUBJECT, 'health', 'HEALTHY', at=self.t3)[1])
        latency_ids = list(converge(self.db, SUBJECT, 'latency_elevated', True, at=self.t3,
                                    relation=RELATION_CONTRADICTS)[1])
        resolve_prediction(self.db, helps.prediction_id, outcome=OUTCOME_TRUE,
                           evidence_refs=health_ids, now=self.t4)
        resolve_prediction(self.db, useless.prediction_id, outcome=OUTCOME_FALSE,
                           evidence_refs=latency_ids, now=self.t4)

        # --- 4.3: the causal assessment moved, on canonical evidence alone --------------------
        self.assertEqual(hypothesis_assessment(self.db, deployment.hypothesis_id,
                                               now=self.t4).status, HYPOTHESIS_SUPPORTED)
        self.assertEqual(hypothesis_assessment(self.db, upstream.hypothesis_id,
                                               now=self.t4).status, HYPOTHESIS_REFUTED)

        # --- 4.4 Gate Four: the AFTER state is measured, not narrated -------------------------
        outcome = close_investigation(self.db, outcome_id, attempted=True, now=self.t4)
        self.assertEqual(outcome.result, RESULT_RESOLVED)
        self.assertGreater(outcome.information_gain, 0)
        self.assertEqual(uncertainty_status(self.db, target, now=self.t4), STATUS_SATISFIED)
        self.assertNotIn(target, {u.uncertainty_id
                                  for u in derive_uncertainties(self.db, now=self.t4)})

        # --- RESTART: every 4.2 / 4.3 / 4.4 digest identical ----------------------------------
        bundle = digest_bundle(self.db, self.t4)
        self.assert_restart_reproduces(bundle, self.t4)

    # ------------------------------------------------------------------ the hostile twin
    def test_the_hostile_twin_never_authorised_moves_nothing(self):
        deployment, _upstream, _helps, _useless = self.seed_problem()
        target = uncertainty_id_for(KIND_WEAK_CAUSAL_HYPOTHESIS, deployment.hypothesis_id)
        proposal = propose_investigation(self.db, uncertainty_id=target,
                                         investigation_type=TYPE_OBSERVE,
                                         required_capabilities=[CAPABILITY], now=self.t3)

        before = digest_bundle(self.db, self.t3)
        observations_before = self.count('ciph_observations')

        # The operator never authorises. Nothing else happens. Then the process restarts.
        self.assertEqual(proposal_status(self.db, proposal.proposal_id, now=self.t3), 'PROPOSED')
        self.assertEqual(self.count('ciph_ipc_jobs'), 0)
        self.assertEqual(self.count('execution_permits'), 0)
        self.assertEqual(len(reconstruct(self.db).actions), 0)
        self.assertEqual(self.count('ciph_mission_actions'), 0)

        self.assert_restart_reproduces(before, self.t3)
        self.assertEqual(digest_bundle(self.db, self.t3), before)
        self.assertEqual(self.count('ciph_observations'), observations_before,
                         'no observation was ever taken')
        self.assertEqual(len(proposal_history(self.db)), 1, 'the proposal is preserved historically')
        self.assertIsNone(proposal_history(self.db)[0]['decision'])


if __name__ == '__main__':
    unittest.main()
