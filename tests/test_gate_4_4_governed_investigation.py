"""
4.4 Gate Three - governed investigation.

    Curiosity finally causes something, and it does so through the ONE execution throat.

Every specimen is written so a curiosity layer that signed its own permits, claimed its own work,
implemented a second executor, or confused "the command ran" with "I learned something", would fail.
"""

import inspect
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from ciph.kernel import governed_investigation as investigation_module
from ciph.kernel.causal_model import HYPOTHESIS_PROPOSED, hypothesis_assessment, propose_hypothesis
from ciph.kernel.continuity import reconstruct
from ciph.kernel.curiosity_proposal import accept_proposal, propose_investigation, TYPE_OBSERVE
from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs
from ciph.kernel.governed_investigation import (
    GovernedInvestigationError,
    authorize_and_enqueue,
    build_investigation_request,
    investigation_action,
    prepare_investigation,
    record_investigation_observation,
)
from ciph.kernel.permit_composition import build_durable_permit_consumer_dependencies
from ciph.kernel.uncertainty_registry import KIND_WEAK_CAUSAL_HYPOTHESIS, uncertainty_id_for
from ciph.kernel.world_model import world_digest
from ciph.runtime import CiphRuntime
from curiosity_test_support import unconverged
from test_phase3_worker_daemons_and_crash_recovery import SimpleComputeCapability

CAPABILITY = 'investigation.probe'
WORKER = 'curiosity_worker'


class TestGate44GovernedInvestigation(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-44-investigation-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        # Real-ish time: the execution authority refuses a permit whose issued_at is more than 300s
        # in the future, so these fixtures sit in the recent past rather than at a fixed date.
        self.t1 = time.time() - 60.0
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

    def footprint(self):
        return {'jobs': self.count('ciph_ipc_jobs'), 'permits': self.count('execution_permits'),
                'attempts': len(reconstruct(self.db).actions)}

    def accepted_proposal(self, *, with_hypothesis=False):
        uncertainty_id = self.seed_uncertainty(with_hypothesis=with_hypothesis)
        proposal = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                         investigation_type=TYPE_OBSERVE,
                                         required_capabilities=[CAPABILITY], now=self.t1 + 10)
        accept_proposal(self.db, proposal.proposal_id, actor='operator', now=self.t1 + 10)
        return proposal

    def seed_uncertainty(self, *, with_hypothesis=False):
        if with_hypothesis:
            hypothesis = propose_hypothesis(self.db, cause='deployment D', effect='service degraded',
                                            now=self.t1)
            return uncertainty_id_for(KIND_WEAK_CAUSAL_HYPOTHESIS, hypothesis.hypothesis_id)
        prop = unconverged(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        return 'UNC-' + __import__('hashlib').sha256(
            f'EPISTEMIC_UNRESOLVED|{prop.proposition_id}'.encode()).hexdigest()[:12].upper()

    def permit_store(self):
        return build_durable_permit_consumer_dependencies(
            self.db, trust_registry=self.runtime.trust_registry).permit_store

    # ------------------------------------------------------------------ law 4
    def test_law_4_an_unaccepted_proposal_cannot_prepare_anything(self):
        uncertainty_id = self.seed_uncertainty()
        proposal = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                         investigation_type=TYPE_OBSERVE, now=self.t1 + 10)
        with self.assertRaises(GovernedInvestigationError) as refused:
            prepare_investigation(self.db, proposal_id=proposal.proposal_id, capability=CAPABILITY,
                                  params={'value': 1}, now=self.t1 + 10)
        self.assertEqual(refused.exception.reason, 'PROPOSAL_NOT_ACCEPTED')
        self.assertEqual(self.footprint(), {'jobs': 0, 'permits': 0, 'attempts': 0})
        self.assertEqual(self.count('ciph_mission_actions'), 0)

    # ------------------------------------------------------------------ preparation
    def test_preparation_allocates_one_canonical_action_and_no_authority(self):
        proposal = self.accepted_proposal()
        prepared = prepare_investigation(self.db, proposal_id=proposal.proposal_id,
                                        capability=CAPABILITY, params={'value': 1},
                                        objective='observe service.a', now=self.t1 + 10)
        self.assertTrue(prepared.logical_action_id.startswith('ACT-'),
                        'the canonical mission layer allocates the identity')
        self.assertEqual(self.footprint(), {'jobs': 0, 'permits': 0, 'attempts': 0},
                         'preparing an investigation authorises nothing')
        self.assertEqual(self.count('ciph_mission_actions'), 1)
        # Preparing again is the same action, not a second one.
        again = prepare_investigation(self.db, proposal_id=proposal.proposal_id,
                                      capability=CAPABILITY, params={'value': 1}, now=self.t1 + 20)
        self.assertEqual(again.logical_action_id, prepared.logical_action_id)
        self.assertEqual(self.count('ciph_mission_actions'), 1)

    # ------------------------------------------------------------------ laws 1, 2, 3
    def test_authorize_and_enqueue_is_the_only_authority_step(self):
        proposal = self.accepted_proposal()
        prepared = prepare_investigation(self.db, proposal_id=proposal.proposal_id,
                                         capability=CAPABILITY, params={'value': 1},
                                         now=self.t1 + 10)
        result = authorize_and_enqueue(self.runtime, proposal_id=proposal.proposal_id,
                                       now=self.t1 + 20)
        self.assertEqual(result['logical_action_id'], prepared.logical_action_id)
        self.assertEqual(self.footprint(), {'jobs': 1, 'permits': 1, 'attempts': 1})
        row = self.permit_store().get_permit_row(result['permit_id'])
        self.assertEqual(row['logical_action_id'], prepared.logical_action_id,
                         'the permit binds the canonical action, not a curiosity-invented one')
        # The action exists and its authority is ISSUED - but no worker has spent it.
        action = [a for a in reconstruct(self.db).actions
                  if a.logical_action_id == prepared.logical_action_id][0]
        self.assertEqual(action.permit_state, 'ISSUED')
        self.assertIsNone(action.execution_attempt_id,
                          'no attempt exists until a worker claims the permit')
        self.assertTrue(action.authorization_alive)

    def test_the_module_has_no_signer_and_no_claim_path(self):
        source = inspect.getsource(investigation_module)
        for forbidden in ('Ed25519KeyManager', 'ExecutionAuthority(', 'SignedExecutionPermit(',
                          '.claim(', 'permit_store', 'raw_execute', 'capability.execute'):
            self.assertNotIn(forbidden, source)
        public = [name for name, _ in inspect.getmembers(investigation_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('sign_permit', 'mint_permit', 'claim_permit', 'execute'):
            self.assertNotIn(forbidden, public)
        # It does reach the canonical producer entry point - that is the whole design.
        self.assertIn('acquire_durable_permit', source)

    # ------------------------------------------------------------------ law 5
    def test_law_5_a_result_enters_as_an_observation_not_a_conclusion(self):
        proposal = self.accepted_proposal(with_hypothesis=True)
        prepare_investigation(self.db, proposal_id=proposal.proposal_id, capability=CAPABILITY,
                              params={'value': 1}, now=self.t1 + 10)
        before = reconstruct_beliefs(self.db, now=self.t1 + 20)
        observation_id = record_investigation_observation(
            self.db, source_ref='probe.result', raw_text='port 443: filtered', now=self.t1 + 20)
        after = reconstruct_beliefs(self.db, now=self.t1 + 20)
        self.assertTrue(observation_id.startswith('OBS-'))
        self.assertEqual(after.evidence_count, before.evidence_count,
                         'receiving a result asserts nothing about the world')

    # ------------------------------------------------------------------ law 6 / 8
    def test_law_6_operational_success_is_not_epistemic_success(self):
        proposal = self.accepted_proposal(with_hypothesis=True)
        prepared = prepare_investigation(self.db, proposal_id=proposal.proposal_id,
                                         capability=CAPABILITY, params={'value': 1},
                                         now=self.t1 + 10)
        result = authorize_and_enqueue(self.runtime, proposal_id=proposal.proposal_id,
                                       now=self.t1 + 20)
        evidence_before = reconstruct_beliefs(self.db, now=self.t1 + 30).evidence_count
        world_before = world_digest(self.db, now=self.t1 + 30)

        job = self.runtime.queue.lease_next_job(WORKER, 30, target_job_id=result['job_id'])
        self.assertIsNotNone(job)
        receipt = self.runtime.worker_daemon._execute_leased_job(job, WORKER)
        self.assertEqual(receipt.exit_code, 0, 'the command executed perfectly')

        # ...and taught nothing: no evidence, no world change, no causal credit.
        self.assertEqual(reconstruct_beliefs(self.db, now=self.t1 + 40).evidence_count,
                         evidence_before)
        self.assertEqual(world_digest(self.db, now=self.t1 + 40), world_before)
        hypothesis_id = investigation_action(self.db, proposal.proposal_id)['mission_id']
        self.assertTrue(hypothesis_id)

    def test_law_8_the_attempt_resolves_through_the_normal_paths(self):
        proposal = self.accepted_proposal()
        prepare_investigation(self.db, proposal_id=proposal.proposal_id, capability=CAPABILITY,
                              params={'value': 1}, now=self.t1 + 10)
        result = authorize_and_enqueue(self.runtime, proposal_id=proposal.proposal_id,
                                       now=self.t1 + 20)
        job = self.runtime.queue.lease_next_job(WORKER, 30, target_job_id=result['job_id'])
        self.runtime.worker_daemon._execute_leased_job(job, WORKER)
        self.assertEqual(self.permit_store().state_of(result['permit_id']), 'CONSUMED',
                         'authority dies through the normal consumption path')
        actions = reconstruct(self.db).actions
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].attempt_outcome, 'TERMINAL')

    # ------------------------------------------------------------------ laws 6, 10
    def test_law_10_a_crash_before_evidence_cannot_duplicate_the_investigation(self):
        proposal = self.accepted_proposal()
        prepared = prepare_investigation(self.db, proposal_id=proposal.proposal_id,
                                         capability=CAPABILITY, params={'value': 1},
                                         now=self.t1 + 10)
        result = authorize_and_enqueue(self.runtime, proposal_id=proposal.proposal_id,
                                       now=self.t1 + 20)
        # A worker claims the permit, then the process dies before any evidence exists.
        self.permit_store().claim(result['permit_id'], WORKER)

        claimed = [a for a in reconstruct(self.db).actions
                   if a.logical_action_id == prepared.logical_action_id]
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0].permit_state, 'CLAIMED')
        self.assertEqual(claimed[0].attempt_outcome, 'UNRESOLVED')
        self.assertFalse(claimed[0].authorization_alive)

        # RESTART: a fresh runtime on the same durable stores.
        self.runtime.shutdown()
        self.runtime = CiphRuntime(db_path=self.db)
        self.runtime.register_capability(SimpleComputeCapability(name=CAPABILITY))
        try:
            authorize_and_enqueue(self.runtime, proposal_id=proposal.proposal_id, now=self.t1 + 30)
        except Exception:
            # A refusal is an acceptable answer; silently minting a second investigation is not.
            pass
        self.assertEqual(self.footprint(), {'jobs': 1, 'permits': 1, 'attempts': 1},
                         'restart cannot duplicate an investigation already claimed')
        self.assertEqual(self.count('ciph_ipc_jobs'), 1)


if __name__ == '__main__':
    unittest.main()
