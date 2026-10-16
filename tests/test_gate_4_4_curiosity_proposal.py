"""
4.4 Gate Two - curiosity proposals.

    A curiosity proposal grants ZERO execution authority.

The load-bearing specimen is that creating AND accepting a proposal moves no jobs, no permits, no
attempts and no claims. Acceptance means "this investigation is approved as a proposal", never "this
investigation has execution authority".
"""

import inspect
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import curiosity_proposal as proposal_module
from ciph.kernel.continuity import reconstruct
from ciph.kernel.curiosity_proposal import (
    STATUS_ACCEPTED,
    STATUS_PROPOSED,
    STATUS_REJECTED,
    STATUS_STALE,
    TYPE_DO_NOTHING,
    TYPE_OBSERVE,
    TYPE_RUN_SIMULATION,
    CuriosityProposalError,
    accept_proposal,
    get_proposal,
    propose_investigation,
    proposal_digest,
    proposal_history,
    proposal_status,
    recommend_do_nothing,
    reject_proposal,
)
from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs
from ciph.kernel.self_model import LEVEL_AVAILABLE, project_capability, record_installation
from ciph.kernel.uncertainty_registry import KIND_EPISTEMIC_UNRESOLVED, uncertainty_id_for
from curiosity_test_support import add_evidence, unconverged


class TestGate44CuriosityProposal(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-44-proposal-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.t2 = self.t1 + 100

    def tearDown(self):
        self.temp.cleanup()

    def count(self, table):
        conn = sqlite3.connect(self.db)
        try:
            return int(conn.execute(f'SELECT COUNT(*) FROM {table};').fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    def authority_footprint(self):
        return {'jobs': self.count('ciph_ipc_jobs'), 'permits': self.count('execution_permits'),
                'attempts': len(reconstruct(self.db).actions),
                'claims': self.count('ciph_permit_claims')}

    def seed(self):
        prop = unconverged(self.db, 'service.a', 'is_healthy', True, at=self.t1)
        return uncertainty_id_for(KIND_EPISTEMIC_UNRESOLVED, prop.proposition_id)

    # ------------------------------------------------------------------ the load-bearing specimen
    def test_creating_and_accepting_a_proposal_grants_zero_authority(self):
        uncertainty_id = self.seed()
        before = self.authority_footprint()
        self.assertEqual(before, {'jobs': 0, 'permits': 0, 'attempts': 0, 'claims': 0})

        proposal = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                         investigation_type=TYPE_OBSERVE,
                                         required_capabilities=['probe.port'],
                                         expected_resolution_conditions=['port state observed'],
                                         now=self.t2)
        self.assertEqual(self.authority_footprint(), before, 'creating a proposal authorises nothing')
        accept_proposal(self.db, proposal.proposal_id, actor='operator', now=self.t2)
        self.assertEqual(self.authority_footprint(), before,
                         'ACCEPTING a proposal still authorises nothing at all')
        self.assertEqual(proposal_status(self.db, proposal.proposal_id, now=self.t2), STATUS_ACCEPTED)
        # The proposal is a statement of intent, and it says so.
        self.assertEqual(get_proposal(self.db, proposal.proposal_id).investigation_type, TYPE_OBSERVE)

    # ------------------------------------------------------------------ structural
    def test_the_module_has_no_authority_surface(self):
        source = inspect.getsource(proposal_module)
        for forbidden in ('acquire_durable_permit', 'permit_store', 'ExecutionAuthority',
                          'enqueue_job', 'apply_plan_proposal', 'mint_execution_token',
                          'GuardedExecutor'):
            self.assertNotIn(forbidden, source)
        public = [name for name, _ in inspect.getmembers(proposal_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('execute', 'authorize', 'enqueue', 'issue_permit', 'claim'):
            self.assertNotIn(forbidden, public)

    # ------------------------------------------------------------------ laws 4 and 5
    def test_law_4_and_5_a_proposal_binds_its_basis_and_goes_stale_when_it_moves(self):
        uncertainty_id = self.seed()
        proposal = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                         investigation_type=TYPE_OBSERVE, now=self.t2)
        self.assertEqual(proposal_status(self.db, proposal.proposal_id, now=self.t2), STATUS_PROPOSED)

        # The canonical uncertainty moves (the source-dependence picture changes) without resolving.
        from ciph.kernel.epistemic_ledger import canonical_proposition
        from ciph.kernel.world_model import canonical_scope
        prop = canonical_proposition('service.a', 'is_healthy', True,
                                     temporal_scope=canonical_scope(self.t1))
        add_evidence(self.db, prop, source_ref='mirror', at=self.t1, independent=False)

        self.assertEqual(proposal_status(self.db, proposal.proposal_id, now=self.t2), STATUS_STALE)
        before = self.authority_footprint()
        with self.assertRaises(CuriosityProposalError) as refused:
            accept_proposal(self.db, proposal.proposal_id, actor='operator', now=self.t2)
        self.assertEqual(refused.exception.reason, 'STALE_CURIOSITY_PROPOSAL')
        self.assertEqual(self.authority_footprint(), before, 'a stale acceptance has no side effects')

    # ------------------------------------------------------------------ law 3
    def test_law_3_a_proposal_carries_no_logical_action_identity(self):
        uncertainty_id = self.seed()
        proposal = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                         investigation_type=TYPE_OBSERVE, now=self.t2)
        payload = proposal.as_dict()
        for forbidden in ('logical_action_id', 'action_id', 'job_id', 'permit_id'):
            self.assertNotIn(forbidden, payload)
        self.assertEqual(self.count('ciph_mission_actions'), 0)
        self.assertEqual(self.count('ciph_curiosity_investigation_actions'), 0)

    # ------------------------------------------------------------------ law 6
    def test_law_6_requiring_a_capability_does_not_grant_it(self):
        uncertainty_id = self.seed()
        record_installation(self.db, capability_id='probe.port', module_ref='probe.py',
                            environment_ref='host:a', now=self.t1)
        before = project_capability(self.db, capability_id='probe.port', environment_ref='host:a',
                                    now=self.t2)
        self.assertEqual(before.claim_level, LEVEL_AVAILABLE)
        propose_investigation(self.db, uncertainty_id=uncertainty_id, investigation_type=TYPE_OBSERVE,
                              required_capabilities=['probe.port'], now=self.t2)
        after = project_capability(self.db, capability_id='probe.port', environment_ref='host:a',
                                   now=self.t2)
        self.assertEqual(after.claim_level, before.claim_level,
                         'asking for a capability is a request, not a grant')
        self.assertEqual(self.count('ciph_self_authorizations'), 0)
        self.assertEqual(self.count('ciph_self_executions'), 0)

    # ------------------------------------------------------------------ law 9
    def test_law_9_do_nothing_is_a_valid_conclusion(self):
        uncertainty_id = self.seed()
        proposal = recommend_do_nothing(self.db, uncertainty_id=uncertainty_id,
                                        rationale='cost exceeds any plausible decision value',
                                        now=self.t2)
        self.assertEqual(proposal.investigation_type, TYPE_DO_NOTHING)
        self.assertEqual(proposal.required_capabilities, ())
        self.assertEqual(self.authority_footprint(),
                         {'jobs': 0, 'permits': 0, 'attempts': 0, 'claims': 0})

    # ------------------------------------------------------------------ law 10
    def test_law_10_a_rejected_curiosity_remains_historical(self):
        uncertainty_id = self.seed()
        proposal = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                         investigation_type=TYPE_OBSERVE, now=self.t2)
        reject_proposal(self.db, proposal.proposal_id, actor='operator',
                        reason='not worth it', now=self.t2)
        self.assertEqual(proposal_status(self.db, proposal.proposal_id, now=self.t2), STATUS_REJECTED)
        history = proposal_history(self.db)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['proposal_id'], proposal.proposal_id)
        self.assertEqual(history[0]['decision'], STATUS_REJECTED)
        self.assertEqual(history[0]['reason'], 'not worth it')

    # ------------------------------------------------------------------ law 7
    def test_law_7_a_simulation_proposal_only_proposes(self):
        uncertainty_id = self.seed()
        propose_investigation(self.db, uncertainty_id=uncertainty_id,
                              investigation_type=TYPE_RUN_SIMULATION, now=self.t2)
        self.assertEqual(self.count('ciph_simulations'), 0,
                         'proposing a simulation does not run one')
        self.assertEqual(reconstruct_beliefs(self.db, now=self.t2).evidence_count, 1,
                         'only the seed evidence; a proposal fabricates nothing')

    # ------------------------------------------------------------------ identity
    def test_the_same_proposal_is_one_proposal(self):
        uncertainty_id = self.seed()
        first = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                      investigation_type=TYPE_OBSERVE,
                                      required_capabilities=['probe.port'], now=self.t2)
        second = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                       investigation_type=TYPE_OBSERVE,
                                       required_capabilities=['probe.port'], now=self.t2 + 50)
        self.assertEqual(first.proposal_id, second.proposal_id)
        self.assertEqual(len(proposal_history(self.db)), 1)

    # ------------------------------------------------------------------ refusals
    def test_an_unknown_uncertainty_is_refused(self):
        with self.assertRaises(CuriosityProposalError) as refused:
            propose_investigation(self.db, uncertainty_id='UNC-NOPE',
                                  investigation_type=TYPE_OBSERVE, now=self.t2)
        self.assertEqual(refused.exception.reason, 'UNKNOWN_UNCERTAINTY')
        with self.assertRaises(CuriosityProposalError) as bad_type:
            propose_investigation(self.db, uncertainty_id=self.seed(),
                                  investigation_type='GO_FISHING', now=self.t2)
        self.assertEqual(bad_type.exception.reason, 'INVALID_INVESTIGATION_TYPE')

    # ------------------------------------------------------------------ determinism
    def test_proposal_digest_is_deterministic_across_restart(self):
        uncertainty_id = self.seed()
        proposal = propose_investigation(self.db, uncertainty_id=uncertainty_id,
                                         investigation_type=TYPE_OBSERVE, now=self.t2)
        accept_proposal(self.db, proposal.proposal_id, actor='operator', now=self.t2)
        expected = proposal_digest(self.db)
        self.assertEqual(proposal_digest(self.db), expected)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.curiosity_proposal import proposal_digest;'
                'print(proposal_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)


if __name__ == '__main__':
    unittest.main()
