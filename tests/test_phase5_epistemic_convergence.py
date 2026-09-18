"""Adversarial regression checks; finite test cases, not formal proofs."""
import dataclasses
import json
import sqlite3
import time
from unittest.mock import patch
from ciph.contracts.base import ContractValidationError,canonical_json
from ciph.contracts.epistemic import Claim,Observation,ObservationIngestor,EpistemicAdmissionError
from ciph.contracts.enums import EpistemicState,DecayProfile,ReliabilityClass,LifecycleState
from ciph.kernel.transmutation_dag import TransmutationNode,TransmutationDAG
from ciph.planner.schemas import IntentProposal
from phase5_test_support import EpistemicTestCase,receipt,EvidenceFixture

class TestPhase5EpistemicConvergence(EpistemicTestCase):
    def test_01_unverified_upsert_and_phantom_receipts_fail_closed(self):
        for state in ('SUPPORTED','VERIFIED_REAL','OBSERVED','INFERRED','HYPOTHESIZED'):
            node=TransmutationNode(claim_id='forged',subject='x',predicate='p',value=True,state=state,evidence_receipt_ids=['unrelated'])
            self.runtime.event_store.append_event('UnrelatedEvent','unrelated',{})
            with self.assertRaises(ContractValidationError):self.worldview.upsert_claim(node)
        self.assertEqual(self.worldview.query_active_claims(),[])

    def test_02_predictive_and_inference_receipts_require_signatures(self):
        for cap in ('sports.predict_match','pentest.cvss_calculate'):
            real=receipt(self.runtime,{'prediction':'x'},capability=cap)
            forged=dataclasses.replace(real,worker_signature='forged')
            with self.assertRaises(ContractValidationError):self.projector.project_claim(forged)
            with self.assertRaises(ContractValidationError):self.projector.project_verified_real(real)
            candidate=self.projector.project_claim(real)
            self.worldview.admit_claim(candidate)
            self.assertIn(candidate.epistemic_state,(EpistemicState.INFERRED,EpistemicState.HYPOTHESIZED))
            self.assertLessEqual(candidate.assurance_score,.8)

    def test_03_anti_retargeting_all_projection_branches(self):
        real=receipt(self.runtime,{'base_score':5.0},capability='pentest.cvss_calculate')
        with self.assertRaises(ContractValidationError):self.projector.project_claim(real,subject='victim')
        with self.assertRaises(ContractValidationError):self.projector.project_claim(real,predicate='base_score',value=10)
        good=self.projector.project_claim(real,predicate='base_score')
        d=good.to_dict();d['scope_id']='forged';d['claim_id']='changed'
        with self.assertRaises(ContractValidationError):self.worldview.admit_claim(Claim(**d))

    def test_04_untrusted_observation_labels_cannot_assign_authority(self):
        for source in ('https://feed.invalid','local:any-caller','worker:pretend'):
            with self.assertRaises(ContractValidationError):ObservationIngestor.ingest(source,'victim','compromised',True,reliability_class='AUTHORITATIVE_LOCAL')
            obs=ObservationIngestor.ingest(source,'victim','compromised',True)
            with self.assertRaises(ContractValidationError):self.worldview.store_observation(obs)

    def test_05_observation_identity_is_immutable_and_typed(self):
        proof=receipt(self.runtime,{'observation':{'source':'feed','subject':'s','predicate':'p','value':False}},capability='test.collect')
        obs=self.worldview.ingest_observation(proof.receipt_id)
        changed=obs.to_dict();changed['value']=True
        with self.assertRaises(ContractValidationError):self.worldview.store_observation(Observation.from_dict(changed))
        self.assertIs(self.worldview.get_observation(obs.observation_id).value,False)
        self.assertEqual(self.worldview.ingest_observation(proof.receipt_id),obs)

    def test_06_old_observation_cannot_reset_freshness_clock(self):
        old=time.time()-172800
        proof=receipt(self.runtime,{'observation':{'source':'feed','subject':'s','predicate':'p','value':1,'observed_at':old}},capability='test.collect')
        obs=self.worldview.ingest_observation(proof.receipt_id)
        candidate=self.projector.project_from_observation(obs,decay_profile=DecayProfile.LIVE_NETWORK_STATE)
        self.assertEqual(candidate.created_at,old)
        self.assertEqual(candidate.freshness_deadline,old+300)
        self.worldview.admit_claim(candidate)
        self.assertEqual(self.worldview.query_active_claims(),[])
        self.worldview.admit_claim(candidate)
        self.assertEqual(self.worldview.get_canonical_claim(candidate.claim_id).freshness_deadline,old+300)

    def test_07_finite_timestamps_and_payload_integrity(self):
        for invalid in (float('nan'),float('inf'),-1,time.time()+100):
            with self.assertRaises(ContractValidationError):ObservationIngestor.ingest('feed','s','p',1,observed_at=invalid)
        with self.assertRaises(ContractValidationError):ObservationIngestor.ingest('feed','s','p',1,raw_payload=b'changed',expected_content_hash='0'*64)

    def test_08_raw_sql_changes_cannot_become_active_claims(self):
        self.seed('real')
        with self.worldview._get_connection() as conn:conn.execute("UPDATE ciph_active_claims SET value='true' WHERE claim_id='real'")
        with self.assertRaises(ContractValidationError):self.worldview.query_active_claims()
        self.worldview.replay_from_event_store()
        self.assertEqual(self.worldview.get_claim('real').value,'ONLINE')

    def test_09_graph_cycles_depth_and_width_rejected(self):
        dag=TransmutationDAG()
        dag.add_node(TransmutationNode('root','s','p',1))
        for i in range(1,17):dag.add_node(TransmutationNode(str(i),'s','p',1,parent_claim_ids=['root' if i==1 else str(i-1)]))
        with self.assertRaises(ValueError):dag.add_node(TransmutationNode('17','s','p',1,parent_claim_ids=['16']))
        with self.assertRaises(ValueError):dag.add_node(TransmutationNode('root','s','p',1,parent_claim_ids=['16']))
        with self.assertRaises(ValueError):dag.add_node(TransmutationNode('missing-child','s','p',1,parent_claim_ids=['missing']))
        wide=TransmutationDAG();wide.add_node(TransmutationNode('root','s','p',1))
        for i in range(256):wide.add_node(TransmutationNode(str(i),'s','p',1,parent_claim_ids=['root']))
        with self.assertRaises(ValueError):wide.add_node(TransmutationNode('overflow','s','p',1,parent_claim_ids=['root']))

    def test_10_runtime_cannot_fall_back_after_admission_rejection(self):
        self.runtime.register_capability(EvidenceFixture('memory.retrieve',{'found':True,'value':'safe'}))
        proposal=IntentProposal(proposal_id='reject',objective='Read local fixture',proposed_capability='memory.retrieve',provided_parameters={'key':'x'})
        with patch.object(self.worldview,'admit_claim',side_effect=EpistemicAdmissionError('injected rejection')):
            result=self.runtime.execute_reference_loop(proposal)
        self.assertEqual(result['status'],'EPISTEMIC_ADMISSION_REJECTED')
        self.assertIsNotNone(result['receipt'])
        self.assertIsNone(result['claim'])
        self.assertEqual(self.worldview.query_active_claims(),[])

    def test_11_unsigned_receipt_event_cannot_replay_into_a_claim(self):
        proof=receipt(self.runtime)
        forged=dataclasses.replace(proof,receipt_id='forged',worker_signature='garbage')
        self.runtime.event_store.append_event('ExecutionReceiptStoredEvent','forged',forged.to_dict())
        self.assertEqual(self.worldview.replay_from_event_store(),0)
        node=TransmutationNode('forged','tor.check_status','status','ONLINE',state='VERIFIED_REAL',evidence_receipt_ids=['forged'])
        with self.assertRaises(ContractValidationError):self.worldview.admit_claim(node)

    def test_12_transaction_failure_rolls_back_event_and_projection(self):
        candidate=self.seed('rollback',admit=False)
        original=self.worldview._apply_changes
        def fail(conn,changes,event_id):
            original(conn,changes,event_id)
            raise sqlite3.OperationalError('simulated crash before commit')
        with patch.object(self.worldview,'_apply_changes',side_effect=fail):
            with self.assertRaises(sqlite3.OperationalError):self.worldview.admit_claim(candidate)
        self.assertIsNone(self.worldview.get_claim('rollback'))
        self.assertEqual(self.runtime.event_store.get_events(aggregate_id='rollback'),[])

    def test_13_same_value_new_evidence_reopens_investigation_only(self):
        first=self.seed('buried')
        self.worldview.bury_in_graveyard(first.subject,first.predicate,'maintenance',claim_id='buried')
        new=receipt(self.runtime)
        self.worldview.reopen_claim('buried',reason='new collection',evidence_id=new.receipt_id)
        self.assertEqual(self.worldview.get_claim('buried').lifecycle_state,LifecycleState.REOPENED)
        self.assertEqual(self.worldview.query_active_claims(),[])
        self.assertFalse(self.worldview.is_in_graveyard(first.subject,first.predicate))

    def test_14_cascade_crash_is_atomic(self):
        self.seed('parent');self.seed('child',parents=['parent'])
        before=self.worldview.get_canonical_claim('parent')
        original=self.worldview._event
        def fail(conn,kind,aggregate,changes):
            if kind=='EpistemicCascadeCheckpoint':raise sqlite3.OperationalError('crash')
            return original(conn,kind,aggregate,changes)
        with patch.object(self.worldview,'_event',side_effect=fail):
            with self.assertRaises(sqlite3.OperationalError):self.worldview.propagate_invalidation_cascade('parent')
        self.assertEqual(self.worldview.get_canonical_claim('parent'),before)
        self.assertEqual(len(self.worldview.query_active_claims()),2)

    def test_15_unregistered_domain_predicate_never_mints_verified_real(self):
        proof=receipt(self.runtime,{'compromised':True},capability='test.collect')
        with self.assertRaises(ContractValidationError):self.projector.project_verified_real(proof,predicate='compromised')
        with self.assertRaises(ContractValidationError):self.projector.project_claim(proof,predicate='compromised')
        report=self.projector.project_claim(proof)
        self.assertEqual(report.predicate,'execution_report')
        self.assertEqual(report.epistemic_state,EpistemicState.OBSERVED)

    def test_16_caller_cannot_choose_an_infinite_sensor_lifetime(self):
        proof=receipt(self.runtime)
        candidate=self.projector.project_verified_real(proof,predicate='status',decay_profile=DecayProfile.MATHEMATICAL_FACT)
        self.assertLessEqual(candidate.freshness_deadline,proof.completed_at+300)
        self.worldview.admit_claim(candidate)
        self.assertLessEqual(self.worldview.get_canonical_claim(candidate.claim_id).freshness_deadline,proof.completed_at+300)

    def test_17_signature_without_committed_job_is_not_admissible(self):
        proof=receipt(self.runtime)
        uncommitted=dataclasses.replace(proof,receipt_id='orphan',job_id='missing-job',worker_signature=None).sign(self.runtime.worker_priv_bytes,worker_key_id=self.runtime.worker_key_id)
        candidate=self.projector.project_claim(uncommitted)
        self.runtime.event_store.append_event('ExecutionReceiptStoredEvent','orphan',uncommitted.to_dict())
        with self.assertRaises(ContractValidationError):self.worldview.admit_claim(candidate)
        self.assertEqual(self.worldview.query_active_claims(),[])

    def test_18_required_premise_bounds_assurance_and_freshness(self):
        proof=receipt(self.runtime,{'report':'local collection'},capability='test.collect')
        parent=self.projector.project_claim(proof,claim_id='weak-parent',decay_profile=DecayProfile.LIVE_NETWORK_STATE)
        self.worldview.admit_claim(parent)
        self.seed('strong-child',parents=['weak-parent'])
        child=self.worldview.get_canonical_claim('strong-child')
        self.assertLessEqual(child.assurance_score,parent.assurance_score)
        self.assertLessEqual(child.freshness_deadline,parent.freshness_deadline)
        self.worldview.reap_expired_claims(parent.freshness_deadline+1)
        self.assertEqual(self.worldview.query_active_claims(),[])
        self.assertNotEqual(self.worldview.get_claim('strong-child').state,EpistemicState.REFUTED)

    def test_19_unsigned_transition_event_replay_is_rejected_atomically(self):
        before=self.seed('real')
        self.runtime.event_store.append_event('EpistemicClaimTransitioned','real',{'version':1,'kind':'EpistemicClaimTransitioned','aggregate_id':'real','changes':[]})
        with self.assertRaises(ContractValidationError):self.worldview.replay_from_event_store()
        with self.worldview._get_connection() as conn:
            self.assertEqual(conn.execute("SELECT value FROM ciph_active_claims WHERE claim_id='real'").fetchone()[0],canonical_json(before.value))

    def test_20_manual_read_bypasses_grave_suppression_but_apply_needs_auth(self):
        self.runtime.register_capability(EvidenceFixture('memory.retrieve',{'found':True,'value':'record'}))
        proposal=IntentProposal(proposal_id='manual-seed',objective='Read a record',proposed_capability='memory.retrieve',provided_parameters={'key':'x'})
        result=self.runtime.execute_reference_loop(proposal)
        candidate=result['claim']
        self.worldview.bury_in_graveyard(candidate.subject,candidate.predicate,'avoid autonomous repetition',claim_id=candidate.claim_id)
        result=self.runtime.dispatch_slash_command('/memory key=x')
        self.assertEqual(result['status'],'SUCCESS')
        denied=self.runtime.dispatch_slash_command('/apply proposal_id=not-real')
        self.assertEqual(denied['status'],'AUTHORIZATION_REQUIRED')

    def test_21_shared_ancestors_do_not_expand_exponentially(self):
        dag=TransmutationDAG()
        dag.add_node(TransmutationNode('root','s','p',1,freshness_deadline=time.time()+30))
        previous=['root']
        for level in range(8):
            current=[f'{level}-{i}' for i in range(8)]
            for cid in current:dag.add_node(TransmutationNode(cid,'s','p',1,parent_claim_ids=previous))
            previous=current
        with patch.object(dag,'_nodes',wraps=dag._nodes) as nodes:
            self.assertTrue(dag.verify_weakest_link_invariants(previous[0]))
            self.assertLess(nodes.get.call_count,1024)
        derived=dag.derive_inference('derived','s','p',1,previous,'fixture')
        self.assertLessEqual(derived.freshness_deadline,dag.get_node('root').freshness_deadline)

    def test_22_previously_queued_question_cannot_bypass_a_new_grave(self):
        original=self.seed('queued-then-buried')
        self.runtime.question_dag.propose_question(target_subject=original.subject,target_predicate=original.predicate,
            question_text='Recheck this measurement',impact_score=5,estimated_cost_score=1)
        self.worldview.bury_in_graveyard(original.subject,original.predicate,'suppress repeated probe',claim_id=original.claim_id)
        with patch.object(self.runtime,'execute_reference_loop') as dispatch:
            results=self.runtime.run_curiosity_cycle()
        dispatch.assert_not_called()
        self.assertEqual(results,[])
