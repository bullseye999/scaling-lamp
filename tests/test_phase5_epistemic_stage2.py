"""Durable admission tests with actual committed worker evidence."""
import json
import sqlite3
from unittest.mock import patch
from ciph.contracts.epistemic import Claim, Observation, EpistemicAdmissionError
from ciph.contracts.enums import EpistemicState
from ciph.memory.materialized_views import MaterializedWorldview
from phase5_test_support import EpistemicTestCase, receipt

class TestPhase5EpistemicStage2(EpistemicTestCase):
    def test_01_schema_migration_and_column_persistence(self):
        path=self.temp.name+'/legacy.db'
        legacy=MaterializedWorldview(path)
        with legacy._get_connection() as conn:
            conn.execute("INSERT INTO ciph_active_claims (claim_id,subject,predicate,value,state,reliability,assurance_score,evidence_receipt_ids,parent_claim_ids,created_at,updated_at) VALUES ('legacy','s','p','true','SUPPORTED','DIRECT_SENSOR',0.9,'[]','[]',1,1)")
        legacy=MaterializedWorldview(path)
        with legacy._get_connection() as conn:
            row=conn.execute('SELECT * FROM ciph_active_claims').fetchone()
            self.assertEqual(row['migration_status'],'LEGACY_QUARANTINE')
            self.assertEqual(row['lifecycle_state'],'ARCHIVED')
            original=json.loads(conn.execute('SELECT original_row FROM ciph_legacy_claims').fetchone()[0])
            self.assertEqual(original['state'],'SUPPORTED')
            self.assertEqual(original['value'],'true')
        self.assertEqual(legacy.query_active_claims(),[])

    def test_02_observation_persistence_and_query(self):
        proof=receipt(self.runtime,{'observation':{'source':'https://feed.invalid','subject':'server','predicate':'compromised','value':False}},capability='test.collect')
        observation=self.worldview.ingest_observation(proof.receipt_id)
        self.assertIs(self.worldview.get_observation(observation.observation_id).value,False)
        self.worldview.admit_claim(self.projector.project_from_observation(observation))
        result=self.worldview.query_active_claims()[0]
        self.assertEqual(result.subject,'https://feed.invalid')
        self.assertEqual(result.predicate,'source_reported')
        self.assertIs(result.value['value'],False)
        self.assertLessEqual(result.assurance_score,.4)

    def test_03_claim_dependency_dag_persistence(self):
        self.seed('parent');self.seed('child',parents=['parent'])
        self.assertEqual(self.worldview.get_dependencies('child'),['parent'])
        self.worldview.replay_from_event_store()
        self.assertEqual(self.worldview.get_downstream_dependents('parent'),['child'])
        with self.assertRaises(ValueError):self.worldview.link_dependency('child','parent')
        with self.assertRaises(ValueError):self.worldview.link_dependency('missing','child')

    def test_04_transition_audit_trail_is_atomic(self):
        candidate=self.seed('atomic',admit=False)
        with patch.object(self.worldview,'record_transition',side_effect=sqlite3.OperationalError('injected write failure')):
            with self.assertRaises(sqlite3.OperationalError):self.worldview.admit_claim(candidate)
        self.assertIsNone(self.worldview.get_claim('atomic'))
        self.assertEqual(self.worldview.get_transitions('atomic'),[])
        self.assertEqual(self.runtime.event_store.get_events(aggregate_id='atomic'),[])
        self.worldview.admit_claim(candidate)
        self.assertEqual(len(self.worldview.get_transitions('atomic')),1)

    def test_05_admit_claim_verified_real_gates(self):
        for state in (EpistemicState.SUPPORTED,EpistemicState.OBSERVED,EpistemicState.INFERRED,EpistemicState.HYPOTHESIZED):
            candidate=Claim(claim_id='fake',subject='x',predicate='p',value=True,epistemic_state=state,evidence_receipt_ids=['missing'])
            with self.assertRaises(EpistemicAdmissionError):self.worldview.admit_claim(candidate)
        self.assertEqual(self.worldview.query_active_claims(),[])
        self.seed('valid');self.assertIsNotNone(self.worldview.get_canonical_claim('valid'))

    def test_06_observation_requires_authenticated_intake(self):
        observation=Observation(observation_id='fake',source='local:caller',subject='s',predicate='p',value=True)
        with self.assertRaises(EpistemicAdmissionError):self.worldview.store_observation(observation)
        candidate=self.projector.project_from_observation(observation)
        with self.assertRaises(EpistemicAdmissionError):self.worldview.admit_claim(candidate)

    def test_07_deterministic_claim_identity_and_collision(self):
        proof=receipt(self.runtime)
        first=self.projector.project_claim(proof)
        self.assertEqual(first,self.projector.project_claim(proof))
        self.worldview.admit_claim(first);self.worldview.admit_claim(first)
        self.assertEqual(len(self.worldview.query_active_claims()),1)
        with self.assertRaises(EpistemicAdmissionError):self.seed(first.claim_id,value='OFFLINE')

    def test_08_crash_recovery_replay_from_event_store(self):
        first=self.seed('root');self.seed('child',parents=['root'])
        self.worldview.bury_in_graveyard(first.subject,first.predicate,'maintenance',claim_id='root')
        before=[self.worldview.get_canonical_claim(cid) for cid in ('root','child')]
        graves=self.worldview.query_graveyard();transitions=self.worldview.get_transitions()
        for _ in range(2):
            self.assertEqual(self.worldview.replay_from_event_store(),2)
            self.assertEqual(before,[self.worldview.get_canonical_claim(cid) for cid in ('root','child')])
            self.assertEqual(graves,self.worldview.query_graveyard())
            self.assertEqual(transitions,self.worldview.get_transitions())
        from ciph.runtime import CiphRuntime
        restarted=CiphRuntime(db_path=self.runtime.db_path)
        self.assertEqual(before,[restarted.worldview.get_canonical_claim(cid) for cid in ('root','child')])
        restarted.close()
