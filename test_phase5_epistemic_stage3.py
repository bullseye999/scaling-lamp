"""Freshness, contradiction, graph and reopening checks with durable evidence."""
import time
from unittest.mock import patch
from ciph.contracts.enums import LifecycleState, EpistemicState
from ciph.contracts.epistemic import EpistemicAdmissionError
from ciph.contracts.base import canonical_json
from ciph.kernel.crypto_identity import Ed25519KeyManager
from phase5_test_support import EpistemicTestCase

class TestPhase5EpistemicStage3(EpistemicTestCase):
    def test_01_three_axis_reaper_preserves_epistemic_judgment(self):
        candidate=self.seed('fresh')
        self.worldview.reap_dormant_claims(candidate.freshness_deadline+1)
        current=self.worldview.get_claim('fresh')
        self.assertEqual(current.state,candidate.epistemic_state)
        self.assertEqual(current.lifecycle_state,LifecycleState.DORMANT)
        self.assertEqual(self.worldview.query_active_claims(),[])
        self.worldview.admit_claim(candidate)
        self.assertEqual(self.worldview.get_claim('fresh').lifecycle_state,LifecycleState.DORMANT)

    def test_02_reaper_never_overwrites_disputed_or_archived(self):
        first=self.seed('old');self.seed('conflict',value='OFFLINE')
        self.assertEqual(self.worldview.get_claim('old').state,EpistemicState.DISPUTED)
        self.worldview.reap_dormant_claims(first.freshness_deadline+1)
        self.assertEqual(self.worldview.get_claim('old').state,EpistemicState.DISPUTED)
        self.worldview.bury_in_graveyard(first.subject,first.predicate,'manual suppression',claim_id='old')
        self.worldview.reap_dormant_claims(first.freshness_deadline+100)
        self.assertEqual(self.worldview.get_claim('old').lifecycle_state,LifecycleState.ARCHIVED)

    def test_03_context_aware_temporal_supersession(self):
        self.seed('old',deadline=time.time()+.02)
        time.sleep(.03)
        self.seed('new',value='OFFLINE')
        old=self.worldview.get_claim('old')
        self.assertEqual(old.state,EpistemicState.SUPERSEDED)
        self.assertEqual(old.superseded_by,'new')
        self.assertEqual(self.worldview.get_claim('new').state,EpistemicState.VERIFIED_REAL)

    def test_04_distinct_contexts_prevent_false_contradictions(self):
        self.seed('one',subject='scope.one')
        self.seed('two',subject='scope.two',value='OFFLINE')
        self.assertEqual(len(self.worldview.query_active_claims()),2)
        self.assertNotEqual(self.worldview.get_claim('one').normalized_context_hash,self.worldview.get_claim('two').normalized_context_hash)

    def test_05_bounded_dag_invalidation_cascade(self):
        self.seed('root');self.seed('child',parents=['root']);self.seed('grandchild',parents=['child'])
        result=self.worldview.propagate_invalidation_cascade('root',max_budget=1)
        self.assertTrue(result['budget_exhausted'])
        self.assertEqual(self.worldview.query_active_claims(),[])
        self.worldview.replay_from_event_store()
        self.assertEqual(self.worldview.query_active_claims(),[])
        self.assertIsNotNone(self.worldview.get_claim('grandchild'))

    def test_06_governed_graveyard_reopening(self):
        first=self.seed('buried')
        grave=self.worldview.bury_in_graveyard(first.subject,first.predicate,'maintenance',claim_id=first.claim_id)
        with self.assertRaises(EpistemicAdmissionError):self.worldview.reopen_claim(first.claim_id,reason='caller says so',actor='operator')
        reason='operator requests inspection'
        signature=Ed25519KeyManager.sign(self.runtime.operator_priv_bytes,canonical_json(['REOPEN',grave,first.claim_id,reason]).encode())
        self.worldview.reopen_claim(first.claim_id,reason=reason,operator_signature=signature)
        node=self.worldview.get_claim(first.claim_id)
        self.assertEqual(node.lifecycle_state,LifecycleState.REOPENED)
        self.assertEqual(node.state,first.epistemic_state)
        self.assertEqual(self.worldview.query_active_claims(),[])
        self.assertFalse(self.worldview.is_in_graveyard(first.subject,first.predicate))
        with self.assertRaises(EpistemicAdmissionError):self.worldview.clear_invalidation_barrier(first.claim_id,reason='trust me')
