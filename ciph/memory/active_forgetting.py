"""Governed supersession through the canonical worldview transaction boundary."""
from ciph.contracts.base import ContractValidationError
from ciph.memory.materialized_views import MaterializedWorldview
from ciph.memory.claim_leases import ClaimLeaseManager
from ciph.memory.event_store import EventStore

class ActiveForgettingEngine:
    def __init__(self, worldview=None, leases=None, event_store=None, db_path='ciph_vault.db'):
        self.worldview=worldview or MaterializedWorldview(db_path)
        self.leases=leases or ClaimLeaseManager(db_path)
        self.event_store=event_store or EventStore(db_path)

    def dispute_claim(self,claim_id,contradicting_evidence):
        receipt_id=contradicting_evidence.get('receipt_id') if isinstance(contradicting_evidence,dict) else None
        if not receipt_id:return {'success':False,'error':'VERIFIABLE_CONTRADICTING_EVIDENCE_REQUIRED'}
        old=self.worldview.get_claim(claim_id)
        if old is None:return {'success':False,'error':'CLAIM_NOT_FOUND'}
        receipt=self.worldview._receipt(receipt_id)
        candidate=self.worldview._authority().claim_projector.project_claim(receipt,predicate=old.predicate)
        self.worldview.admit_claim(candidate)
        result=self.worldview.get_claim(claim_id)
        return {'success':result.state.value=='DISPUTED','state':result.state.value,
                'claim_id':claim_id,'dependents_preserved':self.worldview.get_downstream_dependents(claim_id)}

    def confirm_supersession(self,old_claim_id,new_claim_id,force=False):
        if self.leases.is_claim_pinned(old_claim_id):
            return {'success':False,'error':'TOCTOU_COLLISION_DETECTED','pinning_workers':self.leases.get_pinning_workers(old_claim_id)}
        with self.worldview._transaction() as conn:
            old=self.worldview._checked_row(conn,old_claim_id);new=self.worldview._checked_row(conn,new_claim_id)
            if not old or not new:return {'success':False,'error':'AUTHENTIC_SUCCESSOR_REQUIRED'}
            if (old['subject'],old['predicate'],old['normalized_context_hash'])!=(new['subject'],new['predicate'],new['normalized_context_hash']) or new['valid_from']<=old['valid_from'] or (old['valid_until'] is None or new['valid_from']<old['valid_until']):
                return {'success':False,'error':'UNPROVEN_SUPERSESSION'}
            self.worldview._revision(conn,old,'TEMPORAL_SUPERSESSION',state='SUPERSEDED',lifecycle='DORMANT',barrier=1,superseded_by=new_claim_id)
            cascade=self.worldview._cascade(conn,old_claim_id,'PARENT_SUPERSEDED')
        return {'success':True,'superseded_claim_id':old_claim_id,'superseding_claim_id':new_claim_id,
                'cascaded_stale_count':cascade['invalidated_count']}

    def restore_disputed_claim(self,claim_id):
        # Existing proof cannot be promoted by an unverified assertion of restoration.
        return {'success':False,'error':'FRESH_EVIDENCE_AND_REEVALUATION_REQUIRED','claim_id':claim_id}
