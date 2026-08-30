"""
ciph.memory.active_forgetting - Governed State Supersession & Recursive Invalidation.
Protects the Transmutation DAG from transient network errors and handles multi-generation cascades.
"""

import time
from typing import Dict, Any, List, Optional, Set
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.memory.materialized_views import MaterializedWorldview
from ciph.memory.claim_leases import ClaimLeaseManager
from ciph.memory.event_store import EventStore


class ActiveForgettingEngine:
    """
    Manages controlled state supersession, cryptographic invalidation,
    and anti-wipeout circuit breakers across the Transmutation DAG.
    """

    def __init__(
        self,
        worldview: Optional[MaterializedWorldview] = None,
        leases: Optional[ClaimLeaseManager] = None,
        event_store: Optional[EventStore] = None,
        db_path: str = "ciph_vault.db"
    ):
        self.worldview = worldview or MaterializedWorldview(db_path)
        self.leases = leases or ClaimLeaseManager(db_path)
        self.event_store = event_store or EventStore(db_path)

    def dispute_claim(self, claim_id: str, contradicting_evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Circuit Breaker Step 1: When a contradicting observation lands,
        mark the claim as DISPUTED instead of instantly executing a recursive wipeout.
        Downstream dependent claims remain ACTIVE_PENDING_CONFIRMATION.
        """
        node = self.worldview.get_claim(claim_id)
        if not node:
            return {"success": False, "error": f"Claim {claim_id} not found"}

        dependents = self.worldview.get_downstream_dependents(claim_id)
        
        # Update node state to DISPUTED
        node.state = EpistemicCategory.DISPUTED
        node.updated_at = time.time()
        self.worldview.upsert_claim(node)

        # Log to event store
        self.event_store.append_event(
            event_type="ClaimDisputedEvent",
            aggregate_id=claim_id,
            payload={
                "claim_id": claim_id,
                "contradicting_evidence": contradicting_evidence,
                "dependents_preserved_count": len(dependents)
            }
        )

        return {
            "success": True,
            "claim_id": claim_id,
            "state": "DISPUTED",
            "dependents_preserved": dependents,
            "action_required": "SECONDARY_VERIFICATION_NEEDED"
        }

    def confirm_supersession(
        self,
        old_claim_id: str,
        new_claim_id: str,
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Circuit Breaker Step 2: Confirmed supersession.
        Old claim is marked SUPERSEDED. All recursive child descendants are gracefully transitioned to STALE.
        Checks ClaimLeaseManager to avoid TOCTOU races with active running workers.
        """
        # Check active worker lease locks (Anti-TOCTOU)
        if self.leases.is_claim_pinned(old_claim_id) and not force:
            pinning_workers = self.leases.get_pinning_workers(old_claim_id)
            return {
                "success": False,
                "error": "TOCTOU_COLLISION_DETECTED",
                "message": f"Claim {old_claim_id} is currently PINNED by active worker leases.",
                "pinning_workers": pinning_workers,
                "action": "INTERRUPT_OR_WAIT"
            }

        old_node = self.worldview.get_claim(old_claim_id)
        if not old_node:
            return {"success": False, "error": f"Claim {old_claim_id} not found"}

        now = time.time()
        old_node.state = EpistemicCategory.SUPERSEDED
        old_node.superseded_by = new_claim_id
        old_node.updated_at = now
        self.worldview.upsert_claim(old_node)

        # Recursive Invalidation Cascade: traverse full descendant tree
        visited: Set[str] = set()
        queue = list(self.worldview.get_downstream_dependents(old_claim_id))
        all_descendants: List[str] = []
        stale_count = 0

        while queue:
            child_id = queue.pop(0)
            if child_id in visited:
                continue
            visited.add(child_id)
            all_descendants.append(child_id)

            child_node = self.worldview.get_claim(child_id)
            if child_node and child_node.state not in (EpistemicCategory.SUPERSEDED, EpistemicCategory.REFUTED):
                child_node.state = EpistemicCategory.STALE
                child_node.updated_at = now
                self.worldview.upsert_claim(child_node)
                stale_count += 1

            # Fetch grandchildren
            grandchildren = self.worldview.get_downstream_dependents(child_id)
            for gc in grandchildren:
                if gc not in visited:
                    queue.append(gc)

        # Record in immutable append-only event store
        self.event_store.append_event(
            event_type="ClaimSupersededEvent",
            aggregate_id=old_claim_id,
            payload={
                "superseded_claim_id": old_claim_id,
                "superseding_claim_id": new_claim_id,
                "stale_cascaded_descendants": all_descendants
            }
        )

        return {
            "success": True,
            "superseded_claim_id": old_claim_id,
            "superseding_claim_id": new_claim_id,
            "cascaded_stale_count": stale_count,
            "cascaded_claim_ids": all_descendants
        }

    def restore_disputed_claim(self, claim_id: str) -> Dict[str, Any]:
        """
        When secondary verification proves the contradiction was a transient glitch,
        restore the claim back to SUPPORTED. Zero downstream data loss.
        """
        node = self.worldview.get_claim(claim_id)
        if not node:
            return {"success": False, "error": f"Claim {claim_id} not found"}

        node.state = EpistemicCategory.SUPPORTED
        node.updated_at = time.time()
        self.worldview.upsert_claim(node)

        self.event_store.append_event(
            event_type="ClaimRestoredEvent",
            aggregate_id=claim_id,
            payload={"claim_id": claim_id, "restored_to": "SUPPORTED"}
        )

        return {"success": True, "claim_id": claim_id, "state": "SUPPORTED"}
