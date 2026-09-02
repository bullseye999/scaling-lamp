"""
ciph.perception.curiosity_daemon - Governed Autonomous Curiosity Daemon (CIPH 4.0).
Discovers epistemic gaps, prioritizes testable inquiries within rate budgets, and obeys read-only safety limits.
"""

import time
import uuid
import threading
from typing import Dict, Any, List, Optional, Tuple
from ciph.kernel.transmutation_dag import EpistemicCategory, TransmutationNode
from ciph.kernel.policy_engine import ReversibilityClass, AuthorizationTier, RiskTier, NetworkPolicy, ScopeGrant, ScopeType
from ciph.planner.schemas import IntentProposal
from ciph.perception.observation import Observation, ReliabilityClass


class CuriosityDaemon:
    """
    Autonomous Epistemic Inquiry & Curiosity Engine.
    Scans the Materialized Worldview for intelligence gaps, expired stale claims,
    and ungrounded premises, formulating read-only hypotheses and inquiry jobs.
    """

    def __init__(
        self,
        max_inquiries_per_hour: int = 12,
        inquiry_interval_seconds: float = 5.0,
        allowed_capabilities: Optional[List[str]] = None
    ):
        self.max_inquiries_per_hour = max_inquiries_per_hour
        self.inquiry_interval_seconds = inquiry_interval_seconds
        self.allowed_capabilities = allowed_capabilities or [
            "memory.retrieve",
            "tor.check_status",
            "pentest.cvss_calculate",
            "code.audit_dependencies"
        ]
        
        self.inquiry_history: List[float] = []
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def can_inquire_under_budget(self, now: Optional[float] = None) -> bool:
        """Rate-limiter: Ensures inquiries do not exceed max_inquiries_per_hour."""
        current_time = now if now is not None else time.time()
        one_hour_ago = current_time - 3600.0
        # Purge entries older than 1 hour
        self.inquiry_history = [t for t in self.inquiry_history if t > one_hour_ago]
        return len(self.inquiry_history) < self.max_inquiries_per_hour

    def record_inquiry(self, timestamp: Optional[float] = None) -> None:
        """Record an inquiry execution for rate-budgeting."""
        self.inquiry_history.append(timestamp or time.time())

    def discover_epistemic_gaps(self, worldview) -> List[TransmutationNode]:
        """
        Scan worldview for claims in STALE, INTELLIGENCE_GAP, or DISPUTED states,
        filtering out those already quarantined in the Tabu Graveyard.
        """
        all_stale = worldview.query_active_claims(states=["STALE", "INTELLIGENCE_GAP", "DISPUTED"])
        
        valid_gaps = []
        for claim in all_stale:
            # Check Tabu Graveyard
            if worldview.is_in_graveyard(claim.subject, claim.predicate):
                continue
            valid_gaps.append(claim)

        # Prioritize by lowest assurance score
        valid_gaps.sort(key=lambda c: c.assurance_score)
        return valid_gaps

    def formulate_inquiry_proposal(
        self,
        gap_claim: TransmutationNode,
        runtime: Any
    ) -> Optional[IntentProposal]:
        """
        Synthesize a safe IntentProposal to resolve the specified epistemic gap.
        Enforces strict safety: Read-only capabilities only.
        """
        # Determine capability based on subject/predicate
        cap_name = None
        params: Dict[str, Any] = {}

        if "memory" in gap_claim.subject.lower() or "vault" in gap_claim.subject.lower():
            cap_name = "memory.retrieve"
            params = {"key": gap_claim.predicate, "target": "local_memory"}
        elif "tor" in gap_claim.subject.lower() or "circuit" in gap_claim.predicate.lower():
            cap_name = "tor.check_status"
            params = {}
        elif "dep" in gap_claim.predicate.lower() or "code" in gap_claim.subject.lower():
            cap_name = "code.audit_dependencies"
            params = {"target_file": gap_claim.subject}
        else:
            # Default fallback read inquiry
            cap_name = "memory.retrieve"
            params = {"key": f"{gap_claim.subject}:{gap_claim.predicate}", "target": "local_memory"}

        cap = runtime.registry.get(cap_name)
        if not cap:
            return None

        # Safety Check: Ban non-read-only capabilities in curiosity daemon
        manifest = cap.manifest
        if manifest.reversibility != ReversibilityClass.READ_ONLY or manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
            # Requires operator grant; cannot be executed autonomously
            return IntentProposal(
                proposal_id=f"gap_prop_{uuid.uuid4().hex[:8]}",
                objective=f"Verify epistemic gap on {gap_claim.subject}",
                proposed_capability=cap_name,
                provided_parameters=params,
                missing_parameters=[],
                constraints={"requires_operator_approval": True, "safety_veto": True}
            )

        return IntentProposal(
            proposal_id=f"inq_{uuid.uuid4().hex[:8]}",
            objective=f"Autonomous refresh of {gap_claim.subject} -> {gap_claim.predicate}",
            proposed_capability=cap_name,
            provided_parameters=params,
            missing_parameters=[],
            constraints={"source": "curiosity_daemon", "gap_claim_id": gap_claim.claim_id}
        )

    def run_inquiry_cycle(self, runtime: Any) -> List[Dict[str, Any]]:
        """
        Execute one complete curiosity cycle (Governed DAG Execution):
        1. Reap expired claims in worldview.
        2. Discover top epistemic gaps not in Tabu Graveyard.
        3. Propose and link questions in CuriosityQuestionDAG.
        4. Execute ready unanswered questions within hourly rate budget.
        5. Ground results in EventStore and resolve DAG question nodes with evidence.
        """
        results = []
        runtime.worldview.reap_expired_claims()
        gaps = self.discover_epistemic_gaps(runtime.worldview)

        # 1. Propose questions to DAG for each discovered gap
        for gap in gaps:
            runtime.question_dag.propose_question(
                target_subject=gap.subject,
                target_predicate=gap.predicate,
                question_text=f"Verify epistemic state of {gap.subject} [{gap.predicate}]",
                impact_score=max(1.0, round(10.0 - (gap.assurance_score * 10.0), 1)),
                estimated_cost_score=1.0
            )

        # 2. Get prioritized ready questions from DAG
        ready_questions = runtime.question_dag.get_ready_unanswered_questions()

        for q in ready_questions[:3]:
            if not self.can_inquire_under_budget():
                break

            # Find matching gap node
            matching_gaps = [g for g in gaps if g.subject == q.target_subject and g.predicate == q.target_predicate]
            gap = matching_gaps[0] if matching_gaps else TransmutationNode(
                claim_id=f"CLM-{uuid.uuid4().hex[:8].upper()}",
                subject=q.target_subject,
                predicate=q.target_predicate,
                value=None,
                state=EpistemicCategory.INTELLIGENCE_GAP,
                reliability=ReliabilityClass.DIRECT_SENSOR,
                assurance_score=0.1
            )

            proposal = self.formulate_inquiry_proposal(gap, runtime)
            if not proposal:
                continue

            if proposal.constraints.get("safety_veto"):
                results.append({
                    "status": "SAFETY_BLOCKED_REQUIRES_OPERATOR",
                    "question_id": q.question_id,
                    "claim_id": gap.claim_id,
                    "proposal_id": proposal.proposal_id
                })
                continue

            # Execute safe read-only reference loop
            scope = ScopeGrant(
                scope_id="scope_curiosity_ro",
                scope_type=ScopeType.LOCAL_SYSTEM,
                allowed_targets=["local_memory", "system", gap.subject],
                valid_until=time.time() + 60
            )

            res = runtime.execute_reference_loop(proposal, scope_grant=scope)
            self.record_inquiry()

            # Resolve question in DAG with empirical evidence receipt
            receipt_id = res["receipt"].receipt_id if res.get("receipt") else None
            if res["status"] == "SUCCESS" and receipt_id:
                runtime.question_dag.resolve_question_with_evidence(
                    question_id=q.question_id,
                    answer_value=res["receipt"].results,
                    receipt_ids=[receipt_id]
                )

            results.append({
                "status": res["status"],
                "question_id": q.question_id,
                "gap_claim_id": gap.claim_id,
                "proposal_id": proposal.proposal_id,
                "receipt_id": receipt_id
            })

        return results

    def start(self, runtime: Any):
        """Start autonomous background curiosity thread."""
        self.running = True
        def _loop():
            while self.running:
                try:
                    self.run_inquiry_cycle(runtime)
                except Exception:
                    pass
                time.sleep(self.inquiry_interval_seconds)

        self._thread = threading.Thread(target=_loop, name="CIPH-CuriosityDaemon", daemon=True)
        self._thread.start()

    def stop(self):
        """Stop background curiosity thread."""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
