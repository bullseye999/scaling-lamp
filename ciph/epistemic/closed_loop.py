"""
ciph.epistemic.closed_loop - Autonomous Epistemic Closed-Loop (Stage 4).
Connects Curiosity, Ingress Gating, Worker Receipts, Transmutation DAG, and Worldview
into a self-sustaining, continuous loop of empirical discovery and belief hygiene.
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from ciph.planner.schemas import IntentProposal
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.contracts.enums import LifecycleState
from ciph.perception.observation import ReliabilityClass


@dataclass
class EpistemicCycleReport:
    cycle_id: str
    timestamp: float
    stale_claims_detected: int
    inquiries_dispatched: int
    receipts_committed: int
    claims_refreshed: int
    errors: List[str] = field(default_factory=list)


class EpistemicClosedLoopDaemon:
    """
    Stage 4 Cognitive Daemon:
    Perpetually monitors worldview claims for epistemic decay, stale deadlines,
    and contradictions, automatically generating and executing empirical probes.
    """

    def __init__(self, check_interval_seconds: int = 60):
        self.check_interval_seconds = check_interval_seconds
        self.last_run_timestamp = 0.0
        self.history: List[EpistemicCycleReport] = []

    def audit_worldview_freshness(self, runtime) -> List[TransmutationNode]:
        """Identify claims whose freshness deadline has lapsed or is expiring soon."""
        now = time.time()
        stale_nodes = []
        try:
            # Query active claims from the materialized worldview including expired, dormant, and stale states
            all_claims = runtime.worldview.query_active_claims(
                states=["SUPPORTED", "OBSERVED", "STALE", "DISPUTED", "INFERRED", "HYPOTHESIZED", "VERIFIED_REAL"],
                include_expired=True,
                include_archived=True,
                limit=100
            )
            for claim in all_claims:
                if claim.freshness_deadline and claim.freshness_deadline <= now:
                    stale_nodes.append(claim)
                elif claim.state in (EpistemicCategory.STALE, EpistemicCategory.DISPUTED) or getattr(claim, 'lifecycle_state', None) == LifecycleState.DORMANT:
                    stale_nodes.append(claim)
        except Exception:
            raise
        return stale_nodes

    def run_closed_loop_cycle(self, runtime, force_refresh_all: bool = False) -> EpistemicCycleReport:
        """Execute one complete autonomous closed-loop inquiry and worldview update cycle."""
        cycle_id = f"CYC-{uuid.uuid4().hex[:8].upper()}"
        now = time.time()
        report = EpistemicCycleReport(
            cycle_id=cycle_id,
            timestamp=now,
            stale_claims_detected=0,
            inquiries_dispatched=0,
            receipts_committed=0,
            claims_refreshed=0
        )

        stale_claims = self.audit_worldview_freshness(runtime)
        report.stale_claims_detected = len(stale_claims)

        # Phase 6 owns all autonomous dispatch, evidence resolution and budgets.
        # force_refresh_all requests a scan; it cannot synthesize an external probe.
        results = runtime.curiosity_daemon.run_inquiry_cycle(runtime)
        report.inquiries_dispatched = sum(bool(r.get('dispatched')) for r in results)
        report.receipts_committed = sum(bool(r.get('receipt_id')) for r in results)
        report.claims_refreshed = sum(bool(r.get('answered')) for r in results)
        report.errors = [r['status'] for r in results if not r.get('answered')]

        self.last_run_timestamp = now
        self.history.append(report)
        return report
