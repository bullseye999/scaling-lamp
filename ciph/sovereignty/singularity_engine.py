"""
ciph.sovereignty.singularity_engine - Governed Singularity Engine (Stage 7).
Coordinates economic solvency telemetry, perpetual self-maintenance, and strict operator-tethered evolution.
"""

import time
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass

from ciph.kernel.policy_engine import AuthorizationGrant, AuthorizationTier


@dataclass
class SolvencyStatus:
    total_reserve_usd: float
    burn_rate_daily_usd: float
    runway_days: float
    is_solvent: bool
    last_audit_timestamp: float


class SovereigntyEngine:
    """
    Stage 7 Sovereign Governance & Self-Sustaining Runtime Engine.
    Monitors economic runway, orchestrates autonomous maintenance, and enforces the operator leash.
    """

    def __init__(self, vault=None):
        self.vault = vault

    def calculate_solvency(self, reserve_override: Optional[float] = None) -> SolvencyStatus:
        """Compute operational runway based on available reserves and estimated compute burn."""
        reserve = reserve_override if reserve_override is not None else 2500.0  # Default initial treasury
        daily_burn = 12.50  # VPS + proxy + API token average daily cost
        runway = reserve / daily_burn if daily_burn > 0 else 999.0
        return SolvencyStatus(
            total_reserve_usd=round(reserve, 2),
            burn_rate_daily_usd=round(daily_burn, 2),
            runway_days=round(runway, 1),
            is_solvent=runway > 30.0,
            last_audit_timestamp=time.time()
        )

    def evaluate_system_health(self, runtime) -> Dict[str, Any]:
        """Perform comprehensive self-maintenance audit across memory, capabilities, and trust registry."""
        manifests = runtime.get_manifests()
        worldview_claims = runtime.worldview.query_active_claims(limit=50)
        solvency = self.calculate_solvency()

        return {
            "status": "HEALTHY" if solvency.is_solvent else "LOW_RUNWAY_WARNING",
            "active_capabilities": len(manifests),
            "worldview_active_claims": len(worldview_claims),
            "solvency": {
                "reserve_usd": solvency.total_reserve_usd,
                "runway_days": solvency.runway_days,
                "is_solvent": solvency.is_solvent
            },
            "timestamp": time.time()
        }

    def execute_governed_evolution_promotion(
        self,
        runtime,
        proposal_id: str,
        operator_grant: Optional[AuthorizationGrant] = None
    ) -> Dict[str, Any]:
        """
        Promote a staged upgrade into the live kernel.
        Constitutional Invariant: Halts fail-closed without an authentic operator grant.
        """
        if operator_grant is None:
            return {
                "success": False,
                "status": "CONSTITUTIONAL_VETO",
                "error": "Model cannot promote self-upgrades autonomously. Cryptographic Operator Consent (K_operator) required."
            }

        if not operator_grant.verify_signature(runtime.auth_secret_key):
            return {
                "success": False,
                "status": "INVALID_GRANT",
                "error": "Operator consent grant signature invalid or expired."
            }

        # Dispatch via governed reference loop (Worker-Only Execution Spine)
        from ciph.planner.schemas import IntentProposal
        proposal = IntentProposal(
            proposal_id=f"PROP-PROMO-{proposal_id}",
            objective=f"Promote evolved upgrade: {proposal_id}",
            proposed_capability="code.promote_upgrade",
            provided_parameters={"proposal_id": proposal_id}
        )
        res = runtime.execute_reference_loop(proposal, auth_grant=operator_grant)
        receipt = res.get("receipt")
        return {
            "success": res.get("status") == "SUCCESS",
            "status": "PROMOTION_COMMITTED" if res.get("status") == "SUCCESS" else "PROMOTION_FAILED",
            "receipt": receipt
        }
