"""
ciph.capabilities.registry - Dynamic Capability Registry & In-Place Adapters.
Manages all decoupled capability plugins and routes execution through verified manifests.
"""

from typing import Dict, List, Optional, Any
from ciph.capabilities.base import BaseCapability
from ciph.kernel.policy_engine import CapabilityManifest, ExecutionLane


class CapabilityRegistry:
    """Registry managing all operational capabilities in CIPH 4.0."""

    def __init__(self):
        self._capabilities: Dict[str, BaseCapability] = {}

    def register(self, capability: BaseCapability) -> None:
        """Register a capability plugin instance."""
        manifest = capability.manifest
        self._capabilities[manifest.name] = capability

    def get(self, name: str) -> Optional[BaseCapability]:
        """Retrieve capability by registered manifest name."""
        return self._capabilities.get(name)

    def list_manifests(self) -> List[CapabilityManifest]:
        """Return all registered capability manifests."""
        return [cap.manifest for cap in self._capabilities.values()]

    def list_names(self) -> List[str]:
        """Return all registered capability names."""
        return list(self._capabilities.keys())

    def dispatch(self, name: str, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Any:
        """Dispatch execution directly through the capability wrapper."""
        cap = self.get(name)
        if not cap:
            raise KeyError(f"Capability '{name}' not found in registry. Available: {self.list_names()}")
        return cap.execute(params, context)


# ─────────────────────────────────────────────────────────────────────────────
# In-Place Capability Adapters for Existing CIPH 3.0 Modules
# ─────────────────────────────────────────────────────────────────────────────

from ciph.kernel.policy_engine import (
    NetworkPolicy,
    ReversibilityClass,
    RiskTier,
    AuthorizationTier
)


class BountyScanCapability(BaseCapability):
    """Adapter for bounty_hunter.deep_scan"""

    def __init__(self, bounty_instance):
        self._bounty = bounty_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="cybersecurity.bounty_scan",
            description="Execute comprehensive passive reconnaissance & takeover audit over Tor",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.TOR_MANDATORY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=60
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        target = params.get("target") or params.get("domain", "")
        force = params.get("force", True)
        return self._bounty.deep_scan(target, force=force)


class OsintMonetizeCapability(BaseCapability):
    """Adapter for osint_miner.find_monetizable_threats"""

    def __init__(self, osint_instance):
        self._osint = osint_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="osint.find_monetizable_threats",
            description="Triage fresh threat feeds for high-priority bug bounty opportunities",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.DIRECT_APPROVED,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=30
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ops = self._osint.find_monetizable_threats()
        return {"success": True, "opportunities": ops, "count": len(ops)}


class SportsPredictCapability(BaseCapability):
    """Adapter for sports_predictor.predict_match"""

    def __init__(self, sports_instance):
        self._sports = sports_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="sports.predict_match",
            description="5-factor probabilistic sports prediction (Poisson + xG modeling)",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.DIRECT_APPROVED,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=20
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        home = params.get("home") or params.get("home_team", "")
        away = params.get("away") or params.get("away_team", "")
        res = self._sports.predict_match(home, away)
        return {"success": True, "prediction": res}
