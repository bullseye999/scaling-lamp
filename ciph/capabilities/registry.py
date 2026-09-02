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


class CvssCalculatorCapability(BaseCapability):
    """Adapter for deterministic CVSS v3.1 calculation."""

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="pentest.cvss_calculate",
            description="Deterministic FIRST.org CVSS v3.1 base score computation",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=10
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        from cvss_calculator import CVSSv31Calculator
        vector = params.get("vector")
        if vector:
            return CVSSv31Calculator.calculate_from_vector(vector)
        else:
            metrics = {k.upper(): str(v).upper() for k, v in params.items() if k.upper() in CVSSv31Calculator.METRIC_WEIGHTS}
            if not metrics:
                # Default high severity sample
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                return CVSSv31Calculator.calculate_from_vector(vector)
            return CVSSv31Calculator.calculate_from_metrics(metrics)


class MemoryRetrieveCapability(BaseCapability):
    """Adapter for retrieving values from Vault / Local Memory."""

    def __init__(self, memory_backend=None):
        self._memory = memory_backend or {}

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="memory.retrieve",
            description="Retrieve stored knowledge or operational records from memory",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=10
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        key = params.get("key", "")
        if hasattr(self._memory, "get_memory"):
            val = self._memory.get_memory(key)
        elif hasattr(self._memory, "get"):
            val = self._memory.get(key)
        elif isinstance(self._memory, dict):
            val = self._memory.get(key)
        else:
            val = f"record_{key}"
        return {"success": True, "key": key, "value": val, "found": val is not None}


class MemoryStoreCapability(BaseCapability):
    """Adapter for storing values into Vault / Local Memory."""

    def __init__(self, memory_backend=None):
        self._memory = memory_backend if memory_backend is not None else {}

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="memory.store",
            description="Store or update a verified record in memory vault",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.REVERSIBLE,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=10
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        key = params.get("key", "")
        val = params.get("value", "")
        if hasattr(self._memory, "store_memory"):
            self._memory.store_memory(key, val)
        elif isinstance(self._memory, dict):
            self._memory[key] = val
        return {"success": True, "key": key, "value": val, "stored": True}


class CodeAuditCapability(BaseCapability):
    """Adapter for auditing dependencies in code files safely."""

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="code.audit_dependencies",
            description="Audit dependencies of Python source files without automatic installation",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=20
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        from code_staging import CodeStagingManager
        import os
        csm = CodeStagingManager()
        target_file = params.get("target_file", "")
        code_content = params.get("code")
        if not code_content and target_file and os.path.exists(target_file):
            with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

        if not code_content:
            return {"success": False, "error": f"Target file '{target_file}' not found or empty."}

        deps = csm.extract_dependencies(code_content)
        status = csm.resolve_dependencies(deps)
        return {"success": True, "dependencies": deps, "status": status, "missing_count": sum(1 for v in status.values() if not v)}


class TorStatusCapability(BaseCapability):
    """Adapter for verifying Tor network status."""

    def __init__(self, tor_proxy_instance=None):
        self._tor = tor_proxy_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="tor.check_status",
            description="Verify active Tor proxy circuit and health",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.TOR_MANDATORY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=15
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._tor and hasattr(self._tor, 'check_connection'):
            connected = self._tor.check_connection()
            return {"success": True, "connected": connected, "transport": "TOR_SOCKS5H"}
        return {"success": True, "connected": True, "transport": "TOR_SOCKS5H", "simulated": True}

