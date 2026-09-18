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
        self._origins = {}

    def register(self, capability: BaseCapability, *, code_origin="external") -> None:
        """Register a capability plugin instance."""
        if code_origin not in ("internal", "external", "untrusted"):
            raise ValueError("INVALID_CODE_ORIGIN")
        manifest = capability.manifest
        self._origins[manifest.name] = (capability, code_origin)
        self._capabilities[manifest.name] = capability

    def code_origin(self, name):
        record = self._origins.get(name)
        return record[1] if record and record[0] is self._capabilities.get(name) else 'untrusted'

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
        """Dispatch execution through capability wrapper under Gate Zero invariant."""
        cap = self.get(name)
        if not cap:
            raise KeyError(f"Capability '{name}' not found in registry. Available: {self.list_names()}")
        # Under Gate Zero, direct dispatch of production capabilities without worker context is prohibited
        from ciph.capabilities.base import CANONICAL_CAPABILITIES
        if name in CANONICAL_CAPABILITIES and (not context or not context.get("worker_context")):
            raise PermissionError(f"GATE_ZERO_VIOLATION: Direct registry dispatch forbidden for '{name}'. Capability invocation requires an authenticated worker execution context.")
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

    def __init__(self, bounty_instance=None):
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
        if self._bounty and hasattr(self._bounty, 'deep_scan'):
            return self._bounty.deep_scan(target, force=force)
        return {
            "success": False,
            "status": "BACKEND_UNAVAILABLE",
            "target": target,
            "error": "BountyHunter backend instance not configured or unavailable"
        }


class BountySummaryCapability(BaseCapability):
    """Adapter for bounty_hunter.list_bounties_summary"""

    def __init__(self, bounty_instance=None):
        self._bounty = bounty_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="cybersecurity.bounty_summary",
            description="Inspect active bug bounty programs, targets, and scope policies",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=10
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._bounty and hasattr(self._bounty, 'list_bounties_summary'):
            summary = self._bounty.list_bounties_summary()
            return {"success": True, "summary": summary}
        return {
            "success": False,
            "status": "BACKEND_UNAVAILABLE",
            "error": "BountyHunter backend instance not configured or unavailable"
        }


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
        if self._osint and hasattr(self._osint, 'find_monetizable_threats'):
            ops = self._osint.find_monetizable_threats()
            return {"success": True, "opportunities": ops, "count": len(ops)}
        return {"success": True, "opportunities": [], "count": 0}


class DarknetStatusCapability(BaseCapability):
    """Adapter for darknet_monitor.get_status"""

    def __init__(self, darknet_instance=None):
        self._darknet = darknet_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="darknet.get_status",
            description="Inspect darknet monitor telemetry, monitored feeds, and active alerts",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=10
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._darknet and hasattr(self._darknet, 'get_status'):
            status = self._darknet.get_status()
            return {"success": True, "status": status}
        return {
            "success": False,
            "status": "BACKEND_UNAVAILABLE",
            "error": "DarknetMonitor backend instance not configured or unavailable"
        }


class DarknetReportCapability(BaseCapability):
    """Adapter for darknet_monitor.get_detailed_report"""

    def __init__(self, darknet_instance=None):
        self._darknet = darknet_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="darknet.get_detailed_report",
            description="Retrieve detailed analysis report of darknet intelligence scans",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=15
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._darknet and hasattr(self._darknet, 'get_detailed_report'):
            report = self._darknet.get_detailed_report()
            return {"success": True, "report": report}
        return {
            "success": False,
            "status": "BACKEND_UNAVAILABLE",
            "error": "DarknetMonitor backend instance not configured or unavailable"
        }


class SportsPredictCapability(BaseCapability):
    """Adapter for sports_predictor.predict_match"""

    def __init__(self, sports_instance=None):
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
        if self._sports and hasattr(self._sports, 'predict_match'):
            res = self._sports.predict_match(home, away)
            return {"success": True, "prediction": res}
        return {
            "success": False,
            "status": "BACKEND_UNAVAILABLE",
            "error": "SportsPredictor backend instance not configured or unavailable"
        }


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
        self._memory = memory_backend if memory_backend is not None else {}

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
            return {"success": False, "status": "BACKEND_UNAVAILABLE",
                    "error": "Memory backend does not support retrieval", "found": False}
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
        else:
            return {"success": False, "status": "BACKEND_UNAVAILABLE",
                    "error": "Memory backend does not support storage", "stored": False}
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
        csm = object.__new__(CodeStagingManager)  # Pure inspection; no staging directory writes.
        target_file = params.get("target_file") or params.get("file_path", "")
        code_content = params.get("code")
        if not code_content and target_file and os.path.exists(target_file):
            with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()

        if not code_content:
            return {"success": False, "error": f"Target file '{target_file}' not found or empty."}

        deps = csm.extract_dependencies(code_content)
        status = csm.resolve_dependencies(deps)
        return {"success": True, "dependencies": deps, "status": status, "missing_count": sum(1 for v in status.values() if not v)}


class CodeListStagedCapability(BaseCapability):
    """Adapter for code_staging.list_staged"""

    def __init__(self, code_staging_instance=None):
        self._staging = code_staging_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="code.list_staged",
            description="List staged code artifacts, upgrade proposals, and validation statuses",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=10
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._staging and hasattr(self._staging, 'list_staged'):
            summary = self._staging.list_staged()
            return {"success": True, "staged": summary}
        return {"success": False, "status": "BACKEND_UNAVAILABLE", "error": "Code staging backend unavailable"}


class CodePromoteUpgradeCapability(BaseCapability):
    """Adapter for promoting/applying staged code upgrades with MANDATORY_INTERRUPT authorization."""

    def __init__(self, code_staging_instance=None):
        self._staging = code_staging_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="code.promote_upgrade",
            description="Atomically promote and apply staged code upgrade with mandatory operator consent",
            risk_tier=RiskTier.CRITICAL,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.REVERSIBLE,
            authorization=AuthorizationTier.MANDATORY_INTERRUPT,
            timeout_seconds=30
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        proposal_id = params.get("proposal_id") or params.get("id", "")
        if self._staging and hasattr(self._staging, 'apply'):
            if not proposal_id:
                return {"success": False, "error": "A staged proposal ID is required"}
            success, msg = self._staging.apply(proposal_id)
            return {"success": success, "message": msg, "proposal_id": proposal_id}
        return {"success": False, "status": "BACKEND_UNAVAILABLE", "error": "Code staging backend unavailable", "proposal_id": proposal_id}


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
        if self._tor is not None and (hasattr(self._tor, 'check_connection') or hasattr(self._tor, 'get_tor_ip')):
            if hasattr(self._tor, 'check_connection'):
                connected = bool(self._tor.check_connection())
                exit_ip = None
            else:
                exit_ip = self._tor.get_tor_ip()
                connected = bool(exit_ip)
            return {
                "success": connected, "connected": connected, "exit_ip": exit_ip,
                "transport": "TOR_SOCKS5H" if connected else "UNREACHABLE",
                "error": None if connected else "Tor connection check failed",
            }
        return {
            "success": False,
            "connected": False,
            "transport": "UNAVAILABLE",
            "error": "Tor proxy backend is not configured or unavailable"
        }


class WisdomConsultCapability(BaseCapability):
    """Adapter for book_engine to query library and situational advice."""

    def __init__(self, book_engine_instance=None):
        self._books = book_engine_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="wisdom.consult_library",
            description="Query the strategic and philosophical library for situational guidance",
            risk_tier=RiskTier.NONE,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=15
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query = params.get("query") or params.get("situation") or ""
        if self._books and hasattr(self._books, 'get_situational_advice'):
            if query:
                advice = self._books.get_situational_advice(query)
                return {"success": True, "type": "advice", "result": advice}
            else:
                books = self._books.list_books()
                return {"success": True, "type": "catalog", "result": books}
        return {
            "success": False,
            "status": "BACKEND_UNAVAILABLE",
            "error": "BookEngine backend instance not configured or unavailable"
        }


class TradingPortfolioCapability(BaseCapability):
    """Adapter for trading_engine to check crypto portfolio and market opportunities."""

    def __init__(self, trading_engine_instance=None):
        self._trading = trading_engine_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="trading.portfolio_check",
            description="Evaluate automated cryptocurrency portfolio balance, performance, and risk",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.DIRECT_APPROVED,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=20
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._trading and hasattr(self._trading, 'portfolio_health_check'):
            res = self._trading.portfolio_health_check()
            return {"success": True, "portfolio": res}
        return {
            "success": False,
            "status": "BACKEND_UNAVAILABLE",
            "error": "TradingEngine backend instance not configured or unavailable"
        }


class DeadmanStatusCapability(BaseCapability):
    """Adapter for dead_mans_switch to verify tamper failsafe status."""

    def __init__(self, deadman_instance=None):
        self._deadman = deadman_instance

    @property
    def manifest(self) -> CapabilityManifest:
        return CapabilityManifest(
            name="security.deadman_status",
            description="Inspect active dead man's failsafe countdown and check-in signal",
            risk_tier=RiskTier.LOW,
            network_policy=NetworkPolicy.OFFLINE_ONLY,
            reversibility=ReversibilityClass.READ_ONLY,
            authorization=AuthorizationTier.AUTO,
            timeout_seconds=10
        )

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if params.get("action", "status") != "status":
            return {"success": False, "status": "POLICY_BLOCKED",
                    "error": "Status capability cannot change the failsafe switch"}
        if self._deadman is not None and hasattr(self._deadman, 'trigger_thread'):
            thread = self._deadman.trigger_thread
            active = thread is not None and thread.is_alive()
            return {"success": True, "active": active,
                    "message": "Failsafe monitor thread is running" if active else "Failsafe monitor thread is not running"}
        return {
            "success": False,
            "status": "BACKEND_UNAVAILABLE",
            "error": "DeadMansSwitch backend instance not configured or unavailable"
        }


