"""
ciph.kernel.policy_engine - Strict typed enums, capability manifests, and policy definitions.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional, List


class NetworkPolicy(str, Enum):
    TOR_MANDATORY   = "TOR_MANDATORY"    # SOCKS5h Tor only (Fail-closed; drops if proxy down)
    DIRECT_APPROVED = "DIRECT_APPROVED"  # Clearnet authorized (e.g. LLM API, live sports data)
    LOCAL_ONLY      = "LOCAL_ONLY"       # Localhost / Subnet only (Internet sockets disabled)
    OFFLINE_ONLY    = "OFFLINE_ONLY"     # Zero network sockets allowed (Pure local compute)
    NETWORK_DENIED  = "NETWORK_DENIED"   # Blocked by security policy


class ReversibilityClass(str, Enum):
    REVERSIBLE    = "REVERSIBLE"      # Local files, staging artifacts (T₀ rollback snapshot)
    COMPENSATABLE = "COMPENSATABLE"    # DB rows, daemon services (Registered inverse action)
    IRREVERSIBLE  = "IRREVERSIBLE"    # External network writes, trades, sent messages
    READ_ONLY     = "READ_ONLY"        # Zero side-effects / state mutation


class RiskTier(str, Enum):
    NONE     = "NONE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AuthorizationTier(str, Enum):
    AUTO                = "AUTO"                 # Pre-authorized by policy
    BATCH_APPROVE       = "BATCH_APPROVE"        # Staged for 1-click batch review
    MANDATORY_INTERRUPT = "MANDATORY_INTERRUPT"  # Requires immediate operator confirmation


class ExecutionLane(str, Enum):
    LANE_1_READ_ONLY    = "LANE_1_READ_ONLY"     # Fast memory/vault read -> output
    LANE_2_LOCAL_MATH   = "LANE_2_LOCAL_MATH"    # Pure deterministic computation
    LANE_3_OBSERVATION  = "LANE_3_OBSERVATION"   # External passive observation
    LANE_4_CONSEQUENTIAL= "LANE_4_CONSEQUENTIAL" # Local mutation with T₀ snapshot
    LANE_5_AUTONOMOUS   = "LANE_5_AUTONOMOUS"    # Multi-step DAG workflow


@dataclass(frozen=True)
class CapabilityManifest:
    name: str
    description: str
    risk_tier: RiskTier
    network_policy: NetworkPolicy
    reversibility: ReversibilityClass
    authorization: AuthorizationTier
    requires_red_team: bool = False
    timeout_seconds: int = 30

    def derive_execution_lane(self) -> ExecutionLane:
        """Deterministically derive execution lane from static capability attributes."""
        if self.reversibility == ReversibilityClass.READ_ONLY:
            if self.network_policy in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.LOCAL_ONLY) and self.risk_tier == RiskTier.NONE:
                return ExecutionLane.LANE_1_READ_ONLY
            elif self.network_policy in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.LOCAL_ONLY):
                return ExecutionLane.LANE_2_LOCAL_MATH
            else:
                return ExecutionLane.LANE_3_OBSERVATION
        elif self.reversibility in (ReversibilityClass.REVERSIBLE, ReversibilityClass.COMPENSATABLE):
            return ExecutionLane.LANE_4_CONSEQUENTIAL
        else:
            return ExecutionLane.LANE_5_AUTONOMOUS
