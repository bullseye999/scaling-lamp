"""
ciph.contracts.enums - Dependency-leaf enumeration definitions for CIPH 4.0.
All subsystems import shared enums from here to avoid circular imports and ensure identical enum identities.
"""

from enum import Enum
from typing import Dict, Optional


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
    LANE_1_READ_ONLY     = "LANE_1_READ_ONLY"     # Fast memory/vault read -> output
    LANE_2_LOCAL_MATH    = "LANE_2_LOCAL_MATH"    # Pure deterministic computation
    LANE_3_OBSERVATION   = "LANE_3_OBSERVATION"   # External passive observation
    LANE_4_CONSEQUENTIAL = "LANE_4_CONSEQUENTIAL" # Local mutation with T₀ snapshot
    LANE_5_AUTONOMOUS    = "LANE_5_AUTONOMOUS"    # Multi-step DAG workflow


class ScopeType(str, Enum):
    LOCAL_SYSTEM       = "LOCAL_SYSTEM"
    TARGET_DOMAIN      = "TARGET_DOMAIN"
    TELEMETRY_ONLY     = "TELEMETRY_ONLY"
    CONTAINER_SANDBOX  = "CONTAINER_SANDBOX"
    GLOBAL_READ_ONLY   = "GLOBAL_READ_ONLY"
    PROCESS_ISOLATED   = "PROCESS_ISOLATED"


class JobState(str, Enum):
    QUEUED                  = "QUEUED"
    AWAITING_AUTHORIZE      = "AWAITING_AUTHORIZE"
    AUTHORIZED              = "AUTHORIZED"
    LEASED                  = "LEASED"
    EXECUTING               = "EXECUTING"
    RECEIPT_COMMITTED       = "RECEIPT_COMMITTED"
    RETRYING                = "RETRYING"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    COMPLETED               = "COMPLETED"
    SUCCEEDED               = "SUCCEEDED"
    FAILED                  = "FAILED"
    TIMED_OUT               = "TIMED_OUT"
    QUARANTINED             = "QUARANTINED"
    CANCELLED               = "CANCELLED"
    DEAD_LETTER             = "DEAD_LETTER"


class ProjectionState(str, Enum):
    PENDING                 = "PENDING"
    PROCESSING              = "PROCESSING"
    COMPLETE                = "COMPLETE"
    FAILED                  = "FAILED"


class ExecutionOutcome(str, Enum):
    SUCCESS                 = "SUCCESS"
    PARTIAL                 = "PARTIAL"
    FAILED                  = "FAILED"
    BLOCKED                 = "BLOCKED"
    UNAVAILABLE             = "UNAVAILABLE"
    UNREACHABLE             = "UNREACHABLE"
    TIMEOUT                 = "TIMEOUT"


class EvidenceMode(str, Enum):
    REAL                    = "REAL"
    SYNTHETIC               = "SYNTHETIC"


class EpistemicDecision(str, Enum):
    PENDING                 = "PENDING"
    ACCEPTED                = "ACCEPTED"
    SUPPORTED               = "SUPPORTED"
    DISPUTED                = "DISPUTED"
    REJECTED                = "REJECTED"
    INCONCLUSIVE            = "INCONCLUSIVE"


class OutcomeCategory(str, Enum):
    SUCCESS            = "SUCCESS"
    PARTIAL_SUCCESS    = "PARTIAL_SUCCESS"
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    POLICY_BLOCKED     = "POLICY_BLOCKED"
    TIMEOUT            = "TIMEOUT"
    EXECUTION_ERROR    = "EXECUTION_ERROR"
    AUTH_REQUIRED      = "AUTH_REQUIRED"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    SANDBOX_VIOLATION  = "SANDBOX_VIOLATION"
    CANCELLED          = "CANCELLED"


class ReliabilityClass(str, Enum):
    AUTHORITATIVE_LOCAL = "AUTHORITATIVE_LOCAL"  # Local system commands (git, fs, os)
    DIRECT_SENSOR       = "DIRECT_SENSOR"        # Direct HTTP/Socket response from target
    THIRD_PARTY_FEED    = "THIRD_PARTY_FEED"     # RSS, CVE, NVD, AlienVault feeds
    PASSIVE_RECON       = "PASSIVE_RECON"        # Wayback, crt.sh, search engine caches
    UNVERIFIED_INCOMING = "UNVERIFIED_INCOMING"  # Incoming external messages / whispers


class EpistemicState(str, Enum):
    UNKNOWN          = "UNKNOWN"           # Explicitly acknowledged gap
    INTELLIGENCE_GAP = "INTELLIGENCE_GAP"  # Backward compatibility alias
    HYPOTHESIZED     = "HYPOTHESIZED"      # Formal testable premise
    OBSERVED         = "OBSERVED"          # Point-in-time telemetry received
    INFERRED         = "INFERRED"          # Derived via deterministic logic
    CORROBORATED     = "CORROBORATED"      # Corroborated by independent sources
    SUPPORTED        = "SUPPORTED"         # Corroborated with verified receipts
    DISPUTED         = "DISPUTED"          # Quarantined pending confirmation
    REFUTED          = "REFUTED"           # Negative result -> Sent to Graveyard
    STALE            = "STALE"             # Freshness deadline expired
    SUPERSEDED       = "SUPERSEDED"        # Overridden by newer valid event
    VERIFIED_REAL    = "VERIFIED_REAL"     # Empirically proven within scope & TTL


# Canonical alias
EpistemicCategory = EpistemicState


class LifecycleState(str, Enum):
    ACTIVE   = "ACTIVE"
    DORMANT  = "DORMANT"
    ARCHIVED = "ARCHIVED"
    REOPENED = "REOPENED"


class DecayProfile(str, Enum):
    LIVE_NETWORK_STATE   = "LIVE_NETWORK_STATE"    # 5 minutes
    OPERATIONAL_ANOMALY  = "OPERATIONAL_ANOMALY"   # 24 hours
    SOFTWARE_BEHAVIOR    = "SOFTWARE_BEHAVIOR"     # 7 days
    STRATEGIC_HYPOTHESIS = "STRATEGIC_HYPOTHESIS"  # 30 days
    MATHEMATICAL_FACT    = "MATHEMATICAL_FACT"     # Never decays


DECAY_DURATIONS_SECONDS: Dict[DecayProfile, Optional[float]] = {
    DecayProfile.LIVE_NETWORK_STATE: 300.0,
    DecayProfile.OPERATIONAL_ANOMALY: 86400.0,
    DecayProfile.SOFTWARE_BEHAVIOR: 604800.0,
    DecayProfile.STRATEGIC_HYPOTHESIS: 2592000.0,
    DecayProfile.MATHEMATICAL_FACT: None,
}


class SkillPromotionTier(str, Enum):
    CANDIDATE = "CANDIDATE"  # Succeeded 1 time
    VALIDATED = "VALIDATED"  # Succeeded >= 3 times across varied parameters
    APPROVED  = "APPROVED"   # Signed off by operator
    ACTIVE    = "ACTIVE"     # Available for fast-path compilation
    REVOKED   = "REVOKED"    # Deprecated / environment drifted


RELIABILITY_BASE_WEIGHTS: Dict[ReliabilityClass, float] = {
    ReliabilityClass.AUTHORITATIVE_LOCAL: 0.95,
    ReliabilityClass.DIRECT_SENSOR: 0.85,
    ReliabilityClass.THIRD_PARTY_FEED: 0.70,
    ReliabilityClass.PASSIVE_RECON: 0.60,
    ReliabilityClass.UNVERIFIED_INCOMING: 0.40,
}
