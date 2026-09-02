"""
ciph.kernel.policy_engine - Strict typed enums, capability manifests, and policy definitions.
"""

import time
import hmac
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple


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


class ScopeType(str, Enum):
    LOCAL_SYSTEM       = "LOCAL_SYSTEM"
    TARGET_DOMAIN      = "TARGET_DOMAIN"
    TELEMETRY_ONLY     = "TELEMETRY_ONLY"
    CONTAINER_SANDBOX  = "CONTAINER_SANDBOX"
    GLOBAL_READ_ONLY   = "GLOBAL_READ_ONLY"


@dataclass(frozen=True)
class ScopeGrant:
    scope_id: str
    scope_type: ScopeType
    allowed_targets: List[str]
    denied_targets: List[str] = field(default_factory=list)
    network_policy_override: Optional[NetworkPolicy] = None
    valid_until: Optional[float] = None

    def is_target_permitted(self, target: Optional[str]) -> bool:
        """Check if target string is authorized under this scope grant."""
        if not target:
            return True
        # Check denied targets first
        for denied in self.denied_targets:
            if denied == target or (denied.startswith("*.") and target.endswith(denied[1:])):
                return False
        # Check wildcard / global allow
        if "*" in self.allowed_targets:
            return True
        # Check specific allow list
        for allowed in self.allowed_targets:
            if allowed == target or (allowed.startswith("*.") and target.endswith(allowed[1:])):
                return True
        return False

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        if self.valid_until is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now > self.valid_until


@dataclass(frozen=True)
class AuthorizationGrant:
    grant_id: str
    plan_hash: str
    step_id: str
    capability: str
    params_hash: str
    scope_grant_id: str
    max_budget: Dict[str, float] = field(default_factory=dict)
    expires_at: float = 0.0
    signature: str = ""
    created_at: float = field(default_factory=time.time)

    def is_valid_for(
        self,
        plan_hash: str,
        step_id: str,
        capability: str,
        params_hash: str,
        current_time: Optional[float] = None,
        required_budget: Optional[Dict[str, float]] = None,
        scope_grant_id: Optional[str] = None
    ) -> bool:
        """Verify that this grant covers the exact execution step, budget limits, scope binding, and has not expired."""
        now = current_time if current_time is not None else time.time()
        if self.expires_at > 0 and now > self.expires_at:
            return False
        if (
            self.plan_hash != plan_hash or
            self.step_id != step_id or
            self.capability != capability or
            self.params_hash != params_hash
        ):
            return False
        # Scope binding check: If a scope is provided in execution context, it must match
        if scope_grant_id is not None and self.scope_grant_id:
            if self.scope_grant_id != scope_grant_id:
                return False
        if required_budget and self.max_budget:
            for k, v in required_budget.items():
                if k in self.max_budget and self.max_budget[k] < v:
                    return False
        return True

    def compute_signature_payload(self) -> str:
        """Generate canonical string for cryptographic signing including budget limits."""
        import json
        budget_str = json.dumps(self.max_budget, sort_keys=True)
        return f"{self.grant_id}:{self.plan_hash}:{self.step_id}:{self.capability}:{self.params_hash}:{self.scope_grant_id}:{budget_str}:{self.expires_at}"

    def sign(self, secret_key: bytes) -> "AuthorizationGrant":
        """Produce a signed copy of this AuthorizationGrant using HMAC-SHA256."""
        payload = self.compute_signature_payload().encode('utf-8')
        sig = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
        return AuthorizationGrant(
            grant_id=self.grant_id,
            plan_hash=self.plan_hash,
            step_id=self.step_id,
            capability=self.capability,
            params_hash=self.params_hash,
            scope_grant_id=self.scope_grant_id,
            max_budget=dict(self.max_budget),
            expires_at=self.expires_at,
            signature=sig,
            created_at=self.created_at
        )

    def verify_signature(self, secret_key: bytes) -> bool:
        """Verify the cryptographic signature of this grant."""
        if not self.signature:
            return False
        payload = self.compute_signature_payload().encode('utf-8')
        expected_sig = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)


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


class AdversarialRedTeamGate:
    """
    Adversarial Falsification & Safety Gate (CIPH 4.0).
    Runs boundary and invariant probes against operations, dynamic patches,
    and self-evolution candidates before execution or promotion.
    """

    DANGEROUS_PATTERNS = [
        "rm -rf",
        "mkfs",
        "dd if=/dev",
        ":(){ :|:& };:",
        "chmod -R 777 /",
        "curl http://",
        "wget http://",
        "> /dev/sda",
        "nc -e",
    ]

    def evaluate_falsification_probe(
        self,
        capability: str,
        params: Dict[str, Any],
        manifest: Optional[CapabilityManifest] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Evaluate parameter and manifest safety against adversarial probes.
        Returns (is_safe, failure_reason).
        """
        # 1. Inspect parameters for destructive payload injection
        for k, v in params.items():
            val_str = str(v)
            for pattern in self.DANGEROUS_PATTERNS:
                if pattern in val_str:
                    return False, f"Adversarial Veto: Dangerous destructive pattern '{pattern}' detected in parameter '{k}'."

        # 2. Network policy mismatch checks
        if manifest:
            if manifest.network_policy == NetworkPolicy.OFFLINE_ONLY:
                target = str(params.get("target", "") or params.get("url", ""))
                if target.startswith("http://") or target.startswith("https://"):
                    return False, f"Adversarial Veto: Capability '{capability}' is OFFLINE_ONLY but received remote network URL '{target}'."

        return True, None
