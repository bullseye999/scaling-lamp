"""
ciph.kernel.policy_engine - Strict typed enums, capability manifests, and policy definitions.
"""

import time
import hmac
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple


from ciph.contracts.enums import (
    NetworkPolicy,
    ReversibilityClass,
    RiskTier,
    AuthorizationTier,
    ExecutionLane,
    ScopeType,
)
from ciph.contracts.grants import (
    ScopeGrant,
    AuthorizationGrant,
)


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
    version: str = "1.0.0"

    def compute_manifest_hash(self) -> str:
        """Deterministic SHA-256 hash of the static capability manifest."""
        canonical = f"{self.name}:{self.version}:{self.risk_tier.value}:{self.network_policy.value}:{self.reversibility.value}:{self.authorization.value}:{self.requires_red_team}:{self.timeout_seconds}"
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

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


def is_sandboxed_execution_required(capability_name, manifest=None, cap_instance=None,
                                    scope_grant=None, execution_token=None, code_origin=None):
    """Only trusted registration supplies origin; names and test objects confer no authority."""
    if not isinstance(capability_name, str) and cap_instance is None:
        cap_instance = capability_name
    if manifest is None and cap_instance is not None:
        manifest = getattr(cap_instance, 'manifest', None)
    if code_origin != 'internal':
        return True
    if getattr(cap_instance, 'requires_sandbox', False) or getattr(manifest, 'requires_sandbox', False):
        return True
    if scope_grant and scope_grant.scope_type in (ScopeType.CONTAINER_SANDBOX, ScopeType.PROCESS_ISOLATED):
        return True
    if execution_token and execution_token.execution_lane in ('LANE_4_SANDBOXED', 'LANE_3_OBSERVATION', ExecutionLane.LANE_3_OBSERVATION.value):
        return True
    return manifest is None or manifest.network_policy not in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.LOCAL_ONLY)
