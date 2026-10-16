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
    ReplaySemantics,
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


MANIFEST_HASH_VERSION_V1 = "1"
MANIFEST_HASH_VERSION_V2 = "2"
MANIFEST_HASH_V2_DOMAIN = "CIPH_CAPABILITY_MANIFEST_V2"

# Imported at module scope so `target_mode()` is total; the semantics digest is resolved lazily
# inside compute_manifest_hash_v2 to avoid a policy_engine <-> target_identity import cycle.
from ciph.kernel.target_identity import (
    TARGET_MODE_TARGETLESS,
    TARGET_MODE_TARGET_BEARING,
)


REPLAY_POLICY_DOMAIN = "CIPH_REPLAY_POLICY_V1"


def replay_policy_digest(subject) -> "Optional[str]":
    """
    The IMMUTABLE binding for a capability's replay policy.

    `ReplaySemantics` is deliberately outside the frozen V1 manifest hash, so the manifest identity
    cannot carry it - and re-checking an identity does not pin a fact the identity excludes. Without
    this binding, an attempt executed while the capability declared UNSAFE could be granted retry
    authority later, once somebody edited the declaration to IDEMPOTENT and left the identity alone.
    That is retroactive authority broadening.

    The digest is computed from the DECLARATION (versioned domain + value), so a future policy with
    more parameters changes every bound digest automatically rather than silently re-using the old
    one. Accepts a manifest or a bare `ReplaySemantics`; returns None when there is nothing to bind.
    """
    semantics = getattr(subject, "replay_semantics", subject)
    value = getattr(semantics, "value", None)
    if value is None:
        return None
    return hashlib.sha256(f"{REPLAY_POLICY_DOMAIN}|{str(value).upper()}".encode("utf-8")).hexdigest()


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
    # Register item 0.15 / TARGET_IDENTITY_V1: a target-bearing capability declares which
    # canonicalizer defines its target's identity. There is no fallback - a capability that
    # declares none is refused rather than defaulted to a reference implementation.
    # TODO: include these in compute_manifest_hash() once the hash migration is planned;
    # until then changing a canonicalizer does not invalidate capability credit.
    target_canonicalizer_id: Optional[str] = None
    target_canonicalizer_version: Optional[str] = None
    # Which manifest hash algorithm identifies this capability. V1 by default so an
    # un-migrated manifest keeps the identity it has always had; migration to V2 is an
    # explicit act with its own lineage record.
    manifest_hash_version: str = MANIFEST_HASH_VERSION_V1
    # RETRY SAFETY (S3). The ONLY canonical source of "a repeat cannot duplicate an uncontrolled
    # effect". Declared by the capability, defaulted fail-closed, and deliberately NOT part of the
    # frozen V1 manifest hash - the same treatment `target_canonicalizer_id` gets - so capability
    # credit keeps the identity it has always had. `canonical_retry_safety` re-checks this against
    # the manifest identity the exact attempt's evidence attests, so a declaration can never be
    # borrowed by a different manifest.
    replay_semantics: ReplaySemantics = ReplaySemantics.UNSAFE

    def compute_manifest_hash(self) -> str:
        """
        MANIFEST_HASH_V1. **Frozen forever.** Its existing hashes keep their meaning and are never
        recomputed under new rules; existing capability credit keys off them.
        """
        canonical = f"{self.name}:{self.version}:{self.risk_tier.value}:{self.network_policy.value}:{self.reversibility.value}:{self.authorization.value}:{self.requires_red_team}:{self.timeout_seconds}"
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    def target_mode(self) -> str:
        """Explicit, never inferred from absence: a targetless capability says so."""
        return (
            TARGET_MODE_TARGET_BEARING if self.target_canonicalizer_id
            else TARGET_MODE_TARGETLESS
        )

    def identity(self):
        """
        This manifest's exact identity, as evidence will carry it.

        The governed path derives identity from the *resolved manifest object*, so a receipt
        records what actually executed rather than what a caller claimed would execute.

        **Version-faithful.** This never means "compute identity with whatever the newest
        algorithm is". A V1 manifest yields a V1 identity under the frozen V1 algorithm; a V2
        manifest yields a V2 identity. An unknown version raises rather than being upgraded by
        convenience, because silently promoting an identity would move historical evidence to
        a claim it never made.
        """
        from ciph.kernel.manifest_identity import ManifestIdentity
        version = str(self.manifest_hash_version)
        if version == MANIFEST_HASH_VERSION_V1:
            return ManifestIdentity(
                hash_version=int(MANIFEST_HASH_VERSION_V1),
                manifest_hash=self.compute_manifest_hash(),
            )
        if version == MANIFEST_HASH_VERSION_V2:
            return ManifestIdentity(
                hash_version=int(MANIFEST_HASH_VERSION_V2),
                manifest_hash=self.compute_manifest_hash_v2(),
            )
        raise ValueError(f"UNSUPPORTED_MANIFEST_HASH_VERSION: {version}")

    def compute_manifest_hash_v2(self) -> str:
        """
        MANIFEST_HASH_V2, a separate domain.

        Commits everything V1 committed to **plus target semantics**, because a target
        canonicalizer decides which resource the capability believes it is acting on - that is
        authorization semantics, not metadata. A target-bearing capability whose canonicalizer
        has no declared semantic contract is refused: adopting an undeclared meaning would make
        the manifest assert something nobody specified.
        """
        mode = self.target_mode()
        if mode == TARGET_MODE_TARGETLESS:
            canonicalizer_id = "NONE"
            canonicalizer_version = "NONE"
            semantics_digest = "NONE"
        else:
            from ciph.kernel.target_identity import canonicalizer_semantics_digest
            canonicalizer_id = self.target_canonicalizer_id
            canonicalizer_version = self.target_canonicalizer_version or ""
            semantics_digest = canonicalizer_semantics_digest(
                canonicalizer_id, canonicalizer_version
            )
            if semantics_digest is None:
                raise ValueError(
                    "CANONICALIZER_SEMANTICS_UNDECLARED: manifest identity V2 requires a declared "
                    f"semantic contract for {canonicalizer_id}@{canonicalizer_version}"
                )
        body = "|".join([
            MANIFEST_HASH_V2_DOMAIN,
            MANIFEST_HASH_VERSION_V2,
            str(self.name), str(self.version),
            self.risk_tier.value, self.network_policy.value,
            self.reversibility.value, self.authorization.value,
            str(self.requires_red_team), str(self.timeout_seconds),
            mode, canonicalizer_id,
            str(canonicalizer_version), str(semantics_digest),
        ])
        return hashlib.sha256(body.encode('utf-8')).hexdigest()

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
