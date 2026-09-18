"""
ciph.contracts.grants - First-Class ScopeGrant and AuthorizationGrant Contracts.
Formally defined, deeply immutable, and HMAC-signed.
"""

import time
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple
from ciph.contracts.enums import ScopeType, NetworkPolicy
from ciph.contracts.base import ContractValidationError, canonical_json, freeze_value


SUPPORTED_GRANT_SCHEMA_VERSIONS = {"1.0"}


@dataclass(frozen=True)
class ScopeGrant:
    """
    Explicit boundary grant defining permitted execution targets.
    Deeply immutable: target collections are frozen into immutable tuples.
    HMAC-signed by Kernel.
    """
    scope_id: str
    scope_type: ScopeType
    allowed_targets: Tuple[str, ...]
    denied_targets: Tuple[str, ...] = field(default_factory=tuple)
    network_policy_override: Optional[NetworkPolicy] = None
    valid_until: Optional[float] = None
    created_at: float = field(default_factory=time.time)
    schema_version: str = "1.0"
    signing_key_id: str = "kernel_primary"
    signature: str = ""

    def __init__(
        self,
        scope_id: str,
        scope_type: ScopeType,
        allowed_targets: Any,
        denied_targets: Any = (),
        network_policy_override: Optional[NetworkPolicy] = None,
        valid_until: Optional[float] = None,
        created_at: Optional[float] = None,
        schema_version: str = "1.0",
        signing_key_id: str = "kernel_primary",
        signature: str = ""
    ):
        if schema_version not in SUPPORTED_GRANT_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported ScopeGrant schema_version: {schema_version}")

        object.__setattr__(self, "scope_id", str(scope_id))
        st = scope_type if isinstance(scope_type, ScopeType) else ScopeType(scope_type)
        object.__setattr__(self, "scope_type", st)
        
        # Deep immutability: ensure targets are converted to immutable tuples
        at = tuple(str(x) for x in (allowed_targets or ()))
        dt = tuple(str(x) for x in (denied_targets or ()))
        object.__setattr__(self, "allowed_targets", at)
        object.__setattr__(self, "denied_targets", dt)

        npo = network_policy_override
        if npo is not None and not isinstance(npo, NetworkPolicy):
            npo = NetworkPolicy(npo)
        object.__setattr__(self, "network_policy_override", npo)
        object.__setattr__(self, "valid_until", float(valid_until) if valid_until is not None else None)
        object.__setattr__(self, "created_at", float(created_at) if created_at is not None else time.time())
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "signing_key_id", str(signing_key_id))
        object.__setattr__(self, "signature", str(signature))

    def compute_canonical_payload(self) -> bytes:
        """Deterministically encode all authority-relevant fields including schema_version."""
        payload_data = {
            "schema_version": self.schema_version,
            "scope_id": self.scope_id,
            "scope_type": self.scope_type.value,
            "allowed_targets": sorted(self.allowed_targets),
            "denied_targets": sorted(self.denied_targets),
            "network_policy_override": self.network_policy_override.value if self.network_policy_override else None,
            "valid_until": self.valid_until,
            "created_at": self.created_at,
            "signing_key_id": self.signing_key_id,
        }
        return canonical_json(payload_data).encode("utf-8")

    def compute_signature_payload(self) -> str:
        """String representation of canonical payload for compatibility."""
        return self.compute_canonical_payload().decode("utf-8")

    def sign(self, secret_key: bytes, signing_key_id: Optional[str] = None) -> "ScopeGrant":
        """Produce a new ScopeGrant with authenticated Kernel HMAC signature."""
        key_id = signing_key_id or self.signing_key_id
        # Build new grant with signing_key_id to compute payload
        unsigned = ScopeGrant(
            scope_id=self.scope_id,
            scope_type=self.scope_type,
            allowed_targets=self.allowed_targets,
            denied_targets=self.denied_targets,
            network_policy_override=self.network_policy_override,
            valid_until=self.valid_until,
            created_at=self.created_at,
            schema_version=self.schema_version,
            signing_key_id=key_id,
            signature=""
        )
        sig = hmac.new(secret_key, unsigned.compute_canonical_payload(), hashlib.sha256).hexdigest()
        return ScopeGrant(
            scope_id=self.scope_id,
            scope_type=self.scope_type,
            allowed_targets=self.allowed_targets,
            denied_targets=self.denied_targets,
            network_policy_override=self.network_policy_override,
            valid_until=self.valid_until,
            created_at=self.created_at,
            schema_version=self.schema_version,
            signing_key_id=key_id,
            signature=sig
        )

    def verify_signature(self, secret_key: bytes) -> bool:
        """Verify HMAC signature over all canonical grant fields."""
        if not self.signature or not secret_key:
            return False
        unsigned = ScopeGrant(
            scope_id=self.scope_id,
            scope_type=self.scope_type,
            allowed_targets=self.allowed_targets,
            denied_targets=self.denied_targets,
            network_policy_override=self.network_policy_override,
            valid_until=self.valid_until,
            created_at=self.created_at,
            schema_version=self.schema_version,
            signing_key_id=self.signing_key_id,
            signature=""
        )
        expected_sig = hmac.new(secret_key, unsigned.compute_canonical_payload(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)

    def is_target_permitted(self, target: Optional[str], current_time: Optional[float] = None) -> bool:
        """Check if target string is authorized under this scope grant with strict deny precedence."""
        if self.is_expired(current_time):
            return False
        if not target:
            if self.scope_type == ScopeType.TARGET_DOMAIN:
                return False
            if self.allowed_targets and "*" not in self.allowed_targets:
                return False
            return True
        # Explicit deny always takes precedence
        for denied in self.denied_targets:
            if denied == target or (denied.startswith("*.") and target.endswith(denied[1:])):
                return False
        # Wildcard allow
        if "*" in self.allowed_targets:
            return True
        # Specific allow list
        for allowed in self.allowed_targets:
            if allowed == target or (allowed.startswith("*.") and target.endswith(allowed[1:])):
                return True
        return False

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if scope grant has passed its validity window."""
        if self.valid_until is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now > self.valid_until

    def compute_scope_hash(self) -> str:
        """Compute deterministic SHA-256 fingerprint of the scope grant."""
        return hashlib.sha256(self.compute_canonical_payload()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scope_id": self.scope_id,
            "scope_type": self.scope_type.value,
            "allowed_targets": list(self.allowed_targets),
            "denied_targets": list(self.denied_targets),
            "network_policy_override": self.network_policy_override.value if self.network_policy_override else None,
            "valid_until": self.valid_until,
            "created_at": self.created_at,
            "signing_key_id": self.signing_key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScopeGrant":
        d = dict(data)
        ver = d.get("schema_version", "1.0")
        if ver not in SUPPORTED_GRANT_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported ScopeGrant schema_version: {ver}")
        st = ScopeType(d["scope_type"]) if isinstance(d.get("scope_type"), str) else d.get("scope_type")
        npo = d.get("network_policy_override")
        if npo and isinstance(npo, str):
            npo = NetworkPolicy(npo)
        return cls(
            scope_id=d["scope_id"],
            scope_type=st,
            allowed_targets=d.get("allowed_targets", ()),
            denied_targets=d.get("denied_targets", ()),
            network_policy_override=npo,
            valid_until=d.get("valid_until"),
            created_at=d.get("created_at"),
            schema_version=ver,
            signing_key_id=d.get("signing_key_id", "kernel_primary"),
            signature=d.get("signature", "")
        )


@dataclass(frozen=True)
class AuthorizationGrant:
    """
    First-class immutable authorization object binding an authorized DAG step to capability,
    parameters hash, and scope grant. Strictly HMAC-signed by Kernel.
    """
    grant_id: str
    plan_hash: str
    step_id: str
    capability: str
    params_hash: str
    scope_grant_id: str
    max_budget: Dict[str, float] = field(default_factory=dict)
    expires_at: float = 0.0
    signature: str = ""
    signing_key_id: str = "kernel_primary"
    created_at: float = field(default_factory=time.time)
    schema_version: str = "1.0"

    def __init__(
        self,
        grant_id: str,
        plan_hash: str,
        step_id: str,
        capability: str,
        params_hash: str,
        scope_grant_id: str,
        max_budget: Optional[Dict[str, float]] = None,
        expires_at: float = 0.0,
        signature: str = "",
        signing_key_id: str = "kernel_primary",
        created_at: Optional[float] = None,
        schema_version: str = "1.0"
    ):
        if schema_version not in SUPPORTED_GRANT_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported AuthorizationGrant schema_version: {schema_version}")

        object.__setattr__(self, "grant_id", str(grant_id))
        object.__setattr__(self, "plan_hash", str(plan_hash))
        object.__setattr__(self, "step_id", str(step_id))
        object.__setattr__(self, "capability", str(capability))
        object.__setattr__(self, "params_hash", str(params_hash))
        object.__setattr__(self, "scope_grant_id", str(scope_grant_id))
        # Deep defensive copy of budget dict into immutable mapping
        b = dict(max_budget) if max_budget else {}
        object.__setattr__(self, "max_budget", freeze_value({str(k): float(v) for k, v in b.items()}))
        object.__setattr__(self, "expires_at", float(expires_at))
        object.__setattr__(self, "signature", str(signature))
        object.__setattr__(self, "signing_key_id", str(signing_key_id))
        object.__setattr__(self, "created_at", float(created_at) if created_at is not None else time.time())
        object.__setattr__(self, "schema_version", schema_version)

    def compute_canonical_payload(self) -> bytes:
        """Deterministically encode all binding fields including schema_version."""
        payload_data = {
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "plan_hash": self.plan_hash,
            "step_id": self.step_id,
            "capability": self.capability,
            "params_hash": self.params_hash,
            "scope_grant_id": self.scope_grant_id,
            "max_budget": sorted(self.max_budget.items()),
            "expires_at": self.expires_at,
            "signing_key_id": self.signing_key_id,
            "created_at": self.created_at,
        }
        return canonical_json(payload_data).encode("utf-8")

    def compute_signature_payload(self) -> str:
        """String representation of canonical payload for compatibility."""
        return self.compute_canonical_payload().decode("utf-8")

    def sign(self, secret_key: bytes, signing_key_id: Optional[str] = None) -> "AuthorizationGrant":
        """Compute HMAC-SHA256 signature and return authenticated grant."""
        key_id = signing_key_id or self.signing_key_id
        unsigned = AuthorizationGrant(
            grant_id=self.grant_id,
            plan_hash=self.plan_hash,
            step_id=self.step_id,
            capability=self.capability,
            params_hash=self.params_hash,
            scope_grant_id=self.scope_grant_id,
            max_budget=self.max_budget,
            expires_at=self.expires_at,
            signature="",
            signing_key_id=key_id,
            created_at=self.created_at,
            schema_version=self.schema_version
        )
        sig = hmac.new(secret_key, unsigned.compute_canonical_payload(), hashlib.sha256).hexdigest()
        return AuthorizationGrant(
            grant_id=self.grant_id,
            plan_hash=self.plan_hash,
            step_id=self.step_id,
            capability=self.capability,
            params_hash=self.params_hash,
            scope_grant_id=self.scope_grant_id,
            max_budget=self.max_budget,
            expires_at=self.expires_at,
            signature=sig,
            signing_key_id=key_id,
            created_at=self.created_at,
            schema_version=self.schema_version
        )

    def verify_signature(self, secret_key: bytes) -> bool:
        """Cryptographically verify that signature matches grant canonical payload."""
        if not self.signature or not secret_key:
            return False
        unsigned = AuthorizationGrant(
            grant_id=self.grant_id,
            plan_hash=self.plan_hash,
            step_id=self.step_id,
            capability=self.capability,
            params_hash=self.params_hash,
            scope_grant_id=self.scope_grant_id,
            max_budget=self.max_budget,
            expires_at=self.expires_at,
            signature="",
            signing_key_id=self.signing_key_id,
            created_at=self.created_at,
            schema_version=self.schema_version
        )
        expected_sig = hmac.new(secret_key, unsigned.compute_canonical_payload(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)

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
        """Verify that this grant strictly covers the execution context and has not expired."""
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
        if scope_grant_id and self.scope_grant_id and self.scope_grant_id != "NONE":
            if self.scope_grant_id != scope_grant_id:
                return False
        if required_budget and self.max_budget:
            for resource, amount in required_budget.items():
                if resource in self.max_budget and amount > self.max_budget[resource]:
                    return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "plan_hash": self.plan_hash,
            "step_id": self.step_id,
            "capability": self.capability,
            "params_hash": self.params_hash,
            "scope_grant_id": self.scope_grant_id,
            "max_budget": dict(self.max_budget),
            "expires_at": self.expires_at,
            "signature": self.signature,
            "signing_key_id": self.signing_key_id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizationGrant":
        d = dict(data)
        ver = d.get("schema_version", "1.0")
        if ver not in SUPPORTED_GRANT_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported AuthorizationGrant schema_version: {ver}")
        return cls(
            grant_id=d["grant_id"],
            plan_hash=d["plan_hash"],
            step_id=d["step_id"],
            capability=d["capability"],
            params_hash=d["params_hash"],
            scope_grant_id=d["scope_grant_id"],
            max_budget=d.get("max_budget"),
            expires_at=d.get("expires_at", 0.0),
            signature=d.get("signature", ""),
            signing_key_id=d.get("signing_key_id", "kernel_primary"),
            created_at=d.get("created_at"),
            schema_version=ver
        )
