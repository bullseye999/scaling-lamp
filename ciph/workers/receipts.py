import time
import os
import sys
import json
import hmac
import hashlib
import platform
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple
from ciph.contracts.enums import NetworkPolicy


def compute_idempotency_key(plan_id: str, step_id: str, params_hash: str) -> str:
    """Derive deterministic idempotency key for an action step."""
    seed = f"{plan_id}:{step_id}:{params_hash}"
    return hashlib.sha256(seed.encode('utf-8')).hexdigest()


def get_host_fingerprint_prefix() -> str:
    """Deterministic 8-char hex host identifier based on OS, release, Python version and CIPH_ENV."""
    host_seed = f"{platform.system()}:{platform.release()}:{sys.version}:{os.environ.get('CIPH_ENV', 'production')}"
    return hashlib.sha256(host_seed.encode('utf-8')).hexdigest()[:8]


def generate_environment_fingerprint() -> str:
    """Bind measurements to OS, full Python version and implementation source.

    Host prefix (first 8 chars) binds strictly to OS, release, Python version and CIPH_ENV.
    Source suffix (next 8 chars) binds to the package source.
    """
    from pathlib import Path
    host_prefix = get_host_fingerprint_prefix()

    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for path in sorted(root.rglob('*.py')):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    source_suffix = digest.hexdigest()[:8]
    return f"{host_prefix}{source_suffix}"


from ciph.contracts.enums import (
    JobState,
    ProjectionState,
    ExecutionOutcome,
    EvidenceMode,
    EpistemicDecision,
    OutcomeCategory,
)
from ciph.contracts.base import ContractValidationError


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str                          # e.g., "rcpt_comp_a8f93b12"
    job_id: str                              # e.g., "JOB-SEC-09A1"
    capability: str                          # e.g., "cybersecurity.subdomain_scan"
    target: Optional[str]                    # e.g., "api.crypto.com" or None
    started_at: float
    completed_at: float
    input_hash: str                          # SHA-256 canonical hash of input params
    output_hash: str                         # SHA-256 canonical hash of output payload
    exit_code: int                           # 0 = clean exit, non-zero = error
    outcome: OutcomeCategory                 # Semantic outcome category
    results: Dict[str, Any]                  # Structured verified findings
    side_effects: List[str]                  # Modified files, open sockets, spawned processes
    idempotency_key: str                     # Deduplication token
    attempt_number: int                      # Attempt count
    requested_network_policy: NetworkPolicy
    actual_transport_used: str               # "TOR_SOCKS5H", "LOCAL_SOCKET", "CLEARNET_DIRECT"
    worker_id: str = "worker_local"          # Authenticated executing daemon
    worker_signature: Optional[str] = None   # Ed25519 or HMAC signature
    worker_key_id: Optional[str] = "worker_primary" # Key ID registered in TrustRegistry
    artifact_ref: Optional[str] = None       # Pointer to large payload blob (>64KB)
    environment_fingerprint: str = field(default_factory=generate_environment_fingerprint)
    error_class: Optional[str] = None        # Exception name / failure category
    backtrace: Optional[str] = None          # Truncated stacktrace if failed
    error_message: Optional[str] = None      # Structured error detail if failed
    provenance: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "4.1"

    @staticmethod
    def hash_payload(data: Any) -> str:
        """Deterministically hash any payload or dictionary."""
        from ciph.contracts.base import canonical_json
        return hashlib.sha256(canonical_json(data).encode('utf-8')).hexdigest()

    def compute_signature_payload(self) -> str:
        """
        Generate canonical deterministic payload for cryptographic receipt signing.
        Binds target, capability, outcomes, and all authority-relevant receipt fields.
        """
        from ciph.contracts.base import canonical_json
        if not isinstance(self.side_effects, list) or not all(isinstance(x, str) for x in self.side_effects):
            raise ValueError("INVALID_SIDE_EFFECTS: expected a list of strings")
        outcome_val = self.outcome.value if hasattr(self.outcome, "value") else str(self.outcome)
        policy_val = (
            self.requested_network_policy.value
            if hasattr(self.requested_network_policy, "value")
            else str(self.requested_network_policy)
        )
        payload_data = {
            "schema_version": str(self.schema_version),
            "receipt_id": str(self.receipt_id),
            "job_id": str(self.job_id),
            "capability": str(self.capability),
            "target": str(self.target or ""),
            "worker_id": str(self.worker_id),
            "worker_key_id": str(getattr(self, "worker_key_id", None) or self.worker_id),
            "input_hash": str(self.input_hash),
            "output_hash": str(self.output_hash),
            "exit_code": int(self.exit_code),
            "outcome": outcome_val,
            "requested_network_policy": policy_val,
            "actual_transport_used": str(self.actual_transport_used),
            "idempotency_key": str(self.idempotency_key),
            "attempt_number": int(self.attempt_number),
            "environment_fingerprint": str(self.environment_fingerprint),
            "side_effects": sorted(self.side_effects),
            "error_class": str(self.error_class or ""),
            "error_message": str(self.error_message or ""),
            "backtrace": str(self.backtrace or ""),
            "artifact_ref": str(self.artifact_ref or ""),
            "provenance": canonical_json(self.provenance or {}),
            "started_at": float(self.started_at),
            "completed_at": float(self.completed_at),
        }
        return canonical_json(payload_data)

    def sign(self, secret_key: bytes, worker_key_id: Optional[str] = None) -> "ExecutionReceipt":
        """Produce an Ed25519-signed or HMAC-signed copy of this ExecutionReceipt."""
        key_id = worker_key_id or getattr(self, "worker_key_id", None) or "worker_primary"

        # Apply worker_key_id to receipt BEFORE computing signature payload so key_id is bound
        d = asdict(self)
        d['worker_key_id'] = key_id
        d['outcome'] = self.outcome
        d['requested_network_policy'] = self.requested_network_policy
        receipt_to_sign = ExecutionReceipt(**d)

        payload = receipt_to_sign.compute_signature_payload().encode('utf-8')

        sig = None
        if len(secret_key) == 32:
            try:
                from ciph.kernel.crypto_identity import Ed25519KeyManager
                sig = Ed25519KeyManager.sign(secret_key, payload)
            except Exception:
                sig = None
        if sig is None:
            sig = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()

        # Reconstruct with signature and bound key_id
        d['worker_signature'] = sig
        return ExecutionReceipt(**d)

    def verify(
        self,
        trust_registry: Any,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str]:
        """
        Verify execution receipt using TrustRegistry and verify output payload hash integrity.
        """
        if not isinstance(self.side_effects, list) or not all(isinstance(x, str) for x in self.side_effects):
            return False, "INVALID_SIDE_EFFECTS"
        if not self.worker_signature:
            return False, "MISSING_WORKER_SIGNATURE"

        # Ed25519 signatures in TrustRegistry are strictly 64 bytes (128 hex characters)
        if len(self.worker_signature) != 128:
            return False, "KEY_NOT_FOUND: Not an Ed25519 signature format"

        computed_output_hash = self.hash_payload(self.results)
        if not hmac.compare_digest(self.output_hash, computed_output_hash):
            return False, f"OUTPUT_HASH_MISMATCH: expected {self.output_hash}, got {computed_output_hash}"

        payload = self.compute_signature_payload().encode('utf-8')
        
        # Check against future timestamps during live evaluation
        if current_time is not None and self.completed_at and self.completed_at > current_time + 5.0:
            return False, f"FUTURE_TIMESTAMP: completed_at={self.completed_at} > current_time={current_time}"

        # Prevent retirement backdating:
        # At ingress, current_time is provided and used as the evaluation timestamp.
        # A live receipt cannot use a key that is retired at evaluation time by backdating completed_at.
        signed_time = current_time if current_time is not None else (self.completed_at or time.time())
        key_id = getattr(self, "worker_key_id", None) or self.worker_id

        # Enforce WORKER role constraint: only WORKER keys may sign ExecutionReceipts
        key_rec = trust_registry.get_key(key_id)
        if key_rec is not None:
            role = getattr(key_rec.get("role"), "value", key_rec.get("role"))
            if str(role).upper() != "WORKER":
                return False, f"ROLE_MISMATCH: ExecutionReceipt signer '{key_id}' has role '{role}', expected 'WORKER'"

        # 1. Try key_id directly
        valid, reason = trust_registry.verify_signature_at_time(key_id, payload, self.worker_signature, signed_time)
        if valid:
            ver_rec = trust_registry.get_key(key_id)
            if ver_rec:
                role = getattr(ver_rec.get("role"), "value", ver_rec.get("role"))
                if str(role).upper() != "WORKER":
                    return False, f"ROLE_MISMATCH: ExecutionReceipt signer '{key_id}' has role '{role}', expected 'WORKER'"
            return True, "VALID"
        if not reason.startswith("KEY_NOT_FOUND"):
            return False, reason

        # 2. Try fallbacks (worker_primary, worker_local) only if specific instance ID wasn't separately registered
        for fallback_id in ["worker_primary", "worker_local"]:
            if fallback_id != key_id:
                fallback_rec = trust_registry.get_key(fallback_id)
                if not fallback_rec:
                    continue
                fb_role = getattr(fallback_rec.get("role"), "value", fallback_rec.get("role"))
                if str(fb_role).upper() != "WORKER":
                    continue
                v, r = trust_registry.verify_signature_at_time(fallback_id, payload, self.worker_signature, signed_time)
                if v:
                    return True, "VALID"
                elif not r.startswith("KEY_NOT_FOUND"):
                    return False, r

        return False, reason

    def verify_signature(
        self,
        secret_key: Optional[bytes] = None,
        trust_registry: Optional[Any] = None,
        current_time: Optional[float] = None
    ) -> bool:
        """
        Verify the cryptographic signature and payload integrity of this receipt.
        When trust_registry is provided, it is the sole authority for registered keys (zero fallback).
        """
        if not isinstance(self.side_effects, list) or not all(isinstance(x, str) for x in self.side_effects):
            return False
        if not self.worker_signature:
            return False

        computed_output_hash = self.hash_payload(self.results)
        if not hmac.compare_digest(self.output_hash, computed_output_hash):
            return False

        payload = self.compute_signature_payload().encode('utf-8')

        # 1. Verify via TrustRegistry if provided (sole authority, NO fallback for registered keys)
        if trust_registry is not None:
            valid, reason = self.verify(trust_registry, current_time=current_time)
            if valid:
                return True
            # If the key is known to TrustRegistry, any failure is definitive: zero fallback permitted.
            if not reason.startswith("KEY_NOT_FOUND"):
                return False

        # 2. Legacy symmetric HMAC fallback only when key is NOT registered in TrustRegistry
        if secret_key is not None:
            if len(secret_key) == 32:
                try:
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    from ciph.kernel.crypto_identity import Ed25519KeyManager
                    try:
                        priv = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)
                        pub_bytes = priv.public_key().public_bytes_raw()
                        if Ed25519KeyManager.verify(pub_bytes, payload, self.worker_signature):
                            return True
                    except Exception:
                        pass
                    if Ed25519KeyManager.verify(secret_key, payload, self.worker_signature):
                        return True
                except Exception:
                    pass

            try:
                expected_sig = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
                if hmac.compare_digest(self.worker_signature, expected_sig):
                    return True
            except Exception:
                pass

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize receipt to dictionary."""
        d = asdict(self)
        d['outcome'] = self.outcome.value
        d['requested_network_policy'] = self.requested_network_policy.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionReceipt":
        """Reconstitute receipt from dictionary with version validation and legacy migration."""
        d = dict(data)
        ver = str(d.get("schema_version", "4.0"))
        # Recognized versions: 4.1 (current), 4.0 / 1.0 (legacy migrated to 4.1)
        if ver in ("4.0", "1.0"):
            d["schema_version"] = "4.1"
        elif ver == "4.1":
            d["schema_version"] = "4.1"
        else:
            raise ContractValidationError(f"Unsupported ExecutionReceipt schema_version: '{ver}'")

        if 'outcome' in d and isinstance(d['outcome'], str):
            d['outcome'] = OutcomeCategory(d['outcome'])
        if 'requested_network_policy' in d and isinstance(d['requested_network_policy'], str):
            d['requested_network_policy'] = NetworkPolicy(d['requested_network_policy'])
        field_names = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in field_names}
        return cls(**filtered)
