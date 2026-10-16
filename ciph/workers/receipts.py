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
    EFFECT_CERTAINTY_CUTOVER_SCHEMA,
    EffectCertainty,
    schema_at_least,
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
    # Known schemas only. Version-aware comparison decides cutover semantics *after* a schema
    # is recognised; it never grants forward compatibility. A future 4.3 may carry an
    # authority-critical field this parser would silently ignore while applying 4.2 rules.
    KNOWN_RECEIPT_SCHEMAS = ("4.0", "1.0", "4.1", "4.2")
    CURRENT_RECEIPT_SCHEMA = "4.2"
    # Committed to the signature for schema >= 4.2. Absent means the receipt predates the
    # certainty contract, which is interpretable historically but never newly issuable.
    effect_certainty: Optional[str] = None

    def __post_init__(self):
        # 4.1 never carried certainty, so a receipt claiming it did is noncanonical rather than
        # a richer 4.1. Accepting it would blur two schema contracts into one.
        if str(self.schema_version) == "4.1" and self.effect_certainty:
            raise ContractValidationError("EFFECT_CERTAINTY_NOT_IN_SCHEMA_4_1")

        # A schema >= 4.2 receipt cannot be constructed without stating what happened to
        # reality. Without this, the field would be optional decoration rather than evidence.
        if schema_at_least(self.schema_version, EFFECT_CERTAINTY_CUTOVER_SCHEMA):
            if not self.effect_certainty:
                raise ContractValidationError(
                    "EFFECT_CERTAINTY_REQUIRED_AT_OR_AFTER_CUTOVER"
                )
            try:
                EffectCertainty(str(self.effect_certainty))
            except ValueError as error:
                raise ContractValidationError(
                    f"UNKNOWN_EFFECT_CERTAINTY: {self.effect_certainty}"
                ) from error

    @classmethod
    def issue(cls, effect_certainty, **fields):
        """
        The issuance path for new receipts: current schema only, certainty stated explicitly.

        Certainty must come from independent evidence that the declared effect occurred - not
        from the outcome. Deriving `EFFECT_CONFIRMED` from `SUCCESS` would recreate, one layer
        up, the exact bug the strict metric exists to prevent.

        There is deliberately no way to request an older schema here. Allowing a new execution
        to emit 4.1 would reopen the legacy downgrade path through schema selection rather than
        field omission, and the executor's conservative conclusion may legitimately be
        `EFFECT_UNKNOWN` - but it must be an explicit conclusion, never a constructor default.
        """
        if "schema_version" in fields:
            raise ContractValidationError("SCHEMA_VERSION_NOT_CALLER_SELECTABLE")
        if not effect_certainty:
            raise ContractValidationError("EFFECT_CERTAINTY_REQUIRED_FOR_ISSUANCE")
        fields["schema_version"] = cls.CURRENT_RECEIPT_SCHEMA
        # Accept either an EffectCertainty member or its string value. `str(member)` yields
        # "EffectCertainty.EFFECT_UNKNOWN" under enum semantics, so normalising here keeps the
        # issuance path honest for callers that pass the enum directly.
        fields["effect_certainty"] = str(getattr(effect_certainty, "value", effect_certainty))
        return cls(**fields)

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
        # Included only when present, so pre-cutover payloads keep byte-identical signatures.
        if self.effect_certainty:
            payload_data["effect_certainty"] = str(self.effect_certainty)
        return canonical_json(payload_data)

    # Governed provenance rides inside the existing `provenance` dict, which is already part of
    # the signature payload. A bare class attribute (no annotation) is not a dataclass field.
    GOVERNED_PROVENANCE_KEY = "governed_authorization"

    def has_governed_provenance(self) -> bool:
        """True when this receipt carries an explicit authorization lineage."""
        return bool((self.provenance or {}).get(self.GOVERNED_PROVENANCE_KEY))

    def governed_claims(self):
        """
        The authorization lineage this receipt claims, or None.

        None means *legacy*, explicitly: a receipt that predates permits. It never means
        "governed but the fields went missing", because a governed receipt is signed over its
        provenance block and cannot lose it without breaking its own signature.
        """
        block = (self.provenance or {}).get(self.GOVERNED_PROVENANCE_KEY)
        if not block:
            return None
        from ciph.kernel.authorization_provenance import GovernedReceiptClaims
        return GovernedReceiptClaims(
            authorization_provenance=block.get("authorization_provenance", ""),
            execution_permit_id=block.get("execution_permit_id", ""),
            execution_permit_digest=block.get("execution_permit_digest", ""),
            execution_attempt_id=block.get("execution_attempt_id", ""),
            authorization_epoch=block.get("authorization_epoch"),
        )

    # Observational metadata deliberately excluded from terminal identity. It stays in the
    # signed payload as authenticated evidence about where execution happened - it just must not
    # decide whether two receipts describe the same terminal execution, or recovery on a
    # different machine would raise false integrity incidents by design.
    TERMINAL_IDENTITY_EXCLUDED = (
        "environment_fingerprint",
        "receipt_id",
        "worker_id",
        "backtrace",
        "artifact_ref",
    )

    def terminal_identity_digest(self) -> str:
        """
        Do these receipts represent the same terminal execution fact?

        A different question from receipt integrity, which asks whether the exact signed bytes
        are authentic. Integrity stays byte-strict and immutable; terminal identity binds only
        the fields that define the fact.
        """
        claims = self.governed_claims()
        outcome_val = (
            self.outcome.value if hasattr(self.outcome, "value") else str(self.outcome)
        )
        return self.hash_payload({
            # Another hash with semantic meaning, so it gets its own namespace. Changing what
            # constitutes "the same terminal fact" must produce V2, never silently redefine V1.
            "_domain": "CIPH_TERMINAL_RECEIPT_IDENTITY_V1",
            "execution_attempt_id": claims.execution_attempt_id if claims else "",
            "execution_permit_id": claims.execution_permit_id if claims else "",
            "execution_permit_digest": claims.execution_permit_digest if claims else "",
            "capability": str(self.capability),
            "target": str(self.target or ""),
            "outcome": outcome_val,
            "exit_code": int(self.exit_code),
            "output_hash": str(self.output_hash),
            "results_digest": self.hash_payload(self.results),
            "error_class": str(self.error_class or ""),
            "execution_started_at_us": int(round(float(self.started_at) * 1_000_000)),
            "execution_finished_at_us": int(round(float(self.completed_at) * 1_000_000)),
        })

    def execution_facts(self):
        """
        What this receipt says happened: identity and timing, not authorization and not outcome.

        Timestamps convert from the receipt's float seconds to integer microseconds, which is the
        only time representation the permit domain uses.
        """
        from ciph.kernel.authorization_provenance import ExecutionFacts
        return ExecutionFacts(
            capability=self.capability,
            execution_started_at_us=int(round(float(self.started_at) * 1_000_000)),
            execution_finished_at_us=int(round(float(self.completed_at) * 1_000_000)),
            execution_identity=self.worker_id,
        )

    def attach_governed_claims(self, claims) -> "ExecutionReceipt":
        """
        Return a copy carrying explicit governed provenance.

        The claims are validated here, so an impossible combination - a governed lane with no
        permit reference, or a legacy lane citing one - is refused at construction rather than
        left for a verifier to notice later.
        """
        claims.validate_construction()
        block = {
            "authorization_provenance": claims.authorization_provenance,
            "execution_permit_id": claims.execution_permit_id,
            "execution_permit_digest": claims.execution_permit_digest,
            "execution_attempt_id": claims.execution_attempt_id,
            "authorization_epoch": claims.authorization_epoch,
        }
        data = asdict(self)
        data["provenance"] = {
            **(self.provenance or {}),
            self.GOVERNED_PROVENANCE_KEY: block,
        }
        data["outcome"] = self.outcome
        data["requested_network_policy"] = self.requested_network_policy
        return ExecutionReceipt(**data)

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
        elif ver == "4.2":
            d["schema_version"] = ver
        else:
            # Unknown future versions are refused, not interpreted under current rules.
            raise ContractValidationError(f"Unsupported ExecutionReceipt schema_version: '{ver}'")

        if 'outcome' in d and isinstance(d['outcome'], str):
            d['outcome'] = OutcomeCategory(d['outcome'])
        if 'requested_network_policy' in d and isinstance(d['requested_network_policy'], str):
            d['requested_network_policy'] = NetworkPolicy(d['requested_network_policy'])
        field_names = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in field_names}
        return cls(**filtered)
