import time
import os
import sys
import json
import hmac
import hashlib
import platform
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from ciph.kernel.policy_engine import NetworkPolicy


def compute_idempotency_key(plan_id: str, step_id: str, params_hash: str) -> str:
    """Derive deterministic idempotency key for an action step."""
    seed = f"{plan_id}:{step_id}:{params_hash}"
    return hashlib.sha256(seed.encode('utf-8')).hexdigest()


def generate_environment_fingerprint() -> str:
    """Generate deterministic environment fingerprint for reproducibility audits."""
    raw = f"{platform.system()}:{platform.release()}:{sys.version_info.major}.{sys.version_info.minor}:{os.environ.get('CIPH_ENV', 'production')}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]


class JobState(str, Enum):
    QUEUED             = "QUEUED"
    AWAITING_AUTHORIZE = "AWAITING_AUTHORIZE"
    AUTHORIZED         = "AUTHORIZED"
    LEASED             = "LEASED"
    EXECUTING          = "EXECUTING"
    RETRYING           = "RETRYING"
    SUCCEEDED          = "SUCCEEDED"
    FAILED             = "FAILED"
    TIMED_OUT          = "TIMED_OUT"
    QUARANTINED        = "QUARANTINED"
    CANCELLED          = "CANCELLED"


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
    worker_signature: Optional[str] = None   # HMAC-SHA256 signature
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
        try:
            canonical_str = json.dumps(data, sort_keys=True, default=str)
        except Exception:
            canonical_str = str(data)
        return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

    def compute_signature_payload(self) -> str:
        """Generate canonical string for cryptographic receipt signing."""
        side_effects_str = json.dumps(self.side_effects, sort_keys=True)
        return f"{self.receipt_id}:{self.job_id}:{self.capability}:{self.worker_id}:{self.input_hash}:{self.output_hash}:{self.exit_code}:{self.outcome.value}:{self.actual_transport_used}:{self.environment_fingerprint}:{side_effects_str}:{self.started_at}:{self.completed_at}"

    def sign(self, secret_key: bytes) -> "ExecutionReceipt":
        """Produce an HMAC-signed copy of this ExecutionReceipt."""
        payload = self.compute_signature_payload().encode('utf-8')
        sig = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
        # Reconstruct with signature
        d = asdict(self)
        d['worker_signature'] = sig
        d['outcome'] = self.outcome
        d['requested_network_policy'] = self.requested_network_policy
        return ExecutionReceipt(**d)

    def verify_signature(self, secret_key: bytes) -> bool:
        """Verify the cryptographic HMAC signature and payload integrity of this receipt."""
        if not self.worker_signature:
            return False
        
        # 1. Recompute and verify that output_hash matches current results
        computed_output_hash = self.hash_payload(self.results)
        if not hmac.compare_digest(self.output_hash, computed_output_hash):
            return False

        # 2. Verify cryptographic HMAC signature
        payload = self.compute_signature_payload().encode('utf-8')
        expected_sig = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.worker_signature, expected_sig)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize receipt to dictionary."""
        d = asdict(self)
        d['outcome'] = self.outcome.value
        d['requested_network_policy'] = self.requested_network_policy.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionReceipt":
        """Reconstitute receipt from dictionary."""
        d = dict(data)
        if 'outcome' in d and isinstance(d['outcome'], str):
            d['outcome'] = OutcomeCategory(d['outcome'])
        if 'requested_network_policy' in d and isinstance(d['requested_network_policy'], str):
            d['requested_network_policy'] = NetworkPolicy(d['requested_network_policy'])
        return cls(**d)
