"""
ciph.workers.receipts - Canonical ExecutionReceipt and 11-State Job Lifecycle.
"""

import time
import json
import hashlib
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from ciph.kernel.policy_engine import NetworkPolicy


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
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
    POLICY_BLOCKED     = "POLICY_BLOCKED"
    TIMEOUT            = "TIMEOUT"
    EXECUTION_ERROR    = "EXECUTION_ERROR"
    AUTH_REQUIRED      = "AUTH_REQUIRED"


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
    error_message: Optional[str] = None      # Structured error detail if failed
    provenance: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "4.0"

    @staticmethod
    def hash_payload(data: Any) -> str:
        """Deterministically hash any payload or dictionary."""
        try:
            canonical_str = json.dumps(data, sort_keys=True, default=str)
        except Exception:
            canonical_str = str(data)
        return hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()

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
