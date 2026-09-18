"""
ciph.contracts.execution - Canonical Contracts for ExecutionReceipt, JobAttempt, and ExecutionToken.
Preserves ratified Ed25519/TrustRegistry cryptography and version 4.1 receipts.
"""

import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional, List, Tuple

from ciph.contracts.enums import NetworkPolicy, JobState, OutcomeCategory
from ciph.contracts.base import ContractValidationError, canonical_json
try:
    from ciph.workers.receipts import (
        ExecutionReceipt,
        compute_idempotency_key,
        generate_environment_fingerprint,
    )
except ImportError:
    pass

def __getattr__(name: str):
    if name in ("ExecutionReceipt", "compute_idempotency_key", "generate_environment_fingerprint"):
        import ciph.workers.receipts as _rcpt
        val = getattr(_rcpt, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
from ciph.kernel.crypto_identity import ExecutionToken


SUPPORTED_JOB_ATTEMPT_VERSIONS = {"1.0"}


@dataclass(frozen=True)
class JobAttempt:
    """
    Typed contract representing an active worker lease attempt on a queued job.
    Note: Atomicity remains an IPCJobQueue SQLite transaction invariant;
    JobAttempt models the immutable typed contract for worker execution.
    """
    job_id: str
    capability: str
    attempt_number: int
    max_retries: int
    worker_id: str
    leased_at: float
    lease_expires_at: float
    idempotency_key: str
    execution_token_hash: Optional[str] = None
    plan_id: Optional[str] = None
    step_id: Optional[str] = None
    schema_version: str = "1.0"

    def __post_init__(self):
        if self.schema_version not in SUPPORTED_JOB_ATTEMPT_VERSIONS:
            raise ContractValidationError(f"Unsupported JobAttempt schema_version: {self.schema_version}")

    def is_lease_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if lease heartbeat has lapsed."""
        now = current_time if current_time is not None else time.time()
        return now > self.lease_expires_at

    def compute_attempt_fingerprint(self) -> str:
        """Compute deterministic hash of the lease attempt."""
        payload = {
            "schema_version": self.schema_version,
            "job_id": self.job_id,
            "capability": self.capability,
            "attempt_number": self.attempt_number,
            "worker_id": self.worker_id,
            "idempotency_key": self.idempotency_key,
            "execution_token_hash": self.execution_token_hash,
            "plan_id": self.plan_id,
            "step_id": self.step_id,
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "job_id": self.job_id,
            "capability": self.capability,
            "attempt_number": self.attempt_number,
            "max_retries": self.max_retries,
            "worker_id": self.worker_id,
            "leased_at": self.leased_at,
            "lease_expires_at": self.lease_expires_at,
            "idempotency_key": self.idempotency_key,
            "execution_token_hash": self.execution_token_hash,
            "plan_id": self.plan_id,
            "step_id": self.step_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JobAttempt":
        d = dict(data)
        ver = d.get("schema_version", "1.0")
        if ver not in SUPPORTED_JOB_ATTEMPT_VERSIONS:
            raise ContractValidationError(f"Unsupported JobAttempt schema_version: {ver}")
        return cls(
            job_id=d["job_id"],
            capability=d["capability"],
            attempt_number=d["attempt_number"],
            max_retries=d["max_retries"],
            worker_id=d["worker_id"],
            leased_at=d["leased_at"],
            lease_expires_at=d["lease_expires_at"],
            idempotency_key=d["idempotency_key"],
            execution_token_hash=d.get("execution_token_hash"),
            plan_id=d.get("plan_id"),
            step_id=d.get("step_id"),
            schema_version=ver
        )
