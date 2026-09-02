"""
ciph.capabilities.base - Abstract Base Capability Interface.
Every capability is a decoupled limb exposing a uniform execution contract.
"""

import time
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from ciph.kernel.policy_engine import CapabilityManifest
from ciph.kernel.network_sandbox import enforce_network_policy, NetworkPolicyViolation
from ciph.workers.receipts import ExecutionReceipt, OutcomeCategory


class BaseCapability(ABC):
    """Abstract Base Class for all CIPH 4.0 Capabilities."""

    @property
    @abstractmethod
    def manifest(self) -> CapabilityManifest:
        """Return the static, immutable capability manifest."""
        pass

    @abstractmethod
    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute core logic and return raw result dictionary."""
        pass

    def execute(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> ExecutionReceipt:
        """Wrap execution in canonical ExecutionReceipt envelope with timing and hashing."""
        context = context or {}
        job_id = context.get("job_id", f"JOB-{uuid.uuid4().hex[:8].upper()}")
        idempotency_key = context.get("idempotency_key", f"idemp_{uuid.uuid4().hex[:8]}")
        target = params.get("target") or params.get("domain") or params.get("symbol") or None
        
        input_hash = ExecutionReceipt.hash_payload(params)
        started_at = time.time()
        
        try:
            with enforce_network_policy(self.manifest.network_policy):
                raw_results = self.run(params, context)
            completed_at = time.time()
            output_hash = ExecutionReceipt.hash_payload(raw_results)
            
            exit_code = 0 if raw_results.get("success", True) is not False else 1
            outcome = OutcomeCategory.SUCCESS if exit_code == 0 else OutcomeCategory.EXECUTION_ERROR
            error_msg = raw_results.get("error") if exit_code != 0 else None
            
            return ExecutionReceipt(
                receipt_id=f"rcpt_{uuid.uuid4().hex[:12]}",
                job_id=job_id,
                capability=self.manifest.name,
                target=str(target) if target else None,
                started_at=started_at,
                completed_at=completed_at,
                input_hash=input_hash,
                output_hash=output_hash,
                exit_code=exit_code,
                outcome=outcome,
                results=raw_results,
                side_effects=raw_results.get("side_effects", []),
                idempotency_key=idempotency_key,
                attempt_number=context.get("attempt_number", 1),
                requested_network_policy=self.manifest.network_policy,
                actual_transport_used=context.get("actual_transport_used", self.manifest.network_policy.value),
                error_message=error_msg,
                provenance=context.get("provenance", {})
            )
        except NetworkPolicyViolation as e:
            completed_at = time.time()
            error_msg = str(e)
            output_hash = ExecutionReceipt.hash_payload({"error": error_msg})
            
            return ExecutionReceipt(
                receipt_id=f"rcpt_{uuid.uuid4().hex[:12]}",
                job_id=job_id,
                capability=self.manifest.name,
                target=str(target) if target else None,
                started_at=started_at,
                completed_at=completed_at,
                input_hash=input_hash,
                output_hash=output_hash,
                exit_code=1,
                outcome=OutcomeCategory.SANDBOX_VIOLATION,
                results={"error": error_msg},
                side_effects=[],
                idempotency_key=idempotency_key,
                attempt_number=context.get("attempt_number", 1),
                requested_network_policy=self.manifest.network_policy,
                actual_transport_used="NETWORK_SANDBOX_BLOCKED",
                error_message=error_msg,
                provenance=context.get("provenance", {})
            )
        except Exception as e:
            completed_at = time.time()
            error_msg = str(e)
            output_hash = ExecutionReceipt.hash_payload({"error": error_msg})
            
            return ExecutionReceipt(
                receipt_id=f"rcpt_{uuid.uuid4().hex[:12]}",
                job_id=job_id,
                capability=self.manifest.name,
                target=str(target) if target else None,
                started_at=started_at,
                completed_at=completed_at,
                input_hash=input_hash,
                output_hash=output_hash,
                exit_code=1,
                outcome=OutcomeCategory.EXECUTION_ERROR,
                results={"error": error_msg},
                side_effects=[],
                idempotency_key=idempotency_key,
                attempt_number=context.get("attempt_number", 1),
                requested_network_policy=self.manifest.network_policy,
                actual_transport_used=context.get("actual_transport_used", "FAILED"),
                error_message=error_msg,
                provenance=context.get("provenance", {})
            )
