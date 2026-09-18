"""
ciph.contracts.evolution - Canonical Versioned Contracts for Evidence-Driven Self-Evolution (Phase 8).
Enforces strongly-typed immutable contracts across gap discovery, evaluation authorization,
deployment consent, and execution receipts. All grants require Ed25519 signatures from active KeyRole.OPERATOR identities.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import time
import math
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from ciph.contracts.base import (
    ContractValidationError,
    FrozenDict,
    VersionedContract,
    canonical_json,
    freeze_value,
    _unfreeze,
)
from ciph.contracts.enums import RiskTier
from ciph.kernel.crypto_identity import Ed25519KeyManager, KeyRole, KeyStatus, TrustRegistry


class GapCategory(str, Enum):
    DEFECT = "DEFECT"
    MISSING_TELEMETRY = "MISSING_TELEMETRY"
    MISSING_BEHAVIOR = "MISSING_BEHAVIOR"
    OPERATIONAL_INEFFICIENCY = "OPERATIONAL_INEFFICIENCY"


class DeploymentStage(str, Enum):
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    PRODUCTION = "PRODUCTION"


SUPPORTED_EVOLUTION_SCHEMA_VERSIONS = {"1.0"}


@dataclass(frozen=True)
class EngineeringGapCandidate(VersionedContract):
    """
    Evidence-backed engineering gap.
    Must demonstrate a repeatable operational or defect gap supported by distinct
    execution receipts, quantifiable impact, and testable improvement criterion.
    """
    gap_id: str
    category: GapCategory
    target_capability: str
    affected_revision: str
    reproducible_conditions: FrozenDict
    failure_evidence_hashes: Tuple[str, ...]
    measured_impact: FrozenDict
    testable_improvement_criterion: str
    risk_tier: RiskTier
    proposed_owner: str
    created_at: float = field(default_factory=time.time)
    source_question_ids: Tuple[str, ...] = ()
    schema_version: str = "1.0"

    def __init__(
        self,
        gap_id: str,
        category: Union[GapCategory, str],
        target_capability: str,
        affected_revision: str,
        reproducible_conditions: Any,
        failure_evidence_hashes: Sequence[str],
        measured_impact: Any,
        testable_improvement_criterion: str,
        risk_tier: Union[RiskTier, str],
        proposed_owner: str,
        created_at: Optional[float] = None,
        schema_version: str = "1.0",
        source_question_ids: Sequence[str] = (),
    ):
        if schema_version not in SUPPORTED_EVOLUTION_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported schema_version: {schema_version}")

        if not gap_id or not isinstance(gap_id, str):
            raise ContractValidationError("gap_id must be a non-empty string")
        if not target_capability or not isinstance(target_capability, str):
            raise ContractValidationError("target_capability must be a non-empty string")
        if not affected_revision or not isinstance(affected_revision, str):
            raise ContractValidationError("affected_revision must be a non-empty string")
        if not testable_improvement_criterion or not isinstance(testable_improvement_criterion, str):
            raise ContractValidationError("testable_improvement_criterion must be a non-empty string")
        if not proposed_owner or not isinstance(proposed_owner, str):
            raise ContractValidationError("proposed_owner must be a non-empty string")

        cat = category if isinstance(category, GapCategory) else GapCategory(category)
        rt = risk_tier if isinstance(risk_tier, RiskTier) else RiskTier(risk_tier)

        ev_hashes = tuple(str(h) for h in failure_evidence_hashes)
        if not ev_hashes:
            raise ContractValidationError("failure_evidence_hashes must contain at least one receipt hash")
        if any(not re.fullmatch(r"[0-9a-fA-F]{64}", h) for h in ev_hashes):
            raise ContractValidationError("verification_evidence_hashes must be SHA-256 digests")
        if len(set(ev_hashes)) != len(ev_hashes):
            raise ContractValidationError(
                "failure_evidence_hashes contains duplicate hashes: repeated references to a single receipt are forbidden"
            )

        if len(source_question_ids)>64 or any(not isinstance(q,str) or not q for q in source_question_ids):
            raise ContractValidationError("INVALID_SOURCE_QUESTIONS")
        object.__setattr__(self,"source_question_ids",tuple(sorted(set(source_question_ids))))
        object.__setattr__(self, "gap_id", str(gap_id))
        object.__setattr__(self, "category", cat)
        object.__setattr__(self, "target_capability", str(target_capability))
        object.__setattr__(self, "affected_revision", str(affected_revision))
        object.__setattr__(self, "reproducible_conditions", freeze_value(reproducible_conditions or {}))
        object.__setattr__(self, "failure_evidence_hashes", ev_hashes)
        object.__setattr__(self, "measured_impact", freeze_value(measured_impact or {}))
        object.__setattr__(self, "testable_improvement_criterion", str(testable_improvement_criterion))
        object.__setattr__(self, "risk_tier", rt)
        object.__setattr__(self, "proposed_owner", str(proposed_owner))
        object.__setattr__(self, "created_at", float(created_at if created_at is not None else time.time()))
        object.__setattr__(self, "schema_version", schema_version)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "gap_id": self.gap_id,
            "source_question_ids":list(self.source_question_ids),
            "category": self.category.value,
            "target_capability": self.target_capability,
            "affected_revision": self.affected_revision,
            "reproducible_conditions": _unfreeze(self.reproducible_conditions),
            "failure_evidence_hashes": list(self.failure_evidence_hashes),
            "measured_impact": _unfreeze(self.measured_impact),
            "testable_improvement_criterion": self.testable_improvement_criterion,
            "risk_tier": self.risk_tier.value,
            "proposed_owner": self.proposed_owner,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EngineeringGapCandidate":
        d = dict(data)
        return cls(
            gap_id=d["gap_id"],
            source_question_ids=d.get("source_question_ids",()),
            category=d["category"],
            target_capability=d["target_capability"],
            affected_revision=d["affected_revision"],
            reproducible_conditions=d.get("reproducible_conditions", {}),
            failure_evidence_hashes=d.get("failure_evidence_hashes", ()),
            measured_impact=d.get("measured_impact", {}),
            testable_improvement_criterion=d["testable_improvement_criterion"],
            risk_tier=d["risk_tier"],
            proposed_owner=d["proposed_owner"],
            created_at=d.get("created_at"),
            schema_version=d.get("schema_version", "1.0"),
        )


@dataclass(frozen=True)
class CanaryCriteria(VersionedContract):
    """
    Explicit, immutable criteria for canary evaluation.
    Must be fixed at deployment approval time.
    """
    sample_size: int
    error_threshold: float
    comparison_baseline: FrozenDict
    deadline_seconds: float
    rollback_conditions: Tuple[str, ...]
    schema_version: str = "1.0"

    def __init__(
        self,
        sample_size: int,
        error_threshold: float,
        comparison_baseline: Any,
        deadline_seconds: float,
        rollback_conditions: Sequence[str] = (),
        schema_version: str = "1.0",
    ):
        if schema_version not in SUPPORTED_EVOLUTION_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported schema_version: {schema_version}")
        if isinstance(sample_size, bool) or not isinstance(sample_size, int) or not 1 <= sample_size <= 10000:
            raise ContractValidationError("sample_size must be at least 1")
        thresh = float(error_threshold)
        if not (0.0 <= thresh <= 1.0):
            raise ContractValidationError("error_threshold must be between 0.0 and 1.0")
        deadline = float(deadline_seconds)
        if not math.isfinite(deadline) or not 0 < deadline <= 86400:
            raise ContractValidationError("deadline_seconds must be positive")

        object.__setattr__(self, "sample_size", int(sample_size))
        object.__setattr__(self, "error_threshold", thresh)
        object.__setattr__(self, "comparison_baseline", freeze_value(comparison_baseline or {}))
        object.__setattr__(self, "deadline_seconds", deadline)
        object.__setattr__(self, "rollback_conditions", tuple(str(x) for x in (rollback_conditions or ())))
        object.__setattr__(self, "schema_version", schema_version)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sample_size": self.sample_size,
            "error_threshold": self.error_threshold,
            "comparison_baseline": _unfreeze(self.comparison_baseline),
            "deadline_seconds": self.deadline_seconds,
            "rollback_conditions": list(self.rollback_conditions),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanaryCriteria":
        d = dict(data)
        return cls(
            sample_size=d["sample_size"],
            error_threshold=d["error_threshold"],
            comparison_baseline=d.get("comparison_baseline", {}),
            deadline_seconds=d["deadline_seconds"],
            rollback_conditions=d.get("rollback_conditions", ()),
            schema_version=d.get("schema_version", "1.0"),
        )


@dataclass(frozen=True)
class EvolutionEvaluationGrant(VersionedContract):
    """
    Operator grant authorizing staging and isolated sandbox testing/benchmarking.
    Signed exclusively by K_operator (Ed25519).
    Fails closed if used to activate or deploy code.
    """
    grant_id: str
    gap_id: str
    candidate_hash: str
    target_capability: str
    base_commit_id: str
    base_file_hash: str
    allowed_isolation_tier: str
    max_resource_budget: FrozenDict
    created_at: float
    expires_at: float
    operator_id: str
    operator_signature: str = ""
    schema_version: str = "1.0"

    def __init__(
        self,
        grant_id: str,
        gap_id: str,
        candidate_hash: str,
        target_capability: str,
        base_commit_id: str,
        base_file_hash: str,
        allowed_isolation_tier: str,
        max_resource_budget: Any,
        expires_at: float,
        operator_id: str,
        created_at: Optional[float] = None,
        operator_signature: str = "",
        schema_version: str = "1.0",
    ):
        if schema_version not in SUPPORTED_EVOLUTION_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported schema_version: {schema_version}")
        if not grant_id or not isinstance(grant_id, str):
            raise ContractValidationError("grant_id must be a non-empty string")
        if not isinstance(candidate_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", candidate_hash):
            raise ContractValidationError("candidate_hash must be a 64-char sha256 hex string")
        if not isinstance(base_file_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", base_file_hash):
            raise ContractValidationError("base_file_hash must be a 64-char sha256 hex string")

        object.__setattr__(self, "grant_id", str(grant_id))
        object.__setattr__(self, "gap_id", str(gap_id))
        object.__setattr__(self, "candidate_hash", str(candidate_hash).lower())
        object.__setattr__(self, "target_capability", str(target_capability))
        object.__setattr__(self, "base_commit_id", str(base_commit_id))
        object.__setattr__(self, "base_file_hash", str(base_file_hash).lower())
        if allowed_isolation_tier not in ('DISPOSABLE_PROCESS','ROOTLESS_CONTAINER'):
            raise ContractValidationError('UNSUPPORTED_ISOLATION_TIER')
        budget=max_resource_budget or {}
        allowed={'timeout','max_memory_bytes','max_output_bytes','max_cpu_seconds','max_processes','max_runs'}
        if not isinstance(budget,(dict,FrozenDict)) or set(budget.keys())-allowed:
            raise ContractValidationError('UNSUPPORTED_EVALUATION_BUDGET')
        for key,value in budget.items():
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<=0:
                raise ContractValidationError('INVALID_EVALUATION_BUDGET')
            if key!='timeout' and int(value)!=value:raise ContractValidationError('INTEGER_RESOURCE_LIMIT_REQUIRED')
        object.__setattr__(self, "allowed_isolation_tier", str(allowed_isolation_tier))
        object.__setattr__(self, "max_resource_budget", freeze_value(max_resource_budget or {}))
        object.__setattr__(self, "created_at", float(created_at if created_at is not None else time.time()))
        object.__setattr__(self, "expires_at", float(expires_at))
        object.__setattr__(self, "operator_id", str(operator_id))
        object.__setattr__(self, "operator_signature", str(operator_signature))
        object.__setattr__(self, "schema_version", schema_version)

    def compute_canonical_payload(self) -> bytes:
        payload_data = {
            "grant_type": "EVOLUTION_EVALUATION",
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "gap_id": self.gap_id,
            "candidate_hash": self.candidate_hash,
            "target_capability": self.target_capability,
            "base_commit_id": self.base_commit_id,
            "base_file_hash": self.base_file_hash,
            "allowed_isolation_tier": self.allowed_isolation_tier,
            "max_resource_budget": _unfreeze(self.max_resource_budget),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "operator_id": self.operator_id,
        }
        return canonical_json(payload_data).encode("utf-8")

    def sign(self, operator_private_key_bytes: bytes) -> "EvolutionEvaluationGrant":
        payload = self.compute_canonical_payload()
        sig = Ed25519KeyManager.sign(operator_private_key_bytes, payload)
        return EvolutionEvaluationGrant(
            grant_id=self.grant_id,
            gap_id=self.gap_id,
            candidate_hash=self.candidate_hash,
            target_capability=self.target_capability,
            base_commit_id=self.base_commit_id,
            base_file_hash=self.base_file_hash,
            allowed_isolation_tier=self.allowed_isolation_tier,
            max_resource_budget=self.max_resource_budget,
            created_at=self.created_at,
            expires_at=self.expires_at,
            operator_id=self.operator_id,
            operator_signature=sig,
            schema_version=self.schema_version,
        )

    def verify_signature(
        self,
        trust_registry: TrustRegistry,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str]:
        if not self.operator_signature:
            return False, "MISSING_OPERATOR_SIGNATURE"
        now = current_time if current_time is not None else time.time()
        if (not all(math.isfinite(v) for v in (now, self.created_at, self.expires_at))
                or self.created_at > now or self.expires_at <= self.created_at):
            return False, "INVALID_GRANT_TIME"
        if not trust_registry.pinned_operator_pub_hex:
            return False, "UNPINNED_OPERATOR_AUTHORITY"
        if now >= self.expires_at:
            return False, f"GRANT_EXPIRED: now={now} > expires_at={self.expires_at}"

        record = trust_registry.get_key(self.operator_id)
        if not record:
            return False, f"OPERATOR_KEY_NOT_FOUND: {self.operator_id}"
        if record.get("role") != KeyRole.OPERATOR.value:
            return False, f"WRONG_KEY_ROLE: key role is {record.get('role')}, expected {KeyRole.OPERATOR.value}"
        if record.get("status") != KeyStatus.ACTIVE.value:
            return False, f"KEY_NOT_ACTIVE: status={record.get('status')}"

        payload = self.compute_canonical_payload()
        return trust_registry.verify_signature_at_time(
            self.operator_id, payload, self.operator_signature, self.created_at
        )


@dataclass(frozen=True)
class EvolutionDeploymentGrant(VersionedContract):
    """
    Operator grant authorizing activation (Shadow, Canary, or Production).
    Binds the exact tested candidate hash, base file hash, verification evidence hashes,
    and canary criteria. Signed exclusively by K_operator (Ed25519).
    """
    grant_id: str
    gap_id: str
    candidate_hash: str
    target_capability: str
    target_file_path: str
    base_commit_id: str
    base_file_hash: str
    dependency_changes: Tuple[str, ...]
    manifest_changes: FrozenDict
    verification_evidence_hashes: Tuple[str, ...]
    permitted_stages: Tuple[str, ...]
    canary_criteria: Optional[CanaryCriteria]
    allow_auto_promotion: bool
    created_at: float
    expires_at: float
    operator_id: str
    operator_signature: str = ""
    schema_version: str = "1.0"

    def __init__(
        self,
        grant_id: str,
        gap_id: str,
        candidate_hash: str,
        target_capability: str,
        target_file_path: str,
        base_commit_id: str,
        base_file_hash: str,
        dependency_changes: Sequence[str],
        manifest_changes: Any,
        verification_evidence_hashes: Sequence[str],
        permitted_stages: Sequence[Union[DeploymentStage, str]],
        expires_at: float,
        operator_id: str,
        canary_criteria: Optional[Union[CanaryCriteria, Dict[str, Any]]] = None,
        allow_auto_promotion: bool = False,
        created_at: Optional[float] = None,
        operator_signature: str = "",
        schema_version: str = "1.0",
    ):
        if schema_version not in SUPPORTED_EVOLUTION_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported schema_version: {schema_version}")
        if not grant_id or not isinstance(grant_id, str):
            raise ContractValidationError("grant_id must be a non-empty string")
        if not isinstance(candidate_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", candidate_hash):
            raise ContractValidationError("candidate_hash must be a 64-char sha256 hex string")
        if not isinstance(base_file_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", base_file_hash):
            raise ContractValidationError("base_file_hash must be a 64-char sha256 hex string")
        if not target_file_path or not isinstance(target_file_path, str):
            raise ContractValidationError("target_file_path must be a non-empty string")

        if not isinstance(allow_auto_promotion, bool):
            raise ContractValidationError("allow_auto_promotion must be boolean")
        ev_hashes = tuple(str(h) for h in verification_evidence_hashes)
        if not ev_hashes:
            raise ContractValidationError("verification_evidence_hashes must contain at least one verified receipt hash")
        if any(not re.fullmatch(r"[0-9a-fA-F]{64}", h) for h in ev_hashes):
            raise ContractValidationError("verification_evidence_hashes must be SHA-256 digests")
        if len(set(ev_hashes)) != len(ev_hashes):
            raise ContractValidationError("verification_evidence_hashes contains duplicate hashes")

        stages = []
        for st in permitted_stages:
            val = st.value if isinstance(st, DeploymentStage) else DeploymentStage(st).value
            stages.append(val)
        if not stages:
            raise ContractValidationError("permitted_stages must contain at least one valid DeploymentStage")

        if allow_auto_promotion and "PRODUCTION" not in stages:
            raise ContractValidationError("Auto-promotion requires PRODUCTION permission")
        cc = None
        if canary_criteria is not None:
            if isinstance(canary_criteria, CanaryCriteria):
                cc = canary_criteria
            elif isinstance(canary_criteria, dict):
                cc = CanaryCriteria.from_dict(canary_criteria)
            else:
                raise ContractValidationError("canary_criteria must be a CanaryCriteria instance or dict")

        object.__setattr__(self, "grant_id", str(grant_id))
        object.__setattr__(self, "gap_id", str(gap_id))
        object.__setattr__(self, "candidate_hash", str(candidate_hash).lower())
        object.__setattr__(self, "target_capability", str(target_capability))
        object.__setattr__(self, "target_file_path", str(target_file_path))
        object.__setattr__(self, "base_commit_id", str(base_commit_id))
        object.__setattr__(self, "base_file_hash", str(base_file_hash).lower())
        object.__setattr__(self, "dependency_changes", tuple(sorted(str(d) for d in (dependency_changes or ()))))
        object.__setattr__(self, "manifest_changes", freeze_value(manifest_changes or {}))
        object.__setattr__(self, "verification_evidence_hashes", ev_hashes)
        object.__setattr__(self, "permitted_stages", tuple(stages))
        object.__setattr__(self, "canary_criteria", cc)
        object.__setattr__(self, "allow_auto_promotion", bool(allow_auto_promotion))
        object.__setattr__(self, "created_at", float(created_at if created_at is not None else time.time()))
        object.__setattr__(self, "expires_at", float(expires_at))
        object.__setattr__(self, "operator_id", str(operator_id))
        object.__setattr__(self, "operator_signature", str(operator_signature))
        object.__setattr__(self, "schema_version", schema_version)

    def compute_canonical_payload(self) -> bytes:
        payload_data = {
            "grant_type": "EVOLUTION_DEPLOYMENT",
            "schema_version": self.schema_version,
            "grant_id": self.grant_id,
            "gap_id": self.gap_id,
            "candidate_hash": self.candidate_hash,
            "target_capability": self.target_capability,
            "target_file_path": self.target_file_path,
            "base_commit_id": self.base_commit_id,
            "base_file_hash": self.base_file_hash,
            "dependency_changes": list(self.dependency_changes),
            "manifest_changes": _unfreeze(self.manifest_changes),
            "verification_evidence_hashes": list(self.verification_evidence_hashes),
            "permitted_stages": list(self.permitted_stages),
            "canary_criteria": self.canary_criteria.to_dict() if self.canary_criteria else None,
            "allow_auto_promotion": self.allow_auto_promotion,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "operator_id": self.operator_id,
        }
        return canonical_json(payload_data).encode("utf-8")

    def sign(self, operator_private_key_bytes: bytes) -> "EvolutionDeploymentGrant":
        payload = self.compute_canonical_payload()
        sig = Ed25519KeyManager.sign(operator_private_key_bytes, payload)
        return EvolutionDeploymentGrant(
            grant_id=self.grant_id,
            gap_id=self.gap_id,
            candidate_hash=self.candidate_hash,
            target_capability=self.target_capability,
            target_file_path=self.target_file_path,
            base_commit_id=self.base_commit_id,
            base_file_hash=self.base_file_hash,
            dependency_changes=self.dependency_changes,
            manifest_changes=self.manifest_changes,
            verification_evidence_hashes=self.verification_evidence_hashes,
            permitted_stages=self.permitted_stages,
            canary_criteria=self.canary_criteria,
            allow_auto_promotion=self.allow_auto_promotion,
            created_at=self.created_at,
            expires_at=self.expires_at,
            operator_id=self.operator_id,
            operator_signature=sig,
            schema_version=self.schema_version,
        )

    def verify_signature(
        self,
        trust_registry: TrustRegistry,
        current_time: Optional[float] = None
    ) -> Tuple[bool, str]:
        if not self.operator_signature:
            return False, "MISSING_OPERATOR_SIGNATURE"
        now = current_time if current_time is not None else time.time()
        if (not all(math.isfinite(v) for v in (now, self.created_at, self.expires_at))
                or self.created_at > now or self.expires_at <= self.created_at):
            return False, "INVALID_GRANT_TIME"
        if not trust_registry.pinned_operator_pub_hex:
            return False, "UNPINNED_OPERATOR_AUTHORITY"
        if now >= self.expires_at:
            return False, f"GRANT_EXPIRED: now={now} > expires_at={self.expires_at}"

        record = trust_registry.get_key(self.operator_id)
        if not record:
            return False, f"OPERATOR_KEY_NOT_FOUND: {self.operator_id}"
        if record.get("role") != KeyRole.OPERATOR.value:
            return False, f"WRONG_KEY_ROLE: key role is {record.get('role')}, expected {KeyRole.OPERATOR.value}"
        if record.get("status") != KeyStatus.ACTIVE.value:
            return False, f"KEY_NOT_ACTIVE: status={record.get('status')}"

        payload = self.compute_canonical_payload()
        return trust_registry.verify_signature_at_time(
            self.operator_id, payload, self.operator_signature, self.created_at
        )


@dataclass(frozen=True)
class EvolutionReceipt(VersionedContract):
    """
    Immutable receipt of an evolution lifecycle transition (staged, tested, deployed, rolled back).
    Committed atomically to EventStore.
    """
    receipt_id: str
    grant_id: str
    candidate_hash: str
    outcome: str
    details: FrozenDict
    timestamp: float = field(default_factory=time.time)
    schema_version: str = "1.0"

    def __init__(
        self,
        receipt_id: str,
        grant_id: str,
        candidate_hash: str,
        outcome: str,
        details: Any,
        timestamp: Optional[float] = None,
        schema_version: str = "1.0",
    ):
        if schema_version not in SUPPORTED_EVOLUTION_SCHEMA_VERSIONS:
            raise ContractValidationError(f"Unsupported schema_version: {schema_version}")

        object.__setattr__(self, "receipt_id", str(receipt_id))
        object.__setattr__(self, "grant_id", str(grant_id))
        object.__setattr__(self, "candidate_hash", str(candidate_hash).lower())
        object.__setattr__(self, "outcome", str(outcome))
        object.__setattr__(self, "details", freeze_value(details or {}))
        object.__setattr__(self, "timestamp", float(timestamp if timestamp is not None else time.time()))
        object.__setattr__(self, "schema_version", schema_version)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "grant_id": self.grant_id,
            "candidate_hash": self.candidate_hash,
            "outcome": self.outcome,
            "details": _unfreeze(self.details),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvolutionReceipt":
        d = dict(data)
        return cls(
            receipt_id=d["receipt_id"],
            grant_id=d["grant_id"],
            candidate_hash=d["candidate_hash"],
            outcome=d["outcome"],
            details=d.get("details", {}),
            timestamp=d.get("timestamp"),
            schema_version=d.get("schema_version", "1.0"),
        )
