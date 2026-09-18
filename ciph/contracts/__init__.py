"""
ciph.contracts - Canonical Versioned Data Contracts for CIPH 4.0.
Provides strongly-typed, immutable, versioned contracts across Authority, Planning, Execution, and Epistemic boundaries.
"""

from ciph.contracts.base import (
    ContractValidationError,
    VersionedContract,
    FrozenDict,
    canonical_json,
    freeze_value,
    _unfreeze,
)

from ciph.contracts.enums import (
    NetworkPolicy,
    ReversibilityClass,
    RiskTier,
    AuthorizationTier,
    ExecutionLane,
    ScopeType,
    JobState,
    OutcomeCategory,
    ExecutionOutcome,
    EvidenceMode,
    EpistemicDecision,
    ProjectionState,
    ReliabilityClass,
    EpistemicState,
    EpistemicCategory,
    LifecycleState,
    DecayProfile,
    SkillPromotionTier,
    DECAY_DURATIONS_SECONDS,
    RELIABILITY_BASE_WEIGHTS,
)

from ciph.contracts.grants import (
    ScopeGrant,
    AuthorizationGrant,
)

from ciph.contracts.planning import (
    IntentProposal,
    PlanValidationResult,
    PlanStep,
    ExecutionDAG,
    SkillTemplate,
)

from ciph.contracts.execution import (
    JobAttempt,
    ExecutionToken,
)

def __getattr__(name: str):
    if name in ("ExecutionReceipt", "compute_idempotency_key", "generate_environment_fingerprint"):
        import ciph.workers.receipts as _rcpt
        val = getattr(_rcpt, name)
        globals()[name] = val
        return val
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

from ciph.contracts.epistemic import (
    Observation,
    ObservationIngestor,
    Claim,
    ClaimProjector,
    EpistemicAdmissionError,
)

from ciph.contracts.evolution import (
    GapCategory,
    DeploymentStage,
    EngineeringGapCandidate,
    CanaryCriteria,
    EvolutionEvaluationGrant,
    EvolutionDeploymentGrant,
    EvolutionReceipt,
)

__all__ = [
    # Base
    "ContractValidationError",
    "EpistemicAdmissionError",
    "VersionedContract",
    "FrozenDict",
    "canonical_json",
    "freeze_value",
    "_unfreeze",
    # Enums
    "NetworkPolicy",
    "ReversibilityClass",
    "RiskTier",
    "AuthorizationTier",
    "ExecutionLane",
    "ScopeType",
    "JobState",
    "OutcomeCategory",
    "ExecutionOutcome",
    "EvidenceMode",
    "EpistemicDecision",
    "ProjectionState",
    "ReliabilityClass",
    "EpistemicState",
    "EpistemicCategory",
    "LifecycleState",
    "DecayProfile",
    "SkillPromotionTier",
    "DECAY_DURATIONS_SECONDS",
    "RELIABILITY_BASE_WEIGHTS",
    # 10 Canonical Contracts
    "ScopeGrant",
    "AuthorizationGrant",
    "IntentProposal",
    "PlanStep",
    "ExecutionDAG",
    "PlanValidationResult",
    "SkillTemplate",
    "JobAttempt",
    "ExecutionReceipt",
    "ExecutionToken",
    "Observation",
    "ObservationIngestor",
    "Claim",
    # Services & Authorities
    "ClaimProjector",
    # Evolution Contracts (Phase 8)
    "GapCategory",
    "DeploymentStage",
    "EngineeringGapCandidate",
    "CanaryCriteria",
    "EvolutionEvaluationGrant",
    "EvolutionDeploymentGrant",
    "EvolutionReceipt",
    # Utilities
    "compute_idempotency_key",
    "generate_environment_fingerprint",
]
