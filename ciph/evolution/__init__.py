"""
ciph.evolution - Governed Evidence-Driven Self-Evolution Subsystem (Phase 8).
Provides automated gap detection, independent benchmark verification,
and crash-resilient canary deployment lifecycle management.
"""

from ciph.evolution.gap_detector import (
    EngineeringGapDetector,
    FailureClassification,
)
from ciph.evolution.benchmark_harness import (
    IndependentBenchmarkHarness,
    BenchmarkReport,
)
from ciph.evolution.canary_manager import (
    CanaryDeploymentManager,
    CanaryState,
    CanaryRecord,
)

__all__ = [
    "EngineeringGapDetector",
    "FailureClassification",
    "IndependentBenchmarkHarness",
    "BenchmarkReport",
    "CanaryDeploymentManager",
    "CanaryState",
    "CanaryRecord",
]
