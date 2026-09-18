"""
ciph.kernel.sandbox.base - Typed contracts, diagnostic structures, and policies
for multi-tier sandboxed execution (Program 2, Phase 7).
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.contracts.enums import NetworkPolicy


class SandboxDiagnosticState(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_TESTED = "NOT_TESTED"


class SandboxTerminationReason(str, Enum):
    SUCCESS = "SUCCESS"
    EXIT_ERROR = "EXIT_ERROR"
    TIMEOUT = "TIMEOUT"
    OUTPUT_FLOOD = "OUTPUT_FLOOD"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    CONTAINMENT_VIOLATION = "CONTAINMENT_VIOLATION"
    SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
    UNCERTAIN_CLEANUP = "UNCERTAIN_CLEANUP"
    LAUNCHER_FAILURE = "LAUNCHER_FAILURE"


@dataclass
class DiagnosticCheck:
    state: SandboxDiagnosticState
    observation: str
    tested_config: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "observation": self.observation,
            "tested_config": self.tested_config
        }


@dataclass
class SandboxDiagnostics:
    launcher_status: DiagnosticCheck
    filesystem_isolation: DiagnosticCheck
    network_isolation: DiagnosticCheck
    resource_enforcement: DiagnosticCheck
    descendant_cleanup: DiagnosticCheck
    overall: str  # "AVAILABLE" or "UNAVAILABLE"
    tested_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall": self.overall,
            "tested_at": self.tested_at,
            "launcher_status": self.launcher_status.to_dict(),
            "filesystem_isolation": self.filesystem_isolation.to_dict(),
            "network_isolation": self.network_isolation.to_dict(),
            "resource_enforcement": self.resource_enforcement.to_dict(),
            "descendant_cleanup": self.descendant_cleanup.to_dict(),
        }


@dataclass(frozen=True)
class SandboxPolicy:
    network_policy: NetworkPolicy = NetworkPolicy.OFFLINE_ONLY
    allowed_read_paths: Tuple[str, ...] = ()
    allowed_write_paths: Tuple[str, ...] = ()
    scratch_dir: Optional[str] = None
    env_allowlist: Tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "CIPH_SANDBOX_ID")
    max_wall_time_seconds: float = 10.0
    max_output_bytes: int = 1_048_576  # 1 MB
    max_input_bytes: int = 1_048_576   # 1 MB
    max_memory_bytes: Optional[int] = 536_870_912  # 512 MB
    max_cpu_seconds: Optional[int] = 10
    max_processes: Optional[int] = 32
    require_filesystem_isolation: bool = True
    require_network_isolation: bool = True
    require_pid_isolation: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network_policy": self.network_policy.value,
            "allowed_read_paths": list(self.allowed_read_paths),
            "allowed_write_paths": list(self.allowed_write_paths),
            "scratch_dir": self.scratch_dir,
            "env_allowlist": list(self.env_allowlist),
            "max_wall_time_seconds": self.max_wall_time_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_input_bytes": self.max_input_bytes,
            "max_memory_bytes": self.max_memory_bytes,
            "max_cpu_seconds": self.max_cpu_seconds,
            "max_processes": self.max_processes,
            "require_filesystem_isolation": self.require_filesystem_isolation,
            "require_network_isolation": self.require_network_isolation,
            "require_pid_isolation": self.require_pid_isolation,
        }


@dataclass
class SandboxResult:
    exit_code: Optional[int]
    stdout: str
    stderr: str
    termination_reason: SandboxTerminationReason
    diagnostics: Optional[SandboxDiagnostics] = None
    cleaned_up: bool = True
    execution_confirmed: bool = False
    data: Optional[Dict[str, Any]] = None
    duration_seconds: float = 0.0
    peak_memory_bytes: int = 0
    cpu_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout_length": len(self.stdout),
            "stderr_length": len(self.stderr),
            "termination_reason": self.termination_reason.value,
            "cleaned_up": self.cleaned_up,
            "execution_confirmed": self.execution_confirmed,
            "data": self.data,
            "duration_seconds": self.duration_seconds,
            "peak_memory_bytes": self.peak_memory_bytes,
            "cpu_seconds": self.cpu_seconds,
            "diagnostics": self.diagnostics.to_dict() if self.diagnostics else None
        }


class SandboxUnavailableError(RuntimeError):
    """Raised when required containment cannot be established by the runner."""

    def __init__(self, diagnostics: SandboxDiagnostics, message: Optional[str] = None):
        self.diagnostics = diagnostics
        failed_checks = []
        for name in ("launcher_status", "filesystem_isolation", "network_isolation", "resource_enforcement", "descendant_cleanup"):
            check = getattr(diagnostics, name)
            if check.state == SandboxDiagnosticState.FAIL:
                failed_checks.append(f"{name}: {check.observation}")
        details = "; ".join(failed_checks) if failed_checks else "Containment criteria not met"
        super().__init__(message or f"SANDBOX_UNAVAILABLE: {details}")
