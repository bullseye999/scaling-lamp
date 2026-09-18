"""
ciph.capabilities.evolution - Governed Self-Evolution, Isolated Subprocess Sandboxing & Canary Pipeline (CIPH 4.0 Blueprint Phase 8).
Enforces fail-closed static AST manifest extraction, early authorization verification prior to any execution,
and restricted-filesystem sandboxed subprocess execution within isolated temporary directories.
Candidate code is NEVER imported or instantiated in the host supervisor's memory.
"""

import os
import ast
import json
import time
import uuid
import sys
import tempfile
import subprocess
import hashlib
import contextvars
import sqlite3
from typing import Dict, Any, List, Optional, Tuple, Union

from ciph.capabilities.base import BaseCapability
from ciph.capabilities.registry import CapabilityRegistry
from ciph.kernel.policy_engine import (
    CapabilityManifest,
    RiskTier,
    NetworkPolicy,
    ReversibilityClass,
    AuthorizationTier,
    AuthorizationGrant,
    AdversarialRedTeamGate
)
from ciph.planner.schemas import SkillTemplate, SkillPromotionTier, PlanStep, ExecutionDAG
from ciph.planner.skill_registry import SkillRegistry
from ciph.contracts.evolution import (
    EngineeringGapCandidate,
    EvolutionEvaluationGrant,
    EvolutionDeploymentGrant,
    CanaryCriteria,
    EvolutionReceipt,
    GapCategory,
    DeploymentStage,
)
from ciph.kernel.crypto_identity import KeyRole, KeyStatus, TrustRegistry


_host_fs_isolation_active: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "_host_fs_isolation_active", default=False
)
_host_fs_hook_installed = False


def _ciph_host_fs_audit_hook(event: str, args: tuple) -> None:
    if not _host_fs_isolation_active.get():
        return
    if event == "open":
        mode = args[1] if len(args) > 1 else "r"
        flags = args[2] if len(args) > 2 else 0
        if (isinstance(mode, str) and any(m in mode for m in ("w", "a", "+", "x"))) or (isinstance(flags, int) and (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))):
            raise PermissionError(f"Host filesystem write blocked during capability module compilation: open({args[0]!r})")
    elif event in ("os.mkdir", "os.symlink", "os.link", "os.remove", "os.unlink", "os.rmdir", "os.chmod", "os.chown", "os.truncate", "os.rename", "os.replace"):
        raise PermissionError(f"Host filesystem modification blocked during capability module compilation: {event}")


def _ensure_host_fs_hook_installed():
    global _host_fs_hook_installed
    if not _host_fs_hook_installed:
        sys.addaudithook(_ciph_host_fs_audit_hook)
        _host_fs_hook_installed = True


class CanaryStatus(str):
    PENDING = "PENDING"
    CANARY_ACTIVE = "CANARY_ACTIVE"
    PROMOTED = "PROMOTED"
    ROLLED_BACK = "ROLLED_BACK"


class IsolatedEvolvedCapability(BaseCapability):
    """
    Governed capability wrapper that represents an evolved capability in the registry.
    Strictly forbids executing candidate code inside the supervisor's memory.
    All executions are dispatched to an isolated subprocess; candidate code is NEVER
    imported or instantiated into the supervisor's Python process.
    """
    def __init__(
        self,
        manifest: CapabilityManifest,
        code_source: str,
        class_name: str,
        allowed_isolation_tier: str = "DISPOSABLE_PROCESS"
    ):
        self._manifest = manifest
        self._code_source = code_source
        self._class_name = class_name
        self._allowed_isolation_tier = allowed_isolation_tier

    @property
    def manifest(self) -> CapabilityManifest:
        return self._manifest

    def run(self, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Legacy detached wrappers cannot bypass the governed evolution pipeline."""
        raise PermissionError("GOVERNED_CANARY_REQUIRED: detached evolved wrappers cannot execute")


class HotReloadEngine:
    """
    Sandboxed Self-Evolution & Capability Hot-Reload Engine.
    Enforces fail-closed static AST manifest extraction, early authorization verification BEFORE any execution,
    and sandboxed subprocess execution with host filesystem isolation.
    Candidate code is NEVER imported or instantiated in the host supervisor's memory.
    """

    FORBIDDEN_AST_CALLS = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "breakpoint"
    }

    def __init__(self, red_team_gate: Optional[AdversarialRedTeamGate] = None, db_path: Optional[str] = None):
        self.red_team_gate = red_team_gate or AdversarialRedTeamGate()
        self.candidates: Dict[str, Any] = {}
        self.db_path = db_path
        _ensure_host_fs_hook_installed()

    def _init_consumed_grants_table(self, conn: sqlite3.Connection):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ciph_consumed_evolution_grants (
                grant_id TEXT PRIMARY KEY,
                candidate_hash TEXT NOT NULL,
                consumed_at REAL NOT NULL,
                status TEXT NOT NULL
            )
        """)
        conn.commit()

    def audit_code_safety(self, code_source: str) -> Tuple[bool, List[str]]:
        """Static AST security analysis of candidate capability code."""
        errors = []
        try:
            tree = ast.parse(code_source)
        except SyntaxError as e:
            return False, [f"Syntax Error in candidate code: {str(e)}"]

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in self.FORBIDDEN_AST_CALLS:
                    errors.append(f"Security Veto: Forbidden dynamic execution function '{node.func.id}()' detected.")
            elif isinstance(node, ast.Attribute):
                if node.attr in ("system", "popen", "spawn"):
                    errors.append(f"Security Veto: Forbidden process spawning attribute '{node.attr}' detected.")

        return len(errors) == 0, errors

    def extract_static_manifest_info(self, code_source: str) -> Dict[str, Any]:
        """
        Statically inspects AST to extract manifest properties.
        FAIL-CLOSED PRINCIPLE: Any dynamic expression, getattr, variable reference,
        or unrecognized AST structure defaults strictly to MANDATORY_INTERRUPT and CRITICAL.
        """
        info: Dict[str, Any] = {
            "name": "unknown.capability",
            "authorization": AuthorizationTier.MANDATORY_INTERRUPT.value,
            "risk_tier": RiskTier.CRITICAL.value,
            "network_policy": NetworkPolicy.OFFLINE_ONLY.value,
            "reversibility": ReversibilityClass.IRREVERSIBLE.value,
            "is_statically_proven_safe": False
        }
        try:
            tree = ast.parse(code_source)
            has_dynamic_manifest = False
            extracted_count = 0

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
                    if func_name == "CapabilityManifest":
                        for kw in node.keywords:
                            if isinstance(kw.value, ast.Constant):
                                info[kw.arg] = str(kw.value.value)
                                extracted_count += 1
                            elif isinstance(kw.value, ast.Attribute):
                                if isinstance(kw.value.value, ast.Name):
                                    attr_name = kw.value.attr
                                    info[kw.arg] = attr_name
                                    extracted_count += 1
                                else:
                                    has_dynamic_manifest = True
                            else:
                                has_dynamic_manifest = True

            if not has_dynamic_manifest and extracted_count >= 3:
                info["is_statically_proven_safe"] = True
            else:
                info["authorization"] = AuthorizationTier.MANDATORY_INTERRUPT.value
                info["risk_tier"] = RiskTier.CRITICAL.value
                info["is_statically_proven_safe"] = False

        except Exception:
            info["authorization"] = AuthorizationTier.MANDATORY_INTERRUPT.value
            info["risk_tier"] = RiskTier.CRITICAL.value

        return info

    def build_manifest_from_static_info(self, info: Dict[str, Any]) -> CapabilityManifest:
        """Construct CapabilityManifest safely from validated static AST info."""
        name = info.get("name", "evolved.capability")
        desc = info.get("description", "Evolved sandboxed capability")
        rt = RiskTier(info.get("risk_tier", RiskTier.CRITICAL.value))
        np = NetworkPolicy(info.get("network_policy", NetworkPolicy.OFFLINE_ONLY.value))
        rc = ReversibilityClass(info.get("reversibility", ReversibilityClass.IRREVERSIBLE.value))
        at = AuthorizationTier(info.get("authorization", AuthorizationTier.MANDATORY_INTERRUPT.value))
        return CapabilityManifest(
            name=name,
            description=desc,
            risk_tier=rt,
            network_policy=np,
            reversibility=rc,
            authorization=at,
            timeout_seconds=15
        )

    def test_in_disposable_subprocess(self, code_source, class_name, test_params,
                                     isolation_tier="DISPOSABLE_PROCESS", evaluation_grant=None, trust_registry=None):
        """Retired shortcut: budgets and independent assertions live in one harness."""
        return False, {}, ["AUTHORIZATION_REQUIRED: use IndependentBenchmarkHarness with a single-use evaluation grant"]

    def hot_reload_capability(
        self,
        code_source: str,
        class_name: str,
        runtime: Any,
        auth_grant: Optional[Any] = None,
        deployment_grant: Optional[Any] = None,
        test_params: Optional[Dict[str, Any]] = None,
        allowed_isolation_tier: str = "DISPOSABLE_PROCESS"
    ) -> Dict[str, Any]:
        """Compatibility refusal for the retired direct hot-reload interface."""
        # Runtime registration is an activation. Only the durable canary manager
        # may perform it after independent evidence and per-stage consent checks.
        grant = deployment_grant or auth_grant
        if not isinstance(grant, EvolutionDeploymentGrant):
            return {"success": False, "status": "AUTHORIZATION_REQUIRED",
                    "errors": ["Operator EvolutionDeploymentGrant and governed canary activation required"]}
        valid, reason = grant.verify_signature(runtime.trust_registry)
        if not valid:
            return {"success": False, "status": "INVALID_AUTHORIZATION_SIGNATURE", "errors": [reason]}
        return {"success": False, "status": "GOVERNED_CANARY_REQUIRED",
                "errors": ["Use CanaryDeploymentManager; direct live registry replacement is disabled"]}

    def promote_skill_with_operator_grant(self, signature, skill_registry, auth_grant, auth_secret_key):
        return {"success": False, "status": "GOVERNED_CANARY_REQUIRED",
                "errors": ["Legacy skill promotion cannot substitute HMAC consent for evolution verification"]}
