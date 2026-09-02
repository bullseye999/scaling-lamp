"""
ciph.capabilities.evolution - Governed Self-Evolution, Isolated Subprocess Sandboxing & Canary Pipeline (CIPH 4.0 Blueprint Phase 8).
Enforces fail-closed static AST manifest extraction, early authorization verification prior to any execution,
and restricted-filesystem sandboxed subprocess execution within isolated temporary directories.
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
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
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


@dataclass
class EngineeringGapCandidate:
    candidate_id: str
    gap_description: str
    target_capability_name: str
    hypothesis: str
    staged_code: str
    class_name: str
    created_at: float = field(default_factory=time.time)
    test_params: Dict[str, Any] = field(default_factory=dict)
    benchmark_score: float = 0.0
    canary_status: str = CanaryStatus.PENDING
    canary_runs: int = 0
    canary_errors: int = 0
    promoted_at: Optional[float] = None
    rolled_back_at: Optional[float] = None
    operator_grant_id: Optional[str] = None


class HotReloadEngine:
    """
    Sandboxed Self-Evolution & Capability Hot-Reload Engine.
    Enforces fail-closed static AST manifest extraction, early authorization verification BEFORE any execution,
    and sandboxed subprocess execution with host filesystem isolation.
    """

    FORBIDDEN_AST_CALLS = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "breakpoint"
    }

    def __init__(self, red_team_gate: Optional[AdversarialRedTeamGate] = None):
        self.red_team_gate = red_team_gate or AdversarialRedTeamGate()
        self.candidates: Dict[str, EngineeringGapCandidate] = {}
        _ensure_host_fs_hook_installed()

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

    def extract_static_manifest_info(self, code_source: str) -> Dict[str, str]:
        """
        Statically inspects AST to extract manifest properties.
        FAIL-CLOSED PRINCIPLE: Any dynamic expression, getattr, variable reference,
        or unrecognized AST structure defaults strictly to MANDATORY_INTERRUPT and CRITICAL.
        """
        info = {
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

    def test_in_disposable_subprocess(
        self,
        code_source: str,
        class_name: str,
        test_params: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, Any], List[str]]:
        """
        Execute mock test in an isolated disposable subprocess inside a clean temp directory
        with strict host filesystem write restrictions across all filesystem operations.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir_abs = os.path.abspath(tmp_dir)
            runner_script = f"""
import os
import sys
import json
import builtins
import io
import pathlib

tmp_dir_abs = {repr(tmp_dir_abs)}

def _fs_audit_hook(event, args):
    if event == "open":
        path = args[0]
        mode = args[1] if len(args) > 1 else "r"
        flags = args[2] if len(args) > 2 else 0
        is_write = False
        if isinstance(mode, str) and any(m in mode for m in ("w", "a", "+", "x")):
            is_write = True
        elif isinstance(flags, int) and (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | getattr(os, "O_APPEND", 0) | getattr(os, "O_TRUNC", 0))):
            is_write = True
        if is_write:
            p = os.path.abspath(os.fsdecode(path))
            if not p.startswith(tmp_dir_abs):
                raise PermissionError(f"File write blocked outside sandbox: {{p}}")
    elif event in ("os.mkdir", "os.remove", "os.unlink", "os.rmdir", "os.chmod", "os.chown", "os.truncate"):
        p = os.path.abspath(os.fsdecode(args[0]))
        if not p.startswith(tmp_dir_abs):
            raise PermissionError(f"Filesystem mutation blocked outside sandbox: {{p}}")
    elif event in ("os.symlink", "os.link"):
        p = os.path.abspath(os.fsdecode(args[1]))
        if not p.startswith(tmp_dir_abs):
            raise PermissionError(f"Link creation blocked outside sandbox: {{p}}")
    elif event in ("os.rename", "os.replace"):
        for idx in (0, 1):
            p = os.path.abspath(os.fsdecode(args[idx]))
            if not p.startswith(tmp_dir_abs):
                raise PermissionError(f"Path rename/replace blocked outside sandbox: {{p}}")

sys.addaudithook(_fs_audit_hook)

sys.path.insert(0, {json.dumps(os.path.abspath("."))})
{code_source}

try:
    instance = {class_name}()
    manifest = instance.manifest
    test_params = json.loads({json.dumps(json.dumps(test_params))})
    receipt = instance.execute(test_params)
    out = {{
        "success": receipt.exit_code == 0,
        "exit_code": receipt.exit_code,
        "results": receipt.results,
        "manifest": {{
            "name": manifest.name,
            "risk_tier": manifest.risk_tier.value,
            "network_policy": manifest.network_policy.value,
            "reversibility": manifest.reversibility.value,
            "authorization": manifest.authorization.value
        }},
        "error": receipt.error_message
    }}
    print(json.dumps(out))
except Exception as ex:
    print(json.dumps({{"success": False, "exit_code": 1, "error": str(ex)}}))
"""
            clean_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONPATH": os.path.abspath("."),
                "LANG": "C.UTF-8"
            }
            try:
                proc = subprocess.run(
                    [sys.executable, "-c", runner_script],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    cwd=tmp_dir,
                    env=clean_env
                )
                if proc.returncode != 0:
                    return False, {}, [f"Subprocess test crashed: {proc.stderr}"]
                
                output_lines = [line.strip() for line in proc.stdout.strip().splitlines() if line.strip()]
                if not output_lines:
                    return False, {}, [f"Subprocess produced no output. Stderr: {proc.stderr}"]
                
                result_data = json.loads(output_lines[-1])
                if not result_data.get("success"):
                    return False, result_data, [result_data.get("error") or "Mock run failed in isolated subprocess."]
                
                return True, result_data, []
            except subprocess.TimeoutExpired:
                return False, {}, ["Subprocess execution timed out (>8s)."]
            except Exception as ex:
                return False, {}, [f"Subprocess runner exception: {str(ex)}"]

    def stage_and_instantiate_capability(
        self,
        code_source: str,
        class_name: str
    ) -> Tuple[Optional[BaseCapability], List[str]]:
        """Instantiate capability instance for registration in a host-isolated compilation scope."""
        is_safe, audit_errors = self.audit_code_safety(code_source)
        if not is_safe:
            return None, audit_errors

        safe_builtins = dict(__builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__)

        sandbox_globals: Dict[str, Any] = {
            "__builtins__": safe_builtins,
            "BaseCapability": BaseCapability,
            "CapabilityManifest": CapabilityManifest,
            "RiskTier": RiskTier,
            "NetworkPolicy": NetworkPolicy,
            "ReversibilityClass": ReversibilityClass,
            "AuthorizationTier": AuthorizationTier,
            "time": time,
            "Dict": Dict,
            "Any": Any,
            "Optional": Optional,
            "List": List,
        }

        # Activate host filesystem mutation block via audit hook
        tok = _host_fs_isolation_active.set(True)
        try:
            compiled = compile(code_source, filename="<ciph_evolved_capability>", mode="exec")
            exec(compiled, sandbox_globals)

            target_cls = sandbox_globals.get(class_name)
            if not target_cls or not issubclass(target_cls, BaseCapability):
                return None, [f"Class '{class_name}' not found or does not inherit from BaseCapability."]

            instance = target_cls()
            _ = instance.manifest
            return instance, []
        except Exception as ex:
            return None, [f"Failed to instantiate capability: {str(ex)}"]
        finally:
            _host_fs_isolation_active.reset(tok)

    def hot_reload_capability(
        self,
        code_source: str,
        class_name: str,
        runtime: Any,
        auth_grant: Optional[AuthorizationGrant] = None,
        test_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Hardened hot-reload evolution cycle:
        1. Static AST Audit
        2. Fail-Closed Static Manifest Extraction (Zero Execution)
        3. EARLY Cryptographic Authorization Verification BEFORE any subprocess
        4. Falsification Probe Check
        5. Sandboxed Subprocess Test Execution (Isolated filesystem)
        6. Safe Host Instantiation & Registration
        """
        test_params = test_params or {}

        # 1. Static AST Audit
        is_safe, audit_errors = self.audit_code_safety(code_source)
        if not is_safe:
            return {
                "success": False,
                "status": "COMPILATION_OR_AUDIT_FAILED",
                "errors": audit_errors
            }

        # 2. Fail-Closed Static Manifest Extraction without executing code
        static_manifest = self.extract_static_manifest_info(code_source)
        auth_tier = static_manifest.get("authorization")
        risk_tier = static_manifest.get("risk_tier")
        cap_name = static_manifest.get("name", class_name)
        is_proven_safe = static_manifest.get("is_statically_proven_safe", False)

        # 3. EARLY Authorization Verification (Checked BEFORE any subprocess or host execution)
        if not is_proven_safe or auth_tier == AuthorizationTier.MANDATORY_INTERRUPT.value or risk_tier in ("HIGH", "CRITICAL"):
            if not auth_grant or not isinstance(auth_grant, AuthorizationGrant) or not auth_grant.verify_signature(runtime.auth_secret_key):
                return {
                    "success": False,
                    "status": "AUTHORIZATION_REQUIRED",
                    "capability": cap_name,
                    "errors": ["Operator cryptographic AuthorizationGrant required BEFORE executing or staging candidate capability."]
                }

        # 4. Red Team Falsification Probe
        safe, reason = self.red_team_gate.evaluate_falsification_probe(
            capability=cap_name,
            params=test_params,
            manifest=None
        )
        if not safe:
            return {
                "success": False,
                "status": "RED_TEAM_FALSIFICATION_VETO",
                "errors": [reason]
            }

        # 5. Test in Isolated Disposable Subprocess (inside clean temp directory with write sandbox)
        sub_ok, sub_data, sub_errors = self.test_in_disposable_subprocess(code_source, class_name, test_params)
        if not sub_ok:
            return {
                "success": False,
                "status": "MOCK_EXECUTION_TEST_FAILED",
                "errors": sub_errors
            }

        # 6. Safe host instantiation & registration
        instance, inst_errors = self.stage_and_instantiate_capability(code_source, class_name)
        if not instance:
            return {
                "success": False,
                "status": "COMPILATION_OR_AUDIT_FAILED",
                "errors": inst_errors
            }

        # Double check actual instance manifest after instantiation
        real_manifest = instance.manifest
        if real_manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT or real_manifest.risk_tier in (RiskTier.HIGH, RiskTier.CRITICAL):
            if not auth_grant or not isinstance(auth_grant, AuthorizationGrant) or not auth_grant.verify_signature(runtime.auth_secret_key):
                return {
                    "success": False,
                    "status": "AUTHORIZATION_REQUIRED",
                    "capability": real_manifest.name,
                    "errors": ["Operator cryptographic AuthorizationGrant required for instantiated high-risk capability."]
                }

        runtime.register_capability(instance)

        return {
            "success": True,
            "status": "HOT_RELOAD_SUCCESS",
            "capability_name": instance.manifest.name,
            "lane": instance.manifest.derive_execution_lane().value,
            "sandbox_tested": True
        }

    def promote_skill_with_operator_grant(
        self,
        signature: str,
        skill_registry: SkillRegistry,
        auth_grant: AuthorizationGrant,
        auth_secret_key: bytes
    ) -> Dict[str, Any]:
        """Promote a candidate skill template to ACTIVE status using cryptographic operator grant."""
        if not auth_grant or not auth_grant.verify_signature(auth_secret_key):
            return {
                "success": False,
                "status": "INVALID_AUTHORIZATION_SIGNATURE",
                "signature": signature
            }

        template = skill_registry._templates.get(signature)
        if not template:
            return {
                "success": False,
                "status": "SKILL_TEMPLATE_NOT_FOUND",
                "signature": signature
            }

        skill_registry.approve_skill(signature, auto_activate=True)

        return {
            "success": True,
            "status": "SKILL_PROMOTED_ACTIVE",
            "signature": signature,
            "promotion_tier": template.promotion_tier.value
        }
