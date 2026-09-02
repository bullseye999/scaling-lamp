"""
ciph.planner.dag_planner - Deterministic DAG Executor with Real T₀ Rollback & Topological Sort.
Executes multi-step dependency graphs safely, sorting dependencies, taking T₀ file backups,
and invoking compensations or atomic rollbacks on failure.
"""

import time
import uuid
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import deque
from ciph.planner.schemas import PlanStep, ExecutionDAG, ReversibilityClass, PlanValidationResult, AuthorizationTier
from ciph.planner.predicates import evaluate_success_condition
from ciph.capabilities.registry import CapabilityRegistry
from ciph.workers.receipts import ExecutionReceipt


class DAGExecutor:
    """
    Executes a structured ExecutionDAG step-by-step.
    Enforces topological dependency ordering, takes real T₀ filesystem snapshots,
    validates success conditions via AST, and runs compensations / file rollbacks if execution fails.
    """

    def __init__(
        self,
        registry: CapabilityRegistry,
        backups_dir: str = "ciph_backups"
    ):
        self.registry = registry
        self.backups_dir = Path(backups_dir)
        self.backups_dir.mkdir(exist_ok=True)

    def validate_plan(self, dag: ExecutionDAG) -> PlanValidationResult:
        """
        Statically validates DAG topology, capability availability, and authorization tier requirements.
        """
        errors = []
        required_grants = []

        # 1. Check topological validity
        try:
            self.topological_sort(dag.steps)
        except ValueError as ex:
            errors.append(f"Topology Error: {str(ex)}")

        # 2. Check capability existence & authorization tiers
        for step in dag.steps:
            cap = self.registry.get(step.capability)
            if not cap:
                errors.append(f"Unregistered capability '{step.capability}' in step '{step.step_id}'.")
            else:
                if cap.manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
                    required_grants.append(step.step_id)

        return PlanValidationResult(
            plan_id=dag.plan_id,
            is_valid=len(errors) == 0,
            errors=errors,
            required_grants=required_grants
        )

    def topological_sort(self, steps: List[PlanStep]) -> List[PlanStep]:
        """
        Sort steps in valid topological dependency execution order.
        Raises ValueError if dependency cycle is detected or dependency step is missing.
        """
        step_map = {s.step_id: s for s in steps}
        in_degree = {s.step_id: 0 for s in steps}
        adj = {s.step_id: [] for s in steps}

        for s in steps:
            for dep in s.depends_on:
                if dep not in step_map:
                    raise ValueError(f"Step '{s.step_id}' depends on non-existent step '{dep}'")
                adj[dep].append(s.step_id)
                in_degree[s.step_id] += 1

        queue = deque([sid for sid, deg in in_degree.items() if deg == 0])
        sorted_steps = []

        while queue:
            curr_id = queue.popleft()
            sorted_steps.append(step_map[curr_id])
            for neighbor in adj[curr_id]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(sorted_steps) != len(steps):
            raise ValueError("Dependency cycle detected in ExecutionDAG steps.")

        return sorted_steps

    def create_t0_snapshot(self, snapshot_tag: str, target_paths: List[str]) -> Tuple[Path, Dict[str, bool]]:
        """
        Create a real T₀ filesystem backup in ciph_backups/.
        Returns (snap_dir, existence_map) tracking which files existed before execution.
        """
        snap_dir = self.backups_dir / snapshot_tag
        snap_dir.mkdir(parents=True, exist_ok=True)
        existence_map: Dict[str, bool] = {}

        for p_str in target_paths:
            p = Path(p_str)
            existed = p.exists()
            existence_map[p_str] = existed

            if existed:
                # Store by sanitized path string to avoid basename collision
                safe_rel_name = p_str.replace("/", "___").replace("\\", "___")
                dest = snap_dir / safe_rel_name
                if p.is_file():
                    shutil.copy2(p, dest)
                elif p.is_dir():
                    shutil.copytree(p, dest, dirs_exist_ok=True)

        return snap_dir, existence_map

    def restore_t0_snapshot(self, snapshot_tag: str, target_paths: List[str], existence_map: Optional[Dict[str, bool]] = None) -> None:
        """
        Restore files from ciph_backups/ and purge newly created dirty files upon failure.
        """
        snap_dir = self.backups_dir / snapshot_tag
        if not snap_dir.exists():
            return

        existence_map = existence_map or {}

        for p_str in target_paths:
            p = Path(p_str)
            existed = existence_map.get(p_str, True)
            safe_rel_name = p_str.replace("/", "___").replace("\\", "___")
            src = snap_dir / safe_rel_name

            if existed and src.exists():
                if src.is_file():
                    shutil.copy2(src, p)
                elif src.is_dir():
                    shutil.copytree(src, p, dirs_exist_ok=True)
            elif not existed and p.exists():
                # File was created during failed run -> purge to restore clean pre-run state
                if p.is_file():
                    p.unlink()
                elif p.is_dir():
                    shutil.rmtree(p)

    def execute_dag(self, dag: ExecutionDAG, target_backup_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Execute all steps in strict topological dependency order.
        Returns detailed summary of executed steps and overall status.
        """
        executed_steps: Dict[str, ExecutionReceipt] = {}
        executed_compensations: List[Tuple[str, Dict[str, Any]]] = []
        overall_success = True
        error_details = None

        # 1. Topological Sort
        try:
            sorted_steps = self.topological_sort(dag.steps)
        except ValueError as e:
            return {
                "plan_id": dag.plan_id,
                "objective": dag.objective,
                "success": False,
                "error": str(e),
                "executed_steps_count": 0,
                "total_steps_count": len(dag.steps),
                "step_receipts": {},
                "rollback_snapshot_id": None
            }

        # 2. Create Real T₀ Snapshot if REVERSIBLE steps exist and paths are provided
        has_reversible = any(s.reversibility == ReversibilityClass.REVERSIBLE for s in sorted_steps)
        snapshot_tag = None
        backup_paths = target_backup_paths or []
        existence_map: Dict[str, bool] = {}
        if has_reversible and backup_paths:
            snapshot_tag = f"snap_{dag.plan_id}_{int(time.time())}"
            dag.rollback_snapshot_id = snapshot_tag
            _, existence_map = self.create_t0_snapshot(snapshot_tag, backup_paths)

        # 3. Execute Steps
        for step in sorted_steps:
            # Verify dependencies succeeded
            for dep_id in step.depends_on:
                if dep_id not in executed_steps or executed_steps[dep_id].exit_code != 0:
                    overall_success = False
                    error_details = f"Dependency '{dep_id}' failed for step '{step.step_id}'"
                    break
            if not overall_success:
                break

            # Resolve parameter references like $S1.results.domain
            resolved_params = self._resolve_parameters(step.parameters, executed_steps)

            cap = self.registry.get(step.capability)
            if not cap:
                overall_success = False
                error_details = f"Capability '{step.capability}' not found in registry."
                break

            context = {
                "job_id": f"JOB-{dag.plan_id}-{step.step_id}",
                "plan_id": dag.plan_id,
                "step_id": step.step_id,
                "idempotency_key": step.idempotency_key or f"idemp_{dag.plan_id}_{step.step_id}"
            }
            receipt = cap.execute(resolved_params, context)
            executed_steps[step.step_id] = receipt

            # Record compensation if declared
            if step.compensation_action and receipt.exit_code == 0:
                comp_params = self._resolve_parameters(step.compensation_params or {}, executed_steps)
                executed_compensations.append((step.compensation_action, comp_params))

            # Validate success condition using safe AST evaluator
            eval_context = {
                "exit_code": receipt.exit_code,
                "results": receipt.results,
                "outcome": receipt.outcome.value
            }
            condition_passed = evaluate_success_condition(step.success_condition, eval_context)

            if receipt.exit_code != 0 or not condition_passed:
                overall_success = False
                error_details = f"Step '{step.step_id}' failed. Exit code: {receipt.exit_code}, Condition '{step.success_condition}' passed: {condition_passed}"
                break

        # 4. Handle Failure: Real T₀ Rollback and/or Compensations
        if not overall_success:
            if snapshot_tag and backup_paths:
                self.restore_t0_snapshot(snapshot_tag, backup_paths, existence_map)
            self._handle_failure_remediation(executed_compensations)

        return {
            "plan_id": dag.plan_id,
            "objective": dag.objective,
            "success": overall_success,
            "executed_steps_count": len(executed_steps),
            "total_steps_count": len(dag.steps),
            "error": error_details,
            "step_receipts": {sid: r.to_dict() for sid, r in executed_steps.items()},
            "rollback_snapshot_id": snapshot_tag
        }

    def _resolve_parameters(
        self,
        params: Dict[str, Any],
        executed_steps: Dict[str, ExecutionReceipt]
    ) -> Dict[str, Any]:
        """Resolves references like '$step_id.results.key' in parameter dictionaries."""
        resolved = {}
        for k, v in params.items():
            if isinstance(v, str) and v.startswith("$"):
                parts = v[1:].split(".")
                step_id = parts[0]
                if step_id in executed_steps and len(parts) > 1:
                    target_obj = executed_steps[step_id].results
                    for subkey in parts[2:]:
                        if isinstance(target_obj, dict):
                            target_obj = target_obj.get(subkey)
                    resolved[k] = target_obj
                else:
                    resolved[k] = v
            else:
                resolved[k] = v
        return resolved

    def _handle_failure_remediation(
        self,
        compensations: List[Tuple[str, Dict[str, Any]]]
    ):
        """Execute registered inverse compensations in reverse order."""
        for comp_action, comp_params in reversed(compensations):
            cap = self.registry.get(comp_action)
            if cap:
                try:
                    cap.execute(comp_params, {"is_compensation": True})
                except Exception:
                    pass
