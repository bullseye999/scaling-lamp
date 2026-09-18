"""
ciph.maintenance.engine - Phase 9 Idle Maintenance Engine.
Orchestrates durable quiescence detection, atomic exclusive lease management,
background signed heartbeat renewal, and execution of routine maintenance tasks 1-6.
"""

import os
import time
import uuid
import json
import sqlite3
import threading
import inspect
import ast
from typing import Optional, Tuple, Dict, Any, List

from ciph.maintenance.exclusion import (
    SharedExclusionCoordinator,
    MaintenanceInProgressError,
)
from ciph.memory.event_store import EventStore
from ciph.memory.claim_leases import ClaimLeaseManager
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.capabilities.capability_ledger import CapabilityLedger


class IdleDetector:
    """
    Evaluates the 5 durable SQLite quiescence criteria:
    1. ciph_ipc_jobs: zero jobs in ('QUEUED', 'LEASED', 'EXECUTING')
    2. ciph_curiosity_questions: zero questions with status == 'SEARCHING'
    3. ciph_curiosity_attempts: zero attempts with status == 'RESERVED'
    4. ciph_phase8_canary_state: zero active canaries with in_flight IS NOT NULL
    5. Quiescence window: >= quiescence_window_seconds elapsed since last completed job/event
    """

    def __init__(self, db_path: str = "ciph_vault.db", quiescence_window_seconds: float = 10.0):
        self.db_path = db_path
        self.quiescence_window_seconds = quiescence_window_seconds

    def is_idle(self) -> Tuple[bool, str]:
        """Returns (True, 'IDLE') if all criteria indicate system is quiescent, else (False, reason)."""
        now = time.time()
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
            # 1. Active IPC jobs
            try:
                cur = conn.execute("SELECT COUNT(*) FROM ciph_ipc_jobs WHERE status = 'QUEUED' OR status = 'EXECUTING' OR (status = 'LEASED' AND (lease_expires_at IS NULL OR lease_expires_at >= ?));", (now,))
                if cur.fetchone()[0] > 0:
                    return False, "ACTIVE_WORK_IN_PROGRESS"
            except sqlite3.OperationalError as ex:
                if "no such table" not in str(ex):
                    return False, f"STORAGE_ERROR_{type(ex).__name__}"

            # 2. Curiosity searching questions
            try:
                cur = conn.execute("SELECT COUNT(*) FROM ciph_curiosity_questions WHERE json_extract(payload, '$.status') = 'SEARCHING';")
                if cur.fetchone()[0] > 0:
                    return False, "CURIOSITY_ACTIVE"
            except sqlite3.OperationalError as ex:
                if "no such table" not in str(ex):
                    return False, f"STORAGE_ERROR_{type(ex).__name__}"

            # 3. Curiosity reserved attempts
            try:
                cur = conn.execute("SELECT COUNT(*) FROM ciph_curiosity_attempts WHERE json_extract(payload, '$.status') = 'RESERVED';")
                if cur.fetchone()[0] > 0:
                    return False, "CURIOSITY_RESERVED"
            except sqlite3.OperationalError as ex:
                if "no such table" not in str(ex):
                    return False, f"STORAGE_ERROR_{type(ex).__name__}"

            # 4. In-flight canaries
            try:
                cur = conn.execute("SELECT COUNT(*) FROM ciph_phase8_canary_state WHERE json_extract(payload, '$.in_flight') IS NOT NULL;")
                if cur.fetchone()[0] > 0:
                    return False, "CANARY_IN_FLIGHT"
            except sqlite3.OperationalError as ex:
                if "no such table" not in str(ex):
                    return False, f"STORAGE_ERROR_{type(ex).__name__}"

            # 5. Durable quiescence window check (COALESCE for empty history)
            try:
                cur = conn.execute("""
                    SELECT COALESCE(MAX(ts), 0.0) FROM (
                        SELECT MAX(completed_at) AS ts FROM ciph_ipc_jobs
                        UNION ALL
                        SELECT MAX(timestamp) AS ts FROM ciph_event_store
                    );
                """)
                max_ts = cur.fetchone()[0] or 0.0
                if max_ts > 0.0 and (now - max_ts) < self.quiescence_window_seconds:
                    return False, "QUIESCENCE_WINDOW_ACTIVE"
            except sqlite3.OperationalError as ex:
                if "no such table" not in str(ex):
                    return False, f"STORAGE_ERROR_{type(ex).__name__}"

        return True, "IDLE"


class IdleMaintenanceEngine:
    """
    Phase 9 Idle Maintenance Engine.
    Executes Tasks 1-6 sequentially within a 120s cycle budget, maintaining an
    active signed operator heartbeat and appending lifecycle audit events.
    Raw evidence is strictly immutable; maintenance never erases raw evidence.
    """

    DEFAULT_LEASE_NAME = "global_db_maintenance"

    def __init__(
        self,
        db_path: str = "ciph_vault.db",
        trust_registry: Optional[Any] = None,
        registry: Optional[Any] = None,
        operator_key_id: str = "operator_primary",
        operator_secret_key: Optional[bytes] = None,
        dependency_evidence_map: Optional[Dict[str, Any]] = None,
        quiescence_window_seconds: float = 10.0,
        cycle_budget_seconds: float = 120.0,
        task_timeout_seconds: float = 30.0,
        lease_ttl_seconds: int = 30,
        heartbeat_interval_seconds: float = 10.0,
    ):
        self.db_path = db_path
        self.trust_registry = trust_registry
        self.operator_key_id = operator_key_id
        self.operator_secret_key = operator_secret_key
        self.dependency_evidence_map = dependency_evidence_map
        self.quiescence_window_seconds = quiescence_window_seconds
        self.cycle_budget_seconds = cycle_budget_seconds
        self.task_timeout_seconds = task_timeout_seconds
        self.lease_ttl_seconds = lease_ttl_seconds
        self.heartbeat_interval_seconds = heartbeat_interval_seconds

        self.coordinator = SharedExclusionCoordinator(self.db_path, trust_registry=self.trust_registry)
        self.event_store = EventStore(self.db_path)
        self.idle_detector = IdleDetector(self.db_path, quiescence_window_seconds=self.quiescence_window_seconds)

        from ciph.capabilities.registry import CapabilityRegistry
        self.registry = registry if registry is not None else CapabilityRegistry()

        self._heartbeat_failed = False
        self.compiled_ledger_cache = None

    def _heartbeat_loop(self, stop_event: threading.Event, cycle_id: str):
        """Background thread extending exclusive lease TTL with fresh operator signatures."""
        while not stop_event.wait(self.heartbeat_interval_seconds):
            try:
                renewed = self.coordinator.renew_lease(
                    lease_name=self.DEFAULT_LEASE_NAME,
                    holder_id=self.operator_key_id,
                    operator_secret_key=self.operator_secret_key,
                    cycle_id=cycle_id,
                    extension_seconds=self.lease_ttl_seconds,
                    task_name="HEARTBEAT"
                )
                if not renewed:
                    self._heartbeat_failed = True
                    break
            except Exception:
                self._heartbeat_failed = True
                break

    def _task1_event_integrity(self, cycle_id: str) -> Dict[str, Any]:
        """Task 1: Re-verify cryptographic event chain integrity via bounded row streaming."""
        valid, bad_id = self.event_store.verify_integrity()
        return {
            "task_name": "TASK1_EVENT_INTEGRITY",
            "success": valid,
            "metrics": {
                "chain_valid": valid,
                "first_corrupted_id": bad_id
            }
        }

    def _task2_hardened_scavenger(self, cycle_id: str) -> Dict[str, Any]:
        """Task 2: Hardened Scavenger: Scavenge expired IPC job leases and claim leases."""
        ipc_queue = IPCJobQueue(self.db_path, trust_registry=self.trust_registry)
        reclaimed_jobs = ipc_queue.reclaim_expired_leases(calling_holder_id=self.operator_key_id)

        claim_mgr = ClaimLeaseManager(self.db_path)
        reclaimed_claims = claim_mgr.cleanup_expired_leases(calling_holder_id=self.operator_key_id)

        return {
            "task_name": "TASK2_HARDENED_SCAVENGER",
            "success": True,
            "metrics": {
                "reclaimed_job_leases": reclaimed_jobs,
                "reclaimed_claim_leases": reclaimed_claims
            }
        }

    def _task3_safe_db_maintenance(self, cycle_id: str) -> Dict[str, Any]:
        """Task 3: Safe Database Maintenance: Execute routine non-blocking WAL PASSIVE checkpoint and optimize."""
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            cur = conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
            row = cur.fetchone()
            busy, log_frames, checkpointed = row if row else (0, 0, 0)
            conn.execute("PRAGMA optimize;")

        return {
            "task_name": "TASK3_SAFE_DB_MAINTENANCE",
            "success": True,
            "metrics": {
                "mode": "PASSIVE",
                "busy": busy,
                "log_frames": log_frames,
                "checkpointed_frames": checkpointed,
                "optimized": True
            }
        }

    def _task4_ledger_cache_compilation(
        self,
        cycle_id: str,
        dependency_evidence_map: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Task 4: Capability Ledger Cache Compilation: Compile empirical ledger profiles and checkpoint."""
        dep_map = dict(self.dependency_evidence_map or {})
        if dependency_evidence_map:
            dep_map.update(dependency_evidence_map)
        else:
            # Generate bounded static dependency evidence for registered capabilities
            from ciph.capabilities.capability_ledger import StaticDependencyInspector, generate_environment_fingerprint
            cur_env = generate_environment_fingerprint()
            now_t = time.time()
            if self.registry and hasattr(self.registry, "list_manifests"):
                for manifest in self.registry.list_manifests():
                    if manifest.name not in dep_map:
                        declared = getattr(manifest, "declared_modules", ())
                        dep_map[manifest.name] = StaticDependencyInspector.check_declared_modules(
                            manifest.name, declared, cur_env, checked_at=now_t
                        )

        ledger = CapabilityLedger(
            self.event_store,
            registry=self.registry,
            worker_secret_key=None,
            trust_registry=self.trust_registry,
            db_path=self.db_path
        )
        profiles, checkpoint = ledger.compile_empirical_ledger(dependency_evidence_map=dep_map)
        self.compiled_ledger_cache = (profiles, checkpoint)

        verified_active = sum(1 for p in profiles.values() if getattr(p.health_status, "value", p.health_status) == "VERIFIED_ACTIVE")
        untested = sum(1 for p in profiles.values() if getattr(p.health_status, "value", p.health_status) == "UNTESTED")
        degraded = sum(1 for p in profiles.values() if getattr(p.health_status, "value", p.health_status) in ("DEGRADED", "OPERATIONAL_DEGRADED", "FAILING"))
        conflicted = sum(1 for p in profiles.values() if getattr(p.health_status, "value", p.health_status) == "INTEGRITY_CONFLICT")

        return {
            "task_name": "TASK4_LEDGER_CACHE_COMPILATION",
            "success": checkpoint.verification_status in ("VERIFIED_COMPLETE", "VERIFIED_EMPTY"),
            "metrics": {
                "total_capabilities_tracked": len(profiles),
                "verified_active_count": verified_active,
                "untested_count": untested,
                "degraded_count": degraded,
                "conflicted_count": conflicted,
                "verification_status": checkpoint.verification_status,
                "dependency_blind": len(dep_map) == 0,
                "dependency_evidence_count": len(dep_map)
            }
        }

    def _task5_stale_hypothesis_expiry(self, cycle_id: str) -> Dict[str, Any]:
        """Task 5: Worldview Stale Hypothesis Expiry: Transition expired active claims to STALE without refutation."""
        now = time.time()
        transitioned = 0
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            try:
                cur = conn.execute("""
                    UPDATE ciph_active_claims
                    SET state = 'STALE', updated_at = ?
                    WHERE lifecycle_state = 'ACTIVE'
                      AND state NOT IN ('REFUTED', 'SUPERSEDED', 'STALE')
                      AND freshness_deadline IS NOT NULL
                      AND freshness_deadline <= ?;
                """, (now, now))
                transitioned = cur.rowcount
                conn.commit()
            except sqlite3.OperationalError as ex:
                if "no such table" in str(ex):
                    pass
                else:
                    return {
                        "task_name": "TASK5_STALE_HYPOTHESIS_EXPIRY",
                        "success": False,
                        "metrics": {"stale_claims_transitioned": 0},
                        "error": str(ex)
                    }

        return {
            "task_name": "TASK5_STALE_HYPOTHESIS_EXPIRY",
            "success": True,
            "metrics": {
                "stale_claims_transitioned": transitioned
            }
        }

    def _task6_static_ast_audit(self, cycle_id: str) -> Dict[str, Any]:
        """Task 6: Static AST Dependency Audit: Inspect capability source code without importing untrusted modules."""
        from ciph.capabilities.evolution import HotReloadEngine
        auditor = HotReloadEngine()

        diagnostics: Dict[str, Any] = {}
        overall_safety = True
        total_audited = 0

        # 1. Audit registered capabilities if registry is available
        if self.registry and hasattr(self.registry, "_capabilities"):
            for cap_name, cap_obj in self.registry._capabilities.items():
                try:
                    cls = cap_obj.__class__
                    src_file = inspect.getsourcefile(cls)
                    if src_file and os.path.exists(src_file):
                        with open(src_file, "r", encoding="utf-8") as f:
                            code = f.read()
                    else:
                        code = inspect.getsource(cls)
                    safe, errors = auditor.audit_code_safety(code)
                    diagnostics[cap_name] = {"safe": safe, "errors": errors}
                    if not safe:
                        overall_safety = False
                    total_audited += 1
                except Exception as ex:
                    diagnostics[cap_name] = {"safe": False, "errors": [str(ex)]}
                    overall_safety = False
                    total_audited += 1

        # 2. If registry empty or none, scan standard capabilities directory
        if total_audited == 0:
            caps_dir = os.path.join(os.path.dirname(__file__), "..", "capabilities")
            if os.path.exists(caps_dir):
                for fname in sorted(os.listdir(caps_dir)):
                    if fname.endswith(".py") and not fname.startswith("__"):
                        fpath = os.path.join(caps_dir, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                code = f.read()
                            safe, errors = auditor.audit_code_safety(code)
                            diagnostics[fname] = {"safe": safe, "errors": errors}
                            if not safe:
                                overall_safety = False
                            total_audited += 1
                        except Exception as ex:
                            diagnostics[fname] = {"safe": False, "errors": [str(ex)]}
                            overall_safety = False
                            total_audited += 1

        return {
            "task_name": "TASK6_STATIC_AST_AUDIT",
            "success": overall_safety,
            "metrics": {
                "capabilities_audited": total_audited,
                "safety_passed": overall_safety,
                "diagnostics": diagnostics
            }
        }

    def run_cycle(
        self,
        bypass_idle_checks: bool = False,
        dependency_evidence_map: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes an authenticated maintenance cycle under the exclusive lease.
        """
        # 1. Idle detection
        if not bypass_idle_checks:
            idle, reason = self.idle_detector.is_idle()
            if not idle:
                return {
                    "success": False,
                    "status": "NOT_IDLE",
                    "reason": reason
                }

        # 2. Acquire exclusive lease
        cycle_id = f"cycle_{uuid.uuid4().hex[:12]}"
        acquired, acq_reason, cid = self.coordinator.acquire_lease(
            lease_name=self.DEFAULT_LEASE_NAME,
            holder_id=self.operator_key_id,
            operator_secret_key=self.operator_secret_key,
            ttl_seconds=self.lease_ttl_seconds,
            cycle_id=cycle_id,
            bypass_idle_checks=bypass_idle_checks,
            quiescence_window_seconds=self.quiescence_window_seconds
        )
        if not acquired:
            return {
                "success": False,
                "status": f"ACQUISITION_FAILED_{acq_reason}",
                "reason": acq_reason
            }

        started_at = time.time()
        self._heartbeat_failed = False  # Reset per cycle to enable transient recovery
        stop_heartbeat = threading.Event()
        heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(stop_heartbeat, cycle_id),
            daemon=True
        )
        heartbeat_thread.start()

        task_results = []
        overall_success = True
        aborted_status = None
        timed_out = False

        try:
            # 3. Record MaintenanceCycleStartedEvent
            self.event_store.append_event(
                event_type="MaintenanceCycleStartedEvent",
                aggregate_id=f"maintenance:{cycle_id}",
                payload={
                    "cycle_id": cycle_id,
                    "holder_id": self.operator_key_id,
                    "started_at": started_at,
                    "planned_tasks": [
                        "TASK1_EVENT_INTEGRITY",
                        "TASK2_HARDENED_SCAVENGER",
                        "TASK3_SAFE_DB_MAINTENANCE",
                        "TASK4_LEDGER_CACHE_COMPILATION",
                        "TASK5_STALE_HYPOTHESIS_EXPIRY",
                        "TASK6_STATIC_AST_AUDIT"
                    ]
                },
                calling_holder_id=self.operator_key_id
            )

            tasks = [
                ("TASK1_EVENT_INTEGRITY", self._task1_event_integrity),
                ("TASK2_HARDENED_SCAVENGER", self._task2_hardened_scavenger),
                ("TASK3_SAFE_DB_MAINTENANCE", self._task3_safe_db_maintenance),
                ("TASK4_LEDGER_CACHE_COMPILATION", lambda cid: self._task4_ledger_cache_compilation(cid, dependency_evidence_map=dependency_evidence_map)),
                ("TASK5_STALE_HYPOTHESIS_EXPIRY", self._task5_stale_hypothesis_expiry),
                ("TASK6_STATIC_AST_AUDIT", self._task6_static_ast_audit),
            ]

            for t_name, t_fn in tasks:
                t_start = time.time()

                # Check heartbeat health & lease validity
                active_lease = self.coordinator.get_active_lease(self.DEFAULT_LEASE_NAME)
                if self._heartbeat_failed or not active_lease or active_lease.get("cycle_id") != cycle_id:
                    overall_success = False
                    aborted_status = "ABORTED_LEASE_LOST"
                    res = {
                        "task_name": t_name,
                        "success": False,
                        "status": "ABORTED_LEASE_LOST",
                        "duration_seconds": 0.0,
                        "metrics": {},
                        "error": "Maintenance lease lost or heartbeat renewal failed."
                    }
                    task_results.append(res)
                    break

                # Check cycle budget
                if (t_start - started_at) > self.cycle_budget_seconds:
                    overall_success = False
                    aborted_status = "SKIPPED_CYCLE_BUDGET_EXCEEDED"
                    res = {
                        "task_name": t_name,
                        "success": False,
                        "status": "SKIPPED_CYCLE_BUDGET_EXCEEDED",
                        "duration_seconds": 0.0,
                        "metrics": {},
                        "error": "Cycle budget exceeded."
                    }
                    task_results.append(res)
                    break

                # Execute task with timeout enforcement
                task_container: Dict[str, Any] = {}

                def _run_target():
                    try:
                        task_container["result"] = t_fn(cycle_id)
                    except Exception as ex:
                        task_container["exception"] = ex

                t_thread = threading.Thread(target=_run_target, daemon=True)
                t_thread.start()
                t_thread.join(timeout=self.task_timeout_seconds)
                t_duration = time.time() - t_start

                if t_thread.is_alive():
                    overall_success = False
                    aborted_status = "FAILED_TIMEOUT"
                    timed_out = True
                    res = {
                        "task_name": t_name,
                        "success": False,
                        "status": "FAILED_TIMEOUT",
                        "duration_seconds": t_duration,
                        "metrics": {},
                        "error": f"Task timed out after {self.task_timeout_seconds}s"
                    }
                    task_results.append(res)
                    break
                elif "exception" in task_container:
                    overall_success = False
                    res = {
                        "task_name": t_name,
                        "success": False,
                        "status": "FAILED",
                        "duration_seconds": t_duration,
                        "metrics": {},
                        "error": str(task_container["exception"])
                    }
                    task_results.append(res)
                else:
                    t_res = task_container["result"]
                    t_res["duration_seconds"] = t_duration
                    t_res["status"] = "SUCCESS" if t_res.get("success", False) else "FAILED"
                    if not t_res.get("success", False):
                        overall_success = False
                    task_results.append(t_res)

                # Record MaintenanceTaskExecutedEvent
                latest_res = task_results[-1]
                self.event_store.append_event(
                    event_type="MaintenanceTaskExecutedEvent",
                    aggregate_id=f"maintenance:{cycle_id}:{t_name}",
                    payload={
                        "cycle_id": cycle_id,
                        "task_name": t_name,
                        "status": latest_res.get("status"),
                        "duration_seconds": latest_res.get("duration_seconds", 0.0),
                        "metrics": latest_res.get("metrics", {}),
                        "error": latest_res.get("error")
                    },
                    calling_holder_id=self.operator_key_id
                )

            # 4. Record MaintenanceCycleCompletedEvent
            completed_at = time.time()
            total_duration = completed_at - started_at
            if aborted_status:
                status_str = aborted_status
            elif overall_success:
                status_str = "COMPLETED"
            else:
                status_str = "FAILED"

            self.event_store.append_event(
                event_type="MaintenanceCycleCompletedEvent",
                aggregate_id=f"maintenance:{cycle_id}",
                payload={
                    "cycle_id": cycle_id,
                    "holder_id": self.operator_key_id,
                    "completed_at": completed_at,
                    "duration_seconds": total_duration,
                    "status": status_str,
                    "tasks": {r["task_name"]: r for r in task_results}
                },
                calling_holder_id=self.operator_key_id
            )

            return {
                "success": overall_success,
                "status": status_str,
                "cycle_id": cycle_id,
                "holder_id": self.operator_key_id,
                "duration_seconds": total_duration,
                "task_results": task_results
            }

        finally:
            stop_heartbeat.set()
            heartbeat_thread.join(timeout=2.0)
            # If a task timed out, do not release lease early to allow thread to die without racing external writers
            if not timed_out:
                self.coordinator.release_lease(
                    lease_name=self.DEFAULT_LEASE_NAME,
                    holder_id=self.operator_key_id,
                    cycle_id=cycle_id
                )
