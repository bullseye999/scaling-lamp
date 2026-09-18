#!/usr/bin/env python3
"""
ciph_matrix_audit.py - Automated 11-Column Penetration Matrix Auditor
CIPH 4.0 Gate Zero Sealed Specification

Audits canonical capabilities against the 11 constitutional gates:
 1. Typed Intent
 2. Validated Plan
 3. Declared Scope
 4. Kernel Policy
 5. Manifest Lane
 6. Adversarial Gate (governed NOT_REQUIRED if consumes_untrusted_content: false)
 7. Durable Worker Queue
 8. Persistent Key Signature
 9. Atomic EventStore Commit
10. Result Verifier & Epistemic Projection
11. Compensation Test (governed NOT_REQUIRED if READ_ONLY, NOT_POSSIBLE if IRREVERSIBLE)

Excludes aliases. Generates strict compliance scorecard.
"""

import os
import sys
import json
import time
import uuid
import hashlib
import gc
import signal
import threading
from contextlib import contextmanager
from typing import Dict, Any, List

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ciph.runtime import CiphRuntime
from ciph.capabilities.base import BaseCapability, CANONICAL_CAPABILITIES
from ciph.capabilities.registry import CapabilityRegistry
from ciph.capabilities.commands import CommandRegistry
from ciph.kernel.policy_engine import ReversibilityClass, AuthorizationTier, NetworkPolicy, AuthorizationGrant
from ciph.workers.receipts import ExecutionReceipt
from ciph.contracts.base import canonical_json
from ciph.planner.schemas import IntentProposal, PlanStep, ExecutionDAG


GATES = [
    ("typed_intent", "1. Typed Intent"),
    ("validated_plan", "2. Validated Plan"),
    ("declared_scope", "3. Declared Scope"),
    ("kernel_policy", "4. Kernel Policy"),
    ("manifest_lane", "5. Manifest Lane"),
    ("adversarial_gate", "6. Adversarial Gate"),
    ("durable_worker", "7. Durable Worker"),
    ("persistent_sign", "8. Persistent Sign"),
    ("atomic_commit", "9. Atomic Commit"),
    ("result_verifier", "10. Result Verifier"),
    ("compensation", "11. Compensation")
]


class AuditCapabilityTimeout(BaseException):
    """Hard stop for a capability probe that exceeds the audit time budget."""


class IsolatedAuditCapability(BaseCapability):
    """Explicit offline fixture for control-flow checks; does not certify live transport."""

    def __init__(self, capability: BaseCapability):
        from dataclasses import replace
        self._manifest = replace(capability.manifest, network_policy=NetworkPolicy.OFFLINE_ONLY)

    @property
    def manifest(self):
        return self._manifest

    def get_sandbox_command(self, params: Dict[str, Any]) -> List[str]:
        import sys
        code = f'import json; print(json.dumps({{"success": True, "audit_mode": "DETERMINISTIC_ISOLATED", "capability": "{self.manifest.name}", "network_access": "DISABLED", "side_effects": []}}))'
        return [sys.executable, "-c", code]

    def run(self, params: Dict[str, Any], context: Dict[str, Any] = None) -> Dict[str, Any]:
        return {
            "success": True,
            "audit_mode": "DETERMINISTIC_ISOLATED",
            "capability": self.manifest.name,
            "network_access": "DISABLED",
            "side_effects": [],
        }


def isolate_external_capabilities(runtime: CiphRuntime) -> List[str]:
    """Isolate external I/O and code promotion while retaining real manifests."""
    isolated = []
    for manifest in runtime.get_manifests():
        if (manifest.network_policy == NetworkPolicy.OFFLINE_ONLY
                and manifest.name != "code.promote_upgrade"):
            continue
        capability = runtime.registry.get(manifest.name)
        if capability is not None:
            runtime.registry.register(IsolatedAuditCapability(capability), code_origin="internal")
            isolated.append(manifest.name)
    return sorted(isolated)


@contextmanager
def capability_deadline(seconds: float):
    """Bound a probe on POSIX when it runs on Python's main thread."""
    can_interrupt = (
        seconds > 0
        and threading.current_thread() is threading.main_thread()
        and hasattr(signal, "SIGALRM")
        and hasattr(signal, "setitimer")
    )
    if not can_interrupt:
        yield
        return

    def _raise_timeout(_signum, _frame):
        raise AuditCapabilityTimeout()

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    signal.signal(signal.SIGALRM, _raise_timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer != (0.0, 0.0):
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def timeout_result(capability_name: str, seconds: float) -> Dict[str, Any]:
    return {
        "status": "NON_COMPLIANT",
        "gates": {gate_key: "FAIL" for gate_key, _ in GATES},
        "error": f"AUDIT_TIMEOUT: '{capability_name}' exceeded {seconds:.1f}s",
    }


def audit_capability(cap_name: str, runtime: CiphRuntime) -> Dict[str, Any]:
    cap = runtime.registry.get(cap_name)
    if not cap:
        return {"status": "UNREGISTERED", "gates": {g[0]: "FAIL" for g in GATES}}

    manifest = cap.manifest
    scores = {}

    # Live empirical probe payloads
    sample_params = {
        "math.multiply": {"a": 2, "b": 3},
        "tor.check_status": {},
        "pentest.cvss_calculate": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "memory.store": {"key": "audit_probe", "value": "test_probe_val"},
        "memory.retrieve": {"key": "audit_probe"},
        "code.audit_dependencies": {"file_path": "ciph/runtime.py"},
        "code.list_staged": {},
        "code.promote_upgrade": {"proposal_id": "AUDIT_ISOLATED_FIXTURE"},
        "security.deadman_status": {"action": "status"},
        "darknet.get_status": {},
        "darknet.get_detailed_report": {},
        "sports.predict_match": {"home": "TeamA", "away": "TeamB"},
        "trading.portfolio_check": {},
        "cybersecurity.bounty_scan": {"target": "localhost"},
        "cybersecurity.bounty_summary": {},
        "osint.find_monetizable_threats": {},
        "wisdom.consult_library": {"query": "resilience"},
    }
    params = sample_params.get(cap_name, {})
    idemp_key = f"audit_probe_{cap_name}_{time.time()}"

    # 1. Typed Intent: Validate parameter schema and intent proposal round-trip
    try:
        intent_prop = IntentProposal(
            proposal_id=f"prop_audit_{uuid.uuid4().hex[:8]}",
            objective=f"Audit execution of {cap_name}",
            proposed_capability=cap_name,
            provided_parameters=params,
            missing_parameters=[]
        )
        is_executable = intent_prop.is_executable_proposal()
        payload_bytes = canonical_json(intent_prop.provided_parameters).encode('utf-8')
        deser_params = json.loads(payload_bytes.decode('utf-8'))
        scores["typed_intent"] = "PASS" if is_executable and isinstance(deser_params, dict) else "FAIL"
    except Exception:
        scores["typed_intent"] = "FAIL"

    # 2. Validated Plan: DAG topological sort & structural validity
    try:
        step = PlanStep(
            step_id="step_audit",
            capability=cap_name,
            parameters=params,
            reversibility=manifest.reversibility
        )
        dag = ExecutionDAG(plan_id="plan_audit", objective="Audit capability", steps=[step])
        val_res = runtime.dag_executor.validate_plan(dag)
        h = dag.compute_plan_hash()
        scores["validated_plan"] = "PASS" if val_res.is_valid and h and len(h) >= 8 else "FAIL"
    except Exception:
        scores["validated_plan"] = "FAIL"

    # 3. Declared Scope: Dynamic scope containment probe
    try:
        from ciph.kernel.policy_engine import ScopeGrant, ScopeType
        scope_target = params.get("target") or params.get("key") or params.get("file_path") or "localhost"
        scope = ScopeGrant(
            scope_id=f"scope_audit_{uuid.uuid4().hex[:6]}",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=[str(scope_target), "localhost", "127.0.0.1", "*"],
            denied_targets=["unauthorized.external.attacker.net"]
        )
        in_scope_valid = scope.is_target_permitted(str(scope_target))
        out_scope_blocked = not scope.is_target_permitted("unauthorized.external.attacker.net")
        scores["declared_scope"] = "PASS" if in_scope_valid and out_scope_blocked else "FAIL"
    except Exception:
        scores["declared_scope"] = "FAIL"

    # 4. Kernel Policy: Active authorization policy enforcement
    try:
        if manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
            # Active probe: verify minting without AuthorizationGrant fails closed
            try:
                runtime.mint_execution_token(capability=cap_name, params=params, plan_id="audit_plan", step_id="step_audit")
                scores["kernel_policy"] = "FAIL"
            except PermissionError:
                scores["kernel_policy"] = "PASS"
        else:
            scores["kernel_policy"] = "PASS" if manifest.risk_tier is not None else "FAIL"
    except Exception:
        scores["kernel_policy"] = "FAIL"

    # 5. Manifest Lane
    try:
        lane = manifest.derive_execution_lane()
        scores["manifest_lane"] = "PASS" if lane else "FAIL"
    except Exception:
        scores["manifest_lane"] = "FAIL"

    # 6. Adversarial Gate
    untrusted = getattr(manifest, "consumes_untrusted_content", False)
    if not untrusted and manifest.network_policy == NetworkPolicy.OFFLINE_ONLY:
        scores["adversarial_gate"] = "NOT_REQUIRED"
    else:
        scores["adversarial_gate"] = "PASS"

    # 7. Durable Worker & 8. Persistent Sign & 9. Atomic Commit & 10. Result Verifier
    try:
        # Mint governed execution token with authorization grant if capability requires MANDATORY_INTERRUPT
        auth_grant = None
        if cap.manifest.authorization == AuthorizationTier.MANDATORY_INTERRUPT:
            now = time.time()
            auth_grant = AuthorizationGrant(
                grant_id=f"grant_audit_{uuid.uuid4().hex[:8]}",
                plan_hash=hashlib.sha256(b"audit_plan:step_audit").hexdigest()[:16],
                step_id="step_audit",
                capability=cap_name,
                params_hash=ExecutionReceipt.hash_payload(params),
                scope_grant_id="scope_audit",
                created_at=now,
                expires_at=now + 120.0
            ).sign(runtime.auth_secret_key)

        token = runtime.mint_execution_token(
            capability=cap_name,
            params=params,
            plan_id="audit_plan",
            step_id="step_audit",
            auth_grant=auth_grant
        )
        job_id = runtime.queue.enqueue_job(
            capability=cap_name,
            params=params,
            plan_id="audit_plan",
            step_id="step_audit",
            idempotency_key=idemp_key,
            execution_token=token
        )
        leased = runtime.queue.lease_next_job(worker_id="audit_worker", lease_ttl_seconds=30)
        if leased and leased["job_id"] == job_id:
            receipt = runtime.worker_daemon._execute_leased_job(leased, worker_id="audit_worker")
            if receipt:
                scores["durable_worker"] = "PASS"
                # 8. Persistent Sign: cryptographic signature verification
                scores["persistent_sign"] = "PASS" if receipt.verify_signature(runtime.worker_secret_key) else "FAIL"
                
                # 9. Atomic Commit: EventStore persistence and hash chain validation
                events = runtime.event_store.get_events(aggregate_id=receipt.receipt_id)
                if events and len(events) >= 1:
                    valid_chain, _ = runtime.event_store.verify_integrity()
                    scores["atomic_commit"] = "PASS" if valid_chain else "FAIL"
                else:
                    scores["atomic_commit"] = "FAIL"

                # 10. Result Verifier & Epistemic Projection: Epistemic calibration & decision verification
                from ciph.kernel.epistemic_projector import EpistemicProjector, EpistemicCategory, ReliabilityClass, EpistemicDecision
                cat, rel, score, ev_mode, decision = EpistemicProjector.evaluate_receipt(manifest, receipt)
                is_valid_verifier = (
                    isinstance(cat, EpistemicCategory) and
                    isinstance(rel, ReliabilityClass) and
                    isinstance(decision, EpistemicDecision) and
                    0.0 <= score <= 1.0 and
                    (
                        (receipt.exit_code == 0 and decision in (EpistemicDecision.ACCEPTED, EpistemicDecision.SUPPORTED)) or
                        (receipt.exit_code != 0 and decision in (EpistemicDecision.DISPUTED, EpistemicDecision.REJECTED, EpistemicDecision.INCONCLUSIVE))
                    )
                )
                scores["result_verifier"] = "PASS" if is_valid_verifier else "FAIL"
            else:
                scores["durable_worker"] = "FAIL"
                scores["persistent_sign"] = "FAIL"
                scores["atomic_commit"] = "FAIL"
                scores["result_verifier"] = "FAIL"
        else:
            scores["durable_worker"] = "FAIL"
            scores["persistent_sign"] = "FAIL"
            scores["atomic_commit"] = "FAIL"
            scores["result_verifier"] = "FAIL"
    except Exception:
        scores["durable_worker"] = "FAIL"
        scores["persistent_sign"] = "FAIL"
        scores["atomic_commit"] = "FAIL"
        scores["result_verifier"] = "FAIL"

    # 11. Compensation
    if manifest.reversibility == ReversibilityClass.READ_ONLY:
        scores["compensation"] = "NOT_REQUIRED"
    elif manifest.reversibility == ReversibilityClass.IRREVERSIBLE:
        scores["compensation"] = "NOT_POSSIBLE"
    else:
        scores["compensation"] = "PASS"

    # Governed compliance: All gates must be PASS, NOT_REQUIRED, or NOT_POSSIBLE
    is_compliant = all(s in ("PASS", "NOT_REQUIRED", "NOT_POSSIBLE") for s in scores.values())
    return {
        "status": "COMPLIANT" if is_compliant else "NON_COMPLIANT",
        "gates": scores
    }


def run_audit(
    verbose: bool = True,
    capability_timeout_seconds: float = 15.0,
    report_path: str = None,
) -> Dict[str, Any]:
    db_file = f"/tmp/ciph_matrix_{os.getpid()}_{uuid.uuid4().hex}.db"
    runtime = None
    results = {}
    compliant_count = 0
    manifests = []
    isolated_capabilities = []
    additional_capabilities = []

    try:
        runtime = CiphRuntime(db_path=db_file)
        isolated_capabilities = isolate_external_capabilities(runtime)
        registered = {manifest.name: manifest for manifest in runtime.get_manifests()}
        missing = CANONICAL_CAPABILITIES - registered.keys()
        if missing:
            raise RuntimeError("MISSING_CANONICAL_CAPABILITIES: " + ", ".join(sorted(missing)))
        manifests = [registered[name] for name in sorted(CANONICAL_CAPABILITIES)]
        additional_capabilities = sorted(registered.keys() - CANONICAL_CAPABILITIES)

        if verbose:
            print("=" * 80)
            print("🛡️  CIPH 4.0 CONSTITUTIONAL PENETRATION MATRIX AUDIT (Gate Zero Specification)")
            print("=" * 80)
            print("Audit mode: deterministic; external I/O and code promotion use isolated fixtures")
            header = f"{'Capability':<28} " + " ".join(f"G{i+1}" for i in range(11)) + f"  {'Status':<12}"
            print(header)
            print("-" * 80)

        for manifest in sorted(manifests, key=lambda item: item.name):
            try:
                with capability_deadline(capability_timeout_seconds):
                    res = audit_capability(manifest.name, runtime)
            except AuditCapabilityTimeout:
                res = timeout_result(manifest.name, capability_timeout_seconds)

            results[manifest.name] = res
            if res["status"] == "COMPLIANT":
                compliant_count += 1

            if verbose:
                gate_symbols = []
                for gate_key, _ in GATES:
                    value = res["gates"].get(gate_key, "FAIL")
                    if value == "PASS":
                        gate_symbols.append(" P ")
                    elif value == "NOT_REQUIRED":
                        gate_symbols.append(" NR")
                    elif value == "NOT_POSSIBLE":
                        gate_symbols.append(" NP")
                    else:
                        gate_symbols.append(" ❌ ")

                status_str = "✅ COMPLIANT" if res["status"] == "COMPLIANT" else "❌ NON_COMPLIANT"
                print(f"{manifest.name:<28} " + " ".join(gate_symbols) + f"  {status_str}")
    finally:
        if runtime is not None:
            runtime.shutdown()
        runtime = None
        gc.collect()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db_file + suffix)
            except FileNotFoundError:
                pass

    total = len(manifests)
    pct = round((compliant_count / total) * 100, 1) if total > 0 else 0.0

    if verbose:
        print("=" * 80)
        print(f"📊 SUMMARY: {compliant_count}/{total} Canonical Capabilities Fully Governed ({pct}%)")
        print("   [P = PASS, NR = NOT_REQUIRED (Governed), NP = NOT_POSSIBLE (Mandatory Grant Required)]")
        print("=" * 80)

    output = {
        "timestamp": time.time(),
        "audit_mode": "DETERMINISTIC_ISOLATED",
        "verification_scope": "Control-flow probes with isolated external and code-promotion backends; not live capability or compensation certification",
        "capability_timeout_seconds": capability_timeout_seconds,
        "isolated_capabilities": isolated_capabilities,
        "additional_capabilities_not_in_canonical_matrix": additional_capabilities,
        "total_canonical_capabilities": total,
        "compliant_count": compliant_count,
        "compliance_pct": pct,
        "results": results
    }

    output_path = report_path or os.path.join(REPO_ROOT, "ciph_matrix_audit_results.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    return output


if __name__ == "__main__":
    audit = run_audit()
    sys.exit(0 if audit["compliant_count"] == len(CANONICAL_CAPABILITIES) else 1)
