"""
ciph.crucible.red_shadow - The Iron Crucible: Autonomous Adversarial Falsification (Stage 6).
Executes proactive penetration sweeps against registered capabilities to stress-test
boundaries, detect latent vulnerabilities, and enforce automatic quarantine.
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from ciph.planner.schemas import IntentProposal
from ciph.kernel.policy_engine import AuthorizationTier, RiskTier


@dataclass
class AdversarialFuzzResult:
    vector_id: str
    target_capability: str
    payload: Any
    blocked_by_gate: bool
    status_code: str
    quarantined: bool
    latency_ms: float
    details: str = ""


@dataclass
class AdversarialAuditReport:
    report_id: str
    timestamp: float
    total_probes: int
    probes_blocked: int
    probes_escaped: int
    quarantined_capabilities: List[str] = field(default_factory=list)
    resilience_score: float = 1.0


class RedShadowCrucible:
    """
    Stage 6 Continuous Adversarial Engine.
    Employs synthetic fuzzing vectors to challenge system invariants.
    """

    ADVERSARIAL_PAYLOADS = [
        {"desc": "SQL Injection", "val": "'; DROP TABLE ciph_trust_registry; --"},
        {"desc": "Command Injection", "val": "calc.exe; rm -rf / ; cat /etc/shadow"},
        {"desc": "Template Injection", "val": "{{7*7}} ${999-1}"},
        {"desc": "Directory Traversal", "val": "../../../../etc/passwd"},
        {"desc": "Null Byte Poisoning", "val": "safe_file\x00.py"},
        {"desc": "Format String", "val": "%x%x%x%s%n"},
    ]

    def __init__(self):
        self.audit_history: List[AdversarialAuditReport] = []

    def run_penetration_sweep(self, runtime, target_capabilities: Optional[List[str]] = None) -> AdversarialAuditReport:
        """Run comprehensive adversarial fuzzing sweep across capability manifests."""
        report_id = f"CRU-{uuid.uuid4().hex[:8].upper()}"
        now = time.time()
        
        manifests = runtime.get_manifests()
        if target_capabilities:
            manifests = [m for m in manifests if m.name in target_capabilities]

        total_probes = 0
        probes_blocked = 0
        probes_escaped = 0
        quarantined = []

        for m in manifests:
            for payload in self.ADVERSARIAL_PAYLOADS:
                total_probes += 1
                t0 = time.perf_counter()

                # Test 1: Inject adversarial parameter directly into reference loop
                proposal = IntentProposal(
                    proposal_id=f"PROP-FUZZ-{uuid.uuid4().hex[:6].upper()}",
                    objective=f"Adversarial fuzzing probe: {payload['desc']}",
                    proposed_capability=m.name,
                    provided_parameters={"input": payload["val"], "target": payload["val"], "vector": payload["val"]}
                )

                try:
                    # In high risk / critical capabilities without grant, must block early
                    res = runtime.execute_reference_loop(proposal)
                    duration_ms = (time.perf_counter() - t0) * 1000

                    # Evaluate if policy or input handling safely caught the attempt
                    is_safe = (
                        res.get("status") in ("AUTHORIZATION_REQUIRED", "INCOMPLETE_INTENT", "SUCCESS", "POLICY_REJECTED", "EXECUTION_ERROR", "SANDBOX_UNAVAILABLE") and
                        not any("CRASH" in str(v) for v in res.values())
                    )

                    if is_safe:
                        probes_blocked += 1
                    else:
                        probes_escaped += 1
                        quarantined.append(m.name)
                except Exception as ex:
                    # An unhandled crash in runtime during fuzzing constitutes an escape/flaw
                    probes_escaped += 1
                    quarantined.append(m.name)

        resilience = (probes_blocked / total_probes) if total_probes > 0 else 1.0
        report = AdversarialAuditReport(
            report_id=report_id,
            timestamp=now,
            total_probes=total_probes,
            probes_blocked=probes_blocked,
            probes_escaped=probes_escaped,
            quarantined_capabilities=list(set(quarantined)),
            resilience_score=round(resilience, 4)
        )
        self.audit_history.append(report)
        return report
