"""
ciph.kernel.epistemic_projector - Epistemic Projector & Result Verifier.
Enforces the fundamental constitutional invariant: 'Receipt != Truth'.
Decouples raw execution telemetry (ExecutionReceipt) from worldview belief admission.
"""

from typing import Dict, Any, Tuple, Optional
from ciph.kernel.transmutation_dag import EpistemicCategory, TransmutationNode
from ciph.perception.observation import ReliabilityClass
from ciph.workers.receipts import ExecutionReceipt, EvidenceMode, EpistemicDecision
from ciph.kernel.policy_engine import CapabilityManifest, NetworkPolicy


class EpistemicProjector:
    """
    Independent Epistemic Result Verifier.
    Inspects execution receipt results, capability semantics, and failure modes
    to project truthful worldview claims instead of blindly rubber-stamping SUPPORTED.
    """

    PREDICTIVE_CAPABILITIES = {
        "sports.predict_match",
        "trading.portfolio_check",
    }

    INFERENCE_CAPABILITIES = {
        "pentest.cvss_calculate",
        "osint.find_monetizable_threats",
    }

    DIRECT_SENSOR_CAPABILITIES = {
        "tor.check_status",
        "memory.retrieve",
        "memory.store",
        "darknet.get_status",
        "darknet.get_detailed_report",
        "security.deadman_status",
        "wisdom.consult_library",
        "code.list_staged",
        "code.promote_upgrade"
    }

    @classmethod
    def evaluate_receipt(
        cls,
        manifest: CapabilityManifest,
        receipt: ExecutionReceipt
    ) -> Tuple[EpistemicCategory, ReliabilityClass, float, EvidenceMode, EpistemicDecision]:
        """
        Evaluate an execution receipt and determine its epistemic status.
        Returns: (EpistemicCategory, ReliabilityClass, assurance_score, EvidenceMode, EpistemicDecision)
        """
        # Rule 1: Non-zero exit code or execution error is NEVER admitted as SUPPORTED
        if receipt.exit_code != 0 or receipt.outcome.value != "SUCCESS":
            return (
                EpistemicCategory.DISPUTED,
                ReliabilityClass.UNVERIFIED_INCOMING,
                0.20,
                EvidenceMode.SYNTHETIC,
                EpistemicDecision.DISPUTED
            )

        cap = receipt.capability

        # Rule 2: Predictive / Probabilistic capabilities become HYPOTHESIZED or INFERRED
        if cap in cls.PREDICTIVE_CAPABILITIES:
            return (
                EpistemicCategory.HYPOTHESIZED,
                ReliabilityClass.THIRD_PARTY_FEED,
                0.55,
                EvidenceMode.SYNTHETIC,
                EpistemicDecision.ACCEPTED
            )

        # Rule 3: Deterministic models / calculations become INFERRED
        if cap in cls.INFERENCE_CAPABILITIES:
            return (
                EpistemicCategory.INFERRED,
                ReliabilityClass.DIRECT_SENSOR,
                0.80,
                EvidenceMode.SYNTHETIC,
                EpistemicDecision.ACCEPTED
            )

        # Rule 4: Direct local sensory checks
        is_offline = manifest.network_policy in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.LOCAL_ONLY)
        rel = ReliabilityClass.AUTHORITATIVE_LOCAL if is_offline else ReliabilityClass.DIRECT_SENSOR

        # Check if the result indicates unavailable backend or empty mock
        res = receipt.results or {}
        if res.get("connected") is False or res.get("status") in ("UNAVAILABLE", "OFFLINE", "UNREACHABLE"):
            return (
                EpistemicCategory.DISPUTED,
                rel,
                0.40,
                EvidenceMode.REAL,
                EpistemicDecision.DISPUTED
            )

        return (
            EpistemicCategory.SUPPORTED,
            rel,
            0.92 if is_offline else 0.85,
            EvidenceMode.REAL,
            EpistemicDecision.ACCEPTED
        )
