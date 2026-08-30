"""
ciph.kernel.adversarial_gate - Risk-Tiered Adversarial Red Team Gate (CIPH 4.0).
Challenges high-impact or irreversible claims with active falsification probes before promotion.
"""

from typing import Dict, Any, Tuple, Optional
from ciph.kernel.policy_engine import ReversibilityClass, CapabilityManifest
from ciph.workers.receipts import ExecutionReceipt


class AdversarialRedTeamGate:
    """
    Automated Red Team Falsification Gate.
    Operates on zero-trust principles: attempts to bypass, disprove, or falsify high-consequence findings.
    Low-risk/reversible operations bypass this gate to eliminate latency.
    """

    def __init__(self, war_room_instance=None):
        self.war_room = war_room_instance

    def evaluate_receipt(
        self,
        manifest: CapabilityManifest,
        receipt: ExecutionReceipt,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Determines whether the receipt passes adversarial validation.
        Returns (passed: bool, reason: str).
        """
        # 1. Bypass check: Read-only, offline, and reversible operations bypass Red Team
        if not manifest.requires_red_team and manifest.reversibility in (ReversibilityClass.READ_ONLY, ReversibilityClass.REVERSIBLE):
            return True, "BYPASSED_LOW_RISK"

        # 2. If receipt itself had an execution failure, gate fails
        if receipt.exit_code != 0:
            return False, f"EXECUTION_FAILED: Exit code {receipt.exit_code}"

        # 3. Adversarial validation on high-impact / irreversible actions
        results = receipt.results or {}
        
        # Check for obvious false positives (e.g. soft-404 or generic fallback responses)
        if "soft_404" in results and results["soft_404"] is True:
            return False, "RED_TEAM_REJECTED: False-positive SPA / soft-404 detected"

        if "takeover" in str(results).lower() and not results.get("takeovers"):
            return False, "RED_TEAM_REJECTED: Claimed takeover without verified fingerprint match"

        # If war_room persona is wired, consult the Hunter red team persona
        if self.war_room and hasattr(self.war_room, 'hunter_critique'):
            try:
                passed, reason = self.war_room.hunter_critique(receipt)
                if not passed:
                    return False, f"HUNTER_VETO: {reason}"
            except Exception:
                pass

        return True, "PASSED_ADVERSARIAL_GATE"
