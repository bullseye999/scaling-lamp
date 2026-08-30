"""
ciph.operator.dialogue_formatter - Epistemically Tagged Dialogue Protocol (CIPH 4.0).
Demarcates facts, observations, inferences, hypotheses, recommendations, and unknowns clearly.
"""

from typing import Dict, Any, List, Optional
from ciph.workers.receipts import ExecutionReceipt
from ciph.kernel.transmutation_dag import TransmutationNode


class DialogueFormatter:
    """
    Renders structured, epistemically honest outputs to the operator.
    Prevents hallucination by making the distinction between verified truth and deductive inference visible.
    """

    REGISTERS = {
        "FACT": "[FACT]",
        "OBSERVATION": "[OBSERVATION]",
        "INFERENCE": "[INFERENCE]",
        "HYPOTHESIS": "[HYPOTHESIS]",
        "RECOMMENDATION": "[RECOMMENDATION]",
        "UNKNOWN": "[UNKNOWN]",
    }

    @classmethod
    def format_entry(
        cls,
        register: str,
        content: str,
        evidence_id: Optional[str] = None,
        assurance: Optional[float] = None
    ) -> str:
        """
        Format a single dialogue line with its epistemic marker and optional evidence/assurance tag.
        """
        tag = cls.REGISTERS.get(register.upper(), f"[{register.upper()}]")
        meta_parts = []
        if evidence_id:
            meta_parts.append(f"Evidence: {evidence_id}")
        if assurance is not None:
            meta_parts.append(f"Assurance: {int(assurance * 100)}%")

        meta_str = f" ({' | '.join(meta_parts)})" if meta_parts else ""
        return f"{tag} {content}{meta_str}"

    @classmethod
    def format_receipt_card(cls, receipt: ExecutionReceipt) -> str:
        """Render a verified execution receipt into a clean terminal card."""
        status_symbol = "✅" if receipt.exit_code == 0 else "❌"
        duration_s = round(receipt.completed_at - receipt.started_at, 2)
        
        lines = [
            f"{status_symbol} [RECEIPT {receipt.receipt_id}] • Capability: {receipt.capability}",
            f"  Target   : {receipt.target or 'local_system'}",
            f"  Outcome  : {receipt.outcome.value} (Exit: {receipt.exit_code}, Duration: {duration_s}s)",
            f"  Transport: {receipt.actual_transport_used} (Idempotency: {receipt.idempotency_key[:10]}...)",
        ]
        if receipt.error_message:
            lines.append(f"  Error    : {receipt.error_message}")
        return "\n".join(lines)

    @classmethod
    def format_worldview_briefing(cls, active_claims: List[TransmutationNode]) -> str:
        """Render a high-level briefing card from verified active claims."""
        if not active_claims:
            return "‖ Worldview: 0 active claims on record. ‖"

        lines = [f"🏛️ ACTIVE VERIFIED WORLDVIEW ({len(active_claims)} Claims):"]
        for c in active_claims[:10]:
            state_tag = f"[{c.state.value}]"
            assure_tag = f"({int(c.assurance_score * 100)}%)"
            lines.append(f"  • {c.subject} -> {c.predicate}: {c.value} {state_tag} {assure_tag}")
        return "\n".join(lines)
