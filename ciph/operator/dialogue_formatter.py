"""
ciph.operator.dialogue_formatter - Epistemically Tagged Dialogue Protocol (CIPH 4.0).
Demarcates facts, observations, inferences, hypotheses, recommendations, and unknowns clearly.
"""

from typing import Dict, Any, List, Optional
from ciph.workers.receipts import ExecutionReceipt
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory


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

    @classmethod
    def format_grounded_response(cls, claim: TransmutationNode) -> str:
        """Format a single claim strictly grounded in its epistemic category and evidence."""
        if not claim.evidence_receipt_ids and claim.state == EpistemicCategory.OBSERVED:
            reg = "UNKNOWN"
        elif claim.state == EpistemicCategory.SUPPORTED:
            reg = "FACT" if claim.assurance_score >= 0.90 else "OBSERVATION"
        elif claim.state == EpistemicCategory.INFERRED:
            reg = "INFERENCE"
        elif claim.state == EpistemicCategory.HYPOTHESIZED:
            reg = "HYPOTHESIS"
        elif claim.state == EpistemicCategory.DISPUTED:
            reg = "UNKNOWN"
        else:
            reg = "OBSERVATION"

        evidence_str = claim.evidence_receipt_ids[0] if claim.evidence_receipt_ids else None
        return cls.format_entry(
            register=reg,
            content=f"{claim.subject} [{claim.predicate}]: {claim.value}",
            evidence_id=evidence_str,
            assurance=claim.assurance_score
        )

    @classmethod
    def format_hypothesis_card(
        cls,
        hypothesis_id: str,
        premise: str,
        parent_evidence_ids: List[str],
        proposed_test: str
    ) -> str:
        """Render a testable hypothesis card demarcating premises and required empirical experiments."""
        ev_str = ", ".join(parent_evidence_ids) if parent_evidence_ids else "None (Unsubstantiated)"
        return "\n".join([
            f"🧪 [HYPOTHESIS {hypothesis_id}]",
            f"  Premise      : {premise}",
            f"  Grounding Ev : {ev_str}",
            f"  Proposed Test: {proposed_test}"
        ])

    @classmethod
    def format_epistemic_audit_report(cls, claims: List[TransmutationNode]) -> str:
        """Generate an audit breakdown of beliefs by epistemic category."""
        counts: Dict[str, int] = {}
        for c in claims:
            k = c.state.value
            counts[k] = counts.get(k, 0) + 1

        lines = ["⚖️ EPISTEMIC AUDIT REPORT:"]
        for cat, count in sorted(counts.items()):
            lines.append(f"  • {cat:<18}: {count}")
        return "\n".join(lines)

    @classmethod
    def verify_epistemic_integrity(cls, text: str) -> bool:
        """
        Verify that all assertion lines begin with a valid epistemic register tag.
        Used to prevent ungrounded assertions from reaching the operator.
        """
        valid_tags = tuple(cls.REGISTERS.values())
        for line in text.strip().splitlines():
            s = line.strip()
            if not s or s.startswith("•") or s.startswith("🏛️") or s.startswith("✅") or s.startswith("❌") or s.startswith("⚖️") or s.startswith("🧪") or s.startswith("╔") or s.startswith("║") or s.startswith("╚"):
                continue
            if not any(s.startswith(tag) for tag in valid_tags):
                return False
        return True

