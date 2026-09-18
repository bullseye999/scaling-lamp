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
        "WARNING": "[WARNING]",
    }

    CAPABILITY_CARD_WHITELIST_FIELDS = (
        "Capability:",
        "Registered:",
        "Available now:",
        "Provider version:",
        "Manifest hash:",
        "Last verified:",
        "Recent attempts:",
        "Successful:",
        "Partial:",
        "Execution failures:",
        "Policy-blocked:",
        "Tested targets:",
        "Verified transport:",
        "Environment:",
        "Evidence receipts:",
    )

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
        if receipt.results and isinstance(receipt.results, dict):
            if "report_data" in receipt.results and receipt.capability.startswith("operator."):
                import json
                rendered = json.dumps(receipt.results["report_data"], ensure_ascii=True, indent=2, sort_keys=True)
                lines.append("  " + receipt.results.get("semantics", "Local inspection report"))
                lines.append(rendered[:12000])
                if len(rendered) > 12000:
                    lines.append("[Display shortened; full bounded report is in the execution receipt.]")
            elif "prediction" in receipt.results and isinstance(receipt.results["prediction"], dict):
                pred = receipt.results["prediction"]
                lines.append(f"  Result   : Prediction -> Predicted winner: {pred.get('winner', 'N/A')}")
            elif isinstance(receipt.results.get("prediction"), str):
                lines.append(f"  Prediction output: {receipt.results['prediction']}")
            elif "base_score" in receipt.results and "severity" in receipt.results:
                lines.append(f"  Result   : CVSS {receipt.results['base_score']} ({receipt.results['severity']})")
            elif "message" in receipt.results and receipt.results["message"]:
                lines.append(f"  Message  : {str(receipt.results['message'])[:100]}")
            elif "summary" in receipt.results and receipt.results["summary"]:
                lines.append(f"  Summary  : {str(receipt.results['summary'])[:100]}")
            elif "value" in receipt.results and receipt.results.get("found"):
                lines.append(f"  Value    : {receipt.results.get('key')} = {str(receipt.results.get('value'))[:80]}")
            elif "opportunities" in receipt.results and isinstance(receipt.results["opportunities"], list):
                lines.append(f"  Intel    : {len(receipt.results['opportunities'])} monetizable threat opportunities")
            elif "report" in receipt.results and receipt.results["report"]:
                lines.append(f"  Report   : {str(receipt.results['report'])[:100]}")
            elif "staged" in receipt.results and receipt.results["staged"]:
                lines.append(f"  Staged   : {receipt.results['staged']}")
            elif "result" in receipt.results:
                lines.append(f"  Result   : {receipt.results['result']}")
            elif "portfolio" in receipt.results:
                lines.append(f"  Portfolio: {receipt.results['portfolio']}")
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
    def format_single_capability_card(
        cls,
        profile: Any,
        manifest_hash: Optional[str] = None
    ) -> str:
        """
        Render a single capability profile into a headed Section 19 card.
        The block header carries the epistemic register tag ([FACT], [OBSERVATION], or [WARNING]),
        and the indented body adheres to the strict Section 19 field whitelist.
        """
        from ciph.capabilities.capability_ledger import CapabilityLedger
        status_val = getattr(profile.health_status, "value", profile.health_status)

        if status_val == "VERIFIED_ACTIVE":
            tag = "FACT"
        elif status_val == "UNTESTED":
            tag = "OBSERVATION"
        else:
            tag = "WARNING"

        raw_body = CapabilityLedger.format_capability_card(profile, manifest_hash=manifest_hash)
        indented_body = "\n".join(f"  {line}" for line in raw_body.splitlines())
        return f"[{tag}] CAPABILITY PROFILE: {profile.capability_name}\n{indented_body}"

    @classmethod
    def format_capability_briefing(
        cls,
        report_dict: Dict[str, Any],
        scan_timestamp: Optional[float] = None,
        is_stale: bool = False
    ) -> str:
        """
        Render a high-level capability briefing from a generate_self_knowledge_report dict.
        Discloses snapshot timestamp, high-level counts, and three-state capability listings.
        """
        import time
        ts = scan_timestamp or report_dict.get("checkpoint", {}).get("scan_timestamp")
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "N/A"

        header_suffix = f" [STALE CACHE - As of {ts_str} - Idle maintenance recommended]" if is_stale else f" (As of {ts_str})"
        lines = [f"🏛️ EMPIRICAL CAPABILITY BRIEFING{header_suffix}:"]

        summary = report_dict.get("summary", {})
        total = summary.get("total_capabilities_tracked", 0)
        verified_active = summary.get("verified_active_capabilities", [])
        untested = summary.get("untested_capabilities", [])
        warning = summary.get("warning_capabilities", [])
        warning_status = summary.get("warning_status_by_name", {})

        # Backwards-compatible fallback for older report dicts that predate the warning bucket.
        if not warning and not warning_status:
            for name in summary.get("historical_only_capabilities", []):
                warning.append(name)
                warning_status[name] = "HISTORICAL_ONLY"
            for name in summary.get("degraded_capabilities", []):
                warning.append(name)
                warning_status[name] = "DEGRADED"
            for name in summary.get("conflicted_capabilities", []):
                warning.append(name)
                warning_status[name] = "INTEGRITY_CONFLICT"

        lines.append(
            f"  • Total Tracked: {total} | Verified Active: {len(verified_active)} | "
            f"Untested: {len(untested)} | Warning: {len(warning)}"
        )

        # Disclose unverifiable historical evidence: legacy receipts confer no credit, and the
        # operator must be able to see that the ledger's silence is evidence-related, not absence.
        checkpoint = report_dict.get("checkpoint", {})
        unverifiable = int(checkpoint.get("unverifiable_receipts_count", 0) or 0)
        legacy_verified = int(checkpoint.get("legacy_verified_receipts_count", 0) or 0)
        if unverifiable > 0:
            if legacy_verified > 0:
                lines.append(
                    f"  • Historical receipts: {unverifiable} unverified under current canonical rules "
                    f"({legacy_verified} verified against era-correct legacy hashes; confer no capability credit)"
                )
            else:
                lines.append(
                    f"  • Historical receipts that could not be verified: {unverifiable} "
                    "(legacy format; they confer no capability credit)"
                )

        if verified_active:
            lines.append("[FACT] VERIFIED ACTIVE CAPABILITIES (Proven in this environment):")
            for name in verified_active:
                lines.append(f"  • {name} (VERIFIED_ACTIVE)")

        if untested:
            lines.append("[OBSERVATION] UNTESTED REGISTERED CAPABILITIES (Declared in manifest; 0 verified executions):")
            for name in untested:
                lines.append(f"  • {name} (UNTESTED)")

        if warning:
            lines.append("[WARNING] UNVERIFIED / DEGRADED / UNAVAILABLE CAPABILITIES:")
            for name in warning:
                lines.append(f"  • {name} ({warning_status.get(name, 'WARNING')})")

        # Self-audit: nothing tracked may be silently omitted from the listing.
        categorized = len(verified_active) + len(untested) + len(warning)
        if total != categorized:
            lines.append(
                f"[WARNING] {total - categorized} of {total} tracked capabilities were not "
                "categorized by the report builder; the briefing is incomplete."
            )

        return "\n".join(lines)

    @classmethod
    def verify_epistemic_integrity(cls, text: str) -> bool:
        """
        Verify that all assertion lines begin with a valid epistemic register tag,
        or conform to recognized structured formats like the Section 19 capability card grammar.
        Used to prevent ungrounded assertions from reaching the operator.
        """
        valid_tags = tuple(cls.REGISTERS.values())
        in_card_block = False
        card_header_tag = None

        for line in text.strip().splitlines():
            s = line.strip()
            if not s:
                continue

            # Check if this line is a tagged capability card header
            matched_header_tag = None
            for tag in valid_tags:
                if s.startswith(f"{tag} CAPABILITY PROFILE:"):
                    matched_header_tag = tag
                    break

            if matched_header_tag is not None:
                in_card_block = True
                card_header_tag = matched_header_tag
                continue

            if in_card_block:
                # If unindented non-empty line starts, card block has ended
                if not line.startswith(" ") and not line.startswith("\t"):
                    in_card_block = False
                    card_header_tag = None
                else:
                    # Inside card block: whitelist check takes absolute precedence!
                    # Bullet prefixing or other decorators cannot bypass the whitelist.
                    stripped_field = s.lstrip("•").strip()
                    if not any(stripped_field.startswith(kf) for kf in cls.CAPABILITY_CARD_WHITELIST_FIELDS):
                        return False

                    # Anti-spoofing truth cross-check: Header tag must align with "Available now:" status
                    if stripped_field.startswith("Available now:"):
                        avail_val = stripped_field.split("Available now:", 1)[1].strip()
                        if card_header_tag == "[FACT]":
                            if "VERIFIED_ACTIVE" not in avail_val:
                                return False
                        elif card_header_tag == "[OBSERVATION]":
                            if "UNTESTED" not in avail_val:
                                return False
                        elif card_header_tag in ("[WARNING]", "[UNKNOWN]"):
                            if "VERIFIED_ACTIVE" in avail_val:
                                return False
                    continue

            if s.startswith("•") or s.startswith("🏛️") or s.startswith("✅") or s.startswith("❌") or s.startswith("⚖️") or s.startswith("🧪") or s.startswith("╔") or s.startswith("║") or s.startswith("╚"):
                continue

            if not any(s.startswith(tag) for tag in valid_tags):
                return False

        return True
