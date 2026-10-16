
"""
ciph.kernel.credit_policy - the authority decision, structurally unable to reach history.

`authorize_current_credit` accepts exactly one thing: a `CurrentCreditResult`. It cannot accept raw
evidence, it cannot accept `LineageCreditHistory`, and it resolves no ancestors. A policy written
against this signature is a shape error away from consulting history, not a memory test away.

This is the same separation the credit primitive draws: `compute_current_credit` is retrieval-blind
and lineage-blind, and the policy that spends its verdict is lineage-blind too.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ciph.kernel.manifest_credit import CurrentCreditResult, CreditStatus


class CreditDecision(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    REFUSED = "REFUSED"


@dataclass(frozen=True)
class CreditPolicyResult:
    decision: CreditDecision
    reason: str
    manifest_identity: Optional[object] = None
    usable_evidence_count: int = 0
    status: Optional[CreditStatus] = None


def authorize_current_credit(result: CurrentCreditResult) -> CreditPolicyResult:
    """
    Spend exactly one verdict: this identity, now.

    The signature is the enforcement. Passing a lineage history or a raw evidence list is a shape
    error rather than something the policy has to remember not to do.
    """
    if not isinstance(result, CurrentCreditResult):
        raise TypeError("POLICY_REQUIRES_A_CURRENT_CREDIT_RESULT")

    if result.authority_usable:
        return CreditPolicyResult(
            decision=CreditDecision.AUTHORIZED,
            reason="AUTHORITY_USABLE",
            manifest_identity=result.manifest_identity,
            usable_evidence_count=result.usable_evidence_count,
            status=result.status,
        )

    if result.integrity_incidents:
        reason = result.integrity_incidents[0].reason
    elif result.status == CreditStatus.UNVERIFIED:
        reason = "NO_USABLE_EXACT_EVIDENCE"
    else:
        reason = result.status.value

    return CreditPolicyResult(
        decision=CreditDecision.REFUSED,
        reason=reason,
        manifest_identity=result.manifest_identity,
        usable_evidence_count=result.usable_evidence_count,
        status=result.status,
    )
