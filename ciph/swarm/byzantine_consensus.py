"""
ciph.swarm.byzantine_consensus - Byzantine Swarm Consensus Engine (Stage 9).
Orchestrates Operator's Council as independent, asynchronous agent nodes executing
Byzantine Fault Tolerant (BFT) threshold voting over critical mutations.
"""

import time
import json
import uuid
import math
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def _canonical_bytes(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')


@dataclass
class ConsensusProposal:
    proposal_id: str
    subject: str
    mutation_type: str
    details: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


@dataclass
class CouncilVote:
    vote_id: str
    proposal_id: str
    node_id: str
    decision: str  # "APPROVE" or "REJECT"
    reason: str
    timestamp: float
    signature: str = ""

    def sign(self, signing_key: SigningKey) -> "CouncilVote":
        payload = {
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "node_id": self.node_id,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp
        }
        signed = signing_key.sign(_canonical_bytes(payload))
        self.signature = signed.signature.hex()
        return self

    def verify(self, verify_key_hex: str) -> bool:
        if not self.signature:
            return False
        payload = {
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "node_id": self.node_id,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp
        }
        try:
            vk = VerifyKey(bytes.fromhex(verify_key_hex))
            vk.verify(_canonical_bytes(payload), bytes.fromhex(self.signature))
            return True
        except BadSignatureError:
            return False


class CouncilNode:
    """Independent agent node in Operator's Swarm Council."""

    def __init__(self, node_id: str, role: str, signing_key: Optional[SigningKey] = None):
        self.node_id = node_id
        self.role = role
        self.signing_key = signing_key or SigningKey.generate()
        self.verify_key_hex = self.signing_key.verify_key.encode().hex()

    def vote(self, proposal: ConsensusProposal, decision: str = "APPROVE", reason: str = "Policy validated") -> CouncilVote:
        vote = CouncilVote(
            vote_id=f"VOTE-{uuid.uuid4().hex[:8].upper()}",
            proposal_id=proposal.proposal_id,
            node_id=self.node_id,
            decision=decision,
            reason=reason,
            timestamp=time.time()
        )
        return vote.sign(self.signing_key)


@dataclass
class ConsensusResult:
    proposal_id: str
    approved: bool
    quorum_reached: bool
    threshold_required: int
    affirmative_votes: int
    rejection_votes: int
    participating_nodes: List[str]
    faulty_nodes: List[str]


class ByzantineConsensusEngine:
    """
    Stage 9 BFT Consensus Engine.
    Enforces (2/3 + 1) supermajority threshold and detects Byzantine anomalies.
    """

    def __init__(self, council_nodes: List[CouncilNode]):
        self.nodes = {n.node_id: n for n in council_nodes}

    def evaluate_consensus(self, proposal: ConsensusProposal, votes: List[CouncilVote]) -> ConsensusResult:
        total_council = len(self.nodes)
        # BFT supermajority threshold: ceil((2N + 1) / 3)
        threshold_required = math.ceil((2 * total_council + 1) / 3)

        seen_nodes = set()
        approvals = 0
        rejections = 0
        faulty_nodes = []
        valid_participants = []

        for vote in votes:
            node = self.nodes.get(vote.node_id)
            if not node:
                faulty_nodes.append(vote.node_id)
                continue

            # Check for double-voting / equivocation
            if vote.node_id in seen_nodes:
                faulty_nodes.append(vote.node_id)
                continue

            # Verify cryptographic signature
            if not vote.verify(node.verify_key_hex):
                faulty_nodes.append(vote.node_id)
                continue

            seen_nodes.add(vote.node_id)
            valid_participants.append(vote.node_id)

            if vote.decision == "APPROVE":
                approvals += 1
            else:
                rejections += 1

        quorum_reached = len(valid_participants) >= threshold_required
        approved = quorum_reached and (approvals >= threshold_required)

        return ConsensusResult(
            proposal_id=proposal.proposal_id,
            approved=approved,
            quorum_reached=quorum_reached,
            threshold_required=threshold_required,
            affirmative_votes=approvals,
            rejection_votes=rejections,
            participating_nodes=valid_participants,
            faulty_nodes=list(set(faulty_nodes))
        )
