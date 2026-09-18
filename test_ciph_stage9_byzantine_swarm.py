"""
test_ciph_stage9_byzantine_swarm.py - Verification for Stage 9 Byzantine Swarm Consensus & Operator's Council.
"""

import unittest
from ciph.swarm.byzantine_consensus import (
    ByzantineConsensusEngine,
    CouncilNode,
    ConsensusProposal
)


class TestCiphStage9ByzantineSwarm(unittest.TestCase):

    def setUp(self):
        # 4 independent council agents
        self.node_inquisitor = CouncilNode("inquisitor", "Epistemic Auditor")
        self.node_strategist = CouncilNode("strategist", "Strategic Arbiter")
        self.node_red_auditor = CouncilNode("red_auditor", "Adversarial Falsifier")
        self.node_operator = CouncilNode("sovereign_operator", "Constitutional Guardian")

        self.council = [
            self.node_inquisitor,
            self.node_strategist,
            self.node_red_auditor,
            self.node_operator
        ]
        self.engine = ByzantineConsensusEngine(self.council)

    def test_supermajority_consensus_approval(self):
        """Verify 3-of-4 BFT consensus approval on critical worldview mutation."""
        proposal = ConsensusProposal(
            proposal_id="PROP-SWARM-01",
            subject="ciph_core.architecture",
            mutation_type="EPIC_PROMOTION",
            details={"patch": "v4_kernel_consolidation"}
        )

        # 3 nodes approve, 1 rejects
        votes = [
            self.node_inquisitor.vote(proposal, decision="APPROVE"),
            self.node_strategist.vote(proposal, decision="APPROVE"),
            self.node_operator.vote(proposal, decision="APPROVE"),
            self.node_red_auditor.vote(proposal, decision="REJECT", reason="Dissenting caution")
        ]

        result = self.engine.evaluate_consensus(proposal, votes)

        self.assertTrue(result.quorum_reached)
        self.assertTrue(result.approved)
        self.assertEqual(result.affirmative_votes, 3)
        self.assertEqual(result.threshold_required, 3)
        self.assertEqual(len(result.faulty_nodes), 0)

    def test_byzantine_tampered_signature_anomaly_detection(self):
        """Tampered vote payload is flagged as Byzantine faulty node and excluded from quorum."""
        proposal = ConsensusProposal(
            proposal_id="PROP-SWARM-02",
            subject="treasury.transfer",
            mutation_type="ASSET_OUTFLOW",
            details={"amount": 1000}
        )

        vote_1 = self.node_inquisitor.vote(proposal, decision="APPROVE")
        vote_2 = self.node_strategist.vote(proposal, decision="APPROVE")
        
        # Tampered vote from red_auditor
        vote_tampered = self.node_red_auditor.vote(proposal, decision="APPROVE")
        vote_tampered.decision = "REJECT"  # Tampered after signature!

        result = self.engine.evaluate_consensus(proposal, [vote_1, vote_2, vote_tampered])

        self.assertIn("red_auditor", result.faulty_nodes)
        self.assertFalse(result.approved)  # Only 2 valid approvals, needs 3


if __name__ == "__main__":
    unittest.main()
