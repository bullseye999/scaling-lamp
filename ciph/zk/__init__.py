"""
ciph.zk - PLACEHOLDER / NOT ENABLED (Stage 8 scaffold).

NOT IMPLEMENTED. This module does not perform zero-knowledge proofs. It computes hash
commitments, which are neither zero-knowledge nor proofs, and disclose the payload to
anyone holding it. There is no proof system, witness, verifier relation or soundness
argument here.

It must not be described as proving faithful capability execution or sensory integrity
until a concrete statement to prove exists and the implementation follows it (see Part IV,
"ZK stays in Horizon until it has a statement"). Register item 0.10; decisions D3/D7.
"""

from .zk_engine import ZKEvidenceProof, ZKReceiptVerifier

__all__ = ["ZKEvidenceProof", "ZKReceiptVerifier"]
