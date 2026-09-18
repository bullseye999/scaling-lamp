"""
ciph.zk - Zero-Knowledge Epistemic Proofs & Verifiable Computation (Stage 8).
Cryptographically proves faithful capability execution and sensory integrity without disclosing private inputs.
"""

from .zk_engine import ZKEvidenceProof, ZKReceiptVerifier

__all__ = ["ZKEvidenceProof", "ZKReceiptVerifier"]
