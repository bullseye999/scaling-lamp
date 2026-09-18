"""
ciph.silicon - The Silicon Sovereign: Hardware Root of Trust & Post-Quantum Boundary (Stage 10).
Hardware Security Module (HSM) enclave key isolation, physical human presence confirmation,
and NIST ML-DSA lattice-based post-quantum signature verification.
"""

from .hardware_root import (
    HardwareSecurityModule,
    PostQuantumLatticeSigner,
    SiliconSovereignGuard,
    HardwareEnclaveAttestation
)

__all__ = [
    "HardwareSecurityModule",
    "PostQuantumLatticeSigner",
    "SiliconSovereignGuard",
    "HardwareEnclaveAttestation"
]
