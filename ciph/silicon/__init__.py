"""
ciph.silicon - PLACEHOLDER / NOT ENABLED (Stage 10 scaffold).

NOT IMPLEMENTED. There is no HSM, no enclave, no physical presence confirmation and no
post-quantum signature scheme here. The module imports `hmac` and performs symmetric
operations. It must not be described as hardware-rooted or post-quantum until those exist
and are verified. Register item 0.10; decisions D3/D7.
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
