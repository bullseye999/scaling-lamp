"""
ciph.perception.observation - First-Class Observation Contract.
Bridges raw external telemetry to the Epistemic Kernel.
"""

import time
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional, Dict


class ReliabilityClass(str, Enum):
    AUTHORITATIVE_LOCAL = "AUTHORITATIVE_LOCAL"  # Local system commands (git, fs, os)
    DIRECT_SENSOR       = "DIRECT_SENSOR"        # Direct HTTP/Socket response from target
    THIRD_PARTY_FEED    = "THIRD_PARTY_FEED"     # RSS, CVE, NVD, AlienVault feeds
    PASSIVE_RECON       = "PASSIVE_RECON"        # Wayback, crt.sh, search engine caches
    UNVERIFIED_INCOMING = "UNVERIFIED_INCOMING"  # Incoming external messages / whispers


@dataclass(frozen=True)
class Observation:
    observation_id: str                          # Unique ID e.g., "obs_90128a"
    source: str                                  # Source identifier (e.g. "perception.git", "nvd_feed")
    subject: str                                 # Target asset / entity (e.g. "local_repo", "cve-2026-101")
    predicate: str                               # Observed attribute (e.g. "active_branch", "cvss_score")
    value: Any                                   # Observed value (e.g. "main", 9.8)
    observed_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None           # Freshness TTL deadline
    raw_evidence_ref: str = ""                   # Vault hash or pointer to raw response
    reliability_class: ReliabilityClass = ReliabilityClass.DIRECT_SENSOR
    environment: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if observation has passed its freshness deadline."""
        if self.expires_at is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Serialize observation to structured dictionary."""
        data = asdict(self)
        data['reliability_class'] = self.reliability_class.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Observation":
        """Reconstitute observation from dictionary."""
        d = dict(data)
        if 'reliability_class' in d and isinstance(d['reliability_class'], str):
            d['reliability_class'] = ReliabilityClass(d['reliability_class'])
        return cls(**d)
