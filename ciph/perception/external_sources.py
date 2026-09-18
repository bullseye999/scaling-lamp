"""Operator-configured external sources. Payload text never selects its own authority."""
from dataclasses import dataclass
import base64
import hashlib
import html
import re
from urllib.parse import urlsplit
from ciph.contracts.enums import ReliabilityClass, DecayProfile

SOURCE_POLICIES = {
    ReliabilityClass.DIRECT_SENSOR: (0.40, DecayProfile.LIVE_NETWORK_STATE, 300),
    ReliabilityClass.THIRD_PARTY_FEED: (0.40, DecayProfile.SOFTWARE_BEHAVIOR, 604800),
    ReliabilityClass.PASSIVE_RECON: (0.40, DecayProfile.OPERATIONAL_ANOMALY, 86400),
    ReliabilityClass.UNVERIFIED_INCOMING: (0.30, DecayProfile.LIVE_NETWORK_STATE, 300),
}

@dataclass(frozen=True)
class ExternalSource:
    source_id: str
    url: str
    reliability: ReliabilityClass = ReliabilityClass.THIRD_PARTY_FEED
    max_bytes: int = 65536
    timeout_seconds: int = 10

    def __post_init__(self):
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,47}', self.source_id):
            raise ValueError('INVALID_SOURCE_ID')
        if self.reliability not in SOURCE_POLICIES:
            raise ValueError('EXTERNAL_SOURCE_CANNOT_BE_AUTHORITATIVE_LOCAL')
        if not 1 <= self.max_bytes <= 65536 or not 1 <= self.timeout_seconds <= 30:
            raise ValueError('INVALID_SOURCE_BUDGET')
        validate_url(self.url)

    def provenance(self):
        return {'source_id': self.source_id, 'url': self.url, 'reliability': self.reliability.value,
                'decay_profile': SOURCE_POLICIES[self.reliability][1].value,
                'ttl_seconds': SOURCE_POLICIES[self.reliability][2], 'max_bytes': self.max_bytes, 'timeout_seconds': self.timeout_seconds}


def public_address(address):
    # is_global alone includes multicast in Python's ipaddress classification.
    return address.is_global and not any((address.is_multicast, address.is_reserved,
        address.is_unspecified, address.is_loopback, address.is_link_local))


def validate_url(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in url) or '\\' in url:
        raise ValueError('INVALID_SOURCE_URL')
    u = urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.fragment:
        raise ValueError('INVALID_SOURCE_URL')
    host = u.hostname.lower()
    if len(host) > 253 or not re.fullmatch(r'[a-z0-9.-]+', host) or host.endswith('.') or '..' in host:
        raise ValueError('INVALID_SOURCE_HOST')
    if u.port not in (None, 80 if u.scheme == 'http' else 443):
        raise ValueError('SOURCE_PORT_DENIED')
    import ipaddress
    try: ip = ipaddress.ip_address(host)
    except ValueError:
        if '.' not in host or host.endswith(('.localhost', '.local', '.internal', '.onion')) or host == 'localhost':
            raise ValueError('NON_PUBLIC_TARGET')
    else:
        if not public_address(ip): raise ValueError('NON_PUBLIC_TARGET')
    return u


def display_external_body(value):
    """Derived escaped display only; callers retain the original bytes and digest."""
    raw = base64.b64decode(value['body_base64'], validate=True)
    if hashlib.sha256(raw).hexdigest() != value['body_sha256']:
        raise ValueError('EXTERNAL_PAYLOAD_INTEGRITY_MISMATCH')
    text = raw.decode('utf-8', errors='replace')
    text = ''.join(c if c in '\n\t' or ord(c) >= 32 and ord(c) != 127 else '\ufffd' for c in text)
    return html.escape(text)
