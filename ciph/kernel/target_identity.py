"""
ciph.kernel.target_identity - what exact thing is this?

Step 4.5 of the throat plan. Decision of record: TARGET_IDENTITY_V1.

ONE GLOBAL NORMALIZER IS WRONG
A target means different things to different capabilities. "example.com:443" as a network
endpoint, as an HTTP origin, as a filesystem path and as a git remote are four different
identities that may happen to share bytes. A single global normalizer will eventually merge two
things that must stay distinct, so the **capability contract owns its canonicalizer**.

SCOPE AND EXECUTION MUST SHARE THE CANONICALIZER
    raw target -> capability canonicalizer -> TargetIdentity
                                                 |-> canonical_bytes -> scope evaluation
                                                 |-> digest          -> portable permit
If scope normalizes one way and a permit digests another way, an authorization-equivalence bug
exists. There is exactly one canonicalizer per capability, versioned.

DOMAIN SEPARATION
Digest is not SHA256(canonical_bytes) alone. The identity is computed over a length-prefixed,
domain-separated structure:

    "CIPH_TARGET_IDENTITY_V1" | len(id) | id | len(version) | version | len(bytes) | bytes

Length prefixes, not naive concatenation, because concatenation is ambiguous: (id="ab", bytes="c")
and (id="a", bytes="bc") would otherwise collide. Same bytes under a different canonicalizer, or
the same canonicalizer at a different version, produce different identities.

DIGEST IS BINDING, NOT CONFIDENTIALITY
A digest binds authorization to a canonical target identity without embedding the raw target. It
does not hide the target: hashing a hostname is dictionary-guessable by anyone holding the digest.
Never document or treat this as secrecy.

THIS OBJECT IS NOT A POLICY ENGINE
TargetIdentity answers "what exact thing is this?" Containment - "does this identity fall inside
the authorized set?" - belongs to ScopeRule, which may reason about subtrees, CIDRs, wildcards and
repository+ref pairs. Keep the two separate or canonicalisation will slowly absorb policy.
"""

import hashlib
import posixpath
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

TARGET_IDENTITY_DOMAIN = b"CIPH_TARGET_IDENTITY_V1"
SUPPORTED_TARGET_IDENTITY_VERSION = "1"


class TargetIdentityError(Exception):
    """Raised when a target cannot be canonicalised."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _length_prefixed(parts) -> bytes:
    """Unambiguous framing. Length prefixes make concatenation-injection impossible."""
    encoded = bytearray(TARGET_IDENTITY_DOMAIN)
    for part in parts:
        payload = part if isinstance(part, bytes) else str(part).encode("utf-8")
        encoded.extend(len(payload).to_bytes(8, "big"))
        encoded.extend(payload)
    return bytes(encoded)


@dataclass(frozen=True)
class TargetIdentity:
    """
    The exact identity of a target under one capability's canonicalizer.

    `canonical_bytes` is for local scope evaluation. It must NOT be placed in a portable permit,
    or the raw-target digest would be smuggling the normalized target back inside the artifact.
    """

    canonicalizer_id: str
    canonicalizer_version: str
    canonical_bytes: bytes
    digest: str

    def portable_reference(self) -> Dict[str, str]:
        """What a signed permit carries: identity without the target material."""
        return {
            "target_canonicalizer_id": self.canonicalizer_id,
            "target_canonicalizer_version": self.canonicalizer_version,
            "target_digest": self.digest,
        }


CANONICALIZER_SEMANTICS_DOMAIN = b"CIPH_CANONICALIZER_SEMANTICS_V1"
TARGET_MODE_TARGET_BEARING = "TARGET_BEARING"
TARGET_MODE_TARGETLESS = "TARGETLESS"


class CanonicalizerRegistrationConflict(Exception):
    """
    The same (id, version) was offered two different semantic contracts.

    Version numbers exist precisely so history cannot be edited: correcting a canonicalizer
    means a new version, never a silent redefinition under the old name.
    """


@dataclass(frozen=True)
class CanonicalizerContract:
    """
    What a canonicalizer *means*, independent of how it happens to be written.

    The semantics digest commits to a behavioural contract - normalization rules plus golden
    input -> output vectors - rather than to source text. Hashing the source would make a local
    rename or a comment invalidate capability identity with zero semantic change; a hand-typed
    constant would let behaviour drift while the constant stayed stale. Generating the digest
    from rules and vectors makes the implementation provably match the contract, and makes the
    contract itself the thing a manifest commits to.
    """

    canonicalizer_id: str
    version: str
    normalization_rules: tuple
    golden_vectors: tuple

    def semantics_digest(self) -> str:
        # Each vector carries its own length prefix, so no reordering or concatenation can make
        # two different contracts coincide accidentally.
        parts = [self.canonicalizer_id, self.version]
        for rule in self.normalization_rules:
            parts.append(rule)
        for raw, expected in self.golden_vectors:
            parts.append(raw)
            parts.append(expected)
        return hashlib.sha256(
            _framed(CANONICALIZER_SEMANTICS_DOMAIN, parts)
        ).hexdigest()


def implementation_digest(function) -> str:
    """
    Secondary evidence: which implementation currently backs a contract.

    Deliberately NOT part of identity. A refactor may change this freely; only the semantics
    digest decides whether a capability's meaning moved.
    """
    try:
        import inspect
        source = inspect.getsource(function)
    except Exception:
        source = repr(function)
    return hashlib.sha256(source.encode("utf-8", "replace")).hexdigest()


def _framed(domain: bytes, parts) -> bytes:
    encoded = bytearray(domain)
    for part in parts:
        payload = part if isinstance(part, bytes) else str(part).encode("utf-8")
        encoded.extend(len(payload).to_bytes(8, "big"))
        encoded.extend(payload)
    return bytes(encoded)


_CANONICALIZERS: Dict[Tuple[str, str], Callable[[str], bytes]] = {}
_SEMANTICS: Dict[Tuple[str, str], str] = {}


def register_canonicalizer(canonicalizer_id: str, version: str, contract=None):
    """
    Register a capability-owned canonicalizer. One canonicalizer per capability contract.

    Supplying a `CanonicalizerContract` records the *meaning* of the canonicalizer, which is
    what a V2 capability manifest commits to. Offering a second, different contract for the
    same (id, version) is refused, permanently: not even a corrected implementation may
    redefine an existing version.
    """
    def decorator(function: Callable[[str], bytes]):
        key = (canonicalizer_id, version)
        # The conflict check comes first on purpose: when the same (id, version) is offered a
        # different meaning, that is the more specific and more useful diagnosis than "already
        # registered". A corrected implementation still has to take a new version.
        if contract is not None:
            digest = contract.semantics_digest()
            existing = _SEMANTICS.get(key)
            if existing is not None and existing != digest:
                raise CanonicalizerRegistrationConflict(
                    f"REGISTRATION_CONFLICT: {key} already means {existing}, offered {digest}"
                )
        if key in _CANONICALIZERS:
            raise TargetIdentityError("CANONICALIZER_ALREADY_REGISTERED", f"{key}")
        if contract is not None:
            _SEMANTICS[key] = digest
        _CANONICALIZERS[key] = function
        return function
    return decorator


def canonicalizer_semantics_digest(canonicalizer_id: str, version: str):
    """The declared meaning of a canonicalizer, or None when nobody declared one."""
    return _SEMANTICS.get((canonicalizer_id, version))


def canonicalize(
    canonicalizer_id: str,
    canonicalizer_version: str,
    raw_target: str,
) -> TargetIdentity:
    key = (canonicalizer_id, canonicalizer_version)
    function = _CANONICALIZERS.get(key)
    if function is None:
        raise TargetIdentityError("UNKNOWN_CANONICALIZER", f"{canonicalizer_id}@{canonicalizer_version}")
    if raw_target is None:
        raise TargetIdentityError("TARGET_REQUIRED")
    canonical_bytes = function(raw_target)
    digest = hashlib.sha256(
        _length_prefixed([canonicalizer_id, canonicalizer_version, canonical_bytes])
    ).hexdigest()
    return TargetIdentity(
        canonicalizer_id=canonicalizer_id,
        canonicalizer_version=canonicalizer_version,
        canonical_bytes=canonical_bytes,
        digest=digest,
    )


@register_canonicalizer("network.endpoint", "1")
def _network_endpoint(raw: str) -> bytes:
    host, _, port = raw.strip().partition(":")
    host = host.strip().strip(".").lower()
    if port:
        return b"tcp://" + host.encode("utf-8") + b":" + port.encode("utf-8")
    return b"tcp://" + host.encode("utf-8")


@register_canonicalizer("http.origin", "1")
def _http_origin(raw: str) -> bytes:
    text = raw.strip().lower()
    scheme, sep, rest = text.partition("://")
    if not sep:
        scheme, rest = "https", text
    host, _, port = rest.partition("/")[0].partition(":")
    host = host.strip().strip(".")
    default = (scheme == "https" and port in ("", "443")) or (scheme == "http" and port in ("", "80"))
    if default:
        return scheme.encode("utf-8") + b"://" + host.encode("utf-8")
    return scheme.encode("utf-8") + b"://" + host.encode("utf-8") + b":" + port.encode("utf-8")


@register_canonicalizer("filesystem.path", "1")
def _filesystem_path(raw: str) -> bytes:
    text = raw.strip().replace("\\", "/")
    normalized = posixpath.normpath(text)
    return normalized.encode("utf-8")


@register_canonicalizer("git.repository", "1")
def _git_repository(raw: str) -> bytes:
    repository, _, ref = raw.strip().partition("#")
    repository = posixpath.normpath(repository.replace("\\", "/"))
    return repository.encode("utf-8") + b"#" + (ref or "HEAD").encode("utf-8")
