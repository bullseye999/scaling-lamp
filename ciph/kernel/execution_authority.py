"""
ciph.kernel.execution_authority - the authority that signs permission for what may happen.

Register items 0.5 / 0.15, Step 2 and Step 3 of the throat plan. Decision of record: EXECUTION
PERMIT V1 (see the blueprint's implementation note).

TWO SIGNING ROLES, NEVER ONE
ReceiptAuthority signs evidence of what happened. ExecutionAuthority signs permission for what may
happen. Separate keys, separate key ids, separate epochs. A permit signed by the receipt key must
be rejected, and the verifier holds a public key only, so a compromised worker path cannot mint
authority even if it can run code.

CANONICAL SERIALIZATION IS DEFINED BEFORE SIGNING
Whatever is signed is canonicalized deterministically: sorted keys, no incidental whitespace, all
values normalized. Without this, the same semantic permit eventually serializes two different ways
and verification fails for reasons nobody can reproduce.

THE SIGNER HAS NO GENERIC INTERFACE
ExecutionAuthority.issue_permit() takes a structured payload and refuses an invalid one. There is
deliberately no sign_arbitrary_blob(). A signer that can sign anything is a signing oracle.
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ciph.kernel.crypto_identity import Ed25519KeyManager

PERMIT_VERSION = "1"
# Every digest in the system gets its own namespace. Hashes increasingly *mean* things, so the
# same bytes coming from a different object type must not inhabit the same hash space.
PERMIT_ENVELOPE_DOMAIN = b"CIPH_EXECUTION_PERMIT_ENVELOPE_V1"
SIGNATURE_SCHEME_ED25519 = "ed25519"

ROLE_EXECUTION = "execution_authority"
ROLE_RECEIPT = "receipt_authority"


class PermitError(Exception):
    """Base for permit construction and validation failures."""


class PermitVerificationError(PermitError):
    """A permit failed verification. Carries a stable reason for receipts and tests."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


DENY_BAD_SIGNATURE = "DENY_BAD_PERMIT_SIGNATURE"
DENY_WRONG_ROLE = "DENY_PERMIT_WRONG_SIGNING_ROLE"
DENY_BAD_KEY_ID = "DENY_PERMIT_UNKNOWN_KEY_ID"
DENY_BAD_VERSION = "DENY_PERMIT_UNSUPPORTED_VERSION"
DENY_BAD_SCHEME = "DENY_PERMIT_UNSUPPORTED_SCHEME"
DENY_EXPIRED = "DENY_PERMIT_EXPIRED"
DENY_EPOCH = "DENY_PERMIT_SIGNING_EPOCH"


def canonical_permit_bytes(fields: Dict[str, Any]) -> bytes:
    """
    Deterministic serialization of the signed permit body.

    Sorted keys, no incidental whitespace, ASCII-safe, values normalized to JSON primitives. Two
    processes constructing the same semantic permit produce byte-identical output, which is what
    makes a signature over it meaningful.
    """
    if not isinstance(fields, dict):
        raise PermitError("PERMIT_BODY_MUST_BE_A_MAPPING")
    normalized = {
        str(key): (None if value is None else value)
        for key, value in fields.items()
    }
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def _framed(domain: bytes, parts) -> bytes:
    """Length-prefixed framing. Concatenation is ambiguous; prefixes are not."""
    encoded = bytearray(domain)
    for part in parts:
        payload = part if isinstance(part, bytes) else str(part).encode("utf-8")
        encoded.extend(len(payload).to_bytes(8, "big"))
        encoded.extend(payload)
    return bytes(encoded)


def execution_permit_digest(permit: "SignedExecutionPermit") -> str:
    """
    Digest of the complete signed authorization artifact, not merely its claims.

    Covers the canonical signed body plus the signature metadata and the signature itself, so
    a receipt citing this digest cites *this exact artifact* rather than anything sharing an
    id. The digest is not part of the material it digests, and permit_id is an independent
    UUID inside the body, so there is no cycle.
    """
    return hashlib.sha256(
        _framed(PERMIT_ENVELOPE_DOMAIN, [
            permit.payload.canonical_bytes(),
            permit.key_id,
            str(permit.signing_epoch),
            permit.signature_scheme,
            permit.signature,
        ])
    ).hexdigest()


def time_us(now: Optional[float] = None) -> int:
    """Unix microseconds as an integer. The only time representation a permit may carry."""
    return int((now if now is not None else time.time()) * 1_000_000)


def target_digest(target: Optional[str]) -> Optional[str]:
    """
    Binding, NOT confidentiality.

    A digest binds authorization to a canonical target identity without embedding the raw target.
    It does not hide the target: hashing a hostname is dictionary-guessable by anyone holding the
    digest. Treating this as secrecy would be an overclaim of exactly the kind this project
    punishes. Canonical target identity itself lives in ciph.kernel.target_identity, where scope
    evaluation and permit issuance share one canonicalizer per capability.
    """
    if target is None:
        return None
    return hashlib.sha256(str(target).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionPermitPayload:
    """
    The body of a permit: everything the authority attests to.

    Fields are the V1 subset of the agreed contract. Immutable once constructed.
    """

    permit_id: str
    capability_id: str
    request_digest: str
    action_fingerprint: str
    issued_at_us: int
    expires_at_us: int
    nonce: str
    permit_version: str = PERMIT_VERSION
    job_id: Optional[str] = None
    mission_id: Optional[str] = None
    logical_action_id: Optional[str] = None
    # The authorization generation for this semantic action. The action identity stays stable
    # across retries; each authorized retry advances the generation and receives a fresh
    # single-use permit. Issuance uniqueness is (logical_action_id, authorization_generation).
    authorization_generation: int = 0
    scope_grant_id: Optional[str] = None
    authorization_envelope_id: Optional[str] = None
    authorization_epoch: Optional[int] = None
    lease_set_digest: Optional[str] = None
    network_policy: Optional[str] = None
    target_digest: Optional[str] = None
    # Bound at issuance and signed with the rest of the payload: the replay policy that existed when
    # this authority was granted. A retry is decided against THIS, never against whatever the
    # capability declares now.
    replay_policy_digest: Optional[str] = None

    @classmethod
    def build(
        cls,
        capability_id: str,
        request_digest: str,
        action_fingerprint: str,
        issued_at_us: int,
        ttl_seconds: float,
        target: Optional[str] = None,
        **kwargs: Any,
    ) -> "ExecutionPermitPayload":
        return cls(
            permit_id=f"permit_{uuid.uuid4().hex[:12]}",
            capability_id=capability_id,
            request_digest=request_digest,
            action_fingerprint=action_fingerprint,
            issued_at_us=int(issued_at_us),
            expires_at_us=int(issued_at_us) + int(ttl_seconds * 1_000_000),
            nonce=uuid.uuid4().hex,
            target_digest=target_digest(target),
            **kwargs,
        )

    def as_mapping(self) -> Dict[str, Any]:
        body = {
            "permit_version": self.permit_version,
            "permit_id": self.permit_id,
            "capability_id": self.capability_id,
            "request_digest": self.request_digest,
            "action_fingerprint": self.action_fingerprint,
            "target_digest": self.target_digest,
            "scope_grant_id": self.scope_grant_id,
            "authorization_envelope_id": self.authorization_envelope_id,
            "authorization_epoch": self.authorization_epoch,
            "lease_set_digest": self.lease_set_digest,
            "network_policy": self.network_policy,
            "job_id": self.job_id,
            "mission_id": self.mission_id,
            "logical_action_id": self.logical_action_id,
            "authorization_generation": int(self.authorization_generation or 0),
            "issued_at_us": self.issued_at_us,
            "expires_at_us": self.expires_at_us,
            "nonce": self.nonce,
        }
        # Included only when present, so a permit minted before this binding keeps its exact signed
        # bytes - the same evolution rule the receipt schema uses for `effect_certainty`.
        if self.replay_policy_digest is not None:
            body["replay_policy_digest"] = self.replay_policy_digest
        return body

    def canonical_bytes(self) -> bytes:
        return canonical_permit_bytes(self.as_mapping())


@dataclass(frozen=True)
class SignedExecutionPermit:
    """A portable permit: payload plus the authority's attestation over it."""

    payload: ExecutionPermitPayload
    signature: str
    key_id: str
    signing_epoch: int
    signature_scheme: str = SIGNATURE_SCHEME_ED25519

    def permit_digest(self) -> str:
        """Convenience accessor; the function form stays authoritative."""
        return execution_permit_digest(self)

    def to_dict(self) -> Dict[str, Any]:
        body = self.payload.as_mapping()
        body.update({
            "signature": self.signature,
            "key_id": self.key_id,
            "signing_epoch": self.signing_epoch,
            "signature_scheme": self.signature_scheme,
        })
        return body

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "SignedExecutionPermit":
        data = dict(raw)
        signature = data.pop("signature", None)
        key_id = data.pop("key_id", None)
        signing_epoch = data.pop("signing_epoch", None)
        scheme = data.pop("signature_scheme", SIGNATURE_SCHEME_ED25519)
        if signature is None or key_id is None or signing_epoch is None:
            raise PermitError("PERMIT_MISSING_ATTESTATION")
        try:
            payload = ExecutionPermitPayload(**data)
        except TypeError as error:
            raise PermitError(f"PERMIT_MALFORMED_PAYLOAD: {error}") from error
        return cls(
            payload=payload,
            signature=signature,
            key_id=key_id,
            signing_epoch=int(signing_epoch),
            signature_scheme=scheme,
        )


class ExecutionAuthority:
    """
    Signs permission for what may happen. Holds the private key; the worker never does.

    Deliberately narrow: the only signing entry point takes a structured payload and validates it
    first. There is no generic blob-signing method, because a signer that can sign anything is a
    signing oracle and would quietly make the worker able to mint authority.
    """

    role = ROLE_EXECUTION

    def __init__(
        self,
        private_key: bytes,
        key_id: str = "execution_authority_primary",
        signing_epoch: int = 1,
        permit_ttl_seconds: float = 60.0,
    ):
        if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
            raise PermitError("EXECUTION_AUTHORITY_REQUIRES_32_BYTE_ED25519_KEY")
        if permit_ttl_seconds <= 0:
            raise PermitError("INVALID_PERMIT_TTL")
        self._private_key = bytes(private_key)
        self.key_id = key_id
        self.signing_epoch = signing_epoch
        self.permit_ttl_seconds = permit_ttl_seconds
        self.issued_count = 0

    @classmethod
    def generate(cls, key_id: str = "execution_authority_primary", signing_epoch: int = 1):
        private_key, public_key = Ed25519KeyManager.generate_keypair()
        return cls(private_key, key_id=key_id, signing_epoch=signing_epoch), public_key

    @property
    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return ed25519.Ed25519PrivateKey.from_private_bytes(
            self._private_key
        ).public_key().public_bytes_raw()

    def validate_payload(self, payload: ExecutionPermitPayload, now: Optional[float] = None) -> None:
        """Refuse to attest to a permit that is already malformed."""
        moment = now if now is not None else time.time()
        if payload.permit_version != PERMIT_VERSION:
            raise PermitError(f"UNSUPPORTED_PERMIT_VERSION:{payload.permit_version}")
        if not payload.permit_id or not payload.request_digest or not payload.nonce:
            raise PermitError("PERMIT_MISSING_REQUIRED_FIELD")
        if payload.expires_at_us <= payload.issued_at_us:
            raise PermitError("PERMIT_EXPIRES_BEFORE_ISSUE")
        if payload.expires_at_us - payload.issued_at_us > 3_600_000_000:
            raise PermitError("PERMIT_TTL_TOO_LONG: permits are single-use instantiations")
        if payload.issued_at_us > time_us(moment) + 300_000_000:
            raise PermitError("PERMIT_ISSUED_IN_THE_FUTURE")

    def issue_permit(
        self,
        payload: ExecutionPermitPayload,
        now: Optional[float] = None,
    ) -> SignedExecutionPermit:
        self.validate_payload(payload, now=now)
        signature = Ed25519KeyManager.sign(self._private_key, payload.canonical_bytes())
        self.issued_count += 1
        return SignedExecutionPermit(
            payload=payload,
            signature=signature,
            key_id=self.key_id,
            signing_epoch=self.signing_epoch,
        )


class ExecutionPermitVerifier:
    """
    Verifies permits. Holds a PUBLIC key only - and therefore has no ability to mint authority,
    which is what makes "the worker never mints permits" a property rather than a convention.

    This class performs cryptographic verification only. Whether a permit is currently usable is a
    question for the durable permit state, because a perfectly signed permit can still be revoked
    or already consumed.
    """

    def __init__(
        self,
        public_key: bytes,
        key_id: str = "execution_authority_primary",
        accepted_epochs: Optional[Any] = None,
        required_role: str = ROLE_EXECUTION,
    ):
        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise PermitError("VERIFIER_REQUIRES_32_BYTE_ED25519_PUBLIC_KEY")
        self._public_key = bytes(public_key)
        self.key_id = key_id
        self.accepted_epochs = set(accepted_epochs) if accepted_epochs else None
        self.required_role = required_role

    def verify(
        self,
        permit: SignedExecutionPermit,
        now: Optional[float] = None,
        require_unexpired: bool = True,
    ) -> SignedExecutionPermit:
        """Raise PermitVerificationError unless the permit is authentic and currently valid."""
        if permit.signature_scheme != SIGNATURE_SCHEME_ED25519:
            raise PermitVerificationError(DENY_BAD_SCHEME, permit.signature_scheme)
        if permit.payload.permit_version != PERMIT_VERSION:
            raise PermitVerificationError(DENY_BAD_VERSION, permit.payload.permit_version)
        if permit.key_id != self.key_id:
            # A permit naming another authority - including the receipt authority - is refused
            # before any signature work: these are different roles with different keys.
            raise PermitVerificationError(DENY_BAD_KEY_ID, permit.key_id)
        if self.accepted_epochs is not None and permit.signing_epoch not in self.accepted_epochs:
            raise PermitVerificationError(DENY_EPOCH, str(permit.signing_epoch))
        if not Ed25519KeyManager.verify(
            self._public_key, permit.payload.canonical_bytes(), permit.signature
        ):
            raise PermitVerificationError(DENY_BAD_SIGNATURE, permit.payload.permit_id)
        if require_unexpired:
            if time_us(now) > permit.payload.expires_at_us:
                raise PermitVerificationError(DENY_EXPIRED, permit.payload.permit_id)
        return permit
