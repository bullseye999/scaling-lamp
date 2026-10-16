"""
ciph.kernel.manifest_identity - which exact manifest identity earned this evidence?

Decision of record: D11, MANIFEST_HASH_V2.

ONE EVIDENCE RECORD, ONE IDENTITY
Evidence carries exactly one `ManifestIdentity`. Not a V1 hash beside a V2 hash, because two peers
merely relocate the ambiguity: some later caller will ask which of them owns the evidence. Lineage
may reference many identities; authority belongs to exactly one.

VERSION IS PART OF IDENTITY, NOT METADATA ABOUT IT
    ManifestIdentity(1, ABC) != ManifestIdentity(2, ABC)
even when the hash strings are byte-identical. That is the whole point of versioning a hash
algorithm: the same bytes computed under different rules are different claims.

NO GUESSING CONSTRUCTOR
There is deliberately no `ManifestIdentity.from_hash(...)`. "Missing version means V1" is the exact
inference that would silently reattribute historical evidence, so classification of old material
is a separate, explicit operation that must be given evidence of provenance schema and algorithm.
Unversioned legacy material stays visibly unversioned rather than being quietly upgraded.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

MANIFEST_IDENTITY_DOMAIN = "CIPH_MANIFEST_IDENTITY_V1"
MANIFEST_IDENTITY_KEY = "manifest_identity"


class ManifestIdentityError(Exception):
    """Raised when a manifest identity cannot legally be constructed."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class ManifestBinding(str, Enum):
    """
    How an evidence record relates to a manifest identity.

    Three states, because collapsing them is how parsing launders history:
      VERSIONED           the record names its exact identity
      LEGACY_UNVERSIONED  the record predates versioned identity and cannot be upgraded silently
      UNBOUND             the record carries no manifest information at all
      CORRUPT             the record claims a versioned identity and is malformed

    CORRUPT exists so a broken versioned block is never quietly downgraded to historical
    legacy. "I could not read the identity" and "this predates identity" are different
    facts, and treating the first as the second would silently convert corruption into
    innocent history.
    """

    VERSIONED = "VERSIONED"
    LEGACY_UNVERSIONED = "LEGACY_UNVERSIONED"
    UNBOUND = "UNBOUND"
    CORRUPT = "CORRUPT"


@dataclass(frozen=True)
class ManifestIdentity:
    """
    The exact manifest identity that produced some evidence.

    Both fields are required and both participate in equality. There is no default version and no
    conversion from a bare hash.
    """

    hash_version: int
    manifest_hash: str

    def __post_init__(self):
        if not isinstance(self.hash_version, int) or isinstance(self.hash_version, bool):
            raise ManifestIdentityError("HASH_VERSION_MUST_BE_INTEGER", repr(self.hash_version))
        if self.hash_version < 1:
            raise ManifestIdentityError("HASH_VERSION_MUST_BE_POSITIVE", str(self.hash_version))
        if not isinstance(self.manifest_hash, str) or not self.manifest_hash.strip():
            raise ManifestIdentityError("MANIFEST_HASH_REQUIRED", repr(self.manifest_hash))

    def to_dict(self) -> Dict[str, Any]:
        return {"hash_version": self.hash_version, "manifest_hash": self.manifest_hash}

    @classmethod
    def from_dict(cls, data: Any) -> "ManifestIdentity":
        """
        Strict: both fields must be present. A bare hash is refused rather than interpreted.
        """
        if not isinstance(data, dict):
            raise ManifestIdentityError("MANIFEST_IDENTITY_MUST_BE_A_MAPPING", repr(type(data)))
        if "hash_version" not in data or "manifest_hash" not in data:
            raise ManifestIdentityError(
                "MANIFEST_IDENTITY_REQUIRES_VERSION_AND_HASH",
                ",".join(sorted(data.keys())),
            )
        return cls(
            hash_version=int(data["hash_version"]),
            manifest_hash=str(data["manifest_hash"]),
        )

    def __str__(self) -> str:
        return f"v{self.hash_version}:{self.manifest_hash}"


@dataclass(frozen=True)
class ManifestBindingResult:
    """
    The outcome of classifying evidence provenance.

    `identity` is populated only when the record genuinely names a versioned identity. Legacy
    material keeps its raw hash in `legacy_hash` and a None identity, so downstream code cannot
    mistake it for a versioned claim by accident.
    """

    binding: ManifestBinding
    identity: Optional[ManifestIdentity]
    legacy_hash: Optional[str]
    reason: str


def classify_manifest_binding(
    provenance: Optional[Dict[str, Any]],
    pre_v2_schema_provable: bool = False,
    v1_algorithm_reproduces: bool = False,
) -> ManifestBindingResult:
    """
    Classify a receipt's manifest binding **without laundering history**.

    A bare legacy hash is upgraded to `ManifestIdentity(1, hash)` only when the caller can supply
    two independent facts: the provenance schema predates V2, *and* the hash reproduces under the
    frozen V1 algorithm. Absent both, it stays explicitly unversioned. Recomputing the current
    manifest and matching hashes is never sufficient, because that is exactly how a capability's
    old evidence would be reattributed to its new identity.
    """
    if not provenance:
        return ManifestBindingResult(
            binding=ManifestBinding.UNBOUND,
            identity=None,
            legacy_hash=None,
            reason="NO_MANIFEST_PROVENANCE",
        )

    # The governed path writes authority inside the governed namespace, so the authoritative
    # block is consulted first. The flat top-level lookup is retained for receipts written before
    # namespacing existed; it is a compatibility path, not the preferred shape.
    # (`governed` is spelled literally here to avoid a manifest_identity <-> governed_provenance
    # import cycle.)
    governed_block = provenance.get("governed")
    governed_identity = None
    if isinstance(governed_block, dict):
        governed_identity = governed_block.get(MANIFEST_IDENTITY_KEY)
    flat_identity = provenance.get(MANIFEST_IDENTITY_KEY)

    # Two authoritative identity representations at once is not a precedence question. Choosing
    # the modern one would silently hide tampering or a malformed migration, so a conflict is
    # corruption rather than a resolution.
    if governed_identity is not None and flat_identity is not None:
        try:
            from_governed = ManifestIdentity.from_dict(governed_identity)
            from_flat = ManifestIdentity.from_dict(flat_identity)
        except ManifestIdentityError as error:
            return ManifestBindingResult(
                binding=ManifestBinding.CORRUPT,
                identity=None,
                legacy_hash=None,
                reason=f"MALFORMED_VERSIONED_IDENTITY:{error.reason}",
            )
        if from_governed != from_flat:
            return ManifestBindingResult(
                binding=ManifestBinding.CORRUPT,
                identity=None,
                legacy_hash=None,
                reason="CONFLICTING_AUTHORITATIVE_IDENTITIES",
            )
        return ManifestBindingResult(
            binding=ManifestBinding.VERSIONED,
            identity=from_governed,
            legacy_hash=None,
            reason="EXPLICIT_VERSIONED_IDENTITY",
        )

    versioned = governed_identity if governed_identity is not None else flat_identity
    if versioned is not None:
        try:
            identity = ManifestIdentity.from_dict(versioned)
        except ManifestIdentityError as error:
            # Deliberately NOT downgraded to legacy, and deliberately no fallback to a legacy
            # hash in the same record. A malformed identity claim is corruption; reinterpreting
            # it as "this just predates versioning" would launder corruption into history.
            return ManifestBindingResult(
                binding=ManifestBinding.CORRUPT,
                identity=None,
                legacy_hash=None,
                reason=f"MALFORMED_VERSIONED_IDENTITY:{error.reason}",
            )
        return ManifestBindingResult(
            binding=ManifestBinding.VERSIONED,
            identity=identity,
            legacy_hash=None,
            reason="EXPLICIT_VERSIONED_IDENTITY",
        )

    legacy_hash = provenance.get("manifest_hash")
    if not legacy_hash:
        return ManifestBindingResult(
            binding=ManifestBinding.UNBOUND,
            identity=None,
            legacy_hash=None,
            reason="NO_MANIFEST_PROVENANCE",
        )

    if pre_v2_schema_provable and v1_algorithm_reproduces:
        return ManifestBindingResult(
            binding=ManifestBinding.VERSIONED,
            identity=ManifestIdentity(hash_version=1, manifest_hash=str(legacy_hash)),
            legacy_hash=str(legacy_hash),
            reason="VERIFIED_PRE_V2_SCHEMA",
        )

    return ManifestBindingResult(
        binding=ManifestBinding.LEGACY_UNVERSIONED,
        identity=None,
        legacy_hash=str(legacy_hash),
        reason="UNVERSIONED_AND_NOT_PROVABLE",
    )
