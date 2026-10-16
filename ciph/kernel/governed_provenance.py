"""
ciph.kernel.governed_provenance - authoritative execution provenance, built from canonical state.

Decision of record: D11, MANIFEST_HASH_V2.

CALLER METADATA MAY DESCRIBE EXECUTION. IT MAY NEVER DEFINE EXECUTION IDENTITY.

The rule is structural, not a matter of merging carefully. Authoritative fields are stripped from
caller input and regenerated from canonical objects, and the two live in separate namespaces so no
future programmer can add `metadata["execution_attempt_id"]` and have some downstream function
mistake it for authority.

WHY THE BLOCK IS BUILT IN TWO PHASES
`execution_attempt_id` does not exist before the claim. It is evidence of a successful
`PermitStore.claim()` transition, not something the registry can predict in advance. So the
authoritative block is constructed in two steps around that transition:

    pre-claim   resolved manifest  -> manifest_identity
                signed permit      -> permit_id, permit_digest
                authorization      -> authorization_provenance

    claim       PermitStore.claim() -> execution_attempt_id

    post-claim  -> the complete authoritative block a receipt is built from

Collapsing these into one block built at registry entry would make the attempt id a prediction
rather than a record, which is exactly what crash recovery will later need it not to be.
"""

from typing import Any, Dict, Optional

from ciph.kernel.manifest_identity import ManifestIdentity

GOVERNED_BLOCK = "governed"
METADATA_BLOCK = "metadata"

# The authoritative set. Anything here is rebuilt from canonical state, never accepted from input.
AUTHORITATIVE_KEYS = (
    "manifest_identity",
    "authorization_provenance",
    "execution_permit_id",
    "execution_permit_digest",
    "execution_attempt_id",
)

# The subset that can legitimately exist before the claim transition.
PRE_CLAIM_AUTHORITATIVE_KEYS = (
    "manifest_identity",
    "authorization_provenance",
    "execution_permit_id",
    "execution_permit_digest",
)


class ProvenanceError(Exception):
    """Raised when an authoritative block cannot legally be constructed."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


def sanitize_caller_metadata(provenance: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Take caller-supplied provenance and return it with every authoritative key removed.

    A pre-existing `governed` block is discarded wholesale: the caller never supplies authority,
    including by pretending to.
    """
    metadata: Dict[str, Any] = {}
    if provenance:
        existing_metadata = provenance.get(METADATA_BLOCK)
        if isinstance(existing_metadata, dict):
            metadata.update(existing_metadata)
        for key, value in provenance.items():
            if key in AUTHORITATIVE_KEYS or key == GOVERNED_BLOCK:
                continue
            if key == METADATA_BLOCK:
                continue
            metadata[key] = value
    return {METADATA_BLOCK: metadata}


def build_pre_claim_authority(
    manifest_identity: ManifestIdentity,
    permit: Any = None,
    permit_id: Optional[str] = None,
    permit_digest: Optional[str] = None,
    authorization_provenance: str = "",
) -> Dict[str, Any]:
    """
    The authoritative block as it exists before execution is claimed.

    Deliberately has no parameter through which an attempt id could be supplied: it cannot exist
    yet, so accepting one would be accepting a prediction.
    """
    if not isinstance(manifest_identity, ManifestIdentity):
        raise ProvenanceError(
            "MANIFEST_IDENTITY_REQUIRED", repr(type(manifest_identity))
        )
    if permit is not None:
        permit_id = permit_id or permit.payload.permit_id
        permit_digest = permit_digest or permit.permit_digest()
    if not permit_id or not permit_digest:
        raise ProvenanceError("PERMIT_REFERENCE_REQUIRED", str(permit_id))

    block: Dict[str, Any] = {
        "manifest_identity": manifest_identity.to_dict(),
        "execution_permit_id": permit_id,
        "execution_permit_digest": permit_digest,
    }
    # A governed block must always declare its lane. Omitting it would leave a receipt that cannot
    # say which authorization regime produced it.
    if not authorization_provenance:
        raise ProvenanceError("AUTHORIZATION_PROVENANCE_REQUIRED")
    block["authorization_provenance"] = authorization_provenance
    return block


def complete_authority_after_claim(
    pre_claim_block: Dict[str, Any],
    claim: Any,
) -> Dict[str, Any]:
    """
    Add the attempt identity that the claim transaction produced.

    The attempt id comes from the durable claim, never from the caller and never from the pre-claim
    block, so `receipt -> attempt -> permit` is anchored in state rather than in intent.
    """
    attempt_id = getattr(claim, "execution_attempt_id", None)
    if not attempt_id:
        raise ProvenanceError("CLAIM_MISSING_ATTEMPT_IDENTITY", repr(claim))
    completed = dict(pre_claim_block)
    completed["execution_attempt_id"] = attempt_id
    return completed


def assemble_provenance(
    caller_provenance: Optional[Dict[str, Any]],
    governed_block: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Combine caller metadata with registry-owned authority under separate namespaces.

    The governed block is written last and wholesale. There is no merge of caller values into it,
    because a merge is where authority would eventually leak back in.
    """
    assembled = sanitize_caller_metadata(caller_provenance)
    assembled[GOVERNED_BLOCK] = dict(governed_block)
    return assembled
