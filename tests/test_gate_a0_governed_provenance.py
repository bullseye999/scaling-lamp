"""
Gate A0 closure test - authoritative provenance construction.

The properties that matter: the attempt id cannot exist before the claim, a caller cannot supply
any authoritative field, and the two namespaces stay separate.
"""

import inspect
import unittest

from ciph.kernel.governed_provenance import (
    AUTHORITATIVE_KEYS,
    GOVERNED_BLOCK,
    METADATA_BLOCK,
    PRE_CLAIM_AUTHORITATIVE_KEYS,
    ProvenanceError,
    assemble_provenance,
    build_pre_claim_authority,
    complete_authority_after_claim,
    sanitize_caller_metadata,
)
from ciph.kernel.manifest_identity import ManifestIdentity


class _Permit:
    class _Payload:
        permit_id = "permit_X"
    payload = _Payload()

    def permit_digest(self):
        return "digest_of_X"


class _Claim:
    execution_attempt_id = "attempt_A"
    claimant = "registry"


class PreClaimAuthorityTests(unittest.TestCase):

    def test_no_attempt_id_before_the_claim(self):
        block = build_pre_claim_authority(ManifestIdentity(2, "HX"), permit=_Permit(), authorization_provenance="EXECUTION_PERMIT_V1")
        self.assertNotIn("execution_attempt_id", block)
        self.assertEqual(
            sorted(block),
            sorted(PRE_CLAIM_AUTHORITATIVE_KEYS),
        )

    def test_it_is_impossible_to_supply_an_attempt_id_pre_claim(self):
        """Not merely unused: there is no parameter for it, so it cannot be predicted."""
        parameters = inspect.signature(build_pre_claim_authority).parameters
        self.assertNotIn("execution_attempt_id", parameters)
        self.assertNotIn("attempt_id", parameters)

    def test_a_manifest_identity_object_is_required(self):
        with self.assertRaises(ProvenanceError) as caught:
            build_pre_claim_authority("v2:HX", permit=_Permit())
        self.assertEqual(caught.exception.reason, "MANIFEST_IDENTITY_REQUIRED")

    def test_permit_reference_is_required(self):
        with self.assertRaises(ProvenanceError) as caught:
            build_pre_claim_authority(ManifestIdentity(2, "HX"))
        self.assertEqual(caught.exception.reason, "PERMIT_REFERENCE_REQUIRED")


class PostClaimAuthorityTests(unittest.TestCase):

    def test_attempt_identity_comes_from_the_claim(self):
        block = build_pre_claim_authority(ManifestIdentity(2, "HX"), permit=_Permit(), authorization_provenance="EXECUTION_PERMIT_V1")
        completed = complete_authority_after_claim(block, _Claim())
        self.assertEqual(completed["execution_attempt_id"], "attempt_A")
        self.assertEqual(completed["execution_permit_id"], "permit_X")
        self.assertEqual(completed["manifest_identity"], {"hash_version": 2, "manifest_hash": "HX"})

    def test_a_claim_without_attempt_identity_is_refused(self):
        block = build_pre_claim_authority(ManifestIdentity(2, "HX"), permit=_Permit(), authorization_provenance="EXECUTION_PERMIT_V1")
        with self.assertRaises(ProvenanceError) as caught:
            complete_authority_after_claim(block, object())
        self.assertEqual(caught.exception.reason, "CLAIM_MISSING_ATTEMPT_IDENTITY")


class CallerCannotDefineIdentityTests(unittest.TestCase):

    def test_authoritative_keys_are_stripped_from_caller_input(self):
        hostile = {
            "manifest_identity": {"hash_version": 2, "manifest_hash": "Y"},
            "execution_attempt_id": "attempt_forged",
            "execution_permit_id": "permit_forged",
            "execution_permit_digest": "digest_forged",
            "authorization_provenance": "FORGED",
            "note": "harmless descriptive text",
        }
        cleaned = sanitize_caller_metadata(hostile)
        self.assertEqual(cleaned[METADATA_BLOCK], {"note": "harmless descriptive text"})
        for key in AUTHORITATIVE_KEYS:
            self.assertNotIn(key, cleaned)
            self.assertNotIn(key, cleaned[METADATA_BLOCK])

    def test_a_caller_supplied_governed_block_is_discarded_wholesale(self):
        cleaned = sanitize_caller_metadata({
            GOVERNED_BLOCK: {"manifest_identity": {"hash_version": 2, "manifest_hash": "Y"}},
            "keep": 1,
        })
        self.assertNotIn(GOVERNED_BLOCK, cleaned)
        self.assertEqual(cleaned[METADATA_BLOCK], {"keep": 1})

    def test_registry_authority_wins_and_caller_identity_never_reaches_it(self):
        """The nasty case: caller claims Y, canonical state resolves X."""
        caller = {"manifest_identity": {"hash_version": 2, "manifest_hash": "Y"}}
        governed = complete_authority_after_claim(
            build_pre_claim_authority(ManifestIdentity(2, "X"), permit=_Permit(), authorization_provenance="EXECUTION_PERMIT_V1"),
            _Claim(),
        )
        assembled = assemble_provenance(caller, governed)

        self.assertEqual(
            assembled[GOVERNED_BLOCK]["manifest_identity"],
            {"hash_version": 2, "manifest_hash": "X"},
        )
        self.assertNotIn("Y", str(assembled[GOVERNED_BLOCK]))
        self.assertNotIn("manifest_identity", assembled[METADATA_BLOCK])

    def test_namespaces_stay_separate(self):
        assembled = assemble_provenance({"note": "x"}, {"manifest_identity": {"hash_version": 2, "manifest_hash": "X"}})
        self.assertEqual(sorted(assembled), sorted([GOVERNED_BLOCK, METADATA_BLOCK]))
        self.assertEqual(assembled[METADATA_BLOCK], {"note": "x"})

    def test_absent_caller_provenance_yields_an_empty_metadata_namespace(self):
        assembled = assemble_provenance(None, {"manifest_identity": {"hash_version": 2, "manifest_hash": "X"}})
        self.assertEqual(assembled[METADATA_BLOCK], {})


if __name__ == "__main__":
    unittest.main()
