"""
Gate A0 closure test - the ManifestIdentity value object (D11, MANIFEST_HASH_V2).

The two properties that matter most are negative: version participates in identity, and a legacy
hash is never silently upgraded. Both are tested because both fail silently.
"""

import unittest

from ciph.kernel.manifest_identity import (
    MANIFEST_IDENTITY_KEY,
    ManifestBinding,
    ManifestIdentity,
    ManifestIdentityError,
    classify_manifest_binding,
)


class ManifestIdentityValueObjectTests(unittest.TestCase):

    def test_both_fields_are_required(self):
        with self.assertRaises(ManifestIdentityError):
            ManifestIdentity(hash_version=2, manifest_hash="")
        with self.assertRaises(ManifestIdentityError):
            ManifestIdentity(hash_version=0, manifest_hash="abc")
        with self.assertRaises(ManifestIdentityError):
            ManifestIdentity(hash_version="2", manifest_hash="abc")

    def test_a_bare_hash_cannot_be_interpreted(self):
        """'Missing version means V1' is the inference that reattributes history."""
        self.assertFalse(hasattr(ManifestIdentity, "from_hash"))
        with self.assertRaises(ManifestIdentityError) as caught:
            ManifestIdentity.from_dict("abc123")
        self.assertEqual(caught.exception.reason, "MANIFEST_IDENTITY_MUST_BE_A_MAPPING")
        with self.assertRaises(ManifestIdentityError) as caught:
            ManifestIdentity.from_dict({"manifest_hash": "abc123"})
        self.assertEqual(
            caught.exception.reason, "MANIFEST_IDENTITY_REQUIRES_VERSION_AND_HASH"
        )

    def test_version_is_part_of_identity_not_metadata(self):
        """Identical hash strings under different rules are different claims."""
        v1 = ManifestIdentity(hash_version=1, manifest_hash="ABC")
        v2 = ManifestIdentity(hash_version=2, manifest_hash="ABC")
        self.assertNotEqual(v1, v2)
        self.assertNotEqual(hash(v1), hash(v2))
        self.assertNotEqual(v1.to_dict(), v2.to_dict())

    def test_serialization_round_trips_deterministically(self):
        identity = ManifestIdentity(hash_version=2, manifest_hash="XYZ")
        self.assertEqual(identity.to_dict(), {"hash_version": 2, "manifest_hash": "XYZ"})
        self.assertEqual(ManifestIdentity.from_dict(identity.to_dict()), identity)
        self.assertEqual(str(identity), "v2:XYZ")


class ManifestBindingClassificationTests(unittest.TestCase):

    def test_versioned_provenance_yields_a_versioned_binding(self):
        result = classify_manifest_binding({
            MANIFEST_IDENTITY_KEY: {"hash_version": 2, "manifest_hash": "XYZ"}
        })
        self.assertEqual(result.binding, ManifestBinding.VERSIONED)
        self.assertEqual(result.identity, ManifestIdentity(2, "XYZ"))
        self.assertIsNone(result.legacy_hash)

    def test_unversioned_legacy_hash_is_not_upgraded_without_proof(self):
        result = classify_manifest_binding({"manifest_hash": "ABC"})
        self.assertEqual(result.binding, ManifestBinding.LEGACY_UNVERSIONED)
        self.assertIsNone(result.identity)
        self.assertEqual(result.legacy_hash, "ABC")
        self.assertEqual(result.reason, "UNVERSIONED_AND_NOT_PROVABLE")

    def test_unversioned_legacy_hash_upgrades_only_with_both_facts(self):
        provenance = {"manifest_hash": "ABC"}
        partially_proven = classify_manifest_binding(
            provenance, pre_v2_schema_provable=True
        )
        self.assertEqual(partially_proven.binding, ManifestBinding.LEGACY_UNVERSIONED)

        fully_proven = classify_manifest_binding(
            provenance, pre_v2_schema_provable=True, v1_algorithm_reproduces=True
        )
        self.assertEqual(fully_proven.binding, ManifestBinding.VERSIONED)
        self.assertEqual(fully_proven.identity, ManifestIdentity(1, "ABC"))
        self.assertEqual(fully_proven.reason, "VERIFIED_PRE_V2_SCHEMA")

    def test_empty_provenance_is_unbound(self):
        self.assertEqual(classify_manifest_binding({}).binding, ManifestBinding.UNBOUND)
        self.assertEqual(classify_manifest_binding(None).binding, ManifestBinding.UNBOUND)

    def test_malformed_versioned_block_is_corrupt_not_legacy(self):
        """
        A broken identity claim must never be quietly downgraded to historical legacy, and must not
        fall back to a legacy hash in the same record: "I cannot read the identity" is not the same
        fact as "this predates identity".
        """
        result = classify_manifest_binding({
            MANIFEST_IDENTITY_KEY: {"manifest_hash": "ABC"},
            "manifest_hash": "ABC",
        })
        self.assertEqual(result.binding, ManifestBinding.CORRUPT)
        self.assertIsNone(result.identity)
        self.assertIsNone(result.legacy_hash, "a corrupt claim must not fall back to a legacy hash")
        self.assertIn("MALFORMED_VERSIONED_IDENTITY", result.reason)

    def test_governed_only_identity_is_versioned(self):
        result = classify_manifest_binding({
            "governed": {MANIFEST_IDENTITY_KEY: {"hash_version": 2, "manifest_hash": "X"}}
        })
        self.assertEqual(result.binding, ManifestBinding.VERSIONED)
        self.assertEqual(result.identity, ManifestIdentity(2, "X"))

    def test_agreeing_governed_and_flat_identities_are_tolerated(self):
        same = {"hash_version": 2, "manifest_hash": "X"}
        result = classify_manifest_binding({
            "governed": {MANIFEST_IDENTITY_KEY: dict(same)},
            MANIFEST_IDENTITY_KEY: dict(same),
        })
        self.assertEqual(result.binding, ManifestBinding.VERSIONED)
        self.assertEqual(result.identity, ManifestIdentity(2, "X"))

    def test_conflicting_governed_and_flat_identities_are_corruption(self):
        """
        Two authoritative representations at once is not a precedence question. Choosing the
        modern one would hide tampering or a malformed migration behind a compatibility rule.
        """
        result = classify_manifest_binding({
            "governed": {MANIFEST_IDENTITY_KEY: {"hash_version": 2, "manifest_hash": "X"}},
            MANIFEST_IDENTITY_KEY: {"hash_version": 2, "manifest_hash": "Y"},
        })
        self.assertEqual(result.binding, ManifestBinding.CORRUPT)
        self.assertIsNone(result.identity)
        self.assertIsNone(result.legacy_hash)
        self.assertEqual(result.reason, "CONFLICTING_AUTHORITATIVE_IDENTITIES")

    def test_identical_hash_strings_do_not_unify_across_versions(self):
        """
        The laundering guard: legacy ABC and versioned (2, ABC) are different claims even though
        the raw hash strings coincide.
        """
        legacy = classify_manifest_binding({"manifest_hash": "ABC"})
        versioned = classify_manifest_binding({
            MANIFEST_IDENTITY_KEY: {"hash_version": 2, "manifest_hash": "ABC"}
        })
        self.assertIsNone(legacy.identity)
        self.assertIsNotNone(versioned.identity)
        self.assertNotEqual(legacy.identity, versioned.identity)
        self.assertFalse(
            versioned.identity == ManifestIdentity(1, "ABC"),
            "a V2 identity must not equal a V1 identity carrying the same hash string",
        )


if __name__ == "__main__":
    unittest.main()
