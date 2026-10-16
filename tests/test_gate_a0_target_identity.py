"""
Gate A0 closure test - Step 4.5: TargetIdentity V1.

Decision of record: TARGET_IDENTITY_V1.

THE PROPERTY THAT MATTERS
The same bytes under different canonicalizers must NOT be the same identity, and the digest must
not be crackable by concatenation ambiguity. Both are tested, because both are silent when wrong.
"""

import unittest

from ciph.kernel.target_identity import (
    TargetIdentityError,
    _length_prefixed,
    canonicalize,
    register_canonicalizer,
)


@register_canonicalizer("test.v2canonicalizer", "2")
def _alternate_version(raw: str) -> bytes:
    return raw.strip().upper().encode("utf-8")


class TargetIdentityTests(unittest.TestCase):

    def test_same_bytes_under_different_canonicalizers_are_different_identities(self):
        """Domain separation: identical text, different meaning, different identity."""
        endpoint = canonicalize("network.endpoint", "1", "example.com:443")
        origin = canonicalize("http.origin", "1", "example.com:443")
        self.assertNotEqual(endpoint.digest, origin.digest)

    def test_same_canonicalizer_at_a_different_version_is_a_different_identity(self):
        """A version bump is a different identity, not a compatible edit."""
        lower = canonicalize("network.endpoint", "1", "host")
        upper = canonicalize("test.v2canonicalizer", "2", "Host")
        self.assertNotEqual(lower.digest, upper.digest)

    def test_length_prefixing_prevents_concatenation_ambiguity(self):
        """(id='ab', bytes='c') and (id='a', bytes='bc') must not frame identically."""
        left = _length_prefixed(["ab", "1", b"c"])
        right = _length_prefixed(["a", "1", b"bc"])
        self.assertNotEqual(left, right)

    def test_network_endpoint_normalizes_case_and_trailing_dot(self):
        self.assertEqual(
            canonicalize("network.endpoint", "1", "Example.COM.").digest,
            canonicalize("network.endpoint", "1", "example.com").digest,
        )

    def test_http_origin_elides_the_default_port(self):
        self.assertEqual(
            canonicalize("http.origin", "1", "https://example.com:443").digest,
            canonicalize("http.origin", "1", "https://example.com").digest,
        )
        self.assertNotEqual(
            canonicalize("http.origin", "1", "https://example.com:8443").digest,
            canonicalize("http.origin", "1", "https://example.com").digest,
        )

    def test_filesystem_path_normalizes_trailing_separator(self):
        self.assertEqual(
            canonicalize("filesystem.path", "1", "/srv/app/").digest,
            canonicalize("filesystem.path", "1", "/srv/app").digest,
        )

    def test_git_repository_ref_is_part_of_the_identity(self):
        self.assertEqual(
            canonicalize("git.repository", "1", "/srv/repo").digest,
            canonicalize("git.repository", "1", "/srv/repo#HEAD").digest,
        )
        self.assertNotEqual(
            canonicalize("git.repository", "1", "/srv/repo#main").digest,
            canonicalize("git.repository", "1", "/srv/repo#release").digest,
        )

    def test_portable_reference_carries_identity_without_target_material(self):
        """
        The signed permit must not smuggle the normalized target back in after the raw target was
        deliberately reduced to a digest.
        """
        identity = canonicalize("network.endpoint", "1", "internal.example.com")
        reference = identity.portable_reference()
        self.assertEqual(
            sorted(reference), ["target_canonicalizer_id", "target_canonicalizer_version",
                                 "target_digest"]
        )
        self.assertNotIn("internal.example.com", str(reference))
        self.assertNotIn(identity.canonical_bytes.decode(), str(reference))

    def test_unknown_canonicalizer_is_refused(self):
        with self.assertRaises(TargetIdentityError) as caught:
            canonicalize("does.not.exist", "1", "target")
        self.assertEqual(caught.exception.reason, "UNKNOWN_CANONICALIZER")

    def test_missing_target_is_refused(self):
        with self.assertRaises(TargetIdentityError) as caught:
            canonicalize("network.endpoint", "1", None)
        self.assertEqual(caught.exception.reason, "TARGET_REQUIRED")

    def test_identity_is_stable_across_calls(self):
        first = canonicalize("http.origin", "1", "https://example.com")
        second = canonicalize("http.origin", "1", "https://example.com")
        self.assertEqual(first.digest, second.digest)


if __name__ == "__main__":
    unittest.main()
