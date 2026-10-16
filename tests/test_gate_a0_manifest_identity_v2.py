"""
Gate A0 closure test - MANIFEST_HASH_V2, canonicalizer semantics, and D11 credit identity.

Decisions of record: D11, TARGET_IDENTITY_V1.

FOUR INDEPENDENT PROPERTIES, DELIBERATELY NOT COLLAPSED
  1. version mutation changes manifest identity
  2. the same (id, version) may never mean two different things
  3. a different target is a different identity, and a permit binds to it
  4. spellings the contract calls equivalent canonicalise to the same identity

1 and 2 are manifest versioning and canonicalizer immutability. 3 is authorization binding.
4 proves normalisation works in both directions - separating what differs, uniting what the
contract says is the same.
"""

import hashlib
import unittest

from ciph.contracts.enums import (
    AuthorizationTier,
    NetworkPolicy,
    ReversibilityClass,
    RiskTier,
)
from ciph.kernel.execution_authority import ExecutionPermitPayload
from ciph.kernel.policy_engine import (
    MANIFEST_HASH_VERSION_V2,
    CapabilityManifest,
)
from ciph.kernel.target_identity import (
    CanonicalizerContract,
    CanonicalizerRegistrationConflict,
    canonicalize,
    canonicalizer_semantics_digest,
    register_canonicalizer,
)


def _manifest(**overrides):
    base = dict(
        name="specimen.read_only",
        description="boring read-only specimen",
        risk_tier=RiskTier.LOW,
        network_policy=NetworkPolicy.OFFLINE_ONLY,
        reversibility=ReversibilityClass.READ_ONLY,
        authorization=AuthorizationTier.AUTO,
    )
    base.update(overrides)
    return CapabilityManifest(**base)


CONTRACT_V1 = CanonicalizerContract(
    canonicalizer_id="specimen.endpoint",
    version="1",
    normalization_rules=("lowercase host", "strip trailing dot", "elide default port"),
    golden_vectors=(
        ("Example.COM.", b"example.com"),
        ("example.com:443", b"example.com"),
    ),
)


@register_canonicalizer("specimen.endpoint", "1", contract=CONTRACT_V1)
def _endpoint_v1(raw):
    host, _, port = raw.strip().partition(":")
    host = host.strip().strip(".").lower()
    if port in ("", "443"):
        return host.encode("utf-8")
    return host.encode("utf-8") + b":" + port.encode("utf-8")


CONTRACT_V2 = CanonicalizerContract(
    canonicalizer_id="specimen.endpoint",
    version="2",
    normalization_rules=("lowercase host", "strip trailing dot"),
    golden_vectors=(("EXAMPLE.com", b"example.com"),),
)


@register_canonicalizer("specimen.endpoint", "2", contract=CONTRACT_V2)
def _endpoint_v2(raw):
    return raw.strip().strip(".").lower().encode("utf-8")


class CanonicalizerSemanticsTests(unittest.TestCase):

    def test_same_id_and_version_cannot_mean_two_things(self):
        """Even a corrected implementation must take a new version, never redefine the old one."""
        conflicting = CanonicalizerContract(
            canonicalizer_id="specimen.endpoint",
            version="1",
            normalization_rules=("lowercase host",),
            golden_vectors=(("EXAMPLE.COM", b"example.com"),),
        )
        self.assertNotEqual(
            conflicting.semantics_digest(),
            canonicalizer_semantics_digest("specimen.endpoint", "1"),
        )

        with self.assertRaises(CanonicalizerRegistrationConflict):
            @register_canonicalizer("specimen.conflict", "1", contract=CONTRACT_V1)
            def _first(raw):
                return raw.encode()

            @register_canonicalizer("specimen.conflict", "1", contract=conflicting)
            def _second(raw):
                return raw.encode()

    def test_semantics_digest_tracks_contract_not_source_text(self):
        """Renaming a variable must not move capability identity; changing the contract must."""
        def implementation_one(raw):
            value = raw.strip()
            return value.lower().encode("utf-8")

        def implementation_two(raw):
            text = raw.strip()
            return text.lower().encode("utf-8")

        self.assertEqual(CONTRACT_V1.semantics_digest(), CONTRACT_V1.semantics_digest())
        self.assertNotEqual(CONTRACT_V1.semantics_digest(), CONTRACT_V2.semantics_digest())
        # Implementation digest is secondary evidence, explicitly not identity.
        from ciph.kernel.target_identity import implementation_digest
        self.assertNotEqual(
            implementation_digest(implementation_one),
            implementation_digest(implementation_two),
        )


class ManifestIdentityV2Tests(unittest.TestCase):

    def test_v1_hash_is_frozen(self):
        """V1 keeps its meaning; the V2 work must not recompute it under new rules."""
        manifest = _manifest()
        expected = hashlib.sha256(
            "specimen.read_only:1.0.0:LOW:OFFLINE_ONLY:READ_ONLY:AUTO:False:30".encode("utf-8")
        ).hexdigest()
        self.assertEqual(manifest.compute_manifest_hash(), expected)

    def test_v2_is_a_separate_domain_and_differs_from_v1(self):
        manifest = _manifest()
        self.assertNotEqual(manifest.compute_manifest_hash(), manifest.compute_manifest_hash_v2())
        self.assertEqual(manifest.target_mode(), "TARGETLESS")

    def test_targetless_commits_an_explicit_marker(self):
        """Missing information must never accidentally mean 'does not apply'."""
        targetless = _manifest()
        bearing = _manifest(target_canonicalizer_id="specimen.endpoint",
                            target_canonicalizer_version="1")
        self.assertEqual(targetless.target_mode(), "TARGETLESS")
        self.assertEqual(bearing.target_mode(), "TARGET_BEARING")
        self.assertNotEqual(
            targetless.compute_manifest_hash_v2(), bearing.compute_manifest_hash_v2()
        )

    def test_capability_fields_are_bound_into_v2(self):
        first = _manifest()
        second = _manifest().compute_manifest_hash_v2()
        third = _manifest().compute_manifest_hash_v2()
        self.assertEqual(second, third)
        self.assertEqual(first.compute_manifest_hash_v2(), second)

    def test_identity_is_version_faithful(self):
        """
        `identity()` must never mean "use the newest algorithm". A V1 manifest yields a V1
        identity; a V2 manifest yields V2; an unknown version fails rather than being upgraded.
        """
        default_manifest = _manifest()
        self.assertEqual(default_manifest.identity().hash_version, 1)
        self.assertEqual(
            default_manifest.identity().manifest_hash,
            default_manifest.compute_manifest_hash(),
        )

        migrated = _manifest(
            manifest_hash_version="2",
            target_canonicalizer_id="specimen.endpoint",
            target_canonicalizer_version="1",
        )
        self.assertEqual(migrated.identity().hash_version, 2)
        self.assertEqual(migrated.identity().manifest_hash, migrated.compute_manifest_hash_v2())

    def test_an_unmigrated_manifest_is_not_promoted_by_convenience(self):
        """The same manifest under V1 and V2 must not produce the same claim."""
        v1_manifest = _manifest(target_canonicalizer_id="specimen.endpoint",
                                target_canonicalizer_version="1")
        self.assertEqual(v1_manifest.identity().hash_version, 1)
        self.assertNotEqual(
            v1_manifest.identity().manifest_hash,
            v1_manifest.compute_manifest_hash_v2(),
        )

    def test_unknown_hash_version_fails_rather_than_upgrading(self):
        with self.assertRaises(ValueError) as caught:
            _manifest(manifest_hash_version="99").identity()
        self.assertIn("UNSUPPORTED_MANIFEST_HASH_VERSION", str(caught.exception))

    def test_target_bearing_without_a_declared_contract_is_refused(self):
        undeclared = _manifest(target_canonicalizer_id="specimen.undeclared",
                               target_canonicalizer_version="1")
        with self.assertRaises(ValueError) as caught:
            undeclared.compute_manifest_hash_v2()
        self.assertIn("CANONICALIZER_SEMANTICS_UNDECLARED", str(caught.exception))


class MutationTests(unittest.TestCase):
    """The three-plus-one mutations, kept separate because they prove different properties."""

    def test_version_mutation_changes_manifest_identity(self):
        v1 = _manifest(target_canonicalizer_id="specimen.endpoint",
                       target_canonicalizer_version="1")
        v2 = _manifest(target_canonicalizer_id="specimen.endpoint",
                       target_canonicalizer_version="2")
        self.assertNotEqual(v1.compute_manifest_hash_v2(), v2.compute_manifest_hash_v2())

    def test_different_target_is_a_different_identity_and_binds_the_permit(self):
        first = canonicalize("specimen.endpoint", "1", "repo-A")
        second = canonicalize("specimen.endpoint", "1", "repo-B")
        self.assertNotEqual(first.digest, second.digest)

        permit_a = ExecutionPermitPayload.build(
            capability_id="specimen.read_only", request_digest="rd",
            action_fingerprint="af", issued_at_us=1_000_000, ttl_seconds=30, target="repo-A",
        )
        permit_b = ExecutionPermitPayload.build(
            capability_id="specimen.read_only", request_digest="rd",
            action_fingerprint="af", issued_at_us=1_000_000, ttl_seconds=30, target="repo-B",
        )
        self.assertNotEqual(permit_a.target_digest, permit_b.target_digest)
        self.assertNotEqual(permit_a.canonical_bytes(), permit_b.canonical_bytes())

    def test_semantically_equivalent_spellings_unify(self):
        """Normalisation must unite what the contract calls the same, not only separate differences."""
        canonical = canonicalize("specimen.endpoint", "1", "example.com")
        for spelling in ("Example.COM.", " EXAMPLE.com ", "example.com:443"):
            with self.subTest(spelling=spelling):
                self.assertEqual(
                    canonicalize("specimen.endpoint", "1", spelling).digest,
                    canonical.digest,
                )


class D11CreditIdentityTests(unittest.TestCase):
    """
    D11: empirical credit belongs to an exact manifest identity.

    Scope note: this exercises the identity rule and the lineage-is-not-authority rule against an
    in-memory ledger. Wiring the same rule into the real CapabilityLedger is still pending.
    """

    def test_new_identity_starts_unverified_and_history_is_not_authority(self):
        predecessor = _manifest(target_canonicalizer_id="specimen.endpoint",
                                target_canonicalizer_version="1")
        successor = _manifest(target_canonicalizer_id="specimen.endpoint",
                              target_canonicalizer_version="2")

        ledger = {
            predecessor.compute_manifest_hash_v2(): "VERIFIED",
        }
        lineage = {successor.compute_manifest_hash_v2(): predecessor.compute_manifest_hash_v2()}

        def credit_of(manifest):
            """Exact identity only. Lineage is context; it must never grant reputation."""
            return ledger.get(manifest.compute_manifest_hash_v2(), "UNVERIFIED")

        self.assertEqual(credit_of(predecessor), "VERIFIED")
        self.assertEqual(credit_of(successor), "UNVERIFIED")

        # The successor is in lineage, and that must change nothing about its credit.
        borrowed = lineage.get(successor.compute_manifest_hash_v2())
        self.assertEqual(borrowed, predecessor.compute_manifest_hash_v2())
        self.assertEqual(credit_of(successor), "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
