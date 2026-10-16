"""
Gate A0 closure test - Steps 2 and 3 of the throat plan.

ExecutionAuthority signing role, and the canonical signed portable ExecutionPermit.
Decision of record: EXECUTION PERMIT V1.

WHAT IS BEING PROVEN
Not merely "signatures verify", but the two properties that make the authority boundary real:

  role separation   a permit signed by the receipt authority is rejected, in both directions
  no minting power  the verifier holds a public key only, so a compromised worker path cannot
                    manufacture authority even though it can run arbitrary code

Canonical serialization is tested first, because a signature over a non-deterministic encoding is
not a signature over meaning.
"""

import time
import unittest

from ciph.kernel.crypto_identity import Ed25519KeyManager
from ciph.kernel.execution_authority import (
    DENY_BAD_KEY_ID,
    DENY_BAD_SIGNATURE,
    DENY_BAD_VERSION,
    DENY_EXPIRED,
    PERMIT_VERSION,
    ROLE_RECEIPT,
    ExecutionAuthority,
    ExecutionPermitPayload,
    ExecutionPermitVerifier,
    PermitError,
    PermitVerificationError,
    SignedExecutionPermit,
    canonical_permit_bytes,
    execution_permit_digest,
    target_digest,
    time_us,
)


class CanonicalSerializationTests(unittest.TestCase):

    def test_key_order_does_not_change_the_signed_bytes(self):
        """Otherwise the same permit eventually verifies in one process and not another."""
        first = {"b": 2, "a": 1, "c": None}
        second = {"c": None, "a": 1, "b": 2}
        self.assertEqual(canonical_permit_bytes(first), canonical_permit_bytes(second))

    def test_encoding_is_compact_and_ascii_stable(self):
        encoded = canonical_permit_bytes({"k": "value", "n": 1})
        self.assertNotIn(b" ", encoded)
        self.assertEqual(encoded, b'{"k":"value","n":1}')

    def test_semantically_identical_payloads_serialize_identically(self):
        left = ExecutionPermitPayload.build(
            capability_id="cap.read", request_digest="rd", action_fingerprint="af",
            issued_at_us=1_000_000_000, ttl_seconds=30, target="repo-A",
        )
        right = ExecutionPermitPayload.build(
            capability_id="cap.read", request_digest="rd", action_fingerprint="af",
            issued_at_us=1_000_000_000, ttl_seconds=30, target="repo-A",
        )
        # Different permit_id and nonce by construction, so compare the stable projection.
        left_body = {k: v for k, v in left.as_mapping().items()
                     if k not in ("permit_id", "nonce")}
        right_body = {k: v for k, v in right.as_mapping().items()
                      if k not in ("permit_id", "nonce")}
        self.assertEqual(canonical_permit_bytes(left_body), canonical_permit_bytes(right_body))


class PermitAuthorityTests(unittest.TestCase):

    def setUp(self):
        self.authority, self.authority_public = ExecutionAuthority.generate()
        self.verifier = ExecutionPermitVerifier(
            self.authority_public, key_id=self.authority.key_id
        )
        self.receipt_private, self.receipt_public = Ed25519KeyManager.generate_keypair()

    def _payload(self, ttl=30.0, issued_at_us=None, version=PERMIT_VERSION, target="repo-A"):
        moment = issued_at_us if issued_at_us is not None else time_us()
        return ExecutionPermitPayload.build(
            capability_id="capability.read",
            request_digest="digest-of-exact-request",
            action_fingerprint="action-fingerprint",
            issued_at_us=moment,
            ttl_seconds=ttl,
            target=target,
            permit_version=version,
            scope_grant_id="scope-1",
            authorization_epoch=7,
            lease_set_digest="lease-digest",
        )

    def test_valid_permit_verifies(self):
        permit = self.authority.issue_permit(self._payload())
        self.assertIs(self.verifier.verify(permit), permit)

    def test_serialized_permit_survives_a_process_boundary(self):
        """The worker receives bytes, not an object graph."""
        permit = self.authority.issue_permit(self._payload())
        rebuilt = SignedExecutionPermit.from_dict(permit.to_dict())
        self.assertEqual(rebuilt.payload.canonical_bytes(), permit.payload.canonical_bytes())
        self.verifier.verify(rebuilt)

    def test_modified_payload_fails_verification(self):
        permit = self.authority.issue_permit(self._payload())
        body = permit.to_dict()
        body["capability_id"] = "capability.delete_everything"
        tampered = SignedExecutionPermit.from_dict(body)
        with self.assertRaises(PermitVerificationError) as caught:
            self.verifier.verify(tampered)
        self.assertEqual(caught.exception.reason, DENY_BAD_SIGNATURE)

    def test_forged_signature_fails_verification(self):
        permit = self.authority.issue_permit(self._payload())
        forged = SignedExecutionPermit(
            payload=permit.payload,
            signature="00" * 64,
            key_id=permit.key_id,
            signing_epoch=permit.signing_epoch,
        )
        with self.assertRaises(PermitVerificationError) as caught:
            self.verifier.verify(forged)
        self.assertEqual(caught.exception.reason, DENY_BAD_SIGNATURE)

    def test_permit_signed_by_the_receipt_authority_is_rejected(self):
        """
        Key-role separation, direction one: a permit that honestly declares the receipt authority
        is refused before any signature work, because these are different roles.
        """
        payload = self._payload()
        signature = Ed25519KeyManager.sign(self.receipt_private, payload.canonical_bytes())
        permit = SignedExecutionPermit(
            payload=payload, signature=signature,
            key_id="receipt_authority_primary", signing_epoch=1,
        )
        with self.assertRaises(PermitVerificationError) as caught:
            self.verifier.verify(permit)
        self.assertEqual(caught.exception.reason, DENY_BAD_KEY_ID)

    def test_receipt_key_cannot_impersonate_the_execution_authority(self):
        """
        Key-role separation, direction two: claiming the execution key id while holding the receipt
        private key must fail, which is what makes the roles cryptographic rather than nominal.
        """
        payload = self._payload()
        signature = Ed25519KeyManager.sign(self.receipt_private, payload.canonical_bytes())
        permit = SignedExecutionPermit(
            payload=payload, signature=signature,
            key_id=self.authority.key_id, signing_epoch=self.authority.signing_epoch,
        )
        with self.assertRaises(PermitVerificationError) as caught:
            self.verifier.verify(permit)
        self.assertEqual(caught.exception.reason, DENY_BAD_SIGNATURE)

    def test_verifier_cannot_mint_authority(self):
        """The worker holds a public key. This asserts it has no signing surface at all."""
        self.assertFalse(hasattr(self.verifier, "issue_permit"))
        self.assertFalse(hasattr(self.verifier, "sign"))
        self.assertFalse(hasattr(self.verifier, "_private_key"))
        for name in dir(self.verifier):
            self.assertNotIn("private", name.lower())

    def test_authority_has_no_generic_blob_signing_interface(self):
        """A signer that can sign anything is a signing oracle."""
        public_methods = {
            name for name in dir(self.authority)
            if not name.startswith("_") and callable(getattr(self.authority, name))
        }
        signing_surface = {
            name for name in public_methods
            if "sign" in name.lower() and name != "signing_epoch"
        }
        self.assertEqual(signing_surface, set(), f"generic signing surface: {signing_surface}")

    def test_expired_permit_is_rejected(self):
        moment = time_us() - 600_000_000
        permit = self.authority.issue_permit(self._payload(ttl=30.0, issued_at_us=moment))
        with self.assertRaises(PermitVerificationError) as caught:
            self.verifier.verify(permit)
        self.assertEqual(caught.exception.reason, DENY_EXPIRED)

    def test_unsupported_permit_version_is_refused_at_issuance_and_verification(self):
        with self.assertRaises(PermitError):
            self.authority.issue_permit(self._payload(version="99"))
        payload = self._payload()
        permit = SignedExecutionPermit(
            payload=payload, signature="00" * 64,
            key_id=self.authority.key_id, signing_epoch=1,
        )
        object.__setattr__(payload, "permit_version", "99")
        with self.assertRaises(PermitVerificationError) as caught:
            self.verifier.verify(permit)
        self.assertEqual(caught.exception.reason, DENY_BAD_VERSION)

    def test_authority_refuses_a_permit_that_expires_before_it_is_issued(self):
        payload = self._payload()
        broken = ExecutionPermitPayload(
            **{**payload.as_mapping(), "expires_at_us": payload.issued_at_us - 1}
        )
        with self.assertRaises(PermitError):
            self.authority.issue_permit(broken)

    def test_authority_refuses_a_long_lived_permit(self):
        """The mission envelope is long-lived authority; a permit is one instantiation of it."""
        with self.assertRaises(PermitError):
            self.authority.issue_permit(self._payload(ttl=7200.0))

    def test_signed_body_contains_no_floating_point(self):
        """
        Floats are forbidden in a signed permit body. A decimal rendering is not a portable
        cryptographic primitive: the first non-Python verifier could disagree about the bytes
        without anybody altering the permit.
        """
        permit = self.authority.issue_permit(self._payload())
        body = permit.payload.as_mapping()
        for key, value in body.items():
            self.assertNotIsInstance(
                value, float, f"{key} is a float in a signed body: {value!r}"
            )
        encoded = permit.payload.canonical_bytes().decode("utf-8")
        self.assertNotIn(".", encoded.split("issued_at_us")[1][:24])
        self.assertIsInstance(body["issued_at_us"], int)
        self.assertIsInstance(body["expires_at_us"], int)

    def test_microsecond_ttl_is_exact_integer_arithmetic(self):
        payload = self._payload(ttl=0.5)
        self.assertEqual(
            payload.expires_at_us - payload.issued_at_us, 500_000
        )

    def test_permit_envelope_digest_is_stable_and_portable(self):
        permit = self.authority.issue_permit(self._payload())
        rebuilt = SignedExecutionPermit.from_dict(permit.to_dict())
        self.assertEqual(permit.permit_digest(), execution_permit_digest(rebuilt))
        self.assertEqual(permit.permit_digest(), permit.permit_digest())

    def test_envelope_digest_covers_signature_metadata_not_just_the_body(self):
        """A receipt must cite this exact artifact, not anything sharing an id."""
        permit = self.authority.issue_permit(self._payload())
        base = permit.permit_digest()
        for replacement in (
            SignedExecutionPermit(permit.payload, permit.signature, "other_key", 1),
            SignedExecutionPermit(permit.payload, permit.signature, permit.key_id, 99),
            SignedExecutionPermit(permit.payload, "ab" * 64, permit.key_id, 1),
        ):
            with self.subTest(replacement=replacement.key_id + str(replacement.signing_epoch)):
                self.assertNotEqual(base, execution_permit_digest(replacement))

    def test_envelope_digest_is_domain_separated(self):
        """Not merely SHA256(body): the domain prefix is part of the contract."""
        import hashlib
        permit = self.authority.issue_permit(self._payload())
        plain = hashlib.sha256(permit.payload.canonical_bytes()).hexdigest()
        self.assertNotEqual(plain, permit.permit_digest())

    def test_permit_digest_is_not_inside_the_signed_body(self):
        """No circularity: the digest never appears in the material it digests."""
        permit = self.authority.issue_permit(self._payload())
        self.assertNotIn("permit_digest", permit.payload.as_mapping())
        self.assertNotIn("execution_permit_digest", permit.payload.as_mapping())
        self.assertNotIn(permit.permit_digest().encode(), permit.payload.canonical_bytes())

    def test_target_is_carried_as_a_digest_not_in_the_clear(self):
        permit = self.authority.issue_permit(self._payload(target="secret-internal-host"))
        serialized = str(permit.to_dict())
        self.assertNotIn("secret-internal-host", serialized)
        self.assertEqual(permit.payload.target_digest, target_digest("secret-internal-host"))


if __name__ == "__main__":
    unittest.main()
