"""
Gate A0 closure test - the parser's manifest binding output.

These four cases were the "green but not proven" gap: `parse_raw_receipt` reported a manifest
binding, but nothing asserted it, so 807/807 said nothing about whether the values were right.

Four states, directly covered. The CORRUPT case additionally proves the absence of a legacy
fallback, because "I cannot read the identity claim" must never be reinterpreted as "this merely
predates identity".
"""

import unittest

from ciph.capabilities.capability_ledger import StrictHistoricalReceiptParser
from ciph.kernel.manifest_identity import MANIFEST_IDENTITY_KEY, ManifestIdentity
from ciph.workers.receipts import ExecutionReceipt


def _payload(provenance):
    """Minimal receipt payload, carrying the provenance under test."""
    return {
        "receipt_id": "rcpt_binding",
        "job_id": "JOB-BIND",
        "capability": "test.binding",
        "target": "repo-A",
        "started_at": 1700000000.0,
        "completed_at": 1700000001.0,
        "input_hash": "ih",
        # The parser verifies output_hash against results, so it must be a real hash.
        "output_hash": ExecutionReceipt.hash_payload({}),
        "exit_code": 0,
        "outcome": "SUCCESS",
        "results": {},
        "side_effects": [],
        "idempotency_key": "idem-binding",
        "attempt_number": 1,
        "requested_network_policy": "OFFLINE_ONLY",
        "actual_transport_used": "NONE",
        "worker_id": "worker-A",
        "provenance": provenance,
        "schema_version": "4.1",
    }


class ReceiptParserBindingTests(unittest.TestCase):

    def _metadata(self, provenance):
        _receipt, metadata = StrictHistoricalReceiptParser.parse_raw_receipt(
            _payload(provenance)
        )
        return metadata

    def test_empty_provenance_is_unbound(self):
        metadata = self._metadata({})
        self.assertEqual(metadata["manifest_binding"], "UNBOUND")
        self.assertIsNone(metadata["manifest_identity"])

    def test_valid_versioned_identity_is_reported_exactly(self):
        metadata = self._metadata({
            MANIFEST_IDENTITY_KEY: {"hash_version": 2, "manifest_hash": "XYZ"},
        })
        self.assertEqual(metadata["manifest_binding"], "VERSIONED")
        self.assertEqual(
            metadata["manifest_identity"],
            {"hash_version": 2, "manifest_hash": "XYZ"},
        )
        self.assertEqual(
            ManifestIdentity.from_dict(metadata["manifest_identity"]),
            ManifestIdentity(2, "XYZ"),
        )

    def test_malformed_versioned_identity_is_corrupt_with_no_legacy_fallback(self):
        metadata = self._metadata({
            MANIFEST_IDENTITY_KEY: {"manifest_hash": "ABC"},
            "manifest_hash": "ABC",
        })
        self.assertEqual(metadata["manifest_binding"], "CORRUPT")
        self.assertIsNone(metadata["manifest_identity"])
        self.assertNotEqual(
            metadata["manifest_binding"], "LEGACY_UNVERSIONED",
            "a malformed identity claim must never be downgraded to honest history",
        )
        self.assertIn("MALFORMED_VERSIONED_IDENTITY", metadata["manifest_binding_reason"])

    def test_legacy_bare_hash_without_proof_stays_legacy_unversioned(self):
        metadata = self._metadata({"manifest_hash": "ABC"})
        self.assertEqual(metadata["manifest_binding"], "LEGACY_UNVERSIONED")
        self.assertIsNone(metadata["manifest_identity"])

    def test_binding_fields_do_not_disturb_existing_provenance_reporting(self):
        """The new fields are additive: the pre-existing report keeps working."""
        metadata = self._metadata({"manifest_hash": "ABC"})
        self.assertIn("has_complete_provenance", metadata)
        self.assertIn("manifest_hash", metadata)
        self.assertEqual(metadata["manifest_hash"], "ABC")


if __name__ == "__main__":
    unittest.main()
