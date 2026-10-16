
"""
Gate A0 - S3.1 worker-side permit consumer composition.

The worker verifies and spends authority; it never issues it. That has to be a property of what the
worker-side bundle can even hold, not a convention: no ExecutionAuthority, no ExecutionGateway, no
private execution-authority key.
"""

import os
import tempfile
import unittest

from ciph.kernel.permit_composition import (
    build_durable_permit_consumer_dependencies,
    build_durable_permit_dependencies,
)


class PermitConsumerCompositionTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_consumer_")
        self.db = f"{self._dir}/vault.db"

    def test_the_consumer_never_provisions_the_signing_identity(self):
        with self.assertRaises(PermissionError) as caught:
            build_durable_permit_consumer_dependencies(self.db)
        self.assertIn("EXECUTION_AUTHORITY_NOT_PROVISIONED", str(caught.exception))

    def test_the_consumer_resolves_the_same_lineage_the_producer_provisioned(self):
        producer = build_durable_permit_dependencies(self.db)
        consumer = build_durable_permit_consumer_dependencies(self.db)

        self.assertEqual(consumer.authority_public_key, producer.public_key_bytes)
        self.assertEqual(consumer.key_id, producer.key_id)

    def test_the_consumer_bundle_has_no_issuance_capability(self):
        build_durable_permit_dependencies(self.db)
        consumer = build_durable_permit_consumer_dependencies(self.db)

        for forbidden in ("authority", "gateway", "issue_permit", "_authority"):
            self.assertFalse(hasattr(consumer, forbidden), forbidden)
        # It can verify and spend, which is the whole worker surface.
        self.assertTrue(hasattr(consumer, "verifier"))
        self.assertTrue(hasattr(consumer, "permit_store"))

    def test_the_verifier_holds_only_a_public_key(self):
        build_durable_permit_dependencies(self.db)
        consumer = build_durable_permit_consumer_dependencies(self.db)
        self.assertEqual(len(consumer.authority_public_key), 32)
        self.assertEqual(len(consumer.verifier._public_key), 32)
        self.assertFalse(hasattr(consumer.verifier, "_private_key"))


if __name__ == "__main__":
    unittest.main()
