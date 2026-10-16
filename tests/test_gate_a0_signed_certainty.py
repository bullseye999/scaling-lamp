"""Cutover tests for the signed effect-certainty contract."""

import unittest

from ciph.contracts.enums import (
    EFFECT_CERTAINTY_CUTOVER_SCHEMA,
    EffectCertainty,
    schema_at_least,
)
from ciph.contracts.enums import NetworkPolicy, OutcomeCategory
from ciph.kernel.crypto_identity import Ed25519KeyManager
from ciph.kernel.performance_metric import (
    CertaintyProvenance,
    classify_certainty_provenance,
    observe_execution_success,
    observe_legacy_execution_outcome,
)
from ciph.workers.receipts import ExecutionReceipt


def _base_fields():
    return dict(
        receipt_id="rcpt_cutover",
        job_id="JOB-CUT",
        capability="test.cutover",
        target="repo-A",
        started_at=1_700_000_000.0,
        completed_at=1_700_000_001.0,
        input_hash="ih",
        output_hash=ExecutionReceipt.hash_payload({"ok": True}),
        exit_code=0,
        outcome=OutcomeCategory.SUCCESS,
        results={"ok": True},
        side_effects=[],
        idempotency_key="idem-cut",
        attempt_number=1,
        requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
        actual_transport_used="NONE",
        worker_id="worker-A",
    )


def _receipt(**overrides):
    base = _base_fields()
    base.update(overrides)
    return ExecutionReceipt(**base)


class VersionComparisonTests(unittest.TestCase):

    def test_comparison_is_numeric_not_lexicographic(self):
        """'4.10' must not sort below '4.2' - the classic landmine."""
        self.assertTrue(schema_at_least("4.10", EFFECT_CERTAINTY_CUTOVER_SCHEMA))
        self.assertTrue(schema_at_least("5.0", EFFECT_CERTAINTY_CUTOVER_SCHEMA))
        self.assertFalse(schema_at_least("4.1", EFFECT_CERTAINTY_CUTOVER_SCHEMA))

    def test_unparseable_versions_are_not_silently_treated_as_current(self):
        self.assertFalse(schema_at_least("not-a-version", EFFECT_CERTAINTY_CUTOVER_SCHEMA))
        self.assertEqual(
            classify_certainty_provenance("not-a-version", None),
            CertaintyProvenance.MALFORMED,
        )


class CutoverClassificationTests(unittest.TestCase):

    def test_pre_cutover_without_certainty_is_legacy(self):
        self.assertEqual(
            classify_certainty_provenance("4.1", None),
            CertaintyProvenance.LEGACY_OUTCOME_ONLY,
        )

    def test_pre_cutover_success_is_historical_and_cannot_satisfy_strict(self):
        legacy = observe_legacy_execution_outcome("SUCCESS", schema_version="4.1")
        self.assertEqual(legacy.score, 1.0)
        self.assertNotEqual(legacy.metric_id, "EXECUTION_SUCCESS")

        # The strict metric, given the same record's information, refuses to confirm anything.
        strict = observe_execution_success("SUCCESS", None)
        self.assertIsNone(strict.score)

    def test_post_cutover_with_certainty_is_strict(self):
        self.assertEqual(
            classify_certainty_provenance("4.2", EffectCertainty.EFFECT_CONFIRMED),
            CertaintyProvenance.STRICT,
        )

    def test_post_cutover_without_certainty_is_malformed_with_no_fallback(self):
        provenance = classify_certainty_provenance("4.2", None)
        self.assertEqual(provenance, CertaintyProvenance.MALFORMED)
        self.assertNotEqual(provenance, CertaintyProvenance.LEGACY_OUTCOME_ONLY)
        with self.assertRaises(ValueError):
            observe_legacy_execution_outcome("SUCCESS", schema_version="4.2")


class SignedReceiptContractTests(unittest.TestCase):

    def test_post_cutover_issuance_requires_certainty(self):
        with self.assertRaises(Exception) as caught:
            _receipt(schema_version=EFFECT_CERTAINTY_CUTOVER_SCHEMA)
        self.assertIn("EFFECT_CERTAINTY_REQUIRED", str(caught.exception))

    def test_post_cutover_issuance_rejects_an_unknown_certainty_value(self):
        with self.assertRaises(Exception) as caught:
            _receipt(schema_version="4.2", effect_certainty="PROBABLY_FINE")
        self.assertIn("UNKNOWN_EFFECT_CERTAINTY", str(caught.exception))

    def test_pre_cutover_receipts_remain_constructible_and_unsigned_over_certainty(self):
        receipt = _receipt()
        self.assertEqual(receipt.schema_version, "4.1")
        self.assertIsNone(receipt.effect_certainty)
        self.assertNotIn("effect_certainty", receipt.compute_signature_payload())

    def test_the_signature_commits_to_certainty(self):
        """If certainty can be edited after signing, it is storage decoration, not evidence."""
        private_key, public_key = Ed25519KeyManager.generate_keypair()
        signed = _receipt(
            schema_version="4.2",
            effect_certainty=EffectCertainty.EFFECT_CONFIRMED.value,
        ).sign(private_key, worker_key_id="worker-A")
        self.assertTrue(signed.verify_signature(public_key))

        mutated = _receipt(
            schema_version="4.2",
            effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value,
        )
        self.assertNotEqual(
            signed.compute_signature_payload(), mutated.compute_signature_payload()
        )

    def test_post_cutover_receipts_round_trip_through_from_dict(self):
        receipt = _receipt(
            schema_version="4.2",
            effect_certainty=EffectCertainty.EFFECT_CONFIRMED.value,
        )
        rebuilt = ExecutionReceipt.from_dict(receipt.to_dict())
        self.assertEqual(rebuilt.schema_version, "4.2")
        self.assertEqual(rebuilt.effect_certainty, "EFFECT_CONFIRMED")

    def test_a_post_cutover_dict_without_certainty_is_refused_on_load(self):
        body = _receipt().to_dict()
        body["schema_version"] = "4.2"
        body.pop("effect_certainty", None)
        with self.assertRaises(Exception):
            ExecutionReceipt.from_dict(body)


class SchemaSupportTests(unittest.TestCase):
    """
    Known schemas only. Version-aware comparison decides cutover semantics *after* recognition; it
    never grants forward compatibility. A future 4.3 may add an authority-critical field this
    parser would ignore while applying 4.2 rules.
    """

    def test_an_unknown_future_schema_is_refused_not_interpreted(self):
        body = _receipt().to_dict()
        body["schema_version"] = "4.3"
        with self.assertRaises(Exception) as caught:
            ExecutionReceipt.from_dict(body)
        self.assertIn("schema_version", str(caught.exception))

    def test_known_legacy_schemas_still_load_as_legacy(self):
        for legacy_version in ("4.0", "1.0", "4.1"):
            with self.subTest(schema=legacy_version):
                body = _receipt().to_dict()
                body["schema_version"] = legacy_version
                body.pop("effect_certainty", None)
                rebuilt = ExecutionReceipt.from_dict(body)
                self.assertEqual(rebuilt.schema_version, "4.1")
                self.assertIsNone(rebuilt.effect_certainty)

    def test_schema_4_1_rejects_certainty_as_noncanonical(self):
        """4.1 never carried certainty; accepting one would blur two schema contracts into one."""
        with self.assertRaises(Exception) as caught:
            _receipt(schema_version="4.1", effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value)
        self.assertIn("EFFECT_CERTAINTY_NOT_IN_SCHEMA_4_1", str(caught.exception))


class IssuanceTests(unittest.TestCase):
    """
    New executions may only be issued under the current schema, with certainty stated explicitly.

    There is deliberately no way to request an older schema: a new execution pinned to 4.1 would
    reopen the legacy downgrade path through schema selection rather than field omission.
    """

    def test_issuance_emits_the_current_schema(self):
        receipt = ExecutionReceipt.issue(
            effect_certainty=EffectCertainty.EFFECT_CONFIRMED.value, **_base_fields()
        )
        self.assertEqual(receipt.schema_version, "4.2")
        self.assertEqual(receipt.effect_certainty, "EFFECT_CONFIRMED")

    def test_issuance_cannot_select_an_older_schema(self):
        with self.assertRaises(Exception) as caught:
            ExecutionReceipt.issue(
                effect_certainty=EffectCertainty.EFFECT_UNKNOWN.value,
                schema_version="4.1",
                **_base_fields()
            )
        self.assertIn("SCHEMA_VERSION_NOT_CALLER_SELECTABLE", str(caught.exception))

    def test_issuance_requires_explicit_certainty(self):
        """UNKNOWN may be the executor's conservative conclusion, but never a constructor default."""
        with self.assertRaises(Exception):
            ExecutionReceipt.issue(**_base_fields())             # omitted entirely
        with self.assertRaises(Exception) as caught:
            ExecutionReceipt.issue(effect_certainty=None, **_base_fields())   # explicit None
        self.assertIn("EFFECT_CERTAINTY_REQUIRED_FOR_ISSUANCE", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
