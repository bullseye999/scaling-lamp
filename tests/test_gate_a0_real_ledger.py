
"""
Gate A0 closure test - real ledger credit path (D11).

The ledger's authoritative path must be thin: resolve, load, adapt, compose. These specimens drive
the real CapabilityLedger against a real EventStore, so the credit result is computed from stored
receipts rather than from hand-built EvidenceRecords.
"""

import tempfile
import unittest

from ciph.capabilities.capability_ledger import CapabilityLedger
from ciph.contracts.enums import EffectCertainty, NetworkPolicy, OutcomeCategory
from ciph.kernel.manifest_credit import CreditStatus, IncidentScope
from ciph.kernel.manifest_identity import ManifestIdentity
from ciph.memory.event_store import EventStore
from ciph.workers.receipts import ExecutionReceipt

WORKER_KEY = bytes(range(32))
H1 = ManifestIdentity(2, "H1")
H2 = ManifestIdentity(2, "H2")

VERSIONED_H1 = {"manifest_identity": {"hash_version": 2, "manifest_hash": "H1"}}
VERSIONED_H2 = {"manifest_identity": {"hash_version": 2, "manifest_hash": "H2"}}
CONFLICTING = {
    "governed": {"manifest_identity": {"hash_version": 2, "manifest_hash": "H2"}},
    "manifest_identity": {"hash_version": 2, "manifest_hash": "H1"},
}


class _Manifest:
    """Stands in for a resolved capability manifest; the credit path only asks for its identity."""

    def __init__(self, identity):
        self._identity = identity

    def identity(self):
        return self._identity


class _Registry:
    """Maps capability names to manifests; a bare manifest applies to every name asked for."""

    def __init__(self, manifests):
        self._manifests = manifests if isinstance(manifests, dict) else {"cap.X": manifests}

    def get_manifest(self, name):
        return self._manifests.get(name)

    def get(self, name):
        return None


def _fields(outcome, exit_code, provenance, receipt_id, capability="cap.X"):
    results = {"ok": outcome is OutcomeCategory.SUCCESS}
    return dict(
        receipt_id=receipt_id,
        job_id=f"JOB-{receipt_id}",
        capability=capability,
        target="t",
        started_at=1_700_000_000.0,
        completed_at=1_700_000_001.0,
        input_hash="ih",
        output_hash=ExecutionReceipt.hash_payload(results),
        exit_code=exit_code,
        outcome=outcome,
        results=results,
        side_effects=[],
        idempotency_key="idem",
        attempt_number=1,
        requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
        actual_transport_used="NONE",
        worker_id="worker-A",
        provenance=provenance,
    )


def _strict(provenance, certainty, outcome=OutcomeCategory.SUCCESS, exit_code=0,
            receipt_id="rcpt", capability="cap.X"):
    receipt = ExecutionReceipt.issue(
        effect_certainty=certainty,
        **_fields(outcome, exit_code, provenance, receipt_id, capability)
    )
    return receipt.sign(WORKER_KEY, worker_key_id="worker-A")


def _unsigned(provenance, certainty, outcome=OutcomeCategory.SUCCESS, exit_code=0,
              receipt_id="rcpt_unsigned", capability="cap.X"):
    """No signature: the capability label is present but unauthenticated."""
    return ExecutionReceipt.issue(
        effect_certainty=certainty,
        **_fields(outcome, exit_code, provenance, receipt_id, capability)
    )


def _historical(provenance, receipt_id="rcpt_legacy", capability="cap.X"):
    receipt = ExecutionReceipt(
        schema_version="4.1",
        **_fields(OutcomeCategory.SUCCESS, 0, provenance, receipt_id, capability)
    )
    return receipt.sign(WORKER_KEY, worker_key_id="worker-A")


class RealLedgerCreditTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_ledger_credit_")
        self.db = f"{self._dir}/vault.db"
        self.event_store = EventStore(self.db)

    def _ledger(self, identity):
        return self._ledger_multi(_Manifest(identity))

    def _ledger_multi(self, manifests):
        return CapabilityLedger(
            self.event_store,
            _Registry(manifests),
            worker_secret_key=WORKER_KEY,
            db_path=self.db,
        )

    def _store(self, receipt):
        self.event_store.append_event(
            "ExecutionReceiptStoredEvent", receipt.receipt_id, receipt.to_dict()
        )

    def test_strong_history_on_one_identity_cannot_authorize_its_successor(self):
        """
        The D11 specimen: H1 has overwhelming strict evidence, H2 has none. The real ledger must
        refuse H2 instead of reaching for the predecessor's strength.
        """
        for index in range(100):
            self._store(_strict(VERSIONED_H1, EffectCertainty.EFFECT_CONFIRMED,
                                receipt_id=f"rcpt_h1_{index}"))

        result = self._ledger(H2).get_current_credit("cap.X")

        self.assertEqual(result.status, CreditStatus.UNVERIFIED)
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.excluded_historical_count, 100)
        self.assertFalse(result.authority_usable)
        # A different manifest identity is not a different metric, and not a semantic exclusion.
        # The 100 belong to lineage context, not to any current-H2 evidence bucket.
        self.assertEqual(result.different_metric_excluded_count, 0)
        self.assertEqual(result.semantic_excluded_count, 0)
        self.assertEqual(result.unobserved_count, 0)

    def test_excellent_stored_evidence_is_verified_and_usable(self):
        for index in range(10):
            self._store(_strict(VERSIONED_H2, EffectCertainty.EFFECT_CONFIRMED,
                                receipt_id=f"rcpt_h2_{index}"))

        result = self._ledger(H2).get_current_credit("cap.X")

        self.assertEqual(result.status, CreditStatus.VERIFIED)
        self.assertEqual(result.usable_evidence_count, 10)
        self.assertEqual(result.mean_performance, 1.0)
        self.assertTrue(result.authority_usable)

    def test_a_corrupt_record_blocks_authority_without_moving_the_statistics(self):
        for index in range(10):
            self._store(_strict(VERSIONED_H2, EffectCertainty.EFFECT_CONFIRMED,
                                receipt_id=f"rcpt_ok_{index}"))
        self._store(_strict(CONFLICTING, EffectCertainty.EFFECT_CONFIRMED, receipt_id="rcpt_bad"))

        result = self._ledger(H2).get_current_credit("cap.X")

        self.assertEqual(result.usable_evidence_count, 10)
        self.assertEqual(result.mean_performance, 1.0)
        self.assertEqual(result.status, CreditStatus.INTEGRITY_BLOCKED)
        self.assertFalse(result.authority_usable)

    def test_unknown_effect_receipts_are_semantic_exclusions_not_failures(self):
        for index in range(5):
            self._store(_strict(VERSIONED_H2, EffectCertainty.EFFECT_UNKNOWN,
                                receipt_id=f"rcpt_unknown_{index}"))

        result = self._ledger(H2).get_current_credit("cap.X")

        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.semantic_excluded_count, 5)
        self.assertEqual(result.status, CreditStatus.UNVERIFIED)
        self.assertFalse(result.authority_usable)

    def test_historical_legacy_receipts_are_a_different_metric_not_strict_credit(self):
        for index in range(7):
            self._store(_historical(VERSIONED_H2, receipt_id=f"rcpt_legacy_{index}"))

        result = self._ledger(H2).get_current_credit("cap.X")

        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.different_metric_excluded_count, 7)
        self.assertFalse(result.authority_usable)

    def test_another_capabilitys_corruption_does_not_contaminate_a_clean_capability(self):
        """Containment in production: Y's trusted-attributed corruption must not touch X."""
        for index in range(10):
            self._store(_strict(VERSIONED_H2, EffectCertainty.EFFECT_CONFIRMED,
                                receipt_id=f"rcpt_x_{index}", capability="cap.X"))
        self._store(_strict(CONFLICTING, EffectCertainty.EFFECT_CONFIRMED,
                            receipt_id="rcpt_y_bad", capability="cap.Y"))

        result = self._ledger_multi({
            "cap.X": _Manifest(H2),
            "cap.Y": _Manifest(ManifestIdentity(2, "H2Y")),
        }).get_current_credit("cap.X")

        self.assertEqual(result.integrity_incidents, ())
        self.assertEqual(result.usable_evidence_count, 10)
        self.assertTrue(result.authority_usable)

    def test_unattributable_corruption_blocks_every_capability_as_ledger_global(self):
        """An unauthenticated corrupt record belongs to no partition, so it blocks all of them."""
        self._store(_strict(VERSIONED_H2, EffectCertainty.EFFECT_CONFIRMED,
                            receipt_id="rcpt_x_ok", capability="cap.X"))
        self._store(_unsigned(CONFLICTING, EffectCertainty.EFFECT_CONFIRMED,
                              receipt_id="rcpt_global_bad", capability="cap.UNKNOWN"))
        self._store(_strict(VERSIONED_H2, EffectCertainty.EFFECT_CONFIRMED,
                            receipt_id="rcpt_y_ok", capability="cap.Y"))

        ledger = self._ledger_multi({
            "cap.X": _Manifest(H2),
            "cap.Y": _Manifest(ManifestIdentity(2, "H2Y")),
        })

        for capability in ("cap.X", "cap.Y"):
            with self.subTest(capability=capability):
                result = ledger.get_current_credit(capability)
                self.assertFalse(result.authority_usable)
                self.assertEqual(result.integrity_incidents[0].scope, IncidentScope.LEDGER_GLOBAL)

    def test_lineage_diagnostic_surfaces_the_strong_ancestor_without_credit(self):
        for index in range(100):
            self._store(_strict(VERSIONED_H1, EffectCertainty.EFFECT_CONFIRMED,
                                receipt_id=f"rcpt_h1_{index}"))

        history = self._ledger(H2).get_lineage_credit_history("cap.X")

        self.assertEqual(history.current_identity, H2)
        self.assertEqual(len(history.ancestor_entries), 1)
        self.assertEqual(history.ancestor_entries[0].identity, H1)
        self.assertIn("100", history.ancestor_entries[0].reason)
        # The diagnostic type carries no spendable field for a policy to consume.
        self.assertFalse(hasattr(history, "authority_usable"))
        self.assertFalse(hasattr(history, "credit"))


if __name__ == "__main__":
    unittest.main()
