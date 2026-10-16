
"""
Gate A0 closure test - D11 policy seal.

The policy spends exactly one verdict: this identity, now. It accepts a CurrentCreditResult and
nothing else, and it resolves no ancestors - so history cannot re-enter authority through a
refactor that "helpfully" looks at the predecessor.
"""

import inspect
import tempfile
import unittest

from ciph.capabilities.capability_ledger import CapabilityLedger
from ciph.contracts.enums import EffectCertainty
from ciph.kernel.credit_policy import CreditDecision, authorize_current_credit
from ciph.kernel.manifest_credit import CreditStatus, LineageCreditHistory
from ciph.memory.event_store import EventStore

from test_gate_a0_real_ledger import (
    CONFLICTING,
    H1,
    H2,
    VERSIONED_H1,
    VERSIONED_H2,
    WORKER_KEY,
    _Manifest,
    _Registry,
    _strict,
)


class CreditPolicySealTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_policy_")
        self.db = f"{self._dir}/vault.db"
        self.event_store = EventStore(self.db)

    def _ledger(self, identity):
        return CapabilityLedger(
            self.event_store,
            _Registry(_Manifest(identity)),
            worker_secret_key=WORKER_KEY,
            db_path=self.db,
        )

    def _store(self, receipt):
        self.event_store.append_event(
            "ExecutionReceiptStoredEvent", receipt.receipt_id, receipt.to_dict()
        )

    def test_policy_accepts_only_a_current_credit_result(self):
        parameters = set(inspect.signature(authorize_current_credit).parameters)
        self.assertEqual(parameters, {"result"})
        for forbidden in ("evidence", "lineage", "history", "ancestors", "predecessor"):
            self.assertNotIn(forbidden, parameters)

    def test_policy_refuses_a_lineage_history_and_a_raw_evidence_list(self):
        with self.assertRaises(TypeError):
            authorize_current_credit(LineageCreditHistory(current_identity=H2))
        with self.assertRaises(TypeError):
            authorize_current_credit([])

    def test_strong_history_on_h1_does_not_authorize_h2(self):
        """The seal: overwhelming ancestor credit is invisible to the authority decision."""
        for index in range(100):
            self._store(_strict(VERSIONED_H1, EffectCertainty.EFFECT_CONFIRMED,
                                receipt_id=f"rcpt_h1_{index}"))
        ledger = self._ledger(H2)

        lineage_calls = []
        original = ledger.get_lineage_credit_history

        def spy(*args, **kwargs):
            lineage_calls.append(args)
            return original(*args, **kwargs)

        ledger.get_lineage_credit_history = spy

        result = ledger.get_current_credit("cap.X")
        decision = authorize_current_credit(result)

        self.assertEqual(result.status, CreditStatus.UNVERIFIED)
        self.assertEqual(decision.decision, CreditDecision.REFUSED)
        self.assertEqual(decision.reason, "NO_USABLE_EXACT_EVIDENCE")
        self.assertEqual(lineage_calls, [])

    def test_verified_exact_evidence_is_authorized(self):
        """The inverse sanity check: the policy is not simply hardcoded to refuse."""
        for index in range(10):
            self._store(_strict(VERSIONED_H2, EffectCertainty.EFFECT_CONFIRMED,
                                receipt_id=f"rcpt_h2_{index}"))

        result = self._ledger(H2).get_current_credit("cap.X")
        decision = authorize_current_credit(result)

        self.assertEqual(decision.decision, CreditDecision.AUTHORIZED)
        self.assertEqual(decision.reason, "AUTHORITY_USABLE")
        self.assertEqual(decision.usable_evidence_count, 10)

    def test_policy_refuses_with_the_blocking_incident_reason(self):
        for index in range(10):
            self._store(_strict(VERSIONED_H2, EffectCertainty.EFFECT_CONFIRMED,
                                receipt_id=f"rcpt_ok_{index}"))
        self._store(_strict(CONFLICTING, EffectCertainty.EFFECT_CONFIRMED, receipt_id="rcpt_bad"))

        result = self._ledger(H2).get_current_credit("cap.X")
        decision = authorize_current_credit(result)

        self.assertEqual(decision.decision, CreditDecision.REFUSED)
        self.assertEqual(decision.reason, "CONFLICTING_AUTHORITATIVE_IDENTITIES")
        self.assertEqual(decision.status, CreditStatus.INTEGRITY_BLOCKED)


if __name__ == "__main__":
    unittest.main()
