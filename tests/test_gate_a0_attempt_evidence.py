
"""
Gate A0 - exact-attempt evidence read.

Retry authority must be decided on evidence for ONE exact attempt. No closest receipt, no timestamp
inference, no job-level matching.
"""

import tempfile
import unittest

from ciph.memory.event_store import AttemptEvidenceOutcome, EventStore

BLOCK = {
    "authorization_provenance": "PROVENANCE_PERMIT_V1",
    "execution_attempt_id": "A0",
    "execution_permit_id": "P0",
    "execution_permit_digest": "D0",
    "authorization_generation": 0,
    "logical_action_id": "L",
}


def _event(store, event_type, block, aggregate_id="agg"):
    store.append_event(event_type, aggregate_id, {"governed_authorization": block})


class ExactAttemptEvidenceTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_att_")
        self.store = EventStore(f"{self._dir}/vault.db")

    def _read(self, **overrides):
        args = dict(execution_attempt_id="A0", permit_id="P0", permit_digest="D0",
                    authorization_generation=0)
        args.update(overrides)
        return self.store.get_attempt_evidence(**args)

    def test_several_consistent_events_for_one_attempt_are_attributable(self):
        _event(self.store, "ExecutionReceiptStoredEvent", dict(BLOCK))
        _event(self.store, "ReconciliationRequiredEvent", dict(BLOCK))

        result = self._read()

        self.assertEqual(result.outcome, AttemptEvidenceOutcome.ATTRIBUTABLE)
        self.assertEqual(len(result.events), 2)

    def test_evidence_without_claim_provenance_is_never_attributed(self):
        self.store.append_event("ExecutionReceiptStoredEvent", "agg", {"results": {"ok": True}})

        result = self._read()

        self.assertEqual(result.outcome, AttemptEvidenceOutcome.NO_ATTRIBUTABLE_EVIDENCE)
        self.assertEqual(result.events, ())

    def test_same_attempt_but_a_different_digest_is_an_integrity_conflict(self):
        bad = dict(BLOCK, execution_permit_digest="D-OTHER")
        _event(self.store, "ExecutionReceiptStoredEvent", bad)

        result = self._read()

        self.assertEqual(result.outcome, AttemptEvidenceOutcome.INTEGRITY_CONFLICT)

    def test_an_a1_event_is_never_returned_for_an_a0_query(self):
        a1 = dict(BLOCK, execution_attempt_id="A1", execution_permit_id="P1",
                  execution_permit_digest="D1", authorization_generation=1)
        _event(self.store, "ExecutionReceiptStoredEvent", a1)

        result = self._read(execution_attempt_id="A0", permit_id="P0", permit_digest="D0",
                            authorization_generation=0)

        self.assertEqual(result.outcome, AttemptEvidenceOutcome.NO_ATTRIBUTABLE_EVIDENCE)

    def test_a_different_generation_for_the_same_permit_is_a_conflict(self):
        bad = dict(BLOCK, authorization_generation=2)
        _event(self.store, "ExecutionReceiptStoredEvent", bad)

        result = self._read()

        self.assertEqual(result.outcome, AttemptEvidenceOutcome.INTEGRITY_CONFLICT)


if __name__ == "__main__":
    unittest.main()
