"""Signed terminal-ledger unit fixtures, plus real worker ingress integration."""
from dataclasses import replace
from phase8_test_support import Phase8Case,sha,BASE
from ciph.contracts.base import ContractValidationError
from ciph.contracts.enums import OutcomeCategory
from ciph.evolution.gap_detector import EngineeringGapDetector

class TestPhase81(Phase8Case):
    def test_unsigned_and_uncommitted_receipts_rejected(self):
        for r in (self.receipt(signed=False),self.receipt(committed=False)):
            with self.assertRaises(ContractValidationError):self.detector.ingest_receipt(r)
    def test_repeated_defect_requires_two_and_survives_restart(self):
        self.assertIsNone(self.detector.ingest_receipt(self.receipt()))
        detector=EngineeringGapDetector(self.trust.db_path,trust_registry=self.trust)
        gap=detector.ingest_receipt(self.receipt());self.assertIsNotNone(gap)
        self.assertEqual(detector.get_gap(gap.gap_id),gap)
    def test_replayed_receipt_cannot_create_gap(self):
        r=self.receipt()
        for _ in range(3):self.assertIsNone(self.detector.ingest_receipt(r))
    def test_operational_and_dependency_failures_record_no_relevance(self):
        for outcome in (OutcomeCategory.AUTH_REQUIRED,OutcomeCategory.TARGET_UNREACHABLE,OutcomeCategory.DEPENDENCY_FAILURE):
            self.assertIsNone(self.detector.ingest_receipt(self.receipt(outcome=outcome)))
        self.assertEqual(self.detector.list_gaps(),[])
        self.assertTrue(any(e['payload'].get('kind')=='NO_RELEVANCE_FOUND' for e in self.store.get_events(event_type='EvolutionEvidenceEvent')))
    def test_different_revision_or_environment_not_grouped(self):
        for kwargs in ({},{'env':'different'},{'revision':sha('different')}):
            self.assertIsNone(self.detector.ingest_receipt(self.receipt(**kwargs)))
    def test_telemetry_must_actually_be_missing(self):
        receipts=[self.receipt(outcome=OutcomeCategory.SUCCESS,results={'present':1}) for _ in range(2)]
        with self.assertRaises(ContractValidationError):self.detector.detect_missing_telemetry_gap('math.compute',receipts,['present'])
        gap=self.detector.detect_missing_telemetry_gap('math.compute',receipts,['missing']);self.assertIsNotNone(gap)
    def test_grant_binding_rejects_wrong_capability(self):
        grant=self.evaluation(target_capability='other.capability')
        self.assertFalse(self.detector.bind_evaluation_grant(grant.gap_id,grant,self.trust)[0])
    def test_receipt_payload_tampering_rejected(self):
        r=self.receipt(results={'a':1})
        with self.assertRaises(ContractValidationError):self.detector.ingest_receipt(replace(r,results={'a':2}))
    def test_real_worker_receipt_admitted(self):
        from phase5_test_support import receipt
        r=receipt(self.runtime,{'stored_record':'fixture'},capability='memory.retrieve')
        self.assertEqual(self.detector.evidence.authenticate_execution(r).receipt_id,r.receipt_id)
