"""
Gate A0 closure test - D11 exact-identity credit.

The two properties that matter: corruption is on a different axis from performance, and the
authority path cannot reach ancestry.
"""

import inspect
import unittest

from ciph.kernel.manifest_credit import (
    POPULATION_LEDGER_GLOBAL_INCIDENTS,
    POPULATION_SUBJECT_EVIDENCE,
    CreditQuery,
    assessment_from_complete_partition_scan,
    assessment_untrustworthy,
    RetrievalIntegrity,
    AttributionSource,
    IncidentAxis,
    IntegrityIncident,
    ReceiptIntegrity,
    CreditSubject,
    compute_subject_credit,
    select_evidence_for_subject,
    IncidentScope,
    IntegrityIncident,
    TrustedCapabilityAttribution,
    CreditStatus,
    CurrentCreditResult,
    EvidenceRecord,
    EvidenceVerdict,
    LineageCreditHistory,
    classify_evidence,
    compute_current_credit,
)
from ciph.contracts.enums import EffectCertainty
from ciph.kernel.performance_metric import (
    EXECUTION_SUCCESS_V1,
    LEGACY_EXECUTION_OUTCOME_V1,
    PerformanceObservation,
    UnsupportedMetricVersion,
    observe_execution_success,
    observe_legacy_execution_outcome,
)
from ciph.workers.receipts import ExecutionReceipt
from ciph.kernel.manifest_identity import (
    ManifestBinding,
    ManifestBindingResult,
    ManifestIdentity,
)

H1 = ManifestIdentity(2, "H1")
H2 = ManifestIdentity(2, "H2")

class _PartitionRecord:
    """Stands in for an independent ledger-partition record."""

    def __init__(self, capability_id, digest="partition-digest", source_ref="partition-1"):
        self.capability_id = capability_id
        self.digest = digest
        self.source_ref = source_ref


def _query(subject, snapshot="S1", metric_ref=EXECUTION_SUCCESS_V1):
    return CreditQuery(
        subject=subject, metric_ref=metric_ref, snapshot_ref=snapshot
    )


def complete_fixture_retrieval(query, subject_records, global_incidents=()):
    """
    Test-only completeness witness for an isolated universe.

    Commits to the labelled populations as a MULTISET of per-record digests, so [A, B] differs
    from [A, A, B], and moving an identical digest between populations also differs.
    """
    def _digest(record):
        return repr((record.binding.binding.value, str(record.binding.identity),
                     record.performance, record.receipt_integrity.value))

    parts = ["CIPH_TEST_COMPLETE_RETRIEVAL_V1", str(query.subject.capability_id),
             str(query.metric_ref.name), query.snapshot_ref, POPULATION_SUBJECT_EVIDENCE]
    parts.extend(sorted(_digest(r) for r in subject_records))
    parts.append(POPULATION_LEDGER_GLOBAL_INCIDENTS)
    parts.extend(sorted(_digest(r) for r in global_incidents))

    return assessment_from_complete_partition_scan(
        subject=query.subject,
        metric_ref=query.metric_ref,
        snapshot_ref=query.snapshot_ref,
        source_ref="test_fixture",
        source_digest=ExecutionReceipt.hash_payload(parts),
    )


def _trusted(capability_id):
    from ciph.kernel.manifest_credit import attribution_from_ledger_partition
    return attribution_from_ledger_partition(_PartitionRecord(capability_id))

def _versioned(identity, reason="EXPLICIT_VERSIONED_IDENTITY"):
    return ManifestBindingResult(
        binding=ManifestBinding.VERSIONED, identity=identity, legacy_hash=None, reason=reason
    )

def _corrupt(reason="MALFORMED_VERSIONED_IDENTITY"):
    return ManifestBindingResult(
        binding=ManifestBinding.CORRUPT, identity=None, legacy_hash=None, reason=reason
    )

def _unbound():
    return ManifestBindingResult(
        binding=ManifestBinding.UNBOUND, identity=None, legacy_hash=None,
        reason="NO_MANIFEST_PROVENANCE",
    )

def _legacy():
    return ManifestBindingResult(
        binding=ManifestBinding.LEGACY_UNVERSIONED, identity=None, legacy_hash="ABC",
        reason="UNVERSIONED_AND_NOT_PROVABLE",
    )

def _perf(score, metric_ref=EXECUTION_SUCCESS_V1):
    """An observation stated under an explicit metric contract (the authority metric by default)."""
    return PerformanceObservation(
        metric_id=metric_ref.metric_id,
        metric_version=metric_ref.metric_version,
        score=score,
    )

class EvidenceClassificationTests(unittest.TestCase):

    def test_exact_identity_is_current(self):
        self.assertEqual(
            classify_evidence(EvidenceRecord(_versioned(H1)), H1), EvidenceVerdict.CURRENT
        )

    def test_different_identity_is_historical_mismatch(self):
        self.assertEqual(
            classify_evidence(EvidenceRecord(_versioned(H1)), H2),
            EvidenceVerdict.HISTORICAL_VERSION_MISMATCH,
        )

    def test_legacy_and_unbound_are_historical(self):
        self.assertEqual(
            classify_evidence(EvidenceRecord(_legacy()), H2), EvidenceVerdict.HISTORICAL_UNBOUND
        )
        self.assertEqual(
            classify_evidence(EvidenceRecord(_unbound()), H2), EvidenceVerdict.HISTORICAL_UNBOUND
        )

    def test_corrupt_is_an_integrity_incident_not_a_history_category(self):
        self.assertEqual(
            classify_evidence(EvidenceRecord(_corrupt()), H2),
            EvidenceVerdict.INTEGRITY_INCIDENT,
        )

class CurrentCreditTests(unittest.TestCase):

    def test_no_evidence_is_unverified_with_no_incidents(self):
        result = compute_current_credit(H2, [])
        self.assertEqual(result.status, CreditStatus.UNVERIFIED)
        self.assertEqual(result.integrity_incidents, ())
        self.assertFalse(result.authority_usable)

    def test_strong_clean_evidence_is_verified_and_usable(self):
        result = compute_current_credit(
            H2, [EvidenceRecord(_versioned(H2), performance=_perf(0.95))]
        )
        self.assertEqual(result.status, CreditStatus.VERIFIED)
        self.assertTrue(result.authority_usable)
        self.assertEqual(result.usable_evidence_count, 1)

    def test_corruption_blocks_authority_even_when_credit_is_strong(self):
        """
        \"Excellent credit plus unexplained corruption\" is not \"excellent clean credit\".
        """
        result = compute_current_credit(
            H2,
            [
                EvidenceRecord(_versioned(H2), performance=_perf(0.99)),
                EvidenceRecord(_corrupt("MALFORMED_VERSIONED_IDENTITY:HASH_VERSION_MUST_BE_INTEGER")),
            ],
        )
        self.assertEqual(result.status, CreditStatus.INTEGRITY_BLOCKED)
        self.assertFalse(result.authority_usable)
        self.assertEqual(len(result.integrity_incidents), 1)
        self.assertIn("MALFORMED_VERSIONED_IDENTITY", result.integrity_incidents[0].reason)

    def test_corruption_moves_the_score_in_neither_direction(self):
        """Corrupt evidence is not bad performance evidence."""
        clean = compute_current_credit(H2, [EvidenceRecord(_versioned(H2), performance=_perf(0.5))])
        with_corrupt = compute_current_credit(
            H2,
            [
                EvidenceRecord(_versioned(H2), performance=_perf(0.5)),
                EvidenceRecord(_corrupt(), performance=_perf(0.0)),
            ],
        )
        self.assertEqual(clean.mean_performance, with_corrupt.mean_performance)
        self.assertEqual(clean.usable_evidence_count, with_corrupt.usable_evidence_count)

    def test_other_identity_evidence_is_excluded_not_counted(self):
        result = compute_current_credit(
            H2,
            [
                EvidenceRecord(_versioned(H1), performance=_perf(1.0)),
                EvidenceRecord(_legacy(), performance=_perf(1.0)),
                EvidenceRecord(_unbound(), performance=_perf(1.0)),
            ],
        )
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.excluded_historical_count, 3)
        self.assertEqual(result.status, CreditStatus.UNVERIFIED)

class IntegrityIncidentScopeTests(unittest.TestCase):
    """
    Corruption contaminates its own partition, not the whole capability system, and not nothing.
    """

    def test_corrupt_evidence_for_the_queried_capability_blocks_it(self):
        result = compute_current_credit(
            H2,
            [EvidenceRecord(_corrupt(), capability_attribution=_trusted("cap.X"))],
            queried_capability="cap.X",
        )
        self.assertFalse(result.authority_usable)
        self.assertEqual(result.integrity_incidents[0].scope, IncidentScope.CAPABILITY)
        self.assertEqual(result.integrity_incidents[0].capability, "cap.X")

    def test_corrupt_evidence_for_another_capability_does_not_contaminate_this_one(self):
        """The over-broad failure mode: one bad receipt poisoning every capability."""
        result = compute_current_credit(
            H2,
            [
                EvidenceRecord(_versioned(H2), performance=_perf(0.9), capability_attribution=_trusted("cap.X")),
                EvidenceRecord(_corrupt(), capability_attribution=_trusted("cap.OTHER")),
            ],
            queried_capability="cap.X",
        )
        self.assertEqual(result.integrity_incidents, ())
        self.assertTrue(result.authority_usable)
        self.assertEqual(result.excluded_historical_count, 1)

    def test_unattributable_corruption_is_conservatively_global(self):
        """Refusing on unknown corruption is recoverable; ignoring it is not."""
        result = compute_current_credit(
            H2,
            [EvidenceRecord(_corrupt())],
            queried_capability="cap.X",
        )
        self.assertFalse(result.authority_usable)
        self.assertEqual(result.integrity_incidents[0].scope, IncidentScope.LEDGER_GLOBAL)

class StructuralLineageBlindnessTests(unittest.TestCase):

    def test_current_credit_cannot_consult_lineage(self):
        """Not a rule callers must respect: the parameter does not exist."""
        parameters = set(inspect.signature(compute_current_credit).parameters)
        self.assertEqual(
            parameters,
            {
                "queried_identity",
                "evidence",
                "queried_capability",
                "projection_incidents",
                "metric_ref",
            },
        )
        for forbidden in ("lineage", "history", "ancestors", "predecessor", "retrieval"):
            self.assertNotIn(forbidden, parameters)

    def test_lineage_history_has_no_spendable_credit_field(self):
        """
        A policy function written for CurrentCreditResult must not accept this object. There is no
        credit, no status and no authority flag to accidentally consume.
        """
        fields = set(LineageCreditHistory.__dataclass_fields__)
        self.assertEqual(fields, {"current_identity", "ancestor_entries", "transitions", "note"})
        for forbidden in ("credit", "status", "authority_usable", "mean_performance"):
            self.assertNotIn(forbidden, fields)

    def test_ancestor_context_is_explicitly_marked_non_authoritative(self):
        history = LineageCreditHistory(current_identity=H2)
        self.assertEqual(history.note, "NON_AUTHORITATIVE_CONTEXT")

    def test_an_attributed_incident_names_no_exact_identity(self):
        result = compute_current_credit(
            H2,
            [EvidenceRecord(_corrupt(), capability_attribution=_trusted("cap.X"))],
            queried_capability="cap.X",
        )
        incident = result.integrity_incidents[0]
        self.assertEqual(incident.scope, IncidentScope.CAPABILITY)
        self.assertEqual(incident.capability, "cap.X")
        self.assertIsNone(incident.manifest_identity)

    def test_a_bare_construction_cannot_mint_an_attribution(self):
        """
        `source` alone is a claim about where an attribution came from. Only evidence-derived
        factories may issue one, so fabrication is structurally abnormal rather than convenient.
        """
        from ciph.kernel.manifest_credit import TrustedCapabilityAttribution
        with self.assertRaises(ValueError) as caught:
            TrustedCapabilityAttribution(
                capability_id="cap.X",
                source_type=AttributionSource.LEDGER_PARTITION,
                source_ref="r",
                source_digest="d",
            )
        self.assertIn("EVIDENCE_DERIVED", str(caught.exception))

    def test_factories_require_evidence_with_a_capability_and_a_digest(self):
        from ciph.kernel.manifest_credit import attribution_from_execution_record
        with self.assertRaises(ValueError) as caught:
            attribution_from_execution_record(_PartitionRecord("cap.X", digest=""))
        self.assertIn("INSUFFICIENT", str(caught.exception))
        with self.assertRaises(ValueError):
            attribution_from_execution_record(_PartitionRecord(""))

    def test_an_issued_attribution_carries_the_evidence_it_came_from(self):
        attribution = _trusted("cap.X")
        self.assertEqual(attribution.capability_id, "cap.X")
        self.assertEqual(attribution.source_digest, "partition-digest")
        self.assertEqual(attribution.source_ref, "partition-1")

class _Manifest:
    """Stands in for a resolved manifest that can state its identity."""

    def __init__(self, identity):
        self._identity = identity

    def identity(self):
        return self._identity


class CreditSubjectTests(unittest.TestCase):

    def _subject(self, capability_id="cap.X", identity=H2):
        return CreditSubject.from_manifest(capability_id, _Manifest(identity))

    def test_the_pair_is_derived_from_the_manifest_not_supplied_by_the_caller(self):
        subject = self._subject(identity=H2)
        self.assertEqual(subject.manifest_identity, H2)
        self.assertEqual(subject.capability_id, "cap.X")

    def test_a_manifest_without_identity_cannot_form_a_subject(self):
        with self.assertRaises(ValueError) as caught:
            CreditSubject.from_manifest("cap.X", object())
        self.assertIn("MANIFEST_WITH_IDENTITY", str(caught.exception))

    def test_ledger_global_incidents_survive_capability_filtering(self):
        """
        The integration trap: an unattributable corrupt record belongs to no capability
        partition, so a naive filter by capability would drop exactly the evidence meant to
        block every partition.
        """
        global_corruption = EvidenceRecord(_corrupt("MALFORMED_VERSIONED_IDENTITY"))
        evidence = [
            EvidenceRecord(_versioned(H2), performance=_perf(0.9), capability_attribution=_trusted("cap.X")),
            global_corruption,
        ]
        selected = select_evidence_for_subject(self._subject(), evidence)
        self.assertIn(global_corruption, selected)

    def test_the_same_global_incident_blocks_every_partition(self):
        global_corruption = EvidenceRecord(_corrupt())
        evidence = [
            EvidenceRecord(_versioned(H2), performance=_perf(0.99), capability_attribution=_trusted("cap.X")),
            EvidenceRecord(_versioned(H2), performance=_perf(0.99), capability_attribution=_trusted("cap.Y")),
            global_corruption,
        ]
        for capability in ("cap.X", "cap.Y"):
            with self.subTest(capability=capability):
                result = compute_subject_credit(_query(self._subject(capability)), evidence)
                self.assertFalse(result.authority_usable)
                self.assertEqual(
                    result.integrity_incidents[0].scope, IncidentScope.LEDGER_GLOBAL
                )

    def test_another_capabilitys_corruption_does_not_contaminate_this_one(self):
        evidence = [
            EvidenceRecord(_versioned(H2), performance=_perf(0.9), capability_attribution=_trusted("cap.X")),
            EvidenceRecord(_corrupt(), capability_attribution=_trusted("cap.OTHER")),
        ]
        query = _query(self._subject("cap.X"))
        result = compute_subject_credit(
            query, evidence,
            retrieval_assessment=complete_fixture_retrieval(query, evidence),
        )
        self.assertEqual(result.integrity_incidents, ())
        self.assertTrue(result.authority_usable)

    def test_an_extremely_strong_ancestor_does_not_transfer_to_the_successor(self):
        evidence = [
            EvidenceRecord(_versioned(H1), performance=_perf(1.0), capability_attribution=_trusted("cap.X"))
            for _ in range(100)
        ]
        result = compute_subject_credit(_query(self._subject("cap.X", identity=H2)), evidence)
        self.assertEqual(result.status, CreditStatus.UNVERIFIED)
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertFalse(result.authority_usable)

class CrossAxisTests(unittest.TestCase):
    """
    A performance fact may be trustworthy as a fact without being eligible for exact-manifest
    credit. Two different questions: can I trust what happened, and can I prove which semantic
    version deserves credit for it?
    """

    def test_invalid_receipt_integrity_yields_no_performance_even_with_a_valid_identity(self):
        """
        The supposedly authoritative execution fields are authoritative only when their
        containing evidence passes its integrity contract.
        """
        record = EvidenceRecord(
            _versioned(H2),
            performance=_perf(1.0),
            capability_attribution=_trusted("cap.X"),
            receipt_integrity=ReceiptIntegrity.INVALID,
        )
        result = compute_subject_credit(_query(self._subject("cap.X", H2)), [record])
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertFalse(result.authority_usable)
        self.assertEqual(result.integrity_incidents[0].reason, "RECEIPT_INTEGRITY_FAILURE")

    def test_unverifiable_integrity_fails_closed_with_a_distinct_statement(self):
        """
        INVALID and UNVERIFIABLE are both non-spendable, but they are different claims:
        evidence contradicting its integrity contract is not the same finding as integrity
        that cannot currently be established.
        """
        unverifiable = EvidenceRecord(
            _versioned(H2), performance=_perf(1.0),
            capability_attribution=_trusted("cap.X"),
            receipt_integrity=ReceiptIntegrity.UNVERIFIABLE,
        )
        invalid = EvidenceRecord(
            _versioned(H2), performance=_perf(1.0),
            capability_attribution=_trusted("cap.X"),
            receipt_integrity=ReceiptIntegrity.INVALID,
        )
        unverifiable_result = compute_subject_credit(_query(self._subject("cap.X", H2)), [unverifiable])
        invalid_result = compute_subject_credit(_query(self._subject("cap.X", H2)), [invalid])

        for result in (unverifiable_result, invalid_result):
            self.assertEqual(result.usable_evidence_count, 0)
            self.assertFalse(result.authority_usable)

        self.assertEqual(
            unverifiable_result.integrity_incidents[0].reason,
            "RECEIPT_INTEGRITY_UNVERIFIABLE",
        )
        self.assertEqual(
            invalid_result.integrity_incidents[0].reason,
            "RECEIPT_INTEGRITY_FAILURE",
        )
        self.assertNotEqual(
            unverifiable_result.integrity_incidents[0].reason,
            invalid_result.integrity_incidents[0].reason,
        )

    def _subject(self, capability_id, identity):
        return CreditSubject.from_manifest(capability_id, _Manifest(identity))

    def test_a_sound_performance_fact_survives_a_corrupt_identity_without_being_spendable(self):
        """
        The cross-axis case: the execution fact is real and stays on the record, but it cannot be
        spent for any exact-manifest credit, because the generation that produced it is unknown.
        """
        record = EvidenceRecord(
            _corrupt(),
            performance=_perf(1.0),
            capability_attribution=_trusted("cap.X"),
        )
        self.assertEqual(record.performance.score, 1.0)   # the fact is preserved, not deleted

        result = compute_subject_credit(_query(self._subject("cap.X", H2)), [record])
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertFalse(result.authority_usable)
        self.assertEqual(result.integrity_incidents[0].scope, IncidentScope.CAPABILITY)
        self.assertEqual(result.integrity_incidents[0].capability, "cap.X")

    def test_corrupt_identity_without_attribution_goes_global_even_with_a_sound_fact(self):
        record = EvidenceRecord(_corrupt(), performance=_perf(1.0))
        result = compute_subject_credit(_query(self._subject("cap.X", H2)), [record])
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.integrity_incidents[0].scope, IncidentScope.LEDGER_GLOBAL)

class IncidentAxisTests(unittest.TestCase):
    """
    Projection disagreement must be visible without being able to disable authority. Otherwise
    a stale cache inverts the hierarchy and "projection disagrees with authority" quietly
    becomes "projection disables authority".
    """

    def _projection_incident(self):
        return IntegrityIncident(
            reason="DENORMALIZED_OUTCOME_MISMATCH",
            scope=IncidentScope.CAPABILITY,
            axis=IncidentAxis.PROJECTION,
            capability="cap.X",
        )

    def test_a_projection_mismatch_does_not_block_authority(self):
        subject = CreditSubject.from_manifest("cap.X", _Manifest(H2))
        record = EvidenceRecord(
            _versioned(H2), performance=_perf(0.0), capability_attribution=_trusted("cap.X")
        )
        query = _query(subject)
        result = compute_subject_credit(
            query, [record], projection_incidents=[self._projection_incident()],
            retrieval_assessment=complete_fixture_retrieval(query, [record]),
        )

        self.assertEqual(result.integrity_incidents, ())
        self.assertEqual(len(result.projection_incidents), 1)
        self.assertTrue(result.authority_usable)
        self.assertEqual(result.usable_evidence_count, 1)
        self.assertEqual(result.mean_performance, 0.0)

    def test_a_projection_mismatch_does_not_change_the_statistics(self):
        subject = CreditSubject.from_manifest("cap.X", _Manifest(H2))
        record = EvidenceRecord(
            _versioned(H2), performance=_perf(0.75), capability_attribution=_trusted("cap.X")
        )
        clean = compute_subject_credit(_query(subject), [record])
        degraded = compute_subject_credit(
            _query(subject), [record], projection_incidents=[self._projection_incident()]
        )
        self.assertEqual(clean.mean_performance, degraded.mean_performance)
        self.assertEqual(clean.usable_evidence_count, degraded.usable_evidence_count)
        self.assertEqual(clean.status, degraded.status)

    def test_known_incomplete_retrieval_blocks_with_untrustworthy_status(self):
        subject = CreditSubject.from_manifest("cap.X", _Manifest(H2))
        record = EvidenceRecord(
            _versioned(H2), performance=_perf(1.0), capability_attribution=_trusted("cap.X")
        )
        result = compute_subject_credit(
            _query(subject), [record],
            retrieval_assessment=assessment_untrustworthy(
                _query(subject), EXECUTION_SUCCESS_V1, "S1", "test_fixture"
            ),
        )
        self.assertFalse(result.authority_usable)
        self.assertEqual(result.integrity_incidents[0].axis, IncidentAxis.RETRIEVAL)
        self.assertEqual(
            result.integrity_incidents[0].reason, "RETRIEVAL_UNTRUSTWORTHY"
        )

class RetrievalEnforcementTests(unittest.TestCase):

    def _subject(self):
        return CreditSubject.from_manifest("cap.X", _Manifest(H2))

    def test_missing_completeness_evidence_blocks_as_unverifiable(self):
        """The migration thesis: excellent evidence from an unknown subset is not credit."""
        records = [
            EvidenceRecord(_versioned(H2), performance=_perf(1.0),
                           capability_attribution=_trusted("cap.X"))
            for _ in range(10)
        ]
        result = compute_subject_credit(_query(self._subject()), records)

        self.assertEqual(result.usable_evidence_count, 10)
        self.assertEqual(result.mean_performance, 1.0)
        self.assertEqual(result.retrieval_integrity, RetrievalIntegrity.UNVERIFIABLE)
        self.assertEqual(result.integrity_incidents[0].reason, "NO_COMPLETENESS_EVIDENCE")
        self.assertFalse(result.authority_usable)

    def test_assessment_scope_mismatch_does_not_authorize(self):
        """A proof for S does not cover S+1, and is not reinterpreted as unverifiable."""
        subject = self._subject()
        records = [EvidenceRecord(_versioned(H2), performance=_perf(1.0),
                                  capability_attribution=_trusted("cap.X"))]
        proof = complete_fixture_retrieval(_query(subject, snapshot="S1"), records)

        result = compute_subject_credit(_query(subject, snapshot="S2"), records,
                                        retrieval_assessment=proof)
        self.assertEqual(result.integrity_incidents[0].reason, "ASSESSMENT_SCOPE_MISMATCH")
        self.assertFalse(result.authority_usable)
        self.assertEqual(proof.snapshot_ref, "S1")

class MetricEligibilityTests(unittest.TestCase):
    """
    Metric identity is part of eligibility.

    A credit query names a measurement contract. Evidence produced under a different contract is
    valid empirical history, but it is not eligible for this aggregate - the metric-axis version
    of "H1 has strong credit, H2 cannot spend it". Preserve history without borrowing it.
    """

    def _subject(self):
        return CreditSubject.from_manifest("cap.X", _Manifest(H2))

    def _record(self, observation, identity=H2):
        return EvidenceRecord(
            _versioned(identity),
            performance=observation,
            capability_attribution=_trusted("cap.X"),
        )

    def test_mixed_legacy_and_strict_population_scores_only_the_strict_metric(self):
        """
        90 legacy successes + 10 strict confirmed successes + 2 strict confirmed failures.

        The strict query must resolve 10/12 over the twelve strict observations and use none of
        the ninety legacy ones. The legacy observations stay visible as history, not as credit.
        """
        legacy = [
            self._record(observe_legacy_execution_outcome("SUCCESS", schema_version="4.1"))
            for _ in range(90)
        ]
        strict_success = [
            self._record(observe_execution_success("SUCCESS", EffectCertainty.EFFECT_CONFIRMED))
            for _ in range(10)
        ]
        strict_failure = [
            self._record(observe_execution_success("EXECUTION_ERROR", EffectCertainty.EFFECT_CONFIRMED))
            for _ in range(2)
        ]

        result = compute_current_credit(
            H2, legacy + strict_success + strict_failure,
            queried_capability="cap.X", metric_ref=EXECUTION_SUCCESS_V1,
        )

        self.assertEqual(result.usable_evidence_count, 12)
        self.assertAlmostEqual(result.mean_performance, 10 / 12)
        self.assertEqual(result.different_metric_excluded_count, 90)
        self.assertEqual(result.semantic_excluded_count, 0)
        self.assertEqual(result.metric_ref, EXECUTION_SUCCESS_V1)

    def test_same_metric_semantic_exclusion_is_not_a_different_metric(self):
        """
        EFFECT_UNKNOWN is the strict metric declining to adjudicate - same metric, excluded.
        A legacy success is a valid observation under a weaker contract - different metric.
        The two must never collapse into one bucket.
        """
        unknown = self._record(observe_execution_success("SUCCESS", EffectCertainty.EFFECT_UNKNOWN))
        legacy = self._record(observe_legacy_execution_outcome("SUCCESS", schema_version="4.1"))

        result = compute_current_credit(H2, [unknown, legacy], queried_capability="cap.X")

        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.semantic_excluded_count, 1)
        self.assertEqual(result.different_metric_excluded_count, 1)
        self.assertFalse(result.authority_usable)

    def test_a_record_without_any_observation_is_not_scored(self):
        record = EvidenceRecord(_versioned(H2), capability_attribution=_trusted("cap.X"))
        result = compute_current_credit(H2, [record], queried_capability="cap.X")
        self.assertEqual(result.usable_evidence_count, 0)
        self.assertEqual(result.unobserved_count, 1)
        self.assertEqual(result.different_metric_excluded_count, 0)
        self.assertFalse(result.authority_usable)

    def test_an_authority_query_cannot_be_pinned_to_a_historical_metric(self):
        """
        The legacy lane is historical interpretation, not an authority contract. Allowing an
        authority query to pin it would reopen the downgrade path: query the permissive metric,
        spend the result.
        """
        query = CreditQuery(
            subject=self._subject(),
            metric_ref=LEGACY_EXECUTION_OUTCOME_V1,
            snapshot_ref="S1",
        )
        with self.assertRaises(UnsupportedMetricVersion):
            compute_subject_credit(query, [])


if __name__ == "__main__":
    unittest.main()
