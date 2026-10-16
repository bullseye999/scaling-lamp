"""Tests for EffectCertainty, the strict SUCCESS rule, and the historical-only legacy lane."""

import unittest

from ciph.kernel.performance_metric import (
    EFFECT_CERTAINTY_CUTOVER_SCHEMA,
    EXECUTION_SUCCESS_V1,
    LEGACY_EXECUTION_OUTCOME_V1,
    CertaintyProvenance,
    EffectCertainty,
    ExclusionReason,
    classify_certainty_provenance,
    observe_execution_success,
    observe_legacy_execution_outcome,
)


class EffectCertaintyTypeTests(unittest.TestCase):

    def test_the_type_is_real_rather_than_string_literals(self):
        self.assertEqual(EffectCertainty.EFFECT_CONFIRMED.value, "EFFECT_CONFIRMED")
        self.assertEqual(EffectCertainty.EFFECT_UNKNOWN.value, "EFFECT_UNKNOWN")

    def test_an_enum_member_is_accepted_where_a_string_was_before(self):
        observation = observe_execution_success(
            "SUCCESS", EffectCertainty.EFFECT_CONFIRMED
        )
        self.assertEqual(observation.score, 1.0)


class StrictSuccessTests(unittest.TestCase):

    def test_confirmed_success_scores_one(self):
        self.assertEqual(
            observe_execution_success("SUCCESS", EffectCertainty.EFFECT_CONFIRMED).score,
            1.0,
        )

    def test_success_without_certainty_is_excluded_not_promoted(self):
        """The defect this change exists to kill: absence was being read as confirmation."""
        observation = observe_execution_success("SUCCESS", None)
        self.assertIsNone(observation.score)
        self.assertEqual(observation.exclusion_reason, ExclusionReason.UNRESOLVED)

    def test_unknown_effect_is_excluded_in_both_directions(self):
        for outcome in ("SUCCESS", "EXECUTION_ERROR"):
            with self.subTest(outcome=outcome):
                observation = observe_execution_success(
                    outcome, EffectCertainty.EFFECT_UNKNOWN
                )
                self.assertIsNone(observation.score)
                self.assertEqual(
                    observation.exclusion_reason, ExclusionReason.EFFECT_UNKNOWN
                )

    def test_established_failure_still_scores_zero_without_certainty(self):
        """
        Conservative asymmetry: scoring a failure as 0.0 cannot overclaim success, and the
        machinery failing is itself established by the outcome.
        """
        self.assertEqual(observe_execution_success("EXECUTION_ERROR", None).score, 0.0)


class CertaintyProvenanceTests(unittest.TestCase):

    def test_pre_cutover_without_certainty_permits_legacy_interpretation(self):
        self.assertEqual(
            classify_certainty_provenance("4.0", None),
            CertaintyProvenance.LEGACY_OUTCOME_ONLY,
        )

    def test_post_cutover_with_certainty_is_strict(self):
        self.assertEqual(
            classify_certainty_provenance(EFFECT_CERTAINTY_CUTOVER_SCHEMA, "EFFECT_CONFIRMED"),
            CertaintyProvenance.STRICT,
        )

    def test_post_cutover_without_certainty_is_malformed_never_legacy(self):
        """
        The load-bearing rule: 'certainty missing' alone must not mean legacy, or a malformed new
        receipt could omit the field and downgrade itself into the permissive lane.
        """
        self.assertEqual(
            classify_certainty_provenance(EFFECT_CERTAINTY_CUTOVER_SCHEMA, None),
            CertaintyProvenance.MALFORMED,
        )
        self.assertEqual(
            classify_certainty_provenance("5.0", ""), CertaintyProvenance.MALFORMED
        )

    def test_unparseable_schema_is_malformed(self):
        self.assertEqual(
            classify_certainty_provenance("not-a-version", None),
            CertaintyProvenance.MALFORMED,
        )


class LegacyLaneTests(unittest.TestCase):

    def test_pre_cutover_outcomes_score_on_outcome_alone(self):
        success = observe_legacy_execution_outcome("SUCCESS", schema_version="4.0")
        failure = observe_legacy_execution_outcome("EXECUTION_ERROR", schema_version="4.0")
        self.assertEqual(success.score, 1.0)
        self.assertEqual(failure.score, 0.0)

    def test_the_legacy_observation_is_not_the_strict_metric(self):
        """It may say 'success under the outcome-only metric'. It may not say 'effect confirmed'."""
        observation = observe_legacy_execution_outcome("SUCCESS", schema_version="4.0")
        self.assertEqual(observation.metric_id, LEGACY_EXECUTION_OUTCOME_V1.metric_id)
        self.assertNotEqual(observation.metric_id, EXECUTION_SUCCESS_V1.metric_id)
        # Both are V1 of their own metric, which is correct: these are different metrics, not two
        # versions of one. The composite identity is what must differ.
        self.assertNotEqual(
            (observation.metric_id, observation.metric_version),
            (EXECUTION_SUCCESS_V1.metric_id, EXECUTION_SUCCESS_V1.metric_version),
        )

    def test_the_legacy_lane_refuses_post_cutover_records(self):
        """Otherwise legacy becomes a downgrade path for malformed new evidence."""
        with self.assertRaises(ValueError) as caught:
            observe_legacy_execution_outcome(
                "SUCCESS", schema_version=EFFECT_CERTAINTY_CUTOVER_SCHEMA
            )
        self.assertIn("LEGACY_LANE_NOT_PERMITTED", str(caught.exception))

    def test_unadjudicated_outcomes_are_excluded_even_in_the_legacy_lane(self):
        observation = observe_legacy_execution_outcome("POLICY_BLOCKED", schema_version="4.0")
        self.assertIsNone(observation.score)


if __name__ == "__main__":
    unittest.main()
