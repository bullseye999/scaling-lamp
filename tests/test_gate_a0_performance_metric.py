"""
Gate A0 closure test - D12 empirical performance semantics.

The load-bearing property: only resolved evidence moves the metric. Uncertainty, policy refusals
and unresolved effects are excluded, not scored as failure.
"""

import unittest

from ciph.kernel.performance_metric import (
    EXECUTION_SUCCESS_METRIC,
    EXECUTION_SUCCESS_V1,
    MetricRef,
    UnsupportedMetricVersion,
    resolve_metric_ref,
    split_performance_population,
    ExclusionReason,
    PerformanceObservation,
    aggregate_success_rate,
    observe_execution_success,
)


class EligibilityTests(unittest.TestCase):

    def test_confirmed_success_is_eligible_at_one(self):
        observation = observe_execution_success("SUCCESS", "EFFECT_CONFIRMED")
        self.assertTrue(observation.eligible)
        self.assertEqual(observation.score, 1.0)
        self.assertIsNone(observation.exclusion_reason)

    def test_established_failure_is_eligible_at_zero(self):
        observation = observe_execution_success("EXECUTION_ERROR", "NO_EFFECT_CONFIRMED")
        self.assertTrue(observation.eligible)
        self.assertEqual(observation.score, 0.0)

    def test_a_zero_score_is_not_an_exclusion(self):
        """A resolved negative result must not be confused with 'no observation'."""
        observation = observe_execution_success("EXECUTION_ERROR", "NO_EFFECT_CONFIRMED")
        self.assertIsNone(observation.exclusion_reason)
        self.assertTrue(observation.eligible)

    def test_policy_blocked_is_excluded_and_does_not_score_zero(self):
        observation = observe_execution_success("POLICY_BLOCKED")
        self.assertIsNone(observation.score)
        self.assertEqual(observation.exclusion_reason, ExclusionReason.POLICY_BLOCKED)

    def test_unknown_effect_is_excluded_in_both_directions(self):
        reports_success = observe_execution_success("SUCCESS", "EFFECT_UNKNOWN")
        reports_failure = observe_execution_success("EXECUTION_ERROR", "EFFECT_UNKNOWN")
        for observation in (reports_success, reports_failure):
            self.assertFalse(observation.eligible)
            self.assertEqual(observation.exclusion_reason, ExclusionReason.EFFECT_UNKNOWN)

    def test_reconciliation_required_is_excluded(self):
        observation = observe_execution_success("RECONCILIATION_REQUIRED")
        self.assertFalse(observation.eligible)
        self.assertEqual(
            observation.exclusion_reason, ExclusionReason.RECONCILIATION_REQUIRED
        )


class AggregateTests(unittest.TestCase):

    def test_the_mixed_distribution_does_not_collapse(self):
        """
        8 successes, 2 failures, 40 policy-blocked, 20 unknown-effect.

        Eligible observations are 10 and the rate is 0.8. The blocked and unresolved records are
        not a denominator - treating them as failures would give 0.114 and would make stronger
        governance look like worse capability performance.
        """
        observations = (
            [observe_execution_success("SUCCESS", "EFFECT_CONFIRMED")] * 8
            + [observe_execution_success("EXECUTION_ERROR", "NO_EFFECT_CONFIRMED")] * 2
            + [observe_execution_success("POLICY_BLOCKED")] * 40
            + [observe_execution_success("SUCCESS", "EFFECT_UNKNOWN")] * 20
        )
        aggregate = aggregate_success_rate(observations)

        self.assertEqual(aggregate.eligible_observations, 10)
        self.assertEqual(aggregate.excluded_observations, 60)
        self.assertAlmostEqual(aggregate.resolved_success_rate, 0.8)
        self.assertEqual(aggregate.metric, EXECUTION_SUCCESS_METRIC)
        by_reason = dict(aggregate.excluded_by_reason)
        self.assertEqual(by_reason["POLICY_BLOCKED"], 40)
        self.assertEqual(by_reason["EFFECT_UNKNOWN"], 20)

    def test_the_aggregate_carries_its_metric_identity(self):
        aggregate = aggregate_success_rate([])
        self.assertEqual(aggregate.metric, "EXECUTION_SUCCESS_V1")
        self.assertIsNone(aggregate.resolved_success_rate)
        self.assertEqual(aggregate.eligible_observations, 0)

    def test_observations_default_to_the_v1_metric(self):
        observation = PerformanceObservation(score=1.0)
        self.assertEqual(observation.metric_id, "EXECUTION_SUCCESS")
        self.assertEqual(observation.metric_version, 1)


class MetricSelectionTests(unittest.TestCase):

    def test_v1_selection_is_supported_and_pinned(self):
        observation = observe_execution_success(
            "SUCCESS", "EFFECT_CONFIRMED", metric_ref=EXECUTION_SUCCESS_V1
        )
        self.assertEqual(observation.score, 1.0)
        self.assertEqual(EXECUTION_SUCCESS_V1.name, "EXECUTION_SUCCESS_V1")

    def test_an_unsupported_metric_version_is_refused_not_substituted(self):
        """
        The hole versioning alone does not close: if a query selecting V2 silently fell back to
        the newest semantics, a future metric change would rescore V1 authority history while
        the version number sat in the data being decorative.
        """
        future = MetricRef(metric_id="EXECUTION_SUCCESS", metric_version=2)
        with self.assertRaises(UnsupportedMetricVersion) as caught:
            resolve_metric_ref(future)
        self.assertIn("UNSUPPORTED_METRIC_VERSION", str(caught.exception))

        with self.assertRaises(UnsupportedMetricVersion):
            observe_execution_success(
                "SUCCESS", "EFFECT_CONFIRMED", metric_ref=future
            )

    def test_a_metric_ref_is_not_interchangeable_across_ids(self):
        other = MetricRef(metric_id="SOMETHING_ELSE", metric_version=1)
        with self.assertRaises(UnsupportedMetricVersion):
            resolve_metric_ref(other)


class PerformancePopulationTests(unittest.TestCase):

    def test_integrity_incidents_are_not_part_of_the_performance_denominator(self):
        """
        "excluded = 61" would blend sixty legitimate non-trials with one malformed record and
        weaken what the statistic means. Corrupt evidence lives only on the integrity axis.
        """
        successes = [observe_execution_success("SUCCESS", "EFFECT_CONFIRMED")] * 10
        blocked = [observe_execution_success("POLICY_BLOCKED")] * 60
        entries = [(o, False) for o in successes + blocked] + [(None, True)]

        performance, integrity_incidents = split_performance_population(entries)
        aggregate = aggregate_success_rate(performance)

        self.assertEqual(integrity_incidents, 1)
        self.assertEqual(aggregate.eligible_observations, 10)
        self.assertEqual(aggregate.excluded_observations, 60)
        self.assertAlmostEqual(aggregate.resolved_success_rate, 1.0)
        self.assertEqual(
            aggregate.eligible_observations + aggregate.excluded_observations,
            len(performance),
        )

    def test_the_denominator_invariant_holds_on_a_mixed_population(self):
        entries = [
            (observe_execution_success("SUCCESS", "EFFECT_CONFIRMED"), False),
            (observe_execution_success("EXECUTION_ERROR", "NO_EFFECT_CONFIRMED"), False),
            (observe_execution_success("POLICY_BLOCKED"), False),
            (observe_execution_success("SUCCESS", "EFFECT_UNKNOWN"), False),
            (None, True),
            (None, True),
        ]
        performance, integrity_incidents = split_performance_population(entries)
        aggregate = aggregate_success_rate(performance)
        self.assertEqual(integrity_incidents, 2)
        self.assertEqual(
            aggregate.eligible_observations + aggregate.excluded_observations, 4
        )

if __name__ == "__main__":
    unittest.main()
