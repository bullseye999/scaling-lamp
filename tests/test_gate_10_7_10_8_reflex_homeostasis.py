"""
10.7 governed reflexes + 10.8 operational homeostasis.

    One Ciph. Continuous observation. Bounded reflexes. Evidence-grounded self-maintenance. No invented
    authority.

The specimens use the REAL owners: 6.x spawn governance and worker state, 5.x standing authorization and
swarm quiescence, 10.3 sensor status and gaps, 10.4 architectural integrity claims, 10.6 attention. Every
positive result is paired with a refusal or uncertainty case.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

from ciph.kernel import governed_reflexes as reflexes
from ciph.kernel import operational_homeostasis as homeostasis
from ciph.kernel import sensory_fabric as fabric
from ciph.kernel.architectural_proprioception import register_component, witness_observation
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.reflex_ownership import assert_ownership_clean
from ciph.kernel.standing_authorization import create_standing_authorization

T1 = 1_800_000_000.0
OPERATOR = "operator:operator"


class ReflexCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-1078-")
        self.base = pathlib.Path(self.temp.name)
        self.db = str(self.base / "state.db")

    def tearDown(self):
        self.temp.cleanup()

    def counts(self, table):
        import sqlite3
        if not pathlib.Path(self.db).exists():
            return 0
        connection = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            return int(connection.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            connection.close()

    def spawns(self, count, *, now=T1):
        from ciph.kernel.swarm_resources import record_spawn
        for index in range(count):
            record_spawn(self.db, worker_id=f"W{index}", instance_generation=1, actor=OPERATOR,
                         now=now + index)

    def register_resource_reflex(self, *, limit=3, mechanism="SPAWN_GOVERNANCE", rule="resource.ceiling",
                                 basis="EXISTING_OWNER_GUARD", version=1):
        return reflexes.register_reflex(
            self.db, rule_id=rule, trigger_kind=reflexes.RESOURCE_CEILING,
            evidence_source="6.x spawn governance",
            authority_basis=basis, response_mechanism=mechanism,
            trigger_params={"limit": limit, "window_seconds": 3600.0}, version=version, now=T1)


class TestReflexContract(ReflexCase):

    def test_the_contract_declares_every_required_field(self):
        registered = self.register_resource_reflex()
        for field in ("rule_id", "version", "trigger_kind", "evidence_source", "authority_basis",
                      "response_mechanism", "max_actions_per_window", "window_seconds", "retry_policy",
                      "failure_semantics", "contract_digest"):
            self.assertIn(field, registered)
        self.assertEqual(registered["retry_policy"], "NO_RETRY_AFTER_OUTCOME")

    def test_a_contract_change_without_a_version_is_refused(self):
        self.register_resource_reflex(limit=3)
        with self.assertRaises(CrucibleError) as refused:
            self.register_resource_reflex(limit=99)
        self.assertEqual(refused.exception.reason, "REFLEX_CONTRACT_CHANGED_WITHOUT_A_VERSION")
        bumped = self.register_resource_reflex(limit=99, version=2)
        self.assertEqual(bumped["version"], 2)

    def test_a_trigger_is_computable_from_canonical_state_alone(self):
        self.register_resource_reflex(limit=3)
        self.spawns(2)
        not_yet = reflexes.evaluate(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        self.assertFalse(not_yet["satisfied"])
        self.assertTrue(not_yet["computable_from_canonical_state"])
        self.assertFalse(not_yet["used_the_model"])
        self.spawns(2, now=T1 + 10)
        met = reflexes.evaluate(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        self.assertTrue(met["satisfied"])
        self.assertIn("ceiling", met["reason"])


class TestReflexExecution(ReflexCase):

    def test_the_owner_enforces_and_the_reflex_records_the_owners_verdict(self):
        self.register_resource_reflex(limit=3)
        self.spawns(4)
        result = reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        self.assertEqual(result["decision"], reflexes.TRIGGERED)
        self.assertEqual(result["owner_outcome"], reflexes.ENFORCED_BY_OWNER)
        self.assertEqual(result["owner_ref"], "ciph/kernel/swarm_resources.py")
        self.assertTrue(result["effect_recorded"])
        # decision and outcome are distinguishable records
        self.assertTrue(all(not row["is_an_effect"] for row in reflexes.decisions(self.db)))
        self.assertTrue(all(row["is_an_effect"] for row in reflexes.outcomes(self.db)))

    def test_a_reflex_without_its_authority_basis_refuses_and_preserves_the_reason(self):
        reflexes.register_reflex(self.db, rule_id="quiescence.authorized",
                                 trigger_kind=reflexes.QUIESCENCE_REQUEST,
                                 evidence_source="6.x spawn governance",
                                 authority_basis="OPERATOR_ACTOR",
                                 response_mechanism="SWARM_QUIESCENCE", response_actor="ciph-reflex",
                                 trigger_params={"limit": 1, "window_seconds": 3600.0}, now=T1)
        self.spawns(3)
        refused = reflexes.invoke(self.db, rule_id="quiescence.authorized", subject_ref="swarm",
                                  now=T1 + 100)
        self.assertEqual(refused["decision"], reflexes.REFUSED)
        self.assertEqual(refused["refusal_reason"], reflexes.REASON_NOT_AN_OPERATOR)
        self.assertFalse(refused["effect_recorded"])
        self.assertEqual(self.counts("ciph_reflex_outcomes"), 0)
        # NEGATIVE: with an operator-derived authority the OWNER (5.x quiescence) opens the barrier.
        reflexes.register_reflex(self.db, rule_id="quiescence.operator",
                                 trigger_kind=reflexes.QUIESCENCE_REQUEST,
                                 evidence_source="6.x spawn governance",
                                 authority_basis="OPERATOR_ACTOR", response_mechanism="SWARM_QUIESCENCE",
                                 response_actor=OPERATOR, trigger_params={"limit": 1, "window_seconds": 3600.0},
                                 now=T1)
        allowed = reflexes.invoke(self.db, rule_id="quiescence.operator", subject_ref="swarm",
                                  now=T1 + 200)
        self.assertEqual(allowed["decision"], reflexes.TRIGGERED)
        self.assertEqual(allowed["owner_outcome"], "BARRIER_OPENED_BY_OWNER")

    def test_an_expired_authorization_cannot_be_acted_upon(self):
        grant = create_standing_authorization(self.db, mission_id="M", permitted_work_classes=["RESEARCH"],
                                              granted_by=OPERATOR, risk_ceiling="LOW",
                                              valid_until=T1 + 10, now=T1)
        reflexes.register_reflex(self.db, rule_id="authorization.expired",
                                 trigger_kind=reflexes.AUTHORIZATION_EXPIRED,
                                 evidence_source="5.x standing authorizations",
                                 authority_basis="STANDING_AUTHORIZATION",
                                 response_mechanism="REFUSE_AND_RECORD", now=T1)
        expired = reflexes.invoke(self.db, rule_id="authorization.expired",
                                  subject_ref=grant.standing_auth_id, now=T1 + 100000)
        self.assertEqual(expired["decision"], reflexes.REFUSED)
        self.assertEqual(expired["refusal_reason"], reflexes.REASON_NO_AUTHORITY)
        self.assertEqual(expired["authority_detail"]["status"], "EXPIRED")
        self.assertFalse(expired["effect_recorded"])

    def test_a_duplicate_delivery_is_applied_once(self):
        self.register_resource_reflex(limit=1)
        self.spawns(2)
        first = reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        second = reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 101)
        self.assertTrue(first["effect_recorded"])
        self.assertTrue(second.get("idempotent_replay"))
        self.assertEqual(second["refusal_reason"], reflexes.REASON_DUPLICATE)
        self.assertEqual(len(reflexes.outcomes(self.db)), 1)

    def test_a_missing_witness_is_marked_stale_not_failed(self):
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", freshness_ttl=10.0, now=T1)
        reflexes.register_reflex(self.db, rule_id="witness.missing",
                                 trigger_kind=reflexes.WITNESS_MISSING,
                                 evidence_source="10.3 sensor status", authority_basis="EXISTING_OWNER_GUARD",
                                 response_mechanism="SENSOR_STATUS", now=T1)
        result = reflexes.invoke(self.db, rule_id="witness.missing", subject_ref="beat", now=T1 + 1000)
        self.assertEqual(result["decision"], reflexes.TRIGGERED)
        self.assertEqual(result["owner_outcome"], reflexes.MARKER_PRESERVED)
        self.assertEqual(result["detail"]["sensor_status"], fabric.UNKNOWN)
        self.assertFalse(result["detail"]["subject_failed"])
        # an explicitly marked sensor stays UNKNOWN - a deliberate "we do not know", never "it failed"
        later = fabric.sensor_status(self.db, "beat", now=T1 + 2000)
        self.assertEqual(later["status"], fabric.UNKNOWN)
        self.assertNotEqual(later["status"], fabric.FAILED)
        self.assertFalse(later["is_a_verdict_about_the_subject"])

    def test_a_disputed_integrity_claim_is_flagged_not_executed(self):
        register_component(self.db, component_id="ciph.x", path=str(self.base / "x.py"))
        (self.base / "x.py").write_text("V1\n", encoding="utf-8")
        from ciph.kernel.architectural_proprioception import observations as arch_observations
        witness_observation(self.db, component_id="ciph.x", view="SOURCE", digest="AAA",
                            observer_ref="node-b", independent=True)
        witness_observation(self.db, component_id="ciph.x", view="SOURCE", digest="BBB",
                            observer_ref="node-c", independent=True)
        reflexes.register_reflex(self.db, rule_id="integrity.disputed",
                                 trigger_kind=reflexes.INTEGRITY_DISPUTED,
                                 evidence_source="10.4 integrity claim", authority_basis="READ_ONLY_ASSERTION",
                                 response_mechanism="ATTENTION_FLAG", now=T1)
        result = reflexes.invoke(self.db, rule_id="integrity.disputed", subject_ref="ciph.x", now=T1 + 5)
        self.assertEqual(result["decision"], reflexes.TRIGGERED)
        self.assertEqual(result["owner_outcome"], reflexes.FLAGGED_FOR_ATTENTION)
        self.assertNotEqual(result["detail"]["attention_category"], "CRITICAL")
        self.assertEqual(self.counts("ciph_permits"), 0)
        self.assertTrue(arch_observations(self.db, component_id="ciph.x"))


class TestReflexIndependence(ReflexCase):

    def test_a_reflex_evaluates_with_the_model_completely_unavailable(self):
        class ForbiddenModel:
            def __getattr__(self, item):
                raise AssertionError("a reflex touched the model")
        sentinel = ForbiddenModel()
        self.register_resource_reflex(limit=1)
        self.spawns(2)
        result = reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        self.assertEqual(result["decision"], reflexes.TRIGGERED)
        self.assertEqual(result["owner_outcome"], reflexes.ENFORCED_BY_OWNER)
        self.assertIsNotNone(sentinel)
        for relative in ("ciph/kernel/governed_reflexes.py", "ciph/kernel/operational_homeostasis.py"):
            text = (pathlib.Path(__file__).resolve().parents[1] / relative).read_text(encoding="utf-8")
            for needle in ("call_model(", "invoke_llm(", "query_model(", "BrainRouter"):
                self.assertNotIn(needle, text, relative)

    def test_an_interruption_between_decision_and_outcome_is_visible(self):
        self.register_resource_reflex(limit=1)
        self.spawns(2)
        # simulate an interruption: record a decision via invoke, then delete the outcome row
        reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        import sqlite3
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("DELETE FROM ciph_reflex_outcomes;")
            connection.commit()
        finally:
            connection.close()
        pending = reflexes.decisions_without_an_outcome(self.db)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["decision"], reflexes.TRIGGERED)

    def test_a_reflex_cannot_mint_a_permit(self):
        self.register_resource_reflex(limit=1)
        self.spawns(3)
        before = self.counts("ciph_permits")
        reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        self.assertEqual(self.counts("ciph_permits"), before)
        census = assert_ownership_clean()
        self.assertEqual(census["permits_minted_outside_the_owner"], [])


class TestBaselines(ReflexCase):

    def metric(self, values, *, metric="worker.latency", context="default", start=T1):
        for index, value in enumerate(values):
            homeostasis.observe(self.db, metric=metric, context_key=context, value=value,
                                unit="seconds", source_ref="6.x results", now=start + index)

    def approved(self, *, threshold=0.5, expected_samples=10, values=(10.0,) * 10):
        self.metric(values)
        candidate = homeostasis.propose_baseline(
            self.db, metric="worker.latency", context_key="default", definition="median worker latency",
            source="6.x worker results", units="seconds", window_seconds=3600.0,
            reference_from=T1 - 1, reference_to=T1 + 100, comparison_method="mean-vs-reference-mean",
            threshold=threshold, threshold_justification="policy: 50% over the reference mean",
            expected_samples=expected_samples, confidence=0.9, now=T1 + 200)
        homeostasis.approve_baseline(self.db, candidate_id=candidate["baseline_id"],
                                     approved_by=OPERATOR, now=T1 + 201)
        return candidate

    def test_a_candidate_is_not_normal_until_it_is_approved(self):
        self.metric((10.0,) * 10)
        candidate = homeostasis.propose_baseline(
            self.db, metric="worker.latency", context_key="default", definition="d", source="6.x",
            units="s", window_seconds=3600.0, reference_from=T1 - 1, reference_to=T1 + 100,
            comparison_method="mean-vs-reference-mean", threshold=0.5,
            threshold_justification="policy", expected_samples=10, now=T1 + 200)
        self.assertEqual(candidate["status"], homeostasis.CANDIDATE)
        self.assertTrue(candidate["candidate_is_not_normal_yet"])
        self.assertIsNone(homeostasis.approved_baseline(self.db, metric="worker.latency",
                                                        context_key="default"))
        verdict = homeostasis.evaluate(self.db, metric="worker.latency", context_key="default",
                                       now=T1 + 300)
        self.assertEqual(verdict["verdict"], homeostasis.INCONCLUSIVE)
        self.assertEqual(verdict["reason"], homeostasis.NO_APPROVED_BASELINE)

    def test_only_an_operator_may_promote_a_baseline(self):
        self.metric((10.0,) * 10)
        candidate = homeostasis.propose_baseline(
            self.db, metric="worker.latency", context_key="default", definition="d", source="6.x",
            units="s", window_seconds=3600.0, reference_from=T1 - 1, reference_to=T1 + 100,
            comparison_method="mean-vs-reference-mean", threshold=0.5,
            threshold_justification="policy", expected_samples=10, now=T1 + 200)
        with self.assertRaises(CrucibleError) as refused:
            homeostasis.approve_baseline(self.db, candidate_id=candidate["baseline_id"],
                                         approved_by="ciph", now=T1 + 201)
        self.assertEqual(refused.exception.reason, "BASELINE_PROMOTION_REQUIRES_AN_OPERATOR")

    def test_a_deviation_is_detected_without_a_cause(self):
        self.approved()
        self.metric((40.0,) * 10, start=T1 + 3000)
        verdict = homeostasis.evaluate(self.db, metric="worker.latency", context_key="default",
                                       now=T1 + 3100)
        self.assertEqual(verdict["verdict"], homeostasis.DEVIATION)
        self.assertIsNone(verdict["causal_claim"])
        self.assertFalse(verdict["cause_established"])
        self.assertIn("anomaly_id", verdict)
        record = homeostasis.interpretation(self.db, anomaly_id=verdict["anomaly_id"])
        self.assertEqual(record["anomaly"]["state"], homeostasis.OBSERVED_DEVIATION)
        self.assertFalse(record["authorizes_corrective_action"])

    def test_an_unlike_workload_is_inconclusive(self):
        self.approved()
        self.metric((40.0,) * 10, start=T1 + 3000)
        verdict = homeostasis.evaluate(self.db, metric="worker.latency", context_key="default",
                                       live_context="peak-season", now=T1 + 3100)
        self.assertEqual(verdict["verdict"], homeostasis.INCONCLUSIVE)
        self.assertEqual(verdict["reason"], homeostasis.WORKLOAD_CONTEXT_CHANGED)
        self.assertEqual(homeostasis.anomalies(self.db), [])

    def test_an_incomplete_window_is_inconclusive(self):
        self.approved(expected_samples=100)
        self.metric((40.0,), start=T1 + 3000)
        verdict = homeostasis.evaluate(self.db, metric="worker.latency", context_key="default",
                                       now=T1 + 3100)
        self.assertEqual(verdict["verdict"], homeostasis.INCONCLUSIVE)
        self.assertEqual(verdict["reason"], homeostasis.INSUFFICIENT_OBSERVATIONS)
        self.assertEqual(homeostasis.anomalies(self.db), [])

    def test_a_flood_cannot_rewrite_the_approved_baseline(self):
        self.approved()
        self.metric((999.0,) * 200, start=T1 + 3000)
        baseline = homeostasis.approved_baseline(self.db, metric="worker.latency", context_key="default")
        self.assertEqual(baseline["expected_value"], 10.0)
        self.assertEqual(baseline["version"], 1)
        self.assertEqual(len(homeostasis.baselines(self.db, status=homeostasis.CANDIDATE)), 0)

    def test_a_new_baseline_supersedes_the_previous_approved_one(self):
        self.approved()
        self.metric((20.0,) * 10, start=T1 + 5000)
        candidate = homeostasis.propose_baseline(
            self.db, metric="worker.latency", context_key="default", definition="d2", source="6.x",
            units="s", window_seconds=3600.0, reference_from=T1 + 4999, reference_to=T1 + 6000,
            comparison_method="mean-vs-reference-mean", threshold=0.5, threshold_justification="policy",
            expected_samples=10, now=T1 + 6100)
        self.assertEqual(candidate["version"], 2)
        homeostasis.approve_baseline(self.db, candidate_id=candidate["baseline_id"], approved_by=OPERATOR,
                                     now=T1 + 6101)
        superseded = homeostasis.baselines(self.db, status=homeostasis.SUPERSEDED)
        self.assertEqual(len(superseded), 1)
        self.assertEqual(superseded[0]["version"], 1)
        current = homeostasis.approved_baseline(self.db, metric="worker.latency", context_key="default")
        self.assertEqual(current["version"], 2)


class TestInterpretationAndReflection(ReflexCase):

    def _anomaly(self):
        for index in range(10):
            homeostasis.observe(self.db, metric="worker.latency", context_key="default", value=10.0,
                                unit="s", now=T1 + index)
        candidate = homeostasis.propose_baseline(
            self.db, metric="worker.latency", context_key="default", definition="d", source="6.x", units="s",
            window_seconds=3600.0, reference_from=T1 - 1, reference_to=T1 + 100,
            comparison_method="mean-vs-reference-mean", threshold=0.5, threshold_justification="policy",
            expected_samples=10, now=T1 + 200)
        homeostasis.approve_baseline(self.db, candidate_id=candidate["baseline_id"], approved_by=OPERATOR,
                                     now=T1 + 201)
        for index in range(10):
            homeostasis.observe(self.db, metric="worker.latency", context_key="default", value=40.0,
                                unit="s", now=T1 + 3000 + index)
        return homeostasis.evaluate(self.db, metric="worker.latency", context_key="default",
                                     now=T1 + 3100)["anomaly_id"]

    def test_interpretation_states_are_separate_and_ordered(self):
        anomaly_id = self._anomaly()
        for state in (homeostasis.ANOMALY, homeostasis.CONCERN, homeostasis.HYPOTHESIS):
            homeostasis.advance(self.db, anomaly_id=anomaly_id, state=state, note="staged", now=T1 + 4000)
        with self.assertRaises(CrucibleError) as refused:
            homeostasis.advance(self.db, anomaly_id=anomaly_id, state=homeostasis.ANOMALY, now=T1 + 4001)
        self.assertEqual(refused.exception.reason, "INTERPRETATION_STATES_ARE_ORDERED")
        with self.assertRaises(CrucibleError) as no_evidence:
            homeostasis.advance(self.db, anomaly_id=anomaly_id, state=homeostasis.VERIFIED_CAUSE,
                                now=T1 + 4002)
        self.assertEqual(no_evidence.exception.reason, "VERIFIED_CAUSE_REQUIRES_EVIDENCE")
        confirmed = homeostasis.advance(self.db, anomaly_id=anomaly_id, state=homeostasis.VERIFIED_CAUSE,
                                        evidence_ref="EVID-1", note="reproduced under a controlled run",
                                        now=T1 + 4003)
        self.assertTrue(confirmed["cause_established"])
        record = homeostasis.interpretation(self.db, anomaly_id=anomaly_id)
        self.assertEqual(len(record["history"]), 5)

    def test_an_anomaly_does_not_authorize_corrective_action(self):
        anomaly_id = self._anomaly()
        before = (self.counts("ciph_permits"), self.counts("ciph_crucible_deployments"))
        routed = homeostasis.to_attention(self.db, anomaly_id=anomaly_id, now=T1 + 4000)
        self.assertFalse(routed["grants_authority"])
        self.assertFalse(routed["self_declared_critical"])
        self.assertIn(routed["attention_category"], ("BACKGROUND", "FOCUSED", "CRITICAL"))
        after = (self.counts("ciph_permits"), self.counts("ciph_crucible_deployments"))
        self.assertEqual(before, after)

    def test_the_attention_ratio_is_arithmetic_over_real_records(self):
        from ciph.kernel.selective_attention import submit
        for index in range(3):
            submit(self.db, subject_ref=f"arch-{index}", sensor_kind="CHANGE",
                   evidence_ref="UNRESOLVED", now=T1 + index)
        for index in range(7):
            submit(self.db, subject_ref=f"other-{index}", sensor_kind="ROUTINE", now=T1 + 10 + index)
        ratio = homeostasis.attention_allocation_ratio(self.db, category="FOCUSED",
                                                       window_seconds=1000.0, now=T1 + 100)
        self.assertEqual(ratio["numerator"], 3)
        self.assertEqual(ratio["denominator"], 10)
        self.assertAlmostEqual(ratio["ratio"], 0.3)
        self.assertEqual(ratio["window_to"] - ratio["window_from"], 1000.0)
        self.assertFalse(ratio["model_intuition"])
        self.assertIsNone(ratio["causal_claim"])

    def test_a_wrong_denominator_is_visible(self):
        from ciph.kernel.selective_attention import submit
        submit(self.db, subject_ref="a", sensor_kind="ROUTINE", now=T1)
        ratio = homeostasis.attention_allocation_ratio(self.db, category="FOCUSED",
                                                       window_seconds=1000.0, now=T1 + 10)
        # the numerator and the denominator are BOTH exposed, so a wrong denominator is visible
        self.assertEqual(ratio["denominator"], 1)
        self.assertEqual(ratio["numerator"], 0)
        self.assertEqual(ratio["ratio"], 0.0)
        self.assertFalse(ratio["comparison_permitted"], "no approved baseline means no comparison")


class TestFoundingScenario(ReflexCase):

    def test_the_founding_end_to_end_scenario(self):
        # (1) start the sensory fabric; (2) the main reasoning model is unavailable
        fabric.register_sensor(self.db, sensor_id="resource.consumption", capability="resources",
                               canonical_owner="ciph/kernel/sensory_fabric.py",
                               collection_method="BOUNDED_POLL", freshness_ttl=10.0, now=T1)
        from ciph.kernel.selective_attention import invoke as attention_invoke
        from ciph.kernel.selective_attention import model_available, model_unavailable, submit
        model_unavailable(self.db, reason="main model outage", now=T1)
        # (3) existing authorized worker activity; (4) canonical resource observations
        self.register_resource_reflex(limit=3)
        self.spawns(4)
        fabric.ingest(self.db, sensor_id="resource.consumption", payload={"rss_kb": 999999},
                      kind=fabric.ANOMALY, now=T1 + 1)
        # (5)/(6)/(7) the reflex evaluates WITHOUT the model and asks the existing owner
        result = reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 2)
        self.assertEqual(result["decision"], reflexes.TRIGGERED)
        self.assertEqual(result["owner_outcome"], reflexes.ENFORCED_BY_OWNER)
        # (8) an invalid authorization refuses rather than executes
        expired = create_standing_authorization(self.db, mission_id="M", permitted_work_classes=["R"],
                                                granted_by=OPERATOR, risk_ceiling="LOW",
                                                valid_until=T1 + 1, now=T1)
        reflexes.register_reflex(self.db, rule_id="authorization.expired",
                                 trigger_kind=reflexes.AUTHORIZATION_EXPIRED,
                                 evidence_source="5.x standing authorizations",
                                 authority_basis="STANDING_AUTHORIZATION",
                                 response_mechanism="REFUSE_AND_RECORD", now=T1)
        refusal = reflexes.invoke(self.db, rule_id="authorization.expired",
                                  subject_ref=expired.standing_auth_id, now=T1 + 100000)
        self.assertEqual(refusal["decision"], reflexes.REFUSED)
        self.assertFalse(refusal["effect_recorded"])
        # (9) decisions and effects are separate records
        self.assertTrue(reflexes.decisions(self.db))
        self.assertTrue(reflexes.outcomes(self.db))
        # (10) a meaningful latency departure against an APPROVED baseline
        for index in range(10):
            homeostasis.observe(self.db, metric="worker.latency", context_key="default", value=10.0,
                                unit="s", now=T1 + index)
        candidate = homeostasis.propose_baseline(
            self.db, metric="worker.latency", context_key="default", definition="median latency",
            source="6.x results", units="s", window_seconds=3600.0, reference_from=T1 - 1,
            reference_to=T1 + 100, comparison_method="mean-vs-reference-mean", threshold=0.5,
            threshold_justification="policy: 50% over reference", expected_samples=10, now=T1 + 200)
        homeostasis.approve_baseline(self.db, candidate_id=candidate["baseline_id"], approved_by=OPERATOR,
                                     now=T1 + 201)
        for index in range(10):
            homeostasis.observe(self.db, metric="worker.latency", context_key="default", value=40.0,
                                unit="s", now=T1 + 3000 + index)
        # (11) a deviation is detected WITHOUT a cause
        verdict = homeostasis.evaluate(self.db, metric="worker.latency", context_key="default",
                                       now=T1 + 3200)
        self.assertEqual(verdict["verdict"], homeostasis.DEVIATION)
        self.assertIsNone(verdict["causal_claim"])
        anomaly_id = verdict["anomaly_id"]
        # (12)/(13) a conflicting sensor observation leaves the baseline alone
        register_component(self.db, component_id="ciph.x", path=str(self.base / "x.py"))
        witness_observation(self.db, component_id="ciph.x", view="SOURCE", digest="AAA",
                            observer_ref="node-b", independent=True)
        witness_observation(self.db, component_id="ciph.x", view="SOURCE", digest="BBB",
                            observer_ref="node-c", independent=True)
        baseline_before = homeostasis.approved_baseline(self.db, metric="worker.latency",
                                                        context_key="default")["baseline_id"]
        self.assertEqual(homeostasis.approved_baseline(self.db, metric="worker.latency",
                                                       context_key="default")["baseline_id"],
                         baseline_before)
        # (14) routed into 10.6 without execution standing
        routed = homeostasis.to_attention(self.db, anomaly_id=anomaly_id, now=T1 + 4000)
        self.assertFalse(routed["grants_authority"])
        self.assertEqual(self.counts("ciph_permits"), 0)
        # (15)/(16) interrupt, then reconstruct history, baseline identity and unresolved anomalies
        expected = (reflexes.reflex_digest(self.db), homeostasis.homeostasis_digest(self.db))
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.governed_reflexes import reflex_digest;"
                "from ciph.kernel.operational_homeostasis import homeostasis_digest, anomalies;"
                "print(json.dumps([reflex_digest(%r), homeostasis_digest(%r), "
                "len(anomalies(%r))]))" % ((str(pathlib.Path(__file__).resolve().parents[1]),) + (self.db,) * 3))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        rebuilt = json.loads(out.stdout.strip())
        self.assertEqual((rebuilt[0], rebuilt[1]), expected)
        self.assertEqual(rebuilt[2], 1)
        # (17)/(18) restore the model; the account is evidence-linked
        model_available(self.db, now=T1 + 5000)
        self.assertFalse(attention_invoke(self.db, now=T1 + 5001)["outcome_recorded"] is None)
        self.assertTrue(reflexes.decisions(self.db, rule_id="resource.ceiling"))
        # (20)/(21) no causal claim without causal evidence
        record = homeostasis.interpretation(self.db, anomaly_id=anomaly_id)
        self.assertIsNone(record["anomaly"]["causal_claim"])
        self.assertFalse(record["cause_established"])
        # (22) no unauthorized permit, deployment or execution standing
        self.assertEqual(self.counts("ciph_permits"), 0)
        self.assertEqual(self.counts("ciph_crucible_deployments"), 0)
        self.assertTrue(submit(self.db, subject_ref="x", sensor_kind="ROUTINE", now=T1 + 5002)["queued"])


class TestRemainingAdversarial(ReflexCase):

    def test_a_trigger_without_its_canonical_evidence_is_not_satisfied(self):
        self.register_resource_reflex(limit=5)
        self.spawns(1)
        result = reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        self.assertEqual(result["decision"], reflexes.NOT_TRIGGERED)
        self.assertIsNone(result["outcome"])
        self.assertEqual(self.counts("ciph_reflex_outcomes"), 0)

    def test_a_model_account_cannot_turn_a_refusal_into_an_effect(self):
        from ciph.kernel.epistemic_ledger import record_model_output
        reflexes.register_reflex(self.db, rule_id="quiescence.unauthorized",
                                 trigger_kind=reflexes.QUIESCENCE_REQUEST,
                                 evidence_source="6.x spawn governance",
                                 authority_basis="OPERATOR_ACTOR", response_mechanism="SWARM_QUIESCENCE",
                                 response_actor="ciph-reflex",
                                 trigger_params={"limit": 1, "window_seconds": 3600.0}, now=T1)
        self.spawns(3)
        refused = reflexes.invoke(self.db, rule_id="quiescence.unauthorized", subject_ref="swarm",
                                  now=T1 + 100)
        self.assertEqual(refused["decision"], reflexes.REFUSED)
        record_model_output(self.db, model_ref="llm:test",
                            output_text="The protective action executed successfully.", now=T1 + 200)
        # the MODEL's account is not an effect: the outcome table is still empty
        self.assertEqual(self.counts("ciph_reflex_outcomes"), 0)
        self.assertTrue(all(not row["is_an_effect"] for row in reflexes.decisions(self.db)))

    def test_a_starved_attention_queue_cannot_block_a_required_enforcement_path(self):
        from ciph.kernel.selective_attention import AttentionBudget, submit
        self.register_resource_reflex(limit=1)
        self.spawns(3)
        budget = AttentionBudget(max_queue=1)
        for index in range(50):  # an anomaly flood exhausts the attention queue
            submit(self.db, subject_ref=f"flood-{index}", sensor_kind="ROUTINE", budget=budget,
                   now=T1 + index)
        result = reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 100)
        self.assertEqual(result["decision"], reflexes.TRIGGERED)
        self.assertEqual(result["owner_outcome"], reflexes.ENFORCED_BY_OWNER,
                         "the deterministic enforcement path must not depend on attention")

    def test_the_ratio_compares_against_an_approved_versioned_baseline(self):
        from ciph.kernel.selective_attention import submit
        for index in range(10):
            homeostasis.observe(self.db, metric="attention.category.FOCUSED", context_key="default",
                                value=0.2, now=T1 + index)
        candidate = homeostasis.propose_baseline(
            self.db, metric="attention.category.FOCUSED", context_key="default",
            definition="share of focused attention requests", source="10.6 requests", units="ratio",
            window_seconds=1000.0, reference_from=T1 - 1, reference_to=T1 + 100,
            comparison_method="mean-vs-reference-mean", threshold=0.5,
            threshold_justification="policy", expected_samples=10, now=T1 + 200)
        homeostasis.approve_baseline(self.db, candidate_id=candidate["baseline_id"],
                                     approved_by=OPERATOR, now=T1 + 201)
        for index in range(4):
            submit(self.db, subject_ref=f"f-{index}", sensor_kind="CHANGE", evidence_ref="UNRESOLVED",
                   now=T1 + 300 + index)
        for index in range(6):
            submit(self.db, subject_ref=f"r-{index}", sensor_kind="ROUTINE", now=T1 + 310 + index)
        ratio = homeostasis.attention_allocation_ratio(self.db, category="FOCUSED",
                                                       window_seconds=1000.0, now=T1 + 400)
        self.assertEqual((ratio["numerator"], ratio["denominator"]), (4, 10))
        self.assertAlmostEqual(ratio["ratio"], 0.4)
        self.assertIsNotNone(ratio["baseline"])
        self.assertEqual(ratio["baseline"]["version"], 1)
        self.assertEqual(ratio["baseline"]["expected_ratio"], 0.2)
        self.assertTrue(ratio["comparison_permitted"])
        self.assertIsNone(ratio["causal_claim"])


class TestOwnership(unittest.TestCase):

    def test_the_census_is_clean_and_names_the_owners(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 10)
        for key in ("rival_reflex_or_baseline_owners", "owned_modules_write_canonical",
                    "permits_minted_outside_the_owner", "forbidden_reflex_patterns",
                    "reflex_modules_are_llm_free", "retained_machinery_missing"):
            self.assertEqual(report[key], [], key)

    def test_each_zero_fires_on_its_own_synthetic_violation(self):
        from ciph.kernel import reflex_ownership as census
        real = dict(census.production_sources())
        rogue = "ciph/kernel/rogue_reflex.py"
        cases = [
            (census.rival_reflex_or_baseline_owners,
             "def steal(c):\n    c.execute('INSERT INTO ciph_reflex_decisions VALUES (1);')\n"),
            (census.owned_modules_write_canonical,
             "def go(c):\n    c.execute('INSERT INTO ciph_permits VALUES (1);')\n"),
            (census.permits_minted_outside_the_owner, "P = SignedExecutionPermit(fields={})\n"),
            (census.forbidden_reflex_patterns,
             "def go(db):\n    return reflex_grants_authority(db)\n"),
            (census.reflex_modules_are_llm_free,
             "def go(db):\n    return BrainRouter().ask(db)\n"),
        ]
        for predicate, body in cases:
            with self.subTest(predicate=predicate.__name__):
                if predicate is census.owned_modules_write_canonical:
                    sources = {**real, census.REFLEX_OWNER: body}
                elif predicate is census.reflex_modules_are_llm_free:
                    sources = {**real, census.HOMEOSTASIS_OWNER: body}
                else:
                    sources = {**real, rogue: body}
                self.assertTrue(predicate(sources=list(sources.items())),
                                f"{predicate.__name__} did not fire")


if __name__ == "__main__":
    unittest.main()
