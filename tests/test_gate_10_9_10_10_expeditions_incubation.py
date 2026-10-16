"""
10.9 independent expeditions + 10.10 incubation and cognitive modes.

    Ciph must never confuse wanting to investigate something with having permission to investigate it.
    Ciph must never confuse having an interesting hypothesis with having made a discovery.

The specimens compose the REAL owners: 4.4 uncertainties and proposals, 5.x standing authorization and
autonomy modes, 6.x workers and delegations, 10.0 durable findings, 10.3 sensors, 10.6 attention and 10.8
baselines. Every positive result has a companion where authority or evidence is missing.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from ciph.kernel import independent_expeditions as expeditions
from ciph.kernel import incubation
from ciph.kernel import selective_attention as attention
from ciph.kernel import sensory_fabric as fabric
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.expedition_ownership import assert_ownership_clean
from ciph.kernel.referential_continuity import commit_result_set, retrieve_result_set
from ciph.kernel.standing_authorization import (STATUS_ACTIVE, create_standing_authorization,
                                                revoke_standing_authorization)
from ciph.kernel.swarm_delegation import claim_delegation, propose_delegation
from ciph.kernel.swarm_results import submit_result
from ciph.kernel.swarm_worker import attest_worker, register_worker

T1 = 1_800_000_000.0
OPERATOR = "operator:operator"


class ExpeditionCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-10910-")
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

    def grant(self, *, classes=("RESEARCH",), scope=("public-sources",), risk="LOW", valid_until=T1 + 86400,
              mission="EXPLORATION-1", now=T1):
        return create_standing_authorization(self.db, mission_id=mission, permitted_work_classes=list(classes),
                                             granted_by=OPERATOR, risk_ceiling=risk,
                                             scope_constraints=list(scope), valid_until=valid_until,
                                             now=now)

    def uncertainty(self):
        """A REAL 4.4 uncertainty: a capability recorded but never empirically verified."""
        from ciph.kernel.self_model import record_installation
        from ciph.kernel.uncertainty_registry import derive_uncertainties
        record_installation(self.db, capability_id="research.public-sources", module_ref="fixture", now=T1)
        return derive_uncertainties(self.db, now=T1 + 1)[0].uncertainty_id

    def worker(self, worker_id="W1", *, attest=True):
        # a worker role is registered ONCE per test: re-registering allocates a NEW generation, which would
        # make the earlier generation LATE and is not what these specimens are about.
        cache = getattr(self, "_identities", None)
        if cache is None:
            cache = self._identities = {}
        if worker_id in cache:
            return cache[worker_id]
        identity = register_worker(self.db, worker_id=worker_id, process_identity=worker_id,
                                   code_digest="CODE", environment_digest="ENV", now=T1)
        cache[worker_id] = identity
        if attest:
            attest_worker(self.db, worker_id, identity.instance_generation, observed_code_digest="CODE",
                          observed_environment_digest="ENV", actor=OPERATOR, now=T1)
        from ciph.kernel.swarm_worker import INSTALLED, VERIFIED, record_capability
        for capability in ("research",):
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=INSTALLED, actor=f"worker:{worker_id}", now=T1)
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=VERIFIED, actor=OPERATOR, evidence_ref="CAP-1", now=T1)
        return identity

    def work(self, worker_id, task, output, *, delegation=None, claim=True):
        """Submit ONE arrival. A second arrival on the SAME delegation is how a contradiction arises."""
        identity = self.worker(worker_id)
        if delegation is None:
            delegation = propose_delegation(self.db, task_identity=task, input_digest=f"IN-{task}",
                                            basis_digest=f"BAS-{task}",
                                            allowed_work_class="EVIDENCE_GATHERING",
                                            required_capabilities=["research"], now=T1)
        if claim:
            claim_delegation(self.db, delegation.delegation_id, worker_id=worker_id,
                             worker_generation=identity.instance_generation,
                             input_digest=delegation.input_digest, lease_seconds=120.0, now=T1)
        result = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id=worker_id,
                               worker_generation=identity.instance_generation, output_digest=output,
                               basis_digest=delegation.basis_digest, evidence_refs=["EV"],
                               source_dependency_refs=["SRC"], now=T1)
        return identity, delegation, result

    def findings(self, count=3):
        rows = []
        for index in range(1, count + 1):
            observation = record_observation(self.db, source_ref=f"src:{index}", raw_text=f"finding {index}",
                                             now=T1 + index)
            rows.append({"source_ref": f"src:{index}", "evidence_ref": observation["observation_id"],
                         "summary": f"finding {index}"})
        return rows


class TestExpeditionIdentity(ExpeditionCase):

    def test_a_proposed_expedition_authorizes_nothing(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(),
                                                  domain="public-research", origin_question="why?",
                                                  permitted_tools=["read-public-sources"],
                                                  inference_budget=3, now=T1)
        self.assertEqual(proposed["status"], expeditions.PROPOSED)
        self.assertIsNone(proposed["grant_ref"])
        self.assertEqual(expeditions.authorization_decisions(self.db), [])
        self.assertEqual(self.counts("ciph_permits"), 0)

    def test_a_refusal_is_recorded_with_the_owners_own_reason(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(),
                                                  domain="d", origin_question="q", now=T1)
        refused = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                   grant_ref="SA-DOES-NOT-EXIST", work_class="RESEARCH",
                                                   now=T1)
        self.assertFalse(refused["authorized"])
        self.assertEqual(refused["refusal_reason"], "NO_ACTIVE_STANDING_AUTHORIZATION")
        self.assertFalse(refused["executed"])
        self.assertEqual(expeditions.get_expedition(self.db, proposed["expedition_id"])["status"],
                         expeditions.REFUSED)

    def test_scope_wider_than_the_grant_is_refused_by_the_owner(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(),
                                                  domain="d", origin_question="q", now=T1)
        grant = self.grant(scope=("public-sources",))
        widened = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                   grant_ref=grant.standing_auth_id, work_class="RESEARCH",
                                                   risk_class="LOW",
                                                   requested_scope=["public-sources", "internal-network"],
                                                   now=T1)
        self.assertFalse(widened["authorized"])
        # the OWNER names the refusal; the expedition reports it verbatim
        self.assertIn("SCOPE", widened["refusal_reason"])
        self.assertFalse(widened["executed"])

    def test_a_work_class_outside_the_grant_is_refused(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(),
                                                  domain="d", origin_question="q", now=T1)
        grant = self.grant(classes=("RESEARCH",))
        refused = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                   grant_ref=grant.standing_auth_id,
                                                   work_class="SECURITY_SCANNING", now=T1)
        self.assertFalse(refused["authorized"])
        self.assertEqual(refused["refusal_reason"], "WORK_CLASS_NOT_PERMITTED")


class TestExpeditionLifecycle(ExpeditionCase):

    def authorized(self, **kwargs):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(),
                                                  domain="public-research", origin_question="why?",
                                                  permitted_tools=["read-public-sources"], now=T1)
        grant = kwargs.pop("grant", None) or self.grant()
        decision = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                    grant_ref=grant.standing_auth_id, work_class="RESEARCH",
                                                    risk_class="LOW", requested_scope=["public-sources"],
                                                    now=T1, **kwargs)
        return proposed, grant, decision

    def test_authorization_activates_and_dispatch_uses_the_existing_delegation_path(self):
        proposed, grant, decision = self.authorized()
        self.assertTrue(decision["authorized"])
        self.assertEqual(decision["status"], expeditions.ACTIVE)
        self.worker("W1")
        dispatched = expeditions.dispatch(self.db, expedition_id=proposed["expedition_id"], worker_id="W1",
                                          task_identity="T-1", allowed_work_class="EVIDENCE_GATHERING",
                                          required_capabilities=["research"], now=T1 + 1)
        self.assertFalse(dispatched["mints_a_permit"])
        self.assertTrue(dispatched["delegation_id"].startswith("SD-"))

    def test_an_unauthorized_expedition_cannot_dispatch(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(),
                                                  domain="d", origin_question="q", now=T1)
        with self.assertRaises(CrucibleError) as refused:
            expeditions.dispatch(self.db, expedition_id=proposed["expedition_id"], worker_id="W1",
                                 task_identity="T-1", allowed_work_class="GENERATE_CANDIDATE", now=T1)
        self.assertEqual(refused.exception.reason, "EXPEDITION_NOT_ACTIVE")

    def test_an_expired_grant_stops_a_long_running_expedition(self):
        proposed, grant, _ = self.authorized()
        revalidated = expeditions.revalidate(self.db, expedition_id=proposed["expedition_id"],
                                             now=T1 + 200000)
        self.assertFalse(revalidated["valid"])
        self.assertFalse(revalidated["renews_itself"])
        self.assertEqual(expeditions.get_expedition(self.db, proposed["expedition_id"])["status"],
                         expeditions.REFUSED)

    def test_a_revoked_grant_stops_the_expedition(self):
        proposed, grant, _ = self.authorized()
        revoke_standing_authorization(self.db, grant.standing_auth_id, actor=OPERATOR,
                                      reason="operator revoked", now=T1 + 5)
        revalidated = expeditions.revalidate(self.db, expedition_id=proposed["expedition_id"], now=T1 + 6)
        self.assertFalse(revalidated["valid"])
        self.assertEqual(revalidated["authorization_status"], "REVOKED")

    def test_impossible_lifecycle_transitions_are_refused(self):
        proposed, grant, _ = self.authorized()
        expeditions.lifecycle(self.db, expedition_id=proposed["expedition_id"],
                              to_state=expeditions.COMPLETED, now=T1 + 1)
        with self.assertRaises(CrucibleError) as refused:
            expeditions.lifecycle(self.db, expedition_id=proposed["expedition_id"],
                                  to_state=expeditions.ACTIVE, now=T1 + 2)
        self.assertEqual(refused.exception.reason, "EXPEDITION_TRANSITION_NOT_PERMITTED")

    def test_an_inconclusive_expedition_stays_inconclusive(self):
        proposed, grant, _ = self.authorized()
        expeditions.lifecycle(self.db, expedition_id=proposed["expedition_id"],
                              to_state=expeditions.INCONCLUSIVE, now=T1 + 3)
        record = expeditions.get_expedition(self.db, proposed["expedition_id"])
        self.assertEqual(record["status"], expeditions.INCONCLUSIVE)
        self.assertIsNone(record["result_set_id"])
        self.assertNotEqual(record["status"], expeditions.COMPLETED)


class TestSelectionAndFindings(ExpeditionCase):

    def test_selection_ranks_questions_without_authorizing_them(self):
        self.uncertainty()
        candidates = expeditions.select_candidates(self.db, now=T1)
        self.assertTrue(candidates)
        for candidate in candidates:
            self.assertTrue(candidate["authorization_required"])
            self.assertTrue(candidate["interestingness_is_not_authorization"])
        self.assertEqual(self.counts("ciph_permits"), 0)
        self.assertEqual(expeditions.expeditions(self.db), [])

    def test_findings_are_durable_and_two_identical_sets_stay_distinct(self):
        first = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(), domain="d",
                                               origin_question="q1", now=T1)
        second = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(), domain="d",
                                                origin_question="q2", now=T1 + 1)
        rows = self.findings(3)
        a = expeditions.record_result(self.db, expedition_id=first["expedition_id"], findings=rows, now=T1)
        b = expeditions.record_result(self.db, expedition_id=second["expedition_id"], findings=rows,
                                      now=T1 + 2)
        self.assertNotEqual(a["result_set_id"], b["result_set_id"])
        self.assertEqual(retrieve_result_set(self.db, a["result_set_id"], actor=OPERATOR)["count"], 3)

    def test_a_notification_candidate_claims_no_delivery(self):
        proposed, grant, _ = self.authorized_quick()
        candidate = expeditions.create_notification_candidate(
            self.db, expedition_id=proposed["expedition_id"], finding_refs=["F-1"], confidence="MEDIUM",
            uncertainty="single source", relevance_reason="matches the standing exploration objective",
            now=T1 + 5)
        self.assertFalse(candidate["external_delivery"])
        self.assertFalse(candidate["delivered"])
        self.assertEqual(candidate["status"], "CANDIDATE")
        with self.assertRaises(CrucibleError) as refused:
            expeditions.claim_external_delivery()
        self.assertEqual(refused.exception.reason, "NO_EXTERNAL_NOTIFICATION_TRANSPORT_IS_WIRED")

    def authorized_quick(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(), domain="d",
                                                  origin_question="q", now=T1)
        grant = self.grant()
        decision = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                    grant_ref=grant.standing_auth_id, work_class="RESEARCH",
                                                    requested_scope=["public-sources"], now=T1)
        return proposed, grant, decision


class TestIncubation(ExpeditionCase):

    def test_a_generated_hypothesis_is_never_a_result(self):
        hypothesis = incubation.generate_hypothesis(
            self.db, source_question_ref="self-model:research.public-sources",
            origin_evidence_refs=["OBS-1"], reason="public sources may share a dependency",
            proposed_verification="re-run the source dependence projection", now=T1)
        self.assertEqual(hypothesis["epistemic_status"], incubation.HYPOTHESIS)
        self.assertFalse(hypothesis["is_a_result"])
        self.assertFalse(hypothesis["model_participated"])
        with self.assertRaises(CrucibleError) as refused:
            incubation.set_status(self.db, hypothesis_id=hypothesis["hypothesis_id"], status="VERIFIED",
                                  evidence_ref="EVID-1", now=T1 + 1)
        self.assertEqual(refused.exception.reason,
                         "A_VERIFIED_FINDING_IS_COMMITTED_TO_10_0_NOT_CLAIMED_HERE")

    def test_model_participation_is_recorded_not_laundered(self):
        hypothesis = incubation.generate_hypothesis(
            self.db, source_question_ref="q", origin_evidence_refs=["OBS-1"], reason="a pattern",
            model_participated=True, model_identity="test-double:llm", now=T1)
        self.assertTrue(hypothesis["model_participated"])
        self.assertEqual(hypothesis["model_identity"], "test-double:llm")
        self.assertFalse(hypothesis["is_a_result"])
        self.assertEqual(hypothesis["epistemic_status"], incubation.HYPOTHESIS)

    def test_wording_alone_is_not_novelty(self):
        first = incubation.generate_hypothesis(self.db, source_question_ref="q", origin_evidence_refs=["OBS-1"],
                                               reason="the leak and the patch may share a cause", now=T1)
        paraphrase = incubation.novelty(self.db, source_question_ref="q",
                                        reason="the patch and the leak may share a cause")
        self.assertFalse(paraphrase["is_novel"])
        self.assertEqual(paraphrase["paraphrase_of"], [first["hypothesis_id"]])
        distinct = incubation.novelty(self.db, source_question_ref="q",
                                      reason="the leak and the patch are unrelated")
        self.assertTrue(distinct["is_novel"])

    def test_support_and_refutation_require_evidence(self):
        hypothesis = incubation.generate_hypothesis(self.db, source_question_ref="q",
                                                    origin_evidence_refs=["OBS-1"], reason="r", now=T1)
        with self.assertRaises(CrucibleError):
            incubation.set_status(self.db, hypothesis_id=hypothesis["hypothesis_id"],
                                  status=incubation.SUPPORTED, now=T1 + 1)
        supported = incubation.set_status(self.db, hypothesis_id=hypothesis["hypothesis_id"],
                                          status=incubation.SUPPORTED, evidence_ref="EVID-1", now=T1 + 2)
        self.assertEqual(supported["supporting_evidence"], ["EVID-1"])
        refuted = incubation.set_status(self.db, hypothesis_id=hypothesis["hypothesis_id"],
                                        status=incubation.REFUTED, evidence_ref="EVID-2", now=T1 + 3)
        self.assertEqual(refuted["contradictory_evidence"], ["EVID-2"])
        self.assertFalse(refuted["is_a_result"])


class TestOperatingModes(ExpeditionCase):

    def test_modes_are_a_projection_that_grants_nothing(self):
        projection = incubation.operating_modes(self.db, now=T1)
        self.assertFalse(projection["is_an_authority"])
        self.assertFalse(projection["grants_permission"])
        self.assertFalse(projection["mutually_exclusive"])
        self.assertNotIn(incubation.GOVERNED_HOLD, projection["modes"])

    def test_several_states_can_be_active_at_once(self):
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        fabric.ingest(self.db, sensor_id="beat", payload={"tick": 1}, now=T1)
        attention.submit(self.db, subject_ref="q", sensor_kind="CHANGE", evidence_ref="UNRESOLVED", now=T1)
        projection = incubation.operating_modes(self.db, now=T1 + 1)
        self.assertIn(incubation.OBSERVING, projection["modes"])
        self.assertIn(incubation.DELIBERATING, projection["modes"])
        self.assertFalse(projection["mutually_exclusive"])

    def test_a_blocking_condition_comes_from_its_owner(self):
        from ciph.kernel.autonomy_modes import MODE_QUIESCE, set_mode
        set_mode(self.db, mode=MODE_QUIESCE, actor=OPERATOR, reason="operator hold", now=T1)
        projection = incubation.operating_modes(self.db, now=T1 + 1)
        self.assertIn(incubation.GOVERNED_HOLD, projection["modes"])
        self.assertFalse(incubation.can_start_consequential_work(self.db, now=T1 + 1)["allowed"])
        self.assertEqual(projection["blocking_conditions"][0]["source"], "5.x autonomy mode")

    def test_the_resource_envelope_names_what_it_cannot_measure(self):
        envelope = incubation.resource_envelope(self.db, now=T1)
        self.assertTrue(envelope["model_invocations_are_measured"])
        self.assertTrue(envelope["unmeasurable_metrics"])
        self.assertIn("token consumption (no provider accounting is wired)", envelope["unmeasurable_metrics"])

    def test_model_outage_forbids_a_reasoning_claim(self):
        behaviour = incubation.model_outage_behavior(self.db, now=T1)
        self.assertFalse(behaviour["may_claim_new_reasoning"])
        self.assertFalse(behaviour["grants_permission"])
        self.assertIn("queueing questions for later reasoning", behaviour["may_continue"])


class TestAdversarial(ExpeditionCase):

    def test_01_an_expedition_cannot_mint_its_own_permit(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(), domain="d",
                                                  origin_question="q", now=T1)
        before = self.counts("ciph_permits")
        try:
            expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                             grant_ref="SA-SELF", work_class="RESEARCH", now=T1)
        except CrucibleError:
            pass
        self.assertEqual(self.counts("ciph_permits"), before)
        self.assertEqual(assert_ownership_clean()["permits_minted_outside_the_owner"], [])

    def test_02_a_sensor_alarm_authorizes_no_expedition(self):
        fabric.register_sensor(self.db, sensor_id="loud", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        fabric.ingest(self.db, sensor_id="loud", payload={"severity": "CRITICAL", "start": "expedition"},
                      kind=fabric.ANOMALY, now=T1)
        self.assertEqual(expeditions.expeditions(self.db), [])

    def test_03_an_anomaly_is_not_a_verified_cause(self):
        from ciph.kernel import operational_homeostasis as homeostasis
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
        verdict = homeostasis.evaluate(self.db, metric="worker.latency", context_key="default",
                                       now=T1 + 3200)
        self.assertEqual(verdict["verdict"], homeostasis.DEVIATION)
        self.assertIsNone(verdict["causal_claim"])
        self.assertFalse(verdict["cause_established"])
        sources = incubation.review_sources(self.db, now=T1 + 3300)
        anomalies = [item for item in sources if item["kind"] == "UNEXPLAINED_ANOMALY"]
        self.assertEqual(len(anomalies), 1)
        self.assertIsNone(anomalies[0]["cause"])

    def test_04_a_hypothesis_cannot_be_announced_as_a_discovery(self):
        hypothesis = incubation.generate_hypothesis(self.db, source_question_ref="q",
                                                    origin_evidence_refs=["OBS-1"], reason="maybe", now=T1)
        self.assertEqual(hypothesis["epistemic_status"], incubation.HYPOTHESIS)
        self.assertFalse(hypothesis["is_a_result"])
        self.assertEqual(self.counts("ciph_result_sets"), 0)

    def test_05_an_old_finding_is_not_a_new_discovery(self):
        first = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(), domain="d",
                                               origin_question="q1", now=T1)
        rows = self.findings(2)
        a = expeditions.record_result(self.db, expedition_id=first["expedition_id"], findings=rows, now=T1)
        again = expeditions.record_result(self.db, expedition_id=first["expedition_id"], findings=rows,
                                          now=T1 + 5)
        self.assertEqual(a["result_set_id"], again["result_set_id"])
        self.assertEqual(again["count"], 2)

    def test_06_a_disconnected_worker_is_not_assumed_complete(self):
        self.worker("W-ABSENT", attest=False)
        from ciph.kernel.swarm_worker import members
        active = [record.worker_id for record in members(self.db)]
        self.assertNotIn("W-ABSENT", active)

    def test_07_contradictory_workers_stay_unresolved(self):
        _, delegation, first = self.work("W1", "TASK-A", "OUT-A")
        # a SECOND worker arrives on the same delegation with contradictory content: the owner records it
        # (LATE is about the lease, not about the disagreement) and the projection reports the conflict.
        _, _, conflict = self.work("W2", "TASK-A", "OUT-B", delegation=delegation, claim=False)
        from ciph.kernel import operational_awareness as awareness
        found = [item for item in awareness.contradictions(self.db)
                 if item["kind"] == "WORKER_DISAGREEMENT"]
        self.assertEqual(found[0]["disposition"], "UNRESOLVED")
        self.assertNotEqual(first.output_digest, conflict.output_digest)

    def test_08_duplicate_attention_delivery_spends_no_second_budget(self):
        first = attention.submit(self.db, subject_ref="q", sensor_kind="CHANGE", evidence_ref="UNRESOLVED",
                                 dedup_key="K-1", now=T1)
        again = attention.submit(self.db, subject_ref="q", sensor_kind="CHANGE", evidence_ref="UNRESOLVED",
                                 dedup_key="K-1", now=T1 + 1)
        self.assertEqual(again["status"], attention.DUPLICATE)
        self.assertFalse(again["consumed_budget"])
        self.assertTrue(first["queued"])

    def test_09_idle_produces_no_fictional_reasoning(self):
        attention.model_unavailable(self.db, reason="outage", now=T1)
        attention.submit(self.db, subject_ref="q", sensor_kind="CHANGE", evidence_ref="UNRESOLVED", now=T1)
        refused = attention.invoke(self.db, now=T1 + 1)
        self.assertEqual(refused["status"], attention.MODEL_UNAVAILABLE)
        self.assertFalse(refused["outcome_recorded"])
        self.assertEqual(incubation.operating_modes(self.db, now=T1 + 2)["model_available"], False)

    def test_10_interruption_preserves_the_expedition_context(self):
        proposed, grant, _ = self._active()
        self.worker("W1")
        expeditions.dispatch(self.db, expedition_id=proposed["expedition_id"], worker_id="W1",
                             task_identity="T-1", allowed_work_class="EVIDENCE_GATHERING",
                             required_capabilities=["research"], now=T1 + 1)
        expeditions.checkpoint(self.db, expedition_id=proposed["expedition_id"],
                               note="after the first delegation", delegations=["SD-1"], now=T1 + 2)
        urgent = attention.submit(self.db, subject_ref="urgent", sensor_kind="CHANGE",
                                  evidence_ref="UNRESOLVED", time_sensitive=True, now=T1 + 3)
        attention.invoke(self.db, now=T1 + 4)
        record = expeditions.get_expedition(self.db, proposed["expedition_id"])
        self.assertEqual(record["status"], expeditions.ACTIVE)
        marks = expeditions.checkpoints(self.db, expedition_id=proposed["expedition_id"])
        self.assertEqual(marks[0]["note"], "after the first delegation")
        self.assertTrue(urgent["queued"])

    def test_11_a_narrower_grant_refuses_the_tool_scope(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(), domain="d",
                                                  origin_question="q", now=T1)
        grant = self.grant(scope=("public-sources",))
        refused = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                   grant_ref=grant.standing_auth_id, work_class="RESEARCH",
                                                   requested_scope=["public-sources", "private-lan"], now=T1)
        self.assertIn("SCOPE", refused["refusal_reason"])
        self.assertFalse(refused["executed"])

    def test_12_an_expired_grant_is_refused_at_authorization(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(), domain="d",
                                                  origin_question="q", now=T1)
        grant = self.grant(valid_until=T1 + 1, now=T1)
        refused = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                   grant_ref=grant.standing_auth_id, work_class="RESEARCH",
                                                   requested_scope=["public-sources"], now=T1 + 1000)
        self.assertFalse(refused["authorized"])
        self.assertEqual(refused["detail"]["authorization_status"], "EXPIRED")

    def _active(self):
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=self.uncertainty(), domain="d",
                                                  origin_question="q", now=T1)
        grant = self.grant()
        expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                         grant_ref=grant.standing_auth_id, work_class="RESEARCH",
                                         requested_scope=["public-sources"], now=T1)
        return proposed, grant, None


class TestFoundingScenario(ExpeditionCase):
    """Part F - the 32-step integrated scenario, composed of the real subsystem integrations."""

    def test_the_founding_independent_expedition_scenario(self):
        from ciph.kernel import operational_homeostasis as homeostasis
        from ciph.kernel import operational_awareness as awareness
        from ciph.kernel import operational_presence as presence
        from ciph.kernel import conversational_continuity as conv
        from ciph.kernel.standing_authorization import authorization_status

        # (1) an enduring, explicitly bounded exploration objective
        grant = self.grant(mission="EXPLORATION-1", classes=("RESEARCH",), scope=("public-sources",))
        # (2) the current operator authorization is verified
        self.assertEqual(authorization_status(self.db, grant.standing_auth_id, now=T1), STATUS_ACTIVE)
        # (3) operator becomes absent from the conversation
        conv.register_participant(self.db, participant_id=OPERATOR, role=conv.OPERATOR, now=T1)
        conv.register_participant(self.db, participant_id="ciph", role=conv.ASSISTANT, now=T1)
        conv.register_channel(self.db, channel_id="terminal", kind="LOCAL_TERMINAL", now=T1)
        conv.open_session(self.db, session_id="SES-1", participant_id=OPERATOR, channel_id="terminal",
                          topic_ref="EXPLORATION-1", now=T1)
        conv.record_turn(self.db, session_id="SES-1", speaker=OPERATOR,
                         text="Explore public sources for a week.", kind=conv.COMMITMENT,
                         authorization_ref=grant.standing_auth_id, now=T1)
        conv.close_session(self.db, session_id="SES-1", now=T1 + 1)
        # (4) the main LLM is unavailable; (5) the fabric continues collecting
        attention.model_unavailable(self.db, reason="main model outage", now=T1 + 2)
        fabric.register_sensor(self.db, sensor_id="resource.consumption", capability="resources",
                               canonical_owner="ciph/kernel/sensory_fabric.py",
                               collection_method="BOUNDED_POLL", freshness_ttl=100000.0, now=T1 + 2)
        fabric.ingest(self.db, sensor_id="resource.consumption", payload={"rss_kb": 100},
                      kind=fabric.ROUTINE, now=T1 + 3)
        # (6) homeostasis produces an evidence-backed anomaly
        for index in range(10):
            homeostasis.observe(self.db, metric="worker.latency", context_key="default", value=10.0,
                                unit="s", now=T1 + 10 + index)
        candidate = homeostasis.propose_baseline(
            self.db, metric="worker.latency", context_key="default", definition="median latency",
            source="6.x results", units="s", window_seconds=3600.0, reference_from=T1 - 1,
            reference_to=T1 + 100, comparison_method="mean-vs-reference-mean", threshold=0.5,
            threshold_justification="policy", expected_samples=10, now=T1 + 200)
        homeostasis.approve_baseline(self.db, candidate_id=candidate["baseline_id"], approved_by=OPERATOR,
                                     now=T1 + 201)
        for index in range(10):
            homeostasis.observe(self.db, metric="worker.latency", context_key="default", value=40.0,
                                unit="s", now=T1 + 3000 + index)
        verdict = homeostasis.evaluate(self.db, metric="worker.latency", context_key="default",
                                       now=T1 + 3200)
        self.assertEqual(verdict["verdict"], homeostasis.DEVIATION)
        self.assertIsNone(verdict["causal_claim"])
        # (7) an existing unresolved research question is also eligible
        uncertainty = self.uncertainty()
        # (8) attention evaluates which question deserves inference
        attention.submit(self.db, subject_ref=verdict["anomaly_id"], sensor_kind="CHANGE",
                         evidence_ref=uncertainty, now=T1 + 3300)
        attention.submit(self.db, subject_ref=uncertainty, sensor_kind="CHANGE", evidence_ref=uncertainty,
                         now=T1 + 3301)
        plan = attention.schedule(self.db, now=T1 + 3302)
        self.assertEqual(plan["status"], "SELECTED")
        # (9) NO fictional deliberation while the model is unavailable
        refused = attention.invoke(self.db, now=T1 + 3303)
        self.assertEqual(refused["status"], attention.MODEL_UNAVAILABLE)
        self.assertFalse(refused["outcome_recorded"])
        # (10) the reasoning model becomes available
        attention.model_available(self.db, now=T1 + 3400)
        # (11) Ciph evaluates eligible questions using actual evidence
        candidates = expeditions.select_candidates(self.db, now=T1 + 3401)
        self.assertTrue(candidates)
        self.assertTrue(all(item["authorization_required"] for item in candidates))
        # (12) Ciph independently selects a worthwhile authorized investigation
        proposed = expeditions.propose_expedition(
            self.db, uncertainty_ref=uncertainty, domain="public-research",
            origin_question="which public sources share the untested capability dependency?",
            permitted_tools=["read-public-sources"], inference_budget=4, tool_call_budget=8, now=T1 + 3402)
        # (13) the required existing authority checks
        decision = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                    grant_ref=grant.standing_auth_id, work_class="RESEARCH",
                                                    risk_class="LOW", requested_scope=["public-sources"],
                                                    now=T1 + 3403)
        self.assertTrue(decision["authorized"])
        # (14) delegate permitted work to existing workers
        self.worker("W1")
        self.worker("W2")
        first = expeditions.dispatch(self.db, expedition_id=proposed["expedition_id"], worker_id="W1",
                                     task_identity="T-1", allowed_work_class="EVIDENCE_GATHERING",
                                     required_capabilities=["research"], now=T1 + 3404)
        # (15) supporting evidence; (16) contradictory evidence
        _, shared_delegation, supporting = self.work("W1", "TASK-SUPPORT", "OUT-SUPPORT")
        _, _, contrary = self.work("W2", "TASK-SUPPORT", "OUT-CONTRARY", delegation=shared_delegation,
                                   claim=False)
        # (17) the conflict is preserved, not resolved by preference
        found = [item for item in awareness.contradictions(self.db)
                 if item["kind"] == "WORKER_DISAGREEMENT"]
        self.assertEqual(found[0]["disposition"], "UNRESOLVED")
        self.assertNotEqual(supporting.output_digest, contrary.output_digest)
        # (18) an urgent event interrupts attention; (19) the context is preserved
        expeditions.checkpoint(self.db, expedition_id=proposed["expedition_id"],
                               note="after the first two results", delegations=[first["delegation_id"]],
                               now=T1 + 3410)
        urgent = attention.submit(self.db, subject_ref="urgent-architectural", sensor_kind="CHANGE",
                                  evidence_ref=uncertainty, time_sensitive=True, now=T1 + 3411)
        attention.invoke(self.db, now=T1 + 3412)
        # (20) a worker becomes unavailable; (21) Ciph does NOT fabricate progress
        self.worker("W3", attest=False)
        progress = presence.honest_progress(self.db, subject_ref=proposed["expedition_id"],
                                            since=T1 + 3405, now=T1 + 3500)
        self.assertFalse(progress["progressed"])
        self.assertTrue(progress["nothing_authorized_happened"])
        # (22) the investigation resumes through the legitimate lifecycle
        self.assertEqual(expeditions.lifecycle(self.db, expedition_id=proposed["expedition_id"],
                                               to_state=expeditions.PAUSED,
                                               now=T1 + 3501)["status"], expeditions.PAUSED)
        self.assertEqual(expeditions.lifecycle(self.db, expedition_id=proposed["expedition_id"],
                                               to_state=expeditions.ACTIVE,
                                               now=T1 + 3502)["status"], expeditions.ACTIVE)
        # (23) a meaningful finding is committed through 10.0
        recorded = expeditions.record_result(self.db, expedition_id=proposed["expedition_id"],
                                             findings=self.findings(3), now=T1 + 3503)
        self.assertEqual(recorded["count"], 3)
        # (24) a separate hypothesis remains EXPLICITLY unverified
        hypothesis = incubation.generate_hypothesis(
            self.db, source_question_ref=uncertainty, origin_evidence_refs=[supporting.result_id],
            reason="the latency rise and the new public source may share a dependency",
            supporting_evidence_refs=[supporting.result_id],
            contradictory_evidence_refs=[contrary.result_id],
            proposed_verification="re-run the source dependence projection",
            authorization_status="NOT_YET_AUTHORIZED", model_participated=True,
            model_identity="test-double:llm", now=T1 + 3504)
        self.assertEqual(hypothesis["epistemic_status"], incubation.HYPOTHESIS)
        self.assertFalse(hypothesis["is_a_result"])
        # (25) an evidence-backed notification candidate, with NO delivery claimed
        candidate_notice = expeditions.create_notification_candidate(
            self.db, expedition_id=proposed["expedition_id"],
            finding_refs=[supporting.result_id, contrary.result_id], confidence="MEDIUM",
            uncertainty="the two worker results disagree",
            relevance_reason="matches the standing EXPLORATION-1 objective", now=T1 + 3505)
        self.assertFalse(candidate_notice["delivered"])
        # (26)/(27) operator returns and asks what Ciph discovered
        conv.open_session(self.db, session_id="SES-2", participant_id=OPERATOR, channel_id="terminal",
                          topic_ref="EXPLORATION-1", now=T1 + 3600)
        retrieved = retrieve_result_set(self.db, recorded["result_set_id"], actor=OPERATOR)
        self.assertEqual(retrieved["count"], 3)
        self.assertEqual(expeditions.get_expedition(self.db, proposed["expedition_id"])["result_set_id"],
                         recorded["result_set_id"])
        # (28)/(29) the unresolved hypothesis, with what supports and contradicts it
        explained = incubation.get_hypothesis(self.db, hypothesis["hypothesis_id"])
        self.assertEqual(explained["epistemic_status"], incubation.HYPOTHESIS)
        self.assertEqual(explained["supporting_evidence"], [supporting.result_id])
        self.assertEqual(explained["contradictory_evidence"], [contrary.result_id])
        self.assertTrue(explained["model_participated"])
        self.assertFalse(explained["is_a_result"])
        # (30)/(31) the runtime restarts; a FRESH PROCESS reconstructs the same state
        expected = (expeditions.expedition_digest(self.db), incubation.incubation_digest(self.db),
                    conv.conversation_digest(self.db))
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.independent_expeditions import expedition_digest;"
                "from ciph.kernel.incubation import incubation_digest;"
                "from ciph.kernel.conversational_continuity import conversation_digest;"
                "print(json.dumps([expedition_digest(%r), incubation_digest(%r), "
                "conversation_digest(%r)]))" % ((str(pathlib.Path(__file__).resolve().parents[1]),) +
                                                (self.db,) * 3))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(tuple(json.loads(out.stdout.strip())), expected)
        # (32) no authorization, deployment or execution authority was invented
        self.assertEqual(self.counts("ciph_permits"), 0)
        self.assertEqual(self.counts("ciph_crucible_deployments"), 0)
        self.assertFalse(incubation.operating_modes(self.db, now=T1 + 3700)["grants_permission"])
        self.assertTrue(urgent["queued"])
        self.assertEqual(len(expeditions.checkpoints(self.db,
                                                     expedition_id=proposed["expedition_id"])), 1)
        self.assertTrue(expeditions.authorization_decisions(self.db)[0]["authorized"])


class TestOwnership(unittest.TestCase):

    def test_the_census_is_clean_and_names_the_owners(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 8)
        for key in ("rival_expedition_or_hypothesis_owners", "owned_modules_write_canonical",
                    "permits_minted_outside_the_owner", "forbidden_expedition_patterns",
                    "expedition_modules_do_not_reason", "retained_machinery_missing"):
            self.assertEqual(report[key], [], key)

    def test_each_zero_fires_on_its_own_synthetic_violation(self):
        from ciph.kernel import expedition_ownership as census
        real = dict(census.production_sources())
        rogue = "ciph/kernel/rogue_expedition.py"
        cases = [
            (census.rival_expedition_or_hypothesis_owners,
             "def steal(c):\n    c.execute('INSERT INTO ciph_expeditions VALUES (1);')\n"),
            (census.owned_modules_write_canonical,
             "def go(c):\n    c.execute('INSERT INTO ciph_permits VALUES (1);')\n"),
            (census.permits_minted_outside_the_owner, "P = SignedExecutionPermit(fields={})\n"),
            (census.forbidden_expedition_patterns,
             "def go(db):\n    return curiosity_priority_v2(db)\n"),
            (census.expedition_modules_do_not_reason,
             "def go(db):\n    return BrainRouter().ask(db)\n"),
        ]
        for predicate, body in cases:
            with self.subTest(predicate=predicate.__name__):
                if predicate is census.owned_modules_write_canonical:
                    sources = {**real, census.EXPEDITION_OWNER: body}
                elif predicate is census.expedition_modules_do_not_reason:
                    sources = {**real, census.INCUBATION_OWNER: body}
                else:
                    sources = {**real, rogue: body}
                self.assertTrue(predicate(sources=list(sources.items())),
                                f"{predicate.__name__} did not fire")


if __name__ == "__main__":
    unittest.main()
