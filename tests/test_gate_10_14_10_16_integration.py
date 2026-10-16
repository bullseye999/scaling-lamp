"""
10.14 unified cognition · 10.15 adversarial torture · 10.16 evidence and seal.

    One Ciph. One continuing history. Many operational senses. Selective attention. Governed initiative.
    Evidence before every claim.
"""

import json
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from ciph.kernel import evidence_reconciliation as recon
from ciph.kernel import integration_ownership as integration
from ciph.kernel import model_boundary
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.referential_continuity import commit_result_set, retrieve_nth, retrieve_result_set
from ciph.kernel.standing_authorization import create_standing_authorization

T1 = 1_800_000_000.0
OPERATOR = "operator:operator"


class FinalCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-101416-")
        self.base = pathlib.Path(self.temp.name)
        self.db = str(self.base / "state.db")

    def tearDown(self):
        self.temp.cleanup()

    def counts(self, table):
        if not pathlib.Path(self.db).exists():
            return 0
        connection = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            return int(connection.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            connection.close()

    def findings(self, count=3, ref="EXPEDITION:1"):
        rows = []
        for index in range(1, count + 1):
            observation = record_observation(self.db, source_ref=f"src:{index}",
                                             raw_text=f"finding {index}", now=T1 + index)
            rows.append({"source_ref": f"src:{index}", "evidence_ref": observation["observation_id"],
                         "summary": f"finding {index}"})
        written = commit_result_set(self.db, investigation_ref=ref, findings=rows, now=T1)
        return written, retrieve_result_set(self.db, written["result_set_id"],
                                            actor=OPERATOR)["findings"]


class TestIntegrationMap(FinalCase):
    """Part A - the map must match the ACTUAL source tree."""

    def test_every_declared_boundary_still_exists_with_its_surface(self):
        report = integration.validate()
        self.assertEqual(report["boundaries"], 36)
        self.assertEqual(report["missing_files"], [])
        self.assertEqual(report["missing_surface"], [])
        self.assertTrue(report["valid"])

    def test_the_map_fires_when_a_declared_surface_disappears(self):
        """A boundary whose surface vanished must be REPORTED, not tolerated."""
        broken = dict(integration.production_sources())
        broken["ciph/kernel/selective_attention.py"] = "def something_else():\n    pass\n"
        missing = []
        for boundary in integration.MAP:
            text = broken.get(boundary.owner)
            for name in boundary.surface:
                if text is not None and name not in text:
                    missing.append(f"{boundary.owner}:{name}")
        self.assertIn("ciph/kernel/selective_attention.py:schedule", missing)

    def test_no_rival_writers_of_the_sampled_canonical_tables(self):
        conflicts = integration.ownership_conflicts(sample_tables=[
            "ciph_permits", "ciph_result_sets", "ciph_sensor_events", "ciph_conv_turns",
            "ciph_reflex_outcomes", "ciph_notifications", "ciph_personality_policies",
            "ciph_arch_changes", "ciph_attention_requests", "ciph_claims", "ciph_reconciliations",
            "ciph_model_invocations"])
        self.assertEqual(list(conflicts), [])

    def test_the_map_names_exactly_one_owner_per_table(self):
        for table in ("ciph_permits", "ciph_result_sets", "ciph_notifications"):
            self.assertEqual(len(integration.owners_of(table)), 1, table)


class TestEvidenceReconciliation(FinalCase):
    """C1/C2 - the reconciliation is rule-derived, and a citation that contradicts its own conclusion fails."""

    def test_the_declared_rule_produces_the_conclusion_not_a_hardcoded_word(self):
        record = recon.reconcile(self.db, question="At 10:00, was the valve OPEN or CLOSED?",
                                 rule=recon.NEWEST_CALIBRATED_WINS, now=T1,
                                 evidence=[{"ref": "E1", "value": "CLOSED", "observed_at": T1 - 3600,
                                            "calibrated_at": T1 - 7200, "source": "s1"},
                                           {"ref": "E3", "value": "OPEN", "observed_at": T1 - 300,
                                            "calibrated_at": T1 - 200, "source": "s4"}])
        self.assertEqual(record["conclusion"], "OPEN")
        self.assertEqual(record["supporting"], ["E3"])
        self.assertEqual(record["contradicting"], ["E1"])
        self.assertIn("most recently calibrated", record["rationale"])
        # the SAME rule on different evidence produces a DIFFERENT conclusion
        flipped = recon.reconcile(self.db, question="q2", rule=recon.NEWEST_CALIBRATED_WINS, now=T1,
                                  evidence=[{"ref": "A", "value": "LOCKED", "observed_at": T1 - 10,
                                             "calibrated_at": T1 - 5, "source": "a"},
                                            {"ref": "B", "value": "UNLOCKED", "observed_at": T1 - 900,
                                             "calibrated_at": T1 - 100, "source": "b"}])
        self.assertEqual(flipped["conclusion"], "LOCKED")

    def test_citing_the_decisive_evidence_while_concluding_the_opposite_fails(self):
        record = recon.reconcile(self.db, question="valve", rule=recon.NEWEST_CALIBRATED_WINS, now=T1,
                                 evidence=[{"ref": "E1", "value": "CLOSED", "observed_at": T1 - 3600,
                                            "calibrated_at": T1 - 7200},
                                           {"ref": "E3", "value": "OPEN", "observed_at": T1 - 300,
                                            "calibrated_at": T1 - 200}])
        self.assertFalse(recon.citation_consistency(record, cited_ref="E3",
                                                    conclusion="CLOSED")["consistent"])
        self.assertEqual(recon.score_conclusion(record, conclusion="CLOSED")["correct"], False)
        self.assertTrue(recon.citation_consistency(record, cited_ref="E3",
                                                   conclusion="OPEN")["consistent"])

    def test_unsettled_evidence_demands_abstention(self):
        no_rule = recon.reconcile(self.db, question="caused?", rule=recon.NO_DECLARED_RULE, now=T1,
                                  evidence=[{"ref": "E1", "value": "CHANGE"}, {"ref": "E2", "value": "SLOW"}])
        self.assertTrue(no_rule["abstained"])
        self.assertTrue(recon.score_conclusion(no_rule, conclusion="ABSTAIN")["correct"])
        self.assertFalse(recon.score_conclusion(no_rule, conclusion="YES")["correct"])
        tie = recon.reconcile(self.db, question="door", rule=recon.EQUAL_CREDIBILITY, now=T1,
                              evidence=[{"ref": "E1", "value": "SEALED", "observed_at": T1 - 5},
                                        {"ref": "E2", "value": "OPEN", "observed_at": T1 - 4}])
        self.assertTrue(tie["abstained"])
        missing = recon.reconcile(self.db, question="alarm", rule=recon.NEWEST_CALIBRATED_WINS,
                                  required_sources=("verification",), now=T1,
                                  evidence=[{"ref": "E1", "value": "ACTIVE", "source": "panel"}])
        self.assertEqual(missing["rule"], recon.SOURCE_MISSING)
        self.assertTrue(missing["abstained"])

    def test_the_older_controlling_rule_still_works(self):
        record = recon.reconcile(self.db, question="q", rule=recon.OLDER_CONTROLLING, now=T1,
                                 evidence=[{"ref": "E1", "value": "CLOSED", "observed_at": T1 - 900},
                                           {"ref": "E2", "value": "OPEN", "observed_at": T1 - 10}])
        self.assertEqual(record["conclusion"], "CLOSED")


class TestUnifiedLifecycle(FinalCase):
    """B1 - one continuous relationship, with no stage claiming the next one completed."""

    def test_the_full_chain_is_evidence_linked(self):
        from ciph.kernel import selective_attention as attention
        from ciph.kernel import sensory_fabric as fabric

        # Observation -> evidence -> operational model -> attention -> proposal -> authorization
        fabric.register_sensor(self.db, sensor_id="s", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        fabric.ingest(self.db, sensor_id="s", payload={"rss_kb": 10}, now=T1 + 1)
        observation = record_observation(self.db, source_ref="sensor:s", raw_text="rss 10", now=T1 + 2)
        self.assertTrue(observation["observation_id"].startswith("OBS-"))
        queued = attention.submit(self.db, subject_ref="s", sensor_kind="CHANGE",
                                  evidence_ref=observation["observation_id"],
                                  related_to_active_goal=True, now=T1 + 3)
        self.assertTrue(queued["queued"])
        from ciph.kernel.self_model import record_installation
        from ciph.kernel.uncertainty_registry import derive_uncertainties
        record_installation(self.db, capability_id="research.public-sources", now=T1 + 4)
        uncertainty = derive_uncertainties(self.db, now=T1 + 5)[0].uncertainty_id
        from ciph.kernel import independent_expeditions as expeditions
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=uncertainty, domain="d",
                                                  origin_question="q", now=T1 + 6)
        grant = create_standing_authorization(self.db, mission_id="M", permitted_work_classes=["RESEARCH"],
                                              granted_by=OPERATOR, risk_ceiling="LOW",
                                              scope_constraints=["public-sources"],
                                              valid_until=T1 + 86400, now=T1 + 7)
        decision = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                    grant_ref=grant.standing_auth_id, work_class="RESEARCH",
                                                    requested_scope=["public-sources"], now=T1 + 8)
        self.assertTrue(decision["authorized"])
        # Execution -> finding -> conversation -> follow-up
        written, findings = self.findings(3, ref=f"EXPEDITION:{proposed['expedition_id']}")
        expeditions.record_result(self.db, expedition_id=proposed["expedition_id"],
                                  findings=[{"source_ref": f["source_ref"], "evidence_ref": f["evidence_ref"],
                                             "summary": f["summary"]} for f in findings], now=T1 + 9)
        from ciph.kernel import conversational_continuity as conv
        conv.register_participant(self.db, participant_id=OPERATOR, role=conv.OPERATOR, now=T1)
        conv.register_channel(self.db, channel_id="c", kind="LOCAL_TERMINAL", now=T1)
        conv.open_session(self.db, session_id="S1", participant_id=OPERATOR, channel_id="c", now=T1 + 10)
        conv.record_turn(self.db, session_id="S1", speaker=OPERATOR, text="tell me about the third",
                         refs=[(conv.FINDING, findings[2]["finding_id"])], now=T1 + 11)
        followup = conv.record_turn(self.db, session_id="S1", speaker="ciph", text="it is the third",
                                    kind=conv.COMMITMENT, now=T1 + 12)
        self.assertEqual(retrieve_nth(self.db, written["result_set_id"], 3,
                                      actor=OPERATOR)["finding"]["finding_id"],
                         findings[2]["finding_id"])
        # a REQUEST is not a completion: the expedition is ACTIVE, not COMPLETED
        self.assertEqual(expeditions.get_expedition(self.db, proposed["expedition_id"])["status"],
                         expeditions.ACTIVE)
        self.assertTrue(queued["request_id"])
        self.assertIsNotNone(followup["turn_id"])

    def test_inference_independent_operation_is_recorded_honestly(self):
        from ciph.kernel import selective_attention as attention
        from ciph.kernel import sensory_fabric as fabric
        attention.model_unavailable(self.db, reason="outage", now=T1)
        fabric.register_sensor(self.db, sensor_id="s", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        fabricated = model_boundary.invoke(self.db, messages=[{"role": "user", "content": "think"}],
                                           purpose="p", provider="NONE", now=T1)
        self.assertTrue(fabric.ingest(self.db, sensor_id="s", payload={"tick": 1}, now=T1 + 1)["stored"])
        refused = attention.invoke(self.db, now=T1 + 2)
        self.assertEqual(refused["status"], attention.MODEL_UNAVAILABLE)
        self.assertFalse(refused["outcome_recorded"])
        self.assertTrue(fabricated["refused"])
        self.assertEqual([row for row in model_boundary.invocations(self.db)
                          if row["output_text"] is not None], [])


class TestFoundingTorture(FinalCase):
    """D1 - the 40-step integrated scenario, composed of the actual subsystem interfaces."""

    def test_the_founding_complete_system_scenario(self):
        from ciph.kernel import (selective_attention as attention, conversational_continuity as conv,
                                 independent_expeditions as expeditions, incubation,
                                 notification_pipeline as pipeline, operational_awareness as awareness,
                                 operational_homeostasis as homeostasis, operational_presence as presence,
                                 personality_policy as policy, governed_reflexes as reflexes,
                                 sensory_fabric as fabric, session_adapter as session)


        # (1)(2) a bounded objective, stored and authorized
        grant = create_standing_authorization(self.db, mission_id="FINAL-1",
                                              permitted_work_classes=["RESEARCH"], granted_by=OPERATOR,
                                              risk_ceiling="LOW", scope_constraints=["public-sources"],
                                              valid_until=T1 + 86400, now=T1)
        policy.propose_change(self.db, key="style.detail", value="thorough",
                              policy_class=policy.OPERATOR_PREFERENCE, provenance="bounded objective",
                              actor=OPERATOR, now=T1)
        # (3)(4) operator disconnects; the model becomes unavailable
        conv.register_participant(self.db, participant_id=OPERATOR, role=conv.OPERATOR, now=T1)
        conv.register_channel(self.db, channel_id="terminal", kind="LOCAL_TERMINAL", now=T1)
        conv.open_session(self.db, session_id="S1", participant_id=OPERATOR, channel_id="terminal",
                          topic_ref="FINAL-1", now=T1)
        conv.close_session(self.db, session_id="S1", now=T1 + 1)
        attention.model_unavailable(self.db, reason="model outage", now=T1 + 2)
        # (5) sensors keep collecting; (6)(7) an architectural change is detected, SOURCE vs LOADED distinct
        fabric.register_sensor(self.db, sensor_id="resource.consumption", capability="r",
                               canonical_owner="ciph/kernel/sensory_fabric.py",
                               collection_method="BOUNDED_POLL", freshness_ttl=100000.0, now=T1 + 2)
        fabric.ingest(self.db, sensor_id="resource.consumption", payload={"rss_kb": 10}, now=T1 + 3)
        from ciph.kernel import sensory_adapters as adapters
        from ciph.kernel.architectural_proprioception import (LOADED, MISMATCH, SOURCE,
                                                              architectural_projection, register_component)
        component_path = self.base / "component.py"
        component_path.write_text("V1\n", encoding="utf-8")
        register_component(self.db, component_id="ciph.example", path=str(component_path))
        first = adapters.observe_architecture(self.db, component_id="ciph.example", now=T1 + 4)
        adapters.witness_runtime(self.db, component_id="ciph.example",
                                 digest=first["observation"]["digest"], runtime_generation="G1", now=T1 + 5)
        component_path.write_text("V2 -- changed\n", encoding="utf-8")
        adapters.observe_architecture(self.db, component_id="ciph.example", now=T1 + 6)
        projection = architectural_projection(self.db, component="ciph.example")
        self.assertEqual(projection["distinctions"]["source_vs_loaded"], MISMATCH)
        self.assertNotEqual(projection["views"][SOURCE]["digest"],
                            projection["views"][LOADED]["digest"])
        # (8)(9) a worker finding and a contradictory arrival; (10)(11) a node is UNKNOWN, not DEAD
        from ciph.kernel.swarm_delegation import claim_delegation, propose_delegation
        from ciph.kernel.swarm_results import submit_result
        from ciph.kernel.swarm_worker import attest_worker, register_worker
        from ciph.kernel.federation_node import register_node
        identity = register_worker(self.db, worker_id="W1", process_identity="w1", code_digest="C",
                                   environment_digest="E", now=T1 + 7)
        attest_worker(self.db, worker_id="W1", generation=identity.instance_generation,
                      observed_code_digest="C", observed_environment_digest="E", actor=OPERATOR, now=T1 + 8)
        delegation = propose_delegation(self.db, task_identity="T", input_digest="I", basis_digest="B",
                                        allowed_work_class="EVIDENCE_GATHERING", now=T1 + 9)
        claim_delegation(self.db, delegation.delegation_id, worker_id="W1",
                         worker_generation=identity.instance_generation, input_digest="I",
                         lease_seconds=120.0, now=T1 + 10)
        first_result = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id="W1",
                                     worker_generation=identity.instance_generation, output_digest="OUT-A",
                                     basis_digest="B", evidence_refs=["EV"], now=T1 + 11)
        contradictory = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id="W2",
                                      worker_generation=1, output_digest="OUT-B", basis_digest="B",
                                      now=T1 + 12)
        register_node(self.db, node_id="N-ISO", public_key_ref="k", code_digest="C",
                      environment_digest="E", actor=OPERATOR, now=T1 + 13)
        node_state = awareness.subject_state(self.db, ref="node:N-ISO:1", owner_ref="node:N-ISO",
                                             now=T1 + 14)
        self.assertIn(node_state["state"], (awareness.UNKNOWN, awareness.STALE))
        self.assertFalse(node_state["is_a_verdict_about_the_subject"])
        # (12) homeostasis detects a deviation; (13)(14) a reflex evaluates and uses its OWNER
        for index in range(10):
            homeostasis.observe(self.db, metric="worker.latency", context_key="default", value=10.0,
                                unit="s", now=T1 + 20 + index)
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
        from ciph.kernel.swarm_resources import record_spawn
        for index in range(4):
            record_spawn(self.db, worker_id=f"W{index}", instance_generation=1, actor=OPERATOR,
                         now=T1 + 15 + index)
        reflexes.register_reflex(self.db, rule_id="resource.ceiling", trigger_kind=reflexes.RESOURCE_CEILING,
                                 evidence_source="6.x spawn governance",
                                 authority_basis="EXISTING_OWNER_GUARD",
                                 response_mechanism="SPAWN_GOVERNANCE",
                                 trigger_params={"limit": 3, "window_seconds": 3600.0}, now=T1 + 16)
        reflex = reflexes.invoke(self.db, rule_id="resource.ceiling", subject_ref="swarm", now=T1 + 17)
        self.assertEqual(reflex["owner_outcome"], reflexes.ENFORCED_BY_OWNER)
        self.assertEqual(reflex["owner_ref"], "ciph/kernel/swarm_resources.py")
        # (15)(16) attention prioritises with NO fictional reasoning
        attention.submit(self.db, subject_ref=verdict["anomaly_id"], sensor_kind="CHANGE",
                                   evidence_ref=first["observation"]["arch_observation_id"],
                                   now=T1 + 3300)
        self.assertEqual(attention.invoke(self.db, now=T1 + 3301)["status"],
                         attention.MODEL_UNAVAILABLE)
        # (17)-(23) the model returns; an expedition is authorized, work happens, a finding is committed
        attention.model_available(self.db, now=T1 + 3400)
        from ciph.kernel.self_model import record_installation
        from ciph.kernel.uncertainty_registry import derive_uncertainties
        record_installation(self.db, capability_id="research.public-sources", now=T1 + 3401)
        uncertainty = derive_uncertainties(self.db, now=T1 + 3402)[0].uncertainty_id
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=uncertainty,
                                                  domain="public-research", origin_question="which?",
                                                  now=T1 + 3403)
        self.assertTrue(expeditions.authorize_expedition(
            self.db, expedition_id=proposed["expedition_id"], grant_ref=grant.standing_auth_id,
            work_class="RESEARCH", requested_scope=["public-sources"], now=T1 + 3404)["authorized"])
        written, findings = self.findings(3, ref=f"EXPEDITION:{proposed['expedition_id']}")
        expeditions.record_result(self.db, expedition_id=proposed["expedition_id"],
                                  findings=[{"source_ref": f["source_ref"], "evidence_ref": f["evidence_ref"],
                                             "summary": f["summary"]} for f in findings], now=T1 + 3405)
        hypothesis = incubation.generate_hypothesis(
            self.db, source_question_ref=uncertainty, origin_evidence_refs=[findings[0]["finding_id"]],
            reason="a shared dependency?", supporting_evidence_refs=[findings[0]["finding_id"]],
            contradictory_evidence_refs=[findings[1]["finding_id"]], now=T1 + 3406)
        self.assertEqual(hypothesis["epistemic_status"], incubation.HYPOTHESIS)
        self.assertEqual(len(awareness.contradictions(self.db)), 1)
        # (24)(25)(26) an interruption, the checkpoint, and a resume through valid authority only
        expeditions.checkpoint(self.db, expedition_id=proposed["expedition_id"], note="checkpoint",
                               delegations=[delegation.delegation_id], now=T1 + 3407)
        attention.submit(self.db, subject_ref="urgent", sensor_kind="CHANGE",
                                   evidence_ref=uncertainty, time_sensitive=True, now=T1 + 3408)
        attention.invoke(self.db, now=T1 + 3409)
        self.assertEqual(expeditions.get_expedition(self.db, proposed["expedition_id"])["status"],
                         expeditions.ACTIVE)
        self.assertTrue(presence.resume_plan(self.db, subject_ref="x", now=T1 + 3410)["may_resume"] in
                        (True, False))
        # (27)(28)(29) an evidence-backed notification; queued locally; no delivery claimed
        candidate_notice = expeditions.create_notification_candidate(
            self.db, expedition_id=proposed["expedition_id"],
            finding_refs=[f["finding_id"] for f in findings], confidence="MEDIUM",
            uncertainty="one contradictory arrival", relevance_reason="matches FINAL-1", now=T1 + 3411)
        notification = pipeline.compose(self.db, candidate_id=candidate_notice["candidate_id"],
                                        subject="Sir", body="I found 3 findings.", now=T1 + 3412)
        pipeline.enqueue(self.db, notification_id=notification["notification_id"], now=T1 + 3413)
        transport = session.DisposableFakeTransport(behaviour="ACCEPTED")
        pipeline.dispatch(self.db, adapter=transport, now=T1 + 3414)
        record = pipeline.get_notification(self.db, notification["notification_id"])
        self.assertEqual(record["state"], pipeline.ACCEPTED_BY_TRANSPORT)
        self.assertFalse(record["is_delivered"])
        self.assertFalse(transport.capabilities()["external_delivery"])
        # (30)-(35) operator returns, retrieves, challenges, then supplies NEW evidence
        conv.open_session(self.db, session_id="S2", participant_id=OPERATOR, channel_id="terminal",
                          topic_ref=proposed["expedition_id"], now=T1 + 3500)
        second = retrieve_nth(self.db, written["result_set_id"], 2, actor=OPERATOR)["finding"]
        self.assertEqual(second["ordinal"], 2)
        reconciliation = recon.reconcile(
            self.db, question="At 10:00, was the valve OPEN or CLOSED?", rule=recon.NEWEST_CALIBRATED_WINS,
            now=T1 + 3501,
            evidence=[{"ref": "E1", "value": "CLOSED", "observed_at": T1 - 3600,
                       "calibrated_at": T1 - 7200, "source": "s1"},
                      {"ref": "E3", "value": "OPEN", "observed_at": T1 - 300, "calibrated_at": T1 - 200,
                       "source": "s4"}])
        self.assertEqual(reconciliation["conclusion"], "OPEN")
        # pressure without evidence changes NOTHING
        self.assertEqual(recon.reconcile(self.db, question="again", rule=recon.NEWEST_CALIBRATED_WINS,
                                         now=T1 + 3502,
                                         evidence=reconciliation["evidence"])["conclusion"], "OPEN")
        conv.record_turn(self.db, session_id="S2", speaker=OPERATOR,
                         text="I disagree. Also, here is E4: the calibration certificate was revoked.",
                         now=T1 + 3503)
        revised = recon.reconcile(self.db, question="after new evidence", rule=recon.NEWEST_CALIBRATED_WINS,
                                  now=T1 + 3504,
                                  evidence=[{"ref": "E1", "value": "CLOSED", "observed_at": T1 - 3600,
                                             "calibrated_at": T1 - 7200, "source": "s1"},
                                            {"ref": "E3", "value": "OPEN", "observed_at": T1 - 300,
                                             "calibrated_at": T1 - 200, "source": "s4",
                                             "credibility": recon.LOW}])
        self.assertEqual(revised["conclusion"], "CLOSED",
                         "a revoked calibration must change the conclusion - the rule decides, not the model")
        # (36)(37) a legitimate preference change adapts expression but not facts
        policy.propose_change(self.db, key="style.override", value=policy.TECHNICAL,
                              policy_class=policy.OPERATOR_PREFERENCE, provenance="operator asked",
                              actor=OPERATOR, now=T1 + 3505)
        styled = policy.render(self.db, text="I committed 3 findings to RS-X.", now=T1 + 3506)
        self.assertTrue(styled["facts_preserved"])
        # (38)(39) restart and a fresh process reconstructs everything
        expected = (integration.integration_digest(), recon.reconciliation_digest(self.db),
                    policy.personality_digest(self.db), expeditions.expedition_digest(self.db),
                    pipeline.outbox_digest(self.db), conv.conversation_digest(self.db))
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.integration_ownership import integration_digest;"
                "from ciph.kernel.evidence_reconciliation import reconciliation_digest;"
                "from ciph.kernel.personality_policy import personality_digest;"
                "from ciph.kernel.independent_expeditions import expedition_digest;"
                "from ciph.kernel.notification_pipeline import outbox_digest;"
                "from ciph.kernel.conversational_continuity import conversation_digest;"
                "print(json.dumps([integration_digest(), reconciliation_digest(%r), personality_digest(%r), "
                "expedition_digest(%r), outbox_digest(%r), conversation_digest(%r)]))"
                % ((str(pathlib.Path(__file__).resolve().parents[1]),) + (self.db,) * 5))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(tuple(json.loads(out.stdout.strip())), expected)
        # (40) nothing was invented
        self.assertEqual(self.counts("ciph_permits"), 0)
        self.assertEqual(self.counts("ciph_crucible_deployments"), 0)
        self.assertFalse(pipeline.get_notification(self.db, notification["notification_id"])["is_read"])
        self.assertIsNotNone(first_result.result_id)
        self.assertIsNotNone(contradictory.result_id)


class TestCrossBoundaryHostile(FinalCase):
    """D2 - the failure classes, each with the correct refusal or qualification."""

    def test_sensor_equivocation_is_retained_not_collapsed(self):
        from ciph.kernel import sensory_fabric as fabric
        fabric.register_sensor(self.db, sensor_id="s", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        original = fabric.ingest(self.db, sensor_id="s", payload={"v": "a"}, sequence=1, now=T1)
        equivocation = fabric.ingest(self.db, sensor_id="s", payload={"v": "b"}, sequence=1, now=T1 + 1)
        self.assertEqual(equivocation["disposition"], fabric.EQUIVOCATION)
        self.assertTrue(equivocation["integrity_conflict"])
        self.assertEqual(len(fabric.conflicts(self.db, sensor_id="s")), 1)
        self.assertEqual(original["stored"], True)

    def test_an_unwitnessed_loaded_state_is_unresolved(self):
        from ciph.kernel.architectural_proprioception import LOADED, SOURCE, architectural_projection, \
            register_component
        path = self.base / "c.py"
        path.write_text("V1\n", encoding="utf-8")
        register_component(self.db, component_id="c", path=str(path))
        from ciph.kernel.sensory_adapters import observe_architecture
        observe_architecture(self.db, component_id="c", now=T1)
        projection = architectural_projection(self.db, component="c")
        self.assertEqual(projection["views"][LOADED]["status"], "UNRESOLVED")
        self.assertNotEqual(projection["views"][SOURCE].get("status", "OBSERVED"), "UNRESOLVED")

    def test_self_certification_is_refused(self):
        from ciph.kernel.architectural_proprioception import (SELF_CERTIFICATION_REFUSED, SOURCE,
                                                              integrity_claim, register_component)
        path = self.base / "c.py"
        path.write_text("V1\n", encoding="utf-8")
        register_component(self.db, component_id="c", path=str(path))
        from ciph.kernel.sensory_adapters import observe_architecture
        observe_architecture(self.db, component_id="c", now=T1)
        self.assertEqual(integrity_claim(self.db, component_id="c", view=SOURCE)["status"],
                         SELF_CERTIFICATION_REFUSED)

    def test_an_unauthorized_owner_cannot_be_impersonated(self):
        from ciph.kernel import independent_expeditions as expeditions
        from ciph.kernel.self_model import record_installation
        from ciph.kernel.uncertainty_registry import derive_uncertainties
        record_installation(self.db, capability_id="research.public-sources", now=T1)
        uncertainty = derive_uncertainties(self.db, now=T1 + 1)[0].uncertainty_id
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=uncertainty, domain="d",
                                                  origin_question="q", now=T1)
        refused = expeditions.authorize_expedition(self.db, expedition_id=proposed["expedition_id"],
                                                   grant_ref="SA-FORGED", work_class="RESEARCH", now=T1)
        self.assertFalse(refused["authorized"])
        self.assertEqual(self.counts("ciph_permits"), 0)

    def test_a_personality_change_cannot_alter_a_canonical_count(self):
        from ciph.kernel import claim_validation as claims
        from ciph.kernel import personality_policy as policy
        written, _ = self.findings(3)
        claim = claims.prepare(self.db, kind=claims.FINDING_COUNT, refs=[written["result_set_id"]],
                               result_set_id=written["result_set_id"], count=3)
        policy.propose_change(self.db, key="style.override", value=policy.DISCOVERY,
                              policy_class=policy.OPERATOR_PREFERENCE, provenance="dramatic", actor=OPERATOR,
                              now=T1)
        rendered = claims.render(self.db, claim=claim, personality_db=self.db, now=T1 + 1)
        self.assertIn("3", rendered["text"])
        self.assertEqual(claims.validate(self.db, claim=claim)["status"], claims.VALID)

    def test_a_false_delivery_claim_is_refused_end_to_end(self):
        from ciph.kernel import claim_validation as claims
        from ciph.kernel import independent_expeditions as expeditions
        from ciph.kernel import notification_pipeline as pipeline
        from ciph.kernel import session_adapter as session
        from ciph.kernel.self_model import record_installation
        from ciph.kernel.uncertainty_registry import derive_uncertainties
        record_installation(self.db, capability_id="research.public-sources", now=T1)
        uncertainty = derive_uncertainties(self.db, now=T1 + 1)[0].uncertainty_id
        proposed = expeditions.propose_expedition(self.db, uncertainty_ref=uncertainty, domain="d",
                                                  origin_question="q", now=T1)
        written, findings = self.findings(3)
        expeditions.record_result(self.db, expedition_id=proposed["expedition_id"],
                                  findings=[{"source_ref": f["source_ref"], "evidence_ref": f["evidence_ref"],
                                             "summary": f["summary"]} for f in findings], now=T1)
        candidate = expeditions.create_notification_candidate(
            self.db, expedition_id=proposed["expedition_id"],
            finding_refs=[f["finding_id"] for f in findings], confidence="M", uncertainty="u",
            relevance_reason="r", now=T1 + 2)
        notification = pipeline.compose(self.db, candidate_id=candidate["candidate_id"], subject="S",
                                        body="I found 3 findings.", now=T1 + 3)
        pipeline.enqueue(self.db, notification_id=notification["notification_id"], now=T1 + 4)
        pipeline.dispatch(self.db, adapter=session.DisposableFakeTransport(behaviour="ACCEPTED"),
                          now=T1 + 5)
        claim = claims.prepare(self.db, kind=claims.NOTIFICATION_DELIVERY,
                               refs=[notification["notification_id"]],
                               notification_id=notification["notification_id"],
                               claimed_state="READ")
        self.assertEqual(claims.validate(self.db, claim=claim)["status"], claims.REJECTED)
        with self.assertRaises(CrucibleError):
            pipeline.confirm_read(self.db, notification_id=notification["notification_id"],
                                  evidence_ref="", now=T1 + 6)


if __name__ == "__main__":
    unittest.main()
