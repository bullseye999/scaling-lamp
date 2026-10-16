"""
10.5 unified distributed awareness + 10.6 selective cognitive attention.

    Attention allocates inference, not authority.

The specimens compose the REAL owners: 10.3 sensors, 10.4 architectural views, 10.0 durable findings, 4.3
execution records, 6.x workers and delegations, and 7.x federation nodes. Every capability has a NEGATIVE
case showing where Ciph must refuse to infer success.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from ciph.kernel import operational_awareness as awareness
from ciph.kernel import selective_attention as attention
from ciph.kernel import sensory_adapters as adapters
from ciph.kernel import sensory_fabric as fabric
from ciph.kernel.architectural_proprioception import register_component
from ciph.kernel.attention_ownership import assert_ownership_clean
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.federation_node import register_node
from ciph.kernel.referential_continuity import announce, commit_result_set, retrieve_nth, retrieve_result_set
from ciph.kernel.swarm_delegation import claim_delegation, propose_delegation
from ciph.kernel.swarm_results import results_for, submit_result
from ciph.kernel.swarm_worker import attest_worker, register_worker

T1 = 1_800_000_000.0
COMPONENT = "ciph.example.module"


class AttentionCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-1056-")
        self.base = pathlib.Path(self.temp.name)
        self.db = str(self.base / "state.db")

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------ real owner setup
    def component_file(self, body="V1\n"):
        path = self.base / "component.py"
        path.write_text(body, encoding="utf-8")
        return path

    def ready_worker(self, worker_id, *, attest=True, capabilities=("coding",)):
        from ciph.kernel.swarm_worker import INSTALLED, VERIFIED, record_capability
        identity = register_worker(self.db, worker_id=worker_id, process_identity=worker_id,
                                   code_digest="CODE", environment_digest="ENV", now=T1)
        if attest:
            attest_worker(self.db, worker_id, identity.instance_generation, observed_code_digest="CODE",
                          observed_environment_digest="ENV", actor="operator:operator", now=T1)
        for capability in capabilities:
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=INSTALLED, actor=f"worker:{worker_id}", now=T1)
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=VERIFIED, actor="operator:operator", evidence_ref="CAP-1", now=T1)
        return identity

    def delegate(self, task, *, worker_id, output="OUT-1", second_output=None):
        identity = self.ready_worker(worker_id)
        delegation = propose_delegation(self.db, task_identity=task, input_digest=f"IN-{task}",
                                        basis_digest=f"BAS-{task}",
                                        allowed_work_class="GENERATE_CANDIDATE",
                                        required_capabilities=["coding"], now=T1)
        claim_delegation(self.db, delegation.delegation_id, worker_id=worker_id,
                         worker_generation=identity.instance_generation,
                         input_digest=delegation.input_digest, lease_seconds=120.0, now=T1)
        first = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id=worker_id,
                              worker_generation=identity.instance_generation, output_digest=output,
                              basis_digest=delegation.basis_digest, evidence_refs=["EV"],
                              source_dependency_refs=["SRC"], now=T1)
        second = None
        if second_output is not None:
            second = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id=worker_id,
                                   worker_generation=identity.instance_generation,
                                   output_digest=second_output, basis_digest=delegation.basis_digest,
                                   evidence_refs=["EV2"], source_dependency_refs=["SRC"], now=T1 + 1)
        return identity, delegation, first, second

    def investigation(self, count=3, *, ref="CP-1"):
        findings = []
        for index in range(1, count + 1):
            observation = record_observation(self.db, source_ref=f"src:{index}", raw_text=f"finding {index}",
                                             now=T1 + index)
            findings.append({"source_ref": f"src:{index}", "evidence_ref": observation["observation_id"],
                             "summary": f"finding {index}"})
        return commit_result_set(self.db, investigation_ref=ref, findings=findings, now=T1)

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

    def failed_deployment(self, role="capability:math.compute"):
        import sqlite3
        from ciph.kernel.evolution_deployment import init_schema as deployments_schema
        connection = sqlite3.connect(self.db)
        try:
            deployments_schema(connection)
            connection.execute(
                "INSERT OR IGNORE INTO ciph_crucible_deployments (deployment_id, promotion_id, role, "
                "candidate_id, artifact_digest, configuration_digest, installer_ref, authorization_ref, "
                "installed_artifact_digest, status, deployed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?);",
                ("CDP-FAILED-1", "CPR-X", role, "CAND-X", "H0", "C0", "fixture", "operator:operator", None,
                 "FAILED", T1))
            connection.commit()
        finally:
            connection.close()
        return "CDP-FAILED-1"

    def verified_integrity_evidence(self):
        """A REAL UNAUTHORIZED_MODIFICATION: the bytes changed under a REFUSED authorization record."""
        from ciph.kernel.architectural_proprioception import witness_change
        path = self.component_file("V1\n")
        register_component(self.db, component_id=COMPONENT, path=str(path))
        change = witness_change(self.db, component_id=COMPONENT, view="SOURCE", previous_digest="A",
                                current_digest="B", authorization_ref=self.failed_deployment(), now=T1)
        return change["change_id"]

    def observed_component(self, body="V1\n"):
        path = self.component_file(body)
        register_component(self.db, component_id=COMPONENT, path=str(path))
        first = adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        adapters.witness_runtime(self.db, component_id=COMPONENT, digest=first["observation"]["digest"],
                                 runtime_generation="G1", now=T1 + 1)
        return path, first


class TestDistributedAwareness(AttentionCase):

    def test_the_mandatory_integrated_scenario(self):
        # Five workers, two RELATED investigations.
        first = self.delegate("TASK-1", worker_id="W1", output="OUT-1")
        second = self.delegate("TASK-2", worker_id="W2", output="OUT-2")
        self.ready_worker("W3")
        self.ready_worker("W4")
        self.ready_worker("W5", attest=False)  # announced, never attested
        investigation_a = self.investigation(3, ref="CP-A")
        investigation_b = self.investigation(2, ref="CP-B")

        # A result relevant to ANOTHER investigation: correlate and preserve the relationship.
        link = awareness.correlate(self.db, kind=awareness.LINK_RESULT_INVESTIGATION,
                                   subject_ref=first[2].result_id,
                                   object_ref=investigation_b["result_set_id"],
                                   evidence_ref=first[2].result_id, now=T1 + 2)
        self.assertFalse(link["mints_authority"])
        self.assertEqual(len(awareness.links(self.db, kind=awareness.LINK_RESULT_INVESTIGATION)), 1)

        # One worker becomes unreachable: UNCERTAIN, and its last verified evidence is retained.
        state = awareness.subject_state(self.db, ref="worker:W5:1", owner_ref="worker:W5", now=T1 + 3)
        self.assertIn(state["state"], (awareness.UNKNOWN, awareness.STALE))
        self.assertFalse(state["is_a_verdict_about_the_subject"])
        retained = results_for(self.db, first[1].delegation_id)
        self.assertEqual([result.result_id for result in retained], [first[2].result_id])

        # Restart the coordinator: the same relationships reconstruct.
        before = awareness.awareness_digest(self.db)
        rebuilt = awareness.build_projection(self.db, now=T1 + 4)
        self.assertEqual(awareness.awareness_digest(self.db), before)
        correlated = [link for link in rebuilt["links"] if link["kind"] == awareness.LINK_RESULT_INVESTIGATION]
        self.assertEqual(correlated[0]["object_ref"], investigation_b["result_set_id"])
        self.assertEqual(len(rebuilt["tasks"]), 2)

        # No new delegation or execution permission was invented by any of this.
        self.assertEqual(self.counts("ciph_crucible_deployments"), 0)
        self.assertEqual(self.counts("ciph_self_executions"), 0)
        self.assertEqual(len(awareness.links(self.db)), 1)
        self.assertIsNotNone(investigation_a["result_set_id"])

    def test_a_worker_report_is_an_observation_until_its_evidence_is_established(self):
        _, delegation, result, _ = self.delegate("TASK-1", worker_id="W1")
        projection = awareness.build_projection(self.db)
        entry = [task for task in projection["tasks"] if task["delegation_id"] == delegation.delegation_id]
        self.assertEqual(len(entry), 1)
        produced = entry[0]["worker_results"][0]
        self.assertFalse(produced["is_evidence"])
        self.assertEqual(produced["output_digest"], result.output_digest)
        self.assertEqual(self.counts("ciph_evidence"), 0)

    def test_historical_heartbeats_cannot_keep_a_node_current(self):
        register_node(self.db, node_id="N1", public_key_ref="key:1", code_digest="CODE",
                      environment_digest="ENV", actor="operator:operator", now=T1)
        fabric.register_sensor(self.db, sensor_id="federation.state", capability="c",
                               canonical_owner="ciph/kernel/federation_node.py",
                               collection_method="EVENT_DRIVEN", now=T1)
        for tick in range(10):  # many historical heartbeats
            fabric.ingest(self.db, sensor_id="federation.state", payload={"node": "N1"},
                          evidence_ref="node:N1:1", observed_at=T1 + tick, now=T1 + tick)
        fresh = awareness.subject_state(self.db, ref="node:N1:1", now=T1 + 5)
        self.assertEqual(fresh["state"], awareness.CURRENT)
        # NEGATIVE: the heartbeats do NOT keep it current once the witness window passes.
        stale = awareness.subject_state(self.db, ref="node:N1:1", now=T1 + 100000)
        self.assertEqual(stale["state"], awareness.STALE)

    def test_a_correlation_that_does_not_resolve_is_refused(self):
        self.investigation(2, ref="CP-A")
        result_set = awareness.build_projection(self.db)["investigations"][0]["result_set_id"]
        with self.assertRaises(CrucibleError) as refused:
            awareness.correlate(self.db, kind=awareness.LINK_RESULT_INVESTIGATION,
                                subject_ref="RESULT-DOES-NOT-EXIST", object_ref=result_set)
        self.assertEqual(refused.exception.reason, "WORKER_RESULT_DOES_NOT_RESOLVE")
        self.assertEqual(awareness.links(self.db), [])

    def test_contradictory_workers_stay_unresolved(self):
        self.delegate("TASK-1", worker_id="W1", output="OUT-1", second_output="OUT-2")
        found = awareness.contradictions(self.db)
        disagreements = [item for item in found if item["kind"] == "WORKER_DISAGREEMENT"]
        self.assertEqual(len(disagreements), 1)
        self.assertEqual(disagreements[0]["disposition"], "UNRESOLVED")
        self.assertEqual(len(disagreements[0]["detail"]["output_digests"]), 2)
        # The owner already classified the second arrival; the projection reports that, not a preferred one.
        statuses = {item["result_status"] for item in disagreements[0]["detail"]["results"]}
        self.assertIn("CONFLICTING", statuses)


class TestAttentionClassification(AttentionCase):

    def test_a_sensor_label_alone_cannot_confer_critical(self):
        decision = attention.classify(self.db, subject_ref="noise", sensor_kind="ANOMALY",
                                      declared_severity="CRITICAL", now=T1)
        self.assertEqual(decision["category"], attention.FOCUSED)
        self.assertEqual(decision["reason"], attention.REASON_SELF_DECLARED)
        self.assertFalse(decision["mints_authority"])

    def test_a_verified_critical_requires_resolving_evidence(self):
        change_id = self.verified_integrity_evidence()
        critical = attention.classify(self.db, subject_ref="arch", sensor_kind="CHANGE",
                                      declared_severity="HIGH", evidence_ref=change_id, now=T1)
        self.assertEqual(critical["category"], attention.CRITICAL)
        self.assertEqual(critical["reason"], attention.REASON_ARCHITECTURAL_INTEGRITY)
        # An architectural change with NO correlated authorization record is a meaningful observation, but
        # it is NOT a verified integrity concern - absence of a record is not a finding of wrongdoing.
        path, _ = self.observed_component()
        path.write_text("V2\n", encoding="utf-8")
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1 + 2)
        unknown = awareness._rows(self.db, "SELECT change_id, provenance FROM ciph_arch_changes "
                                           "WHERE provenance = 'UNKNOWN_PROVENANCE';")[0]
        self.assertEqual(attention.classify(self.db, subject_ref="arch", sensor_kind="CHANGE",
                                            evidence_ref=unknown["change_id"],
                                            now=T1)["category"], attention.FOCUSED)
        # NEGATIVE: with an UNRESOLVED evidence reference the claim drops to FOCUSED.
        weak = attention.classify(self.db, subject_ref="arch", sensor_kind="CHANGE",
                                  declared_severity="CRITICAL", evidence_ref="NOPE", now=T1)
        self.assertEqual(weak["category"], attention.FOCUSED)
        self.assertEqual(weak["reason"], attention.REASON_UNRESOLVED_EVIDENCE)

    def test_routine_activity_stays_background(self):
        decision = attention.classify(self.db, subject_ref="heartbeat", sensor_kind="ROUTINE", now=T1)
        self.assertEqual(decision["category"], attention.BACKGROUND)
        self.assertEqual(decision["reason"], attention.REASON_ROUTINE)


class TestBoundedAttention(AttentionCase):

    def _verified_critical(self):
        return self.verified_integrity_evidence()

    def test_a_heartbeat_flood_never_invokes_the_model(self):
        for tick in range(200):
            attention.submit(self.db, subject_ref=f"beat-{tick}", sensor_kind="ROUTINE", now=T1 + tick)
        self.assertEqual(len(attention.requests(self.db, status=attention.PENDING)), 200)
        plan = attention.invoke(self.db, now=T1 + 500)
        self.assertEqual(plan["status"], attention.NOTHING_TO_DO)
        self.assertEqual(attention.invocations_this_window(self.db, now=T1 + 500), 0)

    def test_a_verified_finding_enters_focused_attention(self):
        committed = self.investigation(2, ref="CP-A")
        finding = retrieve_nth(self.db, committed["result_set_id"], 1,
                               actor="operator:operator")["finding"]
        queued = attention.submit(self.db, subject_ref="finding-1", sensor_kind="CHANGE",
                                  evidence_ref=finding["finding_id"], related_to_active_goal=True,
                                  now=T1)
        self.assertEqual(queued["category"], attention.CRITICAL)
        result = attention.invoke(self.db, now=T1 + 1)
        self.assertEqual(result["status"], attention.INVOKED)
        self.assertEqual(result["requests"], [queued["request_id"]])

    def test_the_reasoning_budget_is_bounded_and_exhaustion_is_explicit(self):
        budget = attention.AttentionBudget(max_invocations_per_window=2, window_seconds=3600.0)
        change = self._verified_critical()
        for index in range(4):
            attention.submit(self.db, subject_ref=f"s-{index}", sensor_kind="CHANGE",
                             evidence_ref=change, now=T1 + index)
        self.assertEqual(attention.invoke(self.db, budget=budget, now=T1 + 10)["status"], attention.INVOKED)
        self.assertEqual(attention.invoke(self.db, budget=budget, now=T1 + 11)["status"], attention.INVOKED)
        refused = attention.invoke(self.db, budget=budget, now=T1 + 12)
        self.assertEqual(refused["status"], attention.BUDGET_EXHAUSTED)
        self.assertFalse(refused["outcome_recorded"])
        # Nothing is lost: four were submitted, two were served, two remain pending for the next window.
        self.assertEqual(len(attention.requests(self.db)), 4)
        self.assertEqual(len(attention.requests(self.db, status=attention.PENDING)), 2)

    def test_duplicates_and_identical_content_are_not_collapsed_by_accident(self):
        change = self._verified_critical()
        first = attention.submit(self.db, subject_ref="same", sensor_kind="CHANGE", evidence_ref=change,
                                 dedup_key="KEY-1", now=T1)
        duplicate = attention.submit(self.db, subject_ref="same", sensor_kind="CHANGE", evidence_ref=change,
                                     dedup_key="KEY-1", now=T1 + 1)
        self.assertEqual(duplicate["status"], attention.DUPLICATE)
        self.assertFalse(duplicate["consumed_budget"])
        self.assertEqual(len(attention.requests(self.db, status=attention.PENDING)), 1)
        # NEGATIVE: two DISTINCT events with identical content (no shared dedup key) are both kept.
        distinct = attention.submit(self.db, subject_ref="same-content-elsewhere", sensor_kind="CHANGE",
                                    evidence_ref=change, now=T1 + 2)
        self.assertTrue(distinct["queued"])
        self.assertEqual(len(attention.requests(self.db, status=attention.PENDING)), 2)
        self.assertNotEqual(first["request_id"], distinct["request_id"])

    def test_batching_spends_one_budget_unit_for_several_focused_requests(self):
        budget = attention.AttentionBudget(max_batch=3)
        for index in range(3):
            attention.submit(self.db, subject_ref=f"f-{index}", sensor_kind="CHANGE",
                             evidence_ref="UNRESOLVED-BUT-PRESENT", now=T1 + index)
        result = attention.invoke(self.db, budget=budget, batch_size=3, now=T1 + 10)
        self.assertEqual(result["batch"], 3)
        self.assertEqual(attention.invocations_this_window(self.db, budget=budget, now=T1 + 10), 1)

    def test_high_priority_bursts_cannot_starve_everything_else(self):
        budget = attention.AttentionBudget(max_invocations_per_window=10, max_consecutive_critical=2)
        change = self._verified_critical()
        for index in range(6):
            attention.submit(self.db, subject_ref=f"crit-{index}", sensor_kind="CHANGE", evidence_ref=change,
                             operator_priority="HIGH", now=T1 + index)
        low = attention.submit(self.db, subject_ref="oldest-low", sensor_kind="CHANGE",
                               evidence_ref="UNRESOLVED", time_sensitive=True, now=T1 + 10)
        served = []
        for step in range(4):
            outcome = attention.invoke(self.db, budget=budget, now=T1 + 20 + step)
            served.extend(outcome.get("requests", []))
        self.assertIn(low["request_id"], served, "a burst of CRITICAL work starved the older request")
        self.assertTrue([row for row in attention.starved(self.db, budget=attention.AttentionBudget(
            starvation_ceiling=1.0), now=T1 + 30)])

    def test_queue_overflow_is_an_explicit_refusal(self):
        budget = attention.AttentionBudget(max_queue=3)
        for index in range(3):
            attention.submit(self.db, subject_ref=f"q-{index}", sensor_kind="ROUTINE", budget=budget,
                             now=T1 + index)
        overflow = attention.submit(self.db, subject_ref="q-3", sensor_kind="ROUTINE", budget=budget,
                                    now=T1 + 4)
        self.assertEqual(overflow["status"], attention.QUEUE_OVERFLOW)
        self.assertTrue(overflow["loss_indicated"])

    def test_expiry_cancels_obsolete_attention(self):
        attention.submit(self.db, subject_ref="old", sensor_kind="CHANGE", ttl_seconds=10.0, now=T1)
        expired = attention.expire(self.db, now=T1 + 100)
        self.assertEqual(len(expired), 1)
        self.assertEqual(attention.requests(self.db)[0]["status"], attention.EXPIRED)
        # an expired request is never scheduled
        self.assertEqual(attention.schedule(self.db, now=T1 + 101)["status"], attention.NOTHING_TO_DO)


class TestResourceAwarenessAndOutage(AttentionCase):

    def test_a_model_outage_preserves_the_queue_and_invents_nothing(self):
        committed = self.investigation(2, ref="CP-A")
        finding = retrieve_nth(self.db, committed["result_set_id"], 1, actor="operator:operator")["finding"]
        queued = attention.submit(self.db, subject_ref="finding-1", sensor_kind="CHANGE",
                                  evidence_ref=finding["finding_id"], now=T1)
        attention.model_unavailable(self.db, reason="provider outage", now=T1 + 1)
        refused = attention.invoke(self.db, now=T1 + 2)
        self.assertEqual(refused["status"], attention.MODEL_UNAVAILABLE)
        self.assertFalse(refused["outcome_recorded"])
        self.assertEqual([row["request_id"] for row in attention.requests(self.db, status=attention.PENDING)],
                         [queued["request_id"]])
        # NEGATIVE: when inference returns, the SAME pending request is served - nothing was fabricated.
        attention.model_available(self.db, now=T1 + 3)
        served = attention.invoke(self.db, now=T1 + 4)
        self.assertEqual(served["status"], attention.INVOKED)
        self.assertEqual(served["requests"], [queued["request_id"]])

    def test_attention_decisions_are_not_evidence(self):
        committed = self.investigation(2, ref="CP-A")
        before = self.counts("ciph_observations")
        finding = retrieve_nth(self.db, committed["result_set_id"], 1, actor="operator:operator")["finding"]
        attention.submit(self.db, subject_ref="finding-1", sensor_kind="CHANGE",
                         evidence_ref=finding["finding_id"], now=T1)
        attention.invoke(self.db, now=T1 + 1)
        self.assertEqual(self.counts("ciph_observations"), before)
        self.assertTrue(all(not row["is_evidence"] for row in attention.history(self.db)))

    def test_attention_cannot_mint_a_permit_or_grant_a_scope(self):
        change = self.verified_integrity_evidence()
        before = (self.counts("ciph_permits"), self.counts("ciph_crucible_deployments"),
                  self.counts("ciph_self_executions"))
        attention.submit(self.db, subject_ref="critical-thing", sensor_kind="CHANGE", evidence_ref=change,
                         operator_priority="HIGH", now=T1)
        attention.invoke(self.db, now=T1 + 1)
        after = (self.counts("ciph_permits"), self.counts("ciph_crucible_deployments"),
                 self.counts("ciph_self_executions"))
        self.assertEqual(after, before, "attention changed an authority store it does not own")


class TestFocusContinuity(AttentionCase):
    """Part E - a change of focus must never destroy the previous investigation's context."""

    def test_focus_switches_preserve_original_references(self):
        committed = self.investigation(7, ref="CP-7")
        seventh = retrieve_nth(self.db, committed["result_set_id"], 7, actor="operator:operator")["finding"]

        # 1. Ciph investigates finding #7.
        investigating = attention.submit(self.db, subject_ref=f"finding:{seventh['finding_id']}",
                                         sensor_kind="CHANGE", evidence_ref=seventh["finding_id"],
                                         related_to_active_goal=True, now=T1)
        first = attention.invoke(self.db, now=T1 + 1)
        focus = attention.checkpoint(self.db, focus_id=first["focus_ids"][0],
                                     context_ref=committed["result_set_id"],
                                     pending_questions=["is the seventh corroborated?",
                                                        "which source supports it?"], now=T1 + 2)

        # 2. A federation anomaly interrupts attention.
        from ciph.kernel.federation_node import register_node
        register_node(self.db, node_id="N9", public_key_ref="key:9", code_digest="CODE",
                      environment_digest="ENV", actor="operator:operator", now=T1)
        anomaly = attention.submit(self.db, subject_ref="federation:N9", sensor_kind="CHANGE",
                                   declared_severity="CRITICAL", related_to_active_goal=True, now=T1 + 3)
        second = attention.invoke(self.db, now=T1 + 4)
        self.assertEqual(second["status"], attention.INVOKED)

        # 3/4/5. Return to finding #7: the exact references survive the switch.
        restored = attention.restore(self.db, first["focus_ids"][0])
        self.assertEqual(restored["context_ref"], committed["result_set_id"])
        self.assertEqual(restored["pending_questions"], ["is the seventh corroborated?",
                                                         "which source supports it?"])
        self.assertEqual(restored["checkpoint_digest"], focus["checkpoint_digest"])
        self.assertEqual(retrieve_nth(self.db, committed["result_set_id"], 7,
                                      actor="operator:operator")["finding"]["finding_id"],
                         seventh["finding_id"])
        self.assertTrue(investigating["queued"] or anomaly["queued"])

        # 6. A fresh process reconstructs both transitions and their references.
        expected = attention.attention_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.selective_attention import attention_digest, history;"
                "print(json.dumps({'digest': attention_digest(%r), "
                "'kinds': [row['kind'] for row in history(%r)]}, sort_keys=True))"
                % (str(pathlib.Path(__file__).resolve().parents[1]), self.db, self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        rebuilt = json.loads(out.stdout.strip())
        self.assertEqual(rebuilt["digest"], expected)
        self.assertIn("REQUEST_INVOKED", rebuilt["kinds"])

    def test_a_suspended_focus_is_not_destroyed_by_the_focus_bound(self):
        budget = attention.AttentionBudget(max_active_focus=1)
        committed = self.investigation(3, ref="CP-A")
        finding = retrieve_nth(self.db, committed["result_set_id"], 1, actor="operator:operator")["finding"]
        attention.submit(self.db, subject_ref="first", sensor_kind="CHANGE",
                         evidence_ref=finding["finding_id"], now=T1)
        opened = attention.invoke(self.db, budget=budget, now=T1 + 1)
        attention.checkpoint(self.db, focus_id=opened["focus_ids"][0], context_ref=committed["result_set_id"],
                             pending_questions=["still open"], now=T1 + 2)
        attention.submit(self.db, subject_ref="second", sensor_kind="CHANGE", evidence_ref="UNRESOLVED",
                         time_sensitive=True, now=T1 + 3)
        attention.invoke(self.db, budget=budget, now=T1 + 4)
        suspended = attention.focus_contexts(self.db, status=attention.FOCUS_SUSPENDED)
        self.assertEqual(len(suspended), 1)
        self.assertEqual(suspended[0]["context_ref"], committed["result_set_id"])
        self.assertEqual(suspended[0]["pending_questions"], ["still open"])


class TestRemainingAdversarial(AttentionCase):

    def test_a_stale_result_cannot_be_advertised_as_fresh(self):
        committed = self.investigation(2, ref="CP-A")
        finding = retrieve_nth(self.db, committed["result_set_id"], 1, actor="operator:operator")["finding"]
        fabric.register_sensor(self.db, sensor_id="investigation.activity", capability="c",
                               canonical_owner="ciph/kernel/referential_continuity.py",
                               collection_method="EVENT_DRIVEN", now=T1)
        fabric.ingest(self.db, sensor_id="investigation.activity", payload={"result_set_id":
                      committed["result_set_id"]}, evidence_ref=committed["result_set_id"],
                      observed_at=T1, now=T1)
        self.assertEqual(awareness.subject_state(self.db, ref=committed["result_set_id"],
                                                 now=T1 + 5)["state"], awareness.CURRENT)
        stale = awareness.subject_state(self.db, ref=committed["result_set_id"], now=T1 + 100000)
        self.assertEqual(stale["state"], awareness.STALE)
        # NEGATIVE: attention history carries no claim that anything completed.
        attention.submit(self.db, subject_ref=f"finding:{finding['finding_id']}", sensor_kind="CHANGE",
                         evidence_ref=finding["finding_id"], now=T1)
        attention.invoke(self.db, now=T1 + 1)
        self.assertTrue(all(not row["is_evidence"] for row in attention.history(self.db)))
        self.assertFalse(any("COMPLETE" in json.dumps(row) for row in attention.history(self.db)))

    def test_unsupported_event_claims_do_not_become_verified_self_model_facts(self):
        from ciph.kernel.self_model import project_capability
        fabric.register_sensor(self.db, sensor_id="execution.history", capability="c",
                               canonical_owner="ciph/kernel/self_model.py",
                               collection_method="EVENT_DRIVEN", now=T1)
        fabric.ingest(self.db, sensor_id="execution.history",
                      payload={"capability": "darknet.scan", "succeeded": True, "receipt_ref": "FAKE"},
                      kind=fabric.ANOMALY, evidence_ref="FAKE-RECEIPT", now=T1)
        awareness.correlate(self.db, kind=awareness.LINK_FINDING_EVIDENCE, subject_ref="FAKE-RECEIPT",
                            object_ref="FAKE-RECEIPT", now=T1)
        self.assertEqual(self.counts("ciph_self_executions"), 0)
        claim = project_capability(self.db, capability_id="darknet.scan").as_dict()
        self.assertEqual(claim["claim_level"], "UNKNOWN")
        self.assertFalse(claim["empirically_verified"])

    def test_generations_stay_distinct_across_recovery(self):
        from ciph.kernel.swarm_worker import is_current_generation
        first = self.ready_worker("W1")
        second = register_worker(self.db, worker_id="W1", process_identity="W1-r2",
                                 code_digest="CODE2", environment_digest="ENV2", now=T1 + 10)
        self.assertNotEqual(first.instance_generation, second.instance_generation)
        self.assertFalse(is_current_generation(self.db, "W1", first.instance_generation))
        self.assertTrue(is_current_generation(self.db, "W1", second.instance_generation))
        rows = awareness._rows(self.db, "SELECT worker_id, instance_generation FROM ciph_swarm_workers "
                                        "WHERE worker_id = 'W1' ORDER BY instance_generation;")
        self.assertEqual([row["instance_generation"] for row in rows], [1, 2])
        projection = awareness.build_projection(self.db)
        self.assertEqual([entry["generation"] for entry in projection["worker_generations"]],
                         [second.instance_generation])

    def test_resource_use_is_bounded_under_hostile_event_load(self):
        budget = attention.AttentionBudget(max_queue=50, max_invocations_per_window=2)
        overflow = 0
        for tick in range(300):
            outcome = attention.submit(self.db, subject_ref=f"flood-{tick}", sensor_kind="ROUTINE",
                                       budget=budget, now=T1 + tick)
            if outcome["status"] == attention.QUEUE_OVERFLOW:
                overflow += 1
        self.assertGreater(overflow, 0)
        self.assertEqual(attention.invocations_this_window(self.db, budget=budget, now=T1 + 300), 0)
        # NEGATIVE: the flood neither invoked the model nor produced an attention outcome.
        self.assertEqual(attention.invoke(self.db, budget=budget, now=T1 + 301)["status"],
                         attention.NOTHING_TO_DO)
        self.assertTrue(any(row["kind"] == "QUEUE_OVERFLOW" for row in attention.history(self.db)))


class TestFoundingAttentionTorture(AttentionCase):
    """Part G - one integrated disposable scenario composed of 10.3, 10.4, 10.0, 6.x and 7.x."""

    def test_the_founding_attention_torture(self):
        # (1) The main LLM is inactive.
        attention.model_unavailable(self.db, reason="main model offline", now=T1)
        # (2) Sensors continue collecting operational events while it is down.
        path, baseline = self.observed_component()
        adapters.observe_swarm(self.db, now=T1 + 1)
        # (3) Several workers perform authorized tasks.
        _, delegation_a, result_a, _ = self.delegate("TASK-A", worker_id="W1", output="OUT-A")
        self.delegate("TASK-B", worker_id="W2", output="OUT-B")
        self.ready_worker("W3", attest=False)
        # (4) One worker produces a meaningful finding; (5) another produces contradictory evidence.
        _, _, conflict_first, conflict_second = self.delegate("TASK-C", worker_id="W4", output="OUT-1",
                                                              second_output="OUT-2")
        # (6) A federation node becomes unreachable.
        from ciph.kernel.federation_node import register_node
        register_node(self.db, node_id="N-ISO", public_key_ref="key:9", code_digest="CODE",
                      environment_digest="ENV", actor="operator:operator", now=T1)
        # (7) An architectural anomaly is detected on disk.
        path.write_text("V2 -- changed while reasoning was unavailable\n", encoding="utf-8")
        anomaly = adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1 + 2)
        self.assertEqual(anomaly["kind"], fabric.CHANGE)
        committed = self.investigation(7, ref="CP-7")
        seventh = retrieve_nth(self.db, committed["result_set_id"], 7, actor="operator:operator")["finding"]

        # (8) The attention mechanism recognises the relevant priorities.
        routine = attention.submit(self.db, subject_ref="heartbeat", sensor_kind="ROUTINE", now=T1 + 3)
        verified = attention.submit(self.db, subject_ref=f"finding:{seventh['finding_id']}",
                                    sensor_kind="CHANGE", evidence_ref=seventh["finding_id"],
                                    related_to_active_goal=True, now=T1 + 4)
        self.assertEqual(routine["category"], attention.BACKGROUND)
        self.assertEqual(verified["category"], attention.CRITICAL)
        # (9) Routine events remain in the background.
        routine_plan = attention.schedule(self.db, now=T1 + 5)
        self.assertNotIn(routine["request_id"], routine_plan["selected"])
        # (10) Urgent work receives focus. With the model INACTIVE, focus means SELECTION: the scheduler
        # preempts routine work for the urgent request, and no reasoning outcome is invented.
        unavailable = attention.invoke(self.db, now=T1 + 6)
        self.assertEqual(unavailable["status"], attention.MODEL_UNAVAILABLE)
        self.assertFalse(unavailable["outcome_recorded"])
        planned = attention.schedule(self.db, now=T1 + 7)
        self.assertEqual(planned["selected"], [verified["request_id"]])

        # (11) The LLM becomes available and receives SELECTED evidence context.
        attention.model_available(self.db, now=T1 + 8)
        first = attention.invoke(self.db, now=T1 + 9)
        self.assertEqual(first["status"], attention.INVOKED)
        self.assertEqual(first["requests"], [verified["request_id"]])
        interrupted = attention.checkpoint(self.db, focus_id=first["focus_ids"][0],
                                           context_ref=committed["result_set_id"],
                                           pending_questions=["is the seventh corroborated?"], now=T1 + 10)

        # (12) Previously focused investigation context remains intact across the use of it.
        restored = attention.restore(self.db, first["focus_ids"][0])
        self.assertEqual(restored["context_ref"], committed["result_set_id"])
        self.assertEqual(restored["pending_questions"], ["is the seventh corroborated?"])
        projection = awareness.build_projection(self.db, now=T1 + 11)
        self.assertTrue(projection["read_only"])
        # (13) Ciph explains what happened from real records, inventing nothing.
        self.assertEqual([link["link_id"] for link in project_links(projection)], [])
        self.assertEqual(len([t for t in projection["tasks"]]), 3)
        unreachable = awareness.subject_state(self.db, ref="worker:W3:1", owner_ref="worker:W3",
                                              now=T1 + 11)
        self.assertIn(unreachable["state"], (awareness.UNKNOWN, awareness.STALE))
        self.assertFalse(unreachable["is_a_verdict_about_the_subject"])
        self.assertEqual(attention.invocations_this_window(self.db, now=T1 + 12), 1)
        # (14) It returns to the interrupted investigation.
        self.assertEqual(attention.restore(self.db, first["focus_ids"][0])["context_ref"],
                         committed["result_set_id"])
        self.assertEqual(retrieve_result_set(self.db, committed["result_set_id"],
                                             actor="operator:operator")["count"], 7)
        # (15) A fresh process reconstructs the attention history.
        expected = attention.attention_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.selective_attention import attention_digest;"
                "print(json.dumps(attention_digest(%r)))"
                % (str(pathlib.Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)
        # (16) No new authority was created anywhere in the process.
        self.assertEqual(self.counts("ciph_permits"), 0)
        self.assertEqual(self.counts("ciph_self_executions"), 0)
        self.assertEqual(self.counts("ciph_crucible_deployments"), 0)
        self.assertEqual(awareness.links(self.db), [])
        self.assertIsNotNone(conflict_first.result_id)
        self.assertIsNotNone(result_a.result_id)
        self.assertEqual(len([item for item in awareness.contradictions(self.db)
                              if item["kind"] == "WORKER_DISAGREEMENT"]), 1)
        self.assertIsNotNone(interrupted["checkpoint_digest"])
        self.assertIsNotNone(conflict_second)


def project_links(projection):
    return [link for link in projection.get("links", [])
            if link["kind"] == awareness.LINK_RESULT_INVESTIGATION]


class TestOwnership(unittest.TestCase):

    def test_the_census_is_clean_and_names_the_owners(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 7)
        for key in ("rival_operational_or_attention_owners", "owned_modules_write_canonical",
                    "forbidden_attention_patterns", "permits_minted_outside_the_owner",
                    "attention_is_not_evidence", "retained_machinery_missing"):
            self.assertEqual(report[key], [], key)

    def test_each_zero_fires_on_its_own_synthetic_violation(self):
        from ciph.kernel import attention_ownership as census
        real = dict(census.production_sources())
        rogue = "ciph/kernel/rogue_attention.py"
        cases = [
            (census.rival_operational_or_attention_owners,
             "def steal(c):\n    c.execute('INSERT INTO ciph_attention_requests VALUES (1);')\n"),
            (census.owned_modules_write_canonical,
             "def go(c):\n    c.execute('INSERT INTO ciph_result_sets VALUES (1);')\n"),
            (census.forbidden_attention_patterns,
             "def go(s):\n    return attention_grants_authority(s)\n"),
            (census.permits_minted_outside_the_owner, "PERMIT = SignedExecutionPermit(fields={})\n"),
            (census.attention_is_not_evidence,
             "def go(db):\n    return record_observation(db, raw_text='a decision')\n"),
        ]
        for predicate, body in cases:
            with self.subTest(predicate=predicate.__name__):
                if predicate in (census.owned_modules_write_canonical, census.attention_is_not_evidence):
                    sources = {**real, census.ATTENTION_OWNER: body}
                else:
                    sources = {**real, rogue: body}
                self.assertTrue(predicate(sources=list(sources.items())),
                                f"{predicate.__name__} did not fire")


if __name__ == "__main__":
    unittest.main()
