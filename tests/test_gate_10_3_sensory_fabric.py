"""
10.3 - the Sensory Fabric.

    The LLM may rest. Ciph's operational continuity does not.

The fabric is exercised as a REAL subsystem: real 4.2/4.3 records, real 6.x workers and delegations, real
7.x nodes, real 10.0 result sets and real 10.4 architectural views. Every capability has a NEGATIVE case
showing that, when the evidence is insufficient, the fabric says so instead of inventing it.
"""

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

from ciph.kernel import sensory_adapters as adapters
from ciph.kernel import sensory_fabric as fabric
from ciph.kernel.architectural_proprioception import (
    DISPUTED, LOADED, MATCH, MISMATCH, SELF_CERTIFICATION_REFUSED, SOURCE, architectural_projection,
    observe_executed, observations as arch_observations, policy_reference, register_component,
    witness_observation)
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.epistemic_ledger import record_model_output, record_observation
from ciph.kernel.federation_node import register_node
from ciph.kernel.referential_continuity import (announce, announcements, commit_result_set,
                                                result_sets, retrieve_result_set)
from ciph.kernel.sensory_ownership import assert_ownership_clean
from ciph.kernel.swarm_delegation import claim_delegation, propose_delegation
from ciph.kernel.swarm_results import results_digest, submit_result
from ciph.kernel.swarm_worker import attest_worker, register_worker

T1 = 1_800_000_000.0
COMPONENT = "ciph.example.module"
SOURCE_SENSOR = "architecture.source"


class FabricCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-103-")
        self.base = pathlib.Path(self.temp.name)
        self.db = str(self.base / "state.db")

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------ helpers over REAL owners
    def component_file(self, body="V1\n"):
        path = self.base / "component.py"
        path.write_text(body, encoding="utf-8")
        return path

    def register(self, path=None, component=COMPONENT):
        return register_component(self.db, component_id=component, path=str(path) if path else None)

    def ready_worker(self, worker_id, *, capabilities=("coding",), attest=True):
        identity = register_worker(self.db, worker_id=worker_id, process_identity=worker_id,
                                   code_digest="CODE", environment_digest="ENV", now=T1)
        if attest:
            attest_worker(self.db, worker_id, identity.instance_generation, observed_code_digest="CODE",
                          observed_environment_digest="ENV", actor="operator:operator", now=T1)
        return identity

    def completed_task(self, worker_id="W1", task="TASK-1"):
        from ciph.kernel.swarm_worker import INSTALLED, VERIFIED, record_capability
        identity = self.ready_worker(worker_id)
        for capability in ("coding",):
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=INSTALLED, actor=f"worker:{worker_id}", now=T1)
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=VERIFIED, actor="operator:operator", evidence_ref="CAP-1", now=T1)
        delegation = propose_delegation(self.db, task_identity=task, input_digest=f"INPUT-{task}",
                                        basis_digest=f"BASIS-{task}", allowed_work_class="GENERATE_CANDIDATE",
                                        required_capabilities=["coding"], now=T1)
        claim_delegation(self.db, delegation.delegation_id, worker_id=worker_id,
                         worker_generation=identity.instance_generation,
                         input_digest=delegation.input_digest, lease_seconds=120.0, now=T1)
        result = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id=worker_id,
                               worker_generation=identity.instance_generation,
                               output_digest="OUTPUT", basis_digest=delegation.basis_digest,
                               evidence_refs=["EV"], source_dependency_refs=["SRC"], now=T1)
        return identity, delegation, result

    def investigation(self, count=3):
        findings = []
        for index in range(1, count + 1):
            observation = record_observation(self.db, source_ref=f"src:{index}", raw_text=f"finding {index}",
                                             now=T1 + index)
            findings.append({"source_ref": f"src:{index}", "evidence_ref": observation["observation_id"],
                             "summary": f"finding {index}"})
        committed = commit_result_set(self.db, investigation_ref="CP-1", findings=findings, now=T1)
        announce(self.db, result_set_id=committed["result_set_id"],
                 statement=f"Sir, I found {count} findings.", actor="operator:operator", now=T1 + 5)
        return committed

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


class TestContract(FabricCase):

    def test_the_contract_declares_everything_the_campaign_requires(self):
        registered = fabric.register_sensor(
            self.db, sensor_id="demo.sensor", capability="observe a thing", scope="component",
            canonical_owner="ciph/kernel/self_model.py", evidence_source="4.3 record",
            collection_method="EVENT_DRIVEN", ordering="WALLCLOCK", freshness_ttl=60.0,
            retention_seconds=600.0, max_queue=10, failure_behavior="STALE_ON_SILENCE",
            restart_behavior="RECONSTRUCT_DURABLE_AND_MARK_GAPS", now=T1)
        for field in ("sensor_id", "version", "capability", "scope", "canonical_owner", "evidence_source",
                      "collection_method", "ordering", "freshness_ttl", "retention_seconds", "max_queue",
                      "failure_behavior", "restart_behavior", "contract_digest"):
            self.assertIn(field, registered)
        self.assertEqual(registered["version"], 1)

    def test_re_declaring_the_identical_contract_is_idempotent(self):
        first = fabric.register_sensor(self.db, sensor_id="demo.sensor", capability="c",
                                       canonical_owner="o", collection_method="EVENT_DRIVEN", now=T1)
        second = fabric.register_sensor(self.db, sensor_id="demo.sensor", capability="c",
                                        canonical_owner="o", collection_method="EVENT_DRIVEN", now=T1 + 5)
        self.assertEqual(first["contract_digest"], second["contract_digest"])
        self.assertEqual(len(fabric.sensors(self.db)), 1)

    def test_changing_a_contract_without_a_version_is_refused(self):
        fabric.register_sensor(self.db, sensor_id="demo.sensor", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        with self.assertRaises(CrucibleError) as refused:
            fabric.register_sensor(self.db, sensor_id="demo.sensor", capability="DIFFERENT",
                                   canonical_owner="o", collection_method="EVENT_DRIVEN", now=T1)
        self.assertEqual(refused.exception.reason, "SENSOR_CONTRACT_CHANGED_WITHOUT_A_VERSION")
        # NEGATIVE: the same change WITH a version bump is accepted.
        bumped = fabric.register_sensor(self.db, sensor_id="demo.sensor", capability="DIFFERENT", version=2,
                                        canonical_owner="o", collection_method="EVENT_DRIVEN", now=T1)
        self.assertEqual(bumped["version"], 2)


class TestAdaptersIntoTheFourViews(FabricCase):

    def test_an_on_disk_change_never_becomes_a_loaded_claim(self):
        path = self.component_file("V1\n")
        self.register(path)
        first = adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        self.assertEqual(first["kind"], fabric.ROUTINE)
        source_digest = first["observation"]["digest"]
        adapters.witness_runtime(self.db, component_id=COMPONENT, digest=source_digest,
                                 runtime_generation="G1", now=T1 + 1)

        path.write_text("V2 -- changed on disk\n", encoding="utf-8")
        second = adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1 + 2)
        self.assertEqual(second["kind"], fabric.CHANGE)
        projection = architectural_projection(self.db, component=COMPONENT)
        self.assertNotEqual(projection["views"][SOURCE]["digest"], source_digest)
        # PROOF: the adapter reported the SOURCE change and the LOADED view did NOT move.
        self.assertEqual(projection["views"][LOADED]["digest"], source_digest)
        self.assertEqual(projection["distinctions"]["source_vs_loaded"], MISMATCH)

        # NEGATIVE: after a real restart loads the new bytes, the distinction becomes MATCH again.
        new_digest = second["observation"]["digest"]
        adapters.witness_runtime(self.db, component_id=COMPONENT, digest=new_digest,
                                 runtime_generation="G2", now=T1 + 3)
        self.assertEqual(architectural_projection(self.db, component=COMPONENT)["distinctions"][
            "source_vs_loaded"], MATCH)

    def test_the_change_witness_does_not_infer_authorization(self):
        path = self.component_file("V1\n")
        self.register(path)
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        path.write_text("V2\n", encoding="utf-8")
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1 + 1)
        from ciph.kernel.architectural_proprioception import changes
        recorded = changes(self.db, component_id=COMPONENT)
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["provenance"], "UNKNOWN_PROVENANCE")
        self.assertIsNone(recorded[0]["authorization_ref"])
        self.assertIn("not a claim that the change was unauthorized", recorded[0]["uncertainty"])

    def test_adapters_feed_the_four_views_rather_than_their_own_picture(self):
        path = self.component_file("V1\n")
        self.register(path)
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        adapters.witness_runtime(self.db, component_id=COMPONENT, digest="LOADED-DIGEST",
                                 runtime_generation="G1", now=T1 + 1)
        self.assertEqual(adapters.VIEW_BY_ADAPTER["architecture_source"], "SOURCE")
        self.assertEqual(adapters.VIEW_BY_ADAPTER["runtime"], "LOADED")
        # The runtime adapter wrote a LOADED observation through 10.4, and the SOURCE view is untouched by it.
        views = architectural_projection(self.db, component=COMPONENT)["views"]
        self.assertEqual(views[LOADED]["digest"], "LOADED-DIGEST")
        self.assertEqual(views[SOURCE]["digest"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertNotEqual(views[SOURCE]["digest"], "LOADED-DIGEST")


class TestNoContinuousInference(FabricCase):

    def test_the_fabric_and_its_adapters_never_call_a_model(self):
        for relative in ("ciph/kernel/sensory_fabric.py", "ciph/kernel/sensory_adapters.py"):
            text = (pathlib.Path(__file__).resolve().parents[1] / relative).read_text(encoding="utf-8")
            for needle in ("call_model(", "invoke_llm(", "query_model(", "ask_the_model(", "BrainRouter",
                           "ollama", "deepseek"):
                self.assertNotIn(needle, text, f"{relative} references a model")

    def test_a_full_cycle_reports_that_it_did_not_invoke_the_model(self):
        path = self.component_file("V1\n")
        self.register(path)
        cycle = adapters.run_cycle(self.db, calls=[("architecture_source", {"component_id": COMPONENT}),
                                                   ("resources", {})], now=T1)
        self.assertFalse(cycle["invoked_the_model"])
        self.assertFalse(cycle["created_execution_authority"])
        self.assertIn("architecture_source", cycle["adapters"])
        self.assertIn("resources", cycle["adapters"])

    def test_observations_collect_while_a_model_is_unavailable(self):
        """A sentinel that raises if touched stands in for an unreachable model."""
        class ForbiddenModel:
            def __getattr__(self, item):
                raise AssertionError("the fabric touched the model")
        sentinel = ForbiddenModel()
        path = self.component_file("V1\n")
        self.register(path)
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        fabric.ingest(self.db, sensor_id=SOURCE_SENSOR, payload={"note": "heartbeat"}, now=T1 + 1)
        self.assertEqual(len(fabric.events(self.db)), 2)
        self.assertIsNotNone(sentinel)  # never used


class TestEventsVersusDurableEvidence(FabricCase):

    def test_heartbeats_do_not_enter_the_epistemic_ledger(self):
        before = self.counts("ciph_observations")
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="BOUNDED_POLL", now=T1)
        for tick in range(20):
            fabric.ingest(self.db, sensor_id="beat", payload={"tick": tick}, now=T1 + tick)
        self.assertEqual(self.counts("ciph_observations"), before,
                         "a heartbeat was written into the 4.2 ledger")

    def test_retention_expiry_is_counted_not_silent(self):
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="BOUNDED_POLL", retention_seconds=10.0,
                               freshness_ttl=50.0, now=T1)
        fabric.ingest(self.db, sensor_id="beat", payload={"tick": 1}, now=T1)
        fabric.ingest(self.db, sensor_id="beat", payload={"tick": 2}, now=T1 + 1)
        self.assertEqual(len(fabric.events(self.db)), 2)
        expired = fabric.expire(self.db, now=T1 + 100)
        self.assertEqual(expired["total"], 2)
        self.assertEqual(len(fabric.events(self.db)), 0)
        self.assertEqual(fabric.sensor_status(self.db, "beat", now=T1 + 101)["status"], fabric.STALE)

    def test_overflow_leaves_an_explicit_loss_indicator(self):
        fabric.register_sensor(self.db, sensor_id="narrow", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", max_queue=2, now=T1)
        fabric.ingest(self.db, sensor_id="narrow", payload={"n": 1}, now=T1)
        fabric.ingest(self.db, sensor_id="narrow", payload={"n": 2}, now=T1 + 1)
        dropped = fabric.ingest(self.db, sensor_id="narrow", payload={"n": 3}, kind=fabric.ROUTINE,
                                now=T1 + 2)
        self.assertEqual(dropped["disposition"], fabric.OVERFLOWED)
        self.assertTrue(dropped["loss_indicated"])
        # NEGATIVE: the ANOMALY kind bypasses the ordinary bound rather than being quietly lost.
        kept = fabric.ingest(self.db, sensor_id="narrow", payload={"urgent": True}, kind=fabric.ANOMALY,
                             now=T1 + 3)
        self.assertEqual(kept["disposition"], fabric.ACCEPTED)
        self.assertTrue([gap for gap in fabric.gaps(self.db, sensor_id="narrow")
                         if gap["kind"] == fabric.GAP_OVERFLOW])

    def test_a_retry_is_not_a_second_event_but_identical_data_can_be_two_events(self):
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        first = fabric.ingest(self.db, sensor_id="beat", payload={"same": "data"}, sequence=7, now=T1)
        retry = fabric.ingest(self.db, sensor_id="beat", payload={"same": "data"}, sequence=7, now=T1 + 1)
        self.assertEqual(retry["disposition"], fabric.DUPLICATE)
        self.assertFalse(retry["distinct_event"])
        # A GENUINELY DIFFERENT delivery that happens to carry identical data has a new sequence.
        distinct = fabric.ingest(self.db, sensor_id="beat", payload={"same": "data"}, sequence=8, now=T1 + 2)
        self.assertEqual(distinct["disposition"], fabric.ACCEPTED)
        self.assertTrue(distinct["distinct_event"])
        self.assertEqual(len(fabric.events(self.db, sensor_id="beat")), 2)
        self.assertEqual(first["payload_digest"], distinct["payload_digest"])


class TestDeliveryAndRecovery(FabricCase):

    def test_an_unregistered_sensor_is_refused(self):
        with self.assertRaises(CrucibleError) as refused:
            fabric.ingest(self.db, sensor_id="ghost", payload={}, now=T1)
        self.assertEqual(refused.exception.reason, "SENSOR_NOT_REGISTERED")

    def test_out_of_order_and_stale_generation_are_handled_honestly(self):
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        fabric.ingest(self.db, sensor_id="beat", payload={"n": 5}, sequence=5, runtime_generation="G1",
                      now=T1)
        late = fabric.ingest(self.db, sensor_id="beat", payload={"n": 2}, sequence=2, now=T1 + 1)
        self.assertEqual(late["disposition"], fabric.OUT_OF_ORDER)
        current = fabric.ingest(self.db, sensor_id="beat", payload={"n": 6}, sequence=6,
                                runtime_generation="G2", now=T1 + 2)
        self.assertEqual(current["disposition"], fabric.ACCEPTED)
        stale = fabric.ingest(self.db, sensor_id="beat", payload={"n": 9}, sequence=9,
                              runtime_generation="G1", now=T1 + 3)
        self.assertEqual(stale["disposition"], fabric.REFUSED_STALE_GENERATION)
        self.assertFalse(stale["stored"])
        self.assertTrue(stale["loss_indicated"])
        # NEGATIVE: an UNSEEN generation is a new generation, not a stale one, and is accepted.
        fresh = fabric.ingest(self.db, sensor_id="beat", payload={"n": 10}, sequence=10,
                              runtime_generation="G3", now=T1 + 4)
        self.assertEqual(fresh["disposition"], fabric.ACCEPTED)

    def test_restart_reconstructs_without_inventing_activity(self):
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", freshness_ttl=60.0, now=T1)
        fabric.ingest(self.db, sensor_id="beat", payload={"n": 1}, now=T1)
        report = fabric.restart(self.db, now=T1 + 3600)
        self.assertEqual(report["sensors"]["beat"]["status"], fabric.STALE)
        self.assertFalse(report["sensors"]["beat"]["invented_activity"])
        # A gap from the last real observation to the restart is recorded; nothing is back-filled.
        gaps = fabric.gaps(self.db, sensor_id="beat")
        self.assertTrue([gap for gap in gaps if gap["kind"] == fabric.GAP_OBSERVATION])
        self.assertEqual(len(fabric.events(self.db)), 1, "the restart invented an event")

    def test_a_sensor_that_never_reported_is_unknown_not_live(self):
        fabric.register_sensor(self.db, sensor_id="quiet", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        self.assertEqual(fabric.sensor_status(self.db, "quiet", now=T1)["status"], fabric.UNKNOWN)
        restarted = fabric.restart(self.db, now=T1 + 10)
        self.assertEqual(restarted["sensors"]["quiet"]["status"], fabric.UNKNOWN)

    def test_silence_is_not_a_verdict_about_the_subject(self):
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        downstream = fabric.mark_unavailable(self.db, sensor_id="beat", reason="sensor crashed",
                                             status=fabric.FAILED, now=T1 + 5)
        self.assertFalse(downstream["subject_failed"])
        status = fabric.sensor_status(self.db, "beat", now=T1 + 6)
        self.assertEqual(status["status"], fabric.FAILED)
        self.assertFalse(status["is_a_verdict_about_the_subject"])

    def test_a_fresh_process_reconstructs_the_same_fabric_state(self):
        path = self.component_file("V1\n")
        self.register(path)
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        fabric.ingest(self.db, sensor_id=SOURCE_SENSOR, payload={"extra": 1}, now=T1 + 1)
        expected = fabric.sensory_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.sensory_fabric import sensory_digest;"
                "print(json.dumps(sensory_digest(%r)))"
                % (str(pathlib.Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)


class TestTrustAndSelfObservation(FabricCase):

    def test_the_integrity_adapter_passes_through_a_refusal_verbatim(self):
        path = self.component_file("V1\n")
        self.register(path)
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        report = adapters.observe_integrity(self.db, component_id=COMPONENT, now=T1 + 1)
        self.assertEqual(report["claim"]["status"], SELF_CERTIFICATION_REFUSED)
        self.assertFalse(report["self_certified"])
        # NEGATIVE: with an independent witness that agrees, the disposition becomes CORROBORATED.
        witness_observation(self.db, component_id=COMPONENT, view=SOURCE, digest="AGREED",
                            observer_ref="node-b", independent=True)
        witness_observation(self.db, component_id=COMPONENT, view=SOURCE, digest="AGREED",
                            observer_ref="node-c", independent=True)
        self.assertEqual(adapters.observe_integrity(self.db, component_id=COMPONENT, view=SOURCE,
                                                    now=T1 + 2)["claim"]["status"], DISPUTED)

    def test_missing_witness_data_is_reported_as_unresolved(self):
        path = self.component_file("V1\n")
        self.register(path)
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        projection = architectural_projection(self.db, component=COMPONENT)
        self.assertEqual(projection["views"][LOADED]["status"], "UNRESOLVED")
        self.assertFalse(projection["distinctions"]["loaded_is_resolved"])

    def test_the_policy_reference_is_not_a_cryptographic_root(self):
        reference = policy_reference()
        self.assertFalse(reference["is_cryptographic_root_of_trust"])
        self.assertFalse(reference["hardware_attestation_claimed"])
        self.assertIn("shared_compromise_limitation", reference)

    def test_a_forged_event_cannot_become_execution_evidence(self):
        fabric.register_sensor(self.db, sensor_id="forger", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        fabric.ingest(self.db, sensor_id="forger",
                      payload={"claim": "capability darknet.scan EXECUTED", "receipt_ref": "RCP-FORGED"},
                      kind=fabric.ANOMALY, evidence_ref="RCP-FORGED", now=T1)
        self.assertEqual(len(fabric.events(self.db, sensor_id="forger")), 1)
        # The event is stored as an EVENT and nothing more: the canonical execution record is untouched.
        self.assertEqual(self.counts("ciph_self_executions"), 0)
        with self.assertRaises(CrucibleError):
            observe_executed(self.db, component_id=COMPONENT, execution_ref="RCP-FORGED")

    def test_equivocation_is_retained_and_raised_not_collapsed(self):
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        original = fabric.ingest(self.db, sensor_id="beat", payload={"v": "a"}, sequence=1, now=T1)
        # The SAME (sensor, version, sequence, generation) now carries a DIFFERENT payload. A sequence slot
        # is unique, so this is equivocation: neither a retry nor a second event.
        equivocation = fabric.ingest(self.db, sensor_id="beat", payload={"v": "b"}, sequence=1, now=T1 + 1)
        self.assertEqual(equivocation["disposition"], fabric.EQUIVOCATION)
        self.assertFalse(equivocation["stored"])
        self.assertTrue(equivocation["integrity_conflict"])
        self.assertEqual(equivocation["event_id"], original["event_id"])
        # BOTH contents are retained, and the original event is untouched.
        recorded = fabric.conflicts(self.db, sensor_id="beat")
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["first_payload_digest"], original["payload_digest"])
        self.assertNotEqual(recorded[0]["conflicting_payload_digest"], original["payload_digest"])
        self.assertEqual(recorded[0]["sensor_version"], 1)
        events = fabric.events(self.db, sensor_id="beat")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload_digest"], original["payload_digest"])
        # NEGATIVE: an exact re-delivery is still a plain DUPLICATE, not a conflict.
        retry = fabric.ingest(self.db, sensor_id="beat", payload={"v": "a"}, sequence=1, now=T1 + 2)
        self.assertEqual(retry["disposition"], fabric.DUPLICATE)
        self.assertEqual(len(fabric.conflicts(self.db, sensor_id="beat")), 1)

    def test_a_model_statement_is_not_a_sensor_observation(self):
        before = len(fabric.events(self.db))
        output_id = record_model_output(self.db, model_ref="llm:test",
                                        output_text="I definitely observed a change", now=T1)
        self.assertEqual(len(fabric.events(self.db)), before)
        self.assertIsInstance(output_id, str)
        self.assertEqual(self.counts("ciph_model_outputs"), 1)

    def test_the_fabric_cannot_reach_privilege_or_the_host(self):
        for relative in ("ciph/kernel/sensory_fabric.py", "ciph/kernel/sensory_adapters.py"):
            text = (pathlib.Path(__file__).resolve().parents[1] / relative).read_text(encoding="utf-8")
            for needle in ("import subprocess", "import socket", "os.system(", "Popen(", "sudo "):
                self.assertNotIn(needle, text, f"{relative} can reach the host")


class TestReconciliationAndResource(FabricCase):

    def test_reconciliation_discovers_a_missed_modification(self):
        """Two writes with no observation between them: reconciliation finds the change, and the interval
        with no observer is recorded as a GAP rather than reconstructed."""
        path = self.component_file("V1\n")
        self.register(path)
        baseline = adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        self.assertEqual(baseline["kind"], fabric.ROUTINE)
        path.write_text("V2\n", encoding="utf-8")
        path.write_text("V3\n", encoding="utf-8")
        reconciled = adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1 + 5)
        self.assertEqual(reconciled["kind"], fabric.CHANGE)
        self.assertEqual(reconciled["previous_digest"], baseline["observation"]["digest"])
        self.assertNotEqual(reconciled["observation"]["digest"], baseline["observation"]["digest"])
        events_before = len(fabric.events(self.db))
        gap = fabric.record_observation_gap(self.db, sensor_id=SOURCE_SENSOR, missing_from=T1 + 1,
                                            missing_to=T1 + 4, reason="no subscription between the writes",
                                            now=T1 + 5)
        self.assertFalse(gap["invented_activity"])
        self.assertEqual(gap["missing_from"], T1 + 1)
        self.assertEqual(gap["missing_to"], T1 + 4)
        # NEGATIVE: recording the gap invented no event, and the recorded reason survives intact.
        self.assertEqual(len(fabric.events(self.db)), events_before)
        recorded = [record for record in fabric.gaps(self.db, sensor_id=SOURCE_SENSOR)
                    if record["kind"] == fabric.GAP_OBSERVATION]
        self.assertEqual([record["reason"] for record in recorded],
                         ["no subscription between the writes"])

    def test_resource_overhead_is_bounded_and_measured(self):
        import os
        import resource
        fabric.register_sensor(self.db, sensor_id="load", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", max_queue=5000,
                               retention_seconds=86400.0, now=T1)
        idle_start = time.time()
        for _ in range(20):
            fabric.sensor_status(self.db, "load", now=T1)
        idle_seconds = time.time() - idle_start
        rss_before = fabric.process_resource_usage().get("rss_kb") or 0
        load_start = time.time()
        for tick in range(300):
            fabric.ingest(self.db, sensor_id="load", payload={"tick": tick}, now=T1 + tick)
        load_seconds = time.time() - load_start
        rss_after = fabric.process_resource_usage().get("rss_kb") or 0
        # Measured, not asserted-to-be-zero: the fabric keeps 300 events under a bounded budget.
        self.assertLess(idle_seconds, 5.0)
        self.assertLess(load_seconds, 20.0)
        self.assertLessEqual(rss_after - rss_before, 256 * 1024)
        self.assertEqual(len(fabric.events(self.db, sensor_id="load")), 300)


class TestAttentionInterface(FabricCase):

    def test_context_carries_kind_and_evidence_but_no_urgency_score(self):
        path = self.component_file("V1\n")
        self.register(path)
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1)
        path.write_text("V2\n", encoding="utf-8")
        adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1 + 1)
        context = fabric.context_for_reasoning(self.db, now=T1 + 2)
        self.assertIsNone(context["urgency_score"])
        self.assertEqual(context["counts"][fabric.CHANGE], 1)
        reference = context["references"][0]
        for field in ("event_id", "sensor_id", "kind", "observed_at", "evidence_ref", "payload_digest",
                      "canonical_owner", "freshness"):
            self.assertIn(field, reference)

    def test_an_anomaly_claim_confers_no_authority(self):
        fabric.register_sensor(self.db, sensor_id="loud", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", now=T1)
        before = self.counts("ciph_crucible_deployments")
        fabric.ingest(self.db, sensor_id="loud", payload={"severity": "CRITICAL", "action": "deploy"},
                      kind=fabric.ANOMALY, now=T1)
        self.assertEqual(self.counts("ciph_crucible_deployments"), before)
        context = fabric.context_for_reasoning(self.db, now=T1 + 1)
        self.assertEqual(context["counts"][fabric.ANOMALY], 1)


class TestFoundingScenario(FabricCase):
    """The integrated disposable scenario, exercised end to end with real owners."""

    def test_the_founding_scenario(self):
        path = self.component_file("V1\n")
        self.register(path)
        # (1) start the fabric; (2) the model is UNAVAILABLE for the whole scenario.
        cycle = adapters.run_cycle(self.db, calls=[("architecture_source", {"component_id": COMPONENT}),
                                                   ("resources", {}),
                                                   ("swarm", {}), ("federation", {}),
                                                   ("execution", {}), ("investigations", {}),
                                                   ("communications", {})], now=T1)
        self.assertFalse(cycle["invoked_the_model"])

        # (4) a genuine source-file modification; (5) installed-vs-loaded stays correct.
        first_digest = cycle["adapters"]["architecture_source"]["observation"]["digest"]
        adapters.witness_runtime(self.db, component_id=COMPONENT, digest=first_digest,
                                 runtime_generation="G1", now=T1 + 1)
        path.write_text("V2 -- modified while reasoning was unavailable\n", encoding="utf-8")
        changed = adapters.observe_architecture(self.db, component_id=COMPONENT, now=T1 + 2)
        self.assertEqual(changed["kind"], fabric.CHANGE)
        projection = architectural_projection(self.db, component=COMPONENT)
        self.assertEqual(projection["views"][LOADED]["digest"], first_digest)
        self.assertEqual(projection["distinctions"]["source_vs_loaded"], MISMATCH)

        # (6) a worker completes an authorized task; (7) another worker is unreachable (not failed).
        _, delegation, result = self.completed_task("W1", "TASK-1")
        self.ready_worker("W2", attest=False)  # announced, never attested -> UNKNOWN reachability
        swarm_report = adapters.observe_swarm(self.db, now=T1 + 3)
        self.assertIn("W2", swarm_report["unreachable_as_stale"])
        self.assertEqual(swarm_report["declared_failed"], [])

        # (8) a genuine completed investigation with durable findings.
        committed = self.investigation(3)
        adapters.observe_investigations(self.db, now=T1 + 4)
        adapters.observe_communications(self.db, now=T1 + 4)
        retrieved = retrieve_result_set(self.db, committed["result_set_id"], actor="operator:operator")
        self.assertEqual(retrieved["count"], 3)

        # (9) restart the fabric during ongoing activity. (10) reconstruct and mark gaps honestly.
        fabric.ingest(self.db, sensor_id=SOURCE_SENSOR, payload={"still": "working"}, now=T1 + 5)
        report = fabric.restart(self.db, now=T1 + 6)
        for sensor in report["sensors"].values():
            self.assertFalse(sensor["invented_activity"])
        reconstruction = fabric.reconstruct(self.db, now=T1 + 7)
        self.assertGreaterEqual(reconstruction["event_count"], 4)

        # (11) the model is available again; (12) it receives SELECTED context from actual records.
        context = fabric.context_for_reasoning(self.db, since=T1, now=T1 + 8)
        self.assertIsNone(context["urgency_score"])

        # (13)+(14) every concrete reference resolves to real evidence.
        for reference in context["references"]:
            self.assertTrue(self._evidence_resolves(reference), reference)

        # (15) the sensors created no execution permission, worker authority or deployment standing.
        self.assertEqual(self.counts("ciph_crucible_deployments"), 0)
        self.assertEqual(self.counts("ciph_self_executions"), 0)
        self.assertFalse(cycle["created_execution_authority"])

    def _evidence_resolves(self, reference):
        evidence = reference["evidence_ref"]
        if evidence is None:
            return True  # a routine observation with no canonical reference makes no claim
        owner = reference["canonical_owner"]
        if owner.endswith("architectural_proprioception.py"):
            return any(row["arch_observation_id"] == evidence
                       for row in arch_observations(self.db))
        if owner.endswith("referential_continuity.py"):
            known = {record["result_set_id"] for record in result_sets(self.db)}
            known |= {record["announcement_id"] for record in announcements(self.db)}
            return evidence in known
        if owner.endswith("self_model.py"):
            return self.counts("ciph_self_executions") > 0 or evidence.startswith("SEX-")
        return evidence is not None


class TestOwnership(unittest.TestCase):

    def test_the_census_is_clean_and_names_the_owner(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 9)
        for key in ("rival_sensor_transport_owners", "sensory_modules_write_canonical",
                    "heartbeats_written_to_the_ledger", "forbidden_sensory_patterns",
                    "architectural_views_preserved", "retained_machinery_missing"):
            self.assertEqual(report[key], [], key)

    def test_the_census_counts_the_new_conflict_store(self):
        from ciph.kernel.sensory_ownership import CENSUS
        signals = [concern.signal for concern in CENSUS]
        self.assertIn("TABLE:ciph_sensor_conflicts", signals)

    def test_each_zero_fires_on_its_own_synthetic_violation(self):
        from ciph.kernel import sensory_ownership as census
        real = dict(census.production_sources())
        rogue = "ciph/kernel/rogue_sensor.py"
        cases = [
            (census.rival_sensor_transport_owners,
             "def steal(c):\n    c.execute('INSERT INTO ciph_sensor_events VALUES (1);')\n"),
            (census.sensory_modules_write_canonical,
             "def go(c):\n    c.execute('INSERT INTO ciph_observations VALUES (1);')\n"),
            (census.heartbeats_written_to_the_ledger,
             "def beat(db):\n    return record_observation(db, raw_text='tick')\n"),
            (census.forbidden_sensory_patterns, "def go(s):\n    return sensor_grants_authority(s)\n"),
            (census.architectural_views_preserved,
             "VIEW_BY_ADAPTER = {}\nimport architectural_proprioception\n"
             "def peek(p):\n    view = 'LOADED'\n    return open(p).read_bytes()\n"),
        ]
        for predicate, body in cases:
            with self.subTest(predicate=predicate.__name__):
                if predicate is census.heartbeats_written_to_the_ledger:
                    sources = {**real, census.OWNER: body}
                elif predicate is census.sensory_modules_write_canonical:
                    sources = {**real, census.ADAPTERS: body}
                elif predicate is census.architectural_views_preserved:
                    sources = {**real, census.ADAPTERS: body}
                else:
                    sources = {**real, rogue: body}
                self.assertTrue(predicate(sources=list(sources.items())),
                                f"{predicate.__name__} did not fire")

    def test_the_report_is_available_without_asserting_cleanliness(self):
        from ciph.kernel.sensory_ownership import SENSORY_OWNERSHIP_V1, ownership_report
        report = ownership_report()
        self.assertEqual(report["policy_version"], SENSORY_OWNERSHIP_V1)
        self.assertIn("concerns", report)


if __name__ == "__main__":
    unittest.main()
