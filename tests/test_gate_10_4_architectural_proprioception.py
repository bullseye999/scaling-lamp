"""
10.4 - architectural proprioception.

    Four views that are never collapsed.  A LOADED witness is captured at LOAD, not re-derived from disk.
    A self-observation cannot certify the observer it is evaluating.  An authorized deployment is only
    "authorized" once the installed bytes are independently corroborated.

Every positive specimen is paired with a NEGATIVE counterpart: the point is that the unjustified claim
produces the OPPOSITE answer (UNRESOLVED / UNAUTHORIZED / DISPUTED / refused), not merely that a happy
path works. Real 4.2, 4.3 and R7 machinery is exercised where the law is about those systems.
"""

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from ciph.kernel.architectural_ownership import assert_ownership_clean
from ciph.kernel.architectural_proprioception import (
    AUTHORIZED_BUT_UNVERIFIED, AUTHORIZED_DEPLOYMENT, CORROBORATED, DISPUTED, EXECUTED, FRESH,
    INSTALLED, LOADED, MATCH, MISMATCH, OBSERVATION_GAP, SELF_CERTIFICATION_REFUSED, SOURCE, STALE,
    UNKNOWN, UNKNOWN_PROVENANCE, UNRESOLVED, UNAUTHORIZED_MODIFICATION, architectural_digest, architectural_projection,
    changes, classify_freshness, digest_bytes, explain, integrity_claim, is_protected_artifact,
    load_time_digest, observations, observe_executed, observe_installed, observe_source, policy_reference,
    record_model_architectural_claim, record_observation_gap, register_component, witness_change,
    witness_loaded, witness_observation)
from ciph.kernel.crucible_candidates import register_candidate
from ciph.kernel.crucible_metrics import STATUS_DOMINATES
from ciph.kernel.crucible_promotion import promote
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_types import CrucibleError, KIND_CAPABILITY_IMPLEMENTATION
from ciph.kernel.evolution_deployment import deploy
from ciph.kernel.self_model import record_execution_evidence

T1 = 1_800_000_000.0
COMPONENT = "ciph.example.module"


class ProprioceptionCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-104-")
        self.base = pathlib.Path(self.temp.name)
        self.db = str(self.base / "state.db")

    def tearDown(self):
        self.temp.cleanup()

    def component_file(self, body: str = "V1\n"):
        path = self.base / "component.py"
        path.write_text(body, encoding="utf-8")
        return path

    def register(self, path=None, component=COMPONENT):
        return register_component(self.db, component_id=component, path=str(path) if path else None)

    def view(self, component=COMPONENT):
        return architectural_projection(self.db, component=component)["views"]


class TestFourViews(ProprioceptionCase):

    def test_01_source_changes_while_the_loaded_version_stays_put(self):
        path = self.component_file("V1\n")
        self.register(path)
        v1 = observe_source(self.db, component_id=COMPONENT)["digest"]
        self.assertEqual(v1, load_time_digest(path))
        witness_loaded(self.db, component_id=COMPONENT, digest=v1, runtime_generation="G1")

        path.write_text("V2 -- edited on disk after the process loaded\n", encoding="utf-8")
        v2 = observe_source(self.db, component_id=COMPONENT)["digest"]
        self.assertNotEqual(v1, v2)

        views = self.view()
        self.assertEqual(views[SOURCE]["digest"], v2)
        # PROOF: the LOADED view did NOT move when the file changed on disk. Re-hashing is not loading.
        self.assertEqual(views[LOADED]["digest"], v1, "re-hashing a changed file must not change LOADED")
        self.assertEqual(architectural_projection(self.db, component=COMPONENT)["distinctions"][
            "source_vs_loaded"], MISMATCH)

        # NEGATIVE: with only the LOCAL source observer and no load witness, LOADED is UNRESOLVED, never
        # "probably the source".
        register_component(self.db, component_id="ciph.example.unwitnessed", path=str(path))
        observe_source(self.db, component_id="ciph.example.unwitnessed")
        self.assertEqual(self.view("ciph.example.unwitnessed")[LOADED]["status"], UNRESOLVED)

    def test_02_installed_bytes_change_but_no_execution_is_proven(self):
        path = self.component_file("V1\n")
        self.register(path)
        installed = self.base / "installed.bin"
        installed.write_bytes(b"artifact-v1")
        observe_installed(self.db, component_id=COMPONENT, artifact_path=str(installed))
        projection = architectural_projection(self.db, component=COMPONENT)
        self.assertEqual(projection["views"][EXECUTED]["status"], UNRESOLVED)
        self.assertFalse(projection["distinctions"]["executed_is_resolved"])
        # NEGATIVE: changing the installed artifact does not manufacture an execution claim.
        installed.write_bytes(b"artifact-v2")
        observe_installed(self.db, component_id=COMPONENT, artifact_path=str(installed))
        self.assertEqual(self.view()[EXECUTED]["status"], UNRESOLVED)
        self.assertEqual([c for c in changes(self.db) if c["view"] == EXECUTED], [])

    def test_03_a_new_runtime_loads_an_updated_version_after_restart(self):
        path = self.component_file("V1\n")
        self.register(path)
        v1 = observe_source(self.db, component_id=COMPONENT)["digest"]
        witness_loaded(self.db, component_id=COMPONENT, digest=v1, runtime_generation="G1")
        path.write_text("V2\n", encoding="utf-8")
        v2 = observe_source(self.db, component_id=COMPONENT)["digest"]
        self.assertEqual(architectural_projection(self.db, component=COMPONENT)["distinctions"][
            "source_vs_loaded"], MISMATCH)
        # A restart loads the new version: a fresh load-time witness for generation G2.
        witness_loaded(self.db, component_id=COMPONENT, digest=v2, runtime_generation="G2")
        self.assertEqual(architectural_projection(self.db, component=COMPONENT)["distinctions"][
            "source_vs_loaded"], MATCH)
        # NEGATIVE: the old witness is history, not overwritten.
        generations = {row["runtime_generation"]
                       for row in observations(self.db, component_id=COMPONENT, view=LOADED)}
        self.assertEqual(generations, {"G1", "G2"})

    def test_15_distinctions_survive_restart_and_rollback(self):
        path = self.component_file("V1\n")
        self.register(path)
        v1 = observe_source(self.db, component_id=COMPONENT)["digest"]
        installed = self.base / "installed.bin"
        installed.write_bytes(b"v1")
        observe_installed(self.db, component_id=COMPONENT, artifact_path=str(installed))
        witness_loaded(self.db, component_id=COMPONENT, digest=v1, runtime_generation="G1")
        # a disk edit that is NOT loaded
        path.write_text("V2\n", encoding="utf-8")
        observe_source(self.db, component_id=COMPONENT)
        # a rollback: the file goes back, and a NEW runtime loads the restored bytes
        path.write_text("V1\n", encoding="utf-8")
        observe_source(self.db, component_id=COMPONENT)
        witness_loaded(self.db, component_id=COMPONENT, digest=v1, runtime_generation="G-ROLLED-BACK")
        distinctions = architectural_projection(self.db, component=COMPONENT)["distinctions"]
        self.assertEqual(distinctions["source_vs_loaded"], MATCH)
        self.assertEqual(distinctions["source_vs_installed"], MISMATCH)  # v1 source vs b"v1" artifact
        self.assertNotEqual(distinctions["installed_vs_loaded"], UNKNOWN)
        self.assertTrue(distinctions["loaded_is_resolved"])
        self.assertGreaterEqual(len(architectural_digest(self.db)), 32)


class TestChangeWitnessing(ProprioceptionCase):

    def _real_deployment(self, artifact: pathlib.Path, key: str):
        role = f"capability:{key}"
        baseline = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                      artifact_digest="H0", configuration_digest="C0")
        artifact_digest = digest_bytes(artifact.read_bytes())
        candidate = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                       artifact_digest=artifact_digest, configuration_digest="C1",
                                       baseline_candidate_id=baseline.candidate_id)
        protocol = freeze_protocol(self.db, candidate_kind=KIND_CAPABILITY_IMPLEMENTATION,
                                   development_cases=["d"], heldout_cases=["h"],
                                   metric_definitions=[MetricDefinition("task_success", "v1",
                                                                        "HIGHER_BETTER", 0.02)],
                                   environment_identity="host:eval", minimum_evidence=1, now=T1)
        promotion = promote(self.db, role=role, candidate_id=candidate.candidate_id,
                            protocol_id=protocol.protocol_id, comparison_status=STATUS_DOMINATES,
                            evaluation_refs=["T1"], authorization_ref="operator:operator",
                            replaced_candidate_id=baseline.candidate_id, now=T1)
        record = deploy(self.db, promotion_id=promotion.promotion_id, role=role,
                        candidate_id=candidate.candidate_id, artifact_digest=artifact_digest,
                        configuration_digest="C1",
                        installer=lambda *, promotion_id, candidate_id, artifact_digest: artifact_digest,
                        authorization_ref="operator:operator", installer_ref="fixture", now=T1)
        return record, artifact_digest

    def test_04_an_authorized_deployment_correlates_with_observed_installed_bytes(self):
        artifact = self.base / "capability.py"
        artifact.write_text("EXPECTED\n", encoding="utf-8")
        self.register(self.component_file("V1\n"))
        record, artifact_digest = self._real_deployment(artifact, "math.compute")
        installed = observe_installed(self.db, component_id=COMPONENT, artifact_path=str(artifact))
        self.assertEqual(installed["digest"], artifact_digest)
        accepted = witness_change(self.db, component_id=COMPONENT, view=INSTALLED, previous_digest="H0",
                                  current_digest=artifact_digest, authorization_ref=record.deployment_id,
                                  verified_installed_digest=installed["digest"], now=T1 + 10)
        self.assertEqual(accepted["provenance"], AUTHORIZED_DEPLOYMENT)
        self.assertTrue(accepted["authorized"])
        # NEGATIVE: the deployment's INTENT is not enough. If the observed bytes disagree, the change is a
        # MISMATCH, not an authorization.
        wrong = witness_change(self.db, component_id=COMPONENT, view=INSTALLED, previous_digest="H0",
                               current_digest="SOMETHING-ELSE",
                               authorization_ref=record.deployment_id,
                               verified_installed_digest=installed["digest"], now=T1 + 11)
        self.assertEqual(wrong["provenance"], AUTHORIZED_BUT_UNVERIFIED)
        self.assertFalse(wrong["authorized"])

    def _failed_deployment(self, role="capability:math.compute"):
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

    def test_05_the_absence_of_a_record_is_not_an_unauthorized_actor(self):
        self.register(self.component_file("V1\n"))
        # NO authorization record was correlated. That is an absence of knowledge, NOT a finding that the
        # change was unauthorized - the observer did not see who changed it.
        change = witness_change(self.db, component_id=COMPONENT, view=SOURCE, previous_digest="A",
                                current_digest="B", now=T1)
        self.assertEqual(change["provenance"], UNKNOWN_PROVENANCE)
        self.assertFalse(change["authorized"])
        self.assertIsNone(change["authorization_ref"])
        self.assertIn("not a claim that the change was unauthorized", change["uncertainty"])
        dangling = witness_change(self.db, component_id=COMPONENT, view=SOURCE, previous_digest="B",
                                  current_digest="C", authorization_ref="CDP-DOES-NOT-EXIST", now=T1 + 1)
        self.assertEqual(dangling["provenance"], UNKNOWN_PROVENANCE)
        self.assertFalse(dangling["authorized"])
        # NEGATIVE, the other way: a record that EXISTS and was REFUSED, with changed bytes, IS an
        # unauthorized modification - positive evidence, not an inference from absence.
        failed = self._failed_deployment()
        refused = witness_change(self.db, component_id=COMPONENT, view=SOURCE, previous_digest="C",
                                 current_digest="D", authorization_ref=failed, now=T1 + 2)
        self.assertEqual(refused["provenance"], UNAUTHORIZED_MODIFICATION)
        self.assertFalse(refused["authorized"])

    def test_06_an_offline_observer_records_a_gap_not_an_invented_history(self):
        self.register(self.component_file("V1\n"))
        gap = record_observation_gap(self.db, component_id=COMPONENT, missing_from=T1,
                                     missing_to=T1 + 600, reason="observer offline", now=T1 + 700)
        self.assertEqual(gap["provenance"], OBSERVATION_GAP)
        self.assertFalse(gap["invented_history"])
        recorded = [c for c in changes(self.db) if c["change_id"] == gap["change_id"]][0]
        self.assertIsNone(recorded["previous_digest"])
        self.assertIsNone(recorded["current_digest"])
        self.assertEqual(recorded["uncertainty"], "observer offline")
        # NEGATIVE: nothing in the gap claims a digest.
        self.assertEqual([c for c in changes(self.db) if c["provenance"] == OBSERVATION_GAP
                          and c["current_digest"] is not None], [])

    def test_07_a_forged_architectural_observation_is_refused(self):
        self.register(self.component_file("V1\n"))
        # A LOADED view with no captured digest is a forged "what is running" claim.
        with self.assertRaises(CrucibleError) as forged:
            witness_loaded(self.db, component_id=COMPONENT, digest="", runtime_generation="G1")
        self.assertEqual(forged.exception.reason, "LOAD_WITNESS_REQUIRES_A_CAPTURED_DIGEST")
        # An EXECUTED claim from a non-canonical reference is refused.
        with self.assertRaises(CrucibleError) as fake_exec:
            observe_executed(self.db, component_id=COMPONENT, execution_ref="MDL-NOT-REAL")
        self.assertEqual(fake_exec.exception.reason, "EXECUTION_EVIDENCE_NOT_CANONICAL")
        # NEGATIVE: a genuinely captured digest is accepted.
        v1 = observe_source(self.db, component_id=COMPONENT)["digest"]
        self.assertTrue(witness_loaded(self.db, component_id=COMPONENT, digest=v1,
                                       runtime_generation="G1")["arch_observation_id"])


class TestTrustBoundary(ProprioceptionCase):

    def test_08_two_observers_disagree_so_the_claim_is_disputed(self):
        self.register(self.component_file("V1\n"))
        observe_source(self.db, component_id=COMPONENT)
        witness_observation(self.db, component_id=COMPONENT, view=SOURCE, digest="AAA",
                            observer_ref="node-b", independent=True)
        witness_observation(self.db, component_id=COMPONENT, view=SOURCE, digest="BBB",
                            observer_ref="node-c", independent=True)
        self.assertEqual(integrity_claim(self.db, component_id=COMPONENT, view=SOURCE)["status"],
                         DISPUTED)
        # NEGATIVE: in a clean set, independent witnesses that AGREE corroborate.
        clean = str(self.base / "clean.db")
        register_component(clean, component_id=COMPONENT)
        witness_observation(clean, component_id=COMPONENT, view=SOURCE, digest="CCC",
                            observer_ref="node-d", independent=True)
        witness_observation(clean, component_id=COMPONENT, view=SOURCE, digest="CCC",
                            observer_ref="node-e", independent=True)
        self.assertEqual(integrity_claim(clean, component_id=COMPONENT, view=SOURCE)["status"],
                         CORROBORATED)

    def test_09_the_local_observer_cannot_certify_itself(self):
        self.register(self.component_file("V1\n"))
        observe_source(self.db, component_id=COMPONENT)
        claim = integrity_claim(self.db, component_id=COMPONENT, view=SOURCE)
        self.assertEqual(claim["status"], SELF_CERTIFICATION_REFUSED)
        self.assertEqual(claim["witnesses"], 0)
        # A "witness" that shares the compromised trust domain (independent=False) is still self-evidence.
        witness_observation(self.db, component_id=COMPONENT, view=SOURCE, digest="X",
                            observer_ref="compromised-local-witness", independent=False)
        self.assertEqual(integrity_claim(self.db, component_id=COMPONENT, view=SOURCE)["status"],
                         SELF_CERTIFICATION_REFUSED)
        # The limitation is stated, not hidden: the census is policy, not a cryptographic root.
        reference = policy_reference()
        self.assertFalse(reference["is_cryptographic_root_of_trust"])
        self.assertFalse(reference["hardware_attestation_claimed"])

    def test_10_a_restored_instance_keeps_history_and_gets_a_new_generation(self):
        path = self.component_file("V1\n")
        self.register(path)
        v1 = observe_source(self.db, component_id=COMPONENT)["digest"]
        witness_loaded(self.db, component_id=COMPONENT, digest=v1, runtime_generation="G1")
        witness_change(self.db, component_id=COMPONENT, view=SOURCE, previous_digest="OLD",
                       current_digest=v1, now=T1)
        history_before = len(changes(self.db))

        restored = str(self.base / "restored.db")
        shutil.copyfile(self.db, restored)
        witness_loaded(restored, component_id=COMPONENT, digest=v1, runtime_generation="G-RESTORED")
        self.assertEqual(len(changes(restored)), history_before, "restore preserves change history")
        views = architectural_projection(restored, component=COMPONENT)["views"]
        self.assertEqual(views[LOADED]["runtime_generation"], "G-RESTORED")
        self.assertEqual(views[LOADED]["digest"], v1)


class TestIntegration(ProprioceptionCase):

    def test_11_a_disconnected_node_is_stale_not_current(self):
        self.assertEqual(classify_freshness(T1, now=T1 + 5, ttl=60), FRESH)
        self.assertEqual(classify_freshness(T1, now=T1 + 600, ttl=60), STALE)
        self.assertEqual(classify_freshness(None, now=T1, ttl=60), UNKNOWN)

    def test_12_a_model_statement_cannot_become_execution_evidence(self):
        self.register(self.component_file("V1\n"))
        claim = record_model_architectural_claim(self.db, model_ref="llm:test",
                                                 output_text="I have definitely executed the scan")
        self.assertFalse(claim["canonical_execution"])
        with self.assertRaises(CrucibleError) as refused:
            observe_executed(self.db, component_id=COMPONENT, execution_ref=claim["model_output"])
        self.assertEqual(refused.exception.reason, "EXECUTION_EVIDENCE_NOT_CANONICAL")
        # NEGATIVE: real governed execution evidence DOES resolve.
        record = record_execution_evidence(self.db, capability_id="darknet.scan", succeeded=True,
                                           attempt_ref="ATT-1", receipt_ref="RCP-1")
        accepted = observe_executed(self.db, component_id=COMPONENT, execution_ref=record)
        self.assertEqual(accepted["view"], EXECUTED)

    def test_13_protected_introspection_cannot_expose_secrets_or_held_out_material(self):
        self.register(self.component_file("MARKER-FILE-CONTENT\n"))
        secret = self.base / "ciph.key"
        secret.write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")
        self.assertTrue(is_protected_artifact(secret))
        with self.assertRaises(CrucibleError) as refused:
            observe_source(self.db, component_id=COMPONENT, path=str(secret))
        self.assertEqual(refused.exception.reason, "PROTECTED_ARTIFACT_CANNOT_BE_OBSERVED")
        heldout = self.base / "meta_corpus_sealed_eval.py"
        heldout.write_text("ANSWERS = ['a']", encoding="utf-8")
        self.assertTrue(is_protected_artifact(heldout))
        with self.assertRaises(CrucibleError):
            observe_installed(self.db, component_id=COMPONENT, artifact_path=str(heldout))
        # NEGATIVE: the projection exposes DIGESTS and metadata only, never content.
        observe_source(self.db, component_id=COMPONENT)
        blob = json.dumps(architectural_projection(self.db))
        self.assertNotIn("PRIVATE KEY", blob)
        self.assertNotIn("MARKER-FILE-CONTENT", blob, "the projection leaked file content")

    def test_14_a_fresh_process_reconstructs_the_same_projection(self):
        path = self.component_file("V1\n")
        self.register(path)
        observe_source(self.db, component_id=COMPONENT)
        witness_loaded(self.db, component_id=COMPONENT, digest=load_time_digest(path),
                       runtime_generation="G1")
        expected = architectural_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.architectural_proprioception import architectural_digest;"
                "print(json.dumps(architectural_digest(%r)))"
                % (str(pathlib.Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)

    def test_the_explanation_answers_from_evidence(self):
        path = self.component_file("V1\n")
        self.register(path)
        observe_source(self.db, component_id=COMPONENT)
        witness_loaded(self.db, component_id=COMPONENT, digest=load_time_digest(path),
                       runtime_generation="G1")
        witness_change(self.db, component_id=COMPONENT, view=SOURCE, previous_digest="OLD",
                       current_digest="NEW", affected=["worker-a"], now=T1)
        answer = explain(self.db, component=COMPONENT)
        self.assertIn(COMPONENT, answer["components_with_evidence"])
        self.assertIn(COMPONENT, answer["running_implementation"])
        self.assertIn("worker-a", answer["dependent_components_of_changes"])
        self.assertTrue(answer["uncertain"]["unauthorized_or_unknown"])
        self.assertFalse(answer["policy_reference"]["is_cryptographic_root_of_trust"])


class TestOwnership(unittest.TestCase):

    def test_the_census_is_clean_and_the_owner_is_named(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 6)
        for key in ("rival_architectural_owners", "rival_epistemic_or_deployment_owners",
                    "forbidden_architectural_patterns", "loaded_view_is_a_witness",
                    "attestation_overclaims", "retained_machinery_missing"):
            self.assertEqual(report[key], [], key)

    def test_each_zero_fires_on_its_own_synthetic_violation(self):
        from ciph.kernel import architectural_ownership as census
        real = dict(census.production_sources())
        rogue = "ciph/kernel/rogue_arch.py"
        cases = [
            (census.rival_architectural_owners,
             "def steal(c):\n    c.execute('INSERT INTO ciph_arch_observations VALUES (1);')\n"),
            (census.rival_epistemic_or_deployment_owners,
             "def steal(c):\n    c.execute('INSERT INTO ciph_crucible_deployments VALUES (1);')\n"),
            (census.forbidden_architectural_patterns,
             "def go(db):\n    return self_certified_integrity(db)\n"),
            (census.loaded_view_is_a_witness,
             "def peek(path):\n    view = 'LOADED'\n    return open(path).read_bytes()\n"),
            (census.attestation_overclaims, "hardware_backed_attestation = True\n"),
        ]
        for predicate, body in cases:
            with self.subTest(predicate=predicate.__name__):
                self.assertTrue(predicate(sources=list({**real, rogue: body}.items())),
                                f"{predicate.__name__} did not fire")

    def test_r14_legacy_owners_are_settled_by_responsibility(self):
        from ciph.kernel.referential_ownership import legacy_owners_to_classify
        dispositions = {item["module"]: item["disposition"] for item in legacy_owners_to_classify()}
        for module in ("smart_memory.py", "enhanced_conversation.py", "personality_engine.py",
                       "mood_engine.py", "self_awareness.py"):
            self.assertIn(module, dispositions)
            self.assertNotIn("TBD", dispositions[module], f"{module} is still unsettled")
        self.assertIn("10.4", dispositions["self_awareness.py"])


if __name__ == "__main__":
    unittest.main()
