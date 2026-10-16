"""
8.0-8.5 - the sovereignty foundation, and the two R12 findings closed by EXECUTION.

    Possession of Ciph's bytes is not possession of Ciph's authority.

The specimens below deliberately EXERCISE the unsafe paths rather than scanning for them: the legacy
backup entry point is called, the dead-man destructor is called, and the refusals are asserted. A scanner
reporting zero is not evidence that a path is gone.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.backup_constitution import (APPROVED, CORRUPTED, CREATED, INCOMPLETE,
                                             INSECURE_HISTORICAL, LEGACY_DEFAULT_PASSPHRASE,
                                             MINIMUM_PASSPHRASE_LENGTH, REASON_INSECURE,
                                             REASON_NOT_OPERATOR, REASON_NOT_VERIFIED,
                                             REASON_ROOT_MEMBER, UNKNOWN_PROTECTION, VERIFIED,
                                             assert_backup_configuration, authorize_for_recovery,
                                             backup_digest, backup_sets, cannot_activate_itself,
                                             classify_historical_backup, create_approved_backup,
                                             verify_backup)
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.evolution_ownership import production_sources
from ciph.kernel.recovery_manifest import (COMPLETE, MANIFEST_TAMPERED, MUST_NOT_COPY, MUST_RESTORE,
                                           MAY_REBUILD, RECONCILE_BEFORE_USE, SPECIAL_CUSTODY,
                                           build_manifest, families_with, get_manifest,
                                           manifest_digest, requirements, verify_manifest)
from ciph.kernel.recovery_state import (ACTIVATED, AUTHORIZED_ACTIVATION, ENVIRONMENT_ATTESTED,
                                        FENCED, IDENTITY_VERIFIED, KEY_UNAVAILABLE, LIFECYCLE,
                                        RECONCILED, RECOVERY_ACTIVATION_HOLD, RESTORE_STARTED,
                                        STATE_VERIFIED, SUPERSEDED, UNFENCED, UNRECOVERABLE, advance,
                                        activation_history, assert_no_standing, assess_fencing,
                                        begin_recovery, clone_record, clone_registry, fail_run,
                                        get_run, recovery_digest, register_clone)
from ciph.kernel.sovereign_identity import (RECOVERABLE, RECOVERY_REQUIRES_OPERATOR, ROOT_KEY_ACTIVE,
                                            arm_destruction, assert_identity_continuity,
                                            assess_recoverability, destruction_policy,
                                            destruction_state_after_recovery, disarm_destruction,
                                            establish_identity, identity, identity_history,
                                            register_root_key, revoke_root_key,
                                            sovereign_identity_digest, UNRECOVERABLE as KEY_UNRECOVERABLE)
from ciph.kernel.sovereignty_ownership import (assert_ownership_clean, backup_activation_paths,
                                               clone_authority_claims,
                                               destruction_state_restorable,
                                               host_identity_dependencies, ownership_report,
                                               root_copied_as_ordinary_artifact,
                                               wall_clock_recovery_selection)

T1 = 1_800_000_000.0
DIGEST = "c" * 64
IDENTITY = "CIPH-IDENTITY-1"


class SovereigntyTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-80-")
        self.db = str(Path(self.temp.name) / "sovereignty.db")
        self.passphrase = "a-real-passphrase-for-the-backup"

    def tearDown(self):
        self.temp.cleanup()

    def identity_and_root(self, *, keys=("root-1",)):
        for key_ref in keys:
            register_root_key(self.db, key_ref=key_ref, actor="operator:operator", now=T1)
        return establish_identity(self.db, ciph_identity_id=IDENTITY,
                                  vault_identity_ref="VAULT-0E79C7AFD84740BB",
                                  constitutional_root_digest=DIGEST,
                                  recovery_policy_id="RECOVERY_POLICY_V1",
                                  authorized_root_key_refs=list(keys),
                                  node_identity_root_refs=["N-A"], actor="operator:operator", now=T1)

    def manifest(self, *, families=None):
        return build_manifest(self.db, ciph_identity_id=IDENTITY,
                              constitutional_versions=["4.0", "5.0", "6.0", "7.0", "8.0"],
                              required_state_families=families or ["missions", "epistemic_ledger",
                                                                  "evolution_epochs",
                                                                  "federation_authority"],
                              required_secret_refs=["root-1"],
                              required_artifact_digests={"vault": DIGEST},
                              schema_versions={"ciph_missions": "S3"},
                              created_from_canonical_state_digest=DIGEST, now=T1)

    def backup(self, manifest=None, *, included=("ciph_missions", "ciph_observations")):
        manifest = manifest or self.manifest()
        return create_approved_backup(self.db, source_identity=IDENTITY,
                                      manifest_id=manifest["manifest_id"], state_digest=DIGEST,
                                      artifact_digest=DIGEST, schema_digest=DIGEST,
                                      included=list(included), excluded=["ciph.key", "*.pid"],
                                      encryption_identity="gpg:aes256",
                                      consistency_boundary=f"sqlite-snapshot@{int(T1)}",
                                      passphrase=self.passphrase, now=T1)


class TestR12Closure(SovereigntyTestCase):
    """The two findings, closed by calling the code rather than by reading it."""

    def test_the_legacy_backup_entry_point_refuses_its_own_configuration(self):
        import security_layer
        os.environ.pop("CIPH_BACKUP_PASSPHRASE", None)

        class Vault:
            def store_conversation(self, *a, **k):
                return None

        with self.assertRaises(security_layer.InsecureBackupError) as refused:
            security_layer.SecurityLayer(Vault()).encrypted_backup()
        self.assertIn(REASON_INSECURE, str(refused.exception))
        os.environ["CIPH_BACKUP_PASSPHRASE"] = LEGACY_DEFAULT_PASSPHRASE
        try:
            with self.assertRaises(security_layer.InsecureBackupError) as legacy_default:
                security_layer.SecurityLayer(Vault()).encrypted_backup()
            self.assertIn(REASON_INSECURE, str(legacy_default.exception))
        finally:
            os.environ.pop("CIPH_BACKUP_PASSPHRASE", None)

    def test_the_approved_creator_refuses_root_material_and_weak_passphrases(self):
        manifest = self.manifest()
        with self.assertRaises(CrucibleError) as weak:
            create_approved_backup(self.db, source_identity=IDENTITY,
                                   manifest_id=manifest["manifest_id"], state_digest=DIGEST,
                                   artifact_digest=DIGEST, schema_digest=DIGEST,
                                   included=["ciph_missions"], encryption_identity="gpg:aes256",
                                   consistency_boundary="b", passphrase="short", now=T1)
        self.assertEqual(weak.exception.reason, REASON_INSECURE)
        with self.assertRaises(CrucibleError) as default:
            assert_backup_configuration(passphrase=LEGACY_DEFAULT_PASSPHRASE, included=["ciph_x"])
        self.assertEqual(default.exception.reason, REASON_INSECURE)
        with self.assertRaises(CrucibleError) as root_member:
            assert_backup_configuration(passphrase=self.passphrase, included=["ciph_vault.db",
                                                                             "ciph.key"])
        self.assertEqual(root_member.exception.reason, REASON_ROOT_MEMBER)
        with self.assertRaises(CrucibleError) as no_boundary:
            create_approved_backup(self.db, source_identity=IDENTITY,
                                   manifest_id=manifest["manifest_id"], state_digest=DIGEST,
                                   artifact_digest=DIGEST, schema_digest=DIGEST,
                                   included=["ciph_missions"], encryption_identity="gpg:aes256",
                                   consistency_boundary="  ", passphrase=self.passphrase, now=T1)
        self.assertEqual(no_boundary.exception.reason, "BACKUP_REQUIRES_AN_EXPLICIT_CONSISTENCY_BOUNDARY")

    def test_the_approved_backup_actually_excludes_root_material(self):
        created = self.backup()
        self.assertEqual(created.status, CREATED)
        self.assertNotIn("ciph.key", created.included)
        self.assertIn("ciph.key", created.excluded)
        for name in ("ciph.key", "quantum.key", "root_secret"):
            self.assertNotIn(name, created.included)
        self.assertEqual(len(str(self.passphrase)) >= MINIMUM_PASSPHRASE_LENGTH, True)

    def test_an_armed_dead_man_state_does_not_survive_recovery(self):
        from dead_mans_switch import DeadMansSwitch, DestructionRefused
        self.identity_and_root()

        class Vault:
            pass

        backend = DeadMansSwitch(Vault())
        with self.assertRaises(DestructionRefused) as unauthorized:
            backend._emergency_destruct()
        self.assertEqual(unauthorized.exception.reason,
                         "DESTRUCTION_REQUIRES_AN_OPERATOR_AUTHORIZATION")
        with self.assertRaises(DestructionRefused):
            backend.authorize_destruction(actor="node:N-A", evidence_ref="EVD-1")
        armed = arm_destruction(self.db, actor="operator:operator", evidence_ref="OPERATOR-ORDER-1",
                                now=T1)
        self.assertTrue(armed["armed"])
        after_recovery = destruction_state_after_recovery(self.db)
        self.assertTrue(after_recovery["historical_armed_state_present"])
        self.assertFalse(after_recovery["armed_after_recovery"])
        self.assertEqual(after_recovery["policy_version"], "DESTRUCTION_POLICY_V1")
        self.assertIn("separate operator authorization", after_recovery["rearm_requires"])
        disarmed = disarm_destruction(self.db, actor="operator:operator", now=T1 + 1)
        self.assertFalse(disarmed["armed"])

    def test_r12_census_is_clean_and_each_zero_fires_on_a_synthetic_violation(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 19)
        real = dict(production_sources())
        rogue = "ciph/kernel/sovereignty_rogue.py"
        cases = [
            (backup_activation_paths, "def go(db):\n    return activate_from_backup(db)\n"),
            (clone_authority_claims, "def go(clone):\n    return clone_is_production(clone)\n"),
            (wall_clock_recovery_selection,
             "def pick(sets):\n    return latest_backup_wins(sets)\n"),
            (host_identity_dependencies, "def who():\n    return socket.gethostname()\n"),
            (destruction_state_restorable,
             "def restore(db):\n    return restore_wipe_state(db)\n"),
        ]
        for predicate, body in cases:
            with self.subTest(predicate=predicate.__name__):
                found = predicate(sources=list({**real, rogue: body}.items()))
                self.assertTrue(found, f"{predicate.__name__} did not fire on its own violation")

    def test_r12_destruction_policy_ownership_is_explicit(self):
        self.assertEqual(destruction_policy(self.db)["default"], "DISARMED")
        with self.assertRaises(CrucibleError) as refused:
            arm_destruction(self.db, actor="daemon:curiosity", evidence_ref="E")
        self.assertIn("OPERATOR", refused.exception.reason)


class TestSovereignIdentity(SovereigntyTestCase):

    def test_identity_is_established_by_an_operator_and_carries_lineage(self):
        with self.assertRaises(CrucibleError):
            establish_identity(self.db, ciph_identity_id=IDENTITY, vault_identity_ref="V",
                               constitutional_root_digest=DIGEST, recovery_policy_id="P",
                               actor="node:N-A", now=T1)
        first = self.identity_and_root()
        self.assertEqual(first.identity_generation, 1)
        self.assertIsNone(first.predecessor_identity_digest)
        self.assertEqual(first.authorized_root_key_refs, ("root-1",))
        self.assertEqual(identity(self.db).ciph_identity_id, IDENTITY)
        self.assertEqual(len(identity_history(self.db)), 1)
        self.assertTrue(sovereign_identity_digest(self.db))

    def test_a_copy_without_the_expected_identity_is_not_this_ciph(self):
        self.identity_and_root()
        assert_identity_continuity(self.db, expected_identity_id=IDENTITY,
                                   expected_vault_ref="VAULT-0E79C7AFD84740BB")
        with self.assertRaises(CrucibleError) as wrong_identity:
            assert_identity_continuity(self.db, expected_identity_id="SOME-OTHER-CIPH")
        self.assertEqual(wrong_identity.exception.reason, "SOVEREIGN_IDENTITY_MISMATCH")
        with self.assertRaises(CrucibleError) as wrong_vault:
            assert_identity_continuity(self.db, expected_identity_id=IDENTITY,
                                       expected_vault_ref="VAULT-SOMETHING-ELSE")
        self.assertEqual(wrong_vault.exception.reason, "SOVEREIGN_IDENTITY_MISMATCH")

    def test_missing_root_material_is_unrecoverable_and_invents_no_identity(self):
        self.identity_and_root(keys=("root-1",))
        revoke_root_key(self.db, "root-1", actor="operator:operator", reason="lost in the fire", now=T1)
        assessment = assess_recoverability(self.db, required_root_key_refs=["root-1"])
        self.assertEqual(assessment["status"], KEY_UNRECOVERABLE)
        self.assertEqual(assessment["missing_root_key_refs"], ["root-1"])
        self.assertFalse(assessment["replacement_identity_created"])
        self.assertEqual(assess_recoverability(self.db)["status"], RECOVERY_REQUIRES_OPERATOR)
        self.assertEqual(len(identity_history(self.db)), 1,
                         "an unavailable root does not create a second identity")


class TestRecoveryManifest(SovereigntyTestCase):

    def test_every_family_is_classified_into_a_disposition(self):
        self.assertGreaterEqual(len(requirements()), 25)
        for disposition in (MUST_RESTORE, MAY_REBUILD, MUST_NOT_COPY, RECONCILE_BEFORE_USE,
                            SPECIAL_CUSTODY):
            self.assertTrue(families_with(disposition), disposition)
        for family in ("missions", "epistemic_ledger", "crucible_history", "evolution_epochs",
                       "federation_authority", "vault_identity", "pid_and_runtime_state",
                       "deadman_configuration", "model_configuration"):
            self.assertTrue(requirements(family)["disposition"])
        with self.assertRaises(CrucibleError):
            requirements("nobody_classified_this")

    def test_manifest_integrity_binds_the_requirements_themselves(self):
        self.identity_and_root()
        manifest = self.manifest()
        self.assertEqual(verify_manifest(self.db, manifest["manifest_id"],
                                        present_families=["missions", "epistemic_ledger",
                                                          "evolution_epochs",
                                                          "federation_authority"],
                                        observed_artifacts={"vault": DIGEST})["status"], COMPLETE)
        incomplete = verify_manifest(self.db, manifest["manifest_id"], present_families=["missions"])
        self.assertEqual(incomplete["status"], "INCOMPLETE")
        self.assertIn("epistemic_ledger", incomplete["missing_families"])
        import sqlite3
        connection = sqlite3.connect(self.db)
        connection.execute("UPDATE ciph_recovery_manifests SET required_state_families_json = ? "
                           "WHERE manifest_id = ?;",
                           (json.dumps(["missions"]), manifest["manifest_id"]))
        connection.commit()
        connection.close()
        self.assertEqual(verify_manifest(self.db, manifest["manifest_id"])["status"], MANIFEST_TAMPERED)
        self.assertTrue(manifest_digest(self.db))


class TestBackupConstitution(SovereigntyTestCase):

    def test_created_is_not_verified_and_verified_is_not_authorized(self):
        self.identity_and_root()
        created = self.backup()
        self.assertEqual(created.status, CREATED)
        with self.assertRaises(CrucibleError) as not_verified:
            authorize_for_recovery(self.db, created.backup_id, actor="operator:operator",
                                   evidence_ref="EVD-1", now=T1)
        self.assertEqual(not_verified.exception.reason, REASON_NOT_VERIFIED)
        verified = verify_backup(self.db, created.backup_id, observed_state_digest=DIGEST,
                                 observed_artifact_digest=DIGEST,
                                 present_families=["missions", "epistemic_ledger",
                                                   "evolution_epochs", "federation_authority"],
                                 observed_artifacts={"vault": DIGEST}, now=T1 + 1)
        self.assertEqual(verified["status"], VERIFIED)
        self.assertTrue(verified["verified"])
        self.assertEqual(cannot_activate_itself(self.db, created.backup_id)["activation_authority"],
                         "none")
        authorization = authorize_for_recovery(self.db, created.backup_id, actor="operator:operator",
                                              evidence_ref="OPERATOR-DECISION-1", now=T1 + 2)
        self.assertTrue(authorization["authorized_for_recovery"])
        self.assertFalse(authorization["authorized_for_activation"])

    def test_corruption_and_incompleteness_are_distinguished(self):
        self.identity_and_root()
        created = self.backup()
        corrupted = verify_backup(self.db, created.backup_id, observed_state_digest="f" * 64,
                                  observed_artifact_digest=DIGEST, now=T1 + 1)
        self.assertEqual(corrupted["status"], CORRUPTED)
        self.assertFalse(corrupted["verified"])
        second = self.backup(included=("ciph_missions",))
        incomplete = verify_backup(self.db, second.backup_id, observed_state_digest=DIGEST,
                                   observed_artifact_digest=DIGEST, present_families=["missions"],
                                   observed_artifacts={"vault": DIGEST}, now=T1 + 2)
        self.assertEqual(incomplete["status"], INCOMPLETE)
        self.assertIn("epistemic_ledger", incomplete["missing_families"])
        self.assertEqual(len(backup_sets(self.db)), 2)
        self.assertTrue(backup_digest(self.db))

    def test_a_historical_archive_is_never_promoted_by_the_improvement(self):
        legacy = classify_historical_backup(contains_root_material=True, used_default_passphrase=True,
                                            integrity_proof=False,
                                            consistency_boundary_declared=False)
        self.assertEqual(legacy["classification"], INSECURE_HISTORICAL)
        self.assertFalse(legacy["approved_for_restore"])
        unknown = classify_historical_backup(contains_root_material=False, used_default_passphrase=False,
                                             integrity_proof=False,
                                             consistency_boundary_declared=True)
        self.assertEqual(unknown["classification"], UNKNOWN_PROTECTION)
        approved = classify_historical_backup(contains_root_material=False,
                                              used_default_passphrase=False, integrity_proof=True,
                                              consistency_boundary_declared=True)
        self.assertEqual(approved["classification"], APPROVED)
        self.assertTrue(approved["approved_for_restore"])


class TestRecoveryLifecycle(SovereigntyTestCase):

    def prepared_backup(self):
        self.identity_and_root()
        manifest = self.manifest()
        created = self.backup(manifest)
        verify_backup(self.db, created.backup_id, observed_state_digest=DIGEST,
                      observed_artifact_digest=DIGEST,
                      present_families=["missions", "epistemic_ledger", "evolution_epochs",
                                        "federation_authority"],
                      observed_artifacts={"vault": DIGEST}, now=T1 + 1)
        authorize_for_recovery(self.db, created.backup_id, actor="operator:operator",
                               evidence_ref="OPERATOR-DECISION-1", now=T1 + 2)
        return created

    def run_to_ready(self):
        created = self.prepared_backup()
        run = begin_recovery(self.db, backup_id=created.backup_id, source_identity=IDENTITY,
                             target_environment_digest="CLEAN-HOST-2", now=T1 + 3)
        self.assertEqual(run.status, RESTORE_STARTED)
        advance(self.db, run.run_id, IDENTITY_VERIFIED, evidence={"ciph_identity_id": IDENTITY},
                now=T1 + 4)
        advance(self.db, run.run_id, STATE_VERIFIED,
                evidence={"present_families": ["missions", "epistemic_ledger", "evolution_epochs",
                                               "federation_authority"]}, now=T1 + 5)
        advance(self.db, run.run_id, RECONCILED, evidence={"reconciliation_conflicts": 0}, now=T1 + 6)
        advance(self.db, run.run_id, ENVIRONMENT_ATTESTED,
                evidence={"environment_digest": "CLEAN-HOST-2"}, now=T1 + 7)
        advance(self.db, run.run_id, "READY", evidence={"required_root_key_refs": ["root-1"]},
                now=T1 + 8)
        return get_run(self.db, run.run_id)

    def test_the_full_lifecycle_activates_only_with_authorization_and_a_fence(self):
        run = self.run_to_ready()
        self.assertEqual(run.status, "READY")
        self.assertEqual(run.history[0], RESTORE_STARTED)
        held = advance(self.db, run.run_id, AUTHORIZED_ACTIVATION,
                       evidence={"operator_authorization": "operator:operator",
                                 "fencing_disposition": UNFENCED}, now=T1 + 9)
        self.assertEqual(held.status, RECOVERY_ACTIVATION_HOLD)
        self.assertEqual(activation_history(self.db), [], "a held recovery activated nothing")
        # The hold resumes the honest way: the operator supplies a fence, and the run proceeds.
        resume_evidence = {"operator_authorization": "operator:operator",
                           "fencing_disposition": SUPERSEDED,
                           "fencing_evidence_ref": "OLD-HOST-WIPED-LOG-1"}
        resumed = advance(self.db, run.run_id, AUTHORIZED_ACTIVATION, evidence=resume_evidence,
                          now=T1 + 10)
        self.assertEqual(resumed.status, AUTHORIZED_ACTIVATION)
        resumption = advance(self.db, run.run_id, ACTIVATED, evidence=resume_evidence, now=T1 + 11)
        self.assertEqual(resumption.status, ACTIVATED)
        self.assertEqual(activation_history(self.db)[0]["ciph_identity_id"], IDENTITY)
        self.assertTrue(recovery_digest(self.db))

    def test_missing_root_material_stops_the_lifecycle_honestly(self):
        created = self.prepared_backup()
        revoke_root_key(self.db, "root-1", actor="operator:operator", reason="lost", now=T1 + 3)
        run = begin_recovery(self.db, backup_id=created.backup_id, source_identity=IDENTITY,
                             target_environment_digest="CLEAN-HOST-2", now=T1 + 4)
        advance(self.db, run.run_id, IDENTITY_VERIFIED, evidence={"ciph_identity_id": IDENTITY},
                now=T1 + 5)
        advance(self.db, run.run_id, STATE_VERIFIED,
                evidence={"present_families": ["missions", "epistemic_ledger", "evolution_epochs",
                                               "federation_authority"]}, now=T1 + 6)
        advance(self.db, run.run_id, RECONCILED, now=T1 + 7)
        advance(self.db, run.run_id, ENVIRONMENT_ATTESTED,
                evidence={"environment_digest": "CLEAN-HOST-2"}, now=T1 + 8)
        stopped = advance(self.db, run.run_id, "READY", evidence={"required_root_key_refs": ["root-1"]},
                          now=T1 + 9)
        self.assertEqual(stopped.status, UNRECOVERABLE)
        self.assertEqual(activation_history(self.db), [])

    def test_a_clone_has_no_standing_and_no_path_to_it(self):
        self.identity_and_root()
        clone = register_clone(self.db, source_identity=IDENTITY, purpose="disaster drill",
                               now=T1)
        self.assertEqual(clone["standing"], "NONE")
        self.assertEqual(clone["production_authority"], "none")
        refusal = assert_no_standing(self.db, clone["clone_id"])
        self.assertFalse(refusal["may_activate"])
        self.assertIn("copy, not a continuation", refusal["reason"])
        self.assertEqual(len(clone_registry(self.db)), 1)
        self.assertEqual(activation_history(self.db), [], "a clone activated nothing")

    def test_an_invalid_transition_is_refused(self):
        run = self.run_to_ready()
        with self.assertRaises(CrucibleError) as illegal:
            advance(self.db, run.run_id, ACTIVATED, evidence={}, now=T1 + 9)
        self.assertEqual(illegal.exception.reason, "ILLEGAL_RECOVERY_TRANSITION")
        self.assertEqual(len(LIFECYCLE), 8)

    def test_recovery_state_reconstructs_in_a_fresh_process(self):
        self.run_to_ready()
        expected = recovery_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.recovery_state import recovery_digest;"
                "from ciph.kernel.sovereign_identity import sovereign_identity_digest;"
                "print(json.dumps({'recovery': recovery_digest(%r), 'identity': "
                "sovereign_identity_digest(%r)}, sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        recovered = json.loads(out.stdout.strip())
        self.assertEqual(recovered["recovery"], expected)
        self.assertEqual(recovered["identity"], sovereign_identity_digest(self.db))


if __name__ == "__main__":
    unittest.main()
