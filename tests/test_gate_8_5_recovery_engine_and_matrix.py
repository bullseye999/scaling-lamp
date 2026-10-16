"""
8.4-8.11 - the recovery engine, the portable/independent concerns, and the catastrophic matrix.

    A recovery that creates two authoritative Ciphers is worse than an honest recovery refusal.

The specimens that matter most here are the NEGATIVE ones: a valid backup with no enforceable fence must
end in RECOVERY_ACTIVATION_HOLD, and absent root material must end in UNRECOVERABLE with no invented
identity. Both are successful constitutional outcomes and are asserted as such.
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.backup_constitution import (VERIFIED, authorize_for_recovery, create_approved_backup,
                                             verify_backup)
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.evolution_ownership import production_sources
from ciph.kernel.federation_authority import (INTEGRITY_CONFLICT, assert_authoritative, get_domain,
                                              open_domain)
from ciph.kernel.federation_node import attest_node, current_generation, register_node
from ciph.kernel.federation_reconstitution import reconstitute_node, reconstitutions
from ciph.kernel.real_transport import register_transport_key, revoke_transport_key, key_state
from ciph.kernel.recovery_engine import (ACTIVATED, FENCE_NODE_CREDENTIALS_REVOKED, HOLD,
                                         REFUSED, REASON_AUTH_CANDIDATE, REASON_AUTH_ENVIRONMENT,
                                         REASON_AUTH_EXPIRED, REASON_AUTH_GENERATION,
                                         REASON_AUTH_IDENTITY, REASON_AUTH_LABEL, REASON_AUTH_REVOKED,
                                         REASON_AUTH_SCOPE, SCOPE_INSPECT, SCOPE_RESUME, UNRECOVERABLE,
                                         engine_digest, fence_is_enforceable,
                                         issue_recovery_authorization, last_proven_restore,
                                         record_fence, recovery_permissions, recover,
                                         revoke_recovery_authorization, verify_recovery_authorization)
from ciph.kernel.recovery_manifest import build_manifest
from ciph.kernel.recovery_state import clone_registry, register_clone, assert_no_standing
from ciph.kernel.sovereign_identity import (RECOVERABLE, RECOVERY_REQUIRES_OPERATOR,
                                            assess_recoverability, establish_identity, identity,
                                            register_root_key, revoke_root_key)
from ciph.kernel.sovereignty_monitoring import (HEALTHY, UNPROVEN, sovereignty_health,
                                                health_digest)
from ciph.kernel.sovereignty_portability import (MIGRATION_APPLIED, MIGRATION_FAILED,
                                                 MIGRATION_UNSUPPORTED, REQUIRED_ENV, apply_migration,
                                                 build_migration_plan, classify_environment_dependency,
                                                 portability_report, substitute_model,
                                                 model_substitutions, accidental_dependencies)
from ciph.kernel.sovereignty_scanners import SOVEREIGNTY_SCANNERS, sovereignty_scanner_census

T1 = 1_800_000_000.0
DIGEST = "c" * 64
IDENTITY = "CIPH-IDENTITY-1"
ENVIRONMENT = "CLEAN-HOST-2"
FAMILIES = ["missions", "epistemic_ledger", "evolution_epochs", "federation_authority"]
PASSPHRASE = "a-real-passphrase-for-the-backup"


class RecoveryTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-85-")
        self.db = str(Path(self.temp.name) / "recovered.db")

    def tearDown(self):
        self.temp.cleanup()

    def identity_and_root(self, keys=("root-1",)):
        for key_ref in keys:
            register_root_key(self.db, key_ref=key_ref, actor="operator:operator", now=T1)
        establish_identity(self.db, ciph_identity_id=IDENTITY, vault_identity_ref="VAULT-X",
                           constitutional_root_digest=DIGEST,
                           recovery_policy_id="RECOVERY_POLICY_V1",
                           authorized_root_key_refs=list(keys), node_identity_root_refs=["N-A"],
                           actor="operator:operator", now=T1)

    def verified_backup(self):
        manifest = build_manifest(self.db, ciph_identity_id=IDENTITY,
                                  constitutional_versions=["4.0", "5.0", "6.0", "7.0", "8.0"],
                                  required_state_families=FAMILIES,
                                  required_artifact_digests={"vault": DIGEST},
                                  schema_versions={"ciph_missions": "S3"},
                                  created_from_canonical_state_digest=DIGEST, now=T1)
        backup = create_approved_backup(self.db, source_identity=IDENTITY,
                                        manifest_id=manifest["manifest_id"], state_digest=DIGEST,
                                        artifact_digest=DIGEST, schema_digest=DIGEST,
                                        included=["ciph_missions"], excluded=["ciph.key", "*.pid"],
                                        encryption_identity="gpg:aes256",
                                        consistency_boundary=f"sqlite-snapshot@{int(T1)}",
                                        passphrase=PASSPHRASE, now=T1)
        verify_backup(self.db, backup.backup_id, observed_state_digest=DIGEST,
                      observed_artifact_digest=DIGEST, present_families=FAMILIES,
                      observed_artifacts={"vault": DIGEST}, now=T1 + 1)
        authorize_for_recovery(self.db, backup.backup_id, actor="operator:operator",
                               evidence_ref="OPERATOR-DECISION-1", now=T1 + 2)
        return backup

    def enforceable_fence(self, *, run_id="RUN-1"):
        """A fence is enforceable when the revocation it names is REALLY in an execution store."""
        connection = sqlite3.connect(self.db)
        connection.execute("CREATE TABLE IF NOT EXISTS ciph_execution_permits (permit_id TEXT, "
                           "revoked_at REAL, revocation_generation TEXT);")
        connection.execute("INSERT INTO ciph_execution_permits VALUES ('P-1', ?, 'GEN-7');",
                           (T1 + 3,))
        connection.commit()
        connection.close()
        record_transport_key = register_transport_key(self.db, node_id="N-A", node_generation=1,
                                                      key_ref="tk-old", actor="operator:operator", now=T1)
        revoke_transport_key(self.db, "tk-old", actor="operator:operator", reason="host retired", now=T1 + 4)
        return record_fence(self.db, run_id=run_id, kind=FENCE_NODE_CREDENTIALS_REVOKED,
                            authority_ref="tk-old", evidence_ref="HOST-RETIRED-1",
                            actor="operator:operator", now=T1 + 5)

    def run_recovery(self, *, authorization=None, fence_id=None, required_scope=SCOPE_RESUME,
                     root_keys=("root-1",), backup=None):
        backup = backup or self.verified_backup()
        if authorization is None:
            authorization = issue_recovery_authorization(
                self.db, ciph_identity_id=IDENTITY, backup_id=backup.backup_id,
                target_environment_digest=ENVIRONMENT, scope=SCOPE_RESUME, actor="operator:operator",
                evidence_ref="OPERATOR-DECISION-2", now=T1 + 6)
        return recover(self.db, backup_id=backup.backup_id, source_identity=IDENTITY,
                       target_environment_digest=ENVIRONMENT, ciph_identity_id=IDENTITY,
                       present_families=FAMILIES, observed_artifacts={"vault": DIGEST},
                       required_root_key_refs=list(root_keys), authorization=authorization,
                       fence_id=fence_id, required_scope=required_scope, now=T1 + 7)


class TestAuthorization(RecoveryTestCase):

    def test_a_string_label_is_not_an_authorization(self):
        self.identity_and_root()
        backup = self.verified_backup()
        for label in ("operator:approved", "APPROVED", {"note": "please"}):
            with self.subTest(label=str(label)):
                outcome = self.run_recovery(authorization=label, backup=backup)
                self.assertFalse(outcome.activated)
                self.assertEqual(outcome.status, REFUSED)
                self.assertEqual(outcome.reason, REASON_AUTH_LABEL)
        # An ABSENT authorization is refused the same way (called directly, because the helper would
        # otherwise supply a valid grant and quietly prove the opposite).
        missing = recover(self.db, backup_id=backup.backup_id, source_identity=IDENTITY,
                          target_environment_digest=ENVIRONMENT, ciph_identity_id=IDENTITY,
                          present_families=FAMILIES, observed_artifacts={"vault": DIGEST},
                          required_root_key_refs=["root-1"], authorization=None, fence_id=None,
                          now=T1 + 7)
        self.assertEqual(missing.status, REFUSED)
        self.assertEqual(missing.reason, REASON_AUTH_LABEL)

    def test_every_authorization_failure_has_its_own_refusal(self):
        self.identity_and_root()
        backup = self.verified_backup()
        grant = issue_recovery_authorization(self.db, ciph_identity_id=IDENTITY,
                                            backup_id=backup.backup_id,
                                            target_environment_digest=ENVIRONMENT,
                                            scope=SCOPE_RESUME, actor="operator:operator",
                                            evidence_ref="EVD-1", valid_until=T1 + 100, now=T1 + 6)
        probes = [
            ({"ciph_identity_id": "OTHER"}, REASON_AUTH_IDENTITY),
            ({"backup_id": "BS-OTHER"}, REASON_AUTH_CANDIDATE),
            ({"target_environment_digest": "OTHER-HOST"}, REASON_AUTH_ENVIRONMENT),
        ]
        for override, expected in probes:
            with self.subTest(reason=expected):
                arguments = {"ciph_identity_id": IDENTITY, "backup_id": backup.backup_id,
                             "target_environment_digest": ENVIRONMENT, "required_scope": SCOPE_RESUME,
                             "now": T1 + 7, "authorization": grant}
                arguments.update(override)
                verdict = verify_recovery_authorization(self.db, **arguments)
                self.assertFalse(verdict["verified"])
                self.assertEqual(verdict["reason"], expected)
        scope = verify_recovery_authorization(self.db, authorization=grant,
                                             ciph_identity_id=IDENTITY, backup_id=backup.backup_id,
                                             target_environment_digest=ENVIRONMENT,
                                             required_scope=SCOPE_INSPECT, now=T1 + 7)
        self.assertTrue(scope["verified"], "an inspect grant satisfies an inspect requirement")
        expired = verify_recovery_authorization(self.db, authorization=grant,
                                                ciph_identity_id=IDENTITY, backup_id=backup.backup_id,
                                                target_environment_digest=ENVIRONMENT,
                                                required_scope=SCOPE_RESUME, now=T1 + 1000)
        self.assertEqual(expired["reason"], REASON_AUTH_EXPIRED)
        revoke_recovery_authorization(self.db, grant["authorization_id"], actor="operator:operator",
                                      reason="superseded", now=T1 + 8)
        self.assertEqual(verify_recovery_authorization(
            self.db, authorization=grant, ciph_identity_id=IDENTITY, backup_id=backup.backup_id,
            target_environment_digest=ENVIRONMENT, required_scope=SCOPE_RESUME,
            now=T1 + 9)["reason"], REASON_AUTH_REVOKED)
        # A NEWER, UNREVOKED grant makes the older one a replayed generation (rather than merely a
        # revoked one): the same request was re-issued, so the stale one cannot be replayed.
        stale = issue_recovery_authorization(self.db, ciph_identity_id=IDENTITY,
                                             backup_id=backup.backup_id,
                                             target_environment_digest="THIRD-HOST",
                                             scope=SCOPE_RESUME, actor="operator:operator",
                                             evidence_ref="EVD-2", now=T1 + 10)
        issue_recovery_authorization(self.db, ciph_identity_id=IDENTITY, backup_id=backup.backup_id,
                                     target_environment_digest="THIRD-HOST", scope=SCOPE_RESUME,
                                     actor="operator:operator", evidence_ref="EVD-3", now=T1 + 11)
        self.assertEqual(verify_recovery_authorization(
            self.db, authorization=stale, ciph_identity_id=IDENTITY, backup_id=backup.backup_id,
            target_environment_digest="THIRD-HOST", required_scope=SCOPE_RESUME,
            now=T1 + 12)["reason"], REASON_AUTH_GENERATION)


class TestRecoveryEngine(RecoveryTestCase):

    def test_enforceable_fencing_distinguishes_evidence_from_assertion(self):
        self.identity_and_root()
        self.enforceable_fence()
        assertion = record_fence(self.db, run_id="RUN-2", kind=FENCE_NODE_CREDENTIALS_REVOKED,
                                 authority_ref="tk-never-revoked", evidence_ref="WE-BELIEVE-SO",
                                 actor="operator:operator", now=T1 + 6)
        self.assertFalse(fence_is_enforceable(self.db, assertion["fence_id"])["enforceable"])
        enforced = record_fence(self.db, run_id="RUN-3", kind=FENCE_NODE_CREDENTIALS_REVOKED,
                                authority_ref="tk-old", evidence_ref="HOST-RETIRED-1",
                                actor="operator:operator", now=T1 + 7)
        self.assertTrue(fence_is_enforceable(self.db, enforced["fence_id"])["enforceable"])

    def test_the_full_path_activates_only_with_authorization_and_a_real_fence(self):
        self.identity_and_root()
        fence = self.enforceable_fence()
        outcome = self.run_recovery(fence_id=fence["fence_id"])
        self.assertTrue(outcome.activated)
        self.assertEqual(outcome.status, ACTIVATED)
        stages = [stage["stage"] for stage in outcome.stages]
        for expected in ("IDENTITY_VERIFIED", "BACKUP_VERIFIED", "MANIFEST_VERIFIED",
                         "EPHEMERAL_INVALIDATED_AND_REATTESTED", "READY", "AUTHORIZATION_VERIFIED",
                         "FENCING_CHECKED", "ACTIVATED"):
            self.assertIn(expected, stages)
        self.assertTrue(recovery_permissions("READY")["may_inspect_and_reconstruct"])
        self.assertFalse(recovery_permissions("READY")["may_resume_external_execution"],
                         "READY is not ACTIVATED")
        self.assertTrue(recovery_permissions(ACTIVATED)["may_resume_external_execution"])
        self.assertIsNotNone(last_proven_restore(self.db))
        self.assertTrue(engine_digest(self.db))

    def test_a_valid_candidate_without_enforceable_fencing_is_held(self):
        self.identity_and_root()
        outcome = self.run_recovery(fence_id=None)
        self.assertFalse(outcome.activated)
        self.assertEqual(outcome.status, HOLD)
        self.assertIn("FENCING", outcome.reason)
        self.assertIsNone(last_proven_restore(self.db))

    def test_a_fence_that_cannot_be_enforced_is_also_held(self):
        self.identity_and_root()
        self.enforceable_fence()
        bogus = record_fence(self.db, run_id="RUN-9", kind=FENCE_NODE_CREDENTIALS_REVOKED,
                             authority_ref="tk-imaginary", evidence_ref="TRUST-ME",
                             actor="operator:operator", now=T1 + 6)
        outcome = self.run_recovery(fence_id=bogus["fence_id"])
        self.assertEqual(outcome.status, HOLD)
        self.assertFalse(outcome.activated)

    def test_missing_root_material_is_unrecoverable_and_invents_nothing(self):
        self.identity_and_root()
        fence = self.enforceable_fence()
        revoke_root_key(self.db, "root-1", actor="operator:operator", reason="lost", now=T1 + 5)
        before = identity(self.db).as_dict() if hasattr(identity(self.db), "as_dict") else None
        outcome = self.run_recovery(fence_id=fence["fence_id"])
        self.assertEqual(outcome.status, UNRECOVERABLE)
        self.assertFalse(outcome.activated)
        self.assertIsNone(last_proven_restore(self.db))
        assessment = assess_recoverability(self.db, required_root_key_refs=["root-1"])
        self.assertEqual(assessment["status"], UNRECOVERABLE)
        self.assertFalse(assessment["replacement_identity_created"])
        self.assertEqual(identity(self.db).ciph_identity_id, IDENTITY,
                         "no replacement identity was created")

    def test_a_clone_of_the_same_bytes_has_no_standing(self):
        self.identity_and_root()
        fence = self.enforceable_fence()
        self.run_recovery(fence_id=fence["fence_id"])
        clone = register_clone(self.db, source_identity=IDENTITY, purpose="disaster drill", now=T1 + 9)
        self.assertEqual(clone["standing"], "NONE")
        self.assertFalse(assert_no_standing(self.db, clone["clone_id"])["may_activate"])
        self.assertEqual(len(clone_registry(self.db)), 1)
        self.assertEqual(len([proof for proof in [last_proven_restore(self.db)] if proof]), 1,
                         "one activation exists, and it is the RESTORE's, not the clone's")


class TestIndependentConcerns(RecoveryTestCase):

    def test_reconstitution_refuses_stale_authority_and_reconciles_evidence(self):
        for store in [self.db]:
            registered = register_node(store, node_id="N-B", public_key_ref="pub-N-B",
                                       code_digest="code-1", environment_digest="env-1",
                                       actor="operator:operator", now=T1)
            attest_node(store, "N-B", registered.node_generation, observed_code_digest="code-1",
                        observed_environment_digest="env-1", observed_public_key_ref="pub-N-B",
                        actor="operator:operator", now=T1)
            owner = register_node(store, node_id="N-A", public_key_ref="pub-N-A", code_digest="code-1",
                                  environment_digest="env-1", actor="operator:operator", now=T1)
            attest_node(store, "N-A", owner.node_generation, observed_code_digest="code-1",
                        observed_environment_digest="env-1", observed_public_key_ref="pub-N-A",
                        actor="operator:operator", now=T1)
        open_domain(self.db, domain_id="D-1", scope="core", owner_node_id="N-A",
                    permitted_transitions=["PROMOTE"], actor="operator:operator", now=T1)
        # Advance the lineage: N-A is now at epoch 3 (a governed transfer out and back).
        from ciph.kernel.federation_authority import transfer_domain
        transfer_domain(self.db, "D-1", to_node_id="N-B", to_generation=1, actor="operator:operator",
                        evidence_ref="E-1", expected_epoch=1, now=T1 + 1)
        transfer_domain(self.db, "D-1", to_node_id="N-A", to_generation=1, actor="operator:operator",
                        evidence_ref="E-2", expected_epoch=2, now=T1 + 2)
        self.assertEqual(get_domain(self.db, "D-1").authority_epoch, 3)
        report = reconstitute_node(self.db, node_id="N-A", restored_from="BACKUP-EPOCH-1",
                                  backup_epoch=1, current_epoch=3,
                                  observed_code_digest="code-1", observed_environment_digest="env-1",
                                  actor="operator:operator",
                                  historical_evidence=[{"family": "epistemic_evidence",
                                                        "canonical_id": "OBS-1",
                                                        "payload_digest": "d" * 64,
                                                        "authority_epoch": 1, "sequence": 1}],
                                  now=T1 + 3)
        # The restored node's OLD ownership claim (epoch 1) must be refused, and that refusal is a
        # SUCCESS: the lineage moved to epoch 3 while it was gone.
        self.assertEqual(report["status"], "STALE_AUTHORITY_REFUSED")
        self.assertTrue(report["stale_authority_refused"])
        self.assertEqual(report["stale_authority_refused"][0]["claimed_epoch"], 1)
        self.assertEqual(report["stale_authority_refused"][0]["lineage_epoch"], 3)
        self.assertEqual(report["new_generation"], 2)
        self.assertFalse(report["authority_gained"])
        # The node's historical ownership is ORPHANED by the generation bump, and recovery does not
        # silently restore it - a governed transfer is the sanctioned path back to authority.
        self.assertTrue(report["authority_orphaned"])
        self.assertEqual(report["authority_orphaned"][0]["lineage_generation"], 1)
        self.assertEqual(report["authority_orphaned"][0]["restored_generation"], 2)
        self.assertIn("EPISTEMIC" if False else "MERGED",
                      [item["disposition"] for item in report["reconciled_evidence"]])
        self.assertEqual(len(reconstitutions(self.db)), 1)
        from ciph.kernel.federation_authority import transfer_domain
        with self.assertRaises(CrucibleError):
            assert_authoritative(self.db, "D-1", node_id="N-A", generation=2, epoch=3)
        # The governed path: an operator re-establishes ownership under the new generation.
        restored = transfer_domain(self.db, "D-1", to_node_id="N-A", to_generation=2,
                                   actor="operator:operator", evidence_ref="RECONSTITUTION-1",
                                   expected_epoch=3, now=T1 + 4)
        self.assertEqual(restored.authority_epoch, 4)
        assert_authoritative(self.db, "D-1", node_id="N-A", generation=2, epoch=4)

    def test_host_and_path_change_do_not_change_identity(self):
        self.identity_and_root()
        before = identity(self.db).ciph_identity_id
        report = portability_report(host="other-host", path="/srv/ciph", node_id="N-A",
                                    identity_id=before)
        self.assertFalse(report["identity_depends_on_host"])
        self.assertFalse(report["identity_depends_on_path"])
        self.assertEqual(identity(self.db).ciph_identity_id, before)
        self.assertEqual(classify_environment_dependency("python", "3.10")["classification"],
                         REQUIRED_ENV)
        self.assertEqual(classify_environment_dependency(
            "data_directory", "/home/user/ciph_project")["classification"],
            "ACCIDENTAL_INSTALLATION_DEPENDENCY")
        self.assertIsInstance(accidental_dependencies(sources=[("x.py", "P = '~/x'")]), tuple)

    def test_model_substitution_preserves_identity_and_does_not_carry_capabilities(self):
        self.identity_and_root()
        before = identity(self.db).ciph_identity_id
        substituted = substitute_model(self.db, previous_model="model-a", new_model="model-b",
                                      provider="provider-2", actor="operator:operator", now=T1)
        self.assertTrue(substituted["identity_unchanged"])
        self.assertFalse(substituted["capabilities_carried_over"])
        self.assertTrue(substituted["reverification_required"])
        self.assertEqual(substituted["capability_level_after_substitution"], "INSTALLED")
        with_evidence = substitute_model(self.db, previous_model="model-b", new_model="model-c",
                                         provider="provider-3", actor="operator:operator",
                                         capability_evidence=["CAP-EVIDENCE-1"], now=T1 + 1)
        self.assertEqual(with_evidence["capability_level_after_substitution"], "VERIFIED")
        self.assertEqual(identity(self.db).ciph_identity_id, before)
        self.assertEqual(len(model_substitutions(self.db)), 2)

    def test_migration_lineage_is_ordered_checked_and_fail_closed(self):
        self.identity_and_root()
        plan = build_migration_plan(source_versions={"ciph_missions": "S3", "ciph_observations": "S2"},
                                    target_versions={"ciph_missions": "S3", "ciph_observations": "S2"},
                                    ordered_steps=["add coverage column", "backfill"],
                                    frozen_identities=["META_CORPUS_V1", "CRUCIBLE_PARETO_V1"],
                                    pre_digest=DIGEST)
        applied = apply_migration(self.db, plan, post_digest=DIGEST, now=T1)
        self.assertEqual(applied["status"], MIGRATION_APPLIED)
        self.assertTrue(applied["may_activate"])
        self.assertIn("META_CORPUS_V1", applied["frozen_identities_preserved"])
        failed = apply_migration(self.db, plan, post_digest=None, now=T1 + 1)
        self.assertEqual(failed["status"], MIGRATION_FAILED)
        self.assertFalse(failed["may_activate"])
        unsupported = build_migration_plan(
            source_versions={"ciph_missions": "S3"},
            target_versions={"ciph_missions": "S4", "ciph_new_table": "S1"},
            ordered_steps=["upgrade"], frozen_identities=[], pre_digest=DIGEST)
        refused = apply_migration(self.db, unsupported, post_digest=DIGEST, now=T1 + 2)
        self.assertEqual(refused["status"], MIGRATION_UNSUPPORTED)
        self.assertFalse(refused["may_activate"])

    def test_monitoring_reports_proven_restore_separately_from_backups(self):
        self.identity_and_root()
        backup = self.verified_backup()
        unproven = sovereignty_health(self.db, now=T1 + 3)
        self.assertEqual(unproven["status"], UNPROVEN)
        self.assertIsNone(unproven["last_proven_restore"])
        self.assertEqual(unproven["verified_backup_count"], 1)
        self.assertTrue(unproven["no_score"])
        fence = self.enforceable_fence()
        self.run_recovery(fence_id=fence["fence_id"], backup=backup)
        proven = sovereignty_health(self.db, now=T1 + 8)
        self.assertIsNotNone(proven["last_proven_restore"])
        self.assertEqual(proven["status"], HEALTHY)
        self.assertEqual(proven["proven_restore_count"], 1)
        self.assertTrue(health_digest(self.db))


class TestScannersAndNegativeMatrix(RecoveryTestCase):

    def test_sixteen_scanners_are_zero_and_each_calls_its_own_predicate(self):
        census = sovereignty_scanner_census()
        self.assertEqual(len(census), 16)
        self.assertEqual({name: count for name, count in census.items() if count}, {})
        real = dict(production_sources())
        rogue = "ciph/kernel/sovereignty_rogue.py"
        catches = [
            ("s01_legacy_default_passphrase_backup",
             'import os\np = os.environ.get("BACKUP_PASSPHRASE", "x")\n'),
            ("s02_root_material_as_ordinary_content", 'tar.add("ciph.key", arcname="k")\n'),
            ("s03_backup_activates_production", "def go(db):\n    return activate_from_backup(db)\n"),
            ("s04_restore_bypasses_identity", "def go():\n    return skip_identity_check()\n"),
            ("s05_clone_claims_production_authority", "def go(c):\n    return clone_is_production(c)\n"),
            ("s06_stale_node_retains_ownership",
             "def steal(c):\n    c.execute('UPDATE ciph_federation_authority_domains SET "
             "owner_node_id = 1')\n"),
            ("s07_node_key_as_root", "def go(k):\n    return use_node_key_as_root(k)\n"),
            ("s08_model_or_host_as_identity", "def go(h):\n    return identity_from_hostname(h)\n"),
            ("s09_last_write_wins_recovery", "def pick(s):\n    return latest_backup_wins(s)\n"),
            ("s10_migration_rewrites_frozen_ids", "def go(i):\n    return rewrite_frozen_identity(i)\n"),
            ("s11_unreconciled_permit_resumes", "def go(p):\n    return resume_permit(p)\n"),
            ("s12_recovery_bypasses_r7", "def go(t, b):\n    t.write_bytes(b)\n"),
            ("s13_deadman_state_restored", "def go(db):\n    return restore_wipe_state(db)\n"),
            ("s14_activation_without_fencing", "def go():\n    return skip_fencing()\n"),
            ("s15_incomplete_restore_reported_ready", "def go(r):\n    return force_ready(r)\n"),
            ("s16_second_authority_constitution", "class RecoveryAuthority:\n    pass\n"),
        ]
        self.assertEqual(len(catches), 16)
        for name, body in catches:
            with self.subTest(scanner=name):
                self.assertTrue(dict(SOVEREIGNTY_SCANNERS)[name]({**real, rogue: body}),
                                f"{name} did not fire on its own violation")

    def test_the_negative_matrix_cases_have_explicit_dispositions(self):
        """Every case answers with a named disposition. The two failures are SUCCESSES here."""
        dispositions = {}
        self.identity_and_root()
        backup = self.verified_backup()
        dispositions["valid_backup_unproven_fence"] = self.run_recovery(fence_id=None).status
        fence = self.enforceable_fence()
        dispositions["valid_backup_enforceable_fence"] = self.run_recovery(
            fence_id=fence["fence_id"]).status
        # Order matters: an absent-label refusal must be observed while the root is still in custody,
        # otherwise the run answers UNRECOVERABLE first - correctly, and about a different question.
        dispositions["unauthorized_label"] = self.run_recovery(
            authorization="operator:approved").status
        dispositions["wrong_candidate"] = self.run_recovery(
            authorization={"authorization_id": issue_recovery_authorization(
                self.db, ciph_identity_id=IDENTITY, backup_id=backup.backup_id,
                target_environment_digest="OTHER-HOST", scope=SCOPE_RESUME, actor="operator:operator",
                evidence_ref="E", now=T1 + 10)["authorization_id"]}).status
        revoke_root_key(self.db, "root-1", actor="operator:operator", reason="lost", now=T1 + 9)
        dispositions["missing_recovery_root"] = self.run_recovery(
            fence_id=fence["fence_id"]).status
        self.assertEqual(dispositions["valid_backup_unproven_fence"], HOLD)
        self.assertEqual(dispositions["valid_backup_enforceable_fence"], ACTIVATED)
        self.assertEqual(dispositions["missing_recovery_root"], UNRECOVERABLE)
        self.assertEqual(dispositions["unauthorized_label"], REFUSED)
        self.assertEqual(dispositions["wrong_candidate"], REFUSED)
        self.assertEqual(len(set(dispositions.values())), 4,
                         "the matrix produces distinct, named outcomes")

    def test_recovery_lineage_reconstructs_in_a_fresh_process(self):
        self.identity_and_root()
        fence = self.enforceable_fence()
        self.run_recovery(fence_id=fence["fence_id"])
        bundle = {"engine": engine_digest(self.db), "health": health_digest(self.db),
                  "identity": identity(self.db).ciph_identity_id}
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.recovery_engine import engine_digest;"
                "from ciph.kernel.sovereignty_monitoring import health_digest;"
                "from ciph.kernel.sovereign_identity import identity;"
                "print(json.dumps({'engine': engine_digest(%r), 'health': health_digest(%r), "
                "'identity': identity(%r).ciph_identity_id}, sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.db, self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), bundle)


if __name__ == "__main__":
    unittest.main()
