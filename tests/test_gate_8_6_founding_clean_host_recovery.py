"""
B7 - the founding clean-host recovery.

    Ciph survives the loss of its machine without allowing a copy of its machine to become Ciph
    by accident.

A DISPOSABLE Ciph is built with representative history from the real modules, backed up, and then has
its installation DESTROYED. Its continuation is restored into a clean environment through
`recovery_engine.recover`, activated with an enforceable fence, and then read back from an independent
process.

The fencing proof is the part that must not be theatre: after the fence is recorded, an operation using
the SUPERSEDED instance's own credential is attempted through the real transport boundary and must be
refused. A revocation record that nothing checks is a sentence, not a fence.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.backup_constitution import (authorize_for_recovery, create_approved_backup,
                                             verify_backup)
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.federation_authority import assert_authoritative, get_domain, open_domain
from ciph.kernel.federation_node import attest_node, current_generation, register_node
from ciph.kernel.missions import complete_mission, open_mission, reconstruct_missions
from ciph.kernel.real_transport import (accept_envelope, make_envelope, open_session,
                                        register_transport_key, revoke_transport_key)
from ciph.kernel.recovery_engine import (ACTIVATED, HOLD, SCOPE_RESUME, engine_digest,
                                         fence_is_enforceable, issue_recovery_authorization,
                                         last_proven_restore, recover, record_fence,
                                         FENCE_NODE_CREDENTIALS_REVOKED, FENCE_PERMIT_GENERATION_REVOKED)
from ciph.kernel.recovery_manifest import build_manifest, verify_manifest
from ciph.kernel.recovery_state import assert_no_standing, clone_record, register_clone
from ciph.kernel.sovereign_identity import (RECOVERABLE, assess_recoverability, destruction_policy,
                                            destruction_state_after_recovery, establish_identity,
                                            identity, register_root_key, sovereign_identity_digest)
from ciph.kernel.sovereignty_monitoring import ATTENTION, HEALTHY, sovereignty_health

T1 = 1_800_000_000.0
DIGEST = "c" * 64
IDENTITY = "CIPH-IDENTITY-FOUNDING"
ENVIRONMENT = "CLEAN-HOST-B7"
PASSPHRASE = "a-real-passphrase-for-the-founding-run"
SECRET = "peer-shared-secret-1"


class FoundingRecoveryTest(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-b7-")
        self.base = Path(self.temp.name)
        # The DISPOSABLE installation, and the recovery material kept outside it.
        self.installation = self.base / "installation"
        self.installation.mkdir()
        self.vault = str(self.installation / "ciph_vault.db")
        self.recovery_material = self.base / "recovery_material"
        self.recovery_material.mkdir()
        self.clean = self.base / "clean_host"
        self.clean.mkdir()
        self.restored = str(self.clean / "recovered.db")

    def tearDown(self):
        self.temp.cleanup()

    # ---------------------------------------------------------------- building the disposable Ciph
    def populate(self):
        """Representative history from the REAL modules - not disconnected fixtures."""
        register_root_key(self.vault, key_ref="root-1", actor="operator:operator", now=T1)
        establish_identity(self.vault, ciph_identity_id=IDENTITY, vault_identity_ref="VAULT-DISPOSABLE",
                           constitutional_root_digest=DIGEST,
                           recovery_policy_id="RECOVERY_POLICY_V1",
                           authorized_root_key_refs=["root-1"], node_identity_root_refs=["N-A"],
                           actor="operator:operator", now=T1)
        for node in ("N-A", "N-B"):
            registered = register_node(self.vault, node_id=node, public_key_ref=f"pub-{node}",
                                       code_digest="code-1", environment_digest="env-1",
                                       actor="operator:operator", now=T1)
            attest_node(self.vault, node, registered.node_generation, observed_code_digest="code-1",
                        observed_environment_digest="env-1", observed_public_key_ref=f"pub-{node}",
                        actor="operator:operator", now=T1)
            register_transport_key(self.vault, node_id=node,
                                   node_generation=registered.node_generation, key_ref=f"tk-{node}",
                                   actor="operator:operator", now=T1)
        open_domain(self.vault, domain_id="D-1", scope="constitution", owner_node_id="N-A",
                    permitted_transitions=["PROMOTE"], actor="operator:operator", now=T1)
        mission = open_mission(self.vault, objective="Maintain repository health", now=T1)
        complete_mission(self.vault, mission_id=mission, reason="done", now=T1 + 1)
        connection = sqlite3.connect(self.vault)
        connection.execute("CREATE TABLE IF NOT EXISTS ciph_observations (observation_id TEXT, "
                           "source_ref TEXT, observed_at REAL);")
        connection.execute("INSERT INTO ciph_observations VALUES ('OBS-1', 'SOURCE:primary', ?);",
                           (T1,))
        # The superseded instance holds credentials and a permit generation that recovery must fence.
        connection.execute("CREATE TABLE IF NOT EXISTS ciph_execution_permits (permit_id TEXT, "
                           "revoked_at REAL, revocation_generation TEXT);")
        connection.execute("INSERT INTO ciph_execution_permits VALUES ('P-1', NULL, 'GEN-OLD');")
        connection.commit()
        connection.close()
        return mission

    def backup_and_manifest(self):
        manifest = build_manifest(self.vault, ciph_identity_id=IDENTITY,
                                  constitutional_versions=["4.0", "5.0", "6.0", "7.0", "8.0"],
                                  required_state_families=["missions", "epistemic_ledger",
                                                           "federation_authority", "evolution_epochs"],
                                  required_secret_refs=["root-1"],
                                  required_artifact_digests={"vault": DIGEST},
                                  schema_versions={"ciph_missions": "S3"},
                                  created_from_canonical_state_digest=DIGEST,
                                  software_revision="8.0", now=T1)
        backup = create_approved_backup(self.vault, source_identity=IDENTITY,
                                        manifest_id=manifest["manifest_id"], state_digest=DIGEST,
                                        artifact_digest=DIGEST, schema_digest=DIGEST,
                                        included=["ciph_missions", "ciph_observations",
                                                  "ciph_federation_authority_domains"],
                                        excluded=["ciph.key", "*.pid", "ciph_transport_sessions"],
                                        encryption_identity="gpg:aes256",
                                        consistency_boundary=f"sqlite-snapshot@{int(T1)}",
                                        passphrase=PASSPHRASE, now=T1)
        verify_backup(self.vault, backup.backup_id, observed_state_digest=DIGEST,
                      observed_artifact_digest=DIGEST,
                      present_families=["missions", "epistemic_ledger", "federation_authority",
                                        "evolution_epochs"],
                      observed_artifacts={"vault": DIGEST}, now=T1 + 1)
        authorize_for_recovery(self.vault, backup.backup_id, actor="operator:operator",
                               evidence_ref="OPERATOR-DECISION-B7", now=T1 + 2)
        # Approved recovery material is kept OUTSIDE the installation, which is what makes destroying
        # the installation survivable.
        shutil.copy(self.vault, str(self.recovery_material / "approved-backup.db"))
        (self.recovery_material / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return manifest, backup

    def destroy_installation(self):
        shutil.rmtree(self.installation)
        self.assertFalse(self.installation.exists(), "the disposable installation is gone")

    # ---------------------------------------------------------------- the recovery
    def materialise_clean_host(self):
        """
        Place the recovery material on the clean host ONCE.

        Materialising is not recovering, and it must not happen again mid-ceremony: an earlier version
        re-copied the backup before every attempt, which silently erased the fence the operator had just
        established - a fixture bug that made a fenced recovery look unfenced.
        """
        if not Path(self.restored).exists():
            shutil.copy(str(self.recovery_material / "approved-backup.db"), self.restored)
        return self.restored

    def recover_into_clean_host(self, *, fence_id=None, authorization=None):
        self.materialise_clean_host()
        # The clean host has the recovery material and NOTHING else: no runtime state, no sessions,
        # no permits, no armed timer.
        if authorization is None:
            authorization = issue_recovery_authorization(
                self.restored, ciph_identity_id=IDENTITY, backup_id=self.backup_id,
                target_environment_digest=ENVIRONMENT, scope=SCOPE_RESUME, actor="operator:operator",
                evidence_ref="OPERATOR-DECISION-RESTORE", now=T1 + 10)
        return recover(self.restored, backup_id=self.backup_id, source_identity=IDENTITY,
                       target_environment_digest=ENVIRONMENT, ciph_identity_id=IDENTITY,
                       present_families=["missions", "epistemic_ledger", "federation_authority",
                                         "evolution_epochs"],
                       observed_artifacts={"vault": DIGEST}, required_root_key_refs=["root-1"],
                       authorization=authorization, fence_id=fence_id, required_scope=SCOPE_RESUME,
                       now=T1 + 11)

    def fence_superseded_instance(self):
        """A real fence: revoke the superseded node's transport credential AND its permit generation."""
        revoke_transport_key(self.restored, "tk-N-A", actor="operator:operator",
                             reason="superseded by recovery", now=T1 + 12)
        connection = sqlite3.connect(self.restored)
        connection.execute("UPDATE ciph_execution_permits SET revoked_at = ?, "
                           "revocation_generation = 'GEN-7' WHERE permit_id = 'P-1';", (T1 + 12,))
        connection.commit()
        connection.close()
        credential = record_fence(self.restored, run_id="FOUNDING", kind=FENCE_NODE_CREDENTIALS_REVOKED,
                                  authority_ref="tk-N-A", evidence_ref="OLD-HOST-RETIRED-B7",
                                  actor="operator:operator", now=T1 + 13)
        permits = record_fence(self.restored, run_id="FOUNDING", kind=FENCE_PERMIT_GENERATION_REVOKED,
                               authority_ref="GEN-7", evidence_ref="PERMITS-REVOKED-B7",
                               actor="operator:operator", now=T1 + 14)
        return credential, permits

    # ---------------------------------------------------------------- the founding proof
    def test_founding_clean_host_recovery(self):
        self.populate()
        manifest, backup = self.backup_and_manifest()
        self.backup_id = backup.backup_id
        source_identity_digest = sovereign_identity_digest(self.vault)
        source_missions = [state.mission_id for state in reconstruct_missions(self.vault).missions]
        self.destroy_installation()

        # 1. A copy of the bytes WITHOUT the authorized material does not activate: no grant, no fence.
        ungranted = self.recover_into_clean_host(authorization="operator:approved")
        self.assertFalse(ungranted.activated)
        self.assertEqual(ungranted.status, "REFUSED")

        # 2. A valid, authorized candidate with NO enforceable fence is HELD - not activated.
        no_fence = self.recover_into_clean_host()
        self.assertEqual(no_fence.status, HOLD)
        self.assertFalse(no_fence.activated)
        self.assertIsNone(last_proven_restore(self.restored))

        # 3. With a real fence, the legitimate continuation activates through the governed ceremony.
        self.materialise_clean_host()
        credential_fence, permit_fence = self.fence_superseded_instance()
        self.assertTrue(fence_is_enforceable(self.restored, credential_fence["fence_id"])["enforceable"])
        self.assertTrue(fence_is_enforceable(self.restored, permit_fence["fence_id"])["enforceable"])
        activated = self.recover_into_clean_host(fence_id=credential_fence["fence_id"])
        self.assertTrue(activated.activated, activated.reason)
        self.assertEqual(activated.status, ACTIVATED)
        proof = last_proven_restore(self.restored)
        self.assertIsNotNone(proof)
        self.assertEqual(proof["ciph_identity_id"], IDENTITY)

        # 4. Identity and history survived; the runtime identity did NOT.
        self.assertEqual(identity(self.restored).ciph_identity_id, IDENTITY)
        self.assertEqual(identity(self.restored).vault_identity_ref, "VAULT-DISPOSABLE")
        self.assertEqual(sovereign_identity_digest(self.restored), source_identity_digest,
                         "the sovereign identity and root custody are unchanged by the move")
        self.assertEqual([state.mission_id for state in
                          reconstruct_missions(self.restored).missions], source_missions,
                         "canonical history is preserved")
        self.assertEqual(get_domain(self.restored, "D-1").owner_node_id, "N-A")
        # The federation lineage is preserved, and no runtime state came with it.
        self.assertEqual(current_generation(self.restored, "N-A"), 1)

        # 5. Ephemeral and destructive state did NOT revive.
        self.assertFalse(destruction_policy(self.restored)["armed"])
        after = destruction_state_after_recovery(self.restored)
        self.assertFalse(after["armed_after_recovery"])
        self.assertEqual(len(_table(self.restored, "ciph_transport_sessions")), 0,
                         "sessions are dead the moment the host is")
        # The projection reports what HAPPENED, not what we wish had: this datastore carries a held
        # attempt in its history (the unfenced run above), so "attention required" is the honest answer
        # alongside the proven restore. A store with no holds is HEALTHY - the projection distinguishes.
        verdict = sovereignty_health(self.restored, now=T1 + 20)
        self.assertEqual(verdict["status"], "ATTENTION_REQUIRED")
        self.assertTrue(verdict["recovery_holds"], "the held attempt is part of the record")
        self.assertIsNotNone(verdict["last_proven_restore"])
        self.assertEqual(verdict["proven_restore_count"], 1)
        self.assertTrue(verdict["no_score"])

    def test_the_superseded_credential_is_refused_by_the_real_boundary(self):
        """
        The fence has teeth: after fencing, the OLD credential cannot be used to authenticate, and the
        refusal comes from the transport boundary - not from a flag somebody is supposed to respect.
        """
        self.populate()
        manifest, backup = self.backup_and_manifest()
        self.backup_id = backup.backup_id
        self.destroy_installation()
        self.materialise_clean_host()
        self.materialise_clean_host()
        credential_fence, permit_fence = self.fence_superseded_instance()
        activated = self.recover_into_clean_host(fence_id=credential_fence["fence_id"])
        self.assertTrue(activated.activated)
        with self.assertRaises(CrucibleError) as refused:
            open_session(self.restored, local_node="N-B", remote_node="N-A", peer_key_ref="tk-N-A")
        self.assertEqual(refused.exception.reason, "PEER_KEY_REVOKED")
        # And a session opened BEFORE the revocation is refused on its next envelope.
        register_transport_key(self.restored, node_id="N-A", node_generation=1, key_ref="tk-N-A2",
                               actor="operator:operator", now=T1 + 15)
        session = open_session(self.restored, local_node="N-B", remote_node="N-A",
                               peer_key_ref="tk-N-A2")
        revoke_transport_key(self.restored, "tk-N-A2", actor="operator:operator", reason="fence",
                             now=T1 + 16)
        mid = accept_envelope(self.restored, session.session_id,
                              make_envelope(message_id="M-OLD", sender_node="N-A",
                                            sender_generation=1, causal_ref="M-OLD",
                                            payload_digest=DIGEST, secret=SECRET.encode()),
                              secret=SECRET.encode())
        self.assertEqual(mid["disposition"], "REFUSED")
        self.assertEqual(mid["reason"], "PEER_KEY_REVOKED")

    def test_a_clone_of_the_same_material_never_activates(self):
        self.populate()
        manifest, backup = self.backup_and_manifest()
        self.backup_id = backup.backup_id
        self.destroy_installation()
        self.materialise_clean_host()
        credential_fence, _ = self.fence_superseded_instance()
        activated = self.recover_into_clean_host(fence_id=credential_fence["fence_id"])
        self.assertTrue(activated.activated)
        clone_dir = self.base / "clone_host"
        clone_dir.mkdir()
        clone_db = str(clone_dir / "clone.db")
        shutil.copy(str(self.recovery_material / "approved-backup.db"), clone_db)
        clone = register_clone(clone_db, source_identity=IDENTITY, purpose="post-mortem analysis",
                               now=T1 + 30)
        self.assertEqual(clone["standing"], "NONE")
        self.assertFalse(assert_no_standing(clone_db, clone["clone_id"])["may_activate"])
        self.assertIsNone(last_proven_restore(clone_db),
                          "identical bytes with no ceremony confer no activation")
        self.assertIsNotNone(last_proven_restore(self.restored),
                             "the RESTORED instance is the one that holds the activation")

    def test_the_recovered_state_reconstructs_in_an_independent_process(self):
        self.populate()
        manifest, backup = self.backup_and_manifest()
        self.backup_id = backup.backup_id
        self.destroy_installation()
        self.materialise_clean_host()
        credential_fence, _ = self.fence_superseded_instance()
        self.recover_into_clean_host(fence_id=credential_fence["fence_id"])
        bundle = {"identity": sovereign_identity_digest(self.restored),
                  "engine": engine_digest(self.restored)}
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.sovereign_identity import sovereign_identity_digest;"
                "from ciph.kernel.recovery_engine import engine_digest, last_proven_restore;"
                "print(json.dumps({'identity': sovereign_identity_digest(%r), "
                "'engine': engine_digest(%r), 'proof': (last_proven_restore(%r) or {}).get('run_id')}, "
                "sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.restored, self.restored, self.restored))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        fresh = json.loads(out.stdout.strip())
        self.assertEqual(fresh["identity"], bundle["identity"])
        self.assertEqual(fresh["engine"], bundle["engine"])
        self.assertIsNotNone(fresh["proof"])


def _table(db_path, table):
    connection = sqlite3.connect(db_path)
    try:
        return [dict(zip([column[0] for column in connection.execute(f"SELECT * FROM {table} LIMIT 0;")
                          .description], row))
                for row in connection.execute(f"SELECT * FROM {table};")]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
