"""
PRIORITY ZERO - does recovery fencing reach the AUTHORITATIVE EXECUTION surfaces?

    An old valid signature is not sufficient authority.

The question was whether 4.0's machinery can enforce a recovery-generation fence, or whether 8.x has to
build something. The answer, read out of the constitution rather than assumed: the permit store's claim
path ALREADY refuses a permit minted under a superseded authorization epoch, and it represents that
refusal as a REVOCATION ON THE ROW (`AUTHORIZATION_EPOCH_SUPERSEDED`) rather than by erasing history.

So 8.x adds nothing here. What 8.x owes is the PROOF that a recovery supersession actually reaches that
boundary - which is what these specimens do, using the real `ExecutionPermitStore`.
"""

import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.permit_store import (DENY_EPOCH_MISMATCH, DENY_EPOCH_NOT_AUTHORITATIVE, DENY_REVOKED,
                                      STATE_CLAIMED, STATE_ISSUED, STATE_REVOKED, ExecutionPermitStore,
                                      PermitStoreError, permit_digest, derive_permit_state)
from ciph.kernel.recovery_engine import (ACTIVATED, SCOPE_RESUME, fence_is_enforceable,
                                         issue_recovery_authorization, last_proven_restore, recover,
                                         record_fence, FENCE_NODE_CREDENTIALS_REVOKED)
from ciph.kernel.backup_constitution import (authorize_for_recovery, create_approved_backup,
                                             verify_backup)
from ciph.kernel.recovery_manifest import build_manifest
from ciph.kernel.real_transport import register_transport_key, revoke_transport_key
from ciph.kernel.sovereign_identity import establish_identity, register_root_key
from ciph.kernel.sovereignty_scanners import SOVEREIGNTY_SCANNERS

T1 = 1_800_000_000.0
DIGEST = "c" * 64
IDENTITY = "CIPH-IDENTITY-FENCE"
ENVIRONMENT = "CLEAN-HOST-FENCE"
PASSPHRASE = "a-real-passphrase-for-the-fence"
EPOCH_BEFORE = 1
EPOCH_AFTER = 2


class RecoveryGenerationFencing(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-89-")
        self.base = Path(self.temp.name)
        self.installation = self.base / "installation"
        self.installation.mkdir()
        self.vault = str(self.installation / "ciph_vault.db")
        self.material = self.base / "recovery_material"
        self.material.mkdir()
        self.clean = self.base / "clean_host"
        self.clean.mkdir()
        self.restored = str(self.clean / "recovered.db")
        self.store = ExecutionPermitStore(db_path=self.vault)
        self.permit_digest = permit_digest(b"canonical-permit-body")

    def tearDown(self):
        self.temp.cleanup()

    def issue_permit(self, db_path, permit_id="permit_old", *, epoch=EPOCH_BEFORE, ttl=86400.0,
                     logical_action_id=None):
        store = ExecutionPermitStore(db_path=db_path)
        now = time.time()
        # A logical action carries a fingerprint by law: once L is observed with fingerprint A it may
        # never bind to B, so the fixture must state the action's meaning, not just its name.
        store.register(permit_id=permit_id, digest=self.permit_digest, issued_at=now,
                       expires_at=now + ttl, authorization_epoch=epoch,
                       logical_action_id=logical_action_id,
                       action_fingerprint=f"fp-{logical_action_id}" if logical_action_id else None)
        return permit_id

    def build_and_back_up(self):
        register_root_key(self.vault, key_ref="root-1", actor="operator:operator", now=T1)
        establish_identity(self.vault, ciph_identity_id=IDENTITY, vault_identity_ref="VAULT-FENCE",
                           constitutional_root_digest=DIGEST, recovery_policy_id="RECOVERY_POLICY_V1",
                           authorized_root_key_refs=["root-1"], actor="operator:operator", now=T1)
        register_transport_key(self.vault, node_id="N-A", node_generation=1, key_ref="tk-N-A",
                               actor="operator:operator", now=T1)
        # The superseded instance holds a permit that was legitimately issued and never used.
        self.issue_permit(self.vault, "permit_old", epoch=EPOCH_BEFORE,
                          logical_action_id="ACT-1")
        manifest = build_manifest(self.vault, ciph_identity_id=IDENTITY,
                                  constitutional_versions=["4.0", "8.0"],
                                  required_state_families=["missions"],
                                  required_artifact_digests={"vault": DIGEST},
                                  created_from_canonical_state_digest=DIGEST, now=T1)
        backup = create_approved_backup(self.vault, source_identity=IDENTITY,
                                        manifest_id=manifest["manifest_id"], state_digest=DIGEST,
                                        artifact_digest=DIGEST, schema_digest=DIGEST,
                                        included=["ciph_missions"], excluded=["ciph.key"],
                                        encryption_identity="gpg:aes256",
                                        consistency_boundary=f"sqlite-snapshot@{int(T1)}",
                                        passphrase=PASSPHRASE, now=T1)
        verify_backup(self.vault, backup.backup_id, observed_state_digest=DIGEST,
                      observed_artifact_digest=DIGEST, present_families=["missions"],
                      observed_artifacts={"vault": DIGEST}, now=T1 + 1)
        authorize_for_recovery(self.vault, backup.backup_id, actor="operator:operator",
                               evidence_ref="OPERATOR-DECISION-FENCE", now=T1 + 2)
        return manifest, backup

    def recover_and_activate(self, backup):
        import shutil
        shutil.copy(self.vault, self.restored)
        revoke_transport_key(self.restored, "tk-N-A", actor="operator:operator",
                             reason="superseded", now=T1 + 3)
        fence = record_fence(self.restored, run_id="FENCE-RUN", kind=FENCE_NODE_CREDENTIALS_REVOKED,
                             authority_ref="tk-N-A", evidence_ref="OLD-HOST-RETIRED",
                             actor="operator:operator", now=T1 + 4)
        self.assertTrue(fence_is_enforceable(self.restored, fence["fence_id"])["enforceable"])
        grant = issue_recovery_authorization(self.restored, ciph_identity_id=IDENTITY,
                                             backup_id=backup.backup_id,
                                             target_environment_digest=ENVIRONMENT,
                                             scope=SCOPE_RESUME, actor="operator:operator",
                                             evidence_ref="OPERATOR-DECISION-FENCE", now=T1 + 5)
        outcome = recover(self.restored, backup_id=backup.backup_id, source_identity=IDENTITY,
                          target_environment_digest=ENVIRONMENT, ciph_identity_id=IDENTITY,
                          present_families=["missions"], observed_artifacts={"vault": DIGEST},
                          required_root_key_refs=["root-1"], authorization=grant,
                          fence_id=fence["fence_id"], required_scope=SCOPE_RESUME, now=T1 + 6)
        self.assertTrue(outcome.activated, outcome.reason)
        return outcome, fence

    # ---------------------------------------------------------------- the hostile case
    def test_the_superseded_instances_permit_is_refused_at_the_execution_boundary(self):
        manifest, backup = self.build_and_back_up()
        self.assertEqual(ExecutionPermitStore(db_path=self.vault).state_of("permit_old"),
                         STATE_ISSUED)
        outcome, fence = self.recover_and_activate(backup)
        self.assertEqual(outcome.status, ACTIVATED)
        self.assertIsNotNone(last_proven_restore(self.restored))

        # The operator's supersession is the SAME event the fence recorded; recovery then presents the
        # new epoch at the boundary. The old permit dies on the strength of the constitution that owns
        # this decision - not on a rule 8.x invented.
        continued = ExecutionPermitStore(db_path=self.restored)
        with self.assertRaises(PermitStoreError) as refused:
            continued.claim("permit_old", "old-instance-worker", digest=self.permit_digest,
                            current_authorization_epoch=EPOCH_AFTER)
        self.assertEqual(refused.exception.reason, DENY_EPOCH_MISMATCH)

        # History is PRESERVED and the revocation is REPRESENTED, not erased.
        row = _row(self.restored, "permit_old")
        self.assertEqual(row["state"], STATE_REVOKED)
        self.assertEqual(row["revoke_reason"], "AUTHORIZATION_EPOCH_SUPERSEDED")
        self.assertIsNotNone(row["revoked_at"])
        self.assertEqual(row["permit_digest"], self.permit_digest, "the original record is intact")

        # And it stays dead: a second attempt is refused as revoked, and a fresh process agrees.
        with self.assertRaises(PermitStoreError) as again:
            continued.claim("permit_old", "old-instance-worker", digest=self.permit_digest,
                            current_authorization_epoch=EPOCH_AFTER)
        self.assertEqual(again.exception.reason, DENY_REVOKED)
        fresh_state = subprocess.run(
            [sys.executable, "-B", "-c",
             "import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
             "from ciph.kernel.permit_store import ExecutionPermitStore;"
             "print(ExecutionPermitStore(db_path=%r).state_of('permit_old'))"
             % (str(Path(__file__).resolve().parents[1]), self.restored)],
            capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1]), timeout=120)
        self.assertEqual(fresh_state.returncode, 0, fresh_state.stderr)
        self.assertEqual(fresh_state.stdout.strip(), STATE_REVOKED)

    def test_the_legitimate_continuation_can_still_act(self):
        """Supersession must not paralyse the successor: new authority at the new epoch works."""
        manifest, backup = self.build_and_back_up()
        self.recover_and_activate(backup)
        continued = ExecutionPermitStore(db_path=self.restored)
        now = time.time()
        continued.register(permit_id="permit_new", digest=permit_digest(b"successor-permit"),
                           issued_at=now, expires_at=now + 3600.0,
                           authorization_epoch=EPOCH_AFTER, logical_action_id="ACT-1-NEW",
                           action_fingerprint="fp-ACT-1-NEW")
        claim = continued.claim("permit_new", "recovered-worker",
                                digest=permit_digest(b"successor-permit"),
                                current_authorization_epoch=EPOCH_AFTER)
        self.assertEqual(claim.claimant, "recovered-worker")
        self.assertEqual(continued.state_of("permit_new"), STATE_CLAIMED)
        # The superseded permit is still ISSUED here, and that is the honest reading: the broad
        # invalidation fires when the stale authority is PRESENTED at the boundary, which is exactly
        # when it would otherwise have had an effect. Until then the row keeps its history untouched.
        self.assertEqual(continued.state_of("permit_old"), STATE_ISSUED)
        self.assertNotEqual(claim.execution_attempt_id, "")

    def test_no_new_permit_can_be_minted_under_the_superseded_epoch(self):
        """A stale instance cannot re-arm itself by issuing fresh permits at the OLD epoch."""
        manifest, backup = self.build_and_back_up()
        self.recover_and_activate(backup)
        continued = ExecutionPermitStore(db_path=self.restored)
        now = time.time()
        stale = continued.register(permit_id="permit_stale", digest=permit_digest(b"stale-mint"),
                                   issued_at=now, expires_at=now + 3600.0,
                                   authorization_epoch=EPOCH_BEFORE, logical_action_id="ACT-2",
                                   action_fingerprint="fp-ACT-2")
        self.assertTrue(stale.permit_id)
        with self.assertRaises(PermitStoreError) as refused:
            continued.claim("permit_stale", "old-instance-worker",
                            digest=permit_digest(b"stale-mint"),
                            current_authorization_epoch=EPOCH_AFTER)
        self.assertEqual(refused.exception.reason, DENY_EPOCH_MISMATCH,
                         "minting at the superseded epoch buys nothing at the boundary")

    def test_a_stale_instance_cannot_supply_its_own_epoch_to_the_boundary(self):
        """
        THE caller-controlled hole, closed and asserted.

        Before this, `claim(current_authorization_epoch=N)` trusted the caller: an isolated superseded
        instance could present its OWN stale epoch, pass the comparison, and claim its permit after
        supersession - a fence made of the prisoner's own testimony. The store now keeps its own
        authoritative epoch, and a caller that disagrees with it is refused.
        """
        manifest, backup = self.build_and_back_up()
        self.recover_and_activate(backup)
        continued = ExecutionPermitStore(db_path=self.restored)
        generation = continued.supersede_authority_epoch(actor="operator:operator",
                                                        evidence_ref="RECOVERY-FENCE-EPOCH")
        self.assertEqual(generation, EPOCH_AFTER)
        self.assertEqual(continued.current_authority_epoch(), EPOCH_AFTER)
        with self.assertRaises(PermitStoreError) as lying:
            continued.claim("permit_old", "old-instance-worker", digest=self.permit_digest,
                            current_authorization_epoch=EPOCH_BEFORE)
        self.assertEqual(lying.exception.reason, DENY_EPOCH_NOT_AUTHORITATIVE)
        # Omitting the parameter is not an escape either: the store's own epoch is used.
        with self.assertRaises(PermitStoreError) as omitted:
            continued.claim("permit_old", "old-instance-worker", digest=self.permit_digest)
        self.assertEqual(omitted.exception.reason, DENY_EPOCH_MISMATCH)
        # A supersession that does not EXCEED the minted epochs is refused as not-superseding.
        with self.assertRaises(PermitStoreError) as weak:
            continued.record_authority_generation(generation=EPOCH_AFTER, actor="operator:operator",
                                                  evidence_ref="WEAK")
        self.assertEqual(weak.exception.reason, "DENY_AUTHORITY_EPOCH_NOT_SUPERSEDING")

    def test_a_superseded_instance_cannot_produce_an_effect_by_minting_fresh_permits(self):
        """The whole point: no new attributable authorized effect from stale standing."""
        manifest, backup = self.build_and_back_up()
        self.recover_and_activate(backup)
        continued = ExecutionPermitStore(db_path=self.restored)
        continued.supersede_authority_epoch(actor="operator:operator", evidence_ref="RECOVERY-FENCE-EPOCH")
        now = time.time()
        continued.register(permit_id="permit_after_fence", digest=permit_digest(b"after-fence"),
                           issued_at=now, expires_at=now + 3600.0,
                           authorization_epoch=EPOCH_BEFORE, logical_action_id="ACT-9",
                           action_fingerprint="fp-ACT-9")
        with self.assertRaises(PermitStoreError) as refused:
            continued.claim("permit_after_fence", "old-instance-worker",
                            digest=permit_digest(b"after-fence"),
                            current_authorization_epoch=EPOCH_BEFORE)
        self.assertEqual(refused.exception.reason, DENY_EPOCH_NOT_AUTHORITATIVE)
        self.assertEqual(continued.state_of("permit_after_fence"), STATE_ISSUED,
                         "no attributable effect, and no corrupted history")

    def test_fencing_adds_no_second_execution_constitution(self):
        """The refusal comes from 4.0's own store, and 8.x defines no rival claim or consume path."""
        real = dict(__import__("ciph.kernel.evolution_ownership", fromlist=["production_sources"])
                    .production_sources())
        scanners = dict(SOVEREIGNTY_SCANNERS)
        self.assertEqual(scanners["s12_recovery_bypasses_r7"](real), ())
        self.assertEqual(scanners["s16_second_authority_constitution"](real), ())
        for module in ("ciph/kernel/permit_store.py", "ciph/kernel/execution_authority.py"):
            self.assertIn(module, real)


def _row(db_path, permit_id):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        return dict(connection.execute("SELECT * FROM execution_permits WHERE permit_id = ?;",
                                       (permit_id,)).fetchone())
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
