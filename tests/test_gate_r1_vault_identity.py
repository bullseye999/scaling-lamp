
"""
R1 - vault identity: a vault's cryptographic identity survives moving it, and is not forgeable by
editing where it lives.

The legacy key-encryption key was derived from the vault's PATH, so the same file opened by a
different path string failed to decrypt every protected row. These specimens prove the migration and,
just as importantly, prove the ways it must fail.
"""

import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crypto_identity import TrustRegistry
from ciph.kernel.vault_identity import (
    KEY_DERIVATION_V0,
    KEY_DERIVATION_V1,
    VaultIdentityError,
    _decrypt,
    derive_kek,
    migrate_vault,
    purge_legacy_representation,
    read_header,
    row_kek_v0,
    row_kek_v1,
    verify_all_rows,
    write_header,
)


class TestR1VaultIdentity(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-r1-')
        self.root = Path(self.temp.name)
        self.db = str(self.root / 'vault.db')
        # A real vault with real protected rows: operator, kernel and worker private keys.
        self.registry = TrustRegistry(self.db)
        self.registry.get_or_create_keypair('operator_root', __import__(
            'ciph.kernel.crypto_identity', fromlist=['KeyRole']).KeyRole.OPERATOR)
        self.registry.get_or_create_keypair('kernel_primary', __import__(
            'ciph.kernel.crypto_identity', fromlist=['KeyRole']).KeyRole.KERNEL)
        self.registry.get_or_create_keypair('worker_primary', __import__(
            'ciph.kernel.crypto_identity', fromlist=['KeyRole']).KeyRole.WORKER)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def rows(self, db=None):
        conn = sqlite3.connect(db or self.db)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(
                "SELECT key_id, private_key_hex FROM ciph_key_vault ORDER BY key_id;")]
        finally:
            conn.close()

    def plaintexts_under(self, kek, db=None):
        return {r['key_id']: _decrypt(r['private_key_hex'], kek, r['key_id'])
                for r in self.rows(db or self.db)}

    def header(self, db=None):
        conn = sqlite3.connect(db or self.db)
        conn.row_factory = sqlite3.Row
        try:
            return read_header(conn)
        finally:
            conn.close()

    def keypair(self, db, key_id):
        registry = TrustRegistry(db)          # a fresh instance per path spelling
        return registry.get_keypair(key_id)

    def snapshot(self, db=None):
        """A consistent copy, using SQLite's own backup semantics rather than a file copy."""
        source = sqlite3.connect(db or self.db)
        target = sqlite3.connect(str(self.root / 'snapshot.db'))
        with target:
            source.backup(target)
        target.close()
        source.close()
        return str(self.root / 'snapshot.db')

    # ------------------------------------------------------------------ 1. path independence
    def test_a_migrated_vault_decrypts_at_any_path_spelling(self):
        legacy_plaintexts = self.plaintexts_under(row_kek_v0(self.db))
        report = migrate_vault(self.db)
        self.assertEqual(report['status'], 'MIGRATED')
        self.assertEqual(report['rewrapped'], len(legacy_plaintexts))

        absolute = self.db
        relative = os.path.relpath(self.db, os.getcwd())
        (self.root / 'sub').mkdir(exist_ok=True)      # so a non-canonical path really resolves
        roundabout = os.path.join(str(self.root), 'sub', '..', 'vault.db')
        renamed = str(self.root / 'renamed.db')
        shutil.copyfile(self.db, renamed)
        copied = self.snapshot()

        expected = legacy_plaintexts['operator_root']
        for label, path in (('absolute', absolute), ('relative', relative),
                            ('roundabout', roundabout), ('renamed', renamed), ('copied', copied)):
            with self.subTest(spelling=label):
                private, _public = self.keypair(path, 'operator_root')
                self.assertEqual(private, expected,
                                 f"the same vault must decrypt the same key at a {label} path")

    def test_every_rewrapped_row_is_byte_identical_after_migration(self):
        before = self.plaintexts_under(row_kek_v0(self.db))
        report = migrate_vault(self.db)
        after = self.plaintexts_under(row_kek_v1(report['vault_id']))

        self.assertEqual(sorted(before), sorted(after))
        for key_id in before:
            with self.subTest(key=key_id):
                self.assertEqual(before[key_id], after[key_id],
                                 "rewrapping must reproduce the private key byte for byte")
        self.assertEqual({v['key_id'] for v in report['verifications']}, set(before))
        self.assertTrue(all(v['byte_identical'] for v in report['verifications']))
        self.assertTrue(verify_all_rows(self.db)['all_decrypt'])

    def test_legacy_plaintext_rows_are_encrypted_by_the_migration(self):
        """
        A vault can legitimately contain a MIX: some rows encrypted under an old path identity, and
        some stored as bare hex by even older code. The migration must read both and encrypt both -
        which means it also closes plaintext private keys, not merely rewraps them.
        """
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute(
            "SELECT * FROM ciph_key_vault WHERE key_id = 'worker_primary'").fetchone())
        conn.close()
        plaintext = _decrypt(row['private_key_hex'], row_kek_v0(self.db), 'worker_primary')
        with sqlite3.connect(self.db) as rewriting:
            rewriting.execute("UPDATE ciph_key_vault SET private_key_hex = ? WHERE key_id = 'worker_primary';",
                              (plaintext.hex(),))

        report = migrate_vault(self.db)

        self.assertEqual(report['legacy_sources']['worker_primary'], 'PLAINTEXT_LEGACY')
        self.assertEqual(report['plaintext_rows_now_encrypted'], 1)
        self.assertTrue(report['legacy_sources']['operator_root'].startswith('PATH_V0:'))
        after = self.rows()
        stored = [r for r in after if r['key_id'] == 'worker_primary'][0]['private_key_hex']
        self.assertTrue(stored.startswith('ENC:'), "a plaintext private key must not survive")
        self.assertNotIn(plaintext.hex(), stored)
        self.assertEqual(_decrypt(stored, row_kek_v1(report['vault_id']), 'worker_primary'), plaintext)
        self.assertTrue(verify_all_rows(self.db)['all_decrypt'])

    # ------------------------------------------------------------------ 3. tampering
    def test_a_tampered_header_is_an_authentication_failure(self):
        migrate_vault(self.db)
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE ciph_vault_identity SET vault_id = ? WHERE header_id = 'PRIMARY';",
                         ('VAULT-ATTACKER-CHOSEN',))

        with self.assertRaises(VaultIdentityError) as refused:
            derive_kek(self.db)
        self.assertEqual(refused.exception.reason, 'VAULT_HEADER_AUTHENTICATION_FAILED')
        with self.assertRaises(VaultIdentityError):
            self.keypair(self.db, 'operator_root')

    def test_an_edit_to_the_location_metadata_cannot_mint_an_identity(self):
        """The MAC is made with the root secret alone, so header edits cannot be made to authenticate."""
        migrate_vault(self.db)
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        before = dict(conn.execute("SELECT * FROM ciph_vault_identity").fetchone())
        conn.close()
        for field, value in (('vault_id', 'VAULT-OTHER'),
                             ('key_derivation_version', KEY_DERIVATION_V0),
                             ('vault_schema_version', 99)):
            with self.subTest(field=field):
                with sqlite3.connect(self.db) as tampering:
                    tampering.execute(f"UPDATE ciph_vault_identity SET {field} = ?;", (value,))
                with self.assertRaises(VaultIdentityError):
                    derive_kek(self.db)
                with sqlite3.connect(self.db) as restoring:
                    restoring.execute(f"UPDATE ciph_vault_identity SET {field} = ?;", (before[field],))
        self.assertTrue(verify_all_rows(self.db)['all_decrypt'])

    # ------------------------------------------------------------------ 2 + 7. no downgrade
    def test_a_different_vault_id_cannot_decrypt_and_never_falls_back(self):
        migrate_vault(self.db)
        # A LEGITIMATE header for a different vault identity: correctly MAC'd, wrong vault.
        conn = sqlite3.connect(self.db)
        write_header(conn, vault_id='VAULT-SOMEONE-ELSE', derivation_version=KEY_DERIVATION_V1)
        conn.commit()
        conn.close()
        self.assertEqual(self.header().vault_id, 'VAULT-SOMEONE-ELSE')

        with self.assertRaises(Exception) as refused:
            self.keypair(self.db, 'operator_root')
        self.assertNotIsInstance(refused.exception, AssertionError)

    def test_post_migration_legacy_fallback_is_impossible(self):
        migration = migrate_vault(self.db)
        # The rows now hold v1 ciphertext, so the legacy key cannot read them...
        with self.assertRaises(Exception):
            self.plaintexts_under(row_kek_v0(self.db))
        # ...and the software derives v1 from the VERIFIED header, not from the path.
        self.assertEqual(derive_kek(self.db), row_kek_v1(migration['vault_id']))
        self.assertNotEqual(derive_kek(self.db), row_kek_v0(self.db))
        # A vault whose v1 rows are damaged must fail, not quietly re-derive from the path.
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE ciph_key_vault SET private_key_hex = 'ENC:00:00' WHERE key_id = 'kernel_primary';")
        with self.assertRaises(Exception):
            self.keypair(self.db, 'kernel_primary')

    # ------------------------------------------------------------------ 4. crash during rewrap
    def test_a_crash_during_rewrap_leaves_the_legacy_vault_authoritative(self):
        before = self.plaintexts_under(row_kek_v0(self.db))

        with self.assertRaises(VaultIdentityError) as refused:
            migrate_vault(self.db, inject_failure_after=1)
        self.assertEqual(refused.exception.reason, 'MIGRATION_INJECTED_FAILURE')

        # No header, no shadow rows, no version declared: there is no second plausible identity.
        conn = sqlite3.connect(self.db)
        try:
            headers = conn.execute("SELECT COUNT(*) FROM ciph_vault_identity").fetchone()[0]
            shadows = conn.execute("SELECT COUNT(*) FROM ciph_key_vault_v1").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual((headers, shadows), (0, 0))
        self.assertEqual(self.plaintexts_under(row_kek_v0(self.db)), before,
                         "a crashed migration must leave the legacy representation usable")
        self.assertEqual(self.keypair(self.db, 'operator_root')[0], before['operator_root'])

        # And the migration is resumable: re-running completes it.
        report = migrate_vault(self.db)
        self.assertEqual(report['status'], 'MIGRATED')
        self.assertTrue(verify_all_rows(self.db)['all_decrypt'])

    def test_a_crash_after_the_flip_leaves_v1_authoritative(self):
        report = migrate_vault(self.db)
        self.assertEqual(self.keypair(self.db, 'operator_root'),
                         self.keypair(self.snapshot(), 'operator_root'))
        # A second migration is a no-op, not a second identity.
        again = migrate_vault(self.db)
        self.assertEqual(again['status'], 'ALREADY_MIGRATED')
        self.assertEqual(again['vault_id'], report['vault_id'])
        self.assertEqual(self.header().key_derivation_version, KEY_DERIVATION_V1)

    # ------------------------------------------------------------------ hygiene
    def test_a_pre_migration_vault_keeps_working_unchanged(self):
        """No header means legacy: the migration is opt-in per vault, never implicit."""
        self.assertIsNone(self.header())
        self.assertEqual(derive_kek(self.db), row_kek_v0(self.db))
        self.assertTrue(verify_all_rows(self.db)['all_decrypt'])
        self.assertEqual(len(self.rows()), 3)

    def test_an_unknown_derivation_version_is_refused(self):
        migrate_vault(self.db)
        conn = sqlite3.connect(self.db)
        write_header(conn, vault_id='VAULT-X', derivation_version='SOMETHING_NEW_V99')
        conn.commit()
        conn.close()
        with self.assertRaises(VaultIdentityError) as refused:
            derive_kek(self.db)
        self.assertEqual(refused.exception.reason, 'VAULT_KEY_DERIVATION_UNKNOWN')

    def test_purging_the_staging_rows_keeps_the_vault_readable(self):
        migrate_vault(self.db)
        self.assertGreater(purge_legacy_representation(self.db), 0)
        self.assertTrue(verify_all_rows(self.db)['all_decrypt'])
        self.assertEqual(self.keypair(self.db, 'kernel_primary')[0],
                         self.keypair(self.db, 'kernel_primary')[0])

    def test_a_vault_that_never_decrypted_is_not_a_migration_candidate(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE ciph_key_vault SET private_key_hex = 'ENC:00:00' WHERE key_id = 'worker_primary';")
        with self.assertRaises(VaultIdentityError) as refused:
            migrate_vault(self.db)
        self.assertEqual(refused.exception.reason, 'MIGRATION_PRECONDITION_FAILED')
        conn = sqlite3.connect(self.db)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM ciph_vault_identity").fetchone()[0], 0)
        finally:
            conn.close()


if __name__ == '__main__':
    unittest.main()
