"""
4.5 ENTRY - production storage composition.

    The runtime, 4.2 epistemics, 4.3 world/self model and 4.4 curiosity must inhabit ONE runtime-shaped
    vault without schema ownership ambiguity.

This is the entry gate to the Crucible: until storage ownership is proven, the Crucible must not write
its own durable records. Every specimen here is written so that a second, silent owner of a table name
would fail.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import schema_ownership as ownership
from ciph.kernel.causal_model import propose_hypothesis
from ciph.kernel.epistemic_ledger import (
    canonical_proposition,
    init_schema as ledger_init,
    record_observation,
)
from ciph.kernel.schema_ownership import (
    SchemaOwnershipError,
    classify_live_table,
    columns_fingerprint,
    live_table_columns,
    migrate_legacy_observations,
    scan_text,
)
from ciph.kernel.uncertainty_registry import derive_uncertainties, init_schema as registry_init
from ciph.kernel.world_model import init_schema as world_init, world_digest
from ciph.runtime import CiphRuntime
from curiosity_test_support import add_evidence, proposition

LEDGER_COLUMNS = ('observation_id', 'source_ref', 'observed_at', 'received_at', 'content_digest',
                  'raw_text')


class TestGate45StorageComposition(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-storage-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.runtime = None

    def tearDown(self):
        if self.runtime is not None:
            self.runtime.shutdown()
        self.temp.cleanup()

    def start_runtime(self, db=None):
        self.runtime = CiphRuntime(db_path=db or self.db)
        return self.runtime

    def legacy_columns(self):
        declarations = ownership.declarations_by_table().get('ciph_mv_observations', [])
        self.assertTrue(declarations, 'the legacy table must still be declared somewhere')
        return declarations[0].columns, declarations[0].fingerprint

    def make_legacy_vault(self, rows=3):
        """A vault shaped like production is TODAY: the legacy store owns ciph_observations."""
        columns, fingerprint = self.legacy_columns()
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "CREATE TABLE ciph_observations (%s);"
                % ", ".join(f"{column} TEXT" for column in columns))
            for index in range(rows):
                connection.execute(
                    "INSERT INTO ciph_observations (observation_id, source, subject) "
                    "VALUES (?,?,?);", (f"OBS-L{index}", "legacy", f"subject-{index}"))
            connection.commit()
        finally:
            connection.close()
        return fingerprint

    # ------------------------------------------------------------------ the scanner
    def test_no_duplicate_canonical_table_owners_in_the_project(self):
        duplicates = ownership.duplicate_canonical_table_owners()
        self.assertEqual(duplicates, (),
                         f'these table names have incompatible canonical owners: {duplicates}')
        self.assertGreater(len(ownership.declarations_by_table()), 50)

    def test_the_scanner_reads_names_placeholders_and_real_collisions(self):
        prose = "see `CREATE TABLE IF NOT EXISTS` for the idiom, and nothing else here"
        self.assertEqual(scan_text(prose, 'prose.py'), [],
                         'prose mentioning the idiom is not a declaration')
        placeholder = "conn.execute(\'\'\'CREATE TABLE IF NOT EXISTS {HEADER} (a TEXT, b REAL)\'\'\')"
        self.assertEqual([d.table for d in scan_text(placeholder, 'p.py')], ['{header}'])
        colliding = (
            "CREATE TABLE IF NOT EXISTS shared (one TEXT, two TEXT);\n"
            "CREATE TABLE IF NOT EXISTS shared (one TEXT, three INTEGER);")
        declarations = scan_text(colliding, 'collide.py')
        self.assertEqual({d.fingerprint for d in declarations}.__len__(), 2,
                         'two incompatible shapes for one name must be distinguishable')
        compatible = ("CREATE TABLE IF NOT EXISTS shared (one TEXT);\n"
                      "CREATE TABLE IF NOT EXISTS shared (one TEXT);")
        self.assertEqual({d.fingerprint for d in scan_text(compatible, 'same.py')}.__len__(), 1)

    # ------------------------------------------------------------------ the integration matrix
    def matrix_order(self, order, db):
        """Initialize the layers in one order, then assert a single canonical ownership."""
        for step in order:
            if step == 'ledger':
                connection = sqlite3.connect(db)
                try:
                    ledger_init(connection)
                    connection.commit()
                finally:
                    connection.close()
            elif step == 'runtime':
                runtime = CiphRuntime(db_path=db)
                runtime.shutdown()
            elif step == 'world':
                connection = sqlite3.connect(db)
                try:
                    world_init(connection)
                    connection.commit()
                finally:
                    connection.close()
            elif step == 'curiosity':
                connection = sqlite3.connect(db)
                try:
                    registry_init(connection)
                    connection.commit()
                finally:
                    connection.close()

    def assert_composed(self, db):
        self.assertEqual(live_table_columns(db, 'ciph_observations'), LEDGER_COLUMNS,
                         'the ledger must own ciph_observations after composition')
        # One grounded support: evidence exists, so the uncertainty registry has work to do.
        prop = proposition('service.a', 'is_healthy', True, at=1_800_000_000.0)
        add_evidence(db, prop, source_ref='compose', at=1_800_000_000.0)
        observation = record_observation(db, source_ref='compose', raw_text='x',
                                         now=1_800_000_001.0)
        self.assertTrue(observation['observation_id'])
        self.assertTrue(world_digest(db, now=1_800_000_002.0))
        self.assertEqual(len(derive_uncertainties(db, now=1_800_000_002.0)), 1)
        runtime = CiphRuntime(db_path=db)
        runtime.shutdown()

    def test_every_initialization_order_composes_to_one_ownership(self):
        for index, order in enumerate((
                ('runtime', 'ledger', 'world', 'curiosity'),
                ('ledger', 'runtime', 'world', 'curiosity'),
                ('world', 'runtime', 'ledger', 'curiosity'),
                ('curiosity', 'runtime', 'ledger', 'world'))):
            with self.subTest(order=order):
                db = str(Path(self.temp.name) / f'matrix-{index}.db')
                self.matrix_order(order, db)
                self.assert_composed(db)

    def test_a_restart_in_a_different_order_composes_to_the_same_ownership(self):
        db = str(Path(self.temp.name) / 'restart.db')
        self.matrix_order(('runtime', 'ledger', 'world', 'curiosity'), db)
        first = live_table_columns(db, 'ciph_observations')
        self.matrix_order(('curiosity', 'world', 'ledger', 'runtime'), db)
        self.assertEqual(live_table_columns(db, 'ciph_observations'), first)
        self.assert_composed(db)

    # ------------------------------------------------------------------ classification by fingerprint
    def test_a_live_table_is_classified_by_fingerprint_not_by_name(self):
        fingerprint = self.make_legacy_vault()
        report = classify_live_table(self.db, 'ciph_observations')
        self.assertTrue(report['exists'])
        self.assertEqual(report['fingerprint'], fingerprint)
        self.assertEqual([owner for owner in report['declared_owners']
                          if owner['matches_live']], [],
                         'the ledger does NOT own the live shape under this name')
        matched_owners = {entry['owner'] for entry in report['global_matches']}
        self.assertIn('ciph/memory/materialized_views.py', matched_owners,
                      'the live legacy shape is recognized as the legacy module\'s table')
        self.assertNotIn('ciph/kernel/epistemic_ledger.py', matched_owners,
                         'and it is emphatically NOT the ledger shape - migration is required')
        self.assertNotEqual(columns_fingerprint(LEDGER_COLUMNS), fingerprint)

        # And once the ledger owns the name, the same classifier says so.
        migrate_legacy_observations(self.db, expected_fingerprint=fingerprint)
        after = classify_live_table(self.db, 'ciph_observations')
        self.assertEqual({entry['owner'] for entry in after['global_matches']},
                         {'ciph/kernel/epistemic_ledger.py'})

    def test_an_additively_upgraded_legacy_table_is_still_recognized(self):
        """Production is not a clean declaration: an upgrade added two trailing columns."""
        legacy_columns, _fingerprint = self.legacy_columns()
        live_columns = tuple(legacy_columns) + ('canonical_payload', 'revision_event_id')
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("CREATE TABLE ciph_observations (%s);"
                               % ", ".join(f"{column} TEXT" for column in live_columns))
            connection.execute("INSERT INTO ciph_observations (observation_id, source, subject) "
                               "VALUES ('OBS-UP','legacy','subject');")
            connection.commit()
        finally:
            connection.close()

        report = classify_live_table(self.db, 'ciph_observations')
        self.assertEqual(report['columns'], list(live_columns))
        relations = {entry['owner']: entry['relation'] for entry in report['global_matches']}
        self.assertEqual(relations.get('ciph/memory/materialized_views.py'), 'EXTENDS',
                         'the legacy owner is recognized through its additive upgrade')
        self.assertFalse(((report['declared_owners'] or [{}])[0]).get('matches_live', False),
                         'an upgraded shape is not EXACT, and must not claim to be')

        # The migration pins the EXACT live shape, so the upgrade columns are part of the proof.
        result = migrate_legacy_observations(
            self.db, expected_fingerprint=columns_fingerprint(live_columns))
        self.assertEqual(result['rows'], 1)
        self.assertEqual(live_table_columns(self.db, 'ciph_mv_observations'), live_columns)
        self.assertEqual(live_table_columns(self.db, 'ciph_observations'), LEDGER_COLUMNS)

    # ------------------------------------------------------------------ the migration
    def test_migration_hands_the_name_to_the_ledger_with_proof(self):
        fingerprint = self.make_legacy_vault(rows=4)
        result = migrate_legacy_observations(self.db, expected_fingerprint=fingerprint)
        self.assertEqual(result['rows'], 4)
        self.assertEqual(live_table_columns(self.db, 'ciph_mv_observations'),
                         self.legacy_columns()[0])
        self.assertEqual(live_table_columns(self.db, 'ciph_observations'), LEDGER_COLUMNS)
        # The legacy rows survived the rename intact.
        connection = sqlite3.connect(self.db)
        try:
            rows = list(connection.execute(
                "SELECT observation_id, source FROM ciph_mv_observations ORDER BY 1;"))
        finally:
            connection.close()
        self.assertEqual(rows, [('OBS-L0', 'legacy'), ('OBS-L1', 'legacy'),
                                ('OBS-L2', 'legacy'), ('OBS-L3', 'legacy')])
        # And the epistemic stack now works in the same file.
        self.assert_composed(self.db)

    def test_migration_refuses_a_wrong_fingerprint_and_an_existing_destination(self):
        self.make_legacy_vault()
        with self.assertRaises(SchemaOwnershipError) as wrong:
            migrate_legacy_observations(self.db, expected_fingerprint=columns_fingerprint(
                LEDGER_COLUMNS))
        self.assertEqual(wrong.exception.reason, 'SCHEMA_FINGERPRINT_MISMATCH')
        self.assertEqual(live_table_columns(self.db, 'ciph_mv_observations'), None,
                         'a refused migration changes nothing')

        connection = sqlite3.connect(self.db)
        try:
            connection.execute("CREATE TABLE ciph_mv_observations (observation_id TEXT);")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(SchemaOwnershipError) as occupied:
            migrate_legacy_observations(self.db, expected_fingerprint=self.legacy_columns()[1])
        self.assertEqual(occupied.exception.reason, 'DESTINATION_ALREADY_EXISTS')

    def test_migration_refuses_a_vault_with_no_source_table(self):
        with self.assertRaises(SchemaOwnershipError) as missing:
            migrate_legacy_observations(self.db, expected_fingerprint=self.legacy_columns()[1])
        self.assertEqual(missing.exception.reason, 'NO_SOURCE_TABLE')

    def test_migration_refuses_when_the_ledger_already_owns_the_name(self):
        connection = sqlite3.connect(self.db)
        ledger_init(connection)
        connection.commit()
        connection.close()
        with self.assertRaises(SchemaOwnershipError) as owned:
            migrate_legacy_observations(self.db, expected_fingerprint=self.legacy_columns()[1])
        self.assertEqual(owned.exception.reason, 'SCHEMA_FINGERPRINT_MISMATCH')
        self.assertEqual(live_table_columns(self.db, 'ciph_observations'), LEDGER_COLUMNS)

    # ------------------------------------------------------------------ the R4 defect itself
    def test_the_r4_defect_is_reproducible_before_the_rename_and_absent_after(self):
        db = str(Path(self.temp.name) / 'r4.db')
        connection = sqlite3.connect(db)
        try:
            connection.execute("CREATE TABLE ciph_observations (observation_id TEXT PRIMARY KEY, "
                               "source TEXT NOT NULL, subject TEXT NOT NULL);")
            connection.commit()
        finally:
            connection.close()
        # Before the rename, the ledger cannot write - the runtime-shaped vault has no source_ref.
        with self.assertRaises(sqlite3.OperationalError) as refused:
            record_observation(db, source_ref='s', raw_text='x', now=1_800_000_000.0)
        self.assertIn('source_ref', str(refused.exception))
        fingerprint = columns_fingerprint(('observation_id', 'source', 'subject'))
        migrate_legacy_observations(db, expected_fingerprint=fingerprint)
        self.assertTrue(record_observation(db, source_ref='s', raw_text='x',
                                           now=1_800_000_000.0)['observation_id'])


if __name__ == '__main__':
    unittest.main()
