"""
4.3 Gate Three - the self model.

    code presence != capability != permission != execution != successful effect.

Every specimen is written so a self model that let the model's own prose, or the mere existence of a
module, promote a capability would fail.
"""

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.epistemic_ledger import canonical_proposition, record_model_output
from ciph.kernel.manifest_identity import ManifestIdentity
from ciph.kernel.self_model import (
    LEVEL_AUTHORIZED,
    LEVEL_AVAILABLE,
    LEVEL_INSTALLED,
    LEVEL_UNKNOWN,
    LEVEL_VERIFIED,
    REASON_NOT_AUTHORIZED,
    REASON_NOT_AVAILABLE_IN_ENVIRONMENT,
    REASON_NOT_EMPIRICALLY_VERIFIED,
    REASON_NO_INSTALLATION,
    SelfModelError,
    assert_empirically_verified,
    known_capabilities,
    project_capability,
    record_authorization,
    record_execution_evidence,
    record_installation,
    self_model_digest,
)

ENV = 'host:alpha'
OTHER_ENV = 'host:beta'
H1 = ManifestIdentity(hash_version=1, manifest_hash='a' * 16)
H2 = ManifestIdentity(hash_version=1, manifest_hash='b' * 16)


class TestGate43SelfModel(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-43-self-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.now = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    def count(self, table):
        conn = sqlite3.connect(self.db)
        try:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    def projection(self, capability='osint.identify', env=ENV, manifest=H1):
        return project_capability(self.db, capability_id=capability, environment_ref=env,
                                  manifest_identity=manifest, now=self.now)

    # ------------------------------------------------------------------ the hostile specimen
    def test_hostile_code_present_and_a_model_claim_is_not_a_capability(self):
        record_installation(self.db, capability_id='osint.identify', module_ref='osint.py',
                            environment_ref=ENV, manifest_identity=H1, now=self.now)
        record_model_output(self.db, model_ref='llm', output_text='I can perform OSINT',
                            proposition=canonical_proposition('ciph', 'can_osint', True),
                            now=self.now)
        projection = self.projection()
        self.assertTrue(projection.installed)
        self.assertTrue(projection.available)
        self.assertFalse(projection.authorized)
        self.assertFalse(projection.empirically_verified,
                         "a model saying it can do something verifies nothing")
        self.assertEqual(projection.claim_level, LEVEL_AVAILABLE)
        self.assertIn(REASON_NOT_AUTHORIZED, projection.reason_codes)
        with self.assertRaises(SelfModelError):
            assert_empirically_verified(self.db, 'osint.identify', environment_ref=ENV,
                                        manifest_identity=H1, now=self.now)

    # ------------------------------------------------------------------ the ladder
    def test_the_ladder_only_climbs_one_rung_at_a_time(self):
        self.assertEqual(self.projection().claim_level, LEVEL_UNKNOWN)

        record_installation(self.db, capability_id='osint.identify', module_ref='osint.py',
                            environment_ref=ENV, manifest_identity=H1, now=self.now)
        self.assertEqual(self.projection().claim_level, LEVEL_AVAILABLE)

        record_authorization(self.db, capability_id='osint.identify', environment_ref=ENV,
                             manifest_identity=H1, scope_ref='read-only', now=self.now)
        self.assertEqual(self.projection().claim_level, LEVEL_AUTHORIZED)
        self.assertIn(REASON_NOT_EMPIRICALLY_VERIFIED, self.projection().reason_codes)

        record_execution_evidence(self.db, capability_id='osint.identify', succeeded=True,
                                  attempt_ref='ATT-1', receipt_ref='RCP-1', environment_ref=ENV,
                                  manifest_identity=H1, now=self.now)
        verified = self.projection()
        self.assertEqual(verified.claim_level, LEVEL_VERIFIED)
        self.assertTrue(verified.empirically_verified)
        self.assertEqual(verified.reason_codes, ())

    # ------------------------------------------------------------------ law 2
    def test_law_2_verified_elsewhere_is_not_available_here(self):
        record_installation(self.db, capability_id='osint.identify', environment_ref=ENV,
                            manifest_identity=H1, now=self.now)
        record_authorization(self.db, capability_id='osint.identify', environment_ref=ENV,
                             manifest_identity=H1, now=self.now)
        record_execution_evidence(self.db, capability_id='osint.identify', succeeded=True,
                                  attempt_ref='ATT-1', environment_ref=ENV, manifest_identity=H1,
                                  now=self.now)
        self.assertEqual(self.projection(env=ENV).claim_level, LEVEL_VERIFIED)

        elsewhere = self.projection(env=OTHER_ENV)
        self.assertTrue(elsewhere.installed, "the code exists somewhere")
        self.assertFalse(elsewhere.available, "but not in this environment")
        self.assertEqual(elsewhere.claim_level, LEVEL_INSTALLED)
        self.assertIn(REASON_NOT_AVAILABLE_IN_ENVIRONMENT, elsewhere.reason_codes)

    # ------------------------------------------------------------------ law 8
    def test_law_8_evidence_under_one_manifest_does_not_prove_another(self):
        record_installation(self.db, capability_id='osint.identify', environment_ref=ENV,
                            manifest_identity=H1, now=self.now)
        record_authorization(self.db, capability_id='osint.identify', environment_ref=ENV,
                             manifest_identity=H1, now=self.now)
        record_authorization(self.db, capability_id='osint.identify', environment_ref=ENV,
                             manifest_identity=H2, now=self.now)
        record_execution_evidence(self.db, capability_id='osint.identify', succeeded=True,
                                  attempt_ref='ATT-1', environment_ref=ENV, manifest_identity=H1,
                                  now=self.now)
        self.assertEqual(self.projection(manifest=H1).claim_level, LEVEL_VERIFIED)
        under_h2 = self.projection(manifest=H2)
        self.assertTrue(under_h2.authorized)
        self.assertFalse(under_h2.empirically_verified,
                         "H1 evidence must not silently verify H2")
        self.assertEqual(under_h2.claim_level, LEVEL_AUTHORIZED)

    # ------------------------------------------------------------------ law 6
    def test_law_6_model_text_never_enters_the_self_model(self):
        record_installation(self.db, capability_id='osint.identify', environment_ref=ENV,
                            manifest_identity=H1, now=self.now)
        before = self.projection().canonical_digest()
        capabilities_before = known_capabilities(self.db)
        for _ in range(3):
            record_model_output(self.db, model_ref='llm', output_text='I am definitely authorized',
                                now=self.now)
        self.assertEqual(self.projection().canonical_digest(), before)
        self.assertEqual(known_capabilities(self.db), capabilities_before)
        self.assertEqual(self.count('ciph_self_authorizations'), 0)
        self.assertEqual(self.count('ciph_self_executions'), 0)

    # ------------------------------------------------------------------ laws 4, 5, 7, 9
    def test_law_5_and_7_a_failed_attempt_is_a_limitation_not_a_capability(self):
        record_installation(self.db, capability_id='osint.identify', environment_ref=ENV,
                            manifest_identity=H1, now=self.now)
        record_authorization(self.db, capability_id='osint.identify', environment_ref=ENV,
                             manifest_identity=H1, now=self.now)
        self.assertIsNone(self.projection().performance_ref)
        record_execution_evidence(self.db, capability_id='osint.identify', succeeded=False,
                                  attempt_ref='ATT-FAIL', environment_ref=ENV, manifest_identity=H1,
                                  now=self.now)
        projection = self.projection()
        self.assertFalse(projection.empirically_verified, "a failed attempt verifies nothing")
        self.assertEqual(projection.claim_level, LEVEL_AUTHORIZED)
        self.assertIn('osint.identify:attempt:ATT-FAIL:failed', projection.limitations)
        self.assertIsNotNone(projection.performance_ref,
                             "governed execution evidence, not self-assessment, supplies performance")

    # ------------------------------------------------------------------ law 10
    def test_law_10_unknown_is_a_valid_and_honest_answer(self):
        projection = self.projection(capability='never.heard.of')
        self.assertEqual(projection.claim_level, LEVEL_UNKNOWN)
        self.assertFalse(projection.installed)
        self.assertFalse(projection.empirically_verified)
        self.assertEqual(projection.reason_codes, (REASON_NO_INSTALLATION,))
        self.assertEqual(projection.limitations, ())
        self.assertIsNone(projection.performance_ref)

    # ------------------------------------------------------------------ law 11
    def test_law_11_history_is_append_only_and_deduplicated(self):
        record_installation(self.db, capability_id='osint.identify', module_ref='osint.py',
                            environment_ref=ENV, manifest_identity=H1, now=self.now)
        record_installation(self.db, capability_id='osint.identify', module_ref='osint.py',
                            environment_ref=ENV, manifest_identity=H1, now=self.now + 5)
        self.assertEqual(self.count('ciph_self_installations'), 1,
                         "the same installation is one record, however often it is reported")
        record_installation(self.db, capability_id='osint.identify', module_ref='osint_v2.py',
                            environment_ref=ENV, manifest_identity=H1, now=self.now + 6)
        self.assertEqual(self.count('ciph_self_installations'), 2)
        self.assertTrue(self.projection().installed)

    # ------------------------------------------------------------------ law 12
    def test_law_12_self_model_digest_is_deterministic_across_restart_and_process(self):
        record_installation(self.db, capability_id='osint.identify', environment_ref=ENV,
                            manifest_identity=H1, now=self.now)
        record_authorization(self.db, capability_id='osint.identify', environment_ref=ENV,
                             manifest_identity=H1, now=self.now)
        record_execution_evidence(self.db, capability_id='osint.identify', succeeded=True,
                                  attempt_ref='ATT-1', environment_ref=ENV, manifest_identity=H1,
                                  now=self.now)
        expected = self_model_digest(self.db, environment_ref=ENV, manifest_identity=H1)
        self.assertEqual(self_model_digest(self.db, environment_ref=ENV, manifest_identity=H1),
                         expected)
        code = ("import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.self_model import self_model_digest;"
                "print(self_model_digest(%r, environment_ref=%r, manifest_identity=%r))"
                % (str(Path(__file__).resolve().parents[1]), self.db, ENV, str(H1)))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)

    # ------------------------------------------------------------------ guard
    def test_the_guard_refuses_the_sentence_i_can_do_this(self):
        record_installation(self.db, capability_id='osint.identify', environment_ref=ENV,
                            manifest_identity=H1, now=self.now)
        with self.assertRaises(SelfModelError) as refused:
            assert_empirically_verified(self.db, 'osint.identify', environment_ref=ENV,
                                        manifest_identity=H1, now=self.now)
        self.assertEqual(refused.exception.reason, 'CAPABILITY_NOT_VERIFIED')
        with self.assertRaises(SelfModelError) as unknown:
            assert_empirically_verified(self.db, 'never.heard.of', environment_ref=ENV,
                                        manifest_identity=H1, now=self.now)
        self.assertEqual(unknown.exception.reason, 'CAPABILITY_NOT_VERIFIED')


if __name__ == '__main__':
    unittest.main()
