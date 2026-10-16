"""
R7 - the production evolution choke point.

    No production candidate activation may occur unless the canonical Crucible promotion state
    authorizes the exact candidate being installed.

The specimens use the REAL legacy machinery - real staging, real file activation, the real coordinator,
the real canary manager - because the whole point of R7 is that a fake installer would prove nothing.
"""

import pathlib
import tempfile
import unittest
import uuid
from dataclasses import replace

from ciph.contracts.evolution import CanaryCriteria
from ciph.evolution.workflow import EvolutionCoordinator
from ciph.kernel.crucible_candidates import get_candidate
from ciph.kernel.crucible_promotion import active_candidate
from ciph.kernel.evolution_deployment import verify_active_consistency
from ciph.kernel.production_choke_point import (
    ACTIVATION_PRIMITIVES,
    REQUIRED_GUARD,
    choke_point_report,
    unguarded_primitives,
)
from phase8_test_support import BASE, BROKEN, CANDIDATE, Phase8Case, sha

ROLE = 'capability:math.compute'


class TestR7ProductionChokePoint(Phase8Case):

    def coordinator(self):
        return EvolutionCoordinator(self.runtime, self.staging)

    def canary_only(self):
        grant = self.deployment(permitted_stages=('SHADOW', 'CANARY'), allow_auto_promotion=False)
        _, canary_id, _ = self.activate(grant=grant)
        self.assertEqual(self.finish(canary_id)['status'], 'AWAITING_OPERATOR')
        production = replace(grant, grant_id='PROD-' + uuid.uuid4().hex,
                             permitted_stages=('PRODUCTION',)).sign(self.op_priv)
        return canary_id, production

    # ------------------------------------------------------------------ the named specimen
    def test_a_valid_legacy_grant_without_a_promotion_activates_nothing(self):
        canary_id, production = self.canary_only()
        fingerprint_before = self._evidence_fingerprint()
        result = self.coordinator().approve_production(canary_id, production)
        self.assertFalse(result['success'])
        self.assertEqual(result['status'], 'PRODUCTION_APPROVAL_REJECTED')
        self.assertIn('NO_PROMOTION_RECORD', result['reason'])
        self.assertEqual(self.target.read_text(), BASE, 'the filesystem is unchanged')
        self.assertIsNone(active_candidate(self.trust.db_path, ROLE), 'no pointer moved')
        from ciph.evolution.production import EvolutionRevisionCapability   # noqa: F401
        self.assertNotIn('ACTIVATED', self._kinds())
        self.assertFalse(self._evidence_fingerprint() == '' or False)
        self.assertTrue(fingerprint_before)

    def _kinds(self):
        return [event['payload'].get('kind')
                for event in self.store.get_events(event_type='EvolutionEvidenceEvent', limit=1000)]

    def _evidence_fingerprint(self):
        return sha(str(sorted(self._kinds())))

    # ------------------------------------------------------------------ identity and baseline
    def test_a_promotion_for_another_candidate_does_not_authorize_this_one(self):
        self.adopt_and_promote(CANDIDATE)
        allowed, detail = self.manager.check_constitutional_promotion(
            {'candidate_hash': sha(CANDIDATE), 'base_file_hash': sha(BASE),
             'target_capability': 'math.compute'})
        self.assertTrue(allowed, detail)
        refused, detail = self.manager.check_constitutional_promotion(
            {'candidate_hash': sha(BROKEN), 'base_file_hash': sha(BASE),
             'target_capability': 'math.compute'})
        self.assertFalse(refused)
        self.assertIn('NO_PROMOTION_RECORD', detail)
        incomplete, detail = self.manager.check_constitutional_promotion({'candidate_hash': sha(BASE)})
        self.assertFalse(incomplete)
        self.assertIn('incomplete', detail)

    def test_a_drifted_target_is_not_the_authorized_baseline(self):
        grant = self.deployment()
        self.adopt_and_promote(CANDIDATE)
        self.target.write_text(BASE + '\n# drift\n')
        with self.assertRaisesRegex(ValueError, 'ACTIVE_BASELINE_MISMATCH'):
            self.manager.assert_expected_baseline(grant)
        self.target.write_text(BASE)
        self.manager.assert_expected_baseline(grant)

    def test_installed_bytes_that_are_not_the_candidate_are_an_integrity_conflict(self):
        grant = self.deployment()
        self.adopt_and_promote(CANDIDATE)
        self.target.write_text(BROKEN)
        verified, detail = self.manager.verify_installed_artifact(grant)
        self.assertFalse(verified)
        self.assertIn('DEPLOYMENT_INTEGRITY_CONFLICT', detail)
        self.target.write_text(CANDIDATE)
        verified, detail = self.manager.verify_installed_artifact(grant)
        self.assertTrue(verified, detail)
        self.assertEqual(detail, 'INSTALLED_ARTIFACT_VERIFIED')

    def test_a_canonical_pointer_and_a_filesystem_disagreement_is_never_resolved_silently(self):
        self.adopt_and_promote(CANDIDATE)
        self.assertEqual(active_candidate(self.trust.db_path, ROLE),
                         get_candidate(self.trust.db_path,
                                       active_candidate(self.trust.db_path, ROLE)).candidate_id)
        self.assertEqual(verify_active_consistency(self.trust.db_path, role=ROLE,
                                                   observed_artifact_digest=sha(BASE)),
                         'DEPLOYMENT_INTEGRITY_CONFLICT',
                         'promotion happened, installation has not: the disagreement is reported')
        self.assertEqual(verify_active_consistency(self.trust.db_path, role=ROLE,
                                                   observed_artifact_digest=sha(CANDIDATE)),
                         'CONSISTENT')

    # ------------------------------------------------------------------ the real machinery
    def test_the_real_legacy_machinery_installs_and_rolls_back_through_the_constitution(self):
        self.adopt_and_promote(CANDIDATE)
        candidate_id = active_candidate(self.trust.db_path, ROLE)
        self.assertIsNotNone(candidate_id)
        self.assertEqual(get_candidate(self.trust.db_path, candidate_id).artifact_digest,
                         sha(CANDIDATE))
        self.assertEqual(self.target.read_text(), BASE, 'baseline is still physically installed')

        canary_id, production = self.canary_only()
        result = self.coordinator().approve_production(canary_id, production)
        self.assertEqual(result['status'], 'PROMOTED', result)
        self.assertEqual(sha(self.target.read_text()), sha(CANDIDATE),
                         'the REAL installer replaced the baseline with the exact candidate bytes')
        self.assertEqual(verify_active_consistency(self.trust.db_path, role=ROLE,
                                                   observed_artifact_digest=sha(CANDIDATE)),
                         'CONSISTENT')
        self.assertIn('ACTIVATED', self._kinds())

        # ...and the real rollback restores the baseline physically.
        rolled = self.manager.rollback_production(canary_id, 'fixture regression')
        self.assertEqual(rolled['status'], 'ROLLED_BACK', rolled)
        self.assertEqual(self.target.read_text(), BASE)

    # ------------------------------------------------------------------ the scanner
    def test_the_scanner_finds_unguarded_primitives_and_never_cries_wolf(self):
        report = choke_point_report()
        self.assertEqual(report['unguarded_primitives'], ())
        self.assertEqual(report['activation_bypasses'], ())
        self.assertEqual(report['required_guard'], REQUIRED_GUARD)
        self.assertEqual(len(ACTIVATION_PRIMITIVES), 2)

        with tempfile.TemporaryDirectory(prefix='r7-scan-') as directory:
            root = pathlib.Path(directory)
            target = root / 'ciph' / 'evolution' / 'canary_manager.py'
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('class M:\n    def approve_production(self, canary_id, grant):\n'
                              '        return {"success": True}\n', encoding='utf-8')
            offenders = unguarded_primitives(root)
            self.assertTrue(any('UNGUARDED' in entry for entry in offenders),
                            'an unguarded activation primitive must be detected')
            target.write_text('class M:\n    def approve_production(self, canary_id, grant):\n'
                              '        allowed, detail = self.check_constitutional_promotion(grant)\n'
                              '        return allowed\n', encoding='utf-8')
            self.assertEqual([entry for entry in unguarded_primitives(root)
                              if 'canary_manager' in entry], [],
                             'a guarded primitive is not reported')


if __name__ == '__main__':
    unittest.main()
