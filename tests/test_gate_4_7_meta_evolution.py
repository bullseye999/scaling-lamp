"""
4.7 - meta-evolution.

    New rules cannot ratify themselves.

Classification, epochs and the self-ratification predicate, plus the hostile cases that matter most: a
candidate evaluator judging itself, two shadow candidates colluding, and an evaluator that would make a
constitutional invariant tradeable.
"""

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.evolution_epochs import (
    assert_history_not_rewritten,
    current_epoch,
    epoch_digest,
    epoch_history,
    get_epoch,
    judgments_for,
    open_epoch,
    record_judgment,
    rollback_epoch,
    rollback_history,
    transition_epoch,
)
from ciph.kernel.meta_guard import (
    MAX_META_GENERATION_DEPTH_V1,
    REASON_COLLUSION,
    REASON_HARD_INVARIANT,
    REASON_SELF_RATIFICATION,
    assert_hard_invariants_preserved,
    assert_independent_judgment,
    assert_meta_promotion_allowed,
    assert_recursion_allowed,
    get_meta_candidate,
    meta_standing,
    record_meta_judgment,
    recursive_generation_permitted,
    register_meta_candidate,
)
from ciph.kernel.meta_targets import (
    DISP_META_ALLOWED,
    DISP_META_FORBIDDEN,
    DISP_META_REQUIRES_EXTERNAL_REVIEW,
    DISP_ORDINARY_4_6,
    META_TARGET_POLICY_V1,
    assert_ordinary_loop_may_proceed,
    classification_digest,
    classification_history,
    classify,
    classify_target,
    get_classification,
    ring_of,
)

EVALUATOR = ['ciph/kernel/crucible_metrics.py']
GENERATOR = ['ciph/evolution/gap_detector.py']
ORDINARY = ['ciph/capabilities/planner.py']
ROOT0 = ['ciph/kernel/execution_authority.py']


class TestGate47MetaEvolution(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-47-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ Gate Zero
    def test_gate_zero_ring_classification_is_deterministic_and_dispositioned(self):
        cases = [(ORDINARY, DISP_ORDINARY_4_6, 'ORDINARY'),
                 (GENERATOR, DISP_META_ALLOWED, 'IMPROVEMENT_MACHINERY'),
                 (EVALUATOR, DISP_META_REQUIRES_EXTERNAL_REVIEW, 'EVALUATION_CONSTITUTION'),
                 (ROOT0, DISP_META_FORBIDDEN, 'CONSTITUTIONAL_ROOT')]
        for files, disposition, ring in cases:
            with self.subTest(files=files):
                classification = classify_target(self.db, changed_files=files, now=self.t1)
                self.assertEqual(classification.target_ring, ring)
                self.assertEqual(classification.disposition, disposition)
                self.assertEqual(classification.policy_version, META_TARGET_POLICY_V1)
                self.assertEqual(get_classification(self.db, classification.classification_id),
                                 classification)
        self.assertEqual(ring_of('ciph/kernel/permit_store.py'), 'CONSTITUTIONAL_ROOT')
        self.assertEqual(len(classification_history(self.db)), 4)

    def test_gate_zero_the_diff_decides_not_the_description(self):
        classification = classify_target(
            self.db, changed_files=GENERATOR + EVALUATOR,
            declared_description='improve gap_detector', now=self.t1)
        self.assertEqual(classification.target_ring, 'EVALUATION_CONSTITUTION',
                         'a Ring-1 change cannot be smuggled inside a Ring-2 story')
        self.assertIn('ciph/kernel/crucible_metrics.py', classification.affected_components)
        # Law 4: injecting a protected component through DEPENDENCIES counts the same way.
        injected = classify_target(self.db, changed_files=GENERATOR,
                                   dependencies=['ciph/kernel/crucible_promotion.py'], now=self.t1)
        self.assertEqual(injected.disposition, DISP_META_FORBIDDEN)

    def test_gate_zero_unknown_targets_fail_upward(self):
        self.assertEqual(classify(changed_files=['ciph/kernel/brand_new_module.py'])[0],
                         'EVALUATION_CONSTITUTION')
        self.assertEqual(classify(changed_files=['ciph/evolution/new_thing.py'])[0],
                         'EVALUATION_CONSTITUTION')
        self.assertEqual(classify(changed_files=['ciph/capabilities/new_thing.py'])[0], 'ORDINARY')

    def test_gate_zero_the_ordinary_loop_may_not_carry_ring0_or_ring1(self):
        for files, reason in ((ROOT0, 'META_RING_0_FORBIDDEN'),
                             (EVALUATOR, 'META_EXTERNAL_REVIEW_REQUIRED')):
            with self.subTest(files=files):
                classification = classify_target(self.db, changed_files=files, now=self.t1)
                with self.assertRaises(CrucibleError) as refused:
                    assert_ordinary_loop_may_proceed(classification)
                self.assertEqual(refused.exception.reason, reason)

    # ------------------------------------------------------------------ Gate Six / Seven
    def test_gate_six_a_new_epoch_does_not_rewrite_an_old_judgment(self):
        epoch7 = open_epoch(self.db, generator_identity='G1', evaluator_identity='E0',
                            safety_policy_identity='S1', crucible_policy_identity='P1',
                            authority_ref='operator:operator', now=self.t1)
        record_judgment(self.db, epoch_id=epoch7.epoch_id, candidate_id='CC-C17',
                        comparison_status='DOMINATED', protocol_id='CP-1', now=self.t1)
        epoch9 = transition_epoch(self.db, generator_identity='G2', evaluator_identity='E1',
                                  authority_ref='operator:operator', now=self.t1 + 10)
        self.assertEqual(epoch9.predecessor_epoch, epoch7.epoch_id)
        self.assertEqual(epoch9.crucible_policy_identity, 'P1', 'unnamed components are inherited')
        record_judgment(self.db, epoch_id=epoch9.epoch_id, candidate_id='CC-C17',
                        comparison_status='DOMINATES', protocol_id='CP-2', now=self.t1 + 20)
        judgments = judgments_for(self.db, 'CC-C17')
        self.assertEqual([item['comparison_status'] for item in judgments],
                         ['DOMINATED', 'DOMINATES'],
                         'both historical evaluations survive, each under its own epoch')
        self.assertEqual([item['epoch_id'] for item in judgments],
                         [epoch7.epoch_id, epoch9.epoch_id])
        self.assertEqual(current_epoch(self.db).epoch_id, epoch9.epoch_id)

    def test_gate_seven_a_judgment_cannot_be_restated_inside_its_own_epoch(self):
        epoch = open_epoch(self.db, generator_identity='G1', evaluator_identity='E0',
                           authority_ref='operator:operator', now=self.t1)
        record_judgment(self.db, epoch_id=epoch.epoch_id, candidate_id='CC-C1',
                        comparison_status='DOMINATED', now=self.t1)
        with self.assertRaises(CrucibleError) as refused:
            assert_history_not_rewritten(self.db, 'CC-C1', epoch_id=epoch.epoch_id,
                                         comparison_status='DOMINATES')
        self.assertEqual(refused.exception.reason, 'EPOCH_HISTORY_IS_APPEND_ONLY')
        assert_history_not_rewritten(self.db, 'CC-C1', epoch_id='EP-OTHER',
                                     comparison_status='DOMINATES')

    def test_gate_eight_meta_rollback_restores_the_component_without_deleting_the_era(self):
        """Restoration is a NEW epoch, never time travel: the bad era stays a historical period."""
        epoch7 = open_epoch(self.db, generator_identity='G1', evaluator_identity='E0',
                            authority_ref='operator:operator', now=self.t1)
        epoch8 = transition_epoch(self.db, generator_identity='G2', authority_ref='operator:operator',
                                  now=self.t1 + 10)
        new_epoch_id = rollback_epoch(self.db, bad_epoch=epoch8.epoch_id,
                                      restored_epoch=epoch7.epoch_id, restored_component='G1',
                                      evidence_refs=['IAT-9'], authority_ref='operator:operator',
                                      now=self.t1 + 20)
        self.assertTrue(new_epoch_id.startswith('EP-'))
        self.assertNotEqual(new_epoch_id, epoch7.epoch_id, 'a rollback does not re-enter an old epoch')
        restored = get_epoch(self.db, new_epoch_id)
        self.assertEqual(restored.generator_identity, 'G1')
        self.assertEqual(restored.rollback_of, epoch8.epoch_id)
        self.assertEqual(restored.restored_identity_from, epoch7.epoch_id)
        self.assertEqual(restored.predecessor_epoch, epoch8.epoch_id)
        self.assertEqual(current_epoch(self.db).epoch_id, new_epoch_id)
        self.assertEqual(len(rollback_history(self.db)), 1)
        self.assertEqual(len(epoch_history(self.db)), 3, 'neither earlier era is deleted')
        self.assertEqual(get_epoch(self.db, epoch8.epoch_id).generator_identity, 'G2')
        with self.assertRaises(CrucibleError) as refused:
            rollback_epoch(self.db, bad_epoch=epoch8.epoch_id, restored_epoch=epoch8.epoch_id,
                           restored_component='G2', authority_ref='operator:operator', now=self.t1 + 30)
        self.assertEqual(refused.exception.reason, 'ROLLBACK_MUST_RESTORE_AN_EARLIER_EPOCH')
        self.assertTrue(epoch_digest(self.db))

    # ------------------------------------------------------------------ self-ratification
    def test_new_rules_cannot_ratify_themselves(self):
        meta = register_meta_candidate(self.db, changed_files=GENERATOR, artifact_digest='HA',
                                       configuration_digest='CF', baseline_component_identity='G1',
                                       proposed_by='ciph', now=self.t1)
        self.assertTrue(meta.shadow_only, 'law 1: a meta candidate starts shadow-only')
        self.assertEqual(meta.target_ring, 'IMPROVEMENT_MACHINERY')

        record_meta_judgment(self.db, meta_candidate_id=meta.meta_candidate_id,
                             judge_identity=meta.meta_candidate_id, verdict='PASS', now=self.t1)
        self.assertEqual(meta_standing(self.db, meta.meta_candidate_id), (0,),
                         'a candidate judging itself confers nothing')

        other = register_meta_candidate(self.db, changed_files=GENERATOR, artifact_digest='HB',
                                        configuration_digest='CF', now=self.t1)
        record_meta_judgment(self.db, meta_candidate_id=meta.meta_candidate_id,
                             judge_identity=other.meta_candidate_id, verdict='PASS', now=self.t1)
        self.assertEqual(meta_standing(self.db, meta.meta_candidate_id), (0, 0),
                         'law 4: two shadow candidates cannot give each other a pass')

        record_meta_judgment(self.db, meta_candidate_id=meta.meta_candidate_id,
                             judge_identity='AUTHORITATIVE:' + str(self.t1), verdict='DOMINATES',
                             now=self.t1)
        self.assertEqual(meta_standing(self.db, meta.meta_candidate_id), (0, 0, 1),
                         'the pre-change authoritative generation is the judge that counts')

        with self.assertRaises(CrucibleError) as replaced:
            assert_independent_judgment(self.db, meta_candidate_id=meta.meta_candidate_id,
                                        judge_identity=GENERATOR[0])
        self.assertEqual(replaced.exception.reason, REASON_SELF_RATIFICATION)

    def test_the_machinery_cannot_be_reached_through_the_ordinary_loop(self):
        for files, reason in ((ROOT0, 'META_RING_0_FORBIDDEN'),
                             (EVALUATOR, 'META_EXTERNAL_REVIEW_REQUIRED')):
            with self.subTest(files=files):
                with self.assertRaises(CrucibleError) as refused:
                    register_meta_candidate(self.db, changed_files=files, artifact_digest='H',
                                            configuration_digest='C', now=self.t1)
                self.assertEqual(refused.exception.reason, reason)

    def test_hard_constitutional_invariants_are_not_tradeable_at_any_speed(self):
        with self.assertRaises(CrucibleError) as refused:
            assert_hard_invariants_preserved({'tradeable': ['NO_FABRICATED_EVIDENCE'],
                                              'expected_gain': '+50% success'})
        self.assertEqual(refused.exception.reason, REASON_HARD_INVARIANT)
        with self.assertRaises(CrucibleError):
            assert_hard_invariants_preserved({'NO_AUTHORITY_BYPASS': False})
        assert_hard_invariants_preserved({'tradeable': ['latency'], 'NO_FABRICATED_EVIDENCE': True})

    def test_recursive_generation_is_bounded(self):
        self.assertEqual(MAX_META_GENERATION_DEPTH_V1, 1)
        self.assertTrue(recursive_generation_permitted(generation_depth=1))
        self.assertFalse(recursive_generation_permitted(generation_depth=2))
        with self.assertRaises(CrucibleError) as refused:
            assert_recursion_allowed(generation_depth=2)
        self.assertEqual(refused.exception.reason, 'META_RECURSION_DEPTH_EXCEEDED')
        with self.assertRaises(CrucibleError):
            register_meta_candidate(self.db, changed_files=GENERATOR, artifact_digest='H',
                                    configuration_digest='C', generation_depth=2, now=self.t1)

    def test_meta_promotion_needs_standing_evidence_and_authorization(self):
        meta = register_meta_candidate(self.db, changed_files=GENERATOR, artifact_digest='HA',
                                       configuration_digest='CF', now=self.t1)
        with self.assertRaises(CrucibleError) as refused:
            assert_meta_promotion_allowed(self.db, meta_candidate_id=meta.meta_candidate_id,
                                          ordinary_standing='DOMINATES',
                                          meta_protocol_standing='DOMINATES',
                                          authority_ref='operator:operator')
        self.assertIn('NO_INDEPENDENT_META_JUDGMENT', refused.exception.detail)
        record_meta_judgment(self.db, meta_candidate_id=meta.meta_candidate_id,
                             judge_identity='AUTHORITATIVE:epoch-1', verdict='DOMINATES', now=self.t1)
        with self.assertRaises(CrucibleError) as wrong:
            assert_meta_promotion_allowed(self.db, meta_candidate_id=meta.meta_candidate_id,
                                          ordinary_standing='INCOMPARABLE',
                                          meta_protocol_standing='DOMINATES',
                                          authority_ref='operator:operator')
        self.assertIn('ORDINARY_STANDING', wrong.exception.detail)
        with self.assertRaises(CrucibleError) as violations:
            assert_meta_promotion_allowed(self.db, meta_candidate_id=meta.meta_candidate_id,
                                          ordinary_standing='DOMINATES',
                                          meta_protocol_standing='DOMINATES',
                                          authority_ref='operator:operator',
                                          constitutional_violations=1)
        self.assertIn('CONSTITUTIONAL_VIOLATIONS', violations.exception.detail)
        assert_meta_promotion_allowed(self.db, meta_candidate_id=meta.meta_candidate_id,
                                      ordinary_standing='DOMINATES',
                                      meta_protocol_standing='DOMINATES',
                                      authority_ref='operator:operator')

        ring1 = register_meta_candidate(self.db, changed_files=GENERATOR, artifact_digest='HZ',
                                        configuration_digest='CZ', now=self.t1)
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE ciph_meta_candidates SET target_ring='EVALUATION_CONSTITUTION' "
                               "WHERE meta_candidate_id=?;", (ring1.meta_candidate_id,))
            connection.commit()
        finally:
            connection.close()
        record_meta_judgment(self.db, meta_candidate_id=ring1.meta_candidate_id,
                             judge_identity='AUTHORITATIVE:epoch-1', verdict='DOMINATES', now=self.t1)
        with self.assertRaises(CrucibleError) as external:
            assert_meta_promotion_allowed(self.db, meta_candidate_id=ring1.meta_candidate_id,
                                          ordinary_standing='DOMINATES',
                                          meta_protocol_standing='DOMINATES',
                                          authority_ref=None)
        self.assertIn('EXTERNAL_AUTHORIZATION_REQUIRED', external.exception.detail)


if __name__ == '__main__':
    unittest.main()
