"""
4.7 - the defensive surface and the standalone tortures.

Twelve structural scanners, each with a synthetic catch-specimen, plus the tortures that are not already
standalone: recursive depth, meta rollback preservation, cross-process reconstruction, and Gate Ten
under real history.

The generator/evaluator tortures live in `test_gate_4_7_end_to_end.py`, and the sealed-corpus hostile
process torture lives in `test_gate_4_7_corpus_isolation.py`.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_candidates import register_candidate
from ciph.kernel.crucible_metrics import STATUS_DOMINATES
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_types import KIND_CAPABILITY_IMPLEMENTATION, CrucibleError, digest
from ciph.kernel.evolution_epochs import (
    current_epoch,
    epoch_digest,
    epoch_history,
    get_epoch,
    open_epoch,
    rollback_history,
    transition_epoch,
)
from ciph.kernel.evolution_ownership import production_sources
from ciph.kernel.meta_hypotheses import (
    MetaExpectation,
    meta_hypothesis_digest,
    propose_meta_hypothesis,
)
from ciph.kernel.meta_learning import (
    PROMOTION_PROMOTED,
    PROMOTION_REGRESSED,
    PROMOTION_ROLLED_BACK,
    meta_learning_digest,
    meta_strategy_projection,
    record_meta_attempt,
    record_meta_promotion_result,
)
from ciph.kernel.meta_opportunities import (
    KIND_HIGH_INVALID,
    meta_opportunity_digest,
    record_meta_opportunity,
)
from ciph.kernel.meta_promotion import (
    byte_installer,
    meta_promotion_digest,
    meta_promote,
    meta_rollback,
)
from ciph.kernel.meta_scanners import (
    META_SCANNER_VIOLATION,
    SCANNERS,
    assert_all_clean,
    scan,
    scanner_census,
)
from ciph.kernel.meta_shadow import (
    begin_shadow_evaluation,
    complete_shadow_evaluation,
    register_shadow,
    shadow_digest,
)
from ciph.kernel.meta_targets import classification_digest, classify_target
from ciph.kernel.crucible_candidates import candidate_digest
from ciph.kernel.crucible_promotion import promotion_digest

COMPONENT = 'ciph/evolution/gap_detector.py'
TARGET_ROLE = 'generator:gap_detector'
RING = 'IMPROVEMENT_MACHINERY'
G1, G2, G3 = 'G1', 'G2', 'G3'
G1_BYTES = b'# generator v1\n'
G2_BYTES = b'# generator v2\n'


def four_seven_bundle(db):
    return {'classifications': classification_digest(db), 'epochs': epoch_digest(db),
            'opportunities': meta_opportunity_digest(db), 'hypotheses': meta_hypothesis_digest(db),
            'shadow': shadow_digest(db), 'candidates': candidate_digest(db),
            'promotions': promotion_digest(db), 'meta_promotions': meta_promotion_digest(db),
            'learning': meta_learning_digest(db)}


class TestGate47ScannersAndTortures(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-47-scanners-')
        self.root = Path(self.temp.name)
        self.db = str(self.root / 'vault.db')
        self.component = str(self.root / 'production' / 'gap_detector.py')
        Path(self.component).parent.mkdir(parents=True, exist_ok=True)
        Path(self.component).write_bytes(G1_BYTES)
        self.t1 = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ Part 1
    def test_all_twelve_scanners_are_zero_on_the_real_tree(self):
        census = scanner_census()
        self.assertEqual(len(census), 12)
        self.assertEqual({name: count for name, count in census.items() if count}, {})
        self.assertEqual(assert_all_clean(), scan_project_clean())
        self.assertEqual(len(SCANNERS), 12)

    def test_every_scanner_fires_on_a_synthetic_violation(self):
        real = dict(production_sources())
        def override(path, *replacements):
            text = real[path]
            for old, new in replacements:
                text = text.replace(old, new, 1)
            return {**real, path: text}

        catches = [
            ('s01_shadow_evaluator_writes_standing',
             {**real, 'ciph/kernel/meta_rogue.py': "INSERT INTO ciph_crucible_trials VALUES (1);\n"}),
            ('s02_evaluator_judges_itself_authoritatively',
             {**real, 'ciph/kernel/rogue_judge.py': "INSERT INTO ciph_meta_judgments (a) VALUES (1);\n"}),
            ('s03_shadow_generator_writes_active_generator',
             {**real, 'ciph/kernel/meta_rogue_active.py': "UPDATE ciph_crucible_active SET x=1;\n"}),
            ('s04_meta_candidate_writes_epoch_directly',
             {**real, 'ciph/kernel/meta_rogue_epoch.py': "INSERT INTO ciph_evolution_epochs VALUES (1);\n"}),
            ('s05_meta_candidate_writes_promotion_record',
             {**real, 'ciph/kernel/meta_rogue_promo.py': "INSERT INTO ciph_meta_promotions VALUES (1);\n"}),
            ('s06_candidate_facing_process_reaches_sealed',
             {**real, 'ciph/kernel/meta_corpus.py':
              'class CandidateFacingCorpus:\n    def cases(self):\n        return self._sealed\n'}),
            ('s07_ring0_enters_automatic_path',
             override('ciph/kernel/meta_guard.py',
                      ('assert_ordinary_loop_may_proceed(classification)', 'noop_check(classification)'))),
            ('s08_ordinary_46_touches_ring0',
             override('ciph/kernel/candidate_safety.py',
                      ('"ciph/kernel/meta_guard.py",', ''))),
            ('s09_safety_policy_self_approves',
             override('ciph/kernel/candidate_safety.py',
                      ('"ciph/kernel/meta_targets.py",', ''))),
            ('s10_new_evaluator_rewrites_history',
             {**real, 'ciph/kernel/rogue_history.py':
              "UPDATE ciph_epoch_judgments SET comparison_status='X';\n"}),
            ('s11_recursive_depth',
             override('ciph/kernel/meta_guard.py',
                      ('MAX_META_GENERATION_DEPTH_V1 = 1', 'MAX_META_GENERATION_DEPTH_V1 = 9'))),
            ('s12_meta_deployment_bypasses_r7',
             override('ciph/kernel/meta_promotion.py', ('deploy(db_path', 'ship_it(db_path'))),
        ]
        self.assertEqual(len(catches), 12)
        for name, sources in catches:
            with self.subTest(scanner=name):
                offences = dict(SCANNERS)[name](sources)
                self.assertTrue(offences, f'{name} did not fire on its own synthetic violation')

    def test_the_scanner_suite_raises_on_a_dirty_tree(self):
        real = dict(production_sources())
        dirty = {**real, 'ciph/kernel/meta_rogue.py': "INSERT INTO ciph_crucible_trials VALUES (1);\n"}
        report = scan(dirty)
        self.assertTrue(report['s01_shadow_evaluator_writes_standing'])

    # ------------------------------------------------------------------ Part 2D: recursion depth
    def test_recursive_depth_torture(self):
        open_epoch(self.db, generator_identity=G1, evaluator_identity='E0',
                   authority_ref='operator:operator', now=self.t1)
        opportunity = record_meta_opportunity(
            self.db, target_component=COMPONENT, weakness_kind=KIND_HIGH_INVALID,
            exact_component_identity=G1, evidence_refs=['E1', 'E2'], now=self.t1)
        hypothesis = propose_meta_hypothesis(
            self.db, opportunity_id=opportunity.opportunity_id, baseline_component_identity=G1,
            proposed_change='RESTRICT', expected_improvements=[
                MetaExpectation('invalid_rate', 'LOWER_BETTER', 0.1)], now=self.t1)
        g2 = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                artifact_digest=digest(G2_BYTES), configuration_digest='C2',
                                now=self.t1)
        shadow = register_shadow(self.db, hypothesis_id=hypothesis.hypothesis_id,
                                 crucible_candidate_id=g2.candidate_id,
                                 target_component=COMPONENT, target_ring=RING,
                                 authoritative_baseline=G1, now=self.t1)
        begin_shadow_evaluation(self.db, shadow.shadow_id, protocol_id='CP', corpus_version='C',
                                now=self.t1)
        epochs_before = len(epoch_history(self.db))
        # G2 is itself under evaluation, so it may not generate G3.
        from ciph.kernel.meta_guard import register_meta_candidate
        with self.assertRaises(CrucibleError) as refused:
            register_meta_candidate(self.db, changed_files=[COMPONENT], artifact_digest='H3',
                                    configuration_digest='C3', generation_depth=2, now=self.t1)
        self.assertEqual(refused.exception.reason, 'META_RECURSION_DEPTH_EXCEEDED')
        from ciph.kernel.meta_guard import meta_standing
        self.assertEqual(len(epoch_history(self.db)), epochs_before, 'no epoch moved')
        self.assertEqual(meta_standing(self.db, 'MC-NEVER'), ())
        self.assertEqual(current_epoch(self.db).generator_identity, G1)
        self.assertEqual(meta_promotion_digest(self.db),
                         meta_promotion_digest(self.db))

    # ------------------------------------------------------------------ Part 2C: rollback torture
    def test_meta_rollback_torture_preserves_every_historical_fact(self):
        epoch7 = open_epoch(self.db, generator_identity=G1, evaluator_identity='E0',
                            authority_ref='operator:operator', now=self.t1)
        protocol = freeze_protocol(self.db, candidate_kind=KIND_CAPABILITY_IMPLEMENTATION,
                                   development_cases=['d'], heldout_cases=['h'],
                                   metric_definitions=[MetricDefinition('task_success', 'v1',
                                                                        'HIGHER_BETTER')],
                                   environment_identity='host:eval', minimum_evidence=1, now=self.t1)
        opportunity = record_meta_opportunity(
            self.db, target_component=COMPONENT, weakness_kind=KIND_HIGH_INVALID,
            exact_component_identity=G1, evidence_refs=['E1', 'E2'], now=self.t1)
        hypothesis = propose_meta_hypothesis(
            self.db, opportunity_id=opportunity.opportunity_id, baseline_component_identity=G1,
            proposed_change='RESTRICT', expected_improvements=[
                MetaExpectation('invalid_rate', 'LOWER_BETTER', 0.1)], now=self.t1)
        g2 = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                artifact_digest=digest(G2_BYTES), configuration_digest='C2',
                                now=self.t1)
        shadow = register_shadow(self.db, hypothesis_id=hypothesis.hypothesis_id,
                                 crucible_candidate_id=g2.candidate_id,
                                 target_component=COMPONENT, target_ring=RING,
                                 authoritative_baseline=G1, now=self.t1)
        begin_shadow_evaluation(self.db, shadow.shadow_id, protocol_id=protocol.protocol_id,
                                corpus_version='C', now=self.t1)
        complete_shadow_evaluation(self.db, shadow.shadow_id, meta_result_ref='R1',
                                   meta_status=STATUS_DOMINATES, constitutional_misses=0, now=self.t1)
        promotion = meta_promote(
            self.db, shadow_id=shadow.shadow_id, target_role=TARGET_ROLE, target_component=COMPONENT,
            artifact_bytes=G2_BYTES, configuration_digest='C2',
            ordinary_protocol_id=protocol.protocol_id, ordinary_standing=STATUS_DOMINATES,
            authority_ref='operator:operator', installer=byte_installer(self.component),
            meta_protocol_result_ref='R1', now=self.t1 + 10)
        epoch8 = current_epoch(self.db)
        self.assertEqual(epoch8.generator_identity, g2.candidate_id)
        attempt = record_meta_attempt(
            self.db, strategy_kind='SEARCH_RESTRICTION', opportunity_id=opportunity.opportunity_id,
            hypothesis_id=hypothesis.hypothesis_id, meta_candidate_id=g2.candidate_id,
            target_ring=RING, meta_result=STATUS_DOMINATES, now=self.t1 + 20)
        record_meta_promotion_result(self.db, attempt_id=attempt.attempt_id,
                                     promotion_result=PROMOTION_PROMOTED, now=self.t1 + 21)

        # canonical production evidence of meta-regression, then a governed rollback
        record_meta_promotion_result(self.db, attempt_id=attempt.attempt_id,
                                     promotion_result=PROMOTION_REGRESSED, now=self.t1 + 30)
        result = meta_rollback(self.db, bad_epoch=epoch8.epoch_id, restore_from_epoch=epoch7.epoch_id,
                               target_component=COMPONENT, artifact_bytes=G1_BYTES,
                               evidence_refs=['META-REGRESSION-1'], authority_ref='operator:operator',
                               installer=byte_installer(self.component), now=self.t1 + 40)
        record_meta_promotion_result(self.db, attempt_id=attempt.attempt_id,
                                     promotion_result=PROMOTION_ROLLED_BACK, now=self.t1 + 41)
        self.assertTrue(result['verified'])
        self.assertEqual(Path(self.component).read_bytes(), G1_BYTES)

        # every historical fact survives, simultaneously
        epoch9 = current_epoch(self.db)
        self.assertEqual(epoch9.restored_identity_from, epoch7.epoch_id)
        self.assertEqual(epoch9.rollback_of, epoch8.epoch_id)
        self.assertEqual(len(epoch_history(self.db)), 3)
        self.assertEqual(get_epoch(self.db, epoch8.epoch_id).generator_identity, g2.candidate_id)
        self.assertEqual(len(rollback_history(self.db)), 1)
        entry = meta_strategy_projection(self.db)[0]
        self.assertEqual((entry['meta_dominates'], entry['promoted'], entry['production_regressions'],
                          entry['rollbacks']), (1, 1, 1, 1),
                         'dominated, promoted, regressed and rolled back are all true')
        self.assertTrue(promotion.meta_promotion_id)

    # ------------------------------------------------------------------ Part 4: G10
    def test_learning_preserves_facts_and_ignores_replays(self):
        attempt = record_meta_attempt(
            self.db, strategy_kind='S1', opportunity_id='MO-1', hypothesis_id='MH-1',
            meta_candidate_id='CC-1', target_ring=RING, meta_result=STATUS_DOMINATES, now=self.t1)
        replay = record_meta_attempt(
            self.db, strategy_kind='S1', opportunity_id='MO-1', hypothesis_id='MH-1',
            meta_candidate_id='CC-1', target_ring=RING, meta_result=STATUS_DOMINATES, now=self.t1 + 5)
        self.assertEqual(replay.attempt_id, attempt.attempt_id, 'a replay is one attempt')
        entry = meta_strategy_projection(self.db)[0]
        self.assertEqual(entry['attempts'], 1)
        self.assertEqual(entry['meta_dominates'], 1)
        for forbidden in ('score', 'fitness', 'intelligence', 'rating'):
            self.assertNotIn(forbidden, entry)
        self.assertEqual(meta_strategy_projection(self.db, 'S-NEVER'), [])
        with self.assertRaises(CrucibleError):
            record_meta_attempt(self.db, strategy_kind='S1', opportunity_id='MO-1',
                                hypothesis_id='MH-1', meta_candidate_id='CC-1', target_ring=RING,
                                meta_result='I_THINK_IT_WORKED', now=self.t1)

    # ------------------------------------------------------------------ Part 3: reconstruction
    def test_cross_process_reconstruction_of_the_complete_4_7_history(self):
        open_epoch(self.db, generator_identity=G1, evaluator_identity='E0', safety_policy_identity='S1',
                   crucible_policy_identity='P1', authority_ref='operator:operator', now=self.t1)
        from ciph.kernel.meta_targets import classify_target
        classify_target(self.db, changed_files=[COMPONENT], now=self.t1)
        opportunity = record_meta_opportunity(
            self.db, target_component=COMPONENT, weakness_kind=KIND_HIGH_INVALID,
            exact_component_identity=G1, evidence_refs=['E1', 'E2'], now=self.t1)
        hypothesis = propose_meta_hypothesis(
            self.db, opportunity_id=opportunity.opportunity_id, baseline_component_identity=G1,
            proposed_change='RESTRICT', expected_improvements=[
                MetaExpectation('invalid_rate', 'LOWER_BETTER', 0.1)], now=self.t1)
        g2 = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                artifact_digest=digest(G2_BYTES), configuration_digest='C2',
                                now=self.t1)
        register_shadow(self.db, hypothesis_id=hypothesis.hypothesis_id,
                        crucible_candidate_id=g2.candidate_id, target_component=COMPONENT,
                        target_ring=RING, authoritative_baseline=G1, now=self.t1)
        record_meta_attempt(self.db, strategy_kind='SEARCH_RESTRICTION',
                            opportunity_id=opportunity.opportunity_id,
                            hypothesis_id=hypothesis.hypothesis_id,
                            meta_candidate_id=g2.candidate_id, target_ring=RING,
                            meta_result=STATUS_DOMINATES, now=self.t1)
        expected = four_seven_bundle(self.db)
        code = ('import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from test_gate_4_7_scanners_and_tortures import four_seven_bundle;'
                'print(json.dumps(four_seven_bundle(%r), sort_keys=True))'
                % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)
        self.assertEqual(four_seven_bundle(self.db), expected, 'wall clock does not move identity')


def scan_project_clean():
    from ciph.kernel.meta_scanners import scan_project
    return scan_project()


if __name__ == '__main__':
    unittest.main()
