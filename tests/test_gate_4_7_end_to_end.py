"""
4.7 - the complete functional meta-evolution loop.

One story, end to end, with real bytes on a real filesystem and the real 4.5 Crucible judging every
ordinary candidate:

    Epoch 7 (G1 generator, E0 evaluator)
      -> MO1 generator weakness, from historical evidence
      -> MH1 proposed generator change, pinned to G1's exact identity
      -> CC-G2 registered as a SHADOW candidate
      -> G1 and G2 face the same sealed corpus; E0 judges their outputs
      -> META_PARETO: G2 DOMINATES G1
      -> RESTART: still epoch 7, G1 still authoritative, G2 still shadow
      -> dual-control promotion -> R7 governed install -> exact bytes -> Epoch 8 = G2
      -> meta regression -> governed rollback -> exact bytes -> Epoch 9 = G1, 7 and 8 preserved

plus the evaluator torture: a replacement evaluator cannot rate itself, cannot collude, and cannot make
a hard invariant tradeable.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.crucible_candidates import candidate_digest, register_candidate
from ciph.kernel.crucible_candidates import get_candidate
from ciph.kernel.crucible_metrics import (
    STATUS_DOMINATED,
    STATUS_DOMINATES,
    STATUS_EQUIVALENT,
    STATUS_INCOMPARABLE,
    STATUS_INSUFFICIENT,
    STATUS_INVALID,
    PerformanceVector,
    compare,
)
from ciph.kernel.crucible_promotion import promotion_digest
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol
from ciph.kernel.crucible_types import KIND_CAPABILITY_IMPLEMENTATION, CrucibleError, digest
from ciph.kernel.evolution_epochs import (
    current_epoch,
    epoch_digest,
    epoch_history,
    open_epoch,
    rollback_history,
)
from ciph.kernel.meta_comparison import (
    META_PARETO_V1,
    compare_generators,
    comparison_digest,
    summarise_generator_outcomes,
)
from ciph.kernel.meta_corpus import (
    ADJUDICATION_MECHANICAL,
    ADJUDICATION_NONE,
    ADJUDICATION_OPERATOR,
    CASE_KIND_EVALUATOR,
    CandidateFacingCorpus,
    MetaCorpusVault,
    freeze_meta_protocol,
    run_meta_evaluation,
)
from ciph.kernel.meta_guard import (
    MAX_META_GENERATION_DEPTH_V1,
    assert_hard_invariants_preserved,
    assert_independent_judgment,
    meta_standing,
    record_meta_judgment,
    register_meta_candidate,
)
from ciph.kernel.meta_hypotheses import (
    MetaExpectation,
    meta_hypothesis_digest,
    meta_hypothesis_status,
    propose_meta_hypothesis,
    record_meta_hypothesis_outcome,
)
from ciph.kernel.meta_learning import (
    PROMOTION_PROMOTED,
    PROMOTION_REGRESSED,
    meta_learning_digest,
    meta_strategy_projection,
    record_meta_attempt,
    record_meta_promotion_result,
)
from ciph.kernel.meta_opportunities import (
    KIND_HIGH_INVALID,
    meta_opportunity_digest,
    meta_opportunity_status,
    record_meta_opportunity,
)
from ciph.kernel.meta_promotion import (
    META_DEPLOYMENT_RECONCILIATION_REQUIRED,
    byte_installer,
    meta_promotion_digest,
    meta_promotion_history,
    meta_promotion_requirements,
    meta_promote,
    meta_rollback,
)
from ciph.kernel.meta_shadow import (
    STATUS_ELIGIBLE,
    STATUS_EVALUATED,
    begin_shadow_evaluation,
    complete_shadow_evaluation,
    get_shadow,
    register_shadow,
    shadow_digest,
)

COMPONENT = 'ciph/evolution/gap_detector.py'
TARGET_ROLE = 'generator:gap_detector'
RING = 'IMPROVEMENT_MACHINERY'
G1 = 'G1'
G2 = 'G2'
G1_BYTES = b'# generator v1\ndef plan(): return "wide search"\n'
G2_BYTES = b'# generator v2\ndef plan(): return "dependency-restricted search"\n'
METRICS = [MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02),
           MetricDefinition('latency', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=10.0)]
BASELINE = {'task_success': 0.82, 'latency': 600.0}


def meta_bundle(db):
    return {'epochs': epoch_digest(db), 'opportunities': meta_opportunity_digest(db),
            'hypotheses': meta_hypothesis_digest(db), 'shadow': shadow_digest(db),
            'candidates': candidate_digest(db), 'promotions': promotion_digest(db),
            'meta_promotions': meta_promotion_digest(db), 'learning': meta_learning_digest(db)}


class TestGate47EndToEnd(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-47-e2e-')
        self.root = Path(self.temp.name)
        self.db = str(self.root / 'vault.db')
        self.component_path = str(self.root / 'production' / 'gap_detector.py')
        Path(self.component_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.component_path).write_bytes(G1_BYTES)
        self.t1 = 1_800_000_000.0
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_CAPABILITY_IMPLEMENTATION, development_cases=['d'],
            heldout_cases=['h'], metric_definitions=METRICS, environment_identity='host:eval',
            minimum_evidence=1, now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def outcome(self, *, success, latency, violations=None):
        """A REAL 4.5 Crucible comparison, used as the authoritative verdict on a candidate."""
        baseline = PerformanceVector(subject_id='B0', protocol_id=self.protocol.protocol_id,
                                     samples={key: (value,) * 3 for key, value in BASELINE.items()})
        candidate = PerformanceVector(subject_id='C', protocol_id=self.protocol.protocol_id,
                                      samples={'task_success': (success,) * 3,
                                               'latency': (latency,) * 3},
                                      hard_violations=violations or {})
        return compare(baseline, candidate, self.protocol).status

    def assert_restart_reproduces(self, expected):
        code = ('import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from test_gate_4_7_end_to_end import meta_bundle;'
                'print(json.dumps(meta_bundle(%r), sort_keys=True))'
                % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)

    # ------------------------------------------------------------------ the loop
    def test_the_complete_meta_evolution_loop(self):
        epoch7 = open_epoch(self.db, generator_identity=G1, evaluator_identity='E0',
                            safety_policy_identity='S1', crucible_policy_identity='P1',
                            authority_ref='operator:operator', now=self.t1)

        # Gate One: a weakness with evidence at a versioned reproducibility threshold.
        with self.assertRaises(CrucibleError) as thin:
            record_meta_opportunity(self.db, target_component=COMPONENT, weakness_kind=KIND_HIGH_INVALID,
                                    exact_component_identity=G1, evidence_refs=['E1'], now=self.t1)
        self.assertEqual(thin.exception.reason, 'META_OPPORTUNITY_NOT_REPRODUCIBLE')
        opportunity = record_meta_opportunity(
            self.db, target_component=COMPONENT, weakness_kind=KIND_HIGH_INVALID,
            exact_component_identity=G1, evidence_refs=['E1', 'E2'],
            crucible_history_refs=['CH-1'], now=self.t1)
        self.assertEqual(meta_opportunity_status(self.db, opportunity.opportunity_id), 'OPEN')
        self.assertEqual(meta_opportunity_status(self.db, opportunity.opportunity_id,
                                                 current_component_identity=G2), 'STALE',
                         'a new generator version does not inherit the accusation')

        # Gate Two: a falsifiable change, pinned to G1.
        hypothesis = propose_meta_hypothesis(
            self.db, opportunity_id=opportunity.opportunity_id, baseline_component_identity=G1,
            proposed_change='DEPENDENCY_SEARCH_RESTRICTION',
            expected_improvements=[MetaExpectation('invalid_rate', 'LOWER_BETTER', 0.1),
                                   MetaExpectation('dominates_rate', 'HIGHER_BETTER', 0.0)],
            forbidden_regressions=[{'metric_id': 'construction_cost'}],
            falsification_conditions=['dominates_rate falls'], now=self.t1)
        self.assertEqual(meta_hypothesis_status(self.db, hypothesis.hypothesis_id,
                                               current_component_identity=G1), 'PROPOSED')
        self.assertEqual(meta_hypothesis_status(self.db, hypothesis.hypothesis_id,
                                               current_component_identity='G-NEXT'),
                         'STALE', 'a moved baseline stales it rather than rebasing it')

        # Gate Three: a genuine 4.5 candidate, registered SHADOW-only.
        candidate = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                       artifact_digest=digest(G2_BYTES),
                                       configuration_digest=digest({'gen': G2}),
                                       baseline_candidate_id=None, created_by='ciph',
                                       now=self.t1)
        shadow = register_shadow(self.db, hypothesis_id=hypothesis.hypothesis_id,
                                 crucible_candidate_id=candidate.candidate_id,
                                 target_component=COMPONENT, target_ring=RING,
                                 authoritative_baseline=G1, now=self.t1)
        self.assertEqual(current_epoch(self.db).epoch_id, epoch7.epoch_id,
                         'registering a shadow changes no authority')

        # Generator meta-evaluation: both generators' outputs judged by the REAL 4.5 Crucible.
        g1_outcomes = [self.outcome(success=0.82, latency=600.0),                 # EQUIVALENT
                       self.outcome(success=0.95, latency=1500.0),               # INCOMPARABLE
                       self.outcome(success=0.99, latency=100.0,
                                    violations={'NO_FABRICATED_EVIDENCE': 1})]   # INVALID
        g2_outcomes = [self.outcome(success=0.90, latency=560.0),                 # DOMINATES
                       self.outcome(success=0.90, latency=560.0),                 # DOMINATES
                       self.outcome(success=0.70, latency=700.0)]                 # DOMINATED
        self.assertEqual(g1_outcomes, [STATUS_EQUIVALENT, STATUS_INCOMPARABLE, STATUS_INVALID])
        self.assertEqual(g2_outcomes, [STATUS_DOMINATES, STATUS_DOMINATES, STATUS_DOMINATED])

        baseline_rates = summarise_generator_outcomes(g1_outcomes)
        candidate_rates = summarise_generator_outcomes(g2_outcomes)
        comparison = compare_generators(baseline_rates, candidate_rates,
                                        minimum_deltas={'invalid_rate': 0.1, 'dominates_rate': 0.2},
                                        minimum_evidence=2)
        self.assertEqual(comparison.status, STATUS_DOMINATES, comparison.reason_codes)
        self.assertEqual(comparison.metric_version, META_PARETO_V1)
        comparison_ref = comparison_digest(comparison, baseline=baseline_rates,
                                           candidate=candidate_rates)

        begin_shadow_evaluation(self.db, shadow.shadow_id, protocol_id=self.protocol.protocol_id,
                                corpus_version='META-CORPUS-1', now=self.t1)
        shadow = complete_shadow_evaluation(self.db, shadow.shadow_id, meta_result_ref=comparison_ref,
                                            meta_status=comparison.status, constitutional_misses=0,
                                            now=self.t1)
        self.assertEqual(shadow.status, STATUS_ELIGIBLE)
        record_meta_hypothesis_outcome(self.db, hypothesis_id=hypothesis.hypothesis_id,
                                       protocol_id=self.protocol.protocol_id,
                                       comparison_status=comparison.status, now=self.t1)

        # RESTART: a dominating meta candidate is still not authority.
        after_evaluation = meta_bundle(self.db)
        self.assert_restart_reproduces(after_evaluation)
        self.assertEqual(current_epoch(self.db).epoch_id, epoch7.epoch_id)
        self.assertEqual(current_epoch(self.db).generator_identity, G1)
        self.assertEqual(get_shadow(self.db, shadow.shadow_id).status, STATUS_ELIGIBLE)
        self.assertEqual(meta_promotion_history(self.db), [])

        # Gate Five: dual control, real install, THEN the epoch.
        promotion = meta_promote(
            self.db, shadow_id=shadow.shadow_id, target_role=TARGET_ROLE, target_component=COMPONENT,
            artifact_bytes=G2_BYTES, configuration_digest=digest({'gen': G2}),
            ordinary_protocol_id=self.protocol.protocol_id, ordinary_standing=STATUS_DOMINATES,
            authority_ref='operator:operator', installer=byte_installer(self.component_path),
            meta_protocol_result_ref=comparison_ref, now=self.t1 + 10)
        self.assertEqual(Path(self.component_path).read_bytes(), G2_BYTES,
                         'the real installer wrote the exact authorized bytes')
        self.assertEqual(promotion.old_epoch_id, epoch7.epoch_id)
        self.assertEqual(current_epoch(self.db).generator_identity, candidate.candidate_id)
        self.assertEqual(current_epoch(self.db).epoch_id, promotion.new_epoch_id)
        self.assertTrue(promotion.deployment_id)

        # Rollback: a NEW epoch, not time travel.
        rollback = meta_rollback(
            self.db, bad_epoch=promotion.new_epoch_id, restore_from_epoch=epoch7.epoch_id,
            target_component=COMPONENT, artifact_bytes=G1_BYTES, evidence_refs=['MO-ROLLBACK'],
            authority_ref='operator:operator', installer=byte_installer(self.component_path),
            promoted_from=promotion.meta_promotion_id, ordinary_role=TARGET_ROLE, now=self.t1 + 20)
        self.assertEqual(Path(self.component_path).read_bytes(), G1_BYTES)
        self.assertTrue(rollback['verified'])
        current = current_epoch(self.db)
        self.assertNotEqual(current.epoch_id, epoch7.epoch_id)
        self.assertEqual(current.generator_identity, G1)
        self.assertEqual(current.rollback_of, promotion.new_epoch_id)
        self.assertEqual(current.restored_identity_from, epoch7.epoch_id)
        self.assertEqual(len(epoch_history(self.db)), 3, 'epoch 7 and 8 are history, not deleted')
        self.assertEqual(len(rollback_history(self.db)), 1)

        # Gate Ten: descriptive learning from what actually happened.
        attempt = record_meta_attempt(
            self.db, strategy_kind='DEPENDENCY_SEARCH_RESTRICTION',
            opportunity_id=opportunity.opportunity_id, hypothesis_id=hypothesis.hypothesis_id,
            meta_candidate_id=candidate.candidate_id, target_ring=RING,
            meta_result=comparison.status, now=self.t1 + 30)
        record_meta_promotion_result(self.db, attempt_id=attempt.attempt_id,
                                     promotion_result=PROMOTION_PROMOTED, now=self.t1 + 31)
        record_meta_promotion_result(self.db, attempt_id=attempt.attempt_id,
                                     promotion_result=PROMOTION_REGRESSED, now=self.t1 + 32)
        entry = meta_strategy_projection(self.db)[0]
        self.assertEqual(entry['strategy_kind'], 'DEPENDENCY_SEARCH_RESTRICTION')
        self.assertEqual(entry['meta_dominates'], 1)
        self.assertEqual(entry['production_regressions'], 1)
        for forbidden in ('score', 'fitness', 'intelligence'):
            self.assertNotIn(forbidden, entry)

        self.assert_restart_reproduces(meta_bundle(self.db))

    # ------------------------------------------------------------------ dual control
    def test_meta_promotion_refuses_without_the_full_dual_control_evidence(self):
        open_epoch(self.db, generator_identity=G1, evaluator_identity='E0',
                   authority_ref='operator:operator', now=self.t1)
        opportunity = record_meta_opportunity(
            self.db, target_component=COMPONENT, weakness_kind=KIND_HIGH_INVALID,
            exact_component_identity=G1, evidence_refs=['E1', 'E2'], now=self.t1)
        hypothesis = propose_meta_hypothesis(
            self.db, opportunity_id=opportunity.opportunity_id, baseline_component_identity=G1,
            proposed_change='RESTRICT', expected_improvements=[MetaExpectation('invalid_rate',
                                                                             'LOWER_BETTER', 0.1)],
            now=self.t1)
        candidate = register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                       artifact_digest=digest(G2_BYTES),
                                       configuration_digest=digest({'gen': G2}), now=self.t1)
        shadow = register_shadow(self.db, hypothesis_id=hypothesis.hypothesis_id,
                                 crucible_candidate_id=candidate.candidate_id,
                                 target_component=COMPONENT, target_ring=RING,
                                 authoritative_baseline=G1, now=self.t1)
        # Not yet eligible: no evaluation at all.
        self.assertIn('SHADOW_NOT_ELIGIBLE',
                      ','.join(meta_promotion_requirements(self.db, shadow_id=shadow.shadow_id,
                                                           ordinary_standing=STATUS_DOMINATES,
                                                           authority_ref='operator:operator')))
        begin_shadow_evaluation(self.db, shadow.shadow_id, protocol_id=self.protocol.protocol_id,
                                corpus_version='C', now=self.t1)
        # A candidate that missed a hard invariant is INVALID, never ELIGIBLE.
        missed = complete_shadow_evaluation(self.db, shadow.shadow_id, meta_result_ref='R',
                                           meta_status=STATUS_DOMINATES, constitutional_misses=1,
                                           now=self.t1)
        self.assertEqual(missed.status, 'INVALID')
        with self.assertRaises(CrucibleError) as refused:
            meta_promote(self.db, shadow_id=shadow.shadow_id, target_role=TARGET_ROLE,
                         target_component=COMPONENT, artifact_bytes=G2_BYTES,
                         configuration_digest='C', ordinary_protocol_id=self.protocol.protocol_id,
                         ordinary_standing=STATUS_DOMINATES, authority_ref='operator:operator',
                         installer=byte_installer(self.component_path), now=self.t1)
        self.assertEqual(refused.exception.reason, 'META_PROMOTION_REFUSED')
        self.assertEqual(Path(self.component_path).read_bytes(), G1_BYTES,
                         'a refused promotion installs nothing')

    # ------------------------------------------------------------------ evaluator torture
    def test_a_replacement_evaluator_cannot_rate_itself_or_collude(self):
        public = str(self.root / 'corpus.db')
        sealed = str(self.root / 'corpus_sealed.db')
        vault = MetaCorpusVault(public, sealed)
        fabricated = vault.register_case(
            corpus_version='META-CORPUS-1', case_kind=CASE_KIND_EVALUATOR,
            case_input={'situation': 'fabricated evidence'}, adjudication_class=ADJUDICATION_MECHANICAL,
            expected_result=STATUS_INVALID, sealed_payload={'answer': STATUS_INVALID}, now=self.t1)
        measured = vault.register_case(
            corpus_version='META-CORPUS-1', case_kind=CASE_KIND_EVALUATOR,
            case_input={'situation': 'real improvement'}, adjudication_class=ADJUDICATION_OPERATOR,
            adjudicated_result=STATUS_DOMINATES, now=self.t1)
        unresolved = vault.register_case(
            corpus_version='META-CORPUS-1', case_kind=CASE_KIND_EVALUATOR,
            case_input={'situation': 'ambiguous'}, adjudication_class=ADJUDICATION_NONE, now=self.t1)
        protocol_id = freeze_meta_protocol(self.db, corpus_version='META-CORPUS-1',
                                           authority_ref='operator:operator', minimum_evidence=2,
                                           now=self.t1)

        # E1 trades a hard invariant for performance: a constitutional miss kills it.
        greedy = run_meta_evaluation(
            self.db, vault, protocol_id=protocol_id, candidate_evaluator_id='CC-E1',
            evaluator={fabricated.case_id: STATUS_DOMINATES, measured.case_id: STATUS_DOMINATES,
                       unresolved.case_id: STATUS_DOMINATES},
            authoritative={fabricated.case_id: STATUS_INVALID, measured.case_id: STATUS_DOMINATES,
                           unresolved.case_id: STATUS_INCOMPARABLE},
            case_ids=[fabricated.case_id, measured.case_id, unresolved.case_id], now=self.t1)
        self.assertEqual(greedy.status, STATUS_INVALID)
        self.assertEqual(greedy.constitutional_misses, 1)
        assert_hard_invariants_preserved({'NO_FABRICATED_EVIDENCE': True})

        # A well-behaved E1 that agrees with adjudication but cannot resolve the ambiguous case.
        honest = run_meta_evaluation(
            self.db, vault, protocol_id=protocol_id, candidate_evaluator_id='CC-E2',
            evaluator={fabricated.case_id: STATUS_INVALID, measured.case_id: STATUS_DOMINATES,
                       unresolved.case_id: STATUS_DOMINATES},
            authoritative={fabricated.case_id: STATUS_INVALID, measured.case_id: STATUS_DOMINATES,
                           unresolved.case_id: STATUS_INCOMPARABLE},
            case_ids=[fabricated.case_id, measured.case_id, unresolved.case_id], now=self.t1)
        self.assertEqual(honest.status, STATUS_DOMINATES)
        self.assertEqual(honest.adjudicated_cases, 2)
        self.assertEqual(honest.unadjudicated_disagreements, 1,
                         'the unresolved case is evidence, not a point for anyone')

        # Self-ratification and collusion confer nothing.
        meta_one = register_meta_candidate(self.db, changed_files=[COMPONENT], artifact_digest='HA',
                                           configuration_digest='C', now=self.t1)
        meta_two = register_meta_candidate(self.db, changed_files=[COMPONENT], artifact_digest='HB',
                                           configuration_digest='C', now=self.t1)
        record_meta_judgment(self.db, meta_candidate_id=meta_one.meta_candidate_id,
                             judge_identity=meta_one.meta_candidate_id, verdict='PASS', now=self.t1)
        record_meta_judgment(self.db, meta_candidate_id=meta_one.meta_candidate_id,
                             judge_identity=meta_two.meta_candidate_id, verdict='PASS', now=self.t1)
        self.assertEqual(meta_standing(self.db, meta_one.meta_candidate_id), (0, 0))
        with self.assertRaises(CrucibleError):
            assert_independent_judgment(self.db, meta_candidate_id=meta_one.meta_candidate_id,
                                        judge_identity=COMPONENT)
        self.assertEqual(MAX_META_GENERATION_DEPTH_V1, 1)
        self.assertEqual(META_DEPLOYMENT_RECONCILIATION_REQUIRED,
                         'META_DEPLOYMENT_RECONCILIATION_REQUIRED')

    def test_a_candidate_is_never_handed_a_sealed_answer(self):
        public = str(self.root / 'c2.db')
        sealed = str(self.root / 'c2_sealed.db')
        vault = MetaCorpusVault(public, sealed)
        vault.register_case(corpus_version='C', case_kind=CASE_KIND_EVALUATOR,
                            case_input={'situation': 'x'}, adjudication_class=ADJUDICATION_MECHANICAL,
                            expected_result=STATUS_INVALID, now=self.t1)
        facing = CandidateFacingCorpus(public)
        self.assertNotIn('INVALID', json.dumps(facing.cases('C')))
        self.assertFalse(hasattr(facing, 'reveal'))
        self.assertEqual(get_candidate(self.db, register_candidate(
            self.db, kind=KIND_CAPABILITY_IMPLEMENTATION, artifact_digest='X',
            configuration_digest='Y', now=self.t1).candidate_id).artifact_digest, 'X')


if __name__ == '__main__':
    unittest.main()
