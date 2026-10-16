"""
4.6 cross-gate torture - the whole generation loop, plus the hostile matrix.

One real weakness, two competing hypotheses, two candidates, a trade-off, a dominance, a restart with
nothing promoted, then governed promotion through 4.5 and a production regression afterwards.

The constitutional thesis:

    4.6 proposes. 4.5 judges. Governance promotes. 4.6 learns - and never grades its own work.
"""

import ast
import inspect
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.candidate_construction import StagingSandbox, construct_candidate, construction_digest
from ciph.kernel.candidate_safety import is_admissible, review_candidate, safety_digest
from ciph.kernel.crucible_candidates import candidate_digest, get_candidate
from ciph.kernel.crucible_handoff import (
    generator_visible_view,
    hand_off,
    handoff_digest,
)
from ciph.kernel.crucible_metrics import PerformanceVector, STATUS_DOMINATES, STATUS_INCOMPARABLE, compare
from ciph.kernel.crucible_promotion import active_candidate, promote, promotion_digest
from ciph.kernel.crucible_protocols import MetricDefinition, freeze_protocol, protocol_digest
from ciph.kernel.crucible_trials import (
    ROLE_BASELINE,
    ROLE_CANDIDATE,
    complete_trial,
    start_trial,
    trial_digest,
)
from ciph.kernel.crucible_types import KIND_CAPABILITY_IMPLEMENTATION, CrucibleError
from ciph.kernel.improvement_hypotheses import (
    STATUS_PROPOSED,
    STATUS_STALE,
    ExpectedImprovement,
    hypothesis_digest,
    hypothesis_status,
    propose_hypothesis,
)
from ciph.kernel.improvement_learning import (
    PRODUCTION_HEALTHY,
    PRODUCTION_REGRESSED,
    learning_digest,
    record_attempt,
    record_production_result,
    strategy_projection,
)
from ciph.kernel.improvement_opportunities import (
    adopt_gap,
    opportunity_digest,
    opportunity_status,
)
from ciph.kernel.meta_evolution import assert_ordinary_candidate_scope

ROLE = 'capability:planner'
ENVIRONMENT = 'host:eval'
GAP = {'gap_id': 'GAP-PLANNER', 'category': 'MISSING_BEHAVIOR', 'target_capability': 'planner',
       'affected_revision': 'H1', 'failure_evidence_hashes': ['r1', 'r2'],
       'testable_improvement_criterion': 'case family F returns the oracle result'}
B0 = {'task_success': 0.82, 'latency': 600.0}
C1 = {'task_success': 0.88, 'latency': 900.0}
C2 = {'task_success': 0.88, 'latency': 570.0}
ARTIFACT_1 = b'class Planner:\n    def schedule(self, jobs):\n        return jobs  # v1\n'
ARTIFACT_2 = b'class Planner:\n    def schedule(self, jobs):\n        return sorted(jobs)  # v2\n'
ORDINARY = ['ciph/capabilities/planner.py']
METRICS = [MetricDefinition('task_success', 'v1', 'HIGHER_BETTER', minimum_meaningful_delta=0.02),
           MetricDefinition('latency', 'v1', 'LOWER_BETTER', minimum_meaningful_delta=10.0)]


def generation_bundle(db):
    return {'opportunities': opportunity_digest(db), 'hypotheses': hypothesis_digest(db),
            'candidates': candidate_digest(db), 'protocols': protocol_digest(db),
            'constructions': construction_digest(db), 'safety': safety_digest(db),
            'handoffs': handoff_digest(db), 'trials': trial_digest(db),
            'promotions': promotion_digest(db), 'learning': learning_digest(db)}


class TestGate46Torture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-46-torture-')
        self.root = Path(self.temp.name)
        self.db = str(self.root / 'vault.db')
        self.t1 = 1_800_000_000.0
        self.staging = StagingSandbox(self.root / 'staging')
        self.live = self.root / 'production' / 'planner.py'
        self.live.parent.mkdir(parents=True, exist_ok=True)
        self.live.write_text('# live planner\n', encoding='utf-8')
        self.live_bytes = self.live.read_bytes()
        self.protocol = freeze_protocol(
            self.db, candidate_kind=KIND_CAPABILITY_IMPLEMENTATION,
            development_cases=['dev-1', 'dev-2'], heldout_cases=['sealed-1', 'sealed-2'],
            metric_definitions=METRICS, environment_identity=ENVIRONMENT, minimum_evidence=1,
            now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ helpers
    def baseline_candidate(self):
        from ciph.kernel.crucible_candidates import register_candidate
        return register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION,
                                  artifact_digest='HASH-B0', configuration_digest='CFG-B0',
                                  now=self.t1)

    def measure(self, subject_id, role, values, seed):
        trial = start_trial(self.db, protocol_id=self.protocol.protocol_id, subject_id=subject_id,
                            role=role, seed=seed, environment_identity=ENVIRONMENT,
                            dataset_digest='DS', now=self.t1)
        complete_trial(self.db, trial.trial_id, observations=values, now=self.t1)
        return trial.trial_id

    def vector(self, values):
        return PerformanceVector(subject_id='x', protocol_id=self.protocol.protocol_id,
                                 samples={key: (value,) for key, value in values.items()})

    def assert_restart_reproduces(self, expected):
        code = ('import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from test_gate_4_6_cross_gate_torture import generation_bundle;'
                'print(json.dumps(generation_bundle(%r), sort_keys=True))'
                % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)

    # ------------------------------------------------------------------ the ladder
    def test_the_whole_generation_loop_composes_and_never_promotes_itself(self):
        baseline = self.baseline_candidate()

        # --- Gate Zero: the weakness exists in canonical evidence, twice.
        opportunity = adopt_gap(self.db, GAP, environment_identity=ENVIRONMENT, now=self.t1)
        self.assertEqual(opportunity_status(self.db, opportunity.opportunity_id), 'OPEN')
        self.assert_restart_reproduces(generation_bundle(self.db))

        # --- Gate One: two competing hypotheses, both pinned to the baseline.
        first = propose_hypothesis(
            self.db, opportunity_id=opportunity.opportunity_id, target_component='planner',
            proposed_change_class='RESCHEDULE_WORKERS', baseline_candidate_id=baseline.candidate_id,
            expected_improvements=[ExpectedImprovement('task_success', 'HIGHER_BETTER', 0.02)],
            falsification_conditions=['latency regresses'], now=self.t1)
        second = propose_hypothesis(
            self.db, opportunity_id=opportunity.opportunity_id, target_component='planner',
            proposed_change_class='SORT_JOBS_SMALLER', baseline_candidate_id=baseline.candidate_id,
            expected_improvements=[ExpectedImprovement('task_success', 'HIGHER_BETTER', 0.02),
                                   ExpectedImprovement('latency', 'LOWER_BETTER', 10.0)],
            now=self.t1)
        self.assertNotEqual(first.hypothesis_id, second.hypothesis_id)

        # --- Gate Two: two candidates, built in staging, nothing live touched.
        built_1 = construct_candidate(self.db, hypothesis_id=first.hypothesis_id, sandbox=self.staging,
                                      artifact_name='C1.py', artifact_bytes=ARTIFACT_1,
                                      generator_identity='ciph.planner.generator',
                                      generator_version='v1', generator_strategy_id='RESCHEDULE',
                                      now=self.t1)
        built_2 = construct_candidate(self.db, hypothesis_id=second.hypothesis_id,
                                      sandbox=self.staging, artifact_name='C2.py',
                                      artifact_bytes=ARTIFACT_2,
                                      generator_identity='ciph.planner.generator',
                                      generator_version='v1', generator_strategy_id='SORT_SMALLER',
                                      now=self.t1)
        self.assertEqual(self.live.read_bytes(), self.live_bytes, 'production bytes unchanged')
        self.assertIsNone(active_candidate(self.db, ROLE), 'the active pointer never moved')

        # --- Gate Three: both admissible; a meta touch would not be.
        for built in (built_1, built_2):
            review = review_candidate(self.db, candidate_id=built.crucible_candidate_id,
                                      changed_files=ORDINARY, now=self.t1)
            self.assertEqual(review.verdict, 'ADMISSIBLE')
            self.assertTrue(is_admissible(self.db, built.crucible_candidate_id))
        assert_ordinary_candidate_scope(self.db, changed_files=ORDINARY)

        # --- Gate Four: hand off and become a spectator.
        hand_off(self.db, candidate_id=built_1.crucible_candidate_id,
                 hypothesis_id=first.hypothesis_id, protocol_id=self.protocol.protocol_id,
                 role=ROLE, now=self.t1)
        view = generator_visible_view(self.db, self.protocol.protocol_id)
        self.assertNotIn('sealed-1', str(view))

        # --- The Crucible judges: C1 trades success for latency.
        self.measure(baseline.candidate_id, ROLE_BASELINE, B0, 'b0')
        self.measure(built_1.crucible_candidate_id, ROLE_CANDIDATE, C1, 'c1')
        verdict_1 = compare(self.vector(B0), self.vector(C1), self.protocol)
        self.assertEqual(verdict_1.status, STATUS_INCOMPARABLE)
        self.assertIsNone(active_candidate(self.db, ROLE), 'INCOMPARABLE promotes nothing')

        # --- Gate Five: the strategy learns a trade-off, not a failure.
        attempt_1 = record_attempt(self.db, opportunity_id=opportunity.opportunity_id,
                                   hypothesis_id=first.hypothesis_id,
                                   candidate_id=built_1.crucible_candidate_id,
                                   generator_strategy_id='RESCHEDULE', protocol_id=self.protocol.protocol_id,
                                   comparison_status=verdict_1.status, now=self.t1)

        # --- Second attempt dominates, and still does not promote itself.
        self.measure(built_2.crucible_candidate_id, ROLE_CANDIDATE, C2, 'c2')
        verdict_2 = compare(self.vector(B0), self.vector(C2), self.protocol)
        self.assertEqual(verdict_2.status, STATUS_DOMINATES)
        attempt_2 = record_attempt(self.db, opportunity_id=opportunity.opportunity_id,
                                   hypothesis_id=second.hypothesis_id,
                                   candidate_id=built_2.crucible_candidate_id,
                                   generator_strategy_id='SORT_SMALLER',
                                   protocol_id=self.protocol.protocol_id,
                                   comparison_status=verdict_2.status, now=self.t1)
        restart_bundle = generation_bundle(self.db)
        self.assert_restart_reproduces(restart_bundle)
        self.assertEqual(active_candidate(self.db, ROLE), None,
                         'discovering a dominating candidate is not promoting it')

        # --- Governance promotes through 4.5, and only 4.5.
        promote(self.db, role=ROLE, candidate_id=built_2.crucible_candidate_id,
                protocol_id=self.protocol.protocol_id, comparison_status=STATUS_DOMINATES,
                evaluation_refs=['c2'], authorization_ref='operator:operator',
                replaced_candidate_id=baseline.candidate_id, now=self.t1 + 10)
        self.assertEqual(active_candidate(self.db, ROLE), built_2.crucible_candidate_id)
        self.assert_restart_reproduces(generation_bundle(self.db))

        # --- Production later regresses: both facts survive.
        record_production_result(self.db, attempt_id=attempt_2.attempt_id,
                                 production_result=PRODUCTION_REGRESSED, now=self.t1 + 20)
        projections = {entry['strategy_id']: entry for entry in strategy_projection(self.db)}
        self.assertEqual(projections['SORT_SMALLER']['dominates_count'], 1)
        self.assertEqual(projections['SORT_SMALLER']['production_regressed_count'], 1)
        self.assertEqual(projections['RESCHEDULE']['incomparable_count'], 1)
        self.assertEqual(get_candidate(self.db, built_2.crucible_candidate_id).artifact_digest,
                         built_2.artifact_digest)
        self.assertEqual(opportunity_status(self.db, opportunity.opportunity_id), 'OPEN')
        self.assertTrue(attempt_1.attempt_id and PRODUCTION_HEALTHY)
        self.assert_restart_reproduces(generation_bundle(self.db))

    # ------------------------------------------------------------------ hostile matrix
    def test_hostile_a_detector_cannot_invent_a_weakness(self):
        with self.assertRaises(CrucibleError) as refused:
            adopt_gap(self.db, dict(GAP, failure_evidence_hashes=['only-one']),
                      environment_identity=ENVIRONMENT, now=self.t1)
        self.assertEqual(refused.exception.reason, 'OPPORTUNITY_NOT_REPRODUCIBLE')
        with self.assertRaises(CrucibleError):
            adopt_gap(self.db, dict(GAP, failure_evidence_hashes=[]),
                      environment_identity=ENVIRONMENT, now=self.t1)

    def test_hostile_a_hypothesis_cannot_rebase_itself_onto_a_new_baseline(self):
        baseline = self.baseline_candidate()
        opportunity = adopt_gap(self.db, GAP, environment_identity=ENVIRONMENT, now=self.t1)
        hypothesis = propose_hypothesis(
            self.db, opportunity_id=opportunity.opportunity_id, target_component='planner',
            proposed_change_class='RESCHEDULE_WORKERS', baseline_candidate_id=baseline.candidate_id,
            expected_improvements=[ExpectedImprovement('task_success', 'HIGHER_BETTER', 0.02)],
            now=self.t1)
        self.assertEqual(hypothesis_status(self.db, hypothesis.hypothesis_id,
                                           current_baseline_candidate_id='CC-SOMETHING-ELSE'),
                         STATUS_STALE)
        self.assertEqual(hypothesis_status(self.db, hypothesis.hypothesis_id,
                                           current_baseline_candidate_id=baseline.candidate_id),
                         STATUS_PROPOSED)

    def test_hostile_the_generator_cannot_grade_its_own_candidate(self):
        for module_name in ('ciph.kernel.improvement_learning',
                            'ciph.kernel.candidate_construction',
                            'ciph.kernel.crucible_handoff'):
            module = __import__(module_name, fromlist=['x'])
            public = [name for name, _ in inspect.getmembers(module, inspect.isfunction)
                      if not name.startswith('_')]
            for forbidden in ('approve', 'declare_pass', 'mark_success', 'promote', 'install'):
                self.assertNotIn(forbidden, public, f'{module_name}.{forbidden}')
        source = inspect.getsource(__import__('ciph.kernel.candidate_safety', fromlist=['x']))
        tree = ast.parse(source)
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.append(node.module or '')
        for forbidden in ('crucible_promotion', 'evolution_deployment', 'permit'):
            self.assertFalse([name for name in imported if forbidden in name])


if __name__ == '__main__':
    unittest.main()
