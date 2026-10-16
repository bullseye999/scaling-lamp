"""
4.5 Gate Zero - candidate registry.

    What exactly is being evaluated?

Candidate identity is immutable and derived from the exact artifact and configuration that will be
measured. Every specimen is written so a candidate that could be silently redefined - or that could
promote itself - would fail.
"""

import ast
import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import crucible_candidates as candidates_module
from ciph.kernel.crucible_candidates import (
    candidate_digest,
    candidate_history,
    candidate_identity_payload,
    get_candidate,
    init_schema,
    register_candidate,
    verify_candidate_identity,
)
from ciph.kernel.crucible_types import (
    CRUCIBLE_CANDIDATE_ID_V1,
    CrucibleError,
    KIND_CAPABILITY_IMPLEMENTATION,
    KIND_PLANNER_STRATEGY,
    digest,
)


class TestGate45CandidateRegistry(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-45-candidates-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    def register(self, *, artifact='H1', configuration='C1', kind=KIND_PLANNER_STRATEGY,
                 parent=None, baseline=None, manifest=None, objective=None, changes=(),
                 by='operator', now=None):
        return register_candidate(
            self.db, kind=kind, artifact_digest=artifact, configuration_digest=configuration,
            manifest_identity=manifest, parent_candidate_id=parent,
            baseline_candidate_id=baseline, declared_objective=objective,
            declared_changes=changes, created_by=by, now=now or self.t1)

    # ------------------------------------------------------------------ the founding specimen
    def test_founding_a_candidate_is_a_new_identity_with_historical_lineage(self):
        baseline = self.register(artifact='H0', configuration='C0', by='operator',
                                 objective='current planner')
        candidate = self.register(artifact='H1', configuration='C1', parent=baseline.candidate_id,
                                  baseline=baseline.candidate_id, by='ciph',
                                  changes=['new scoring heuristic'])
        self.assertNotEqual(candidate.candidate_id, baseline.candidate_id)
        self.assertEqual(candidate.parent_candidate_id, baseline.candidate_id)
        self.assertEqual(candidate.baseline_candidate_id, baseline.candidate_id)
        self.assertEqual(len(candidate_history(self.db)), 2)
        # Law 4: lineage is a historical reference, not authority. Nothing about the parent grants
        # the child anything, and the parent record is untouched.
        self.assertEqual(get_candidate(self.db, baseline.candidate_id).artifact_digest, 'H0')

    # ------------------------------------------------------------------ law 2 and law 10
    def test_law_2_and_10_editing_bytes_creates_a_new_candidate(self):
        first = self.register(artifact='H1', configuration='C1')
        again = self.register(artifact='H1', configuration='C1')
        self.assertEqual(first.candidate_id, again.candidate_id,
                         'the same artifact and configuration are the same candidate')
        self.assertEqual(len(candidate_history(self.db)), 1)

        with self.assertRaises(CrucibleError) as refused:
            verify_candidate_identity(self.db, first.candidate_id, artifact_digest='H2',
                                      configuration_digest='C1')
        self.assertEqual(refused.exception.reason, 'CANDIDATE_IDENTITY_MISMATCH')

        # The edited artifact is a different candidate, not an updated one.
        edited = self.register(artifact='H2', configuration='C1')
        self.assertNotEqual(edited.candidate_id, first.candidate_id)
        self.assertEqual(get_candidate(self.db, first.candidate_id).artifact_digest, 'H1',
                         'the registered candidate keeps exactly what was evaluated')

    def test_law_3_identity_includes_configuration_and_manifest(self):
        base = self.register(artifact='H1', configuration='C1')
        self.assertNotEqual(self.register(artifact='H1', configuration='C2').candidate_id,
                            base.candidate_id)
        with_manifest = self.register(artifact='H1', configuration='C1', manifest='v1:abc')
        self.assertNotEqual(with_manifest.candidate_id, base.candidate_id)
        with self.assertRaises(CrucibleError):
            verify_candidate_identity(self.db, with_manifest.candidate_id, artifact_digest='H1',
                                      configuration_digest='C1', manifest_identity='v1:zzz')

    # ------------------------------------------------------------------ law 5
    def test_law_5_a_declaration_never_redefines_identity(self):
        stated = self.register(artifact='H1', configuration='C1',
                               objective='this will be 40% faster',
                               changes=['rewrite the scorer'])
        restated = self.register(artifact='H1', configuration='C1',
                                 objective='actually it is 12% faster and cheaper',
                                 changes=['rewrite the scorer', 'and the patch selector'])
        self.assertEqual(stated.candidate_id, restated.candidate_id,
                         'an edited description must not silently redefine the candidate')
        payload = candidate_identity_payload(kind=KIND_PLANNER_STRATEGY, artifact_digest='H1',
                                             configuration_digest='C1')
        for forbidden in ('declared_objective', 'declared_changes', 'created_by', 'created_at',
                          'declared'):
            self.assertNotIn(forbidden, payload)
        self.assertEqual(payload['identity_version'], CRUCIBLE_CANDIDATE_ID_V1)

    # ------------------------------------------------------------------ laws 6, 7, 9
    def test_law_6_7_and_9_the_registry_holds_no_promotion_or_eligibility_power(self):
        public = [name for name, _ in inspect.getmembers(candidates_module, inspect.isfunction)
                  if not name.startswith('_')]
        for forbidden in ('promote', 'set_active', 'mark_eligible', 'self_modify', 'set_status',
                          'best_candidate', 'winner', 'rank_candidates', 'approve'):
            self.assertNotIn(forbidden, public, f'{forbidden} must not exist at Gate Zero')
        # Identifiers, not prose: the module's docstring may STATE these laws, but no name may
        # implement them here. Otherwise this specimen would be satisfied by deleting a comment.
        tree = ast.parse(inspect.getsource(candidates_module))
        identifiers = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                identifiers.add(node.id)
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                identifiers.add(node.name)
            elif isinstance(node, ast.arg):
                identifiers.add(node.arg)
        lowered = {name.lower() for name in identifiers}
        for forbidden in ('active_candidate', 'eligible', 'eligibility', 'promote', 'promotion',
                          'permit', 'guardedexecutor', 'promoted'):
            self.assertNotIn(forbidden, lowered,
                             f'{forbidden} must not exist as an identifier at Gate Zero')

    # ------------------------------------------------------------------ law 8
    def test_law_8_newest_is_not_better(self):
        late = self.register(artifact='H9', configuration='C9', now=self.t1 + 1000)
        early = self.register(artifact='H1', configuration='C1', now=self.t1)
        history = candidate_history(self.db)
        self.assertEqual([candidate.candidate_id for candidate in history],
                         [early.candidate_id, late.candidate_id])
        # Ordering is by registration time and nothing else: there is no comparison surface here.
        for candidate in history:
            self.assertFalse(hasattr(candidate, 'score'))
            self.assertFalse(hasattr(candidate, 'rank'))

    # ------------------------------------------------------------------ refusals
    def test_invalid_kind_and_missing_identity_are_refused(self):
        with self.assertRaises(CrucibleError) as bad_kind:
            self.register(kind='SELF_REWRITE_THE_KERNEL')
        self.assertEqual(bad_kind.exception.reason, 'INVALID_CANDIDATE_KIND')
        with self.assertRaises(CrucibleError) as missing:
            register_candidate(self.db, kind=KIND_CAPABILITY_IMPLEMENTATION, artifact_digest='',
                               configuration_digest='C1')
        self.assertEqual(missing.exception.reason,
                         'CANDIDATE_REQUIRES_ARTIFACT_AND_CONFIGURATION')

    # ------------------------------------------------------------------ determinism
    def test_candidate_digest_is_deterministic_across_restart_and_process(self):
        self.register(artifact='H0', configuration='C0', objective='baseline')
        self.register(artifact='H1', configuration='C1', objective='candidate')
        expected = candidate_digest(self.db)
        self.assertEqual(candidate_digest(self.db), expected)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.crucible_candidates import candidate_digest;'
                'print(candidate_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)
        self.assertEqual(len(digest({})), 64)


if __name__ == '__main__':
    unittest.main()
