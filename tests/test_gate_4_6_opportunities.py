"""
4.6 Gate Zero - improvement opportunities.

    Detector output is not a confirmed weakness.

Every specimen is written so that a detector result, an operator's irritation, or a single bad afternoon
could become a "reproducible weakness" on its own would fail.
"""

import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel import improvement_opportunities as opportunities
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.improvement_opportunities import (
    OPPORTUNITY_REPRODUCIBILITY_V1,
    REQUIRED_REPRODUCTIONS_V1,
    STATUS_OPEN,
    STATUS_SATISFIED,
    STATUS_STALE,
    adopt_gap,
    get_opportunity,
    opportunity_digest,
    opportunity_evidence,
    opportunity_history,
    opportunity_id_for,
    opportunity_status,
    record_operator_request,
    weakness_basis,
)

GAP = {'gap_id': 'GAP-BEH-1', 'category': 'MISSING_BEHAVIOR', 'target_capability': 'planner',
       'affected_revision': 'H1', 'failure_evidence_hashes': ['e1', 'e2'],
       'measured_impact': {'violations': 2}, 'testable_improvement_criterion': 'results match oracle',
       'reproducible_conditions': {'environment_fingerprint': 'env-1'}}


class TestGate46Opportunities(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ciph-46-opportunities-')
        self.db = str(Path(self.temp.name) / 'vault.db')
        self.t1 = 1_800_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    def adopt(self, **overrides):
        gap = dict(GAP)
        gap.update(overrides)
        return adopt_gap(self.db, gap, environment_identity='host:alpha', now=self.t1)

    # ------------------------------------------------------------------ founding
    def test_founding_a_reproduced_failure_becomes_one_traceable_opportunity(self):
        opportunity = self.adopt()
        self.assertTrue(opportunity.opportunity_id.startswith('OPP-'))
        self.assertEqual(opportunity.source_kind, 'REPEATED_FAILURE',
                         'the legacy MISSING_BEHAVIOR category maps into the constitutional vocabulary')
        self.assertEqual(opportunity.affected_component, 'planner')
        self.assertEqual(opportunity.affected_revision, 'H1')
        self.assertEqual(opportunity.evidence_refs, ('e1', 'e2'))
        self.assertEqual(opportunity.policy_version, OPPORTUNITY_REPRODUCIBILITY_V1)
        self.assertEqual(opportunity_status(self.db, opportunity.opportunity_id), STATUS_OPEN)
        # Re-adopting the same detector result is the same opportunity, not a second one.
        self.assertEqual(self.adopt().opportunity_id, opportunity.opportunity_id)
        self.assertEqual(len(opportunity_history(self.db)), 1)

    # ------------------------------------------------------------------ law 4
    def test_law_4_one_anomalous_failure_is_not_a_reproducible_weakness(self):
        with self.assertRaises(CrucibleError) as refused:
            self.adopt(failure_evidence_hashes=['only-one'])
        self.assertEqual(refused.exception.reason, 'OPPORTUNITY_NOT_REPRODUCIBLE')
        self.assertEqual(opportunity_history(self.db), [])
        self.assertEqual(REQUIRED_REPRODUCTIONS_V1, 2)

    # ------------------------------------------------------------------ law 2 and law 3
    def test_law_2_and_3_a_claim_without_evidence_is_not_an_opportunity(self):
        with self.assertRaises(CrucibleError) as refused:
            self.adopt(failure_evidence_hashes=[])
        self.assertEqual(refused.exception.reason, 'OPPORTUNITY_REQUIRES_EVIDENCE')
        for forbidden in ('record_model_dissatisfaction', 'declare_weakness', 'note_self_doubt',
                          'record_self_criticism'):
            self.assertFalse(hasattr(opportunities, forbidden))
        # An operator may raise one - and still has to cite something.
        with self.assertRaises(CrucibleError) as operator:
            record_operator_request(self.db, affected_component='planner',
                                    weakness_description='feels slow', evidence_refs=[], now=self.t1)
        self.assertEqual(operator.exception.reason, 'OPPORTUNITY_REQUIRES_EVIDENCE')
        raised = record_operator_request(self.db, affected_component='planner',
                                         weakness_description='p95 latency above SLO',
                                         evidence_refs=['R-9'], improvement_criterion='p95 < 200ms',
                                         now=self.t1)
        self.assertEqual(raised.source_kind, 'RESOURCE_REGRESSION')
        self.assertEqual(opportunity_evidence(self.db, raised.opportunity_id), ['R-9'])

    # ------------------------------------------------------------------ laws 8 and 9
    def test_law_8_and_9_more_symptoms_enrich_one_opportunity_and_identity_is_the_weakness(self):
        opportunity = self.adopt()
        self.adopt(failure_evidence_hashes=['e3'])
        self.assertEqual(opportunity_evidence(self.db, opportunity.opportunity_id),
                         ['e1', 'e2', 'e3'],
                         'a third observation is more evidence for the same weakness')
        self.assertEqual(len(opportunity_history(self.db)), 1,
                         'more evidence must not mint a second opportunity')
        self.assertEqual(get_opportunity(self.db, opportunity.opportunity_id).evidence_refs,
                         ('e1', 'e2', 'e3'))
        # A different environment is a different question.
        self.assertNotEqual(self.adopt(environment_identity='host:beta')
                            if False else adopt_gap(self.db, GAP, environment_identity='host:beta',
                                                    now=self.t1).opportunity_id,
                            opportunity.opportunity_id)

    def test_law_9_identity_is_a_pure_function_of_the_weakness_basis(self):
        basis = weakness_basis(source_kind='REPEATED_FAILURE', affected_component='planner',
                               affected_revision='H1', environment_identity='host:alpha',
                               symptom_signature='results match oracle')
        self.assertEqual(opportunity_id_for(basis), self.adopt().opportunity_id)
        other = dict(basis, symptom_signature='different oracle')
        self.assertNotEqual(opportunity_id_for(other), opportunity_id_for(basis))

    # ------------------------------------------------------------------ law 7
    def test_law_7_a_weakness_that_stops_reproducing_is_retained_as_history(self):
        opportunity = self.adopt()
        self.assertEqual(opportunity_status(self.db, opportunity.opportunity_id,
                                            current_revision='H2'), STATUS_STALE)
        self.assertEqual(opportunity_status(self.db, opportunity.opportunity_id,
                                            weakness_present=False), STATUS_SATISFIED)
        self.assertEqual(len(opportunity_history(self.db)), 1, 'SATISFIED is not deletion')
        self.assertEqual(opportunity_status(self.db, 'OPP-NEVER-EXISTED'), 'INVALID')

    # ------------------------------------------------------------------ law 10
    def test_law_10_the_registry_is_reproducible_across_restart(self):
        self.adopt()
        expected = opportunity_digest(self.db)
        code = ('import sys;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));'
                'from ciph.kernel.improvement_opportunities import opportunity_digest;'
                'print(opportunity_digest(%r))' % (str(Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), expected)
        self.assertEqual(opportunity_digest(self.db), expected)
        self.assertTrue(inspect.getsource(opportunities).count('canonical') > 0)


if __name__ == '__main__':
    unittest.main()
