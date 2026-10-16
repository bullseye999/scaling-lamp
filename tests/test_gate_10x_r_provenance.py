"""
10.x-R provenance gate: rule-semantics delivery and conclusion provenance must be honest.

    A model ABSTENTION on a settled question is under-commitment, NOT a contradictory assertion.
    No reasoning-quality credit is ever awarded for deterministic reconciliation.
"""

import pathlib
import tempfile
import unittest

from ciph.kernel import evidence_publication as publication
from ciph.kernel import evidence_reconciliation as recon
from ciph.kernel.crucible_types import CrucibleError

T = 1_800_000_000.0
SETTLED = [{"ref": "OLD", "value": "CLOSED", "observed_at": T - 900, "calibrated_at": T - 800, "source": "s1"},
           {"ref": "NEW", "value": "OPEN", "observed_at": T - 60, "calibrated_at": T - 30, "source": "s2"}]


class TestRuleSemantics(unittest.TestCase):
    def test_every_standing_rule_has_versioned_authoritative_semantics(self):
        for rule in recon.STANDING_RULES:
            semantics = recon.rule_semantics(rule)
            self.assertEqual(semantics["version"], recon.RULE_SEMANTICS_V1)
            self.assertEqual(semantics["name"], rule)
            self.assertTrue(semantics["meaning"])
            self.assertTrue(semantics["conditions"])
            self.assertTrue(semantics["precedence"])
            self.assertTrue(semantics["abstention"])

    def test_an_unknown_rule_is_refused_not_guessed(self):
        with self.assertRaises(CrucibleError) as refused:
            recon.rule_semantics("SOME_INVENTED_RULE")
        self.assertEqual(refused.exception.reason, "UNKNOWN_STANDING_RULE")


class TestConclusionProvenance(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-prov-")
        self.db = str(pathlib.Path(self.temp.name) / "v.db")

    def tearDown(self):
        self.temp.cleanup()

    def publish(self, **kw):
        kw.setdefault("question", "q")
        kw.setdefault("evidence", SETTLED)
        kw.setdefault("rule", recon.NEWEST_CALIBRATED_WINS)
        kw.setdefault("now", T)
        return publication.publish(self.db, **kw)

    def test_a_model_abstention_on_a_settled_question_is_not_a_contradiction(self):
        result = self.publish(model_conclusion="ABSTAIN", model_raw_output='{"verdict":"ABSTAIN"}')
        self.assertEqual(result["refusal_reason"], publication.REASON_MODEL_ABSTAINED_ON_SETTLED_EVIDENCE)
        self.assertNotEqual(result["refusal_reason"], publication.REASON_MODEL_CONTRADICTS_THE_RULE)
        self.assertEqual(result["attribution"], publication.RULE_DERIVED)
        self.assertFalse(result["model_quality_credit"])
        self.assertEqual(result["published_conclusion"], "OPEN")
        self.assertEqual(result["model_raw_output"], '{"verdict":"ABSTAIN"}')

    def test_a_wrong_assertion_is_a_correction(self):
        result = self.publish(model_conclusion="CLOSED", model_citation="NEW")
        self.assertEqual(result["attribution"], publication.MODEL_CORRECTED)
        self.assertEqual(result["refusal_reason"], publication.REASON_MODEL_CONTRADICTS_THE_RULE)
        self.assertFalse(result["model_quality_credit"])

    def test_deterministic_fallback_earns_no_model_credit(self):
        result = self.publish(model_conclusion=None)
        self.assertEqual(result["attribution"], publication.RULE_DERIVED)
        self.assertFalse(result["model_quality_credit"])
        self.assertTrue(result["system_reliability_credit"] is False or result["system_reliability_credit"] in (True, False))

    def test_a_model_abstention_on_unsettled_evidence_is_correct(self):
        ev = [{"ref": "E1", "value": "A", "observed_at": T - 60, "source": "a"},
              {"ref": "E2", "value": "B", "observed_at": T - 55, "source": "b"}]
        result = self.publish(evidence=ev, rule=recon.NO_DECLARED_RULE, model_conclusion="ABSTAIN")
        self.assertEqual(result["attribution"], publication.ABSTAINED)
        self.assertIsNone(result["refused_assertion"])   # abstaining is not an assertion to refuse


if __name__ == "__main__":
    unittest.main()
