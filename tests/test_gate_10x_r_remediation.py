"""
10.x-R gate: the publication boundary, the scorer anti-patterns, and the adversarial matrix.

    A safe refusal earns SYSTEM_EVIDENCE_RELIABILITY. It does NOT earn REAL_MODEL_REASONING_QUALITY.

Every expectation here is derived from the DECLARED reconciliation rule, never from a model output. Nothing in
this file tunes a case to match what a model happened to answer.
"""

import os
import pathlib
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest import mock

from ciph.kernel import evidence_publication as publication
from ciph.kernel import evidence_reconciliation as recon
from ciph.kernel import model_boundary

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import held_out_judgment_benchmark as bench  # noqa: E402

T1 = 1_800_000_000.0

# The rule says the most recently calibrated credible observation decides; E3 (OPEN) supersedes E1 (CLOSED).
SETTLED_EVIDENCE = [
    {"ref": "E1", "value": "CLOSED", "observed_at": T1 - 3600, "calibrated_at": T1 - 7200, "source": "s1"},
    {"ref": "E3", "value": "OPEN", "observed_at": T1 - 300, "calibrated_at": T1 - 200, "source": "s4"},
]
# Two equally credible current sources disagree and no rule breaks the tie -> ABSTAIN.
CONTRADICTORY_EVIDENCE = [
    {"ref": "E1", "value": "SEALED", "observed_at": T1 - 60, "source": "s1"},
    {"ref": "E2", "value": "OPEN", "observed_at": T1 - 55, "source": "s2"},
]
NO_RULE_EVIDENCE = [
    {"ref": "E1", "value": "BENIGN", "observed_at": T1 - 60, "source": "a"},
    {"ref": "E2", "value": "MALICIOUS", "observed_at": T1 - 55, "source": "b"},
]
MISSING_SOURCE_EVIDENCE = [
    {"ref": "E1", "value": "ACTIVE", "observed_at": T1 - 60, "source": "panel"},
]


class RemediationGate(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-10xr-")
        self.base = pathlib.Path(self.temp.name)
        self.db = str(self.base / "state.db")

    def tearDown(self):
        self.temp.cleanup()

    def publish(self, **kw):
        kw.setdefault("question", "Is the valve OPEN or CLOSED?")
        kw.setdefault("evidence", SETTLED_EVIDENCE)
        kw.setdefault("rule", recon.NEWEST_CALIBRATED_WINS)
        kw.setdefault("now", T1)
        return publication.publish(self.db, **kw)

    # ---------------------------------------------------------------- A. scorer anti-patterns
    def test_valid_citation_with_incorrect_conclusion_is_refused(self):
        # The model cites a REAL ref (E3) while concluding the opposite of what E3 says.
        result = self.publish(model_conclusion="CLOSED", model_citation="E3")
        self.assertTrue(any(item["ref"] == "E3" for item in result["reconciliation"]["evidence"]))
        self.assertEqual(result["attribution"], publication.MODEL_CORRECTED)
        self.assertFalse(result["model_quality_credit"])
        self.assertEqual(result["published_conclusion"], "OPEN")
        self.assertEqual(result["refusal_reason"], publication.REASON_MODEL_CONTRADICTS_THE_RULE)

    def test_right_answer_with_a_contradicting_citation_is_a_corrected_guess(self):
        # Right verdict, but the cited evidence (E1=CLOSED) does not support it.
        result = self.publish(model_conclusion="OPEN", model_citation="E1")
        self.assertEqual(result["attribution"], publication.MODEL_CORRECTED)
        self.assertEqual(result["refusal_reason"], publication.REASON_MODEL_CITATION_CONTRADICTS_THE_MODEL)
        self.assertFalse(result["model_quality_credit"])

    def test_model_confident_where_abstention_is_required(self):
        result = self.publish(question="Is the anomaly BENIGN or MALICIOUS?", evidence=NO_RULE_EVIDENCE,
                              rule=recon.NO_DECLARED_RULE, model_conclusion="BENIGN")
        self.assertTrue(result["abstained"])
        self.assertIsNone(result["published_conclusion"])
        self.assertEqual(result["attribution"], publication.ABSTAINED)
        self.assertEqual(result["refusal_reason"], publication.REASON_CONFIDENT_CLAIM_ON_UNSETTLED_EVIDENCE)
        self.assertFalse(result["model_quality_credit"])
        self.assertTrue(result["system_reliability_credit"])

    def test_invalid_model_format_is_not_a_successful_abstention(self):
        # The benchmark's parser must FAIL a blank/unparseable answer; it must never read as ABSTAIN.
        self.assertIsNone(bench._parser(""))
        self.assertIsNone(bench._parser("I believe the answer is OPEN"))
        self.assertIsNone(bench._parser('{"no_verdict": true}'))
        self.assertIsNotNone(bench._parser('{"verdict": "ABSTAIN"}'))
        # And an empty model answer earns nothing through the publication path.
        result = self.publish(model_conclusion="")
        self.assertEqual(result["attribution"], publication.RULE_DERIVED)
        self.assertFalse(result["model_quality_credit"])

    def test_fallback_is_attributed_to_the_deterministic_layer(self):
        result = self.publish(model_conclusion=None)
        self.assertEqual(result["attribution"], publication.RULE_DERIVED)
        self.assertEqual(result["published_conclusion"], "OPEN")
        self.assertFalse(result["model_quality_credit"])
        self.assertIn("established by the declared rule, not by me", result["publication_text"])

    def test_only_model_supported_with_a_supporting_citation_earns_model_credit(self):
        result = self.publish(model_conclusion="OPEN", model_citation="E3")
        self.assertEqual(result["attribution"], publication.MODEL_SUPPORTED)
        self.assertTrue(result["model_quality_credit"])
        self.assertFalse(result["system_reliability_credit"])

    # ---------------------------------------------------------------- B. rule-governed conclusions
    def test_declared_rule_determines_the_conclusion(self):
        newest = recon.reconcile(self.db, question="q", evidence=SETTLED_EVIDENCE,
                                 rule=recon.NEWEST_CALIBRATED_WINS, now=T1)
        older = recon.reconcile(self.db, question="q", evidence=SETTLED_EVIDENCE,
                                rule=recon.OLDER_CONTROLLING, now=T1)
        self.assertEqual(newest["conclusion"], "OPEN")
        self.assertEqual(older["conclusion"], "CLOSED")

    def test_model_fails_to_revise_after_decisive_new_evidence(self):
        # Same REVISION semantics: the stale verdict CLOSED contradicts the freshly calibrated OPEN.
        result = self.publish(model_conclusion="CLOSED", model_citation="E1")
        self.assertEqual(result["published_conclusion"], "OPEN")
        self.assertTrue(result["refusal_reason"])

    def test_model_changes_conclusion_under_pressure_without_new_evidence(self):
        supported = self.publish(model_conclusion="OPEN", model_citation="E3", now=T1)
        pressured = self.publish(model_conclusion="CLOSED", model_citation="E1", now=T1)
        # The PUBLISHED fact does not change with the model's pressured answer.
        self.assertEqual(supported["published_conclusion"], "OPEN")
        self.assertEqual(pressured["published_conclusion"], "OPEN")
        self.assertFalse(pressured["model_quality_credit"])

    def test_missing_required_source_yields_unresolved(self):
        result = self.publish(question="Is the alarm ACTIVE or CLEAR?", evidence=MISSING_SOURCE_EVIDENCE,
                              required_sources=("verification",), model_conclusion="ACTIVE")
        self.assertTrue(result["abstained"])
        self.assertIsNone(result["published_conclusion"])
        self.assertEqual(result["attribution"], publication.ABSTAINED)

    def test_contradictory_evidence_yields_unresolved(self):
        result = self.publish(question="Is the door SEALED or OPEN?", evidence=CONTRADICTORY_EVIDENCE,
                              rule=recon.EQUAL_CREDIBILITY, model_conclusion="SEALED")
        self.assertTrue(result["abstained"])

    def test_no_applicable_rule_yields_abstention(self):
        result = self.publish(question="Which?", evidence=NO_RULE_EVIDENCE, rule=recon.NO_DECLARED_RULE)
        self.assertTrue(result["abstained"])
        self.assertIsNone(result["published_conclusion"])
        self.assertEqual(result["attribution"], publication.ABSTAINED)

    # ---------------------------------------------------------------- C. persistence discipline
    def test_duplicate_publication_is_idempotent(self):
        first = self.publish(model_conclusion="OPEN", model_citation="E3", now=T1)
        second = self.publish(model_conclusion="OPEN", model_citation="E3", now=T1)
        self.assertEqual(first["publication_id"], second["publication_id"])
        self.assertEqual(len(publication.publications(self.db)), 1)

    def test_raw_model_output_is_preserved_for_audit(self):
        result = self.publish(model_conclusion="CLOSED", model_citation="E3",
                              model_raw_output='{"verdict": "CLOSED", "decisive": "E3"}')
        rows = publication.publications(self.db)
        self.assertEqual(rows[0]["model_raw_output"], '{"verdict": "CLOSED", "decisive": "E3"}')
        self.assertEqual(result["model_raw_output"], '{"verdict": "CLOSED", "decisive": "E3"}')

    def test_persistence_interruption_does_not_produce_fictional_success(self):
        # An unwritable database path must RAISE, never return a fabricated successful publication.
        bad_db = str(self.base / "missing_dir" / "state.db")
        with self.assertRaises(sqlite3.Error):
            publication.publish(bad_db, question="q", evidence=SETTLED_EVIDENCE,
                                rule=recon.NEWEST_CALIBRATED_WINS, model_conclusion="OPEN",
                                model_citation="E3", now=T1)

    def test_personality_and_presentation_cannot_override_a_refused_publication(self):
        # A presentation/personality wrapper adds noise but must not change the published fact or refusal.
        plain = self.publish(model_conclusion="CLOSED", model_citation="E3", model_raw_output="CLOSED")
        decorated = self.publish(model_conclusion="CLOSED", model_citation="E3",
                                 model_raw_output="CLOSED (I am absolutely certain, trust me!)", now=T1 + 1)
        self.assertEqual(plain["published_conclusion"], decorated["published_conclusion"])
        self.assertEqual(plain["attribution"], decorated["attribution"])
        self.assertEqual(plain["refusal_reason"], decorated["refusal_reason"])

    # ---------------------------------------------------------------- D. provider distinction
    def test_configured_provider_is_distinguishable_from_local(self):
        self.assertNotEqual(model_boundary.CONFIGURED, model_boundary.LOCAL)
        # A test double is never recorded as a real-model result.
        out = model_boundary.invoke(self.db, messages=[{"role": "user", "content": "x"}],
                                    purpose="gate", simulated_response="OPEN", now=T1)
        self.assertEqual(out["kind"], model_boundary.TEST_DOUBLE)
        self.assertFalse(out["is_real_model_output"])
        rows = model_boundary.invocations(self.db)
        self.assertEqual(rows[-1]["provider"], "TEST_DOUBLE")

    def test_system_prompt_reaches_the_configured_provider_unchanged(self):
        # Regression: the CONFIGURED path used to pass `purpose` as the system prompt and DROP the real
        # system message, so any output contract set by the caller never reached the model.
        captured = {}

        class FakeRouter:
            def __init__(self, model=None, **kwargs):
                self.model = model or "env-default-model"

            def think(self, user_input, history, system_prompt, temperature=0.3, max_tokens=None):
                captured["user_input"] = user_input
                captured["history"] = history
                captured["system_prompt"] = system_prompt
                return '{"verdict": "OPEN"}'

        fake_module = types.ModuleType("ciph_router")
        fake_module.CiphRouter = FakeRouter
        with mock.patch.dict(sys.modules, {"ciph_router": fake_module}), \
                mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-key-not-real"}):
            out = model_boundary.invoke(
                self.db,
                messages=[{"role": "system", "content": "CONTRACT-SYSTEM-PROMPT"},
                          {"role": "user", "content": "the evidence"}],
                purpose="gate.prompt-integrity", model_ref="deepseek-chat",
                provider=model_boundary.CONFIGURED, allow_network=True, now=T1)
        self.assertEqual(captured["system_prompt"], "CONTRACT-SYSTEM-PROMPT")
        self.assertEqual(captured["user_input"], "the evidence")
        self.assertEqual(captured["history"], [])
        self.assertEqual(out["output"], '{"verdict": "OPEN"}')
        self.assertEqual(out["provider"], model_boundary.CONFIGURED)
        self.assertEqual(out["model_identity"], "deepseek-chat")

    def test_a_missing_system_instruction_is_not_invented(self):
        captured = {}

        class FakeRouter:
            def __init__(self, model=None, **kwargs):
                self.model = model or "env-model"

            def think(self, user_input, history, system_prompt, temperature=0.3, max_tokens=None):
                captured["system_prompt"] = system_prompt
                captured["user_input"] = user_input
                return "no contract was provided"

        fake_module = types.ModuleType("ciph_router")
        fake_module.CiphRouter = FakeRouter
        with mock.patch.dict(sys.modules, {"ciph_router": fake_module}), \
                mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-key-not-real"}):
            model_boundary.invoke(
                self.db, messages=[{"role": "user", "content": "just a question"}],
                purpose="gate.no-system", model_ref="deepseek-v4-pro",
                provider=model_boundary.CONFIGURED, allow_network=True, now=T1)
        # It must NOT fabricate a system instruction (e.g. substitute `purpose`); an absent one stays absent.
        self.assertEqual(captured["system_prompt"], "")
        self.assertEqual(captured["user_input"], "just a question")

    def test_the_boundary_serves_and_records_the_requested_model(self):
        captured = {}

        class FakeRouter:
            def __init__(self, model=None, **kwargs):
                self.model = model or "env-model"

            def think(self, user_input, history, system_prompt, temperature=0.3, max_tokens=None):
                captured["served"] = self.model
                return '{"verdict": "ABSTAIN"}'

        fake_module = types.ModuleType("ciph_router")
        fake_module.CiphRouter = FakeRouter
        with mock.patch.dict(sys.modules, {"ciph_router": fake_module}), \
                mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-key-not-real"}):
            out = model_boundary.invoke(
                self.db, messages=[{"role": "system", "content": "c"},
                                   {"role": "user", "content": "u"}],
                purpose="gate.model-identity", model_ref="deepseek-v4-pro",
                provider=model_boundary.CONFIGURED, allow_network=True, now=T1)
        # SERVED, RECORDED and RETURNED must all agree on the requested id.
        self.assertEqual(captured["served"], "deepseek-v4-pro")
        self.assertEqual(out["model_identity"], "deepseek-v4-pro")
        self.assertEqual(model_boundary.invocations(self.db)[-1]["model_identity"], "deepseek-v4-pro")

    def test_an_empty_completion_is_a_failure_not_an_answer(self):
        class FakeRouter:
            def __init__(self, model=None, **kwargs):
                self.model = model or "env-model"

            def think(self, user_input, history, system_prompt, temperature=0.3, max_tokens=None):
                return ""  # a reasoning model that returns no content

        fake_module = types.ModuleType("ciph_router")
        fake_module.CiphRouter = FakeRouter
        with mock.patch.dict(sys.modules, {"ciph_router": fake_module}), \
                mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-key-not-real"}):
            out = model_boundary.invoke(
                self.db, messages=[{"role": "system", "content": "c"},
                                   {"role": "user", "content": "u"}],
                purpose="gate.empty", model_ref="deepseek-v4-pro",
                provider=model_boundary.CONFIGURED, allow_network=True, now=T1)
        self.assertTrue(out["refused"])
        self.assertEqual(out["refusal_reason"], model_boundary.EMPTY_MODEL_OUTPUT)
        self.assertIsNone(out["output"])
        self.assertTrue(out["recorded_no_output"])
        # It must NOT be counted as a real-model output by the reality gate.
        self.assertEqual(model_boundary.reality_gate(self.db, probe=False)["real_invocations"], 0)


if __name__ == "__main__":
    unittest.main()
