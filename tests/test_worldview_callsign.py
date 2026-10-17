"""Callsign substitution and worldview-context isolation.

The persona template must address the operator by their stored callsign, and injected runtime
context (memory, tool output, telemetry) must survive VERBATIM - a literal "operator" in evidence
is not a display word and must never be rewritten.
"""
import tempfile
import unittest
from pathlib import Path

from ciph_worldview import get_worldview


class WorldviewCallsignTests(unittest.TestCase):
    def test_template_tokens_are_all_resolved(self):
        text = get_worldview(operator_name="david", operator_pronoun="he/him")
        for token in ("{OPERATOR}", "{OPERATOR_POSSESSIVE}", "{date}"):
            self.assertNotIn(token, text)

    def test_callsign_and_possessive_are_applied(self):
        text = get_worldview(operator_name="david")
        self.assertIn("built by david", text)
        self.assertIn("david's", text)
        self.assertIn("OPERATOR IDENTITY: address the operator as 'david'.", text)

    def test_pronoun_is_carried_into_the_identity_line(self):
        text = get_worldview(operator_name="david", operator_pronoun="he/him")
        self.assertIn("address the operator as 'david (he/him)'", text)

    def test_defaults_to_generic_operator_when_unset(self):
        text = get_worldview()
        self.assertIn("built by Operator", text)
        self.assertIn("Operator's", text)
        self.assertNotIn("OPERATOR IDENTITY", text)

    def test_injected_memory_context_is_never_rewritten(self):
        memory = "operator said the operator's access to the operator log was revoked."
        text = get_worldview(operator_name="david", memory_context=memory)
        self.assertIn(memory, text)
        self.assertIn("WHAT YOU REMEMBER ABOUT david:", text)

    def test_injected_operational_context_is_never_rewritten(self):
        finding = "scan target=operator.internal result=open deadline=operator timezone"
        text = get_worldview(operator_name="david", operational_context=finding)
        self.assertIn(finding, text)

    def test_injected_world_context_is_never_rewritten(self):
        world = "telemetry note: the operator process restarted"
        text = get_worldview(operator_name="david", world_context=world)
        self.assertIn(world, text)

    def test_operator_declared_tone_override_from_policy_owner(self):
        from ciph.kernel import personality_policy as policy
        with tempfile.TemporaryDirectory() as folder:
            db = str(Path(folder) / "policy.db")
            policy.propose_change(db, key="worldview.tone", value="warm and concise",
                                  policy_class=policy.OPERATOR_PREFERENCE,
                                  provenance="test", actor="operator:1")
            text = get_worldview(operator_name="david", policy_db=db)
            self.assertIn("TONE OVERRIDE (operator-declared preference): warm and concise.", text)
        self.assertNotIn("TONE OVERRIDE", get_worldview(operator_name="david"))


if __name__ == "__main__":
    unittest.main()
