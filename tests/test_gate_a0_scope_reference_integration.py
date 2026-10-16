
"""
Gate A0 closure test - SCOPE.4: durable scope references are earned, not assumed.

The observable order must be: canonical scope exists -> a durable reference may exist. Never the
reverse, and never a downgrade: a failed canonicalisation stops the operation rather than producing
a reference without authority.
"""

import pathlib
import unittest


class ScopeReferenceIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.runtime_src = pathlib.Path("ciph/runtime.py").read_text(encoding="utf-8")
        self.planner_src = pathlib.Path("ciph/planner/dag_planner.py").read_text(encoding="utf-8")

    def test_the_plan_step_is_only_referenced_after_scope_is_durable(self):
        step = self.runtime_src.index("plan_step = PlanStep(")
        self.assertIn(
            "self.scope_grant_store().persist_and_verify(scope_grant)",
            self.runtime_src[:step],
        )

    def test_the_authorization_row_is_only_written_after_scope_is_durable(self):
        insert = self.runtime_src.index("INSERT INTO ciph_authorization_grants")
        self.assertIn(
            "self.scope_grant_store().persist_and_verify(scope_grant)",
            self.runtime_src[:insert],
        )

    def test_the_runtime_never_swallows_a_scope_refusal(self):
        """A failed canonicalisation stops the operation; it never downgrades to no-scope."""
        self.assertNotIn("except ScopeGrantReferenceRefused", self.runtime_src)
        self.assertNotIn("ScopeGrantReferenceRefused", self.runtime_src)

    def test_the_planner_blocks_unresolved_references_outside_the_swallowing_try(self):
        """NOT_FOUND / UNVERIFIABLE are authority failures, not diagnostics beside a written row."""
        start = self.planner_src.index("if hasattr(grant_obj, 'grant_id'):")
        swallow = self.planner_src.index("except Exception:", start)
        # The refusal must sit inside the authorization-write block and BEFORE the swallowing try.
        self.assertIn("SCOPE_REFERENCE_UNRESOLVED", self.planner_src[start:swallow])

    def test_the_planner_requires_a_resolver_for_a_non_none_reference(self):
        self.assertIn("SCOPE_REFERENCE_REQUIRES_RESOLVER", self.planner_src)
        # NONE stays an explicit, legitimate case rather than a lookup value.
        self.assertIn('scope_reference != "NONE"', self.planner_src)


if __name__ == "__main__":
    unittest.main()
