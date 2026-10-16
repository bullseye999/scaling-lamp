
"""
Gate A0 closure test - the job claim deadline is a job-level fact, not a token property.

Characterisation of record: the daemon refuses a job whose token expiry has passed
(`EXECUTION_TOKEN_EXPIRED`), so the grace period is a real JOB-START bound rather than session
padding. It is therefore promoted to a canonical job timing fact that BOTH lanes consume. The
permit lane must never read its authority back out of an artifact that S3 will demote.
"""

import pathlib
import unittest

from ciph.runtime import CiphRuntime


class _Grant:
    def __init__(self, expires_at=0.0, valid_until=None):
        self.expires_at = expires_at
        self.valid_until = valid_until


class JobClaimDeadlineTests(unittest.TestCase):

    def test_the_deadline_is_computed_from_canonical_inputs_only(self):
        """The token artifact is not an input: a demoted artifact cannot source authority."""
        code = CiphRuntime.job_claim_deadline.__func__.__code__
        parameters = set(code.co_varnames[: code.co_argcount + code.co_kwonlyargcount])
        for forbidden in ("token", "execution_token", "token_expiry", "token_expires_at"):
            self.assertNotIn(forbidden, parameters)
        self.assertIn("auth_grant", parameters)
        self.assertIn("scope_grant", parameters)

    def test_the_deadline_is_bounded_by_the_authorization_grant(self):
        now = 1_700_000_000.0
        grant = _Grant(expires_at=now + 120.0)
        deadline = CiphRuntime.job_claim_deadline(
            now=now, timeout_seconds=600.0, auth_grant=grant
        )
        self.assertEqual(deadline, now + 120.0)

    def test_the_deadline_is_bounded_by_the_scope_grant(self):
        now = 1_700_000_000.0
        scope = _Grant(valid_until=now + 45.0)
        deadline = CiphRuntime.job_claim_deadline(
            now=now, timeout_seconds=600.0, scope_grant=scope
        )
        self.assertEqual(deadline, now + 45.0)

    def test_the_deadline_includes_the_queue_claim_grace_when_unbounded(self):
        now = 1_700_000_000.0
        deadline = CiphRuntime.job_claim_deadline(now=now, timeout_seconds=30.0)
        self.assertEqual(deadline, now + 30.0 + CiphRuntime.QUEUE_CLAIM_GRACE_SECONDS)

    def test_the_token_lane_now_consumes_the_promoted_fact(self):
        """One timing fact, two lanes - rather than the permit lane re-deriving token semantics."""
        source = pathlib.Path("ciph/runtime.py").read_text(encoding="utf-8")
        self.assertIn("token_expiry = self.job_claim_deadline(", source)
        self.assertNotIn("now + t_sec + 300.0", source)


class JobTimingNeutralityTests(unittest.TestCase):
    """The timing law is neutral: both lanes consume one function and one constant."""

    def test_the_law_module_depends_on_neither_consumer(self):
        import ast
        import pathlib

        source = pathlib.Path("ciph/kernel/job_timing.py").read_text(encoding="utf-8")
        code_only = "\n".join(
            ast.get_source_segment(source, node) or ""
            for node in ast.parse(source).body
            if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
        )
        # A neutral law must not import either lane; otherwise the planner would close a cycle.
        self.assertNotIn("ciph.runtime", code_only)
        self.assertNotIn("dag_planner", code_only)

    def test_the_constant_owner_and_the_consumer_agree(self):
        from ciph.kernel.job_timing import (
            DEFAULT_QUEUE_CLAIM_GRACE_SECONDS,
            job_claim_deadline,
        )

        now = 1_700_000_000.0
        self.assertEqual(
            CiphRuntime.QUEUE_CLAIM_GRACE_SECONDS, DEFAULT_QUEUE_CLAIM_GRACE_SECONDS
        )
        self.assertEqual(
            CiphRuntime.job_claim_deadline(now=now, timeout_seconds=30.0),
            job_claim_deadline(now=now, timeout_seconds=30.0),
        )


class PlannerTimingDedupTests(unittest.TestCase):
    """The planner consumes the neutral law; the duplicate formula cannot come back."""

    def test_the_planner_no_longer_owns_a_timing_formula(self):
        import pathlib

        source = pathlib.Path("ciph/planner/dag_planner.py").read_text(encoding="utf-8")
        self.assertNotIn("+ 300.0", source)
        self.assertGreaterEqual(source.count("job_claim_deadline("), 2)
        self.assertIn("from ciph.kernel.job_timing import job_claim_deadline", source)


if __name__ == "__main__":
    unittest.main()
