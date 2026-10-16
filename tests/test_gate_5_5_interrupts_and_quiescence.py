"""
5.5 - interrupts, intervention and safe quiescence.

    STOP has to mean something specific, in bounded time, and it has to mean it about the work in
    flight - not about the next piece of work somebody gets around to cancelling.

The specimens assert the operational meanings of the modes, that an interrupt needs an operator, that a
retry cannot duplicate the intervention, and that settling REFUSES to close over an attempt whose
outcome is unknown.
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ciph.kernel.autonomy_eligibility import OUTCOME_OPERATOR_HOLD, evaluate_eligibility
from ciph.kernel.autonomy_interrupts import (
    KIND_EMERGENCY_STOP,
    KIND_NO_ACTION,
    KIND_QUIESCE,
    KIND_STOP_SESSIONS,
    REASON_DRAIN_REQUIRED,
    REASON_INTERVENTION_REQUIRES_OPERATOR,
    enforce_operator_mode,
    intervention_digest,
    interventions,
    settle_session,
)
from ciph.kernel.autonomy_modes import (
    MODE_EMERGENCY_STOP,
    MODE_LIMITED,
    MODE_NORMAL,
    MODE_OFF,
    MODE_QUIESCE,
    MODE_READ_ONLY,
    current_mode,
    mode_digest,
    set_mode,
)
from ciph.kernel.autonomy_session import (SESSION_CLOSED, SESSION_INTERRUPTED, SESSION_QUIESCING,
                                          get_session, open_session, record_session_work,
                                          session_history)
from ciph.kernel.autonomous_work import propose_work_intent
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.missions import open_mission
from ciph.kernel.standing_authorization import (STATUS_ACTIVE, STATUS_REVOKED, authorization_status,
                                               create_standing_authorization)
from ciph.kernel.autonomy_eligibility import OUTCOME_NO_AUTHORITY


class TestGate55InterruptsAndQuiescence(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-55-")
        self.db = str(Path(self.temp.name) / "vault.db")
        self.t1 = 1_800_000_000.0
        self.mission = open_mission(self.db, objective="Maintain repository health", now=self.t1)
        self.authorization = create_standing_authorization(
            self.db, mission_id=self.mission, permitted_work_classes=["RUN_TEST_SUITE"],
            granted_by="operator:operator", now=self.t1)

    def tearDown(self):
        self.temp.cleanup()

    def intent(self, evidence="E-1"):
        return propose_work_intent(self.db, origin_kind="SCHEDULED_REVIEW",
                                   work_class="RUN_TEST_SUITE",
                                   triggering_evidence_refs=[evidence],
                                   parent_mission_id=self.mission, now=self.t1)

    def session(self, intent, **kwargs):
        return open_session(self.db, trigger_kind="SCHEDULED_REVIEW", trigger_ref=intent.intent_id,
                            mission_id=self.mission,
                            standing_auth_id=self.authorization.standing_auth_id,
                            now=kwargs.pop("now", self.t1))

    def attempt(self, session, intent, *, ref, evidence=None, now=None):
        return record_session_work(self.db, session_id=session.session_id, intent_id=intent.intent_id,
                                   eligibility_outcome="ELIGIBLE", attempt_ref=ref,
                                   evidence_ref=evidence, now=now or self.t1)

    # ---------------------------------------------------------------- who may interrupt
    def test_an_interrupt_requires_an_operator(self):
        intent = self.intent()
        session = self.session(intent)
        set_mode(self.db, mode=MODE_QUIESCE, actor="operator:operator", now=self.t1)
        with self.assertRaises(CrucibleError) as refused:
            enforce_operator_mode(self.db, actor="daemon:curiosity", now=self.t1)
        self.assertEqual(refused.exception.reason, REASON_INTERVENTION_REQUIRES_OPERATOR)
        self.assertEqual(get_session(self.db, session.session_id).status, "OPEN")

    def test_a_daemon_cannot_release_an_operator_hold(self):
        set_mode(self.db, mode=MODE_EMERGENCY_STOP, actor="operator:operator", now=self.t1)
        with self.assertRaises(CrucibleError):
            set_mode(self.db, mode=MODE_NORMAL, actor="daemon:curiosity", now=self.t1)
        with self.assertRaises(CrucibleError):
            set_mode(self.db, mode=MODE_LIMITED, actor="daemon:curiosity", now=self.t1)
        self.assertEqual(current_mode(self.db), MODE_EMERGENCY_STOP)
        # A daemon may always tighten - a self-hold is how it stops itself.
        set_mode(self.db, mode=MODE_OFF, actor="daemon:curiosity", now=self.t1)
        self.assertEqual(current_mode(self.db), MODE_OFF)

    # ---------------------------------------------------------------- what each mode means
    def test_quiesce_stops_new_work_and_leaves_the_attempt_alone(self):
        intent = self.intent()
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, "ELIGIBLE")
        session = self.session(intent)
        self.attempt(session, intent, ref="ATT-1")
        set_mode(self.db, mode=MODE_QUIESCE, actor="operator:operator", now=self.t1)
        intervention = enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
        self.assertEqual(intervention.kind, KIND_QUIESCE)
        self.assertEqual(intervention.sessions_quiesced, (session.session_id,))
        self.assertEqual(get_session(self.db, session.session_id).status, SESSION_QUIESCING)
        # New permits are refused by the mode gate, and the attempt that was already in flight is
        # still there - an interrupt is not a licence to clobber work in progress.
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_OPERATOR_HOLD)
        self.assertEqual(len(session_history(self.db)), 1)
        with self.assertRaises(CrucibleError) as refused:
            settle_session(self.db, session.session_id, actor="operator:operator", now=self.t1 + 1)
        self.assertEqual(refused.exception.reason, REASON_DRAIN_REQUIRED)
        self.assertEqual(get_session(self.db, session.session_id).status, SESSION_QUIESCING)

    def test_settling_closes_once_the_boundary_is_resolved(self):
        intent = self.intent()
        session = self.session(intent)
        self.attempt(session, intent, ref="ATT-1")
        set_mode(self.db, mode=MODE_QUIESCE, actor="operator:operator", now=self.t1)
        enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
        # The attempt resolves with attributable evidence, so the boundary is settled. It is the SAME
        # logical work item: the evidence completes the record instead of appending a second one.
        self.attempt(session, intent, ref="ATT-2", evidence="EVD-2", now=self.t1 + 1)
        settled = settle_session(self.db, session.session_id, actor="operator:operator", now=self.t1 + 2)
        self.assertEqual(settled["status"], SESSION_CLOSED)
        self.assertEqual(settled["stop_reason"], "OPERATOR_INTERRUPT")
        # The record of what was STOPPED survives the stop.
        self.assertEqual(len(session_history(self.db)), 1)

    def test_emergency_stop_withdraws_the_standing_authority(self):
        intent = self.intent()
        session = self.session(intent)
        set_mode(self.db, mode=MODE_EMERGENCY_STOP, actor="operator:operator", now=self.t1)
        intervention = enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
        self.assertEqual(intervention.kind, KIND_EMERGENCY_STOP)
        self.assertEqual(intervention.sessions_interrupted, (session.session_id,))
        self.assertEqual(get_session(self.db, session.session_id).status, SESSION_INTERRUPTED)
        self.assertEqual(intervention.authorizations_revoked,
                         (self.authorization.standing_auth_id,))
        self.assertEqual(authorization_status(self.db, self.authorization.standing_auth_id,
                                              now=self.t1), STATUS_REVOKED)
        # While the stop is in force the operator hold is the answer. The revocation shows up when the
        # operator releases the hold: the wake is refused for want of AUTHORITY, not for want of a mode.
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1).outcome, OUTCOME_OPERATOR_HOLD)
        set_mode(self.db, mode=MODE_NORMAL, actor="operator:operator", now=self.t1 + 1)
        self.assertEqual(current_mode(self.db), MODE_NORMAL)
        self.assertEqual(evaluate_eligibility(self.db, intent_id=intent.intent_id,
                                              now=self.t1 + 1).outcome, OUTCOME_NO_AUTHORITY)

    def test_autonomy_off_stops_the_work_without_rewriting_the_grant(self):
        intent = self.intent()
        session = self.session(intent)
        set_mode(self.db, mode=MODE_OFF, actor="operator:operator", now=self.t1)
        intervention = enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
        self.assertEqual(intervention.kind, KIND_STOP_SESSIONS)
        self.assertEqual(intervention.authorizations_revoked, ())
        self.assertEqual(authorization_status(self.db, self.authorization.standing_auth_id,
                                              now=self.t1), STATUS_ACTIVE)
        self.assertEqual(get_session(self.db, session.session_id).status, SESSION_INTERRUPTED)

    def test_a_permissive_mode_is_a_no_op_intervention(self):
        intent = self.intent()
        session = self.session(intent)
        for mode in (MODE_NORMAL, MODE_LIMITED, MODE_READ_ONLY):
            set_mode(self.db, mode=mode, actor="operator:operator", now=self.t1)
            intervention = enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
            self.assertEqual(intervention.kind, KIND_NO_ACTION)
            self.assertFalse(intervention.changed)
        self.assertEqual(get_session(self.db, session.session_id).status, "OPEN")

    # ---------------------------------------------------------------- retry and reconstruction
    def test_a_retried_intervention_does_not_duplicate_itself(self):
        intent = self.intent()
        self.session(intent)
        set_mode(self.db, mode=MODE_QUIESCE, actor="operator:operator", now=self.t1)
        first = enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
        second = enforce_operator_mode(self.db, actor="operator:operator", now=self.t1 + 1)
        self.assertTrue(first.changed)
        self.assertFalse(second.changed, "the retry reported a change it did not make")
        self.assertEqual(second.sessions_quiesced, first.sessions_quiesced)
        self.assertEqual(len(interventions(self.db)), 1)

    def test_emergency_stop_is_idempotent_against_the_revocation(self):
        self.session(self.intent())
        set_mode(self.db, mode=MODE_EMERGENCY_STOP, actor="operator:operator", now=self.t1)
        first = enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
        again = enforce_operator_mode(self.db, actor="operator:operator", now=self.t1 + 5)
        self.assertEqual(again.authorizations_revoked, first.authorizations_revoked)
        self.assertFalse(again.changed)
        self.assertEqual(len(interventions(self.db)), 1)

    def test_interrupt_state_reconstructs_identically_in_a_fresh_process(self):
        intent = self.intent()
        self.session(intent)
        set_mode(self.db, mode=MODE_EMERGENCY_STOP, actor="operator:operator", now=self.t1)
        enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
        expected = {"modes": mode_digest(self.db), "interventions": intervention_digest(self.db)}
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.autonomy_interrupts import intervention_digest;"
                "from ciph.kernel.autonomy_modes import mode_digest;"
                "print(json.dumps({'modes': mode_digest(%r), 'interventions': "
                "intervention_digest(%r)}, sort_keys=True))"
                % (str(Path(__file__).resolve().parents[1]), self.db, self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)

    def test_interrupt_leaves_no_deleted_history(self):
        intent = self.intent()
        session = self.session(intent)
        self.attempt(session, intent, ref="ATT-1")
        set_mode(self.db, mode=MODE_EMERGENCY_STOP, actor="operator:operator", now=self.t1)
        enforce_operator_mode(self.db, actor="operator:operator", now=self.t1)
        connection = sqlite3.connect(self.db)
        rows = connection.execute("SELECT COUNT(*) FROM ciph_autonomy_sessions;").fetchone()[0]
        work = connection.execute("SELECT COUNT(*) FROM ciph_autonomy_session_work;").fetchone()[0]
        connection.close()
        self.assertEqual((rows, work), (1, 1))


if __name__ == "__main__":
    unittest.main()
