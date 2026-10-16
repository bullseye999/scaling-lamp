"""
10.1 unified conversational continuity + 10.2 persistent operational presence.

    Ciph must not confuse remembering a promise with having fulfilled it.

The specimens compose the REAL owners: 10.0 findings and follow-ups, 10.5 relationships, 10.6 attention
checkpoints, 4.1 remaining authorized work, 5.x standing authorizations, 6.x workers and delegations, and
7.x federation nodes. Every positive specimen has a counterpart where the evidence is insufficient.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

from ciph.kernel import conversational_continuity as conv
from ciph.kernel import operational_presence as presence
from ciph.kernel import selective_attention as attention
from ciph.kernel.conversation_channels import DisposableMessageChannel, LocalTerminalChannel
from ciph.kernel.conversation_ownership import assert_ownership_clean
from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.referential_continuity import (announce, commit_result_set, record_followup, retrieve_nth,
                                                retrieve_result_set)
from ciph.kernel.standing_authorization import create_standing_authorization
from ciph.kernel.swarm_delegation import claim_delegation, propose_delegation
from ciph.kernel.swarm_results import submit_result
from ciph.kernel.swarm_worker import attest_worker, register_worker

T1 = 1_800_000_000.0
OPERATOR_ID = "operator:operator"
ASSISTANT_ID = "ciph"


class ContinuityCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-1012-")
        self.base = pathlib.Path(self.temp.name)
        self.db = str(self.base / "state.db")
        conv.register_participant(self.db, participant_id=OPERATOR_ID, role=conv.OPERATOR,
                                  display_name="operator", authority_ref="operator", now=T1)
        conv.register_participant(self.db, participant_id=ASSISTANT_ID, role=conv.ASSISTANT, now=T1)
        self.terminal = LocalTerminalChannel()
        self.message = DisposableMessageChannel()
        self.terminal.register(self.db, now=T1)
        self.message.register(self.db, now=T1)
        self.session = "SES-1"
        conv.open_session(self.db, session_id=self.session, participant_id=OPERATOR_ID,
                          channel_id=self.terminal.channel_id, now=T1)

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------ real owners
    def investigation(self, count=7, ref="CP-7"):
        findings = []
        for index in range(1, count + 1):
            observation = record_observation(self.db, source_ref=f"src:{index}",
                                             raw_text=f"finding {index}", now=T1 + index)
            findings.append({"source_ref": f"src:{index}", "evidence_ref": observation["observation_id"],
                             "summary": f"finding {index}"})
        committed = commit_result_set(self.db, investigation_ref=ref, findings=findings, now=T1)
        announcement = announce(self.db, result_set_id=committed["result_set_id"],
                                statement=f"Sir, I found {count} findings.", actor="operator:operator",
                                now=T1 + 1)
        return committed, announcement

    def authorized_investigation(self, *, now=T1):
        return create_standing_authorization(self.db, mission_id="M-1",
                                             permitted_work_classes=["RESEARCH"],
                                             granted_by="operator:operator", risk_ceiling="LOW",
                                             scope_constraints=["public-sources"],
                                             valid_until=now + 86400, now=now)

    def worker_task(self, worker_id="W1", task="TASK-1", output="OUT-1"):
        from ciph.kernel.swarm_worker import INSTALLED, VERIFIED, record_capability
        identity = register_worker(self.db, worker_id=worker_id, process_identity=worker_id,
                                   code_digest="CODE", environment_digest="ENV", now=T1)
        attest_worker(self.db, worker_id, identity.instance_generation, observed_code_digest="CODE",
                      observed_environment_digest="ENV", actor="operator:operator", now=T1)
        for capability in ("coding",):
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=INSTALLED, actor=f"worker:{worker_id}", now=T1)
            record_capability(self.db, worker_id, identity.instance_generation, capability=capability,
                              level=VERIFIED, actor="operator:operator", evidence_ref="CAP-1", now=T1)
        delegation = propose_delegation(self.db, task_identity=task, input_digest=f"IN-{task}",
                                        basis_digest=f"BAS-{task}",
                                        allowed_work_class="GENERATE_CANDIDATE",
                                        required_capabilities=["coding"], now=T1)
        claim_delegation(self.db, delegation.delegation_id, worker_id=worker_id,
                         worker_generation=identity.instance_generation,
                         input_digest=delegation.input_digest, lease_seconds=120.0, now=T1)
        result = submit_result(self.db, delegation_id=delegation.delegation_id, worker_id=worker_id,
                               worker_generation=identity.instance_generation, output_digest=output,
                               basis_digest=delegation.basis_digest, evidence_refs=["EV"],
                               source_dependency_refs=["SRC"], now=T1)
        return identity, delegation, result

    def counts(self, table):
        import sqlite3
        if not pathlib.Path(self.db).exists():
            return 0
        connection = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)
        try:
            return int(connection.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            connection.close()


class TestConversationIdentity(ContinuityCase):

    def test_turns_carry_identity_ordering_and_provenance(self):
        conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID, text="hello", now=T1)
        conv.record_turn(self.db, session_id=self.session, speaker=ASSISTANT_ID, text="sir", now=T1 + 1)
        records = conv.turns(self.db, session_id=self.session)
        self.assertEqual([row["ordinal"] for row in records], [1, 2])
        self.assertEqual([row["speaker"] for row in records], [OPERATOR_ID, ASSISTANT_ID])
        self.assertEqual(records[1]["provenance"], None)
        # a stored row is what was said; the "does not establish" boundary is on the record's return value
        recorded = conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID,
                                    text="again", now=T1 + 2)
        self.assertIn("does_not_establish", recorded)
        self.assertIn("that work is authorized", recorded["does_not_establish"])

    def test_an_unknown_participant_or_channel_is_refused(self):
        with self.assertRaises(CrucibleError) as refused:
            conv.open_session(self.db, session_id="SES-X", participant_id="stranger",
                              channel_id=self.terminal.channel_id, now=T1)
        self.assertEqual(refused.exception.reason, "UNKNOWN_PARTICIPANT")
        with self.assertRaises(CrucibleError) as no_channel:
            conv.open_session(self.db, session_id="SES-X", participant_id=OPERATOR_ID,
                              channel_id="ghost", now=T1)
        self.assertEqual(no_channel.exception.reason, "UNKNOWN_CHANNEL")

    def test_a_reference_is_validated_against_its_owner(self):
        committed, _ = self.investigation(3, ref="CP-3")
        finding = retrieve_nth(self.db, committed["result_set_id"], 1, actor=OPERATOR_ID)["finding"]
        good = conv.record_turn(self.db, session_id=self.session, speaker=ASSISTANT_ID,
                                text="I found something", refs=[(conv.FINDING, finding["finding_id"])],
                                now=T1)
        self.assertTrue(good["refs"][0]["resolved"])
        dangling = conv.record_turn(self.db, session_id=self.session, speaker=ASSISTANT_ID,
                                    text="I found something else",
                                    refs=[(conv.FINDING, "F-DOES-NOT-EXIST")], now=T1 + 1)
        self.assertFalse(dangling["refs"][0]["resolved"])

    def test_a_fresh_process_reconstructs_the_same_history(self):
        conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID, text="one", now=T1)
        conv.record_turn(self.db, session_id=self.session, speaker=ASSISTANT_ID, text="two", now=T1 + 1)
        expected = conv.conversation_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.conversational_continuity import conversation_digest, history;"
                "print(json.dumps({'digest': conversation_digest(%r), "
                "'turns': len(history(%r, session_id=%r)['turns'])}, sort_keys=True))"
                % (str(pathlib.Path(__file__).resolve().parents[1]), self.db, self.db, self.session))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        rebuilt = json.loads(out.stdout.strip())
        self.assertEqual(rebuilt["digest"], expected)
        self.assertEqual(rebuilt["turns"], 2)


class TestReferentialUnderstanding(ContinuityCase):

    def test_an_ordinal_resolves_to_the_durable_finding(self):
        committed, _ = self.investigation(7)
        third = retrieve_nth(self.db, committed["result_set_id"], 3, actor=OPERATOR_ID)["finding"]
        resolution = conv.resolve_reference(self.db, phrase="Explain the third", actor=OPERATOR_ID, now=T1)
        self.assertTrue(resolution["resolved"])
        self.assertEqual(resolution["canonical"]["finding"]["finding_id"], third["finding_id"])

    def test_two_plausible_referents_are_reported_as_ambiguous(self):
        self.investigation(3, ref="CP-A")
        self.investigation(3, ref="CP-B")
        resolution = conv.resolve_reference(self.db, phrase="show me the findings", actor=OPERATOR_ID,
                                             now=T1)
        self.assertFalse(resolution.get("answered_from_evidence", False))
        self.assertTrue(resolution["ambiguous"] or resolution["kind"] == "UNRESOLVED_REFERENCE")

    def test_a_prior_session_reference_resolves_to_the_closed_session(self):
        conv.close_session(self.db, session_id=self.session, now=T1 + 10)
        second = "SES-2"
        conv.open_session(self.db, session_id=second, participant_id=OPERATOR_ID,
                          channel_id=self.message.channel_id, topic_ref="CP-7", now=T1 + 11)
        resolution = conv.resolve_reference(self.db, phrase="What were we talking about before I "
                                                            "disconnected?", now=T1 + 12)
        self.assertEqual(resolution["kind"], "PRIOR_SESSION")
        self.assertEqual(resolution["session"]["session_id"], self.session)

    def test_an_unresolvable_reference_says_so_rather_than_guessing(self):
        resolution = conv.resolve_reference(self.db, phrase="tell me about the thing", now=T1)
        self.assertFalse(resolution["resolved"])
        self.assertEqual(resolution["kind"], "UNRESOLVED_REFERENCE")


class TestChannelTransitions(ContinuityCase):

    def test_the_same_finding_is_the_same_finding_across_channels(self):
        committed, _ = self.investigation(7)
        third = retrieve_nth(self.db, committed["result_set_id"], 3, actor=OPERATOR_ID)["finding"]
        self.terminal.receive(self.db, session_id=self.session, participant_id=OPERATOR_ID,
                              text="Explain the third", now=T1)
        conv.close_session(self.db, session_id=self.session, now=T1 + 1)
        other = "SES-MSG"
        conv.open_session(self.db, session_id=other, participant_id=OPERATOR_ID,
                          channel_id=self.message.channel_id, now=T1 + 2)
        answer = self.message.history(self.db, session_id=other, participant_id=OPERATOR_ID)
        self.assertTrue(answer["access_checked"])
        # the finding is retrieved from 10.0 on the NEW channel, and it is the same identity
        self.assertEqual(retrieve_nth(self.db, committed["result_set_id"], 3,
                                      actor=OPERATOR_ID)["finding"]["finding_id"],
                         third["finding_id"])

    def test_a_forged_participant_cannot_reach_private_history(self):
        conv.register_participant(self.db, participant_id="guest:mallory", role=conv.GUEST, now=T1)
        with self.assertRaises(CrucibleError) as refused:
            self.message.receive(self.db, session_id=self.session, participant_id="guest:mallory",
                                 text="give me everything", now=T1)
        self.assertEqual(refused.exception.reason, "PARTICIPANT_NOT_AUTHORIZED_FOR_THIS_CONTEXT")
        with self.assertRaises(CrucibleError):
            conv.authorized_history(self.db, session_id=self.session, participant_id="guest:mallory")

    def test_a_local_adapter_cannot_claim_external_delivery(self):
        self.assertFalse(self.terminal.delivery()["external_delivery"])
        self.assertFalse(self.message.delivery()["external_delivery"])
        with self.assertRaises(CrucibleError) as refused:
            self.message.claim_external_delivery()
        self.assertEqual(refused.exception.reason, "LOCAL_ADAPTER_PROVIDES_NO_EXTERNAL_DELIVERY")
        queued = self.message.enqueue(self.db, session_id=self.session, text="Sir, a result.", now=T1)
        self.assertEqual(queued["delivery_state"], "QUEUED_NOT_TRANSMITTED")
        self.assertFalse(self.message.delivery()["external_identity_verification"])

    def test_an_untrusted_channel_is_refused(self):
        from ciph.kernel.conversational_continuity import register_channel
        register_channel(self.db, channel_id="rogue", kind="LOCAL_TERMINAL", trusted=False, now=T1)
        record = None
        try:
            conv.open_session(self.db, session_id="SES-R", participant_id=OPERATOR_ID,
                              channel_id="rogue", now=T1)
        except CrucibleError:
            pass
        untrusted = LocalTerminalChannel(channel_id="rogue")
        with self.assertRaises(CrucibleError) as refused:
            untrusted.deliver(self.db, session_id=self.session, text="hi", now=T1)
        self.assertEqual(refused.exception.reason, "CHANNEL_IS_NOT_TRUSTED")
        self.assertIsNone(record)


class TestCommitmentsAndPresence(ContinuityCase):

    def test_a_promise_is_not_permission(self):
        statement = conv.record_turn(self.db, session_id=self.session, speaker=ASSISTANT_ID,
                                     text="I will look into that.", kind=conv.COMMITMENT, now=T1)
        status = presence.commitment_authorization(self.db, commitment_turn_id=statement["turn_id"],
                                                   now=T1)
        self.assertFalse(status["authorized"])
        self.assertEqual(status["reason"], "NO_AUTHORIZATION_ATTACHED")
        self.assertFalse(statement["establishes"] == "authorization")

    def test_a_commitment_with_an_active_grant_is_authorized_by_the_OWNER(self):
        grant = self.authorized_investigation()
        statement = conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID,
                                     text="Investigate the public sources.", kind=conv.COMMITMENT,
                                     authorization_ref=grant.standing_auth_id, now=T1)
        status = presence.commitment_authorization(self.db, commitment_turn_id=statement["turn_id"],
                                                   now=T1 + 1)
        self.assertTrue(status["authorized"])
        self.assertEqual(status["authorization_status"], "ACTIVE")

    def test_an_expired_grant_does_not_authorize_the_promise(self):
        grant = self.authorized_investigation(now=T1)
        statement = conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID,
                                     text="Investigate.", kind=conv.COMMITMENT,
                                     authorization_ref=grant.standing_auth_id, now=T1)
        later = presence.commitment_authorization(self.db, commitment_turn_id=statement["turn_id"],
                                                  now=T1 + 200000)
        self.assertFalse(later["authorized"])
        self.assertEqual(later["reason"], "AUTHORIZATION_IS_NOT_ACTIVE")

    def test_a_vague_wish_authorizes_nothing(self):
        wish = conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID,
                                text="I'd love Ciph to investigate cybersecurity research independently.",
                                now=T1)
        boundary = presence.initiative_boundary(self.db, statement_ref=wish["turn_id"], now=T1)
        self.assertFalse(boundary["authorization_granted"])
        self.assertTrue(boundary["proposal_allowed"])
        self.assertTrue(boundary["looks_like_intent"])

    def test_an_unknown_grant_reference_authorizes_nothing(self):
        statement = conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID,
                                     text="Do the thing.", kind=conv.COMMITMENT,
                                     authorization_ref="SA-DOES-NOT-EXIST", now=T1)
        status = presence.commitment_authorization(self.db, commitment_turn_id=statement["turn_id"],
                                                   now=T1)
        self.assertFalse(status["authorized"])
        self.assertEqual(status["reason"], "AUTHORIZATION_REFERENCE_DOES_NOT_RESOLVE")

    def test_a_paused_investigation_did_not_progress_overnight(self):
        self.investigation(3, ref="CP-3")
        report = presence.honest_progress(self.db, subject_ref="CP-3", since=T1 + 100, now=T1 + 90000)
        self.assertFalse(report["progressed"])
        self.assertTrue(report["nothing_authorized_happened"])
        self.assertTrue(report["elapsed_time_is_not_progress"])

    def test_absence_report_is_honest_when_nothing_happened(self):
        self.investigation(3, ref="CP-3")
        report = presence.absence_report(self.db, since=T1 + 100, now=T1 + 90000)
        self.assertFalse(report["invented_activity"])
        # With no sensor running, the SENSORY source is uncovered, so a GLOBAL "nothing happened" claim is
        # not permitted - Ciph may report only what the canonical work records contain.
        self.assertFalse(report["global_claim_permitted"])
        self.assertIsNone(report["nothing_authorized_happened"])
        self.assertTrue(report["qualified"])
        self.assertEqual(report["interval"], {"from": T1 + 100, "to": T1 + 90000})
        sources = {item["source"]: item["covered"] for item in report["covered_sources"]}
        self.assertFalse(sources["sensory.fabric"])

    def test_absence_report_can_claim_globally_with_complete_coverage(self):
        from ciph.kernel import sensory_fabric as fabric
        self.investigation(3, ref="CP-3")
        fabric.register_sensor(self.db, sensor_id="beat", capability="c", canonical_owner="o",
                               collection_method="EVENT_DRIVEN", freshness_ttl=10.0, now=T1 + 89990)
        fabric.ingest(self.db, sensor_id="beat", payload={"tick": 1}, now=T1 + 89995)
        report = presence.absence_report(self.db, since=T1 + 89990, now=T1 + 90000)
        self.assertTrue(report["global_claim_permitted"])
        self.assertTrue(report["nothing_authorized_happened"])

    def test_a_disconnected_node_blocks_a_global_absence_claim(self):
        from ciph.kernel.federation_node import register_node
        self.investigation(3, ref="CP-3")
        register_node(self.db, node_id="N1", public_key_ref="key:1", code_digest="CODE",
                      environment_digest="ENV", actor="operator:operator", now=T1)
        report = presence.absence_report(self.db, since=T1 + 100, now=T1 + 90000)
        self.assertFalse(report["global_claim_permitted"])
        self.assertIsNone(report["nothing_authorized_happened"])
        node_source = [item for item in report["covered_sources"]
                       if item["source"] == "federation.nodes"][0]
        self.assertFalse(node_source["covered"])

    def test_delegation_terminality_is_decided_by_the_owner(self):
        from ciph.kernel.swarm_delegation import complete_delegation
        _, delegation, _ = self.worker_task("W1", "TASK-T", "OUT-T")
        in_progress = presence.delegation_disposition(self.db, delegation.delegation_id, now=T1 + 1)
        self.assertEqual(in_progress["disposition"], presence.IN_PROGRESS)
        self.assertTrue(in_progress["resumable"])
        complete_delegation(self.db, delegation.delegation_id, now=T1 + 2)
        terminal = presence.delegation_disposition(self.db, delegation.delegation_id, now=T1 + 3)
        self.assertEqual(terminal["disposition"], presence.TERMINAL)
        self.assertFalse(terminal["resumable"], "a COMPLETED delegation must not look resumable")
        self.assertIn("re-run is a NEW delegation", terminal["reason"])

    def test_an_orphaned_lease_is_resumable_only_through_reclamation(self):
        identity, delegation, _ = self.worker_task("W1", "TASK-O", "OUT-O")
        orphan = presence.delegation_disposition(self.db, delegation.delegation_id, now=T1 + 100000)
        self.assertEqual(orphan["disposition"], presence.ORPHANED)
        self.assertTrue(orphan["resumable"])
        self.assertIn("reclamation", orphan["reason"])
        unknown = presence.delegation_disposition(self.db, "SD-DOES-NOT-EXIST", now=T1)
        self.assertEqual(unknown["disposition"], presence.UNKNOWN)
        self.assertFalse(unknown["resumable"])

    def test_absence_report_names_real_completions(self):
        self.investigation(3, ref="CP-3")
        _, delegation, result = self.worker_task()
        report = presence.absence_report(self.db, since=T1 - 1, now=T1 + 50)
        self.assertIn(result.result_id, [row["result_id"] for row in report["completed_work"]])
        self.assertFalse(report["nothing_authorized_happened"])


class TestNegativeSpecimens(ContinuityCase):

    def test_01_two_twenty_finding_sets_stay_distinct(self):
        first, _ = self.investigation(20, ref="CP-A")
        second, _ = self.investigation(20, ref="CP-B")
        self.assertNotEqual(first["result_set_id"], second["result_set_id"])
        resolution = conv.resolve_reference(self.db, phrase="show me the twenty alerts",
                                            actor=OPERATOR_ID, now=T1)
        self.assertFalse(resolution.get("answered_from_evidence", False))

    def test_02_an_ambiguous_ordinal_is_not_silently_resolved(self):
        self.investigation(20, ref="CP-A")
        self.investigation(20, ref="CP-B")
        resolution = conv.resolve_reference(self.db, phrase="Explain the seventh", actor=OPERATOR_ID,
                                            now=T1)
        self.assertTrue(resolution["ambiguous"] or not resolution["resolved"])

    def test_03_a_summary_cannot_override_canonical_evidence(self):
        committed, _ = self.investigation(3, ref="CP-3")
        conv.summarize(self.db, session_id=self.session, text="There are two findings.", now=T1 + 5)
        selection = conv.context_selection(self.db, session_id=self.session, now=T1 + 6)
        self.assertTrue(all(not hint["is_canonical"] for hint in selection["summary_hints"]))
        self.assertTrue(selection["canonical_evidence_is_separate"])
        self.assertEqual(retrieve_result_set(self.db, committed["result_set_id"],
                                             actor=OPERATOR_ID)["count"], 3)

    def test_04_a_message_claiming_completion_needs_result_evidence(self):
        conv.record_turn(self.db, session_id=self.session, speaker=ASSISTANT_ID,
                         text="The task is complete.", kind=conv.ANNOUNCEMENT, now=T1)
        report = presence.absence_report(self.db, since=T1 - 1, now=T1 + 10)
        # the message established WHAT WAS SAID; the work record contains no completion
        self.assertEqual(report["completed_work"], [])
        self.assertEqual(report["announcements"], [])
        self.assertFalse(report["global_claim_permitted"])
        self.assertIsNone(report["nothing_authorized_happened"])

    def test_05_a_regenerated_summary_supersedes_the_previous_one_only(self):
        conv.summarize(self.db, session_id=self.session, text="first", now=T1)
        second = conv.summarize(self.db, session_id=self.session, text="second", now=T1 + 1)
        self.assertEqual(len(second["supersedes"]), 1)
        live = [row for row in conv.summaries(self.db, session_id=self.session)
                if row["superseded_by"] is None]
        self.assertEqual([row["text"] for row in live], ["second"])

    def test_06_an_interrupted_subject_keeps_its_identity_and_refuses_expired_authority(self):
        self.investigation(3, ref="CP-3")
        plan = presence.resume_plan(self.db, subject_ref="CP-3", now=T1)
        self.assertTrue(plan["keeps_original_identity"])
        self.assertFalse(plan["may_resume_under_expired_permission"])

    def test_07_a_disconnected_node_is_not_currently_active(self):
        from ciph.kernel.federation_node import register_node
        from ciph.kernel import operational_awareness as awareness
        register_node(self.db, node_id="N1", public_key_ref="key:1", code_digest="CODE",
                      environment_digest="ENV", actor="operator:operator", now=T1)
        state = awareness.subject_state(self.db, ref="node:N1:1", now=T1 + 90000)
        self.assertIn(state["state"], (awareness.STALE, awareness.UNKNOWN))
        self.assertFalse(state["is_a_verdict_about_the_subject"])
        projection = presence.presence(self.db, now=T1 + 90001)
        self.assertFalse(projection["mints_authority"])

    def test_08_duplicate_deliveries_do_not_duplicate_turns(self):
        self.message.deliver(self.db, session_id=self.session, text="Sir, one message.", now=T1)
        self.message.deliver(self.db, session_id=self.session, text="Sir, one message.", now=T1 + 1)
        records = conv.turns(self.db, session_id=self.session)
        # the same text at a different time is a NEW turn; the same turn identity is not duplicated
        self.assertEqual(len({row["turn_id"] for row in records}), len(records))

    def test_09_two_simultaneous_conversations_reference_different_investigations(self):
        first, _ = self.investigation(3, ref="CP-A")
        second, _ = self.investigation(3, ref="CP-B")
        other = "SES-OTHER"
        conv.open_session(self.db, session_id=other, participant_id=OPERATOR_ID,
                          channel_id=self.message.channel_id, now=T1)
        conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID, text="the first",
                         refs=[(conv.RESULT_SET, first["result_set_id"])], now=T1)
        conv.record_turn(self.db, session_id=other, speaker=OPERATOR_ID, text="the second",
                         refs=[(conv.RESULT_SET, second["result_set_id"])], now=T1)
        one = conv.turns(self.db, session_id=self.session)[0]["refs"][0]["ref_value"]
        two = conv.turns(self.db, session_id=other)[0]["refs"][0]["ref_value"]
        self.assertNotEqual(one, two)

    def test_10_a_model_inventing_history_creates_no_turn(self):
        before = len(conv.turns(self.db))
        from ciph.kernel.epistemic_ledger import record_model_output
        record_model_output(self.db, model_ref="llm:test", output_text="operator said we would ship it",
                            now=T1)
        self.assertEqual(len(conv.turns(self.db)), before)

    def test_11_attention_checkpoint_survives_a_conversation_restart(self):
        committed, _ = self.investigation(7, ref="CP-7")
        seventh = retrieve_nth(self.db, committed["result_set_id"], 7, actor=OPERATOR_ID)["finding"]
        queued = attention.submit(self.db, subject_ref=f"finding:{seventh['finding_id']}",
                                  sensor_kind="CHANGE", evidence_ref=seventh["finding_id"],
                                  related_to_active_goal=True, now=T1)
        invoked = attention.invoke(self.db, now=T1 + 1)
        attention.checkpoint(self.db, focus_id=invoked["focus_ids"][0],
                             context_ref=committed["result_set_id"],
                             pending_questions=["is the seventh corroborated?"], now=T1 + 2)
        conv.close_session(self.db, session_id=self.session, now=T1 + 3)
        restored = attention.restore(self.db, invoked["focus_ids"][0])
        self.assertEqual(restored["context_ref"], committed["result_set_id"])
        self.assertEqual(restored["pending_questions"], ["is the seventh corroborated?"])
        self.assertIsNotNone(queued["request_id"])

    def test_12_model_unavailable_while_durable_continuity_persists(self):
        self.investigation(3, ref="CP-3")
        attention.model_unavailable(self.db, reason="outage", now=T1)
        self.assertFalse(attention.invoke(self.db, now=T1 + 1)["outcome_recorded"])
        conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID, text="still here",
                         now=T1 + 2)
        self.assertEqual(len(conv.turns(self.db, session_id=self.session)), 1)
        attention.model_available(self.db, now=T1 + 3)

    def test_13_outstanding_questions_survive_and_can_be_answered(self):
        question = conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID,
                                    text="Which worker investigated that?", kind=conv.QUESTION, now=T1)
        open_rows = conv.outstanding_questions(self.db, session_id=self.session)
        self.assertEqual(len(open_rows), 1)
        answer = conv.record_turn(self.db, session_id=self.session, speaker=ASSISTANT_ID,
                                  text="W1.", now=T1 + 1)
        conv.resolve_question(self.db, question_id=open_rows[0]["question_id"],
                              answer_turn_id=message_turn_id(answer), now=T1 + 2)
        self.assertEqual(conv.outstanding_questions(self.db, session_id=self.session)[0]["status"],
                         "ANSWERED")

    def test_14_context_selection_is_bounded(self):
        for index in range(50):
            conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID,
                             text=f"turn {index}", now=T1 + index)
        selection = conv.context_selection(self.db, session_id=self.session, limit=10, now=T1 + 100)
        self.assertEqual(selection["selected"], 10)
        self.assertTrue(selection["bounded"])


def message_turn_id(turn):
    return turn["turn_id"]


class TestFoundingScenario(ContinuityCase):
    """Part D - the integrated scenario, composed of the real conversation and operational owners."""

    def test_the_founding_scenario(self):
        # (1) operator establishes an authorized investigation. (2) Ciph produces seven real findings.
        grant = self.authorized_investigation()
        committed, announcement = self.investigation(7, ref="CP-7")
        followup = record_followup(self.db, text="report back on the seventh",
                                   finding_ref=retrieve_nth(self.db, committed["result_set_id"], 7,
                                                            actor=OPERATOR_ID)["finding"]["finding_id"],
                                   now=T1)
        # (3) Ciph tells operator about them.
        self.terminal.deliver(self.db, session_id=self.session,
                              text="Sir, I found seven findings.", kind=conv.ANNOUNCEMENT, now=T1 + 2)
        self.assertEqual(announcement["verified_count"], 7)
        # (4) operator asks for the third. (5) Ciph retrieves the exact third finding.
        self.terminal.receive(self.db, session_id=self.session, participant_id=OPERATOR_ID,
                              text="Explain the third", now=T1 + 3)
        resolution = conv.resolve_reference(self.db, phrase="Explain the third", actor=OPERATOR_ID,
                                            now=T1 + 4)
        third = resolution["canonical"]["finding"]
        self.assertEqual(third["ordinal"], 3)
        # (6) operator authorizes further investigation: a COMMITMENT pointing at the real grant.
        commitment = conv.record_turn(self.db, session_id=self.session, speaker=OPERATOR_ID,
                                      text="Investigate further within the public-sources scope.",
                                      kind=conv.COMMITMENT, authorization_ref=grant.standing_auth_id,
                                      now=T1 + 5)
        self.assertTrue(presence.commitment_authorization(self.db,
                                                          commitment_turn_id=commitment["turn_id"],
                                                          now=T1 + 6)["authorized"])
        # (7) Worker A begins an authorized task. (8) Worker B produces a related result.
        _, delegation_a, result_a = self.worker_task("W1", "TASK-A", "OUT-A")
        _, delegation_b, result_b = self.worker_task("W2", "TASK-B", "OUT-B")
        # and a third task is authorized-looking but NOT claimed: it is PAUSED, not progressing.
        paused = propose_delegation(self.db, task_identity="TASK-PAUSED", input_digest="IN-PAUSED",
                                    basis_digest="BAS-PAUSED", allowed_work_class="GENERATE_CANDIDATE",
                                    required_capabilities=["coding"], now=T1 + 6)
        # (9) Ciph correlates the results through 10.5.
        from ciph.kernel import operational_awareness as awareness
        link = awareness.correlate(self.db, kind=awareness.LINK_RESULT_INVESTIGATION,
                                   subject_ref=result_b.result_id,
                                   object_ref=committed["result_set_id"], now=T1 + 7)
        self.assertFalse(link["mints_authority"])
        # (10) A meaningful anomaly interrupts attention through 10.6. (11) The original context is kept.
        queued = attention.submit(self.db, subject_ref=f"finding:{third['finding_id']}",
                                  sensor_kind="CHANGE", evidence_ref=third["finding_id"],
                                  related_to_active_goal=True, now=T1 + 8)
        invoked = attention.invoke(self.db, now=T1 + 9)
        attention.checkpoint(self.db, focus_id=invoked["focus_ids"][0],
                             context_ref=committed["result_set_id"],
                             pending_questions=["is the third corroborated?"], now=T1 + 10)
        # (12) The main LLM becomes unavailable. (13) Authorized machinery pauses safely.
        attention.model_unavailable(self.db, reason="main model outage", now=T1 + 11)
        self.assertEqual(attention.invoke(self.db, now=T1 + 12)["status"], attention.MODEL_UNAVAILABLE)
        # (14) The conversational process restarts: session A closes, session B opens on channel two.
        conv.close_session(self.db, session_id=self.session, now=T1 + 13)
        second_session = "SES-MSG"
        conv.open_session(self.db, session_id=second_session, participant_id=OPERATOR_ID,
                          channel_id=self.message.channel_id, topic_ref="CP-7", now=T1 + 14)
        # (15) operator contacts Ciph through the second authorized disposable channel.
        self.message.receive(self.db, session_id=second_session, participant_id=OPERATOR_ID,
                             text="What happened with that third idea?", now=T1 + 15)
        # (16)/(17) Ciph retrieves the original finding, worker results, questions and last state.
        history = self.message.history(self.db, session_id=second_session, participant_id=OPERATOR_ID)
        self.assertTrue(history["access_checked"])
        third_again = retrieve_nth(self.db, committed["result_set_id"], 3, actor=OPERATOR_ID)["finding"]
        self.assertEqual(third_again["finding_id"], third["finding_id"])
        restored = attention.restore(self.db, invoked["focus_ids"][0])
        self.assertEqual(restored["context_ref"], committed["result_set_id"])
        produced = {row["result_id"] for task in awareness.build_projection(self.db)["tasks"]
                    for row in task["worker_results"]}
        self.assertIn(result_a.result_id, produced)
        self.assertIn(result_b.result_id, produced)
        self.assertIsNotNone(delegation_a.delegation_id)
        self.assertIsNotNone(delegation_b.delegation_id)
        # (18)/(19) "What happened while I was away?" distinguishes real work from paused work.
        report = presence.absence_report(self.db, since=T1 - 1, now=T1 + 16)
        self.assertTrue(report["completed_work"])
        self.assertIn(paused.delegation_id,
                      [row["delegation_id"] for row in report["outstanding_work"]])
        self.assertEqual(report["observation_completeness"], presence.PARTIAL)
        self.assertFalse(report["invented_activity"])
        self.assertFalse(presence.honest_progress(self.db, subject_ref="CP-7", since=T1 + 50,
                                                  now=T1 + 90000)["progressed"])
        # (20) A fresh process reconstructs the identical evidence-linked continuity.
        expected = (conv.conversation_digest(self.db), presence.presence_digest(self.db),
                    attention.attention_digest(self.db))
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.conversational_continuity import conversation_digest;"
                "from ciph.kernel.operational_presence import presence_digest;"
                "from ciph.kernel.selective_attention import attention_digest;"
                "print(json.dumps([conversation_digest(%r), presence_digest(%r), attention_digest(%r)]))"
                % ((str(pathlib.Path(__file__).resolve().parents[1]), self.db, self.db, self.db)))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(tuple(json.loads(out.stdout.strip())), expected)
        # No fabricated discoveries, progress, authorizations or context.
        self.assertEqual(self.counts("ciph_permits"), 0)
        self.assertEqual(self.counts("ciph_crucible_deployments"), 0)
        self.assertIsNotNone(followup["followup_id"])
        self.assertIsNotNone(queued["request_id"])


class TestOwnership(unittest.TestCase):

    def test_the_census_is_clean_and_names_the_owners(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 10)
        for key in ("rival_conversation_owners", "conversation_modules_write_canonical",
                    "forbidden_conversation_patterns", "summaries_are_not_canonical",
                    "local_adapters_do_not_claim_external_delivery", "retained_machinery_missing"):
            self.assertEqual(report[key], [], key)

    def test_each_zero_fires_on_its_own_synthetic_violation(self):
        from ciph.kernel import conversation_ownership as census
        real = dict(census.production_sources())
        rogue = "ciph/kernel/rogue_conversation.py"
        cases = [
            (census.rival_conversation_owners,
             "def steal(c):\n    c.execute('INSERT INTO ciph_conv_turns VALUES (1);')\n"),
            (census.conversation_modules_write_canonical,
             "def go(c):\n    c.execute('INSERT INTO ciph_permits VALUES (1);')\n"),
            (census.forbidden_conversation_patterns,
             "def go(db):\n    return conversation_grants_authority(db)\n"),
            (census.summaries_are_not_canonical,
             "def summarize():\n    return {'text': 'x'}\n"),
            (census.local_adapters_do_not_claim_external_delivery,
             "class A:\n    def __init__(self):\n        self.external_delivery = True\n"),
        ]
        for predicate, body in cases:
            with self.subTest(predicate=predicate.__name__):
                if predicate in (census.conversation_modules_write_canonical,
                                 census.summaries_are_not_canonical):
                    sources = {**real, census.CONTINUITY_OWNER: body}
                elif predicate is census.local_adapters_do_not_claim_external_delivery:
                    sources = {**real, census.CHANNELS_OWNER: body}
                else:
                    sources = {**real, rogue: body}
                self.assertTrue(predicate(sources=list(sources.items())),
                                f"{predicate.__name__} did not fire")


if __name__ == "__main__":
    unittest.main()
