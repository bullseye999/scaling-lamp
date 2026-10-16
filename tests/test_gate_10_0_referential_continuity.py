"""
10.0 - referential continuity, and R14's ownership enforcement.

    Ciph must never lose the evidence behind a discovery it has announced while claiming that discovery
    remains retrievable.

The founding specimen runs the eight steps the campaign requires, against the REAL 4.2 ledger for evidence
references and across a REAL process boundary for the restart.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.evolution_ownership import production_sources
from ciph.kernel.referential_continuity import (AMBIGUOUS, ANNOUNCED, AVAILABLE, EXPIRED, NOT_FOUND,
                                                REFUSED, REASON_COUNT_MISMATCH, REASON_NOT_OPERATOR,
                                                REASON_OUT_OF_RANGE, REASON_UNKNOWN_SET, RESOLVED,
                                                announce, announcement_snapshot, announcements,
                                                commit_result_set, followups, get_announcement,
                                                get_finding, mark_finding_unavailable,
                                                record_followup, record_new_scan, referential_digest,
                                                resolve_reference, result_sets, retrieve_nth,
                                                retrieve_result_set, revise_result_set)
from ciph.kernel.referential_ownership import (REFERENTIAL_OWNERSHIP_V1, assert_ownership_clean,
                                               conversation_memory_writes_truth,
                                               invented_finding_identities, legacy_owners_to_classify,
                                               ownership_report, rescans_substituted_for_retrieval,
                                               rival_result_store_owners,
                                               unverified_announcement_paths)

T1 = 1_800_000_000.0
INVESTIGATION = "CP-INVESTIGATION-1"


class ReferentialTestCase(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-100-")
        self.db = str(pathlib.Path(self.temp.name) / "continuity.db")

    def tearDown(self):
        self.temp.cleanup()

    def findings(self, count, *, prefix="ALERT", when=T1):
        """Real findings: each one carries a 4.2 ledger observation as its evidence."""
        built = []
        self._last_findings = built
        for index in range(1, count + 1):
            observation = record_observation(self.db, source_ref=f"SOURCE:{prefix}-{index}",
                                             raw_text=f"{prefix} {index} payload",
                                             now=when + index)
            built.append({"source_ref": f"SOURCE:{prefix}-{index}",
                          "evidence_ref": observation["observation_id"],
                          "observation_ref": observation["observation_id"],
                          "summary": f"{prefix} {index}"})
        self._last_findings = built
        return built

    def committed(self, count=20, *, investigation=INVESTIGATION, prefix="ALERT"):
        return commit_result_set(self.db, investigation_ref=investigation,
                                 findings=self.findings(count, prefix=prefix), now=T1)


class TestFoundingSpecimen(ReferentialTestCase):

    def test_founding_eight_step_specimen(self):
        # 1. produce an investigation with exactly twenty PERSISTED findings
        committed = self.committed(20)
        self.assertEqual(committed["count"], 20)

        # 2. announce that twenty were found - the count is verified against committed bytes
        announcement = announce(self.db, result_set_id=committed["result_set_id"],
                                statement="Sir, I found twenty alerts.", actor="operator:operator",
                                now=T1 + 50)
        self.assertEqual(announcement["status"], ANNOUNCED)
        self.assertEqual(announcement["verified_count"], 20)

        # 3. retrieve all twenty
        everything = retrieve_result_set(self.db, committed["result_set_id"], actor="operator:operator")
        self.assertEqual(everything["count"], 20)
        self.assertEqual(everything["available_count"], 20)
        self.assertEqual([item["ordinal"] for item in everything["findings"]], list(range(1, 21)))

        # 4. retrieve the seventh
        seventh = retrieve_nth(self.db, committed["result_set_id"], 7, actor="operator:operator")
        original_id = seventh["finding"]["finding_id"]
        original_evidence = seventh["finding"]["evidence_ref"]

        # 5/6. restart and ask again: identical identity and evidence, from a fresh process
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.referential_continuity import retrieve_nth, referential_digest;"
                "print(json.dumps({'seventh': retrieve_nth(%r, %r, 7, actor='operator:operator')"
                "['finding']['finding_id'], 'evidence': retrieve_nth(%r, %r, 7, "
                "actor='operator:operator')['finding']['evidence_ref'], 'digest': "
                "referential_digest(%r)}, sort_keys=True))"
                % (str(pathlib.Path(__file__).resolve().parents[1]), self.db, committed["result_set_id"],
                   self.db, committed["result_set_id"], self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        reconstructed = json.loads(out.stdout.strip())
        self.assertEqual(reconstructed["seventh"], original_id)
        self.assertEqual(reconstructed["evidence"], original_evidence)
        self.assertEqual(reconstruct_if_changed := reconstructed["digest"], referential_digest(self.db))
        self.assertEqual(retrieve_nth(self.db, committed["result_set_id"], 7,
                                      actor="operator:operator")["finding"]["finding_id"], original_id)

        # 7. attempt to announce twenty backed by only seventeen committed findings
        seventeen = self.committed(17, investigation="CP-INVESTIGATION-2", prefix="TRAIL")
        self.assertEqual(seventeen["count"], 17)
        refused = announce(self.db, result_set_id=seventeen["result_set_id"],
                           statement="Sir, I found twenty alerts.", actor="operator:operator", now=T1 + 60)
        self.assertEqual(refused["status"], REFUSED)
        self.assertEqual(refused["detail"], REASON_COUNT_MISMATCH)
        self.assertEqual(refused["verified_count"], 17)
        self.assertFalse(refused["retrievable_as_announced"])

        # 8. the refusal is real: seventeen identities exist, the missing three cannot be produced, and
        #    the refused announcement is not a retrievable record of twenty
        reachable = retrieve_result_set(self.db, seventeen["result_set_id"], actor="operator:operator")
        self.assertEqual(reachable["count"], 17)
        self.assertEqual(len({item["finding_id"] for item in reachable["findings"]}), 17)
        snapshot = announcement_snapshot(self.db, refused["announcement_id"], actor="operator:operator")
        self.assertFalse(snapshot["retrievable"])
        self.assertEqual(snapshot["status"], REFUSED)
        self.assertEqual(len(announcements(self.db)), 2)
        self.assertTrue(referential_digest(self.db))


class TestHostileSpecimens(ReferentialTestCase):

    def test_two_investigations_make_the_phrase_ambiguous(self):
        first = self.committed(20, investigation="CP-A", prefix="A")
        second = self.committed(20, investigation="CP-B", prefix="B")
        ambiguous = resolve_reference(self.db, candidates=[first["result_set_id"],
                                                          second["result_set_id"]],
                                      phrase="those twenty alerts", actor="operator:operator")
        self.assertEqual(ambiguous["status"], AMBIGUOUS)
        self.assertEqual(len(ambiguous["candidates"]), 2)
        resolved = resolve_reference(self.db, candidates=[first["result_set_id"]],
                                     phrase="those twenty alerts", actor="operator:operator")
        self.assertEqual(resolved["status"], RESOLVED)
        self.assertEqual(resolve_reference(self.db, candidates=[], phrase="nothing",
                                           actor="operator:operator")["status"], NOT_FOUND)

    def test_commit_then_notify_and_crash_between_them(self):
        committed = self.committed(20)
        # A crash here means: findings committed, no announcement yet. Retrieval works; nothing claims it
        # was announced.
        self.assertEqual(announcements(self.db), [])
        self.assertEqual(retrieve_result_set(self.db, committed["result_set_id"],
                                             actor="operator:operator")["count"], 20)

    def test_a_retried_announcement_is_one_announcement(self):
        committed = self.committed(20)
        first = announce(self.db, result_set_id=committed["result_set_id"],
                         statement="Sir, I found twenty alerts.", actor="operator:operator", now=T1 + 50)
        second = announce(self.db, result_set_id=committed["result_set_id"],
                          statement="Sir, I found twenty alerts.", actor="operator:operator", now=T1 + 90)
        self.assertEqual(first["announcement_id"], second["announcement_id"])
        self.assertEqual(len(announcements(self.db)), 1, "a retried delivery is one announcement")

    def test_an_announcement_for_an_uncommitted_set_is_refused(self):
        with self.assertRaises(CrucibleError) as refused:
            announce(self.db, result_set_id="RS-DOES-NOT-EXIST", statement="Sir, I found twenty alerts.",
                     actor="operator:operator", now=T1)
        self.assertEqual(refused.exception.reason, REASON_UNKNOWN_SET)

    def test_missing_evidence_is_reported_and_never_substituted(self):
        committed = self.committed(20)
        seventh = retrieve_nth(self.db, committed["result_set_id"], 7,
                               actor="operator:operator")["finding"]
        mark_finding_unavailable(self.db, seventh["finding_id"], availability=EXPIRED,
                                 reason="retention window closed", now=T1 + 100)
        after = retrieve_result_set(self.db, committed["result_set_id"], actor="operator:operator")
        self.assertEqual(after["count"], 20, "the identity is still part of the set")
        self.assertEqual(after["available_count"], 19)
        self.assertEqual(after["unavailable"], [{"finding_id": seventh["finding_id"],
                                                 "availability": EXPIRED}])
        self.assertFalse(after["substituted_by_a_new_scan"])

    def test_a_finding_cannot_be_committed_without_source_and_evidence(self):
        with self.assertRaises(CrucibleError) as missing:
            commit_result_set(self.db, investigation_ref="CP-X",
                              findings=[{"source_ref": "S", "summary": "an assertion with no evidence"}],
                              now=T1)
        self.assertEqual(missing.exception.reason, "FINDING_REQUIRES_SOURCE_AND_EVIDENCE")
        with self.assertRaises(CrucibleError):
            commit_result_set(self.db, investigation_ref="CP-X",
                              findings=[{"evidence_ref": "OBS-1", "summary": "no source"}], now=T1)

    def test_identities_are_derived_and_cannot_be_supplied_by_the_caller(self):
        """The API accepts no id: a model cannot invent one, and the same findings reproduce the same set."""
        committed = self.committed(20)
        # Re-committing the SAME evidence is idempotent: same set, same findings, no new revision. This is
        # what makes a crash-and-retry after the commit safe.
        identical = commit_result_set(self.db, investigation_ref=INVESTIGATION,
                                      findings=self._last_findings, now=T1 + 5)
        self.assertEqual(committed["result_set_id"], identical["result_set_id"])
        self.assertEqual(committed["finding_ids"], identical["finding_ids"])
        self.assertTrue(identical["idempotent"])
        self.assertEqual(identical["revision"], 1, "a retry is not a new revision")
        # A genuinely NEW observation is a new set: identity follows evidence, not intent.
        different = self.committed(20, prefix="OTHER")
        self.assertNotEqual(committed["result_set_id"], different["result_set_id"])

    def test_a_new_scan_is_a_new_set_and_never_a_substitution(self):
        original = self.committed(20)
        rescan = record_new_scan(self.db, investigation_ref=INVESTIGATION,
                                 findings=self.findings(6, prefix="RESCAN"),
                                 previous_result_set=original["result_set_id"], now=T1 + 200)
        self.assertTrue(rescan["is_a_new_scan"])
        self.assertNotEqual(rescan["result_set_id"], original["result_set_id"])
        self.assertEqual(rescan["count"], 6)
        # The original is still exactly itself.
        again = retrieve_result_set(self.db, original["result_set_id"], actor="operator:operator")
        self.assertEqual(again["count"], 20)
        self.assertFalse(again["substituted_by_a_new_scan"])

    def test_a_revision_does_not_rewrite_what_was_announced(self):
        committed = self.committed(20)
        announcement = announce(self.db, result_set_id=committed["result_set_id"],
                                statement="Sir, I found twenty alerts.", actor="operator:operator",
                                now=T1 + 50)
        # Findings are DISCOVERED: a revision appends. Two more truly-observed findings arrive, so the set
        # grows to 22 while the announcement keeps pointing at the twenty it was made against.
        added = revise_result_set(self.db, committed["result_set_id"],
                                  findings=self.findings(2, prefix="LATE"), note="two more arrived",
                                  actor="operator:operator", now=T1 + 300)
        self.assertEqual(added["revision"], 2)
        self.assertEqual(added["added"], 2)
        revised = retrieve_result_set(self.db, committed["result_set_id"], actor="operator:operator")
        self.assertEqual(revised["revision"], 2)
        self.assertEqual(revised["count"], 22)
        self.assertEqual([item["ordinal"] for item in revised["findings"]][-2:], [21, 22],
                         "ordinals continue, so #7 is still #7")
        snapshot = announcement_snapshot(self.db, announcement["announcement_id"], actor="operator:operator")
        self.assertEqual(snapshot["revision"], 1, "the announcement keeps pointing at its own revision")
        self.assertEqual(snapshot["count"], 20)

    def test_protected_findings_require_an_operator(self):
        committed = commit_result_set(self.db, investigation_ref="CP-PROTECTED",
                                     findings=self.findings(3, prefix="SECRET"),
                                     classification="OPERATOR_ONLY", now=T1)
        with self.assertRaises(CrucibleError) as refused:
            retrieve_result_set(self.db, committed["result_set_id"])
        self.assertEqual(refused.exception.reason, REASON_NOT_OPERATOR)
        with self.assertRaises(CrucibleError):
            announce(self.db, result_set_id=committed["result_set_id"],
                     statement="Sir, I found three alerts.", now=T1)
        self.assertEqual(retrieve_result_set(self.db, committed["result_set_id"],
                                             actor="operator:operator")["count"], 3)

    def test_ordinal_out_of_range_is_honest(self):
        committed = self.committed(20)
        with self.assertRaises(CrucibleError) as refused:
            retrieve_nth(self.db, committed["result_set_id"], 21, actor="operator:operator")
        self.assertEqual(refused.exception.reason, REASON_OUT_OF_RANGE)

    def test_a_followup_requires_a_durable_reference(self):
        committed = self.committed(20)
        seventh = retrieve_nth(self.db, committed["result_set_id"], 7, actor="operator:operator")["finding"]
        followup = record_followup(self.db, text="continue investigating #7",
                                   finding_ref=seventh["finding_id"], now=T1 + 400)
        self.assertEqual(followup["finding_ref"], seventh["finding_id"])
        with self.assertRaises(CrucibleError):
            record_followup(self.db, text="remember that thing I mentioned", now=T1 + 401)
        self.assertEqual(len(followups(self.db)), 1)

    def test_cross_process_reconstruction_matches(self):
        committed = self.committed(20)
        announce(self.db, result_set_id=committed["result_set_id"],
                 statement="Sir, I found twenty alerts.", actor="operator:operator", now=T1 + 50)
        expected = referential_digest(self.db)
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from ciph.kernel.referential_continuity import referential_digest;"
                "print(json.dumps(referential_digest(%r)))"
                % (str(pathlib.Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(json.loads(out.stdout.strip()), expected)


class TestR14Ownership(ReferentialTestCase):

    def test_r14_census_is_clean_and_names_the_legacy_owners(self):
        report = assert_ownership_clean()
        self.assertEqual(report["concerns"], 11)
        classified = {item["module"] for item in report["legacy_owners_to_classify"]}
        for expected in ("smart_memory.py", "enhanced_conversation.py", "personality_engine.py",
                         "mood_engine.py", "self_awareness.py"):
            self.assertIn(expected, classified)
        self.assertEqual(legacy_owners_to_classify(), tuple(report["legacy_owners_to_classify"]))

    def test_each_r14_zero_fires_on_its_own_synthetic_violation(self):
        real = dict(production_sources())
        rogue = "ciph/kernel/rogue_referential.py"
        cases = [
            (rival_result_store_owners,
             "def steal(c):\n    c.execute('INSERT INTO ciph_findings VALUES (1);')\n"),
            (unverified_announcement_paths, "def go(db):\n    return announce_without_commit(db)\n"),
            (rescans_substituted_for_retrieval, "def go(db):\n    return rescan_to_answer(db)\n"),
            (invented_finding_identities, "finding_id = \"F-MADE-UP\"\n"),
            (conversation_memory_writes_truth,
             "def remember(c):\n    c.execute('INSERT INTO ciph_observations VALUES (1);')\n"),
        ]
        for predicate, body in cases:
            with self.subTest(predicate=predicate.__name__):
                if predicate is conversation_memory_writes_truth:
                    sources = {**real, "smart_memory.py": body}
                else:
                    sources = {**real, rogue: body}
                self.assertTrue(predicate(sources=list(sources.items())),
                                f"{predicate.__name__} did not fire")

    def test_the_r14_report_is_available_without_asserting_cleanliness(self):
        report = ownership_report()
        self.assertEqual(report["policy_version"], REFERENTIAL_OWNERSHIP_V1)
        self.assertIn("legacy_owners_to_classify", report)


if __name__ == "__main__":
    unittest.main()
