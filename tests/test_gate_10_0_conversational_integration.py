"""
10.0 Part A - the REAL conversational integration.

    Retrieval must never be a scan wearing the word "retrieval".

The three required phrases are routed through `IntentRouter.classify_referential` - the actual routing
decision the runtime consults before either running a command or asking the model - and the answer must
come from durable identity. The restart is a real process boundary.

SCOPE, stated rather than implied: the mandatory interaction is driven by a deterministic LOCAL producer
writing into the real 4.2 epistemic ledger. `RealScanEntryPointTest` then drives the REAL
`DarknetMonitor.full_scan` producer, stubbing only the NETWORK boundary (`verify_tor`/`_tor_get`) because
this environment has no egress - feed scoring, the tally, the alert sync and the durable commit are the
production code. Either way the proven property is the same: durable identity, verified announcement, and
retrieval that cannot re-run the scan it answers from.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest

from ciph.kernel.crucible_types import CrucibleError
from ciph.kernel.epistemic_ledger import record_observation
from ciph.kernel.referential_continuity import (ANNOUNCED, EXPIRED, REFUSED, announce,
                                                commit_result_set, mark_finding_unavailable,
                                                referential_digest, resolve_conversational_reference,
                                                result_sets, retrieve_nth, retrieve_result_set,
                                                revise_result_set)
from intent_router import IntentRouter

T1 = 1_800_000_000.0
INVESTIGATION = "CP-ALERT-SWEEP-1"


class ConversationalIntegrationTest(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-100a-")
        self.db = str(pathlib.Path(self.temp.name) / "vault.db")
        self.router = IntentRouter()

    def tearDown(self):
        self.temp.cleanup()

    # ------------------------------------------------------------------ a real producer
    def run_alert_sweep(self, count=20, *, investigation=INVESTIGATION, prefix="ALERT"):
        """What the scanner path produces: findings, each backed by a durable 4.2 observation."""
        findings = []
        for index in range(1, count + 1):
            observation = record_observation(self.db, source_ref=f"darknet:{prefix}-{index}",
                                             raw_text=f"{prefix} {index} detail", now=T1 + index)
            findings.append({"source_ref": f"darknet:{prefix}-{index}",
                             "evidence_ref": observation["observation_id"],
                             "observation_ref": observation["observation_id"],
                             "summary": f"{prefix} {index} observed"})
        return commit_result_set(self.db, investigation_ref=str(investigation), findings=findings,
                                 now=T1)

    def route(self, phrase, *, actor="operator:operator"):
        return self.router.classify_referential(phrase, db_path=self.db, actor=actor)

    # ------------------------------------------------------------------ the mandatory interaction
    def test_mandatory_end_to_end_conversational_interaction(self):
        committed = self.run_alert_sweep(20)
        announcement = announce(self.db, result_set_id=committed["result_set_id"],
                                statement="Sir, I found twenty alerts.", actor="operator:operator",
                                now=T1 + 50)
        self.assertEqual(announcement["status"], ANNOUNCED)
        self.assertEqual(announcement["verified_count"], 20)
        digest_before = referential_digest(self.db)
        sets_before = len(result_sets(self.db))

        # "Show me the twenty alerts."
        kind, payload = self.route("Show me the twenty alerts")
        self.assertEqual(kind, "RETRIEVAL")
        self.assertEqual(payload["kind"], "RETRIEVAL_RESULT_SET")
        self.assertEqual(payload["count"], 20)
        self.assertFalse(payload["scanned_again"])

        # "Explain number seven."
        kind, payload = self.route("Explain number seven")
        self.assertEqual(kind, "RETRIEVAL")
        self.assertEqual(payload["kind"], "RETRIEVAL_ORDINAL")
        self.assertEqual(payload["ordinal"], 7)
        original_id = payload["finding"]["finding_id"]
        original_evidence = payload["finding"]["evidence_ref"]

        # NOTHING was scanned: no new result set, and the durable state is byte-identical.
        self.assertEqual(len(result_sets(self.db)), sets_before,
                         "a retrieval created a result set, which means it scanned")
        self.assertEqual(referential_digest(self.db), digest_before,
                         "a retrieval changed the durable state, which means it did something")

        # Restart the conversational runtime and ask again.
        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from intent_router import IntentRouter;"
                "router = IntentRouter();"
                "kind, payload = router.classify_referential('What happened with that seventh "
                "alert?', db_path=%r, actor='operator:operator');"
                "print(json.dumps({'kind': kind, 'ordinal': payload.get('ordinal'), "
                "'finding_id': (payload.get('finding') or {}).get('finding_id'), "
                "'evidence': (payload.get('finding') or {}).get('evidence_ref')}, sort_keys=True))"
                % (str(pathlib.Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        after_restart = json.loads(out.stdout.strip())
        self.assertEqual(after_restart["kind"], "RETRIEVAL")
        self.assertEqual(after_restart["ordinal"], 7)
        self.assertEqual(after_restart["finding_id"], original_id,
                         "the seventh finding must be the same finding after a restart")
        self.assertEqual(after_restart["evidence"], original_evidence)

    def test_a_retrieval_asks_nothing_of_the_scanner(self):
        """The router must not be able to satisfy a retrieval by running the tool."""
        committed = self.run_alert_sweep(20)
        announce(self.db, result_set_id=committed["result_set_id"],
                 statement="Sir, I found twenty alerts.", actor="operator:operator", now=T1 + 50)
        source = pathlib.Path("intent_router.py").read_text(encoding="utf-8")
        body = source[source.index("def classify_referential"):source.index("def classify(self")]
        self.assertNotIn("/darknet-report", body, "the retrieval hook routes back to a rescan")
        self.assertIn("resolve_conversational_reference", body)

    def test_nothing_stored_is_reported_rather_than_scanned(self):
        kind, payload = self.route("Show me the twenty alerts")
        self.assertEqual(kind, "CONSULT")
        self.assertTrue(payload["no_stored_result_set"])
        self.assertIn("new scan would be a NEW result set", payload["note"])
        self.assertEqual(result_sets(self.db), [], "a retrieval attempt created a result set")


class IdentityCorrectnessTest(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-100b-")
        self.db = str(pathlib.Path(self.temp.name) / "vault.db")

    def tearDown(self):
        self.temp.cleanup()

    def _findings(self, count=20, *, prefix="A"):
        findings = []
        for index in range(1, count + 1):
            observation = record_observation(self.db, source_ref=f"s:{prefix}-{index}",
                                             raw_text=f"{prefix} {index}", now=T1 + index)
            findings.append({"source_ref": f"s:{prefix}-{index}",
                             "evidence_ref": observation["observation_id"],
                             "summary": f"{prefix} {index}"})
        return findings

    def sweep(self, count=20, *, investigation="CP-1", prefix="A", findings=None):
        if findings is None:
            findings = self._findings(count, prefix=prefix)
        return commit_result_set(self.db, investigation_ref=investigation, findings=findings, now=T1)

    def test_one_retry_of_one_investigation_is_one_result_set(self):
        # A RETRY re-commits the SAME findings - the same evidence references - because a retry is the
        # identical operation repeated, NOT a fresh reception of the world. A genuine re-scan mints new
        # observations and therefore a NEW result set (see record_new_scan); the two must not be confused,
        # and that distinction is the whole reason identity is content-derived rather than chosen.
        findings = self._findings(20)
        first = self.sweep(20, findings=findings)
        retry = self.sweep(20, findings=findings)
        self.assertEqual(first["result_set_id"], retry["result_set_id"])
        self.assertTrue(retry["idempotent"])
        self.assertEqual(retry["revision"], 1)
        self.assertEqual(len(result_sets(self.db)), 1)

    def test_distinct_investigations_keep_distinct_identities(self):
        first = self.sweep(20, investigation="CP-A")
        second = self.sweep(20, investigation="CP-B")
        self.assertNotEqual(first["result_set_id"], second["result_set_id"])
        self.assertEqual(len(result_sets(self.db)), 2)

    def test_a_revision_keeps_identity_and_appends(self):
        committed = self.sweep(20)
        added = revise_result_set(self.db, committed["result_set_id"],
                                  findings=[{"source_ref": "s:late", "evidence_ref": "OBS-LATE",
                                             "summary": "late finding"}],
                                  note="one more", actor="operator:operator", now=T1 + 500)
        self.assertEqual(added["result_set_id"], committed["result_set_id"])
        self.assertEqual(added["revision"], 2)
        self.assertEqual(added["added"], 1)
        self.assertEqual(added["count"], 21)
        self.assertEqual(retrieve_nth(self.db, committed["result_set_id"], 7,
                                      actor="operator:operator")["finding"]["ordinal"], 7)

    def test_an_announcement_keeps_its_own_historical_revision(self):
        committed = self.sweep(20)
        announcement = announce(self.db, result_set_id=committed["result_set_id"],
                                statement="Sir, I found twenty alerts.", actor="operator:operator",
                                now=T1 + 50)
        revise_result_set(self.db, committed["result_set_id"],
                          findings=[{"source_ref": "s:extra", "evidence_ref": "OBS-EXTRA",
                                     "summary": "extra"}], note="later", actor="operator:operator",
                          now=T1 + 600)
        from ciph.kernel.referential_continuity import announcement_snapshot
        snapshot = announcement_snapshot(self.db, announcement["announcement_id"], actor="operator:operator")
        self.assertEqual(snapshot["revision"], 1)
        self.assertEqual(snapshot["count"], 20)

    def test_unauthorized_retrieval_is_refused(self):
        findings = [{"source_ref": "s:secret-1", "evidence_ref": "OBS-SECRET", "summary": "classified"}]
        committed = commit_result_set(self.db, investigation_ref="CP-SECRET", findings=findings,
                                      classification="OPERATOR_ONLY", now=T1)
        with self.assertRaises(CrucibleError):
            retrieve_result_set(self.db, committed["result_set_id"])
        with self.assertRaises(CrucibleError):
            resolve_conversational_reference(self.db, "show me the findings")

    def test_missing_evidence_is_reported_not_replaced(self):
        committed = self.sweep(20)
        seventh = retrieve_nth(self.db, committed["result_set_id"], 7,
                               actor="operator:operator")["finding"]
        mark_finding_unavailable(self.db, seventh["finding_id"], availability=EXPIRED,
                                 reason="retention window closed", now=T1 + 700)
        answer = resolve_conversational_reference(self.db, "show me the twenty alerts",
                                                  actor="operator:operator")
        self.assertTrue(answer["answered_from_evidence"])
        self.assertEqual(answer["count"], 20)
        self.assertEqual(answer["unavailable"], [{"finding_id": seventh["finding_id"],
                                                  "availability": EXPIRED}])
        self.assertFalse(answer["scanned_again"])
        # An ordinal that does not exist is refused BY NAME, and still nothing is scanned.
        missing = resolve_conversational_reference(self.db, "explain number 999", actor="operator:operator")
        self.assertFalse(missing["answered_from_evidence"])
        self.assertEqual(missing["reason"], "ORDINAL_OUT_OF_RANGE")
        self.assertFalse(missing.get("scanned_again", False))


FAKE_FEED = ("<?xml version=\"1.0\"?><rss version=\"2.0\"><channel><title>fake</title>"
             + "".join(
                 "<item><title>CVE-2025-%04d zero-day actively exploited bug bounty #%d</title>"
                 "<link>https://example.invalid/%d</link>"
                 "<description>rce unauthenticated ransomware bug bounty program</description></item>"
                 % (1000 + index, index, index)
                 for index in range(1, 16))
             + "</channel></rss>")


class RealScanEntryPointTest(unittest.TestCase):
    """
    The producer here is the REAL `DarknetMonitor.full_scan`, driven through its real orchestration: Tor
    verification, feed scoring, the tally, the alert sync and the durable 10.0 commit are all production
    code. Only the NETWORK BOUNDARY is stubbed (`verify_tor` + `_tor_get`), because this environment has
    no egress - and the specimen then proves the retrieval does NOT go back through that boundary.

    This is the actual supported entry point for "the twenty alerts": the darknet sweep that R14 found was
    producing findings as an in-memory list with nothing durable to point at.
    """

    def setUp(self):
        import darknet_monitor
        from cipher_vault import CipherVault
        self.temp = tempfile.TemporaryDirectory(prefix="ciph-100c-")
        base = pathlib.Path(self.temp.name)
        self.db = str(base / "vault.db")
        self.vault = CipherVault(db_path=self.db, key_file=str(base / "v.key"),
                                 salt_file=str(base / "v.salt"))
        self.module = darknet_monitor
        self.monitor = darknet_monitor.DarknetMonitor(self.vault)
        self.calls = []
        monitor, calls = self.monitor, self.calls

        def fake_tor_get(url, timeout=20):
            calls.append(url)
            return types.SimpleNamespace(text=FAKE_FEED, status_code=200, json=lambda: [])
        monitor.verify_tor = lambda: {"tor_active": True, "exit_ip": "198.51.100.7", "status": "LIVE"}
        monitor._tor_get = fake_tor_get
        self._real_sleep = darknet_monitor.time.sleep
        darknet_monitor.time.sleep = lambda *a, **k: None
        self.router = IntentRouter()

    def tearDown(self):
        self.module.time.sleep = self._real_sleep
        self.temp.cleanup()

    def test_a_real_scan_commits_durable_identity_and_retrieval_never_rescans(self):
        results = self.monitor.full_scan()
        self.assertNotIn("error", results)
        expected = results["total_alerts"]
        self.assertGreaterEqual(expected, 20, "the stubbed feed must exercise a real multi-finding scan")
        self.assertEqual(len(self.monitor.alerts), expected)

        committed = results.get("result_set")
        self.assertIsInstance(committed, dict)
        self.assertEqual(committed["count"], expected)

        scans_before = len(self.calls)
        from ciph.kernel.referential_continuity import result_sets
        sets_before = len(result_sets(self.db))

        kind, payload = self.router.classify_referential("Show me the alerts", db_path=self.db,
                                                         actor="operator:operator")
        self.assertEqual(kind, "RETRIEVAL")
        self.assertEqual(payload["result_set_id"], committed["result_set_id"])
        self.assertEqual(payload["count"], expected)
        self.assertFalse(payload["scanned_again"])
        # THE PROOF: answering the question did not touch the network boundary again, and did not mint a
        # fresh result set. A re-scan would move both numbers.
        self.assertEqual(len(self.calls), scans_before, "retrieval re-ran the scan")
        self.assertEqual(len(result_sets(self.db)), sets_before, "retrieval created a new result set")

        # The conversational rendering is the production formatter, not a test double.
        from ciph_core import CiphCore
        rendered = CiphCore._format_referential_answer(payload)
        self.assertIn(str(expected), rendered)
        self.assertIn("nothing was rescanned", rendered.lower())

        # An ordinal resolves to one durable identity and stays that identity across a real restart.
        kind, ordinal_payload = self.router.classify_referential("Explain number seven", db_path=self.db,
                                                                 actor="operator:operator")
        self.assertEqual(kind, "RETRIEVAL")
        self.assertEqual(ordinal_payload["ordinal"], 7)
        seventh = ordinal_payload["finding"]["finding_id"]

        code = ("import sys,json;sys.path.insert(0, %r);sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));sys.path.insert(1,sys.path[0]+chr(47)+chr(116)+chr(101)+chr(115)+chr(116)+chr(115));"
                "from intent_router import IntentRouter;"
                "kind, payload = IntentRouter().classify_referential('What happened with that "
                "seventh alert?', db_path=%r, actor='operator:operator');"
                "print(json.dumps({'kind': kind, 'finding': (payload.get('finding') or {})"
                ".get('finding_id')}))" % (str(pathlib.Path(__file__).resolve().parents[1]), self.db))
        out = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                             cwd=str(pathlib.Path(__file__).resolve().parents[1]), timeout=180)
        self.assertEqual(out.returncode, 0, out.stderr)
        after = json.loads(out.stdout.strip())
        self.assertEqual(after["kind"], "RETRIEVAL")
        self.assertEqual(after["finding"], seventh, "the seventh finding must survive a restart")
        self.assertEqual(len(self.calls), scans_before, "the restart retrieval re-ran the scan")


if __name__ == "__main__":
    unittest.main()
