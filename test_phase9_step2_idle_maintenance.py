"""
test_phase9_step2_idle_maintenance.py - Phase 9 Step 2 Adversarial Verification Suite.
Validates the Shared Exclusion Protocol, Idle Maintenance Engine, Ed25519 OPERATOR
authority, bidirectional canary exclusion, authorizer-level write blocking, reader freedom,
scavenger reuse, non-destruction of raw evidence, and crash/abort resilience.
"""

import os
import sys
import time
import json
import uuid
import shutil
import sqlite3
import tempfile
import unittest
import subprocess

from ciph.kernel.crypto_identity import Ed25519KeyManager, KeyRole, TrustRegistry
from ciph.maintenance.exclusion import (
    SharedExclusionCoordinator,
    ExcludedConnection,
    MaintenanceInProgressError,
    check_write_exclusion,
)
from ciph.maintenance.engine import (
    IdleDetector,
    IdleMaintenanceEngine,
)
from ciph.memory.event_store import EventStore
from ciph.memory.claim_leases import ClaimLeaseManager
from ciph.workers.ipc_queue import IPCJobQueue
from ciph.evolution.canary_manager import CanaryDeploymentManager


class TestPhase9Step2IdleMaintenance(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ciph_step2_test_")
        self.db_path = os.path.join(self.test_dir, "test_vault.db")

        # Initialize crypto identities
        self.op_priv, self.op_pub = Ed25519KeyManager.generate_keypair()
        self.op_key_id = "operator_primary"
        self.trust_registry = TrustRegistry(self.db_path, pinned_operator_pub_hex=self.op_pub.hex())
        self.trust_registry.register_key(self.op_key_id, KeyRole.OPERATOR, self.op_pub.hex())

        self.worker_priv, self.worker_pub = Ed25519KeyManager.generate_keypair()
        self.worker_key_id = "worker_node_1"
        payload_w1 = f"REGISTER_KEY:{self.worker_key_id}:{KeyRole.WORKER.value}:{self.worker_pub.hex()}:{None}".encode("utf-8")
        sig_w1 = Ed25519KeyManager.sign(self.op_priv, payload_w1)
        self.trust_registry.register_key(self.worker_key_id, KeyRole.WORKER, self.worker_pub.hex(), operator_signature=sig_w1)

        self.wp_priv, self.wp_pub = Ed25519KeyManager.generate_keypair()
        payload_wp = f"REGISTER_KEY:worker_primary:{KeyRole.WORKER.value}:{self.wp_pub.hex()}:{None}".encode("utf-8")
        sig_wp = Ed25519KeyManager.sign(self.op_priv, payload_wp)
        self.trust_registry.register_key("worker_primary", KeyRole.WORKER, self.wp_pub.hex(), operator_signature=sig_wp)

        self.coordinator = SharedExclusionCoordinator(self.db_path, trust_registry=self.trust_registry)

    def tearDown(self):
        SharedExclusionCoordinator._active_leases.clear()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Probe 1: Schema Migration Idempotency Probe
    # -------------------------------------------------------------------------
    def test_probe1_schema_migration_idempotency(self):
        """Legacy 4-column ciph_maintenance_leases migrates cleanly to 8 columns without data loss."""
        legacy_db = os.path.join(self.test_dir, "legacy.db")
        with sqlite3.connect(legacy_db) as conn:
            conn.execute("""
                CREATE TABLE ciph_maintenance_leases (
                    lease_name TEXT PRIMARY KEY,
                    holder_id TEXT NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
            """)
            conn.execute("""
                INSERT INTO ciph_maintenance_leases VALUES ('global_db_maintenance', 'old_holder', 1000.0, 2000.0);
            """)
            conn.commit()

        # Initialize coordinator on legacy database
        coord = SharedExclusionCoordinator(legacy_db)
        with sqlite3.connect(legacy_db) as conn:
            cur = conn.execute("PRAGMA table_info(ciph_maintenance_leases);")
            cols = {row[1] for row in cur.fetchall()}
            expected_cols = {"lease_name", "holder_id", "acquired_at", "expires_at", "cycle_id", "task_name", "heartbeat_at", "holder_signature"}
            self.assertTrue(expected_cols.issubset(cols), f"Missing columns: {expected_cols - cols}")

            # Verify existing record was preserved
            cur = conn.execute("SELECT holder_id, expires_at, cycle_id, task_name FROM ciph_maintenance_leases WHERE lease_name='global_db_maintenance';")
            row = cur.fetchone()
            self.assertEqual(row[0], "old_holder")
            self.assertEqual(row[1], 2000.0)
            self.assertEqual(row[2], "")
            self.assertEqual(row[3], "INIT")

    # -------------------------------------------------------------------------
    # Probe 2: Authority Model & Role Enforcement Probe
    # -------------------------------------------------------------------------
    def test_probe2_role_authority_rejection(self):
        """Only authenticated OPERATOR keys can acquire leases; WORKER or unenrolled keys fail closed."""
        # 1. Attempt acquisition with WORKER key -> PermissionError(MAINTENANCE_UNAUTHORIZED_ROLE)
        with self.assertRaises(PermissionError) as ctx:
            self.coordinator.acquire_lease(
                holder_id=self.worker_key_id,
                operator_secret_key=self.worker_priv,
                bypass_idle_checks=True
            )
        self.assertIn("MAINTENANCE_UNAUTHORIZED_ROLE", str(ctx.exception))

        # 2. Attempt acquisition with unenrolled key -> PermissionError(MAINTENANCE_UNENROLLED_KEY)
        fake_priv, _ = Ed25519KeyManager.generate_keypair()
        with self.assertRaises(PermissionError) as ctx:
            self.coordinator.acquire_lease(
                holder_id="unregistered_rogue_id",
                operator_secret_key=fake_priv,
                bypass_idle_checks=True
            )
        self.assertIn("MAINTENANCE_UNENROLLED_KEY", str(ctx.exception))

        # 3. Valid OPERATOR key -> SUCCESS
        acquired, status, cid = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            bypass_idle_checks=True
        )
        self.assertTrue(acquired)
        self.assertEqual(status, "ACQUIRED")
        self.assertIsNotNone(cid)

    # -------------------------------------------------------------------------
    # Probe 3: Canary In-Flight Bi-Directional Blocker Probe
    # -------------------------------------------------------------------------
    def test_probe3_canary_bidirectional_exclusion(self):
        """Active canary in_flight blocks maintenance; active maintenance blocks canary activation/execution."""
        # Setup canary state table using canonical evidence_hash column
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_phase8_canary_state (
                    canary_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL
                );
            """)
            # Active in-flight canary
            conn.execute("""
                INSERT INTO ciph_phase8_canary_state VALUES ('CANARY-1', json_object('in_flight', 'RUN-12345'), 'evidence_hash_123');
            """)
            conn.commit()

        # Maintenance acquisition MUST be refused
        acquired, reason, _ = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            bypass_idle_checks=False
        )
        self.assertFalse(acquired)
        self.assertEqual(reason, "CANARY_IN_FLIGHT")

        # Now clear canary in_flight
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE ciph_phase8_canary_state SET payload = json_object('in_flight', null) WHERE canary_id = 'CANARY-1';")
            conn.commit()

        # Instantiate CanaryDeploymentManager before acquiring maintenance lease
        cm = CanaryDeploymentManager(db_path=self.db_path, trust_registry=self.trust_registry)

        # Acquire maintenance lease
        acquired, reason, cid = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            bypass_idle_checks=True
        )
        self.assertTrue(acquired)

        # While maintenance is active: CanaryDeploymentManager.activate_canary and execute_canary MUST fail closed
        with self.assertRaises(MaintenanceInProgressError):
            cm.activate_canary(None, "dummy_staging_id")

        with self.assertRaises(MaintenanceInProgressError):
            cm.execute_canary("CANARY-1", {})

        # Release lease
        self.coordinator.release_lease(holder_id=self.op_key_id, cycle_id=cid)

    # -------------------------------------------------------------------------
    # Probe 4: Curiosity Searching Blocker Probe
    # -------------------------------------------------------------------------
    def test_probe4_curiosity_searching_blocker(self):
        """Active SEARCHING question or RESERVED attempt blocks maintenance acquisition."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_curiosity_questions (
                    question_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
            """)
            conn.execute("""
                INSERT INTO ciph_curiosity_questions VALUES ('Q-1', json_object('status', 'SEARCHING'));
            """)
            conn.commit()

        # Blocked by searching curiosity
        acquired, reason, _ = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            bypass_idle_checks=False
        )
        self.assertFalse(acquired)
        self.assertEqual(reason, "CURIOSITY_ACTIVE")

        # Resolve question and add reserved attempt
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE ciph_curiosity_questions SET payload = json_object('status', 'ANSWERED');")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_curiosity_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
            """)
            conn.execute("""
                INSERT INTO ciph_curiosity_attempts VALUES ('ATT-1', json_object('status', 'RESERVED'));
            """)
            conn.commit()

        # Blocked by reserved attempt
        acquired, reason, _ = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            bypass_idle_checks=False
        )
        self.assertFalse(acquired)
        self.assertEqual(reason, "CURIOSITY_RESERVED")

    # -------------------------------------------------------------------------
    # Probe 5: Idle-to-Acquire CAS Race Probe
    # -------------------------------------------------------------------------
    def test_probe5_idle_to_acquire_cas_race(self):
        """Concurrently enqueued jobs or active work detected inside the BEGIN IMMEDIATE transaction reject lease."""
        ipc = IPCJobQueue(self.db_path, trust_registry=self.trust_registry)
        ipc.enqueue_job("TEST_CAP", {"arg": 1})

        # Lease acquisition must detect active job inside transaction and rollback
        acquired, reason, _ = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            bypass_idle_checks=False
        )
        self.assertFalse(acquired)
        self.assertEqual(reason, "ACTIVE_WORK_IN_PROGRESS")

    # -------------------------------------------------------------------------
    # Probe 6: Write-Only Interception & Reader Freedom Probe (Cross-Process Verified)
    # -------------------------------------------------------------------------
    def test_probe6_write_only_interception_and_reader_freedom(self):
        """Readers execute normally during maintenance; unauthorized writes fail closed across in-proc and cross-proc."""
        es = EventStore(self.db_path)
        # Pre-populate an event
        es.append_event("SetupEvent", "agg-1", {"v": 100})

        # Acquire exclusive lease
        acquired, _, cid = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            bypass_idle_checks=True
        )
        self.assertTrue(acquired)

        # 1. Readers are NOT blocked: SELECT executes cleanly!
        events = es.get_events(aggregate_id="agg-1")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["v"], 100)

        # 2. Worker / unauthorized write connections are blocked in-process:
        worker_conn = ExcludedConnection(sqlite3.connect(self.db_path), calling_holder_id=self.worker_key_id, db_path=self.db_path)

        # 2a. execute("INSERT ...") fails closed
        with self.assertRaises((sqlite3.OperationalError, sqlite3.DatabaseError)):
            worker_conn.execute("INSERT INTO ciph_event_store (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash) VALUES ('X', 'Y', '{}', 0, '', '');")

        # 2b. executemany fails closed
        with self.assertRaises((sqlite3.OperationalError, sqlite3.DatabaseError)):
            worker_conn.executemany("INSERT INTO ciph_event_store (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?);", [('X', 'Y', '{}', 0, '', '')])

        # 2c. cursor().execute fails closed
        cur = worker_conn.cursor()
        with self.assertRaises((sqlite3.OperationalError, sqlite3.DatabaseError)):
            cur.execute("UPDATE ciph_event_store SET aggregate_id='hacked';")

        # 2d. executescript fails closed
        with self.assertRaises((sqlite3.OperationalError, sqlite3.DatabaseError)):
            worker_conn.executescript("DELETE FROM ciph_event_store;")

        # 2e. PRAGMA wal_checkpoint fails closed
        with self.assertRaises((sqlite3.OperationalError, sqlite3.DatabaseError)):
            worker_conn.execute("PRAGMA wal_checkpoint(PASSIVE);")

        # 2f. IPC enqueue fails closed with MaintenanceInProgressError
        ipc = IPCJobQueue(self.db_path, trust_registry=self.trust_registry)
        with self.assertRaises(MaintenanceInProgressError):
            ipc.enqueue_job("TEST_CAP", {"arg": 2})

        # 2g. Cross-process write attempt fails closed
        ext_script = f"""
import sys
import sqlite3
from ciph.maintenance.exclusion import ExcludedConnection

conn = sqlite3.connect({repr(self.db_path)})
ex_conn = ExcludedConnection(conn, calling_holder_id="external_worker_process", db_path={repr(self.db_path)})
try:
    ex_conn.execute("INSERT INTO ciph_event_store (event_type, aggregate_id, payload, timestamp, previous_hash, event_hash) VALUES ('CrossProc', 'agg-cp', '{{}}', 0, '', '');")
    sys.exit(0)
except Exception:
    sys.exit(42)
"""
        ciph_dir = os.path.dirname(os.path.abspath(__file__))
        env = {**os.environ, "PYTHONPATH": ciph_dir}
        proc = subprocess.run([sys.executable, "-c", ext_script], capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 42, f"External process succeeded writing during maintenance: stdout={proc.stdout} stderr={proc.stderr}")

        # Release lease
        self.coordinator.release_lease(holder_id=self.op_key_id, cycle_id=cid)

    # -------------------------------------------------------------------------
    # Probe 7: Engine Holder Exemption Probe
    # -------------------------------------------------------------------------
    def test_probe7_engine_holder_exemption(self):
        """The maintenance holder is exempt and successfully appends lifecycle events during maintenance."""
        acquired, _, cid = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            bypass_idle_checks=True
        )
        self.assertTrue(acquired)

        es = EventStore(self.db_path)
        # Holder connection appends event without error
        ev_id = es.append_event(
            event_type="MaintenanceCycleStartedEvent",
            aggregate_id=f"maintenance:{cid}",
            payload={"cycle_id": cid, "holder": self.op_key_id},
            calling_holder_id=self.op_key_id
        )
        self.assertGreater(ev_id, 0)

        events = es.get_events(aggregate_id=f"maintenance:{cid}")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "MaintenanceCycleStartedEvent")

        self.coordinator.release_lease(holder_id=self.op_key_id, cycle_id=cid)

    # -------------------------------------------------------------------------
    # Probe 8: Crash Recovery & TTL Expiry Probe
    # -------------------------------------------------------------------------
    def test_probe8_crash_recovery_ttl_expiry(self):
        """A lease whose holder crashed expires automatically by TTL; queue resumes cleanly."""
        # Acquire lease with 1 second TTL
        acquired, _, cid = self.coordinator.acquire_lease(
            holder_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            ttl_seconds=1,
            bypass_idle_checks=True
        )
        self.assertTrue(acquired)

        ipc = IPCJobQueue(self.db_path, trust_registry=self.trust_registry)
        # Immediately blocked
        with self.assertRaises(MaintenanceInProgressError):
            ipc.enqueue_job("CAP_1", {"x": 1})

        # Wait for TTL to elapse (simulating process crash without explicit release)
        time.sleep(1.2)

        # Enqueue must now succeed cleanly
        jid = ipc.enqueue_job("CAP_1", {"x": 1})
        self.assertIsNotNone(jid)
        self.assertTrue(jid.startswith("JOB-"))

    # -------------------------------------------------------------------------
    # Probe 9: Full Cycle Verification of Spec Tasks 1-6
    # -------------------------------------------------------------------------
    def test_probe9_full_maintenance_cycle_scavenger_and_verifier(self):
        """Full cycle executes exact spec Tasks 1-6, transitions stale claims, compiles ledger, and audits AST."""
        # 1. Setup events in EventStore
        es = EventStore(self.db_path)
        for i in range(5):
            es.append_event("EventA", f"agg-{i}", {"index": i})

        # 2. Setup expired claim lease
        clm = ClaimLeaseManager(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO ciph_claim_leases (lease_id, claim_id, worker_id, job_id, acquired_at, expires_at)
                VALUES ('lease_exp', 'claim_1', 'w1', 'j1', 100.0, 200.0);
            """)
            conn.commit()

        # 3. Setup expired IPC job lease
        ipc = IPCJobQueue(self.db_path, trust_registry=self.trust_registry)
        jid = ipc.enqueue_job("TASK_TEST", {"p": 1})
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE ciph_ipc_jobs SET status='LEASED', leased_to='w1', lease_expires_at=100.0 WHERE job_id=?;", (jid,))
            conn.commit()

        # 4. Setup stale claim in ciph_active_claims
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_active_claims (
                    claim_id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    value TEXT NOT NULL,
                    condition TEXT,
                    state TEXT NOT NULL,
                    reliability TEXT NOT NULL,
                    assurance_score REAL NOT NULL,
                    evidence_receipt_ids TEXT NOT NULL,
                    observation_ids TEXT DEFAULT '[]',
                    parent_claim_ids TEXT NOT NULL,
                    superseded_by TEXT,
                    freshness_deadline REAL,
                    valid_from REAL,
                    valid_until REAL,
                    predicate_class TEXT,
                    normalized_context_hash TEXT,
                    verifier_provenance TEXT,
                    migration_status TEXT NOT NULL DEFAULT 'CANONICAL',
                    lifecycle_state TEXT NOT NULL DEFAULT 'ACTIVE',
                    decay_profile TEXT DEFAULT 'SOFTWARE_BEHAVIOR',
                    invalidation_barrier INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)
            conn.execute("""
                INSERT INTO ciph_active_claims (
                    claim_id, subject, predicate, value, state, reliability, assurance_score,
                    evidence_receipt_ids, parent_claim_ids, freshness_deadline, created_at, updated_at
                ) VALUES (
                    'claim_stale_exp_1', 'system.metric', 'load', 'high', 'SUPPORTED', 'DIRECT_SENSOR', 0.95,
                    '[]', '[]', 50.0, 10.0, 10.0
                );
            """)
            conn.commit()

        # 5. Instantiate Engine and Run Cycle
        engine = IdleMaintenanceEngine(
            db_path=self.db_path,
            trust_registry=self.trust_registry,
            operator_key_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            quiescence_window_seconds=0.01,
            lease_ttl_seconds=30
        )

        time.sleep(0.05)
        res = engine.run_cycle(bypass_idle_checks=False)
        self.assertTrue(res["success"], f"Cycle failed: {res}")
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(len(res["task_results"]), 6)

        # Task 1 (Integrity): Chain valid
        t1 = next(t for t in res["task_results"] if t["task_name"] == "TASK1_EVENT_INTEGRITY")
        self.assertTrue(t1["metrics"]["chain_valid"])

        # Task 2 (Hardened Scavenger): Reclaimed job and claim leases
        t2 = next(t for t in res["task_results"] if t["task_name"] == "TASK2_HARDENED_SCAVENGER")
        self.assertEqual(t2["metrics"]["reclaimed_job_leases"], 1)
        self.assertEqual(t2["metrics"]["reclaimed_claim_leases"], 1)

        # Task 3 (Safe DB Maintenance): WAL PASSIVE and optimize
        t3 = next(t for t in res["task_results"] if t["task_name"] == "TASK3_SAFE_DB_MAINTENANCE")
        self.assertEqual(t3["metrics"]["mode"], "PASSIVE")
        self.assertTrue(t3["metrics"]["optimized"])

        # Task 4 (Ledger Cache Compilation): Compiled empirical ledger
        t4 = next(t for t in res["task_results"] if t["task_name"] == "TASK4_LEDGER_CACHE_COMPILATION")
        self.assertIn(t4["metrics"]["verification_status"], ("VERIFIED_COMPLETE", "VERIFIED_EMPTY"))
        self.assertIsNotNone(engine.compiled_ledger_cache)

        # Task 5 (Stale Hypothesis Expiry): Transitioned expired claim to STALE
        t5 = next(t for t in res["task_results"] if t["task_name"] == "TASK5_STALE_HYPOTHESIS_EXPIRY")
        self.assertEqual(t5["metrics"]["stale_claims_transitioned"], 1)
        with sqlite3.connect(self.db_path) as conn:
            claim_state = conn.execute("SELECT state FROM ciph_active_claims WHERE claim_id='claim_stale_exp_1';").fetchone()[0]
            self.assertEqual(claim_state, "STALE")

        # Task 6 (Static AST Audit): Audited capability code safety
        t6 = next(t for t in res["task_results"] if t["task_name"] == "TASK6_STATIC_AST_AUDIT")
        self.assertTrue(t6["metrics"]["safety_passed"])
        self.assertGreater(t6["metrics"]["capabilities_audited"], 0)

        # Verify lifecycle events were recorded in EventStore
        cycle_id = res["cycle_id"]
        started_ev = es.get_events(aggregate_id=f"maintenance:{cycle_id}", event_type="MaintenanceCycleStartedEvent")
        self.assertEqual(len(started_ev), 1)

        completed_ev = es.get_events(aggregate_id=f"maintenance:{cycle_id}", event_type="MaintenanceCycleCompletedEvent")
        self.assertEqual(len(completed_ev), 1)

        task_evs = es.get_events(event_type="MaintenanceTaskExecutedEvent")
        self.assertEqual(len(task_evs), 6)

        # Verify lease was cleanly released
        self.assertIsNone(self.coordinator.get_active_lease())

    # -------------------------------------------------------------------------
    # Probe 10: Non-Destruction of Raw Evidence Probe
    # -------------------------------------------------------------------------
    def test_probe10_maintenance_never_erases_raw_evidence(self):
        """Maintenance strictly preserves ciph_consumed_tokens and ciph_authorization_grants."""
        old_time = time.time() - (30 * 86400.0)  # 30 days old
        ipc = IPCJobQueue(self.db_path, trust_registry=self.trust_registry)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO ciph_consumed_tokens (token_id, nonce, job_id, worker_id, consumed_at)
                VALUES ('tok_historical_1', 'nonce_hist_1', 'job_h1', 'w1', ?);
            """, (old_time,))
            conn.execute("""
                INSERT INTO ciph_authorization_grants (grant_id, plan_hash, step_id, capability, params_hash, signature, expires_at, created_at)
                VALUES ('grant_hist_1', 'phash', 'step1', 'cap1', 'params', 'sig', ?, ?);
            """, (old_time, old_time))
            conn.commit()

        # Run maintenance cycle
        engine = IdleMaintenanceEngine(
            db_path=self.db_path,
            trust_registry=self.trust_registry,
            operator_key_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            quiescence_window_seconds=0.01,
            lease_ttl_seconds=30
        )
        res = engine.run_cycle(bypass_idle_checks=True)
        self.assertTrue(res["success"], f"Cycle failed: {res}")

        # Assert raw evidence was NOT deleted
        with sqlite3.connect(self.db_path) as conn:
            tok_count = conn.execute("SELECT COUNT(*) FROM ciph_consumed_tokens WHERE token_id='tok_historical_1';").fetchone()[0]
            grant_count = conn.execute("SELECT COUNT(*) FROM ciph_authorization_grants WHERE grant_id='grant_hist_1';").fetchone()[0]
            self.assertEqual(tok_count, 1, "ciph_consumed_tokens row was deleted! Raw evidence must never be erased.")
            self.assertEqual(grant_count, 1, "ciph_authorization_grants row was deleted! Raw evidence must never be erased.")

        # Assert CapabilityLedger compiles cleanly and retains access to consumed tokens
        from ciph.capabilities.capability_ledger import CapabilityLedger
        from ciph.capabilities.registry import CapabilityRegistry
        es = EventStore(self.db_path)
        ledger = CapabilityLedger(es, registry=CapabilityRegistry(), trust_registry=self.trust_registry, db_path=self.db_path)
        profiles, cp = ledger.compile_empirical_ledger()
        self.assertIn(cp.verification_status, ("VERIFIED_COMPLETE", "VERIFIED_EMPTY"))

    # -------------------------------------------------------------------------
    # Probe 11: Heartbeat Failure & Lease Loss Mid-Cycle Abort & Recovery Probe
    # -------------------------------------------------------------------------
    def test_probe11_heartbeat_failure_or_lease_loss_aborts_cycle(self):
        """Heartbeat failure mid-cycle aborts with ABORTED_LEASE_LOST, and transient failure recovers on next cycle."""
        engine = IdleMaintenanceEngine(
            db_path=self.db_path,
            trust_registry=self.trust_registry,
            operator_key_id=self.op_key_id,
            operator_secret_key=self.op_priv,
            quiescence_window_seconds=0.01,
            lease_ttl_seconds=30,
            heartbeat_interval_seconds=0.01
        )

        # Cycle 1: Simulate heartbeat renewal failure mid-cycle
        orig_renew = engine.coordinator.renew_lease
        def failing_renew(*args, **kwargs):
            raise RuntimeError("Simulated transient network/DB failure during heartbeat renewal")
        engine.coordinator.renew_lease = failing_renew

        # Ensure heartbeat thread has time to fire during Task 1
        orig_task1 = engine._task1_event_integrity
        def slow_task1(cycle_id):
            time.sleep(0.04)
            return orig_task1(cycle_id)
        engine._task1_event_integrity = slow_task1

        res1 = engine.run_cycle(bypass_idle_checks=True)
        self.assertFalse(res1["success"])
        self.assertEqual(res1["status"], "ABORTED_LEASE_LOST")
        aborted_tasks = [t for t in res1["task_results"] if t.get("status") == "ABORTED_LEASE_LOST"]
        self.assertTrue(len(aborted_tasks) >= 1)

        # Cycle 2: Restore renew_lease and task 1; run again on same engine instance
        engine.coordinator.renew_lease = orig_renew
        engine._task1_event_integrity = orig_task1

        res2 = engine.run_cycle(bypass_idle_checks=True)
        self.assertTrue(res2["success"])
        self.assertEqual(res2["status"], "COMPLETED")
        self.assertEqual(len(res2["task_results"]), 6)
        self.assertFalse(engine._heartbeat_failed)

    # -------------------------------------------------------------------------
    # Probe 12: Missing TrustRegistry Fails Closed Probe
    # -------------------------------------------------------------------------
    def test_probe12_missing_trust_registry_fails_closed(self):
        """Coordinator without configured trust registry fails closed on lease acquisition with PermissionError."""
        coord_no_tr = SharedExclusionCoordinator(self.db_path, trust_registry=None)
        with self.assertRaises(PermissionError) as ctx:
            coord_no_tr.acquire_lease(
                holder_id=self.op_key_id,
                operator_secret_key=self.op_priv,
                bypass_idle_checks=True
            )
        self.assertIn("MAINTENANCE_TRUST_REGISTRY_REQUIRED", str(ctx.exception))

    # -------------------------------------------------------------------------
    # Probe 13: CiphRuntime Maintenance Wiring & Ledger Cache Compilation Probe
    # -------------------------------------------------------------------------
    def test_probe13_runtime_maintenance_wiring_and_ledger_compilation(self):
        """CiphRuntime executes idle maintenance, compiling empirical ledger cache with verified dependencies."""
        from ciph.runtime import CiphRuntime
        from ciph.kernel.policy_engine import CapabilityManifest, RiskTier, NetworkPolicy, ReversibilityClass, AuthorizationTier
        from ciph.capabilities.base import BaseCapability

        class SandboxedSuccessCap(BaseCapability):
            requires_sandbox = True
            @property
            def manifest(self):
                return CapabilityManifest(
                    name="test.sandbox.maint_success",
                    description="Sandbox maintenance test capability",
                    risk_tier=RiskTier.LOW,
                    network_policy=NetworkPolicy.OFFLINE_ONLY,
                    reversibility=ReversibilityClass.READ_ONLY,
                    authorization=AuthorizationTier.AUTO
                )
            def get_sandbox_command(self, params):
                return [sys.executable, "-c", "import json, sys; print(json.dumps({'result': 'ok'})); sys.exit(0)"]
            def run(self, params, context=None):
                raise AssertionError("Must run in sandbox")

        rt_db = os.path.join(self.test_dir, "runtime_test.db")
        rt = CiphRuntime(db_path=rt_db)
        try:
            cap = SandboxedSuccessCap()
            rt.register_capability(cap)
            params = {"test": 1}
            token = rt.mint_execution_token(cap.manifest.name, params, max_attempts=1)
            job = rt.queue.enqueue_job(cap.manifest.name, params, max_retries=1, execution_token=token, idempotency_key="rt-maint-idemp-1")
            receipt = rt.worker_daemon.drain_once(worker_id="worker_maint", target_job_id=job)
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt.exit_code, 0)
            self.assertTrue(receipt.verify(rt.trust_registry)[0])

            # Run idle maintenance via runtime wrapper
            res = rt.run_idle_maintenance(bypass_idle_checks=True)
            self.assertTrue(res["success"], f"Runtime maintenance failed: {res}")
            self.assertEqual(res["status"], "COMPLETED")
            self.assertEqual(len(res["task_results"]), 6)

            # Verify Task 4 compiled ledger cache
            cached = rt.get_cached_capability_ledger()
            self.assertIsNotNone(cached)
            profiles, checkpoint = cached
            self.assertIn(cap.manifest.name, profiles)
            p = profiles[cap.manifest.name]
            self.assertEqual(p.health_status.value, "VERIFIED_ACTIVE")
            self.assertEqual(p.current_version_clean_successes, 1)

            # Check task 4 metrics
            task4_res = [r for r in res["task_results"] if r["task_name"] == "TASK4_LEDGER_CACHE_COMPILATION"][0]
            self.assertFalse(task4_res["metrics"]["dependency_blind"])
            self.assertTrue(task4_res["metrics"]["dependency_evidence_count"] > 0)
            self.assertTrue(task4_res["metrics"]["verified_active_count"] >= 1)
        finally:
            rt.shutdown()


if __name__ == "__main__":
    unittest.main()

