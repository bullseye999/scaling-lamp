"""
test_phase5_epistemic_stage1.py - Comprehensive Verification for Stage 1:
Evidence Admission Rules & Observation Ingestion.

Validates the concrete acceptance boundary:
1. Authenticated committed evidence.
2. Evidence-bound predicates and context (Receipt != Truth).
3. Controlled observation provenance (ObservationIngestor).
4. Default rejection of unsupported predicates.
5. No caller-controlled verification authority.
6. Anchored freshness and anti-clock-resetting.
"""

import time
import unittest
from typing import Dict, Any

from ciph.contracts.epistemic import (
    Claim,
    ClaimProjector,
    Observation,
    ObservationIngestor,
    ContractValidationError,
)
from ciph.contracts.enums import (
    EpistemicState,
    LifecycleState,
    DecayProfile,
    ReliabilityClass,
    OutcomeCategory,
    NetworkPolicy,
)
from ciph.workers.receipts import ExecutionReceipt
from ciph.runtime import CiphRuntime
import tempfile, shutil, os


class TestPhase5EpistemicStage1(unittest.TestCase):
    """Rigorous acceptance tests for Stage 1 Epistemic Convergence."""

    def setUp(self):
        self._temp_dir = tempfile.mkdtemp()
        self._temp_db = os.path.join(self._temp_dir, "test_stage1_vault.db")
        self.runtime = CiphRuntime(db_path=self._temp_db)
        self.registry = self.runtime.trust_registry
        self.projector = self.runtime.claim_projector
        self._op_priv, self._op_pub = self.registry.get_keypair("operator_root")
        self._wrk_priv, self._wrk_pub = self.registry.get_keypair("worker_primary")

    def tearDown(self):
        self.runtime.close()
        if os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _sign_receipt(self, receipt: ExecutionReceipt) -> ExecutionReceipt:
        return receipt.sign(self._wrk_priv, worker_key_id="worker_primary")

    def test_predictive_capability_cannot_mint_verified_real(self):
        """sports.predict_match cannot assert VERIFIED_REAL even with valid signed successful receipt."""
        results = {"predicted_outcome": "Arsenal_wins", "probability": 0.78}
        rcpt = ExecutionReceipt(
            receipt_id="rcpt_pred_01",
            job_id="job_pred_01",
            capability="sports.predict_match",
            target="match_4401",
            started_at=100.0,
            completed_at=102.0,
            input_hash="inhash1",
            output_hash=ExecutionReceipt.hash_payload(results),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="idem1",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="DIRECT",
            worker_id="wrk_stage1",
            worker_key_id="wrk_stage1",
        )
        signed = self._sign_receipt(rcpt)

        # Direct verified real projection must fail closed
        with self.assertRaises(ContractValidationError) as ctx:
            self.projector.project_verified_real(signed, predicate="predicted_outcome")
        self.assertIn("CAPABILITY_CANNOT_MINT_VERIFIED_REAL", str(ctx.exception))

        # Consolidated project_claim must project as HYPOTHESIZED with bounded assurance
        claim = self.projector.project_claim(signed, predicate="predicted_outcome")
        self.assertEqual(claim.epistemic_state, EpistemicState.HYPOTHESIZED)
        self.assertLessEqual(claim.assurance_score, 0.60)
        self.assertEqual(claim.evidence_receipt_ids, ("rcpt_pred_01",))
        self.assertEqual(claim.value, "Arsenal_wins")

    def test_inferential_capability_cannot_mint_verified_real(self):
        """pentest.cvss_calculate cannot assert VERIFIED_REAL."""
        results = {"base_score": 7.5, "severity": "HIGH"}
        rcpt = ExecutionReceipt(
            receipt_id="rcpt_cvss_01",
            job_id="job_cvss_01",
            capability="pentest.cvss_calculate",
            target="CVE-2026-1001",
            started_at=100.0,
            completed_at=101.0,
            input_hash="inhash2",
            output_hash=ExecutionReceipt.hash_payload(results),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="idem2",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="NONE",
            worker_id="wrk_stage1",
            worker_key_id="wrk_stage1",
        )
        signed = self._sign_receipt(rcpt)

        with self.assertRaises(ContractValidationError) as ctx:
            self.projector.project_verified_real(signed, predicate="base_score")
        self.assertIn("CAPABILITY_CANNOT_MINT_VERIFIED_REAL", str(ctx.exception))

        claim = self.projector.project_claim(signed, predicate="base_score")
        self.assertEqual(claim.epistemic_state, EpistemicState.INFERRED)
        self.assertLessEqual(claim.assurance_score, 0.80)
        self.assertEqual(claim.value, 7.5)

    def test_portfolio_check_separates_balance_from_forecast(self):
        """trading.portfolio_check admits ledger balance as VERIFIED_REAL, but rejects forecast."""
        results = {
            "balance_usd": 50000.0,
            "forecast_yield": 0.12,
        }
        rcpt = ExecutionReceipt(
            receipt_id="rcpt_port_01",
            job_id="job_port_01",
            capability="trading.portfolio_check",
            target="portfolio_alpha",
            started_at=100.0,
            completed_at=103.0,
            input_hash="inhash3",
            output_hash=ExecutionReceipt.hash_payload(results),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="idem3",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="DIRECT",
            worker_id="wrk_stage1",
            worker_key_id="wrk_stage1",
        )
        signed = self._sign_receipt(rcpt)

        # Forecast yield rejected as VERIFIED_REAL
        with self.assertRaises(ContractValidationError) as ctx:
            self.projector.project_verified_real(signed, predicate="forecast_yield")
        self.assertIn("PREDICATE_NOT_VERIFIABLE_AS_REAL", str(ctx.exception))

        # Balance admitted as VERIFIED_REAL
        claim_balance = self.projector.project_verified_real(signed, predicate="balance_usd")
        self.assertEqual(claim_balance.epistemic_state, EpistemicState.VERIFIED_REAL)
        self.assertEqual(claim_balance.value, 50000.0)

        # Consolidated project_claim on forecast projects as HYPOTHESIZED with ceiling
        claim_forecast = self.projector.project_claim(signed, predicate="forecast_yield")
        self.assertEqual(claim_forecast.epistemic_state, EpistemicState.HYPOTHESIZED)
        self.assertLessEqual(claim_forecast.assurance_score, 0.60)

    def test_memory_retrieve_verifies_stored_record_not_external_domain_truth(self):
        """memory.retrieve can verify stored memory records, but cannot assert external ground truth."""
        results = {"stored_record": "vulnerable_host=192.168.1.5"}
        rcpt = ExecutionReceipt(
            receipt_id="rcpt_mem_01",
            job_id="job_mem_01",
            capability="memory.retrieve",
            target="vault_mem_key",
            started_at=100.0,
            completed_at=101.0,
            input_hash="inhash4",
            output_hash=ExecutionReceipt.hash_payload(results),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="idem4",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="NONE",
            worker_id="wrk_stage1",
            worker_key_id="wrk_stage1",
        )
        signed = self._sign_receipt(rcpt)

        # stored_record is verifiable as real
        claim_stored = self.projector.project_verified_real(signed, predicate="stored_record")
        self.assertEqual(claim_stored.epistemic_state, EpistemicState.VERIFIED_REAL)
        self.assertEqual(claim_stored.value, "vulnerable_host=192.168.1.5")

        # Fake external predicate on memory.retrieve is blocked
        fake_results = {"target_compromised": True}
        rcpt_fake = ExecutionReceipt(
            receipt_id="rcpt_mem_fake",
            job_id="job_mem_02",
            capability="memory.retrieve",
            target="vault_mem_key",
            started_at=100.0,
            completed_at=101.0,
            input_hash="inhash5",
            output_hash=ExecutionReceipt.hash_payload(fake_results),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=fake_results,
            side_effects=[],
            idempotency_key="idem5",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
            actual_transport_used="NONE",
            worker_id="wrk_stage1",
            worker_key_id="wrk_stage1",
        )
        signed_fake = self._sign_receipt(rcpt_fake)
        with self.assertRaises(ContractValidationError) as ctx:
            self.projector.project_verified_real(signed_fake, predicate="target_compromised")
        self.assertIn("PREDICATE_NOT_VERIFIABLE_AS_REAL", str(ctx.exception))

    def test_observation_cannot_mint_verified_real(self):
        """Claims backed by observations can never assert VERIFIED_REAL."""
        obs = Observation(
            observation_id="OBS-001",
            source="external:threat_intel",
            subject="example.com",
            predicate="malicious",
            value=True,
            reliability_class=ReliabilityClass.THIRD_PARTY_FEED,
        )
        with self.assertRaises(ContractValidationError) as ctx:
            Claim(
                claim_id="CLM-FORGED-01",
                subject="example.com",
                predicate="malicious",
                value=True,
                epistemic_state=EpistemicState.VERIFIED_REAL,
                observation=obs,
            )
        self.assertIn("OBSERVATION_CANNOT_MINT_VERIFIED_REAL", str(ctx.exception))

        with self.assertRaises(ContractValidationError) as ctx:
            Claim(
                claim_id="CLM-FORGED-02",
                subject="example.com",
                predicate="malicious",
                value=True,
                epistemic_state=EpistemicState.VERIFIED_REAL,
                observation_ids=["OBS-001"],
            )
        self.assertIn("OBSERVATION_CANNOT_MINT_VERIFIED_REAL", str(ctx.exception))

    def test_observation_ingestor_enforces_provenance_and_integrity(self):
        """ObservationIngestor rejects forged reliability, corrupt payloads, and future timestamps."""
        # 1. External source claiming AUTHORITATIVE_LOCAL is rejected
        with self.assertRaises(ContractValidationError) as ctx:
            ObservationIngestor.ingest(
                source="https://untrusted-feed.com/cve",
                subject="target",
                predicate="cve_status",
                value="active",
                reliability_class=ReliabilityClass.AUTHORITATIVE_LOCAL
            )
        self.assertIn("FORGED_RELIABILITY_REJECTED", str(ctx.exception))

        # 2. Corrupt raw payload digest mismatch
        with self.assertRaises(ContractValidationError) as ctx:
            ObservationIngestor.ingest(
                source="internal_monitor",
                subject="target",
                predicate="latency_ms",
                value=15,
                raw_payload=b"actual_data",
                expected_content_hash="deadbeef" * 8
            )
        self.assertIn("OBSERVATION_PAYLOAD_INTEGRITY_MISMATCH", str(ctx.exception))

        # 3. Future observed_at rejected
        with self.assertRaises(ContractValidationError) as ctx:
            ObservationIngestor.ingest(
                source="internal_monitor",
                subject="target",
                predicate="latency_ms",
                value=15,
                observed_at=time.time() + 100.0
            )
        self.assertIn("FUTURE_TIMESTAMP_REJECTED", str(ctx.exception))

        # 4. Non-finite timestamp rejected
        with self.assertRaises(ContractValidationError) as ctx:
            ObservationIngestor.ingest(
                source="internal_monitor",
                subject="target",
                predicate="latency_ms",
                value=15,
                observed_at=float("nan")
            )
        self.assertIn("NON_FINITE_TIMESTAMP", str(ctx.exception))

        # 5. Valid observation ingests properly with bounded reliability and explicit observed_at
        now_ts = time.time()
        valid_obs = ObservationIngestor.ingest(
            source="https://cve.mitre.org/feed",
            subject="CVE-2026-9999",
            predicate="cvss",
            value=8.8,
            observed_at=now_ts
        )
        self.assertEqual(valid_obs.reliability_class, ReliabilityClass.UNVERIFIED_INCOMING)
        self.assertFalse(valid_obs.uncertain_source_time)
        self.assertEqual(valid_obs.observed_at, now_ts)
        self.assertTrue(len(valid_obs.compute_content_hash()) == 64)

        # 6. Omitted observed_at flags uncertain_source_time explicitly
        uncertain_obs = ObservationIngestor.ingest(
            source="https://cve.mitre.org/feed",
            subject="CVE-2026-9999",
            predicate="cvss",
            value=8.8,
        )
        self.assertTrue(uncertain_obs.uncertain_source_time)

    def test_stale_evidence_replay_cannot_reset_freshness_clock(self):
        """Replaying old evidence anchors to evidence creation time and cannot extend TTL."""
        old_completed_time = time.time() - 600.0  # 10 minutes ago
        results = {"status": "open"}
        rcpt = ExecutionReceipt(
            receipt_id="rcpt_sensor_old",
            job_id="job_sensor_01",
            capability="tor.check_status",
            target="127.0.0.1:9050",
            started_at=old_completed_time - 2.0,
            completed_at=old_completed_time,
            input_hash="inhash6",
            output_hash=ExecutionReceipt.hash_payload(results),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="idem6",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="DIRECT",
            worker_id="wrk_stage1",
            worker_key_id="wrk_stage1",
        )
        signed = self._sign_receipt(rcpt)

        # Project with LIVE_NETWORK_STATE (5 minutes TTL = 300s)
        claim = self.projector.project_verified_real(
            signed,
            predicate="status",
            decay_profile=DecayProfile.LIVE_NETWORK_STATE
        )
        # created_at must be anchored to receipt.completed_at
        self.assertEqual(claim.created_at, old_completed_time)
        # freshness_deadline must be old_completed_time + 300s
        self.assertEqual(claim.freshness_deadline, old_completed_time + 300.0)
        # Since it completed 600s ago, it is already expired!
        self.assertFalse(claim.is_fresh())

        # Attempting to supply a future freshness_deadline is clamped by the decay ceiling
        claim_clamped = Claim(
            claim_id="CLM-CLAMP-01",
            subject="127.0.0.1:9050",
            predicate="status",
            value="open",
            epistemic_state=EpistemicState.VERIFIED_REAL,
            decay_profile=DecayProfile.LIVE_NETWORK_STATE,
            freshness_deadline=time.time() + 99999.0,  # Ridiculous future deadline
            receipt=signed,
            _receipt_verifier=self.projector._ClaimProjector__receipt_verifier,
        )
        self.assertEqual(claim_clamped.freshness_deadline, old_completed_time + 300.0)
        self.assertFalse(claim_clamped.is_fresh())

    def test_project_from_observation_binds_provenance(self):
        """ClaimProjector.project_from_observation mints OBSERVED claim with bound provenance."""
        obs = ObservationIngestor.ingest(
            source="https://cve.mitre.org/feed",
            subject="CVE-2026-8888",
            predicate="cvss",
            value=6.5,
            expires_at=time.time() + 3600.0
        )
        claim = self.projector.project_from_observation(obs)
        self.assertEqual(claim.epistemic_state, EpistemicState.OBSERVED)
        self.assertEqual(claim.observation_ids, (obs.observation_id,))
        self.assertEqual(claim.value["value"], 6.5)
        self.assertEqual(claim.subject, obs.source)
        self.assertEqual(claim.predicate, "source_reported")
        self.assertLessEqual(claim.assurance_score, 0.70)
        self.assertEqual(claim.freshness_deadline, obs.expires_at)
        self.assertTrue(claim.is_fresh())

    def test_no_caller_controlled_verification_authority(self):
        """Caller cannot supply or substitute verification authority."""
        with self.assertRaises(ContractValidationError):
            ClaimProjector(self.registry)

        with self.assertRaises(ContractValidationError):
            Claim(
                claim_id="CLM-AUTH-01",
                subject="test",
                predicate="test",
                value="test",
                epistemic_state=EpistemicState.OBSERVED,
                trust_registry=self.registry
            )


if __name__ == "__main__":
    unittest.main()
