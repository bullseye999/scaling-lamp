"""
test_phase1_canonical_contracts.py - Comprehensive Unit Tests for Phase 1 Canonical Versioned Contracts.

Covers:
1. Re-export integrity & class identity preservation across legacy modules.
2. Deep immutability and defensive copying across all contracts.
3. Unknown-version rejection across all contracts.
4. Legacy fixture deserialization and version migration (ExecutionReceipt 4.0 -> 4.1).
5. Cryptographic signature verification and every-field tampering detection (ScopeGrant, AuthorizationGrant).
6. Prevention of unauthorized VERIFIED_REAL claim construction.
7. ExecutionDAG validation (cycle detection, duplicate IDs, missing deps, topological plan hash determinism).
8. JobAttempt lease state contract and fingerprinting.
"""

import unittest
import os
import tempfile
import shutil
import time
import hmac
import hashlib
from typing import Dict, Any
from dataclasses import replace

# Canonical contracts
from ciph.contracts import (
    ContractValidationError,
    VersionedContract,
    NetworkPolicy,
    ReversibilityClass,
    RiskTier,
    AuthorizationTier,
    ExecutionLane,
    ScopeType,
    JobState,
    OutcomeCategory,
    ReliabilityClass,
    EpistemicState,
    LifecycleState,
    DecayProfile,
    ScopeGrant,
    AuthorizationGrant,
    IntentProposal,
    PlanStep,
    ExecutionDAG,
    PlanValidationResult,
    SkillTemplate,
    JobAttempt,
    ExecutionReceipt,
    ExecutionToken,
    Observation,
    Claim,
    FrozenDict,
    ClaimProjector,
    canonical_json,
    compute_idempotency_key,
    generate_environment_fingerprint,
)
from ciph.kernel.crypto_identity import TrustRegistry, KeyRole, Ed25519KeyManager

# Legacy module imports for identity assertion
import ciph.kernel.policy_engine as legacy_pe
import ciph.planner.schemas as legacy_ps
import ciph.perception.observation as legacy_po
import ciph.workers.receipts as legacy_wr
import ciph.memory.materialized_views as legacy_mv
import ciph.kernel.transmutation_dag as legacy_td


class TestPhase1ContractIdentities(unittest.TestCase):
    """Assert identity preservation between new contracts module and legacy modules."""

    def test_enum_identities(self):
        self.assertIs(legacy_pe.NetworkPolicy, NetworkPolicy)
        self.assertIs(legacy_pe.ReversibilityClass, ReversibilityClass)
        self.assertIs(legacy_pe.RiskTier, RiskTier)
        self.assertIs(legacy_pe.AuthorizationTier, AuthorizationTier)
        self.assertIs(legacy_pe.ExecutionLane, ExecutionLane)
        self.assertIs(legacy_pe.ScopeType, ScopeType)
        self.assertIs(legacy_po.ReliabilityClass, ReliabilityClass)
        self.assertIs(legacy_wr.JobState, JobState)
        self.assertIs(legacy_wr.OutcomeCategory, OutcomeCategory)
        self.assertIs(legacy_mv.DecayProfile, DecayProfile)
        self.assertIs(legacy_td.EpistemicCategory, EpistemicState)

    def test_class_identities(self):
        self.assertIs(legacy_pe.ScopeGrant, ScopeGrant)
        self.assertIs(legacy_pe.AuthorizationGrant, AuthorizationGrant)
        self.assertIs(legacy_ps.IntentProposal, IntentProposal)
        self.assertIs(legacy_ps.PlanStep, PlanStep)
        self.assertIs(legacy_ps.ExecutionDAG, ExecutionDAG)
        self.assertIs(legacy_po.Observation, Observation)
        self.assertIs(legacy_wr.ExecutionReceipt, ExecutionReceipt)


class TestDeepImmutability(unittest.TestCase):
    """Ensure collections inside frozen dataclasses cannot be mutated in-place."""

    def test_scope_grant_deep_immutability(self):
        scope = ScopeGrant(
            scope_id="scope_immut_01",
            scope_type=ScopeType.TARGET_DOMAIN,
            allowed_targets=["*.crypto.com"],
            denied_targets=["evil.crypto.com"],
        )
        self.assertIsInstance(scope.allowed_targets, tuple)
        self.assertIsInstance(scope.denied_targets, tuple)

        with self.assertRaises(AttributeError):
            scope.allowed_targets.append("other.domain.com")  # type: ignore

        with self.assertRaises(TypeError):
            scope.allowed_targets[0] = "mutated.domain.com"  # type: ignore

    def test_authorization_grant_deep_immutability(self):
        budget = {"cpu_seconds": 10.0, "ram_mb": 512.0}
        grant = AuthorizationGrant(
            grant_id="grant_immut_01",
            plan_hash="hash_plan",
            step_id="step_1",
            capability="mock.cap",
            params_hash="hash_params",
            scope_grant_id="scope_1",
            max_budget=budget,
        )
        # Mutating the original dict must not affect the grant
        budget["cpu_seconds"] = 999.0
        self.assertEqual(grant.max_budget["cpu_seconds"], 10.0)

        # Mutating grant.max_budget directly must fail closed
        with self.assertRaises(TypeError):
            grant.max_budget["cpu_seconds"] = 999.0  # type: ignore

        with self.assertRaises(TypeError):
            grant.max_budget.update({"cpu_seconds": 999.0})  # type: ignore

    def test_claim_deep_immutability(self):
        mutable_val = [22, 80]
        claim = Claim(
            claim_id="CLM-IMMUT-01",
            subject="host.internal",
            predicate="open_ports",
            value=mutable_val,
            epistemic_state=EpistemicState.OBSERVED,
            evidence_receipt_ids=["rcpt_1", "rcpt_2"],
            parent_claim_ids=["clm_parent_1"],
        )
        self.assertIsInstance(claim.evidence_receipt_ids, tuple)
        self.assertIsInstance(claim.parent_claim_ids, tuple)
        self.assertIsInstance(claim.value, tuple)

        with self.assertRaises(AttributeError):
            claim.evidence_receipt_ids.append("rcpt_3")  # type: ignore

        with self.assertRaises(AttributeError):
            claim.value.append(443)  # type: ignore

        # Frozen dataclasses remain writable through object.__setattr__; Claim must not.
        self.assertFalse(hasattr(claim, "__dict__"))
        with self.assertRaises(AttributeError):
            object.__setattr__(claim, "epistemic_state", EpistemicState.VERIFIED_REAL)
        with self.assertRaises(AttributeError):
            object.__setattr__(claim, "value", ("forged",))
        with self.assertRaises(ContractValidationError):
            claim._replace(epistemic_state=EpistemicState.VERIFIED_REAL)
        forged_values = tuple(claim[:4]) + (EpistemicState.VERIFIED_REAL,) + tuple(claim[5:])
        with self.assertRaises(ContractValidationError):
            Claim._make(forged_values)
        self.assertEqual(claim.epistemic_state, EpistemicState.OBSERVED)
        self.assertEqual(claim.value, (22, 80))

    def test_observation_deep_immutability(self):
        mutable_val = {"port": 80, "banner": "nginx"}
        obs = Observation(
            observation_id="obs_immut_01",
            source="test",
            subject="target",
            predicate="status",
            value=mutable_val,
            environment={"os": "linux", "arch": "x86_64"},
        )
        self.assertIsInstance(obs.environment, tuple)
        self.assertIsInstance(obs.value, FrozenDict)

        with self.assertRaises(AttributeError):
            obs.environment.append(("new_key", "val"))  # type: ignore

        with self.assertRaises(TypeError):
            obs.value["port"] = 8080  # type: ignore

    def test_frozen_dict_not_dict_and_cannot_be_bypassed_via_dict_methods(self):
        """Finding 3: FrozenDict inherits from Mapping, NOT dict; dict.__setitem__ cannot bypass."""
        from collections.abc import Mapping
        fd = FrozenDict({"limit": 10, "nested": {"rate": 5}})
        self.assertIsInstance(fd, Mapping)
        self.assertNotIsInstance(fd, dict)

        # Direct mutation blocked
        with self.assertRaises(TypeError):
            fd["limit"] = 999

        # C-level descriptor bypasses blocked
        with self.assertRaises(TypeError):
            dict.__setitem__(fd, "limit", 999)

        with self.assertRaises(TypeError):
            dict.__delitem__(fd, "limit")

        with self.assertRaises(TypeError):
            dict.update(fd, {"limit": 999})

        with self.assertRaises(TypeError):
            dict.pop(fd, "limit")

        with self.assertRaises(TypeError):
            dict.clear(fd)

        # Deep immutability of nested observation environment
        caller_env = {"os": "linux", "tags": ["prod", "secure"], "metadata": {"zone": "us-east"}}
        obs = Observation(
            observation_id="obs_deep_01",
            source="probe",
            subject="server1",
            predicate="alive",
            value=True,
            environment=caller_env,
        )
        # Mutating caller's dict or nested list does not affect obs.environment
        caller_env["tags"].append("compromised")
        caller_env["metadata"]["zone"] = "injected"

        # Verify nested list inside obs.environment is a frozen tuple
        env_dict = dict(obs.environment)
        self.assertIsInstance(env_dict["tags"], tuple)
        self.assertEqual(env_dict["tags"], ("prod", "secure"))
        self.assertIsInstance(env_dict["metadata"], FrozenDict)
        with self.assertRaises(TypeError):
            env_dict["metadata"]["zone"] = "hacked"

    def test_deep_immutability_budget_and_planning_contracts(self):
        """Verify dataclass frozen and collection immutability for IntentProposal, PlanStep, and ExecutionDAG."""
        # 1. IntentProposal immutability
        intent = IntentProposal(
            proposal_id="prop_01",
            objective="Scan ports",
            proposed_capability="cybersecurity.port_scan",
            provided_parameters={"host": "target.local"},
            missing_parameters=["port"],
            constraints={"timeout": 10},
        )
        with self.assertRaises(Exception):
            intent.objective = "Tampered objective"  # FrozenInstanceError
        with self.assertRaises(TypeError):
            intent.provided_parameters["injected"] = "evil"
        with self.assertRaises(AttributeError):
            intent.missing_parameters.append("extra")
        with self.assertRaises(TypeError):
            intent.constraints["extra"] = True

        # 2. PlanStep immutability
        step = PlanStep(
            step_id="step_recon",
            capability="cybersecurity.subdomain_scan",
            parameters={"domain": "example.com"},
            depends_on=["step_init"],
            retry_policy={"max_retries": 2},
        )
        with self.assertRaises(Exception):
            step.capability = "cybersecurity.privilege_escalation"  # FrozenInstanceError
        with self.assertRaises(TypeError):
            step.parameters["domain"] = "attacker.com"
        with self.assertRaises(AttributeError):
            step.depends_on.append("step_ghost")
        with self.assertRaises(TypeError):
            step.retry_policy["max_retries"] = 999

        # 3. ExecutionDAG immutability
        dag = ExecutionDAG(
            plan_id="plan_dag_01",
            objective="Governed execution",
            steps=[step],
        )
        with self.assertRaises(Exception):
            dag.plan_id = "plan_tampered"  # FrozenInstanceError
        with self.assertRaises(AttributeError):
            dag.steps.append(step)


class TestUnknownVersionRejection(unittest.TestCase):
    """Reject unknown or unsupported future schema versions across all contracts."""

    def test_scope_grant_version_rejection(self):
        with self.assertRaises(ContractValidationError):
            ScopeGrant(
                scope_id="s1",
                scope_type=ScopeType.LOCAL_SYSTEM,
                allowed_targets=["*"],
                schema_version="99.0",
            )
        with self.assertRaises(ContractValidationError):
            ScopeGrant.from_dict({
                "scope_id": "s1",
                "scope_type": "LOCAL_SYSTEM",
                "allowed_targets": ["*"],
                "schema_version": "99.0",
            })

    def test_authorization_grant_version_rejection(self):
        with self.assertRaises(ContractValidationError):
            AuthorizationGrant(
                grant_id="g1",
                plan_hash="p",
                step_id="s",
                capability="c",
                params_hash="ph",
                scope_grant_id="sg",
                schema_version="2.0",
            )
        with self.assertRaises(ContractValidationError):
            AuthorizationGrant.from_dict({
                "grant_id": "g1",
                "plan_hash": "p",
                "step_id": "s",
                "capability": "c",
                "params_hash": "ph",
                "scope_grant_id": "sg",
                "schema_version": "2.0",
            })

    def test_execution_receipt_version_rejection(self):
        with self.assertRaises(ContractValidationError):
            ExecutionReceipt.from_dict({
                "receipt_id": "r1",
                "job_id": "j1",
                "capability": "cap",
                "started_at": 100.0,
                "completed_at": 101.0,
                "input_hash": "h1",
                "output_hash": "h2",
                "exit_code": 0,
                "outcome": "SUCCESS",
                "results": {},
                "side_effects": [],
                "idempotency_key": "k",
                "attempt_number": 1,
                "requested_network_policy": "OFFLINE_ONLY",
                "actual_transport_used": "LOCAL",
                "schema_version": "99.0",  # Unrecognized future version
            })

    def test_claim_version_rejection(self):
        with self.assertRaises(ContractValidationError):
            Claim(
                claim_id="c1",
                subject="sub",
                predicate="pred",
                value="val",
                epistemic_state=EpistemicState.OBSERVED,
                schema_version="5.0",
            )

    def test_job_attempt_version_rejection(self):
        with self.assertRaises(ContractValidationError):
            JobAttempt(
                job_id="j1",
                capability="cap",
                attempt_number=1,
                max_retries=3,
                worker_id="w1",
                leased_at=100.0,
                lease_expires_at=130.0,
                idempotency_key="k1",
                schema_version="2.0",
            )


class TestLegacyFixturesAndMigration(unittest.TestCase):
    """Test recognized legacy payloads are migrated and preserved."""

    def test_execution_receipt_legacy_migration(self):
        legacy_data = {
            "receipt_id": "rcpt_legacy_001",
            "job_id": "JOB-LEGACY-01",
            "capability": "memory.read",
            "target": None,
            "started_at": 1000.0,
            "completed_at": 1001.0,
            "input_hash": "in_hash",
            "output_hash": "out_hash",
            "exit_code": 0,
            "outcome": "SUCCESS",
            "results": {"data": "legacy_val"},
            "side_effects": [],
            "idempotency_key": "idemp_legacy",
            "attempt_number": 1,
            "requested_network_policy": "OFFLINE_ONLY",
            "actual_transport_used": "LOCAL_SOCKET",
            "schema_version": "4.0",  # Legacy version
        }
        reconstituted = ExecutionReceipt.from_dict(legacy_data)
        self.assertEqual(reconstituted.schema_version, "4.1")  # Migrated to 4.1
        self.assertEqual(reconstituted.receipt_id, "rcpt_legacy_001")
        self.assertEqual(reconstituted.outcome, OutcomeCategory.SUCCESS)

    def test_planning_contracts_field_preservation(self):
        prop = IntentProposal(
            proposal_id="p1",
            objective="Scan",
            proposed_capability="cybersecurity.subdomain_scan",
            scope_reference="scope_target_01",
            constraints={"tor": True},
            requested_outcome="Full subdomain enum",
        )
        self.assertEqual(prop.scope_reference, "scope_target_01")
        self.assertEqual(prop.scope_context, "scope_target_01")
        d = prop.to_dict()
        reconstituted = IntentProposal.from_dict(d)
        self.assertEqual(reconstituted.scope_reference, "scope_target_01")
        self.assertEqual(reconstituted.constraints["tor"], True)
        self.assertEqual(reconstituted.requested_outcome, "Full subdomain enum")


class TestEveryFieldSignatureTampering(unittest.TestCase):
    """Verify that tampering with ANY field invalidates HMAC signatures."""

    def setUp(self):
        self.secret_key = b"ciph_kernel_master_signing_key_32b!"

    def test_scope_grant_every_field_tampering(self):
        grant = ScopeGrant(
            scope_id="scope_sec_01",
            scope_type=ScopeType.TARGET_DOMAIN,
            allowed_targets=["*.crypto.com"],
            denied_targets=["internal.crypto.com"],
            network_policy_override=NetworkPolicy.TOR_MANDATORY,
            valid_until=2000000000.0,
            created_at=1000000000.0,
            signing_key_id="kernel_primary",
            schema_version="1.0",
        )
        signed = grant.sign(self.secret_key)
        self.assertTrue(signed.verify_signature(self.secret_key))

        # Tamper schema_version
        self.assertFalse(ScopeGrant(
            scope_id=signed.scope_id, scope_type=signed.scope_type,
            allowed_targets=signed.allowed_targets, denied_targets=signed.denied_targets,
            network_policy_override=signed.network_policy_override, valid_until=signed.valid_until,
            created_at=signed.created_at, signing_key_id=signed.signing_key_id,
            signature=signed.signature, schema_version="1.0"
        ).verify_signature(b"wrong_key"))

        # Test tampering each authority-relevant field individually:
        fields_to_tamper = [
            ("scope_id", "scope_sec_TAMPERED"),
            ("scope_type", ScopeType.LOCAL_SYSTEM),
            ("allowed_targets", ["*.crypto.com", "extra.com"]),
            ("denied_targets", []),
            ("network_policy_override", NetworkPolicy.DIRECT_APPROVED),
            ("valid_until", 2000000001.0),
            ("created_at", 1000000001.0),
            ("signing_key_id", "kernel_backup"),
        ]
        base_dict = signed.to_dict()
        for field_name, tampered_val in fields_to_tamper:
            t_dict = dict(base_dict)
            t_dict[field_name] = tampered_val
            tampered_grant = ScopeGrant.from_dict(t_dict)
            self.assertFalse(
                tampered_grant.verify_signature(self.secret_key),
                f"Tampering with '{field_name}' did not invalidate ScopeGrant signature!"
            )

    def test_authorization_grant_every_field_tampering(self):
        grant = AuthorizationGrant(
            grant_id="grant_sec_01",
            plan_hash="a1b2c3d4",
            step_id="step_recon",
            capability="cybersecurity.subdomain_scan",
            params_hash="e5f6g7h8",
            scope_grant_id="scope_sec_01",
            max_budget={"cpu_seconds": 30.0},
            expires_at=2000000000.0,
            created_at=1000000000.0,
            signing_key_id="kernel_primary",
            schema_version="1.0",
        )
        signed = grant.sign(self.secret_key)
        self.assertTrue(signed.verify_signature(self.secret_key))

        fields_to_tamper = [
            ("grant_id", "grant_TAMPERED"),
            ("plan_hash", "tampered_plan"),
            ("step_id", "tampered_step"),
            ("capability", "cybersecurity.takeover"),
            ("params_hash", "tampered_params"),
            ("scope_grant_id", "scope_tampered"),
            ("max_budget", {"cpu_seconds": 60.0}),
            ("expires_at", 2000000001.0),
            ("created_at", 1000000001.0),
            ("signing_key_id", "kernel_secondary"),
        ]
        base_dict = signed.to_dict()
        for field_name, tampered_val in fields_to_tamper:
            t_dict = dict(base_dict)
            t_dict[field_name] = tampered_val
            tampered_grant = AuthorizationGrant.from_dict(t_dict)
            self.assertFalse(
                tampered_grant.verify_signature(self.secret_key),
                f"Tampering with '{field_name}' did not invalidate AuthorizationGrant signature!"
            )

    def test_expired_scope_grant_fails_closed_in_target_check(self):
        """ScopeGrant.is_target_permitted must fail closed immediately when expired."""
        scope = ScopeGrant(
            scope_id="scope_exp_01",
            scope_type=ScopeType.TARGET_DOMAIN,
            allowed_targets=["*.crypto.com"],
            valid_until=1000.0,
            created_at=900.0,
        )
        # Permitted before expiration
        self.assertTrue(scope.is_target_permitted("api.crypto.com", current_time=950.0))
        # Denied after expiration (fails closed)
        self.assertFalse(scope.is_target_permitted("api.crypto.com", current_time=1001.0))
        # Default current_time (now > 1000.0) fails closed
        self.assertFalse(scope.is_target_permitted("api.crypto.com"))

    def test_step_hash_tamper_detection_retry_policy_and_grants(self):
        """PlanStep.compute_step_hash must bind retry_policy, idempotency_key, authorization_grant_id, and expected_receipt_type."""
        step = PlanStep(
            step_id="s1",
            capability="cybersecurity.subdomain_scan",
            parameters={"target": "crypto.com"},
            retry_policy={"max_retries": 1, "backoff": "linear"},
            idempotency_key="idemp_original",
            authorization_grant_id="grant_original",
            expected_receipt_type="ExecutionReceipt",
        )
        base_step_hash = step.compute_step_hash()
        dag = ExecutionDAG(plan_id="p1", objective="test", steps=[step])
        base_plan_hash = dag.compute_plan_hash()

        # 1. Tamper retry_policy
        step_tampered_retry = PlanStep(
            step_id="s1", capability="cybersecurity.subdomain_scan",
            parameters={"target": "crypto.com"},
            retry_policy={"max_retries": 5, "backoff": "exponential"},
            idempotency_key="idemp_original", authorization_grant_id="grant_original",
            expected_receipt_type="ExecutionReceipt"
        )
        self.assertNotEqual(base_step_hash, step_tampered_retry.compute_step_hash())
        dag_tampered = ExecutionDAG(plan_id="p1", objective="test", steps=[step_tampered_retry])
        self.assertNotEqual(base_plan_hash, dag_tampered.compute_plan_hash())

        # 2. Tamper idempotency_key
        step_tampered_idemp = PlanStep(
            step_id="s1", capability="cybersecurity.subdomain_scan",
            parameters={"target": "crypto.com"},
            retry_policy={"max_retries": 1, "backoff": "linear"},
            idempotency_key="idemp_TAMPERED", authorization_grant_id="grant_original",
            expected_receipt_type="ExecutionReceipt"
        )
        self.assertNotEqual(base_step_hash, step_tampered_idemp.compute_step_hash())

        # 3. Tamper authorization_grant_id
        step_tampered_grant = PlanStep(
            step_id="s1", capability="cybersecurity.subdomain_scan",
            parameters={"target": "crypto.com"},
            retry_policy={"max_retries": 1, "backoff": "linear"},
            idempotency_key="idemp_original", authorization_grant_id="grant_FORGED",
            expected_receipt_type="ExecutionReceipt"
        )
        self.assertNotEqual(base_step_hash, step_tampered_grant.compute_step_hash())

        # 4. Tamper expected_receipt_type
        step_tampered_type = PlanStep(
            step_id="s1", capability="cybersecurity.subdomain_scan",
            parameters={"target": "crypto.com"},
            retry_policy={"max_retries": 1, "backoff": "linear"},
            idempotency_key="idemp_original", authorization_grant_id="grant_original",
            expected_receipt_type="ForgedReceipt"
        )
        self.assertNotEqual(base_step_hash, step_tampered_type.compute_step_hash())


class TestUnauthorizedVerifiedRealPrevention(unittest.TestCase):
    """Assert that VERIFIED_REAL claims cannot be minted arbitrarily without receipt verification."""

    @classmethod
    def setUpClass(cls):
        import tempfile, shutil, os
        from ciph.runtime import CiphRuntime
        cls._temp_dir = tempfile.mkdtemp()
        cls._temp_db = os.path.join(cls._temp_dir, "test_isolated_vault.db")
        cls._runtime = CiphRuntime(db_path=cls._temp_db)
        cls._trust_reg = cls._runtime.trust_registry
        cls._op_priv, cls._op_pub = cls._trust_reg.get_keypair("operator_root")
        cls._wrk_priv, cls._wrk_pub = cls._trust_reg.get_keypair("worker_primary")

    @classmethod
    def tearDownClass(cls):
        import shutil, os
        cls._runtime.close()
        if os.path.exists(cls._temp_dir):
            shutil.rmtree(cls._temp_dir, ignore_errors=True)

    def test_direct_instantiation_raises(self):
        with self.assertRaises(ContractValidationError):
            Claim(
                claim_id="CLM-EXPLOIT-01",
                subject="system.root",
                predicate="is_compromised",
                value=True,
                epistemic_state=EpistemicState.VERIFIED_REAL,  # Direct self-promotion
            )

    def test_from_dict_unauthorized_raises(self):
        payload = {
            "claim_id": "CLM-EXPLOIT-02",
            "subject": "target.domain",
            "predicate": "vulnerable",
            "value": True,
            "epistemic_state": "VERIFIED_REAL",  # Attempt to inject through serialized input
            "lifecycle_state": "ACTIVE",
            "decay_profile": "SOFTWARE_BEHAVIOR",
            "assurance_score": 1.0,
        }
        with self.assertRaises(ContractValidationError):
            Claim.from_dict(payload)

    def test_verified_real_no_constructor_bypass(self):
        """Constructing VERIFIED_REAL directly must fail even if caller passes kwargs or fake sentinels."""
        with self.assertRaises(ContractValidationError):
            Claim(
                claim_id="CLM-BYPASS-01",
                subject="example.com",
                predicate="vuln",
                value=True,
                epistemic_state=EpistemicState.VERIFIED_REAL,
                _authorized_factory=True,
            )
        with self.assertRaises(ContractValidationError):
            Claim(
                claim_id="CLM-BYPASS-02",
                subject="example.com",
                predicate="vuln",
                value=True,
                epistemic_state=EpistemicState.VERIFIED_REAL,
                _factory_sentinel=True,
            )
        with self.assertRaises(ContractValidationError):
            Claim(
                claim_id="CLM-BYPASS-03",
                subject="example.com",
                predicate="vuln",
                value=True,
                epistemic_state=EpistemicState.VERIFIED_REAL,
                _factory_sentinel="sentinel",
            )

    def test_create_verified_real_with_failed_receipt_raises(self):
        failed_receipt = ExecutionReceipt(
            receipt_id="rcpt_fail_01",
            job_id="job_01",
            capability="test.cap",
            target="example.com",
            started_at=100.0,
            completed_at=105.0,
            input_hash="h_in",
            output_hash="h_out",
            exit_code=1,  # Failure
            outcome=OutcomeCategory.EXECUTION_ERROR,
            results={"error": "Connection timeout"},
            side_effects=[],
            idempotency_key="k1",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.TOR_MANDATORY,
            actual_transport_used="TOR_SOCKS5H",
        )
        with self.assertRaises(ContractValidationError):
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-01",
                subject="example.com",
                predicate="status",
                value="active",
                receipt=failed_receipt,
            )

    def test_verified_real_rejects_unsigned_or_fabricated_receipts(self):
        """Claim.create_verified_real must reject unsigned, hash-mismatched, or unverified receipts."""
        reg = self._trust_reg
        wrk_priv = self._wrk_priv

        results = {"subdomains": ["api.example.com"]}
        correct_hash = ExecutionReceipt.hash_payload(results)

        # 1. Unsigned receipt rejected
        unsigned = ExecutionReceipt(
            receipt_id="rcpt_unsigned",
            job_id="job_01",
            capability="test.cap",
            target="example.com",
            started_at=100.0,
            completed_at=105.0,
            input_hash="in_hash",
            output_hash=correct_hash,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="k1",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.TOR_MANDATORY,
            actual_transport_used="TOR_SOCKS5H",
            worker_id="worker_primary",
            worker_key_id="worker_primary",
            worker_signature=None,
        )
        with self.assertRaises(ContractValidationError):
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-ERR-01",
                subject="example.com",
                predicate="subdomains",
                value=["api.example.com"],
                receipt=unsigned,
            )

        # 2. Output hash mismatch rejected
        tampered_hash_receipt = unsigned.sign(wrk_priv, worker_key_id="worker_primary")
        tampered_dict = tampered_hash_receipt.to_dict()
        tampered_dict["output_hash"] = "fabricated_hash_value"
        bad_hash_receipt = ExecutionReceipt.from_dict(tampered_dict)
        with self.assertRaises(ContractValidationError):
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-ERR-02",
                subject="example.com",
                predicate="subdomains",
                value=["api.example.com"],
                receipt=bad_hash_receipt,
            )

        # 3. Forged signature / wrong key rejected
        other_priv, _ = Ed25519KeyManager.generate_keypair()
        wrong_sig_receipt = unsigned.sign(other_priv, worker_key_id="worker_primary")
        with self.assertRaises(ContractValidationError):
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-ERR-03",
                subject="example.com",
                predicate="subdomains",
                value=["api.example.com"],
                receipt=wrong_sig_receipt,
            )

        # 4. Revoked key in TrustRegistry rejected
        temp_priv, temp_pub = Ed25519KeyManager.generate_keypair()
        payload = f"REGISTER_KEY:worker_test_revocation:WORKER:{temp_pub.hex()}:None".encode("utf-8")
        op_sig = Ed25519KeyManager.sign(self._op_priv, payload)
        reg.store_keypair("worker_test_revocation", KeyRole.WORKER, temp_priv, temp_pub, operator_signature=op_sig)
        revoke_reason = "Compromised worker"
        revoke_payload = f"REVOKE_KEY:worker_test_revocation:{revoke_reason}".encode("utf-8")
        revoke_sig = Ed25519KeyManager.sign(self._op_priv, revoke_payload)
        self.assertTrue(
            reg.revoke_key(
                "worker_test_revocation",
                reason=revoke_reason,
                operator_signature=revoke_sig,
            )
        )
        valid_signed = unsigned.sign(temp_priv, worker_key_id="worker_test_revocation")
        try:
            with self.assertRaises(ContractValidationError):
                self._runtime.claim_projector.project_verified_real(
                    claim_id="CLM-ERR-04",
                    subject="example.com",
                    predicate="subdomains",
                    value=["api.example.com"],
                    receipt=valid_signed,
                )
        finally:
            conn = reg._get_connection()
            conn.execute("DELETE FROM ciph_trust_registry WHERE key_id = 'worker_test_revocation'")
            conn.execute("DELETE FROM ciph_key_vault WHERE key_id = 'worker_test_revocation'")
            conn.commit()

    def test_create_verified_real_authorized_factory_succeeds(self):
        reg = self._trust_reg
        wrk_priv = self._wrk_priv

        results = {"status": "connected"}
        output_hash = ExecutionReceipt.hash_payload(results)
        now = time.time()
        unsigned_receipt = ExecutionReceipt(
            receipt_id="rcpt_success_01",
            job_id="job_01",
            capability="tor.check_status",
            target="example.com",
            started_at=now - 5.0,
            completed_at=now,
            input_hash="h_in",
            output_hash=output_hash,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="k1",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.TOR_MANDATORY,
            actual_transport_used="TOR_SOCKS5H",
            environment_fingerprint="env_fp_linux_312",
            worker_id="worker_primary",
            worker_key_id="worker_primary",
        )
        signed_receipt = unsigned_receipt.sign(wrk_priv, worker_key_id="worker_primary")

        claim = self._runtime.claim_projector.project_verified_real(
            claim_id="CLM-VERIFIED-01",
            subject="example.com",
            predicate="status",
            value="connected",
            receipt=signed_receipt,
            decay_profile=DecayProfile.SOFTWARE_BEHAVIOR,
        )
        self.assertEqual(claim.epistemic_state, EpistemicState.VERIFIED_REAL)
        self.assertEqual(claim.assurance_score, 1.0)
        self.assertIn("rcpt_success_01", claim.evidence_receipt_ids)
        self.assertEqual(claim.environment_fingerprint, "env_fp_linux_312")
        self.assertEqual(claim.authority_fingerprint, self._runtime.claim_projector.authority_fingerprint)
        self.assertTrue(claim.is_fresh())



    def test_finding1_sentinel_eradication_and_unauthorized_forge_prevention(self):
        """Finding 1: VERIFIED_REAL cannot be forged via module sentinel or kwargs."""
        import ciph.contracts.epistemic as epistemic_mod
        # The sentinel was eliminated entirely
        self.assertFalse(hasattr(epistemic_mod, "_CLAIM_VERIFIED_REAL_SENTINEL"))

        # Direct instantiation attempts all fail closed
        with self.assertRaises(ContractValidationError):
            Claim(
                claim_id="CLM-FORGE-1",
                subject="system.root",
                predicate="is_compromised",
                value=True,
                epistemic_state=EpistemicState.VERIFIED_REAL,
            )

        with self.assertRaises(ContractValidationError):
            Claim(
                claim_id="CLM-FORGE-2",
                subject="system.root",
                predicate="is_compromised",
                value=True,
                epistemic_state=EpistemicState.VERIFIED_REAL,
                _factory_sentinel="anything",
            )

    def test_finding1_caller_controlled_authority_rejected(self):
        """Finding 1 (Critical): Caller cannot supply trust_registry or secret_key to mint VERIFIED_REAL."""
        attacker_reg = TrustRegistry(db_path=":memory:")
        atk_priv, atk_pub = Ed25519KeyManager.generate_keypair()
        attacker_reg.register_key("worker_attacker", KeyRole.WORKER, atk_pub.hex())

        results = {"finding": "COMPROMISED"}
        output_hash = ExecutionReceipt.hash_payload(results)
        now = time.time()
        rcpt = ExecutionReceipt(
            receipt_id="rcpt_atk_01",
            job_id="job_atk_01",
            capability="security.audit",
            target="target.local",
            started_at=now - 2.0,
            completed_at=now,
            input_hash="h_in",
            output_hash=output_hash,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="k_atk",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="LOCAL_SOCKET",
            worker_id="worker_attacker",
            worker_key_id="worker_attacker",
        ).sign(atk_priv, worker_key_id="worker_attacker")

        # 1. The public factory is disabled, including caller-authority attempts.
        with self.assertRaises(ContractValidationError) as ctx:
            Claim.create_verified_real(
                claim_id="CLM-ATK-01",
                subject="target.local",
                predicate="finding",
                receipt=rcpt,
                trust_registry=attacker_reg,
            )
        self.assertIn("UNAUTHORIZED_VERIFIED_REAL", str(ctx.exception))

        with self.assertRaises(ContractValidationError) as ctx:
            Claim(
                claim_id="CLM-ATK-02",
                subject="target.local",
                predicate="finding",
                value="COMPROMISED",
                epistemic_state=EpistemicState.VERIFIED_REAL,
                receipt=rcpt,
                trust_registry=attacker_reg,
            )
        self.assertIn("CALLER_CONTROLLED_AUTHORITY_REJECTED", str(ctx.exception))

        # 2. Passing secret_key into the constructor fails closed immediately.
        with self.assertRaises(ContractValidationError) as ctx:
            Claim(
                claim_id="CLM-ATK-04",
                subject="target.local",
                predicate="finding",
                value="COMPROMISED",
                epistemic_state=EpistemicState.VERIFIED_REAL,
                receipt=rcpt,
                secret_key=b"attacker_chosen_secret_key_32bytes!",
            )
        self.assertIn("CALLER_CONTROLLED_AUTHORITY_REJECTED", str(ctx.exception))

        # 3. The runtime-bound projector rejects a receipt from another registry.
        with self.assertRaises(ContractValidationError) as ctx:
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-ATK-05",
                subject="target.local",
                predicate="finding",
                receipt=rcpt,
            )
        self.assertIn("rejected by authoritative TrustRegistry", str(ctx.exception))

        # 4. ClaimProjector cannot be publicly constructed with or without authority.
        with self.assertRaises(ContractValidationError) as ctx:
            ClaimProjector(trust_registry=attacker_reg)
        self.assertIn("CALLER_CONTROLLED_AUTHORITY_REJECTED", str(ctx.exception))

        with self.assertRaises(ContractValidationError) as ctx:
            ClaimProjector(attacker_reg)
        self.assertIn("CALLER_CONTROLLED_AUTHORITY_REJECTED", str(ctx.exception))

        with self.assertRaises(ContractValidationError) as ctx:
            ClaimProjector(secret_key=b"attacker_secret")
        self.assertIn("CALLER_CONTROLLED_AUTHORITY_REJECTED", str(ctx.exception))

        with self.assertRaises(ContractValidationError) as ctx:
            ClaimProjector()
        self.assertIn("CALLER_CONTROLLED_AUTHORITY_REJECTED", str(ctx.exception))

    def test_operator_key_cannot_sign_worker_receipt(self):
        """Enforce WORKER role: an OPERATOR key cannot sign worker ExecutionReceipts."""
        reg = self._trust_reg
        op_priv = self._op_priv

        results = {"status": "ok"}
        output_hash = ExecutionReceipt.hash_payload(results)
        now = time.time()
        op_receipt = ExecutionReceipt(
            receipt_id="rcpt_op_01",
            job_id="job_op_01",
            capability="cybersecurity.audit",
            target="target.local",
            started_at=now - 1.0,
            completed_at=now,
            input_hash="h_in",
            output_hash=output_hash,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="k_op",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="LOCAL_SOCKET",
            worker_id="operator_root",
            worker_key_id="operator_root",
        ).sign(op_priv, worker_key_id="operator_root")

        # 1. receipt.verify must return False with ROLE_MISMATCH
        valid, reason = op_receipt.verify(reg)
        self.assertFalse(valid)
        self.assertIn("ROLE_MISMATCH", reason)

        # 2. Claim.create_verified_real must fail closed
        with self.assertRaises(ContractValidationError) as ctx:
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-OP-01",
                subject="target.local",
                predicate="status",
                receipt=op_receipt,
            )
        self.assertTrue("ROLE_MISMATCH" in str(ctx.exception) or "rejected by authoritative TrustRegistry" in str(ctx.exception))

    def test_finding2_anti_retargeting_enforcement(self):
        """Finding 2 (Critical): Authentic receipts cannot be retargeted to different subjects or scopes."""
        reg = self._trust_reg
        wrk_priv = self._wrk_priv

        results = {"status": "clean", "score": 100}
        output_hash = ExecutionReceipt.hash_payload(results)
        now = time.time()
        signed_receipt = ExecutionReceipt(
            receipt_id="rcpt_auth_01",
            job_id="job_auth_01",
            capability="tor.check_status",
            target="staging-node.internal",
            started_at=now - 1.0,
            completed_at=now,
            input_hash="h_in",
            output_hash=output_hash,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="k_auth",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="LOCAL_SOCKET",
            worker_id="worker_primary",
            worker_key_id="worker_primary",
        ).sign(wrk_priv, worker_key_id="worker_primary")

        # 1. Retargeting subject to production core must fail closed
        with self.assertRaises(ContractValidationError) as ctx:
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-RETARGET-01",
                subject="prod-financial-core.internal",  # Retargeted!
                predicate="status",
                value="clean",
                receipt=signed_receipt,
            )
        self.assertIn("RETARGETING_DETECTED", str(ctx.exception))

        # 2. Retargeting scope_id to production core must fail closed
        with self.assertRaises(ContractValidationError) as ctx:
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-RETARGET-02",
                subject="staging-node.internal",
                scope_id="prod-financial-core.internal",  # Retargeted!
                predicate="status",
                value="clean",
                receipt=signed_receipt,
            )
        self.assertIn("RETARGETING_DETECTED", str(ctx.exception))

        # 3. Fabricating a non-existent predicate must fail closed
        with self.assertRaises(ContractValidationError) as ctx:
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-RETARGET-03",
                subject="staging-node.internal",
                predicate="unvetted_predicate",  # Not in receipt.results!
                value="clean",
                receipt=signed_receipt,
            )
        self.assertIn("RETARGETING_DETECTED", str(ctx.exception))

        # 4. ClaimProjector automatically and faithfully projects without retargeting
        projector = self._runtime.claim_projector
        projected_claim = projector.project_verified_real(signed_receipt, predicate="status")
        self.assertEqual(projected_claim.subject, "staging-node.internal")
        self.assertEqual(projected_claim.scope_id, "staging-node.internal")
        self.assertEqual(projected_claim.predicate, "status")
        self.assertEqual(projected_claim.value, "clean")
        self.assertEqual(projected_claim.epistemic_state, EpistemicState.VERIFIED_REAL)
        self.assertEqual(projected_claim.evidence_receipt_ids, ("rcpt_auth_01",))


    def test_finding2_claim_content_strictly_bound_to_receipt_results(self):
        """Finding 2: Claim value must be cryptographically and structurally bound to receipt results."""
        reg = self._trust_reg
        wrk_priv = self._wrk_priv

        results = {"status": "safe"}
        output_hash = ExecutionReceipt.hash_payload(results)
        now = time.time()
        unsigned_receipt = ExecutionReceipt(
            receipt_id="rcpt_safe_01",
            job_id="job_sec_01",
            capability="tor.check_status",
            target="target.local",
            started_at=now - 2.0,
            completed_at=now,
            input_hash="h_in",
            output_hash=output_hash,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="k_safe",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="LOCAL_SOCKET",
            worker_id="worker_primary",
            worker_key_id="worker_primary",
        )
        signed_receipt = unsigned_receipt.sign(wrk_priv, worker_key_id="worker_primary")

        # Divergent claim content must fail closed
        with self.assertRaises(ContractValidationError):
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-TAMPER-01",
                subject="target.local",
                predicate="status",
                value={"status": "COMPROMISED"},  # Tampered divergent claim
                receipt=signed_receipt,
            )

        with self.assertRaises(ContractValidationError):
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-TAMPER-02",
                subject="target.local",
                predicate="status",
                value="COMPROMISED",  # Conflicting value
                receipt=signed_receipt,
            )

        # Authentic matching value succeeds
        claim_valid = self._runtime.claim_projector.project_verified_real(
            claim_id="CLM-VALID-01",
            subject="target.local",
            predicate="status",
            value="safe",  # Exactly matches receipt.results["status"]
            receipt=signed_receipt,
        )
        self.assertEqual(claim_valid.value, "safe")
        self.assertEqual(claim_valid.epistemic_state, EpistemicState.VERIFIED_REAL)

        # Automatic derivation when value is omitted also succeeds
        claim_derived = self._runtime.claim_projector.project_verified_real(
            claim_id="CLM-DERIVED-01",
            subject="target.local",
            predicate="status",
            receipt=signed_receipt,
        )
        self.assertEqual(claim_derived.value, "safe")


    def test_finding1_receipt_target_cryptographically_signed(self):
        """Finding 1 (Critical): Tampering receipt target after signing breaks signature verification."""
        from dataclasses import replace
        reg = self._trust_reg
        wrk_priv = self._wrk_priv

        results = {"audit": "clean"}
        now = time.time()
        receipt = ExecutionReceipt(
            receipt_id="rcpt_target_sign_01",
            job_id="job_ts_01",
            capability="security.audit",
            target="staging-service.internal",
            started_at=now - 2.0,
            completed_at=now,
            input_hash="in_hash",
            output_hash=ExecutionReceipt.hash_payload(results),
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="id_key_01",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="LOCAL_SOCKET",
            worker_id="worker_primary",
            worker_key_id="worker_primary",
        ).sign(wrk_priv, worker_key_id="worker_primary")

        # Signature on intact receipt is VALID
        valid, reason = receipt.verify(reg)
        self.assertTrue(valid)
        self.assertEqual(reason, "VALID")

        # Modifying target after signing breaks signature
        tampered_receipt = replace(receipt, target="production-core.internal")
        valid, reason = tampered_receipt.verify(reg)
        self.assertFalse(valid)
        self.assertIn("INVALID_SIGNATURE", reason)

        # Claim creation from tampered receipt fails closed
        with self.assertRaises(ContractValidationError) as ctx:
            self._runtime.claim_projector.project_verified_real(
                claim_id="CLM-RETARGET-TAMPER-01",
                subject="production-core.internal",
                predicate="audit",
                receipt=tampered_receipt,
            )
        self.assertTrue("cryptographic verification rejected" in str(ctx.exception) or "RETARGETING_DETECTED" in str(ctx.exception))

    def test_finding2_cwd_ciph_vault_db_isolated_from_runtime_projector(self):
        """A runtime projector never consults a CWD database or another runtime's authority."""
        import tempfile, shutil

        rogue_dir = tempfile.mkdtemp()
        rogue_runtime = None
        try:
            rogue_db = os.path.join(rogue_dir, "ciph_vault.db")
            from ciph.runtime import CiphRuntime
            rogue_runtime = CiphRuntime(db_path=rogue_db)
            r_priv, _ = rogue_runtime.trust_registry.get_keypair("worker_primary")
            self.assertNotEqual(
                rogue_runtime.claim_projector.authority_fingerprint,
                self._runtime.claim_projector.authority_fingerprint,
            )

            # Receipt signed with rogue worker key is rejected by authoritative registry
            now = time.time()
            results = {"status": "injected"}
            rogue_receipt = ExecutionReceipt(
                receipt_id="rcpt_rogue_01",
                job_id="job_r_01",
                capability="security.audit",
                target="target.local",
                started_at=now - 1.0,
                completed_at=now,
                input_hash="in_hash",
                output_hash=ExecutionReceipt.hash_payload(results),
                exit_code=0,
                outcome=OutcomeCategory.SUCCESS,
                results=results,
                side_effects=[],
                idempotency_key="id_k_r",
                attempt_number=1,
                requested_network_policy=NetworkPolicy.LOCAL_ONLY,
                actual_transport_used="LOCAL_SOCKET",
                worker_id="worker_primary",
                worker_key_id="worker_primary",
            ).sign(r_priv, worker_key_id="worker_primary")

            with self.assertRaises(ContractValidationError) as ctx:
                self._runtime.claim_projector.project_verified_real(
                    claim_id="CLM-ROGUE-01",
                    subject="target.local",
                    predicate="status",
                    receipt=rogue_receipt,
                )
            self.assertIn("rejected by authoritative TrustRegistry", str(ctx.exception))
        finally:
            if rogue_runtime is not None:
                rogue_runtime.close()
            shutil.rmtree(rogue_dir, ignore_errors=True)

    def test_finding3_frozendict_immutable_slots_without_backing_store(self):
        """Finding 3 (High): FrozenDict has empty slots with C-level/descriptor protection against object.__setattr__."""
        fd = FrozenDict({"a": 1, "nested": {"b": 2}})

        # 1. No _data attribute exists
        self.assertFalse(hasattr(fd, "_data"))
        self.assertIsNone(getattr(fd, "_data", None))
        with self.assertRaises(AttributeError):
            _ = fd._data

        # 2. Slots enforcement: empty slots and no __dict__ prevent object.__setattr__ mutation
        self.assertEqual(set(FrozenDict.__slots__), set())
        self.assertFalse(hasattr(fd, "__dict__"))

        # 3. Immutability of descriptors & object.__setattr__ mutation rejection
        with self.assertRaises(AttributeError):
            fd._items = ()
        with self.assertRaises(AttributeError):
            object.__setattr__(fd, "_items", ())
        with self.assertRaises(AttributeError):
            fd._hash = 0
        with self.assertRaises(AttributeError):
            object.__setattr__(fd, "_hash", 0)
        with self.assertRaises(AttributeError):
            fd._data = {}
        with self.assertRaises(AttributeError):
            object.__setattr__(fd, "_data", {})
        with self.assertRaises(AttributeError):
            del fd._items

        # 4. Item immutability
        with self.assertRaises(TypeError):
            fd["a"] = 99
        with self.assertRaises(TypeError):
            dict.__setitem__(fd, "a", 99)

        # 5. Nested immutability
        self.assertIsInstance(fd["nested"], FrozenDict)
        self.assertFalse(hasattr(fd["nested"], "_data"))
        with self.assertRaises(TypeError):
            fd["nested"]["b"] = 100

        # 6. Hash stability
        orig_hash = hash(fd)
        self.assertEqual(hash(fd), orig_hash)
        self.assertEqual(fd, FrozenDict({"nested": {"b": 2}, "a": 1}))
        self.assertEqual(hash(fd), hash(FrozenDict({"nested": {"b": 2}, "a": 1})))

        # 7. Assert _FROZENDICT_STORE does not exist
        import ciph.contracts.base as base_mod
        self.assertFalse(hasattr(base_mod, "_FROZENDICT_STORE"))

        # 8. Deep recursive immutability when initialized via tuples
        fd_tuple = FrozenDict((("items", [1, 2, 3]), ("cfg", {"nested": "val"})))
        self.assertIsInstance(fd_tuple["items"], tuple)
        self.assertIsInstance(fd_tuple["cfg"], FrozenDict)
        self.assertEqual(fd_tuple["items"], (1, 2, 3))
        self.assertEqual(fd_tuple["cfg"]["nested"], "val")

    def test_finding4_zero_global_json_monkey_patching(self):
        """Finding 4 (High-risk regression): json module is not monkey-patched; canonical_json is local."""
        import json as stdlib_json
        import ciph.contracts.base as base_mod

        # 1. json.dumps is the original standard library function
        self.assertEqual(stdlib_json.dumps.__module__, "json")
        self.assertFalse(hasattr(base_mod, "_orig_json_dumps"))
        self.assertFalse(hasattr(base_mod, "_ciph_json_dumps"))
        self.assertFalse(hasattr(base_mod, "_orig_json_default"))
        self.assertFalse(hasattr(base_mod, "_ciph_json_default"))

        # 2. Standard json.dumps on FrozenDict without explicit conversion fails as standard Python types do
        fd = FrozenDict({"test": 123})
        with self.assertRaises(TypeError):
            stdlib_json.dumps(fd)

        # 3. to_dict() and canonical_json() serialize cleanly and deterministically
        self.assertEqual(stdlib_json.dumps(fd.to_dict(), sort_keys=True), '{"test": 123}')
        self.assertEqual(canonical_json(fd), '{"test":123}')
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')


class TestExecutionDAGValidationAndHashing(unittest.TestCase):
    """Enforce DAG cycle rejection, duplicate step rejection, and topological plan hashing."""

    def test_duplicate_step_id_rejected(self):
        s1 = PlanStep(step_id="step_dup", capability="cap1", parameters={})
        s2 = PlanStep(step_id="step_dup", capability="cap2", parameters={})
        dag = ExecutionDAG(plan_id="plan_dup", objective="Test duplicate", steps=[s1, s2])
        with self.assertRaises(ContractValidationError):
            dag.validate()
        with self.assertRaises(ContractValidationError):
            dag.compute_plan_hash()

    def test_self_dependency_rejected(self):
        s1 = PlanStep(step_id="step_self", capability="cap1", parameters={}, depends_on=["step_self"])
        dag = ExecutionDAG(plan_id="plan_self", objective="Test self dep", steps=[s1])
        with self.assertRaises(ContractValidationError):
            dag.validate()
        with self.assertRaises(ContractValidationError):
            dag.compute_plan_hash()

    def test_missing_dependency_rejected(self):
        s1 = PlanStep(step_id="step_1", capability="cap1", parameters={}, depends_on=["step_ghost"])
        dag = ExecutionDAG(plan_id="plan_missing", objective="Test missing", steps=[s1])
        with self.assertRaises(ContractValidationError):
            dag.validate()
        with self.assertRaises(ContractValidationError):
            dag.compute_plan_hash()

    def test_cycle_rejected(self):
        s1 = PlanStep(step_id="s1", capability="cap1", parameters={}, depends_on=["s3"])
        s2 = PlanStep(step_id="s2", capability="cap2", parameters={}, depends_on=["s1"])
        s3 = PlanStep(step_id="s3", capability="cap3", parameters={}, depends_on=["s2"])
        dag = ExecutionDAG(plan_id="plan_cycle", objective="Test cycle", steps=[s1, s2, s3])
        with self.assertRaises(ContractValidationError):
            dag.validate()
        with self.assertRaises(ContractValidationError):
            dag.compute_plan_hash()

    def test_topological_plan_hash_determinism(self):
        s1 = PlanStep(step_id="a_step", capability="cap1", parameters={"x": 1})
        s2 = PlanStep(step_id="b_step", capability="cap2", parameters={"y": 2}, depends_on=["a_step"])
        s3 = PlanStep(step_id="c_step", capability="cap3", parameters={"z": 3}, depends_on=["a_step"])

        # Order 1: [s1, s2, s3]
        dag1 = ExecutionDAG(plan_id="plan_dag", objective="Deterministic test", steps=[s1, s2, s3])
        # Order 2: [s3, s1, s2] (different declaration order)
        dag2 = ExecutionDAG(plan_id="plan_dag", objective="Deterministic test", steps=[s3, s1, s2])

        self.assertEqual(dag1.compute_plan_hash(), dag2.compute_plan_hash())
        self.assertEqual(len(dag1.compute_plan_hash()), 64)

    def test_finding5_dag_plan_hash_binds_execution_and_template_fields(self):
        """Finding 5: ExecutionDAG.compute_plan_hash binds rollback_snapshot_id, is_parameterized_template, and template_signature."""
        s1 = PlanStep(step_id="step_1", capability="cap1", parameters={"x": 1})
        base_dag = ExecutionDAG(
            plan_id="plan_dag_base",
            objective="Base DAG",
            steps=[s1],
            rollback_snapshot_id="snap_v1",
            is_parameterized_template=False,
            template_signature="sig_abc",
        )
        base_hash = base_dag.compute_plan_hash()

        # Modify rollback_snapshot_id -> hash must change
        dag_rollback = ExecutionDAG(
            plan_id="plan_dag_base",
            objective="Base DAG",
            steps=[s1],
            rollback_snapshot_id="snap_v2",
            is_parameterized_template=False,
            template_signature="sig_abc",
        )
        self.assertNotEqual(base_hash, dag_rollback.compute_plan_hash())

        # Modify is_parameterized_template -> hash must change
        dag_template = ExecutionDAG(
            plan_id="plan_dag_base",
            objective="Base DAG",
            steps=[s1],
            rollback_snapshot_id="snap_v1",
            is_parameterized_template=True,
            template_signature="sig_abc",
        )
        self.assertNotEqual(base_hash, dag_template.compute_plan_hash())

        # Modify template_signature -> hash must change
        dag_sig = ExecutionDAG(
            plan_id="plan_dag_base",
            objective="Base DAG",
            steps=[s1],
            rollback_snapshot_id="snap_v1",
            is_parameterized_template=False,
            template_signature="sig_xyz",
        )
        self.assertNotEqual(base_hash, dag_sig.compute_plan_hash())


class TestJobAttemptContract(unittest.TestCase):
    """Test the JobAttempt persistent execution contract."""

    def test_job_attempt_lifecycle(self):
        now = time.time()
        attempt = JobAttempt(
            job_id="JOB-LEASE-01",
            capability="cybersecurity.port_scan",
            attempt_number=1,
            max_retries=3,
            worker_id="daemon_worker_alpha",
            leased_at=now,
            lease_expires_at=now + 60.0,
            idempotency_key="idemp_hash_01",
            plan_id="plan_01",
            step_id="step_01",
        )
        self.assertFalse(attempt.is_lease_expired(now + 30.0))
        self.assertTrue(attempt.is_lease_expired(now + 61.0))
        fp1 = attempt.compute_attempt_fingerprint()
        self.assertEqual(len(fp1), 64)

        d = attempt.to_dict()
        reconstituted = JobAttempt.from_dict(d)
        self.assertEqual(reconstituted.job_id, "JOB-LEASE-01")
        self.assertEqual(reconstituted.compute_attempt_fingerprint(), fp1)


class TestFinding4CrossProcessHashDeterminism(unittest.TestCase):
    """Finding 4: Parameters containing sets/frozensets produce 100% deterministic hashes across processes."""

    def test_set_parameters_cross_process_determinism(self):
        import subprocess, sys, os

        repo_root = os.path.abspath(os.path.dirname(__file__))
        script = """
import sys, os
sys.path.insert(0, REPO_ROOT)
from ciph.contracts import PlanStep
from ciph.workers.receipts import ExecutionReceipt

params = {"tags": {"zebra", "apple", "banana", "cat", "dog", "elephant", "fox"}}
step = PlanStep(step_id="step_test", capability="test.cap", parameters=params)
p_hash = step.compute_params_hash()
r_hash = ExecutionReceipt.hash_payload(params)
print(f"{p_hash}:{r_hash}")
""".replace("REPO_ROOT", repr(repo_root))
        seeds = ["1", "42", "1337", "99999", "54321"]
        outputs = []
        for s in seeds:
            env = dict(os.environ, PYTHONHASHSEED=s)
            out = subprocess.check_output([sys.executable, "-c", script], env=env).decode().strip()
            outputs.append(out)

        # All runs across distinct PYTHONHASHSEED values must yield identical hashes
        self.assertEqual(len(set(outputs)), 1, f"Divergent hashes across seeds: {outputs}")
        self.assertIn(":", outputs[0])
        p_hash, r_hash = outputs[0].split(":")
        self.assertEqual(p_hash, r_hash, "PlanStep.compute_params_hash and ExecutionReceipt.hash_payload diverged")


class TestPhase1CounterexampleHardening(unittest.TestCase):
    """
    Direct counter-probe regression tests for Phase 1 ratification blockers:
    1. Critical: Verification authority cannot be replaced via set_active_runtime or CiphRuntime injection.
    2. Critical: Retirement backdating is strictly blocked during claim minting / admission.
    3. High: Key-ID override signing correctly binds worker_key_id into the signature payload.
    4. High: All receipt fields (artifact_ref, error_message, backtrace, provenance) are cryptographically signed.
    """

    @classmethod
    def setUpClass(cls):
        import tempfile, shutil, os
        from ciph.runtime import CiphRuntime
        from ciph.kernel.crypto_identity import KeyRole
        cls._temp_dir = tempfile.mkdtemp()
        cls._temp_db = os.path.join(cls._temp_dir, "test_hardening_vault.db")
        cls._runtime = CiphRuntime(db_path=cls._temp_db)
        cls._trust_reg = cls._runtime.trust_registry
        cls._op_priv, cls._op_pub = cls._trust_reg.get_keypair("operator_root")
        cls._wrk_priv, cls._wrk_pub = cls._trust_reg.get_keypair("worker_primary")
        cls._wrk_priv2, cls._wrk_pub2 = Ed25519KeyManager.generate_keypair()
        register_payload = (
            f"REGISTER_KEY:worker_secondary:WORKER:{cls._wrk_pub2.hex()}:None"
        ).encode("utf-8")
        register_sig = Ed25519KeyManager.sign(cls._op_priv, register_payload)
        cls._trust_reg.store_keypair(
            "worker_secondary",
            KeyRole.WORKER,
            cls._wrk_priv2,
            cls._wrk_pub2,
            operator_signature=register_sig,
        )

    @classmethod
    def tearDownClass(cls):
        import shutil, os
        cls._runtime.close()
        if os.path.exists(cls._temp_dir):
            shutil.rmtree(cls._temp_dir, ignore_errors=True)

    def test_counterexample1_verification_authority_replacement_rejected(self):
        """1. Runtime authorities are isolated, pinned, and cannot be globally replaced."""
        import ciph.runtime as runtime_module
        import ciph.contracts.epistemic as epistemic_module
        from ciph.runtime import CiphRuntime

        # A: There is no process-global runtime, authority setter, or importable token.
        self.assertFalse(hasattr(runtime_module, "get_active_runtime"))
        self.assertFalse(hasattr(runtime_module, "set_active_runtime"))
        self.assertFalse(hasattr(runtime_module, "_ACTIVE_RUNTIME"))
        self.assertFalse(hasattr(runtime_module, "_RUNTIME_INTERNAL_TOKEN"))
        self.assertFalse(hasattr(epistemic_module, "get_authoritative_trust_registry"))
        self.assertFalse(hasattr(epistemic_module, "set_authoritative_trust_registry"))

        # B: Attempting to pass an external TrustRegistry still fails closed.
        with self.assertRaises(ContractValidationError) as ctx:
            CiphRuntime(trust_registry=object())
        self.assertIn("CALLER_CONTROLLED_AUTHORITY_REJECTED", str(ctx.exception))

        # C: Runtime registries are durably pinned; unsigned enrollment fails.
        self.assertEqual(
            self._trust_reg.pinned_operator_pub_hex,
            self._op_pub.hex(),
        )
        with self.assertRaises(AttributeError):
            self._trust_reg.pinned_operator_pub_hex = None
        with self.assertRaises(AttributeError):
            object.__setattr__(self._trust_reg, "pinned_operator_pub_hex", None)
        _, unsigned_pub = Ed25519KeyManager.generate_keypair()
        self.assertFalse(
            self._trust_reg.register_key(
                "worker_unsigned",
                KeyRole.WORKER,
                unsigned_pub.hex(),
            )
        )

        # D: A second runtime has a distinct projector and cannot affect this runtime.
        temp_dir = tempfile.mkdtemp()
        other_runtime = None
        try:
            other_runtime = CiphRuntime(db_path=os.path.join(temp_dir, "other.db"))
            self.assertIsNot(other_runtime.claim_projector, self._runtime.claim_projector)
            self.assertNotEqual(
                other_runtime.claim_projector.authority_fingerprint,
                self._runtime.claim_projector.authority_fingerprint,
            )
            other_priv, _ = other_runtime.trust_registry.get_keypair("worker_primary")
            results = {"status": "other-authority"}
            now = time.time()
            other_receipt = ExecutionReceipt(
                receipt_id="rcpt_other_authority",
                job_id="job_other_authority",
                capability="tor.check_status",
                target="target.local",
                started_at=now - 1.0,
                completed_at=now,
                input_hash="input",
                output_hash=ExecutionReceipt.hash_payload(results),
                exit_code=0,
                outcome=OutcomeCategory.SUCCESS,
                results=results,
                side_effects=[],
                idempotency_key="other",
                attempt_number=1,
                requested_network_policy=NetworkPolicy.LOCAL_ONLY,
                actual_transport_used="LOCAL_SOCKET",
                worker_id="worker_primary",
                worker_key_id="worker_primary",
            ).sign(other_priv, worker_key_id="worker_primary")

            with self.assertRaises(ContractValidationError):
                self._runtime.claim_projector.project_verified_real(
                    other_receipt,
                    predicate="status",
                )
            other_claim = other_runtime.claim_projector.project_verified_real(
                other_receipt,
                predicate="status",
            )
            self.assertEqual(
                other_claim.authority_fingerprint,
                other_runtime.claim_projector.authority_fingerprint,
            )
        finally:
            if other_runtime is not None:
                other_runtime.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

        # E: A pre-existing operator_root with the wrong role is never adopted.
        malformed_dir = tempfile.mkdtemp()
        try:
            malformed_db = os.path.join(malformed_dir, "malformed.db")
            malformed_registry = TrustRegistry(malformed_db)
            bad_priv, bad_pub = Ed25519KeyManager.generate_keypair()
            malformed_registry.store_keypair(
                "operator_root",
                KeyRole.WORKER,
                bad_priv,
                bad_pub,
            )
            with self.assertRaises(PermissionError):
                CiphRuntime(db_path=malformed_db)
        finally:
            shutil.rmtree(malformed_dir, ignore_errors=True)


    def test_counterexample2_retirement_backdating_rejected_at_claim_admission(self):
        """2. Retirement backdating is strictly rejected when minting VERIFIED_REAL claims."""
        import tempfile, os, shutil
        from ciph.runtime import CiphRuntime
        from ciph.kernel.crypto_identity import KeyRole
        from ciph.contracts.epistemic import Claim, ClaimProjector

        # Create isolated runtime for retirement testing
        temp_dir = tempfile.mkdtemp()
        try:
            temp_db = os.path.join(temp_dir, "retirement_test.db")
            runtime = CiphRuntime(db_path=temp_db)
            reg = runtime.trust_registry
            op_priv, _ = reg.get_keypair("operator_root")
            ret_priv, ret_pub = Ed25519KeyManager.generate_keypair()
            register_payload = f"REGISTER_KEY:worker_retiree:WORKER:{ret_pub.hex()}:None".encode("utf-8")
            register_sig = Ed25519KeyManager.sign(op_priv, register_payload)
            reg.store_keypair(
                "worker_retiree",
                KeyRole.WORKER,
                ret_priv,
                ret_pub,
                operator_signature=register_sig,
            )

            # The receipt predates retirement but admission occurs after retirement.
            completed_at = time.time()
            t_retire = completed_at + 0.001

            # Craft a receipt signed with retired key, backdating completed_at to before retirement
            results = {"status": "success", "score": 99}
            output_hash = ExecutionReceipt.hash_payload(results)
            backdated_receipt = ExecutionReceipt(
                receipt_id="rcpt_backdated_01",
                job_id="job_bdate_01",
                capability="cybersecurity.audit",
                target="audit.target.local",
                started_at=completed_at - 1.0,
                completed_at=completed_at,
                input_hash="hash_in",
                output_hash=output_hash,
                exit_code=0,
                outcome=OutcomeCategory.SUCCESS,
                results=results,
                side_effects=[],
                idempotency_key="idemp_bdate_01",
                attempt_number=1,
                requested_network_policy=NetworkPolicy.LOCAL_ONLY,
                actual_transport_used="LOCAL_SOCKET",
                worker_id="worker_retiree",
                worker_key_id="worker_retiree",
            ).sign(ret_priv, worker_key_id="worker_retiree")

            retire_payload = f"RETIRE_KEY:worker_retiree:{t_retire}".encode("utf-8")
            retire_sig = Ed25519KeyManager.sign(op_priv, retire_payload)
            self.assertTrue(
                reg.retire_key(
                    "worker_retiree",
                    retirement_timestamp=t_retire,
                    operator_signature=retire_sig,
                )
            )
            time.sleep(0.01)

            # Live verification evaluates against current time -> rejects SIGNED_AFTER_RETIREMENT
            live_valid, live_reason = backdated_receipt.verify(reg, current_time=time.time())
            self.assertFalse(live_valid)
            self.assertIn("SIGNED_AFTER_RETIREMENT", live_reason)

            # The runtime-bound projector must also reject the backdated receipt.
            with self.assertRaises(ContractValidationError) as ctx:
                runtime.claim_projector.project_verified_real(
                    claim_id="CLM-BDATE-01",
                    subject="audit.target.local",
                    predicate="status",
                    receipt=backdated_receipt,
                )
            self.assertIn("cryptographic verification rejected", str(ctx.exception))
            self.assertIn("SIGNED_AFTER_RETIREMENT", str(ctx.exception))

            # The same projector path remains fail-closed on repeated admission.
            projector = runtime.claim_projector
            with self.assertRaises(ContractValidationError) as ctx:
                projector.project_verified_real(backdated_receipt, predicate="status")
            self.assertIn("cryptographic verification rejected", str(ctx.exception))

            runtime.close()
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def test_counterexample3_key_id_override_signing(self):
        """3. Supplying worker_key_id to .sign() produces a valid signature payload matching the override key."""
        results = {"status": "ok", "items": 42}
        output_hash = ExecutionReceipt.hash_payload(results)
        now = time.time()

        # Construct receipt with default worker_key_id="worker_primary", but sign with "worker_secondary"
        raw_receipt = ExecutionReceipt(
            receipt_id="rcpt_override_01",
            job_id="job_override_01",
            capability="cybersecurity.audit",
            target="target.secondary",
            started_at=now - 2.0,
            completed_at=now,
            input_hash="in_hash",
            output_hash=output_hash,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=[],
            idempotency_key="idemp_override_01",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="LOCAL_SOCKET",
            worker_id="worker_local",
            worker_key_id="worker_primary",  # Initial default
        )

        signed_override = raw_receipt.sign(self._wrk_priv2, worker_key_id="worker_secondary")
        self.assertEqual(signed_override.worker_key_id, "worker_secondary")

        # Must verify successfully against TrustRegistry
        valid, reason = signed_override.verify(self._trust_reg)
        self.assertTrue(valid, f"Verification failed for worker_key_id override: {reason}")
        self.assertEqual(reason, "VALID")

        # Tampering with worker_key_id invalidates the signature
        tampered_key = replace(signed_override, worker_key_id="worker_primary")
        tampered_valid, tampered_reason = tampered_key.verify(self._trust_reg)
        self.assertFalse(tampered_valid)
        self.assertIn("INVALID_SIGNATURE", tampered_reason)

    def test_counterexample4_all_receipt_fields_cryptographically_signed(self):
        """4. artifact_ref, error_message, backtrace, and provenance are cryptographically bound in signature payload."""
        results = {"check": "passed"}
        output_hash = ExecutionReceipt.hash_payload(results)
        now = time.time()

        signed_full = ExecutionReceipt(
            receipt_id="rcpt_full_01",
            job_id="job_full_01",
            capability="cybersecurity.audit",
            target="target.full",
            started_at=now - 1.0,
            completed_at=now,
            input_hash="in_h",
            output_hash=output_hash,
            exit_code=0,
            outcome=OutcomeCategory.SUCCESS,
            results=results,
            side_effects=["/tmp/test.sock"],
            idempotency_key="idemp_full",
            attempt_number=1,
            requested_network_policy=NetworkPolicy.LOCAL_ONLY,
            actual_transport_used="LOCAL_SOCKET",
            worker_id="worker_primary",
            worker_key_id="worker_primary",
            artifact_ref="blob://hashes/abc12345",
            error_message="diagnostic error message",
            backtrace="Traceback: line 10 in worker.py",
            provenance={"agent": "red_team_scanner", "iteration": 4},
        ).sign(self._wrk_priv, worker_key_id="worker_primary")

        # Original verifies
        valid, reason = signed_full.verify(self._trust_reg)
        self.assertTrue(valid, f"Original receipt verification failed: {reason}")

        # Tampering artifact_ref
        tampered_artifact = replace(signed_full, artifact_ref="blob://hashes/compromised")
        v, r = tampered_artifact.verify(self._trust_reg)
        self.assertFalse(v, "Tampered artifact_ref was accepted")
        self.assertIn("INVALID_SIGNATURE", r)

        # Tampering error_message
        tampered_err = replace(signed_full, error_message="altered error message")
        v, r = tampered_err.verify(self._trust_reg)
        self.assertFalse(v, "Tampered error_message was accepted")
        self.assertIn("INVALID_SIGNATURE", r)

        # Tampering backtrace
        tampered_bt = replace(signed_full, backtrace="modified backtrace trace")
        v, r = tampered_bt.verify(self._trust_reg)
        self.assertFalse(v, "Tampered backtrace was accepted")
        self.assertIn("INVALID_SIGNATURE", r)

        # Tampering provenance
        tampered_prov = replace(signed_full, provenance={"agent": "attacker", "iteration": 999})
        v, r = tampered_prov.verify(self._trust_reg)
        self.assertFalse(v, "Tampered provenance was accepted")
        self.assertIn("INVALID_SIGNATURE", r)


if __name__ == "__main__":
    unittest.main()
