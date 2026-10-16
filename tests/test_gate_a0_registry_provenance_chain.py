"""
Gate A0 closure test - closing the ◐ on REGISTRY SIGNED PERMIT PROVENANCE.

Three things were implemented but unverified: `terminalize()` recovery idempotency, the divergent
terminal-evidence incident, and the full P -> A -> R three-digest chain on the registry route.
This file covers all three, and corrupts each digest leg independently so the chain is shown to be
load-bearing rather than decorative.
"""

import os
import tempfile
import time
import unittest

from ciph.contracts.enums import NetworkPolicy, OutcomeCategory
from ciph.kernel.authorization_provenance import (
    STATUS_VALID,
    AuthorizationProvenanceVerifier,
    create_governed_claims,
)
from ciph.kernel.execution_authority import (
    ExecutionAuthority,
    ExecutionPermitVerifier,
)
from ciph.kernel.execution_gateway import (
    ExecutionGateway,
    GovernedExecutionContext,
    GuardedExecutor,
    TerminalIntegrityIncident,
)
from ciph.kernel.permit_store import (
    OUTCOME_VALID_AT_TIME,
    ExecutionPermitStore,
    STATE_CLAIMED,
    STATE_CONSUMED,
)
from ciph.kernel.target_identity import register_canonicalizer
from ciph.workers.receipts import ExecutionReceipt

try:
    @register_canonicalizer("test.provenance_chain.v1", "1")
    def _canon(raw):
        return raw.strip().lower().encode("utf-8")
except Exception:
    pass


class _Manifest:
    name = "test.chain_capability"
    target_canonicalizer_id = "test.provenance_chain.v1"
    target_canonicalizer_version = "1"

    def identity(self):
        from ciph.kernel.manifest_identity import ManifestIdentity
        return ManifestIdentity(2, "FIXTURE")


class _Capability:
    def __init__(self):
        self.manifest = _Manifest()
        self.calls = 0

    def execute(self, params, context=None):
        self.calls += 1
        return {"ok": True}


class _RegistryView:
    def __init__(self, capabilities):
        self._capabilities = capabilities

    def get(self, name):
        return self._capabilities.get(name)

    def list_names(self):
        return list(self._capabilities)


class _ScopeGrant:
    scope_id = "scope-chain"
    valid_until = None

    def is_expired(self, now=None):
        return False

    def is_target_permitted(self, target):
        return target == "repo-A"


class _History:
    def authority_at(self, permit_id, moment):
        return type("External", (), {
            "authorization_grant_at_T": OUTCOME_VALID_AT_TIME,
            "authorization_epoch_at_T": OUTCOME_VALID_AT_TIME,
            "mission_envelope_at_T": OUTCOME_VALID_AT_TIME,
            "epistemic_leases_at_T": OUTCOME_VALID_AT_TIME,
        })()


def _receipt(attempt_id, **overrides):
    base = dict(
        receipt_id=f"rcpt_{attempt_id}",
        job_id="JOB-1",
        capability="test.chain_capability",
        target="repo-A",
        started_at=time.time(),
        completed_at=time.time() + 1,
        input_hash="ih",
        output_hash=ExecutionReceipt.hash_payload({"ok": True}),
        exit_code=0,
        outcome=OutcomeCategory.SUCCESS,
        results={"ok": True},
        side_effects=[],
        idempotency_key=f"idem-{attempt_id}",
        attempt_number=1,
        requested_network_policy=NetworkPolicy.OFFLINE_ONLY,
        actual_transport_used="NONE",
        worker_id="registry",
        # Pinned so two constructions of the "same" receipt are byte-identical: the default
        # terminal-evidence comparison is deliberately strict, and a per-instance environment
        # fingerprint would otherwise read as divergence rather than as noise.
        environment_fingerprint="test-env-fixed",
    )
    base.update(overrides)
    return ExecutionReceipt(**base)


class RegistryProvenanceChainTests(unittest.TestCase):

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(prefix="test_chain_", suffix=".db")
        os.close(handle)
        self.store = ExecutionPermitStore(db_path=self.db_path)
        self.authority, public = ExecutionAuthority.generate()
        self.verifier = ExecutionPermitVerifier(public, key_id=self.authority.key_id)
        self.gateway = ExecutionGateway(
            registry=None, permit_ttl_seconds=60.0,
            issuer=self.authority, verifier=self.verifier,
        )
        self.capability = _Capability()
        self.registry = _RegistryView({self.capability.manifest.name: self.capability})

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except OSError:
                pass

    def _terminal_receipt(self, claim):
        """
        The terminal receipt for an attempt, deterministic from the claim.

        Deterministic matters: recovery calls the factory again, and a receipt that differs only by
        wall-clock would read as divergent terminal evidence rather than as the same one.
        """
        return _receipt(
            claim.execution_attempt_id,
            started_at=claim.claimed_at,
            completed_at=claim.claimed_at + 1,
        )

    def test_recovery_survives_differing_non_semantic_metadata(self):
        """
        Recovery may happen on a different machine by design. A receipt reconstructed where the
        environment fingerprint (or receipt id) differs still describes the same terminal fact,
        so it must reconcile rather than raise an incident. Receipt *integrity* remains
        byte-strict; only terminal identity is semantic.
        """
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        executor = GuardedExecutor(self.gateway, permit_store=self.store)

        persisted = self._terminal_receipt(claim)
        reconstructed = _receipt(
            claim.execution_attempt_id,
            started_at=claim.claimed_at,
            completed_at=claim.claimed_at + 1,
            receipt_id="rcpt_rebuilt_elsewhere",
            environment_fingerprint="a-completely-different-host",
        )
        self.assertNotEqual(
            persisted.compute_signature_payload(), reconstructed.compute_signature_payload()
        )
        self.assertEqual(
            persisted.terminal_identity_digest(), reconstructed.terminal_identity_digest()
        )

        recovered = executor.terminalize(
            permit, claim,
            receipt_factory=lambda c: reconstructed,
            receipt_sink=lambda r: None,
            existing_terminal_lookup=lambda attempt_id: persisted,
        )
        self.assertIs(recovered, persisted)
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CONSUMED)

    def test_recovery_still_rejects_a_genuinely_different_terminal_fact(self):
        """Semantic identity is narrower, not weaker: a different outcome still conflicts."""
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        executor = GuardedExecutor(self.gateway, permit_store=self.store)

        persisted = self._terminal_receipt(claim)
        different = _receipt(
            claim.execution_attempt_id,
            started_at=claim.claimed_at,
            completed_at=claim.claimed_at + 1,
            results={"ok": False},
            exit_code=3,
        )
        self.assertNotEqual(
            persisted.terminal_identity_digest(), different.terminal_identity_digest()
        )
        with self.assertRaises(TerminalIntegrityIncident):
            executor.terminalize(
                permit, claim,
                receipt_factory=lambda c: different,
                receipt_sink=lambda r: None,
                existing_terminal_lookup=lambda attempt_id: persisted,
            )
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CLAIMED)

    def test_environment_fingerprint_stays_in_the_signed_payload(self):
        """It is excluded from terminal identity, not from the receipt."""
        receipt = self._terminal_receipt_for_isolated_check()
        self.assertIn("environment_fingerprint", receipt.compute_signature_payload())

    def _terminal_receipt_for_isolated_check(self):
        envelope = self._run_governed()
        return self._terminal_receipt(envelope["claim"])

    def _run_governed(self):
        from ciph.capabilities.registry import CapabilityRegistry
        governed = GovernedExecutionContext(
            gateway=self.gateway, permit_store=self.store,
            scope_grant=_ScopeGrant(), target="repo-A", route="registry",
        )
        return CapabilityRegistry.dispatch(
            self.registry, "test.chain_capability", {"target": "repo-A"},
            {"execution_authority": governed},
        )

    # ------------------------------------------------- terminalize recovery

    def test_terminalize_after_crash_between_persist_and_consume(self):
        """
        receipt persisted, process dies before CONSUMED, recovery re-runs terminalize:
        the same terminal receipt advances CLAIMED to CONSUMED and does not duplicate.
        """
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        executor = GuardedExecutor(self.gateway, permit_store=self.store)
        typed = []

        def _factory(c):
            return self._terminal_receipt(c)

        def _lookup(attempt_id):
            return typed[0] if typed else None

        typed.append(_factory(claim))
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CLAIMED)

        recovered = executor.terminalize(
            permit, claim, receipt_factory=_factory,
            receipt_sink=lambda r: None,           # already durable: no second write
            existing_terminal_lookup=_lookup,
        )
        self.assertIs(recovered, typed[0])
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CONSUMED)

    def test_divergent_terminal_evidence_is_an_integrity_incident(self):
        """A different terminal receipt for the same attempt is never last-writer-wins."""
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        executor = GuardedExecutor(self.gateway, permit_store=self.store)

        first = self._terminal_receipt(claim)
        divergent = _receipt(claim.execution_attempt_id, output_hash="different", results={"ok": False})
        written = []

        with self.assertRaises(TerminalIntegrityIncident):
            executor.terminalize(
                permit, claim,
                receipt_factory=lambda c: divergent,
                receipt_sink=written.append,
                existing_terminal_lookup=lambda attempt_id: first,
            )
        self.assertEqual(written, [], "a divergent receipt was written anyway")
        self.assertEqual(
            self.store.state_of(permit.payload.permit_id), STATE_CLAIMED,
            "an integrity incident must not advance the permit",
        )

    def test_normal_terminalize_persists_then_consumes(self):
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        executor = GuardedExecutor(self.gateway, permit_store=self.store)
        written = []
        executor.terminalize(
            permit, claim,
            receipt_factory=lambda c: self._terminal_receipt(c),
            receipt_sink=written.append,
        )
        self.assertEqual(len(written), 1)
        self.assertEqual(self.store.state_of(permit.payload.permit_id), STATE_CONSUMED)

    # --------------------------------------------- P -> A -> R three-digest chain

    def _verify_chain(self, permit, claim, receipt):
        claims = receipt.governed_claims()
        self.assertIsNotNone(claims, "receipt carries no governed lineage")
        verifier = AuthorizationProvenanceVerifier(self.store, authority_history=_History())
        return verifier.verify(claims, receipt.execution_facts(), permit)

    def test_registry_route_yields_a_valid_three_digest_chain(self):
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        receipt = self._terminal_receipt(claim).attach_governed_claims(claims)

        record = self.store.describe(permit.payload.permit_id)
        self.assertEqual(permit.permit_digest(), record["permit_digest"])
        self.assertEqual(permit.permit_digest(), receipt.governed_claims().execution_permit_digest)

        result = self._verify_chain(permit, claim, receipt)
        self.assertEqual(result.descent, "DESCENT_VALID")
        self.assertEqual(result.status, STATUS_VALID, result.contradictions)

    def test_corrupting_the_receipt_digest_breaks_the_chain(self):
        from ciph.kernel.authorization_provenance import GovernedReceiptClaims, PROVENANCE_PERMIT_V1
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        forged = GovernedReceiptClaims(
            authorization_provenance=PROVENANCE_PERMIT_V1,
            execution_permit_id=permit.payload.permit_id,
            execution_permit_digest="00" * 32,
            execution_attempt_id=claim.execution_attempt_id,
        )
        receipt = self._terminal_receipt(claim).attach_governed_claims(forged)
        result = self._verify_chain(permit, claim, receipt)
        self.assertEqual(result.status, "INVALID")
        self.assertIn("receipt_digest_mismatch", result.contradictions)

    def test_corrupting_the_stored_digest_breaks_the_chain(self):
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        receipt = self._terminal_receipt(claim).attach_governed_claims(claims)

        with self.store._connect() as conn:
            conn.execute(
                "UPDATE execution_permits SET permit_digest = ? WHERE permit_id = ?;",
                ("ab" * 32, permit.payload.permit_id),
            )

        result = self._verify_chain(permit, claim, receipt)
        self.assertEqual(result.status, "INVALID")
        self.assertIn("permit_store_digest_not_recomputable", result.contradictions)

    def test_swapping_the_permit_artifact_breaks_the_chain(self):
        """A receipt citing a valid permit that is not its permit."""
        envelope = self._run_governed()
        permit, claim = envelope["permit"], envelope["claim"]
        claims = create_governed_claims(self.store, claim.execution_attempt_id)
        receipt = self._terminal_receipt(claim).attach_governed_claims(claims)

        other = self._run_governed()["permit"]
        result = AuthorizationProvenanceVerifier(
            self.store, authority_history=_History()
        ).verify(receipt.governed_claims(), receipt.execution_facts(), other)
        self.assertEqual(result.status, "INVALID")
        self.assertIn("permit_store_digest_not_recomputable", result.contradictions)


if __name__ == "__main__":
    unittest.main()
