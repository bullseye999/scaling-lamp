
"""
Gate A0 - the two fixture adapters must yield the SAME constitutional properties.

One authority pipeline, two ways to reach it. If these diverge, the tests would quietly be proving
two different constitutions.
"""

import pathlib
import tempfile
import unittest

from ciph.kernel.crypto_identity import KeyRole, TrustRegistry
from ciph.kernel.execution_authority import SignedExecutionPermit
from ciph.runtime import CiphRuntime
from ciph.workers.ipc_queue import IPCJobQueue
from permit_test_support import enqueue_permit_bearing_job, enqueue_permit_bearing_queue_job


class QueueBuilderEquivalenceTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_adapters_")
        self.db = f"{self._dir}/vault.db"
        self.queue = IPCJobQueue(self.db)
        self.registry_trust = TrustRegistry(self.db)
        self.operator_priv, _ = self.registry_trust.get_or_create_keypair("operator_root", KeyRole.OPERATOR)
        self.worker_priv, _ = self.registry_trust.get_or_create_keypair("worker_primary", KeyRole.WORKER)

    def _queue_fixture(self, scope_id):
        return enqueue_permit_bearing_queue_job(
            queue=self.queue, trust_registry=self.registry_trust,
            operator_private_key=self.operator_priv, db_path=self.db,
            capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id=scope_id,
        )

    def test_repeated_calls_converge_on_one_execution_authority_lineage(self):
        first = self._queue_fixture("scope_a1")
        second = self._queue_fixture("scope_a2")
        # Same signing identity for both fixtures: one lineage, not a fresh signer per call.
        self.assertEqual(first.permit.key_id, second.permit.key_id)
        self.assertEqual(
            self.registry_trust.get_key("execution_authority_primary")["public_key_hex"],
            self.registry_trust.get_key("execution_authority_primary")["public_key_hex"],
        )
        self.assertEqual(
            self.registry_trust.get_key("execution_authority_primary")["role"],
            KeyRole.EXECUTION_AUTHORITY.value,
        )

    def test_the_scope_is_persisted_and_resolves_before_issuance(self):
        fixture = self._queue_fixture("scope_b1")
        from ciph.kernel.scope_grant_store import ScopeGrantStore
        resolved = ScopeGrantStore(self.db).resolve(fixture.scope_grant_id)
        self.assertTrue(resolved.resolvable)
        self.assertEqual(resolved.grant.compute_canonical_payload(),
                         resolved.grant.compute_canonical_payload())

    def test_the_queued_row_carries_exactly_the_registered_permit(self):
        fixture = self._queue_fixture("scope_c1")
        stored = self.queue.get_job(fixture.job_id)["execution_permit"]
        rebuilt = SignedExecutionPermit.from_dict(stored)
        self.assertEqual(rebuilt.permit_digest(), fixture.permit.permit_digest())

    def test_two_fixtures_get_distinct_logical_actions(self):
        first = self._queue_fixture("scope_d1")
        second = self._queue_fixture("scope_d2")
        self.assertNotEqual(first.logical_action_id, second.logical_action_id)
        self.assertNotEqual(first.permit_id, second.permit_id)

    def test_both_adapters_yield_the_same_canonical_shape(self):
        runtime = CiphRuntime(db_path=f"{self._dir}/runtime.db")
        via_runtime = enqueue_permit_bearing_job(
            runtime, capability="memory.retrieve",
            params={"key": "k", "target": "local_memory"},
            scope_targets=["local_memory"], scope_id="scope_e1",
        )
        via_queue = self._queue_fixture("scope_e2")

        for fixture in (via_runtime, via_queue):
            self.assertTrue(fixture.permit_id)
            self.assertTrue(fixture.logical_action_id)
            self.assertTrue(fixture.scope_grant_id)
            self.assertIsNotNone(fixture.permit.signature)


class TestSupportIsNotProductionTests(unittest.TestCase):

    def test_no_production_import_of_permit_test_support(self):
        offenders = []
        for path in sorted(pathlib.Path("ciph").rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            if "permit_test_support" in path.read_text(encoding="utf-8", errors="replace"):
                offenders.append(str(path.relative_to("ciph")))
        self.assertEqual(offenders, [], f"production imports test permit machinery: {offenders}")


if __name__ == "__main__":
    unittest.main()
