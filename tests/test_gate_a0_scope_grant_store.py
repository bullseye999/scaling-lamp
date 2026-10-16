
"""
Gate A0 closure test - S2.3b-SCOPE.1/SCOPE.2: canonical durable scope authority.

Durable *references* to scope existed; durable *scope* did not. These specimens pin the binding and
the fail-closed resolution that make the reference real without turning the token artifact into the
canonical source.
"""

import sqlite3
import tempfile
import unittest

from ciph.contracts.enums import ScopeType
from ciph.contracts.grants import ScopeGrant
from ciph.kernel.scope_grant_store import (
    ScopeGrantConflict,
    ScopeGrantResolution,
    ScopeGrantStore,
)


def _scope(scope_id="scope_1", targets=("local_memory",)):
    return ScopeGrant(
        scope_id=scope_id, scope_type=ScopeType.LOCAL_SYSTEM, allowed_targets=list(targets)
    )


class ScopeGrantStoreTests(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_scope_")
        self.db = f"{self._dir}/vault.db"
        self.store = ScopeGrantStore(self.db)

    def _row(self, scope_grant_id):
        with sqlite3.connect(self.db) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute(
                "SELECT * FROM scope_grants WHERE scope_grant_id = ?;", (scope_grant_id,)
            ).fetchone()

    def _rows(self):
        with sqlite3.connect(self.db) as conn:
            return conn.execute("SELECT COUNT(*) FROM scope_grants;").fetchone()[0]

    # ---------------------------------------------------------------- binding

    def test_persisting_the_same_body_twice_is_idempotent(self):
        grant = _scope()

        self.assertTrue(self.store.persist(grant))
        self.assertFalse(self.store.persist(grant))
        self.assertEqual(self._rows(), 1)

    def test_a_reconstructed_equivalent_grant_is_still_a_conflict(self):
        """
        The binding is on canonical BYTES, not on semantics. `created_at` participates in the
        canonical body, so a re-built "equivalent" grant is a different body and must conflict.
        Producers persist the grant object they hold; they do not re-synthesise it.
        """
        self.store.persist(_scope())
        with self.assertRaises(ScopeGrantConflict):
            self.store.persist(_scope())

    def test_the_same_id_with_a_different_body_is_a_hard_conflict(self):
        self.store.persist(_scope(targets=("local_memory",)))
        with self.assertRaises(ScopeGrantConflict):
            self.store.persist(_scope(targets=("local_memory", "other_target")))
        self.assertEqual(self._rows(), 1)

    # ---------------------------------------------------------------- resolution

    def test_a_persisted_grant_resolves_to_its_exact_canonical_body(self):
        grant = _scope()
        self.store.persist(grant)

        resolved = self.store.resolve("scope_1")

        self.assertTrue(resolved.resolvable)
        self.assertEqual(resolved.grant.compute_canonical_payload(), grant.compute_canonical_payload())

    def test_a_missing_reference_is_not_found(self):
        self.assertEqual(self.store.resolve("scope_absent").outcome, ScopeGrantResolution.NOT_FOUND)

    def test_the_none_sentinel_is_no_grant_not_a_lookup(self):
        self.assertEqual(self.store.resolve("NONE").outcome, ScopeGrantResolution.NO_GRANT)
        self.assertEqual(self.store.resolve(None).outcome, ScopeGrantResolution.NO_GRANT)
        self.assertEqual(self.store.resolve("").outcome, ScopeGrantResolution.NO_GRANT)

    def test_a_tampered_digest_is_unverifiable_not_trusted(self):
        self.store.persist(_scope())
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE scope_grants SET body_digest = ? WHERE scope_grant_id = 'scope_1';", ("0" * 64,))

        self.assertEqual(
            self.store.resolve("scope_1").outcome, ScopeGrantResolution.UNVERIFIABLE
        )

    def test_a_tampered_body_is_unverifiable(self):
        self.store.persist(_scope())
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE scope_grants SET canonical_body = ? WHERE scope_grant_id = 'scope_1';", (b"{not json",))

        self.assertEqual(
            self.store.resolve("scope_1").outcome, ScopeGrantResolution.UNVERIFIABLE
        )

    def test_a_restart_resolves_the_same_bytes(self):
        grant = _scope()
        self.store.persist(grant)

        restarted = ScopeGrantStore(self.db)
        resolved = restarted.resolve("scope_1")

        self.assertTrue(resolved.resolvable)
        self.assertEqual(
            resolved.grant.compute_canonical_payload(), self._row("scope_1")["canonical_body"]
        )

    def test_resolution_never_consults_a_token_artifact(self):
        """The authority direction must be canonical store first, never the demoted artifact."""
        import ast
        import pathlib
        source = pathlib.Path("ciph/kernel/scope_grant_store.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        code_only = "\n".join(
            ast.get_source_segment(source, node) or ""
            for node in tree.body
            if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
        )
        self.assertNotIn("scope_payload_json", code_only)
        self.assertNotIn("ExecutionToken", code_only)
        self.assertNotIn("crypto_identity", code_only)


class ScopeGrantResolverSeamTests(unittest.TestCase):
    """SCOPE.3: one narrow seam, and byte-exact durability of the canonical body."""

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_seam_")
        self.db = f"{self._dir}/vault.db"
        self.store = ScopeGrantStore(self.db)

    def _row_body(self, scope_grant_id):
        with sqlite3.connect(self.db) as conn:
            conn.row_factory = sqlite3.Row
            return bytes(conn.execute(
                "SELECT canonical_body FROM scope_grants WHERE scope_grant_id = ?;",
                (scope_grant_id,),
            ).fetchone()["canonical_body"])

    def test_the_resolver_seam_requires_only_resolve(self):
        from ciph.kernel.scope_grant_store import ScopeGrantResolver

        class _OnlyResolve:
            def resolve(self, scope_grant_id):
                return None

        # A consumer implementing nothing but `resolve` satisfies the seam, so no target policy or
        # fallback behaviour can leak into the interface the planner depends on.
        self.assertIsInstance(_OnlyResolve(), ScopeGrantResolver)
        self.assertIsInstance(self.store, ScopeGrantResolver)

    def test_a_resolved_grant_round_trips_byte_exactly(self):
        """
        `created_at` participates in the canonical body, so serialization precision is
        constitutionally significant: a resolve -> to_dict -> reconstruct cycle must reproduce the
        stored bytes exactly, with no float renormalisation.
        """
        grant = ScopeGrant(
            scope_id="scope_precision",
            scope_type=ScopeType.LOCAL_SYSTEM,
            allowed_targets=["local_memory"],
            created_at=1_700_000_000.1234567,
        )
        self.store.persist(grant)

        resolved = self.store.resolve("scope_precision")
        rebuilt = ScopeGrant.from_dict(resolved.grant.to_dict())

        self.assertEqual(rebuilt.compute_canonical_payload(), self._row_body("scope_precision"))
        self.assertEqual(rebuilt.created_at, grant.created_at)


class ScopeReferenceLawTests(unittest.TestCase):
    """SCOPE.4 reference law: persistence is not proof; resolution is."""

    def setUp(self):
        self._dir = tempfile.mkdtemp(prefix="ciph_ref_")
        self.db = f"{self._dir}/vault.db"
        self.store = ScopeGrantStore(self.db)

    def _corrupt_digest(self, scope_grant_id):
        with sqlite3.connect(self.db) as conn:
            conn.execute(
                "UPDATE scope_grants SET body_digest = ? WHERE scope_grant_id = ?;",
                ("0" * 64, scope_grant_id),
            )

    def test_a_healthy_grant_persists_and_verifies(self):
        grant = _scope("scope_ok")
        resolved = self.store.persist_and_verify(grant)
        self.assertTrue(resolved.resolvable)
        self.assertEqual(
            resolved.grant.compute_canonical_payload(), grant.compute_canonical_payload()
        )

    def test_an_existing_corrupted_row_refuses_a_new_reference(self):
        """
        The load-bearing edge: `persist` is idempotent for a correct body even when the stored
        digest is corrupt, so persistence alone would let a NEW durable reference bless pre-existing
        corruption. Resolution must be required at the point authority becomes referential.
        """
        from ciph.kernel.scope_grant_store import ScopeGrantReferenceRefused

        grant = _scope("scope_corrupt")
        self.store.persist(grant)
        self._corrupt_digest("scope_corrupt")

        # Persistence itself already refuses to bless the corrupted row rather than reporting
        # idempotent ...
        with self.assertRaises(ScopeGrantConflict):
            self.store.persist(grant)
        # ... and the reference law refuses too. It surfaces the conflict rather than a resolution
        # outcome, because persistence is the stricter first check; either way the reference is
        # refused, which is the property this specimen exists to pin.
        with self.assertRaises((ScopeGrantConflict, ScopeGrantReferenceRefused)):
            self.store.persist_and_verify(grant)

if __name__ == "__main__":
    unittest.main()
