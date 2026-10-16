
"""
ciph.kernel.scope_grant_store - durable canonical scope authority.

The durable lane persisted the NAME of authority without the authority itself: an authorization row
carried `scope_grant_id` while the ScopeGrant body survived only inside the ExecutionToken. This
store makes the existing authority object durable - it adds no authorization engine, and it decides
nothing about targets. Coverage remains `ScopeGrant.is_target_permitted`.

THE BINDING
    same scope_grant_id + byte-identical canonical body  -> idempotent
    same scope_grant_id + different canonical body       -> HARD CONFLICT

The digest column is evidence and an index. The canonical bytes are what the ID binds to, so
resolution recomputes the digest from the stored body instead of trusting the column.

RESOLUTION IS NOT A FALLBACK
    "NONE"                      -> NO_GRANT
    unknown real id             -> NOT_FOUND
    corrupt / unverifiable body -> UNVERIFIABLE
    valid body                  -> RESOLVED

There is deliberately no fallback to `token.scope_payload_json`. Reading the demoted artifact would
defeat the migration, and historical token-carried scope is never promoted here retroactively.
"""

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Protocol, runtime_checkable

from ciph.contracts.base import ContractValidationError
from ciph.contracts.grants import ScopeGrant

NO_GRANT_SENTINEL = "NONE"


class ScopeGrantResolution(str, Enum):
    RESOLVED = "RESOLVED"
    NOT_FOUND = "NOT_FOUND"
    UNVERIFIABLE = "UNVERIFIABLE"
    NO_GRANT = "NO_GRANT"


class ScopeGrantReferenceRefused(Exception):
    """
    A durable reference to this scope may not be created.

    Raised when the canonical store cannot prove the reference is safe - a missing row, an
    unverifiable body, or a resolved object that is not the exact authority the caller holds.
    """

    def __init__(self, scope_grant_id: str, outcome: "ScopeGrantResolution", detail: str = ""):
        self.scope_grant_id = scope_grant_id
        self.outcome = outcome
        self.detail = detail
        super().__init__(f"SCOPE_REFERENCE_REFUSED: {scope_grant_id} ({outcome.value})"
                         + (f": {detail}" if detail else ""))


class ScopeGrantConflict(Exception):
    """The same scope_grant_id was presented with a different canonical body."""

    def __init__(self, scope_grant_id: str):
        self.scope_grant_id = scope_grant_id
        super().__init__(f"SCOPE_GRANT_IDENTITY_CONFLICT: {scope_grant_id}")


@dataclass(frozen=True)
class ResolvedScopeGrant:
    """The outcome of resolving a durable scope reference."""

    outcome: ScopeGrantResolution
    scope_grant_id: Optional[str] = None
    grant: Optional[ScopeGrant] = None
    detail: str = ""

    @property
    def resolvable(self) -> bool:
        return self.outcome is ScopeGrantResolution.RESOLVED


@runtime_checkable
class ScopeGrantResolver(Protocol):
    """
    The narrow seam `DAGExecutor` may depend on.

    Exactly one method returning exactly the four outcomes. No target checks, no policy decisions,
    and no fallback: target coverage stays in `ExecutionGateway`, and the canonical store is the
    only authority source. Satisfied structurally by `ScopeGrantStore`.
    """

    def resolve(self, scope_grant_id: Optional[str]) -> ResolvedScopeGrant:
        ...


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class ScopeGrantStore:
    """Durable, immutable ID -> canonical ScopeGrant body binding."""

    def __init__(self, db_path: str = "ciph_vault.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA busy_timeout = 10000;")
        conn.row_factory = sqlite3.Row
        conn.isolation_level = None
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scope_grants (
                    scope_grant_id TEXT PRIMARY KEY,
                    canonical_body BLOB NOT NULL,
                    body_digest TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL
                );
            """)

    def persist(self, grant: ScopeGrant) -> bool:
        """
        Persist the complete canonical grant. Returns True when newly stored, False when the exact
        same canonical body was already present. Raises on an identity conflict.
        """
        scope_grant_id = str(grant.scope_id)
        body = grant.compute_canonical_payload()
        digest = _digest(body)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT canonical_body, body_digest FROM scope_grants WHERE scope_grant_id = ?;",
                (scope_grant_id,),
            ).fetchone()
            if row is not None:
                conn.execute("ROLLBACK")
                if bytes(row["canonical_body"]) != body or row["body_digest"] != digest:
                    raise ScopeGrantConflict(scope_grant_id)
                return False
            conn.execute(
                "INSERT INTO scope_grants (scope_grant_id, canonical_body, body_digest, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?);",
                (scope_grant_id, body, digest, time.time(),
                 float(grant.valid_until) if grant.valid_until else None),
            )
            conn.execute("COMMIT")
            return True

    def persist_and_verify(self, grant: ScopeGrant) -> ResolvedScopeGrant:
        """
        Persist the exact grant, then PROVE the durable reference is safe before anyone writes it.

        Persistence succeeding is not sufficient. An existing row whose canonical body is correct but
        whose stored digest is corrupted is idempotent for `persist` yet UNVERIFIABLE on `resolve`,
        so treating persistence as proof would let a NEW durable reference bless pre-existing
        corruption. The reference law is therefore:

            NEW durable reference to G
            => G was persisted
            AND G resolves cleanly
            AND the resolved object is the exact authority expected
        """
        self.persist(grant)
        resolved = self.resolve(str(grant.scope_id))
        if not resolved.resolvable:
            raise ScopeGrantReferenceRefused(
                str(grant.scope_id), resolved.outcome, resolved.detail
            )
        if resolved.grant.compute_canonical_payload() != grant.compute_canonical_payload():
            raise ScopeGrantReferenceRefused(
                str(grant.scope_id), resolved.outcome, "RESOLVED_IDENTITY_MISMATCH"
            )
        return resolved

    def resolve(self, scope_grant_id: Optional[str]) -> ResolvedScopeGrant:
        """Resolve a durable reference to the exact canonical grant, or fail closed."""
        if scope_grant_id is None or str(scope_grant_id).strip() in ("", NO_GRANT_SENTINEL):
            return ResolvedScopeGrant(ScopeGrantResolution.NO_GRANT)

        reference = str(scope_grant_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT canonical_body, body_digest FROM scope_grants WHERE scope_grant_id = ?;",
                (reference,),
            ).fetchone()
        if row is None:
            return ResolvedScopeGrant(ScopeGrantResolution.NOT_FOUND, reference)

        body = bytes(row["canonical_body"])
        if _digest(body) != row["body_digest"]:
            return ResolvedScopeGrant(
                ScopeGrantResolution.UNVERIFIABLE, reference, detail="BODY_DIGEST_MISMATCH"
            )
        try:
            grant = ScopeGrant.from_dict(json.loads(body.decode("utf-8")))
        except (ContractValidationError, ValueError, KeyError, TypeError) as error:
            return ResolvedScopeGrant(
                ScopeGrantResolution.UNVERIFIABLE, reference, detail=f"UNRECONSTITUTABLE:{error}"
            )
        if grant.compute_canonical_payload() != body:
            return ResolvedScopeGrant(
                ScopeGrantResolution.UNVERIFIABLE, reference, detail="CANONICAL_BODY_DRIFT"
            )
        return ResolvedScopeGrant(ScopeGrantResolution.RESOLVED, reference, grant=grant)
