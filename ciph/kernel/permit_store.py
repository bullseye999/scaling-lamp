"""
ciph.kernel.permit_store - durable operational truth for permit usability.

Step 4 of the throat plan. Decision of record: EXECUTION PERMIT V1.

THE TABLE IS NOT A SECOND AUTHORITY
The signature proves *who issued* the permit. This table proves *whether it is still usable*.
Both must agree, and neither substitutes for the other. The store never mints anything.

WHY `CLAIMED` IS IN V1
With a single ISSUED -> CONSUMED transition there is a hole: consume the permit, die before the
capability body runs, and the permit is spent while the effect is unknown. `CLAIMED` makes that
forensic state explicit instead of ambiguous:

    ISSUED -> CLAIMED -> CONSUMED
    CLAIMED with no receipt  =>  RECONCILIATION_REQUIRED

CRITICAL: a consumed or claimed permit does **not** mean the capability succeeded. Permit lifecycle
and effect certainty answer different questions, and the effect-certainty model owns the second one.

SINGLE CLAIMANT, NOT MERELY SINGLE SIGNATURE
The claim transition is atomic, so exactly one claimant can win. A read-then-execute race is
prevented by the database, not by care.

EXPIRY IS DERIVED, NEVER TRUSTED
`state_of()` computes expiry from the clock. The stored EXPIRED state is materialised for clarity
only; a stalled expiry worker must never be able to extend authority.

FROZEN SPEC - PERMIT_CANONICALIZATION_V1
This governs `permit_version = 1` and is part of the cryptographic contract:
  - UTF-8 encoding
  - object keys sorted lexicographically
  - no insignificant whitespace (separators are ',' and ':')
  - ASCII-safe output (ensure_ascii), so encoding is locale independent
  - null is preserved as null, never dropped or coerced to empty string
  - numbers: INTEGERS ONLY. Floating point is forbidden inside a signed permit body, because
    a decimal rendering is not a portable cryptographic primitive. Timestamps are Unix
    microseconds as integers. The first non-Python verifier must not be able to disagree
    about the bytes without anybody altering the permit
  - lists keep caller order; where order is not semantic the caller must sort before signing
  - unknown fields are refused rather than ignored, so a V1 body cannot silently grow
Changing any rule above requires PERMIT_V2 and a new permit_version. It must never be a silent edit
to the V1 canonicalizer, or old permits become unverifiable without anyone altering them.
"""

import hashlib
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


def derive_permit_state(row_state: str, expires_at: float, now: float) -> str:
    """
    The ONE reading of a permit's operational state from a durable row plus a clock.

    Expiry is DERIVED, never trusted from the column, and revocation/consumption are terminal. Any
    other reader - including continuity reconstruction - must call this rather than re-deriving it:
    two readings of "is this authority still alive" is exactly how a restart starts lying.
    """
    state = str(row_state)
    if state in (STATE_REVOKED, STATE_CONSUMED):
        return state
    if now > float(expires_at):
        return STATE_EXPIRED
    if state in (STATE_ISSUED, STATE_CLAIMED):
        return state
    return STATE_UNKNOWN


def consume_permit_row(conn, permit_id: str, *, actor: str = "", now: Optional[float] = None,
                       allow_foreign_claimant: bool = False) -> bool:
    """
    The ONE `CLAIMED -> CONSUMED` transition, runnable inside a CALLER's transaction.

    `CONSUMED` describes the AUTHORITY's lifecycle, not the epistemic quality of the outcome: an
    attempt is resolved when the record says so - by machine evidence or by an operator settlement -
    and its permit is then permanently dead. `CLAIMED` therefore means exactly one thing:

        authority spent, attempt exists, outcome not yet resolved.

    Idempotent on an already-CONSUMED row (returns False), so the crash window "terminal evidence is
    durable, the consume is not" can be completed by recovery without inventing a fact.
    `allow_foreign_claimant` exists for the central disposition and operator-settlement paths, which
    legitimately resolve an attempt they did not claim; the default keeps single-claimant semantics.
    """
    moment = now if now is not None else time.time()
    row = conn.execute("SELECT * FROM execution_permits WHERE permit_id = ?;", (permit_id,)).fetchone()
    if row is None:
        raise PermitStoreError(DENY_UNKNOWN, permit_id)
    state = row["state"]
    if state == STATE_CONSUMED:
        return False
    if state != STATE_CLAIMED:
        raise PermitStoreError(DENY_NOT_CLAIMANT, f"state={state}")
    if not allow_foreign_claimant and actor and row["claimed_by"] != actor:
        raise PermitStoreError(DENY_NOT_CLAIMANT, str(row["claimed_by"]))
    conn.execute(
        "UPDATE execution_permits SET state = ?, consumed_at = ? WHERE permit_id = ?;",
        (STATE_CONSUMED, moment, permit_id),
    )
    return True


class PermitStoreError(Exception):
    """Raised when a permit lifecycle transition is refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


STATE_ISSUED = "ISSUED"
STATE_UNKNOWN = "UNKNOWN"
STATE_CLAIMED = "CLAIMED"
STATE_CONSUMED = "CONSUMED"
STATE_REVOKED = "REVOKED"
STATE_EXPIRED = "EXPIRED"

DENY_UNKNOWN = "DENY_PERMIT_UNKNOWN"
DENY_EXPIRED = "DENY_PERMIT_EXPIRED"
DENY_REVOKED = "DENY_PERMIT_REVOKED"
DENY_ALREADY_CLAIMED = "DENY_PERMIT_ALREADY_CLAIMED"
DENY_ALREADY_CONSUMED = "DENY_PERMIT_ALREADY_CONSUMED"
DENY_DIGEST_MISMATCH = "DENY_PERMIT_DIGEST_MISMATCH"
DENY_EPOCH_MISMATCH = "DENY_PERMIT_AUTHORIZATION_EPOCH_MISMATCH"
DENY_NOT_CLAIMANT = "DENY_PERMIT_CLAIMED_BY_ANOTHER"
DENY_LOGICAL_ACTION_CONFLICT = "DENY_LOGICAL_ACTION_FINGERPRINT_CONFLICT"
DENY_LOGICAL_ACTION_REQUIRES_FINGERPRINT = "DENY_LOGICAL_ACTION_REQUIRES_FINGERPRINT"
DENY_EPOCH_NOT_AUTHORITATIVE = "DENY_PERMIT_AUTHORIZATION_EPOCH_NOT_AUTHORITATIVE"

# States that block a second issuance for the same logical action. CONSUMED is not "live" - it is
# terminal - but it still blocks reissuance, which is why the set is named for what it does rather
# than for liveness. Nothing else (REVOKED, EXPIRED) blocks: those states permit a replacement of
# the *same* logical-action fingerprint.
ISSUANCE_BLOCKING_STATES = (STATE_ISSUED, STATE_CLAIMED, STATE_CONSUMED)

ISSUANCE_REGISTERED = "REGISTERED"
ISSUANCE_ALREADY_ISSUED = "ALREADY_ISSUED"
ISSUANCE_IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"


OUTCOME_VALID_AT_TIME = "VALID_AT_TIME"
OUTCOME_INVALID_AT_TIME = "INVALID_AT_TIME"
OUTCOME_UNVERIFIABLE_HISTORY = "UNVERIFIABLE_HISTORY"

# External facts a permit's own row cannot answer. Their history must be reconstructable from
# evented authority transitions or the verdict for a past moment is genuinely unknown.
EXTERNAL_AUTHORITY_FACTS = (
    "authorization_grant_at_T",
    "authorization_epoch_at_T",
    "mission_envelope_at_T",
    "epistemic_leases_at_T",
)


@dataclass(frozen=True)
class HistoricalAuthorizationResult:
    """
    Whether an execution was authorized at a past moment.

    Deliberately not a boolean. `False` would collapse "definitely unauthorized", "no record
    of the historical grant", "lease history missing" and "epoch history corrupted" into one
    answer, and those are different epistemic states. A 2026 execution examined in 2028 must
    not read as unauthorized merely because today's grant has expired.
    """

    outcome: str
    reason: str
    checked: Dict[str, str]
    unverifiable: tuple

    @property
    def is_valid(self) -> bool:
        return self.outcome == OUTCOME_VALID_AT_TIME

    @property
    def is_conclusive(self) -> bool:
        return self.outcome != OUTCOME_UNVERIFIABLE_HISTORY


@dataclass(frozen=True)
class PermitClaim:
    """
    The durable result of claiming a permit.

    `execution_attempt_id` is generated *by the claim transaction*, never supplied by the
    caller. That is what makes `P -> A` anchored in durable state instead of in a worker's
    account of what it did, and it means a receipt only has to establish `A -> R`.
    """

    permit_id: str
    execution_attempt_id: str
    claimant: str
    claimed_at: float


@dataclass(frozen=True)
class PermitIssuanceResult:
    """
    The outcome of a registration attempt against the canonical issuance unit.

    Returned rather than `None` so a caller can REUSE the canonical identity instead of minting a
    second authority artifact. `registered=False` is not an error: it means canonical authority
    already exists for this logical action and the caller must adopt it.

    Deliberately carries no permit bytes. `permit_id` and `owning_job_id` are enough for the caller
    to locate the permit that was already issued - the job/queue layer owns the serialized artifact.
    """

    registered: bool
    permit_id: str
    state: str
    permit_digest: str
    owning_job_id: Optional[str] = None
    reason: str = ""

    @property
    def already_issued(self) -> bool:
        return (not self.registered) and self.reason == ISSUANCE_ALREADY_ISSUED


def permit_digest(canonical_bytes: bytes) -> str:
    """Digest of the canonical signed body. This is what receipts cite."""
    return hashlib.sha256(canonical_bytes).hexdigest()


def digest_of(value: str) -> str:
    import hashlib
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


class _ExistingConnection:
    """Wrap a caller-owned connection so the store does not close it, commit it, or roll it back."""

    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, exc_type, exc, tb):
        # Never commit or roll back: the transaction belongs to the caller.
        return False


class ExecutionPermitStore:
    """Durable lifecycle state for execution permits."""

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
                CREATE TABLE IF NOT EXISTS execution_permits (
                    permit_id TEXT PRIMARY KEY,
                    permit_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    issued_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    authorization_epoch INTEGER,
                    job_id TEXT,
                    mission_id TEXT,
                    logical_action_id TEXT,
                    attempt_id TEXT,
                    claimed_at REAL,
                    claimed_by TEXT,
                    execution_attempt_id TEXT,
                    consumed_at REAL,
                    revoked_at REAL,
                    revoke_reason TEXT
                );
            """)
            # Additive migration for databases created before attempt identity existed.
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(execution_permits);")
            }
            # Additive migration, tolerant of a concurrent initialiser winning the ALTER. Two
            # threads constructing the store can both observe the column missing; the loser must
            # converge on the migrated schema rather than fail with "duplicate column name".
            for column, ddl in (
                ("execution_attempt_id", "execution_attempt_id TEXT"),
                ("action_fingerprint", "action_fingerprint TEXT"),
                ("authorization_generation", "authorization_generation INTEGER DEFAULT 0"),
            ):
                if column not in columns:
                    try:
                        conn.execute(f"ALTER TABLE execution_permits ADD COLUMN {ddl};")
                    except sqlite3.OperationalError:
                        pass
            # THE AUTHORITATIVE EPOCH, owned by the execution constitution itself.
            #
            # `claim` used to compare against a CALLER-SUPPLIED epoch, which made the recovery fence only
            # as strong as the caller's honesty: an isolated superseded instance could present its own
            # stale epoch, pass the comparison, and claim a permit after it had been superseded. The
            # store now keeps its OWN record: once a supersession is recorded here, no caller - stale,
            # lying or merely out of date - can talk the boundary back into the old epoch.
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_authority_epochs (
                    epoch_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    actor TEXT,
                    evidence_ref TEXT,
                    recorded_at REAL
                );
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_permits_state ON execution_permits(state);"
            )
            # Concurrency backstop for the logical-action law. The transaction below is the primary
            # enforcement; this index makes a second issuance-blocking row impossible even if some
            # future path forgets the check. It is state-only on purpose: the store materialises
            # expiry before replacing, so the index never needs a clock.
            conn.execute("""
                DROP INDEX IF EXISTS idx_permits_blocking_logical_action;
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_permits_blocking_generation
                ON execution_permits(logical_action_id, authorization_generation)
                WHERE logical_action_id IS NOT NULL
                  AND state IN ('ISSUED', 'CLAIMED', 'CONSUMED');
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_permits_job ON execution_permits(job_id);"
            )

    # ------------------------------------------------------------------ registration

    def register(
        self,
        permit_id: str,
        digest: str,
        issued_at: float,
        expires_at: float,
        authorization_epoch: Optional[int] = None,
        job_id: Optional[str] = None,
        mission_id: Optional[str] = None,
        logical_action_id: Optional[str] = None,
        action_fingerprint: Optional[str] = None,
        authorization_generation: int = 0,
        retry_authorization: Optional[Any] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> "PermitIssuanceResult":
        """
        Record an issued permit against the canonical issuance unit: the logical action.

        Two separate invariants, both enforced inside the write transaction:

          LOGICAL ACTION IDENTITY
              once `logical_action_id` L has been observed with fingerprint A, L may never later
              bind to fingerprint B - in any state, including REVOKED and EXPIRED.

          BLOCKING PERMIT UNIQUENESS
              for L, at most one ISSUANCE_BLOCKING permit exists. CONSUMED is not live, but it still
              blocks: a completed logical action is not re-issued.

        A same-fingerprint request whose previous permit still blocks returns ALREADY_ISSUED with the
        canonical identity, so the caller adopts what exists instead of minting a second artifact.
        """
        if logical_action_id and not action_fingerprint:
            raise PermitStoreError(DENY_LOGICAL_ACTION_REQUIRES_FINGERPRINT, logical_action_id)

        # `conn` lets a caller enrol this registration in ITS transaction, which is what makes a
        # retry transition (classify -> register N+1 -> requeue) atomic. When supplied, the caller
        # owns BEGIN/COMMIT/ROLLBACK; this method does not open, commit or roll back.
        owns_transaction = conn is None
        with (self._connect() if owns_transaction else _ExistingConnection(conn)) as active:
            if owns_transaction:
                active.execute("BEGIN IMMEDIATE")
            conn = active

            def _commit():
                if owns_transaction:
                    active.execute("COMMIT")

            def _rollback():
                if owns_transaction:
                    active.execute("ROLLBACK")

            if logical_action_id:
                # Generations are monotonic and cannot skip: generation N+1 is only legal if
                # generation N exists. The permit rows themselves are the retry lineage.
                generation = int(authorization_generation or 0)
                if generation > 0:
                    # Generation > 0 is reachable ONLY through the canonical classifier. Ordinary
                    # issuance is generation 0, so a producer cannot mint fresh authority by asking.
                    proof_ok = (
                        retry_authorization is not None
                        and getattr(retry_authorization, "logical_action_id", None) == logical_action_id
                        and int(getattr(retry_authorization, "next_generation", -1)) == generation
                    )
                    if not proof_ok:
                        (_rollback())
                        raise PermitStoreError(
                            "DENY_RETRY_NOT_AUTHORIZED",
                            f"{logical_action_id}:{generation}",
                        )
                    previous = conn.execute(
                        "SELECT 1 FROM execution_permits WHERE logical_action_id = ? "
                        "AND COALESCE(authorization_generation, 0) = ? LIMIT 1;",
                        (logical_action_id, generation - 1),
                    ).fetchone()
                    if previous is None:
                        (_rollback())
                        raise PermitStoreError(
                            "DENY_GENERATION_SKIP",
                            f"{logical_action_id}:{generation}",
                        )
                # Materialise expiry for this logical action first: a permit that has run out of
                # time stops blocking, and stops occupying the uniqueness index, before any
                # replacement is considered.
                conn.execute(
                    "UPDATE execution_permits SET state = ? "
                    "WHERE logical_action_id = ? AND state = ? AND expires_at <= ?;",
                    (STATE_EXPIRED, logical_action_id, STATE_ISSUED, time.time()),
                )
                historical = self._historical_fingerprint(conn, logical_action_id)
                if historical is not None and historical != action_fingerprint:
                    (_rollback())
                    raise PermitStoreError(DENY_LOGICAL_ACTION_CONFLICT, logical_action_id)

                blocking = conn.execute(
                    "SELECT * FROM execution_permits WHERE logical_action_id = ? "
                    "AND COALESCE(authorization_generation, 0) = ? "
                    "AND state IN (?, ?, ?) LIMIT 1;",
                    (logical_action_id, int(authorization_generation or 0), *ISSUANCE_BLOCKING_STATES),
                ).fetchone()
                if blocking is not None:
                    (_rollback())
                    return PermitIssuanceResult(
                        registered=False,
                        permit_id=blocking["permit_id"],
                        state=blocking["state"],
                        permit_digest=blocking["permit_digest"],
                        owning_job_id=blocking["job_id"],
                        reason=ISSUANCE_ALREADY_ISSUED,
                    )

            existing = conn.execute(
                "SELECT * FROM execution_permits WHERE permit_id = ?;", (permit_id,)
            ).fetchone()
            if existing is not None:
                (_rollback())
                if existing["permit_digest"] != digest:
                    raise PermitStoreError(DENY_DIGEST_MISMATCH, permit_id)
                return PermitIssuanceResult(
                    registered=False,
                    permit_id=permit_id,
                    state=existing["state"],
                    permit_digest=existing["permit_digest"],
                    owning_job_id=existing["job_id"],
                    reason=ISSUANCE_IDEMPOTENT_REPLAY,
                )

            try:
                conn.execute("""
                    INSERT INTO execution_permits
                        (permit_id, permit_digest, state, issued_at, expires_at,
                         authorization_epoch, job_id, mission_id, logical_action_id,
                         action_fingerprint, authorization_generation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (permit_id, digest, STATE_ISSUED, issued_at, expires_at,
                      authorization_epoch, job_id, mission_id, logical_action_id,
                      action_fingerprint, int(authorization_generation or 0)))
            except sqlite3.IntegrityError:
                # Concurrency backstop fired. Reread canonical state and report it; never mint a
                # second permit for the same logical action.
                (_rollback())
                surviving = self._blocking_permit_row(logical_action_id)
                if surviving is None:
                    raise
                if surviving["action_fingerprint"] != action_fingerprint:
                    raise PermitStoreError(DENY_LOGICAL_ACTION_CONFLICT, logical_action_id)
                return PermitIssuanceResult(
                    registered=False,
                    permit_id=surviving["permit_id"],
                    state=surviving["state"],
                    permit_digest=surviving["permit_digest"],
                    owning_job_id=surviving["job_id"],
                    reason=ISSUANCE_ALREADY_ISSUED,
                )

            (_commit())
            return PermitIssuanceResult(
                registered=True,
                permit_id=permit_id,
                state=STATE_ISSUED,
                permit_digest=digest,
                owning_job_id=job_id,
                reason=ISSUANCE_REGISTERED,
            )

    @staticmethod
    def _historical_fingerprint(conn, logical_action_id):
        """The fingerprint this logical action has ever been bound to, if any."""
        row = conn.execute(
            "SELECT action_fingerprint FROM execution_permits "
            "WHERE logical_action_id = ? AND action_fingerprint IS NOT NULL LIMIT 1;",
            (logical_action_id,),
        ).fetchone()
        return row["action_fingerprint"] if row is not None else None

    def get_permit_row(self, permit_id: str, *, conn=None):
        """The canonical permit row, optionally read inside a caller-owned transaction."""
        if conn is not None:
            return conn.execute(
                "SELECT * FROM execution_permits WHERE permit_id = ?;", (permit_id,)
            ).fetchone()
        with self._connect() as owned:
            return owned.execute(
                "SELECT * FROM execution_permits WHERE permit_id = ?;", (permit_id,)
            ).fetchone()

    def _blocking_permit_row(self, logical_action_id, authorization_generation=0):
        """The issuance-blocking permit for one (logical action, authorization generation)."""
        if not logical_action_id:
            return None
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM execution_permits WHERE logical_action_id = ? "
                "AND COALESCE(authorization_generation, 0) = ? "
                "AND state IN (?, ?, ?) LIMIT 1;",
                (logical_action_id, int(authorization_generation or 0), *ISSUANCE_BLOCKING_STATES),
            ).fetchone()

    # ------------------------------------------------------------------------ state

    def _row(self, conn, permit_id: str):
        return conn.execute(
            "SELECT * FROM execution_permits WHERE permit_id = ?;", (permit_id,)
        ).fetchone()

    def state_of(self, permit_id: str, now: Optional[float] = None) -> str:
        """
        Operational state, with expiry derived from the clock rather than trusted from the row.
        """
        moment = now if now is not None else time.time()
        with self._connect() as conn:
            row = self._row(conn, permit_id)
        if row is None:
            raise PermitStoreError(DENY_UNKNOWN, permit_id)
        return derive_permit_state(row["state"], row["expires_at"], moment)

    # ------------------------------------------------------- authoritative epoch (owned here)

    def current_authority_epoch(self) -> Optional[int]:
        """
        The authoritative epoch THIS STORE records, or None if no supersession was ever recorded.

        None preserves the previous behaviour exactly (an installation that has never been superseded
        behaves as before); once a generation exists, it is the store - not the caller - that decides
        which epoch is current.
        """
        with self._connect() as conn:
            row = conn.execute("SELECT COALESCE(MAX(generation), NULL) AS latest FROM "
                               "ciph_authority_epochs;").fetchone()
            return int(row[0]) if row is not None and row[0] is not None else None

    def record_authority_generation(self, *, generation: int, actor: str, evidence_ref: str,
                                    now: Optional[float] = None) -> int:
        """
        Record an authoritative epoch generation. Operator-only, evidence required, append-only.

        This is the recovery fence's write into the execution constitution: it does not corrupt any
        permit, it declares which epoch is current, and the existing epoch comparison then kills
        everything minted before it.
        """
        if not str(actor).startswith("operator:"):
            raise PermitStoreError("DENY_AUTHORITY_EPOCH_REQUIRES_AN_OPERATOR", str(actor))
        if not str(evidence_ref).strip():
            raise PermitStoreError("DENY_AUTHORITY_EPOCH_REQUIRES_EVIDENCE", str(actor))
        moment = now if now is not None else time.time()
        floors = [value for value in (self.current_authority_epoch(), self.highest_minted_epoch())
                  if value is not None]
        if floors and int(generation) <= max(floors):
            raise PermitStoreError("DENY_AUTHORITY_EPOCH_NOT_SUPERSEDING",
                                   f"{generation} <= {max(floors)}")
        epoch_id = f"EPOCH-{int(generation)}-{digest_of(evidence_ref)}"
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO ciph_authority_epochs (epoch_id, generation, actor, "
                         "evidence_ref, recorded_at) VALUES (?,?,?,?,?);",
                         (epoch_id, int(generation), str(actor), str(evidence_ref), moment))
            conn.commit()
        return int(generation)

    def highest_minted_epoch(self) -> Optional[int]:
        """The highest epoch any permit in this store was minted under."""
        with self._connect() as conn:
            row = conn.execute("SELECT MAX(authorization_epoch) AS highest FROM execution_permits "
                               "WHERE authorization_epoch IS NOT NULL;").fetchone()
            return int(row[0]) if row is not None and row[0] is not None else None

    def supersede_authority_epoch(self, *, actor: str, evidence_ref: str,
                                  now: Optional[float] = None) -> int:
        """
        Advance the authoritative epoch beyond everything that exists.

        A supersession that does not EXCEED the epochs already minted is not a supersession: a first
        recorded generation of 1 would leave epoch-1 permits comfortably valid. So the floor is the
        highest of the recorded generation and every permit's epoch, and the new generation is above it.
        """
        floors = [value for value in (self.current_authority_epoch(), self.highest_minted_epoch())
                  if value is not None]
        return self.record_authority_generation(generation=(max(floors) + 1) if floors else 1,
                                                actor=actor, evidence_ref=evidence_ref, now=now)

    # ------------------------------------------------------------------------ claim

    def claim(
        self,
        permit_id: str,
        claimant: str,
        digest: Optional[str] = None,
        current_authorization_epoch: Optional[int] = None,
        now: Optional[float] = None,
    ) -> PermitClaim:
        """
        Atomically claim a permit for execution. Exactly one claimant can win.

        Refuses when the permit is unknown, expired (derived), revoked, already claimed, already
        consumed, presented with the wrong digest, or minted under a superseded authorization epoch.
        Returns a PermitClaim carrying the attempt identity generated by this transaction. The
        caller cannot supply an attempt id, so it cannot claim an attempt it did not create.
        """
        moment = now if now is not None else time.time()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._row(conn, permit_id)
            if row is None:
                conn.execute("ROLLBACK")
                raise PermitStoreError(DENY_UNKNOWN, permit_id)
            if digest is not None and row["permit_digest"] != digest:
                conn.execute("ROLLBACK")
                raise PermitStoreError(DENY_DIGEST_MISMATCH, permit_id)
            if row["state"] == STATE_REVOKED:
                conn.execute("ROLLBACK")
                raise PermitStoreError(DENY_REVOKED, permit_id)
            if row["state"] == STATE_CONSUMED:
                conn.execute("ROLLBACK")
                raise PermitStoreError(DENY_ALREADY_CONSUMED, permit_id)
            if row["state"] == STATE_CLAIMED:
                conn.execute("ROLLBACK")
                raise PermitStoreError(
                    DENY_ALREADY_CLAIMED, f"{permit_id} held by {row['claimed_by']}"
                )
            if moment > row["expires_at"]:
                conn.execute("ROLLBACK")
                raise PermitStoreError(DENY_EXPIRED, permit_id)
            authoritative = self.current_authority_epoch()
            if authoritative is not None and current_authorization_epoch is not None \
                    and int(current_authorization_epoch) != int(authoritative):
                # The caller's notion of "current" disagrees with the store's own record: it is stale
                # or it is lying. Either way it does not get to set the fence's reference point.
                conn.execute("ROLLBACK")
                raise PermitStoreError(DENY_EPOCH_NOT_AUTHORITATIVE,
                                       f"caller={current_authorization_epoch} "
                                       f"authoritative={authoritative}")
            effective_epoch = authoritative if authoritative is not None \
                else current_authorization_epoch
            if (
                effective_epoch is not None
                and row["authorization_epoch"] is not None
                and int(effective_epoch) != int(row["authorization_epoch"])
            ):
                # Broad invalidation: everything minted under a superseded epoch dies at once.
                conn.execute(
                    "UPDATE execution_permits SET state = ?, revoked_at = ?, "
                    "revoke_reason = ? WHERE permit_id = ?;",
                    (STATE_REVOKED, moment, "AUTHORIZATION_EPOCH_SUPERSEDED", permit_id),
                )
                conn.execute("COMMIT")
                raise PermitStoreError(DENY_EPOCH_MISMATCH, permit_id)

            execution_attempt_id = f"attempt_{uuid.uuid4().hex[:12]}"
            conn.execute("""
                UPDATE execution_permits
                SET state = ?, claimed_at = ?, claimed_by = ?, execution_attempt_id = ?
                WHERE permit_id = ? AND state = ?;
            """, (STATE_CLAIMED, moment, claimant, execution_attempt_id,
                  permit_id, STATE_ISSUED))
            conn.execute("COMMIT")
        return PermitClaim(
            permit_id=permit_id,
            execution_attempt_id=execution_attempt_id,
            claimant=claimant,
            claimed_at=moment,
        )

    def consume(self, permit_id: str, claimant: str, now: Optional[float] = None, *,
                conn=None, allow_foreign_claimant: bool = False) -> bool:
        """
        Record that the claimed attempt is RESOLVED, which permanently retires its authority.

        With `conn` supplied the caller owns the transaction - no BEGIN, no COMMIT, no ROLLBACK - so
        terminal evidence, the job's terminal state and the permit's consumption become one atomic
        proposition instead of three adjacent hopes.
        """
        owns = conn is None
        active = self._connect() if owns else conn
        try:
            if owns:
                active.execute("BEGIN IMMEDIATE")
            changed = consume_permit_row(
                active, permit_id, actor=claimant, now=now,
                allow_foreign_claimant=allow_foreign_claimant,
            )
            if owns:
                active.execute("COMMIT")
            return changed
        except Exception:
            if owns:
                try:
                    active.execute("ROLLBACK")
                except Exception:
                    pass
            raise
        finally:
            if owns:
                try:
                    active.close()
                except Exception:
                    pass


    def revoke(self, permit_id: str, reason: str = "OPERATOR_REVOKED",
               now: Optional[float] = None) -> bool:
        """Surgical invalidation of one permit, independent of epoch invalidation."""
        moment = now if now is not None else time.time()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute("""
                UPDATE execution_permits
                SET state = ?, revoked_at = ?, revoke_reason = ?
                WHERE permit_id = ? AND state IN (?, ?);
            """, (STATE_REVOKED, moment, reason, permit_id, STATE_ISSUED, STATE_CLAIMED))
            conn.execute("COMMIT")
            return cursor.rowcount > 0

    def find_by_attempt(self, execution_attempt_id: str) -> Optional[Dict[str, Any]]:
        """
        Look up the durable claim that owns this attempt identity.

        Receipt creation derives its lineage from here rather than from a caller-supplied
        object. A caller can fabricate something that *looks like* a PermitClaim; it cannot
        fabricate a row that this store did not write.
        """
        if not execution_attempt_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM execution_permits WHERE execution_attempt_id = ?;",
                (execution_attempt_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def valid_at(
        self,
        permit_id: str,
        moment: float,
        authority_history=None,
        execution_attempt_id: Optional[str] = None,
    ) -> HistoricalAuthorizationResult:
        """
        Was this permit *authorized for attempt A* at `moment`?

        The claim is narrow on purpose, and the name must not drift beyond it. This answers
        "did authority exist for A at T", not "did A execute at T" and not "did A produce an
        effect". A permit claimed by A that never runs remains CLAIMED, and querying a later
        arbitrary moment still returns authorization validity for that window; it is the
        receipt that says ATTEMPTED and effect evidence that says HAPPENED. Three different
        facts, deliberately kept apart:

            authorization says MAY, receipt says ATTEMPTED, effect evidence says HAPPENED

        `execution_attempt_id` gives the query context that raw timestamps cannot. A permit
        claimed by attempt A is *valid for A* and *invalid for B* - not simply invalid. Without
        that context a claimed permit looks like a denial to the very execution it authorised.

        Permit-local facts are answered from the durable row. External facts (grant, epoch,
        envelope, leases) can only be answered from historical evidence; without an
        `authority_history` source the verdict is UNVERIFIABLE_HISTORY naming exactly which
        facts could not be established. It never guesses, and it never substitutes today's
        authority state for the authority that existed then.
        """
        with self._connect() as conn:
            row = self._row(conn, permit_id)
        if row is None:
            return HistoricalAuthorizationResult(
                outcome=OUTCOME_UNVERIFIABLE_HISTORY,
                reason="NO_PERMIT_RECORD",
                checked={},
                unverifiable=("permit_existence",) + EXTERNAL_AUTHORITY_FACTS,
            )

        checked: Dict[str, str] = {}
        if moment < row["issued_at"]:
            checked["issued_before_moment"] = OUTCOME_INVALID_AT_TIME
            return HistoricalAuthorizationResult(
                OUTCOME_INVALID_AT_TIME, "NOT_YET_ISSUED", checked, ()
            )
        checked["issued_before_moment"] = OUTCOME_VALID_AT_TIME
        if moment > row["expires_at"]:
            checked["unexpired_at_moment"] = OUTCOME_INVALID_AT_TIME
            return HistoricalAuthorizationResult(
                OUTCOME_INVALID_AT_TIME, "EXPIRED_BEFORE_MOMENT", checked, ()
            )
        checked["unexpired_at_moment"] = OUTCOME_VALID_AT_TIME
        if row["revoked_at"] is not None and moment > row["revoked_at"]:
            checked["unrevoked_at_moment"] = OUTCOME_INVALID_AT_TIME
            return HistoricalAuthorizationResult(
                OUTCOME_INVALID_AT_TIME,
                f"REVOKED_BEFORE_MOMENT:{row['revoke_reason']}",
                checked,
                (),
            )
        checked["unrevoked_at_moment"] = OUTCOME_VALID_AT_TIME
        if row["consumed_at"] is not None and moment > row["consumed_at"]:
            checked["unconsumed_at_moment"] = OUTCOME_INVALID_AT_TIME
            return HistoricalAuthorizationResult(
                OUTCOME_INVALID_AT_TIME, "ALREADY_CONSUMED", checked, ()
            )
        checked["unconsumed_at_moment"] = OUTCOME_VALID_AT_TIME

        if execution_attempt_id is not None:
            recorded_attempt = row["execution_attempt_id"]
            if recorded_attempt is not None and recorded_attempt != execution_attempt_id:
                checked["attempt_owns_permit"] = OUTCOME_INVALID_AT_TIME
                return HistoricalAuthorizationResult(
                    OUTCOME_INVALID_AT_TIME,
                    "CLAIMED_BY_ANOTHER_ATTEMPT",
                    checked,
                    (),
                )
            if recorded_attempt is not None:
                checked["attempt_owns_permit"] = OUTCOME_VALID_AT_TIME

        if authority_history is None:
            return HistoricalAuthorizationResult(
                OUTCOME_UNVERIFIABLE_HISTORY,
                "EXTERNAL_AUTHORITY_HISTORY_UNAVAILABLE",
                checked,
                EXTERNAL_AUTHORITY_FACTS,
            )

        external = authority_history.authority_at(permit_id, moment)
        for fact in EXTERNAL_AUTHORITY_FACTS:
            verdict = getattr(external, fact, None)
            if verdict is None:
                checked[fact] = OUTCOME_UNVERIFIABLE_HISTORY
            else:
                checked[fact] = str(verdict)
        unresolved = tuple(
            fact for fact in EXTERNAL_AUTHORITY_FACTS
            if checked[fact] == OUTCOME_UNVERIFIABLE_HISTORY
        )
        if unresolved:
            return HistoricalAuthorizationResult(
                OUTCOME_UNVERIFIABLE_HISTORY,
                "EXTERNAL_AUTHORITY_HISTORY_INCOMPLETE",
                checked,
                unresolved,
            )
        invalid = [
            fact for fact in EXTERNAL_AUTHORITY_FACTS
            if checked[fact] != OUTCOME_VALID_AT_TIME
        ]
        if invalid:
            return HistoricalAuthorizationResult(
                OUTCOME_INVALID_AT_TIME,
                "EXTERNAL_AUTHORITY_INVALID:" + ",".join(invalid),
                checked,
                (),
            )
        return HistoricalAuthorizationResult(
            OUTCOME_VALID_AT_TIME, "AUTHORIZED_AT_MOMENT", checked, ()
        )

    def describe(self, permit_id: str, now: Optional[float] = None) -> Dict[str, Any]:
        moment = now if now is not None else time.time()
        with self._connect() as conn:
            row = self._row(conn, permit_id)
        if row is None:
            raise PermitStoreError(DENY_UNKNOWN, permit_id)
        described = dict(row)
        described["derived_state"] = self.state_of(permit_id, now=moment)
        return described
