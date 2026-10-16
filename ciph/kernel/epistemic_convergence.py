"""
ciph.kernel.epistemic_convergence - has the proposition converged, or is the honest answer still
"we do not know"?

4.2 Gate Four, the last gate. It applies source dependence BEFORE judgement and refuses to promote
anything to a `FACT`: convergence is another epistemic projection, with an explicit policy identity.

    CONVERGENCE_V1 (frozen)

        INTEGRITY conflict                                    -> INTEGRITY_BLOCKED
        all current evidence stale                            -> STALE
        proven support >= 2 AND possible contradiction == 0    -> CONVERGED_SUPPORTED
        proven contradiction >= 2 AND possible support == 0    -> CONVERGED_REFUTED
        proven support >= 1 AND proven contradiction >= 1      -> CONTESTED
        otherwise                                             -> UNRESOLVED

Why `possible contradiction == 0` matters: two proven supports plus one contradiction whose provenance
is UNKNOWN is NOT convergence. Unresolved provenance widens possibility, and possibility blocks a
claim of convergence until it is resolved. That is conservative by design; the `2` is policy, not
metaphysics, and a different standard gets a new policy id rather than a quiet edit to V1.

LAWS (each has a specimen in `test_gate_4_2_convergence.py`)

 1. CONVERGED != FACT.
 2. Raw evidence counts cannot determine convergence directly.
 3. Provenance dependence is applied BEFORE convergence.
 4. Unknown provenance can block convergence.
 5. Dependent copies never outvote independent contradiction.
 6. Support and contradiction are symmetric.
 7. Convergence history is append-only.
 8. New evidence may move CONVERGED_SUPPORTED -> CONTESTED without rewriting history.
 9. STALE does not mean REFUTED.
10. Integrity conflict always blocks convergence.
11. Model confidence cannot force convergence.
12. Same epistemic history -> same convergence state and digest after restart.

OUT OF SCOPE in V1: weighting evidence by predictor or source REPUTATION. Calibration is diagnostic
metadata only; a source that predicts well does not thereby get extra votes.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.belief_revision import revision_history
from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs
from ciph.kernel.source_dependence import RESOLUTION_INTEGRITY_CONFLICT, project_source_dependence

CONVERGENCE_V1 = "CONVERGENCE_V1"
PROVEN_SUPPORT_THRESHOLD = 2
PROVEN_CONTRADICTION_THRESHOLD = 2

STATUS_CONVERGED_SUPPORTED = "CONVERGED_SUPPORTED"
STATUS_CONVERGED_REFUTED = "CONVERGED_REFUTED"
STATUS_CONTESTED = "CONTESTED"
STATUS_UNRESOLVED = "UNRESOLVED"
STATUS_STALE = "STALE"
STATUS_INTEGRITY_BLOCKED = "INTEGRITY_BLOCKED"
VALID_STATUSES = (STATUS_CONVERGED_SUPPORTED, STATUS_CONVERGED_REFUTED, STATUS_CONTESTED,
                  STATUS_UNRESOLVED, STATUS_STALE, STATUS_INTEGRITY_BLOCKED)

REASON_MEETS_SUPPORT_THRESHOLD = "PROVEN_SUPPORT_MEETS_THRESHOLD"
REASON_MEETS_CONTRADICTION_THRESHOLD = "PROVEN_CONTRADICTION_MEETS_THRESHOLD"
REASON_POSSIBLE_CONTRADICTION_BLOCKS = "POSSIBLE_CONTRADICTION_BLOCKS"
REASON_POSSIBLE_SUPPORT_BLOCKS = "POSSIBLE_SUPPORT_BLOCKS"
REASON_BOTH_PROVEN = "PROVEN_SUPPORT_AND_CONTRADICTION"
REASON_NO_PROVEN_ORIGINS = "NO_PROVEN_ORIGINS"
REASON_ALL_EVIDENCE_STALE = "ALL_EVIDENCE_STALE"
REASON_NO_EVIDENCE = "NO_EVIDENCE"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_convergence_projections (
        proposition_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        projection_version INTEGER NOT NULL,
        status TEXT NOT NULL,
        proven_support_origins INTEGER,
        possible_support_origins INTEGER,
        proven_contradict_origins INTEGER,
        possible_contradict_origins INTEGER,
        reason_codes_json TEXT,
        basis_digest TEXT NOT NULL,
        created_at REAL,
        PRIMARY KEY (proposition_id, policy_id, projection_version)
    );
    """,
)


@dataclass(frozen=True)
class ConvergenceProjection:
    proposition_id: str
    policy_id: str
    status: str
    proven_support_origins: int
    possible_support_origins: int
    proven_contradict_origins: int
    possible_contradict_origins: int
    reason_codes: Tuple[str, ...]
    basis_digest: str
    gate_zero_belief_ref: Optional[str] = None
    source_dependence_ref: Optional[str] = None
    latest_revision_ref: Optional[str] = None
    created_at: Optional[float] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"proposition_id": self.proposition_id, "policy_id": self.policy_id,
                "status": self.status,
                "proven_support_origins": self.proven_support_origins,
                "possible_support_origins": self.possible_support_origins,
                "proven_contradict_origins": self.proven_contradict_origins,
                "possible_contradict_origins": self.possible_contradict_origins,
                "reason_codes": list(self.reason_codes), "basis_digest": self.basis_digest,
                "gate_zero_belief_ref": self.gate_zero_belief_ref,
                "source_dependence_ref": self.source_dependence_ref,
                "latest_revision_ref": self.latest_revision_ref,
                "created_at": self.created_at}

    def identity_payload(self) -> Dict[str, Any]:
        """
        The projection's IDENTITY: its epistemic content, without the wall clock.

        `created_at` records when we looked, not what we found, so it is part of the stored record and
        not part of the digest - otherwise the same history read at two moments would look like two
        different epistemic pictures.
        """
        payload = self.as_dict()
        payload.pop("created_at", None)
        return payload

    def canonical_digest(self) -> str:
        blob = json.dumps(self.identity_payload(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            pass
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def apply_policy(*, belief_status: str, integrity: bool, proven_support: int, possible_support: int,
                 proven_contradict: int, possible_contradict: int,
                 evidence_count: int) -> Tuple[str, Tuple[str, ...]]:
    """
    CONVERGENCE_V1, expressed as a pure function so the policy can be read, tested and versioned.

    Precedence is part of the policy: integrity first, then staleness, then the thresholds.
    """
    if integrity:
        return STATUS_INTEGRITY_BLOCKED, (RESOLUTION_INTEGRITY_CONFLICT,)
    if belief_status == "STALE":
        return STATUS_STALE, (REASON_ALL_EVIDENCE_STALE,)
    if not evidence_count:
        return STATUS_UNRESOLVED, (REASON_NO_EVIDENCE,)
    if proven_support >= PROVEN_SUPPORT_THRESHOLD and possible_contradict == 0:
        return STATUS_CONVERGED_SUPPORTED, (REASON_MEETS_SUPPORT_THRESHOLD,)
    if proven_contradict >= PROVEN_CONTRADICTION_THRESHOLD and possible_support == 0:
        return STATUS_CONVERGED_REFUTED, (REASON_MEETS_CONTRADICTION_THRESHOLD,)
    # Symmetric contest: proven support AND proven contradiction.
    if proven_support >= 1 and proven_contradict >= 1:
        reasons: List[str] = [REASON_BOTH_PROVEN]
        if possible_contradict > 0:
            reasons.append(REASON_POSSIBLE_CONTRADICTION_BLOCKS)
        if possible_support > 0:
            reasons.append(REASON_POSSIBLE_SUPPORT_BLOCKS)
        return STATUS_CONTESTED, tuple(reasons)

    reasons = []
    if proven_support < PROVEN_SUPPORT_THRESHOLD and proven_contradict < PROVEN_CONTRADICTION_THRESHOLD:
        reasons.append(REASON_NO_PROVEN_ORIGINS)
    if possible_contradict > 0:
        reasons.append(REASON_POSSIBLE_CONTRADICTION_BLOCKS)
    if possible_support > 0:
        reasons.append(REASON_POSSIBLE_SUPPORT_BLOCKS)
    return STATUS_UNRESOLVED, tuple(reasons)


def project_convergence(db_path: str, proposition_id: str, *, now: Optional[float] = None,
                        stale_after: Optional[float] = None,
                        conn: Optional[sqlite3.Connection] = None) -> ConvergenceProjection:
    """
    Apply CONVERGENCE_V1 to one proposition, on top of Gates Zero, One and Two.

    Read-only, deterministic, and never an input to itself: deleting the stored projections changes
    nothing about this answer.
    """
    moment = time.time() if now is None else float(now)
    belief = reconstruct_beliefs(db_path, now=moment, stale_after=stale_after).belief_for(proposition_id)
    dependence = project_source_dependence(db_path, proposition_id, now=moment, stale_after=stale_after)
    integrity = dependence.resolution_status == RESOLUTION_INTEGRITY_CONFLICT

    status, reasons = apply_policy(
        belief_status=belief.status if belief else "UNRESOLVED",
        integrity=integrity,
        proven_support=dependence.proven_support_count,
        possible_support=dependence.possible_support_count,
        proven_contradict=dependence.proven_contradict_count,
        possible_contradict=dependence.possible_contradict_count,
        evidence_count=dependence.evidence_count,
    )

    history = revision_history(db_path, proposition_id)
    latest_revision = history[-1].revision_id if history else None
    basis = _digest({"gate_zero": belief.derivation_digest if belief else None,
                     "source_dependence": dependence.provenance_digest,
                     "revision": latest_revision, "policy": CONVERGENCE_V1})

    owned = conn is None
    conn = _connect(db_path, read_only=True) if owned else conn
    try:
        latest = None
        try:
            latest = conn.execute(
                "SELECT * FROM ciph_convergence_projections WHERE proposition_id = ? AND policy_id = ? "
                "ORDER BY projection_version DESC LIMIT 1;", (proposition_id, CONVERGENCE_V1)).fetchone()
        except sqlite3.Error:
            latest = None
    finally:
        if owned:
            conn.close()

    return ConvergenceProjection(
        proposition_id=proposition_id, policy_id=CONVERGENCE_V1, status=status,
        proven_support_origins=dependence.proven_support_count,
        possible_support_origins=dependence.possible_support_count,
        proven_contradict_origins=dependence.proven_contradict_count,
        possible_contradict_origins=dependence.possible_contradict_count,
        reason_codes=tuple(reasons), basis_digest=basis,
        gate_zero_belief_ref=(belief.derivation_digest if belief else None),
        source_dependence_ref=dependence.provenance_digest, latest_revision_ref=latest_revision,
        created_at=moment)


def project_all(db_path: str, *, now: Optional[float] = None,
                stale_after: Optional[float] = None) -> Tuple[ConvergenceProjection, ...]:
    state = reconstruct_beliefs(db_path, now=now, stale_after=stale_after)
    return tuple(project_convergence(db_path, proposition.proposition_id, now=now,
                                     stale_after=stale_after)
                 for proposition in state.propositions)


def record_convergence(db_path: str, proposition_id: str, *, now: Optional[float] = None,
                       stale_after: Optional[float] = None) -> int:
    """
    Append the current convergence projection when it changed (law 7). Never an input to itself.
    """
    moment = time.time() if now is None else float(now)
    projection = project_convergence(db_path, proposition_id, now=moment, stale_after=stale_after)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        latest = conn.execute(
            "SELECT * FROM ciph_convergence_projections WHERE proposition_id = ? AND policy_id = ? "
            "ORDER BY projection_version DESC LIMIT 1;", (proposition_id, CONVERGENCE_V1)).fetchone()
        if latest is not None and latest["basis_digest"] == projection.basis_digest:
            return 0
        version = (int(latest["projection_version"]) + 1) if latest else 1
        conn.execute(
            "INSERT INTO ciph_convergence_projections (proposition_id, policy_id, projection_version, "
            "status, proven_support_origins, possible_support_origins, proven_contradict_origins, "
            "possible_contradict_origins, reason_codes_json, basis_digest, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);",
            (proposition_id, CONVERGENCE_V1, version, projection.status,
             projection.proven_support_origins, projection.possible_support_origins,
             projection.proven_contradict_origins, projection.possible_contradict_origins,
             json.dumps(list(projection.reason_codes)), projection.basis_digest, moment),
        )
        conn.commit()
        return version
    finally:
        conn.close()


def convergence_history(db_path: str, proposition_id: str) -> List[Dict[str, Any]]:
    conn = _connect(db_path, read_only=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_convergence_projections WHERE proposition_id = ? ORDER BY projection_version;",
            (proposition_id,))]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def convergence_digest(db_path: str, *, now: Optional[float] = None,
                       stale_after: Optional[float] = None) -> str:
    """The deterministic identity of the whole convergence picture (law 12)."""
    projections = project_all(db_path, now=now, stale_after=stale_after)
    return _digest([p.identity_payload() for p in projections])
