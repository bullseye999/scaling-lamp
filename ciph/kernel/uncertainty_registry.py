"""
ciph.kernel.uncertainty_registry - WHAT is actually unknown, contested or weakly modelled.

4.4 Gate Zero. Curiosity targets are DERIVED, never invented. There is deliberately no
`add_uncertainty`: the only way something becomes a target is for canonical 4.2/4.3 state to already
say the uncertainty exists, so a model that finds something interesting cannot manufacture a question
to chase (law 1).

    source_kind
        EPISTEMIC_UNRESOLVED      evidence exists, but has not converged
        EPISTEMIC_CONTESTED       proven support and proven contradiction both exist
        WORLD_STALE               a world fact's evidence is too old to be current
        WEAK_CAUSAL_HYPOTHESIS    a hypothesis with no empirical credit, or stale reasoning
        DYNAMICS_GAP              a bounded state change whose interior was never observed
        SELF_MODEL_UNKNOWN        a capability that is not empirically verified
        CALIBRATION_WEAKNESS      predictions that expired unresolved, so they can never be scored

    reducibility
        REDUCIBLE / POSSIBLY_REDUCIBLE / IRREDUCIBLE / UNKNOWN

    status (derived, never stored)
        OPEN        derivable now, and the recorded projection matches the current basis
        STALE       derivable now, but the recorded projection was built on an older basis
        SATISFIED   no longer derivable - the underlying state resolved, so it closed itself
        INVALID     this id was never derivable and never recorded

LAWS (each has a specimen in `test_gate_4_4_uncertainty_registry.py`)

 1. Curiosity cannot create an uncertainty merely because the model finds something interesting.
 2. Every uncertainty traces to canonical 4.2/4.3 state.
 3. UNKNOWN is not automatically a problem worth solving (bare model mentions are not targets).
 4. CONTESTED is not automatically reducible.
 5. The uncertainty is immutable as a historical record; a new basis is a new projection version.
 6. If the underlying epistemic/world state resolves, the uncertainty closes automatically.
 7. Model phrasing does not change uncertainty identity.
 8. Same canonical uncertainty state -> same digest after restart.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.causal_model import (
    HYPOTHESIS_CONTESTED,
    HYPOTHESIS_PROPOSED,
    HYPOTHESIS_STALE,
    hypothesis_assessment,
    hypothesis_history,
)
from ciph.kernel.epistemic_convergence import (
    STATUS_CONTESTED,
    STATUS_INTEGRITY_BLOCKED,
    STATUS_STALE,
    STATUS_UNRESOLVED,
    project_convergence,
)
from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs
from ciph.kernel.predictions import calibrate
from ciph.kernel.self_model import LEVEL_VERIFIED, known_capabilities, project_capability
from ciph.kernel.source_dependence import RESOLUTION_INTEGRITY_CONFLICT, project_source_dependence
from ciph.kernel.world_dynamics import derive_transitions
from ciph.kernel.world_model import (
    WORLD_STALE as WORLD_FACT_STALE,
    project_entities,
)

KIND_EPISTEMIC_UNRESOLVED = "EPISTEMIC_UNRESOLVED"
KIND_EPISTEMIC_CONTESTED = "EPISTEMIC_CONTESTED"
KIND_WORLD_STALE = "WORLD_STALE"
KIND_WEAK_CAUSAL_HYPOTHESIS = "WEAK_CAUSAL_HYPOTHESIS"
KIND_DYNAMICS_GAP = "DYNAMICS_GAP"
KIND_SELF_MODEL_UNKNOWN = "SELF_MODEL_UNKNOWN"
KIND_CALIBRATION_WEAKNESS = "CALIBRATION_WEAKNESS"
VALID_SOURCE_KINDS = (KIND_EPISTEMIC_UNRESOLVED, KIND_EPISTEMIC_CONTESTED, KIND_WORLD_STALE,
                      KIND_WEAK_CAUSAL_HYPOTHESIS, KIND_DYNAMICS_GAP, KIND_SELF_MODEL_UNKNOWN,
                      KIND_CALIBRATION_WEAKNESS)

REDUCIBLE = "REDUCIBLE"
POSSIBLY_REDUCIBLE = "POSSIBLY_REDUCIBLE"
IRREDUCIBLE = "IRREDUCIBLE"
REDUCIBILITY_UNKNOWN = "UNKNOWN"
VALID_REDUCIBILITY = (REDUCIBLE, POSSIBLY_REDUCIBLE, IRREDUCIBLE, REDUCIBILITY_UNKNOWN)

STATUS_OPEN = "OPEN"
STATUS_STALE = "STALE"
STATUS_SATISFIED = "SATISFIED"
STATUS_INVALID = "INVALID"
VALID_STATUSES = (STATUS_OPEN, STATUS_STALE, STATUS_SATISFIED, STATUS_INVALID)

REASON_INTEGRITY_BLOCKED = "INTEGRITY_BLOCKED"
REASON_NEEDS_OBSERVATION = "NEEDS_OBSERVATION"
REASON_NEEDS_FALSIFIABLE_TEST = "NEEDS_FALSIFIABLE_TEST"
REASON_NEEDS_GOVERNED_EXECUTION = "NEEDS_GOVERNED_EXECUTION"
REASON_EVIDENCE_CONFLICTS = "EVIDENCE_CONFLICTS"
REASON_EVIDENCE_DID_NOT_CONVERGE = "EVIDENCE_DID_NOT_CONVERGE"
REASON_EVIDENCE_TOO_OLD = "EVIDENCE_TOO_OLD"
REASON_PREDICTIONS_UNSCORABLE = "PREDICTIONS_UNSCORABLE"

REASON_CODES_BY_KIND = {
    KIND_EPISTEMIC_UNRESOLVED: (REASON_EVIDENCE_DID_NOT_CONVERGE,),
    KIND_EPISTEMIC_CONTESTED: (REASON_EVIDENCE_CONFLICTS,),
    KIND_WORLD_STALE: (REASON_EVIDENCE_TOO_OLD,),
    KIND_WEAK_CAUSAL_HYPOTHESIS: (REASON_NEEDS_FALSIFIABLE_TEST,),
    KIND_DYNAMICS_GAP: (REASON_NEEDS_OBSERVATION,),
    KIND_SELF_MODEL_UNKNOWN: (REASON_NEEDS_GOVERNED_EXECUTION,),
    KIND_CALIBRATION_WEAKNESS: (REASON_PREDICTIONS_UNSCORABLE,),
}

# The FROZEN reducibility policy. Contested work is POSSIBLY reducible, not automatically reducible
# (law 4); a stale fact or a bounded gap is reducible by looking again; an integrity conflict is not
# reducible by investigation at all - it has to be repaired first.
REDUCIBILITY_BY_KIND = {
    KIND_EPISTEMIC_UNRESOLVED: POSSIBLY_REDUCIBLE,
    KIND_EPISTEMIC_CONTESTED: POSSIBLY_REDUCIBLE,
    KIND_WORLD_STALE: REDUCIBLE,
    KIND_WEAK_CAUSAL_HYPOTHESIS: REDUCIBLE,
    KIND_DYNAMICS_GAP: REDUCIBLE,
    KIND_SELF_MODEL_UNKNOWN: REDUCIBLE,
    KIND_CALIBRATION_WEAKNESS: POSSIBLY_REDUCIBLE,
}

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_uncertainty_snapshots (
        uncertainty_id TEXT NOT NULL,
        snapshot_version INTEGER NOT NULL,
        source_kind TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        subject TEXT,
        relation TEXT,
        reducibility TEXT NOT NULL,
        reason_codes_json TEXT,
        basis_digest TEXT NOT NULL,
        recorded_at REAL,
        PRIMARY KEY (uncertainty_id, snapshot_version)
    );
    """,
)


class UncertaintyError(Exception):
    """An uncertainty-registry operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class UncertaintyRecord:
    uncertainty_id: str
    source_kind: str
    source_ref: str
    subject: Optional[str]
    relation: Optional[str]
    reducibility: str
    reason_codes: Tuple[str, ...]
    basis_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {"uncertainty_id": self.uncertainty_id, "source_kind": self.source_kind,
                "source_ref": self.source_ref, "subject": self.subject, "relation": self.relation,
                "reducibility": self.reducibility, "reason_codes": list(self.reason_codes),
                "basis_digest": self.basis_digest}

    def canonical_digest(self) -> str:
        return _digest(self.as_dict())


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


def uncertainty_id_for(source_kind: str, source_ref: str) -> str:
    """
    Identity comes from WHAT is uncertain, not from how it was phrased (law 7).
    """
    return "UNC-" + hashlib.sha256(f"{source_kind}|{source_ref}".encode("utf-8")).hexdigest()[:12].upper()


def _record(source_kind: str, source_ref: str, *, subject: Optional[str], relation: Optional[str],
            basis_digest: str, integrity_blocked: bool = False) -> UncertaintyRecord:
    reducibility = IRREDUCIBLE if integrity_blocked else REDUCIBILITY_BY_KIND[source_kind]
    reasons = REASON_CODES_BY_KIND[source_kind]
    if integrity_blocked:
        reasons = (REASON_INTEGRITY_BLOCKED,) + reasons
    return UncertaintyRecord(uncertainty_id=uncertainty_id_for(source_kind, source_ref),
                             source_kind=source_kind, source_ref=source_ref, subject=subject,
                             relation=relation, reducibility=reducibility,
                             reason_codes=tuple(reasons), basis_digest=basis_digest)


def derive_uncertainties(db_path: str, *, now: Optional[float] = None,
                         stale_after: Optional[float] = None) -> Tuple[UncertaintyRecord, ...]:
    """
    Every uncertainty the canonical 4.2/4.3 state currently implies. Read-only.

    There is no parameter for "what the model would like to investigate": the target set is a
    projection, so curiosity is downstream of evidence rather than a second source of it (laws 1, 2).
    """
    moment = time.time() if now is None else float(now)
    records: List[UncertaintyRecord] = []

    # --- epistemic: an unresolved or contested proposition WITH real evidence behind it --------
    state = reconstruct_beliefs(db_path, now=moment, stale_after=stale_after)
    for proposition in state.propositions:
        dependence = project_source_dependence(db_path, proposition.proposition_id, now=moment,
                                               stale_after=stale_after)
        if dependence.evidence_count == 0:
            # Law 3: a proposition that only a model ever mentioned is not a target - otherwise
            # every sentence Ciph utters would mint a question.
            continue
        convergence = project_convergence(db_path, proposition.proposition_id, now=moment,
                                          stale_after=stale_after)
        integrity = (dependence.resolution_status == RESOLUTION_INTEGRITY_CONFLICT
                     or convergence.status == STATUS_INTEGRITY_BLOCKED)
        if convergence.status == STATUS_UNRESOLVED:
            records.append(_record(KIND_EPISTEMIC_UNRESOLVED, proposition.proposition_id,
                                   subject=proposition.subject, relation=proposition.predicate,
                                   basis_digest=convergence.basis_digest,
                                   integrity_blocked=integrity))
        elif convergence.status == STATUS_CONTESTED:
            records.append(_record(KIND_EPISTEMIC_CONTESTED, proposition.proposition_id,
                                   subject=proposition.subject, relation=proposition.predicate,
                                   basis_digest=convergence.basis_digest,
                                   integrity_blocked=integrity))

    # --- world facts whose evidence has gone stale ---------------------------------------------
    for fact in project_entities(db_path, now=moment, stale_after=stale_after):
        if fact.world_status == WORLD_FACT_STALE:
            records.append(_record(KIND_WORLD_STALE, fact.fact_id, subject=fact.entity.canonical_key,
                                   relation=fact.relation,
                                   basis_digest=fact.evidence_basis_digest))

    # --- causal hypotheses with no empirical credit, or stale reasoning ------------------------
    for row in hypothesis_history(db_path):
        hypothesis_id = str(row["hypothesis_id"])
        assessment = hypothesis_assessment(db_path, hypothesis_id, now=moment)
        if assessment.status in (HYPOTHESIS_PROPOSED, HYPOTHESIS_STALE, HYPOTHESIS_CONTESTED):
            records.append(_record(KIND_WEAK_CAUSAL_HYPOTHESIS, hypothesis_id,
                                   subject=str(row["effect"]), relation=str(row["cause"]),
                                   basis_digest=assessment.basis_digest))

    # --- bounded state changes whose interior was never observed -------------------------------
    for transition in derive_transitions(db_path, now=moment, stale_after=stale_after):
        if transition.exact_at is None and transition.intermediate_observations == 0:
            records.append(_record(KIND_DYNAMICS_GAP, transition.transition_id,
                                   subject=transition.entity_id, relation=transition.relation,
                                   basis_digest=transition.canonical_digest()))

    # --- capabilities that are not empirically verified ----------------------------------------
    for capability_id in known_capabilities(db_path):
        projection = project_capability(db_path, capability_id=capability_id, now=moment)
        if projection.claim_level != LEVEL_VERIFIED:
            records.append(_record(KIND_SELF_MODEL_UNKNOWN, capability_id,
                                   subject=capability_id, relation=projection.claim_level,
                                   basis_digest=projection.evidence_basis_digest))

    # --- predictions that expired unresolved, so they can never be scored ----------------------
    calibration = calibrate(db_path, now=moment)
    if calibration["unresolved_count"] > 0:
        records.append(_record(KIND_CALIBRATION_WEAKNESS, "PREDICTIONS", subject=None,
                               relation="PREDICTION_CALIBRATION",
                               basis_digest=str(calibration["calibration_digest"])))

    return tuple(sorted(records, key=lambda record: record.uncertainty_id))


def uncertainty(db_path: str, uncertainty_id: str, *, now: Optional[float] = None,
                stale_after: Optional[float] = None) -> Optional[UncertaintyRecord]:
    """The current projection for one id, or None when the underlying state has resolved (law 6)."""
    for record in derive_uncertainties(db_path, now=now, stale_after=stale_after):
        if record.uncertainty_id == uncertainty_id:
            return record
    return None


def _latest_snapshot(db_path: str, uncertainty_id: str) -> Optional[Dict[str, Any]]:
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute(
            "SELECT * FROM ciph_uncertainty_snapshots WHERE uncertainty_id = ? "
            "ORDER BY snapshot_version DESC LIMIT 1;", (uncertainty_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    return dict(row) if row is not None else None


def uncertainty_status(db_path: str, uncertainty_id: str, *, now: Optional[float] = None,
                       stale_after: Optional[float] = None) -> str:
    """
    DERIVED status. Closure is automatic: nothing has to decide that a question is answered (law 6).
    """
    current = uncertainty(db_path, uncertainty_id, now=now, stale_after=stale_after)
    latest = _latest_snapshot(db_path, uncertainty_id)
    if current is not None:
        if latest is None or latest["basis_digest"] != current.basis_digest:
            return STATUS_STALE if latest is not None else STATUS_OPEN
        return STATUS_OPEN
    return STATUS_SATISFIED if latest is not None else STATUS_INVALID


def record_uncertainty_snapshots(db_path: str, *, now: Optional[float] = None,
                                 stale_after: Optional[float] = None) -> int:
    """
    Append the current projection when it changed. Historical records are never rewritten (law 5).
    """
    moment = time.time() if now is None else float(now)
    records = derive_uncertainties(db_path, now=moment, stale_after=stale_after)
    conn = _connect(db_path)
    appended = 0
    try:
        init_schema(conn)
        for record in records:
            latest = conn.execute(
                "SELECT * FROM ciph_uncertainty_snapshots WHERE uncertainty_id = ? "
                "ORDER BY snapshot_version DESC LIMIT 1;", (record.uncertainty_id,)).fetchone()
            if latest is not None and latest["basis_digest"] == record.basis_digest:
                continue
            version = (int(latest["snapshot_version"]) + 1) if latest is not None else 1
            conn.execute(
                "INSERT INTO ciph_uncertainty_snapshots (uncertainty_id, snapshot_version, "
                "source_kind, source_ref, subject, relation, reducibility, reason_codes_json, "
                "basis_digest, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?);",
                (record.uncertainty_id, version, record.source_kind, record.source_ref,
                 record.subject, record.relation, record.reducibility,
                 json.dumps(list(record.reason_codes)), record.basis_digest, moment),
            )
            appended += 1
        conn.commit()
    finally:
        conn.close()
    return appended


def uncertainty_history(db_path: str, uncertainty_id: str) -> List[Dict[str, Any]]:
    """Every historical projection of one uncertainty, oldest first."""
    conn = _connect(db_path, read_only=True)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_uncertainty_snapshots WHERE uncertainty_id = ? "
            "ORDER BY snapshot_version;", (uncertainty_id,))]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def uncertainty_digest(db_path: str, *, now: Optional[float] = None,
                       stale_after: Optional[float] = None) -> str:
    """The deterministic identity of the registry (law 8)."""
    return _digest([record.as_dict() for record in
                    derive_uncertainties(db_path, now=now, stale_after=stale_after)])
