"""
ciph.kernel.counterfactuals - what MIGHT happen under an intervention, never what DID.

4.3 Gate Four. A simulation begins from an explicit world-state basis and applies explicit
assumptions and interventions. It produces HYPOTHETICAL projections. It is not an observation, it is
not evidence, it is not a world fact, and it never issues authority:

    simulation S1:  IF restart service X   THEN projected recovery probability = 0.7
    simulation S2:  IF no action           THEN projected recovery probability = 0.2

    NEITHER changes world.service_x.status, NEITHER creates evidence, NEITHER mints a permit.

Only if the operator or planner SEPARATELY decides to act does the normal execution constitution
start, and only real observations may later score a simulation.

LAWS (each has a specimen in `test_gate_4_3_counterfactuals.py`)

 1. Simulation begins from an explicit world-state basis.
 2. Assumptions are explicit.
 3. Interventions are explicit.
 4. Simulated output never modifies the canonical world state.
 5. Simulation cannot create evidence.
 6. Simulation cannot issue execution authority.
 7. Multiple counterfactuals may coexist.
 8. Unknown model dynamics remain unknown, not filled with confident narrative.
 9. A simulation becomes a real 4.2 prediction only through that gate's separate boundary.
10. Actual observations may score the simulation afterward, but cannot rewrite what it projected.
11. Same basis + assumptions + deterministic model -> same simulation digest.
12. Historical simulations are immutable.

This module imports no ledger, permit, or execution machinery, and that is deliberate: there is no
call path from a simulation to evidence or to authority, so the separation is structural rather than
a matter of reviewer discipline.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.world_model import world_digest

SIMULATION_KIND = "SIMULATION"
MODEL_VERSION_V1 = "COUNTERFACTUAL_PROJECTION_V1"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_simulations (
        simulation_id TEXT PRIMARY KEY,
        simulation_fingerprint TEXT NOT NULL UNIQUE,
        model_version TEXT NOT NULL,
        world_basis_digest TEXT NOT NULL,
        assumptions_json TEXT,
        interventions_json TEXT,
        projected_outcomes_json TEXT,
        epistemic_kind TEXT NOT NULL,
        created_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_simulation_outcomes (
        outcome_id TEXT PRIMARY KEY,
        simulation_id TEXT NOT NULL,
        observed_outcome TEXT,
        matched INTEGER,
        evidence_ref TEXT,
        recorded_at REAL
    );
    """,
)


class CounterfactualError(Exception):
    """A counterfactual operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class Simulation:
    simulation_id: str
    simulation_fingerprint: str
    model_version: str
    world_basis_digest: str
    assumptions: Tuple[Dict[str, Any], ...]
    interventions: Tuple[Dict[str, Any], ...]
    projected_outcomes: Tuple[Dict[str, Any], ...]
    epistemic_kind: str = SIMULATION_KIND
    created_at: Optional[float] = None

    def as_dict(self) -> Dict[str, Any]:
        return {"simulation_id": self.simulation_id,
                "simulation_fingerprint": self.simulation_fingerprint,
                "model_version": self.model_version, "world_basis_digest": self.world_basis_digest,
                "assumptions": [dict(a) for a in self.assumptions],
                "interventions": [dict(i) for i in self.interventions],
                "projected_outcomes": [dict(o) for o in self.projected_outcomes],
                "epistemic_kind": self.epistemic_kind}

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


def _normalize_items(items: Sequence[Any]) -> List[Dict[str, str]]:
    """Canonical, deterministic rendering of assumptions/interventions/outcomes."""
    out: List[Dict[str, str]] = []
    for item in items:
        if isinstance(item, Mapping):
            out.append({str(key): ("" if value is None else str(value))
                        for key, value in sorted(item.items())})
        else:
            out.append({"statement": str(item)})
    return out


def run_simulation(db_path: str, *, model_version: str = MODEL_VERSION_V1,
                   assumptions: Sequence[Any] = (), interventions: Sequence[Any] = (),
                   projected_outcomes: Sequence[Any] = (),
                   world_basis_digest: Optional[str] = None,
                   now: Optional[float] = None) -> Simulation:
    """
    Record ONE hypothetical projection over an explicit world-state basis (laws 1-3, 11, 12).

    The basis is captured (or supplied by a caller that already holds one), and the projection is
    immutable once written. The same basis, assumptions, interventions and model produce ONE
    simulation, however many times it is run (law 11).
    """
    moment = time.time() if now is None else float(now)
    basis = world_basis_digest or world_digest(db_path, now=moment)
    assumption_items = _normalize_items(assumptions)
    intervention_items = _normalize_items(interventions)
    outcome_items = _normalize_items(projected_outcomes)
    fingerprint = _digest({"model_version": str(model_version), "basis": basis,
                           "assumptions": assumption_items, "interventions": intervention_items,
                           "outcomes": outcome_items})
    simulation_id = "SIM-" + fingerprint[:12].upper()

    conn = _connect(db_path)
    try:
        init_schema(conn)
        existing = conn.execute("SELECT * FROM ciph_simulations WHERE simulation_fingerprint = ?;",
                                (fingerprint,)).fetchone()
        if existing is not None:
            return _row_to_simulation(dict(existing))
        conn.execute(
            "INSERT INTO ciph_simulations (simulation_id, simulation_fingerprint, model_version, "
            "world_basis_digest, assumptions_json, interventions_json, projected_outcomes_json, "
            "epistemic_kind, created_at) VALUES (?,?,?,?,?,?,?,?,?);",
            (simulation_id, fingerprint, str(model_version), basis,
             json.dumps(assumption_items), json.dumps(intervention_items),
             json.dumps(outcome_items), SIMULATION_KIND, moment),
        )
        conn.commit()
    finally:
        conn.close()
    return Simulation(simulation_id=simulation_id, simulation_fingerprint=fingerprint,
                      model_version=str(model_version), world_basis_digest=basis,
                      assumptions=tuple(assumption_items), interventions=tuple(intervention_items),
                      projected_outcomes=tuple(outcome_items), created_at=moment)


def _row_to_simulation(row: Mapping[str, Any]) -> Simulation:
    return Simulation(
        simulation_id=str(row["simulation_id"]),
        simulation_fingerprint=str(row["simulation_fingerprint"]),
        model_version=str(row["model_version"]), world_basis_digest=str(row["world_basis_digest"]),
        assumptions=tuple(json.loads(row["assumptions_json"] or "[]")),
        interventions=tuple(json.loads(row["interventions_json"] or "[]")),
        projected_outcomes=tuple(json.loads(row["projected_outcomes_json"] or "[]")),
        epistemic_kind=str(row["epistemic_kind"]), created_at=row["created_at"])


def get_simulation(db_path: str, simulation_id: str) -> Simulation:
    conn = _connect(db_path, read_only=True)
    try:
        row = conn.execute("SELECT * FROM ciph_simulations WHERE simulation_id = ?;",
                           (simulation_id,)).fetchone()
    except sqlite3.Error:
        row = None
    finally:
        conn.close()
    if row is None:
        raise CounterfactualError("UNKNOWN_SIMULATION", simulation_id)
    return _row_to_simulation(dict(row))


def simulation_history(db_path: str) -> List[Dict[str, Any]]:
    """Every simulation ever recorded. Nothing here is ever rewritten (law 12)."""
    conn = _connect(db_path, read_only=True)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_simulations ORDER BY simulation_id;")]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def attach_outcome(db_path: str, simulation_id: str, *, observed_outcome: str,
                   matched: Optional[bool] = None, evidence_ref: Optional[str] = None,
                   now: Optional[float] = None) -> str:
    """
    Score a simulation against REAL observations afterward (law 10).

    This appends a separate outcome row. It never edits the simulation, so the projection keeps
    whatever it originally said - even when reality disagreed.
    """
    moment = time.time() if now is None else float(now)
    get_simulation(db_path, simulation_id)  # refuses an unknown simulation
    outcome_id = "SOUT-" + hashlib.sha256(
        f"{simulation_id}:{observed_outcome}:{matched}:{evidence_ref}:{moment}".encode("utf-8")
    ).hexdigest()[:12].upper()
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute("INSERT OR IGNORE INTO ciph_simulation_outcomes (outcome_id, simulation_id, "
                     "observed_outcome, matched, evidence_ref, recorded_at) VALUES (?,?,?,?,?,?);",
                     (outcome_id, simulation_id, str(observed_outcome),
                      None if matched is None else (1 if matched else 0), evidence_ref, moment))
        conn.commit()
        return outcome_id
    finally:
        conn.close()


def outcome_history(db_path: str, simulation_id: str) -> List[Dict[str, Any]]:
    conn = _connect(db_path, read_only=True)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_simulation_outcomes WHERE simulation_id = ? ORDER BY outcome_id;",
            (simulation_id,))]
    except sqlite3.Error:
        return []
    finally:
        conn.close()


def as_evidence_ref(*_args: Any, **_kwargs: Any) -> str:
    """A simulation is NEVER admitted as evidence, and the refusal is a function, not a rule (law 5)."""
    raise CounterfactualError("SIMULATION_IS_NOT_EVIDENCE",
                              "a counterfactual projection cannot enter the epistemic ledger")


def simulation_digest(db_path: str) -> str:
    """The deterministic identity of the counterfactual model (law 11)."""
    return _digest([_row_to_simulation(row).as_dict() for row in simulation_history(db_path)])
