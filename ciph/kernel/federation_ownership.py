"""
ciph/kernel/federation_ownership - R11: exactly ONE constitutional owner per federation concern.

    Distribution grants reach, not sovereignty.

The survey (R11, recorded in the register) found three kinds of thing in the tree, and this module makes
the classification ENFORCED rather than remembered.

KEPT AS MECHANISM. `ciph/federation/ghost_mesh.py` carries handshakes, task envelopes and trusted-peer
keys between hosts. `ciph/workers/ipc_queue.py` is the only durable carrier that exists. The Stage-9
Byzantine consensus engine is the signed multi-node opinion mechanism. None of the three may decide
anything constitutional, and that is measured: zero production consumers.

CLASSIFIED BEFORE AUTHORITY. `ciph/sovereignty/singularity_engine.py` is not a mere projection - it
DISPATCHES a promotion through `runtime.execute_reference_loop`, via
`execute_governed_evolution_promotion`. It is fail-closed (no operator grant, no transition) and nothing
in production calls it today, but it is a second promotion-shaped transition path outside 4.5/4.7/R7.
So it is treated as authority-shaped until 7.x explicitly gives it standing, and its consumer count is
scanned like the others. The operator-grant requirement is a failsafe, not a justification.

ABSENT, AND THEREFORE 7.x's. Node identity and generation, membership, state classification, authority
domains, partition semantics, distributed quiescence, clock law, reconciliation, node key custody, node
health, rejoin and retirement, routing and federation learning are all built in `ciph/kernel/federation_*`
and nowhere else.

The last zero matters most: a dormant legacy path that can activate distributed authority. That is
`second_federation_authority` plus `federation_bypasses` - read together they say the federation has one
owner and no back door.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

FEDERATION_OWNERSHIP_V1 = "FEDERATION_OWNERSHIP_V1"
FEDERATION_OWNERSHIP_VIOLATION = "FEDERATION_OWNERSHIP_VIOLATION"

FEDERATION_NAMESPACE = "ciph/kernel/federation_"

# Modules that necessarily CONTAIN other phases' forbidden tokens as data. A catalogue is not code that
# does things - the principle that has now been repaired in three separate phases (4.7's s03 reading
# 5.x's pattern list, the R6 census reading 6.x's scanner, and the swarm scanners reading themselves).
_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")


def _is_catalogue(relative: str) -> bool:
    """A file that declares a pattern is not a file that uses it - a suffix rule, not a list."""
    name = str(relative).rsplit("/", 1)[-1]
    return name.endswith(_CATALOGUE_SUFFIXES)


CATALOGUE = ("ciph/kernel/federation_ownership.py", "ciph/kernel/federation_scanners.py",
             "ciph/kernel/meta_scanners.py", "ciph/kernel/autonomy_scanners.py",
             "ciph/kernel/swarm_scanners.py", "ciph/kernel/swarm_ownership.py",
             "ciph/kernel/evolution_ownership.py")

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

_ONLY = "CANONICAL_ONLY"
_MECHANISM = "MECHANISM_ALLOWED"


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    mechanism_ownership_allowed: bool
    signals: Tuple[str, ...]
    also_allowed: Tuple[str, ...] = ()

    def allowed(self) -> Tuple[str, ...]:
        return (self.canonical_owner,) + tuple(self.also_allowed)


CENSUS: Tuple[Concern, ...] = (
    Concern("node identity", "ciph/kernel/federation_node.py", False,
            ("TABLE:ciph_federation_nodes",)),
    Concern("node membership", "ciph/kernel/federation_node.py", False,
            ("TABLE:ciph_federation_membership",)),
    Concern("node health", "ciph/kernel/federation_node.py", False,
            ("TABLE:ciph_federation_health",)),
    Concern("node key custody", "ciph/kernel/federation_keys.py", False,
            ("TABLE:ciph_federation_node_keys",)),
    Concern("state classification", "ciph/kernel/federation_state.py", False,
            ("CONST:FEDERATION_STATE_CLASSIFICATION_V1",)),
    Concern("authority domains", "ciph/kernel/federation_authority.py", False,
            ("TABLE:ciph_federation_authority_domains",)),
    Concern("authority transitions", "ciph/kernel/federation_authority.py", False,
            ("TABLE:ciph_federation_authority_events",)),
    Concern("partition view", "ciph/kernel/federation_authority.py", False,
            ("TABLE:ciph_federation_partitions",)),
    Concern("replicated records", "ciph/kernel/federation_replication.py", False,
            ("TABLE:ciph_federation_replicated_records",)),
    Concern("reconciliation", "ciph/kernel/federation_replication.py", False,
            ("TABLE:ciph_federation_reconciliations",)),
    Concern("clock law", "ciph/kernel/federation_replication.py", False,
            ("CONST:FEDERATION_CLOCK_LAW_V1",)),
    Concern("federation quiescence", "ciph/kernel/federation_quiescence.py", False,
            ("TABLE:ciph_federation_barriers",)),
    Concern("cross-node delegation", "ciph/kernel/federation_delegation.py", False,
            ("TABLE:ciph_federation_delegations",)),
    Concern("placement", "ciph/kernel/federation_delegation.py", False,
            ("TABLE:ciph_federation_placements",)),
    Concern("federation learning", "ciph/kernel/federation_delegation.py", False,
            ("TABLE:ciph_federation_placement_attempts",)),
    # MECHANISMS. Kept, and allowed to own what they already own.
    Concern("peer transport", "ciph/federation/ghost_mesh.py", True,
            ("CONST:GhostMeshNode", "CONST:MeshHandshake", "CONST:MeshTaskEnvelope"),
            also_allowed=("ciph/kernel/federation_ownership.py", "test_", "tools/")),
    Concern("job queue transport", "ciph/workers/ipc_queue.py", True,
            ("TABLE:ciph_ipc_jobs",),
            also_allowed=("ciph/kernel/retry_transaction.py", "ciph/kernel/permit_issuance.py",
                          "ciph/kernel/permit_store.py", "ciph/kernel/storage_adapter.py",
                          "ciph/workers/activation_evidence.py", "ciph/workers/receipts.py",
                          "test_", "tools/")),
    Concern("legacy consensus mechanism", "ciph/swarm/byzantine_consensus.py", True,
            ("CONST:ByzantineConsensusEngine",)),
    Concern("legacy sovereignty dispatcher", "ciph/sovereignty/singularity_engine.py", True,
            ("CONST:SovereigntyEngine", "CONST:SolvencyStatus")),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("ciph/federation/ghost_mesh.py", ("GhostMeshNode", "MeshHandshake", "MeshTaskEnvelope")),
    ("ciph/workers/ipc_queue.py", ("IPCJobQueue", "lease_next_job", "reclaim_expired_leases")),
    ("ciph/swarm/byzantine_consensus.py", ("ByzantineConsensusEngine", "evaluate_consensus")),
    ("ciph/sovereignty/singularity_engine.py", ("SovereigntyEngine",
                                                "execute_governed_evolution_promotion")),
)

# Authority-shaped symbols that must have ZERO production consumers outside their own mechanism and the
# catalogues that name them.
_AUTHORITY_SHAPED = {
    "ghost_mesh_constitutional": ("GhostMeshNode", "MeshHandshake", "MeshTaskEnvelope"),
    "consensus_verdict": ("ByzantineConsensusEngine",),
    "sovereignty_transition": ("execute_governed_evolution_promotion",),
}
# Mechanisms, plus the packages that merely EXPORT them: an `__init__` re-export is a declaration, and
# reading it as a consumer would be the same false positive this project has now repaired three times.
_MECHANISM_OWNERS = ("ciph/federation/ghost_mesh.py", "ciph/federation/__init__.py",
                     "ciph/swarm/byzantine_consensus.py", "ciph/swarm/__init__.py",
                     "ciph/sovereignty/singularity_engine.py", "ciph/sovereignty/__init__.py")

# A second federation authority would look like a module outside the canonical owners writing canonical
# distributed state. These are the tables that MEAN ownership.
_AUTHORITY_TABLES = ("ciph_federation_authority_domains", "ciph_federation_authority_events",
                     "ciph_federation_membership", "ciph_federation_nodes")

_FEDERATION_BYPASS_PATTERNS = (
    "universal_last_write_wins", "last_write_wins(", "resolve_by_timestamp(", "quorum_seizes",
    "def seize_authority", "def take_over", "assume_dead(", "treat_timeout_as_dead",
    "class FederationExecutor", "def execute_raw", "class PermitAuthority", "def mint_permit",
    "permit_store", ".claim(",
)


def production_sources(root: Optional[Any] = None) -> List[Tuple[str, str]]:
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    sources: List[Tuple[str, str]] = []
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            continue
        try:
            sources.append((path.relative_to(base).as_posix(), path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return sources


def _defines(text: str, name: str) -> bool:
    for pattern in (r"^" + re.escape(name) + r"\s*(?::[^=]+)?=",
                    r"^class\s+" + re.escape(name) + r"\b",
                    r"^def\s+" + re.escape(name) + r"\b"):
        if re.search(pattern, text, re.MULTILINE) is not None:
            return True
    return False


def _writes(text: str, table: str) -> bool:
    if f"UPDATE {table}" in text or f"DELETE FROM {table}" in text:
        return True
    return re.search(rf"INSERT(?: OR \w+)? INTO {re.escape(table)}\b", text) is not None


def _contains_signal(text: str, signal: str) -> bool:
    kind, _, name = signal.partition(":")
    return _defines(text, name) if kind == "CONST" else _writes(text, name)


def _is_allowed(relative: str, concern: Concern) -> bool:
    for candidate in concern.allowed():
        if candidate.startswith("test_") and relative.startswith("test_"):
            return True
        if candidate.endswith("/") and relative.startswith(candidate):
            return True
        if relative == candidate:
            return True
    return False


def ownership_violations(root: Optional[Any] = None) -> Tuple[Dict[str, str], ...]:
    """Modules that own a federation concern they must not own."""
    violations: List[Dict[str, str]] = []
    for relative, text in production_sources(root):
        if relative in CATALOGUE or _is_catalogue(relative):
            continue
        for concern in CENSUS:
            if concern.mechanism_ownership_allowed or _is_allowed(relative, concern):
                continue
            for signal in concern.signals:
                if _contains_signal(text, signal):
                    violations.append({"concern": concern.concern, "owner": relative,
                                       "canonical": concern.canonical_owner, "signal": signal})
    return tuple(violations)


def retained_machinery_missing(root: Optional[Any] = None) -> Tuple[str, ...]:
    sources = dict(production_sources(root))
    missing = []
    for relative, names in RETAINED_MACHINERY:
        text = sources.get(relative)
        if text is None:
            missing.append(f"{relative}:missing-file")
            continue
        for name in names:
            if name not in text:
                missing.append(f"{relative}:{name}")
    return tuple(missing)


def _consumers(root: Optional[Any] = None, symbols: Tuple[str, ...] = (),
               sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """A pure function over a sources mapping when one is given, so a synthetic tree can be scanned."""
    offenders = set()
    for relative, text in (sources if sources is not None else production_sources(root)):
        if relative in CATALOGUE or _is_catalogue(relative) or relative in _MECHANISM_OWNERS:
            continue
        for symbol in symbols:
            if symbol in text:
                offenders.add(relative)
    return tuple(sorted(offenders))


def authority_shaped_consumers(root: Optional[Any] = None,
                               sources: Optional[List[Tuple[str, str]]] = None
                               ) -> Dict[str, Tuple[str, ...]]:
    """
    THE R11 ZEROS: nothing in production consumes a distributed verdict or a sovereignty dispensation.

    Read `sovereignty_transition` carefully - it is the one that would look harmless. A module that
    calls `execute_governed_evolution_promotion` is asking a solvency projection to promote an upgrade;
    the operator-grant check inside it is what keeps that fail-closed today, and the count of callers is
    what keeps it dormant.
    """
    return {name: _consumers(root, symbols, sources=sources)
            for name, symbols in sorted(_AUTHORITY_SHAPED.items())}


def second_federation_authority(root: Optional[Any] = None) -> Tuple[str, ...]:
    """No production module outside the canonical owners writes canonical distributed state."""
    offenders = []
    for relative, text in production_sources(root):
        # The suffix rule, applied EVERYWHERE it belongs. This was the third check in this file to
        # need it: a catalogue that NAMES a table - even inside a pattern that looks exactly like a
        # write - is not a module that writes it.
        if _is_catalogue(relative) or relative in CATALOGUE \
                or relative.startswith(FEDERATION_NAMESPACE):
            continue
        if any(_writes(text, table) for table in _AUTHORITY_TABLES):
            offenders.append(relative)
    return tuple(sorted(set(offenders)))


def federation_bypasses(root: Optional[Any] = None) -> Tuple[str, ...]:
    """No functional module in the 7.x namespace may build a second executor or a vote-to-authority path."""
    offences = []
    for relative, text in production_sources(root):
        if not relative.startswith(FEDERATION_NAMESPACE) or _is_catalogue(relative) \
                or relative in CATALOGUE:
            continue
        for pattern in _FEDERATION_BYPASS_PATTERNS:
            if pattern in text:
                offences.append(f"{relative}:{pattern}")
    return tuple(sorted(set(offences)))


def ownership_report(root: Optional[Any] = None) -> Dict[str, Any]:
    return {"policy_version": FEDERATION_OWNERSHIP_V1, "concerns": len(CENSUS),
            "violations": list(ownership_violations(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root)),
            "authority_shaped_consumers": {name: list(consumers) for name, consumers
                                           in authority_shaped_consumers(root).items()},
            "second_federation_authority": list(second_federation_authority(root)),
            "federation_bypasses": list(federation_bypasses(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: report[key] for key in ("violations", "retained_machinery_missing",
                                             "second_federation_authority", "federation_bypasses")
                if report[key]}
    for name, consumers in report["authority_shaped_consumers"].items():
        if consumers:
            failures[f"consumers:{name}"] = consumers
    if failures:
        raise CrucibleError(FEDERATION_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
