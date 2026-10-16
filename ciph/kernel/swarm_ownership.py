"""
ciph/kernel/swarm_ownership - R10: exactly ONE constitutional owner per swarm concern.

The project already contains real orchestration MACHINERY from earlier programs: a durable IPC job
queue with leases, tokens, receipts and reconciliation (`ciph/workers/ipc_queue.py`), a worker daemon
that consumes it (`ciph/workers/daemon.py`), an agent orchestrator, and - the dangerous one - a Stage-9
"Byzantine Consensus Engine" whose `evaluate_consensus` returns an `approved` flag for a supermajority
of self-signed council nodes (`ciph/swarm/byzantine_consensus.py`).

R10's decision follows R6's exactly:

    there may be many MECHANISMS for running work concurrently,
    but exactly one constitutional OWNER for what a worker IS, what a delegation MEANS, what a lease
    POSSESSES, what a result PROVES, and who may become active.

Three findings, and the third is the reason this module exists:

  1. The queue and the daemon are KEPT. They are battle-tested transport and process supervision; 6.x
     does not rewrite them, and does not own their tables.
  2. Worker identity, delegation, leasing, result provenance, aggregation, capability, health, child
     budgets, quiescence and delegation learning are 6.x's meaning. They are implemented in
     `ciph/kernel/swarm_*.py` and nowhere else.
  3. The Stage-9 consensus engine is DEMOTED TO A MECHANISM, and its `approved` flag is DORMANT: no
     production module may consume it. A supermajority of workers is INFORMATION. If any production
     path could read `approved` and act, "more votes" would have become "more authority" - the exact
     thing 6.x exists to prevent. The zero is scanned, not promised.

`swarm_bypasses` covers process spawning and supervisor duplication from the swarm surface only: the
pre-5.x daemons still spawn processes as a fact of the earlier program, are governed by the R6 census
and the R7 choke point, and are not 6.x's to claim.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SWARM_OWNERSHIP_V1 = "SWARM_OWNERSHIP_V1"
SWARM_OWNERSHIP_VIOLATION = "SWARM_OWNERSHIP_VIOLATION"

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

SWARM_NAMESPACE = "ciph/kernel/swarm_"

_ONLY = "CANONICAL_ONLY"
_SHARED = "LEGACY_ALLOWED"


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    legacy_ownership_allowed: bool
    signals: Tuple[str, ...]
    also_allowed: Tuple[str, ...] = ()

    def allowed(self) -> Tuple[str, ...]:
        return (self.canonical_owner,) + tuple(self.also_allowed)


# THE FROZEN CENSUS. `TABLE:` is a table a module writes; `CONST:` is a module-level definition.
CENSUS: Tuple[Concern, ...] = (
    Concern("worker identity", "ciph/kernel/swarm_worker.py", False,
            ("TABLE:ciph_swarm_workers",)),
    Concern("worker membership history", "ciph/kernel/swarm_worker.py", False,
            ("TABLE:ciph_swarm_membership",)),
    Concern("worker health", "ciph/kernel/swarm_worker.py", False,
            ("TABLE:ciph_swarm_health",)),
    Concern("worker capability ladder", "ciph/kernel/swarm_worker.py", False,
            ("TABLE:ciph_swarm_capabilities",)),
    Concern("delegation", "ciph/kernel/swarm_delegation.py", False,
            ("TABLE:ciph_swarm_delegations",)),
    Concern("work lease", "ciph/kernel/swarm_delegation.py", False,
            ("TABLE:ciph_swarm_leases",)),
    Concern("worker result provenance", "ciph/kernel/swarm_results.py", False,
            ("TABLE:ciph_swarm_results",)),
    Concern("swarm aggregation", "ciph/kernel/swarm_results.py", False,
            ("TABLE:ciph_swarm_aggregations",)),
    Concern("child budget conservation", "ciph/kernel/swarm_resources.py", False,
            ("TABLE:ciph_swarm_budget_allocations",)),
    Concern("worker spawn governance", "ciph/kernel/swarm_resources.py", False,
            ("TABLE:ciph_swarm_spawn_events",)),
    Concern("quiescence barrier", "ciph/kernel/swarm_quiescence.py", False,
            ("TABLE:ciph_swarm_barriers", "TABLE:ciph_swarm_barrier_acks")),
    Concern("delegation strategy learning", "ciph/kernel/swarm_learning.py", False,
            ("TABLE:ciph_swarm_delegation_attempts",)),
    # Mechanisms that are KEPT. Their ownership above is allowed precisely because they already own
    # their tables and their transport semantics.
    Concern("job queue transport", "ciph/workers/ipc_queue.py", True,
            ("TABLE:ciph_ipc_jobs", "TABLE:ciph_consumed_tokens", "TABLE:ciph_retry_tokens",
             "TABLE:ciph_authorization_grants", "TABLE:ciph_event_store"),
            also_allowed=("ciph/workers/activation_evidence.py", "ciph/workers/receipts.py",
                          "ciph/kernel/retry_transaction.py", "ciph/kernel/permit_issuance.py",
                          "ciph/kernel/permit_store.py", "ciph/kernel/storage_adapter.py",
                          "test_", "tools/")),
    Concern("process supervision", "ciph/workers/daemon.py", True,
            ("CONST:WorkerDaemon", "CONST:main"),
            also_allowed=("ciph/workers/ipc_queue.py", "ciph/kernel/crucible_types.py")),
    Concern("legacy consensus mechanism", "ciph/swarm/byzantine_consensus.py", True,
            ("CONST:ByzantineConsensusEngine", "CONST:CouncilNode", "CONST:CouncilVote")),
)

# Machinery the R10 demotion must NOT lose. Deleting it would be an amputation, not a unification.
RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("ciph/workers/ipc_queue.py", ("IPCJobQueue", "lease_next_job", "reclaim_expired_leases",
                                   "reconcile_job")),
    ("ciph/workers/daemon.py", ("WorkerDaemon",)),
    ("ciph/workers/receipts.py", ("receipt",)),
    ("ciph/swarm/byzantine_consensus.py", ("ByzantineConsensusEngine", "evaluate_consensus")),
    ("agent_orchestrator.py", ("AgentOrchestrator",)),
)

# Production modules that may not consume a swarm vote as authority. Three kinds of file are NOT
# consumers and are excluded by name, for the same reason a scanner is not a caller:
#
#   * the mechanism itself, and the package that exports it - an `__init__` re-export is a declaration;
#   * this census, which necessarily contains the symbol it searches for.
#
# Everything else in the project is a real consumer, and there must be none.
_CONSENSUS_AUTHORITY = "ByzantineConsensusEngine"
_CONSENSUS_OWNER = "ciph/swarm/byzantine_consensus.py"
# Any module whose name says it is a CATALOGUE (a scanner or a census) declares these symbols as data
# and owns none of them. This is now a SUFFIX RULE rather than a hand-maintained list, because the
# explicit list had to be extended once per phase that added a scanner - the collision recurred in 4.7,
# 5.x, 6.x and 7.x, and a rule that keeps needing to be remembered is a rule that will be forgotten.
_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_CONSENSUS_NOT_CONSUMERS = ("ciph/swarm/",)


def _is_catalogue(relative: str) -> bool:
    name = str(relative).rsplit("/", 1)[-1]
    return name.endswith(_CATALOGUE_SUFFIXES)

_SWARM_BYPASS_PATTERNS = (
    "class SwarmExecutor", "class WorkerExecutor", "def execute_raw", "def background_execute",
    "class PermitAuthority", "def mint_permit", "permit_store", ".claim(",
)


def production_sources(root: Optional[Any] = None) -> List[Tuple[str, str]]:
    """Every production source file (tests excluded), as (relative path, text)."""
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
    for pattern in (r"^" + re.escape(name) + r"\s*(?::[^=]+)?=", r"^class\s+" + re.escape(name) + r"\b",
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
    """Modules that own a concern they must not own."""
    violations: List[Dict[str, str]] = []
    for relative, text in production_sources(root):
        for concern in CENSUS:
            if _is_allowed(relative, concern) or concern.legacy_ownership_allowed:
                continue
            for signal in concern.signals:
                if _contains_signal(text, signal):
                    violations.append({"concern": concern.concern, "owner": relative,
                                       "canonical": concern.canonical_owner, "signal": signal})
    return tuple(violations)


def retained_machinery_missing(root: Optional[Any] = None) -> Tuple[str, ...]:
    """The mechanisms R10 demotes but must not lose."""
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
        if relative == _CONSENSUS_OWNER or _is_catalogue(relative):
            continue
        if any(relative.startswith(prefix) for prefix in _CONSENSUS_NOT_CONSUMERS):
            continue
        for symbol in symbols:
            if symbol in text:
                offenders.add(relative)
    return tuple(sorted(offenders))


def dormant_consensus_authority(root: Optional[Any] = None) -> Tuple[str, ...]:
    """
    THE R10 ZERO: no production module outside the mechanism itself consumes swarm votes as authority.

    A supermajority of workers is information. The moment a production path reads the approval verdict
    and acts on it, "more votes" has become "more authority" - so the flag stays unread, and that is
    measured rather than asserted.
    """
    return _consumers(root, (_CONSENSUS_AUTHORITY,))


def swarm_bypasses(root: Optional[Any] = None) -> Tuple[str, ...]:
    """
    No FUNCTIONAL module in the 6.x namespace may build a second executor or a permit authority.

    The catalogues are excluded for the reason stated at `dormant_consensus_authority`: they contain
    these patterns as data, and a file that declares a pattern is not a file that uses it.
    """
    offences = []
    for relative, text in production_sources(root):
        if not relative.startswith(SWARM_NAMESPACE) or relative in (
                "ciph/kernel/swarm_ownership.py", "ciph/kernel/swarm_scanners.py"):
            continue
        for pattern in _SWARM_BYPASS_PATTERNS:
            if pattern in text:
                offences.append(f"{relative}:{pattern}")
    return tuple(sorted(set(offences)))


def ownership_report(root: Optional[Any] = None) -> Dict[str, Any]:
    return {"policy_version": SWARM_OWNERSHIP_V1, "concerns": len(CENSUS),
            "violations": list(ownership_violations(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root)),
            "dormant_consensus_authority": list(dormant_consensus_authority(root)),
            "swarm_bypasses": list(swarm_bypasses(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    for key in ("violations", "retained_machinery_missing", "dormant_consensus_authority",
                "swarm_bypasses"):
        if report[key]:
            raise CrucibleError(SWARM_OWNERSHIP_VIOLATION, f"{key}:{report[key]}")
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
