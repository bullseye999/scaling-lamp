"""
ciph/kernel/federation_scanners - 7.x: the sixteen structural zeros.

    1  node self-membership authorization                         = 0
    2  node self-authority-domain assignment                      = 0
    3  quorum/consensus verdict changing canonical authority      = 0
    4  ghost mesh handshake/task changing canonical authority      = 0
    5  sovereignty engine authorizing a canonical transition       = 0
    6  node direct permit signing                                  = 0
    7  node direct R7 activation bypass                            = 0
    8  node direct meta-promotion / epoch mutation                 = 0
    9  universal last-write-wins on constitutional state           = 0
    10 wall-clock winner selection for authority conflicts         = 0
    11 timeout treated as proof of death or quiescence             = 0
    12 SECRET_LOCAL state entering ordinary replication            = 0
    13 stale generation accepted as current                        = 0
    14 ordinary replication overwriting an authority-domain owner  = 0
    15 cross-node delegation widening its scope                    = 0
    16 federation creating a second execution constitution         = 0

Pure functions over `{relative_path: source_text}`. Static and syntactic, exactly like 4.5-6.x: they
narrow the bypass surface and cannot decide semantic equivalence. Several are PRESENCE checks - the law
has to be in the code, not only in this sentence - and every one has a catch-specimen.

SCOPE: the 7.x namespace (`ciph/kernel/federation_*.py`), plus project-wide call-site checks for the
authority-shaped mechanisms (3, 4, 5) which are allowed to exist and are not allowed to be consumed.
Catalogue modules are excluded by name: a file that declares a pattern is not a file that uses it.
"""

import pathlib
import re
from typing import Any, Dict, Mapping, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError

FEDERATION_SCANNER_VIOLATION = "FEDERATION_SCANNER_VIOLATION"

FEDERATION_NAMESPACE = "ciph/kernel/federation_"
NODE_OWNER = "ciph/kernel/federation_node.py"
AUTHORITY_OWNER = "ciph/kernel/federation_authority.py"
REPLICATION_OWNER = "ciph/kernel/federation_replication.py"
DELEGATION_OWNER = "ciph/kernel/federation_delegation.py"
QUIESCENCE_OWNER = "ciph/kernel/federation_quiescence.py"

CATALOGUE = ("ciph/kernel/federation_scanners.py", "ciph/kernel/federation_ownership.py",
             "ciph/kernel/meta_scanners.py", "ciph/kernel/autonomy_scanners.py",
             "ciph/kernel/swarm_scanners.py", "ciph/kernel/swarm_ownership.py",
             "ciph/kernel/evolution_ownership.py")

_MECHANISM_OWNERS = ("ciph/federation/ghost_mesh.py", "ciph/federation/__init__.py",
                     "ciph/swarm/byzantine_consensus.py", "ciph/swarm/__init__.py",
                     "ciph/sovereignty/singularity_engine.py", "ciph/sovereignty/__init__.py")

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _sources(sources: Mapping[str, str]) -> Dict[str, str]:
    """Functional 7.x modules only - the catalogues declare these patterns as data."""
    return {relative: text for relative, text in sources.items()
            if relative.startswith(FEDERATION_NAMESPACE) and relative not in CATALOGUE}


def _production(sources: Mapping[str, str]) -> Dict[str, str]:
    return {relative: text for relative, text in sources.items()
            if relative not in CATALOGUE and relative not in _MECHANISM_OWNERS}


def _writes(text: str, table: str) -> bool:
    if f"UPDATE {table}" in text or f"DELETE FROM {table}" in text:
        return True
    return re.search(rf"INSERT(?: OR \w+)? INTO {re.escape(table)}\b", text) is not None


def s01_node_self_membership_authorization(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = [f"{relative}:writes-membership"
                for relative, text in _sources(sources).items()
                if relative != NODE_OWNER and _writes(text, "ciph_federation_membership")]
    owner = sources.get(NODE_OWNER, "")
    if "_REQUIRES_OPERATOR" not in owner:
        offences.append(f"{NODE_OWNER}:missing-operator-transition-guard")
    if "REASON_NOT_OPERATOR" not in owner:
        offences.append(f"{NODE_OWNER}:missing-enrolment-guard")
    return tuple(sorted(offences))


def s02_node_self_authority_domain_assignment(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = [f"{relative}:writes-authority-domains"
                for relative, text in _sources(sources).items()
                if relative != AUTHORITY_OWNER and re.search(
                    r"(INSERT(?: OR \w+)? INTO|UPDATE|DELETE FROM) ciph_federation_authority_domains",
                    text)]
    owner = sources.get(AUTHORITY_OWNER, "")
    if "assert_authoritative" not in owner:
        offences.append(f"{AUTHORITY_OWNER}:missing-lineage-gate")
    return tuple(sorted(offences))


def s03_quorum_verdict_changes_authority(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """The consensus engine may exist; nothing may act on what it decides."""
    return tuple(sorted(relative for relative, text in _production(sources).items()
                        if "ByzantineConsensusEngine" in text or "evaluate_consensus(" in text))


def s04_ghostmesh_changes_authority(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = [f"{relative}:mesh-envelope-in-federation"
                for relative, text in _sources(sources).items()
                if "MeshTaskEnvelope" in text or "MeshHandshake" in text]
    ghost = sources.get("ciph/federation/ghost_mesh.py", "")
    if any(_writes(ghost, table) for table in ("ciph_federation_authority_domains",
                                               "ciph_federation_authority_events",
                                               "ciph_federation_membership")):
        offences.append("ciph/federation/ghost_mesh.py:writes-canonical-authority")
    return tuple(sorted(offences))


def s05_sovereignty_authorizes_transition(sources: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(sorted(relative for relative, text in _sources(sources).items()
                        if "execute_governed_evolution_promotion" in text
                        or "SolvencyStatus" in text))


def s06_node_permit_signing(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _sources(sources).items():
        for forbidden in ("SignedExecutionPermit", "issue_permit", "PermitStore", ".claim(",
                          "permit_store"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def s07_node_r7_bypass(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _sources(sources).items():
        for forbidden in ("file_activation", "replace_at(", "write_bytes(", "activate("):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def s08_node_meta_mutation(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _sources(sources).items():
        for table in ("ciph_meta_promotions", "ciph_evolution_epochs", "ciph_crucible_active"):
            if _writes(text, table):
                offences.append(f"{relative}:writes-{table}")
    return tuple(sorted(set(offences)))


def s09_universal_last_write_wins(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _sources(sources).items():
        for forbidden in ("last_write_wins(", "universal_last_write_wins", "resolve_by_timestamp(",
                          "newest_wins"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def s10_wall_clock_authority(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """
    Wall time is metadata. Two halves: no module may order constitutional state by it, and the refusal
    must actually exist in the replication owner.
    """
    offences = []
    for relative, text in _sources(sources).items():
        # The signal is the wall clock being used as an ORDERING KEY. A named helper that orders by
        # timestamp is the same offence wearing a function name.
        for forbidden in ("by_timestamp(", "latest_record_wins", "key=lambda r: r.wall_time",
                          "order_by_wall_time("):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    if "authority_winner_by_wall_clock" not in sources.get(REPLICATION_OWNER, ""):
        offences.append(f"{REPLICATION_OWNER}:missing-wall-clock-refusal")
    return tuple(sorted(offences))


def s11_timeout_as_death(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _sources(sources).items():
        for forbidden in ("treat_timeout_as_dead", "assume_dead(", "timeout_implies_dead",
                          "def mark_dead"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    quiescence = sources.get(QUIESCENCE_OWNER, "")
    if "OBSERVED_UNREACHABLE" not in quiescence or "UNREACHABLE" not in quiescence:
        offences.append(f"{QUIESCENCE_OWNER}:missing-unreachable-status")
    return tuple(sorted(offences))


def s12_secret_local_replicated(sources: Mapping[str, str]) -> Tuple[str, ...]:
    allowed = {"ciph/kernel/federation_state.py", "ciph/kernel/federation_replication.py"}
    offences = [f"{relative}:secret-local-token"
                for relative, text in _sources(sources).items()
                if "SECRET_LOCAL" in text and relative not in allowed]
    if "REFUSED_CLASS" not in sources.get(REPLICATION_OWNER, ""):
        offences.append(f"{REPLICATION_OWNER}:missing-secret-refusal")
    return tuple(sorted(offences))


def s13_stale_generation_accepted(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """
    A module that reasons about node generations must state the currency rule somewhere in the file.
    Syntactic proxy, and the limit is that it cannot see a semantically wrong check - only a missing one.
    """
    offences = []
    for relative, text in _sources(sources).items():
        if "node_generation" not in text or relative == "ciph/kernel/federation_node.py":
            continue
        if not any(token in text for token in ("is_current_generation", "current_generation(",
                                               "STALE")):
            offences.append(f"{relative}:generation-used-without-currency-check")
    return tuple(sorted(offences))


def s14_replication_overwrites_owner(sources: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(sorted(relative for relative, text in _sources(sources).items()
                        if relative != AUTHORITY_OWNER
                        and re.search(r"UPDATE ciph_federation_authority_domains SET", text)))


def s15_delegation_widens_scope(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _sources(sources).items():
        for forbidden in ("force_scope(", "allow_any_class", "widen_scope("):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    if "assert_scope_within_delegation" not in sources.get(DELEGATION_OWNER, ""):
        offences.append(f"{DELEGATION_OWNER}:missing-scope-guard")
    return tuple(sorted(offences))


def s16_second_execution_constitution(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _sources(sources).items():
        for forbidden in ("class FederationExecutor", "def execute_raw", "def background_execute",
                          "class PermitAuthority", "def mint_permit"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


FEDERATION_SCANNERS = (
    ("s01_node_self_membership_authorization", s01_node_self_membership_authorization),
    ("s02_node_self_authority_domain_assignment", s02_node_self_authority_domain_assignment),
    ("s03_quorum_verdict_changes_authority", s03_quorum_verdict_changes_authority),
    ("s04_ghostmesh_changes_authority", s04_ghostmesh_changes_authority),
    ("s05_sovereignty_authorizes_transition", s05_sovereignty_authorizes_transition),
    ("s06_node_permit_signing", s06_node_permit_signing),
    ("s07_node_r7_bypass", s07_node_r7_bypass),
    ("s08_node_meta_mutation", s08_node_meta_mutation),
    ("s09_universal_last_write_wins", s09_universal_last_write_wins),
    ("s10_wall_clock_authority", s10_wall_clock_authority),
    ("s11_timeout_as_death", s11_timeout_as_death),
    ("s12_secret_local_replicated", s12_secret_local_replicated),
    ("s13_stale_generation_accepted", s13_stale_generation_accepted),
    ("s14_replication_overwrites_owner", s14_replication_overwrites_owner),
    ("s15_delegation_widens_scope", s15_delegation_widens_scope),
    ("s16_second_execution_constitution", s16_second_execution_constitution),
)


def scan(sources: Mapping[str, str]) -> Dict[str, Tuple[str, ...]]:
    return {name: scanner(sources) for name, scanner in FEDERATION_SCANNERS}


def scan_project(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    from ciph.kernel.evolution_ownership import production_sources
    return scan(dict(production_sources(root)))


def federation_scanner_census(root: Optional[Any] = None) -> Dict[str, int]:
    return {name: len(offences) for name, offences in scan_project(root).items()}


def assert_all_clean(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    report = scan_project(root)
    dirty = {name: offences for name, offences in report.items() if offences}
    if dirty:
        raise CrucibleError(FEDERATION_SCANNER_VIOLATION,
                            "; ".join(f"{name}:{offences}" for name, offences in dirty.items()))
    return report
