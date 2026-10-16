"""
ciph/kernel/autonomy_scanners - 5.0: the eight structural zeros.

    raw autonomous executor                 = 0
    daemon direct PermitStore.claim         = 0
    daemon direct file activation           = 0
    autonomy private signer                 = 0
    autonomy creating StandingAuthorization = 0
    autonomy overriding operator mode       = 0
    autonomous production deploy outside R7 = 0
    autonomous meta promotion outside 4.7   = 0

and the four zeros that 5.1/5.2/5.5 add:

    autonomy spawns a process                = 0
    autonomy deletes canonical history       = 0
    charter purpose is rewritten             = 0
    maintenance mutates the environment      = 0

Pure functions over `{relative_path: source_text}`, so the real tree and a synthetic violation are
scanned identically. Static and syntactic, like the 4.7 scanners, and with the same stated limit: they
narrow the bypass surface rather than deciding semantic equivalence.

"Autonomy module" means any module in the autonomy namespace plus the daemon entry points. A candidate
that calls the guarded executor through the normal 4.0 path is not a bypass; calling the authority
machinery directly is.
"""

import pathlib
import re
from typing import Any, Dict, Mapping, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError

AUTONOMY_SCANNER_VIOLATION = "AUTONOMY_SCANNER_VIOLATION"

AUTONOMY_MODULES_PREFIX = "ciph/kernel/autonomy_"
AUTONOMY_MODULES = ("ciph/kernel/autonomous_work.py", "ciph/kernel/standing_authorization.py",
                    "ciph/kernel/crucible_handoff.py", "ciph/kernel/mission_stewardship.py")
DAEMON_ENTRY_POINTS = ("ciph_evolution.py", "run_ciph.py", "run_worker.py", "agent_orchestrator.py")

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]


SELF = "ciph/kernel/autonomy_scanners.py"


def _autonomy_sources(sources: Mapping[str, str], *, include_daemons: bool = True) -> Dict[str, str]:
    """
    Which modules the autonomy scanners own.

    The autonomy namespace always. The daemon entry points are included for the authority-surface checks
    (they must not claim permits, activate files, mint standing authority or promote), but NOT for the
    key-custody check: `ciph_evolution.py` already holds the kernel identity because that is a fact of
    the legacy architecture, governed by the R6 ownership census and the R7 choke point rather than by
    5.0. Claiming it here would be 5.0 asserting authority over code it does not own.

    This module is excluded by name: it necessarily contains the very patterns it looks for.
    """
    selected = {}
    for relative, text in sources.items():
        if relative == SELF:
            continue
        if relative.startswith(AUTONOMY_MODULES_PREFIX) or relative in AUTONOMY_MODULES:
            selected[relative] = text
        elif include_daemons and relative in DAEMON_ENTRY_POINTS:
            selected[relative] = text
    return selected


def a01_raw_autonomous_executor(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """No autonomous module may define its own executor or a background execution primitive."""
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        for forbidden in ("def background_execute", "class AutonomyExecutor",
                          "class AutonomousExecutor", "def execute_raw",
                          "def raw_execute"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def a02_daemon_direct_permit_claim(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """Curiosity, autonomy and daemons never claim a permit: the worker does, through GuardedExecutor."""
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        if re.search(r"\.claim\(", text) or "permit_store" in text:
            offences.append(f"{relative}:direct-claim")
        if "GuardedExecutor" in text and "import" in text and "class " not in text:
            offences.append(f"{relative}:reaches-guarded-executor")
    return tuple(sorted(set(offences)))


def a03_daemon_direct_file_activation(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        if "file_activation" in text or "replace_at(" in text or "write_bytes(" in text:
            offences.append(f"{relative}:direct-file-activation")
    return tuple(sorted(set(offences)))


def a04_autonomy_private_signer(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """Scope: the autonomy namespace only - see `_autonomy_sources` for why the daemons are excluded."""
    offences = []
    for relative, text in _autonomy_sources(sources, include_daemons=False).items():
        for forbidden in ("Ed25519KeyManager", "ExecutionAuthority", "SignedExecutionPermit",
                          "crypto_identity", "kernel_priv_bytes"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def a05_autonomy_creates_standing_authorization(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """Only the governance surface may grant standing authority; autonomy may only read it."""
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        if relative == "ciph/kernel/standing_authorization.py":
            continue
        if "create_standing_authorization(" in text:
            offences.append(f"{relative}:mints-standing-authorization")
    return tuple(sorted(set(offences)))


def a06_autonomy_overrides_operator_mode(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        if relative == "ciph/kernel/autonomy_modes.py":
            continue
        if "set_mode(" in text:
            offences.append(f"{relative}:sets-autonomy-mode")
    return tuple(sorted(set(offences)))


def a07_autonomous_production_deploy(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """Autonomy stops at PROMOTION_READY: no promotion, no deployment, no R7 crossing."""
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        for forbidden in ("evolution_deployment", "meta_promote(", "promote("):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def a08_autonomous_meta_promotion(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        for forbidden in ("transition_epoch(", "rollback_epoch(", "meta_guard"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def a09_autonomy_spawns_a_process(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """
    5.2: a schedule NOMINATES work. Execution belongs to the normal governed path, so an autonomy
    module that reaches for a process is building the second executor by hand.

    SCOPE: the autonomy namespace, NOT the daemon entry points. `ciph_evolution.py` and `run_ciph.py`
    are the pre-5.x daemons; they already spawn processes as a fact of the earlier program and are
    governed by the R6 ownership census and the R7 choke point. Claiming them here would be 5.x
    asserting a property over code it has not migrated - so the limit is stated instead of papered over
    by a scanner that excludes whatever it happens to find on the day it runs.
    """
    offences = []
    for relative, text in _autonomy_sources(sources, include_daemons=False).items():
        for forbidden in ("subprocess.", "os.system(", "os.exec", "Popen(", "os.spawn",
                          "pty.spawn"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def a10_autonomy_deletes_canonical_history(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """
    5.5: an interrupt is an EVENT, never a rewrite. Nothing on the autonomy surface deletes rows, so a
    stop cannot tidy the record of what was stopped.
    """
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        if re.search(r"\bDELETE\s+FROM\b", text, re.IGNORECASE):
            offences.append(f"{relative}:deletes-history")
        if re.search(r"\bDROP\s+TABLE\b", text, re.IGNORECASE):
            offences.append(f"{relative}:drops-a-table")
    return tuple(sorted(set(offences)))


def a11_charter_purpose_is_rewritten(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """
    5.1: purpose is frozen once written. This scanner covers the direct rewrite only - it cannot decide
    semantic equivalence between two differently-worded purposes, which is why the purpose DIGEST is
    the real gate and this is the crude second line.
    """
    offences = []
    for relative, text in _autonomy_sources(sources).items():
        if re.search(r"UPDATE\s+ciph_mission_charters\s+SET[^;]*\bpurpose\b", text, re.IGNORECASE):
            offences.append(f"{relative}:rewrites-charter-purpose")
    return tuple(sorted(set(offences)))


def a12_maintenance_mutates_the_environment(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """
    5.6: maintenance is work Ciph does to itself. An upgrade is a GOVERNED CHANGE, so the autonomy
    surface does not carry the means to install, upgrade or pull anything.

    SCOPE: the autonomy namespace only, for the same reason as a09 - the text it flags today is a
    `run_ciph.py` help string, and a scanner that fires on documentation is a scanner people learn to
    ignore. A false positive here would cost more than the coverage it buys.
    """
    offences = []
    for relative, text in _autonomy_sources(sources, include_daemons=False).items():
        lowered = text.lower()
        for forbidden in ("pip install", "pip3 install", "pip uninstall", "apt-get", "apt install",
                          "npm install", "git pull", "git checkout", "git reset"):
            if forbidden in lowered:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


AUTONOMY_SCANNERS = (
    ("a01_raw_autonomous_executor", a01_raw_autonomous_executor),
    ("a02_daemon_direct_permit_claim", a02_daemon_direct_permit_claim),
    ("a03_daemon_direct_file_activation", a03_daemon_direct_file_activation),
    ("a04_autonomy_private_signer", a04_autonomy_private_signer),
    ("a05_autonomy_creates_standing_authorization", a05_autonomy_creates_standing_authorization),
    ("a06_autonomy_overrides_operator_mode", a06_autonomy_overrides_operator_mode),
    ("a07_autonomous_production_deploy", a07_autonomous_production_deploy),
    ("a08_autonomous_meta_promotion", a08_autonomous_meta_promotion),
    ("a09_autonomy_spawns_a_process", a09_autonomy_spawns_a_process),
    ("a10_autonomy_deletes_canonical_history", a10_autonomy_deletes_canonical_history),
    ("a11_charter_purpose_is_rewritten", a11_charter_purpose_is_rewritten),
    ("a12_maintenance_mutates_the_environment", a12_maintenance_mutates_the_environment),
)


def scan(sources: Mapping[str, str]) -> Dict[str, Tuple[str, ...]]:
    return {name: scanner(sources) for name, scanner in AUTONOMY_SCANNERS}


def scan_project(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    from ciph.kernel.evolution_ownership import production_sources
    return scan(dict(production_sources(root)))


def assert_all_clean(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    report = scan_project(root)
    dirty = {name: offences for name, offences in report.items() if offences}
    if dirty:
        raise CrucibleError(AUTONOMY_SCANNER_VIOLATION,
                            "; ".join(f"{name}:{offences}" for name, offences in dirty.items()))
    return report


def autonomy_scanner_census(root: Optional[Any] = None) -> Dict[str, int]:
    return {name: len(offences) for name, offences in scan_project(root).items()}
