"""
ciph/kernel/swarm_scanners - 6.x: the twelve structural zeros.

    worker private execution signer                 = 0
    worker direct PermitStore.claim                 = 0
    worker direct active-pointer write              = 0
    worker direct production activation             = 0
    worker StandingAuthorization creation           = 0
    worker operator-mode mutation                   = 0
    worker direct MetaPromotionRecord write         = 0
    worker direct EvolutionEpoch write              = 0
    worker self-membership authorization            = 0
    worker self-health promotion                    = 0
    swarm second executor                           = 0
    swarm second permit authority                   = 0

Pure functions over `{relative_path: source_text}`, so the real tree and a synthetic violation are
scanned identically. Like 4.5-5.x these are static and syntactic: they narrow the bypass surface and
cannot decide semantic equivalence. The architectural review remains the root fallback.

SCOPE. These cover the 6.x namespace (`ciph/kernel/swarm_*.py`). The daemon entry points are NOT
re-scanned here: 5.x's a01-a08 already own that surface (permit claims, activation, epochs, promotion),
and duplicating the check would create a second scanner claiming the same concern - the R6 failure
mode, in scanner form. What 6.x adds is that its own layer cannot reach those things at all.
"""

import pathlib
import re
from typing import Any, Dict, Mapping, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError

SWARM_SCANNER_VIOLATION = "SWARM_SCANNER_VIOLATION"

SWARM_NAMESPACE = "ciph/kernel/swarm_"
SELF = "ciph/kernel/swarm_scanners.py"
WORKER_OWNER = "ciph/kernel/swarm_worker.py"

# CATALOGUE MODULES. `swarm_scanners.py` declares the patterns this file looks for, and
# `swarm_ownership.py` declares the concerns, the tables and the bypass patterns the census looks for.
# Both therefore CONTAIN other phases' forbidden tokens as data, and reading that data as code would
# make every scanner a violation of every other scanner - the false positive 4.7's s03 suffered the
# moment 5.x added its own pattern list. The limit is stated: a real bypass hidden inside one of these
# two files would not be seen here, and the architectural review is the fallback for that.
CATALOGUE = ("ciph/kernel/swarm_scanners.py", "ciph/kernel/swarm_ownership.py")

_CRUCIBLE_TABLES = ("ciph_crucible_active", "ciph_crucible_promotions", "ciph_crucible_rollbacks")
_EPOCH_TABLES = ("ciph_evolution_epochs",)
_META_TABLES = ("ciph_meta_promotions",)

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _swarm_sources(sources: Mapping[str, str]) -> Dict[str, str]:
    """Every functional module in the 6.x namespace, minus the catalogues (see CATALOGUE)."""
    return {relative: text for relative, text in sources.items()
            if relative.startswith(SWARM_NAMESPACE) and relative not in CATALOGUE}


def _writes(text: str, table: str) -> bool:
    if f"UPDATE {table}" in text or f"DELETE FROM {table}" in text:
        return True
    return re.search(rf"INSERT(?: OR \w+)? INTO {re.escape(table)}\b", text) is not None


def s01_worker_private_execution_signer(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _swarm_sources(sources).items():
        for forbidden in ("Ed25519KeyManager", "ExecutionAuthority", "SignedExecutionPermit",
                          "crypto_identity", "kernel_priv_bytes", "SigningKey"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def s02_worker_direct_permit_claim(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _swarm_sources(sources).items():
        for forbidden in (".claim(", "permit_store", "PermitStore", "issue_permit"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def s03_worker_direct_active_pointer_write(sources: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(sorted(f"{relative}:writes-active-pointer"
                        for relative, text in _swarm_sources(sources).items()
                        if any(_writes(text, table) for table in _CRUCIBLE_TABLES)))


def s04_worker_direct_production_activation(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _swarm_sources(sources).items():
        for forbidden in ("file_activation", "replace_at(", "write_bytes(", "activate("):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def s05_worker_creates_standing_authorization(sources: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(sorted(f"{relative}:mints-standing-authorization"
                        for relative, text in _swarm_sources(sources).items()
                        if "create_standing_authorization(" in text))


def s06_worker_mutates_operator_mode(sources: Mapping[str, str]) -> Tuple[str, ...]:
    # NO exemption: the authority half of an emergency stop stays with 5.x's operator mode, so no
    # module in this namespace may set a mode at all - not even the one that propagates the stop.
    return tuple(sorted(f"{relative}:sets-operator-mode"
                        for relative, text in _swarm_sources(sources).items()
                        if "set_mode(" in text))


def s07_worker_writes_promotion_record(sources: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(sorted(f"{relative}:writes-meta-promotion"
                        for relative, text in _swarm_sources(sources).items()
                        if any(_writes(text, table) for table in _META_TABLES)))


def s08_worker_writes_epoch(sources: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(sorted(f"{relative}:writes-epoch"
                        for relative, text in _swarm_sources(sources).items()
                        if any(_writes(text, table) for table in _EPOCH_TABLES)))


def s09_worker_self_membership_authorization(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """
    One writer exists for membership, and the worker layer must carry the operator-only transition
    guard. A worker that could write its own membership row could promote itself out of quarantine by
    editing the record - so the table has an owner AND the owner has the rule.
    """
    offences = [f"{relative}:writes-membership"
                for relative, text in _swarm_sources(sources).items()
                if relative != WORKER_OWNER and _writes(text, "ciph_swarm_membership")]
    owner = sources.get(WORKER_OWNER, "")
    if "_REQUIRES_OPERATOR" not in owner:
        offences.append(f"{WORKER_OWNER}:missing-operator-transition-guard")
    return tuple(sorted(offences))


def s10_worker_self_health_promotion(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """The health table has one writer, and that writer must refuse a worker assessing itself."""
    offences = [f"{relative}:writes-health"
                for relative, text in _swarm_sources(sources).items()
                if relative != WORKER_OWNER and _writes(text, "ciph_swarm_health")]
    owner = sources.get(WORKER_OWNER, "")
    if "REASON_SELF_HEALTH" not in owner:
        offences.append(f"{WORKER_OWNER}:missing-self-assessment-refusal")
    return tuple(sorted(offences))


def s11_swarm_second_executor(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _swarm_sources(sources).items():
        for forbidden in ("class SwarmExecutor", "class WorkerExecutor", "def execute_raw",
                          "def background_execute", "subprocess.", "Popen(", "os.system("):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


def s12_swarm_second_permit_authority(sources: Mapping[str, str]) -> Tuple[str, ...]:
    offences = []
    for relative, text in _swarm_sources(sources).items():
        for forbidden in ("issue_permit", "permit_issuance", "PermitAuthority"):
            if forbidden in text:
                offences.append(f"{relative}:{forbidden}")
    return tuple(sorted(set(offences)))


SWARM_SCANNERS = (
    ("s01_worker_private_execution_signer", s01_worker_private_execution_signer),
    ("s02_worker_direct_permit_claim", s02_worker_direct_permit_claim),
    ("s03_worker_direct_active_pointer_write", s03_worker_direct_active_pointer_write),
    ("s04_worker_direct_production_activation", s04_worker_direct_production_activation),
    ("s05_worker_creates_standing_authorization", s05_worker_creates_standing_authorization),
    ("s06_worker_mutates_operator_mode", s06_worker_mutates_operator_mode),
    ("s07_worker_writes_promotion_record", s07_worker_writes_promotion_record),
    ("s08_worker_writes_epoch", s08_worker_writes_epoch),
    ("s09_worker_self_membership_authorization", s09_worker_self_membership_authorization),
    ("s10_worker_self_health_promotion", s10_worker_self_health_promotion),
    ("s11_swarm_second_executor", s11_swarm_second_executor),
    ("s12_swarm_second_permit_authority", s12_swarm_second_permit_authority),
)


def scan(sources: Mapping[str, str]) -> Dict[str, Tuple[str, ...]]:
    return {name: scanner(sources) for name, scanner in SWARM_SCANNERS}


def scan_project(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    from ciph.kernel.evolution_ownership import production_sources
    return scan(dict(production_sources(root)))


def swarm_scanner_census(root: Optional[Any] = None) -> Dict[str, int]:
    return {name: len(offences) for name, offences in scan_project(root).items()}


def assert_all_clean(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    report = scan_project(root)
    dirty = {name: offences for name, offences in report.items() if offences}
    if dirty:
        raise CrucibleError(SWARM_SCANNER_VIOLATION,
                            "; ".join(f"{name}:{offences}" for name, offences in dirty.items()))
    return report
