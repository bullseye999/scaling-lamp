"""
ciph/kernel/architectural_ownership - the 10.4 ownership census.

    One owner for architectural observation, and no second authority smuggled in beside it.

WHAT THE SURVEY FOUND.  Ciph already has several partial answers to "what am I made of?" and none of them
is an architectural observer:

    `self_awareness.py`        self-DESCRIPTION over a code index (may describe, may not certify)
    `ciph/kernel/self_model.py` (4.3) the EMPIRICAL capability ladder - installed/available/authorized/verified
    `ciph/kernel/manifest_*`    manifest identity and lineage (what a revision claims to be)
    `ciph/kernel/sovereignty_monitoring.py`  sovereignty health counters
    `ciph/kernel/production_choke_point.py`  R7 choke-point SCANNER (static, not an observation)
    `ciph/kernel/environment_*` (9.x) the operating-environment boot/service attestation

None of them distinguishes SOURCE vs INSTALLED vs LOADED vs EXECUTED, and none of them refuses a
self-certification, so a new OWNER is required - a projection over canonical evidence, not a new truth
store. The declarations below name that owner and the boundaries a second one would cross.

LIMITATION, stated rather than hidden: these are SYNTACTIC checks over source text. They catch a named
rival, a table written by the wrong module and an obvious overclaim; they cannot catch obfuscation, an
alias, or a rival introduced under an unrelated name. That limitation is why `integrity_claim` refuses
self-certification at RUNTIME rather than relying on a scanner to be complete.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

ARCHITECTURAL_OWNERSHIP_V1 = "ARCHITECTURAL_OWNERSHIP_V1"
ARCHITECTURAL_OWNERSHIP_VIOLATION = "ARCHITECTURAL_OWNERSHIP_VIOLATION"

OWNER = "ciph/kernel/architectural_proprioception.py"
LEDGER_OWNER = "ciph/kernel/epistemic_ledger.py"
SELF_MODEL_OWNER = "ciph/kernel/self_model.py"
DEPLOYMENT_OWNER = "ciph/kernel/evolution_deployment.py"

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

# The tables only ONE owner may write. A second writer is a rival observer or a rival ledger.
_ARCH_TABLES = ("ciph_arch_components", "ciph_arch_observations", "ciph_arch_changes")
_EPISTEMIC_TABLES = ("ciph_observations", "ciph_evidence")
_DEPLOYMENT_TABLES = ("ciph_crucible_deployments",)

# Names that would be a rival authority or a forbidden synthesis. Each is a real design error, not a
# stylistic preference: a "loaded" view derived from a source read, an observation that grants permission,
# a self-certification, or a second executor.
_FORBIDDEN_NEEDLES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("loaded view synthesized from source",
     ("synthesize_loaded(", "loaded_view_from_source(", "infer_loaded(", "loaded_digest_from_source(")),
    ("observation grants authority",
     ("observation_grants_authority(", "observe_and_authorize(", "observation_is_permission(")),
    ("self-certified integrity",
     ("self_certified_integrity(", "certify_own_integrity(", "is_self_trusted(", "trusts_its_own_report(")),
    ("second execution authority",
     ("class CiphOSExecutor", "grant_execution_authority(", "second_executor(", "class SecondExecutor")),
    ("hardware attestation overclaim",
     ("tpm_verified = True", "secure_boot_attested = True", "measured_boot_verified = True")),
    ("architectural fact asserted directly",
     ("record_architectural_fact(", "assert_component_present(")),
)


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    signal: str

    def owner_path(self) -> str:
        return self.canonical_owner


CENSUS: Tuple[Concern, ...] = (
    Concern("architectural component registry", OWNER, "TABLE:ciph_arch_components"),
    Concern("architectural observation record", OWNER, "TABLE:ciph_arch_observations"),
    Concern("architectural change witness", OWNER, "TABLE:ciph_arch_changes"),
    Concern("epistemic observation ledger", LEDGER_OWNER, "TABLE:ciph_observations"),
    Concern("empirical execution evidence", SELF_MODEL_OWNER, "TABLE:ciph_self_executions"),
    Concern("production deployment record", DEPLOYMENT_OWNER, "TABLE:ciph_crucible_deployments"),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (OWNER, ("SOURCE", "INSTALLED", "LOADED", "EXECUTED", "architectural_projection", "integrity_claim",
             "policy_reference", "witness_change", "record_observation_gap")),
    ("self_awareness.py", ("SelfAwareness",)),
    ("ciph/kernel/self_model.py", ("record_execution_evidence", "project_capability")),
    ("ciph/kernel/environment_ownership.py", ("environment_report",)),
)


def _is_catalogue(relative: str) -> bool:
    return str(relative).rsplit("/", 1)[-1].endswith(_CATALOGUE_SUFFIXES)


def production_sources(root: Optional[Any] = None) -> List[Tuple[str, str]]:
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    sources: List[Tuple[str, str]] = []
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts or any(part in path.parts for part in
                                              ("ciph_env", "site-packages", ".venv", "node_modules")):
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            continue
        try:
            sources.append((path.relative_to(base).as_posix(), path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return sources


def _writes(text: str, table: str) -> bool:
    if re.search(rf"\b(?:CREATE TABLE(?: IF NOT EXISTS)?|ALTER TABLE|DROP TABLE)\s+{re.escape(table)}\b",
                 text, re.IGNORECASE):
        return True
    if re.search(rf"\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO)\s+{re.escape(table)}\b", text,
                 re.IGNORECASE):
        return True
    if re.search(rf"\bUPDATE\s+{re.escape(table)}\b", text, re.IGNORECASE):
        return True
    return re.search(rf"\bDELETE\s+FROM\s+{re.escape(table)}\b", text, re.IGNORECASE) is not None


def _contains(text: str, signal: str) -> bool:
    kind, _, name = signal.partition(":")
    return _writes(text, name) if kind == "TABLE" else (name in text)


def rival_architectural_owners(root: Optional[Any] = None,
                               sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """A second module declaring any architectural table is a rival observer."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative == OWNER or _is_catalogue(relative):
            continue
        for table in _ARCH_TABLES:
            if _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def rival_epistemic_or_deployment_owners(root: Optional[Any] = None,
                                         sources: Optional[List[Tuple[str, str]]] = None
                                         ) -> Tuple[str, ...]:
    """A second truth store or a second deployment authority, in any module."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for table in _EPISTEMIC_TABLES:
            if relative != LEDGER_OWNER and _writes(text, table):
                offenders.append(f"{relative}:{table}")
        for table in _DEPLOYMENT_TABLES:
            if relative != DEPLOYMENT_OWNER and _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def forbidden_architectural_patterns(root: Optional[Any] = None,
                                     sources: Optional[List[Tuple[str, str]]] = None
                                     ) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    found = []
    for relative, text in scope:
        if relative == OWNER or _is_catalogue(relative):
            continue
        for _concern, needles in _FORBIDDEN_NEEDLES:
            for needle in needles:
                if needle in text:
                    found.append(f"{relative}:{needle}")
    return tuple(sorted(set(found)))


def loaded_view_is_a_witness(root: Optional[Any] = None,
                             sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """
    The LOADED view may only be written by a captured load-time digest. Any module that derives it by
    RE-READING a file is treating "source on disk now" as "what is running", which is the collapse the
    four-view model exists to forbid.
    """
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        if relative == OWNER:
            # The owner is allowed exactly one path that reads a file for the LOADED view: the explicit
            # `load_time_digest` helper. A second read that feeds the LOADED view is a violation.
            if text.count("load_time_digest") < 1:
                offenders.append(f"{relative}:missing-load-time-witness")
            continue
        if re.search(r"view\s*=\s*[\"']LOADED[\"']", text) and re.search(r"read_bytes\(|read_text\(", text):
            offenders.append(f"{relative}:loaded-view-from-file-read")
    return tuple(sorted(set(offenders)))


def attestation_overclaims(root: Optional[Any] = None,
                           sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """No TPM/UEFI/measured-boot claim anywhere while CiphOS 9.x host certification is on HOLD."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        if relative == OWNER:
            if "hardware_attestation_claimed\": False" not in text.replace("'", "\""):
                offenders.append(f"{relative}:missing-hardware-attestation-disclaimer")
            continue
        for needle in ("hardware_backed_attestation = True", "attestation_level = \"HARDWARE\""):
            if needle in text:
                offenders.append(f"{relative}:{needle}")
    return tuple(sorted(set(offenders)))


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


def ownership_report(root: Optional[Any] = None) -> Dict[str, Any]:
    return {"policy_version": ARCHITECTURAL_OWNERSHIP_V1, "concerns": len(CENSUS),
            "rival_architectural_owners": list(rival_architectural_owners(root)),
            "rival_epistemic_or_deployment_owners": list(rival_epistemic_or_deployment_owners(root)),
            "forbidden_architectural_patterns": list(forbidden_architectural_patterns(root)),
            "loaded_view_is_a_witness": list(loaded_view_is_a_witness(root)),
            "attestation_overclaims": list(attestation_overclaims(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(ARCHITECTURAL_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
