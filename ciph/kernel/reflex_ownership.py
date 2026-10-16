"""
ciph/kernel/reflex_ownership - the 10.7/10.8 ownership census.

    Reflexes apply existing rules; homeostasis recognizes patterns. Neither mints authority.

The failure modes this census names: a rival reflex store, a reflex that mints or impersonates a permit, a
second executor, a baseline store written by something else, a reflex that calls a model to decide, and a
homeostasis module that grants execution.

LIMITATION, stated rather than hidden: these are SYNTACTIC checks. They catch a named rival, a table written
by the wrong module and an obvious overclaim; they cannot catch an alias or obfuscation.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

REFLEX_OWNERSHIP_V1 = "REFLEX_OWNERSHIP_V1"
REFLEX_OWNERSHIP_VIOLATION = "REFLEX_OWNERSHIP_VIOLATION"

REFLEX_OWNER = "ciph/kernel/governed_reflexes.py"
HOMEOSTASIS_OWNER = "ciph/kernel/operational_homeostasis.py"
PERMIT_OWNER = "ciph/kernel/execution_authority.py"
EXECUTOR_OWNER = "ciph/kernel/execution_gateway.py"
OWNED_MODULES = (REFLEX_OWNER, HOMEOSTASIS_OWNER)

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

_REFLEX_TABLES = ("ciph_reflex_rules", "ciph_reflex_decisions", "ciph_reflex_outcomes",
                  "ciph_reflex_actions")
_HOMEOSTASIS_TABLES = ("ciph_homeostasis_observations", "ciph_homeostasis_baselines",
                       "ciph_homeostasis_anomalies", "ciph_homeostasis_interpretations")
_CANONICAL_TABLES = ("ciph_permits", "ciph_standing_authorizations", "ciph_crucible_deployments",
                     "ciph_swarm_results", "ciph_findings", "ciph_observations", "ciph_arch_changes",
                     "ciph_attention_requests")

_PERMIT_NEEDLE = "SignedExecutionPermit" + "("

_FORBIDDEN_NEEDLES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("a reflex grants authority", ("reflex_grants_authority(", "reflex_authorizes(",
                                   "reflex_mints_permit(")),
    ("homeostasis authorizes execution", ("homeostasis_authorizes(", "baseline_grants_authority(")),
    ("the reflex calls a model", ("call_model(", "invoke_llm(", "query_model(", "ask_the_model(")),
    ("a second executor", ("class GuardedExecutor", "class SecondExecutor", "class CiphOSExecutor")),
    ("hardware attestation overclaim", ("tpm_verified = True", "secure_boot_attested = True")),
)


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    signal: str


CENSUS: Tuple[Concern, ...] = (
    Concern("reflex rule registry", REFLEX_OWNER, "TABLE:ciph_reflex_rules"),
    Concern("reflex decisions", REFLEX_OWNER, "TABLE:ciph_reflex_decisions"),
    Concern("reflex outcomes", REFLEX_OWNER, "TABLE:ciph_reflex_outcomes"),
    Concern("reflex idempotency records", REFLEX_OWNER, "TABLE:ciph_reflex_actions"),
    Concern("homeostatic observations", HOMEOSTASIS_OWNER, "TABLE:ciph_homeostasis_observations"),
    Concern("versioned baselines", HOMEOSTASIS_OWNER, "TABLE:ciph_homeostasis_baselines"),
    Concern("homeostatic anomalies", HOMEOSTASIS_OWNER, "TABLE:ciph_homeostasis_anomalies"),
    Concern("interpretation states", HOMEOSTASIS_OWNER, "TABLE:ciph_homeostasis_interpretations"),
    Concern("execution permits", PERMIT_OWNER, "TABLE:ciph_permits"),
    Concern("guarded execution gateway", EXECUTOR_OWNER, "TABLE:ciph_execution_receipts"),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (REFLEX_OWNER, ("register_reflex", "evaluate", "invoke", "decisions", "outcomes",
                    "decisions_without_an_outcome", "reflex_digest")),
    (HOMEOSTASIS_OWNER, ("observe", "propose_baseline", "approve_baseline", "approved_baseline", "evaluate",
                         "advance", "interpretation", "attention_allocation_ratio", "to_attention")),
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


def rival_reflex_or_baseline_owners(root: Optional[Any] = None,
                                    sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for table in _REFLEX_TABLES:
            if relative != REFLEX_OWNER and _writes(text, table):
                offenders.append(f"{relative}:{table}")
        for table in _HOMEOSTASIS_TABLES:
            if relative != HOMEOSTASIS_OWNER and _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def owned_modules_write_canonical(root: Optional[Any] = None,
                                  sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative not in OWNED_MODULES:
            continue
        for table in _CANONICAL_TABLES:
            if _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def permits_minted_outside_the_owner(root: Optional[Any] = None,
                                     sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative) or relative == PERMIT_OWNER:
            continue
        if _PERMIT_NEEDLE in text:
            offenders.append(f"{relative}:SignedExecutionPermit")
    return tuple(sorted(set(offenders)))


def forbidden_reflex_patterns(root: Optional[Any] = None,
                              sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    found = []
    for relative, text in scope:
        if _is_catalogue(relative) or relative == EXECUTOR_OWNER:
            # The canonical executor legitimately defines the guarded executor; nobody else may.
            continue
        for _concern, needles in _FORBIDDEN_NEEDLES:
            for needle in needles:
                if needle in text:
                    found.append(f"{relative}:{needle}")
    return tuple(sorted(set(found)))


def reflex_modules_are_llm_free(root: Optional[Any] = None,
                                sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """A reflex must evaluate with the model completely unavailable."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative not in OWNED_MODULES:
            continue
        for needle in ("BrainRouter", "ollama", "deepseek", "CiphConversation"):
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
    return {"policy_version": REFLEX_OWNERSHIP_V1, "concerns": len(CENSUS),
            "rival_reflex_or_baseline_owners": list(rival_reflex_or_baseline_owners(root)),
            "owned_modules_write_canonical": list(owned_modules_write_canonical(root)),
            "permits_minted_outside_the_owner": list(permits_minted_outside_the_owner(root)),
            "forbidden_reflex_patterns": list(forbidden_reflex_patterns(root)),
            "reflex_modules_are_llm_free": list(reflex_modules_are_llm_free(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(REFLEX_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
