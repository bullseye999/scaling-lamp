"""
ciph/kernel/attention_ownership - the 10.5/10.6 ownership census.

    One projection owner and one attention owner. Neither mints authority, and neither is a second truth store.

The projection (10.5) reads the canonical owners and writes ONE relationship store. Attention (10.6) writes
only its own queue, focus contexts and decision log - which are NOT evidence. The rules below name each way
that goes wrong: a rival link/queue store, a projection that writes canonical tables, attention that mints a
permit or grants a scope, a single "objective importance" scalar, and a queue that calls the model to
maintain itself.

LIMITATION, stated rather than hidden: these are SYNTACTIC checks. They catch a named rival, a table written
by the wrong module and an obvious overclaim; they cannot catch an alias or obfuscation.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

ATTENTION_OWNERSHIP_V1 = "ATTENTION_OWNERSHIP_V1"
ATTENTION_OWNERSHIP_VIOLATION = "ATTENTION_OWNERSHIP_VIOLATION"

AWARENESS_OWNER = "ciph/kernel/operational_awareness.py"
ATTENTION_OWNER = "ciph/kernel/selective_attention.py"
PERMIT_OWNER = "ciph/kernel/execution_authority.py"
OWNED_MODULES = (AWARENESS_OWNER, ATTENTION_OWNER)

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

_LINK_TABLES = ("ciph_operational_links",)
_ATTENTION_TABLES = ("ciph_attention_requests", "ciph_attention_focus", "ciph_attention_windows",
                     "ciph_attention_state", "ciph_attention_events")
_CANONICAL_TABLES = ("ciph_observations", "ciph_evidence", "ciph_arch_observations", "ciph_arch_changes",
                     "ciph_result_sets", "ciph_findings", "ciph_announcements", "ciph_self_executions",
                     "ciph_crucible_deployments", "ciph_swarm_results", "ciph_federation_nodes",
                     "ciph_sensor_events")

# Names that would be an authority mint, a single objective score, or a queue that reasons to maintain itself.
_FORBIDDEN_NEEDLES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("attention grants authority", ("attention_grants_authority(", "attention_authorizes(",
                                    "attention_confers_permission(")),
    ("a single objective importance scalar", ("objective_importance(", "universal_score(",
                                              "universal_importance(")),
    ("self-declared severity short-circuit", ("severity_confers_critical(", "severity_is_evidence(")),
    ("the queue invokes the model to maintain itself", ("call_model(", "invoke_llm(", "query_model(",
                                                        "ask_the_model(")),
    ("hardware attestation overclaim", ("tpm_verified = True", "secure_boot_attested = True")),
)


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    signal: str


CENSUS: Tuple[Concern, ...] = (
    Concern("operational relationship store", AWARENESS_OWNER, "TABLE:ciph_operational_links"),
    Concern("attention request queue", ATTENTION_OWNER, "TABLE:ciph_attention_requests"),
    Concern("attention focus contexts", ATTENTION_OWNER, "TABLE:ciph_attention_focus"),
    Concern("attention reasoning windows", ATTENTION_OWNER, "TABLE:ciph_attention_windows"),
    Concern("attention decision log", ATTENTION_OWNER, "TABLE:ciph_attention_events"),
    Concern("attention transient state", ATTENTION_OWNER, "TABLE:ciph_attention_state"),
    Concern("execution authority permits", PERMIT_OWNER, "TABLE:ciph_permits"),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (AWARENESS_OWNER, ("correlate", "links", "subject_state", "contradictions", "build_projection",
                       "awareness_digest")),
    (ATTENTION_OWNER, ("classify", "submit", "schedule", "invoke", "checkpoint", "restore",
                       "model_unavailable", "model_available", "starved", "history", "expire", "cancel")),
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


def rival_operational_or_attention_owners(root: Optional[Any] = None,
                                          sources: Optional[List[Tuple[str, str]]] = None
                                          ) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for table in _LINK_TABLES:
            if relative != AWARENESS_OWNER and _writes(text, table):
                offenders.append(f"{relative}:{table}")
        for table in _ATTENTION_TABLES:
            if relative != ATTENTION_OWNER and _writes(text, table):
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


def forbidden_attention_patterns(root: Optional[Any] = None,
                                 sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    found = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for _concern, needles in _FORBIDDEN_NEEDLES:
            for needle in needles:
                if needle in text:
                    found.append(f"{relative}:{needle}")
    return tuple(sorted(set(found)))


# The needle is assembled so that THIS catalogue module does not itself contain the literal construction
# site: the 4.0 authority-throat scanner scans every package file for that literal, and a census that spells
# it out would (correctly, by its own rules) be reported as a permit-constructing module.
_PERMIT_CONSTRUCTION_NEEDLE = "SignedExecutionPermit" + "("


def permits_minted_outside_the_owner(root: Optional[Any] = None,
                                     sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """Only the canonical execution authority may construct a signed permit."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative) or relative == PERMIT_OWNER:
            continue
        if _PERMIT_CONSTRUCTION_NEEDLE in text:
            offenders.append(f"{relative}:SignedExecutionPermit")
    return tuple(sorted(set(offenders)))


def attention_is_not_evidence(root: Optional[Any] = None,
                              sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """
    The attention log must not be handed to an evidence owner. A decision is a decision; it never becomes a
    4.2 observation or a 10.0 finding.
    """
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative != ATTENTION_OWNER:
            continue
        if "record_observation(" in text or "record_evidence(" in text:
            offenders.append(f"{relative}:writes-the-epistemic-ledger")
        if "attention_digest" not in text:
            offenders.append(f"{relative}:missing-deterministic-digest")
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
    return {"policy_version": ATTENTION_OWNERSHIP_V1, "concerns": len(CENSUS),
            "rival_operational_or_attention_owners": list(rival_operational_or_attention_owners(root)),
            "owned_modules_write_canonical": list(owned_modules_write_canonical(root)),
            "forbidden_attention_patterns": list(forbidden_attention_patterns(root)),
            "permits_minted_outside_the_owner": list(permits_minted_outside_the_owner(root)),
            "attention_is_not_evidence": list(attention_is_not_evidence(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(ATTENTION_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
