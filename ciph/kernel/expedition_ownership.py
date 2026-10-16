"""
ciph/kernel/expedition_ownership - the 10.9/10.10 ownership census.

    Deciding a question is worth investigating is not permission to investigate it.

The failure modes this census names: a rival expedition/hypothesis store, a forged finding, a minted permit, a
second curiosity priority, a second autonomy-mode authority, a module that calls a model to decide, and a
notification that claims a delivery nothing performed.

LIMITATION, stated rather than hidden: these are SYNTACTIC checks. They catch a named rival, a table written
by the wrong module and an obvious overclaim; they cannot catch an alias or obfuscation.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

EXPEDITION_OWNERSHIP_V1 = "EXPEDITION_OWNERSHIP_V1"
EXPEDITION_OWNERSHIP_VIOLATION = "EXPEDITION_OWNERSHIP_VIOLATION"

EXPEDITION_OWNER = "ciph/kernel/independent_expeditions.py"
INCUBATION_OWNER = "ciph/kernel/incubation.py"
PERMIT_OWNER = "ciph/kernel/execution_authority.py"
MODE_OWNER = "ciph/kernel/autonomy_modes.py"
REFERENTIAL_OWNER = "ciph/kernel/referential_continuity.py"
OWNED_MODULES = (EXPEDITION_OWNER, INCUBATION_OWNER)

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

_EXPEDITION_TABLES = ("ciph_expeditions", "ciph_expedition_authorizations", "ciph_expedition_checkpoints",
                      "ciph_notification_candidates")
_INCUBATION_TABLES = ("ciph_incubation_hypotheses",)
_CANONICAL_TABLES = ("ciph_permits", "ciph_standing_authorizations", "ciph_result_sets", "ciph_findings",
                     "ciph_observations", "ciph_curiosity_proposals", "ciph_swarm_delegations",
                     "ciph_autonomy_mode_history", "ciph_attention_requests")

_PERMIT_NEEDLE = "SignedExecutionPermit" + "("

_FORBIDDEN_NEEDLES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("a rival curiosity priority", ("curiosity_priority_v2(", "universal_priority(", "score_all_questions(")),
    ("a second mode authority", ("set_autonomy_mode(", "force_mode(")),
    ("the module reasons by itself", ("call_model(", "invoke_llm(", "query_model(", "ask_the_model(")),
    ("a fabricated delivery", ("mark_delivered(", "claim_delivered(", "assume_delivered(")),
    ("a fabricated finding", ("fabricate_finding(", "invent_result(")),
)


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    signal: str


CENSUS: Tuple[Concern, ...] = (
    Concern("expedition identity", EXPEDITION_OWNER, "TABLE:ciph_expeditions"),
    Concern("expedition authorization decisions", EXPEDITION_OWNER, "TABLE:ciph_expedition_authorizations"),
    Concern("expedition checkpoints", EXPEDITION_OWNER, "TABLE:ciph_expedition_checkpoints"),
    Concern("notification candidates", EXPEDITION_OWNER, "TABLE:ciph_notification_candidates"),
    Concern("hypothesis lineage", INCUBATION_OWNER, "TABLE:ciph_incubation_hypotheses"),
    Concern("durable findings", REFERENTIAL_OWNER, "TABLE:ciph_result_sets"),
    Concern("execution permits", PERMIT_OWNER, "TABLE:ciph_permits"),
    Concern("autonomy mode authority", MODE_OWNER, "TABLE:ciph_autonomy_mode_history"),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (EXPEDITION_OWNER, ("propose_expedition", "authorize_expedition", "revalidate", "dispatch",
                        "checkpoint", "record_result", "select_candidates", "create_notification_candidate",
                        "claim_external_delivery", "expedition_digest")),
    (INCUBATION_OWNER, ("generate_hypothesis", "novelty", "set_status", "review_sources", "operating_modes",
                        "can_start_consequential_work", "resource_envelope", "model_outage_behavior",
                        "incubation_digest")),
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


def rival_expedition_or_hypothesis_owners(root: Optional[Any] = None,
                                          sources: Optional[List[Tuple[str, str]]] = None
                                          ) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for table in _EXPEDITION_TABLES:
            if relative != EXPEDITION_OWNER and _writes(text, table):
                offenders.append(f"{relative}:{table}")
        for table in _INCUBATION_TABLES:
            if relative != INCUBATION_OWNER and _writes(text, table):
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


def forbidden_expedition_patterns(root: Optional[Any] = None,
                                  sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    found = []
    for relative, text in scope:
        if _is_catalogue(relative) or relative == MODE_OWNER:
            continue
        for _concern, needles in _FORBIDDEN_NEEDLES:
            for needle in needles:
                if needle in text:
                    found.append(f"{relative}:{needle}")
    return tuple(sorted(set(found)))


def expedition_modules_do_not_reason(root: Optional[Any] = None,
                                     sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """Neither module may invoke a model: the model is invoked by 10.6, through attention."""
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
    return {"policy_version": EXPEDITION_OWNERSHIP_V1, "concerns": len(CENSUS),
            "rival_expedition_or_hypothesis_owners": list(rival_expedition_or_hypothesis_owners(root)),
            "owned_modules_write_canonical": list(owned_modules_write_canonical(root)),
            "permits_minted_outside_the_owner": list(permits_minted_outside_the_owner(root)),
            "forbidden_expedition_patterns": list(forbidden_expedition_patterns(root)),
            "expedition_modules_do_not_reason": list(expedition_modules_do_not_reason(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(EXPEDITION_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
