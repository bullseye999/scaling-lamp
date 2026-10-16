"""
ciph/kernel/personality_ownership - the 10.12 ownership census.

    Expression may vary. Facts may not. And one ambiguous interaction may not rewrite the style.

The failure modes this census names: a rival personality or preference store, a personality module that
writes operational state, a module that mints a permit, a "policy" that becomes a second brain, a replacement
for the R14-classified EXPRESSION owners, and a mood mechanism that fabricates subjective experience.

LIMITATION, stated rather than hidden: these are SYNTACTIC checks. They catch a named rival, a table written
by the wrong module and an obvious overclaim; they cannot catch an alias or obfuscation.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

PERSONALITY_OWNERSHIP_V1 = "PERSONALITY_OWNERSHIP_V1"
PERSONALITY_OWNERSHIP_VIOLATION = "PERSONALITY_OWNERSHIP_VIOLATION"

POLICY_OWNER = "ciph/kernel/personality_policy.py"
CLAIMS_OWNER = "ciph/kernel/claim_validation.py"
PERMIT_OWNER = "ciph/kernel/execution_authority.py"
EXPRESSION_OWNERS = ("personality_engine.py", "mood_engine.py")
OWNED_MODULES = (POLICY_OWNER, CLAIMS_OWNER)

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

_POLICY_TABLES = ("ciph_personality_policies",)
_CLAIM_TABLES = ("ciph_claims",)
_CANONICAL_TABLES = ("ciph_permits", "ciph_standing_authorizations", "ciph_result_sets", "ciph_findings",
                     "ciph_observations", "ciph_conv_turns", "ciph_notifications", "ciph_expeditions",
                     "ciph_incubation_hypotheses")

_PERMIT_NEEDLE = "SignedExecutionPermit" + "("

_FORBIDDEN_NEEDLES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("a rival expression owner", ("class CiphPersonality", "class MoodEngine")),
    ("fabricated subjective experience", ("I feel sad(", "i_am_afraid(", "manufacture_emotion(",
                                          "pretend_to_suffer(")),
    ("the policy layer reasons by itself", ("call_model(", "invoke_llm(", "query_model(")),
)


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    signal: str


CENSUS: Tuple[Concern, ...] = (
    Concern("versioned personality policy", POLICY_OWNER, "TABLE:ciph_personality_policies"),
    Concern("validated operational claims", CLAIMS_OWNER, "TABLE:ciph_claims"),
    Concern("durable findings", "ciph/kernel/referential_continuity.py", "TABLE:ciph_result_sets"),
    Concern("conversation turns", "ciph/kernel/conversational_continuity.py", "TABLE:ciph_conv_turns"),
    Concern("execution permits", PERMIT_OWNER, "TABLE:ciph_permits"),
    Concern("legacy expression mechanism (retained, not replaced)", "personality_engine.py",
            "CONST:CiphPersonality"),
    Concern("legacy tone state (retained, not replaced)", "mood_engine.py", "CONST:MoodEngine"),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (POLICY_OWNER, ("propose_change", "activate", "rollback", "current", "style_for", "render",
                    "facts_preserved", "personality_digest")),
    (CLAIMS_OWNER, ("prepare", "validate", "render", "suspicious_assertions", "conservative_fallback",
                    "claim_digest")),
    ("personality_engine.py", ("CiphPersonality", "inject_personality")),
    ("mood_engine.py", ("MoodEngine",)),
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


def rival_personality_owners(root: Optional[Any] = None,
                             sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for table in _POLICY_TABLES:
            if relative != POLICY_OWNER and _writes(text, table):
                offenders.append(f"{relative}:{table}")
        for table in _CLAIM_TABLES:
            if relative != CLAIMS_OWNER and _writes(text, table):
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


def forbidden_personality_patterns(root: Optional[Any] = None,
                                   sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    found = []
    for relative, text in scope:
        if _is_catalogue(relative) or relative in EXPRESSION_OWNERS:
            continue
        for _concern, needles in _FORBIDDEN_NEEDLES:
            for needle in needles:
                if needle in text:
                    found.append(f"{relative}:{needle}")
    return tuple(sorted(set(found)))


def expression_owners_retained(root: Optional[Any] = None,
                               sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """The R14-classified EXPRESSION owners must still exist and still be the tone mechanism."""
    present = dict(sources if sources is not None else production_sources(root))
    missing = []
    for relative in EXPRESSION_OWNERS:
        text = present.get(relative)
        if text is None:
            missing.append(f"{relative}:missing-file")
        elif "class " not in text:
            missing.append(f"{relative}:no-class")
    return tuple(sorted(missing))


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
    return {"policy_version": PERSONALITY_OWNERSHIP_V1, "concerns": len(CENSUS),
            "rival_personality_owners": list(rival_personality_owners(root)),
            "owned_modules_write_canonical": list(owned_modules_write_canonical(root)),
            "permits_minted_outside_the_owner": list(permits_minted_outside_the_owner(root)),
            "forbidden_personality_patterns": list(forbidden_personality_patterns(root)),
            "expression_owners_retained": list(expression_owners_retained(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(PERSONALITY_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
