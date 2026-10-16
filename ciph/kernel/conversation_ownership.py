"""
ciph/kernel/conversation_ownership - the 10.1/10.2 ownership census.

    Conversational memory is not an alternative source of operational truth.

This census names the ONE owner of conversation identity and the owners it must never write. It exists
because the failure mode is specific and tempting: a conversation store that starts answering "what
happened?" from what was SAID rather than from what the work owners recorded, or a commitment that quietly
becomes permission.

LIMITATION, stated rather than hidden: these are SYNTACTIC checks. They catch a named rival, a table written
by the wrong module and an obvious overclaim; they cannot catch an alias or obfuscation.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

CONVERSATION_OWNERSHIP_V1 = "CONVERSATION_OWNERSHIP_V1"
CONVERSATION_OWNERSHIP_VIOLATION = "CONVERSATION_OWNERSHIP_VIOLATION"

CONTINUITY_OWNER = "ciph/kernel/conversational_continuity.py"
PRESENCE_OWNER = "ciph/kernel/operational_presence.py"
CHANNELS_OWNER = "ciph/kernel/conversation_channels.py"
OWNED_MODULES = (CONTINUITY_OWNER, PRESENCE_OWNER, CHANNELS_OWNER)

PERMIT_OWNER = "ciph/kernel/execution_authority.py"
STANDING_OWNER = "ciph/kernel/standing_authorization.py"
REFERENTIAL_OWNER = "ciph/kernel/referential_continuity.py"
LEDGER_OWNER = "ciph/kernel/epistemic_ledger.py"

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

_CONVERSATION_TABLES = ("ciph_conv_participants", "ciph_conv_channels", "ciph_conv_sessions",
                        "ciph_conv_turns", "ciph_conv_questions", "ciph_conv_summaries")
_CANONICAL_TABLES = ("ciph_permits", "ciph_standing_authorizations", "ciph_result_sets", "ciph_findings",
                     "ciph_observations", "ciph_swarm_results", "ciph_swarm_delegations",
                     "ciph_crucible_deployments", "ciph_self_executions", "ciph_followups")

_FORBIDDEN_NEEDLES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("conversation grants authority", ("conversation_grants_authority(", "commitment_authorizes(",
                                       "treat_as_authorization(")),
    ("a memory promoted into evidence", ("conversation_is_evidence(", "conversation_is_truth(",
                                         "remembered_so_it_happened(")),
    ("a completion claimed without the owner", ("mark_completed(",)),
    ("hardware attestation overclaim", ("tpm_verified = True", "secure_boot_attested = True")),
)


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    signal: str


CENSUS: Tuple[Concern, ...] = (
    Concern("conversation participants", CONTINUITY_OWNER, "TABLE:ciph_conv_participants"),
    Concern("conversation channels", CONTINUITY_OWNER, "TABLE:ciph_conv_channels"),
    Concern("conversation sessions", CONTINUITY_OWNER, "TABLE:ciph_conv_sessions"),
    Concern("conversation turns", CONTINUITY_OWNER, "TABLE:ciph_conv_turns"),
    Concern("outstanding questions", CONTINUITY_OWNER, "TABLE:ciph_conv_questions"),
    Concern("regenerable summaries", CONTINUITY_OWNER, "TABLE:ciph_conv_summaries"),
    Concern("durable findings and result sets", REFERENTIAL_OWNER, "TABLE:ciph_result_sets"),
    Concern("canonical epistemic records", LEDGER_OWNER, "TABLE:ciph_observations"),
    Concern("standing authorizations", STANDING_OWNER, "TABLE:ciph_standing_authorizations"),
    Concern("execution permits", PERMIT_OWNER, "TABLE:ciph_permits"),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (CONTINUITY_OWNER, ("register_participant", "register_channel", "open_session", "record_turn",
                        "authorized_history", "resolve_reference", "summarize", "context_selection",
                        "conversation_digest")),
    (PRESENCE_OWNER, ("commitment_authorization", "initiative_boundary", "honest_progress",
                      "absence_report", "resume_plan", "presence", "presence_digest")),
    (CHANNELS_OWNER, ("LocalTerminalChannel", "DisposableMessageChannel", "claim_external_delivery",
                      "delivery")),
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


def rival_conversation_owners(root: Optional[Any] = None,
                              sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative == CONTINUITY_OWNER or _is_catalogue(relative):
            continue
        for table in _CONVERSATION_TABLES:
            if _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def conversation_modules_write_canonical(root: Optional[Any] = None,
                                         sources: Optional[List[Tuple[str, str]]] = None
                                         ) -> Tuple[str, ...]:
    """A conversation store may REPORT on canonical owners; it may never write their tables."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative not in OWNED_MODULES:
            continue
        for table in _CANONICAL_TABLES:
            if _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def forbidden_conversation_patterns(root: Optional[Any] = None,
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


def summaries_are_not_canonical(root: Optional[Any] = None,
                                sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """A summary must be marked non-canonical in code as well as in prose."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative != CONTINUITY_OWNER:
            continue
        if '"is_canonical": False' not in text:
            offenders.append(f"{relative}:summary-not-marked-non-canonical")
        if "canonical_history_untouched" not in text:
            offenders.append(f"{relative}:missing-canonical-history-guarantee")
    return tuple(sorted(set(offenders)))


def local_adapters_do_not_claim_external_delivery(root: Optional[Any] = None,
                                                  sources: Optional[List[Tuple[str, str]]] = None
                                                  ) -> Tuple[str, ...]:
    """Both disposable adapters must construct with external_delivery=False."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative != CHANNELS_OWNER:
            continue
        if text.count("external_delivery=False") < 2:
            offenders.append(f"{relative}:an-adapter-claims-external-delivery")
        if REASON_EXTERNAL_DELIVERY_REFUSAL not in text:
            offenders.append(f"{relative}:no-refusal-of-external-delivery")
    return tuple(sorted(set(offenders)))


REASON_EXTERNAL_DELIVERY_REFUSAL = "LOCAL_ADAPTER_PROVIDES_NO_EXTERNAL_DELIVERY"


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
    return {"policy_version": CONVERSATION_OWNERSHIP_V1, "concerns": len(CENSUS),
            "rival_conversation_owners": list(rival_conversation_owners(root)),
            "conversation_modules_write_canonical": list(conversation_modules_write_canonical(root)),
            "forbidden_conversation_patterns": list(forbidden_conversation_patterns(root)),
            "summaries_are_not_canonical": list(summaries_are_not_canonical(root)),
            "local_adapters_do_not_claim_external_delivery":
                list(local_adapters_do_not_claim_external_delivery(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(CONVERSATION_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
