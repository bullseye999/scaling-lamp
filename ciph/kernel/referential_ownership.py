"""
ciph/kernel/referential_ownership - R14: one owner per referential-continuity concern.

    A finding is an identifiable reported RESULT linked to its source and evidence.
    It is NOT automatically a verified FACT, and it is not a new authority.

WHAT THE SURVEY FOUND (the actual cause of the twenty-alert failure, and it is structural):

There is NO durable result-set identity, NO finding identity and NO announcement record anywhere in the
tree. Findings are produced as in-memory dicts inside a tool call (`osint_miner` appends to a local
`alerts` list), rendered into a report STRING, and - at best - that prose survives somewhere as text.
`smart_memory.py` is a key -> value store with a single `recall(key)`; `enhanced_conversation.py` builds
prose summaries; `intent_router.py` and `query_router.py` route "alerts"/"findings" to a command that
RE-RUNS the tool.

So "retrieve the seventh alert" is unanswerable by construction, and the only available path is a NEW
scan - which is exactly the substitution the 10.0 hostile list forbids. The fix is not a better summary;
it is durable identity plus a refusal to announce more than was committed.

CANONICAL OWNERS BOUND TO (nothing new is invented over them):

    epistemic observations + evidence   ciph/kernel/epistemic_ledger.py   (4.2, canonical)
    investigation identity              ciph/kernel/curiosity_proposal.py + governed_investigation.py (4.4)
    worker results                      ciph/kernel/swarm_results.py      (6.3)
    federation observations             ciph/kernel/federation_replication.py (7.2)
    execution history                   the 4.0/4.1 owners
    result sets, findings, announcements, follow-ups
                                        ciph/kernel/referential_continuity.py (10.0, NEW)

LEGACY MACHINERY TO CLASSIFY (reported, not silently absorbed): `smart_memory.py` (conversation
utterances), `enhanced_conversation.py` (prose), `personality_engine.py` / `mood_engine.py` (expression),
`self_awareness.py` (self-description). None of them may become a second source of operational truth, and
none may write canonical observational tables.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

REFERENTIAL_OWNERSHIP_V1 = "REFERENTIAL_OWNERSHIP_V1"
REFERENTIAL_OWNERSHIP_VIOLATION = "REFERENTIAL_OWNERSHIP_VIOLATION"

OWNER = "ciph/kernel/referential_continuity.py"
LEDGER_OWNER = "ciph/kernel/epistemic_ledger.py"
INVESTIGATION_OWNERS = ("ciph/kernel/curiosity_proposal.py",
                        "ciph/kernel/governed_investigation.py")
SWARM_RESULT_OWNER = "ciph/kernel/swarm_results.py"
FEDERATION_OBS_OWNER = "ciph/kernel/federation_replication.py"

# Machinery that EXISTS and must be classified rather than duplicated by later 10.x phases.
LEGACY_TO_CLASSIFY: Tuple[Tuple[str, str], ...] = (
    ("smart_memory.py", "RETAINED MECHANISM - conversation utterances only; never operational truth and "
                        "never a writer of canonical observational tables"),
    ("enhanced_conversation.py", "PRESENTATION - prose summaries over canonical evidence; owns nothing"),
    ("personality_engine.py", "EXPRESSION - shapes tone and wording only (10.12); asserts no facts, "
                              "owns no authority"),
    ("mood_engine.py", "EXPRESSION - internal tone state used for wording only (10.12); never truth"),
    ("self_awareness.py", "SELF_DESCRIPTION - describes over the code index; CERTIFICATION is owned by "
                          "10.4 ciph/kernel/architectural_proprioception.py, so it cannot self-certify"),
)

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Tables that only ONE owner may write. A second writer is a rival truth store.
_REFERENTIAL_TABLES = ("ciph_result_sets", "ciph_findings", "ciph_result_set_revisions",
                       "ciph_announcements", "ciph_followups")
_EPISTEMIC_TABLES = ("ciph_observations", "ciph_evidence_links")


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    mechanism_ownership_allowed: bool
    signals: Tuple[str, ...]
    also_allowed: Tuple[str, ...] = ()

    def allowed(self) -> Tuple[str, ...]:
        return (self.canonical_owner,) + tuple(self.also_allowed)


CENSUS: Tuple[Concern, ...] = (
    Concern("result set identity", OWNER, False, ("TABLE:ciph_result_sets",)),
    Concern("finding identity", OWNER, False, ("TABLE:ciph_findings",)),
    Concern("result set revision history", OWNER, False, ("TABLE:ciph_result_set_revisions",)),
    Concern("announcement record", OWNER, False, ("TABLE:ciph_announcements",)),
    Concern("follow-up reference", OWNER, False, ("TABLE:ciph_followups",)),
    Concern("epistemic observation", LEDGER_OWNER, False, ("TABLE:ciph_observations",)),
    Concern("investigation identity", "ciph/kernel/curiosity_proposal.py", False,
            ("TABLE:ciph_curiosity_proposals",)),
    Concern("worker result", SWARM_RESULT_OWNER, False, ("TABLE:ciph_swarm_results",)),
    Concern("federation observation", FEDERATION_OBS_OWNER, False,
            ("TABLE:ciph_federation_replicated_records",)),
    # Machinery, kept.
    Concern("conversation utterance store", "smart_memory.py", True, ("CONST:SmartMemory",)),
    Concern("conversation presentation", "enhanced_conversation.py", True, ()),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("smart_memory.py", ("SmartMemory", "recall")),
    ("enhanced_conversation.py", ()),
    ("ciph/kernel/epistemic_ledger.py", ("record_observation", "record_evidence")),
    ("ciph/kernel/governed_investigation.py", ("prepare_investigation", "record_investigation_observation")),
)

_ANNOUNCE_WITHOUT_COMMIT = ("announce_without_commit(", "claim_findings(", "announce_unverified(")
_RESCAN_SUBSTITUTION = ("re_run_scan_for_retrieval(", "rescan_to_answer(", "rescan_for_retrieval(")
_INVENTED_FINDING = ("finding_id = \"F-", "finding_id = 'F-", "make_up_finding(")


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


def _defines(text: str, name: str) -> bool:
    for pattern in (r"^" + re.escape(name) + r"\s*(?::[^=]+)?=", r"^class\s+" + re.escape(name) + r"\b",
                    r"^def\s+" + re.escape(name) + r"\b"):
        if re.search(pattern, text, re.MULTILINE) is not None:
            return True
    return False


def _contains(text: str, signal: str) -> bool:
    kind, _, name = signal.partition(":")
    return _defines(text, name) if kind == "CONST" else _writes(text, name)


def _allowed(relative: str, concern: Concern) -> bool:
    for candidate in concern.allowed():
        if candidate.endswith("/") and relative.startswith(candidate):
            return True
        if candidate.startswith("test_") and relative.startswith("test_"):
            return True
        if relative == candidate:
            return True
    return False


def ownership_violations(root: Optional[Any] = None,
                         sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[Dict[str, str], ...]:
    violations: List[Dict[str, str]] = []
    scope = sources if sources is not None else production_sources(root)
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for concern in CENSUS:
            if concern.mechanism_ownership_allowed or _allowed(relative, concern):
                continue
            for signal in concern.signals:
                if _contains(text, signal):
                    violations.append({"concern": concern.concern, "owner": relative,
                                       "canonical": concern.canonical_owner, "signal": signal})
    return tuple(violations)


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


def _patterns(needles: Tuple[str, ...], *, sources: Optional[List[Tuple[str, str]]] = None,
              root: Optional[Any] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    found = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for needle in needles:
            if needle in text:
                found.append(f"{relative}:{needle}")
    return tuple(sorted(set(found)))


def unverified_announcement_paths(root: Optional[Any] = None,
                                  sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """An announcement that does not go through the commit-then-verify owner."""
    return _patterns(_ANNOUNCE_WITHOUT_COMMIT, sources=sources, root=root)


def rescans_substituted_for_retrieval(root: Optional[Any] = None,
                                      sources: Optional[List[Tuple[str, str]]] = None
                                      ) -> Tuple[str, ...]:
    findings = _patterns(_RESCAN_SUBSTITUTION, sources=sources, root=root)
    scope = sources if sources is not None else production_sources(root)
    owners = set()
    for relative, text in scope:
        if not _is_catalogue(relative):
            for needle in ("re_run_scan_for_retrieval(", "rescan_to_answer(", "rescan_for_retrieval("):
                if needle in text:
                    owners.add(relative)
    return tuple(sorted(set(findings)))


def invented_finding_identities(root: Optional[Any] = None,
                                sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    return _patterns(_INVENTED_FINDING, sources=sources, root=root)


def conversation_memory_writes_truth(root: Optional[Any] = None,
                                     sources: Optional[List[Tuple[str, str]]] = None
                                     ) -> Tuple[str, ...]:
    """
    A conversational module may remember what was SAID. It may not write canonical observations,
    findings or evidence: that is the difference between a transcript and a truth store.
    """
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        conversational = any(token in relative for token in
                             ("smart_memory", "enhanced_conversation", "personality_engine",
                              "mood_engine", "response_formatter", "intent_router", "query_router",
                              "intent_resolver"))
        if not conversational:
            continue
        for table in _EPISTEMIC_TABLES + _REFERENTIAL_TABLES:
            if _writes(text, table):
                offenders.append(f"{relative}:writes-{table}")
    return tuple(sorted(offenders))


def rival_result_store_owners(root: Optional[Any] = None,
                              sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """A second module declaring any referential table is a rival result store."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative == OWNER or _is_catalogue(relative):
            continue
        for table in _REFERENTIAL_TABLES:
            if _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def legacy_owners_to_classify(root: Optional[Any] = None) -> Tuple[Dict[str, str], ...]:
    present = dict(production_sources(root))
    return tuple({"module": module, "disposition": disposition}
                 for module, disposition in LEGACY_TO_CLASSIFY if module in present)


def ownership_report(root: Optional[Any] = None) -> Dict[str, Any]:
    return {"policy_version": REFERENTIAL_OWNERSHIP_V1, "concerns": len(CENSUS),
            "violations": list(ownership_violations(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root)),
            "unverified_announcement_paths": list(unverified_announcement_paths(root)),
            "rescans_substituted_for_retrieval": list(rescans_substituted_for_retrieval(root)),
            "invented_finding_identities": list(invented_finding_identities(root)),
            "conversation_memory_writes_truth": list(conversation_memory_writes_truth(root)),
            "rival_result_store_owners": list(rival_result_store_owners(root)),
            "legacy_owners_to_classify": [dict(item) for item in legacy_owners_to_classify(root)]}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns", "legacy_owners_to_classify") and value}
    if failures:
        raise CrucibleError(REFERENTIAL_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
