"""
ciph/kernel/communication_ownership - the 10.13 ownership census.

    An adapter carries messages. It is not an execution authority and not a second memory.

The failure modes this census names: a rival outbox or binding store, a messaging module that writes canonical
tables, a module that mints a permit, an adapter that can reach Ciph's vault or operator-root credentials, a
"boundary" that quietly becomes a second brain, and a transport that claims onion routing it does not provide.

LIMITATION, stated rather than hidden: these are SYNTACTIC checks. They catch a named rival, a table written
by the wrong module and an obvious overclaim; they cannot catch an alias or obfuscation.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

COMMUNICATION_OWNERSHIP_V1 = "COMMUNICATION_OWNERSHIP_V1"
COMMUNICATION_OWNERSHIP_VIOLATION = "COMMUNICATION_OWNERSHIP_VIOLATION"

MODEL_OWNER = "ciph/kernel/model_boundary.py"
PIPELINE_OWNER = "ciph/kernel/notification_pipeline.py"
ADAPTER_OWNER = "ciph/kernel/session_adapter.py"
PERMIT_OWNER = "ciph/kernel/execution_authority.py"
VAULT_OWNER = "cipher_vault.py"
OWNED_MODULES = (MODEL_OWNER, PIPELINE_OWNER, ADAPTER_OWNER)

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

_MODEL_TABLES = ("ciph_model_invocations",)
_PIPELINE_TABLES = ("ciph_notifications", "ciph_notification_attempts", "ciph_notification_preferences")
_ADAPTER_TABLES = ("ciph_channel_bindings", "ciph_session_inbound")
_CANONICAL_TABLES = ("ciph_permits", "ciph_standing_authorizations", "ciph_result_sets", "ciph_findings",
                     "ciph_observations", "ciph_conv_turns", "ciph_execution_receipts")

_PERMIT_NEEDLE = "SignedExecutionPermit" + "("

_FORBIDDEN_NEEDLES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("a transport claims onion routing it does not provide", ("onion_routing = True",
                                                              "onion_routing_protected = True",
                                                              "onion_routing_verified = True")),
    ("fabricated receipt", ("assume_delivered(", "mark_read_without_evidence(", "fake_receipt(")),
)


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    signal: str


CENSUS: Tuple[Concern, ...] = (
    Concern("model invocation record", MODEL_OWNER, "TABLE:ciph_model_invocations"),
    Concern("notification outbox", PIPELINE_OWNER, "TABLE:ciph_notifications"),
    Concern("transport attempts", PIPELINE_OWNER, "TABLE:ciph_notification_attempts"),
    Concern("notification preferences", PIPELINE_OWNER, "TABLE:ciph_notification_preferences"),
    Concern("channel bindings", ADAPTER_OWNER, "TABLE:ciph_channel_bindings"),
    Concern("inbound messages", ADAPTER_OWNER, "TABLE:ciph_session_inbound"),
    Concern("execution permits", PERMIT_OWNER, "TABLE:ciph_permits"),
    Concern("vault custody", VAULT_OWNER, "TABLE:ciph_vault_headers"),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (MODEL_OWNER, ("provider_status", "invoke", "invocations", "reality_gate", "fabricated_identities",
                   "selected_context")),
    (PIPELINE_OWNER, ("compose", "enqueue", "dispatch", "confirm_delivery", "confirm_read",
                      "suppress_stale", "set_preferences", "outbox_digest")),
    (ADAPTER_OWNER, ("DisposableFakeTransport", "RealSessionConnector", "bind_operator", "ingest_inbound",
                     "evaluate_session_js", "refuse_constitutional_write", "session_digest")),
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


def _by_owner(root: Optional[Any], ownership: Tuple[Tuple[str, Tuple[str, ...]], ...],
              sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for table, owners in ownership:
            if relative in owners or _writes(text, table) is False:
                continue
            offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def rival_communication_owners(root: Optional[Any] = None,
                               sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    ownership = tuple([(table, (MODEL_OWNER,)) for table in _MODEL_TABLES] +
                      [(table, (PIPELINE_OWNER,)) for table in _PIPELINE_TABLES] +
                      [(table, (ADAPTER_OWNER,)) for table in _ADAPTER_TABLES])
    return _by_owner(root, ownership, sources)


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


def forbidden_communication_patterns(root: Optional[Any] = None,
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


def adapters_hold_no_ciph_credentials(root: Optional[Any] = None,
                                      sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """No messaging module may reach Ciph's vault, keys or operator-root authority."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative not in OWNED_MODULES:
            continue
        for needle in ("CipherVault", "ciph.key", "ciph.salt", "quantum.key", "vault_key", "root_key"):
            if needle in text:
                offenders.append(f"{relative}:{needle}")
    return tuple(sorted(set(offenders)))


def no_second_brain(root: Optional[Any] = None,
                    sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """The boundary WRAPS the existing client; it must not define its own model client class."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative != MODEL_OWNER:
            continue
        for needle in ("class Brain", "class BrainRouter", "class CiphRouter", "class OllamaBrain",
                       "class OpenAI"):
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
    return {"policy_version": COMMUNICATION_OWNERSHIP_V1, "concerns": len(CENSUS),
            "rival_communication_owners": list(rival_communication_owners(root)),
            "owned_modules_write_canonical": list(owned_modules_write_canonical(root)),
            "permits_minted_outside_the_owner": list(permits_minted_outside_the_owner(root)),
            "forbidden_communication_patterns": list(forbidden_communication_patterns(root)),
            "adapters_hold_no_ciph_credentials": list(adapters_hold_no_ciph_credentials(root)),
            "no_second_brain": list(no_second_brain(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(COMMUNICATION_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
