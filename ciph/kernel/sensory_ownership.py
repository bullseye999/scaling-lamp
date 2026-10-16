"""
ciph/kernel/sensory_ownership - the 10.3 ownership census.

    One owner for sensor registration and observation transport. No second truth store beside it.

WHAT THE SURVEY FOUND. Ciph already HAS the state the fabric must observe; it has no single place that
transports observations about that state. The owners are: 4.2 `epistemic_ledger` (epistemic facts), 4.3
`self_model` (the empirical capability ladder and execution record), 10.4 `architectural_proprioception`
(the four architectural views), 5.x `autonomy_session`/`autonomy_schedule`, 6.x `swarm_worker`/
`swarm_delegation`/`swarm_results`, 7.x `federation_node`, and 10.0 `referential_continuity` (findings and
announcements). The fabric binds to ALL of them and duplicates NONE of them.

The rules below exist because each names a real way a "sensory" layer goes wrong: it starts minting
authority, it starts writing the ledger itself, it invents a universal urgency score, it certifies itself, or
it quietly becomes a second architecture observer.

LIMITATION, stated rather than hidden: these are SYNTACTIC checks. They catch a named rival, a message
transported by the wrong module, a heartbeat written into the ledger and an obvious overclaim; they cannot
catch an alias, obfuscation, or a rival introduced under an unrelated name.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SENSORY_OWNERSHIP_V1 = "SENSORY_OWNERSHIP_V1"
SENSORY_OWNERSHIP_VIOLATION = "SENSORY_OWNERSHIP_VIOLATION"

OWNER = "ciph/kernel/sensory_fabric.py"
ADAPTERS = "ciph/kernel/sensory_adapters.py"
SENSORY_MODULES = (OWNER, ADAPTERS)

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Tables only ONE owner may write. A second writer is a rival transport or a rival truth store.
_SENSOR_TABLES = ("ciph_sensors", "ciph_sensor_events", "ciph_sensor_status",
                  "ciph_sensor_generations", "ciph_sensor_gaps", "ciph_sensor_conflicts")
_CANONICAL_TABLES = ("ciph_observations", "ciph_evidence", "ciph_self_executions",
                     "ciph_arch_components", "ciph_arch_observations", "ciph_arch_changes",
                     "ciph_result_sets", "ciph_findings", "ciph_crucible_deployments")

# Names that would be a rival authority, a forbidden synthesis, or a self-certification.
_FORBIDDEN_NEEDLES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("sensor mints authority", ("sensor_grants_authority(", "sensor_mints_permit(", "sensor_approves(",
                                "sensor_authorizes(")),
    ("universal urgency score", ("urgency_score(", "universal_priority(", "attention_score(",
                                 "sensor_priority_score(")),
    ("self-certification", ("sensor_certifies(", "self_attested(", "certify_own_observations(")),
    ("fabric invokes the model", ("call_model(", "invoke_llm(", "query_model(", "ask_the_model(")),
    ("hardware attestation overclaim", ("tpm_verified = True", "secure_boot_attested = True")),
)


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    signal: str

    def owner_path(self) -> str:
        return self.canonical_owner


CENSUS: Tuple[Concern, ...] = (
    Concern("sensor registry", OWNER, "TABLE:ciph_sensors"),
    Concern("sensor event transport", OWNER, "TABLE:ciph_sensor_events"),
    Concern("sensor status", OWNER, "TABLE:ciph_sensor_status"),
    Concern("sensor generation history", OWNER, "TABLE:ciph_sensor_generations"),
    Concern("sensor gap and loss record", OWNER, "TABLE:ciph_sensor_gaps"),
    Concern("sensor integrity conflict store", OWNER, "TABLE:ciph_sensor_conflicts"),
    Concern("epistemic observation ledger", "ciph/kernel/epistemic_ledger.py", "TABLE:ciph_observations"),
    Concern("architectural observation", "ciph/kernel/architectural_proprioception.py",
            "TABLE:ciph_arch_observations"),
    Concern("referential findings", "ciph/kernel/referential_continuity.py", "TABLE:ciph_result_sets"),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (OWNER, ("register_sensor", "ingest", "reconstruct", "restart", "context_for_reasoning",
             "sensor_status", "record_observation_gap", "process_resource_usage")),
    (ADAPTERS, ("observe_architecture", "witness_runtime", "observe_execution", "observe_swarm",
                "observe_federation", "observe_investigations", "observe_resources", "observe_integrity",
                "observe_communications", "run_cycle")),
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


def rival_sensor_transport_owners(root: Optional[Any] = None,
                                  sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """A second module declaring a sensor table is a rival observation transport."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative == OWNER or _is_catalogue(relative):
            continue
        for table in _SENSOR_TABLES:
            if _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def sensory_modules_write_canonical(root: Optional[Any] = None,
                                    sources: Optional[List[Tuple[str, str]]] = None
                                    ) -> Tuple[str, ...]:
    """A sensor reports; it never writes a canonical owner's table."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative not in SENSORY_MODULES:
            continue
        for table in _CANONICAL_TABLES:
            if _writes(text, table):
                offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def heartbeats_written_to_the_ledger(root: Optional[Any] = None,
                                     sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """The fabric core transports observations; it does not append them to the 4.2 ledger itself."""
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative != OWNER:
            continue
        if "record_observation(" in text:
            offenders.append(f"{relative}:record_observation")
    return tuple(sorted(set(offenders)))


def forbidden_sensory_patterns(root: Optional[Any] = None,
                               sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    scope = sources if sources is not None else production_sources(root)
    found = []
    for relative, text in scope:
        if relative in SENSORY_MODULES or _is_catalogue(relative):
            continue
        for _concern, needles in _FORBIDDEN_NEEDLES:
            for needle in needles:
                if needle in text:
                    found.append(f"{relative}:{needle}")
    return tuple(sorted(set(found)))


def architectural_views_preserved(root: Optional[Any] = None,
                                  sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """
    The adapters must feed 10.4's four views rather than keep their own picture of the architecture. The
    check that matters: an adapter that records a source change must NOT write a LOADED view from a file read.
    """
    scope = sources if sources is not None else production_sources(root)
    offenders = []
    for relative, text in scope:
        if relative != ADAPTERS:
            continue
        if "VIEW_BY_ADAPTER" not in text:
            offenders.append(f"{relative}:missing-view-map")
        if "architectural_proprioception" not in text:
            offenders.append(f"{relative}:not-bound-to-10.4")
        if "read_bytes(" in text and "LOADED" in text:
            offenders.append(f"{relative}:loaded-view-from-a-file-read")
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
    return {"policy_version": SENSORY_OWNERSHIP_V1, "concerns": len(CENSUS),
            "rival_sensor_transport_owners": list(rival_sensor_transport_owners(root)),
            "sensory_modules_write_canonical": list(sensory_modules_write_canonical(root)),
            "heartbeats_written_to_the_ledger": list(heartbeats_written_to_the_ledger(root)),
            "forbidden_sensory_patterns": list(forbidden_sensory_patterns(root)),
            "architectural_views_preserved": list(architectural_views_preserved(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(SENSORY_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
