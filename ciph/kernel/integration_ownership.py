"""
ciph/kernel/integration_ownership - 10.14 Part A: the EXECUTABLE owner-to-owner integration map.

    There is no central "Ciph brain" that replaces the constitutional owners. There are owners and boundaries.

Each entry names a phase, its canonical owner module, the public surface the integration actually calls, the
tables that owner is the SOLE writer of (or None when it owns no table), and who may READ its projections.
`validate` checks the map against the actual source tree: a declared surface that has disappeared is a
broken boundary, not a documentation slip, and it fails loudly.

This module owns no operational state. It is a map, and it is checked like one.
"""

import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

INTEGRATION_OWNERSHIP_V1 = "INTEGRATION_OWNERSHIP_V1"
INTEGRATION_MAP_INVALID = "INTEGRATION_MAP_DOES_NOT_MATCH_THE_SOURCE_TREE"

_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Boundary:
    phase: str
    owner: str
    surface: Tuple[str, ...]
    sole_writer_of: Tuple[str, ...] = ()
    read_by: Tuple[str, ...] = ()
    identity: str = ""
    authorization: str = ""
    recovery: str = ""
    failure: str = ""


# The map. `surface` is the integration contract: if one of these names disappears, the boundary is broken.
MAP: Tuple[Boundary, ...] = (
    Boundary("4.0 constitutional execution", "ciph/kernel/execution_authority.py",
             ("SignedExecutionPermit",), ("ciph_permits",), ("permit_store", "execution_gateway"),
             identity="permit digest + authority epoch", authorization="the gateway only",
             recovery="pending claims reconcile through 4.1", failure="refusal recorded, nothing minted"),
    Boundary("4.0 guarded gateway", "ciph/kernel/execution_gateway.py", ("GuardedExecutor",),
             (), ("10.9 expeditions",), identity="attempt + permit", authorization="validates the permit",
             recovery="unresolved attempts surface in 4.1", failure="refuses without a permit"),
    Boundary("4.1 continuity", "ciph/kernel/continuity.py", ("reconstruct", "ActionContinuity"),
             (), ("10.2 presence", "10.7 reflexes"), identity="attempt id", authorization="n/a",
             recovery="reconstruction is the mechanism", failure="reconciliation obligations reported"),
    Boundary("4.2 epistemics", "ciph/kernel/epistemic_ledger.py",
             ("record_observation", "record_evidence", "record_model_output", "reconstruct"),
             ("ciph_observations", "ciph_evidence", "ciph_model_outputs"), ("10.0", "10.4", "10.12"),
             identity="observation/evidence/proposition digest", authorization="n/a",
             recovery="append-only history", failure="no evidence is manufactured"),
    Boundary("4.3 self-model", "ciph/kernel/self_model.py",
             ("record_installation", "record_execution_evidence", "project_capability"),
             ("ciph_self_executions",), ("10.3 adapters", "10.9"), identity="capability + manifest",
             authorization="n/a", recovery="the ladder reconstructs", failure="UNKNOWN until verified"),
    Boundary("4.4 curiosity", "ciph/kernel/curiosity_proposal.py",
             ("propose_investigation", "accept_proposal"), ("ciph_curiosity_proposals",), ("10.9", "10.10"),
             identity="uncertainty basis digest", authorization="n/a", recovery="proposals persist",
             failure="do-nothing is a recordable conclusion"),
    Boundary("4.4 uncertainty registry", "ciph/kernel/uncertainty_registry.py", ("derive_uncertainties",),
             (), ("10.9", "10.10"), identity="uncertainty id", authorization="n/a",
             recovery="projection, reconstructible", failure="derived, never invented"),
    Boundary("4.5-4.7 governed research", "ciph/kernel/crucible_promotion.py", ("promote",),
             ("ciph_crucible_promotions",), ("R7", "10.11"), identity="promotion + candidate",
             authorization="operator path", recovery="promotion history", failure="refused without a protocol"),
    Boundary("R7 production choke point", "ciph/kernel/evolution_deployment.py", ("deploy", "get_deployment"),
             ("ciph_crucible_deployments",), ("10.4", "10.9"), identity="deployment id",
             authorization="promotion + authorization ref", recovery="active pointer reconstruction",
             failure="installer never runs on a refused deployment"),
    Boundary("5.x standing authorization", "ciph/kernel/standing_authorization.py",
             ("authorization_status", "assert_work_permitted"), ("ciph_standing_authorizations",),
             ("10.9", "10.12"), identity="standing auth id", authorization="operator grants only",
             recovery="revocation and expiry are read live", failure="refusal names the reason"),
    Boundary("5.x autonomy modes", "ciph/kernel/autonomy_modes.py", ("assert_mode_permits", "current_mode"),
             ("ciph_autonomy_mode_history",), ("10.9", "10.10"), identity="mode history",
             authorization="operator only", recovery="history", failure="the daemon cannot lower the mode"),
    Boundary("5.x autonomy budgets", "ciph/kernel/autonomy_budgets.py",
             ("open_budget", "budget_status", "consume_budget"), ("ciph_autonomy_budgets",),
             ("10.7", "10.10"), identity="budget id", authorization="operator-granted",
             recovery="consumption is durable", failure="consumption past the limit is refused"),
    Boundary("6.x worker identity", "ciph/kernel/swarm_worker.py",
             ("register_worker", "attest_worker", "is_current_generation"), ("ciph_swarm_workers",),
             ("10.3", "10.5", "10.9"), identity="worker + instance generation",
             authorization="operator attests", recovery="generations are distinct across restarts",
             failure="a superseded generation is refused"),
    Boundary("6.x delegation", "ciph/kernel/swarm_delegation.py",
             ("propose_delegation", "claim_delegation", "reclaim_expired_leases"),
             ("ciph_swarm_delegations", "ciph_swarm_leases"), ("10.2", "10.5", "10.9"),
             identity="task + generation", authorization="the swarm refuses when frozen",
             recovery="expired leases are reclaimed, never silently resumed",
             failure="a second claim is refused"),
    Boundary("6.x results", "ciph/kernel/swarm_results.py", ("submit_result", "results_for"),
             ("ciph_swarm_results",), ("10.2", "10.5", "10.9"), identity="result id",
             authorization="WORK_CLASS must be permitted", recovery="late arrivals are retained and classified",
             failure="a result is a claim, never evidence by itself"),
    Boundary("7.x federation identity", "ciph/kernel/federation_node.py", ("register_node", "nodes"),
             ("ciph_federation_nodes",), ("10.3", "10.5", "10.9"), identity="node + generation",
             authorization="operator attests", recovery="rejoin dispositions",
             failure="a disconnected node is UNKNOWN, never DEAD"),
    Boundary("7.x federation authority", "ciph/kernel/federation_authority.py", ("open_domain", "domains"),
             ("ciph_federation_domains",), ("10.5",), identity="domain id",
             authorization="the domain owner", recovery="partition views",
             failure="a quorum claim cannot override the domain owner"),
    Boundary("8.x recovery", "ciph/kernel/recovery_engine.py",
             ("issue_recovery_authorization", "RECOVERY_ENGINE_V1"),
             ("ciph_recovery_state",), ("10.5", "10.9"), identity="recovery generation",
             authorization="operator activation", recovery="this IS the recovery owner",
             failure="a restored clone does not activate itself"),
    Boundary("9.x environment observation", "ciph/kernel/environment_boot.py", ("begin_boot", "advance_boot"),
             ("ciph_environment_boots",), ("10.4",), identity="boot + service identity",
             authorization="operator activation ceremony",
             recovery="boot states are recorded", failure="no privileged-host claim is made here"),
    Boundary("10.0 referential continuity", "ciph/kernel/referential_continuity.py",
             ("commit_result_set", "announce", "retrieve_nth", "resolve_conversational_reference"),
             ("ciph_result_sets", "ciph_findings", "ciph_announcements", "ciph_followups"),
             ("10.1", "10.9", "10.12", "10.13"), identity="content-derived result/finding id",
             authorization="operator for protected sets", recovery="append-only revisions",
             failure="retrieval never re-runs a scan"),
    Boundary("10.1 conversation", "ciph/kernel/conversational_continuity.py",
             ("record_turn", "authorized_history", "resolve_reference"), ("ciph_conv_turns",),
             ("10.2", "10.12", "10.13"), identity="turn id + ordinal", authorization="session participant",
             recovery="durable rows, no context window", failure="a forged participant is refused"),
    Boundary("10.2 operational presence", "ciph/kernel/operational_presence.py",
             ("delegation_disposition", "absence_report", "resume_plan", "commitment_authorization"),
             (), ("10.12", "10.14"), identity="projection only", authorization="reads the owner",
             recovery="reports gaps honestly", failure="a promise is not permission"),
    Boundary("10.3 sensory fabric", "ciph/kernel/sensory_fabric.py",
             ("register_sensor", "ingest", "sensor_status", "reconstruct"),
             ("ciph_sensors", "ciph_sensor_events", "ciph_sensor_gaps", "ciph_sensor_conflicts"),
             ("10.4", "10.5", "10.7", "10.8"), identity="sensor + version + sequence + generation",
             authorization="none - observations are not authority", recovery="gaps marked, nothing invented",
             failure="silence is not a verdict about the subject"),
    Boundary("10.4 architectural proprioception", "ciph/kernel/architectural_proprioception.py",
             ("observe_source", "witness_loaded", "witness_change", "integrity_claim"),
             ("ciph_arch_components", "ciph_arch_observations", "ciph_arch_changes"),
             ("10.3", "10.7", "10.12"), identity="component + view", authorization="none",
             recovery="append-only change history", failure="self-certification is refused"),
    Boundary("10.5 operational awareness", "ciph/kernel/operational_awareness.py",
             ("correlate", "subject_state", "contradictions", "build_projection"),
             ("ciph_operational_links",), ("10.9", "10.10", "10.15"), identity="link id",
             authorization="none - a projection", recovery="relationships are durable",
             failure="history alone cannot keep a subject CURRENT"),
    Boundary("10.6 attention", "ciph/kernel/selective_attention.py",
             ("classify", "submit", "schedule", "invoke", "checkpoint", "model_unavailable"),
             ("ciph_attention_requests", "ciph_attention_focus"), ("10.7", "10.9", "10.10", "10.12"),
             identity="request id", authorization="none - it allocates inference",
             recovery="focus contexts survive restart", failure="a label cannot confer CRITICAL"),
    Boundary("10.7 reflexes", "ciph/kernel/governed_reflexes.py", ("register_reflex", "evaluate", "invoke"),
             ("ciph_reflex_decisions", "ciph_reflex_outcomes"), ("10.8",), identity="rule id + version",
             authorization="the declared authority basis", recovery="decisions without an outcome are visible",
             failure="a reflex never mints a permit"),
    Boundary("10.8 homeostasis", "ciph/kernel/operational_homeostasis.py",
             ("propose_baseline", "approve_baseline", "evaluate", "interpretation"),
             ("ciph_homeostasis_baselines", "ciph_homeostasis_anomalies"), ("10.9", "10.10"),
             identity="baseline id + version", authorization="operator promotes a baseline",
             recovery="states are append-only", failure="a deviation is not a cause"),
    Boundary("10.9 expeditions", "ciph/kernel/independent_expeditions.py",
             ("propose_expedition", "authorize_expedition", "dispatch", "record_result"),
             ("ciph_expeditions", "ciph_notification_candidates"), ("10.12", "10.13"),
             identity="expedition id", authorization="5.x decides", recovery="lifecycle is refused if illegal",
             failure="interestingness is not permission"),
    Boundary("10.10 incubation", "ciph/kernel/incubation.py",
             ("generate_hypothesis", "novelty", "operating_modes"), ("ciph_incubation_hypotheses",),
             ("10.12",), identity="hypothesis id + novelty key", authorization="none",
             recovery="lineage is durable", failure="a hypothesis is never a result"),
    Boundary("10.12 personality", "ciph/kernel/personality_policy.py",
             ("propose_change", "rollback", "style_for", "render"), ("ciph_personality_policies",),
             ("10.14",), identity="key + version", authorization="operator for stable commitments",
             recovery="append-only version history", failure="low authority needs repetition"),
    Boundary("10.12 claim validation", "ciph/kernel/claim_validation.py",
             ("prepare", "validate", "render", "conservative_fallback"), ("ciph_claims",), ("10.13",),
             identity="claim id", authorization="none", recovery="the canonical owner is re-read",
             failure="conservative fallback instead of an unsupported claim"),
    Boundary("10.13 model boundary", "ciph/kernel/model_boundary.py",
             ("provider_status", "invoke", "reality_gate"), ("ciph_model_invocations",), ("10.12",),
             identity="invocation id + prompt digest", authorization="network egress must be permitted",
             recovery="refusals are recorded", failure="no provider means NO output is invented"),
    Boundary("10.13 notifications", "ciph/kernel/notification_pipeline.py",
             ("compose", "dispatch", "confirm_delivery", "confirm_read"), ("ciph_notifications",),
             ("10.14",), identity="notification id", authorization="operator preferences",
             recovery="outbox reconstructs", failure="a claim without an artifact is only acceptance"),
    Boundary("10.13 session adapter", "ciph/kernel/session_adapter.py",
             ("DisposableFakeTransport", "RealSessionConnector", "ingest_inbound"), ("ciph_channel_bindings",),
             ("10.14",), identity="channel binding + message id", authorization="operator binding",
             recovery="inbound is durable", failure="a forged sender is refused"),
    Boundary("10.14 evidence reconciliation", "ciph/kernel/evidence_reconciliation.py",
             ("reconcile", "score_conclusion", "citation_consistency"), ("ciph_reconciliations",),
             ("10.15",), identity="record id", authorization="none",
             recovery="records persist", failure="an unsettled record demands abstention"),
)


def production_sources(root: Optional[Any] = None) -> Dict[str, str]:
    """PRODUCTION sources only: a test that writes a table is exercising an owner, not competing with one."""
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    found: Dict[str, str] = {}
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts or any(part in path.parts for part in
                                              ("ciph_env", "site-packages", ".venv", "node_modules")):
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            continue
        try:
            found[path.relative_to(base).as_posix()] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return found


def validate(root: Optional[Any] = None) -> Dict[str, Any]:
    """Every declared boundary must exist AND still expose the surface the integration calls."""
    sources = production_sources(root)
    missing_files: List[str] = []
    missing_surface: List[str] = []
    for boundary in MAP:
        text = sources.get(boundary.owner)
        if text is None:
            missing_files.append(boundary.owner)
            continue
        for name in boundary.surface:
            if name not in text:
                missing_surface.append(f"{boundary.owner}:{name}")
    return {"policy_version": INTEGRATION_OWNERSHIP_V1, "boundaries": len(MAP),
            "missing_files": missing_files, "missing_surface": missing_surface,
            "valid": not (missing_files or missing_surface)}


def assert_map_valid(root: Optional[Any] = None) -> Dict[str, Any]:
    report = validate(root)
    if not report["valid"]:
        raise CrucibleError(INTEGRATION_MAP_INVALID,
                            f"files={report['missing_files']} surface={report['missing_surface']}")
    return report


def owners_of(table: str) -> Tuple[str, ...]:
    return tuple(boundary.owner for boundary in MAP if table in boundary.sole_writer_of)


def rival_writers(table: str, root: Optional[Any] = None) -> Tuple[str, ...]:
    """
    Any module that WRITES a table it is not the declared sole writer of. This is the 'no competing canonical
    ownership' check, and it is the same shape the per-phase censuses use.
    """
    import re
    declared = owners_of(table)
    offenders = []
    for relative, text in production_sources(root).items():
        if relative in declared or relative.rsplit("/", 1)[-1].endswith(_CATALOGUE_SUFFIXES):
            continue
        if re.search(rf"\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+"
                     rf"{re.escape(table)}\b", text, re.IGNORECASE):
            offenders.append(relative)
        elif re.search(rf"\bCREATE TABLE(?: IF NOT EXISTS)?\s+{re.escape(table)}\b", text, re.IGNORECASE):
            offenders.append(relative)
    return tuple(sorted(offenders))


def ownership_conflicts(root: Optional[Any] = None, *, sample_tables: Sequence[str] = ()) -> Tuple[str, ...]:
    offenders: List[str] = []
    for table in sample_tables:
        for relative in rival_writers(table, root=root):
            offenders.append(f"{relative}:{table}")
    return tuple(sorted(set(offenders)))


def integration_report(root: Optional[Any] = None, *, sample_tables: Sequence[str] = ()) -> Dict[str, Any]:
    report = validate(root)
    report["sample_tables"] = list(sample_tables)
    report["conflicts"] = list(ownership_conflicts(root, sample_tables=sample_tables))
    return report


def integration_digest(root: Optional[Any] = None) -> str:
    report = validate(root)
    return digest({"boundaries": [boundary.phase for boundary in MAP],
                   "valid": report["valid"], "missing": report["missing_surface"]})
