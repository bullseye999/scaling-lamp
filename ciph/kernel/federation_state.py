"""
ciph/kernel/federation_state - 7.2: state classification.

    "Sync the database" is not a federation strategy.

Before anything replicates, every durable state family has to say WHAT KIND of thing it is, because the
kind decides how it may travel, how it may conflict, and who is allowed to be right. Six kinds, frozen
in one policy identity:

    GLOBAL_CANONICAL     one authoritative lineage for the whole federation, single-writer. Replicates
                         as AUTHORITY, and only from the current owner - never merged, never voted on.
    REPLICATED_EVIDENCE  append-only facts that many nodes may each observe. Merges by canonical
                         identity and digest. Replication grants PROVENANCE, never standing.
    DERIVED_PROJECTION   rebuildable from canonical history. Never replicated as truth; a node that
                         receives it discards and rebuilds.
    NODE_LOCAL           belongs to one host (a process id, a lease carrier). Never becomes global
                         truth merely because it is convenient.
    SECRET_LOCAL         key material and root custody. NEVER ordinary-replicated.
    EPHEMERAL            caches and scratch state. Not replicated, not authoritative, not missed.

The classification covers the families that already exist in the project, including the ones that would
be most tempting to "just sync": the active candidate pointer, the EvolutionEpoch history, the autonomy
session state, the swarm worker/process state, and the vault root secret.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

FEDERATION_STATE_CLASSIFICATION_V1 = "FEDERATION_STATE_CLASSIFICATION_V1"

GLOBAL_CANONICAL = "GLOBAL_CANONICAL"
REPLICATED_EVIDENCE = "REPLICATED_EVIDENCE"
DERIVED_PROJECTION = "DERIVED_PROJECTION"
NODE_LOCAL = "NODE_LOCAL"
SECRET_LOCAL = "SECRET_LOCAL"
EPHEMERAL = "EPHEMERAL"
VALID_CLASSES = (GLOBAL_CANONICAL, REPLICATED_EVIDENCE, DERIVED_PROJECTION, NODE_LOCAL, SECRET_LOCAL,
                 EPHEMERAL)

# Travel: may this family appear in ordinary federation replication at all?
_TRAVELS = {
    GLOBAL_CANONICAL: True,       # as authority, from the owner only
    REPLICATED_EVIDENCE: True,    # as evidence, merging by canonical identity
    DERIVED_PROJECTION: False,    # rebuilt, never shipped as truth
    NODE_LOCAL: False,
    SECRET_LOCAL: False,
    EPHEMERAL: False,
}

REASON_UNKNOWN_FAMILY = "UNCLASSIFIED_STATE_FAMILY"
REASON_NOT_REPLICABLE = "STATE_FAMILY_MUST_NOT_ORDINARILY_REPLICATE"


@dataclass(frozen=True)
class StateFamily:
    family: str
    state_class: str
    carrier: str
    rebuildable: bool
    note: str

    def as_dict(self) -> Dict[str, Any]:
        return {"family": self.family, "state_class": self.state_class, "carrier": self.carrier,
                "rebuildable": self.rebuildable, "note": self.note,
                "policy_version": FEDERATION_STATE_CLASSIFICATION_V1}


# THE FROZEN POLICY. Every durable family the project holds, classified once.
STATE_FAMILIES: Tuple[StateFamily, ...] = (
    StateFamily("missions", GLOBAL_CANONICAL, "ciph_missions", False,
                "mission identity and status: one authoritative lineage"),
    StateFamily("mission_plans", GLOBAL_CANONICAL, "ciph_mission_plans", False,
                "plan projections advance under one writer"),
    StateFamily("epistemic_evidence", REPLICATED_EVIDENCE, "ciph_observations", False,
                "observations merge by canonical identity; replication adds provenance, not standing"),
    StateFamily("beliefs", DERIVED_PROJECTION, "ciph_belief_*", True,
                "belief is a projection of evidence and is rebuilt, not shipped"),
    StateFamily("curiosity_uncertainty", DERIVED_PROJECTION, "ciph_uncertainty_*", True,
                "uncertainty is re-derived from the same evidence"),
    StateFamily("permits", GLOBAL_CANONICAL, "ciph_execution_permits", False,
                "execution authority is single-writer; a permit is not portable by replication"),
    StateFamily("active_candidate_pointer", GLOBAL_CANONICAL, "ciph_crucible_active", False,
                "the pointer is the constitution's answer to 'what is active'"),
    StateFamily("evolution_epoch", GLOBAL_CANONICAL, "ciph_evolution_epochs", False,
                "epochs are an authoritative lineage"),
    StateFamily("crucible_candidates", REPLICATED_EVIDENCE, "ciph_crucible_candidates", False,
                "candidate records may be shared; standing is decided by the lineage, not the copy"),
    StateFamily("autonomy_state", NODE_LOCAL, "ciph_autonomy_*", False,
                "sessions, budgets and modes describe one host's continuous operation"),
    StateFamily("autonomy_standing", GLOBAL_CANONICAL, "ciph_standing_authorizations", False,
                "a standing grant is authority and has one owner"),
    StateFamily("swarm_worker_state", NODE_LOCAL, "ciph_swarm_workers", False,
                "workers are a host's subordinate machinery, not federation state"),
    StateFamily("swarm_delegation", NODE_LOCAL, "ciph_swarm_delegations", False,
                "delegation is host-scoped work assignment"),
    StateFamily("node_membership", GLOBAL_CANONICAL, "ciph_federation_membership", False,
                "who is a member is federation law, not a per-node opinion"),
    StateFamily("authority_domains", GLOBAL_CANONICAL, "ciph_federation_authority_domains", False,
                "domain ownership and epoch are the constitution's distributed answer"),
    StateFamily("federation_membership_replica", REPLICATED_EVIDENCE, "ciph_federation_replicated_records",
                False, "membership EVIDENCE may be replicated; membership DECISION is canonical"),
    StateFamily("vault_root_secret", SECRET_LOCAL, "ciph_vault.db + ciph.key", False,
                "root custody stays with the operator; it never ordinary-replicates"),
    StateFamily("node_keys", SECRET_LOCAL, "node key material", False,
                "a node's private credential stays on the node; only the public reference travels"),
    StateFamily("worldview_cache", EPHEMERAL, "ciph_mv_observations", True,
                "materialized views are a cache over observations"),
    StateFamily("lean_projection_cache", EPHEMERAL, "ciph_epistemic_projection", True,
                "projection caches are disposable by construction"),
    StateFamily("federation_quiescence", GLOBAL_CANONICAL, "ciph_federation_barriers", False,
                "a barrier is federation law: one lineage decides whether the federation is stopped"),
    StateFamily("federation_learning", NODE_LOCAL, "ciph_federation_placement_attempts", False,
                "placement history is descriptive and per-observer"),
    StateFamily("node_health_observation", REPLICATED_EVIDENCE, "ciph_federation_health", False,
                "health observations are evidence; UNREACHABLE is an observation about a link"),
)

_BY_FAMILY: Dict[str, StateFamily] = {item.family: item for item in STATE_FAMILIES}


def classify(family: str) -> StateFamily:
    """An unclassified family FAILS UPWARD - it is never quietly treated as replicable."""
    item = _BY_FAMILY.get(str(family))
    if item is None:
        raise CrucibleError(REASON_UNKNOWN_FAMILY, str(family))
    return item


def state_class(family: str) -> str:
    return classify(family).state_class


def travels_in_ordinary_replication(family: str) -> bool:
    return _TRAVELS[state_class(family)]


def assert_may_replicate(family: str) -> StateFamily:
    item = classify(family)
    if not _TRAVELS[item.state_class]:
        raise CrucibleError(REASON_NOT_REPLICABLE, f"{family}:{item.state_class}")
    return item


def rebuildable(family: str) -> bool:
    return classify(family).rebuildable


def rebuild_plan() -> Dict[str, Any]:
    """Which families a node can regenerate from canonical history instead of receiving them."""
    return {"policy_version": FEDERATION_STATE_CLASSIFICATION_V1,
            "rebuildable": sorted(item.family for item in STATE_FAMILIES if item.rebuildable),
            "secret_local": sorted(item.family for item in STATE_FAMILIES
                                   if item.state_class == SECRET_LOCAL),
            "node_local": sorted(item.family for item in STATE_FAMILIES
                                 if item.state_class == NODE_LOCAL),
            "ordinary_replication": sorted(item.family for item in STATE_FAMILIES
                                           if _TRAVELS[item.state_class])}


def classification_digest() -> str:
    return digest({"version": FEDERATION_STATE_CLASSIFICATION_V1,
                   "families": [item.as_dict() for item in STATE_FAMILIES],
                   "travels": {name: _TRAVELS[name] for name in VALID_CLASSES}})


def explain(family: str) -> Dict[str, Any]:
    """Why a family travels the way it does - the sentence a reviewer needs, not a flag."""
    item = classify(family)
    return {**item.as_dict(), "travels": _TRAVELS[item.state_class],
            "law": "replication grants provenance, never standing"}
