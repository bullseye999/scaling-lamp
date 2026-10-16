"""
ciph.kernel.source_dependence - how many epistemically independent observations does this evidence
actually represent?

4.2 Gate One. Gate Zero answers "what evidence bears on P, and how strongly does the raw evidence
support it?". Gate One answers a different question:

    five articles   vs   five independent witnesses

and returns BOUNDS rather than a new point estimate, because unresolved provenance is a fact about
our knowledge, not a licence to assume independence.

THE SEPARATION (this module must never move Gate Zero's ground)

    Gate Zero    raw evidence confidence          `fresh_support / (fresh + fresh_contradict)`
    Gate One     independence-adjusted picture    its own projection, metric_id SOURCE_INDEPENDENCE_V1

Gate One does not rewrite evidence, does not change polarity, and does not touch the stored Gate Zero
projections. It groups the SAME evidence links into provenance families and reports what follows.

LAWS (each has a specimen in `test_gate_4_2_source_dependence.py`)

 1. SOURCE IDENTITY != SOURCE INDEPENDENCE. Different domains are not automatically different witnesses.
 2. SAME SOURCE != AUTOMATIC DEPENDENCE. One publisher can produce genuinely independent observations.
 3. PROVEN RELAYS DO NOT MULTIPLY CORROBORATION. Syndication preserves history; it adds no witness.
 4. UNKNOWN DEPENDENCE != INDEPENDENCE. Unresolved provenance widens the bounds and never raises the
    proven-independent count.
 5. DEPENDENT EVIDENCE IS NOT DELETED. A mirror remains a real evidence link; it shares a family.
 6. SOURCE DEPENDENCE DOES NOT CHANGE POLARITY. A dependent SUPPORT stays SUPPORT.
 7. CONTENT SIMILARITY IS NOT PROOF OF DEPENDENCE. Similarity is a hypothesis to investigate; only
    canonical provenance creates an edge.
 8. MODEL ASSERTION CANNOT CREATE A PROVENANCE EDGE.
 9. CONTRADICTION IS GROUPED THE SAME WAY AS SUPPORT.
10. PROVENANCE HISTORY IS APPEND-ONLY.
11. CYCLES DO NOT CREATE INDEPENDENCE. A<->B is one component and an integrity condition.
12. SAME PROVENANCE GRAPH -> same families -> same bounds -> same digest after restart.

THE GROUNDING RULE (frozen, and the reason bounds are honest)

    A provenance family is GROUNDED when its lineage is anchored:
        * it has more than one member (a relay chain with a known origin), or
        * a member is declared a PRIMARY observation, or
        * an explicit INDEPENDENCE_PROVEN statement names it.

    grounded family     -> counts toward the LOWER bound (a witness we can point at)
    ungrounded family   -> counts only toward the UPPER bound (it might be independent; nothing proves it)

So a set of unrelated reports with no provenance at all yields min = 0, not "N witnesses", and filling
in the ancestry moves the lower bound up instead of quietly changing what the upper one meant.

OUT OF SCOPE: source REPUTATION ("Reuters is usually reliable"). That is a different question from
"these four stories came from Reuters", and mixing them would let reputation buy extra votes.
"""

from dataclasses import dataclass
import hashlib
import json
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ciph.kernel.epistemic_ledger import reconstruct as reconstruct_beliefs

METRIC_ID = "SOURCE_INDEPENDENCE_V1"

# Dependency relations. Narrow on purpose: each one asserts that two observations share an origin.
RELATION_SYNDICATED_FROM = "SYNDICATED_FROM"
RELATION_COPIED_FROM = "COPIED_FROM"
RELATION_QUOTES = "QUOTES"
RELATION_DERIVED_FROM = "DERIVED_FROM"
RELATION_COMMON_ORIGIN = "COMMON_ORIGIN"
DEPENDENCE_RELATIONS = (RELATION_SYNDICATED_FROM, RELATION_COPIED_FROM, RELATION_QUOTES,
                        RELATION_DERIVED_FROM, RELATION_COMMON_ORIGIN)

# Independence relations.
RELATION_INDEPENDENCE_PROVEN = "INDEPENDENCE_PROVEN"
RELATION_PRIMARY_OBSERVATION = "PRIMARY_OBSERVATION"
INDEPENDENCE_RELATIONS = (RELATION_INDEPENDENCE_PROVEN, RELATION_PRIMARY_OBSERVATION)

RELATION_POSSIBLE_COMMON_ORIGIN = "POSSIBLE_COMMON_ORIGIN"

DEPENDENCE_PROVEN_DEPENDENT = "PROVEN_DEPENDENT"
DEPENDENCE_PROVEN_INDEPENDENT = "PROVEN_INDEPENDENT"
DEPENDENCE_UNKNOWN = "DEPENDENCE_UNKNOWN"

INTEGRITY_PROVENANCE_CYCLE = "PROVENANCE_CYCLE"
INTEGRITY_PROVENANCE_CONFLICT = "PROVENANCE_CONFLICT"

# How completely the provenance picture is RESOLVED. The earlier `dependence_status` says what is
# KNOWN about independence; this says how much of the evidence the provenance graph accounts for.
RESOLUTION_RESOLVED = "RESOLVED"
RESOLUTION_PARTIAL = "PARTIAL"
RESOLUTION_UNKNOWN = "UNKNOWN"
RESOLUTION_INTEGRITY_CONFLICT = "INTEGRITY_CONFLICT"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_provenance_edges (
        edge_id TEXT PRIMARY KEY,
        from_evidence TEXT NOT NULL,
        relation TEXT NOT NULL,
        to_evidence TEXT,
        to_source_ref TEXT,
        note TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_provenance_hypotheses (
        hypothesis_id TEXT PRIMARY KEY,
        evidence_a TEXT,
        evidence_b TEXT,
        claim TEXT,
        model_ref TEXT,
        recorded_at REAL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ciph_source_dependence_projections (
        proposition_id TEXT NOT NULL,
        metric_id TEXT NOT NULL,
        projection_version INTEGER NOT NULL,
        dependence_status TEXT NOT NULL,
        independent_support_min INTEGER,
        independent_support_max INTEGER,
        independent_contradict_min INTEGER,
        independent_contradict_max INTEGER,
        confidence_lower REAL,
        confidence_upper REAL,
        provenance_digest TEXT NOT NULL,
        projected_at REAL,
        PRIMARY KEY (proposition_id, metric_id, projection_version)
    );
    """,
)


class ProvenanceError(Exception):
    """A provenance operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class ProvenanceFamily:
    """One proven-dependency component of evidence instances, and how well it is anchored."""

    family_id: str
    members: Tuple[str, ...]
    origin: Optional[str]
    grounded: bool
    grounding: str
    polarities: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"family_id": self.family_id, "members": list(self.members), "origin": self.origin,
                "grounded": self.grounded, "grounding": self.grounding,
                "polarities": list(self.polarities)}


@dataclass(frozen=True)
class SourceDependenceProjection:
    proposition_id: str
    metric_id: str
    support_families: Tuple[ProvenanceFamily, ...]
    contradiction_families: Tuple[ProvenanceFamily, ...]
    independent_support_min: int
    independent_support_max: int
    independent_contradict_min: int
    independent_contradict_max: int
    confidence_lower: float
    confidence_upper: float
    dependence_status: str
    provenance_digest: str
    integrity_flags: Tuple[str, ...] = ()
    hypothesis_count: int = 0
    evidence_count: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "proposition_id": self.proposition_id,
            "metric_id": self.metric_id,
            "support_families": [f.as_dict() for f in self.support_families],
            "contradiction_families": [f.as_dict() for f in self.contradiction_families],
            "independent_support_min": self.independent_support_min,
            "independent_support_max": self.independent_support_max,
            "independent_contradict_min": self.independent_contradict_min,
            "independent_contradict_max": self.independent_contradict_max,
            "confidence_lower": round(self.confidence_lower, 12),
            "confidence_upper": round(self.confidence_upper, 12),
            "dependence_status": self.dependence_status,
            "provenance_digest": self.provenance_digest,
            "integrity_flags": list(self.integrity_flags),
            "hypothesis_count": self.hypothesis_count,
            "evidence_count": self.evidence_count,
        }

    # ------------------------------------------------------------------ spec vocabulary aliases
    # These names are the same facts as the fields above, exposed under the vocabulary the Gate One
    # specification uses. They are properties, not duplicated computation: there is one derivation and
    # one digest, so the two vocabularies cannot drift apart.
    @property
    def proven_support_count(self) -> int:
        return self.independent_support_min

    @property
    def possible_support_count(self) -> int:
        return self.independent_support_max

    @property
    def proven_contradict_count(self) -> int:
        return self.independent_contradict_min

    @property
    def possible_contradict_count(self) -> int:
        return self.independent_contradict_max

    @property
    def verified_support_origins(self) -> Tuple[str, ...]:
        return tuple(f.family_id for f in self.support_families if f.grounded)

    @property
    def verified_contradict_origins(self) -> Tuple[str, ...]:
        return tuple(f.family_id for f in self.contradiction_families if f.grounded)

    @property
    def unknown_support_groups(self) -> Tuple[str, ...]:
        return tuple(f.family_id for f in self.support_families if not f.grounded)

    @property
    def unknown_contradict_groups(self) -> Tuple[str, ...]:
        return tuple(f.family_id for f in self.contradiction_families if not f.grounded)

    @property
    def resolution_status(self) -> str:
        """
        How much of this evidence the provenance graph accounts for.

            INTEGRITY_CONFLICT   an ancestry/independence disagreement blocks the picture
            RESOLVED             every family is grounded: the bounds have collapsed
            PARTIAL              some families grounded, some unknown
            UNKNOWN              nothing is grounded (and there is evidence to account for)
        """
        if self.integrity_flags:
            return RESOLUTION_INTEGRITY_CONFLICT
        families = self.support_families + self.contradiction_families
        if not families:
            return RESOLUTION_UNKNOWN
        grounded = sum(1 for f in families if f.grounded)
        if grounded == len(families):
            return RESOLUTION_RESOLVED
        if grounded == 0:
            return RESOLUTION_UNKNOWN
        return RESOLUTION_PARTIAL

    def canonical_digest(self) -> str:
        """
        The FULL projection identity (law 12): provenance plus any outstanding hypotheses.

        Two digests, two jobs, deliberately:

            provenance_digest     the PROVENANCE picture only (families, bounds, interval, status)
            canonical_digest()    provenance PLUS the count of uninvestigated hypotheses

        A similarity hypothesis is a fact worth recording ("there is something to look into"), so it
        belongs in the projection's identity. It must not belong to the provenance picture, which is
        what `provenance_only_digest` exposes for exactly that assertion.
        """
        blob = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def provenance_only_digest(self) -> str:
        """The identity of the provenance picture alone: model suspicion cannot move it (law 8)."""
        return self.provenance_digest

    def interval(self) -> Tuple[float, float]:
        return self.confidence_lower, self.confidence_upper


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            pass
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


# ---------------------------------------------------------------------------- writes
def record_provenance(db_path: str, *, from_evidence: str, relation: str,
                      to_evidence: Optional[str] = None, to_source_ref: Optional[str] = None,
                      note: Optional[str] = None, now: Optional[float] = None) -> str:
    """
    Append ONE canonical provenance fact about evidence instances.

    Dependency relations name the OTHER OBSERVATION or the shared origin. `PRIMARY_OBSERVATION`
    declares that this evidence was obtained firsthand, which is what anchors a family. There is no
    update and no delete path (law 10).
    """
    if relation not in DEPENDENCE_RELATIONS + INDEPENDENCE_RELATIONS:
        raise ProvenanceError("INVALID_PROVENANCE_RELATION", str(relation))
    if not from_evidence:
        raise ProvenanceError("PROVENANCE_REQUIRES_EVIDENCE", "from_evidence is empty")
    if relation != RELATION_PRIMARY_OBSERVATION and not to_evidence and not to_source_ref:
        raise ProvenanceError("PROVENANCE_REQUIRES_TARGET", f"{relation} names nothing")
    moment = time.time() if now is None else float(now)
    edge_id = f"PRV-{uuid.uuid4().hex[:12].upper()}"
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute(
            "INSERT INTO ciph_provenance_edges (edge_id, from_evidence, relation, to_evidence, "
            "to_source_ref, note, recorded_at) VALUES (?,?,?,?,?,?,?);",
            (edge_id, from_evidence, relation, to_evidence, to_source_ref, note, moment),
        )
        conn.commit()
        return edge_id
    finally:
        conn.close()


def record_similarity_hypothesis(db_path: str, *, evidence_a: str, evidence_b: str,
                                 claim: str = RELATION_POSSIBLE_COMMON_ORIGIN,
                                 model_ref: Optional[str] = None,
                                 now: Optional[float] = None) -> str:
    """
    Record that a model NOTICED a resemblance (laws 7 and 8).

    This writes a hypothesis and creates no provenance edge. Similarity may tell Ciph where to look;
    it can never decide that two observations share an origin. Only `record_provenance` can do that.
    """
    moment = time.time() if now is None else float(now)
    hypothesis_id = f"HYP-{uuid.uuid4().hex[:12].upper()}"
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute(
            "INSERT INTO ciph_provenance_hypotheses (hypothesis_id, evidence_a, evidence_b, claim, "
            "model_ref, recorded_at) VALUES (?,?,?,?,?,?);",
            (hypothesis_id, evidence_a, evidence_b, claim, model_ref, moment),
        )
        conn.commit()
        return hypothesis_id
    finally:
        conn.close()


# ---------------------------------------------------------------------------- projection
def _load_edges(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_provenance_edges ORDER BY edge_id;")]
    except sqlite3.Error:
        return []


def _load_hypotheses(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_provenance_hypotheses ORDER BY hypothesis_id;")]
    except sqlite3.Error:
        return []


def _families(evidence_ids: Sequence[str], edges: Sequence[Mapping[str, Any]],
              polarities: Mapping[str, str]) -> Tuple[List[ProvenanceFamily], List[str]]:
    """
    Group ONE polarity's evidence into provenance families, mechanically.

    Union-find over dependency edges: cycles collapse into a single component instead of multiplying
    witnesses (law 11), and a proven dependency always wins over a claimed independence with an
    integrity flag rather than a silent preference.
    """
    parent = {e: e for e in evidence_ids}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    members = set(evidence_ids)
    dependency_pairs: List[Tuple[str, str]] = []
    independence_pairs: List[Tuple[str, str]] = []
    primary: set = set()
    for edge in edges:
        source = str(edge["from_evidence"])
        target = str(edge["to_evidence"]) if edge["to_evidence"] else None
        relation = str(edge["relation"])
        if relation == RELATION_PRIMARY_OBSERVATION:
            if source in members:
                primary.add(source)
            continue
        if target not in members or source not in members:
            continue
        pair = (source, target)
        if relation in DEPENDENCE_RELATIONS:
            dependency_pairs.append(pair)
            union(source, target)
        else:
            independence_pairs.append(pair)

    flags: List[str] = []
    for a, b in independence_pairs:
        if find(a) == find(b):
            # Proven ancestry AND a claimed independence: keep the conservative direction (one family)
            # and report the disagreement rather than letting either silently win.
            flags.append(f"{INTEGRITY_PROVENANCE_CONFLICT}:{min(a, b)}:{max(a, b)}")

    # Directed cycle detection over the dependency edges, for the integrity condition (law 11).
    adjacency: Dict[str, List[str]] = {}
    for a, b in dependency_pairs:
        adjacency.setdefault(a, []).append(b)
    state: Dict[str, int] = {}

    def has_cycle(node: str) -> bool:
        state[node] = 1
        for nxt in adjacency.get(node, []):
            if state.get(nxt) == 1:
                return True
            if state.get(nxt, 0) == 0 and has_cycle(nxt):
                return True
        state[node] = 2
        return False

    for node in sorted(adjacency):
        if state.get(node, 0) == 0 and has_cycle(node):
            flags.append(f"{INTEGRITY_PROVENANCE_CYCLE}:{node}")
            break

    grouped: Dict[str, List[str]] = {}
    for evidence_id in sorted(members):
        grouped.setdefault(find(evidence_id), []).append(evidence_id)

    independence_grounded = set()
    for a, b in independence_pairs:
        if find(a) != find(b):
            independence_grounded.add(find(a))
            independence_grounded.add(find(b))

    families: List[ProvenanceFamily] = []
    for root in sorted(grouped):
        group = grouped[root]
        # The origin is the member that derives from nothing ELSE IN THIS FAMILY that we know of.
        derived = {a for a, _b in dependency_pairs if a in group}
        targets = {b for _a, b in dependency_pairs if b in group}
        candidates = sorted((set(group) - derived) | (targets - derived))
        origin = candidates[0] if candidates else None
        if len(group) > 1:
            grounding, grounded = "RELAY_CHAIN", True
        elif group[0] in primary:
            grounding, grounded = "PRIMARY_OBSERVATION", True
        elif root in independence_grounded:
            grounding, grounded = "INDEPENDENCE_PROVEN", True
        else:
            grounding, grounded = "UNKNOWN", False
        families.append(ProvenanceFamily(
            family_id="FAM-" + hashlib.sha256(",".join(group).encode("utf-8")).hexdigest()[:12].upper(),
            members=tuple(group), origin=origin, grounded=grounded, grounding=grounding,
            polarities=(polarities.get(group[0], "UNKNOWN"),),
        ))
    return families, flags


def _bounds(families: Sequence[ProvenanceFamily]) -> Tuple[int, int]:
    lower = sum(1 for family in families if family.grounded)
    upper = lower + sum(1 for family in families if not family.grounded)
    return lower, upper


def _interval(support: Tuple[int, int], contradict: Tuple[int, int]) -> Tuple[float, float]:
    smin, smax = support
    cmin, cmax = contradict
    lower = smin / (smin + cmax) if (smin + cmax) else 0.0
    upper = smax / (smax + cmin) if (smax + cmin) else 0.0
    return round(lower, 12), round(upper, 12)


def project_source_dependence(db_path: str, proposition_id: str, *,
                              now: Optional[float] = None,
                              stale_after: Optional[float] = None,
                              conn: Optional[sqlite3.Connection] = None) -> SourceDependenceProjection:
    """
    Rebuild the independence-adjusted picture for ONE proposition from canonical provenance.

    Reads Gate Zero's evidence for the proposition (never rewrites it), groups it into provenance
    families, and reports bounds. Deleting the stored source-dependence projections changes nothing
    about this answer - they are a record, not an input.
    """
    moment = time.time() if now is None else float(now)
    state = reconstruct_beliefs(db_path, now=moment, stale_after=stale_after)
    belief = state.belief_for(proposition_id)
    supporting = tuple(belief.supporting_evidence) if belief else ()
    contradicting = tuple(belief.contradicting_evidence) if belief else ()

    owned = conn is None
    conn = _connect(db_path, read_only=True) if owned else conn
    try:
        edges = _load_edges(conn)
        hypotheses = _load_hypotheses(conn)
    finally:
        if owned:
            conn.close()

    all_ids = tuple(sorted(set(supporting) | set(contradicting)))
    polarities = {}
    for evidence_id in supporting:
        polarities[evidence_id] = "SUPPORTS"
    for evidence_id in contradicting:
        polarities[evidence_id] = "CONTRADICTS"

    # Families are computed per POLARITY so a dependent contradiction can never be silently counted as
    # part of a support family (law 6 keeps polarity where Gate Zero put it).
    support_families, support_flags = _families(supporting, edges, polarities)
    contradict_families, contradict_flags = _families(contradicting, edges, polarities)

    support_bounds = _bounds(support_families)
    contradict_bounds = _bounds(contradict_families)
    lower, upper = _interval(support_bounds, contradict_bounds)

    any_ungrounded = any(not f.grounded for f in support_families + contradict_families)
    grounded_total = (sum(1 for f in support_families if f.grounded)
                      + sum(1 for f in contradict_families if f.grounded))
    if any_ungrounded or not all_ids:
        status = DEPENDENCE_UNKNOWN
    elif grounded_total >= 2:
        status = DEPENDENCE_PROVEN_INDEPENDENT
    else:
        status = DEPENDENCE_PROVEN_DEPENDENT

    # The digest covers PROVENANCE only. A similarity hypothesis or a model's suspicion is surfaced
    # as a count, but it is not provenance, so it must not be able to move this digest - which is what
    # makes law 8 checkable at the level of the picture rather than only at the level of the edges.
    payload = {
        "proposition_id": proposition_id,
        "metric_id": METRIC_ID,
        "support": [f.as_dict() for f in support_families],
        "contradict": [f.as_dict() for f in contradict_families],
        "support_bounds": list(support_bounds),
        "contradict_bounds": list(contradict_bounds),
        "interval": [lower, upper],
        "status": status,
        "integrity": sorted(set(support_flags + contradict_flags)),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    return SourceDependenceProjection(
        proposition_id=proposition_id,
        metric_id=METRIC_ID,
        support_families=tuple(support_families),
        contradiction_families=tuple(contradict_families),
        independent_support_min=support_bounds[0],
        independent_support_max=support_bounds[1],
        independent_contradict_min=contradict_bounds[0],
        independent_contradict_max=contradict_bounds[1],
        confidence_lower=lower,
        confidence_upper=upper,
        dependence_status=status,
        provenance_digest=digest,
        integrity_flags=tuple(sorted(set(support_flags + contradict_flags))),
        hypothesis_count=len(hypotheses),
        evidence_count=len(all_ids),
    )


def project_all(db_path: str, *, now: Optional[float] = None,
                stale_after: Optional[float] = None) -> Tuple[SourceDependenceProjection, ...]:
    """Every proposition's independence-adjusted picture, in proposition-id order."""
    state = reconstruct_beliefs(db_path, now=now, stale_after=stale_after)
    return tuple(project_source_dependence(db_path, proposition.proposition_id, now=now,
                                           stale_after=stale_after)
                 for proposition in state.propositions)


def record_projection(db_path: str, projection: SourceDependenceProjection, *,
                      now: Optional[float] = None) -> int:
    """
    Persist the current source-dependence projection as a new version when it changed.

    Append-only (law 10), and never an input to a later projection: provenance history is the input,
    and this table is the record of what it said at the time.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        latest = conn.execute(
            "SELECT * FROM ciph_source_dependence_projections WHERE proposition_id = ? AND metric_id = ? "
            "ORDER BY projection_version DESC LIMIT 1;",
            (projection.proposition_id, projection.metric_id)).fetchone()
        if latest is not None and latest["provenance_digest"] == projection.provenance_digest:
            return 0
        version = (int(latest["projection_version"]) + 1) if latest else 1
        conn.execute(
            "INSERT INTO ciph_source_dependence_projections (proposition_id, metric_id, "
            "projection_version, dependence_status, independent_support_min, independent_support_max, "
            "independent_contradict_min, independent_contradict_max, confidence_lower, confidence_upper, "
            "provenance_digest, projected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
            (projection.proposition_id, projection.metric_id, version, projection.dependence_status,
             projection.independent_support_min, projection.independent_support_max,
             projection.independent_contradict_min, projection.independent_contradict_max,
             projection.confidence_lower, projection.confidence_upper, projection.provenance_digest,
             moment),
        )
        conn.commit()
        return version
    finally:
        conn.close()


def projection_history(db_path: str, proposition_id: str) -> List[Dict[str, Any]]:
    conn = _connect(db_path, read_only=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM ciph_source_dependence_projections WHERE proposition_id = ? "
            "ORDER BY projection_version;", (proposition_id,))]
    except sqlite3.Error:
        return []
    finally:
        conn.close()
