"""
ciph/kernel/evolution_ownership - R6 Gate A: exactly ONE constitutional owner per concern.

The project already contains a complete improvement lifecycle from the earlier Program-1 numbering
(`ciph/evolution/`, Phase 8/9), and R6's decision is to KEEP that machinery and take ownership of the
constitutional truth away from it:

    there may be many MECHANISMS for testing and deploying candidates,
    but exactly one constitutional OWNER for candidate identity, comparative standing,
    promotion, active state, and rollback lineage.

This module is the census, made executable. Every concern is declared with its canonical owner, and
every concern that forbids legacy ownership is scanned for violations - so "one owner" is a property
the suite checks rather than a sentence in a document.

It also asserts the machinery is still there. R6 demotes the old lifecycle; it does not delete the
muscles.
"""

import ast
import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

_ONLY = "CANONICAL_ONLY"
_SHARED = "LEGACY_ALLOWED"

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Concern:
    concern: str
    canonical_owner: str
    legacy_ownership_allowed: bool
    signals: Tuple[str, ...]
    also_allowed: Tuple[str, ...] = ()

    def allowed(self) -> Tuple[str, ...]:
        return (self.canonical_owner,) + tuple(self.also_allowed)


# THE FROZEN CENSUS. `TABLE:` signals are table names a module writes; `CONST:` signals are
# module-level definitions. A file that is not in `allowed()` and contains a signal owns a concern it
# must not own.
CENSUS: Tuple[Concern, ...] = (
    Concern("candidate identity", "ciph/kernel/crucible_candidates.py", False,
            ("TABLE:ciph_crucible_candidates", "TABLE:ciph_crucible_candidate_declarations")),
    Concern("evaluation protocol", "ciph/kernel/crucible_protocols.py", False,
            ("TABLE:ciph_crucible_protocols",),
            also_allowed=("ciph/kernel/crucible_types.py",)),
    Concern("trial identity", "ciph/kernel/crucible_trials.py", False,
            ("TABLE:ciph_crucible_trials",)),
    # Signals are deliberately UNIQUE names. `STATUS_INVALID` and `STATUS_INTEGRITY_BLOCKED` are
    # generic words that unrelated 4.2/4.5 modules legitimately define for their own domains, so
    # scanning for them would report honest code as a violation. A scanner that cries wolf is worse
    # than one whose narrower coverage is stated.
    Concern("comparison verdict", "ciph/kernel/crucible_metrics.py", False,
            ("CONST:CRUCIBLE_PARETO_V1", "CONST:CRUCIBLE_METRICS_V1"),
            also_allowed=("ciph/kernel/crucible_types.py",)),
    Concern("promotion state", "ciph/kernel/crucible_promotion.py", False,
            ("TABLE:ciph_crucible_promotions",),
            also_allowed=("ciph/kernel/crucible_types.py",)),
    Concern("active candidate pointer", "ciph/kernel/crucible_promotion.py", False,
            ("TABLE:ciph_crucible_active",),
            also_allowed=("ciph/kernel/evolution_deployment.py",
                          "ciph/kernel/evolution_ownership.py", "tools/", "ciph/kernel/crucible_types.py")),
    Concern("rollback lineage", "ciph/kernel/crucible_promotion.py", False,
            ("TABLE:ciph_crucible_rollbacks",),
            also_allowed=("ciph/kernel/crucible_types.py",)),
    Concern("regression verdict", "ciph/kernel/crucible_monitoring.py", False,
            ("TABLE:ciph_crucible_post_promotion", "CONST:CRUCIBLE_POST_PROMOTION_V1"),
            also_allowed=("ciph/kernel/crucible_types.py",)),
    Concern("deployment record", "ciph/kernel/evolution_deployment.py", False,
            ("TABLE:ciph_crucible_deployments",),
            also_allowed=("ciph/kernel/evolution_ownership.py",)),
    Concern("raw sandbox execution", "ciph/evolution/isolated_execution.py", True,
            ("CONST:execute_candidate",)),
    Concern("benchmark mechanism", "ciph/evolution/benchmark_harness.py", True,
            ("CONST:IndependentBenchmarkHarness",)),
    Concern("dependency and resource review", "ciph/evolution/review.py", True,
            ("CONST:review_changes",)),
    Concern("physical installation mechanism", "ciph/evolution/file_activation.py", True,
            ("CONST:activate", "CONST:restore")),
    Concern("canary measurement mechanism", "ciph/evolution/canary_manager.py", True,
            ("TABLE:ciph_phase8_canary_state",)),
    Concern("workflow orchestration", "ciph/evolution/workflow.py", True,
            ("CONST:EvolutionCoordinator",)),
)

# The machinery R6 DEMOTES but must not lose. If any of this disappears, the unification has quietly
# become an amputation.
RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("ciph/evolution/gap_detector.py", ("EngineeringGapDetector",)),
    ("ciph/evolution/isolated_execution.py", ("execute_candidate",)),
    ("ciph/evolution/benchmark_harness.py", ("IndependentBenchmarkHarness",)),
    ("ciph/evolution/review.py", ("review_changes", "resource_regression")),
    ("ciph/evolution/file_activation.py", ("activate", "restore", "locked_target")),
    ("ciph/evolution/canary_manager.py", ("CanaryDeploymentManager",)),
    ("ciph/evolution/workflow.py", ("EvolutionCoordinator", "prepare_evaluation")),
    ("ciph/evolution/evidence.py", ("EvolutionEvidenceStore",)),
)

# The one function that physically rewrites active files. It may only ever be reached through the
# governed deployment boundary; R6 keeps the count at zero by scanning for it.
_SWAP_FUNCTIONS = ("file_activation.activate", "file_activation import activate")


def production_sources(root: Optional[Any] = None) -> List[Tuple[str, str]]:
    """Every production source file (tests excluded), as (relative path, text)."""
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    sources: List[Tuple[str, str]] = []
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            continue
        try:
            sources.append((path.relative_to(base).as_posix(), path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return sources


def _contains_definition(text: str, name: str) -> bool:
    """A module owns a name if it DEFINES it - as a constant, a class or a function."""
    constant = "^" + re.escape(name) + r"\s*(?::[^=]+)?" + "="
    as_class = "^class\\s+" + re.escape(name) + r"\b"
    as_function = "^def\\s+" + re.escape(name) + r"\b"
    for pattern in (constant, as_class, as_function):
        if re.search(pattern, text, re.MULTILINE) is not None:
            return True
    return False

def _contains_signal(text: str, signal: str) -> bool:
    """
    A TABLE signal means THIS FILE WRITES THAT TABLE - not that it happens to say its name.

    The check used to be `name in text` plus any SQL verb anywhere in the file, which is a co-occurrence
    test, and it produced a false positive in every phase that added a module which merely NAMED a
    canonical table: 4.7's scanner, 5.x's, the 6.x scanner, the 7.x scanner, and now the 8.x recovery
    manifest, whose job is to classify tables by name. Making the test precise makes it STRONGER, not
    weaker: a mention in prose or in a classification list stops counting, and a real write starts
    being the thing that counts.
    """
    kind, _, name = signal.partition(":")
    if kind == "TABLE":
        # CREATE TABLE counts.  A second declaration of a table another module owns is not a mention -
        # it is the R4 failure itself (two subsystems both declaring `ciph_observations` with
        # `CREATE TABLE IF NOT EXISTS`, so whichever initialised first silently won).
        if re.search(rf"\bCREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+{re.escape(name)}\b", text,
                     re.IGNORECASE):
            return True
        # Schema MUTATION counts too, and so do the alternative write syntaxes SQLite accepts:
        # ALTER/DROP on the table, REPLACE INTO, and INSERT OR REPLACE (covered by the INSERT branch).
        if re.search(rf"\b(?:ALTER|DROP)\s+TABLE(?:\s+IF\s+EXISTS)?\s+{re.escape(name)}\b", text,
                     re.IGNORECASE):
            return True
        if re.search(rf"\bREPLACE\s+INTO\s+{re.escape(name)}\b", text, re.IGNORECASE):
            return True
        if re.search(rf"\bINSERT(?:\s+OR\s+\w+)?\s+INTO\s+{re.escape(name)}\b", text):
            return True
        if re.search(rf"\bUPDATE\s+{re.escape(name)}\b", text):
            return True
        return re.search(rf"\bDELETE\s+FROM\s+{re.escape(name)}\b", text) is not None
    if name not in text:
        return False
    return _contains_definition(text, name)


# Modules that DECLARE table/constant signals in order to scan for them. They name these things and
# own none of them, so they are excluded from the signal scan by name - narrowly, and with reasons.
#
# This list has grown once per phase that added a scanner, and the pattern is worth naming: a phase's
# scanner MUST contain other phases' forbidden tokens as DATA, so every scanner is a false positive of
# every other phase's scanner. 4.7's s03 fired on 5.x's pattern list; 6.x's swarm scanners are read by
# this census as owners of the Crucible's promotion state, active pointer and rollback lineage. The
# repair is the same each time and it is a principle, not an exemption: a file that declares a pattern
# is not a file that writes it. The limit is stated - a real write hidden inside a module named here
# would not be seen by this census, and the architectural review is the fallback for that.
_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")


def is_catalogue_module(relative: str) -> bool:
    """
    A module named as a scanner or a census declares signals as DATA and owns none of them.

    This was a hand-maintained list until the collision recurred for the fourth time (4.7, 5.x, 6.x and
    7.x all added a scanner that another phase's census read as an owner). A rule that must be extended
    every phase is a rule that will eventually be forgotten, so it is a SUFFIX RULE now.
    """
    name = str(relative).rsplit("/", 1)[-1]
    return name.endswith(_CATALOGUE_SUFFIXES)


SIGNAL_DECLARING_MODULES: Tuple[str, ...] = ("ciph/kernel/evolution_ownership.py",
                                             "ciph/kernel/meta_scanners.py",
                                             "ciph/kernel/autonomy_scanners.py",
                                             "ciph/kernel/swarm_scanners.py",
                                             "ciph/kernel/swarm_ownership.py",
                                             "ciph/kernel/federation_scanners.py",
                                             "ciph/kernel/federation_ownership.py")


def _is_allowed(relative: str, concern: Concern) -> bool:
    for allowed in concern.allowed():
        if relative == allowed or allowed.endswith("/") and relative.startswith(allowed):
            return True
    return False


def ownership_violations(root: Optional[Any] = None) -> Tuple[Dict[str, str], ...]:
    """
    Every place a module owns a concern it must not own. An empty tuple is the R6 Gate A seal.

    A concern marked legacy-allowed is never a violation: those are the mechanisms R6 keeps.
    """
    violations: List[Dict[str, str]] = []
    sources = production_sources(root)
    for concern in CENSUS:
        if concern.legacy_ownership_allowed:
            continue
        for relative, text in sources:
            if relative in SIGNAL_DECLARING_MODULES or is_catalogue_module(relative):
                continue
            if _is_allowed(relative, concern):
                continue
            for signal in concern.signals:
                if _contains_signal(text, signal):
                    violations.append({"concern": concern.concern, "owner": concern.canonical_owner,
                                       "offender": relative, "signal": signal})
    return tuple(violations)


def activation_bypasses(root: Optional[Any] = None) -> Tuple[str, ...]:
    """
    Call sites of the physical file swap. R6 requires zero: installation goes through the governed
    deployment boundary or it does not go through at all.
    """
    offenders: List[str] = []
    for relative, text in production_sources(root):
        if relative == "ciph/evolution/file_activation.py":
            continue
        tree = ast.parse(text)
        imported = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("file_activation"):
                imported = any(entry.name == "activate" for entry in node.names)
            elif isinstance(node, ast.Name) and node.id == "activate" and imported:
                offenders.append(f"{relative}:{node.lineno}")
    return tuple(offenders)


def retained_machinery_missing(root: Optional[Any] = None) -> Tuple[str, ...]:
    """The demoted mechanisms that must still exist and still export their entry points."""
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    missing: List[str] = []
    for relative, symbols in RETAINED_MACHINERY:
        path = base / relative
        if not path.exists():
            missing.append(f"MISSING_FILE:{relative}")
            continue
        text = path.read_text(encoding="utf-8")
        for symbol in symbols:
            if not _contains_definition(text, symbol):
                missing.append(f"MISSING_SYMBOL:{relative}:{symbol}")
    return tuple(missing)


def ownership_matrix() -> Tuple[Dict[str, Any], ...]:
    """The census as data, for a seal document or an operator review."""
    return tuple({"concern": concern.concern, "canonical_owner": concern.canonical_owner,
                  "legacy_ownership_allowed": concern.legacy_ownership_allowed}
                 for concern in CENSUS)


def canonical_owners(concern: str) -> Tuple[str, ...]:
    """
    The canonical owner(s) of ONE concern, matched by EXACT name.

    A prefix match would be wrong: "candidate identity" and "active candidate pointer" are different
    concerns with legitimately different owners, and a prefix lookup would report two owners for one
    question.
    """
    return tuple(sorted({entry.canonical_owner for entry in CENSUS if entry.concern == concern}))


def canonical_owner_count(concern: str) -> int:
    """How many modules claim ONE concern. Always 1 for a constitutional concern."""
    return len(canonical_owners(concern))


def ownership_report(root: Optional[Any] = None) -> Dict[str, Any]:
    return {"matrix": ownership_matrix(),
            "violations": ownership_violations(root),
            "activation_bypasses": activation_bypasses(root),
            "retained_machinery_missing": retained_machinery_missing(root)}
