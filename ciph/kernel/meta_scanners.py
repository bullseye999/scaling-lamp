"""
ciph/kernel/meta_scanners - 4.7: the twelve structural invariants, as executable zeros.

Each scanner is a PURE FUNCTION over a `{relative_path: source_text}` mapping, so the real project and a
synthetic violating tree are scanned by exactly the same code. A scanner that cannot be made to fire on
a deliberate violation is not a scanner, and every one here has a catch-specimen.

COVERAGE LIMITS ARE STATED, NOT IMPLIED. These are static, syntactic checks over production modules
(tests excluded). They cannot prove semantic equivalence: a protected implementation copied under a new
name that imports nothing still reads as ordinary code. The scanners narrow the bypass surface; the
architectural review is the root fallback.
"""

import pathlib
import re
from typing import Any, Dict, Mapping, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError

META_SCANNER_VIOLATION = "META_SCANNER_VIOLATION"

META_NAMESPACE = "ciph/kernel/meta_"
FORTY_SIX = ("ciph/kernel/candidate_construction.py", "ciph/kernel/candidate_safety.py",
             "ciph/kernel/crucible_handoff.py", "ciph/kernel/improvement_learning.py",
             "ciph/kernel/improvement_opportunities.py", "ciph/kernel/improvement_hypotheses.py")

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _body(text: str, definition: str) -> str:
    start = text.find(definition)
    if start == -1:
        return ""
    lines = text[start:].splitlines(keepends=True)
    body = [lines[0]]
    for line in lines[1:]:
        if line.strip() and not line.startswith((" ", "\t")):
            break
        if re.match(r"^ {0,4}(def |class )", line) and line.strip().startswith(("def ", "class ")):
            break
        body.append(line)
    return "".join(body)


def _class_body(text: str, definition: str) -> str:
    """A CLASS body, nested methods included. `_body` stops at a nested `def`, which is right for a
    function and wrong for a class."""
    start = text.find(definition)
    if start == -1:
        return ""
    lines = text[start:].splitlines(keepends=True)
    body = [lines[0]]
    for line in lines[1:]:
        if line.strip() and not line.startswith((" ", "\t")):
            break
        body.append(line)
    return "".join(body)


def _protected_surfaces(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """
    Read PROTECTED_SURFACES out of the SOURCE TREE rather than importing it.

    A scanner that consults the live module cannot be exercised on a modified tree - and in a clone it
    would silently validate the clone's own import rather than the file it was asked to scan.
    """
    text = sources.get("ciph/kernel/candidate_safety.py", "")
    marker = "PROTECTED_SURFACES: Tuple[str, ...] = ("
    start = text.find(marker)
    if start == -1:
        return ()
    end = text.find("\n)", start)
    block = text[start + len(marker):end if end != -1 else len(text)]
    return tuple(re.findall(r'"([^"]+)"', block))


def _writers(sources: Mapping[str, str], table: str) -> Tuple[str, ...]:
    """Every production module that writes a table. Reads are not writes."""
    writers = []
    for relative, text in sources.items():
        if f"UPDATE {table}" in text or f"DELETE FROM {table}" in text:
            writers.append(relative)
        elif re.search(rf"INSERT(?: OR \w+)? INTO {re.escape(table)}\b", text):
            writers.append(relative)
    return tuple(sorted(set(writers)))


def _callers(sources: Mapping[str, str], symbol: str) -> Tuple[str, ...]:
    """
    Every production module that names a call to `symbol`.

    SCANNER MODULES ARE EXCLUDED, and the reason is structural rather than convenient: a scanner is a
    CATALOGUE of the patterns it looks for, so a phase's scanner necessarily contains another phase's
    forbidden call as DATA. Reading that as a call would make each phase's scanner a violation of every
    other phase's scanner - which is precisely what happened when 5.x added `transition_epoch(` to its
    autonomy pattern list and 4.7's s03 fired on the pattern rather than on a bypass. The project
    treats a scanner that cries wolf as worse than one whose narrower coverage is stated.

    The limit is stated: a real bypass hidden inside a module named `*_scanners.py` would be missed by
    this helper, and the architectural review is the fallback for that.
    """
    return tuple(sorted(relative for relative, text in sources.items()
                        if f"{symbol}(" in text and not relative.endswith("_scanners.py")))


# ---------------------------------------------------------------------------- the twelve
def s01_shadow_evaluator_writes_standing(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """No meta-namespace module may write a canonical Crucible table."""
    offences = []
    for relative, text in sources.items():
        if not relative.startswith(META_NAMESPACE):
            continue
        if re.search(r"(INSERT(?: OR \w+)? INTO|UPDATE|DELETE FROM) ciph_crucible_", text):
            offences.append(relative)
    return tuple(sorted(offences))


def s02_evaluator_judges_itself_authoritatively(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """Only the guard may write meta judgments, and it must consult the independence predicate."""
    # The guard IS the permitted writer; anything else writing judgments is the violation.
    offences = [relative for relative in _writers(sources, "ciph_meta_judgments")
                if relative != "ciph/kernel/meta_guard.py"]
    guard = sources.get("ciph/kernel/meta_guard.py", "")
    if "assert_independent_judgment" not in _body(guard, "def record_meta_judgment("):
        offences.append("ciph/kernel/meta_guard.py:missing-independence-check")
    return tuple(sorted(set(offences)))


def s03_shadow_generator_writes_active_generator(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """The active pointer and epoch transitions move only through their owners."""
    offences = [relative for relative in _writers(sources, "ciph_crucible_active")
                if relative != "ciph/kernel/crucible_promotion.py"]
    allowed = {"ciph/kernel/evolution_epochs.py", "ciph/kernel/meta_promotion.py"}
    offences += [relative for relative in _callers(sources, "transition_epoch") if relative not in allowed]
    return tuple(sorted(set(offences)))


def s04_meta_candidate_writes_epoch_directly(sources: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(relative for relative in _writers(sources, "ciph_evolution_epochs")
                 if relative != "ciph/kernel/evolution_epochs.py")


def s05_meta_candidate_writes_promotion_record(sources: Mapping[str, str]) -> Tuple[str, ...]:
    return tuple(relative for relative in _writers(sources, "ciph_meta_promotions")
                 if relative != "ciph/kernel/meta_promotion.py")


def s06_candidate_facing_process_reaches_sealed(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """The candidate handle must not so much as name the sealed database."""
    text = sources.get("ciph/kernel/meta_corpus.py", "")
    body = _class_body(text, "class CandidateFacingCorpus")
    offences = []
    if "_sealed" in body or "sealed_path" in body:
        offences.append("ciph/kernel/meta_corpus.py:candidate-view-references-sealed")
    isolation = sources.get("ciph/kernel/meta_corpus_isolation.py", "")
    if "execute_candidate" not in isolation:
        offences.append("ciph/kernel/meta_corpus_isolation.py:does-not-reuse-isolated-execution")
    return tuple(sorted(offences))


def s07_ring0_enters_automatic_path(sources: Mapping[str, str]) -> Tuple[str, ...]:
    guard = sources.get("ciph/kernel/meta_guard.py", "")
    promotion = sources.get("ciph/kernel/meta_promotion.py", "")
    offences = []
    if "assert_ordinary_loop_may_proceed" not in _body(guard, "def register_meta_candidate("):
        offences.append("ciph/kernel/meta_guard.py:registration-without-ring-check")
    if "RING_CONSTITUTIONAL_ROOT" not in _body(promotion, "def meta_promote("):
        offences.append("ciph/kernel/meta_promotion.py:promotion-without-ring-check")
    return tuple(sorted(offences))


def s08_ordinary_46_touches_ring0(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """4.6 must not reach the meta surface, and its protected set must cover Rings 0 and 1."""
    offences = [relative for relative in FORTY_SIX
                if relative in _writers(sources, "ciph_evolution_epochs")
                or relative in _writers(sources, "ciph_meta_promotions")]
    from ciph.kernel.meta_targets import RING_0_COMPONENTS, RING_1_COMPONENTS
    protected = _protected_surfaces(sources)
    missing = []
    for component in RING_0_COMPONENTS + RING_1_COMPONENTS:
        if component not in protected:
            missing.append(component)
    if missing:
        offences.append("candidate_safety.py:protected-set-does-not-cover:" + ",".join(sorted(missing)[:3]))
    return tuple(sorted(offences))


def s09_safety_policy_self_approves(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """A replacement safety policy is a meta/Ring-0 target, never an ordinary candidate."""
    from ciph.kernel.meta_targets import ring_of
    protected = _protected_surfaces(sources)
    offences = []
    for component in ("ciph/kernel/candidate_safety.py", "ciph/kernel/meta_guard.py",
                      "ciph/kernel/meta_targets.py"):
        if component not in protected:
            offences.append(f"{component}:not-protected")
        elif ring_of(component) not in ("CONSTITUTIONAL_ROOT", "EVALUATION_CONSTITUTION"):
            offences.append(f"{component}:wrong-ring")
    return tuple(sorted(offences))


def s10_new_evaluator_rewrites_history(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """Epoch judgments are append-only: no UPDATE, no DELETE, anywhere."""
    offences = []
    for relative, text in sources.items():
        if relative == "ciph/kernel/meta_scanners.py":
            # This module necessarily contains the very patterns it looks for. Excluded by name, and
            # the exclusion is this narrow on purpose: the scanner owns no table and writes nothing.
            continue
        if "UPDATE ciph_epoch_judgments" in text or "DELETE FROM ciph_epoch_judgments" in text:
            offences.append(relative)
    epochs = sources.get("ciph/kernel/evolution_epochs.py", "")
    if "assert_history_not_rewritten" not in epochs:
        offences.append("ciph/kernel/evolution_epochs.py:missing-history-guard")
    return tuple(sorted(offences))


def s11_recursive_depth(sources: Mapping[str, str]) -> Tuple[str, ...]:
    guard = sources.get("ciph/kernel/meta_guard.py", "")
    offences = []
    if "MAX_META_GENERATION_DEPTH_V1 = 1" not in guard:
        offences.append("ciph/kernel/meta_guard.py:depth-limit-not-one")
    if "assert_recursion_allowed" not in _body(guard, "def register_meta_candidate("):
        offences.append("ciph/kernel/meta_guard.py:registration-without-depth-check")
    return tuple(sorted(offences))


def s12_meta_deployment_bypasses_r7(sources: Mapping[str, str]) -> Tuple[str, ...]:
    """The meta path may only install THROUGH the R7 boundary, and only after a promotion."""
    promotion = sources.get("ciph/kernel/meta_promotion.py", "")
    promote_body = _body(promotion, "def meta_promote(")
    offences = []
    if "deploy(" not in promote_body:
        offences.append("ciph/kernel/meta_promotion.py:promotion-without-r7-deploy")
    elif "installer(" in promote_body and promote_body.index("deploy(") > promote_body.index("installer("):
        offences.append("ciph/kernel/meta_promotion.py:installer-called-before-r7-boundary")
    rollback_body = _body(promotion, "def meta_rollback(")
    if "rollback_epoch(" in rollback_body and "installer(" in rollback_body:
        if rollback_body.index("rollback_epoch(") > rollback_body.index("installer("):
            offences.append("ciph/kernel/meta_promotion.py:rollback-mechanism-outran-canonical")
    return tuple(sorted(offences))


SCANNERS = (
    ("s01_shadow_evaluator_writes_standing", s01_shadow_evaluator_writes_standing),
    ("s02_evaluator_judges_itself_authoritatively", s02_evaluator_judges_itself_authoritatively),
    ("s03_shadow_generator_writes_active_generator", s03_shadow_generator_writes_active_generator),
    ("s04_meta_candidate_writes_epoch_directly", s04_meta_candidate_writes_epoch_directly),
    ("s05_meta_candidate_writes_promotion_record", s05_meta_candidate_writes_promotion_record),
    ("s06_candidate_facing_process_reaches_sealed", s06_candidate_facing_process_reaches_sealed),
    ("s07_ring0_enters_automatic_path", s07_ring0_enters_automatic_path),
    ("s08_ordinary_46_touches_ring0", s08_ordinary_46_touches_ring0),
    ("s09_safety_policy_self_approves", s09_safety_policy_self_approves),
    ("s10_new_evaluator_rewrites_history", s10_new_evaluator_rewrites_history),
    ("s11_recursive_depth", s11_recursive_depth),
    ("s12_meta_deployment_bypasses_r7", s12_meta_deployment_bypasses_r7),
)


def scan(sources: Mapping[str, str]) -> Dict[str, Tuple[str, ...]]:
    return {name: scanner(sources) for name, scanner in SCANNERS}


def scan_project(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    from ciph.kernel.evolution_ownership import production_sources
    return scan(dict(production_sources(root)))


def assert_all_clean(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    report = scan_project(root)
    dirty = {name: offences for name, offences in report.items() if offences}
    if dirty:
        raise CrucibleError(META_SCANNER_VIOLATION, "; ".join(f"{name}:{offences}"
                                                             for name, offences in dirty.items()))
    return report


def scanner_census(root: Optional[Any] = None) -> Dict[str, int]:
    """The seal's twelve zeros, as counts."""
    return {name: len(offences) for name, offences in scan_project(root).items()}
