"""
ciph/kernel/production_choke_point - R7: the activation primitives must ask the constitution.

The legacy lifecycle keeps its machinery and loses its authority. That is only true while the two
functions that can actually change production think to ask, so this module makes "think to ask" a
scanned property rather than a comment:

    approve_production   the file swap / capability activation
    _install             the revision-capability registration

Each must contain an unconditional call to `check_constitutional_promotion`. The scanner has a
catch-specimen, because a scanner that never fires proves nothing.
"""

import pathlib
import re
from typing import Any, Dict, Optional, Tuple

ACTIVATION_PRIMITIVES: Tuple[Tuple[str, str], ...] = (
    ("ciph/evolution/canary_manager.py", "def approve_production("),
    ("ciph/evolution/workflow.py", "def _install("),
)

REQUIRED_GUARD = "check_constitutional_promotion"

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _body(text: str, definition: str) -> Optional[str]:
    """The source of ONE method, up to the next definition at the same or a shallower indent."""
    start = text.find(definition)
    if start == -1:
        return None
    rest = text[start:]
    lines = rest.splitlines(keepends=True)
    body = [lines[0]]
    for line in lines[1:]:
        stripped = line.strip()
        if stripped and not line.startswith(" ") and not line.startswith("\t"):
            break
        if re.match(r"^ {0,4}(def |class )", line) and stripped.startswith(("def ", "class ")):
            break
        body.append(line)
    return "".join(body)


def unguarded_primitives(root: Optional[Any] = None) -> Tuple[str, ...]:
    """Activation primitives that do not ask the constitution. Empty is the R7 condition."""
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    offenders = []
    for relative, definition in ACTIVATION_PRIMITIVES:
        path = base / relative
        if not path.exists():
            offenders.append(f"MISSING:{relative}")
            continue
        body = _body(path.read_text(encoding="utf-8"), definition)
        if body is None:
            offenders.append(f"MISSING_PRIMITIVE:{relative}:{definition}")
            continue
        if REQUIRED_GUARD not in body:
            offenders.append(f"UNGUARDED:{relative}:{definition}")
    return tuple(offenders)


def activation_bypasses(root: Optional[Any] = None) -> Tuple[str, ...]:
    """Direct physical activation outside the governed path (the R6 scan, kept honest here)."""
    from ciph.kernel.evolution_ownership import activation_bypasses as _scan
    return _scan(root)


def choke_point_report(root: Optional[Any] = None) -> Dict[str, Any]:
    return {"unguarded_primitives": unguarded_primitives(root),
            "activation_bypasses": activation_bypasses(root),
            "primitives": [relative for relative, _ in ACTIVATION_PRIMITIVES],
            "required_guard": REQUIRED_GUARD}
