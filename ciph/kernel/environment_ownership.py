"""
ciph/kernel/environment_ownership - R13: one owner per operating-environment concern, and the
isolated-host effect boundary stated as data rather than as a sentence somebody can forget.

    The operating environment hosts Ciph. It does not become Ciph's authority.

WHAT THE SURVEY FOUND - and the most important part is a NEGATIVE.

There is no boot path. No systemd unit, no service file, no installer that grants privileges, no root
escalation, no key handling in a boot script. `setup_ciph.sh` installs Python dependencies and runs a
dependency test; `run_ciph.py`, `run_worker.py`, `ciph_evolution.py` and `ciph_core.py` are development
entry points a human starts from a shell.

That matters because the dangerous question - "can a boot script become a second execution constitution
by starting Ciph with authority?" - currently answers "there is nothing to hijack YET". The risk is
LATENT, not realised, and 9.x's job is to build the boot and service path UNDER the constitution from its
first line rather than refitting one afterwards. This census exists so 9.0 cannot quietly create a path
that grants authority, while the risk is still cheap to avoid.

THE MANDATORY R13 ENTRY FINDING: THE ISOLATED STALE HOST.

8.x proved node-LOCAL fencing: inside a node whose store recorded a supersession, no caller can talk the
execution boundary back into a superseded epoch. It did not prove - and no protocol can prove - that a
host which is physically unreachable and still holds its own credentials and datastore stops producing
its OWN local effects. Revocation cannot reach what it cannot reach.

So the environment owes a DISTINCTION rather than a promise:

    EXTERNALLY GOVERNED EFFECTS   the resource that accepts the effect can check current authorization
                                  or refuse a revoked credential. Governable.
    PURELY LOCAL EFFECTS          an unreachable machine keeps physical control of its own resources.
                                  CONSTRAINABLE (leases, expiring credentials, resource-level fencing,
                                  boot controls) but not revocable by protocol.

`isolated_host_effect_boundary` returns that classification as data, because a limitation that lives only
in a document is one somebody will eventually contradict by accident.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

ENVIRONMENT_OWNERSHIP_V1 = "ENVIRONMENT_OWNERSHIP_V1"
ISOLATED_HOST_BOUNDARY_V1 = "ISOLATED_HOST_EFFECT_BOUNDARY_V1"
ENVIRONMENT_OWNERSHIP_VIOLATION = "ENVIRONMENT_OWNERSHIP_VIOLATION"

NAMESPACE = "ciph/kernel/environment_"
_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

BOOT_ENTRY_POINTS = ("run_ciph.py", "run_worker.py", "ciph_evolution.py", "ciph_core.py")
INSTALLERS = ("setup_ciph.sh",)


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
    Concern("boot constitution", "ciph/kernel/environment_boot.py", False,
            ("CONST:BOOT_CONSTITUTION_V1", "TABLE:ciph_environment_boots")),
    # The implemented owner. The census names the module that OWNS the concern, and when 9.0/9.1 were
    # built in one module the census is what had to change - not the code, and not by widening an
    # exclusion.
    Concern("service identity", "ciph/kernel/environment_boot.py", False,
            ("CONST:SERVICE_IDENTITY_V1", "TABLE:ciph_environment_services")),
    Concern("boot attestation", "ciph/kernel/environment_attestation.py", False,
            ("CONST:ENVIRONMENT_ATTESTATION_V1",)),
    Concern("operator control plane", "ciph/kernel/environment_operator.py", False,
            ("CONST:OPERATOR_CONTROL_PLANE_V1", "TABLE:ciph_operator_authorizations")),
    Concern("egress policy", "ciph/kernel/environment_operator.py", False,
            ("CONST:EGRESS_POLICY_V1", "TABLE:ciph_egress_rules")),
    Concern("storage and snapshot integration", "ciph/kernel/environment_runtime.py", False,
            ("CONST:ENVIRONMENT_STORAGE_V1", "TABLE:ciph_environment_snapshots")),
    Concern("model runtime independence", "ciph/kernel/environment_runtime.py", False,
            ("CONST:MODEL_RUNTIME_V1", "TABLE:ciph_model_runtimes")),
    Concern("update and rollback", "ciph/kernel/environment_runtime.py", False,
            ("CONST:ENVIRONMENT_UPDATE_V1", "TABLE:ciph_environment_updates")),
    Concern("reproducible installation", "ciph/kernel/environment_runtime.py", False,
            ("CONST:CIPHOS_IMAGE_V1", "CONST:PRIVILEGED_HOST_PROFILE_V1")),
    # MECHANISMS. Kept, and allowed to own what they already own.
    Concern("dependency bootstrap", "setup_ciph.sh", True,
            ("CONST:pip install",), also_allowed=("test_", "tools/")),
    Concern("development entry points", "run_ciph.py", True,
            ("CONST:main",), also_allowed=("run_worker.py", "ciph_core.py", "ciph_evolution.py")),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("setup_ciph.sh", ("pip install",)),
    ("run_ciph.py", ()),
    ("run_worker.py", ()),
)

_BOOT_AUTHORITY_PATTERNS = (
    "grant_authority_at_boot(", "activate_on_boot(", "start_with_production_authority(",
    "boot_grants_standing(", "auto_activate(", "adopt_active_candidate_from_disk(",
)
_SERVICE_BYPASS_PATTERNS = (
    "ExecStartPost=/bin/sh", "bypass_permit", "run_as_operator_without_grant",
    "second_execution_constitution", "service_mints_permit(",
)
_PRIVILEGE_PATTERNS = ("os.setuid(", "sudo ", "chown root", "chmod 4755", "chmod u+s",
                       "/etc/systemd/system", "systemctl enable")


def _is_catalogue(relative: str) -> bool:
    return str(relative).rsplit("/", 1)[-1].endswith(_CATALOGUE_SUFFIXES)


# Vendored dependency trees are NOT Ciph's source. Scanning them made the privilege report cry wolf
# about `sudo` strings inside pip's own filesystem helpers - the same class of noise this project has
# repaired in every phase, so the exclusion is explicit and narrow.
_VENDOR_PARTS = ("ciph_env", "site-packages", ".venv", "node_modules")


def _is_vendored(path: pathlib.Path) -> bool:
    return any(part in _VENDOR_PARTS for part in path.parts)


def production_sources(root: Optional[Any] = None) -> List[Tuple[str, str]]:
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    sources: List[Tuple[str, str]] = []
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts or _is_vendored(path):
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            continue
        try:
            sources.append((path.relative_to(base).as_posix(), path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return sources


def shell_sources(root: Optional[Any] = None) -> List[Tuple[str, str]]:
    """Shell and unit files matter here: an installer or a unit IS an environment entry point."""
    base = pathlib.Path(root) if root is not None else _PROJECT_ROOT
    sources: List[Tuple[str, str]] = []
    for pattern in ("*.sh", "*.service", "*.timer", "*.target", "*.socket"):
        for path in sorted(base.rglob(pattern)):
            if "__pycache__" in path.parts or _is_vendored(path):
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
    for pattern in (r"^" + re.escape(name) + r"\s*(?::[^=]+)?=",
                    r"^class\s+" + re.escape(name) + r"\b",
                    r"^def\s+" + re.escape(name) + r"\b"):
        if re.search(pattern, text, re.MULTILINE) is not None:
            return True
    return False


def _contains_signal(text: str, signal: str) -> bool:
    kind, _, name = signal.partition(":")
    if kind == "CONST":
        if name.startswith("pip install"):
            return name in text
        return _defines(text, name)
    return _writes(text, name)


def _allowed(relative: str, concern: Concern) -> bool:
    for candidate in concern.allowed():
        if candidate.endswith("/") and relative.startswith(candidate):
            return True
        if candidate.startswith("test_") and relative.startswith("test_"):
            return True
        if relative == candidate:
            return True
    return False


def ownership_violations(root: Optional[Any] = None) -> Tuple[Dict[str, str], ...]:
    violations: List[Dict[str, str]] = []
    for relative, text in production_sources(root):
        if _is_catalogue(relative):
            continue
        for concern in CENSUS:
            if concern.mechanism_ownership_allowed or _allowed(relative, concern):
                continue
            for signal in concern.signals:
                if _contains_signal(text, signal):
                    violations.append({"concern": concern.concern, "owner": relative,
                                       "canonical": concern.canonical_owner, "signal": signal})
    return tuple(violations)


def retained_machinery_missing(root: Optional[Any] = None) -> Tuple[str, ...]:
    # Shell files count: an installer is environment machinery, and looking only at *.py would report a
    # perfectly present script as missing.
    sources = dict(production_sources(root) + shell_sources(root))
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


def _pattern_hits(patterns: Tuple[str, ...], *, include_shell: bool = True,
                  root: Optional[Any] = None) -> Tuple[str, ...]:
    scope = production_sources(root) + (shell_sources(root) if include_shell else [])
    found = []
    for relative, text in scope:
        if _is_catalogue(relative):
            continue
        for pattern in patterns:
            if pattern in text:
                found.append(f"{relative}:{pattern}")
    return tuple(sorted(set(found)))


def boot_grants_authority(root: Optional[Any] = None) -> Tuple[str, ...]:
    """No boot, install or launcher path may hand Ciph authority it was never granted."""
    return _pattern_hits(_BOOT_AUTHORITY_PATTERNS, root=root)


def service_bypass(root: Optional[Any] = None) -> Tuple[str, ...]:
    return _pattern_hits(_SERVICE_BYPASS_PATTERNS, root=root)


def ungoverned_privilege_surfaces(root: Optional[Any] = None) -> Tuple[str, ...]:
    """
    Privilege escalation in an install or boot path. REPORTED, not forbidden: 9.x will need some
    privilege (a service account, a unit file). The point is that it becomes a governed act with an owner
    rather than something a shell script happens to do.
    """
    return _pattern_hits(_PRIVILEGE_PATTERNS, root=root)


def boot_entry_points(root: Optional[Any] = None) -> Tuple[str, ...]:
    present = [relative for relative, _ in production_sources(root) if relative in BOOT_ENTRY_POINTS]
    return tuple(sorted(present + [relative for relative, _ in shell_sources(root)
                                   if relative in INSTALLERS]))


def isolated_host_effect_boundary() -> Dict[str, Any]:
    """
    THE R13 ENTRY FINDING, as data.

    A host nobody can reach cannot be revoked by protocol. What the environment owes is therefore a
    distinction, not a promise: externally governed effects are refusable by the resource that owns them,
    and purely local effects are bounded by what the machine physically holds. 9.x's job is to shrink the
    second category wherever the host can enforce it, and to say out loud that it cannot be emptied.
    """
    return {
        "policy_version": ISOLATED_HOST_BOUNDARY_V1,
        "externally_governed_effects": {
            "examples": ["an egress the operator controls",
                         "an effect accepted only with a current authority epoch",
                         "a federation write to a domain owned by another node"],
            "governable": True,
            "how": "the resource checks current authorization or refuses a revoked credential",
        },
        "purely_local_effects": {
            "examples": ["writing to its own disk", "consuming its own CPU",
                         "using a credential it physically holds"],
            "revocable_by_protocol": False,
            "constrainable_by": ["short-lived leases", "credentials with an expiry",
                                 "resource-level fencing (revoked key material)",
                                 "boot controls and disk-level custody"],
            "honest_statement": ("a physically unreachable machine that still holds everything it needs "
                                 "can continue local effects; no protocol revokes authority it cannot "
                                 "reach, and no seal should claim otherwise"),
        },
        "8x_proof_scope": {"node_local_fencing": "PROVEN",
                           "global_fencing_against_an_isolated_stale_host": "NOT CLAIMED"},
        "what_9x_owes": ["shrink the local-effect category wherever the host can enforce it",
                         "refuse external effects from stale authority at the resource",
                         "state this boundary in every deployment's documentation"],
    }


def environment_report(root: Optional[Any] = None) -> Dict[str, Any]:
    return {"policy_version": ENVIRONMENT_OWNERSHIP_V1, "concerns": len(CENSUS),
            "violations": list(ownership_violations(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root)),
            "boot_grants_authority": list(boot_grants_authority(root)),
            "service_bypass": list(service_bypass(root)),
            "ungoverned_privilege_surfaces": list(ungoverned_privilege_surfaces(root)),
            "boot_entry_points": list(boot_entry_points(root)),
            "isolated_host_boundary": isolated_host_effect_boundary()}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = environment_report(root)
    failures = {key: report[key] for key in ("violations", "retained_machinery_missing",
                                             "boot_grants_authority", "service_bypass")
                if report[key]}
    if failures:
        raise CrucibleError(ENVIRONMENT_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(environment_report(root))
