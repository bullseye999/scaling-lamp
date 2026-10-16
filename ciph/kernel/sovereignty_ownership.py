"""
ciph/kernel/sovereignty_ownership - R12: exactly ONE constitutional owner per recovery concern.

    machine != Ciph.  backup != authority.  restored bytes != restored identity.

The survey found three things that already touch recovery, and each is classified rather than trusted.

MECHANISM, KEPT.  `dead_mans_switch.py` overwrites files and exits: a DESTRUCTION mechanism.  It is real
and it works, and destruction is far too serious to be left as an unowned side effect of a timer - so the
POLICY is 8.x's (`ciph/kernel/sovereign_identity.py`) while the file-shredding stays where it is.
`security_layer.encrypted_backup` produces a GPG archive: an ARCHIVE mechanism, and nothing more.
`ciph_backups/` and the clone-assertion tools are deployment snapshots and test tooling.

TWO FINDINGS THAT MATTER.

  * `encrypted_backup` tars `ciph.key` - the ROOT key material - into an ordinary archive member, with
    `os.environ.get("BACKUP_PASSPHRASE", "ciph_backup_passphrase")` as the passphrase.  A default
    passphrase is nominal confidentiality, and root material travelling as an archive member is exactly
    the "copy the root everywhere" pattern 8.x exists to refuse.  The mechanism is kept; root custody is
    classified SPECIAL and the archive is demoted to "a copy of bytes", which cannot authorise anything.

  * The dead-man switch's `_emergency_destruct` can erase state on a timer.  Restoring a "wipe pending"
    flag from a backup would mean SURPRISE DESTRUCTION, so the zero is scanned: a recovery path may not
    resurrect destruction state.

ABSENT, SO 8.x OWNS IT.  Sovereign identity, recovery root custody, the recovery manifest, backup
legitimacy, the recovery state machine and its activation ceremony, the clone-versus-restore distinction,
node reconstitution, host/provider portability, model substitution, migration lineage, drills and
sovereignty monitoring.
"""

import pathlib
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError, digest

SOVEREIGNTY_OWNERSHIP_V1 = "SOVEREIGNTY_OWNERSHIP_V1"
SOVEREIGNTY_OWNERSHIP_VIOLATION = "SOVEREIGNTY_OWNERSHIP_VIOLATION"

NAMESPACE = "ciph/kernel/sovereignty_"

# A catalogue declares patterns as data and owns none of them - a suffix rule, learned the hard way in
# 4.7, 5.x, 6.x and 7.x rather than a list that must be extended every phase.
_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

_ONLY = "CANONICAL_ONLY"
_MECHANISM = "MECHANISM_ALLOWED"


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
    Concern("sovereign identity", "ciph/kernel/sovereign_identity.py", False,
            ("TABLE:ciph_sovereign_identity",)),
    Concern("recovery root custody", "ciph/kernel/sovereign_identity.py", False,
            ("TABLE:ciph_recovery_root_keys",)),
    Concern("destruction policy", "ciph/kernel/sovereign_identity.py", False,
            ("TABLE:ciph_destruction_policy",)),
    Concern("recovery manifest", "ciph/kernel/recovery_manifest.py", False,
            ("CONST:RECOVERY_MANIFEST_V1",)),
    Concern("backup legitimacy", "ciph/kernel/backup_constitution.py", False,
            ("TABLE:ciph_backup_sets",)),
    Concern("recovery state", "ciph/kernel/recovery_state.py", False,
            ("TABLE:ciph_recovery_runs",)),
    Concern("recovery activation", "ciph/kernel/recovery_state.py", False,
            ("TABLE:ciph_recovery_activations",)),
    Concern("clone registry", "ciph/kernel/recovery_state.py", False,
            ("TABLE:ciph_recovery_clones",)),
    Concern("recovery engine", "ciph/kernel/recovery_engine.py", False,
            ("CONST:RECOVERY_ENGINE_V1",)),
    Concern("host portability", "ciph/kernel/sovereignty_portability.py", False,
            ("CONST:HOST_PORTABILITY_V1",)),
    Concern("model substitution", "ciph/kernel/sovereignty_portability.py", False,
            ("CONST:MODEL_SUBSTITUTION_V1",)),
    Concern("migration lineage", "ciph/kernel/sovereignty_portability.py", False,
            ("CONST:RECOVERY_MIGRATION_PLAN_V1",)),
    Concern("node reconstitution", "ciph/kernel/federation_reconstitution.py", False,
            ("TABLE:ciph_federation_reconstitutions",)),
    Concern("real transport sessions", "ciph/kernel/real_transport.py", False,
            ("TABLE:ciph_transport_sessions",)),
    Concern("federation envelopes", "ciph/kernel/real_transport.py", False,
            ("TABLE:ciph_transport_envelopes",)),
    Concern("sovereignty monitoring", "ciph/kernel/sovereignty_monitoring.py", False,
            ("CONST:SOVEREIGNTY_HEALTH_V1",)),
    # MECHANISMS, kept and allowed to own what they already own.
    Concern("destruction mechanism", "dead_mans_switch.py", True,
            ("CONST:DeadMansSwitch",)),
    Concern("archive mechanism", "security_layer.py", True,
            ("CONST:encrypted_backup",)),
    Concern("deployment snapshots", "ciph_backups/", True,
            ("TABLE:ciph_dag_",),
            also_allowed=("tools/", "test_")),
)

RETAINED_MACHINERY: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("dead_mans_switch.py", ("DeadMansSwitch", "secure_delete", "_emergency_destruct")),
    ("security_layer.py", ("encrypted_backup",)),
    ("ciph/kernel/vault_identity.py", ("read_header", "write_header")),
)

# Call sites that would make a mechanism constitutional. Each is a pattern, not a list of files.
_ACTIVATION_PATTERNS = ("activate_from_backup", "restore_and_activate", "backup.activate",
                        "restore_production(", "promote_backup(")
_CLONE_AUTHORITY = ("clone_is_production", "assume_production_identity", "clone_activation")
_WALL_CLOCK_WINNER = ("latest_backup_wins(", "newest_backup(", "by_created_at(")
_ROOT_AS_MEMBER = ("ciph.key", "root_secret", "kernel_priv_bytes")
_HOST_IDENTITY = ("socket.gethostname()", "platform.node()", "os.uname()")


def _is_catalogue(relative: str) -> bool:
    return str(relative).rsplit("/", 1)[-1].endswith(_CATALOGUE_SUFFIXES)


def production_sources(root: Optional[Any] = None) -> List[Tuple[str, str]]:
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


def _defines(text: str, name: str) -> bool:
    for pattern in (r"^" + re.escape(name) + r"\s*(?::[^=]+)?=",
                    r"^class\s+" + re.escape(name) + r"\b",
                    r"^def\s+" + re.escape(name) + r"\b"):
        if re.search(pattern, text, re.MULTILINE) is not None:
            return True
    return False


def _writes(text: str, table: str) -> bool:
    if f"UPDATE {table}" in text or f"DELETE FROM {table}" in text:
        return True
    return re.search(rf"INSERT(?: OR \w+)? INTO {re.escape(table)}\b", text) is not None


def _contains_signal(text: str, signal: str) -> bool:
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
                         sources: Optional[List[Tuple[str, str]]] = None
                         ) -> Tuple[Dict[str, str], ...]:
    violations: List[Dict[str, str]] = []
    for relative, text in (sources if sources is not None else production_sources(root)):
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


def _offenders(root: Optional[Any], patterns: Tuple[str, ...],
               sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    found = set()
    for relative, text in (sources if sources is not None else production_sources(root)):
        if _is_catalogue(relative):
            continue
        for pattern in patterns:
            if pattern in text:
                found.add(f"{relative}:{pattern}")
    return tuple(sorted(found))


def backup_activation_paths(root: Optional[Any] = None,
                            sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """A backup may be restored; it may not be the thing that ACTIVATES production."""
    return _offenders(root, _ACTIVATION_PATTERNS, sources=sources)


def clone_authority_claims(root: Optional[Any] = None,
                           sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    return _offenders(root, _CLONE_AUTHORITY, sources=sources)


def wall_clock_recovery_selection(root: Optional[Any] = None,
                                  sources: Optional[List[Tuple[str, str]]] = None
                                  ) -> Tuple[str, ...]:
    return _offenders(root, _WALL_CLOCK_WINNER, sources=sources)


def root_copied_as_ordinary_artifact(root: Optional[Any] = None,
                                     sources: Optional[List[Tuple[str, str]]] = None
                                     ) -> Tuple[str, ...]:
    """
    Root material named as an ordinary archive member. The archive mechanism is allowed to exist; what is
    refused is a recovery path that treats the root as just another file to unpack.
    """
    offences = []
    for relative, text in (sources if sources is not None else production_sources(root)):
        if _is_catalogue(relative) or relative in ("security_layer.py", "dead_mans_switch.py"):
            continue
        if not relative.startswith(NAMESPACE):
            continue
        for pattern in _ROOT_AS_MEMBER:
            if pattern in text:
                offences.append(f"{relative}:{pattern}")
    return tuple(sorted(set(offences)))


def host_identity_dependencies(root: Optional[Any] = None,
                               sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """A sovereignty module may not read the hostname and call it identity."""
    offences = []
    for relative, text in (sources if sources is not None else production_sources(root)):
        if not relative.startswith(NAMESPACE) or _is_catalogue(relative):
            continue
        for pattern in _HOST_IDENTITY:
            if pattern in text:
                offences.append(f"{relative}:{pattern}")
    return tuple(sorted(set(offences)))


def sovereignty_bypasses(root: Optional[Any] = None,
                         sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """No 8.x module may build its own executor, permit authority or activation path around R7."""
    offences = []
    forbidden = ("class SovereigntyExecutor", "def execute_raw", "class PermitAuthority",
                 "def mint_permit", "permit_store", ".claim(", "file_activation", "replace_at(",
                 "write_bytes(", "create_standing_authorization(", "set_mode(")
    for relative, text in (sources if sources is not None else production_sources(root)):
        if not relative.startswith(NAMESPACE) or _is_catalogue(relative):
            continue
        for pattern in forbidden:
            if pattern in text:
                offences.append(f"{relative}:{pattern}")
    return tuple(sorted(set(offences)))


def destruction_state_restorable(root: Optional[Any] = None,
                                 sources: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, ...]:
    """
    THE SURPRISE-DESTRUCTION ZERO: a recovery path may not carry wipe state across a restore.

    A backup that can silently re-arm the dead-man switch would let a RESTORE decide to destroy the
    machine it just restored onto.
    """
    offences = []
    for relative, text in (sources if sources is not None else production_sources(root)):
        if not relative.startswith(NAMESPACE) or _is_catalogue(relative):
            continue
        for pattern in ("restore_wipe_state", "erased_from_backup", "restore_deadman(",
                        "reinstate_destruction"):
            if pattern in text:
                offences.append(f"{relative}:{pattern}")
    return tuple(sorted(set(offences)))


def ownership_report(root: Optional[Any] = None) -> Dict[str, Any]:
    return {"policy_version": SOVEREIGNTY_OWNERSHIP_V1, "concerns": len(CENSUS),
            "violations": list(ownership_violations(root)),
            "retained_machinery_missing": list(retained_machinery_missing(root)),
            "backup_activation_paths": list(backup_activation_paths(root)),
            "clone_authority_claims": list(clone_authority_claims(root)),
            "wall_clock_recovery_selection": list(wall_clock_recovery_selection(root)),
            "root_copied_as_ordinary_artifact": list(root_copied_as_ordinary_artifact(root)),
            "host_identity_dependencies": list(host_identity_dependencies(root)),
            "sovereignty_bypasses": list(sovereignty_bypasses(root)),
            "destruction_state_restorable": list(destruction_state_restorable(root))}


def assert_ownership_clean(root: Optional[Any] = None) -> Dict[str, Any]:
    report = ownership_report(root)
    failures = {key: value for key, value in report.items()
                if key not in ("policy_version", "concerns") and value}
    if failures:
        raise CrucibleError(SOVEREIGNTY_OWNERSHIP_VIOLATION, str(failures))
    return report


def ownership_digest(root: Optional[Any] = None) -> str:
    return digest(ownership_report(root))
