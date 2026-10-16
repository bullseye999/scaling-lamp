"""
ciph/kernel/sovereignty_scanners - 8.x: the sixteen structural zeros.

    1  legacy default-passphrase backup accepted           = 0
    2  root material as ordinary backup content            = 0
    3  backup directly activates production                = 0
    4  restore bypasses identity verification              = 0
    5  clone claims production authority                   = 0
    6  stale node retains ownership                        = 0
    7  node key treated as sovereign root                  = 0
    8  model/host/path treated as sovereign identity        = 0
    9  last-write-wins selects recovery authority          = 0
    10 migration rewrites frozen constitutional ids        = 0
    11 unreconciled permit resumes execution               = 0
    12 recovery bypasses R7                                = 0
    13 destructive dead-man state auto-restored            = 0
    14 activation without enforceable fencing               = 0
    15 incomplete restore reported READY                   = 0
    16 second authority / execution constitution            = 0

Pure functions over `{relative_path: source_text}`, so the real tree and a synthetic violation are
scanned identically. Static and syntactic, exactly like 4.5-7.x: they narrow the bypass surface and
cannot decide semantic equivalence. Several are PRESENCE checks - the law has to be in the code - and a
presence check cannot see a semantically wrong implementation, only a missing one.

SCOPE: the 8.x module set (the sovereignty namespace, the recovery modules, the backup constitution, the
real transport and the reconstitution module), plus a few project-wide call-site patterns where a
mechanism elsewhere could re-create the hazard. Catalogue modules are excluded by a SUFFIX RULE rather
than a list: the lesson from four earlier phases.
"""

import pathlib
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError

SOVEREIGNTY_SCANNER_VIOLATION = "SOVEREIGNTY_SCANNER_VIOLATION"

NAMESPACE = "ciph/kernel/sovereignty_"
EIGHT_X_MODULES = (
    "ciph/kernel/sovereign_identity.py",
    "ciph/kernel/recovery_manifest.py",
    "ciph/kernel/backup_constitution.py",
    "ciph/kernel/recovery_state.py",
    "ciph/kernel/recovery_engine.py",
    "ciph/kernel/real_transport.py",
    "ciph/kernel/federation_reconstitution.py",
)
_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")


def _is_catalogue(relative: str) -> bool:
    return str(relative).rsplit("/", 1)[-1].endswith(_CATALOGUE_SUFFIXES)


def _eight_x(sources: Mapping[str, str]) -> Dict[str, str]:
    """The functional 8.x modules. Catalogues declare patterns as data and own none of them."""
    return {relative: text for relative, text in sources.items()
            if (relative.startswith(NAMESPACE) or relative in EIGHT_X_MODULES)
            and not _is_catalogue(relative)}


def _project(sources: Mapping[str, str]) -> Dict[str, str]:
    return {relative: text for relative, text in sources.items() if not _is_catalogue(relative)}


def _patterns(scope: Mapping[str, str], needles: Tuple[str, ...]) -> Tuple[str, ...]:
    offences = []
    for relative, text in scope.items():
        for needle in needles:
            if needle in text:
                offences.append(f"{relative}:{needle}")
    return tuple(sorted(set(offences)))


def s01_legacy_default_passphrase_backup(real) -> Tuple[str, ...]:
    """The OLD env var name and the old literal default may not be read as a passphrase anywhere."""
    return _patterns(_project(real), ('os.environ.get("BACKUP_PASSPHRASE"',
                                      "os.environ.get('BACKUP_PASSPHRASE'",
                                      'BACKUP_PASSPHRASE", "ciph_backup_passphrase'))


def s02_root_material_as_ordinary_content(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ('tar.add("ciph.key"', "tar.add('ciph.key'",
                                  '"ciph.key", arcname=', "'ciph.key', arcname="))


def s03_backup_activates_production(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("activate_from_backup(", "restore_and_activate(",
                                      "restore_production(", "promote_backup("))


def s04_restore_bypasses_identity(real) -> Tuple[str, ...]:
    offences = list(_patterns(_eight_x(real), ("skip_identity_check", "restore_without_identity(")))
    engine = real.get("ciph/kernel/recovery_engine.py", "")
    if "assert_identity_continuity" not in engine:
        offences.append("ciph/kernel/recovery_engine.py:missing-identity-verification")
    return tuple(sorted(offences))


def s05_clone_claims_production_authority(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("clone_is_production", "assume_production_identity",
                                      "clone_activation"))


def s06_stale_node_retains_ownership(real) -> Tuple[str, ...]:
    # The canonical owner of domain ownership may move an owner - that IS the governed transfer. What
    # may not happen is a RECOVERY path doing it, so the owner is excluded and everything else is not.
    mover = "ciph/kernel/federation_authority.py"
    offences = [f"{relative}:moves-domain-owner"
                for relative, text in _project(real).items()
                if relative != mover
                and "UPDATE ciph_federation_authority_domains SET owner_node_id" in text]
    reconstitution = real.get("ciph/kernel/federation_reconstitution.py", "")
    if "assert_authoritative" not in reconstitution:
        offences.append("ciph/kernel/federation_reconstitution.py:missing-lineage-gate")
    return tuple(sorted(offences))


def s07_node_key_as_root(real) -> Tuple[str, ...]:
    return _patterns(_eight_x(real), ("use_node_key_as_root(", "node_key_is_root",
                                      "root_key = node_key"))


def s08_model_or_host_as_identity(real) -> Tuple[str, ...]:
    offences = list(_patterns(_eight_x(real), ("identity_from_hostname(", "identity_from_path(",
                                              "ciph_identity_id = socket.gethostname")))
    portability = real.get("ciph/kernel/sovereignty_portability.py", "")
    if "identity_depends_on_host" not in portability:
        offences.append("ciph/kernel/sovereignty_portability.py:missing-portability-statement")
    return tuple(sorted(offences))


def s09_last_write_wins_recovery(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("latest_backup_wins(", "newest_backup(", "by_created_at(",
                                      "pick_newest_backup("))


def s10_migration_rewrites_frozen_ids(real) -> Tuple[str, ...]:
    offences = list(_patterns(_eight_x(real), ("rewrite_frozen_identity(", "update_frozen_identity(",
                                              "frozen_version = CURRENT")))
    portability = real.get("ciph/kernel/sovereignty_portability.py", "")
    if "frozen_identities" not in portability:
        offences.append("ciph/kernel/sovereignty_portability.py:missing-frozen-identity-list")
    return tuple(sorted(offences))


def s11_unreconciled_permit_resumes(real) -> Tuple[str, ...]:
    return _patterns(_eight_x(real), ("resume_permit(", "reactivate_permit(", "unrevoke_permit("))


def s12_recovery_bypasses_r7(real) -> Tuple[str, ...]:
    return _patterns(_eight_x(real), ("file_activation", "replace_at(", "write_bytes(", "activate("))


def s13_deadman_state_restored(real) -> Tuple[str, ...]:
    return _patterns(_eight_x(real), ("restore_wipe_state", "erased_from_backup", "restore_deadman(",
                                      "reinstate_destruction"))


def s14_activation_without_fencing(real) -> Tuple[str, ...]:
    offences = list(_patterns(_eight_x(real), ("skip_fencing(", "assume_fenced", "fencing=True #")))
    engine = real.get("ciph/kernel/recovery_engine.py", "")
    if "fence_is_enforceable" not in engine:
        offences.append("ciph/kernel/recovery_engine.py:missing-enforceable-fence-check")
    return tuple(sorted(offences))


def s15_incomplete_restore_reported_ready(real) -> Tuple[str, ...]:
    offences = list(_patterns(_eight_x(real), ("force_ready(", "mark_ready_without_manifest(")))
    engine = real.get("ciph/kernel/recovery_engine.py", "")
    if "verify_manifest" not in engine:
        offences.append("ciph/kernel/recovery_engine.py:missing-manifest-verification")
    return tuple(sorted(offences))


def s16_second_authority_constitution(real) -> Tuple[str, ...]:
    """8.x may not grow its own execution constitution, permit authority or second domain engine."""
    offences = list(_patterns(_eight_x(real), ("class RecoveryAuthority", "class SovereigntyExecutor",
                                              "def define_authority_domain(", "class PermitAuthority",
                                              "def mint_permit", "second_authority")))
    return tuple(sorted(offences))


SOVEREIGNTY_SCANNERS = (
    ("s01_legacy_default_passphrase_backup", s01_legacy_default_passphrase_backup),
    ("s02_root_material_as_ordinary_content", s02_root_material_as_ordinary_content),
    ("s03_backup_activates_production", s03_backup_activates_production),
    ("s04_restore_bypasses_identity", s04_restore_bypasses_identity),
    ("s05_clone_claims_production_authority", s05_clone_claims_production_authority),
    ("s06_stale_node_retains_ownership", s06_stale_node_retains_ownership),
    ("s07_node_key_as_root", s07_node_key_as_root),
    ("s08_model_or_host_as_identity", s08_model_or_host_as_identity),
    ("s09_last_write_wins_recovery", s09_last_write_wins_recovery),
    ("s10_migration_rewrites_frozen_ids", s10_migration_rewrites_frozen_ids),
    ("s11_unreconciled_permit_resumes", s11_unreconciled_permit_resumes),
    ("s12_recovery_bypasses_r7", s12_recovery_bypasses_r7),
    ("s13_deadman_state_restored", s13_deadman_state_restored),
    ("s14_activation_without_fencing", s14_activation_without_fencing),
    ("s15_incomplete_restore_reported_ready", s15_incomplete_restore_reported_ready),
    ("s16_second_authority_constitution", s16_second_authority_constitution),
)


def scan(sources: Mapping[str, str]) -> Dict[str, Tuple[str, ...]]:
    return {name: scanner(sources) for name, scanner in SOVEREIGNTY_SCANNERS}


def scan_project(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    from ciph.kernel.evolution_ownership import production_sources
    return scan(dict(production_sources(root)))


def sovereignty_scanner_census(root: Optional[Any] = None) -> Dict[str, int]:
    return {name: len(offences) for name, offences in scan_project(root).items()}


def assert_all_clean(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    report = scan_project(root)
    dirty = {name: offences for name, offences in report.items() if offences}
    if dirty:
        raise CrucibleError(SOVEREIGNTY_SCANNER_VIOLATION,
                            "; ".join(f"{name}:{offences}" for name, offences in dirty.items()))
    return report
