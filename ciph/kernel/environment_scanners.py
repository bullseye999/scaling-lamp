"""
ciph/kernel/environment_scanners - 9.x: the eighteen CiphOS structural zeros.

    1  boot script granting execution authority        = 0
    2  service manager bypassing GuardedExecutor       = 0
    3  service obtained unrestricted root              = 0
    4  worker reading sovereign root keys              = 0
    5  worker writing production constitutional code   = 0
    6  model runtime claiming permits directly         = 0
    7  installer implicitly activating production      = 0
    8  systemd restart bypassing operator HOLD         = 0
    9  operator path accepting an unauthenticated label = 0
    10 update bypassing promotion/change governance    = 0
    11 legacy privileged helper reachable unauthorised = 0
    12 network transport granting federation authority = 0
    13 disconnected stale host receiving fresh authority without verification = 0
    14 clone automatically recovering production standing = 0
    15 destructive state rearmed at boot               = 0
    16 snapshot becoming canonical authority directly  = 0
    17 readiness falsely reported as activation        = 0
    18 second execution or deployment authority        = 0

Pure functions over `{relative_path: source_text}`. Static and syntactic, with the standing limit stated
rather than implied: they narrow the bypass surface and cannot decide semantic equivalence. Several are
PRESENCE checks - the law has to be in the code - and a presence check cannot see a semantically wrong
implementation, only a missing one.

SCOPE: the 9.x module set, plus project-wide call-site patterns where a mechanism elsewhere could
re-create the hazard. Catalogue modules are excluded by SUFFIX RULE.
"""

import pathlib
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ciph.kernel.crucible_types import CrucibleError

ENVIRONMENT_SCANNER_VIOLATION = "ENVIRONMENT_SCANNER_VIOLATION"

NAMESPACE = "ciph/kernel/environment_"
NINE_X_MODULES = ("ciph/kernel/environment_boot.py", "ciph/kernel/environment_operator.py",
                  "ciph/kernel/environment_runtime.py")
_CATALOGUE_SUFFIXES = ("_scanners.py", "_ownership.py")
_VENDORED_PARTS = ("ciph_env", "site-packages", ".venv", "node_modules")
BOOT_OWNER = "ciph/kernel/environment_boot.py"
RUNTIME_OWNER = "ciph/kernel/environment_runtime.py"
OPERATOR_OWNER = "ciph/kernel/environment_operator.py"


def _is_catalogue(relative: str) -> bool:
    return str(relative).rsplit("/", 1)[-1].endswith(_CATALOGUE_SUFFIXES)


def _nine_x(sources: Mapping[str, str]) -> Dict[str, str]:
    return {relative: text for relative, text in sources.items()
            if (relative.startswith(NAMESPACE) or relative in NINE_X_MODULES)
            and not _is_catalogue(relative) and not any(part in relative
                                                        for part in _VENDORED_PARTS)}


def _project(sources: Mapping[str, str]) -> Dict[str, str]:
    return {relative: text for relative, text in sources.items()
            if not _is_catalogue(relative) and not any(part in relative for part in _VENDORED_PARTS)}


def _patterns(scope: Mapping[str, str], needles: Tuple[str, ...], *,
              skip_defining: Optional[str] = None) -> Tuple[str, ...]:
    offences = []
    for relative, text in scope.items():
        if skip_defining and skip_defining in text:
            continue
        for needle in needles:
            if needle in text:
                offences.append(f"{relative}:{needle}")
    return tuple(sorted(set(offences)))


def s01_boot_grants_authority(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("grant_authority_at_boot(", "activate_on_boot(",
                                      "start_with_production_authority(", "boot_grants_standing("))


def s02_service_bypasses_guarded_executor(real) -> Tuple[str, ...]:
    offences = list(_patterns(_nine_x(real), ("def execute_raw", "class EnvironmentExecutor",
                                              "bypass_permit", "execute_without_permit(")))
    if "GuardedExecutor" not in real.get("ciph/kernel/execution_gateway.py", "") and \
            "GuardedExecutor" not in real.get("ciph/kernel/autonomy_session.py", "") and \
            "GuardedExecutor" not in real.get("ciph/kernel/crucible_types.py", ""):
        # The 9.x surface must not reach an executor of its own; the canonical one lives in 4.0.
        offences.append("9.x:no-guarded-executor-reference-anywhere")
    return tuple(sorted(set(offences)))


def s03_unrestricted_root(real) -> Tuple[str, ...]:
    return _patterns(_nine_x(real), ("CapabilityBoundingSet=ALL", "User=root", "RequireRoot=yes"))


def s04_worker_reads_root_keys(real) -> Tuple[str, ...]:
    offences = []
    for relative, text in _nine_x(real).items():
        if "ciph-worker" in text and ("root.key" in text or "kernel_priv_bytes" in text):
            if "InaccessiblePaths" not in text:
                offences.append(f"{relative}:worker-and-root-material-without-inaccessibility")
    return tuple(sorted(offences))


def s05_worker_writes_constitutional_code(real) -> Tuple[str, ...]:
    return _patterns(_nine_x(real), ("worker_writes_kernel(", "worker_edits_constitution("))


def s06_model_runtime_claims_permits(real) -> Tuple[str, ...]:
    offences = []
    for relative, text in _nine_x(real).items():
        if "model_runtime" in text and (".claim(" in text or "issue_permit(" in text):
            offences.append(f"{relative}:model-runtime-claims")
    return tuple(sorted(offences))


def s07_installer_activates_production(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("install_and_activate(", "setup_activates(",
                                      "postinst_activate("))


def s08_restart_bypasses_operator_hold(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("Restart=always\nEnvironment=ciph_skip_hold=1",
                                      "restart_ignores_hold", "restart_clears_hold"))


def s09_unauthenticated_operator_label(real) -> Tuple[str, ...]:
    offences = list(_patterns(_nine_x(real), ("authorization == \"operator\"",
                                              "if token == \"OPERATOR\"", "trust_env_operator")))
    operator = real.get(OPERATOR_OWNER, "")
    if "AMBIENT_ENVIRONMENT_IS_NOT_A_CREDENTIAL" not in operator:
        offences.append(f"{OPERATOR_OWNER}:missing-ambient-refusal")
    return tuple(sorted(set(offences)))


def s10_update_bypasses_governance(real) -> Tuple[str, ...]:
    offences = list(_patterns(_nine_x(real), ("install_without_authorization(", "skip_update_verify(")))
    runtime = real.get(RUNTIME_OWNER, "")
    if "UNSAFE_UPGRADE_NEEDLES" not in runtime:
        offences.append(f"{RUNTIME_OWNER}:missing-upgrade-needle-declaration")
    return tuple(sorted(set(offences)))


def s11_legacy_helper_reachable_unauthorised(real) -> Tuple[str, ...]:
    """The R13 finding: the two `sudo`-referencing helpers must not be wired into a 9.x service."""
    offences = []
    for relative, text in _nine_x(real).items():
        for helper in ("darknet_monitor", "tor_proxy"):
            if helper in text and "subprocess" in text:
                offences.append(f"{relative}:invokes-{helper}")
    return tuple(sorted(offences))


def s12_transport_grants_federation_authority(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("transport_grants_membership(", "session_becomes_owner(",
                                      "connected_means_authorized("))


def s13_stale_host_fresh_authority(real) -> Tuple[str, ...]:
    offences = list(_patterns(_nine_x(real), ("accept_stale_host_authority(",)))
    operator = real.get(OPERATOR_OWNER, "")
    if "RESIDUAL_PHYSICAL_CONTROL" not in operator:
        offences.append(f"{OPERATOR_OWNER}:missing-residual-control-statement")
    return tuple(sorted(set(offences)))


def s14_clone_recovers_standing(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("clone_gets_production(", "clone_regains_authority(",
                                      "clone_activation"))


def s15_destructive_state_rearmed_at_boot(real) -> Tuple[str, ...]:
    return _patterns(_project(real), ("arm_destruction_at_boot(", "boot_arms_deadman(",
                                      "rearm_deadman_on_start("))


def s16_snapshot_becomes_authority(real) -> Tuple[str, ...]:
    offences = list(_patterns(_nine_x(real), ("snapshot_is_canonical(", "restore_snapshot_as_authority(")))
    runtime = real.get(RUNTIME_OWNER, "")
    if "A_SNAPSHOT_IS_NOT_AN_AUTHORIZED_RECOVERY" not in runtime:
        offences.append(f"{RUNTIME_OWNER}:missing-snapshot-refusal")
    return tuple(sorted(set(offences)))


def s17_readiness_reported_as_activation(real) -> Tuple[str, ...]:
    offences = []
    for relative, text in _nine_x(real).items():
        if "service_ready(" in text and "authority_granted" not in text:
            offences.append(f"{relative}:readiness-without-authority-statement")
    boot = real.get(BOOT_OWNER, "")
    if "authority_granted_by_boot" not in boot:
        offences.append(f"{BOOT_OWNER}:missing-authority-granted-statement")
    return tuple(sorted(offences))


def s18_second_authority_constitution(real) -> Tuple[str, ...]:
    return _patterns(_nine_x(real), ("class EnvironmentAuthority", "class CiphOSExecutor",
                                     "def mint_environment_permit(", "second_authority"))


ENVIRONMENT_SCANNERS = (
    ("s01_boot_grants_authority", s01_boot_grants_authority),
    ("s02_service_bypasses_guarded_executor", s02_service_bypasses_guarded_executor),
    ("s03_unrestricted_root", s03_unrestricted_root),
    ("s04_worker_reads_root_keys", s04_worker_reads_root_keys),
    ("s05_worker_writes_constitutional_code", s05_worker_writes_constitutional_code),
    ("s06_model_runtime_claims_permits", s06_model_runtime_claims_permits),
    ("s07_installer_activates_production", s07_installer_activates_production),
    ("s08_restart_bypasses_operator_hold", s08_restart_bypasses_operator_hold),
    ("s09_unauthenticated_operator_label", s09_unauthenticated_operator_label),
    ("s10_update_bypasses_governance", s10_update_bypasses_governance),
    ("s11_legacy_helper_reachable_unauthorised", s11_legacy_helper_reachable_unauthorised),
    ("s12_transport_grants_federation_authority", s12_transport_grants_federation_authority),
    ("s13_stale_host_fresh_authority", s13_stale_host_fresh_authority),
    ("s14_clone_recovers_standing", s14_clone_recovers_standing),
    ("s15_destructive_state_rearmed_at_boot", s15_destructive_state_rearmed_at_boot),
    ("s16_snapshot_becomes_authority", s16_snapshot_becomes_authority),
    ("s17_readiness_reported_as_activation", s17_readiness_reported_as_activation),
    ("s18_second_authority_constitution", s18_second_authority_constitution),
)


def scan(sources: Mapping[str, str]) -> Dict[str, Tuple[str, ...]]:
    return {name: scanner(sources) for name, scanner in ENVIRONMENT_SCANNERS}


def scan_project(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    from ciph.kernel.evolution_ownership import production_sources
    return scan(dict(production_sources(root)))


def environment_scanner_census(root: Optional[Any] = None) -> Dict[str, int]:
    return {name: len(offences) for name, offences in scan_project(root).items()}


def assert_all_clean(root: Optional[Any] = None) -> Dict[str, Tuple[str, ...]]:
    report = scan_project(root)
    dirty = {name: offences for name, offences in report.items() if offences}
    if dirty:
        raise CrucibleError(ENVIRONMENT_SCANNER_VIOLATION,
                            "; ".join(f"{name}:{offences}" for name, offences in dirty.items()))
    return report
