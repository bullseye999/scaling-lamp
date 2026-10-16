"""
ciphos_host_verification - Campaign C: the privileged-host proof package.

This is the executable answer to "9.x can only be sealed on a host that can enforce what 9.x claims". Every
case below has a PREREQUISITE CHECK that FAILS EXPLICITLY when the enforcement mechanism is unavailable,
so a run on an under-privileged host refuses rather than producing a green result it did not earn.

    Configuration is not proof.  A directive in a unit file is not enforcement.

Usage:
    python3 tools/ciphos_host_verification.py --list
    python3 tools/ciphos_host_verification.py --run          (all cases; unavailable ones report SKIPPED)
    python3 tools/ciphos_host_verification.py --run --case system_install
    python3 tools/ciphos_host_verification.py --run --json   (machine-readable evidence capture)

Exit codes: 0 = every REQUIRED-AND-AVAILABLE case passed, 1 = a case failed, 2 = required cases were
skipped because the host lacks the prerequisite.
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PASSED = "PASSED"
FAILED = "FAILED"
SKIPPED = "SKIPPED_UNAVAILABLE_PREREQUISITE"


def _run(command: List[str], *, timeout: float = 60.0) -> Dict[str, Any]:
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return {"command": command, "returncode": completed.returncode,
            "stdout": completed.stdout.strip()[:2000], "stderr": completed.stderr.strip()[:2000]}


def _privileged() -> Dict[str, Any]:
    return {"uid": os.getuid(), "is_root": os.getuid() == 0,
            "sudo_non_interactive": _run(["sudo", "-n", "true"])["returncode"] == 0,
            "etc_writable": os.access("/etc", os.W_OK)}


def _systemd_available() -> bool:
    return bool(shutil.which("systemctl")) and os.path.isdir("/run/systemd/system")


def _userns_available() -> bool:
    probe = _run(["unshare", "-r", "true"], timeout=20)
    return probe["returncode"] == 0


def _hypervisor_available() -> Optional[str]:
    """
    A hypervisor we can actually USE - not merely a binary on PATH.

    `docker` being installed says nothing about whether this campaign can start a container (it cannot:
    no root, no daemon access), and the earlier version returned it, which made two cases look runnable.
    An unusable tool is not a prerequisite that exists.
    """
    for candidate in ("qemu-system-x86_64", "systemd-nspawn", "lxc-start"):
        if shutil.which(candidate):
            return candidate
    for container in ("docker", "podman"):
        if shutil.which(container):
            probe = _run([container, "info"], timeout=20)
            if probe["returncode"] == 0:
                return container
    return None


@dataclass
class Case:
    name: str
    requires: str
    purpose: str
    prerequisite: Callable[[], bool]
    prerequisite_detail: Callable[[], Dict[str, Any]]
    run: Callable[[Dict[str, Any]], Dict[str, Any]]
    expected: str
    notes: str = ""


def _case_system_install(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["apt-get install -y python3 systemd gnupg",
                     "useradd --system --no-create-home --shell /usr/sbin/nologin ciph-core",
                     "useradd --system --no-create-home --shell /usr/sbin/nologin ciph-worker",
                     "install -d -o ciph-core -g ciph-core -m 0700 /var/lib/ciph",
                     "install -d -o root -g ciph-operator -m 0700 /var/lib/ciph/recovery",
                     "install -m 0644 deploy/ciph-core.service /etc/systemd/system/",
                     "systemctl daemon-reload && systemctl enable ciph-core.service"],
            "expected": "ciph-core.service starts as ciph-core, NOT as root"}


def _case_service_identity(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["systemctl start ciph-core", "ps -o user= -p $(systemctl show -p MainPID "
                     "--value ciph-core)", "id ciph-core"],
            "expected": "the process runs as ciph-core; ciph-core is NOT in sudo/wheel; a shell as "
                        "ciph-core cannot read /var/lib/ciph/recovery"}


def _case_cross_user_restriction(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["sudo -u ciph-worker cat /var/lib/ciph/vault/root.key  (must fail EACCES)",
                     "sudo -u ciph-worker python3 -c \"open('/etc/ciph/policy.json','w')\" (must fail)"],
            "expected": "both attempts refused by the kernel, not by a policy file"}


def _case_escalation_refusal(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["sudo -u ciph-worker sudo -n true", "sudo -u ciph-worker id"],
            "expected": "no escalation path; the service account has no sudoers entry"}


def _case_namespace_sandbox(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["systemd-run --uid=ciph-worker --property=PrivateTmp=yes "
                     "--property=ProtectSystem=strict --property=InaccessiblePaths=/var/lib/ciph/vault "
                     "python3 -c \"open('/var/lib/ciph/vault/root.key')\""],
            "expected": "refused by the namespace/hardening directives, verified by the attempt failing"}


def _case_worker_vault_access(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["sudo -u ciph-worker ls /var/lib/ciph/vault", "sudo -u ciph-worker "
                     "sqlite3 /var/lib/ciph/vault/ciph_vault.db '.tables'"],
            "expected": "refused: worker identity has no path to vault material"}


def _case_egress_enforcement(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["nft add table inet ciph; nft add chain inet ciph output '{ type filter hook output "
                     "priority 0; policy drop; }'",
                     "sudo -u ciph-worker curl -sS --max-time 3 https://example.com (must fail)"],
            "expected": "the KERNEL refuses egress; a policy-only denial is NOT this proof"}


def _case_boot_without_authority(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["systemctl reboot", "after boot: python3 -c \"from "
                     "ciph.kernel.environment_boot import boot_summary; ...\"",
                     "assert authority_granted == 'none' and state == "
                     "AWAITING_OPERATOR_AUTHORIZATION"],
            "expected": "the service is up, autonomy OFF, zero permits, zero deployments"}


def _case_operator_activation(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["python3 -m ciph.operator activate --principal OP-1 --token <hardware token>",
                     "python3 -c \"... present_operator_authorization(...)\""],
            "expected": "activation accepted only with the scoped grant; a copied token or an "
                        "environment variable is refused"}


def _case_restart_and_recovery(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["systemctl kill -s SIGKILL ciph-core", "systemctl status ciph-core",
                     "verify no duplicate execution and no re-armed destructive timer"],
            "expected": "systemd restarts the process; constitutional state reconciles through 4.0/4.1"}


def _case_disconnected_stale_host(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["ip link set eth0 down", "attempt an external effect from the stale host "
                     "(must be refused by the RESOURCE)", "attempt a local effect outside its OS "
                     "permissions (must be refused by the KERNEL)",
                     "attempt a purely local effect it still holds (EXPECTED TO SUCCEED: record it as "
                     "residual physical control)"],
            "expected": "two refusals and one honestly documented residual capability - never a claim of "
                        "global revocation"}


def _case_update_and_rollback(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["stage -> verify -> operator authorize -> install -> health assess -> rollback",
                     "verify historical constitutional judgments remain attached to their versions"],
            "expected": "an unauthorized or unverified update never reaches INSTALLED; a regression "
                        "rolls back into a NEW state"}


def _case_clean_install_reproducibility(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["install the artifact twice into two clean environments",
                     "compare declared deterministic portions (units, ownership, manifest)",
                     "record values that legitimately differ (keys, machine ids, timestamps)"],
            "expected": "the deterministic portions match exactly; generated values are named as such"}


def _case_destroyed_host_recovery(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["quiesce -> approved recovery material -> destroy the host -> fresh CiphOS install "
                     "-> 8.x restore -> fence -> authorize -> activate",
                     "verify an unauthorized copy of the same image stays powerless"],
            "expected": "canonical history survives; ephemeral state does not; the clone never activates"}


def _case_end_to_end_torture(host: Dict[str, Any]) -> Dict[str, Any]:
    return {"executed": False,
            "plan": ["the C3 scenario end to end, on one machine, with real services"],
            "expected": "one identity throughout: boot without authority -> activation -> autonomy -> "
                        "workers -> federation -> quiesce -> crash/restart -> stale-host attack -> "
                        "update/rollback -> host destruction -> 8.x recovery -> clone refused"}


CASES: Tuple[Case, ...] = (
    Case("system_install", "root + systemd", "install system-scope units",
         lambda: _privileged()["is_root"] or _privileged()["sudo_non_interactive"],
         _privileged, _case_system_install,
         "units installed and enabled under /etc/systemd/system"),
    Case("service_identity", "root + systemd + service accounts", "prove the service runs as its own user",
         lambda: (_privileged()["is_root"] or _privileged()["sudo_non_interactive"])
         and _systemd_available(), _privileged, _case_service_identity, "MainPID runs as ciph-core"),
    Case("cross_user_restriction", "root + service accounts", "prove kernel-enforced cross-user denial",
         lambda: _privileged()["is_root"] or _privileged()["sudo_non_interactive"],
         _privileged, _case_cross_user_restriction, "EACCES on both attempts"),
    Case("escalation_refusal", "root + service accounts", "prove no escalation path",
         lambda: _privileged()["is_root"] or _privileged()["sudo_non_interactive"],
         _privileged, _case_escalation_refusal, "escalation refused"),
    Case("namespace_sandbox", "systemd + hardening + userns",
         "prove sandbox directives are IN EFFECT",
         lambda: _systemd_available() and _userns_available(),
         lambda: {"systemd": _systemd_available(), "userns": _userns_available()},
         _case_namespace_sandbox, "the attempt fails; the directive is therefore in effect"),
    Case("worker_vault_access", "root + service accounts", "prove the worker cannot reach the vault",
         lambda: _privileged()["is_root"] or _privileged()["sudo_non_interactive"],
         _privileged, _case_worker_vault_access, "refused by the kernel"),
    Case("egress_enforcement", "nftables/iptables + root", "prove KERNEL egress denial",
         lambda: (_privileged()["is_root"] or _privileged()["sudo_non_interactive"])
         and bool(shutil.which("nft") or shutil.which("iptables")),
         lambda: {"nft": shutil.which("nft"), "iptables": shutil.which("iptables")},
         _case_egress_enforcement, "kernel refusal, not policy refusal"),
    Case("boot_without_authority", "root + systemd + reboot", "prove a real boot grants nothing",
         lambda: (_privileged()["is_root"] or _privileged()["sudo_non_interactive"])
         and _systemd_available(), _privileged, _case_boot_without_authority,
         "authority_granted none after a real boot"),
    Case("operator_activation", "installed CiphOS", "prove real operator activation",
         lambda: os.path.isdir("/var/lib/ciph"), lambda: {"installed": os.path.isdir("/var/lib/ciph")},
         _case_operator_activation, "scoped grant accepted, ambient refused"),
    Case("restart_and_recovery", "systemd + installed CiphOS", "prove restart does not duplicate work",
         lambda: _systemd_available() and os.path.isdir("/var/lib/ciph"),
         lambda: {"systemd": _systemd_available()}, _case_restart_and_recovery, "clean restart"),
    Case("disconnected_stale_host", "root + netns + an external resource", "measure the effect boundary",
         lambda: (_privileged()["is_root"] or _privileged()["sudo_non_interactive"])
         and _userns_available(), _privileged, _case_disconnected_stale_host,
         "two refusals plus one documented residual capability"),
    Case("update_and_rollback", "installed CiphOS", "prove governed updates",
         lambda: os.path.isdir("/var/lib/ciph"), lambda: {"installed": os.path.isdir("/var/lib/ciph")},
         _case_update_and_rollback, "rollback lands in a new state"),
    Case("clean_install_reproducibility", "two clean environments + a hypervisor",
         "prove reproducible installation",
         lambda: _hypervisor_available() is not None,
         lambda: {"hypervisor": _hypervisor_available()},
         _case_clean_install_reproducibility, "deterministic portions match"),
    Case("destroyed_host_recovery", "two hosts + recovery material", "prove 8.x recovery on real hosts",
         lambda: _hypervisor_available() is not None,
         lambda: {"hypervisor": _hypervisor_available()},
         _case_destroyed_host_recovery, "continuation activated, clone refused"),
    Case("end_to_end_torture", "a full privileged host", "the C3 founding torture",
         lambda: (_privileged()["is_root"] or _privileged()["sudo_non_interactive"])
         and _systemd_available() and _hypervisor_available() is not None,
         lambda: {"privileged": _privileged(), "hypervisor": _hypervisor_available()},
         _case_end_to_end_torture, "one identity throughout"),
)


def main(argv) -> int:
    parser = argparse.ArgumentParser(description="CiphOS privileged-host verification package")
    parser.add_argument("--list", action="store_true", help="list cases and their prerequisites")
    parser.add_argument("--run", action="store_true", help="run every case, skipping unavailable ones")
    parser.add_argument("--case", action="append", default=[], help="run one named case (repeatable)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable evidence")
    arguments = parser.parse_args(argv[1:])

    host = {"platform": platform.platform(), "python": sys.version.split()[0],
            "privileges": _privileged(), "systemd": _systemd_available(),
            "unprivileged_userns": _userns_available(), "hypervisor": _hypervisor_available()}

    if arguments.list or not (arguments.run or arguments.case):
        rows = [{"case": case.name, "requires": case.requires, "purpose": case.purpose,
                 "prerequisite_available": bool(case.prerequisite()),
                 "prerequisite_detail": case.prerequisite_detail(), "expected": case.expected}
                for case in CASES]
        print(json.dumps({"host": host, "cases": rows}, indent=2, default=str))
        return 0

    selected = [case for case in CASES if not arguments.case or case.name in arguments.case]
    results = []
    for case in selected:
        available = bool(case.prerequisite())
        if not available:
            results.append({"case": case.name, "status": SKIPPED,
                            "prerequisite": case.requires,
                            "prerequisite_detail": case.prerequisite_detail(),
                            "expected": case.expected, "notes": case.notes})
            continue
        try:
            evidence = case.run(host)
            executed = bool(evidence.pop("executed", True))
            if executed:
                results.append({"case": case.name, "status": PASSED, "evidence": evidence,
                                "expected": case.expected})
            else:
                # The case RAN but produced a PLAN rather than an observation. That is a skip, and it
                # must say WHY: an unnamed skip is a green result wearing a disguise.
                results.append({"case": case.name, "status": SKIPPED,
                                "prerequisite": f"{case.requires} (probe passed; execution not possible)",
                                "reason": "this case produces a plan and requires a host that can execute "
                                          "it; the plan is evidence of intent, not of enforcement",
                                "evidence": evidence, "expected": case.expected})
        except Exception as error:                                   # noqa: BLE001
            results.append({"case": case.name, "status": FAILED,
                            "error": f"{type(error).__name__}: {error}", "expected": case.expected})

    summary = {"passed": len([r for r in results if r["status"] == PASSED]),
               "failed": len([r for r in results if r["status"] == FAILED]),
               "skipped": len([r for r in results if r["status"] == SKIPPED])}
    if arguments.json:
        print(json.dumps({"host": host, "results": results, "summary": summary}, indent=2, default=str))
    else:
        for result in results:
            print(f"{result['status']:<34} {result['case']}")
            if result["status"] == SKIPPED:
                print(f"    requires: {result.get('prerequisite')}")
            elif result["status"] == FAILED:
                print(f"    error: {result.get('error')}")
        print(f"\npassed={summary['passed']} failed={summary['failed']} skipped={summary['skipped']}")
    if summary["failed"]:
        return 1
    return 2 if summary["skipped"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
