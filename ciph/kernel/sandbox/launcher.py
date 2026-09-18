"""
ciph.kernel.sandbox.launcher - In-child sandbox setup and exec wrapper.
Runs as the single-threaded entrypoint inside the sandbox container/namespace,
setting resource limits, enforcing Landlock filesystem isolation, and preparing
environment without parent preexec_fn.
"""

import ctypes
import json
import os
import resource
import sys
import subprocess
import sysconfig
import errno

# Landlock ABI definitions
LANDLOCK_CREATE_RULESET_VERSION = (1 << 0)
LANDLOCK_ACCESS_FS_EXECUTE = (1 << 0)
LANDLOCK_ACCESS_FS_WRITE_FILE = (1 << 1)
LANDLOCK_ACCESS_FS_READ_FILE = (1 << 2)
LANDLOCK_ACCESS_FS_READ_DIR = (1 << 3)
LANDLOCK_ACCESS_FS_REMOVE_DIR = (1 << 4)
LANDLOCK_ACCESS_FS_REMOVE_FILE = (1 << 5)
LANDLOCK_ACCESS_FS_MAKE_CHAR = (1 << 6)
LANDLOCK_ACCESS_FS_MAKE_DIR = (1 << 7)
LANDLOCK_ACCESS_FS_MAKE_REG = (1 << 8)
LANDLOCK_ACCESS_FS_MAKE_SOCK = (1 << 9)
LANDLOCK_ACCESS_FS_MAKE_FIFO = (1 << 10)
LANDLOCK_ACCESS_FS_MAKE_BLOCK = (1 << 11)
LANDLOCK_ACCESS_FS_MAKE_SYM = (1 << 12)
LANDLOCK_ACCESS_FS_REFER = (1 << 13)
LANDLOCK_ACCESS_FS_TRUNCATE = (1 << 14)

SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule = 445
SYS_landlock_restrict_self = 446
PR_SET_NO_NEW_PRIVS = 38


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def apply_rlimits(limits_dict):
    """Apply POSIX resource limits within child process, raising on failure."""
    limit_mappings = {
        "as": (resource.RLIMIT_AS, "max_memory_bytes"),
        "cpu": (resource.RLIMIT_CPU, "max_cpu_seconds"),
        "fsize": (resource.RLIMIT_FSIZE, "max_output_bytes"),
    }
    if hasattr(resource, "RLIMIT_NPROC"):
        limit_mappings["nproc"] = (resource.RLIMIT_NPROC, "max_processes")
    for key, (res_const, config_key) in limit_mappings.items():
        val = limits_dict.get(config_key)
        if val is not None and val > 0:
            resource.setrlimit(res_const, (int(val), int(val)))


def apply_landlock_isolation(allowed_read=(), allowed_write=()):
    """
    Enforce kernel-level filesystem sandboxing via Linux Landlock LSM.
    Restricts access strictly to declared read/write paths and essential Python runtimes.
    """
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        # Check Landlock support
        abi = libc.syscall(SYS_landlock_create_ruleset, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
        if abi <= 0:
            return False

        read_flags = (
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR
        )
        all_fs_flags = (
            LANDLOCK_ACCESS_FS_EXECUTE |
            LANDLOCK_ACCESS_FS_WRITE_FILE |
            LANDLOCK_ACCESS_FS_READ_FILE |
            LANDLOCK_ACCESS_FS_READ_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_CHAR |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO |
            LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_MAKE_SYM |
            LANDLOCK_ACCESS_FS_REFER |
            LANDLOCK_ACCESS_FS_TRUNCATE
        )

        attr = LandlockRulesetAttr()
        attr.handled_access_fs = all_fs_flags
        ruleset_fd = libc.syscall(SYS_landlock_create_ruleset, ctypes.byref(attr), ctypes.sizeof(attr), 0)
        if ruleset_fd < 0:
            return False

        def _add_rule(p: str, is_write: bool) -> bool:
            if not p or not os.path.exists(p):
                return False
            real_p = os.path.realpath(p)
            is_dir = os.path.isdir(real_p)
            if is_write:
                flags = all_fs_flags if is_dir else (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE)
            else:
                flags = read_flags if is_dir else (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE)
            try:
                fd = os.open(real_p, os.O_PATH | os.O_CLOEXEC)
                path_attr = LandlockPathBeneathAttr()
                path_attr.allowed_access = flags
                path_attr.parent_fd = fd
                rc = libc.syscall(SYS_landlock_add_rule, ruleset_fd, 1, ctypes.byref(path_attr), 0)
                os.close(fd)
                return rc == 0
            except Exception:
                return False

        # Essential runtime paths for python interpreter and standard libraries.
        # Excludes recursive /etc and recursive /dev to prevent undeclared host inspection.
        runtime_paths = [
            os.path.realpath(sys.executable), sysconfig.get_path("stdlib"),
            "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
            "/lib64/ld-linux-x86-64.so.2",
        ]

        for p in runtime_paths:
            if os.path.exists(p):
                if not _add_rule(p, False):
                    os.close(ruleset_fd)
                    return False

        # Essential device nodes for basic I/O (permitted read/write specifically without admitting /dev)
        for dev_node in ("/dev/null", "/dev/urandom", "/dev/zero"):
            if os.path.exists(dev_node):
                try:
                    fd = os.open(dev_node, os.O_PATH | os.O_CLOEXEC)
                    path_attr = LandlockPathBeneathAttr()
                    path_attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE
                    path_attr.parent_fd = fd
                    rc = libc.syscall(SYS_landlock_add_rule, ruleset_fd, 1, ctypes.byref(path_attr), 0)
                    os.close(fd)
                    if rc != 0:
                        os.close(ruleset_fd)
                        return False
                except Exception:
                    os.close(ruleset_fd)
                    return False

        # Declared read paths
        for p in allowed_read:
            if not _add_rule(p, False):
                os.close(ruleset_fd)
                return False

        # Declared write paths
        for p in allowed_write:
            if not _add_rule(p, True):
                os.close(ruleset_fd)
                return False

        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            os.close(ruleset_fd)
            return False

        res = libc.syscall(SYS_landlock_restrict_self, ruleset_fd, 0)
        os.close(ruleset_fd)
        return res == 0
    except Exception:
        return False


def deny_socket_syscalls():
    """Install a kernel filter; fail closed if libseccomp or any rule is unavailable."""
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x7fff0000)  # ALLOW except explicitly denied system calls
    if not ctx:
        raise RuntimeError("SECCOMP_UNAVAILABLE")
    try:
        for name in ("socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
                     "ptrace", "process_vm_readv", "process_vm_writev", "mount", "umount2",
                     "unshare", "setns", "bpf", "userfaultfd", "io_uring_setup", "open_by_handle_at",
                     "chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "lchown", "fchown", "fchownat",
                     "utime", "utimes", "futimesat", "utimensat", "setxattr", "lsetxattr", "fsetxattr",
                     "removexattr", "lremovexattr", "fremovexattr", "ioctl", "pidfd_getfd"):
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number < 0 or lib.seccomp_rule_add(ctx, 0x50000 | errno.EPERM, number, 0) != 0:
                raise RuntimeError("SECCOMP_RULE_FAILED:" + name)
        if lib.seccomp_load(ctx) != 0:
            raise RuntimeError("SECCOMP_LOAD_FAILED")
    finally:
        lib.seccomp_release(ctx)


def main():
    # This trusted process remains namespace init. Untrusted workloads may detach;
    # exiting/killing init still destroys the entire PID namespace.
    config = json.loads(open(sys.argv[1], encoding="utf-8").read())
    lifecycle = config.get("lifecycle_fd")
    def notify(message):
        if lifecycle is not None:
            os.write(lifecycle, message.encode() + b"\n")
    try:
        if os.readlink("/proc/self/ns/pid") == config.get("host_pid_namespace") or os.getpid() != 1:
            raise RuntimeError("PID_NAMESPACE_REQUIRED")
        cmd = config["cmd"]
        if not cmd or not all(isinstance(v, str) and v for v in cmd):
            raise ValueError("INVALID_COMMAND")
        apply_rlimits(config["limits"])
        if not apply_landlock_isolation(config.get("allowed_read_paths", ()),
                                       [config["scratch_dir"]] + config.get("allowed_write_paths", [])):
            raise RuntimeError("LANDLOCK_UNAVAILABLE")
        deny_socket_syscalls()
        os.chdir(config["scratch_dir"])
        # Popen's private CLOEXEC error pipe distinguishes exec failure from the
        # application's own exit code. The lifecycle FD is never inherited by it.
        child = subprocess.Popen(cmd, close_fds=True, start_new_session=True)
    except Exception as exc:
        notify("DENIED")
        sys.stderr.write("Sandbox setup refused: " + str(exc) + "\n")
        return 77
    notify("STARTED")
    _, status, usage = os.wait4(child.pid, 0)
    rc = os.waitstatus_to_exitcode(status)
    child.returncode = rc
    notify('USAGE '+json.dumps({'peak_memory_bytes':int(usage.ru_maxrss)*1024,
                              'cpu_seconds':usage.ru_utime+usage.ru_stime}))
    if lifecycle is not None:
        os.close(lifecycle)
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main())
