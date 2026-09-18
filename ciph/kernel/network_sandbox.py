"""Interpreter-level socket policy with isolated worker and helper-thread contexts.

Permanent audit and context-propagation hooks do not replace socket constructors.
This is an in-process guard; OS/process sandboxing remains a separate boundary.
"""
import contextlib
import contextvars
import functools
import sys
import threading
import _thread
from concurrent.futures import ThreadPoolExecutor
from typing import Generator, Optional
from ciph.kernel.policy_engine import NetworkPolicy


class NetworkPolicyViolation(PermissionError):
    pass


_active_network_policy: contextvars.ContextVar[Optional[NetworkPolicy]] = contextvars.ContextVar(
    "_active_network_policy", default=None
)
_inherited_network_policies = contextvars.ContextVar("_inherited_network_policies", default=())
_executor_worker_start = contextvars.ContextVar("_executor_worker_start", default=False)
_install_lock = threading.Lock()
_audit_hook_installed = False


def _policies():
    inherited = getattr(threading.current_thread(), "_ciph_network_policies", ())
    current = _active_network_policy.get()
    return tuple(dict.fromkeys(inherited + _inherited_network_policies.get() + ((current,) if current else ())))


def _is_loopback(host):
    import ipaddress
    if str(host).lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(str(host)).is_loopback
    except ValueError:
        return False


def _ciph_socket_audit_hook(event: str, args: tuple) -> None:
    if event in ("subprocess.Popen", "os.system", "os.posix_spawn", "os.fork", "os.forkpty", "os.exec", "os.spawn"):
        if any(p in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.NETWORK_DENIED) for p in _policies()):
            raise NetworkPolicyViolation(f"Child process '{event}' blocked by offline policy.")
    if not event.startswith("socket."):
        return
    for policy in _policies():
        if policy in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.NETWORK_DENIED):
            if event in ("socket.__new__", "socket.bind", "socket.connect", "socket.sendto", "socket.sendmsg", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"):
                raise NetworkPolicyViolation(f"Socket operation '{event}' blocked by '{policy.value}'.")
        elif policy in (NetworkPolicy.LOCAL_ONLY, NetworkPolicy.TOR_MANDATORY):
            if event in ("socket.connect", "socket.sendto"):
                address = args[1] if len(args) > 1 else None
                if not isinstance(address, tuple) or len(address) < 2 or not _is_loopback(address[0]):
                    raise NetworkPolicyViolation(f"External address blocked by {policy.value}.")
                if policy == NetworkPolicy.TOR_MANDATORY and address[1] not in (9050, 9150, 9051):
                    raise NetworkPolicyViolation("TOR_MANDATORY requires a local Tor proxy.")
            elif event == "socket.sendmsg":
                raise NetworkPolicyViolation(f"Unverified sendmsg transport blocked by {policy.value}.")
            elif event in ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr"):
                if not args or not _is_loopback(args[0]):
                    raise NetworkPolicyViolation(f"External DNS resolution blocked by {policy.value}.")


def _run_with_policies(policies, function, args, kwargs):
    # Preserve restrictions when a helper outlives its parent capability, and
    # restore reusable executor threads after each task (including exceptions).
    token = _inherited_network_policies.set(_inherited_network_policies.get() + policies)
    try:
        return function(*args, **kwargs)
    finally:
        _inherited_network_policies.reset(token)


def _ensure_audit_hook_installed():
    global _audit_hook_installed
    with _install_lock:
        if _audit_hook_installed:
            return
        original_start = threading.Thread.start
        original_submit = ThreadPoolExecutor.submit
        original_lowlevel_start = _thread.start_new_thread

        @functools.wraps(original_start)
        def start(thread, *args, **kwargs):
            inherited = () if _executor_worker_start.get() else _policies()
            thread._ciph_network_policies = getattr(thread, "_ciph_network_policies", ()) + inherited
            return original_start(thread, *args, **kwargs)

        @functools.wraps(original_submit)
        def submit(executor, function, /, *args, **kwargs):
            policies = _policies()
            starting = _executor_worker_start.set(True)
            try:
                return original_submit(executor, _run_with_policies, policies, function, args, kwargs)
            finally:
                _executor_worker_start.reset(starting)

        @functools.wraps(original_lowlevel_start)
        def start_new_thread(function, args, kwargs=None):
            return original_lowlevel_start(_run_with_policies, (_policies(), function, args, kwargs or {}))

        sys.addaudithook(_ciph_socket_audit_hook)
        threading.Thread.start = start
        ThreadPoolExecutor.submit = submit
        _thread.start_new_thread = start_new_thread
        _audit_hook_installed = True


@contextlib.contextmanager
def enforce_network_policy(policy: NetworkPolicy) -> Generator[None, None, None]:
    _ensure_audit_hook_installed()
    inherited = _inherited_network_policies.set(_inherited_network_policies.get() + _policies())
    token = _active_network_policy.set(policy)
    try:
        yield
    finally:
        _active_network_policy.reset(token)
        _inherited_network_policies.reset(inherited)
