"""
ciph.kernel.network_sandbox - Runner-Level Network Policy & Socket Enforcement (CIPH 4.0).
Strictly prevents OFFLINE_ONLY, LOCAL_ONLY, and TOR_MANDATORY bypass across class replacements,
pre-captured constructor aliases, pre-instantiated socket objects, and direct C-module imports
using CPython standard PEP 578 runtime audit hooks and module wrappers.
"""

import sys
import socket
import _socket
import contextlib
import contextvars
from typing import Generator, Optional
from ciph.kernel.policy_engine import NetworkPolicy


class NetworkPolicyViolation(PermissionError):
    """Raised when a capability violates its declared network policy at the OS/socket boundary."""
    pass


_active_network_policy: contextvars.ContextVar[Optional[NetworkPolicy]] = contextvars.ContextVar(
    "_active_network_policy", default=None
)

_audit_hook_installed = False


def _ciph_socket_audit_hook(event: str, args: tuple) -> None:
    policy = _active_network_policy.get()
    if policy is None:
        return

    if policy in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.NETWORK_DENIED):
        if event in ("socket.__new__", "socket.bind", "socket.connect", "socket.sendto", "socket.sendmsg", "socket.getaddrinfo"):
            raise NetworkPolicyViolation(f"Socket operation '{event}' blocked: Capability is governed by '{policy.value}'.")
    elif policy == NetworkPolicy.LOCAL_ONLY:
        if event == "socket.connect":
            addr = args[1] if len(args) > 1 else None
            host = addr[0] if isinstance(addr, tuple) else addr
            if host and str(host) not in ("127.0.0.1", "localhost", "::1", "0.0.0.0") and not str(host).startswith("127."):
                raise NetworkPolicyViolation(f"External connection to '{host}' blocked by LOCAL_ONLY policy.")
    elif policy == NetworkPolicy.TOR_MANDATORY:
        if event == "socket.connect":
            addr = args[1] if len(args) > 1 else None
            if not isinstance(addr, tuple) or len(addr) < 2:
                raise NetworkPolicyViolation("TOR_MANDATORY violation: Raw socket address without port attempted.")
            host, port = addr[0], addr[1]
            if str(host) not in ("127.0.0.1", "localhost", "::1") or port not in (9050, 9150, 9051):
                raise NetworkPolicyViolation(
                    f"TOR_MANDATORY violation: Direct connection to '{host}:{port}' blocked. All traffic must route through Tor SOCKS proxy (127.0.0.1:9050)."
                )


def _ensure_audit_hook_installed():
    global _audit_hook_installed
    if not _audit_hook_installed:
        sys.addaudithook(_ciph_socket_audit_hook)
        _audit_hook_installed = True


@contextlib.contextmanager
def enforce_network_policy(policy: NetworkPolicy) -> Generator[None, None, None]:
    """
    Context manager enforcing network policies across socket and _socket modules.
    Enforces policies at the CPython runtime boundary via PEP 578 audit hooks and module wrappers.
    """
    _ensure_audit_hook_installed()

    orig_socket_cls = socket.socket
    orig_underscore_cls = getattr(_socket, "socket", None)
    orig_create_conn = getattr(socket, "create_connection", None)
    orig_getaddrinfo = getattr(socket, "getaddrinfo", None)
    orig_u_getaddrinfo = getattr(_socket, "getaddrinfo", None)

    token = _active_network_policy.set(policy)

    if policy in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.NETWORK_DENIED):
        class DeniedSocket:
            def __init__(self, *args, **kwargs):
                raise NetworkPolicyViolation(f"Socket creation blocked: Capability is governed by '{policy.value}'.")

            def __call__(self, *args, **kwargs):
                raise NetworkPolicyViolation(f"Socket creation blocked: Capability is governed by '{policy.value}'.")

        def denied_create_connection(*args, **kwargs):
            raise NetworkPolicyViolation(f"Network connection blocked: Capability is governed by '{policy.value}'.")

        def denied_getaddrinfo(*args, **kwargs):
            raise NetworkPolicyViolation(f"DNS resolution blocked: Capability is governed by '{policy.value}'.")

        socket.socket = DeniedSocket
        if orig_underscore_cls:
            _socket.socket = DeniedSocket
            if hasattr(_socket, "SocketType"):
                _socket.SocketType = DeniedSocket
        if orig_create_conn:
            socket.create_connection = denied_create_connection
        if orig_getaddrinfo:
            socket.getaddrinfo = denied_getaddrinfo
        if orig_u_getaddrinfo:
            _socket.getaddrinfo = denied_getaddrinfo

        try:
            yield
        finally:
            _active_network_policy.reset(token)
            socket.socket = orig_socket_cls
            if orig_underscore_cls:
                _socket.socket = orig_underscore_cls
                if hasattr(_socket, "SocketType"):
                    _socket.SocketType = orig_underscore_cls
            if orig_create_conn:
                socket.create_connection = orig_create_conn
            if orig_getaddrinfo:
                socket.getaddrinfo = orig_getaddrinfo
            if orig_u_getaddrinfo:
                _socket.getaddrinfo = orig_u_getaddrinfo

    else:
        try:
            yield
        finally:
            _active_network_policy.reset(token)
