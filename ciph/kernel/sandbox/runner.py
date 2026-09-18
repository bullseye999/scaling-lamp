"""Bounded runners with a trusted namespace init and no in-process fallback."""
import dataclasses
import json
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional, List

from ciph.contracts.enums import NetworkPolicy
from .base import (DiagnosticCheck, SandboxDiagnostics, SandboxDiagnosticState as State,
                   SandboxPolicy, SandboxResult, SandboxTerminationReason as Reason)


class OfflineSandboxRunner:
    tier = 'DISPOSABLE_PROCESS'

    def __init__(self, launcher_cmd: Optional[List[str]] = None):
        self.launcher_cmd = launcher_cmd if launcher_cmd is not None else [
            'unshare', '-U', '-m', '--propagation', 'unchanged', '-p', '-f', '-n', '--kill-child=KILL']
        self._launcher_path = str(Path(__file__).with_name('launcher.py'))

    def _command(self, config, scratch, policy):
        return self.launcher_cmd + [sys.executable, '-I', '-S', self._launcher_path, config]

    @staticmethod
    def _validate(policy):
        if policy.network_policy not in (NetworkPolicy.OFFLINE_ONLY, NetworkPolicy.LOCAL_ONLY):
            raise ValueError('UNSUPPORTED_NETWORK_POLICY: use the trusted Tor evidence broker')
        if not all((policy.require_filesystem_isolation, policy.require_network_isolation, policy.require_pid_isolation)):
            raise ValueError('REQUIRED_BOUNDARY_CANNOT_BE_DISABLED')
        for key in ('max_wall_time_seconds', 'max_memory_bytes', 'max_cpu_seconds', 'max_processes',
                    'max_output_bytes', 'max_input_bytes'):
            import math
            value = getattr(policy, key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError('INVALID_RESOURCE_LIMIT:' + key)
        if set(policy.env_allowlist) - {'PATH', 'LANG', 'LC_ALL', 'CIPH_SANDBOX_ID'}:
            raise ValueError('UNSAFE_ENVIRONMENT_ALLOWLIST')
        for path in (*policy.allowed_read_paths, *policy.allowed_write_paths):
            if not os.path.isabs(path) or not os.path.exists(path):
                raise ValueError('INVALID_DECLARED_PATH')

    def probe_containment(self, policy=None):
        policy = policy or SandboxPolicy()
        config = json.dumps({'tier': self.tier, 'launcher': self.launcher_cmd, 'policy': policy.to_dict()}, sort_keys=True)
        checks = [DiagnosticCheck(State.NOT_TESTED, 'Not executed', config) for _ in range(5)]
        try:
            self._validate(policy)
            with tempfile.TemporaryDirectory(prefix='ciph_probe_outside_') as outside:
                canary = str(Path(outside) / 'canary')
                Path(canary).write_text('disposable readiness canary')
                code = '''import json,os,socket,resource,sys
r={}
try:
 open(sys.argv[1]).read(); r['fs']=False
except (PermissionError,FileNotFoundError): r['fs']=True
try:
 socket.socket(); r['net']=False
except PermissionError: r['net']=True
open('allowed','w').write('ok')
r['resource']=resource.getrlimit(resource.RLIMIT_AS)[0] == int(sys.argv[2])
r['pid']=os.getpid()!=1
print(json.dumps(r))
'''
                result = self._run([sys.executable, '-I', '-S', '-c', code, canary, str(policy.max_memory_bytes)], None, policy)
                if result.termination_reason != Reason.SUCCESS or not isinstance(result.data, dict):
                    checks[0] = DiagnosticCheck(State.FAIL, result.stderr or result.termination_reason.value, config)
                else:
                    checks[0] = DiagnosticCheck(State.PASS, 'Exact launcher completed its private lifecycle handshake', config)
                    for i, key in ((1, 'fs'), (2, 'net'), (3, 'resource'), (4, 'pid')):
                        passed = result.data.get(key) is True and result.cleaned_up
                        checks[i] = DiagnosticCheck(State.PASS if passed else State.FAIL, ('Undeclared file inaccessible' if key == 'fs' else key + ' enforced by actual launcher'), config)
        except Exception as exc:
            checks[0] = DiagnosticCheck(State.FAIL, str(exc), config)
        return SandboxDiagnostics(*checks, overall='AVAILABLE' if all(c.state == State.PASS for c in checks) else 'UNAVAILABLE')

    def execute_isolated(self, cmd, payload=None, policy=None, scratch_dir=None):
        policy = policy or SandboxPolicy()
        try:
            self._validate(policy)
            encoded = None if payload is None else json.dumps(payload, allow_nan=False).encode()
            if encoded is not None and len(encoded) > policy.max_input_bytes:
                return SandboxResult(None, '', 'INPUT_LIMIT', Reason.RESOURCE_EXHAUSTED)
            if not cmd or not all(isinstance(x, str) and x for x in cmd):
                raise ValueError('INVALID_COMMAND')
        except (ValueError, TypeError) as exc:
            return SandboxResult(None, '', str(exc), Reason.SANDBOX_UNAVAILABLE)
        diag = self.probe_containment(policy)
        if diag.overall != 'AVAILABLE':
            return SandboxResult(None, '', 'SANDBOX_UNAVAILABLE: ' + str(diag.to_dict()), Reason.SANDBOX_UNAVAILABLE, diag)
        result = self._run(cmd, encoded, policy, scratch_dir)
        result.diagnostics = diag
        return result

    def _run(self, cmd, payload, policy, scratch_dir=None):
        if os.path.realpath(cmd[0]) == os.path.realpath(sys.executable):
            cmd = [os.path.realpath(sys.executable), '-I', '-S'] + cmd[1:]
        started_at = time.monotonic()
        with tempfile.TemporaryDirectory(prefix='ciph_sbx_') as owned:
            scratch = scratch_dir or owned
            if scratch_dir and (not os.path.isdir(scratch) or os.path.islink(scratch)):
                return SandboxResult(None, '', 'INVALID_SCRATCH', Reason.SANDBOX_UNAVAILABLE)
            lifecycle_r, lifecycle_w = os.pipe2(os.O_CLOEXEC)
            cfg = {'cmd': cmd, 'scratch_dir': scratch, 'allowed_read_paths': list(policy.allowed_read_paths),
                   'allowed_write_paths': list(policy.allowed_write_paths), 'lifecycle_fd': lifecycle_w,
                   'host_pid_namespace': os.readlink('/proc/self/ns/pid'),
                   'limits': {k: getattr(policy, k) for k in ('max_memory_bytes', 'max_cpu_seconds', 'max_processes', 'max_output_bytes')}}
            # Config is supervisor-owned and read before restrictions. Never reuse a
            # predictable caller-controlled scratch filename or follow its symlinks.
            config = str(Path(owned) / 'launch.json')
            Path(config).write_text(json.dumps(cfg))
            proc = None
            selector = selectors.DefaultSelector()
            buffers = {'out': bytearray(), 'err': bytearray(), 'life': bytearray()}
            total = 0
            reason = None
            confirmed = False
            cleaned = True
            input_offset = 0
            init_pidfds = []
            try:
                env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONUNBUFFERED': '1'}
                proc = subprocess.Popen(self._command(config, scratch, policy),
                    stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                    close_fds=True, pass_fds=(lifecycle_w,), start_new_session=True)
                os.close(lifecycle_w); lifecycle_w = -1
                for stream, name in ((proc.stdout, 'out'), (proc.stderr, 'err'), (lifecycle_r, 'life')):
                    os.set_blocking(stream if isinstance(stream, int) else stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                if proc.stdin:
                    os.set_blocking(proc.stdin.fileno(), False)
                    selector.register(proc.stdin, selectors.EVENT_WRITE, 'in')
                tracked = set()
                while selector.get_map():
                    # Open pidfds to the trusted init while it is still parented by
                    # the launcher; no environment strings or command names are authority.
                    try:
                        children = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                        for child in children:
                            if child not in tracked:
                                init_pidfds.append(os.pidfd_open(int(child))); tracked.add(child)
                    except (OSError, ValueError):
                        pass
                    if time.monotonic() - started_at > policy.max_wall_time_seconds:
                        reason = Reason.TIMEOUT
                        break
                    for key, _ in selector.select(.02):
                        name = key.data
                        fd = key.fd
                        if name == 'in':
                            try:
                                input_offset += os.write(fd, payload[input_offset:input_offset+65536])
                            except BrokenPipeError:
                                input_offset = len(payload)
                            if input_offset >= len(payload):
                                selector.unregister(key.fileobj); proc.stdin.close()
                            continue
                        try: chunk = os.read(fd, 8192)
                        except BlockingIOError: continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        if name == 'life':
                            buffers[name].extend(chunk[:1024-len(buffers[name])])
                        else:
                            remaining = max(0, policy.max_output_bytes-total)
                            buffers[name].extend(chunk[:remaining]); total += len(chunk)
                            if total > policy.max_output_bytes: reason = Reason.OUTPUT_FLOOD
                    if reason is not None: break
                    if proc.poll() is not None and not selector.get_map(): break
                confirmed = b'STARTED\n' in buffers['life']
                if reason is None:
                    try: proc.wait(timeout=max(.01, policy.max_wall_time_seconds-(time.monotonic()-started_at)))
                    except subprocess.TimeoutExpired: reason = Reason.TIMEOUT
            except (OSError, ValueError) as exc:
                buffers['err'].extend(str(exc).encode()[:policy.max_output_bytes])
                reason = Reason.SANDBOX_UNAVAILABLE if proc is None else Reason.UNCERTAIN_CLEANUP
            finally:
                if proc:
                    # Kill the launcher and stable init; detached workload sessions
                    # remain members of the init's PID namespace and die with it.
                    for fd in init_pidfds:
                        try: signal.pidfd_send_signal(fd, signal.SIGKILL)
                        except ProcessLookupError: pass
                    if proc.poll() is None:
                        try: os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                    try: proc.wait(timeout=2)
                    except subprocess.TimeoutExpired: cleaned = False
                    import select
                    for fd in init_pidfds:
                        if not select.select([fd], [], [], 2)[0]: cleaned = False
                        os.close(fd)
                    for stream in (proc.stdin, proc.stdout, proc.stderr):
                        if stream: stream.close()
                selector.close()
                os.close(lifecycle_r)
                if lifecycle_w >= 0: os.close(lifecycle_w)
            if not cleaned: reason = Reason.UNCERTAIN_CLEANUP
            elif not confirmed:
                reason = Reason.SANDBOX_UNAVAILABLE if reason not in (Reason.TIMEOUT, Reason.OUTPUT_FLOOD) else Reason.UNCERTAIN_CLEANUP
            elif reason is None: reason = Reason.SUCCESS if proc.returncode == 0 else Reason.EXIT_ERROR
            out, err = (bytes(buffers[k]).decode('utf-8', errors='replace') for k in ('out','err'))
            # Include supervisor diagnostics inside the same combined byte ceiling.
            notice = ('Output exceeded ceiling' if reason == Reason.OUTPUT_FLOOD else
                      'Wall time exceeded ceiling' if reason == Reason.TIMEOUT else '')
            notice_bytes = notice.encode()[:policy.max_output_bytes]
            remaining = policy.max_output_bytes - len(notice_bytes)
            out_bytes = out.encode()[:remaining]
            err_bytes = err.encode()[:remaining-len(out_bytes)]
            out = out_bytes.decode('utf-8', errors='ignore')
            err = err_bytes.decode('utf-8', errors='ignore') + notice_bytes.decode()
            data = None
            try: data = json.loads(out)
            except (ValueError, TypeError): pass
            usage = {}
            for line in bytes(buffers['life']).splitlines():
                if line.startswith(b'USAGE '):
                    try: usage = json.loads(line[6:])
                    except ValueError: pass
            return SandboxResult(proc.returncode if proc else None, out, err, reason,
                cleaned_up=cleaned, execution_confirmed=confirmed, data=data,
                duration_seconds=time.monotonic()-started_at,
                peak_memory_bytes=usage.get("peak_memory_bytes",0),cpu_seconds=usage.get("cpu_seconds",0.0))


class RootlessContainerRunner(OfflineSandboxRunner):
    """Bubblewrap creates a rootless mount/PID/network container; never pulls images."""
    tier = 'ROOTLESS_CONTAINER'

    def _command(self, config, scratch, policy):
        import sysconfig
        paths = [os.path.realpath(sys.executable), sysconfig.get_path('stdlib'),
                 '/usr/lib/x86_64-linux-gnu', '/usr/lib/aarch64-linux-gnu',
                 '/lib64/ld-linux-x86-64.so.2', self._launcher_path, config]
        # Use the base interpreter so a host virtualenv root is never mounted.
        cmd = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--as-pid-1',
               '--tmpfs', '/', '--proc', '/proc', '--dev', '/dev']
        for path in dict.fromkeys(paths + list(policy.allowed_read_paths)):
            if os.path.exists(path): cmd += ['--ro-bind', os.path.realpath(path), path]
        for path in dict.fromkeys([scratch] + list(policy.allowed_write_paths)):
            cmd += ['--bind', path, path]
        cmd += ['--', os.path.realpath(sys.executable), '-I', '-S', self._launcher_path, config]
        return cmd
