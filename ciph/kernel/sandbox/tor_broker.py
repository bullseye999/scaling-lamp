"""Trusted read-only HTTP broker. DNS and pinned public-IP connections use Tor only.

No caller headers, redirects, cookies, credentials, local DNS or clearnet fallback.
Tor RESOLVE extension: https://spec.torproject.org/socks-extensions.html
"""
import base64
import hashlib
import http.client
import ipaddress
import socket
import ssl
import struct
import time
from ciph.perception.external_sources import validate_url, public_address

class TorUnavailableError(RuntimeError):
    pass

class TorEvidenceBroker:
    def __init__(self, *, socks_port=9050):
        if not isinstance(socks_port, int) or not 1 <= socks_port <= 65535:
            raise ValueError('INVALID_TOR_PORT')
        self.socks_port = socks_port  # trusted host configuration, never task input

    @staticmethod
    def _read(sock, n):
        out = bytearray()
        while len(out) < n:
            chunk = sock.recv(n-len(out))
            if not chunk: raise TorUnavailableError('TRUNCATED_TOR_REPLY')
            out.extend(chunk)
        return bytes(out)

    def _request(self, command, address, port, timeout, register=lambda sock: None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        register(sock)
        sock.settimeout(timeout)
        try:
            # Numeric loopback only. No getaddrinfo call can leak target DNS.
            sock.connect(('127.0.0.1', self.socks_port))
            sock.sendall(b'\x05\x01\x00')
            if self._read(sock, 2) != b'\x05\x00': raise TorUnavailableError('TOR_HANDSHAKE_REJECTED')
            sock.sendall(b'\x05' + bytes([command]) + b'\x00' + address + struct.pack('!H',port))
            header = self._read(sock,4)
            if header[:3] != b'\x05\x00\x00': raise TorUnavailableError('TOR_REQUEST_REJECTED')
            if header[3] not in (1,4): raise TorUnavailableError('TOR_IP_REPLY_REQUIRED')
            reply = self._read(sock,4 if header[3] == 1 else 16)
            self._read(sock,2)
            return sock, ipaddress.ip_address(reply)
        except Exception:
            sock.close(); raise

    def fetch(self, source, *, target, scope):
        u = validate_url(source.url)
        if target != u.hostname or scope is None or scope.is_expired() or not scope.is_target_permitted(target):
            raise ValueError('EXTERNAL_TARGET_OUT_OF_SCOPE')
        deadline = time.monotonic() + source.timeout_seconds
        remaining = lambda: max(.001, deadline-time.monotonic())
        # This wall-clock watchdog closes even a slow-drip reply. Socket timeouts
        # alone are inactivity limits, not a total transaction deadline.
        import threading
        sockets = []
        def stop():
            for s in sockets:
                try: s.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                s.close()
        watchdog = threading.Timer(source.timeout_seconds, stop)
        watchdog.daemon=True; watchdog.start()
        try:
            try: address = ipaddress.ip_address(target)
            except ValueError:
                name = target.encode('ascii')
                sock, address = self._request(0xF0, b'\x03'+bytes([len(name)])+name, 0, remaining(), sockets.append)
                sockets.append(sock); sock.close()
            if not public_address(address): raise ValueError('TOR_RESOLVED_NON_PUBLIC_TARGET')
            packed = bytes([1 if address.version == 4 else 4]) + address.packed
            sock, _ = self._request(1, packed, u.port or (443 if u.scheme=='https' else 80), remaining(), sockets.append)
            sockets.append(sock)
            if u.scheme == 'https':
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=target)
                sockets.append(sock)
            sock.settimeout(remaining())
            path = u.path or '/'
            if u.query: path += '?' + u.query
            request = f'GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\nAccept-Encoding: identity\r\nUser-Agent: CIPH-Evidence/1\r\n\r\n'
            sock.sendall(request.encode('ascii'))
            response = http.client.HTTPResponse(sock)
            response.begin()
            if 300 <= response.status < 400: raise ValueError('REDIRECT_REQUIRES_SEPARATE_APPROVED_SOURCE')
            if response.getheader('Content-Encoding', 'identity').lower() != 'identity': raise ValueError('ENCODED_RESPONSE_REJECTED')
            body = response.read(source.max_bytes+1)
            if len(body) > source.max_bytes: raise ValueError('EXTERNAL_RESPONSE_LIMIT')
            if time.monotonic() > deadline: raise TorUnavailableError('TOR_DEADLINE')
            return {'source': source.url, 'subject': target, 'predicate': 'http_response',
                    'value': {'status': response.status, 'body_base64': base64.b64encode(body).decode(),
                              'body_sha256': hashlib.sha256(body).hexdigest()},
                    'observed_at': time.time()}
        except (OSError, http.client.HTTPException) as exc:
            raise TorUnavailableError('TOR_UNAVAILABLE: ' + type(exc).__name__) from exc
        finally:
            watchdog.cancel(); stop()
