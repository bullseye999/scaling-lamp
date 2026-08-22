#!/usr/bin/env python3
# ghost_transport.py - Fail-Closed Tor SOCKS5h Transport & Remote DNS Resolver

import time
import random
import requests
from typing import Optional, Dict, Any, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
]


class GhostTransport:
    """
    High-performance, Fail-Closed SOCKS5h Tor Transport.
    - Persistent connection pooling (no circuit renegotiation overhead per request)
    - Strict Fail-Closed: Zero clearnet fallback leaks
    - Remote DNS resolution (DNS resolved on Tor exit node, preventing ISP DNS leaks)
    - Anti-fingerprint randomized headers and timing jitter
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(GhostTransport, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, proxy_url: str = TOR_SOCKS_PROXY):
        if getattr(self, '_initialized', False):
            return

        self.proxy_url = proxy_url
        self.proxies = {
            "http": self.proxy_url,
            "https": self.proxy_url
        }
        self.session = self._create_session()
        self._initialized = True

    def _create_session(self) -> requests.Session:
        """Create a pooled requests.Session pre-configured for Tor SOCKS5h."""
        session = requests.Session()
        session.proxies.update(self.proxies)

        retries = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False
        )
        adapter = HTTPAdapter(
            pool_connections=25,
            pool_maxsize=25,
            max_retries=retries
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def get_random_headers(self, custom: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Generate realistic browser headers."""
        base = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        }
        if custom:
            base.update(custom)
        return base

    def request(
        self,
        method: str,
        url: str,
        timeout: int = 12,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        allow_redirects: bool = True,
        jitter: bool = True
    ) -> Optional[requests.Response]:
        """
        Execute an HTTP request strictly over Tor.
        Fails closed (returns None) on error; never makes a clearnet request.
        """
        h = self.get_random_headers(headers)
        if jitter:
            time.sleep(random.uniform(0.05, 0.2))

        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=h,
                params=params,
                data=data,
                json=json_data,
                timeout=timeout,
                allow_redirects=allow_redirects
            )
            return resp
        except Exception:
            # FAIL CLOSED: Do not attempt clearnet fallback
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def resolve_dns_over_tor(self, domain: str, record_type: str = "A") -> List[str]:
        """
        Resolve DNS records remotely via DNS-over-HTTPS (DoH) routed through Tor SOCKS5h.
        Guarantees zero local DNS leaks to the host ISP.
        """
        clean_domain = domain.lower().split(':')[0].strip()
        url = f"https://cloudflare-dns.com/dns-query"
        headers = {"Accept": "application/dns-json"}
        params = {"name": clean_domain, "type": record_type}

        resp = self.get(url, headers=headers, params=params, timeout=8, jitter=False)
        if not resp or resp.status_code != 200:
            return []

        try:
            data = resp.json()
            answers = data.get("Answer", [])
            results = []
            for ans in answers:
                val = ans.get("data", "").strip()
                if val:
                    results.append(val)
            return results
        except Exception:
            return []

    def verify_status(self) -> Dict[str, Any]:
        """Check Tor circuit status, exit IP, and round-trip latency."""
        start_t = time.time()
        resp = self.get("https://check.torproject.org/api/ip", timeout=12, jitter=False)
        latency = round((time.time() - start_t) * 1000, 1)

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                is_tor = data.get("IsTor", False)
                ip = data.get("IP", "Unknown")
                return {
                    "active": is_tor,
                    "exit_ip": ip,
                    "latency_ms": latency,
                    "status": "GHOST_ACTIVE" if is_tor else "PROXY_FAILED"
                }
            except Exception:
                pass

        return {
            "active": False,
            "exit_ip": "Unavailable",
            "latency_ms": latency,
            "status": "TOR_UNREACHABLE"
        }
