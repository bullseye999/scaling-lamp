#!/usr/bin/env python3
# osint_catalog.py - Embedded Anti-Fragile OSINT Catalog & Self-Healing Failover Engine

import time
import requests
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

from ghost_transport import GhostTransport

class OSINTCatalog:
    """
    Anti-Fragile OSINT Catalog.
    Contains embedded knowledge of top public OSINT APIs and data feeds.
    Implements 3-tier automatic failover so Ciph never relies on a single 3rd-party site.
    """

    def __init__(self):
        self.degraded_providers: Set[str] = set()
        self.transport = GhostTransport()

    def _tor_get(self, url: str, timeout: int = 10) -> Optional[requests.Response]:
        return self.transport.get(url, timeout=timeout)

    def query_passive_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Query passive subdomains using 3-tier failover:
        1. crt.sh (Tor)
        2. AlienVault OTX API
        3. HackerTarget API
        """
        clean_domain = domain.lower().split(':')[0]
        subdomains: Set[str] = set()
        provider_used = "None"

        # Tier 1: crt.sh
        if "crt.sh" not in self.degraded_providers:
            try:
                resp = self._tor_get(f"https://crt.sh/?q=%.{clean_domain}&output=json", timeout=12)
                if resp and resp.status_code == 200:
                    for entry in resp.json():
                        nv = entry.get('name_value', '')
                        for sub in nv.splitlines():
                            sub = sub.strip().lower()
                            if sub.startswith('*.'):
                                sub = sub[2:]
                            if sub.endswith(clean_domain) and len(sub) > len(clean_domain):
                                subdomains.add(sub)
                    if subdomains:
                        provider_used = "crt.sh (Tor CT)"
                else:
                    self.degraded_providers.add("crt.sh")
            except Exception:
                self.degraded_providers.add("crt.sh")

        # Tier 2: AlienVault OTX API
        if not subdomains and "alienvault" not in self.degraded_providers:
            try:
                resp = self._tor_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{clean_domain}/passive_dns", timeout=10)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for r in data.get('passive_dns', []):
                        host = r.get('hostname', '').lower()
                        if host.endswith(clean_domain) and len(host) > len(clean_domain):
                            subdomains.add(host)
                    if subdomains:
                        provider_used = "AlienVault OTX"
                else:
                    self.degraded_providers.add("alienvault")
            except Exception:
                self.degraded_providers.add("alienvault")

        # Tier 3: HackerTarget API
        if not subdomains and "hackertarget" not in self.degraded_providers:
            try:
                resp = self._tor_get(f"https://api.hackertarget.com/hostsearch/?q={clean_domain}", timeout=8)
                if resp and resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.splitlines():
                        if "," in line:
                            host = line.split(",")[0].strip().lower()
                            if host.endswith(clean_domain) and len(host) > len(clean_domain):
                                subdomains.add(host)
                    if subdomains:
                        provider_used = "HackerTarget"
                else:
                    self.degraded_providers.add("hackertarget")
            except Exception:
                self.degraded_providers.add("hackertarget")

        return {
            "target": clean_domain,
            "provider_used": provider_used,
            "subdomains": sorted(list(subdomains)),
            "count": len(subdomains)
        }

    def query_historical_urls(self, domain: str, limit: int = 15) -> List[str]:
        """
        Extract historical API endpoints using Wayback Machine CDX API over Tor.
        """
        clean_domain = domain.lower().split(':')[0]
        urls: Set[str] = set()
        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{clean_domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
            resp = self._tor_get(cdx_url, timeout=12)
            if resp and resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:  # Skip header row
                    if row and len(row) > 0:
                        u = row[0]
                        if any(ext in u.lower() for ext in ['/api/', 'swagger', 'v1/', 'v2/', 'graphql', '.json', '.env']):
                            urls.add(u)
        except Exception:
            pass
        return list(urls)

if __name__ == '__main__':
    catalog = OSINTCatalog()
    print('Testing OSINT Catalog...')
    res = catalog.query_passive_subdomains('example.com')
    print(f'Provider: {res["provider_used"]}, Subdomains: {res["count"]}')
