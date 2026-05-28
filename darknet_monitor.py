#!/usr/bin/env python3
# darknet_monitor.py - Darknet intelligence via Tor (generic version)

import requests
import time
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from cipher_vault import CipherVault

# Tor SOCKS5 proxy config (default Tor installation)
TOR_PROXY = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
}

class DarknetMonitor:
    """
    Darknet intelligence through Tor.
    Monitors threat intel, bug bounty leads, credential leaks, market trends.
    All requests are routed through Tor for anonymity.
    """

    def __init__(self, vault: CipherVault):
        self.vault        = vault
        self.last_scan    = None
        self.scan_cache   = {}
        self.alerts       = []

        # ── THREAT INTEL SOURCES (clearnet via Tor) ──
        # Public security feeds accessed anonymously through Tor
        self.threat_feeds = [
            'https://www.exploit-db.com/rss.xml',
            'https://www.cisa.gov/uscert/ncas/current-activity.xml',
            'https://feeds.feedburner.com/TheHackersNews',
            'https://www.bleepingcomputer.com/feed/',
            'https://krebsonsecurity.com/feed/',
        ]

        # ── ONION SOURCES — active darknet intel aggregators ──
        self.onion_sources = {
            'threat_intel': [
                # Dark.fail mirror index — lists active onion services
                'http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion',
            ],
            'ransomware_tracker': [
                # Ransomwatch — tracks ransomware group activity
                'http://ransomwatchuqdexyqxjkfjxm4c4xqnmn2g25jlfhxqepijr5m7vf7hyd.onion',
            ],
        }

        # ── KEYWORD SCORING ──
        self.threat_keywords = {
            'critical':  ['zero-day', '0day', 'actively exploited', 'cve-2025', 'rce', 'unauthenticated'],
            'high':      ['ransomware', 'data breach', 'credential leak', 'backdoor', 'rootkit'],
            'medium':    ['vulnerability', 'exploit', 'patch', 'disclosure', 'bug bounty'],
            'bounty':    ['bug bounty', 'hackerone', 'bugcrowd', 'reward', 'hall of fame'],
            'market':    ['darknet market', 'vendor', 'listing', 'escrow', 'monero', 'xmr'],
        }

        # ── CREDENTIAL LEAK PATTERNS ──
        # Only checks for the user's own identifiers — never used to look up others
        self.monitored_identifiers: List[str] = []  # Add with add_identifier()

    # ─────────────────────────────────────────────
    # TOR CONNECTION
    # ─────────────────────────────────────────────

    def verify_tor(self) -> Dict[str, Any]:
        """Verify Tor is routing correctly"""
        try:
            resp = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=TOR_PROXY,
                headers=HEADERS,
                timeout=15
            )
            data = resp.json()
            return {
                'tor_active': data.get('IsTor', False),
                'exit_ip':    data.get('IP', 'unknown'),
                'status':     'LIVE' if data.get('IsTor') else 'NOT ROUTING THROUGH TOR'
            }
        except Exception as e:
            return {'tor_active': False, 'status': f'ERROR: {str(e)[:60]}'}

    def _tor_get(self, url: str, timeout: int = 20) -> Optional[requests.Response]:
        """Make a GET request through Tor"""
        try:
            resp = requests.get(
                url,
                proxies=TOR_PROXY,
                headers=HEADERS,
                timeout=timeout
            )
            return resp
        except requests.Timeout:
            print(f"  ⏱ Timeout: {url[:60]}")
            return None
        except Exception as e:
            print(f"  ✗ Failed: {url[:60]} — {str(e)[:40]}")
            return None

    # ─────────────────────────────────────────────
    # THREAT INTEL
    # ─────────────────────────────────────────────

    def scan_threat_intel(self) -> List[Dict[str, Any]]:
        """
        Scan threat intel feeds through Tor.
        Returns scored, ranked alerts.
        """
        print("🕵️  Scanning threat intel via Tor...")
        findings = []

        try:
            import feedparser
        except ImportError:
            print("  ✗ feedparser not installed: pip install feedparser")
            return []

        for feed_url in self.threat_feeds:
            try:
                resp = self._tor_get(feed_url)
                if not resp:
                    continue

                feed = feedparser.parse(resp.text)

                for entry in feed.entries[:8]:
                    title   = entry.get('title', '')
                    summary = entry.get('summary', '')
                    content = f"{title} {summary}".lower()
                    link    = entry.get('link', '')

                    score, category = self._score_content(content)

                    if score > 0:
                        findings.append({
                            'title':      title,
                            'link':       link,
                            'source':     feed_url.split('/')[2],
                            'category':   category,
                            'score':      score,
                            'detected':   datetime.now().isoformat(),
                            'via':        'tor'
                        })

                time.sleep(2)  # Polite delay between requests

            except Exception as e:
                print(f"  ✗ Feed error: {str(e)[:50]}")
                continue

        findings.sort(key=lambda x: x['score'], reverse=True)
        return findings[:15]

    def _score_content(self, content: str):
        """Score content for threat relevance"""
        score    = 0
        category = 'general'

        priority = {
            'critical': 10,
            'high':     6,
            'medium':   3,
            'bounty':   5,
            'market':   4,
        }

        for cat, keywords in self.threat_keywords.items():
            for kw in keywords:
                if kw in content:
                    score    += priority.get(cat, 2)
                    category  = cat
                    break

        return score, category

    # ─────────────────────────────────────────────
    # BUG BOUNTY LEADS
    # ─────────────────────────────────────────────

    def scan_bounty_leads(self) -> List[Dict[str, Any]]:
        """
        Find bug bounty leads — new programs, scope changes, high payouts.
        """
        print("💰 Scanning bug bounty leads via Tor...")
        leads = []

        bounty_feeds = [
            'https://www.bleepingcomputer.com/feed/',
            'https://feeds.feedburner.com/TheHackersNews',
        ]

        try:
            import feedparser
        except ImportError:
            return []

        for feed_url in bounty_feeds:
            try:
                resp = self._tor_get(feed_url)
                if not resp:
                    continue

                feed = feedparser.parse(resp.text)

                for entry in feed.entries[:10]:
                    title   = entry.get('title', '')
                    content = f"{title} {entry.get('summary', '')}".lower()

                    bounty_signals = [
                        'bug bounty', 'vulnerability reward', 'security reward',
                        'hackerone', 'bugcrowd', 'responsible disclosure',
                        'hall of fame', 'bounty program', 'cve-'
                    ]

                    if any(sig in content for sig in bounty_signals):
                        # Extract CVE if present
                        cves = re.findall(r'CVE-\d{4}-\d+', title + entry.get('summary', ''), re.IGNORECASE)

                        leads.append({
                            'title':    title,
                            'link':     entry.get('link', ''),
                            'cves':     cves,
                            'source':   feed_url.split('/')[2],
                            'detected': datetime.now().isoformat(),
                            'via':      'tor'
                        })

                time.sleep(1)

            except Exception:
                continue

        return leads[:10]

    # ─────────────────────────────────────────────
    # CREDENTIAL LEAK MONITORING
    # ─────────────────────────────────────────────

    def add_identifier(self, identifier: str):
        """
        Add an email/username to monitor for credential leaks.
        Only for your own identifiers.
        """
        if identifier not in self.monitored_identifiers:
            self.monitored_identifiers.append(identifier.lower())
            # Store encrypted in vault
            existing = self.vault.get_config('monitored_identifiers') or '[]'
            ids = json.loads(existing)
            if identifier.lower() not in ids:
                ids.append(identifier.lower())
                self.vault.set_config('monitored_identifiers', json.dumps(ids))
            print(f"  ✓ Monitoring: {identifier}")

    def check_credential_leaks(self) -> List[Dict[str, Any]]:
        """
        Check if monitored identifiers appear in public breach data.
        Uses HaveIBeenPwned API through Tor.
        """
        print("🔐 Checking credential leaks via Tor...")

        stored = self.vault.get_config('monitored_identifiers')
        if stored:
            self.monitored_identifiers = json.loads(stored)

        if not self.monitored_identifiers:
            return [{'status': 'No identifiers configured. Use add_identifier() first.'}]

        findings = []

        for identifier in self.monitored_identifiers:
            try:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{identifier}"
                hibp_key = self.vault.get_config("HIBP_API_KEY") or ''
                headers = {**HEADERS, 'hibp-api-key': hibp_key}

                resp = self._tor_get(url, timeout=15)

                if resp and resp.status_code == 200:
                    breaches = resp.json()
                    findings.append({
                        'identifier':    identifier,
                        'breached':      True,
                        'breach_count':  len(breaches),
                        'breaches':      [b['Name'] for b in breaches[:5]],
                        'risk':          'HIGH' if len(breaches) > 3 else 'MEDIUM',
                        'checked':       datetime.now().isoformat()
                    })
                    self._store_alert('CREDENTIAL_LEAK', f"{identifier} found in {len(breaches)} breaches", 'HIGH')

                elif resp and resp.status_code == 404:
                    findings.append({
                        'identifier': identifier,
                        'breached':   False,
                        'status':     'CLEAN',
                        'checked':    datetime.now().isoformat()
                    })

                time.sleep(2)  # HIBP rate limit

            except Exception as e:
                findings.append({
                    'identifier': identifier,
                    'error':      str(e)[:60]
                })

        return findings

    # ─────────────────────────────────────────────
    # MARKET MONITORING
    # ─────────────────────────────────────────────

    def scan_market_trends(self) -> Dict[str, Any]:
        """
        Monitor darknet market trends — pricing, activity levels, emerging threats.
        Uses public aggregator sites through Tor, not direct market access.
        """
        print("📊 Scanning market trends via Tor...")

        trends = {
            'scan_time':         datetime.now().isoformat(),
            'ransomware_active': [],
            'market_signals':    [],
            'via':               'tor'
        }

        # Dark.fail — lists active services (public aggregator)
        resp = self._tor_get(
            'https://dark.fail',
            timeout=25
        )

        if resp and resp.status_code == 200:
            content = resp.text.lower()

            service_patterns = [
                'market', 'forum', 'exchange', 'wallet',
                'escrow', 'mixer', 'tumbler'
            ]

            for pattern in service_patterns:
                count = content.count(pattern)
                if count > 2:
                    trends['market_signals'].append({
                        'type':     pattern,
                        'mentions': count
                    })

        self._store_alert(
            'MARKET_SCAN',
            f"Market scan complete. Signals: {len(trends['market_signals'])}",
            'LOW'
        )

        return trends

    # ─────────────────────────────────────────────
    # FULL SCAN CYCLE
    # ─────────────────────────────────────────────

    def full_scan(self) -> Dict[str, Any]:
        """
        Run all four monitoring modules in sequence.
        This is what /darknet-scan calls.
        """
        print("\n🌑 DARKNET SCAN INITIATED")
        print("=" * 50)

        tor_status = self.verify_tor()
        if not tor_status['tor_active']:
            return {
                'error':  'Tor not routing. Run: sudo systemctl start tor',
                'status': 'FAILED'
            }

        print(f"✓ Tor active. Exit IP: {tor_status['exit_ip']}\n")

        results = {
            'scan_time':      datetime.now().isoformat(),
            'tor_exit_ip':    tor_status['exit_ip'],
            'threat_intel':   [],
            'bounty_leads':   [],
            'credential':     [],
            'market_trends':  {},
            'total_alerts':   0,
            'critical_count': 0,
        }

        results['threat_intel'] = self.scan_threat_intel()
        print(f"✓ Threat intel: {len(results['threat_intel'])} findings\n")

        results['bounty_leads'] = self.scan_bounty_leads()
        print(f"✓ Bounty leads: {len(results['bounty_leads'])} leads\n")

        results['credential'] = self.check_credential_leaks()
        print(f"✓ Credential check: complete\n")

        results['market_trends'] = self.scan_market_trends()
        print(f"✓ Market trends: {len(results['market_trends'].get('market_signals', []))} signals\n")

        results['total_alerts']   = len(results['threat_intel']) + len(results['bounty_leads'])
        results['critical_count'] = sum(
            1 for t in results['threat_intel'] if t.get('category') == 'critical'
        )

        self.vault.store_conversation(
            "DARKNET_SCAN",
            f"Threats: {len(results['threat_intel'])} | Bounty: {len(results['bounty_leads'])} | Critical: {results['critical_count']}",
            "darknet"
        )

        self.last_scan = datetime.now()

        print(f"🌑 SCAN COMPLETE — {results['total_alerts']} total alerts, {results['critical_count']} critical")
        print("=" * 50)

        return results

    def get_scan_summary(self, results: Dict[str, Any]) -> str:
        """Generate a readable summary to report back"""
        if 'error' in results:
            return f"Scan failed: {results['error']}"

        lines = [
            f"Darknet scan complete via Tor exit {results.get('tor_exit_ip', 'unknown')}.",
            f"Threat intel: {len(results.get('threat_intel', []))} findings.",
        ]

        threats = results.get('threat_intel', [])
        if threats:
            top = threats[0]
            lines.append(f"Top signal: {top['title'][:80]} ({top['category'].upper()}, score {top['score']}).")

        bounty = results.get('bounty_leads', [])
        if bounty:
            lines.append(f"Bug bounty leads: {len(bounty)} found.")
            cves = [c for lead in bounty for c in lead.get('cves', [])]
            if cves:
                lines.append(f"CVEs detected: {', '.join(cves[:3])}.")

        creds = results.get('credential', [])
        breached = [c for c in creds if c.get('breached')]
        if breached:
            lines.append(f"ALERT: {len(breached)} identifier(s) found in breach data.")
        elif creds and not any('error' in c for c in creds):
            lines.append("Credential check: clean.")

        return ' '.join(lines)

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _store_alert(self, alert_type: str, message: str, risk: str):
        """Store alert in vault"""
        self.alerts.append({
            'type':    alert_type,
            'message': message,
            'risk':    risk,
            'time':    datetime.now().isoformat()
        })
        if risk in ('HIGH', 'CRITICAL'):
            self.vault.store_conversation(
                f"DARKNET_ALERT: {alert_type}",
                message,
                "darknet_alert"
            )

    def get_status(self) -> Dict[str, Any]:
        return {
            'last_scan':             self.last_scan.isoformat() if self.last_scan else 'Never',
            'monitored_identifiers': len(self.monitored_identifiers),
            'total_alerts':          len(self.alerts),
            'tor_required':          True,
            'feeds_monitored':       len(self.threat_feeds),
        }


if __name__ == "__main__":
    from cipher_vault import CipherVault
    vault   = CipherVault()
    monitor = DarknetMonitor(vault)

    print("🧪 Testing Darknet Monitor...")

    print("\n1. Verifying Tor...")
    tor = monitor.verify_tor()
    print(f"   Status: {tor['status']}")
    print(f"   Exit IP: {tor.get('exit_ip', 'N/A')}")

    if tor['tor_active']:
        print("\n2. Running full scan...")
        results = monitor.full_scan()
        print("\n3. Summary:")
        print(monitor.get_scan_summary(results))
    else:
        print("   Tor not active. Run: sudo systemctl start tor")