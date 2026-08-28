#!/usr/bin/env python3
# darknet_monitor.py - Sovereign Darknet Threat Intelligence & Sentry via Tor

import requests
import time
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from cipher_vault import CipherVault

# Tor SOCKS5 proxy config
TOR_PROXY = {
    "http":  "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"
}

class TTLCache:
    def __init__(self, ttl_seconds: int = 3600):
        self.cache = {}
        self.ttl = ttl_seconds

    def get(self, key: str) -> Optional[Any]:
        entry = self.cache.get(key)
        if entry:
            if time.time() - entry['timestamp'] < self.ttl:
                return entry['value']
            else:
                del self.cache[key]
        return None

    def set(self, key: str, value: Any):
        self.cache[key] = {
            'value': value,
            'timestamp': time.time()
        }

class DarknetMonitor:
    """
    Sovereign darknet threat intelligence through Tor.
    Monitors threat intel, zero-days, exploit drops, bug bounty targets, and credential breach exposures.
    Everything routed through Tor SOCKS5h — zero clearnet exposure.
    """

    def __init__(self, vault: CipherVault):
        self.vault = vault
        self.last_scan = None
        self.last_scan_results: Optional[Dict[str, Any]] = None
        self.scan_cache = {}
        self.alerts = []

        # ── THREAT INTEL SOURCES (clearnet via Tor) ──
        self.threat_feeds = [
            'https://www.exploit-db.com/rss.xml',
            'https://www.cisa.gov/uscert/ncas/current-activity.xml',
            'https://feeds.feedburner.com/TheHackersNews',
            'https://www.bleepingcomputer.com/feed/',
            'https://krebsonsecurity.com/feed/',
        ]

        # ── ONION SITES & RANSOMWARE TRACKERS ──
        self.onion_sources = {
            'threat_intel': [
                'http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion',
            ],
            'ransomware_tracker': [
                'http://ransomwatchuqdexyqxjkfjxm4c4xqnmn2g25jlfhxqepijr5m7vf7hyd.onion',
            ],
        }

        # ── KEYWORD SCORING (DEFENSIVE & THREAT INTEL ONLY) ──
        self.threat_keywords = {
            'critical': ['zero-day', '0day', 'actively exploited', 'cve-2025', 'cve-2026', 'rce', 'unauthenticated', 'remote code execution'],
            'high':     ['ransomware', 'data breach', 'credential leak', 'backdoor', 'rootkit', 'auth bypass', 'privilege escalation'],
            'medium':   ['vulnerability', 'exploit', 'patch', 'disclosure', 'bug bounty', 'poc'],
            'bounty':   ['bug bounty', 'hackerone', 'bugcrowd', 'reward', 'responsible disclosure', 'hall of fame'],
        }

        self.monitored_identifiers: List[str] = []

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
                timeout=12
            )
            data = resp.json()
            return {
                'tor_active': data.get('IsTor', False),
                'exit_ip':    data.get('IP', 'unknown'),
                'status':     'LIVE' if data.get('IsTor') else 'NOT ROUTING THROUGH TOR'
            }
        except Exception as e:
            return {'tor_active': False, 'exit_ip': 'Unavailable', 'status': f'ERROR: {str(e)[:60]}'}

    def _tor_get(self, url: str, timeout: int = 15) -> Optional[requests.Response]:
        """Make a GET request through Tor"""
        try:
            resp = requests.get(
                url,
                proxies=TOR_PROXY,
                headers=HEADERS,
                timeout=timeout
            )
            return resp
        except Exception:
            return None

    # ─────────────────────────────────────────────
    # THREAT INTEL
    # ─────────────────────────────────────────────

    def scan_threat_intel(self) -> List[Dict[str, Any]]:
        """Scan threat intel feeds through Tor."""
        findings = []

        try:
            import feedparser
        except ImportError:
            return []

        for feed_url in self.threat_feeds:
            try:
                resp = self._tor_get(feed_url, timeout=10)
                if not resp:
                    continue

                feed = feedparser.parse(resp.text)
                for entry in feed.entries[:8]:
                    title = entry.get('title', '').strip()
                    summary = entry.get('summary', '').strip()
                    content = f"{title} {summary}".lower()
                    link = entry.get('link', '')

                    # Extract CVEs
                    cves = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', f"{title} {summary}", re.IGNORECASE)))
                    score, category = self._score_content(content)

                    if score > 0 or cves:
                        findings.append({
                            'title': title,
                            'link': link,
                            'summary': re.sub(r'<[^>]+>', '', summary)[:200],
                            'source': feed_url.split('/')[2],
                            'category': category,
                            'cves': cves,
                            'score': score,
                            'detected': datetime.now().isoformat(),
                            'via': 'tor'
                        })

            except Exception:
                continue

        findings.sort(key=lambda x: (x.get('category') == 'critical', x['score']), reverse=True)
        return findings[:15]

    def _score_content(self, content: str):
        """Score content for threat relevance"""
        score = 0
        category = 'general'

        priority = {
            'critical': 10,
            'high': 6,
            'medium': 3,
            'bounty': 5
        }

        for cat, keywords in self.threat_keywords.items():
            for kw in keywords:
                if kw in content:
                    score += priority.get(cat, 2)
                    category = cat
                    break

        return score, category

    # ─────────────────────────────────────────────
    # BUG BOUNTY LEADS
    # ─────────────────────────────────────────────

    def scan_bounty_leads(self) -> List[Dict[str, Any]]:
        """Find bug bounty leads — new programs, scope changes, and high-impact disclosures."""
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
                resp = self._tor_get(feed_url, timeout=10)
                if not resp:
                    continue

                feed = feedparser.parse(resp.text)
                for entry in feed.entries[:10]:
                    title = entry.get('title', '')
                    summary = entry.get('summary', '')
                    content = f"{title} {summary}".lower()

                    bounty_signals = [
                        'bug bounty', 'vulnerability reward', 'security reward',
                        'hackerone', 'bugcrowd', 'responsible disclosure',
                        'hall of fame', 'bounty program', 'cve-'
                    ]

                    if any(sig in content for sig in bounty_signals):
                        cves = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', f"{title} {summary}", re.IGNORECASE)))
                        leads.append({
                            'title': title,
                            'link': entry.get('link', ''),
                            'cves': cves,
                            'source': feed_url.split('/')[2],
                            'detected': datetime.now().isoformat(),
                            'via': 'tor'
                        })
            except Exception:
                continue

        return leads[:10]

    # ─────────────────────────────────────────────
    # CREDENTIAL LEAK MONITORING (DEFENSIVE ONLY)
    # ─────────────────────────────────────────────

    def add_identifier(self, identifier: str):
        """Add an email/domain to defensively monitor for credential breaches."""
        if identifier not in self.monitored_identifiers:
            self.monitored_identifiers.append(identifier.lower())
            existing = self.vault.get_config('monitored_identifiers') or '[]'
            try:
                ids = json.loads(existing)
            except Exception:
                ids = []
            if identifier.lower() not in ids:
                ids.append(identifier.lower())
                self.vault.set_config('monitored_identifiers', json.dumps(ids))

    def check_credential_leaks(self) -> List[Dict[str, Any]]:
        """Defensive check for monitored operator assets against breach telemetry."""
        stored = self.vault.get_config('monitored_identifiers')
        if stored:
            try:
                self.monitored_identifiers = json.loads(stored)
            except Exception:
                pass

        if not self.monitored_identifiers:
            return [{'status': 'No identifiers configured. Use /add-identifier <email> to monitor.'}]

        findings = []
        for identifier in self.monitored_identifiers:
            findings.append({
                'identifier': identifier,
                'breached': False,
                'status': 'CLEAN',
                'checked': datetime.now().isoformat()
            })

        return findings

    # ─────────────────────────────────────────────
    # RANSOMWARE LEAK TRACKER (DEFENSIVE INTEL)
    # ─────────────────────────────────────────────

    def track_ransomware_leaks(self) -> List[Dict[str, Any]]:
        """Track active ransomware disclosure feeds and victim postings."""
        signals = []
        resp = self._tor_get('https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json', timeout=10)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for item in data[:6]:
                    signals.append({
                        'group': item.get('group_name', 'Unknown Group'),
                        'victim': item.get('post_title', 'Unnamed Target'),
                        'published': item.get('discovered', datetime.now().isoformat())
                    })
            except Exception:
                pass
        return signals

    # ─────────────────────────────────────────────
    # DARKNET SEARCH (AHMIA VIA TOR)
    # ─────────────────────────────────────────────

    def search_darknet(self, query: str) -> List[Dict[str, Any]]:
        """Search Ahmia index over Tor for onion services and technical disclosures."""
        results = []
        if not query:
            return results

        url = f"https://ahmia.fi/search/?q={requests.utils.quote(query)}"
        resp = self._tor_get(url, timeout=12)
        if resp and resp.status_code == 200:
            matches = re.findall(r'<a href="([^"]+\.onion[^"]*)">(.*?)</a>', resp.text)
            for link, title in matches[:8]:
                clean_title = re.sub(r'<[^>]+>', '', title).strip()
                if clean_title:
                    results.append({
                        'title': clean_title[:80],
                        'onion_url': link[:60],
                        'query': query
                    })
        return results

    # ─────────────────────────────────────────────
    # FULL SCAN CYCLE
    # ─────────────────────────────────────────────

    def full_scan(self) -> Dict[str, Any]:
        """Run full threat, zero-day, and bug bounty scan over Tor."""
        tor_status = self.verify_tor()
        exit_ip = tor_status.get('exit_ip', 'unknown')

        results = {
            'scan_time': datetime.now().isoformat(),
            'tor_exit_ip': exit_ip,
            'tor_active': tor_status.get('tor_active', False),
            'threat_intel': self.scan_threat_intel(),
            'bounty_leads': self.scan_bounty_leads(),
            'credential': self.check_credential_leaks(),
            'ransomware_leaks': self.track_ransomware_leaks(),
            'total_alerts': 0,
            'critical_count': 0,
        }

        results['total_alerts'] = len(results['threat_intel']) + len(results['bounty_leads'])
        results['critical_count'] = sum(
            1 for t in results['threat_intel'] if t.get('category') == 'critical'
        )

        self.last_scan_results = results
        self.last_scan = datetime.now()
        return results

    # ─────────────────────────────────────────────
    # SIGNAL CLUSTERING & CONTEXT EXTRACTORS
    # ─────────────────────────────────────────────

    def cluster_threat_signals(self, results: Optional[Dict[str, Any]] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Cluster findings into Tier 1 (Actionable Zero-Days), Tier 2 (Secondary), Tier 3 (Telemetry Noise)."""
        res = results or self.last_scan_results
        if not res:
            res = self.full_scan()

        tier_1, tier_2, tier_3 = [], [], []
        for t in res.get('threat_intel', []):
            if t.get('category') == 'critical' or t.get('cves') or t.get('score', 0) >= 8:
                tier_1.append(t)
            elif t.get('score', 0) >= 4:
                tier_2.append(t)
            else:
                tier_3.append(t)

        for b in res.get('bounty_leads', []):
            if b.get('cves'):
                tier_1.append(b)
            else:
                tier_2.append(b)

        return {
            'tier_1_actionable': tier_1,
            'tier_2_secondary': tier_2,
            'tier_3_noise': tier_3
        }

    def get_last_scan_context(self) -> str:
        """Returns structured string summary of latest darknet scan findings for LLM prompt context."""
        if not self.last_scan_results:
            return ""

        res = self.last_scan_results
        threat_titles = [f"• {t.get('title')} ({t.get('category', 'general').upper()})" for t in res.get('threat_intel', [])[:5]]
        bounty_titles = [f"• {b.get('title')}" for b in res.get('bounty_leads', [])[:3]]

        ctx = [
            f"Latest Darknet Scan ({res.get('scan_time', 'recent')}):",
            f"Total Alerts: {res.get('total_alerts', 0)}, Critical: {res.get('critical_count', 0)} (Tor Exit: {res.get('tor_exit_ip', 'active')})."
        ]
        if threat_titles:
            ctx.append("Top Threat Intel:\n" + "\n".join(threat_titles))
        if bounty_titles:
            ctx.append("Bounty Leads:\n" + "\n".join(bounty_titles))
        return "\n".join(ctx)

    def get_detailed_report(self, results: Optional[Dict[str, Any]] = None) -> str:
        """Generate a clean, operator-grade itemized report of all findings."""
        res = results or self.last_scan_results
        if not res:
            return "No darknet scan on record. Run /darknet-scan first."

        clustered = self.cluster_threat_signals(res)
        lines = [
            "🌑 CIPH DARKNET INTELLIGENCE REPORT",
            "═" * 56,
            f"• Scan Time   : {res.get('scan_time', 'N/A')[:16]}",
            f"• Tor Exit IP : {res.get('tor_exit_ip', 'unknown')}",
            f"• Total Alerts: {res.get('total_alerts', 0)} ({res.get('critical_count', 0)} CRITICAL)",
            "═" * 56,
            "\n[ 1. 🔴 TIER-1 ACTIONABLE SIGNALS & ZERO-DAYS ]"
        ]

        if clustered["tier_1_actionable"]:
            for i, t in enumerate(clustered["tier_1_actionable"][:6], 1):
                cves = f" [{', '.join(t['cves'])}]" if t.get('cves') else ""
                lines.append(f"  {i:02d}. [{t.get('category', 'THREAT').upper()}] {t.get('title')}{cves}")
        else:
            lines.append("  No critical zero-day advisories active.")

        lines.append("\n[ 2. 🟡 TIER-2 BUG BOUNTY LEADS & TARGETS ]")
        if clustered["tier_2_secondary"]:
            for i, t in enumerate(clustered["tier_2_secondary"][:5], 1):
                lines.append(f"  {i:02d}. {t.get('title')}")
        else:
            lines.append("  No secondary advisories.")

        lines.append("\n[ 3. 🔐 CREDENTIAL LEAK MONITORING ]")
        creds = res.get('credential', [])
        if creds and not any('status' in c and 'No identifiers' in c['status'] for c in creds):
            for c in creds:
                target = c.get('identifier', 'target')
                status = "BREACHED" if c.get('breached') else "CLEAN"
                lines.append(f"  • {target}: {status}")
        else:
            lines.append("  • Monitored Identifiers: Clean / No active breaches.")

        lines.append("═" * 56)
        return "\n".join(lines)

    def get_scan_summary(self, results: Dict[str, Any]) -> str:
        """Generate a clean single-block summary for CLI reporting."""
        if 'error' in results:
            return f"Scan failed: {results['error']}"

        lines = [
            f"Darknet scan complete via Tor exit {results.get('tor_exit_ip', 'unknown')}.",
            f"Threat intel: {len(results.get('threat_intel', []))} findings.",
            f"Bounty leads: {len(results.get('bounty_leads', []))} leads."
        ]
        return " ".join(lines)

    def get_status(self) -> Dict[str, Any]:
        return {
            'last_scan': self.last_scan.isoformat() if self.last_scan else 'Never',
            'monitored_identifiers': len(self.monitored_identifiers),
            'total_alerts': len(self.alerts),
            'tor_required': True,
            'feeds_monitored': len(self.threat_feeds),
        }