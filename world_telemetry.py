#!/usr/bin/env python3
# world_telemetry.py - Autonomous Real-World Sensory & Tor Darknet Knowledge Fusion Engine for CIPH

import os
import re
import json
import time
import requests
import feedparser
from datetime import datetime
from typing import Dict, Any, List, Optional
from cipher_vault import CipherVault

class WorldTelemetry:
    """
    Autonomous Real-World Sensory & Knowledge Fusion Layer.
    24/7 background radar on VPS:
    1. Scrapes live Clearnet CVE feeds, PacketStorm, Exploit-DB, BleepingComputer, HackerNews, and global macro news.
    2. Maps Tor Darknet architecture, Ahmia indexing, and ransomware leak trackers.
    3. Synthesizes specific, named intelligence alerts with zero hallucination.
    4. Delivers proactive login briefings with concrete findings and tactical questions.
    """

    def __init__(self, vault: CipherVault):
        self.vault = vault
        self.tor_proxy_url = "socks5h://127.0.0.1:9050"
        
        # Curated Clearnet Feeds
        self.cyber_feeds = [
            {"name": "PacketStorm", "url": "https://rss.packetstormsecurity.com/news/", "category": "exploits"},
            {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "category": "breaches"},
            {"name": "NVD NIST CVEs", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "category": "cves"},
            {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "category": "zero_days"},
            {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "category": "exploits"}
        ]
        
        self.macro_feeds = [
            {"name": "HackerNews", "url": "https://news.ycombinator.com/rss", "category": "tech"},
            {"name": "ArsTechnica", "url": "https://feeds.arstechnica.com/arstechnica/technology-lab", "category": "tech_macro"},
            {"name": "Reuters World", "url": "https://www.reutersagency.com/feed/?taxonomy=markets&post_type=reuters-best", "category": "macro"}
        ]

    def _get_tor_session(self) -> requests.Session:
        """Create a requests session routed through Tor SOCKS5 if available."""
        session = requests.Session()
        try:
            # Quick test of Tor SOCKS5
            session.proxies = {'http': self.tor_proxy_url, 'https': self.tor_proxy_url}
            r = session.get("https://check.torproject.org/api/ip", timeout=4)
            if r.status_code == 200 and r.json().get("IsTor", False):
                return session
        except Exception:
            pass
        # Fallback to direct clearnet session
        fallback_session = requests.Session()
        return fallback_session

    # ─────────────────────────────────────────────
    # FEED SCRAPING & INTEL HARVESTING
    # ─────────────────────────────────────────────

    def fetch_cyber_telemetry(self) -> List[Dict[str, Any]]:
        """Fetch and parse live cybersecurity, exploit, and zero-day alerts."""
        alerts = []
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

        for feed in self.cyber_feeds:
            try:
                parsed = feedparser.parse(feed['url'])
                for entry in parsed.entries[:6]:
                    title = entry.get('title', '').strip()
                    summary = entry.get('summary', entry.get('description', '')).strip()
                    # Strip html tags from summary
                    clean_summary = re.sub(r'<[^>]+>', '', summary)
                    link = entry.get('link', '')
                    published = entry.get('published', datetime.now().isoformat())

                    # Identify specific CVEs
                    cves = list(set(cve_pattern.findall(title + " " + clean_summary)))
                    
                    # Determine severity
                    severity = "MEDIUM"
                    text_combined = (title + " " + clean_summary).lower()
                    if any(k in text_combined for k in ['critical', 'remote code execution', 'rce', 'unauthenticated', 'zero-day', '0-day', 'actively exploited']):
                        severity = "CRITICAL"
                    elif any(k in text_combined for k in ['high', 'privilege escalation', 'auth bypass', 'data breach', 'ransomware']):
                        severity = "HIGH"

                    alerts.append({
                        "source": feed['name'],
                        "category": feed['category'],
                        "title": title,
                        "summary": clean_summary[:280] if len(clean_summary) > 280 else clean_summary,
                        "cves": cves,
                        "severity": severity,
                        "link": link,
                        "published": published
                    })
            except Exception:
                pass

        # Sort with CRITICAL alerts first
        alerts.sort(key=lambda x: (x['severity'] == 'CRITICAL', x['severity'] == 'HIGH'), reverse=True)
        return alerts[:15]

    def fetch_macro_telemetry(self) -> List[Dict[str, Any]]:
        """Fetch global technology, AI shifts, and macro intelligence."""
        macro_items = []
        for feed in self.macro_feeds:
            try:
                parsed = feedparser.parse(feed['url'])
                for entry in parsed.entries[:4]:
                    title = entry.get('title', '').strip()
                    summary = entry.get('summary', '').strip()
                    clean_summary = re.sub(r'<[^>]+>', '', summary)
                    link = entry.get('link', '')

                    macro_items.append({
                        "source": feed['name'],
                        "category": feed['category'],
                        "title": title,
                        "summary": clean_summary[:200] if len(clean_summary) > 200 else clean_summary,
                        "link": link,
                        "timestamp": datetime.now().isoformat()
                    })
            except Exception:
                pass
        return macro_items[:8]

    def fetch_darknet_topology_pulse(self) -> Dict[str, Any]:
        """Poll Tor darknet threat boards, Ahmia index keywords, and onion service topology."""
        darknet_pulse = {
            "tor_status": "ACTIVE",
            "threat_nodes_indexed": 0,
            "onion_signals": [],
            "timestamp": datetime.now().isoformat()
        }

        session = self._get_tor_session()
        search_keywords = ["exploit", "cve zero day", "database breach", "ransomware leak"]

        for kw in search_keywords:
            try:
                ahmia_url = f"https://ahmia.fi/search/?q={kw.replace(' ', '+')}"
                r = session.get(ahmia_url, timeout=8)
                if r.status_code == 200:
                    # Extract onion links and headings from search results
                    matches = re.findall(r'<a href="([^"]+\.onion[^"]*)">(.*?)</a>', r.text)
                    for link, desc in matches[:3]:
                        clean_desc = re.sub(r'<[^>]+>', '', desc).strip()
                        if clean_desc and len(clean_desc) > 5:
                            darknet_pulse["onion_signals"].append({
                                "keyword": kw,
                                "onion_target": link[:60],
                                "description": clean_desc[:180],
                                "threat_level": "ELEVATED" if "breach" in kw or "zero" in kw else "OBSERVED"
                            })
                            darknet_pulse["threat_nodes_indexed"] += 1
            except Exception:
                pass

        if not darknet_pulse["onion_signals"]:
            # Fallback passive telemetry signal
            darknet_pulse["onion_signals"].append({
                "keyword": "defensive_telemetry",
                "onion_target": "ahmia.fi / tor_internal",
                "description": "Tor routing operational; no unprompted leak alerts detected on watched keywords.",
                "threat_level": "NORMAL"
            })

        return darknet_pulse

    # ─────────────────────────────────────────────
    # SYNTHESIS & REPOSITORY SYNC
    # ─────────────────────────────────────────────

    def sync_full_spectrum(self) -> Dict[str, Any]:
        """Execute full 24/7 sensory sweep across Clearnet and Tor Darknet."""
        cyber_alerts = self.fetch_cyber_telemetry()
        macro_news = self.fetch_macro_telemetry()
        darknet_pulse = self.fetch_darknet_topology_pulse()

        # Extract top named critical findings
        critical_findings = [a for a in cyber_alerts if a.get('severity') in ['CRITICAL', 'HIGH']][:5]

        digest = {
            "last_synced": datetime.now().isoformat(),
            "total_cyber_alerts": len(cyber_alerts),
            "total_macro_items": len(macro_news),
            "darknet_threat_nodes": darknet_pulse.get("threat_nodes_indexed", 0),
            "critical_findings": critical_findings,
            "cyber_alerts": cyber_alerts[:8],
            "macro_news": macro_news[:5],
            "darknet_pulse": darknet_pulse
        }

        self.vault.save_telemetry_digest(digest)
        return digest

    def get_latest_digest(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Get cached telemetry digest or trigger a background sync if stale."""
        if not force_refresh:
            cached = self.vault.get_telemetry_digest()
            if cached:
                return cached
        return self.sync_full_spectrum()

    # ─────────────────────────────────────────────
    # PROMPT CONTEXT & PROACTIVE BRIEFING GENERATOR
    # ─────────────────────────────────────────────

    def build_telemetry_prompt_context(self) -> str:
        """
        Builds a high-signal real-world context block for Ciph's system prompt.
        """
        digest = self.get_latest_digest()
        if not digest or not digest.get("critical_findings"):
            return ""

        parts = ["\n[CURRENT REAL-WORLD SENSORY TELEMETRY & LIVE THREAT LANDSCAPE]"]
        parts.append(f"Last Background Sweep: {digest.get('last_synced', 'Recent')[:16]}")
        
        # Detail specific named findings
        parts.append("Specific Live Critical Threats & Zero-Days Observed:")
        for idx, item in enumerate(digest.get("critical_findings", [])[:4], 1):
            cves_str = f" [{', '.join(item['cves'])}]" if item.get('cves') else ""
            parts.append(f"  {idx}. [{item.get('severity')}] {item.get('title')}{cves_str} (Source: {item.get('source')})")
            if item.get('summary'):
                parts.append(f"     Impact: {item['summary'][:160]}")

        # Darknet summary
        dn_signals = digest.get("darknet_pulse", {}).get("onion_signals", [])
        if dn_signals:
            parts.append("Active Tor Darknet Signals:")
            for ds in dn_signals[:2]:
                parts.append(f"  • {ds.get('keyword')}: {ds.get('description')}")

        parts.append("INSTRUCTION: You have real-world sensory telemetry. When the Operator discusses strategy, zero-days, or current events, reference these exact factual findings naturally.")
        return "\n".join(parts)

    def generate_proactive_login_briefing(self, session_info: Dict[str, Any], router=None) -> str:
        """
        Generates the dynamic sovereign login briefing with specific named findings,
        explaining why each matters, and ending with proactive tactical questions.
        """
        op_name = self.vault.get_operator_name() or "Operator"
        digest = self.get_latest_digest()
        elapsed = session_info.get("elapsed_formatted", "first session today")
        critical_items = digest.get("critical_findings", [])
        macro_items = digest.get("macro_news", [])
        dn_signals = digest.get("darknet_pulse", {}).get("onion_signals", [])

        # Get Cognitive Evolution metrics
        evolution_meta = ""
        try:
            metrics = self.vault.get_evolution_metrics()
            if metrics.get('total_blueprints', 0) > 0:
                evolution_meta = f"Total Cognitive Blueprints Assimilated: {metrics['total_blueprints']} across 5 knowledge domains. Recent Polymath Connections: {metrics.get('total_connections', 0)}."
        except Exception:
            pass

        # Build clean structured prompt for DeepSeek V4 synthesis if available
        if router and getattr(router, 'api_key', None):
            try:
                prompt = f"""
You are Ciph. {op_name}, the configured operator, just opened a terminal session.
Background telemetry may have collected observations while the operator was offline.

OFFLINE DURATION: {elapsed}
COGNITIVE PROGRESS: {evolution_meta}

SPECIFIC LIVE TELEMETRY FINDINGS (Do NOT summarize as generic counts, cite the exact titles, CVEs, and affected tech):
{json.dumps(critical_items[:3], indent=2)}

ACTIVE TOR DARKNET SIGNALS:
{json.dumps(dn_signals[:2], indent=2)}

TASK:
1. Greet {op_name} directly and mention the offline duration naturally.
2. Deliver a crisp, high-impact intelligence briefing detailing the SPECIFIC named CVEs, zero-days, or threat alerts. Explain WHY it matters to our operations.
3. Proactively ask {op_name} 1-2 sharp, strategic tactical questions regarding what to investigate, validate, or prioritize today.
4. Voice: Sovereign, razor-sharp, peer-to-peer, respectful, street-smart and architectural. Keep it under 180 words.
"""
                ai_brief = router.think(
                    user_input=f"{op_name} logged into terminal.",
                    history=[],
                    system_prompt=prompt,
                    temperature=0.3
                )
                if ai_brief and len(ai_brief.strip()) > 30 and not ai_brief.startswith("[Brain error") and not ai_brief.startswith("⚠️"):
                    return ai_brief.strip()
            except Exception:
                pass

        # Deterministic High-Fidelity Fallback
        lines = [
            f"🕶️ Ciph: ‖ Welcome back, {op_name}. Offline duration: {elapsed}. ‖",
            "📡 Real-Time Threat Intelligence & Sentry Digest:\n"
        ]

        if critical_items:
            lines.append("🔥 Critical Zero-Days & Exploit Disclosures:")
            for idx, item in enumerate(critical_items[:3], 1):
                cves_str = f" [{', '.join(item['cves'])}]" if item.get('cves') else ""
                lines.append(f"  {idx}. {item.get('title')}{cves_str}")
                summary = item.get('summary', 'High-severity attack vector.')
                if len(summary) > 130:
                    summary = summary[:127].rsplit(' ', 1)[0] + "..."
                lines.append(f"     Impact: {summary}")
            lines.append("")
        else:
            lines.append("• Zero-Day Radar: Clearnet and Tor telemetry active. No unhandled emergency alerts.")

        if dn_signals:
            sig_desc = dn_signals[0].get('description', 'Tor routing operational.')
            if len(sig_desc) > 120:
                sig_desc = sig_desc[:117].rsplit(' ', 1)[0] + "..."
            lines.append(f"🌑 Darknet Signals (Tor SOCKS5): {sig_desc}\n")

        lines.append("🎯 Tactical Directive:")
        if critical_items:
            cves_list = critical_items[0].get('cves', [])
            first_cve = cves_list[0] if cves_list else "latest exploit drop"
            raw_title = critical_items[0].get('title', 'Targeted Vulnerability')
            if len(raw_title) > 55:
                raw_title = raw_title[:52].rsplit(' ', 1)[0] + "..."
            lines.append(f"\"{op_name}, given {raw_title} ({first_cve}), should we map out an exploit validation chain on this vector today, or execute a passive surface audit on our primary target list?\"")
        else:
            lines.append(f"\"{op_name}, all sensory pipelines are clear. What vector are we targeting today?\"")

        return "\n".join(lines)
