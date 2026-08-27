#!/usr/bin/env python3
"""
ciph_link_reader.py - Dual-Spectrum OPSEC Link Reader & Router
=============================================================
Safely fetches, sanitizes, and audits Clearnet and Darknet (.onion) links
over fail-closed Tor with anti-canary protection and context-driven routing.
"""

import os
import re
import urllib.parse
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
import requests

# Tor Configuration (Fail-Closed SOCKS5h)
TOR_PROXY = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

# OPSEC Anti-Fingerprint Headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'DNT': '1',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1'
}

# Known tracking parameter prefixes/names to strip
TRACKING_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'dclid', 'msclkid', 'twclid', 'yclid',
    'ref', 'source', 'token', 'session_id', 'affiliate', '_hsenc', '_hsmi',
    'mc_cid', 'mc_eid', 'igshid', 'spJobID', 'spReportId'
}

# Known Canary, IP Logger, and Honey-token domains
CANARY_SIGNATURES = [
    'canarytokens.org', 'canarytokens.com', 'grabify.link',
    'iplogger.org', '2no.co', 'iplogger.com', 'iplogger.ru',
    'yip.su', 'iplis.ru', '02ip.ru', 'ezstat.ru', 'whatstheirip.com'
]

class LinkOPSECAuditor:
    """Audits and sanitizes URLs before any network request is initiated."""

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract all http/https/onion URLs from a text string."""
        url_pattern = re.compile(
            r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>"\'`{}\\|^[\]]*)?|'
            r'https?://[a-z2-7]{16,56}\.onion(?::\d+)?(?:/[^\s<>"\'`{}\\|^[\]]*)?'
        )
        return url_pattern.findall(text)

    @staticmethod
    def audit_url(raw_url: str) -> Dict[str, Any]:
        """
        Audits a raw URL for tracking tokens, canary honeypots, and transport spectrum.
        Returns sanitized URL, stripped parameters, risk level, and protocol type.
        """
        try:
            parsed = urllib.parse.urlparse(raw_url)
        except Exception as e:
            return {
                'valid': False,
                'error': f"Malformed URL: {e}",
                'raw_url': raw_url
            }

        domain = parsed.netloc.lower().split(':')[0]
        is_onion = domain.endswith('.onion')

        # 1. Canary Token & Honeypot Detection
        is_canary = any(canary in domain for canary in CANARY_SIGNATURES)
        if is_canary:
            return {
                'valid': False,
                'blocked': True,
                'reason': '🚨 BLOCKED: Known Canary Token / IP Logger domain detected.',
                'raw_url': raw_url,
                'domain': domain,
                'risk': 'CRITICAL'
            }

        # 2. Tracking Parameter Stripping
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        stripped = []
        clean_params = {}

        for k, v in query_params.items():
            if k.lower() in TRACKING_PARAMS or any(k.lower().startswith(p) for p in ['utm_', 'ref_']):
                stripped.append(k)
            else:
                clean_params[k] = v

        clean_query = urllib.parse.urlencode(clean_params, doseq=True)
        clean_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            clean_query,
            parsed.fragment
        ))

        return {
            'valid': True,
            'blocked': False,
            'clean_url': clean_url,
            'raw_url': raw_url,
            'domain': domain,
            'is_onion': is_onion,
            'transport': 'Tor Hidden Service (.onion)' if is_onion else 'Tor SOCKS5h Exit Node',
            'stripped_params': stripped,
            'risk': 'LOW' if not stripped else 'MODERATE (Sanitized)'
        }


class CiphLinkReader:
    """
    Dual-Spectrum OPSEC Link Reader.
    Safely fetches and extracts content over Tor with strict memory and stream bounds.
    """

    def __init__(self, book_dir: str = "ciph_books", max_bytes: int = 2 * 1024 * 1024):
        self.book_dir = book_dir
        self.max_bytes = max_bytes
        self.auditor = LinkOPSECAuditor()
        os.makedirs(self.book_dir, exist_ok=True)

    def fetch_url(self, raw_url: str, timeout: int = 20) -> Dict[str, Any]:
        """
        Sanitizes and fetches URL content over Tor.
        Extracts clean text / Markdown with size limit protection.
        """
        audit = self.auditor.audit_url(raw_url)
        if not audit.get('valid') or audit.get('blocked'):
            return {
                'success': False,
                'audit': audit,
                'error': audit.get('reason', audit.get('error', 'Invalid URL'))
            }

        target_url = audit['clean_url']
        try:
            # Enforce Tor proxy for all fetches (Clearnet & Onion)
            response = requests.get(
                target_url,
                proxies=TOR_PROXY,
                headers=HEADERS,
                timeout=timeout,
                stream=True,
                allow_redirects=True
            )

            # Stream up to max_bytes to avoid memory bombs
            content_chunks = []
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                downloaded += len(chunk)
                if downloaded > self.max_bytes:
                    content_chunks.append(b"\n[...CONTENT TRUNCATED AT 2MB OPSEC CEILING...]")
                    break
                content_chunks.append(chunk)

            raw_bytes = b"".join(content_chunks)
            content_type = response.headers.get('Content-Type', '').lower()

            # Handle PDF downloads
            if 'application/pdf' in content_type or target_url.lower().endswith('.pdf'):
                filename = os.path.basename(urllib.parse.urlparse(target_url).path) or f"download_{int(datetime.now().timestamp())}.pdf"
                pdf_path = os.path.join(self.book_dir, filename)
                with open(pdf_path, 'wb') as f:
                    f.write(raw_bytes)
                return {
                    'success': True,
                    'audit': audit,
                    'is_pdf': True,
                    'file_path': pdf_path,
                    'status_code': response.status_code,
                    'text_content': f"PDF downloaded to {pdf_path} ({len(raw_bytes)} bytes). Indexed for Strategic Library."
                }

            # Handle HTML / Text
            charset = response.encoding or 'utf-8'
            try:
                html_text = raw_bytes.decode(charset, errors='replace')
            except Exception:
                html_text = raw_bytes.decode('utf-8', errors='replace')

            # Clean HTML to plain text / Markdown
            cleaned_text = self._html_to_clean_text(html_text)

            return {
                'success': True,
                'audit': audit,
                'is_pdf': False,
                'status_code': response.status_code,
                'title': self._extract_title(html_text),
                'text_content': cleaned_text[:8000],  # Return up to 8000 chars for context
                'char_count': len(cleaned_text)
            }

        except Exception as e:
            return {
                'success': False,
                'audit': audit,
                'error': f"Tor transport error fetching {target_url}: {str(e)[:120]}"
            }

    def classify_intent(self, user_text: str, url: str) -> str:
        """Classify what the operator or Ciph wants to do with the URL."""
        lower_text = user_text.lower()
        lower_url = url.lower()

        if lower_url.endswith('.pdf') or any(w in lower_text for w in ['book', 'read book', 'pdf', 'add to library', 'ingest']):
            return 'BOOK_INGEST'
        if 'github.com' in lower_url or any(w in lower_text for w in ['repo', 'codebase', 'repository', 'clone']):
            return 'CODE_AUDIT'
        if any(w in lower_text for w in ['bounty', 'target', 'endpoint', 'graphql', 'scan', 'takeover', 'vuln']):
            return 'BOUNTY_AUDIT'
        if any(w in lower_text for w in ['cve', 'zero-day', '0day', 'advisory', 'threat', 'exploit']):
            return 'THREAT_INTEL'
        return 'GENERAL_RESEARCH'

    def _extract_title(self, html: str) -> str:
        """Extract title tag from HTML."""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return "Untitled Document"

    def _html_to_clean_text(self, html: str) -> str:
        """Strips scripts, styles, and tags, converting HTML into clean readable text."""
        # 1. Remove script, style, and svg tags
        text = re.sub(r'<(script|style|svg|noscript)[^>]*>.*?</\1>', '', html, flags=re.DOTALL | re.IGNORECASE)
        # 2. Convert header and paragraph tags to newlines
        text = re.sub(r'<(h[1-6]|p|div|tr|li)[^>]*>', '\n', text, flags=re.IGNORECASE)
        # 3. Strip all remaining HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        # 4. Decode common HTML entities
        text = text.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
        # 5. Compress multiple spaces and newlines
        text = re.sub(r'[ \t]+', ' ', text)
        text = re.sub(r'\n\s*\n+', '\n\n', text)
        return text.strip()

    def format_audit_badge(self, audit: Dict[str, Any]) -> str:
        """Render a clean ASCII OPSEC badge for terminal display."""
        stripped = audit.get('stripped_params', [])
        stripped_str = f"Stripped {len(stripped)} tracking params ({', '.join(stripped[:3])})" if stripped else "Clean (0 tracking params)"
        
        lines = [
            "┌────────────────────────────────────────────────────────────┐",
            "│ 🛡️ OPSEC LINK AUDIT                                         │",
            f"│ • Domain    : {audit.get('domain', 'unknown')[:42]:<42} │",
            f"│ • Transport : {audit.get('transport', 'Tor')[:42]:<42} │",
            f"│ • Privacy   : {stripped_str[:42]:<42} │",
            f"│ • Risk Level: {audit.get('risk', 'LOW')[:42]:<42} │",
            "└────────────────────────────────────────────────────────────┘"
        ]
        return "\n".join(lines)
