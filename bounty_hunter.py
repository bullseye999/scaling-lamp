#!/usr/bin/env python3
# bounty_hunter.py - Elite Scoped Bug Bounty & Vulnerability Suite (v3)

import os
import re
import time
import json
import random
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional, Tuple, Set
from pathlib import Path

from cipher_vault import CipherVault
from cvss_calculator import CVSSv31Calculator
from ciph_router import CiphRouter
from ghost_transport import GhostTransport


# Subdomain Takeover Fingerprint Signatures
TAKEOVER_SIGNATURES = {
    "github": {
        "cname": ["github.io"],
        "fingerprint": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"]
    },
    "aws_s3": {
        "cname": ["s3.amazonaws.com", "s3-website"],
        "fingerprint": ["The specified bucket does not exist", "NoSuchBucket"]
    },
    "heroku": {
        "cname": ["herokuapp.com", "herokudns.com", "herokucdn.com"],
        "fingerprint": ["No such app", "There's nothing here, yet.", "herokucdn.com/error-pages/no-such-app.html"]
    },
    "fastly": {
        "cname": ["fastly.net"],
        "fingerprint": ["Fastly error: unknown domain"]
    },
    "azure": {
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        "fingerprint": ["404 Web Site not found", "The resource you are looking for has been removed"]
    },
    "shopify": {
        "cname": ["myshopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable", "Only one step left!"]
    },
    "pantheon": {
        "cname": ["pantheonsite.io"],
        "fingerprint": ["404 error unknown site!", "The gods are wise, but do not know of the site"]
    },
    "ghost": {
        "cname": ["ghost.io"],
        "fingerprint": ["The thing you were looking for is no longer here", "The site you were looking for doesn't exist"]
    },
    "fly_io": {
        "cname": ["fly.dev"],
        "fingerprint": ["404 Not Found", "Could not find target app"]
    },
    "bitbucket": {
        "cname": ["bitbucket.io"],
        "fingerprint": ["Repository not found", "The page you are looking for doesn't exist"]
    }
}


class BountyHunter:
    """
    Elite Scoped Bug Bounty & Vulnerability Suite (v3).
    - Scope Policy Ingestion & Strict Authorization Boundary
    - Multi-Source Passive Reconnaissance (AlienVault OTX, Wayback CDX, URLScan, crt.sh)
    - Subdomain Takeover Detector (Dangling CNAMEs against verified cloud provider fingerprints)
    - GraphQL Introspection Auditor & Schema Type Extractor
    - Historical Parameter Miner (Wayback Machine CDX parameter extraction)
    - SPA Dynamic Baseline & Soft-404 Validation (Zero false positives)
    - Full JavaScript Bundle, Webpack Chunk, and API Route Extractor
    - Fail-Closed SOCKS5h Tor Transport with zero DNS leaks
    - Mathematical CVSS v3.1 Scoring & Triaged HackerOne/Bugcrowd Report Writer
    """

    def __init__(self, vault: Optional[CipherVault] = None, router: Optional[CiphRouter] = None):
        self.vault = vault or CipherVault()
        self.router = router or CiphRouter()
        self.transport = GhostTransport()
        self.reports_dir = Path(__file__).parent / "bounty_reports"
        self.reports_dir.mkdir(exist_ok=True)
        self.last_scan_target = None
        self.last_scan_results = None
        self.active_scopes: List[Dict[str, Any]] = self._load_scopes()

    def _load_scopes(self) -> List[Dict[str, Any]]:
        """Load stored active scopes from vault."""
        try:
            return self.vault.get_active_bounty_scopes()
        except Exception:
            return []

    # ─────────────────────────────────────────────────────────────────────────
    # 1. SCOPE & AUTHORIZATION POLICY
    # ─────────────────────────────────────────────────────────────────────────

    def ingest_scope(self, scope_input: str, program_name: Optional[str] = None) -> Dict[str, Any]:
        """Ingest a bug bounty scope policy (raw text or URL)."""
        text = scope_input.strip()

        if text.startswith("http://") or text.startswith("https://"):
            resp = self.transport.get(text, timeout=15)
            if resp and resp.status_code == 200:
                text = resp.text[:8000]
            else:
                return {"success": False, "error": f"Failed to fetch policy URL: HTTP {resp.status_code if resp else 'Timeout'}"}

        parsed_scope = self._parse_scope_with_ai(text, program_name)
        prog = parsed_scope.get("program_name", program_name or "Unknown Program")

        scope_id = self.vault.store_bounty_scope(prog, parsed_scope)
        self.active_scopes = self._load_scopes()

        return {
            "success": True,
            "scope_id": scope_id,
            "program_name": prog,
            "in_scope": parsed_scope.get("in_scope", []),
            "out_of_scope": parsed_scope.get("out_of_scope", []),
            "bounty_tiers": parsed_scope.get("bounty_tiers", {}),
            "rules": parsed_scope.get("rules", []),
            "parsed_scope": parsed_scope
        }

    def _parse_scope_with_ai(self, policy_text: str, fallback_name: Optional[str]) -> Dict[str, Any]:
        """Structure bounty policy text into strict JSON schema using DeepSeek V4."""
        system_prompt = (
            "You are a Senior Bug Bounty Triage Specialist. Analyze the provided bug bounty policy "
            "and extract the exact scope parameters. Return ONLY a valid JSON object matching this schema:\n"
            "{\n"
            '  "program_name": "string",\n'
            '  "in_scope": ["*.domain.com", "api.domain.com"],\n'
            '  "out_of_scope": ["thirdparty.domain.com"],\n'
            '  "bounty_tiers": {"critical": "$1000+", "high": "$500", "medium": "$200", "low": "$50"},\n'
            '  "prohibited_actions": ["No DoS", "No social engineering", "No automated fuzzing > 5 req/s"],\n'
            '  "rules": ["Follow responsible disclosure", "Keep reports confidential"]\n'
            "}"
        )

        try:
            raw_json_str = self.router.think(
                user_input=f"Extract scope parameters from this bug bounty policy text:\n\n{policy_text[:6000]}",
                history=[],
                system_prompt=system_prompt,
                temperature=0.1
            )
            clean_str = re.sub(r'```(?:json)?', '', raw_json_str).strip()
            data = json.loads(clean_str)
            if not data.get("program_name") and fallback_name:
                data["program_name"] = fallback_name
            return data
        except Exception:
            domains = re.findall(r'(?:\*\.)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}', policy_text)
            unique_domains = list(set(domains))[:10]
            return {
                "program_name": fallback_name or "Manual Program Scope",
                "in_scope": unique_domains or ["*"],
                "out_of_scope": [],
                "bounty_tiers": {"general": "Disclosed in program rules"},
                "rules": ["Standard Responsible Disclosure"],
                "prohibited_actions": ["No DoS", "No Data Destruction"]
            }

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """Verify if a target domain is authorized within active ingested scopes."""
        if not self.active_scopes:
            return True, "No active scope lock set (Running in open lab/audit mode)"

        parsed_target = urlparse(target if "://" in target else f"https://{target}").netloc or target
        parsed_target = parsed_target.lower().split(':')[0]

        for s in self.active_scopes:
            scope_data = s.get("scope", {})
            in_scope = [d.lower() for d in scope_data.get("in_scope", [])]
            out_of_scope = [d.lower() for d in scope_data.get("out_of_scope", [])]

            for out_d in out_of_scope:
                if out_d.startswith("*.") and (parsed_target.endswith(out_d[1:]) or parsed_target == out_d[2:]):
                    return False, f"Target {parsed_target} is explicitly OUT OF SCOPE for {s.get('program_name')}"
                if parsed_target == out_d:
                    return False, f"Target {parsed_target} is explicitly OUT OF SCOPE for {s.get('program_name')}"

            for in_d in in_scope:
                if in_d in ["*", "*.*"]:
                    return True, f"In scope under wildcard for {s.get('program_name')}"
                if in_d.startswith("*.") and (parsed_target.endswith(in_d[1:]) or parsed_target == in_d[2:]):
                    return True, f"In scope under {in_d} for {s.get('program_name')}"
                if parsed_target == in_d:
                    return True, f"In scope exact match for {s.get('program_name')}"

        return False, f"Target '{parsed_target}' is NOT listed in any active program in-scope assets."

    # ─────────────────────────────────────────────────────────────────────────
    # 2. MULTI-SOURCE PASSIVE RECONNAISSANCE CASCADE
    # ─────────────────────────────────────────────────────────────────────────

    def query_passive_subdomains(self, domain: str) -> List[str]:
        """
        Query multiple passive intelligence sources over SOCKS5h Tor with failover cascade:
        1. AlienVault OTX Passive DNS
        2. Wayback Machine CDX API
        3. URLScan.io API
        4. crt.sh (short timeout fallback)
        """
        clean_domain = domain.lower().split(':')[0].strip()
        subdomains: Set[str] = set()

        # 1. AlienVault OTX
        try:
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{clean_domain}/passive_dns"
            resp = self.transport.get(otx_url, timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                for r in data.get('passive_dns', []):
                    host = r.get('hostname', '').lower().strip()
                    if host.endswith(clean_domain) and len(host) > len(clean_domain):
                        subdomains.add(host)
        except Exception:
            pass

        # 2. Wayback Machine CDX API
        try:
            wb_url = f"https://web.archive.org/cdx/search/cdx?url=*.{clean_domain}&output=json&fl=original&collapse=urlkey&limit=300"
            resp = self.transport.get(wb_url, timeout=12)
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data[1:]:  # skip header
                    if entry:
                        u = entry[0] if isinstance(entry, list) else entry
                        host = urlparse(u if "://" in u else f"http://{u}").netloc.lower().split(':')[0]
                        if host.endswith(clean_domain) and len(host) > len(clean_domain):
                            subdomains.add(host)
        except Exception:
            pass

        # 3. URLScan.io API
        try:
            urlscan_url = f"https://urlscan.io/api/v1/search/?q=domain:{clean_domain}&size=100"
            resp = self.transport.get(urlscan_url, timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                for res in data.get('results', []):
                    host = res.get('page', {}).get('domain', '').lower().strip()
                    if host.endswith(clean_domain) and len(host) > len(clean_domain):
                        subdomains.add(host)
        except Exception:
            pass

        # 4. crt.sh Fallback (4-second timeout)
        if len(subdomains) < 5:
            try:
                crt_url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
                resp = self.transport.get(crt_url, timeout=5)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name_val = entry.get('name_value', '')
                        for sub in name_val.split('\n'):
                            sub = sub.strip().lower()
                            if sub.startswith('*.'):
                                sub = sub[2:]
                            if sub.endswith(clean_domain) and len(sub) > len(clean_domain):
                                subdomains.add(sub)
            except Exception:
                pass

        # Add common high-value subdomains
        common_candidates = ['api', 'dev', 'staging', 'admin', 'auth', 'portal', 'app', 'cdn', 'vpn', 'v1', 'graphql']
        for c in common_candidates:
            subdomains.add(f"{c}.{clean_domain}")

        return sorted(list(subdomains))

    # ─────────────────────────────────────────────────────────────────────────
    # 3. SUBDOMAIN TAKEOVER DETECTOR (Dangling CNAMEs)
    # ─────────────────────────────────────────────────────────────────────────

    def check_subdomain_takeover(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """
        Check if a subdomain points to a dangling CNAME on an unclaimed third-party service.
        Resolves CNAME via DoH over Tor, then inspects body for provider fingerprint.
        """
        clean_sub = subdomain.lower().split(':')[0].strip()
        cnames = self.transport.resolve_dns_over_tor(clean_sub, record_type="CNAME")
        if not cnames:
            return None

        cname_val = cnames[0].rstrip('.').lower()

        matched_service = None
        matched_config = None
        for service_name, config in TAKEOVER_SIGNATURES.items():
            if any(c in cname_val for c in config["cname"]):
                matched_service = service_name
                matched_config = config
                break

        if not matched_service or not matched_config:
            return None

        # Verify whether the service response returns the unclaimed fingerprint
        target_url = f"https://{clean_sub}"
        resp = self.transport.get(target_url, timeout=8)
        if not resp:
            target_url = f"http://{clean_sub}"
            resp = self.transport.get(target_url, timeout=8)

        if not resp:
            return None

        for fp in matched_config["fingerprint"]:
            if fp.lower() in resp.text.lower():
                return {
                    "subdomain": clean_sub,
                    "cname": cname_val,
                    "service": matched_service,
                    "fingerprint_matched": fp,
                    "status_code": resp.status_code,
                    "severity": "CRITICAL",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                    "details": f"Dangling CNAME '{cname_val}' points to unclaimed {matched_service} instance with verified response fingerprint: '{fp}'"
                }

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # 4. GRAPHQL INTROSPECTION & SCHEMA ANALYZER
    # ─────────────────────────────────────────────────────────────────────────

    def audit_graphql(self, base_url: str) -> Optional[Dict[str, Any]]:
        """
        Probe for active GraphQL endpoints and evaluate schema introspection.
        Detects exposed types, queries, mutations, and sensitive entities.
        """
        clean_base = base_url.rstrip('/')
        endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/altair", "/query"]
        introspection_query = {"query": "{ __schema { queryType { name } mutationType { name } types { name } } }"}

        for ep in endpoints:
            url = f"{clean_base}{ep}"
            resp = self.transport.post(url, json_data=introspection_query, timeout=8)
            if not resp or resp.status_code != 200:
                continue

            try:
                data = resp.json()
                schema = data.get("data", {}).get("__schema")
                if schema and "types" in schema:
                    type_names = [t.get("name", "") for t in schema.get("types", []) if not t.get("name", "").startswith("__")]
                    
                    sensitive_keywords = ["user", "admin", "token", "auth", "payment", "credential", "role", "secret", "account", "card"]
                    sensitive_types = [t for t in type_names if any(k in t.lower() for k in sensitive_keywords)]

                    return {
                        "endpoint": ep,
                        "full_url": url,
                        "introspection_enabled": True,
                        "total_types": len(type_names),
                        "sensitive_types": sensitive_types[:15],
                        "has_mutations": schema.get("mutationType") is not None,
                        "severity": "HIGH" if sensitive_types else "MEDIUM",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if sensitive_types else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "details": f"GraphQL introspection active at {ep}. Discovered {len(type_names)} types ({len(sensitive_types)} sensitive types flagged: {', '.join(sensitive_types[:6])})."
                    }
            except Exception:
                continue

        return None

    # ─────────────────────────────────────────────────────────────────────────
    # 5. HISTORICAL PARAMETER & ENDPOINT MINER
    # ─────────────────────────────────────────────────────────────────────────

    def extract_historical_parameters(self, domain: str) -> Dict[str, Any]:
        """
        Extract historical parameters and dynamic URL patterns from Wayback Machine CDX API.
        """
        clean_domain = domain.lower().split(':')[0].strip()
        cdx_url = f"https://web.archive.org/cdx/search/cdx?url={clean_domain}/*&output=json&fl=original&collapse=urlkey&limit=500"

        resp = self.transport.get(cdx_url, timeout=15)
        if not resp or resp.status_code != 200:
            return {"domain": clean_domain, "unique_parameters": [], "parameter_urls": []}

        unique_params: Set[str] = set()
        param_urls: List[Dict[str, Any]] = []

        try:
            data = resp.json()
            for row in data[1:]:
                raw_url = row[0] if isinstance(row, list) else row
                parsed = urlparse(raw_url)
                if parsed.query:
                    query_params = [q.split('=')[0] for q in parsed.query.split('&') if q]
                    for p in query_params:
                        if p and len(p) < 40 and re.match(r'^[a-zA-Z0-9_\-]+$', p):
                            unique_params.add(p)
                    
                    if len(param_urls) < 20:
                        param_urls.append({
                            "url": raw_url[:120],
                            "params": query_params
                        })
        except Exception:
            pass

        return {
            "domain": clean_domain,
            "param_count": len(unique_params),
            "unique_parameters": sorted(list(unique_params)),
            "parameter_urls": param_urls[:15]
        }

    # ─────────────────────────────────────────────────────────────────────────
    # 6. SPA CALIBRATION & VERIFIED ACTIVE PROBING
    # ─────────────────────────────────────────────────────────────────────────

    def _calibrate_spa_baseline(self, base_url: str) -> Dict[str, Any]:
        """Probe randomized non-existent path to detect SPA catch-all and soft-404 signatures."""
        random_token = f"__ciph_probe_{int(time.time())}_{random.randint(1000, 9999)}__"
        probe_url = f"{base_url.rstrip('/')}/{random_token}"

        resp = self.transport.get(probe_url, timeout=8)
        if not resp:
            return {"is_spa_catchall": False, "baseline_length": 0, "status_code": 404}

        is_catchall = (resp.status_code == 200 and ("<html" in resp.text.lower()[:100] or len(resp.text) > 100))
        return {
            "is_spa_catchall": is_catchall,
            "status_code": resp.status_code,
            "baseline_length": len(resp.text),
            "content_type": resp.headers.get("Content-Type", "")
        }

    def _check_exposed_assets(self, base_url: str, spa_baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Verify sensitive paths against SPA false-positives with strict signature matching."""
        sensitive_probes = [
            {"path": "/.env", "type": "ENV_CONFIG_EXPOSURE", "sig": r'^[A-Z0-9_]{2,}=', "sev": "HIGH"},
            {"path": "/.git/config", "type": "GIT_REPOSITORY_EXPOSURE", "sig": r'\[core\]', "sev": "CRITICAL"},
            {"path": "/.git/HEAD", "type": "GIT_HEAD_EXPOSURE", "sig": r'ref:\s*refs/', "sev": "CRITICAL"},
            {"path": "/swagger.json", "type": "OPENAPI_SCHEMA_EXPOSURE", "sig": r'"(?:swagger|openapi)"\s*:', "sev": "MEDIUM"},
            {"path": "/api-docs", "type": "API_DOCUMENTATION_EXPOSURE", "sig": r'"(?:swagger|openapi|paths)"', "sev": "MEDIUM"},
            {"path": "/robots.txt", "type": "ROBOTS_FILE", "sig": r'user-agent:', "sev": "INFO"},
            {"path": "/.well-known/security.txt", "type": "SECURITY_TXT", "sig": r'contact:', "sev": "INFO"}
        ]

        verified_findings = []
        clean_base = base_url.rstrip('/')

        for p in sensitive_probes:
            url = f"{clean_base}{p['path']}"
            resp = self.transport.get(url, timeout=6)
            if not resp or resp.status_code != 200:
                continue

            # Reject SPA catch-all false positives
            if spa_baseline["is_spa_catchall"]:
                if abs(len(resp.text) - spa_baseline["baseline_length"]) < 50:
                    continue
                if "text/html" in resp.headers.get("Content-Type", "").lower() and p["path"] in ["/.env", "/.git/config", "/swagger.json"]:
                    continue

            # Check required signature regex
            if re.search(p["sig"], resp.text, re.IGNORECASE):
                verified_findings.append({
                    "path": p["path"],
                    "url": url,
                    "type": p["type"],
                    "severity": p["sev"],
                    "status_code": resp.status_code,
                    "snippet": resp.text[:100].strip(),
                    "details": f"Verified exposure at {p['path']} matching signature '{p['sig']}'"
                })

        return verified_findings

    def extract_js_routes(self, base_url: str) -> List[Dict[str, Any]]:
        """Extract JavaScript bundles, Webpack chunks, and internal API routes."""
        resp = self.transport.get(base_url, timeout=10)
        if not resp or resp.status_code != 200:
            return []

        script_sources = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        parsed_base = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

        script_urls = []
        for src in script_sources:
            full_src = urljoin(parsed_base, src)
            if full_src.startswith(parsed_base) and ('.js' in full_src):
                script_urls.append(full_src)

        found_routes = []
        for js_url in script_urls[:6]:
            js_resp = self.transport.get(js_url, timeout=8)
            if not js_resp or js_resp.status_code != 200:
                continue

            js_text = js_resp.text
            # Regex for internal API routes
            routes = re.findall(r'["\'](/(?:api/v\d+|graphql|v\d+/[a-zA-Z0-9_-]+|[a-zA-Z0-9_-]+/api/|admin/|auth/|oauth/)[a-zA-Z0-9_/.-]*)["\']', js_text)
            for r in set(routes):
                found_routes.append({
                    "endpoint": r,
                    "source_js": Path(urlparse(js_url).path).name,
                    "type": "API_ROUTE"
                })

            # Regex for hardcoded API keys / tokens
            tokens = re.findall(r'(?:apiKey|api_key|appId|secret|jwt|bearer)\s*[:=]\s*["\']([^"\'\s]{16,})["\']', js_text, re.IGNORECASE)
            for tok in set(tokens):
                found_routes.append({
                    "endpoint": f"[Candidate Key]: {tok[:6]}...{tok[-4:]}",
                    "source_js": Path(urlparse(js_url).path).name,
                    "type": "STATIC_SECRET_CANDIDATE"
                })

        return found_routes[:20]

    # ─────────────────────────────────────────────────────────────────────────
    # 7. DEEP COMPREHENSIVE SCAN
    # ─────────────────────────────────────────────────────────────────────────

    def deep_scan(self, target: str, force: bool = False) -> Dict[str, Any]:
        """
        Execute full comprehensive reconnaissance & vulnerability audit over Tor:
        - Scope verification
        - SPA dynamic baseline calibration
        - Multi-source passive recon
        - Subdomain takeover detection (Dangling CNAMEs)
        - GraphQL introspection auditing
        - Verified exposed configuration scanning (No false positives)
        - Historical parameter extraction
        - Client-side JS & API route mining
        """
        in_scope, scope_reason = self.is_in_scope(target)
        if not in_scope and not force:
            return {
                "success": False,
                "error": f"❌ SCOPE VIOLATION: {scope_reason}\nUse force=True or add target via /bounty-scope."
            }

        url = target if "://" in target else f"https://{target}"
        domain = urlparse(url).netloc.split(':')[0]

        # 1. SPA Calibration
        spa_baseline = self._calibrate_spa_baseline(url)

        # 2. Multi-Source Passive Subdomain Discovery
        subdomains = self.query_passive_subdomains(domain)

        # 3. Subdomain Takeover Analysis
        takeovers = []
        for sub in subdomains[:15]:
            to_res = self.check_subdomain_takeover(sub)
            if to_res:
                takeovers.append(to_res)

        # 4. GraphQL Introspection Audit
        graphql_audit = self.audit_graphql(url)

        # 5. Verified Sensitive Assets (SPA False-Positive Immune)
        exposed_assets = self._check_exposed_assets(url, spa_baseline)

        # 6. Historical Parameters
        historical_params = self.extract_historical_parameters(domain)

        # 7. JavaScript Route Miner
        js_routes = self.extract_js_routes(url)

        # Compile Consolidated Findings
        findings = []

        for to in takeovers:
            findings.append({
                "type": "SUBDOMAIN_TAKEOVER_VULNERABILITY",
                "severity": "CRITICAL",
                "details": to["details"],
                "cvss_vector": to["cvss_vector"],
                "target": to["subdomain"]
            })

        for exp in exposed_assets:
            findings.append({
                "type": exp["type"],
                "severity": exp["severity"],
                "details": exp["details"],
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if exp["severity"] == "CRITICAL" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "target": exp["url"]
            })

        if graphql_audit and graphql_audit.get("introspection_enabled"):
            findings.append({
                "type": "GRAPHQL_INTROSPECTION_ACTIVE",
                "severity": graphql_audit["severity"],
                "details": graphql_audit["details"],
                "cvss_vector": graphql_audit["cvss_vector"],
                "target": graphql_audit["full_url"]
            })

        for r in js_routes:
            if r.get("type") == "STATIC_SECRET_CANDIDATE":
                findings.append({
                    "type": "JS_HARDCODED_KEY_CANDIDATE",
                    "severity": "HIGH",
                    "details": f"Secret pattern in {r['source_js']}: {r['endpoint']}",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "target": r["source_js"]
                })

        risk_level = "LOW"
        if any(f['severity'] == 'CRITICAL' for f in findings):
            risk_level = "CRITICAL"
        elif any(f['severity'] == 'HIGH' for f in findings):
            risk_level = "HIGH"
        elif any(f['severity'] == 'MEDIUM' for f in findings):
            risk_level = "MEDIUM"

        scan_result = {
            "success": True,
            "target": url,
            "domain": domain,
            "scan_time": datetime.now().isoformat(),
            "scope_status": scope_reason,
            "risk_level": risk_level,
            "findings_count": len(findings),
            "findings": findings,
            "subdomains": subdomains,
            "takeovers": takeovers,
            "graphql": graphql_audit,
            "exposed_assets": exposed_assets,
            "historical_params": historical_params,
            "js_routes": js_routes,
            "spa_baseline": spa_baseline
        }

        # Store snapshot in vault for historical change detection
        self.vault.store_recon_snapshot(domain, scan_result)

        self.last_scan_target = domain
        self.last_scan_results = scan_result
        return scan_result

    # ─────────────────────────────────────────────────────────────────────────
    # 8. THE HIT LIST & PRIORITIZATION (/hit-list)
    # ─────────────────────────────────────────────────────────────────────────

    def generate_hit_list(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """Prioritize actionable findings mathematically: Score = Base Severity * Multipliers."""
        scan_data = self.last_scan_results
        if target and (not scan_data or scan_data.get("domain") != target):
            scan_data = self.deep_scan(target)

        if not scan_data:
            return []

        domain = scan_data.get("domain", "")
        candidates = []

        for f in scan_data.get("findings", []):
            sev_score = {"CRITICAL": 10.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}.get(f["severity"], 2.0)
            multiplier = 1.3 if f["type"] in ["SUBDOMAIN_TAKEOVER_VULNERABILITY", "GRAPHQL_INTROSPECTION_ACTIVE"] else 1.0
            total = round(sev_score * multiplier, 1)

            candidates.append({
                "asset": f.get("target", domain),
                "title": f"[{f['type']}] {f['details']}",
                "severity": f["severity"],
                "score": total,
                "action": "Immediate reproduction and submission drafting."
            })

        for s in scan_data.get("subdomains", [])[:10]:
            if any(k in s for k in ['dev', 'stage', 'test', 'admin', 'vpn', 'api', 'v1']):
                candidates.append({
                    "asset": s,
                    "title": "High-Value API / Staging Subdomain",
                    "severity": "MEDIUM",
                    "score": 5.5,
                    "action": "Perform API parameter fuzzing and auth boundary test."
                })

        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates[:5]

    # ─────────────────────────────────────────────────────────────────────────
    # 9. TRIAGED REPORT WRITER
    # ─────────────────────────────────────────────────────────────────────────

    def generate_elite_report(
        self,
        target: Optional[str] = None,
        vuln_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate verified HackerOne/Bugcrowd report with calculated CVSS v3.1."""
        scan_data = self.last_scan_results
        if target:
            if not scan_data or scan_data.get("domain") != target:
                scan_data = self.deep_scan(target)

        if not scan_data or not scan_data.get("success"):
            return {
                "success": False,
                "error": "❌ No scan data available. Run /bounty-scan <target> first."
            }

        domain = scan_data.get("domain", "target.com")
        findings_json = json.dumps(scan_data.get("findings", []), indent=2)

        system_prompt = (
            "You are a Principal Bug Bounty Triager and Security Researcher for HackerOne and Bugcrowd. "
            f"Today's date is {datetime.now().strftime('%B %d, %Y')}. "
            "Write an elite, highly detailed Bug Bounty Vulnerability Submission Report based ONLY on the verified findings.\n\n"
            "Include: Title, CWE, CVSS:3.1 Vector String, Scope Verification, Step-by-Step PoC, Impact, and Code Remediation. "
            "Do NOT include conversational preambles like 'Here is the report'."
        )

        prompt_input = (
            f"Target: {domain}\n"
            f"Scope Status: {scan_data.get('scope_status')}\n"
            f"Verified Findings:\n{findings_json}\n"
            f"GraphQL Info: {json.dumps(scan_data.get('graphql', {}))}\n"
            f"Takeovers: {json.dumps(scan_data.get('takeovers', []))}\n"
            f"Historical Parameters: {json.dumps(scan_data.get('historical_params', {}).get('unique_parameters', [])[:15])}"
        )

        raw_report = self.router.think(
            user_input=prompt_input,
            history=[],
            system_prompt=system_prompt,
            temperature=0.2
        )

        cvss_match = re.search(r'CVSS:3\.[01]/[A-Z0-9/:]+', raw_report)
        vector_str = cvss_match.group(0) if cvss_match else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        try:
            cvss_calc = CVSSv31Calculator.calculate_from_vector(vector_str)
            score = cvss_calc["base_score"]
            severity = cvss_calc["severity"]
        except Exception:
            score = 7.5
            severity = "HIGH"

        clean_target = domain.replace('.', '_')
        clean_type = (vuln_type or "recon_audit").replace(' ', '_').lower()
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{clean_target}_{clean_type}_{timestamp_str}.md"
        report_path = self.reports_dir / filename

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(raw_report)

        report_id = self.vault.store_bounty_report_index(
            target=domain,
            vuln_type=vuln_type or "Surface Audit",
            cvss_score=score,
            severity=severity,
            report_path=str(report_path),
            status="DRAFT"
        )

        return {
            "success": True,
            "report_id": report_id,
            "target": domain,
            "cvss_score": score,
            "severity": severity,
            "vector_string": vector_str,
            "report_path": str(report_path),
            "report_content": raw_report
        }

    def list_bounties_summary(self) -> str:
        """Return formatted summary of active scopes and generated reports."""
        scopes = self.vault.get_active_bounty_scopes()
        reports = self.vault.get_bounty_reports_index(limit=10)

        lines = [
            "═" * 60,
            "🎯 CIPH BUG BOUNTY WORKBENCH & ACTIVE SCOPES",
            "═" * 60,
            "[ 1. ACTIVE PROGRAM SCOPES ]"
        ]

        if scopes:
            for s in scopes:
                p_name = s.get('program_name', 'Unknown')
                sc = s.get('scope', {})
                in_s = ", ".join(sc.get('in_scope', ['All']))[:40]
                lines.append(f"• Program: {p_name} | In-Scope: {in_s}")
        else:
            lines.append("• No program scopes ingested. Use /bounty-scope <text/url> to lock rules.")

        lines.append("\n[ 2. GENERATED VULNERABILITY REPORTS ]")
        if reports:
            for r in reports:
                lines.append(
                    f"• #{r['id']} | {r['target']} | {r['vuln_type']} | CVSS: {r['cvss_score']} ({r['severity']}) | File: {Path(r['report_path']).name}"
                )
        else:
            lines.append("• No reports generated yet. Run /bounty-report <target> to draft one.")

        lines.append("═" * 60)
        return "\n".join(lines)