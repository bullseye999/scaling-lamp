#!/usr/bin/env python3
# bounty_hunter.py - Automated Bug Bounty & Vulnerability Scanner

import requests
import subprocess
import time
import json
import socket
import re
from functools import wraps
from typing import List, Dict, Any
from cipher_vault import CipherVault

class BountyHunter:
    """
    Automated bug bounty hunting and vulnerability reporting
    Scans targets, finds vulnerabilities, generates reports
    """
    
    def __init__(self, vault: CipherVault):
        self.vault = vault
        self.bounty_targets = []
        self.found_vulnerabilities = []
        
        # Common vulnerability patterns
        self.vuln_patterns = {
            'sql_injection': ["'", "1=1", "union select", "drop table"],
            'xss': ["<script>", "alert(", "onerror=", "javascript:"],
            'lfi': ["../../../../etc/passwd", "....//....//etc/passwd"],
            'idor': ["id=1", "user=admin", "account=1"],
            'ssrf': ["url=http://localhost", "proxy=127.0.0.1"]
        }
    
    def scan_website(self, url: str) -> Dict[str, Any]:
        """Comprehensive website vulnerability scan"""
        print(f"🔍 Scanning {url} for vulnerabilities...")
        vulnerabilities = []
        
        # Test for common web vulnerabilities
        vuln_checks = [
            self._test_sql_injection(url),
            self._test_blind_sqli(url),
            self._test_xss(url),
            self._test_lfi(url),
            self._test_ssrf(url)
        ]
        
        for check in vuln_checks:
            if check.get('found'):
                vulnerabilities.append(check)
        
        waf = self._detect_waf(url)
        tech = self.fingerprint_technology(url)

        # Store results
        result = {
            'target': url,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'waf_detected': waf,
            'technologies': tech,
            'scan_time': time.time(),
            'risk_level': 'HIGH' if vulnerabilities else 'LOW'
        }
        
        self.vault.store_conversation(
            f"BOUNTY_SCAN: {url}",
            f"Vulnerabilities: {len(vulnerabilities)} | Risk: {result['risk_level']}",
            "bounty_hunt"
        )
        
        return result
    
    def _test_sql_injection(self, url: str) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities"""
        test_payloads = ["' OR '1'='1", "admin' --", "1' AND 1=1"]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=5)
                
                # Check for SQL errors
                error_indicators = ['sql', 'database', 'mysql', 'syntax']
                if any(error in response.text.lower() for error in error_indicators):
                    return {
                        'type': 'SQL_INJECTION',
                        'found': True,
                        'payload': payload,
                        'confidence': 'HIGH'
                    }
            except Exception:
                continue
        
        return {'type': 'SQL_INJECTION', 'found': False}
    
    def _test_xss(self, url: str) -> Dict[str, Any]:
        """Test for XSS vulnerabilities"""
        test_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}?search={payload}"
                response = requests.get(test_url, timeout=5)
                
                if payload in response.text:
                    return {
                        'type': 'XSS',
                        'found': True,
                        'payload': payload,
                        'confidence': 'HIGH'
                    }
            except Exception:
                continue
        
        return {'type': 'XSS', 'found': False}
    
    def _test_lfi(self, url: str) -> Dict[str, Any]:
        """Test for Local File Inclusion"""
        test_payloads = ["../../../../etc/passwd", "....//....//etc/passwd"]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}?file={payload}"
                response = requests.get(test_url, timeout=5)
                
                if 'root:' in response.text:
                    return {
                        'type': 'LFI',
                        'found': True,
                        'payload': payload,
                        'confidence': 'HIGH'
                    }
            except Exception:
                continue
        
        return {'type': 'LFI', 'found': False}
    
    def _test_ssrf(self, url: str) -> Dict[str, Any]:
        """Test for Server-Side Request Forgery"""
        test_payloads = ["http://localhost", "http://127.0.0.1"]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}?url={payload}"
                response = requests.get(test_url, timeout=5)
                
                # Check for internal service responses
                if response.status_code != 404:
                    return {
                        'type': 'SSRF',
                        'found': True,
                        'payload': payload,
                        'confidence': 'MEDIUM'
                    }
            except Exception:
                continue
        
        return {'type': 'SSRF', 'found': False}
    
    def _detect_waf(self, url: str) -> Optional[str]:
        """Detect WAF signatures in target headers"""
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'aws_waf': ['x-amzn-requestid'],
            'sucuri': ['sucuri-id'],
            'wordfence': ['wf-'],
        }
        try:
            resp = requests.get(url, timeout=5)
            headers_str = str(resp.headers).lower()
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str:
                        return waf_name
        except Exception:
            pass
        return None

    def fingerprint_technology(self, url: str) -> Dict[str, Any]:
        """Identify server technology and web frameworks"""
        tech = {}
        try:
            resp = requests.get(url, timeout=5)
            headers = resp.headers
            content = resp.text
            if 'server' in headers:
                tech['server'] = headers['server']
            if 'x-powered-by' in headers:
                tech['framework'] = headers['x-powered-by']
            if 'wp-content' in content:
                tech['cms'] = 'WordPress'
            elif 'Drupal' in content:
                tech['cms'] = 'Drupal'
        except Exception:
            pass
        return tech

    def _test_blind_sqli(self, url: str) -> Dict[str, Any]:
        """Test for time-based blind SQL injection"""
        payloads = ["' AND SLEEP(3)--", "' OR SLEEP(3)--"]
        for payload in payloads:
            try:
                start = time.time()
                requests.get(f"{url}?id={payload}", timeout=8)
                elapsed = time.time() - start
                if elapsed > 3:
                    return {
                        'type': 'BLIND_SQLI',
                        'found': True,
                        'payload': payload,
                        'confidence': 'HIGH'
                    }
            except Exception:
                pass
        return {'type': 'BLIND_SQLI', 'found': False}

    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using DNS resolution"""
        wordlist = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'portal', 'm']
        found = []
        for sub in wordlist:
            host = f"{sub}.{domain}"
            try:
                socket.gethostbyname(host)
                found.append(host)
            except Exception:
                pass
        return found
    
    def generate_bounty_report(self, target: str) -> str:
        """Generate professional bug bounty report"""
        scan_results = self.scan_website(target)
        
        report = f"""
🐛 BUG BOUNTY REPORT for {target}
==================================
📊 SCAN SUMMARY:
• Vulnerabilities Found: {scan_results['vulnerabilities_found']}
• Overall Risk: {scan_results['risk_level']}
• Scan Time: {time.ctime(scan_results['scan_time'])}

🔍 VULNERABILITY DETAILS:
"""
        
        for vuln in scan_results['vulnerabilities']:
            report += f"• {vuln['type']}: {vuln['payload']} (Confidence: {vuln['confidence']})\n"
        
        report += f"""
💡 RECOMMENDATIONS:
• Submit findings to bug bounty platforms
• Follow responsible disclosure practices
• Document all findings for future reference

💰 POTENTIAL BOUNTIES:
• Critical: $1,000 - $10,000+
• High: $500 - $5,000
• Medium: $100 - $1,000
• Low: $50 - $500
"""
        
        return report
    
    def monitor_bounty_programs(self) -> List[Dict[str, Any]]:
        """Monitor popular bug bounty programs for new targets"""
        print("🎯 Monitoring bug bounty programs...")
        
        # Popular bug bounty platforms (free programs)
        bounty_programs = [
            {'name': 'HackerOne', 'url': 'https://hackerone.com/bug-bounty-programs'},
            {'name': 'Bugcrowd', 'url': 'https://bugcrowd.com/programs'},
            {'name': 'OpenBugBounty', 'url': 'https://www.openbugbounty.org/'}
        ]
        
        # Simulate finding active programs (in real implementation, would scrape these)
        active_programs = [
            {
                'platform': 'HackerOne',
                'program': 'Example Corp',
                'scope': '*.example.com',
                'bounty_range': '$500 - $5,000',
                'last_updated': time.time()
            }
        ]
        
        return active_programs
    
    def automated_bounty_hunt(self, targets: List[str]) -> Dict[str, Any]:
        """Run automated bounty hunting on multiple targets"""
        print("🤖 Starting automated bounty hunt...")
        
        results = {}
        total_vulnerabilities = 0
        
        for target in targets:
            scan_result = self.scan_website(target)
            results[target] = scan_result
            total_vulnerabilities += scan_result['vulnerabilities_found']
        
        # Generate summary
        summary = {
            'total_targets': len(targets),
            'total_vulnerabilities': total_vulnerabilities,
            'targets_with_vulns': sum(1 for r in results.values() if r['vulnerabilities_found'] > 0),
            'highest_risk': max((r['risk_level'] for r in results.values()), key=lambda x: 0 if x == 'LOW' else 1),
            'scan_completion_time': time.time()
        }
        
        # Store hunt results
        self.vault.store_conversation(
            "AUTOMATED_BOUNTY_HUNT",
            f"Targets: {summary['total_targets']} | Vulns: {summary['total_vulnerabilities']} | Risk: {summary['highest_risk']}",
            "bounty_hunt"
        )
        
        return {
            'summary': summary,
            'detailed_results': results
        }

# Test the bounty hunter
if __name__ == "__main__":
    vault = CipherVault()
    hunter = BountyHunter(vault)
    
    print("🧪 TESTING BOUNTY HUNTER...")
    
    # Test website scanning
    test_url = "http://testphp.vulnweb.com"
    scan_results = hunter.scan_website(test_url)
    print(f"🔍 Scan results: {scan_results['vulnerabilities_found']} vulnerabilities found")
    
    # Test report generation
    report = hunter.generate_bounty_report(test_url)
    print(f"📄 Report generated: {len(report)} characters")
    
    # Test bounty program monitoring
    programs = hunter.monitor_bounty_programs()
    print(f"🎯 Bounty programs monitored: {len(programs)}")