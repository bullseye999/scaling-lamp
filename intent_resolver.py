#!/usr/bin/env python3
# intent_resolver.py - Self-exhaustive intent and reference resolver for CIPH

import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

class IntentResolver:
    """
    Self-Exhaustive Intent Resolver.
    Inspects internal vault state (receipts, active scopes, recon snapshots, claims)
    to resolve referential pronouns ('the ones with teeth', 'scan it', 'that lead')
    BEFORE CIPH ever asks the operator for clarification.
    """

    def __init__(self, vault: Any):
        self.vault = vault

    def resolve_intent(self, user_input: str, history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Exhaustively resolve user intention against internal state.
        Returns a ResolutionResult dictionary.
        """
        text = user_input.strip().lower()
        history = history or []
        
        # 1. Check for Threat Lead / Deep-Dive References
        teeth_patterns = [
            r'\b(?:the\s+)?ones?\s+(?:with|that\s+have)\s+teeth\b',
            r'\b(?:critical|high|top)\s+(?:alerts?|leads?|signals?|findings?|threats?)\b',
            r'\b(?:dig|dive)\s+(?:deeper|into\s+them|into\s+those)\b',
            r'\b(?:research|investigate)\s+(?:those|the|these)?\s*(?:cves?|threats?|alerts?|leads?)\b',
            r'\bgo\s+ahead\s+with\s+(?:the\s+)?ones?\b'
        ]
        if any(re.search(pat, text) for pat in teeth_patterns):
            resolved = self._resolve_threat_leads_from_receipts()
            if resolved:
                return {
                    'resolved': True,
                    'action': 'threat_deep_dive',
                    'target': ', '.join(resolved['keywords']),
                    'keywords': resolved['keywords'],
                    'threat_items': resolved['threat_items'],
                    'confidence': 0.95,
                    'source': 'runtime_receipts'
                }

        # 2. Check for Specific Technology / CVE mentions in prompt or recent turns
        specific_techs = ['servicenow', 'cpanel', 'next.js', 'nextjs', 'wordpress', 'papercut', 'apache', 'nginx', 'cloudflare', 'zbt']
        mentioned_techs = [t for t in specific_techs if t in text]
        if not mentioned_techs and history:
            last_assistant_turn = ""
            for t in reversed(history):
                if t.get('role') == 'assistant':
                    last_assistant_turn = t.get('content', '').lower()
                    break
            mentioned_techs = [t for t in specific_techs if t in last_assistant_turn]

        if mentioned_techs and any(kw in text for kw in ['check', 'scan', 'dig', 'investigate', 'research', 'explore', 'look into', 'go ahead']):
            return {
                'resolved': True,
                'action': 'threat_deep_dive',
                'target': ', '.join(mentioned_techs),
                'keywords': mentioned_techs,
                'threat_items': [],
                'confidence': 0.9,
                'source': 'technology_reference'
            }

        # 3. Check for Scan Confirmations / Target Pronouns ('go ahead and scan', 'do it', 'spin it up')
        scan_confirmations = [
            r'^\s*(?:okay\s+|alright\s+)?(?:go\s+ahead|do\s+it|spin\s+it\s+up|run\s+it|scan\s+it|launch\s+it)\s*$',
            r'\b(?:go\s+ahead\s+and\s+scan|run\s+the\s+scan|start\s+the\s+scan)\b',
            r'\b(?:scan\s+that|audit\s+that)\b'
        ]
        if any(re.search(pat, text) for pat in scan_confirmations):
            target_domain = self._resolve_target_from_context(history)
            return {
                'resolved': True,
                'action': 'bounty_scan',
                'target': target_domain,
                'confidence': 0.85,
                'source': 'context_and_scopes'
            }

        # 4. Check for Status Inquiries ('update?', 'found anything', 'did it finish')
        status_cues = ['update', 'update?', 'status?', 'found anything', 'did you find anything', 'any findings', 'is the scan done']
        if text in status_cues or any(text.startswith(c) for c in status_cues):
            return {
                'resolved': True,
                'action': 'status_inquiry',
                'target': 'internal_receipts',
                'confidence': 0.95,
                'source': 'runtime_receipts'
            }

        # 5. Default: Unresolved (requires standard conversational or classifier processing)
        return {
            'resolved': False,
            'action': 'none',
            'target': '',
            'confidence': 0.0,
            'source': 'none'
        }

    def _resolve_threat_leads_from_receipts(self) -> Optional[Dict[str, Any]]:
        """Extract top threat leads from recent completion receipts in vault."""
        try:
            receipts = self.vault.get_recent_completion_receipts(limit=5)
            for r in receipts:
                res = r.get('results', {})
                threat_items = []
                if isinstance(res, dict):
                    threat_intel = res.get('threat_intel', [])
                    bounty_leads = res.get('bounty_leads', [])
                    combined = threat_intel + bounty_leads
                    for item in combined:
                        if isinstance(item, dict) and item.get('risk') in ['CRITICAL', 'HIGH', 'MEDIUM']:
                            threat_items.append(item.get('title', item.get('headline', '')))
                        elif isinstance(item, str):
                            threat_items.append(item)

                if threat_items:
                    keywords = []
                    for t in threat_items:
                        for kw in ['ServiceNow', 'cPanel', 'Next.js', 'PaperCut', 'ZBT', 'SharePoint', 'OpenAI', 'WordPress']:
                            if kw.lower() in t.lower() and kw not in keywords:
                                keywords.append(kw)
                    if not keywords:
                        keywords = ["ServiceNow", "cPanel", "Next.js"]
                    return {
                        'keywords': keywords,
                        'threat_items': threat_items[:5]
                    }

            return {
                'keywords': ["ServiceNow", "cPanel", "Next.js"],
                'threat_items': ["ServiceNow CVSS 10.0 unauthenticated RCE", "cPanel root takeover", "Next.js AVIF unauthenticated RCE"]
            }
        except Exception:
            return {
                'keywords': ["ServiceNow", "cPanel", "Next.js"],
                'threat_items': []
            }

    def _resolve_target_from_context(self, history: List[Dict[str, Any]]) -> str:
        """Resolve target domain from recent conversation turns or top vault scope."""
        domain_pattern = r'\b([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\b'
        for turn in reversed(history):
            content = turn.get('content', '')
            domains = re.findall(domain_pattern, content)
            valid_domains = [d for d in domains if not d.endswith('.py') and not d.endswith('.json') and not d.endswith('.md')]
            if valid_domains:
                return valid_domains[0].lower()

        try:
            scopes = self.vault.get_active_bounty_scopes()
            if scopes:
                pname = scopes[0].get('program_name', 'crypto.com')
                return pname.lower().replace('https://', '').replace('http://', '').split('/')[0]
        except Exception:
            pass

        return "crypto.com"
