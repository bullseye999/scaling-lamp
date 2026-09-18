#!/usr/bin/env python3
# threat_correlator.py - Threat intelligence applicability correlator for CIPH

import json
from typing import Dict, Any, List, Optional
from datetime import datetime

class ThreatCorrelator:
    """
    Threat Applicability Correlator.
    Filters raw threat intelligence and CVE signals through Operator's registered world.
    Classifies applicability into:
      1. DIRECT_MATCH: Authorized target confirmed to expose affected technology.
      2. POTENTIAL_EXPOSURE: Authorized target with unconfirmed version or related surface.
      3. IRRELEVANT_OUT_OF_SCOPE: Threat does not touch any registered scope or asset.
    """

    def __init__(self, vault: Any):
        self.vault = vault

    def correlate_threats(self, threat_signals: List[str]) -> Dict[str, Any]:
        """
        Cross-correlate threat keywords or CVE titles against vault scopes and snapshots.
        Returns a structured ApplicabilityMatrix.
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'total_analyzed': len(threat_signals),
            'direct_matches': [],
            'potential_exposures': [],
            'irrelevant_threats': [],
            'proposed_actions': []
        }

        # 1. Fetch active scopes and snapshots
        scopes = []
        try:
            scopes = self.vault.get_active_bounty_scopes()
        except Exception:
            scopes = []

        snapshots = []
        try:
            # Get latest snapshots for active targets
            conn = self.vault._get_connection()
            c = conn.cursor()
            c.execute('SELECT target, encrypted_snapshot_json, timestamp FROM recon_snapshots ORDER BY timestamp DESC LIMIT 20')
            rows = c.fetchall()
            conn.close()

            seen_targets = set()
            for r in rows:
                tgt = r[0]
                if tgt not in seen_targets:
                    seen_targets.add(tgt)
                    raw_json = self.vault._decrypt(r[1]) or "{}"
                    try:
                        snap_data = json.loads(raw_json)
                    except Exception:
                        snap_data = {}
                    snapshots.append({
                        'target': tgt,
                        'data': snap_data,
                        'timestamp': r[2]
                    })
        except Exception:
            pass

        # 2. Analyze each threat signal
        for signal in threat_signals:
            sig_lower = signal.lower().strip()
            if not sig_lower:
                continue

            matched = False
            
            # Check against snapshots (technologies, subdomains, endpoints)
            for snap in snapshots:
                tgt = snap['target']
                snap_data = snap['data']
                techs = snap_data.get('technologies', {})
                subdomains = snap_data.get('subdomains', [])
                endpoints = snap_data.get('exposed_assets', snap_data.get('exposed_endpoints', []))

                # Keyword match in technologies
                matched_tech_keys = [t for t in techs.keys() if t.lower() in sig_lower or sig_lower in t.lower()]
                matched_tech_vals = [str(v) for v in techs.values() if str(v).lower() in sig_lower or sig_lower in str(v).lower()]
                
                # Check for explicit keywords like Next.js, WordPress, etc.
                is_direct_tech_match = False
                if any(kw in sig_lower for kw in ['next.js', 'nextjs']) and any('next.js' in str(k).lower() or 'next.js' in str(v).lower() for k, v in techs.items()):
                    is_direct_tech_match = True
                elif any(kw in sig_lower for kw in ['wordpress', 'wp']) and any('wordpress' in str(k).lower() or 'wordpress' in str(v).lower() for k, v in techs.items()):
                    is_direct_tech_match = True
                elif any(kw in sig_lower for kw in ['servicenow']) and any('servicenow' in str(k).lower() or 'servicenow' in str(v).lower() for k, v in techs.items()):
                    is_direct_tech_match = True
                elif any(kw in sig_lower for kw in ['cpanel']) and any('cpanel' in str(k).lower() or 'cpanel' in str(v).lower() for k, v in techs.items()):
                    is_direct_tech_match = True

                if is_direct_tech_match or matched_tech_keys or matched_tech_vals:
                    match_item = {
                        'threat': signal,
                        'target': tgt,
                        'applicability': 'DIRECT_MATCH',
                        'evidence': f"Observed technology '{', '.join(matched_tech_keys + matched_tech_vals) or 'Framework match'}' on {tgt}",
                        'severity_assessment': 'HIGH_PRIORITY_VERIFICATION'
                    }
                    results['direct_matches'].append(match_item)
                    matched = True

                    # Generate proposed action (Kernel-subordinate proposal)
                    results['proposed_actions'].append({
                        'action_type': 'PROPOSED_ACTION',
                        'target': tgt,
                        'threat_name': signal,
                        'applicability': 'DIRECT_MATCH',
                        'verification_method': 'PASSIVE_VERSION_FINGERPRINT',
                        'kernel_policy': 'AUTHORIZED_PASSIVE_RECON',
                        'description': f"Passive HTTP header and version fingerprint check over Tor on https://{tgt}"
                    })
                    break

            # If not direct tech match, check scope wildcards for potential exposure
            if not matched:
                for sc in scopes:
                    pname = sc.get('program_name', '')
                    in_s = sc.get('scope', {}).get('in_scope', [])
                    scope_text = (pname + " " + " ".join(in_s)).lower()
                    
                    if any(kw in scope_text for kw in [sig_lower]) or (sig_lower in pname.lower()):
                        results['potential_exposures'].append({
                            'threat': signal,
                            'target': pname,
                            'applicability': 'POTENTIAL_EXPOSURE',
                            'evidence': f"Target scope '{pname}' matches keyword in threat descriptor",
                            'severity_assessment': 'INVESTIGATIVE_PROBE'
                        })
                        matched = True
                        break

            # If no match found, classify as IRRELEVANT_OUT_OF_SCOPE
            if not matched:
                results['irrelevant_threats'].append({
                    'threat': signal,
                    'applicability': 'IRRELEVANT_OUT_OF_SCOPE',
                    'reason': "No active authorized scope or observed asset exhibits this technology profile."
                })

        return results
