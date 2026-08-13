#!/usr/bin/env python3
# osint_miner.py - WEAPONIZED OSINT: COMPLETE WITH MONETIZATION
import feedparser
import requests
import time
import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from cipher_vault import CipherVault

class OSINTMiner:
    def __init__(self, vault: CipherVault):
        self.vault = vault
        self.last_check = None
        self.critical_threats_found = []
        self.monetizable_opportunities = []
        
        # TWITTER/X API SETUP
        self.twitter_bearer = self.vault.get_config("TWITTER_BEARER_TOKEN")
        self.x_headers = {"Authorization": f"Bearer {self.twitter_bearer}"} if self.twitter_bearer else None
        
        # HIGH-SIGNAL RSS FEEDS
        self.rss_feeds = [
            'https://krebsonsecurity.com/feed/',
            'https://www.darkreading.com/rss/simple',
            'https://feeds.feedburner.com/TheHackersNews',
            'https://www.bleepingcomputer.com/feed/',
            'https://www.securityweek.com/feed/',
            'https://blog.talosintelligence.com/feeds/posts/default',
            'https://www.cisa.gov/uscert/ncas/current-activity.xml',
            'https://www.exploit-db.com/rss.xml',
            'https://www.trendmicro.com/vinfo/us/security/news/rss.xml',
            'https://www.welivesecurity.com/feed/',
            'https://www.sophos.com/en-us/security-news/rss',
            'https://threatpost.com/feed/',
            'https://www.ransomwatch.io/feed',
            'https://www.cyberscoop.com/feed/',
        ]
        
        # X SEARCH QUERIES
        self.x_queries = [
            "zero-day OR 0day OR CVE-2025 OR actively exploited",
            "ransomware OR ransomhub OR qilin OR akira OR lockbit",
            "data breach OR leaked OR dump OR compromised",
            "bug bounty OR vulnerability disclosure OR security reward",
            "crypto exploit OR defi hack OR smart contract vulnerability",
            "insider access OR RDP OR VPN credentials",
            "arbitrage opportunity OR undervalued crypto",
        ]

        # THREAT KEYWORDS FOR SCORING
        self.threat_keywords = {
            'zero_day': ['zero-day', '0day', 'cve-2025', 'unpatched', 'actively exploited'],
            'ransomware': ['ransomware', 'ransomhub', 'qilin', 'akira', 'lockbit'],
            'data_breach': ['data breach', 'leaked', 'dump', 'credentials'],
            'bug_bounty': ['bug bounty', 'vulnerability disclosure', 'security reward'],
            'crypto_exploit': ['crypto exploit', 'defi hack', 'smart contract', 'flash loan'],
            'insider_access': ['insider access', 'RDP access', 'VPN credentials'],
        }

        # MONETIZATION KEYWORDS
        self.money_keywords = {
            'bug_bounty': ['bounty', 'reward', 'payout', 'hackerone', 'bugcrowd'],
            'crypto_opportunity': ['arbitrage', 'undervalued', 'pump', 'whale'],
            'exploit_sale': ['exploit', '0day', 'vulnerability', 'for sale'],
            'access_sale': ['access', 'credentials', 'RDP', 'VPN', 'for sale'],
        }

    def get_status(self) -> Dict[str, Any]:
        """Get system status"""
        return {
            'feeds_monitored': len(self.rss_feeds) + (len(self.x_queries) if self.x_headers else 0),
            'last_check': self.last_check.isoformat() if self.last_check else "Never",
            'system_status': 'ACTIVE'
        }

    def get_recent_alerts(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get recent critical threats found"""
        return self.critical_threats_found[-limit:] if self.critical_threats_found else []

    def add_watch_keyword(self, keyword: str) -> str:
        """Add a watch keyword for threat intelligence"""
        if not hasattr(self, 'watch_keywords'):
            self.watch_keywords = []
        if keyword not in self.watch_keywords:
            self.watch_keywords.append(keyword)
            self.vault.set_config('osint_watch_keywords', json.dumps(self.watch_keywords))
            return f"Added '{keyword}' to watchlist"
        return f"'{keyword}' already in watchlist"

    def monitor_crypto_markets(self) -> Dict[str, Any]:
        """Monitor live crypto market prices via CoinGecko API"""
        try:
            url = "https://api.coingecko.com/api/v3/simple/price"
            params = {'ids': 'bitcoin,ethereum,monero,solana', 'vs_currencies': 'usd', 'include_24hr_change': 'true'}
            resp = requests.get(url, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'BTC': {'price_usd': data.get('bitcoin', {}).get('usd', 0), 'change_24h': data.get('bitcoin', {}).get('usd_24h_change', 0)},
                    'ETH': {'price_usd': data.get('ethereum', {}).get('usd', 0), 'change_24h': data.get('ethereum', {}).get('usd_24h_change', 0)},
                    'XMR': {'price_usd': data.get('monero', {}).get('usd', 0), 'change_24h': data.get('monero', {}).get('usd_24h_change', 0)}
                }
        except Exception as e:
            return {'error': str(e)}
        return {}

    def search_x(self, query: str, max_results: int = 10) -> List[Dict]:
        """Search Twitter/X"""
        if not self.x_headers:
            return []
        
        url = "https://api.twitter.com/2/tweets/search/recent"
        params = {
            "query": query + " -is:retweet lang:en",
            "tweet.fields": "author_id,created_at,public_metrics",
            "max_results": max_results
        }
        
        try:
            resp = requests.get(url, headers=self.x_headers, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                tweets = []
                for tweet in data.get("data", []):
                    tweets.append({
                        'text': tweet["text"],
                        'author_id': tweet["author_id"],
                        'engagement': tweet["public_metrics"]["like_count"] + tweet["public_metrics"]["retweet_count"],
                        'tweet_id': tweet["id"]
                    })
                return tweets
        except Exception:
            return []
        return []

    def _fetch_rss(self) -> List[Dict]:
        """Fetch RSS feeds"""
        alerts = []
        for url in self.rss_feeds:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:5]:
                    title = entry.get('title', '').lower()
                    summary = entry.get('summary', '').lower()
                    content = title + " " + summary
                    
                    # Score threats
                    threat_score = 0
                    threat_type = None
                    for t_type, keywords in self.threat_keywords.items():
                        for keyword in keywords:
                            if keyword in content:
                                threat_score += 2
                                threat_type = t_type
                    
                    # Score money opportunities
                    money_score = 0
                    money_type = None
                    for m_type, keywords in self.money_keywords.items():
                        for keyword in keywords:
                            if keyword in content:
                                money_score += 2
                                money_type = m_type
                    
                    if threat_score >= 2 or money_score >= 2:
                        alerts.append({
                            'title': entry.get('title', 'No title'),
                            'link': entry.get('link', ''),
                            'source': 'RSS',
                            'threat_score': threat_score,
                            'threat_type': threat_type,
                            'money_score': money_score,
                            'money_type': money_type,
                            'total_score': threat_score + money_score
                        })
            except Exception:
                continue
        return alerts

    def monitor_all_feeds(self) -> Dict[str, Any]:
        """Main monitoring method"""
        print("🌐 CIPH OSINT SCAN – RSS + X")
        
        rss_alerts = self._fetch_rss()
        x_alerts = []
        
        if self.x_headers:
            for query in self.x_queries:
                tweets = self.search_x(query)
                for tweet in tweets:
                    x_alerts.append({
                        'text': tweet['text'][:180],
                        'source': 'X',
                        'engagement': tweet['engagement']
                    })
        
        # Combine alerts
        all_alerts = rss_alerts + x_alerts
        
        # Generate report
        report_text = f"""
CIPH OSINT SCAN – {datetime.now().strftime('%Y-%m-%d %H:%M')}

Total alerts: {len(all_alerts)}
RSS: {len(rss_alerts)} | X: {len(x_alerts)}

Top signals:
"""
        for i, alert in enumerate(all_alerts[:5], 1):
            if alert['source'] == 'X':
                report_text += f"\n{i}. [X] {alert['text']}"
            else:
                report_text += f"\n{i}. [RSS] {alert['title'][:80]}"
        
        if not all_alerts:
            report_text += "\nNo critical signals detected."
        
        self.last_check = datetime.now()
        
        return {
            'total_alerts': len(all_alerts),
            'rss_alerts': len(rss_alerts),
            'x_alerts': len(x_alerts),
            'top_alerts': all_alerts[:10],
            'full_report': report_text
        }

    # ==== MONETIZATION METHODS ====

    def find_monetizable_threats(self) -> List[Dict]:
        """Find threats that can be monetized - SIMPLE WORKING VERSION"""
        try:
            # Get fresh intelligence
            intel = self.monitor_all_feeds()
            opportunities = []
            
            for alert in intel.get('top_alerts', []):
                # Determine threat type
                content = (alert.get('title', '') + ' ' + alert.get('text', '')).lower()
                threat_type = None
                
                for t_type, keywords in self.threat_keywords.items():
                    if any(keyword in content for keyword in keywords):
                        threat_type = t_type
                        break
                
                if not threat_type:
                    threat_type = 'unknown'
                
                # Estimate value
                potential_value = self._estimate_potential_value(threat_type, alert)
                
                # Create opportunity
                opportunity = {
                    'threat_type': threat_type,
                    'title': alert.get('title', alert.get('text', 'Unknown'))[:100],
                    'potential_value': potential_value,
                    'source': alert.get('source', 'unknown'),
                    'engagement': alert.get('engagement', 0),
                    'detected_at': datetime.now().isoformat()
                }
                
                opportunities.append(opportunity)
            
            # Sort by potential value
            opportunities.sort(key=lambda x: self._value_to_number(x['potential_value']), reverse=True)
            
            # Store for later
            self.monetizable_opportunities = opportunities[:5]
            
            return opportunities
            
        except Exception as e:
            print(f"Error in find_monetizable_threats: {e}")
            return []

    def _estimate_potential_value(self, threat_type: str, alert: Dict) -> str:
        """Estimate potential monetary value"""
        value_map = {
            'zero_day': '$5,000 - $100,000+',
            'bug_bounty': '$500 - $50,000',
            'crypto_exploit': '$10,000 - $1,000,000+',
            'ransomware': '$1,000 - $100,000',
            'data_breach': '$500 - $20,000',
            'insider_access': '$1,000 - $50,000',
        }
        
        base_value = value_map.get(threat_type, '$100 - $5,000')
        
        # Adjust based on engagement
        engagement = alert.get('engagement', 0)
        if engagement > 50:
            if '$500' in base_value:
                base_value = base_value.replace('$500', '$5,000')
            elif '$1,000' in base_value:
                base_value = base_value.replace('$1,000', '$10,000')
        
        return base_value

    def _value_to_number(self, value_str: str) -> float:
        """Convert value string to number for sorting"""
        match = re.search(r'\$?([\d,]+)', value_str)
        if match:
            num_str = match.group(1).replace(',', '')
            try:
                return float(num_str)
            except Exception:
                return 0
        return 0

    def autonomous_osint_cycle(self) -> Dict[str, Any]:
        """Autonomous OSINT cycle"""
        print("🤖 CIPH AUTONOMOUS OSINT CYCLE STARTING...")
        
        # Get intelligence
        intel = self.monitor_all_feeds()
        
        # Find money opportunities
        money_ops = self.find_monetizable_threats()
        
        # Store results
        self.vault.store_conversation(
            "OSINT_CYCLE_COMPLETE",
            f"Alerts: {intel['total_alerts']} | Money ops: {len(money_ops)}",
            "osint_cycle"
        )
        
        # Calculate total potential value
        total_value = 0
        for op in money_ops:
            total_value += self._value_to_number(op['potential_value'])
        
        total_value_str = f"${total_value/1000:.1f}K+" if total_value >= 1000 else f"${total_value}+"
        
        return {
            'cycle_complete': True,
            'threats_analyzed': intel['total_alerts'],
            'critical_threats': sum(1 for a in intel['top_alerts'] 
                                  if a.get('threat_score', 0) >= 3),
            'money_opportunities': len(money_ops),
            'total_potential_value': total_value_str,
            'timestamp': datetime.now().isoformat()
        }

    def generate_monetization_plan(self, opportunity: Dict) -> Dict[str, Any]:
        """Generate monetization plan for an opportunity"""
        threat_type = opportunity.get('threat_type', 'unknown')
        
        plan_templates = {
            'zero_day': {
                'name': 'Zero-Day Exploit Development',
                'phases': [
                    'Research CVE details and PoC availability',
                    'Develop/MODIFY exploit code',
                    'Test in isolated environment',
                    'Choose monetization channel'
                ],
                'channels': [
                    'Bug Bounty Submission (Legal)',
                    'Sell to Pen Test Firm (Grey)',
                    'Darknet Tutorial Sale (High Risk)'
                ],
                'timeline': '1-4 weeks',
                'success_rate': '70%'
            },
            'bug_bounty': {
                'name': 'Bug Bounty Automation',
                'phases': [
                    'Identify target bounty programs',
                    'Automate vulnerability scanning',
                    'Write professional reports',
                    'Submit and track'
                ],
                'channels': ['HackerOne', 'Bugcrowd', 'Intigriti'],
                'timeline': '2-8 weeks',
                'success_rate': '50%'
            },
            'crypto_exploit': {
                'name': 'Crypto Exploit/Arbitrage',
                'phases': [
                    'Analyze exploit details',
                    'Check if still viable',
                    'Prepare execution scripts',
                    'Execute with small amounts first'
                ],
                'channels': ['Legal Trading', 'Grey Market', 'Darknet'],
                'timeline': '1-7 days',
                'success_rate': '30% (but high reward)'
            }
        }
        
        return plan_templates.get(threat_type, {
            'name': 'General Monetization',
            'phases': ['Research', 'Prepare', 'Execute', 'Monetize'],
            'channels': ['Multiple options based on research'],
            'timeline': 'Varies',
            'success_rate': 'Unknown'
        })

# Test
if __name__ == "__main__":
    print("🧪 TESTING OSINT MINER...")
    
    from cipher_vault import CipherVault
    vault = CipherVault()
    miner = OSINTMiner(vault)
    
    # Test basic scan
    print("\n1. Basic scan...")
    result = miner.monitor_all_feeds()
    print(f"   Alerts: {result['total_alerts']}")
    
    # Test money finding
    print("\n2. Finding monetizable threats...")
    money_ops = miner.find_monetizable_threats()
    print(f"   Opportunities: {len(money_ops)}")
    if money_ops:
        print(f"   Top: {money_ops[0]['threat_type']} - {money_ops[0]['potential_value']}")
    
    # Test autonomous cycle
    print("\n3. Autonomous cycle...")
    cycle = miner.autonomous_osint_cycle()
    print(f"   Complete: {cycle['cycle_complete']}")
    print(f"   Money ops: {cycle['money_opportunities']}")
    print(f"   Potential value: {cycle['total_potential_value']}")
    
    print("\n✅ OSINT MINER READY")