#!/usr/bin/env python3
# brain_router.py - Routes to Ollama or OpenAI based on topic

import re
from typing import Tuple

class BrainRouter:
    """
    Routes conversations to the right brain based on topic.
    Sensitive/sovereign topics -> Ollama (local, no logging, no filters)
    General topics -> OpenAI (faster, smarter for everyday use)
    """

    # These topics always go to Ollama — no exceptions
    OLLAMA_TOPICS = [
        # Darknet / OPSEC
        'darknet', 'dark web', 'darkweb', 'onion', 'tor', '.onion',
        'opsec', 'ghost mode', 'anonymity', 'anonymous',

        # Security / hacking
        'exploit', 'vulnerability', 'zero day', '0day', 'cve',
        'pentest', 'penetration', 'port scan', 'sql injection',
        'xss', 'payload', 'shellcode', 'reverse shell', 'rootkit',
        'backdoor', 'malware', 'ransomware', 'botnet',
        'bypass', 'privilege escalation', 'lateral movement',

        # Bug bounty
        'bug bounty', 'hackerone', 'bugcrowd', 'bounty scan',

        # Personal / sensitive
        'suicide', 'note ready', 'kill myself', 'end it', 'betrayed', 'revenge', 'defend',
        'scamming', 'fraud', 'illegal', 'cops', 'police',
         
        # Add these to the existing list:
        'opsec', 'privacy', 'monitoring', 'surveillance', 'backdoor',
        'compromise', 'anxiety', 'stress', 'burnout',
        'security testing', 'penetration test'

        # Ciph internals
        'ciph capabilities', 'what can you do', 'darknet scan',
        'darknet status', 'tor check', 'monitor', 'surveillance',

        # Crypto / markets
        'monero', 'xmr', 'mixing', 'tumbler', 'laundering',
        'darknet market', 'vendor', 'escrow',


        # Added via UP-006
        'operational security',
        'personal finance',
        'identity theft',
        'mental health',
        'emotional intelligence',
        'security audit',
        'penetration testing',
        'social engineering',
    ]

    # These always go to OpenAI — safe, fast, smart
    OPENAI_TOPICS = [
        'weather', 'news', 'recipe', 'translate', 'grammar',
        'email', 'write', 'summarize', 'explain', 'define',
        'math', 'calculate', 'code', 'python', 'javascript',
        'history', 'science', 'geography', 'sports',
    ]

    def __init__(self):
        self.last_route = 'openai'
        self.route_history = []
        self.sensitivity_threshold = 0.5
        self.user_preferences = []

    def _calculate_ollama_score(self, user_input: str) -> float:
        """Calculate weighted sensitivity score for Ollama routing"""
        text = user_input.lower()
        score = 0.0
        
        # Weighted keyword dictionary
        weighted_topics = {
            'darknet': 0.9, 'tor': 0.9, '.onion': 0.9, 'opsec': 0.9,
            'exploit': 0.8, 'malware': 0.9, 'ransomware': 0.9, '0day': 0.9,
            'pentest': 0.8, 'bounty': 0.7, 'monero': 0.8, 'xmr': 0.8,
            'vulnerability': 0.7, 'port scan': 0.8, 'security audit': 0.7,
            'privacy': 0.6, 'mental health': 0.6, 'identity theft': 0.8
        }
        
        for topic, weight in weighted_topics.items():
            if topic in text:
                score += weight
                
        # Check standard topics
        for trigger in self.OLLAMA_TOPICS:
            if trigger in text and trigger not in weighted_topics:
                score += 0.5
                
        return min(1.0, score)

    def route(self, user_input: str) -> Tuple[str, str]:
        """
        Decide which brain to use.
        Returns ('ollama' or 'openai', reason)
        """
        decision = self.route_detailed(user_input)
        return decision['brain'], decision['reason']

    def route_detailed(self, user_input: str, history: list = None) -> dict:
        """Return routing decision with confidence and score details"""
        text = user_input.lower()

        # Check slash commands — darknet/security commands always Ollama
        if user_input.startswith('/'):
            command = user_input.split()[0].lower()
            ollama_commands = [
                '/darknet-scan', '/darknet-status', '/tor-check',
                '/ghost-mode', '/new-identity', '/bounty-scan',
                '/port-scan', '/web-scan', '/security-scan',
                '/security-audit', '/integrity-check',
                '/monitor-id', '/osint',
            ]
            if command in ollama_commands:
                self.last_route = 'ollama'
                self._record('ollama', f"command:{command}")
                return {
                    'brain': 'ollama',
                    'confidence': 1.0,
                    'score': 1.0,
                    'reason': f"sensitive command: {command}"
                }

        # Calculate score
        ollama_score = self._calculate_ollama_score(user_input)
        
        # Boost if context history was sensitive
        if history:
            recent_scores = [self._calculate_ollama_score(h) for h in history[-3:]]
            if recent_scores and (sum(recent_scores) / len(recent_scores)) > 0.4:
                ollama_score = min(1.0, ollama_score + 0.2)

        if ollama_score >= self.sensitivity_threshold:
            decision = 'ollama'
            confidence = min(1.0, ollama_score)
            reason = f"sensitive score: {ollama_score:.2f}"
        else:
            decision = 'openai'
            confidence = 1.0 - ollama_score
            reason = "general topic"

        self.last_route = decision
        self._record(decision, reason)

        return {
            'brain': decision,
            'confidence': round(confidence, 2),
            'score': round(ollama_score, 2),
            'reason': reason
        }

    def learn_from_feedback(self, user_input: str, chosen_brain: str, satisfied: bool):
        """Adapt routing threshold based on user satisfaction feedback"""
        entry = {
            'text': user_input,
            'brain': chosen_brain,
            'satisfied': satisfied
        }
        self.user_preferences.append(entry)

        if satisfied and chosen_brain == 'ollama':
            self.sensitivity_threshold = max(0.3, self.sensitivity_threshold - 0.05)
        elif not satisfied and chosen_brain == 'ollama':
            self.sensitivity_threshold = min(0.85, self.sensitivity_threshold + 0.05)

    def _record(self, brain: str, reason: str):
        self.route_history.append({'brain': brain, 'reason': reason})
        if len(self.route_history) > 50:
            self.route_history = self.route_history[-50:]

    def get_stats(self) -> dict:
        ollama_count = sum(1 for r in self.route_history if r['brain'] == 'ollama')
        openai_count = sum(1 for r in self.route_history if r['brain'] == 'openai')
        return {
            'ollama_routes': ollama_count,
            'openai_routes': openai_count,
            'last_route': self.last_route,
            'sensitivity_threshold': self.sensitivity_threshold
        }