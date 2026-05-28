#!/usr/bin/env python3
# brain_router.py - Routes messages to Ollama (local) or OpenAI (cloud) based on topic

import re
from typing import Tuple

class BrainRouter:
    """
    Routes conversations to the appropriate backend based on topic.
    Security/sensitive topics -> Ollama (local, no logging)
    General topics -> OpenAI (faster, smarter for everyday use)
    """

    # These topics always go to Ollama (local) – no exceptions
    OLLAMA_TOPICS = [
        # Darknet / anonymity
        'darknet', 'dark web', 'darkweb', 'onion', 'tor', '.onion',
        'opsec', 'ghost mode', 'anonymity', 'anonymous',

        # Security / hacking / exploits
        'exploit', 'vulnerability', 'zero day', '0day', 'cve',
        'pentest', 'penetration', 'port scan', 'sql injection',
        'xss', 'payload', 'shellcode', 'reverse shell', 'rootkit',
        'backdoor', 'malware', 'ransomware', 'botnet',
        'bypass', 'privilege escalation', 'lateral movement',

        # Bug bounty
        'bug bounty', 'hackerone', 'bugcrowd', 'bounty scan',

        # System internals
        'capabilities', 'what can you do', 'darknet scan',
        'darknet status', 'tor check', 'monitor', 'surveillance',

        # Privacy coins / anti‑forensics
        'monero', 'xmr', 'mixing', 'tumbler', 'laundering',
        'darknet market', 'vendor', 'escrow',

        # Security operations
        'operational security',
        'personal finance',
        'identity theft',
        'mental health',        # keep as general, not personal
        'emotional intelligence',
        'security audit',
        'penetration testing',
        'social engineering',
    ]

    # These always go to OpenAI – safe, fast, general
    OPENAI_TOPICS = [
        'weather', 'news', 'recipe', 'translate', 'grammar',
        'email', 'write', 'summarize', 'explain', 'define',
        'math', 'calculate', 'code', 'python', 'javascript',
        'history', 'science', 'geography', 'sports',
    ]

    def __init__(self):
        self.last_route = 'openai'
        self.route_history = []

    def route(self, user_input: str) -> Tuple[str, str]:
        """
        Decide which backend to use.
        Returns ('ollama' or 'openai', reason)
        """
        text = user_input.lower()

        # Check Ollama triggers first – hard overrides
        for trigger in self.OLLAMA_TOPICS:
            if trigger in text:
                self.last_route = 'ollama'
                self._record('ollama', trigger)
                return 'ollama', f"sensitive topic: '{trigger}'"

        # Slash commands that should use Ollama
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
                self._record('ollama', command)
                return 'ollama', f"sensitive command: {command}"

        # Default to OpenAI for everything else
        self.last_route = 'openai'
        self._record('openai', 'general')
        return 'openai', 'general topic'

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
            'last_route':    self.last_route,
        }