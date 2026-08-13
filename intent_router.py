#!/usr/bin/env python3
# intent_router.py - Classifies user input before hitting AI

import re
from typing import Tuple, Optional

class IntentRouter:
    """
    Lightweight pre-LLM classifier.
    Tags input as COMMAND, INTEL, or CONSULT.
    Maps natural language to system commands.
    """

    def __init__(self):
        # Natural language to command mappings (no slash needed)
        self.nl_commands = {
            # Darknet / OSINT
            r'\b(run|execute|start|perform)\s+a?\s*darknet\s+scan\b': '/darknet-scan',
            r'\b(darknet|threat)\s+(intel|scan|analysis)\b': '/darknet-scan',
            r'\b(check|show|get)\s+darknet\s+status\b': '/darknet-status',
            r'\bdarknet\s+status\b': '/darknet-status',
            r'\btor\s+check\b': '/tor-check',
            r'\b(new|fresh)\s+identity\b': '/new-identity',
            r'\bghost\s+mode\b': '/ghost-mode',
            r'\bosint\s+scan\b': '/osint',
            r'\bthreat\s+intel\b': '/osint',
            r'\bshow\s+report\b': '/darknet-report',
            r'\b(crypto|btc|eth)\s+price\b': '/market-data',
            r'\b(arbitrage|arb)\s+scan\b': '/arbitrage-scan',
            r'\bmarket\s+trends?\b': '/market-trends',
            r'\btrading\s+signals?\b': '/trading-signals',
            r'\bportfolio\s+health\b': '/portfolio-health',

            # Pentesting / Security
            r'\bport\s+scan\s+(\S+)\b': '/port-scan {1}',
            r'\bscan\s+ports\s+(\S+)\b': '/port-scan {1}',
            r'\bweb\s+scan\s+(\S+)\b': '/web-scan {1}',
            r'\bsecurity\s+audit\s+(\S+)\b': '/security-audit {1}',
            r'\bssl\s+scan\s+(\S+)\b': '/ssl-scan {1}',
            r'\bnetwork\s+discovery\b': '/network-discovery',

            # Bounty
            r'\bbounty\s+scan\s+(\S+)\b': '/bounty-scan {1}',
            r'\bbounty\s+report\s+(\S+)\b': '/bounty-report {1}',
            r'\bbounty\s+programs?\b': '/bounty-programs',

            # Workflows
            r'\bstart\s+workflow\s+(\w+)\b': '/start-workflow {1}',
            r'\bstop\s+workflow\s+(\w+)\b': '/stop-workflow {1}',
            r'\bworkflow\s+status\b': '/workflow-status',
            r'\bauto\s+mode\b': '/auto-mode',
            r'\bstop\s+all\s+workflows?\b': '/stop-all-workflows',

            # Self-awareness / upgrades
            r'\bself\s+report\b': '/self-report',
            r'\bself\s+analyze\b': '/self-analyze',
            r'\bshow\s+upgrades?\b': '/upgrades',
            r'\bapply\s+upgrade\s+(\w+)\b': '/apply-upgrade {1}',
            r'\breject\s+upgrade\s+(\w+)\b': '/reject-upgrade {1}',

            # Status / meta
            r'\bsystem\s+status\b': '/status',
            r'\breality\s+check\b': '/reality-check',
            r'\bmodules?\s+list\b': '/modules',
            r'\bload\s+module\s+(\w+)\b': '/load {1}',
            r'\bunload\s+module\s+(\w+)\b': '/unload {1}',

            # File / project
            r'\bscan\s+project\b': '/scan-project',
            r'\bread\s+file\s+(\S+)\b': '/read-file {1}',
            r'\bsearch\s+files?\s+(\S+)\b': '/search-in-files {1}',

            # Security
            r'\bsecurity\s+scan\b': '/security-scan',
            r'\bclean\s+footprints?\b': '/clean-footprints',
            r'\bintegrity\s+check\b': '/integrity-check',
            r'\bbackup\s+now\b': '/backup-now',
            r'\bdisk\s+(security|encryption)\b': '/disk-security',

            # Trading & Finance Shortcuts
            r'\bpaper\s+trade\s+(\S+)\s+(\S+)\s+(\S+)\b': '/paper-trade {1} {2} {3}',
            r'\bstop\s+loss\s+(\S+)\s+(\S+)\s+(\S+)\b': '/stop-loss {1} {2} {3}',
            r'\bcrypto\s+prices?\b': '/crypto-prices',
        }

        self.learned_mappings = {}

    def classify(self, user_input: str) -> Tuple[str, Optional[str]]:
        text = user_input.strip().lower()
    
        # 1. Already a slash command
        if text.startswith('/'):
            return 'COMMAND', text
    
        # Check learned mappings
        for pattern, cmd in self.learned_mappings.items():
            if re.search(pattern, text, re.IGNORECASE):
                return 'COMMAND', cmd

        # 2. Exclude common greetings
        greetings = ['hello', 'hi', 'hey', 'good morning', 'good evening', 'howdy', 'sup']
        if text in greetings or text.rstrip('!') in greetings:
            return 'CONSULT', None
    
        # 3. Exclude date/time questions
        date_time_phrases = [
            'whats todays date', 'what is todays date', 'todays date',
            'what date is it', 'what is the date', 'date today',
            'what time is it', 'current time', 'the time now',
            'whats the time', 'what is the time'
        ]
        if any(phrase in text for phrase in date_time_phrases):
            return 'CONSULT', None
    
        # 4. Exclude suggestion phrases
        suggestion_phrases = [
            'what do you suggest', 'any suggestions', 'what should we',
            'what do you recommend', 'any ideas', 'what would you do',
            'what do you think we should', 'give me a suggestion'
        ]
        if any(phrase in text for phrase in suggestion_phrases):
            return 'CONSULT', None
    
        # 5. Match natural language commands
        for pattern, command_template in self.nl_commands.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                cmd = command_template
                for i, group in enumerate(match.groups(), start=1):
                    if group:
                        cmd = cmd.replace(f'{{{i}}}', group)
                return 'COMMAND', cmd
    
        # 6. Default to consult (LLM handles it)
        return 'CONSULT', None

    def classify_with_context(self, user_input: str, history: list = None) -> Tuple[str, Optional[str]]:
        """Classify user input with conversation context"""
        intent, cmd = self.classify(user_input)
        if intent == 'CONSULT' and history:
            last_msg = history[-1] if isinstance(history[-1], str) else history[-1].get('content', '')
            if any(term in last_msg.lower() for term in ['scan', 'audit', 'report']):
                if any(kw in user_input.lower() for kw in ['result', 'show', 'status', 'output']):
                    return 'COMMAND', '/reality-check'
        return intent, cmd

    def parse_chain(self, user_input: str) -> list:
        """Parse chained commands separated by 'and', 'then', or ';'"""
        separators = [' and ', ' then ', ';']
        parts = [user_input]
        for sep in separators:
            new_parts = []
            for part in parts:
                if sep in part:
                    new_parts.extend(part.split(sep))
                else:
                    new_parts.append(part)
            parts = new_parts

        commands = []
        for part in parts:
            p = part.strip()
            if p:
                intent, cmd = self.classify(p)
                if intent == 'COMMAND' and cmd:
                    commands.append(cmd)
        return commands

    def learn_mapping(self, natural_phrase: str, command: str):
        """Learn custom phrase to command mapping"""
        pattern = r'\b' + r'\s+'.join(re.escape(w) for w in natural_phrase.split()) + r'\b'
        self.learned_mappings[pattern] = command

    def resolve_command(self, user_input: str) -> Optional[str]:
        """Convenience method: returns command string or None."""
        intent, cmd = self.classify(user_input)
        return cmd if intent == 'COMMAND' else None