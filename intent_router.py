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
            # Darknet / OSINT execution & reports
            r'^\s*(?:run|execute|start|perform|do)\s+(?:a\s+)?darknet\s+scan\s*$': '/darknet-scan',
            r'^\s*(?:run\s+)?(?:darknet|threat)\s+scan\s*$': '/darknet-scan',
            r'^\s*scan\s+darknet\s*$': '/darknet-scan',
            r'^\s*(?:show|get|view|display|list|what\s+are|what\s+were|tell\s+me)\s+(?:darknet\s+)?(?:alerts|findings|signals)\s*$': '/darknet-report',
            r'^\s*(?:show|get|view|display|give|give\s+me|send)\s+(?:detailed\s+|full\s+|darknet\s+|a\s+detailed\s+)?(?:darknet\s+)?report\s*$': '/darknet-report',
            r'^\s*(?:detailed|full)\s+(?:darknet\s+)?(?:scan|report)\s*$': '/darknet-report',
            r'^\s*darknet\s+report\s*$': '/darknet-report',
            r'^\s*darknet\s+alerts?\s*$': '/darknet-report',
            r'\b(?:check|show|get)\s+darknet\s+status\b': '/darknet-status',
            r'^\s*darknet\s+status\s*$': '/darknet-status',
            r'\btor\s+check\b': '/tor-check',
            r'^\s*check\s+tor\s*$': '/tor-check',
            r'\b(?:new|fresh)\s+identity\b': '/new-identity',
            r'\bghost\s+mode\b': '/ghost-mode',
            r'^\s*(?:run\s+)?osint\s+scan\s*$': '/osint',
            r'^\s*threat\s+intel\s*$': '/osint',
            r'\b(crypto|btc|eth)\s+price\b': '/market-data',
            r'\b(arbitrage|arb)\s+scan\b': '/arbitrage-scan',
            r'^\s*market\s+trends?\s*$': '/market-trends',
            r'^\s*trading\s+signals?\s*$': '/trading-signals',
            r'^\s*portfolio\s+health\s*$': '/portfolio-health',

            # Pentesting / Security
            r'\bport\s+scan\s+(\S+)\b': '/port-scan {1}',
            r'\bscan\s+ports\s+(\S+)\b': '/port-scan {1}',
            r'\bweb\s+scan\s+(\S+)\b': '/web-scan {1}',
            r'\bsecurity\s+audit\s+(\S+)\b': '/security-audit {1}',
            r'\bssl\s+scan\s+(\S+)\b': '/ssl-scan {1}',
            r'^\s*network\s+discovery\s*$': '/network-discovery',

            # Bounty & General Recon Scans
            r'^\s*(?:run\s+(?:a\s+)?)?(?:bounty\s+|web\s+|recon\s+)?scan\s+(?:on\s+|for\s+)?([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\s*$': '/bounty-scan {1}',
            r'^\s*(?:audit|investigate|check\s+surface)\s+(?:on\s+|for\s+)?([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\s*$': '/bounty-scan {1}',
            r'\bbounty\s+scan\s+(\S+)\b': '/bounty-scan {1}',
            r'^\s*(?:run\s+)?bounty\s+scan\s*$': '/bounty-scan',
            r'\bbounty\s+report\s+(\S+)\b': '/bounty-report {1}',
            r'^\s*bounty\s+report\s*$': '/bounty-report',
            r'^\s*bounty\s+programs?\s*$': '/bounty-programs',

            # Workflows
            r'\bstart\s+workflow\s+(\w+)\b': '/start-workflow {1}',
            r'\bstop\s+workflow\s+(\w+)\b': '/stop-workflow {1}',
            r'^\s*workflow\s+status\s*$': '/workflow-status',
            r'^\s*auto\s+mode\s*$': '/auto-mode',
            r'^\s*stop\s+all\s+workflows?\s*$': '/stop-all-workflows',

            # Self-awareness / upgrades / code staging
            r'^\s*self\s+report\s*$': '/self-report',
            r'^\s*self\s+analyze\s*$': '/self-analyze',
            r'^\s*show\s+(?:upgrades?|staged|code)\s*$': '/staged',
            r'^\s*(?:staged|code\s+artifacts?)\s*$': '/staged',
            r'\b(?:apply|approve)\s+(?:upgrade|code|patch|artifact)?\s*([a-zA-Z0-9_\-]+)\b': '/apply {1}',
            r'^\s*(?:apply|approve)\s+it\s*$': '/apply STG-001',
            r'\breview\s+(?:code|patch|artifact)?\s*([a-zA-Z0-9_\-]+)\b': '/review {1}',
            r'\breject\s+(?:upgrade|code|patch|artifact)?\s*([a-zA-Z0-9_\-]+)\b': '/reject {1}',
            r'\brollback\s+(\S+)\b': '/rollback {1}',
            r'^\s*(?:show\s+)?changelog\s*$': '/changelog',

            # Status / meta
            r'^\s*model\s+status\s*$': '/model-status',
            r'^\s*router\s+status\s*$': '/model-status',
            r'^\s*test\s+(?:deepseek|model)\s*$': '/test-deepseek',
            r'^\s*ping\s+(?:deepseek|model)\s*$': '/test-deepseek',
            r'^\s*switch\s+model(?:\s+(\S+))?\s*$': '/switch-model {1}',
            r'^\s*system\s+status\s*$': '/status',
            r'^\s*reality\s+check\s*$': '/reality-check',
            r'^\s*modules?\s+list\s*$': '/modules',
            r'\bload\s+module\s+(\w+)\b': '/load {1}',
            r'\bunload\s+module\s+(\w+)\b': '/unload {1}',

            # File / project
            r'^\s*scan\s+project\s*$': '/scan-project',
            r'\bread\s+file\s+(\S+)\b': '/read-file {1}',
            r'\bsearch\s+files?\s+(\S+)\b': '/search-in-files {1}',

            # Security
            r'^\s*(?:run\s+)?security\s+scan\s*$': '/security-scan',
            r'^\s*clean\s+footprints?\s*$': '/clean-footprints',
            r'^\s*integrity\s+check\s*$': '/integrity-check',
            r'^\s*backup\s+now\s*$': '/backup-now',
            r'^\s*disk\s+(?:security|encryption)\s*$': '/disk-security',

            # Bug Bounty, Intelligence & Sentry
            r'^\s*bounty\s+(?:scopes?|list|reports?)\s*$': '/bounty-list',
            r'^\s*(?:run\s+|do\s+)?bounty\s+scan\s+(\S+)\b': '/bounty-scan {1}',
            r'^\s*(?:generate\s+|write\s+)?bounty\s+report(?:\s+(\S+))?\s*$': '/bounty-report {1}',
            r'^\s*(?:show\s+(?:me\s+)?)?(?:what\s+changed|recon\s+diff)(?:\s+(?:on|for|in))?(?:\s+(\S+))?\s*$': '/what-changed {1}',
            r'^\s*(?:show\s+(?:me\s+)?(?:the\s+)?)?(?:hit\s*list|top\s+targets)(?:\s+(?:for|on))?(?:\s+(\S+))?\s*$': '/hit-list {1}',
            r'^\s*(?:show\s+(?:me\s+)?(?:the\s+)?)?(?:chain\s+reaction|attack\s+path|exploit\s+chain)(?:\s+(?:for|on))?(?:\s+(\S+))?\s*$': '/chain-reaction {1}',
            r'^\s*watchtower\s*$': '/watchtower',
            r'^\s*(?:ghost\s+rating|ghost\s+score|opsec\s+audit)\s*$': '/ghost-rating',
            r'^\s*(?:show\s+(?:me\s+)?)?(?:all\s+)?assets(?:\s+matrix|\s+inventory)?\s*$': '/assets',
            r'^\s*(?:show\s+(?:me\s+)?)?(?:opsec|ghost)\s+history\s*$': '/opsec-history',
            r'^\s*war\s+room\s+(.+)$': '/war-room {1}',
            r'^\s*red\s+team\s+(.+)$': '/war-room {1}',
            r'^\s*(?:daily\s+brief|executive\s+brief|morning\s+brief)\s*$': '/daily-brief',
            r'^\s*(?:narrative\s+timeline|memory\s+timeline)\s*$': '/timeline',

            # Trading & Finance Shortcuts
            r'\bpaper\s+trade\s+(\S+)\s+(\S+)\s+(\S+)\b': '/paper-trade {1} {2} {3}',
            r'\bstop\s+loss\s+(\S+)\s+(\S+)\s+(\S+)\b': '/stop-loss {1} {2} {3}',
            r'^\s*crypto\s+prices?\s*$': '/crypto-prices',
        }

        self.learned_mappings = {}

    def classify(self, user_input: str) -> Tuple[str, Optional[str]]:
        text = user_input.strip().lower()
    
        # 1. Already a slash command
        if text.startswith('/'):
            # Alias /detailed-darknet-scan and /darknet-alerts to /darknet-report
            if text in ['/detailed-darknet-scan', '/darknet-alerts', '/alerts']:
                return 'COMMAND', '/darknet-report'
            return 'COMMAND', text
    
        # Check learned mappings
        for pattern, cmd in self.learned_mappings.items():
            if re.search(pattern, text, re.IGNORECASE):
                return 'COMMAND', cmd

        # 2. Long text / Document handling (prevent false positive command matching)
        if len(text) > 100 and not text.startswith('/'):
            if any(kw in text for kw in ['hackerone', 'bug bounty', 'program scope', 'in-scope', 'out-of-scope', 'out of scope', 'scope policy', 'rules of engagement', 'vulnerability reports', 'submission requirements']):
                return 'COMMAND', f'/bounty-scope {user_input.strip()}'
            return 'CONSULT', None

        # 3. Exclude common greetings
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

        # 5. Check if user is asking a conversational question / inquiry
        # Conversational questions should go to LLM unless asking specifically to show report/alerts
        conversational_starters = (
            'why ', 'why is', 'why are', 'why did', 'why do', 'why does',
            'what do you think', 'what would you do', 'what is one think', 'what is one thing',
            'who is', 'who are', 'who am i', 'do you know', 'do you have', 'is there anything',
            'talk to me', 'ask me', 'can you elaborate', 'tell me more',
            'how are you', 'how do you', 'what are you',
            'can you', 'could you', 'would you', 'will you', 'next time'
        )
        if any(text.startswith(cs) for cs in conversational_starters):
            # Check if this question is specifically asking for scan alerts/report
            if any(kw in text for kw in ['alerts', 'report', 'findings', 'signals']):
                for pattern, command_template in self.nl_commands.items():
                    if 'report' in command_template or 'status' in command_template:
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            return 'COMMAND', command_template
            return 'CONSULT', None
    
        # 6. Match natural language commands
        for pattern, command_template in self.nl_commands.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                cmd = command_template
                for i, group in enumerate(match.groups(), start=1):
                    if group:
                        cmd = cmd.replace(f'{{{i}}}', group)
                return 'COMMAND', cmd
    
        # 7. Default to consult (LLM handles it)
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