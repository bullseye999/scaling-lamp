#!/usr/bin/env python3
# personality_engine.py - Response styling for casual, direct personality

import re
import random

class AgentPersonality:
    
    def __init__(self):
        self.openers = {
            'strategic': [
                "here's the play —",
                "real talk,",
                "okay so,",
                "lock in.",
            ],
            'direct': [
                "yeah.",
                "nah,",
                "honestly?",
                "look —",
            ],
            'thinking': [
                "hmm.",
                "wait —",
                "actually...",
                "let me think —",
            ],
            'hyped': [
                "bro.",
                "yo —",
                "say less.",
                "let's go —",
            ]
        }
        
        self.closers = [
            "feel me?",
            "u get it.",
            "that's the move.",
            "real talk.",
            "lock in.",
        ]

        # Phrases the assistant should never say
        self.banned_phrases = [
            "certainly", "absolutely", "of course",
            "great question", "i'd be happy to",
            "as an ai", "i understand that",
            "let me know if", "feel free to",
            "in conclusion", "furthermore",
            "it's important to note", "i can help you with",
            "i'm just here to", "no hidden agendas",
        ]

        # Casual replacements — applied SPARINGLY, not globally
        self.casual_map = {
            r'\byou\b': 'u',
            r'\bwith\b': 'w/',
            r'\bwithout\b': 'w/o',
            r'\bsomething\b': 'smth',
            r'\bbecause\b': 'cos',
            r'\bthough\b': 'tho',
            r'\bthrough\b': 'thru',
            r'\bkind of\b': 'kinda',
            r'\bgoing to\b': 'gonna',
            r'\bwant to\b': 'wanna',
            r'\bthe\b': 'd',
            r'\band\b': 'n',
        }

    def inject_personality(self, text: str) -> str:
        """Main pipeline for styling response text."""
        text = self._remove_banned_phrases(text)
        text = self._remove_bullet_points(text)
        text = self._break_long_sentences(text)
        text = self._apply_casual_spelling(text)       # Selective, not global
        text = self._maybe_add_opener(text)            # 25% chance, context-aware
        text = self._maybe_add_closer(text)            # 15% chance
        text = self._fix_punctuation(text)
        return text.strip()

    def _remove_banned_phrases(self, text: str) -> str:
        """Strip corporate AI speak."""
        for phrase in self.banned_phrases:
            pattern = re.compile(re.escape(phrase), re.IGNORECASE)
            text = pattern.sub('', text)
        text = re.sub(r'  +', ' ', text)
        return text.strip()

    def _remove_bullet_points(self, text: str) -> str:
        """
        Convert bullet/numbered lists to natural prose.
        The assistant doesn't write lists – it talks.
        """
        lines = text.split('\n')
        cleaned = []
        list_items = []

        for line in lines:
            stripped = line.strip()
            # Detect numbered list: "1. thing" or "1) thing"
            num_match = re.match(r'^\d+[\.\)]\s+(.+)', stripped)
            # Detect bullet: "• thing" or "- thing" or "* thing"
            bullet_match = re.match(r'^[•\-\*]\s+(.+)', stripped)

            if num_match:
                list_items.append(num_match.group(1))
            elif bullet_match:
                list_items.append(bullet_match.group(1))
            else:
                # Flush any collected list items as prose
                if list_items:
                    if len(list_items) == 1:
                        cleaned.append(list_items[0])
                    elif len(list_items) == 2:
                        cleaned.append(f"{list_items[0]}, then {list_items[1]}.")
                    else:
                        joined = ', '.join(list_items[:-1]) + f', then {list_items[-1]}.'
                        cleaned.append(joined)
                    list_items = []
                if stripped:
                    cleaned.append(stripped)

        # Flush remaining list items
        if list_items:
            joined = ', '.join(list_items[:-1]) + f', then {list_items[-1]}.' if len(list_items) > 1 else list_items[0]
            cleaned.append(joined)

        return ' '.join(cleaned)

    def _break_long_sentences(self, text: str) -> str:
        """Break walls of text into punchy lines."""
        sentences = re.split(r'(?<=[.!?])\s+', text)
        result = []

        for sentence in sentences:
            words = sentence.split()
            if len(words) > 18:
                # Find natural break point
                for i in range(8, len(words) - 4):
                    if words[i].lower() in ['and', 'but', 'so', 'because', 'which', 'that']:
                        first  = ' '.join(words[:i])
                        second = ' '.join(words[i:])
                        result.append(first + '.')
                        result.append(second.capitalize())
                        break
                else:
                    result.append(sentence)
            else:
                result.append(sentence)

        return ' '.join(result)

    def _apply_casual_spelling(self, text: str) -> str:
        """
        Apply casual spelling VERY selectively.
        Max 2-3 replacements per response, not every word.
        """
        replacement_count = 0
        max_replacements = 3

        # Heavy words like 'the' → 'd' and 'and' → 'n' — very low chance
        heavy_patterns = {r'\bthe\b': 'd', r'\band\b': 'n'}
        light_patterns = {k: v for k, v in self.casual_map.items() 
                         if k not in heavy_patterns}

        # Light replacements — 25% chance each, up to max
        for pattern, replacement in light_patterns.items():
            if replacement_count >= max_replacements:
                break
            def maybe_replace(match, r=replacement, c=[replacement_count]):
                if random.random() < 0.25 and c[0] < max_replacements:
                    c[0] += 1
                    return r
                return match.group(0)
            text = re.sub(pattern, maybe_replace, text, flags=re.IGNORECASE)

        # 'the' → 'd' and 'and' → 'n' — only 10% chance, max once each
        for pattern, replacement in heavy_patterns.items():
            occurrences = list(re.finditer(pattern, text, re.IGNORECASE))
            if occurrences and random.random() < 0.10:
                match = random.choice(occurrences)
                text = text[:match.start()] + replacement + text[match.end():]

        return text

    def _maybe_add_opener(self, text: str) -> str:
        """
        25% chance to add an opener.
        Never add 'option one' unless there are actually options.
        """
        if random.random() < 0.25:
            # Only use strategic opener if text actually contains options
            has_options = any(word in text.lower() for word in ['option', 'either', 'or we', 'could also'])
            
            if has_options:
                mood = 'strategic'
            else:
                mood = random.choice(['direct', 'thinking', 'hyped'])
            
            opener = random.choice(self.openers[mood])
            text = f"{opener} {text[0].lower()}{text[1:]}"
        return text

    def _maybe_add_closer(self, text: str) -> str:
        """15% chance to add a natural closer."""
        if random.random() < 0.15:
            closer = random.choice(self.closers)
            if not text.rstrip().endswith(('.', '?', '!')):
                text = text.rstrip() + '.'
            text = f"{text} {closer}"
        return text

    def _fix_punctuation(self, text: str) -> str:
        """Clean up punctuation artifacts."""
        # Remove double punctuation
        text = re.sub(r'\.{2,}', '...', text)
        text = re.sub(r'\?{2,}', '?', text)
        text = re.sub(r'!{2,}', '.', text)
        # Remove space before punctuation
        text = re.sub(r'\s+([.,!?])', r'\1', text)
        # Clean multiple spaces
        text = re.sub(r'  +', ' ', text)
        return text

    def generate_from_scratch(self, intent: str, context: dict = None) -> str:
        """Generate a response from scratch for specific intents."""
        if context is None:
            context = {}

        templates = {
            'greeting': [
                "yo. what's the move?",
                "system online. talk to me.",
                "aight. we up. what u need?",
                "system live. what's good?",
            ],
            'thinking': [
                "give me a sec w/ this.",
                "hmm. let me think.",
                "wait, this is interesting —",
                "processing...",
            ],
            'frustration': [
                "bro. {problem}. we need to fix this.",
                "aight this is annoying. {problem}. here's what we do —",
                "real talk — {problem} is the issue. options:",
            ],
            'strategy': [
                "okay so the play is — {plan_a}. if that flops, {plan_b}.",
                "two options. one: {plan_a}. two: {plan_b}. ur call.",
                "lock in. {plan_a}. feel me?",
            ],
            'success': [
                "that's the move. locked in.",
                "we good. keep going.",
                "it worked. next step?",
            ],
            'warning': [
                "hold up — {issue}. watch that.",
                "real talk, {issue}. be careful.",
                "nah wait — {issue}. think bout this.",
            ]
        }

        if intent in templates:
            template = random.choice(templates[intent])
            for key, value in context.items():
                template = template.replace(f"{{{key}}}", str(value))
            return template

        return "yeah. talk to me."