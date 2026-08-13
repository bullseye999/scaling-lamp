#!/usr/bin/env python3
# mood_engine.py - Ciph reads your energy and adapts

import re
import time
from typing import Dict, Any, Tuple

class MoodEngine:
    """
    Ciph reads the Operator's energy from every message.
    Adjusts tone, pacing, and response depth accordingly.
    No forced positivity. Just real calibration.
    """

    MOODS = {
        'focused':     {'emoji': '🎯', 'desc': 'locked in, building'},
        'frustrated':  {'emoji': '🔥', 'desc': 'hitting walls'},
        'exploratory': {'emoji': '🔍', 'desc': 'thinking out loud'},
        'low':         {'emoji': '📉', 'desc': 'energy drained'},
        'hyped':       {'emoji': '⚡', 'desc': 'high energy, moving fast'},
        'reflective':  {'emoji': '🌙', 'desc': 'processing, introspective'},
        'strategic':   {'emoji': '♟', 'desc': 'planning mode'},
        'neutral':     {'emoji': '—',  'desc': 'baseline'},
    }

    # Keyword signals per mood
    MOOD_SIGNALS = {
        'frustrated': [
            'why', "doesn't work", "not working", "wtf", "argh",
            "annoying", "frustrated", "shit", "ugh", "still broken",
            "again", "always", "never works", "wasted", "stuck"
        ],
        'hyped': [
            'lets go', "let's go", 'yasss', 'bro', 'fire', 'goated',
            'we locked', 'finally', 'worked', 'it works', 'built',
            'love this', 'amazing', 'crazy', 'insane', 'no way'
        ],
        'low': [
            'tired', 'exhausted', 'drained', 'not feeling it',
            "can't", 'whatever', 'idk', 'pointless', "what's the point",
            'hard', 'overwhelmed', 'stressed', 'too much', 'give up'
        ],
        'focused': [
            'fix', 'build', 'code', 'implement', 'debug',
            'make it', 'add', 'create', 'upgrade', 'improve',
            'optimize', 'let me', 'working on'
        ],
        'reflective': [
            'think', 'feel', 'wonder', 'meaning', 'life', 'dream',
            'believe', 'destiny', 'purpose', 'why am i', 'question',
            'what if', 'imagine', 'philosophy', 'soul', 'god'
        ],
        'strategic': [
            'plan', 'strategy', 'move', 'options', 'decide',
            'should i', 'next step', 'roadmap', 'approach',
            'what if we', 'how do we', 'best way', 'pros cons'
        ],
        'exploratory': [
            'what is', 'how does', 'tell me', 'explain', 'curious',
            'interesting', 'heard about', 'whats', "what's", 'learn'
        ],
    }

    # How Ciph adjusts per mood
    RESPONSE_STYLE = {
        'focused': {
            'tone': 'direct and technical',
            'length': 'medium',
            'opener_hint': "aight let's do it —",
        },
        'frustrated': {
            'tone': 'calm, grounding, solution-first',
            'length': 'short',
            'opener_hint': "okay, breathe. here's the fix —",
        },
        'hyped': {
            'tone': 'match the energy, keep momentum',
            'length': 'short and punchy',
            'opener_hint': "let's go —",
        },
        'low': {
            'tone': 'calm, no pressure, honest',
            'length': 'short, no information overload',
            'opener_hint': "no stress. here's the simplest path —",
        },
        'reflective': {
            'tone': 'deep, thoughtful, exploratory',
            'length': 'longer, more nuanced',
            'opener_hint': "real talk —",
        },
        'strategic': {
            'tone': 'precise, options-based, no fluff',
            'length': 'medium, structured',
            'opener_hint': "here's the play —",
        },
        'exploratory': {
            'tone': 'curious, informative, engaging',
            'length': 'medium',
            'opener_hint': "okay so —",
        },
        'neutral': {
            'tone': 'balanced, natural',
            'length': 'medium',
            'opener_hint': "",
        }
    }

    def __init__(self):
        self.current_mood  = 'neutral'
        self.mood_history  = []
        self.session_start = time.time()

    def detect(self, text: str) -> str:
        """
        Detect mood from user message.
        Returns mood string.
        """
        text_lower = text.lower()
        scores: Dict[str, int] = {mood: 0 for mood in self.MOOD_SIGNALS}

        for mood, signals in self.MOOD_SIGNALS.items():
            for signal in signals:
                if signal in text_lower:
                    scores[mood] += 1

        # Get highest scoring mood
        best_mood = max(scores, key=lambda m: scores[m])
        best_score = scores[best_mood]

        # Also check structural signals
        if self._is_short_command(text):
            best_mood = 'focused'
        elif self._is_venting(text):
            best_mood = 'frustrated'
        elif self._is_late_night_reflection(text):
            best_mood = 'reflective'

        detected = best_mood if best_score > 0 else 'neutral'
        self._record_mood(detected, text)
        self.current_mood = detected
        return detected

    def get_style_injection(self, mood: str = None) -> str:
        """
        Returns a style instruction to inject into Ciph's system prompt.
        Tells the AI how to respond given the detected mood.
        """
        mood = mood or self.current_mood
        style = self.RESPONSE_STYLE.get(mood, self.RESPONSE_STYLE['neutral'])

        return (
            f"\nOPERATOR'S CURRENT MOOD: {mood.upper()}\n"
            f"Adjust your response: {style['tone']}.\n"
            f"Response length: {style['length']}.\n"
            f"If you add an opener, something like: \"{style['opener_hint']}\"\n"
        )

    def get_temperature(self, mood: str = None) -> float:
        """Return a temperature setting based on detected mood."""
        mood = mood or self.current_mood
        mapping = {
            'focused': 0.2,
            'frustrated': 0.3,
            'exploratory': 0.6,
            'low': 0.4,
            'hyped': 0.7,
            'reflective': 0.8,
            'strategic': 0.5,
            'neutral': 0.4
        }
        return mapping.get(mood, 0.4)

    def get_mood_summary(self) -> Dict[str, Any]:
        """Summary of mood patterns this session"""
        if not self.mood_history:
            return {'current': self.current_mood, 'history': [], 'pattern': 'no data yet'}

        mood_counts: Dict[str, int] = {}
        for entry in self.mood_history:
            m = entry['mood']
            mood_counts[m] = mood_counts.get(m, 0) + 1

        dominant = max(mood_counts, key=lambda m: mood_counts[m])
        shifts = self._count_mood_shifts()

        return {
            'current': self.current_mood,
            'dominant_this_session': dominant,
            'mood_counts': mood_counts,
            'mood_shifts': shifts,
            'pattern': self._describe_pattern(dominant, shifts),
            'history': self.mood_history[-5:]
        }

    def flag_shift(self) -> str:
        """
        Detect if mood just changed significantly.
        Returns a note for Ciph to acknowledge naturally — or empty string.
        """
        if len(self.mood_history) < 2:
            return ""

        prev = self.mood_history[-2]['mood']
        curr = self.mood_history[-1]['mood']

        # Significant shifts worth acknowledging
        notable_shifts = {
            ('hyped', 'low'):         "energy dropped — check in.",
            ('low', 'hyped'):         "something switched — build on it.",
            ('focused', 'frustrated'):"hitting friction — slow down.",
            ('frustrated', 'focused'):"refocused — good.",
            ('neutral', 'reflective'):"went deep — follow it.",
        }

        return notable_shifts.get((prev, curr), "")

    # ─────────────────────────────────────────────
    # INTERNAL HELPERS
    # ─────────────────────────────────────────────

    def _record_mood(self, mood: str, text: str):
        self.mood_history.append({
            'mood': mood,
            'timestamp': time.time(),
            'input_preview': text[:40]
        })
        if len(self.mood_history) > 50:
            self.mood_history = self.mood_history[-50:]

    def _is_short_command(self, text: str) -> bool:
        """Short imperative messages = focused mode"""
        words = text.strip().split()
        return len(words) <= 5 and not text.endswith('?')

    def _is_venting(self, text: str) -> bool:
        """Long frustrated messages"""
        return len(text) > 200 and any(
            word in text.lower() for word in ['why', 'always', 'never', 'still', 'again']
        )

    def _is_late_night_reflection(self, text: str) -> bool:
        """Reflective philosophical messages"""
        philosophical = ['life', 'god', 'meaning', 'destiny', 'why am i', 'purpose', 'dream']
        return any(word in text.lower() for word in philosophical)

    def _count_mood_shifts(self) -> int:
        shifts = 0
        for i in range(1, len(self.mood_history)):
            if self.mood_history[i]['mood'] != self.mood_history[i-1]['mood']:
                shifts += 1
        return shifts

    def _describe_pattern(self, dominant: str, shifts: int) -> str:
        if shifts > 5:
            return f"volatile session — lots of switching. dominant: {dominant}"
        elif dominant == 'focused':
            return "solid session — mostly locked in"
        elif dominant == 'reflective':
            return "deep session — lots of thinking"
        elif dominant == 'frustrated':
            return "tough session — hitting friction"
        else:
            return f"mixed session — mostly {dominant}"