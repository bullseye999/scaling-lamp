#!/usr/bin/env python3
# smart_memory.py - Ciph remembers and references naturally

import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from cipher_vault import CipherVault

class SmartMemory:
    """
    Ciph remembers what matters.
    Surfaces past context naturally in conversation — not like a database query,
    like a person who was actually paying attention.
    """

    def __init__(self, vault: CipherVault):
        self.vault = vault
        self.session_memory = []       # Current session
        self.pinned_facts   = {}       # Things explicitly told to remember
        self.mood_history   = []       # Mood tracking across sessions
        self._load_pinned_facts()

    # ─────────────────────────────────────────────
    # PIN / RECALL
    # ─────────────────────────────────────────────

    def _load_pinned_facts(self):
        """Load pinned facts from vault"""
        raw = self.vault.get_config("pinned_facts")
        if raw:
            try:
                self.pinned_facts = json.loads(raw)
            except Exception:
                self.pinned_facts = {}

    def _save_pinned_facts(self):
        self.vault.set_config("pinned_facts", json.dumps(self.pinned_facts))

    def pin(self, key: str, value: str, tags: list = None):
        """Pin a fact for long-term recall with optional category tags"""
        k = key.lower()
        if k in self.pinned_facts and self.pinned_facts[k].get('value') == value:
            return
        self.pinned_facts[k] = {
            'value': value,
            'tags': tags or ['general'],
            'pinned_at': datetime.now().isoformat()
        }
        self._save_pinned_facts()

    def recall(self, key: str) -> Optional[str]:
        """Recall a pinned fact"""
        entry = self.pinned_facts.get(key.lower())
        return entry['value'] if entry else None

    def list_pinned(self) -> Dict[str, str]:
        """List all pinned facts"""
        return {k: v['value'] for k, v in self.pinned_facts.items()}

    def forget(self, key: str) -> bool:
        """Remove a pinned fact"""
        if key.lower() in self.pinned_facts:
            del self.pinned_facts[key.lower()]
            self._save_pinned_facts()
            return True
        return False

    # ─────────────────────────────────────────────
    # SESSION MEMORY
    # ─────────────────────────────────────────────

    def add_to_session(self, role: str, content: str, mood: str = None, thread: str = 'main'):
        """Add a message to current session memory with thread tracking"""
        entry = {
            'role': role,
            'content': content,
            'timestamp': time.time(),
            'mood': mood,
            'thread': thread
        }
        self.session_memory.append(entry)

        # Keep session lean — last 20 exchanges
        if len(self.session_memory) > 40:
            self.session_memory = self.session_memory[-40:]

    def _calculate_recency(self, timestamp: float) -> float:
        """Calculate exponential recency score (1.0 = current, decay half-life = 7 days)"""
        age = time.time() - timestamp
        half_life = 7 * 24 * 3600  # 7 days
        return 2 ** (-age / half_life)

    def get_session_context(self, limit: int = 6) -> List[Dict[str, str]]:
        """Get recent session for AI context window"""
        recent = self.session_memory[-limit * 2:]
        return [
            {'role': m['role'], 'content': m['content']}
            for m in recent
        ]

    # ─────────────────────────────────────────────
    # NATURAL RECALL INJECTION
    # ─────────────────────────────────────────────

    def build_memory_context(self, user_input: str) -> str:
        """
        Build a natural memory context string to inject into the system prompt.
        Surfaces relevant past context without sounding like a database.
        """
        context_parts = []

        # 1. Check pinned facts for relevance
        relevant_pins = self._find_relevant_pins(user_input)
        if relevant_pins:
            facts = '. '.join([f"{k}: {v}" for k, v in relevant_pins.items()])
            context_parts.append(f"Things u know about him: {facts}")

        # 2. Check vault for relevant past convos
        relevant_convos = self._search_relevant_convos(user_input, limit=2)
        if relevant_convos:
            refs = []
            for conv in relevant_convos:
                age = self._time_ago(conv['timestamp'])
                snippet = conv['prompt'][:60].strip()
                refs.append(f'"{snippet}..." ({age})')
            context_parts.append(f"He mentioned this before: {'; '.join(refs)}")

        # 3. Check mood history
        last_mood = self._get_last_mood()
        if last_mood:
            context_parts.append(f"His recent vibe: {last_mood}")

        if not context_parts:
            return ""

        return "\n\nMEMORY CONTEXT:\n" + "\n".join(f"- {p}" for p in context_parts)

    def _find_relevant_pins(self, query: str, limit: int = 3) -> Dict[str, str]:
        """Find pinned facts relevant to the query"""
        query_words = set(query.lower().split())
        scored = []

        for key, entry in self.pinned_facts.items():
            key_words = set(key.split())
            val_words = set(entry['value'].lower().split())
            overlap = len(query_words & (key_words | val_words))
            if overlap > 0:
                scored.append((overlap, key, entry['value']))

        scored.sort(key=lambda x: x[0],reverse=True)
        return {k: v for _, k, v in scored[:limit]}

    def _search_relevant_convos(self, query: str, limit: int = 2) -> List[Dict]:
        """Pull relevant past conversations"""
        all_convos = self.vault.get_recent_conversations(limit=50)
        query_words = set(query.lower().split())
        scored = []

        for conv in all_convos:
            content = f"{conv['prompt']} {conv['response']}".lower()
            content_words = set(content.split())
            overlap = len(query_words & content_words)
            if overlap >= 2:  # At least 2 word match
                scored.append((overlap, conv))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [conv for _, conv in scored[:limit]]

    def _get_last_mood(self) -> Optional[str]:
        """Get last detected mood from session"""
        for entry in reversed(self.session_memory):
            if entry.get('mood'):
                return entry['mood']
        return None

    def _time_ago(self, timestamp: float) -> str:
        """Human-readable time ago"""
        diff = time.time() - timestamp
        if diff < 3600:
            return f"{int(diff/60)}m ago"
        elif diff < 86400:
            return f"{int(diff/3600)}h ago"
        elif diff < 604800:
            return f"{int(diff/86400)}d ago"
        else:
            return f"{int(diff/604800)}w ago"

    # ─────────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────────

    def session_summary(self) -> str:
        """Brief summary of current session"""
        if not self.session_memory:
            return "no convo yet this session."

        turns = len([m for m in self.session_memory if m['role'] == 'user'])
        topics = set()
        for m in self.session_memory:
            words = m['content'].lower().split()
            topics.update(w for w in words if len(w) > 5 and w.isalpha())

        top_topics = list(topics)[:4]
        return f"{turns} turns. topics: {', '.join(top_topics)}."

    def get_stats(self) -> Dict[str, Any]:
        return {
            'session_turns': len(self.session_memory) // 2,
            'pinned_facts': len(self.pinned_facts),
            'last_mood': self._get_last_mood() or 'unknown'
        }