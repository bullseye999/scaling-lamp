#!/usr/bin/env python3
# query_router.py - Direct state and calculation answering without LLM overhead

import time
import re
import ast
import operator
from datetime import datetime
from typing import Dict, Any, Optional

class QueryRouter:
    """Handles factual questions by directly querying system state.
    Bypasses LLM inference for deterministic answers to save tokens and eliminate latency."""

    def __init__(self, state_manager, vault=None):
        self.state = state_manager
        self.vault = vault

    def can_handle(self, user_input: str) -> bool:
        """Check if this query can be answered directly from state or basic math."""
        text = user_input.lower().strip()
        
        # Math calculation check (e.g. "calc 5+5", "calculate 12 * 4")
        if re.match(r'^(calc|calculate|math)\s+[0-9+\-*/() .]+$', text):
            return True

        # Time/date questions
        time_patterns = [
            r'\b(time|clock)\b',
            r'\bwhat(\'s|s)?\s*(is|the)?\s*time\b',
            r'\bcurrent\s*time\b',
            r'\bnow\s*(?:is)?\s*(?:the)?\s*time\b'
        ]
        if any(re.search(p, text) for p in time_patterns):
            return True
        
        if any(phrase in text for phrase in [
            'what date', 'today\'s date', 'what is the date', 'current date',
            'what day is it', 'what\'s the date', 'date today'
        ]):
            return True
        
        # Module questions
        if any(phrase in text for phrase in [
            'what modules', 'loaded modules', 'modules loaded',
            'what is loaded', 'active modules', 'available modules'
        ]):
            return True
        
        # Tor status
        if any(phrase in text for phrase in [
            'tor active', 'is tor', 'tor status', 'anonymous',
            'is my ip hidden', 'tor working'
        ]):
            return True
        
        # Workflow questions
        if any(phrase in text for phrase in [
            'active workflows', 'workflows running', 'any workflows',
            'what workflows', 'workflow status'
        ]):
            return True
        
        # AI status
        if any(phrase in text for phrase in [
            'is ai enabled', 'ai status', 'is ciph working'
        ]):
            return True
        
        # Count questions
        if any(phrase in text for phrase in [
            'how many alerts', 'alert count', 'notifications',
            'pending notifications', 'how many modules'
        ]):
            return True
        
        return False

    def answer_calculation(self, text: str) -> str:
        """Safe basic calculation evaluator"""
        expr = re.sub(r'^(calc|calculate|math)\s*', '', text, flags=re.IGNORECASE).strip()
        try:
            # Evaluate basic math using safe subset
            clean_expr = re.sub(r'[^0-9+\-*/() .]', '', expr)
            result = eval(clean_expr, {"__builtins__": {}}, {})
            return f"🔢 Calculation Result: {result}"
        except Exception:
            return f"❌ Could not calculate: '{expr}'"

    def answer_search(self, query: str) -> str:
        """Direct search helper in vault storage"""
        if not self.vault:
            return "Vault not initialized for search."
        recent = self.vault.get_recent_conversations(limit=50)
        results = []
        for conv in recent:
            if query.lower() in conv['prompt'].lower() or query.lower() in conv['response'].lower():
                results.append(conv['prompt'][:50])
        if results:
            return f"🔍 Search Results:\n" + "\n".join(f"- {r}..." for r in results[:3])
        return f"🔍 No results found for '{query}'"

    def answer(self, user_input: str) -> str:
        """Answer the query directly from state (no LLM)."""
        text = user_input.lower().strip()

        # Math calculation query
        if re.match(r'^(calc|calculate|math)\s+', text):
            return self.answer_calculation(text)
        
        # Time query
        if any(phrase in text for phrase in ['time', 'clock']):
            now = datetime.now()
            return f"🕐 {now.strftime('%H:%M:%S')}"
        
        # Date query
        if any(phrase in text for phrase in ['date', 'day', 'today']):
            now = datetime.now()
            return f"📅 {now.strftime('%A, %B %d, %Y')}"
        
        # Module list query
        if any(phrase in text for phrase in ['modules', 'loaded']):
            snapshot = self.state.get_snapshot()
            modules = snapshot.get('loaded', [])
            if modules:
                return f"📦 Loaded modules: {', '.join(modules)}"
            return "📦 No modules loaded."
        
        # Tor status query
        if any(phrase in text for phrase in ['tor', 'anonymous']):
            snapshot = self.state.get_snapshot()
            tor_active = snapshot.get('tor', False)
            if tor_active:
                return "🔒 Tor is ACTIVE. Your traffic is anonymized."
            return "🔓 Tor is INACTIVE. Use /ghost-mode to enable."
        
        # Workflow query
        if any(phrase in text for phrase in ['workflow']):
            snapshot = self.state.get_snapshot()
            workflows = snapshot.get('workflows', 0)
            if workflows > 0:
                return f"⚙️ {workflows} active workflow(s). Use /workflow-status for details."
            return "⚙️ No active workflows."
        
        # AI status query
        if any(phrase in text for phrase in ['ai enabled', 'ciph working']):
            snapshot = self.state.get_snapshot()
            ai_enabled = snapshot.get('ai', False)
            if ai_enabled:
                return "🧠 AI is ENABLED. I'm ready to chat."
            return "🧠 AI is DISABLED. Use /ai to enable."
        
        # Notification query
        if any(phrase in text for phrase in ['notifications', 'alerts', 'how many']):
            bg_summary = self.state.get_background_summary()
            notifications = bg_summary.get('notifications', 0)
            if notifications > 0:
                return f"🔔 {notifications} pending notification(s). Use /notifications to view."
            return "🔔 No pending notifications."
        
        # Default fallback
        return "I don't have that information directly. Try asking differently or use /help."