#!/usr/bin/env python3
# enhanced_conversation.py - Conversation manager with personality and worldview

import time
import requests
import json
import os

# Renamed imports – adjust to your actual file names after redaction
from personality_engine import AgentPersonality   
from ciph_worldview import get_worldview        

class OllamaBrain:
    """Handles communication with an Ollama instance (local or remote)."""
    
    def __init__(self, model: str = None):
        # Default model – can be overridden by environment variable
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        # Ollama API endpoint – use localhost by default, or override with env var
        self.url = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/chat")

    def think(self, user_input: str, history: list, system_prompt: str) -> str:
        """Send a prompt to Ollama and return the response."""
        # Trim long inputs to avoid token blowout
        trimmed_input = user_input[:200] + "..." if len(user_input) > 200 else user_input

        messages = [{"role": "system", "content": system_prompt}]
        for msg in history[-4:]:
            role = msg["role"] if msg["role"] in ("user", "assistant") else "assistant"
            messages.append({"role": role, "content": msg["content"]})
        messages.append({"role": "user", "content": trimmed_input})

        payload = {
            "model":       self.model,
            "messages":    messages,
            "stream":      False,
            "temperature": 0.3,
            "max_tokens":  600
        }

        try:
            resp = requests.post(self.url, json=payload, timeout=180)
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip()
        except requests.Timeout:
            return "[Ollama timeout]"
        except requests.ConnectionError:
            return "[Ollama offline]"
        except Exception as e:
            return f"[Brain error: {str(e)[:40]}]"


class AgentConversation:
    """Manages conversation state, history, personality injection, and worldview."""
    
    def __init__(self, vault):
        self.vault          = vault
        self.personality    = AgentPersonality()
        self.history        = []
        self.context_window = 6
        self.mood           = "strategic"
        self.brain          = OllamaBrain()
        self.system_prompt  = self._build_system_prompt()

    def _build_system_prompt(self, mood_context="", memory_context="", book_context="") -> str:
        """Build the system prompt from worldview, mood, memory, and book knowledge."""
        return get_worldview(mood_context, memory_context, book_context)

    def process_input(self, user_input: str, mood_context: str = "",
                      memory_context: str = "", book_context: str = "") -> str:
        """Process user input: detect live data requests, get AI response, apply personality."""
        
        # Intercept live data requests and redirect to system commands
        live_data_triggers = [
            'btc price', 'bitcoin price', 'eth price', 'ethereum price',
            'crypto price', 'price of btc', 'price of bitcoin',
            'how much is btc', 'how much is bitcoin', 'current price',
            'whats btc', "what's btc", 'btc rate', 'bitcoin rate'
        ]
        if any(trigger in user_input.lower() for trigger in live_data_triggers):
            return "use /market-data for live crypto prices — I don't guess numbers."

        # Build dynamic system prompt with mood + memory
        dynamic_prompt = self._build_system_prompt(mood_context, memory_context, book_context)

        self._add_to_history("user", user_input)
        raw_thought = self.brain.think(user_input, self.history, dynamic_prompt)
        final_response = self.personality.inject_personality(raw_thought)
        self._add_to_history("assistant", final_response)
        self.vault.store_conversation(user_input, final_response, "convo")
        return final_response

    def _add_to_history(self, role: str, content: str):
        """Store a message in conversation history, respecting window size."""
        self.history.append({
            "role":      role,
            "content":   content,
            "timestamp": time.time()
        })
        if len(self.history) > self.context_window * 2:
            self.history = self.history[-self.context_window * 2:]

    def get_conversation_summary(self) -> str:
        """Generate a short summary of the current conversation."""
        if not self.history:
            return "no active conversation."
        topics = set()
        for msg in self.history:
            for word in msg["content"].lower().split():
                if len(word) > 5 and word.isalpha():
                    topics.add(word)
        top_topics = list(topics)[:5]
        turns = len(self.history) // 2
        return f"{turns} turns. topics: {', '.join(top_topics)}."