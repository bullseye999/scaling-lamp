#!/usr/bin/env python3
# ollama_interface.py - Local LLM interface for Ollama

import requests
import json
from typing import Dict, Any, List

class OllamaBrain:
    """
    Connects to a local Ollama server.
    Uses your system prompt and conversation history.
    """
   
    def __init__(self, model: str = "llama3.1"):
        self.model = model
        self.base_url = "http://localhost:11434/api/chat"
       
    def generate(self, user_input: str, history: List[Dict[str, str]], system_prompt: str) -> str:
        """
        Send prompt + history to Ollama.
        Returns raw response.
        """
        messages = [
            {"role": "system", "content": system_prompt}
        ]
       
        # Add recent history (last 10 exchanges)
        for msg in history[-10:]:
            if msg['role'] == 'user':
                messages.append({"role": "user", "content": msg['content']})
            elif msg['role'] == 'assistant':
                messages.append({"role": "assistant", "content": msg['content']})
       
        messages.append({"role": "user", "content": user_input})
       
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "temperature": 0.7,
            "max_tokens": 1000
        }
       
        try:
            response = requests.post(self.base_url, json=payload, timeout=60)
            if response.status_code == 200:
                data = response.json()
                return data['message']['content'].strip()
            else:
                return f"[Ollama error: {response.status_code}]"
        except Exception as e:
            return f"[Ollama offline: {str(e)}]"