#!/usr/bin/env python3
# ollama_interface.py - Local LLM brain for Ciph
import requests
import json
from typing import Dict, Any, List

class OllamaBrain:
    """
    Connects to local Ollama server
    Uses your system prompt + conversation history
    """
   
    def __init__(self, model: str = "llama3.1"):
        self.model = model
        self.base_url = "http://localhost:11434/api/chat"
       
    def generate(self, user_input: str, history: List[Dict[str, str]], system_prompt: str) -> str:
        """
        Send prompt + history to Ollama
        Returns raw response
        """
        # Build messages
        messages = [
            {"role": "system", "content": system_prompt}
        ]
       
        # Add recent history (alternating user/assistant)
        for msg in history[-10:]:  # Last 10 exchanges
            if msg['role'] == 'user':
                messages.append({"role": "user", "content": msg['content']})
            elif msg['role'] == 'assistant':
                messages.append({"role": "assistant", "content": msg['content']})
       
        # Add current user input
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
        

        