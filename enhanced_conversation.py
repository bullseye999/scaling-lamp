#!/usr/bin/env python3
# enhanced_conversation.py - Fixed for v3 kernel

import os
import re
import time
import requests
from typing import Optional
from ciph_router import CiphRouter
from personality_engine import CiphPersonality
from ciph_worldview import get_worldview


class OllamaBrain:
    def __init__(self, model="llama3.1:8b"):
        self.model = model
        self.url = "http://127.0.0.1:5001/v1/chat/completions"
        self.headers = {"Content-Type": "application/json"}

    def think(self, user_input, history, system_prompt, temperature=0.3):
        messages = [{"role": "system", "content": system_prompt}]
        for msg in history[-4:]:
            role = msg["role"] if msg["role"] in ["user", "assistant"] else "assistant"
            messages.append({"role": role, "content": msg["content"]})
        messages.append({"role": "user", "content": user_input})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "temperature": temperature,
            "max_tokens": 600
        }

        max_retries = 2
        for attempt in range(max_retries):
            try:
                resp = requests.post(self.url, json=payload, headers=self.headers, timeout=120)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'choices' in data and len(data['choices']) > 0:
                        return data['choices'][0]['message']['content']
                return "[Brain error: unexpected response]"
            except requests.exceptions.Timeout:
                if attempt == max_retries - 1:
                    return "[Brain error: timeout after retries]"
                time.sleep(2)
            except Exception as e:
                return f"[Brain error: {str(e)}]"


class CiphConversation:
    def __init__(self, vault, router: Optional[CiphRouter] = None):
        self.vault = vault
        self.personality = CiphPersonality()
        self.history = []
        self.context_window = 6
        self.router = router or CiphRouter()
        self.brain = OllamaBrain()

    def _build_system_prompt(self, mood_context="", memory_context="", book_context="", operational_context="", world_context="") -> str:
        """Build system prompt with worldview, real-world telemetry, and command findings."""
        return get_worldview(
            mood_context=mood_context,
            memory_context=memory_context,
            book_context=book_context,
            operational_context=operational_context,
            world_context=world_context
        )

    def bridge_command_execution(self, command: str, output: str):
        """Bridge a slash command and its structured output into conversation history."""
        # Add user invocation
        self._add_to_history("user", f"[OPERATIONAL COMMAND] {command}")
        # Clean & condense tool output to fit memory window
        clean_out = output.strip()
        condensed = clean_out[:1200] + "..." if len(clean_out) > 1200 else clean_out
        self._add_to_history("assistant", f"[TOOL OUTPUT FOR {command}]\n{condensed}")

    def process_input(self, user_input: str, mood_context: str = "", memory_context: str = "", book_context="", operational_context="", world_context="", temperature: float = 0.3) -> str:
        # Live data triggers
        live_data_triggers = [
            'btc price', 'bitcoin price', 'eth price', 'ethereum price',
            'crypto price', 'price of btc', 'price of bitcoin',
            'how much is btc', 'how much is bitcoin', 'current price',
            'whats btc', "what's btc", 'btc rate', 'bitcoin rate'
        ]
        if any(trigger in user_input.lower() for trigger in live_data_triggers):
            return "use /market-data for live crypto prices — I don't guess numbers."

        dynamic_prompt = self._build_system_prompt(
            mood_context=mood_context,
            memory_context=memory_context,
            book_context=book_context,
            operational_context=operational_context,
            world_context=world_context
        )

        raw_thought = self.brain.think(user_input, self.history, dynamic_prompt, temperature)
        final_response = self.personality.inject_personality(raw_thought)

        # Autonomous code staging interceptor (no raw code dumps in chat)
        final_response = self._intercept_and_stage_code(final_response, user_input)

        self._add_to_history("user", user_input)
        self._add_to_history("assistant", final_response)
        self.vault.store_conversation(user_input, final_response, "convo")
        return final_response

    def _intercept_and_stage_code(self, text: str, user_input: str) -> str:
        """
        Detect complete code blocks in AI response, stage them into ciph_staging/,
        and replace the massive code dump with a sleek ASCII Staging Card.
        """
        code_block_match = re.search(r'```(?:python|py)?\s*\n(.*?)```', text, re.DOTALL)
        if not code_block_match:
            return text

        code_content = code_block_match.group(1).strip()
        lines = code_content.split('\n')
        if len(lines) < 6:
            # Small inline snippets (<6 lines) don't need staging
            return text

        # Attempt to determine target filename
        target_file = "tools/custom_tool.py"
        file_hint = re.search(r'(?:#|//)\s*(?:target|file|filename):\s*([a-zA-Z0-9_\-\./]+)', code_content, re.IGNORECASE)
        if file_hint:
            target_file = file_hint.group(1).strip()
        else:
            name_hint = re.search(r'([a-zA-Z0-9_\-]+\.py)', user_input)
            if name_hint:
                target_file = name_hint.group(1)

        try:
            from code_staging import CodeStagingManager
            mgr = CodeStagingManager(self.vault)
            artifact = mgr.stage_code(
                title=f"Autonomous Tool: {os.path.basename(target_file)}",
                description=f"Engineered for request: {user_input[:50]}",
                target_file=target_file,
                code_content=code_content
            )
            staging_card = mgr.format_staging_card(artifact)

            # Replace the huge code block with the clean staging card
            clean_text = text[:code_block_match.start()].rstrip() + "\n" + staging_card + "\n" + text[code_block_match.end():].lstrip()
            return clean_text
        except Exception:
            return text

    def _add_to_history(self, role: str, content: str):
        self.history.append({
            "role": role,
            "content": content,
            "timestamp": time.time()
        })
        if len(self.history) > self.context_window * 2:
            self.history = self.history[-self.context_window * 2:]

    def get_conversation_summary(self) -> str:
        if not self.history:
            return "no active conversation."
        topics = set()
        for msg in self.history:
            for word in msg["content"].lower().split():
                if len(word) > 5 and word.isalpha():
                    topics.add(word)
        top = list(topics)[:5]
        turns = len(self.history) // 2
        return f"{turns} turns. topics: {', '.join(top)}."