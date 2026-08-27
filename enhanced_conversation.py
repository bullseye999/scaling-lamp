#!/usr/bin/env python3
# enhanced_conversation.py - Fixed for v3 kernel

import os
import re
import time
import requests
from typing import Optional, Any
from ciph_router import CiphRouter
from personality_engine import CiphPersonality
from ciph_worldview import get_worldview
from ciph_link_reader import CiphLinkReader


class CiphConversation:
    def __init__(self, vault, router: Optional[CiphRouter] = None, evolution_engine: Optional[Any] = None, smart_memory: Optional[Any] = None):
        self.vault = vault
        self.personality = CiphPersonality()
        self.history = []
        self.context_window = 6
        self.router = router or CiphRouter()
        self.brain = self.router
        self.link_reader = CiphLinkReader()
        self.evolution_engine = evolution_engine
        self.smart_memory = smart_memory
        self.running_session_summary = ""

    def _add_to_history(self, role: str, content: str):
        """Add to history with dynamic rolling session compression beyond context window."""
        self.history.append({'role': role, 'content': content})
        max_messages = self.context_window * 2  # 12 messages = 6 turns

        if len(self.history) > max_messages:
            # Compress the overflowing turn into the running session summary
            overflow_turn = self.history[:2]
            self.history = self.history[2:]
            u_text = overflow_turn[0].get('content', '')[:160] if overflow_turn else ""
            a_text = overflow_turn[1].get('content', '')[:160] if len(overflow_turn) > 1 else ""
            summary_snippet = f"Earlier in session: Operator discussed '{u_text}' -> Ciph guided: '{a_text}'."
            if self.running_session_summary:
                self.running_session_summary = f"{self.running_session_summary}\n{summary_snippet}"[-800:]
            else:
                self.running_session_summary = summary_snippet

    def _build_system_prompt(self, mood_context="", memory_context="", book_context="", operational_context="", world_context="") -> str:
        """Build system prompt with worldview, real-world telemetry, rolling memory, and organic cognitive evolution."""
        # Organic Cognitive Evolution Assimilation
        cognitive_context = ""
        try:
            recent_bps = self.vault.get_cognitive_blueprints(limit=3)
            if recent_bps:
                bps_lines = [f"• [{b['domain']}]: {b['core_axiom']}" for b in recent_bps]
                cognitive_context = "🧠 RECENT ASSIMILATED COGNITIVE AXIOMS:\n" + "\n".join(bps_lines)
        except Exception:
            pass

        daemon_status = ""
        if hasattr(self, 'evolution_engine') and self.evolution_engine:
            try:
                st = self.evolution_engine.get_status()
                state_str = "RUNNING (Active 24/7 background expeditions over Tor)" if st['is_running'] else "STANDBY (Paused)"
                daemon_status = f"⚡ REAL-TIME COGNITIVE EVOLUTION DAEMON STATUS: {state_str} (Total Blueprints Assimilated: {st['total_blueprints']})"
            except Exception:
                pass

        full_op_context = operational_context
        if self.running_session_summary:
            full_op_context = f"{full_op_context}\n\n[RUNNING SESSION STATE & EARLIER TURNS]\n{self.running_session_summary}".strip() if full_op_context else f"[RUNNING SESSION STATE & EARLIER TURNS]\n{self.running_session_summary}"
        if daemon_status:
            full_op_context = f"{full_op_context}\n\n{daemon_status}".strip() if full_op_context else daemon_status
        if cognitive_context:
            full_op_context = f"{full_op_context}\n\n{cognitive_context}".strip() if full_op_context else cognitive_context

        return get_worldview(
            mood_context=mood_context,
            memory_context=memory_context,
            book_context=book_context,
            operational_context=full_op_context,
            world_context=world_context
        )

    def bridge_command_execution(self, command: str, output: str):
        """Bridge a slash command and its structured output into conversation history."""
        self._add_to_history("user", f"[OPERATIONAL COMMAND] {command}")
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

        # 1. Check for Operator Council Triggers
        council_triggers = [
            'talk to me', "what's on your mind", "what is on your mind",
            'what have you been thinking about', 'what have you been exploring',
            'what did you learn', 'council', '/council'
        ]
        is_council_cue = any(trigger in user_input.lower() for trigger in council_triggers)
        if is_council_cue:
            theses = self.vault.get_pending_council_theses(limit=1)
            if theses:
                top_thesis = theses[0]
                self.vault.mark_council_thesis_discussed(top_thesis['id'])
                operational_context += f"\n\n[OPERATOR COUNCIL DIALECTIC THESIS]\nTitle: {top_thesis['title']}\nConclusion: {top_thesis['conclusion']}\nDialogue Prompt: {top_thesis['dialogue_prompt']}\nInitiate direct, thoughtful peer dialogue with Operator around this thesis."

        # 2. Autonomous Dual-Spectrum URL Fetching & OPSEC Interception
        opsec_badge_prefix = ""
        urls = self.link_reader.auditor.extract_urls(user_input)
        if urls:
            target_url = urls[0]
            fetch_res = self.link_reader.fetch_url(target_url)
            if fetch_res.get('success'):
                opsec_badge_prefix = self.link_reader.format_audit_badge(fetch_res['audit']) + "\n\n"
                if fetch_res.get('is_pdf') and fetch_res.get('file_path'):
                    # Auto-ingest downloaded book into Ciph's Library
                    try:
                        from book_engine import BookEngine
                        books = BookEngine(self.vault)
                        bname = os.path.basename(fetch_res['file_path'])
                        ingest_res = books.ingest_pdf(fetch_res['file_path'])
                        operational_context += f"\n\n[AUTOMATIC LIBRARY INGESTION: {bname}]\n{ingest_res}\nStatus: Ready for immediate reasoning."
                    except Exception as e:
                        operational_context += f"\n\n[PDF DOWNLOADED TO ciph_books/]: {fetch_res['file_path']}"
                else:
                    page_text = fetch_res.get('text_content', '')[:3500]
                    page_title = fetch_res.get('title', 'Target Document')
                    operational_context += f"\n\n[LIVE FETCHED URL CONTENT OVER TOR: {target_url}]\nTitle: {page_title}\nContent:\n{page_text}"
            elif fetch_res.get('error'):
                opsec_badge_prefix = f"🚨 {fetch_res['error']}\n\n"

        dynamic_prompt = self._build_system_prompt(
            mood_context=mood_context,
            memory_context=memory_context,
            book_context=book_context,
            operational_context=operational_context,
            world_context=world_context
        )

        raw_thought = self.router.think(user_input, self.history, dynamic_prompt, temperature)
        final_response = self.personality.inject_personality(raw_thought)
        
        # Prepend OPSEC badge if a link was analyzed
        if opsec_badge_prefix:
            final_response = opsec_badge_prefix + final_response

        # Autonomous code staging interceptor (no raw code dumps in chat)
        final_response = self._intercept_and_stage_code(final_response, user_input)

        self._add_to_history("user", user_input)
        self._add_to_history("assistant", final_response)
        self.vault.store_conversation(user_input, final_response, "convo")

        # Silent Long-Term Memory & Entity Extraction (SMAU v2.0)
        if self.smart_memory:
            try:
                self.smart_memory.extract_implicit_profile_and_entities(user_input, final_response, self.router)
                self.smart_memory.add_to_session("user", user_input)
                self.smart_memory.add_to_session("assistant", final_response)
            except Exception:
                pass

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