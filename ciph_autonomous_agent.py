#!/usr/bin/env python3
# ciph_autonomous_agent.py - Autonomous Conversational Tool-Calling & Action Loop

import json
import re
from typing import Dict, Any, Optional, Tuple
from ciph_router import CiphRouter
from ciph_worldview import get_worldview

class AutonomousActionAgent:
    """
    Autonomous Conversational Agent for CIPH.
    Translates the operator's natural language dialogue into multi-step module actions,
    executes tools over Tor behind the scenes, and synthesizes strategic responses.
    Zero slash commands required.
    """

    def __init__(self, core_instance):
        self.core = core_instance
        self.router = getattr(core_instance, 'ciph_router', None) or CiphRouter()

    def evaluate_and_execute(self, user_input: str, mood_context: str = "", memory_context: str = "", book_context: str = "") -> str:
        """
        Single-turn autonomous loop:
        1. Evaluate conversational intent & tool trigger
        2. Execute tool if needed
        3. Synthesize natural sovereign response with proactive suggestions
        """
        if self._is_pure_chatter(user_input):
            return self.core.conversation.process_input(
                user_input,
                mood_context=mood_context,
                memory_context=memory_context,
                book_context=book_context
            )


        eval_prompt = (
            "You are Ciph's Autonomous Action Dispatcher. The operator spoke to you. "
            "Determine if this request requires executing one of your operational engines. "
            "Available actions:\n"
            "- bounty_scan: Scan/audit a target domain or website\n"
            "- what_changed: Check historical diffs/new subdomains on a target\n"
            "- hit_list: Get top 5 prioritized attack targets\n"
            "- chain_reaction: Map multi-stage exploit paths on findings\n"
            "- ghost_audit: Check our OPSEC/Tor status\n"
            "- global_assets: View all discovered assets across all targets\n"
            "- darknet_search: Search Tor darknet engines for keywords\n"
            "- war_room: Adversarially stress-test a strategy or plan\n"
            "- bounty_report: Draft full bug bounty submission report\n"
            "- daily_brief: Executive intelligence overview\n"
            "- none: General strategic advice, philosophy, or chat\n\n"
            "Return ONLY a JSON object: { \"tool\": \"action_name\", \"target\": \"target_or_query_string\" }"
        )


        try:
            raw_action = self.router.think(
                user_input=f"Operator's message: '{user_input}'",
                history=[],
                system_prompt=eval_prompt,
                temperature=0.1
            )
            clean_str = re.sub(r'```(?:json)?', '', raw_action).strip()
            decision = json.loads(clean_str)
            tool = decision.get("tool", "none").lower()
            target = decision.get("target", "").strip()
        except Exception:
            tool = "none"
            target = ""

        if tool == "none" or not tool:
            return self.core.conversation.process_input(
                user_input,
                mood_context=mood_context,
                memory_context=memory_context,
                book_context=book_context
           )

        tool_output = self._execute_tool(tool, target, user_input)

        synth_prompt = (
            get_worldview(mood_context, memory_context, book_context) +
            "\n\nAUTONOMOUS ACTION EXECUTION COMPLETE:\n" +
            f"Action Taken: {tool} (Target: {target})\n" +
            f"Technical Output:\n{tool_output}\n\n" +
            "TASK: Synthesize these technical results directly to the operator in your sovereign voice. " +
            "Do NOT repeat or echo the raw technical output verbatim. " +
            "Provide a clean, punchy explanation of what the findings mean and end with 1-2 tactical next steps."
        )

        history_ctx = self.core.conversation.history[-4:] if hasattr(self.core, 'conversation') and self.core.conversation else []
        final_response = self.router.think(
            user_input=user_input,
            history=history_ctx,
            system_prompt=synth_prompt,
            temperature=0.3
        )

        self.core.conversation._add_to_history("user", user_input)
        self.core.conversation._add_to_history("assistant", final_response)
        self.core.vault.store_conversation(user_input, final_response, "autonomous_action")

        return final_response

    def _is_pure_chatter(self, text: str) -> bool:
        t = text.lower().strip()
        greetings = ["hi", "hello", "hey", "sup", "yo", "how are you", "you good", "doing good", "thanks"]
        return t in greetings

    def _execute_tool(self, tool: str, target: str, raw_input: str) -> str:
        try:
            if tool == "bounty_scan":
                tgt = target or self.core.bounty.last_scan_target or "target.com"
                res = self.core.bounty.deep_scan(tgt)
                return json.dumps(res, indent=2)
            elif tool == "what_changed":
                tgt = target or self.core.bounty.last_scan_target
                res = self.core.bounty.get_historical_diffs(tgt)
                return json.dumps(res, indent=2)
            elif tool == "hit_list":
                tgt = target or self.core.bounty.last_scan_target
                res = self.core.bounty.generate_hit_list(tgt)
                return json.dumps(res, indent=2)
            elif tool == "chain_reaction":
                tgt = target or self.core.bounty.last_scan_target
                res = self.core.bounty.map_exploit_chains(tgt)
                return json.dumps(res, indent=2)
            elif tool == "ghost_audit":
                res = self.core.bounty.audit_ghost_opsec()
                self.core.vault.store_opsec_audit(res['score'], res['exit_ip'], res['latency_ms'], res['status'])
                return json.dumps(res, indent=2)
            elif tool == "global_assets":
                res = self.core.vault.get_global_assets_summary()
                return json.dumps(res, indent=2)
            elif tool == "darknet_search":
                res = self.core.darknet.search_darknet(target or raw_input)
                return json.dumps(res, indent=2)
            elif tool == "war_room":
                res = self.core.war_room.stress_test(target or raw_input)
                return json.dumps(res, indent=2)
            elif tool == "bounty_report":
                tgt = target or self.core.bounty.last_scan_target
                res = self.core.bounty.generate_elite_report(tgt)
                return json.dumps(res, indent=2)
            elif tool == "daily_brief":
                return self.core.get_daily_briefing()
            return "Action executed successfully."
        except Exception as e:
            return f"Execution note: {str(e)}"
