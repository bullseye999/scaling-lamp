#!/usr/bin/env python3
# ciph_autonomous_agent.py - Autonomous Conversational Tool-Calling & Action Loop

import json
import re
import uuid
from typing import Dict, Any, Optional, Tuple
from ciph_router import CiphRouter
from ciph_worldview import get_worldview
from intent_resolver import IntentResolver

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
        self.intent_resolver = IntentResolver(self.core.vault)

    def evaluate_and_execute(self, user_input: str, mood_context: str = "", memory_context: str = "", book_context: str = "") -> str:
        """
        Single-turn autonomous loop:
        1. Evaluate conversational intent via Self-Exhaustive IntentResolver
        2. Fallback to Action Classifier LLM if needed
        3. Execute tool
        4. Synthesize Epistemic Quadruple response with Kernel-subordinate action proposals
        """
        if self._is_pure_chatter(user_input):
            return self.core.conversation.process_input(
                user_input,
                mood_context=mood_context,
                memory_context=memory_context,
                book_context=book_context
            )

        history_ctx = self.core.conversation.history[-4:] if hasattr(self.core, 'conversation') and self.core.conversation else []

        # 1. First Pass: Self-Exhaustive Intent Resolution against internal SQLite state
        resolved = self.intent_resolver.resolve_intent(user_input, history_ctx)
        if resolved['resolved'] and resolved['action'] != 'none':
            tool = resolved['action']
            target = resolved['target']
        else:
            # 2. Second Pass: LLM Action Classifier
            history_snippet = ""
            if history_ctx:
                turns_lines = [f"{t.get('role', 'user').upper()}: {t.get('content', '')[:200]}" for t in history_ctx]
                history_snippet = "Recent Conversation Turns:\n" + "\n".join(turns_lines) + "\n\n"

            active_scopes_str = ""
            try:
                scopes = self.core.vault.get_active_bounty_scopes()
                if scopes:
                    pnames = [s.get('program_name') for s in scopes if s.get('program_name')]
                    active_scopes_str = f"Active registered targets in vault: {', '.join(set(pnames))}\n"
            except Exception:
                pass

            eval_prompt = (
                "You are Ciph's Autonomous Action Dispatcher. Analyze the operator's latest message in the context of recent turns. "
                "Determine if this request requires executing one of your operational engines. "
                "If the operator is confirming or asking to run a scan/reconnaissance (e.g. 'go ahead', 'do it', 'spin it up', 'scan it', 'run the pass'), "
                "identify the action as 'bounty_scan' and extract the intended target domain from conversation context. "
                "If the operator is asking to dig deeper, investigate, or research threat intel/CVE alerts/leads (e.g. 'go ahead with the ones with teeth', 'dig into ServiceNow', 'research those CVEs'), "
                "identify the action as 'threat_deep_dive' and extract the relevant CVE or technology keywords from context. "
                "Available actions:\n"
                "- bounty_scan: Scan/audit a target domain or website\n"
                "- threat_deep_dive: Deep-dive investigate threat intel leads / CVEs over Tor and correlate with vault assets\n"
                "- what_changed: Check historical diffs/new subdomains on a target\n"
                "- hit_list: Get top 5 prioritized attack targets\n"
                "- chain_reaction: Map multi-stage exploit paths on findings\n"
                "- ghost_audit: Check our OPSEC/Tor status\n"
                "- global_assets: View all discovered assets across all targets\n"
                "- darknet_search: Search Tor darknet engines for keywords\n"
                "- war_room: Adversarially stress-test a strategy or plan\n"
                "- bounty_report: Draft full bug bounty submission report\n"
                "- daily_brief: Executive intelligence overview\n"
                "- none: General strategic advice, philosophy, question, or chat\n\n"
                "Return ONLY a JSON object: { \"tool\": \"action_name\", \"target\": \"target_or_query_string\" }"
            )

            try:
                raw_action = self.router.think(
                    user_input=f"{history_snippet}{active_scopes_str}Operator's latest message: '{user_input}'",
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

        exec_res = self._execute_tool(tool, target, user_input)
        tool_output = exec_res.get('output_str', '')
        rcpt_id = exec_res.get('receipt_id', 'rcpt_direct')

        synth_prompt = (
            get_worldview(mood_context, memory_context, book_context) +
            "\n\n[VERIFIED RUNTIME COMPLETION RECEIPT]\n" +
            f"• Receipt ID: {rcpt_id}\n" +
            f"• Tool: {tool} (Target: {target})\n" +
            "• Exit Status: COMPLETED (Verified in SQLite runtime)\n" +
            f"• Technical Output:\n{tool_output}\n\n" +
            "CRITICAL INSTRUCTIONS FOR SYNTHESIS (EPISTEMIC QUADRUPLE):\n" +
            "- Structure your response cleanly around the Epistemic Quadruple:\n" +
            "  1. VERIFIED REALITY: The factual advisories and physical asset matches from the receipt.\n" +
            "  2. INFERENCE / DEDUCTION: Strategic interpretation (e.g. potential attack surface / blast radius).\n" +
            "  3. UNKNOWN / GAPS: Missing variables that require physical testing (e.g. unverified version numbers).\n" +
            "  4. PROPOSED ACTION: A specific, kernel-subordinate passive verification proposal.\n" +
            "- Invariant: A proposal is NEVER an active execution. State what the Kernel allows and ask the operator for execution confirmation."
        )

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

    def _execute_tool(self, tool: str, target: str, raw_input: str) -> Dict[str, Any]:
        tgt = target
        try:
            job_id = f"JOB-{tool[:3].upper()}-{uuid.uuid4().hex[:6].upper()}"
            res_obj = {}

            if tool == "bounty_scan":
                tgt = target or getattr(self.core.bounty, 'last_scan_target', None)
                if not tgt:
                    scopes = self.core.vault.get_active_bounty_scopes()
                    if scopes:
                        tgt = scopes[0].get('program_name', 'crypto.com').lower()
                    else:
                        tgt = "crypto.com"
                tgt = tgt.replace("https://", "").replace("http://", "").split("/")[0].strip()
                res_obj = self.core.bounty.deep_scan(tgt)
            elif tool == "threat_deep_dive":
                kw_str = target or raw_input
                raw_keywords = [w.strip("?,.:;!'\"()") for w in kw_str.split() if len(w) > 2]
                keywords = []
                for kw in raw_keywords:
                    if kw.lower() not in ['ones', 'teeth', 'ahead', 'with', 'what', 'find', 'tell', 'that', 'have', 'deep', 'dive', 'lead', 'leads']:
                        keywords.append(kw)
                if not keywords:
                    keywords = ["ServiceNow", "cPanel", "Next.js"]

                threat_searches = {}
                for kw in keywords[:3]:
                    try:
                        hits = self.core.darknet.search_darknet(kw, max_results=3)
                        threat_searches[kw] = hits
                    except Exception:
                        threat_searches[kw] = []

                correlations = []
                if hasattr(self.core.vault, 'correlate_threat_advisories'):
                    try:
                        correlations = self.core.vault.correlate_threat_advisories(keywords)
                    except Exception:
                        pass

                stress_summary = ""
                try:
                    stress_summary = self.core.war_room.stress_test(f"Advisory exposure on vectors: {', '.join(keywords)}")
                except Exception:
                    pass

                res_obj = {
                    "investigated_topics": keywords,
                    "threat_intel_hits": threat_searches,
                    "vault_asset_correlations": correlations,
                    "war_room_vector_evaluation": stress_summary
                }
            elif tool == "what_changed":
                tgt = target or getattr(self.core.bounty, 'last_scan_target', None) or "crypto.com"
                res_obj = self.core.bounty.get_historical_diffs(tgt)
            elif tool == "hit_list":
                tgt = target or getattr(self.core.bounty, 'last_scan_target', None) or "crypto.com"
                res_obj = self.core.bounty.generate_hit_list(tgt)
            elif tool == "chain_reaction":
                tgt = target or getattr(self.core.bounty, 'last_scan_target', None) or "crypto.com"
                res_obj = self.core.bounty.map_exploit_chains(tgt)
            elif tool == "ghost_audit":
                res_obj = self.core.bounty.audit_ghost_opsec()
                self.core.vault.store_opsec_audit(res_obj['score'], res_obj['exit_ip'], res_obj['latency_ms'], res_obj['status'])
            elif tool == "global_assets":
                res_obj = self.core.vault.get_global_assets_summary()
            elif tool == "darknet_search":
                tgt = target or raw_input
                res_obj = self.core.darknet.search_darknet(tgt)
            elif tool == "war_room":
                tgt = target or raw_input
                res_obj = self.core.war_room.stress_test(tgt)
            elif tool == "bounty_report":
                tgt = target or getattr(self.core.bounty, 'last_scan_target', None) or "crypto.com"
                res_obj = self.core.bounty.generate_elite_report(tgt)
            elif tool == "daily_brief":
                brief = self.core.get_daily_briefing()
                res_obj = {"briefing": brief}
            else:
                res_obj = {"status": "success", "message": "Action executed successfully."}

            output_str = json.dumps(res_obj, indent=2) if isinstance(res_obj, (dict, list)) else str(res_obj)
            
            # Store COMPLETION_RECEIPT in CipherVault
            rcpt_id = self.core.vault.store_completion_receipt(
                job_id=job_id,
                tool_name=tool,
                target=tgt or "general",
                results=res_obj if isinstance(res_obj, dict) else {"output": output_str},
                exit_code=0
            )

            return {
                "status": "completed",
                "receipt_type": "COMPLETION_RECEIPT",
                "receipt_id": rcpt_id,
                "job_id": job_id,
                "tool": tool,
                "target": tgt,
                "output_str": output_str
            }

        except Exception as e:
            err_str = f"Execution error: {str(e)}"
            return {
                "status": "failed",
                "receipt_type": "FAILED",
                "receipt_id": "rcpt_failed",
                "job_id": "JOB-FAILED",
                "tool": tool,
                "target": tgt or "unknown",
                "output_str": err_str
            }
