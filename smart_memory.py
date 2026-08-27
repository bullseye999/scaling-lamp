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

    def get_pinned(self, key: str) -> Optional[str]:
        """Alias for recall"""
        return self.recall(key)

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
    # NATURAL RECALL INJECTION (SMAU v2.0 FUSION)
    # ─────────────────────────────────────────────

    def build_memory_context(self, user_input: str) -> str:
        """
        Build a high-density memory context string to inject into the system prompt.
        Fuses narrative milestones, Operator's profile, circadian emotion, entity graph,
        and temporal decision outcomes.
        """
        context_parts = []

        # 1. Narrative timeline milestones
        try:
            milestones = self.vault.get_narrative_milestones(limit=2)
            if milestones:
                m_lines = []
                for m in milestones:
                    m_lines.append(f"• Milestone ({self._time_ago(m['timestamp'])}): {m['summary']}")
                    if m.get('decisions'):
                        m_lines.append(f"  Key Decisions: {m['decisions']}")
                context_parts.append("Strategic Narrative Timeline:\n" + "\n".join(m_lines))
        except Exception:
            pass

        # 2. Operator's Strategic Profile (Implicit Long-Term Facts)
        try:
            profile_facts = self.vault.get_profile_facts()
            if profile_facts:
                p_lines = []
                for f in profile_facts[:6]:
                    p_lines.append(f"• [{f['category'].upper()}] {f['key']}: {f['value']}")
                context_parts.append("Operator's Profile & Strategic Boundaries:\n" + "\n".join(p_lines))
        except Exception:
            pass

        # 3. Associative Entity Graph (Targets, CVEs, Staged Tools)
        try:
            relevant_links = self._find_relevant_entity_links(user_input, limit=4)
            if relevant_links:
                g_lines = []
                for link in relevant_links:
                    detail_str = f" ({link['details']})" if link.get('details') else ""
                    g_lines.append(f"• {link['source']} ──[{link['relation']}]──> {link['target']}{detail_str}")
                context_parts.append("Active Associative Entity Graph:\n" + "\n".join(g_lines))
        except Exception:
            pass

        # 4. Decision History & Outcome Feedback Loop
        try:
            decisions = self.vault.get_decision_outcomes(limit=2)
            if decisions:
                d_lines = []
                for d in decisions:
                    d_lines.append(f"• Decision: {d['title']} -> Result: {d['outcome']} ({d['lessons']})")
                context_parts.append("Historical Decision Outcomes:\n" + "\n".join(d_lines))
        except Exception:
            pass

        # 5. Circadian & Emotional State Memory
        circadian_vibe = self._get_circadian_emotional_context()
        if circadian_vibe:
            context_parts.append(f"Emotional & Diurnal Rhythm: {circadian_vibe}")

        # 6. Check vault for relevant past convos
        relevant_convos = self._search_relevant_convos(user_input, limit=2)
        if relevant_convos:
            refs = []
            for conv in relevant_convos:
                age = self._time_ago(conv['timestamp'])
                snippet = conv['prompt'][:60].strip()
                refs.append(f'"{snippet}..." ({age})')
            context_parts.append(f"Past Dialogue References: {'; '.join(refs)}")

        if not context_parts:
            return ""

        return "\n\n[SOVEREIGN LONG-TERM MEMORY & WORLDVIEW CONTEXT]\n" + "\n\n".join(context_parts)

    def _find_relevant_entity_links(self, user_input: str, limit: int = 4) -> List[Dict[str, Any]]:
        """Search entity graph for nodes matching words in user prompt."""
        words = [w.strip("?,.:;!") for w in user_input.split() if len(w) > 3]
        all_links = []
        seen_ids = set()

        for w in words[:6]:
            links = self.vault.search_entity_graph(w, limit=3)
            for l in links:
                if l['id'] not in seen_ids:
                    seen_ids.add(l['id'])
                    all_links.append(l)
                    if len(all_links) >= limit:
                        return all_links

        if not all_links:
            # Fallback to most recent entity links
            all_links = self.vault.get_entity_links(limit=limit)
        return all_links

    def _get_circadian_emotional_context(self) -> str:
        """Derive circadian and emotional context based on hour and recent mood."""
        hour = datetime.now().hour
        if 5 <= hour < 12:
            time_vibe = "Morning operational focus (crisp, direct, high-tempo)."
        elif 12 <= hour < 18:
            time_vibe = "Afternoon tactical momentum (execution, tool validation)."
        elif 18 <= hour < 23:
            time_vibe = "Evening strategic dialectic (deep conversation, polymath connections)."
        else:
            time_vibe = "Midnight sovereign hours (philosophical, reflective, unconventional insights)."

        last_mood = self._get_last_mood()
        if last_mood:
            return f"{time_vibe} Current detected mood: {last_mood}."
        return time_vibe

    # ─────────────────────────────────────────────
    # AUTONOMOUS EXTRACTION & RETROACTIVE LEARNING
    # ─────────────────────────────────────────────

    def extract_implicit_profile_and_entities(self, user_input: str, ai_response: str = "", router: Optional[Any] = None) -> Dict[str, Any]:
        """
        Silently extract Operator's preferences, operational boundaries, active targets,
        entity relationships, and decision outcomes from dialogue turns.
        """
        extracted_facts = []
        extracted_links = []
        text_combined = f"{user_input}\n{ai_response}"
        lower_input = user_input.lower()

        # 1. Deterministic Preference & Boundary Recognition
        import re

        # Languages / Tech Stack
        lang_match = re.search(r'\b(?:i prefer|i like|using|code in|write in|build in)\s+(python|go|golang|rust|c\+\+|javascript|typescript|bash|c)\b', lower_input)
        if lang_match:
            val = lang_match.group(1).capitalize()
            fact_id = f"prof_lang_{val.lower()}"
            self.vault.store_profile_fact(fact_id, "preference", f"preferred_language_{val.lower()}", f"Prefers {val} for implementations.", 0.95)
            extracted_facts.append({"key": "preferred_language", "value": val})

        # Operational Boundaries & Infrastructure
        infra_match = re.search(r'\b(?:server|vps|proxy|infra|infrastructure|node)\s+(?:is\s+)?(?:located\s+in|hosted\s+in|in)\s+([a-zA-Z]+)\b', lower_input)
        if infra_match:
            loc = infra_match.group(1).strip().capitalize()
            fact_id = f"prof_infra_{loc.lower()[:12]}"
            self.vault.store_profile_fact(fact_id, "operational", "infrastructure_location", f"Infrastructure / VPS node located in {loc}.", 0.9)
            extracted_facts.append({"key": "infrastructure_location", "value": loc})

        # Tone / Interaction Philosophy
        if any(kw in lower_input for kw in ["be direct", "no fluff", "straight to the point", "razor sharp", "keep it concise"]):
            self.vault.store_profile_fact("prof_tone_direct", "philosophy", "communication_tone", "Prefers direct, razor-sharp, zero-fluff responses.", 1.0)
            extracted_facts.append({"key": "communication_tone", "value": "Direct & Concise"})

        # 2. Deterministic Target & CVE Entity Extraction
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', user_input, re.IGNORECASE)
        for cve in cves:
            cve_upper = cve.upper()
            link_id = f"link_{int(time.time())}_{cve_upper}"
            self.vault.store_entity_link(link_id, "Operator", "TARGETING_VULNERABILITY", cve_upper, f"Active vulnerability investigated on {datetime.now().strftime('%Y-%m-%d')}")
            extracted_links.append({"source": "Operator", "relation": "TARGETING_VULNERABILITY", "target": cve_upper})

        # Software / Target Names
        for target_kw in ['sharepoint', 'wordpress', 'confluence', 'gitlab', 'jenkins', 'aws', 'cloudflare', 'nginx', 'apache', 'scaling-lamp']:
            if target_kw in lower_input:
                target_name = target_kw.capitalize()
                link_id = f"link_target_{target_kw}_{int(time.time())}"
                self.vault.store_entity_link(link_id, "Operator", "WORKING_ON_TARGET", target_name, f"Target or project discussed on {datetime.now().strftime('%Y-%m-%d')}")
                extracted_links.append({"source": "Operator", "relation": "WORKING_ON_TARGET", "target": target_name})

        # 3. Decision Outcome Feedback
        if any(kw in lower_input for kw in ["that worked", "exploit succeeded", "payload worked", "bounty accepted", "finding verified"]):
            dec_id = f"dec_succ_{int(time.time())}"
            self.vault.store_decision_outcome(dec_id, "Recent Tactical Action", user_input[:100], "SUCCESS", "Executed and confirmed effective by Operator.")
        elif any(kw in lower_input for kw in ["that failed", "payload blocked", "exploit failed", "was patched", "didn't work", "did not work"]):
            dec_id = f"dec_fail_{int(time.time())}"
            self.vault.store_decision_outcome(dec_id, "Recent Tactical Action", user_input[:100], "FAILURE", "Defensive obstruction or failed execution. Adapt vector.")

        # 4. DeepSeek Neocortex High-Signal Pass (for complex inputs)
        if router and getattr(router, 'api_key', None) and len(user_input) > 80:
            try:
                system_prompt = (
                    "You are Ciph's Cognitive Knowledge & Entity Extractor. Analyze this conversation turn "
                    "and extract any persistent user preferences, operational constraints, and entity connections. "
                    "Return ONLY valid JSON matching:\n"
                    "{\n"
                    '  "facts": [{"category": "operational|preference|philosophy|target", "key": "...", "value": "..."}],\n'
                    '  "entity_links": [{"source": "...", "relation": "...", "target": "...", "details": "..."}]\n'
                    "}\n"
                    "If nothing new to extract, return {\"facts\": [], \"entity_links\": []}."
                )
                raw = router.think(
                    user_input=f"Extract knowledge from:\nUSER: {user_input}\nCIPH: {ai_response[:200]}",
                    history=[],
                    system_prompt=system_prompt,
                    temperature=0.1
                )
                clean_json = re.sub(r'```(?:json)?', '', raw).strip()
                parsed = json.loads(clean_json)

                for f in parsed.get('facts', []):
                    if f.get('key') and f.get('value'):
                        fid = f"prof_ai_{f['key'].lower()[:16]}"
                        self.vault.store_profile_fact(fid, f.get('category', 'general'), f['key'], f['value'], 0.85)
                        extracted_facts.append(f)

                for l in parsed.get('entity_links', []):
                    if l.get('source') and l.get('target'):
                        lid = f"link_ai_{int(time.time())}_{l['target'][:10]}"
                        self.vault.store_entity_link(lid, l['source'], l.get('relation', 'RELATED_TO'), l['target'], l.get('details', ''))
                        extracted_links.append(l)
            except Exception:
                pass

        return {
            "facts_extracted": len(extracted_facts),
            "links_extracted": len(extracted_links),
            "details": {"facts": extracted_facts, "links": extracted_links}
        }

    def scan_historical_conversations(self, router: Optional[Any] = None, limit: int = 150) -> Dict[str, Any]:
        """
        Retroactive Cold-Start Learning:
        Scans all past historical conversations in cipher_vault.db to extract baseline
        Operator profile facts, entity relationships, and emotional baselines.
        """
        convos = self.vault.get_all_historical_conversations(limit=limit)
        if not convos:
            return {"status": "No historical conversations found in vault.", "processed": 0}

        total_facts = 0
        total_links = 0

        for conv in convos:
            res = self.extract_implicit_profile_and_entities(
                user_input=conv.get('prompt', ''),
                ai_response=conv.get('response', '')[:200],
                router=None  # Fast deterministic extraction across historical records
            )
            total_facts += res.get('facts_extracted', 0)
            total_links += res.get('links_extracted', 0)

        return {
            "status": "Retroactive learning sweep completed successfully.",
            "conversations_analyzed": len(convos),
            "profile_facts_established": total_facts,
            "entity_links_mapped": total_links
        }

    def compress_session_narrative(self, history: List[Dict[str, str]], router: Optional[Any] = None) -> Optional[Dict[str, Any]]:
        """
        Compress conversation session into an episodic narrative milestone node.
        Uses DeepSeek V4 Pro with strict JSON schema extraction.
        """
        if not history or len(history) < 4:
            return None

        from ciph_router import CiphRouter
        active_router = router or CiphRouter()

        convo_text = ""
        for msg in history[-12:]:
            role = msg.get('role', 'user').upper()
            content = msg.get('content', '')[:300]
            convo_text += f"{role}: {content}\n"

        system_prompt = (
            "You are Ciph's Cognitive Memory Archival Engine. Compress the conversation session "
            "into a high-density episodic memory node. Return ONLY a valid JSON object matching:\n"
            "{\n"
            '  "summary": "1-2 sentence core strategic narrative of what occurred",\n'
            '  "active_targets": ["targets", "domains", "bounties", "technologies discussed"],\n'
            '  "key_decisions": "Key decisions or doctrine agreed upon",\n'
            '  "open_threads": "Unresolved questions or pending steps"\n'
            "}"
        )

        try:
            raw_json = active_router.think(
                user_input=f"Compress this session dialogue into an episodic node:\n\n{convo_text}",
                history=[],
                system_prompt=system_prompt,
                temperature=0.1
            )
            import re
            clean_str = re.sub(r'```(?:json)?', '', raw_json).strip()
            node = json.loads(clean_str)

            summary = node.get("summary", "Session dialogue completed.")
            targets_str = ", ".join(node.get("active_targets", []))
            decisions = node.get("key_decisions", "")

            # Persist in CipherVault SQLite timeline
            milestone_id = self.vault.store_narrative_milestone(
                summary=summary,
                targets=targets_str,
                decisions=decisions,
                tag="session_compression"
            )
            node["milestone_id"] = milestone_id
            return node
        except Exception as e:
            # Fallback simple summary
            simple_summary = f"Completed conversation session of {len(history)} turns."
            milestone_id = self.vault.store_narrative_milestone(
                summary=simple_summary,
                targets="",
                decisions="",
                tag="fallback"
            )
            return {"summary": simple_summary, "milestone_id": milestone_id}

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

    def get_narrative_timeline_formatted(self, limit: int = 5) -> str:
        """Format the narrative timeline for display."""
        milestones = self.vault.get_narrative_milestones(limit=limit)
        if not milestones:
            return "No narrative milestones recorded yet. Sessions compress automatically."

        lines = [
            "═" * 60,
            "🧠 CIPH STRATEGIC NARRATIVE TIMELINE",
            "═" * 60
        ]
        for m in milestones:
            age = self._time_ago(m['timestamp'])
            lines.append(f"• [{age}] {m['summary']}")
            if m.get('targets'):
                lines.append(f"  Targets: {m['targets']}")
            if m.get('decisions'):
                lines.append(f"  Decisions: {m['decisions']}")
            lines.append("")

        lines.append("═" * 60)
        return "\n".join(lines).strip()