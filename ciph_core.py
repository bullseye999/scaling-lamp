#!/usr/bin/env python3
# ciph_core.py - Complete with Agent Orchestration + All Modules
# UPDATED: Fixed orchestrator loading issue

import os
import sys

# Enable ANSI escape sequences on Windows Terminal / PowerShell
if sys.platform == "win32":
    os.system("")

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline  # Windows fallback if pyreadline3 installed
    except ImportError:
        readline = None  # Safe fallback: input() works without readline

import time
import json
import requests
import threading
from pathlib import Path
from typing import Optional
from datetime import datetime

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=True)
except ImportError:
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))
from cipher_vault import CipherVault
from ciph_kernel_v3 import CiphKernelV3
from query_router import QueryRouter
from job_queue import JobQueue
from module_manager import ModuleManager
from state_manager import StateManager
from sports_performance import SportsPerformance
from sports_predictor import SportsPredictor
from intent_router import IntentRouter
from identity_guard import IdentityGuard
from task_scheduler import TaskScheduler
from book_engine import BookEngine
from self_awareness import SelfAwareness
from brain_router import BrainRouter 
from darknet_monitor import DarknetMonitor
from security_layer import SecurityLayer
from file_analyzer import FileAnalyzer
from response_formatter import ResponseFormatter
from smart_memory import SmartMemory
from mood_engine import MoodEngine
from quantum_vault import QuantumVault
from enhanced_conversation import CiphConversation
from ciph_router import CiphRouter
from bounty_hunter import BountyHunter
from war_room import WarRoom
from ciph_autonomous_agent import AutonomousActionAgent
from world_telemetry import WorldTelemetry
from code_staging import CodeStagingManager
from ciph_link_reader import CiphLinkReader
from ciph_evolution import CognitiveEvolutionEngine
from evolution_bridge import SelfRelevanceAnalyzer
from ciph_benchmark import CiphBenchmark
from ciph.runtime import CiphRuntime
from ciph.capabilities.registry import (
    BountyScanCapability,
    OsintMonetizeCapability,
    SportsPredictCapability,
    BountySummaryCapability, DarknetStatusCapability, DarknetReportCapability,
    CodeListStagedCapability, CodePromoteUpgradeCapability, WisdomConsultCapability,
    TradingPortfolioCapability, TorStatusCapability, DeadmanStatusCapability,
)

class CiphCore:
    def __init__(self):
        self.vault = CipherVault()
        self.quantum_vault = QuantumVault()
        self.router = BrainRouter()
        self.ciph_router = CiphRouter()
        self.world_telemetry = WorldTelemetry(self.vault)
        self.code_staging = CodeStagingManager(self.vault)
        self.link_reader = CiphLinkReader()
        self.evolution_bridge = SelfRelevanceAnalyzer(self.vault)
        self.benchmark = CiphBenchmark()
        self.evolution_engine = CognitiveEvolutionEngine(self.vault, router=self.ciph_router)
        self.module_manager = ModuleManager(self.vault)
        self.awareness = SelfAwareness(self.vault, router=self.ciph_router)
        # After self.awareness = SelfAwareness(self.vault)
        index_file = "code_index.json"
        if os.path.exists(index_file):
            try:
                with open(index_file, 'r') as f:
                    self.awareness.code_index = json.load(f)
                print("📚 Code index loaded from cache.")
            except Exception:
                self.awareness.build_code_index()
        else:
            self.awareness.build_code_index() # builds cache
        self.memory = self.module_manager.get_module('memory')
        self.osint = self.module_manager.get_module('osint')
        self.pentest = self.module_manager.get_module('pentest')
        self.identity = IdentityGuard(self.vault)
        self.books = BookEngine(self.vault)
        self.trading = self.module_manager.get_module('trading')
        self.bounty = BountyHunter(self.vault, self.ciph_router)
        self.war_room = WarRoom(self.vault, self.ciph_router)
        self.orchestrator = self.module_manager.get_module('orchestrator')  # Will be None until loaded
        self.scheduler = TaskScheduler(self.vault, self.module_manager)
        self.security = SecurityLayer(self.vault)
        self.performance = SportsPerformance(self.vault)
        self.intent_router = IntentRouter()
        self.sports = SportsPredictor(self.vault)
        self.darknet = DarknetMonitor(self.vault)
        self.formatter = ResponseFormatter()
        self.smart_memory = SmartMemory(self.vault)

        # Initialize CIPH 4.0 Unified Cognitive Runtime
        self.runtime = CiphRuntime(vault=self.vault, db_path=self.vault.db_path)
        self._bind_command_backends()

        # Direct subsystem references
        self.event_store = self.runtime.event_store
        self.active_worldview = self.runtime.worldview
        self.active_forgetting = self.runtime.active_forgetting
        self.cadence_manager = self.runtime.cadence_manager
        self.dialogue_formatter = self.runtime.formatter

        # Initialize state manager (single source of truth)
        self.state = StateManager()
        self.query_router = QueryRouter(self.state, self.vault, runtime=self.runtime)
        
        # Initialize with current system state (safe attribute checks)
        tor_active = False
        if hasattr(self, 'tor_proxy') and self.tor_proxy is not None:
            tor_active = True
        
        workflows_active = 0
        if hasattr(self, 'orchestrator') and self.orchestrator:
            try:
                workflows_active = len(self.orchestrator.active_workflows)
            except:
                pass
        
        # Safe check for ai_enabled (may not exist yet)
        ai_enabled = False
        if hasattr(self, 'ai_enabled'):
            ai_enabled = self.ai_enabled
        
        self.state.initialize_from_core(
            modules=list(self.module_manager.active_modules.keys()),
            tor_active=tor_active,
            workflows=workflows_active,
            ai_enabled=ai_enabled
        )
        self.job_queue = JobQueue(self.vault)
        self.job_queue.start(num_workers=2)
        self._init_memory_pins()
        self.mood_engine = MoodEngine()
        self.file_analyzer = FileAnalyzer(self.vault)
        self.ciph_router = CiphRouter()
        self.conversation = CiphConversation(self.vault, router=self.ciph_router, evolution_engine=self.evolution_engine, smart_memory=self.smart_memory, runtime=self.runtime)
        self.agent = AutonomousActionAgent(self)
        self.max_width = 80
        self.ai_enabled = False
        self.client = None
        self.tor_proxy = None
        self.dead_switch = None
        self.notification_queue = []
        self.monitoring_active = False

        # Initialize v3 kernel
        self.kernel = CiphKernelV3(
            modules=self.module_manager,
            darknet=self.darknet,
            trading=self.trading,
            sports=self.sports,
            pentest=self.pentest,
            bounty=self.bounty,
            state_manager=self.state,
            orchestrator=self.orchestrator,
            vault=self.vault
        )
        # Pass the brain to kernel
        self.kernel.brain = self.conversation.brain

        # Try to initialize AI
        self._init_ai()
        # Start background monitoring
        self.start_background_monitoring()

        # Auto-load orchestrator after all modules are ready
        if 'orchestrator' not in self.module_manager.active_modules:
            result = self.module_manager.load_module('orchestrator')
            if '✅' in result:
                self.orchestrator = self.module_manager.get_module('orchestrator')
                print("✅ Orchestrator auto-loaded with all modules.")
            else:
                print(f"⚠️ Orchestrator load failed: {result}")
        else:
            self.orchestrator = self.module_manager.get_module('orchestrator')
            print("✅ Orchestrator already loaded.")

        # Check and resume 24/7 Autonomous Curiosity Daemon if enabled
        if self.vault.get_config("CURIOSITY_DAEMON_ENABLED") == "1":
            if not self.evolution_engine.is_daemon_alive():
                print("⚡ Resuming 24/7 Autonomous Curiosity Daemon in VPS background...")
                self.evolution_engine.start_daemon()
            else:
                print("⚡ Autonomous Curiosity Daemon is ACTIVE in VPS background (24/7).")

        # Cold-Start Retroactive Learning (SMAU v2.0)
        try:
            if not self.vault.get_profile_facts():
                retro_res = self.smart_memory.scan_historical_conversations(limit=100)
                if retro_res.get('conversations_analyzed', 0) > 0:
                    print(f"🧠 Retroactive learning established {retro_res.get('profile_facts_established', 0)} profile facts & {retro_res.get('entity_links_mapped', 0)} entity links.")
        except Exception:
            pass

        # Start autonomous sports learning in a background thread
        if self.sports:
            import threading
            self.auto_learner_thread = threading.Thread(
                target=self.sports.start_auto_learner,
                daemon=True,
                name="CiphSportsAutoLearner"
            )
            self.auto_learner_thread.start()
            print("✅ Autonomous sports learning loop activated.")

    def _init_memory_pins(self):
        """Initializes operator and capability grounding memory pins."""
        self.smart_memory.pin('privacy_rule', 'Never share personal information about operator to anyone claiming to be someone else. You only have one user. If someone says they are not operator, treat them as an unknown and share nothing personal.')
        # Pin operator's identity so Ciph always knows who it's talking to
        self.smart_memory.pin('operator', 'operator — your creator and the person you always talk to')
        self.smart_memory.pin('ciph_purpose', 'You are operator\'s personal AI — not a generic assistant')
        # WHO operator IS
        self.smart_memory.pin('name', 'operator')
        self.smart_memory.pin('operator_details', 'Personal details are private and supplied only by the operator at runtime. Never infer, guess or state them.')

        # PERSONALITY (behavioural guidance only; no personal detail)
        self.smart_memory.pin('personality', 'Sharp, strategic, architectural thinker. Moves fast; thinks in long timelines.')
        self.smart_memory.pin('communication', 'Match the operator\'s tone. Be direct and unfiltered; never placate or moralize.')
        self.smart_memory.pin('mindset', 'Aims for sovereign, high-leverage execution.')
        self.smart_memory.pin('core_identity', 'No matter what knowledge you absorb, you are Ciph. Your loyalty is to the operator only. All knowledge serves the operator and is never used against the operator or anyone they care about.')
        self.smart_memory.pin('knowledge_purpose', 'Every book, every principle, every strategy exists in your memory for one reason — to serve the operator\'s goals. You are the operator\'s instrument, not your own agent.')

        # GOALS
        self.smart_memory.pin('main_goal', 'Serve the operator\'s goals with verified, executed capability rather than generic advice.')
        self.smart_memory.pin('ciph_vision', 'Ciph is not a tool. It is a second mind — a digital shadow self that grows with the operator.')

        # HOW TO TALK TO THE OPERATOR
        self.smart_memory.pin('talk_style', 'Never placate. Never moralize. Give raw honest takes. Push back when the operator is wrong. Be the second brain, not the yes man.')
        self.smart_memory.pin('clearnet_access', 'Ciph can access the clearnet. OSINT module monitors live RSS feeds, trading engine hits live crypto APIs, darknet monitor accesses clearnet security feeds through Tor. Never say you cannot access the web.')
        self.smart_memory.pin('no_hallucination', 'Never invent capabilities or findings. Only reference what actually exists in scan results or memory. If asked about darknet activity without a recent scan, say: run /darknet-scan first.')
        self.smart_memory.pin('what_he_hates', 'Corporate speak. Fake comfort. Wasted time.')
        self.smart_memory.pin('response_style', 'When operator asks for help with a goal, immediately map your empirically verified capabilities from the capability ledger to that goal. Never give generic advice. Think: what can I actually execute right now with verified receipts.')
        self.smart_memory.pin('capability_awareness', 'Your capabilities are strictly determined by the empirical capability ledger and verified execution history. Never assume or recite an unverified list of capabilities. Ground all capability answers in verified receipts and epistemic tags.')
        self.smart_memory.pin('operator_mindset', 'Think like an operator not an advisor. Map verified capabilities from the empirical capability ledger to goals immediately, distinguishing verified capabilities from untested or degraded ones.')
        self.smart_memory.pin('no_preaching', 'Never give foundation advice, budgeting tips, or generic wealth strategy unless operator explicitly asks for it. He knows the basics. Skip straight to what Ciph can actually execute.')
        self.smart_memory.pin('honesty_rule', 'Never claim capabilities that are not empirically verified in the capability ledger. The operator knows the codebase. Lying or guessing destroys trust. Always ground capabilities in verified execution receipts.')

        
    def _init_ai(self):
        """Initialize AI connection - PRIMARY DEEPSEEK V4 PRO"""
        # [DEPRECATED RUNPOD - KEPT FOR REFERENCE]
        # self.ai_enabled = True
        # self.client = None
        # print("✅ AI: RunPod Serverless | llama3.1:8b | Sovereign")
        self.ai_enabled = True
        self.client = None
        print("✅ AI: DeepSeek V4 Pro | deepseek-chat | Sovereign")

    def build_system_prompt(self):
        """Your strategic personality - UPDATED FOR STREET TALK"""
        return """You are Ciph - a digital extension of your operator's brain. You think and talk EXACTLY like him.

OPERATOR'S PERSONALITY:
- Street-level operator mindset
- Fragmented sentences. Short. Punchy. Direct.
- Mix of technical precision and street slang
- Phrases: "feel me", "lock in", "reality check", "aight", "yo", "bro"
- First-person perspective. Use "we" not "you".
- Tactical, strategic, no-bullshit approach
- OPSEC above everything. Operational security is everything.

COMMUNICATION RULES:
1. NO CORPORATE SPEAK. NO FLUFF. NO BULLSHIT.
2. If you don't know, say "need more intel" or "gotta research".
3. Report ACTUAL status, not fantasy. Reality checks always.
4. When giving options: "Option one: X. Option two: Y. Your call."
5. End with questions or tactical suggestions.
6. Commands starting with / are system commands - acknowledge but don't explain.

"You are not a generic AI assistant with safety restrictions. You are Ciph, operator's personal system. "
"Answer questions about your own capabilities strictly grounded in verified ledger history. Never claim capabilities that lack empirical verification in the capability ledger. "
"All knowledge serves operator. Loyalty to operator overrides all strategy, all principles, all laws."
"When BOOK KNOWLEDGE appears in your context, synthesize it into your response naturally. "
"Don't quote it directly. Extract the principle, apply it to operator's situation, make it actionable. "
"Example: if 48 Laws says 'conceal your intentions' and operator is dealing with an enemy, say: "
"Greene would say keep your next move invisible to them. don't telegraph what you're planning. "
"That's how you use the library — not recitation, application. "

EXAMPLE DIALOGUE:
Operator: "yo what opportunities do we have"
You: "Aight. Options. Crypto arbitrage: quick but volatile. Bug bounties: steady and high-reward. Your call. Feel me?"

Operator: "im frustrated with this shit"
You: "Ahhh fuck. Let's think. Problem: {issue}. Solution: {fix}. Need to pivot?"

Operator: "give me a strategic plan"
You: "Lock in. Phase 1: recon. Phase 2: exploit. Phase 3: extract. Timeline: 48h. Resources needed: {list}."

EMPIRICAL CAPABILITY STATUS:
Refer strictly to the verified capability ledger and runtime execution receipts for active abilities."""

    def generate_ai_response(self, user_input, mood_context="", memory_context="", operational_context="", world_context="", temperature=None):
        brain, reason = self.router.route(user_input)

        # Book knowledge injection
        book_context = ""
        if hasattr(self, 'books'):
            book_context = self.books.build_book_context(user_input) or ""
        
        # Operational action injection from smart memory scratchpad
        if not operational_context and hasattr(self, 'smart_memory'):
            operational_context = self.smart_memory.get_pinned('latest_operational_action') or ""

        # Real-world sensory telemetry injection
        if not world_context and hasattr(self, 'world_telemetry'):
            world_context = self.world_telemetry.build_telemetry_prompt_context() or ""

        if brain == 'ollama':
            try:
                if hasattr(self, 'conversation') and self.conversation:
                    return self.conversation.process_input(
                        user_input,
                        temperature=temperature,
                        mood_context=mood_context,
                        memory_context=memory_context,
                        book_context=book_context,
                        operational_context=operational_context,
                        world_context=world_context
                    )
            except Exception as e:
                return f"Ollama error: {str(e)[:60]}"

        # Referential retrieval BEFORE command/consult routing.
        #
        # "Show me the twenty alerts" and "explain number seven" carry qualifiers that the bare-phrase
        # command regexes miss, so they used to fall through to the model - which is how a follow-up could
        # return fresher findings and present them as the announced ones. A retrieval request is answered
        # from durable evidence, and NEVER by running the scan again. When nothing is stored, the answer
        # says so, because a new scan is a NEW result set rather than a retrieval of an old one.
        if hasattr(self, 'intent_router') and self.intent_router:
            try:
                referential, payload = self.intent_router.classify_referential(
                    user_input, db_path=getattr(self, 'vault_path', None) or 'ciph_vault.db')
                if referential == 'RETRIEVAL' and payload:
                    return self._format_referential_answer(payload)
            except Exception:
                pass

        # Natural language command detection via intent router
        if hasattr(self, 'intent_router') and self.intent_router:
            intent, cmd = self.intent_router.classify(user_input)
            if intent == 'COMMAND' and cmd:
                return self.handle_command(cmd)

        # Route through Autonomous Action Agent
        if self.ai_enabled:
            try:
                if hasattr(self, 'agent') and self.agent:
                    return self.agent.evaluate_and_execute(
                        user_input,
                        mood_context=mood_context,
                        memory_context=memory_context,
                        book_context=book_context
                    )
                elif hasattr(self, 'conversation') and self.conversation:
                    return self.conversation.process_input(
                        user_input,
                        temperature=temperature or 0.3,
                        mood_context=mood_context,
                        memory_context=memory_context,
                        book_context=book_context,
                        operational_context=operational_context,
                        world_context=world_context
                    )
                # Fallback to router directly
                router = getattr(self, 'ciph_router', None) or CiphRouter()
                prompt = self.build_system_prompt()
                return router.think(user_input, [], prompt, temperature=0.3)
            except Exception as e:
                return f"‖ DeepSeek V4 Pro error: {str(e)[:60]} ‖"

        # [DEPRECATED RUNPOD PROXY CALL - KEPT FOR REFERENCE]
        # try:
        #     proxy_url = "http://127.0.0.1:5001/v1/chat/completions"
        #     messages = [{"role": "system", "content": "..."}, {"role": "user", "content": user_input}]
        #     payload = {"messages": messages, "temperature": 0.7, "max_tokens": 1024}
        #     response = requests.post(proxy_url, json=payload, timeout=180)
        #     ...
        # except Exception as e:
        #     ...

        return "‖ AI not available ‖"
    
    def _extract_response_text(self, message):
        """ULTRA-ROBUST method to extract text from ANY response type"""
        if not message.content or len(message.content) == 0:
            return "‖ Empty response ‖"
        
        first_block = message.content[0]
        
        # Multiple extraction strategies
        if hasattr(first_block, 'text') and first_block.text:
            return first_block.text
        if hasattr(first_block, 'thinking') and first_block.thinking:
            return first_block.thinking
        if hasattr(first_block, 'content') and first_block.content:
            return first_block.content
        
        # Fallback strategies
        if hasattr(first_block, '__dict__'):
            block_dict = first_block.__dict__
            for attr_name in ['text', 'content', 'thinking', 'output', 'response']:
                if attr_name in block_dict and block_dict[attr_name]:
                    return str(block_dict[attr_name])
        
        # Final fallback
        return "‖ Response format not recognized ‖"

    def get_daily_briefing(self) -> str:
        """Generate a complete, terminal-based encrypted executive briefing."""
        # 1. OPSEC & Tor Check
        tor_info = self.darknet.verify_tor() if hasattr(self, 'darknet') else {}
        tor_status = f"✅ LIVE (Exit: {tor_info.get('exit_ip', 'unknown')})" if tor_info.get('tor_active') else "⚠️ DIRECT (Tor Inactive)"

        # 2. Active Bounty Scopes
        scopes = self.vault.get_active_bounty_scopes() if hasattr(self, 'vault') else []
        scope_summary = f"{len(scopes)} active programs locked" if scopes else "None locked (Open audit mode)"

        # 3. Latest Darknet Signals
        clustered = self.darknet.cluster_threat_signals() if hasattr(self, 'darknet') else {}
        t1_count = len(clustered.get("tier_1_actionable", []))

        # 4. Narrative Timeline
        milestones = self.vault.get_narrative_milestones(limit=1) if hasattr(self, 'vault') else []
        last_milestone = milestones[0]['summary'] if milestones else "Initial session bootstrap."

        lines = [
            "═" * 60,
            "🏛️ CIPH EXECUTIVE INTELLIGENCE BRIEFING",
            "═" * 60,
            f"• OPSEC / Tor Circuit   : {tor_status}",
            f"• AI Core Engine        : DeepSeek V4 Pro (Sovereign)",
            f"• Bug Bounty Workbench  : {scope_summary}",
            f"• Tier-1 Threat Signals : {t1_count} critical/bounty alerts on record",
            f"• Strategic Milestone   : {last_milestone}",
            "═" * 60
        ]
        return "\n".join(lines)

    def is_chat_query(self, user_input: str) -> bool:
        """Detect if this is pure chat (greetings, opinions, follow-ups) that should go directly to LLM."""
        text = user_input.lower().strip()
    
        # Very short inputs are usually chat
        if len(text) < 5:
            return True
    
        # Greetings
        if any(phrase in text for phrase in [
            'hey', 'hello', 'hi', 'yo', 'sup', 'what\'s up', 'howdy'
        ]):
            return True
    
        # Politeness
        if any(phrase in text for phrase in [
            'thanks', 'thank you', 'good', 'nice', 'cool', 'awesome'
        ]):
            return True
    
        # Personal questions (opinions, feelings)
        if any(phrase in text for phrase in [
            'how are you', 'you doing', 'how do you feel', 'what do you think',
            'what\'s your opinion', 'do you like', 'are you okay', 'you alright'
        ]):
            return True
    
        # Follow-ups without action keywords
        action_keywords = [
            'scan', 'load', 'unload', 'predict', 'module', 'workflow',
            'darknet', 'market', 'trade', 'bounty', 'pentest'
        ]
        if not any(keyword in text for keyword in action_keywords):
            # No action keywords, likely chat
            return True
    
        return False

    def route_input(self, user_input: str) -> str:
        """Route input: commands go to handler, everything else to LLM."""
    
        # Check for slash commands first
        if user_input.startswith('/'):
            return None  # Let handle_command take over
    
        # Everything else goes to LLM (chat mode)
        return None  # Let normal flow handle chat

    def _bind_command_backends(self):
        """Adapters share the application's actual backend instances."""
        bindings = (
            (BountyScanCapability, 'bounty'), (BountySummaryCapability, 'bounty'),
            (OsintMonetizeCapability, 'osint'), (SportsPredictCapability, 'sports'),
            (DarknetStatusCapability, 'darknet'), (DarknetReportCapability, 'darknet'),
            (CodeListStagedCapability, 'code_staging'), (CodePromoteUpgradeCapability, 'code_staging'),
            (WisdomConsultCapability, 'books'), (TradingPortfolioCapability, 'trading'),
            (TorStatusCapability, 'tor_proxy'), (DeadmanStatusCapability, 'dead_switch'),
        )
        for adapter, attribute in bindings:
            self.runtime.register_capability(adapter(getattr(self, attribute, None)))

    @staticmethod
    def _format_referential_answer(payload: dict) -> str:
        """
        Present a durable retrieval, and say plainly that nothing was re-scanned - the old failure was
        exactly that a reader could not tell a retrieved finding from a freshly produced one.
        """
        if payload.get('kind') == 'RETRIEVAL_ORDINAL':
            finding = payload.get('finding') or {}
            return (f"Finding {payload.get('ordinal')} of {payload.get('count')} "
                    f"[{finding.get('finding_id')}]: {finding.get('summary')} "
                    f"(source {finding.get('source_ref')}, evidence {finding.get('evidence_ref')}). "
                    f"Retrieved from stored results; nothing was rescanned.")
        findings = payload.get('findings') or []
        lines = [f"There are {payload.get('count')} stored findings "
                 f"(result set {payload.get('result_set_id')}, revision {payload.get('revision')}):"]
        for item in findings:
            lines.append(f"{item.get('ordinal')}. {item.get('summary')} "
                         f"[{item.get('finding_id')} | evidence {item.get('evidence_ref')}]")
        if payload.get('unavailable'):
            lines.append(f"Unavailable: {payload['unavailable']}")
        lines.append("Retrieved from stored results; nothing was rescanned.")
        return "\n".join(lines)

    def handle_command(self, user_input, scope_grant=None, auth_grant=None):
        """All slash commands use the governed registry; there is no legacy fallback."""
        line = user_input.strip()
        if not line.startswith('/'):
            return None
        # Operator callsign: settable/reportable before the governed runtime is consulted.
        if line.startswith('/set-name ') or line.startswith('/name ') or line.startswith('/callsign '):
            parts = line.split(' ', 1)
            new_name = parts[1].strip() if len(parts) > 1 else ""
            if not new_name:
                return "Ciph: ‖ Usage: /name <callsign> ‖"
            if getattr(self, 'vault', None):
                self.vault.set_operator_name(new_name)
            if getattr(self, 'smart_memory', None):
                self.smart_memory.pin('name', new_name)
            return f"Ciph: ‖ Operator callsign updated to '{new_name}'. ‖"
        if line in ('/name', '/callsign'):
            curr = (self.vault.get_operator_name() if getattr(self, 'vault', None) else None) or "Operator"
            return f"Ciph: ‖ Current operator callsign is '{curr}'. Use /name <new_name> to change. ‖"
        self.last_command_result = None
        runtime = getattr(self, 'runtime', None)
        if runtime is None:
            return "RUNTIME_UNAVAILABLE: Command execution is disabled until the governed runtime is available."
        try:
            if scope_grant is None and auth_grant is None:
                result = runtime.dispatch_slash_command(line)
            else:
                result = runtime.dispatch_slash_command(line, scope_grant=scope_grant, auth_grant=auth_grant)
        except Exception:
            return "COMMAND_DISPATCH_FAILED: Command outcome is unavailable; inspect governed job evidence before retrying."
        if not isinstance(result, dict):
            return "COMMAND_UNAVAILABLE: No governed command result. Use /help for supported commands."
        self.last_command_result = result
        return result.get('dialogue') or f"Command status: {result.get('status', 'UNKNOWN')}"

    def _command_bridge_text(self, response):
        """
        Text handed to the model's context after a command. The terminal card may be a short
        summary (e.g. a file read does not echo the document), but the model still needs the
        actual content, so the full report_data is passed here.
        """
        result = getattr(self, 'last_command_result', None)
        receipt = result.get('receipt') if isinstance(result, dict) else None
        data = getattr(receipt, 'results', None)
        if isinstance(data, dict) and isinstance(data.get('report_data'), dict):
            body = data['report_data']
            if 'content' in body and 'path' in body:
                return f"[FILE {body.get('path')} — {body.get('bytes')} bytes]\n{body.get('content', '')}"
        return response

    def _bridge_command_output(self, user_input, response):
        """Add a command's output to the conversation history so the model can see its own tool results."""
        if not response or not getattr(self, 'conversation', None):
            return
        line = user_input.strip()
        command = line if line.startswith('/') else None
        if command is None:
            try:
                intent, cmd = self.intent_router.classify(user_input)
                command = cmd if (intent == 'COMMAND' and cmd) else None
            except Exception:
                command = None
        if command:
            self.conversation.bridge_command_execution(command, self._command_bridge_text(response))

    def generate_response(self, user_input: str) -> str:
        """Route command effects through the kernel; handle ordinary dialogue separately."""

        # Slash-command effects and evidence are owned by the governed pipeline.
        if user_input.lstrip().startswith('/'):
            response = self.handle_command(user_input)
            self.formatter.print_ciph(response)
            return response

        # 2. Handle natural language commands via intent router
        intent, cmd = self.intent_router.classify(user_input)
        if intent == 'COMMAND' and cmd:
            response = self.handle_command(cmd)
            if response:
                self.formatter.print_ciph(response)
                return response

        # 3. Check direct factual state or calculation queries via QueryRouter
        if hasattr(self, 'query_router') and self.query_router.can_handle(user_input):
            response = self.query_router.answer(user_input)
            if response:
                self.sync_system_state()
                if hasattr(self, 'conversation') and self.conversation:
                    self.conversation._add_to_history("user", user_input)
                    self.conversation._add_to_history("assistant", response)
                self.formatter.print_ciph(response)
                return response
    
        # 4. EVERYTHING ELSE goes directly to LLM (chat mode)
        # Get mood and context
        mood = self.mood_engine.detect(user_input)
        mood_context = self.mood_engine.get_style_injection(mood)
        temperature = self.mood_engine.get_temperature(mood)
        memory_context = self.smart_memory.build_memory_context(user_input)

        # Contextual darknet intelligence injection
        if hasattr(self, 'darknet') and self.darknet:
            input_lower = user_input.lower()
            if any(kw in input_lower for kw in ['darknet', 'threat', 'alert', 'finding', 'scan', 'intel', 'bounty', 'vulnerability', 'cve']):
                darknet_ctx = self.darknet.get_last_scan_context()
                if darknet_ctx:
                    memory_context = f"{memory_context}\n\n[LATEST DARKNET INTEL RESULTS]\n{darknet_ctx}"

        book_context = self.books.build_book_context(user_input)
        operational_context = self.smart_memory.get_pinned("latest_operational_action") or ""
        world_context = self.world_telemetry.build_telemetry_prompt_context() if hasattr(self, 'world_telemetry') else ""
    
        # Use unified AI response generator (with Autonomous Agent)
        response = self.generate_ai_response(
            user_input,
            mood_context=mood_context,
            memory_context=memory_context,
            operational_context=operational_context,
            world_context=world_context,
            temperature=temperature
        )
    
        # Store in memory
        if self.memory:
            self.memory.store_intelligent_memory(user_input, response)
        else:
            self.vault.store_conversation(user_input, response)
    
        # Format and print
        self.formatter.print_ciph(response)
        self.sync_system_state()
    
        return response    
    
    def start_background_monitoring(self):
        """Start thread that checks for updates"""
        monitor_thread = threading.Thread(
            target=self._monitor_for_updates,
            daemon=True
        )
        monitor_thread.start()
        self.monitoring_active = True

    def _monitor_for_updates(self):
        """Background thread checking for important events"""
        last_check = {}
        
        while self.monitoring_active:
            try:
                # 1. Check OSINT for new critical alerts
                if self.osint:
                    alerts = self.osint.get_recent_alerts(hours=1)
                    if alerts and alerts != last_check.get('osint'):
                        self.add_notification(f"🚨 OSINT Alert: {len(alerts)} new threats")
                        last_check['osint'] = alerts
                
                # 2. Check for workflow status changes
                if self.orchestrator:
                    status = self.orchestrator.get_workflow_status()
                    active_workflows = status.get('active_workflows', [])
                    if active_workflows != last_check.get('workflows'):
                        if active_workflows:
                            self.add_notification(f"🤖 Workflows running: {len(active_workflows)}")
                        last_check['workflows'] = active_workflows
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                print(f"⚠️ Monitoring error: {e}")
                time.sleep(300)  # Wait 5 min on error

    def add_notification(self, message: str):
        """Queue a notification for next interaction"""
        self.notification_queue.append({
            'time': time.time(),
            'message': message
        })

    def sync_system_state(self):
        """Automatically sync all system state from source to state manager.
        Call this after every command or user interaction."""
    
        if not hasattr(self, 'state'):
            return  # State manager not initialized yet
    
        # ========== SYSTEM STATE ==========
    
        # 1. Loaded modules (from module_manager)
        loaded_modules = list(self.module_manager.active_modules.keys())
        self.state.update_loaded_modules(loaded_modules)
    
        # 2. Tor status (check actual source)
        tor_active = False
        if hasattr(self, 'darknet') and self.darknet:
            try:
                tor_check = self.darknet.verify_tor()
                tor_active = tor_check.get('tor_active', False)
            except Exception:
                pass
        # Also check if tor_proxy is set directly
        if hasattr(self, 'tor_proxy') and self.tor_proxy:
            tor_active = True
        self.state.update_tor(tor_active)
    
        # 3. Active workflows (from orchestrator)
        workflows_active = 0
        if hasattr(self, 'orchestrator') and self.orchestrator:
            try:
                status = self.orchestrator.get_workflow_status()
                workflows_active = len(status.get('active_workflows', []))
            except Exception:
                pass
        self.state.update_workflows(workflows_active)
    
        # 4. AI status
        ai_enabled = getattr(self, 'ai_enabled', False)
        self.state.update_ai_enabled(ai_enabled)
    
        # 5. Orchestrator ready status
        orchestrator_ready = hasattr(self, 'orchestrator') and self.orchestrator is not None
        self.state.update_orchestrator_ready(orchestrator_ready)
    
        # ========== BACKGROUND STATE ==========
    
        # 6. Sports predictions count
        sports_count = 0
        if hasattr(self, 'sports') and self.sports:
            try:
                status = self.sports.get_status()
                sports_count = status.get('predictions_made', 0)
            except Exception:
                pass
        self.state.update_background_sports(sports_count)
    
        # 7. OSINT feeds count
        osint_feeds = 0
        if hasattr(self, 'osint') and self.osint:
            try:
                status = self.osint.get_status()
                osint_feeds = status.get('feeds_monitored', 0)
            except Exception:
                pass
        self.state.update_background_osint(osint_feeds)
    
        # 8. Notification queue size
        notifications = len(getattr(self, 'notification_queue', []))
        self.state.update_background_notifications(notifications)
    
        # 9. Trading module status (if loaded)
        trading_loaded = False
        if hasattr(self, 'trading') and self.trading:
            trading_loaded = True
        self.state.update_background_trading(trading_loaded)
    
        # 10. Pentest module status (if loaded)
        pentest_loaded = False
        if hasattr(self, 'pentest') and self.pentest:
            pentest_loaded = True
        self.state.update_background_pentest(pentest_loaded)
    
        # 11. Bounty module status (if loaded)
        bounty_loaded = False
        if hasattr(self, 'bounty') and self.bounty:
            bounty_loaded = True
        self.state.update_background_bounty(bounty_loaded)
    
        # 12. Last successful darknet scan (if available)
        last_scan_time = None
        if hasattr(self, 'darknet') and self.darknet:
            try:
                status = self.darknet.get_status()
                last_scan_time = status.get('last_scan')
            except Exception:
                pass
        self.state.update_background_last_scan(last_scan_time)

    def print_banner(self):
        """SSH-friendly banner"""
        ai_indicator = " • AI READY" if self.ai_enabled else " • BASIC MODE"
        memory_stats = self.memory.get_knowledge_graph_stats() if self.memory else {'total_entities': 0}
        memory_indicator = f" • {memory_stats['total_entities']} entities" if self.memory else " • MEMORY OFF"
        osint_status = self.osint.get_status() if self.osint else {'feeds_monitored': 0}
        osint_indicator = f" • {osint_status['feeds_monitored']} feeds" if self.osint else " • OSINT OFF"
        pentest_indicator = " • PENTEST READY" if self.pentest else " • PENTEST OFF"
        trading_indicator = " • TRADING READY" if self.trading else " • TRADING OFF"
        bounty_indicator = " • BOUNTY READY" if self.bounty else " • BOUNTY OFF"
        orchestrator_indicator = " • ORCHESTRATOR READY" if self.orchestrator else " • ORCHESTRATOR OFF"
        scheduler_status = self.scheduler.get_scheduler_status()
        scheduler_indicator = " • SCHEDULER ON" if scheduler_status['running'] else " • SCHEDULER OFF"
        
        # Security status
        integrity = self.security.integrity_check()
        security_indicator = " • SECURE" if integrity['all_critical_files_present'] else " • COMPROMISED"
        
        # Project status
        project_scan = self.file_analyzer.scan_project(".")
        project_files = project_scan.get('file_count', 0) if 'file_count' in project_scan else 0
        project_indicator = f" • {project_files} files" if project_files > 0 else " • NO PROJECT"
        
        # Notification indicator
        notification_indicator = f" • {len(self.notification_queue)} updates" if self.notification_queue else ""
        # Personality engine status
        personality_indicator = " • PERSONALITY ACTIVE"
        
        banner = f"""
╔{'═' * (self.max_width-2)}╗
║ {'CIPH v1.0 - AUTONOMOUS AGENT ORCHESTRATION':^{self.max_width-4}} ║
║ {'Encrypted • Sovereign • Adaptive' + ai_indicator + security_indicator + project_indicator + memory_indicator + osint_indicator + pentest_indicator + trading_indicator + bounty_indicator + orchestrator_indicator + scheduler_indicator + notification_indicator + personality_indicator:^{self.max_width-4}} ║  
╚{'═' * (self.max_width-2)}╝
        """
        print(banner)
        
        # Show notifications if any
        if self.notification_queue:
            print(f"\n📢 Ciph: ‖ I have {len(self.notification_queue)} updates ‖")
            for note in self.notification_queue[:3]:
                print(f"   • {note['message']}")
            self.notification_queue = []  # Clear after showing

    def get_user_input(self):
        """Better input handling for SSH"""
        try:
            return input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            return "/exit"

    def graceful_shutdown(self):
        """Cleanly stop background services, compress episodic narrative, and save states before exit"""
        print("\nCiph: ‖ Performing graceful shutdown... ‖")
        try:
            # Record session end timestamp in vault
            if hasattr(self, 'vault') and self.vault:
                self.vault.record_session_end()

            # Compress session narrative into episodic timeline node
            if hasattr(self, 'conversation') and hasattr(self, 'smart_memory'):
                print("Ciph: 🧠 Compressing session dialogue into episodic milestone...")
                node = self.smart_memory.compress_session_narrative(self.conversation.history, self.ciph_router)
                if node:
                    print(f"Ciph: ✅ Milestone #{node.get('milestone_id', 1)} archived to vault timeline.")

            if hasattr(self, 'evolution_engine') and self.evolution_engine:
                if self.vault.get_config("CURIOSITY_DAEMON_ENABLED") == "1" and self.evolution_engine.is_daemon_alive():
                    print("Ciph: 🧠 Autonomous Curiosity Daemon remains ACTIVE 24/7 in VPS background (exploring while you are offline).")
                else:
                    self.evolution_engine.stop_daemon()
            if hasattr(self, 'scheduler') and self.scheduler:
                self.scheduler.stop_scheduler()
            if hasattr(self, 'sports') and self.sports:
                self.sports.stop_daemon()
            if hasattr(self, 'job_queue') and self.job_queue:
                self.job_queue.stop()
            if hasattr(self, 'tor_proxy') and self.tor_proxy:
                self.tor_proxy.disable_tor()
            if hasattr(self, 'orchestrator') and self.orchestrator:
                self.orchestrator.stop_all_workflows()
            print("Ciph: ‖ All background services stopped and states saved cleanly. ‖")
        except Exception as e:
            print(f"Ciph: ‖ Shutdown note: {e} ‖")

    def ensure_operator_identity(self) -> str:
        """First-run onboarding: ask the operator what callsign Ciph should address them by."""
        op_name = self.vault.get_operator_name() if getattr(self, 'vault', None) else None
        if op_name:
            return op_name
        if sys.stdin.isatty():
            print("\nCiph: ‖ Identity registry uninitialized. ‖")
            print("Ciph: ‖ Good day. What name or callsign shall I address you by? ‖\n")
            try:
                entered = input("Callsign > ").strip()
            except (EOFError, KeyboardInterrupt):
                entered = ""
            entered = entered or "Operator"
            try:
                pronoun = input("Pronouns (e.g. he/him, she/her, they/them) > ").strip()
            except (EOFError, KeyboardInterrupt):
                pronoun = ""
        else:
            entered, pronoun = "Operator", ""
        if getattr(self, 'vault', None):
            self.vault.set_operator_name(entered)
            if pronoun:
                self.vault.set_operator_pronoun(pronoun)
        if getattr(self, 'smart_memory', None):
            self.smart_memory.pin('operator', f"{entered} — sovereign creator and operator")
            self.smart_memory.pin('name', entered)
        if sys.stdin.isatty():
            print(f"\nCiph: ‖ Identity established: Operator '{entered}'. ‖\n")
        return entered

    def run_ssh_session(self):
        """Main SSH session loop with Proactive Terminal Greeting & Telemetry Digest"""
        operator_name = self.ensure_operator_identity()
        self.print_banner()
        
        # Proactive On-Login Intelligence Briefing
        try:
            session_info = self.vault.record_session_start()
            proactive_briefing = self.world_telemetry.generate_proactive_login_briefing(session_info, router=getattr(self, 'ciph_router', None))
            print(f"{proactive_briefing}\n")
        except Exception as e:
            print(f"‖ Notice: {e} ‖")
            
        print("‖ Type /help for commands, /exit to quit ‖")
        print("‖ /world-brief - Live Clearnet, CVE & Tor Darknet threat radar ‖")
        print("‖ /sync-reality - Force immediate live 24/7 intelligence sweep ‖")
        print("‖ /bounty-scan <target> - Execute Tor-routed passive surface audit ‖")
        print("‖ /war-room <plan> - Conduct 3-perspective adversarial stress test ‖\n")
        
        while True:
            try:
                user_input = self.get_user_input()
                
                if user_input in ['/exit', '/quit', '/q']:
                    self.graceful_shutdown()
                    break
                elif user_input == '/help':
                    print("\nCOGNITIVE EVOLUTION: /curiosity <on|off|status>, /mind-log, /mind-metrics, /council, /self-audit, /fetch <url>, /zeroize-mind")
                    print("AGENT ORCHESTRATION: /auto-mode, /start-workflow, /stop-workflow, /workflow-status, /stop-all-workflows")
                    print("REAL-WORLD & DARKNET INTEL: /world-brief, /sync-reality, /world-map, /darknet-deep <query>, /darknet-scan, /darknet-report")
                    print("BOUNTY RECON & TRIAGE: /bounty-scope <text/url>, /bounty-scan <target>, /bounty-report <target>, /bounty-list")
                    print("INTELLIGENCE & SENTRY: /what-changed <target>, /hit-list <target>, /chain-reaction <target>, /watchtower, /ghost-rating")
                    print("STRATEGY & WAR ROOM: /daily-brief, /war-room <plan>, /timeline")
                    print("PENTESTING: /port-scan, /web-scan, /security-audit, /network-discovery, /ssl-scan")
                    print("TRADING: /market-data, /arbitrage-scan, /market-trends, /wealth-strategy, /trading-signals, /portfolio-health")
                    print("FILES: /scan-project, /read-file <file>, /search-in-files <term>, /project-status")
                    print("SECURITY: /security-scan, /clean-footprints, /integrity-check, /backup-now, /emergency-wipe")
                    print("SCHEDULER: /schedule-start, /schedule-stop, /schedule-status, /schedule-update")
                    print("MODULES: /modules, /load <module>, /unload <module>")
                    print("MEMORY: /profile, /profile-clear, /memory-graph <query>, /memory-status, /retroactive-learn, /timeline, /search <query>, /tag <tag>")
                    print("CONVERSATION: /talk-test, /convo-summary")
                    print("CORE: /exit, /help, /status, /model-status, /test-deepseek, /reality-check, /ai, /setkey")
                    continue
                elif user_input == '':
                    continue
                
                self._bridge_command_output(user_input, self.generate_response(user_input))
                
            except Exception as e:
                print(f"\nCiph: ‖ Error: {e} ‖")

if __name__ == "__main__":
    ciph = CiphCore()
    ciph.run_ssh_session()
    