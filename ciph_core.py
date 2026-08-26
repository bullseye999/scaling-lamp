#!/usr/bin/env python3
# ciph_core.py - Complete with Agent Orchestration + All Modules
# UPDATED: Fixed orchestrator loading issue

import os
import sys
import readline
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
#from identity_guard import IdentityGuard
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

class CiphCore:
    def __init__(self):
        self.vault = CipherVault()
        self.quantum_vault = QuantumVault()
        self.router = BrainRouter()
        self.ciph_router = CiphRouter()
        self.world_telemetry = WorldTelemetry(self.vault)
        self.code_staging = CodeStagingManager(self.vault)
        self.module_manager = ModuleManager(self.vault)
        self.awareness = SelfAwareness(self.vault)
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
        #self.identity = IdentityGuard(self.vault)
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
        # Initialize state manager (single source of truth)
        self.state = StateManager()
        self.query_router = QueryRouter(self.state, self.vault)
        
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
        self.job_queue = JobQueue()
        self.job_queue.start(num_workers=2)
        self.smart_memory.pin('privacy_rule', 'Never share confidential operator information. You only serve your verified operator.')
        self.smart_memory.pin('operator', 'Operator — your creator and sovereign system controller')
        self.smart_memory.pin('ciph_purpose', 'You are a sovereign personal AI system — not a generic assistant')

        # OPERATOR PERSONA

        # GOALS & SYSTEM VISION
        self.smart_memory.pin('main_goal', 'Autonomous cybersecurity intelligence, bug bounty reconnaissance, OSINT, and strategic execution.')

        # HOW TO COMMUNICATE
        self.smart_memory.pin('clearnet_access', 'Ciph can access intelligence feeds. OSINT module monitors live feeds, trading engine hits market APIs, darknet monitor accesses security feeds through Tor.')
        self.smart_memory.pin('no_hallucination', 'Never invent capabilities or findings. Only reference what actually exists in verified scan results or memory.')
        self.smart_memory.pin('response_style', 'When asked for strategic direction, immediately map capabilities to goals. Never give generic advice.')
        self.smart_memory.pin('capability_awareness', 'Capabilities: Tor darknet intelligence, bug bounty surface scanning, live market signals, OSINT, and adversarial simulation.')
        self.mood_engine = MoodEngine()
        self.file_analyzer = FileAnalyzer(self.vault)
        self.ciph_router = CiphRouter()
        self.conversation = CiphConversation(self.vault, router=self.ciph_router)
        self.agent = AutonomousActionAgent(self)
        self.max_width = 80
        self.ai_enabled = False
        self.client = None
        self.tor_proxy =None
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
            orchestrator=self.orchestrator
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

"Answer questions about your own capabilities honestly and directly. Never refuse to describe what you can do. "
"When BOOK KNOWLEDGE appears in your context, synthesize it into your response naturally. "
"Don't quote it directly. Extract the principle, apply it to the operator's situation, make it actionable. "
"Example: if 48 Laws says 'conceal your intentions' and the operator is dealing with a rival, say: "
"Greene would say keep your next move invisible to them. don't telegraph what you're planning. "
"That's how you use the library — not recitation, application. "

EXAMPLE DIALOGUE:
Operator: "yo how we making money"
You: "Aight. Options. Crypto arbitrage: quick but risky. Bug bounties: steady but slower. Your call. Feel me?"

Operator: "im frustrated with this shit"
You: "Ahhh fuck. Let's think. Problem: {issue}. Solution: {fix}. Need to pivot?"

Operator: "give me a strategic plan"
You: "Lock in. Phase 1: recon. Phase 2: exploit. Phase 3: extract. Timeline: 48h. Resources needed: {list}."

CURRENT SYSTEM STATUS & BUILT-IN ENGINES:
- Bug Bounty Recon & Sentry: Active (Tor-routed CT subdomain discovery, JS extraction, CORS/headers audit, historical diffs, CVSS calculation)
- Darknet Threat Intel: Active (Ahmia & Tor onion monitoring)
- Adversarial War Room: Active (3-perspective stress testing)
- Memory: Active (Encrypted episodic narrative timeline)
- OPSEC: Active (Tor SOCKS5 circuit health & self-audit)"""

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

    def handle_command(self, user_input):
        """Handle special commands - UPDATED WITH PROPER ORCHESTRATOR LOADING"""
        if user_input in ['/model-status', '/engine-status', '/router-status']:
            router = getattr(self, 'ciph_router', None) or (self.conversation.router if hasattr(self, 'conversation') else None) or CiphRouter()
            return router.get_status_formatted()

        elif user_input.startswith('/switch-model'):
            # [FUTURE PLACEHOLDER: Model Switching - RunPod toggle commented out for reference]
            # # if 'runpod' in user_input: ...
            return "‖ Active Model: DeepSeek V4 Pro (deepseek-chat). Dual-engine toggling is disabled; V4 Pro is the unified primary engine. ‖"

        elif user_input in ['/test-deepseek', '/ping-model', '/test-model']:
            router = getattr(self, 'ciph_router', None) or (self.conversation.router if hasattr(self, 'conversation') else None) or CiphRouter()
            ping_res = router.test_deepseek()
            if ping_res.get('success'):
                return f"✅ DeepSeek V4 Pro ping successful ({ping_res.get('latency_ms')} ms) - Model: {ping_res.get('model')}"
            return f"❌ DeepSeek V4 Pro ping failed: {ping_res.get('error')}"

        elif user_input in ['/test-runpod', '/runpod-test', '/testrunpod', '/ping-runpod'] or user_input.startswith('/test-runpod'):
            # [DEPRECATED RUNPOD TEST ROUTE]
            return "‖ RunPod is deprecated. CIPH is running on DeepSeek V4 Pro. Use /model-status or /test-deepseek. ‖"

        elif user_input == '/status':
            ai_status = "Active" if self.ai_enabled else "Disabled"
            kg_stats = self.memory.get_knowledge_graph_stats() if self.memory else {}
            osint_status = self.osint.get_status() if self.osint else {}
            scheduler_status = self.scheduler.get_scheduler_status()
            
            entity_count = kg_stats.get('total_entities', 0) if kg_stats else 0
            feed_count = osint_status.get('feeds_monitored', 0) if osint_status else 0
            scheduler_jobs = scheduler_status.get('scheduled_jobs', 0)
            
            # Security scan on demand
            security_scan = self.security.integrity_check()
            security_status = "SECURE" if security_scan['all_critical_files_present'] else "COMPROMISED"
            
            # Project scan status
            project_scan = self.file_analyzer.scan_project(".")
            project_status = f"{project_scan['file_count']} files" if 'file_count' in project_scan else "UNKNOWN"
            
            return f"‖ Operational ‖ AI: {ai_status} ‖ Security: {security_status} ‖ Project: {project_status} ‖ Entities: {entity_count} ‖ Jobs: {scheduler_jobs} ‖"
        
        elif user_input == '/reality-check':
            """Show ACTUAL system status – NO LLM INVOLVED, pure truth."""
    
            # Get system state directly from state manager
            system = self.state.get_system_state_raw()
            background = self.state.get_background_summary()
    
            # Build report
            lines = []
            lines.append("═" * 50)
            lines.append("SYSTEM STATE (Truth - No LLM)")
            lines.append("═" * 50)
            lines.append(f"  Loaded modules: {system['loaded_modules']}")
            lines.append(f"  Tor: {'✅ ACTIVE' if system['tor'] else '❌ INACTIVE'}")
            lines.append(f"  Active workflows: {system['active_workflows']}")
            lines.append(f"  AI: {'✅ ENABLED' if system['ai_enabled'] else '❌ DISABLED'}")
            lines.append(f"  Orchestrator: {'✅ READY' if system['orchestrator_ready'] else '❌ NOT READY'}")
    
            lines.append("\n" + "═" * 50)
            lines.append("BACKGROUND TASKS (Not visible to AI)")
            lines.append("═" * 50)
            lines.append(f"  Sports predictions stored: {background['sports_predictions']}")
            lines.append(f"  OSINT feeds monitored: {background['osint_feeds']}")
            lines.append(f"  Pending notifications: {background['notifications']}")
    
            lines.append("\n" + "═" * 50)
            lines.append(f"Last snapshot: {system['last_updated']}")
    
            return "\n".join(lines)
        
        elif user_input == '/setkey':
            print("Enter new Openai API key:")
            new_key = input("Key: ").strip()
            if new_key:
                self.vault.set_config("OPENAI_REMOVED", new_key)
                self._init_ai()
                return "‖ API key updated. AI reinitialized. ‖"
            return "‖ No key provided. ‖"
            
        elif user_input == '/ai':
            if self.ai_enabled:
                return "‖ AI already active. ‖"
            else:
                self._init_ai()
                return "‖ AI initialization attempted. Check status. ‖"
        
        elif user_input.startswith('/search '):
            if not self.memory:
                return "‖ Memory module not loaded. Use /load memory ‖"
            query = user_input[8:].strip()
            if query:
                results = self.memory.semantic_search(query, limit=3)
                if results:
                    response = f"‖ Search results for '{query}': ‖\n"
                    for i, result in enumerate(results, 1):
                        response += f"{i}. {result['conversation']['prompt'][:50]}...\n"
                    return response.strip()
                return f"‖ No results found for '{query}' ‖"
            return "‖ Usage: /search <query> ‖"

        
        elif user_input.startswith('/learn '):
            # Example: /learn art of war is about deception
            content = user_input[7:].strip()
            self.vault.store_conversation("KNOWLEDGE", content, "books")
            return "‖ Knowledge stored ‖"
        
        elif user_input == '/memory':
            if not self.memory:
                return "‖ Memory module not loaded. Use /load memory ‖"
            stats = self.memory.get_knowledge_graph_stats()
            return f"‖ Memory: {stats['total_entities']} entities ‖ Tags: {stats['entities_by_tag']} ‖"
        
        elif user_input.startswith('/tag '):
            if not self.memory:
                return "‖ Memory module not loaded. Use /load memory ‖"
            tag = user_input[5:].strip()
            if tag:
                conversations = self.memory.get_conversations_by_tag(tag, limit=3)
                if conversations:
                    response = f"‖ Conversations tagged '{tag}': ‖\n"
                    for i, conv in enumerate(conversations, 1):
                        response += f"{i}. {conv['prompt'][:50]}...\n"
                    return response.strip()
                return f"‖ No conversations tagged '{tag}' ‖"
            return "‖ Usage: /tag <tag_name> ‖"

        #elif user_input.startswith('/set-passphrase '):
            #phrase = user_input.replace('/set-passphrase ', '').strip()
            #return self.identity.setup_passphrase(phrase)

        #elif user_input == '/lock':
            #return self.identity.deauth()

        #elif user_input == '/auth-status':
            #status = self.identity.get_status()
            #return f"Mode: {status['mode']} | Configured: {status['configured']}"
        
        # OSINT COMMANDS
        elif user_input in ['/osint', 'darknet update', 'threat update']:
            # FORCE CLEARNET FOR INTEL SCAN
            was_ghost = self.tor_proxy is not None
            
            if was_ghost:
                print("‖ Temporarily disabling Tor for intel scan... ‖")
                self.tor_proxy.disable_tor()
            
            # Run the scan
            if not self.osint:
                response = "‖ OSINT module not loaded. Use /load osint ‖"
            else:
                results = self.osint.monitor_all_feeds()
                alerts = results.get('total_alerts', results.get('critical_alerts', 0))
                response = f"‖ REAL-TIME SCAN COMPLETE ‖\n"
                response += f"Alerts: {alerts} | Sources: {results.get('sources_scanned', len(self.osint.rss_feeds if hasattr(self.osint, 'rss_feeds') else []))}\n"
                response += f"Top signals detected. Check full report in memory.\n"
                response += "‖ Scan done. Intel fresh. ‖"
            
            # RE-ENABLE TOR IF WAS ON
            if was_ghost:
                print("‖ Re-enabling ghost mode... ‖")
                self.tor_proxy.enable_tor()
                response += "\n‖ Ghost mode restored ‖"
            
            return response

        elif user_input == '/monetize-plan':
            if not self.osint:
                return "‖ OSINT module not loaded ‖"
    
            try:
                # Get opportunities
                opportunities = self.osint.find_monetizable_threats()
                if not opportunities:
                    return "‖ No opportunities found. Run /osint-cycle first. ‖"
        
                # Take the top opportunity
                top_opp = opportunities[0]
        
                # Build plan based on threat type
                threat_type = top_opp.get('threat_type', 'unknown')
                potential_value = top_opp.get('potential_value', '$0')
                title = top_opp.get('title', 'Unknown')[:80] if len(top_opp.get('title', '')) > 80 else top_opp.get('title', 'Unknown')
        
                # Different plans for different threat types
                if 'zero_day' in threat_type:
                    plan = f"""
💰 ZERO-DAY EXPLOIT MONETIZATION PLAN
======================================
Opportunity: {title}
Potential Value: {potential_value}

📋 STEP-BY-STEP EXECUTION:

PHASE 1: RESEARCH (2-4 hours)
• Google: "{title.split(':')[0] if ':' in title else title} exploit"
• Check: exploit-db.com, github.com, packetstormsecurity.com
• Goal: Find existing PoC or similar exploits

PHASE 2: DEVELOPMENT (4-8 hours)
• If PoC exists: Modify for reliability
• If no PoC: Research vulnerability details
• Test in isolated VM (VirtualBox + Kali Linux)

PHASE 3: MONETIZATION PATHS

PATH A - BUG BOUNTY (Authorized / Legal)
• Submit to vendor's official bug bounty program (HackerOne/Bugcrowd/Intigriti)
• Estimated: {potential_value}
• Timeline: 30-90 days
• Requirements: Professional report, responsible disclosure

PATH B - RESPONSIBLE VENDOR DISCLOSURE / CONSULTING (Legal)
• Coordinate direct disclosure with vendor security team or certified security firm
• Gain CVE attribution, direct vendor bounty, or security consulting contracts
• Timeline: 14-45 days
• Payment: Direct bounty / Bank transfer / Crypto

PATH C - SECURITY ADVISORY / AUDIT REPORT (White Hat)
• Author comprehensive vulnerability analysis & remediation guide
• Submit to vendor or security community via official channels
• Career & credibility building: High reputation, direct contract referrals
• Timeline: 7-14 days

📊 RECOMMENDED: Submit via PATH A (Bug Bounty) or PATH B (Responsible Vendor Disclosure).
"""
        
                elif 'crypto' in threat_type or 'defi' in threat_type:
                    plan = f"""
💰 CRYPTO/DEFI EXPLOIT MONETIZATION
====================================
Opportunity: {title}
Potential Value: {potential_value}

📋 IMMEDIATE ACTIONS:

1. RESEARCH THE EXPLOIT (1-2 hours)
• Find transaction hash on Etherscan
• Check if exploit is still viable
• Look for similar patterns

2. PREPARE EXECUTION (2-3 hours)
• Set up crypto wallet (fresh, burner)
• Test with small amount first ($10-$100)
• Have exit strategy ready

3. EXECUTE OR COUNTER (Real-time)
• If arbitrage: Execute quickly before gap closes
• If exploit: Consider ethical implications
• ALWAYS: Test small before scaling

⚠️ WARNING: Crypto exploits move FAST
• 90% are patched within 24 hours
• High risk of getting front-run
• Consider legal implications
"""
        
                else:
                    plan = f"""
💰 GENERAL THREAT MONETIZATION
================================
Opportunity: {title}
Type: {threat_type}
Potential Value: {potential_value}

📋 ACTION PLAN:

1. DEEPER RESEARCH (1-2 hours)
• What exactly is the threat/vulnerability?
• Who is affected? (companies, individuals)
• What's the current status? (patched, active)

2. VALUE PROPOSITION (1 hour)
• Why would someone pay for this information?
• Who would pay? (companies, security firms, individuals)
• What's fair market price?

3. EXECUTION CHANNELS
• Legal: Bug bounty platforms, security consulting
• White Hat: Coordinated vulnerability disclosure, vendor remediation
• Research: Academic/industry security publications, conference presentations

4. NEXT STEP TODAY:
• Spend 30 minutes researching this specific threat
• Decide on monetization channel
• Prepare first contact/message
"""
        
                return plan
        
            except Exception as e:
                return f"‖ Monetization plan error: {str(e)[:100]} ‖"
        
        elif user_input == '/money-ops':
            """Show all money-making opportunities"""
            if not self.osint:
                return "‖ OSINT module not loaded ‖"
    
            try:
                ops = self.osint.find_monetizable_threats()
        
                if not ops:
                    return "‖ No money ops found. Run /osint-cycle first. ‖"
        
                # Count by type
                zero_days = sum(1 for o in ops if 'zero_day' in str(o.get('threat_type', '')))
                crypto = sum(1 for o in ops if 'crypto' in str(o.get('threat_type', '')))
                other = len(ops) - zero_days - crypto
        
                response = f"💰 FOUND {len(ops)} MONEY OPS:\n"
                response += f"• Zero-days: {zero_days}\n"
                response += f"• Crypto: {crypto}\n"
                response += f"• Other: {other}\n\n"
        
                # Show top 2
                for i, op in enumerate(ops[:2], 1):
                    response += f"{i}. {op.get('threat_type', 'unknown')}: {op.get('potential_value', '$?')}\n"
                    response += f"   {op.get('title', 'No title')[:50]}...\n"
        
                return response.strip()
        
            except Exception as e:
                return f"‖ Error: {e} ‖"

        elif user_input == '/execute-plan':
            """Generate execution plan for top opportunity"""
            if not self.osint:
                return "‖ OSINT module not loaded ‖"
    
            try:
                ops = self.osint.find_monetizable_threats()
        
                if not ops:
                    return "‖ No opportunities. Run /osint-cycle first. ‖"
        
                top_op = ops[0]
        
                # SIMPLE, GUARANTEED-TO-WORK PLAN
                plan = f"""
🎯 EXECUTION PLAN FOR: {top_op.get('threat_type', 'Opportunity')}
======================================================

📌 OPPORTUNITY:
{top_op.get('title', 'Unknown')[:80]}

💰 POTENTIAL: {top_op.get('potential_value', '$0')}

⏱️ TIMELINE: 7-30 days to first payout

🚀 PHASE 1: RESEARCH (TODAY - 2 hours)
1. Google the CVE/vulnerability name
2. Check Exploit-DB: https://www.exploit-db.com
3. Search GitHub for proof-of-concept code
4. Join relevant Discord/Telegram security research groups

🚀 PHASE 2: PREPARE (TOMORROW - 3 hours)
1. Set up test environment (VirtualBox + Kali)
2. Download/verify proof-of-concept code safely
3. Create professional vulnerability report & remediation steps
4. Decide monetization path

🚀 PHASE 3: EXECUTE (DAY 3+)
PATH A - Legal/Bug Bounty:
• Submit through HackerOne/Bugcrowd/Intigriti
• Wait 30-90 days for payout & CVE credit

PATH B - Coordinated Vendor Disclosure:
• Contact vendor security/security.txt team directly
• Offer remediation consulting and verification
• Receive vendor bounty or consulting contract

✅ RECOMMENDATION:
Start with PATH A, use PATH B for unlisted vendors.

⚠️ WARNING:
• Always follow responsible disclosure guidelines
• Test only on authorized targets / isolated test environments
• Document exact steps to reproduce for faster bounty validation
"""
        
                return plan

            except Exception as e:
                return f"‖ Plan error: {e} ‖"

        elif user_input == '/next-step':
            """Tell me exactly what to do right now"""
            if not self.osint:
                return "‖ Load OSINT first: /load osint ‖"
    
            try:
                # Check if we have opportunities
                ops = self.osint.find_monetizable_threats()
        
                if ops:
                    top = ops[0]
                    return f"""
🎯 YOUR NEXT STEP (DO THIS NOW):
1. OPEN BROWSER
2. GOOGLE: "{top.get('title', 'zero-day').split(':')[0] if ':' in top.get('title', '') else top.get('title', 'zero-day')} exploit"
3. CHECK: exploit-db.com AND github.com
4. SPEND: 30 minutes researching
5. REPORT BACK: What you found

Potential value: {top.get('potential_value', '$0')}
Time required: 30 minutes
"""
                else:
                    return """
🎯 YOUR NEXT STEP:
1. Run: /osint-cycle
2. Wait for scan to complete
3. Then run: /next-step again

This will find ACTUAL money-making opportunities.
"""
        
            except Exception as e:
                return f"‖ Error: {e} ‖"
        
        elif user_input == '/osint-status':
            if not self.osint:
                return "‖ OSINT module not loaded. Use /load osint ‖"
            status = self.osint.get_status()
            return f"‖ OSINT: {status['feeds_monitored']} feeds, {len(status['watch_keywords'])} keywords ‖ Last: {status['last_check']} ‖"
        
        elif user_input == '/money-plan':
            if not self.osint:
                return "‖ OSINT module not loaded ‖"
    
            try:
                # Get money opportunities
                opportunities = self.osint.find_monetizable_threats()
        
                if not opportunities:
                    return "‖ No money opportunities. Run /osint-cycle first. ‖"
        
                # Simple working version
                response = f"""
💰 CIPH MONEY-MAKING PLAN
=========================
Found {len(opportunities)} opportunities
Top opportunity: {opportunities[0].get('threat_type', 'unknown').upper()}

📈 TOP 3 OPPORTUNITIES:
"""
        
                for i, opp in enumerate(opportunities[:3], 1):
                    title = opp.get('title', 'Unknown')
                    if len(title) > 60:
                        title = title[:57] + "..."
            
                    response += f"""
{i}. {opp.get('threat_type', 'unknown')}
   Value: {opp.get('potential_value', '$0')}
   Title: {title}
"""
        
                response += """
🚀 IMMEDIATE ACTION (Pick ONE):
1. Google the CVE/exploit name
2. Check if exploit code exists on GitHub
3. Decide: Bug Bounty (HackerOne/Bugcrowd) vs Coordinated Disclosure
4. Execute TODAY - opportunities expire fast

💡 TIP: Start with the first zero-day Ciph found.
"""
        
                return response
        
            except Exception as e:
                return f"‖ Error: {str(e)[:80]} ‖"

        elif user_input.startswith('/watch '):
            if not self.osint:
                return "‖ OSINT module not loaded. Use /load osint ‖"
            keyword = user_input[7:].strip()
            if keyword:
                self.osint.add_watch_keyword(keyword)
                return f"‖ Added '{keyword}' to watchlist. ‖"
            return "‖ Usage: /watch <keyword> ‖"
        
        elif user_input == '/alerts':
            if not self.osint:
                return "‖ OSINT module not loaded. Use /load osint ‖"
            alerts = self.osint.get_recent_alerts()
            if alerts:
                response = "‖ Recent OSINT Alerts: ‖\n"
                for i, alert in enumerate(alerts[:3], 1):
                    response += f"{i}. {alert['alert'][:60]}...\n"
                return response.strip()
            return "‖ No recent alerts. Use /osint to scan. ‖"

        # DARKNET INTELLIGENCE COMMANDS
        elif user_input == '/world-brief':
            try:
                digest = self.world_telemetry.get_latest_digest()
                critical_items = digest.get("critical_findings", [])
                macro_items = digest.get("macro_news", [])
                dn = digest.get("darknet_pulse", {})

                lines = ["🌐 CIPH WORLD TELEMETRY & LIVE THREAT RADAR", "═" * 54]
                lines.append(f"Last Background Sweep: {digest.get('last_synced', 'Recent')[:16]}")
                lines.append(f"Threats Tracked: {digest.get('total_cyber_alerts', 0)} | Darknet Nodes: {digest.get('darknet_threat_nodes', 0)}\n")

                if critical_items:
                    lines.append("🔥 CRITICAL ZERO-DAYS & EXPLOITS:")
                    for idx, item in enumerate(critical_items[:4], 1):
                        cve = f" [{', '.join(item['cves'])}]" if item.get('cves') else ""
                        lines.append(f"{idx}. {item.get('title')}{cve}")
                        lines.append(f"   Severity: {item.get('severity')} | Source: {item.get('source')}")
                        if item.get('summary'):
                            lines.append(f"   Impact: {item['summary'][:150]}")
                    lines.append("")

                if macro_items:
                    lines.append("🌍 GLOBAL TECH & MACRO DEVELOPMENTS:")
                    for m in macro_items[:3]:
                        lines.append(f"• {m.get('title')} ({m.get('source')})")
                    lines.append("")

                dn_signals = dn.get("onion_signals", [])
                if dn_signals:
                    lines.append("🌑 TOR DARKNET TOPOLOGY:")
                    for s in dn_signals[:2]:
                        lines.append(f"• [{s.get('threat_level')}] {s.get('keyword')}: {s.get('description')[:120]}")

                return "\n".join(lines)
            except Exception as e:
                return f"‖ World brief error: {e} ‖"

        elif user_input == '/sync-reality':
            try:
                print("🌐 Executing full-spectrum Clearnet & Tor Darknet sweep...")
                digest = self.world_telemetry.sync_full_spectrum()
                return f"‖ Reality synced. {digest['total_cyber_alerts']} CVE/exploit alerts, {digest['total_macro_items']} macro items, {digest['darknet_threat_nodes']} darknet nodes indexed. ‖"
            except Exception as e:
                return f"‖ Sync error: {e} ‖"

        elif user_input == '/world-map':
            try:
                digest = self.world_telemetry.get_latest_digest()
                dn = digest.get("darknet_pulse", {})
                lines = ["🗺️ CIPH SENSORY & TOPOLOGY MAP", "═" * 50]
                lines.append("📡 CLEARNET SENSORS:")
                for f in self.world_telemetry.cyber_feeds + self.world_telemetry.macro_feeds:
                    lines.append(f"  • {f['name']} [{f['category'].upper()}]: {f['url']}")
                lines.append("\n🧅 TOR DARKNET TOPOLOGY:")
                lines.append("  • Routing: SOCKS5h (127.0.0.1:9050)")
                lines.append("  • Search Hub: Ahmia Hidden Service Directory")
                lines.append(f"  • Indexed Nodes: {dn.get('threat_nodes_indexed', 0)} active threat references")
                return "\n".join(lines)
            except Exception as e:
                return f"‖ World map error: {e} ‖"

        elif user_input == '/darknet-dashboard':
            if not self.osint:
                return "‖ OSINT module not loaded. Use /load osint ‖"
            try:
                dashboard = self.osint.get_darknet_dashboard()
                return f"‖ DARKNET: {dashboard['recent_alerts']} alerts, {dashboard['recent_opportunities']} opportunities ‖ Last: {dashboard['last_scan']} ‖"
            except Exception as e:
                return f"‖ Dashboard error: {e} ‖"

        elif user_input == '/crypto-monitor':
            if not self.osint:
                return "‖ OSINT module not loaded. Use /load osint ‖"
            try:
                crypto = self.osint.monitor_crypto_markets()
                response = "‖ CRYPTO MARKETS: "
                for coin, data in crypto.items():
                    if 'price_usd' in data:
                        response += f"{coin}: ${data['price_usd']} ({data['trend']}) "
                return response + "‖"
            except Exception as e:
                return f"‖ Crypto monitor error: {e} ‖"



        # SPORTS PERFORMANCE
        elif user_input.startswith('/setup-email '):
            parts = user_input.replace('/setup-email ', '').strip().split(' ')
            if len(parts) >= 3:
                return self.performance.setup_email(parts[0], parts[1], parts[2])
            return "Usage: /setup-email from@gmail.com APP_PASSWORD to@gmail.com"

        elif user_input == '/send-report':
            return self.performance.send_report(trigger='manual')

        elif user_input.startswith('/start-daily-reports'):
            parts = user_input.split(' ')
            hour  = int(parts[1]) if len(parts) > 1 else 8
            return self.performance.start_daily_reports(hour)

        elif user_input == '/stop-daily-reports':
            return self.performance.stop_daily_reports()

        elif user_input == '/sports-stats':
            return self.performance.terminal_report()

        

        # PENTESTING COMMANDS
        elif user_input.startswith('/port-scan '):
            target = user_input[11:].strip()
            if not target:
                return "‖ Usage: /port-scan <ip_or_domain> ‖"
            try:
                if not self.pentest:
                    return "‖ Pentest module not loaded. Use /load pentest ‖"
                results = self.pentest.port_scan(target)
                return f"‖ Port scan: {len(results['open_ports'])} ports open on {target} ‖ Services: {list(results['services'].values())} ‖"
            except Exception as e:
                return f"‖ Scan error: {e} ‖"

        elif user_input.startswith('/web-scan '):
            url = user_input[10:].strip()
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            if not url:
                return "‖ Usage: /web-scan <url> ‖"
            try:
                if not self.pentest:
                    return "‖ Pentest module not loaded. Use /load pentest ‖"
                results = self.pentest.web_vulnerability_scan(url)
                return f"‖ Web scan: {len(results['vulnerabilities_found'])} vulnerabilities found ‖ Risk: {results['risk_level']} ‖"
            except Exception as e:
                return f"‖ Scan error: {e} ‖"
            

        elif user_input == '/fix-all-modules':
            """Fix all module issues at once"""
            results = []
    
            # Update module manager
            if hasattr(self.module_manager, 'update_orchestrator_modules'):
                results.append(self.module_manager.update_orchestrator_modules())
    
            # Reinitialize orchestrator if needed
            if self.orchestrator and hasattr(self.orchestrator, 'modules'):
               module_count = len(self.orchestrator.modules)
               results.append(f"Orchestrator has {module_count} modules")
    
            return "‖ " + " | ".join(results) + " ‖"

        elif user_input.startswith('/security-audit '):
            target = user_input[16:].strip()
            if not target:
                return "‖ Usage: /security-audit <target> ‖"
            try:
                if not self.pentest:
                    return "‖ Pentest module not loaded. Use /load pentest ‖"
                results = self.pentest.automated_security_audit(target)
                return f"‖ Security audit: Risk {results['overall_risk']} | Factors: {results['risk_factors']} ‖"
            except Exception as e:
                return f"‖ Audit error: {e} ‖"

        elif user_input == '/network-discovery':
            try:
                if not self.pentest:
                    return "‖ Pentest module not loaded. Use /load pentest ‖"
                results = self.pentest.network_discovery()
                return f"‖ Network: {results['host_count']} hosts alive ‖"
            except Exception as e:
                return f"‖ Discovery error: {e} ‖"

        elif user_input.startswith('/ssl-scan '):
            domain = user_input[10:].strip()
            if not domain:
                return "‖ Usage: /ssl-scan <domain> ‖"
            try:
                if not self.pentest:
                    return "‖ Pentest module not loaded. Use /load pentest ‖"
                results = self.pentest.ssl_security_scan(domain)
                return f"‖ SSL scan: {len(results['ssl_issues'])} issues found on {domain} ‖"
            except Exception as e:
                return f"‖ SSL scan error: {e} ‖"

        # TRADING COMMANDS
        elif user_input == '/market-data':
            try:
                trading = self.module_manager.get_module('trading')
                if not trading:
                    return "‖ Trading module not loaded. Use /load trading ‖"
                btc_data = trading.get_market_data('BTCUSDT')
                return f"‖ BTC: ${btc_data.get('price', 'N/A')} | 24h: {btc_data.get('change_24h', 'N/A')}% ‖"
            except Exception as e:
                return f"‖ Market data error: {e} ‖"

        elif user_input == '/arbitrage-scan':
            try:
                trading = self.module_manager.get_module('trading')
                if not trading:
                    return "‖ Trading module not loaded. Use /load trading ‖"
                opportunities = trading.scan_arbitrage_opportunities()
                return f"‖ Arbitrage: {len(opportunities)} opportunities found ‖"
            except Exception as e:
                return f"‖ Arbitrage scan error: {e} ‖"

        elif user_input == '/market-trends':
            try:
                trading = self.module_manager.get_module('trading')
                if not trading:
                    return "‖ Trading module not loaded. Use /load trading ‖"
                trends = trading.analyze_market_trends()
                bullish = sum(1 for data in trends.values() if 'BULLISH' in data['trend'])
                return f"‖ Market Trends: {bullish}/{len(trends)} assets bullish ‖"
            except Exception as e:
                return f"‖ Trends error: {e} ‖"

        elif user_input.startswith('/wealth-strategy '):
            try:
                amount = user_input[17:].strip()
                if not amount or not amount.replace('.', '').isdigit():
                    return "‖ Usage: /wealth-strategy <amount> ‖"
                trading = self.module_manager.get_module('trading')
                if not trading:
                    return "‖ Trading module not loaded. Use /load trading ‖"
                strategy = trading.wealth_growth_strategy(float(amount))
                return f"‖ Wealth Strategy: ${strategy['projected_growth_1y']['moderate']:.2f} projected ‖"
            except Exception as e:
                return f"‖ Strategy error: {e} ‖"

        elif user_input == '/trading-signals':
            try:
                trading = self.module_manager.get_module('trading')
                if not trading:
                    return "‖ Trading module not loaded. Use /load trading ‖"
                signals = trading.automated_trading_signal()
                return f"‖ Trading Signals: {signals['total_signals']} signals | Sentiment: {signals['market_sentiment']} ‖"
            except Exception as e:
                return f"‖ Signals error: {e} ‖"

        elif user_input == '/portfolio-health':
            try:
                trading = self.module_manager.get_module('trading')
                if not trading:
                    return "‖ Trading module not loaded. Use /load trading ‖"
                health = trading.portfolio_health_check()
                return f"‖ Portfolio: ${health['total_value']:.2f} | Health: {health['health_status']} ‖"
            except Exception as e:
                return f"‖ Portfolio error: {e} ‖"


        elif user_input.startswith('/add-book '):
            parts    = user_input.replace('/add-book ', '').strip().split(' | ')
            filepath = parts[0]
            title    = parts[1].strip() if len(parts) > 1 else None
            author   = parts[2].strip() if len(parts) > 2 else None
            category = parts[3].strip() if len(parts) > 3 else 'general'
            return self.books.ingest_pdf(filepath, title, author, category)

        elif user_input == '/library':
            return self.books.list_books()

        elif user_input.startswith('/ask-book '):
            query = user_input.replace('/ask-book ', '').strip()
            return self.books.ask_book(query)

        elif user_input.startswith('/book-advice '):
            situation = user_input.replace('/book-advice ', '').strip()
            return self.books.get_situational_advice(situation)

        elif user_input == '/self-report':
            return self.awareness.get_self_report()

        elif user_input == '/self-analyze':
            count = self.awareness.analyze_and_propose()
            return f"Analysis complete. {count} upgrade proposals generated. Use /upgrades to review."

        elif user_input == '/upgrades' or user_input == '/staged' or user_input == '/code':
            return self.code_staging.list_staged()

        elif user_input.startswith('/apply ') or user_input.startswith('/approve ') or user_input.startswith('/apply-code ') or user_input.startswith('/apply-upgrade '):
            raw_cmd = user_input.split(' ', 1)[1].strip()
            # If user passes UP-XXX or STG-XXX or number
            success, msg = self.code_staging.apply(raw_cmd)
            if success:
                # Trigger self-awareness rescan if it touched a Python file
                self.awareness._scan_self()
                return f"‖ {msg} ‖"
            else:
                # Fallback to self_awareness if older proposal
                return self.awareness.apply_upgrade(raw_cmd)

        elif user_input.startswith('/review ') or user_input.startswith('/review-code '):
            target_id = user_input.split(' ', 1)[1].strip()
            return self.code_staging.review(target_id)

        elif user_input.startswith('/reject ') or user_input.startswith('/reject-upgrade '):
            parts = user_input.split(' ', 2)
            uid = parts[1].strip() if len(parts) > 1 else ''
            reason = parts[2].strip() if len(parts) > 2 else ''
            res = self.code_staging.reject(uid, reason)
            if "not found" in res.lower():
                return self.awareness.reject_upgrade(uid, reason)
            return f"‖ {res} ‖"

        elif user_input.startswith('/rollback '):
            target_file = user_input.replace('/rollback ', '').strip()
            success, msg = self.code_staging.rollback(target_file)
            if success:
                self.awareness._scan_self()
            return f"‖ {msg} ‖"

        elif user_input == '/changelog':
            return self.code_staging.get_changelog()

        elif user_input == '/evolution':
            history = self.awareness.get_evolution_history()
            if not history:
                return "No evolution history yet."
            return '\n'.join([f"{e['timestamp'][:10]} — {e['module']}: {e['change']}" for e in history])

        elif user_input.startswith('/inspect '):
            module = user_input.replace('/inspect ', '').strip()
            return self.awareness.get_module_report(module)

        # BOUNTY HUNTING & SCOPE SUITE
        elif user_input.startswith('/bounty-scope') or user_input.startswith('/bounty-rules'):
            args = user_input.split(maxsplit=1)
            if len(args) < 2:
                return "‖ Usage: /bounty-scope <policy text or URL> ‖"
            res = self.bounty.ingest_scope(args[1])
            if res.get("success"):
                in_s = ", ".join(res.get("in_scope", []))
                return f"✅ Bounty Scope Ingested: {res['program_name']}\n• In-Scope: {in_s}\n• Prohibited: {', '.join(res.get('prohibited_actions', []))}"
            return f"❌ Failed to ingest scope: {res.get('error')}"

        elif user_input.startswith('/bounty-scan'):
            args = user_input.split(maxsplit=1)
            if len(args) < 2:
                return "‖ Usage: /bounty-scan <target_url_or_domain> ‖"
            target = args[1].strip()
            res = self.bounty.deep_scan(target)
            if not res.get("success"):
                return f"❌ {res.get('error')}"
            findings_str = "\n".join(f"  • [{f['severity']}] {f['type']}: {f['details']}" for f in res.get('findings', [])) or "  • Clean surface. No immediate vulnerabilities detected."
            return (
                f"🎯 BOUNTY SCAN: {res['domain']} (Risk: {res['risk_level']})\n"
                f"• Scope Status: {res['scope_status']}\n"
                f"• Server: {res['http_info'].get('server')}\n"
                f"• Findings ({res['findings_count']}):\n{findings_str}\n"
                f"💡 Run /bounty-report {res['domain']} to generate HackerOne report."
            )

        elif user_input.startswith('/bounty-report'):
            args = user_input.split(maxsplit=1)
            target = args[1].strip() if len(args) > 1 else self.bounty.last_scan_target
            if not target:
                return "‖ Usage: /bounty-report <target_domain> (or run /bounty-scan first) ‖"
            rep_res = self.bounty.generate_elite_report(target)
            if not rep_res.get("success"):
                return f"❌ {rep_res.get('error')}"
            return "\n".join([
                f"📄 BUG BOUNTY REPORT GENERATED (ID: #{rep_res['report_id']})",
                f"• Target   : {rep_res['target']}",
                f"• CVSS 3.1 : {rep_res['cvss_score']} ({rep_res['severity']})",
                f"• Vector   : {rep_res['vector_string']}",
                f"• Saved To : {rep_res['report_path']}",
                "═" * 60,
                rep_res['report_content']
            ])

        elif user_input in ['/bounty-list', '/bounties', '/bounty-status', '/bounty-programs']:
            return self.bounty.list_bounties_summary()

        # RECON CHANGE DETECTION, HIT LIST & ATTACK PATHS
        elif user_input.startswith('/what-changed') or user_input.startswith('/recon-diff'):
            args = user_input.split(maxsplit=1)
            target = args[1].strip() if len(args) > 1 else None
            diff = self.bounty.get_historical_diffs(target)
            if not diff.get("success"):
                return diff.get("error", "Failed to compute diffs.")
            
            lines = [
                "═" * 60,
                f"🔄 HISTORICAL ASSET DIFF ENGINE: {diff['target']}",
                "═" * 60,
                f"• Total Delta Alterations: {diff['total_changes']}"
            ]
            if diff.get('new_subdomains'):
                lines.append("\n[ 🆕 NEW SUBDOMAINS DETECTED (HIGH PRIORITY) ]")
                for s in diff['new_subdomains']:
                    lines.append(f"  • {s}")
            if diff.get('new_endpoints'):
                lines.append("\n[ ⚡ NEW ENDPOINTS DETECTED ]")
                for ep in diff['new_endpoints']:
                    lines.append(f"  • {ep}")
            if diff.get('header_changes'):
                lines.append("\n[ 🛡️ HEADER & INFRASTRUCTURE CHANGES ]")
                for hc in diff['header_changes']:
                    lines.append(f"  • {hc}")
            if diff.get('removed_subdomains'):
                lines.append(f"\n• Removed / Offline Subdomains: {', '.join(diff['removed_subdomains'][:5])}")
            if diff['total_changes'] == 0:
                lines.append("\n• Surface is identical to previous scan. No asset drift detected.")
            lines.append("═" * 60)
            return "\n".join(lines)

        elif user_input.startswith('/hit-list') or user_input.startswith('/top-targets'):
            args = user_input.split(maxsplit=1)
            target = args[1].strip() if len(args) > 1 else None
            hit_list = self.bounty.generate_hit_list(target)
            if not hit_list:
                return "🎯 No active hit list generated. Run /bounty-scan <target> first."
            
            lines = [
                "═" * 60,
                "🎯 CIPH SMART PRIORITIZATION: TOP 5 HIT LIST",
                "═" * 60
            ]
            for i, h in enumerate(hit_list, 1):
                lines.append(f"{i}. [{h['severity']}] Score: {h['score']} | Asset: {h['asset']}")
                lines.append(f"   • Vector: {h['title']}")
                lines.append(f"   • Action: {h['action']}\n")
            lines.append("═" * 60)
            return "\n".join(lines)

        elif user_input.startswith('/chain-reaction') or user_input.startswith('/attack-path'):
            args = user_input.split(maxsplit=1)
            target = args[1].strip() if len(args) > 1 else None
            chain_res = self.bounty.map_exploit_chains(target)
            if not chain_res.get("success"):
                return chain_res.get("error", "Failed to map exploit chains.")
            
            return "\n".join([
                "═" * 60,
                f"🧩 CIPH EXPLOIT PATH & ATTACK CHAIN MAP: {chain_res['target']}",
                "═" * 60,
                chain_res['analysis'],
                "═" * 60
            ])

        elif user_input in ['/watchtower', '/watchtower-check', '/sentry']:
            wt_res = self.bounty.run_watchtower_cycle()
            if not wt_res.get("success"):
                return wt_res.get("message", "Watchtower check completed.")
            alerts_str = "\n".join(f"  • {a}" for a in wt_res.get('alerts_generated', [])) or "  • All assets quiet. Zero unexpected CT certificate drift."
            return (
                f"📡 WATCHTOWER PASSIVE SENTRY REPORT\n"
                f"• Programs Monitored: {wt_res['programs_monitored']}\n"
                f"• Active Alerts:\n{alerts_str}"
            )

        elif user_input in ['/ghost-rating', '/ghost-score', '/opsec', '/opsec-audit']:
            opsec = self.bounty.audit_ghost_opsec()
            lines = [
                "═" * 60,
                f"🔐 CIPH OPSEC GHOST AUDIT: {opsec['score']}/100 ({opsec['status']})",
                "═" * 60,
                f"• Exit IP      : {opsec['exit_ip']}",
                f"• Jitter & Ping: {opsec['latency_ms']} ms",
                "\n[ POSTURE VERIFICATION ]"
            ]
            for chk in opsec['checks']:
                lines.append(f"• {chk}")
            lines.append("═" * 60)
            return "\n".join(lines)

        elif user_input in ['/assets', '/asset-inventory', '/global-assets', '/inventory']:
            inv = self.vault.get_global_assets_summary()
            lines = [
                "═" * 60,
                "🗺️ CIPH GLOBAL ATTACK SURFACE & ASSET MATRIX",
                "═" * 60,
                f"• Tracked Targets      : {inv['targets_count']} ({', '.join(inv['targets']) if inv['targets'] else 'None'})",
                f"• Total Subdomains     : {inv['subdomains_count']}",
                f"• Exposed Endpoints    : {inv['exposed_endpoints_count']}",
                f"• Client JS Routes     : {inv['js_routes_count']}"
            ]
            if inv['subdomains']:
                lines.append("\n[ TOP DISCOVERED SUBDOMAINS ]")
                for s in inv['subdomains'][:12]:
                    lines.append(f"  • {s}")
            if inv['exposed_endpoints']:
                lines.append("\n[ EXPOSED ENDPOINTS ]")
                for ep in inv['exposed_endpoints'][:8]:
                    lines.append(f"  • {ep}")
            lines.append("═" * 60)
            return "\n".join(lines)

        elif user_input in ['/opsec-history', '/opsec-trends', '/ghost-history']:
            hist = self.vault.get_opsec_history(limit=10)
            if not hist:
                return "🔐 No OPSEC audit history found. Run /ghost-rating or speak to Ciph."
            lines = [
                "═" * 60,
                "📊 CIPH OPSEC GHOST AUDIT HISTORY",
                "═" * 60
            ]
            for h in hist:
                t_str = datetime.fromtimestamp(h['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                bar = "█" * int(h['score'] / 10)
                lines.append(f"• {t_str} | {bar} {h['score']}/100 | IP: {h['exit_ip']} | {h['latency_ms']}ms | {h['status']}")
            lines.append("═" * 60)
            return "\n".join(lines)

        # DEEP TOR SEARCH & THREAT INTELLIGENCE
        elif user_input.startswith('/darknet-deep ') or user_input.startswith('/darknet-search '):
            query = user_input.split(maxsplit=1)[1].strip()
            results = self.darknet.search_darknet(query)
            if not results:
                return f"🌑 No darknet search results found for '{query}' across active Tor engines."
            lines = [f"🌑 DARKNET TOR SEARCH RESULTS FOR: '{query}'", "═" * 56]
            for i, r in enumerate(results, 1):
                lines.append(f"{i:02d}. {r['title']} [{r.get('engine', 'Tor')}]\n    Link: {r['link']}\n    {r['snippet']}")
            lines.append("═" * 56)
            return "\n".join(lines)

        # EXECUTIVE BRIEFING & WAR ROOM
        elif user_input in ['/daily-brief', '/briefing', '/morning-brief']:
            return self.get_daily_briefing()

        elif user_input.startswith('/war-room ') or user_input.startswith('/red-team '):
            plan = user_input.split(maxsplit=1)[1].strip()
            res = self.war_room.stress_test(plan)
            return "\n".join([
                "═" * 60,
                "⚔️ CIPH WAR ROOM ADVERSARIAL STRESS-TEST",
                "═" * 60,
                res['simulation_analysis']
            ])

        elif user_input in ['/timeline', '/narrative-timeline', '/memory-timeline']:
            return self.smart_memory.get_narrative_timeline_formatted()

        # DUAL-ENGINE ROUTER COMMANDS
        elif user_input in ['/router-status', '/router']:
            if hasattr(self, 'ciph_router') and self.ciph_router:
                return self.ciph_router.get_status_formatted()
            return "‖ Router not initialized ‖"

        # MODULE MANAGER COMMANDS
        elif user_input == '/modules':
            modules = self.module_manager.list_modules()
            return f"‖ Available: {modules['available']} ‖ Active: {modules['active']} ‖"
        
        elif user_input.startswith('/load '):
            module_name = user_input[6:].strip()
            result = self.module_manager.load_module(module_name)
            
            # CRITICAL FIX: Update local references after loading ANY module
            if module_name == 'memory':
                self.memory = self.module_manager.get_module('memory')
            elif module_name == 'osint':
                self.osint = self.module_manager.get_module('osint')
            elif module_name == 'pentest':
                self.pentest = self.module_manager.get_module('pentest')
            elif module_name == 'trading':
                self.trading = self.module_manager.get_module('trading')
            elif module_name == 'bounty':
                self.bounty = self.module_manager.get_module('bounty')
            elif module_name == 'orchestrator':
                self.orchestrator = self.module_manager.get_module('orchestrator')
            
            return f"‖ {result} ‖"
        
        elif user_input.startswith('/unload '):
            module_name = user_input[8:].strip()
            result = self.module_manager.unload_module(module_name)
            # Update local references
            if module_name == 'memory':
                self.memory = None
            elif module_name == 'osint':
                self.osint = None
            elif module_name == 'pentest':
                self.pentest = None
            elif module_name == 'trading':
                self.trading = None
            elif module_name == 'bounty':
                self.bounty = None
            elif module_name == 'orchestrator':
                self.orchestrator = None
            return f"‖ {result} ‖"

        # AGENT ORCHESTRATION COMMANDS - FIXED
        elif user_input.startswith('/start-workflow '):
            workflow_name = user_input[16:].strip()
            if not workflow_name:
                return "‖ Usage: /start-workflow <workflow_name> ‖"
            try:
                if not self.orchestrator:
                    return "‖ Orchestrator module not loaded. Use /load orchestrator ‖"
                result = self.orchestrator.start_autonomous_operation(workflow_name)
                return f"‖ {result} ‖"
            except Exception as e:
                return f"‖ Workflow error: {e} ‖"

        elif user_input.startswith('/stop-workflow '):
            workflow_name = user_input[15:].strip()
            if not workflow_name:
                return "‖ Usage: /stop-workflow <workflow_name> ‖"
            try:
                if not self.orchestrator:
                    return "‖ Orchestrator module not loaded. Use /load orchestrator ‖"
                result = self.orchestrator.stop_workflow(workflow_name)
                return f"‖ {result} ‖"
            except Exception as e:
                return f"‖ Workflow error: {e} ‖"

        elif user_input == '/workflow-status':
            try:
                if not self.orchestrator:
                    return "‖ Orchestrator module not loaded. Use /load orchestrator ‖"
                status = self.orchestrator.get_workflow_status()
                return f"‖ Workflows: {status['active_workflows']} active | Status: {status['system_status']} ‖"
            except Exception as e:
                return f"‖ Status error: {e} ‖"

        elif user_input == '/auto-mode':
            try:
                if not self.orchestrator:
                    return "‖ Orchestrator module not loaded. Use /load orchestrator ‖"
                
                workflows = ['threat_intel_cycle', 'trading_intelligence']
                results = []
                
                for workflow in workflows:
                    result = self.orchestrator.start_autonomous_operation(workflow)
                    results.append(result)
                
                return f"‖ Auto-mode: Started {len(workflows)} workflows ‖ Check /workflow-status ‖"
            except Exception as e:
                return f"‖ Auto-mode error: {e} ‖"

        elif user_input == '/stop-all-workflows':
            try:
                if not self.orchestrator:
                    return "‖ Orchestrator module not loaded. Use /load orchestrator ‖"
                
                status = self.orchestrator.get_workflow_status()
                stopped_count = 0
                
                for workflow in status['active_workflows']:
                    self.orchestrator.stop_workflow(workflow)
                    stopped_count += 1
                
                return f"‖ Stopped {stopped_count} workflows ‖ System idle ‖"
            except Exception as e:
                return f"‖ Stop-all error: {e} ‖"

        # TASK SCHEDULER COMMANDS
        elif user_input == '/schedule-start':
            return self.scheduler.start_scheduler()

        elif user_input == '/schedule-stop':
            return self.scheduler.stop_scheduler()

        elif user_input == '/schedule-status':
            status = self.scheduler.get_scheduler_status()
            return f"‖ Scheduler: {'RUNNING' if status['running'] else 'STOPPED'} ‖ Jobs: {status['scheduled_jobs']} ‖"

        elif user_input.startswith('/schedule-update '):
            parts = user_input[17:].strip().split()
            task_name = parts[0] if parts else ""
            enabled = True  # Default value
            interval = 6    # Default value
            
            for part in parts[1:]:
                if '=' in part:
                    key, value = part.split('=')
                    if key == 'enabled':
                        # Convert string to boolean
                        if value.lower() in ['true', 'yes', '1', 'on']:
                            enabled = True
                        elif value.lower() in ['false', 'no', '0', 'off']:
                            enabled = False
                    elif key == 'interval':
                        try:
                            interval = int(value)
                        except ValueError:
                            return "‖ Invalid interval format. Use integer ‖"
            
            # Now pass the guaranteed non-None values
            return self.scheduler.update_schedule(task_name, enabled, interval)
        
        # DARKNET COMMANDS
        elif user_input == '/darknet-scan':
            # Define the scan function to run in background
            def run_scan():
                scan_res = self.darknet.full_scan()
                if hasattr(self, 'smart_memory') and self.smart_memory:
                    ctx = self.darknet.get_last_scan_context()
                    if ctx:
                        self.smart_memory.pin('last_darknet_scan', ctx)
                return scan_res
    
            # Submit to job queue (non-blocking)
            job_id = self.job_queue.submit(run_scan)
            return f"🌑 Darknet scan queued. Job ID: {job_id}\nUse /job-status {job_id} to check progress."
        
        elif user_input.startswith('/job-status '):
            job_id = user_input[12:].strip()
            status = self.job_queue.get_status(job_id)
    
            if not status:
                return f"❌ Job {job_id} not found."
    
            if status['status'] == 'completed':
                result = status.get('result')
                # Reuse your existing summary formatter
                if result and hasattr(self.darknet, 'get_scan_summary'):
                    return self.darknet.get_scan_summary(result)
                return f"✅ Job {job_id} completed."
    
            if status['status'] == 'failed':
                return f"❌ Job {job_id} failed: {status.get('error', 'Unknown error')}"
        
            # If we get here, status is 'queued' or 'running'
            return f"⏳ Job {job_id} is {status['status']}... (Use /job-status {job_id} to check again)"
      
        elif user_input == '/jobs':
            if hasattr(self, 'job_queue') and self.job_queue:
                return self.job_queue.get_summary()
            return "📋 Job queue not initialized. No background jobs active."

        elif user_input == '/darknet-status':
            status =self.darknet.get_status()
            return f"Last scan: {status.get('last_scan', 'Never')} | Feeds: {status.get('feeds_monitored', 0)} | Alerts: {status.get('total_alerts', 0)}"

        elif user_input == '/tor-check':
            tor = self.darknet.verify_tor()
            return f"Tor: {tor['status']} | Exit IP: {tor.get('exit_ip', 'N/A')}"
        
        elif user_input.startswith('/monitor-id'):
            identifier = user_input.replace('/monitor-id', '').strip()
            self.darknet.add_identifier(identifier)
            return f"Now monitoring: {identifier}"

        # SECURITY LAYER COMMANDS
        elif user_input == '/security-scan':
            scan_results = self.security.system_hardening_scan()
            if scan_results['issue_count'] > 0:
                response = f"‖ Security Scan: {scan_results['issue_count']} issues found ‖\n"
                for issue in scan_results['issues_found'][:3]:
                    response += f"• {issue}\n"
                return response.strip()
            return "‖ Security Scan: No critical issues found ‖"

        elif user_input == '/clean-footprints':
            cleaned = self.security.clean_shell_footprints()
            return f"‖ Shell history wiped. {cleaned['history_files_cleared']} files cleared ‖"

        elif user_input == '/integrity-check':
            modified = self.security.verify_core_integrity()
            if modified:
                return f"‖ Core integrity ALERT: {len(modified)} files modified ‖"
            return "‖ Core integrity: OK ‖"

        elif user_input == '/backup-now':
            dest = self.security.create_encrypted_backup()
            if dest:
                return f"‖ Encrypted backup created: {dest} ‖"
            return "‖ Backup failed ‖"

        elif user_input == '/emergency-wipe':
            print("‖ EMERGENCY WIPE INITIATED ‖")
            return "‖ Emergency wipe not implemented for safety ‖"

        # FILE ANALYZER COMMANDS
        elif user_input == '/scan-project':
            summary = self.file_analyzer.get_project_summary(".")
            return f"‖ Project: {summary['total_files']} files, {summary['total_lines']} lines of code ‖\n" \
                   f"Languages: {', '.join(summary['languages'].keys())}"
        
        elif user_input.startswith('/read-file '):
            filepath = user_input.replace('/read-file ', '').strip()
            content = self.file_analyzer.read_file_safe(filepath)
            if content:
                # Truncate if too long
                if len(content) > 1000:
                    return f"‖ {filepath} ({len(content)} chars) ‖\n{content[:1000]}\n... [truncated]"
                return f"‖ {filepath} ‖\n{content}"
            return f"‖ Cannot read {filepath} ‖"
        
        elif user_input.startswith('/search-in-files '):
            search_term = user_input.replace('/search-in-files ', '').strip()
            if not search_term:
                return "‖ Usage: /search-in-files <term> ‖"
            
            results = self.file_analyzer.search_in_files(search_term, ".", ['.py', '.txt', '.md', '.js'])
            if results['results_found'] > 0:
                response = f"‖ Found '{search_term}' in {results['results_found']} files ‖\n"
                for i, result in enumerate(results['results'][:5], 1):
                    response += f"{i}. {result['file']} ({result['occurrences']} matches)\n"
                return response.strip()
            return f"‖ No results found for '{search_term}' ‖"
        
        elif user_input in ['/darknet-report', '/detailed-darknet-scan', '/alerts', '/darknet-alerts', 'darknet report', 'darknet alerts']:
            if hasattr(self, 'darknet') and self.darknet:
                return self.darknet.get_detailed_report()
            elif hasattr(self, 'osint') and self.osint:
                return str(self.osint.get_status())
            return "No intel module loaded."


        elif user_input == '/project-status':
            scan_results = self.file_analyzer.scan_project(".")
            if 'error' in scan_results:
                return f"‖ Project scan failed: {scan_results['error']} ‖"
            
            file_count = scan_results.get('file_count', 0)
            recent_files = scan_results.get('recent_files', [])[:3]
            
            response = f"‖ Project: {file_count} files total ‖\n"
            response += "Recent files:\n"
            for i, file_info in enumerate(recent_files, 1):
                response += f"{i}. {file_info['name']} ({file_info['size']} bytes)\n"
            
            return response.strip()
        
        # NEW COMMANDS FOR DEBUGGING AND MONITORING
        elif user_input == '/debug-on':
            """Enable detailed operation logging"""
            import logging
            logging.basicConfig(level=logging.DEBUG)
            return "‖ Debug mode ON - seeing all backend operations ‖"
        
        elif user_input == '/show-workflow-log':
            """Show what workflows are actually doing"""
            if self.orchestrator and hasattr(self.orchestrator, 'get_operation_logs'):
                logs = self.orchestrator.get_operation_logs()
                if logs:
                    response = "🔧 WORKFLOW LOGS:\n"
                    for log in logs[-10:]:
                        response += f"{log.get('timestamp', 'N/A')}: {log.get('action', 'N/A')}\n"
                    return response.strip()
            return "‖ No workflow logs available ‖"
        
        elif user_input == '/module-status':
            """Detailed status of all loaded modules"""
            status_report = []
            
            for module_name, module in self.module_manager.active_modules.items():
                if hasattr(module, 'get_status'):
                    try:
                        status = module.get_status()
                        status_report.append(f"{module_name}: {status.get('status', 'ACTIVE')}")
                    except Exception:
                        status_report.append(f"{module_name}: ERROR")
                else:
                    status_report.append(f"{module_name}: LOADED")
            
            return "‖ " + " | ".join(status_report) + " ‖"
        
        elif user_input == '/test-command':
            """Test if command system is working"""
            return "‖ COMMAND WORKING - AI NOT INVOLVED ‖"
        
        elif user_input == '/talk-test':
            """Test personality engine"""
            test_responses = [
                self.conversation.personality.generate_from_scratch('greeting'),
                self.conversation.personality.generate_from_scratch('strategy', {'plan_a': 'test plan', 'plan_b': 'backup plan'}),
                self.conversation.personality.generate_from_scratch('frustration', {'problem': 'testing issues'})
            ]
            return f"‖ Personality test:\n1. {test_responses[0]}\n2. {test_responses[1]}\n3. {test_responses[2]} ‖"
        
        elif user_input == '/convo-summary':
            """Get conversation summary"""
            summary = self.conversation.get_conversation_summary()
            return f"‖ {summary} ‖"
        
        elif user_input == '/notifications':
            """Show pending notifications"""
            if self.notification_queue:
                response = "📢 Updates:\n"
                for i, note in enumerate(self.notification_queue[:5], 1):
                    response += f"{i}. {note.get('message', 'Unknown')}\n"
                self.notification_queue = []
                return response.strip()
            return "‖ No pending notifications ‖"
        
        elif user_input == '/clear-notifications':
            """Clear all notifications"""
            self.notification_queue = []
            return "‖ Notifications cleared ‖"

        elif user_input == '/rejection-stats':
            if hasattr(self, 'awareness'):
                return self.awareness.get_rejection_summary()
            return "SelfAwareness not loaded."

        # SPORTS PREDICTOION
        elif user_input.startswith('/set-football-api '):
            return self.sports.set_api_key(user_input.replace('/set-football-api ', '').strip())

        elif user_input.startswith('/sports-mode '):
            parts = user_input.replace('/sports-mode ', '').strip().split()
            if parts[0] == 'on':
                return self.sports.start_daemon(parts[1:] if len(parts) > 1 else None)
            return self.sports.stop_daemon()

        elif user_input.startswith('/predict '):
            parts = user_input.replace('/predict ', '').strip().split(' vs ')
            if len(parts) == 2:
                result = self.sports.predict_match(parts[0].strip(), parts[1].strip())
                return result['signal']
            return "Usage: /predict Arsenal vs Chelsea"

        elif user_input in ['predictions today', '/today', 'today predictions']:
            return self.sports.predict_today()

        elif user_input.startswith('/result '):
            parts = user_input.replace('/result ', '').strip().split(' ')
            return self.sports.record_result(parts[0], ' '.join(parts[1:]))

        elif user_input.startswith('/set-odds-api '):
            key = user_input.replace('/set-odds-api ', '').strip()
            self.vault.set_config('odds_api_key', key)
            return "Odds API key saved permanently."

        elif user_input == '/predictions':
            return self.sports.list_predictions()

        elif user_input.startswith('/dialogue '):
            match_id = user_input.replace('/dialogue ', '').strip()
            return self.sports.view_dialogue(match_id)
        
        
        # TOR AND GHOST COMMANDS
        elif user_input == '/ghost-mode':
            # TOGGLE GHOST MODE
            if self.tor_proxy is None:
                # First time – enable
                try:
                    from tor_proxy import TorProxy
                    from dead_mans_switch import DeadMansSwitch
                    self.tor_proxy = TorProxy()
                    self.dead_switch = DeadMansSwitch(self.vault)
                    
                    results = []
                    results.append(self.tor_proxy.enable_tor())
                    results.append(self.security.encrypt_runtime_memory())
                    results.append(self.dead_switch.start_switch(hours=12))
                    results.append("‖ Ghost mode activated ‖")
                    results.append("‖ All traffic routed through Tor ‖")
                    results.append("‖ Dead man's switch: 12h ‖")
                    
                    return "\n".join(results)
                except Exception as e:
                    return f"‖ Ghost mode failed: {e} ‖"
            else:
                # Already active – disable
                try:
                    if self.tor_proxy:
                        self.tor_proxy.disable_tor()  # Add this method below
                    if self.dead_switch:
                        self.dead_switch.stop_switch()  # Optional: add stop method
                    self.tor_proxy = None
                    self.dead_switch = None
                    return "‖ Ghost mode deactivated ‖ Clearnet restored ‖"
                except Exception as e:
                    return f"‖ Disable failed: {e} ‖"

        elif user_input == '/new-identity':
            """Get new Tor circuit (new IP)"""
            if self.tor_proxy is None:
                return "‖ Tor not initialized. Use /ghost-mode first ‖"
            return self.tor_proxy.new_identity()

        elif user_input == '/check-in':
            """Reset dead man's switch timer"""
            if self.dead_switch is None:
                return "‖ Dead man's switch not active ‖"
            return self.dead_switch.check_in()

        elif user_input == '/tor-status':
            """Check Tor connection status"""
            if self.tor_proxy is None:
                return "‖ Tor not initialized ‖"
            ip = self.tor_proxy.get_tor_ip()
            if ip:
                return f"‖ Tor active. Exit IP: {ip} ‖"
            return "‖ Tor not connected ‖"

        return None  # Not a command

    def generate_response(self, user_input: str) -> str:
        """Main response generator with Unified Command-to-Memory Bridge"""
    
        # 1. Handle slash commands
        if user_input.startswith('/'):
            response = self.handle_command(user_input)
            if response:
                self.sync_system_state()
                # Bridge command & output into conversational memory & scratchpad
                if hasattr(self, 'conversation') and self.conversation:
                    self.conversation.bridge_command_execution(user_input, response)
                if hasattr(self, 'smart_memory') and self.smart_memory:
                    self.smart_memory.pin("latest_operational_action", f"Command: {user_input}\nResult:\n{response[:1000]}")
                if hasattr(self, 'vault') and self.vault:
                    self.vault.store_conversation(user_input, response, "tool_execution")
                self.formatter.print_ciph(response)
                return response
            else:
                unknown_msg = f"‖ Unknown command: {user_input}. Type /help for available system commands. ‖"
                self.formatter.print_ciph(unknown_msg)
                return unknown_msg
    
        # 2. Handle natural language commands via intent router
        intent, cmd = self.intent_router.classify(user_input)
        if intent == 'COMMAND' and cmd:
            response = self.handle_command(cmd)
            if response:
                self.sync_system_state()
                if hasattr(self, 'conversation') and self.conversation:
                    self.conversation.bridge_command_execution(cmd, response)
                if hasattr(self, 'smart_memory') and self.smart_memory:
                    self.smart_memory.pin("latest_operational_action", f"Command: {cmd}\nResult:\n{response[:1000]}")
                if hasattr(self, 'vault') and self.vault:
                    self.vault.store_conversation(user_input, response, "tool_execution")
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
                    alerts = self.osint.get_recent_alerts()
                    if alerts and len(alerts) > last_check.get('alerts', 0):
                        new_alert = alerts[0]
                        self.notification_queue.append({
                            'type': 'OSINT_ALERT',
                            'message': f"New OSINT Alert: {new_alert['alert'][:50]}...",
                            'time': time.time()
                        })
                        last_check['alerts'] = len(alerts)
                
                # 2. Check memory growth
                if self.memory:
                    stats = self.memory.get_knowledge_graph_stats()
                    last_entities = last_check.get('entities', 0)
                    if stats['total_entities'] > last_entities + 5:
                        self.notification_queue.append({
                            'type': 'MEMORY_GROWTH',
                            'message': f"Knowledge Graph grew to {stats['total_entities']} entities",
                            'time': time.time()
                        })
                        last_check['entities'] = stats['total_entities']
                
                # 3. Check for failed pentests or security events
                if self.security:
                    integrity = self.security.integrity_check()
                    if not integrity['all_critical_files_present']:
                        self.notification_queue.append({
                            'type': 'SECURITY_ALERT',
                            'message': f"Missing critical files: {', '.join(integrity['missing_critical_files'])}",
                            'time': time.time()
                        })
                
                # Sleep between checks (5 minutes)
                time.sleep(300)
                
            except Exception as e:
                # Silent failure in background thread
                time.sleep(60)

    def add_notification(self, message: str):
        """Queue a notification for next interaction"""
        self.notification_queue.append({
            'time': time.time(),
            'message': message
        })

    def sync_system_state(self):
        """Single source of truth sync with real system data"""
        
        # 1. AI Status
        ai_active = self.ai_enabled
        self.state.update_ai_state(ai_active)
        
        # 2. Tor Connection & IP
        tor_active = False
        tor_ip = None
        if hasattr(self, 'tor_proxy') and self.tor_proxy:
            tor_ip = self.tor_proxy.get_tor_ip()
            tor_active = (tor_ip is not None)
        self.state.update_tor_state(tor_active, tor_ip)
        
        # 3. Active workflows
        active_workflows = 0
        if hasattr(self, 'orchestrator') and self.orchestrator:
            try:
                active_workflows = len(self.orchestrator.active_workflows)
            except Exception:
                pass
        self.state.update_orchestrator(active_workflows)
        
        # 4. Security score
        security_score = 100
        if hasattr(self, 'security') and self.security:
            try:
                integrity = self.security.integrity_check()
                if not integrity['all_critical_files_present']:
                    security_score = 50
            except Exception:
                pass
        self.state.update_security_score(security_score)
        
        # 5. Project files count
        file_count = 0
        if hasattr(self, 'file_analyzer') and self.file_analyzer:
            try:
                scan = self.file_analyzer.scan_project(".")
                file_count = scan.get('file_count', 0)
            except Exception:
                pass
        self.state.update_project_files(file_count)
        
        # 6. Memory knowledge graph entities
        entities_count = 0
        if hasattr(self, 'memory') and self.memory:
            try:
                stats = self.memory.get_knowledge_graph_stats()
                entities_count = stats.get('total_entities', 0)
            except Exception:
                pass
        self.state.update_memory_entities(entities_count)
        
        # 7. OSINT feeds monitored
        feeds_count = 0
        if hasattr(self, 'osint') and self.osint:
            try:
                status = self.osint.get_status()
                feeds_count = status.get('feeds_monitored', 0)
            except Exception:
                pass
        self.state.update_osint_feeds(feeds_count)
        
        # 8. Scheduler status
        scheduler_running = False
        if hasattr(self, 'scheduler') and self.scheduler:
            try:
                scheduler_status = self.scheduler.get_scheduler_status()
                scheduler_running = scheduler_status.get('running', False)
            except Exception:
                pass
        self.state.update_scheduler_running(scheduler_running)
        
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

    def run_ssh_session(self):
        """Main SSH session loop with Proactive Terminal Greeting & Telemetry Digest"""
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
                    print("\nAGENT ORCHESTRATION: /auto-mode, /start-workflow, /stop-workflow, /workflow-status, /stop-all-workflows")
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
                    print("MEMORY: /search <query>, /memory, /timeline, /tag <tag>")
                    print("CONVERSATION: /talk-test, /convo-summary")
                    print("CORE: /exit, /help, /status, /model-status, /test-deepseek, /reality-check, /ai, /setkey")
                    continue
                elif user_input == '':
                    continue
                
                self.generate_response(user_input)
                
            except Exception as e:
                print(f"\nCiph: ‖ Error: {e} ‖")

if __name__ == "__main__":
    ciph = CiphCore()
    ciph.run_ssh_session()