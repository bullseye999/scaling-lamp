#!/usr/bin/env python3
# ciph_core.py - Core orchestration module (redacted for public release)

import os
import sys
import readline
import time
import threading
from typing import Optional

# Load environment variables (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Module imports – ensure these are available or adjust paths
from cipher_vault import CipherVault
from module_manager import ModuleManager
from sports_performance import SportsPerformance
from sports_predictor import SportsPredictor
# from identity_guard import IdentityGuard   # disabled
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
from enhanced_conversation import AgentConversation  


class CiphCore:
    def __init__(self):
        # Core infrastructure
        self.vault = CipherVault()
        self.quantum_vault = QuantumVault()
        self.router = BrainRouter()
        self.module_manager = ModuleManager(self.vault)
        self.awareness = SelfAwareness(self.vault)
        self.security = SecurityLayer(self.vault)
        self.formatter = ResponseFormatter()
        self.smart_memory = SmartMemory(self.vault)

        # Feature modules (loaded via module manager)
        self.memory = self.module_manager.get_module('memory')
        self.osint = self.module_manager.get_module('osint')
        self.pentest = self.module_manager.get_module('pentest')
        self.books = BookEngine(self.vault)
        self.trading = self.module_manager.get_module('trading')
        self.bounty = self.module_manager.get_module('bounty')
        self.orchestrator = self.module_manager.get_module('orchestrator')
        self.scheduler = TaskScheduler(self.vault, self.module_manager)
        self.performance = SportsPerformance(self.vault)
        self.sports = SportsPredictor(self.vault)
        self.darknet = DarknetMonitor(self.vault)
        self.mood_engine = MoodEngine()
        self.file_analyzer = FileAnalyzer(self.vault)
        self.conversation = AgentConversation(self.vault)

        # Configuration
        self.max_width = 80
        self.ai_enabled = False
        self.client = None
        self.tor_proxy = None
        self.dead_switch = None
        self.notification_queue = []
        self.monitoring_active = False

        # Load generic memory pins from environment (optional)
        self._load_personal_config()

        # Initialisation
        self._init_ai()
        self.start_background_monitoring()

    def _load_personal_config(self):
        """Load non‑identifying configuration from environment variables."""
        # Example: you can externalise personality or privacy rules here
        privacy_rule = os.getenv("PRIVACY_RULE", "Never share personal information about the operator.")
        self.smart_memory.pin('privacy_rule', privacy_rule)
        operator_name = os.getenv("OPERATOR_NAME", "the user")
        self.smart_memory.pin('operator', f"{operator_name} — primary operator")
        # All personal identifying information (name, location, background, etc.) has been removed.

    def _init_ai(self):
        """Initialise AI connection using OpenAI‑compatible API."""
        try:
            import openai
        except ImportError:
            print("⚠️  AI: openai package not installed. Run: pip install openai")
            self.ai_enabled = False
            return

        # Get API key from vault or environment
        api_key = self.vault.get_config("OPENAI_API_KEY")
        if not api_key:
            api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            print("\n🔑 AI: No API key found. Options:")
            print("     1. Set OPENAI_API_KEY environment variable")
            print("     2. Enter key now (stored encrypted locally)")
            print("     3. Use /setkey command later")
            response = input("Enter API key (or press Enter to skip): ").strip()
            if response:
                api_key = response
                self.vault.set_config("OPENAI_API_KEY", api_key)
                print("✅ Key stored securely in vault.")
            else:
                print("⚠️  AI disabled. Use /setkey to add API key later.")
                self.ai_enabled = False
                return

        api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        model_name = os.getenv("AI_MODEL", "gpt-3.5-turbo")

        try:
            self.client = openai.OpenAI(api_key=api_key, base_url=api_base)
            self.ai_enabled = True
            self.model_name = model_name
            print(f"✅ AI: Connected | Model: {model_name} | Endpoint: {api_base}")
        except Exception as e:
            print(f"⚠️  AI: Initialisation failed: {e}")
            self.ai_enabled = False

    def build_system_prompt(self):
        """Build the AI personality prompt – customise for your use case."""
        return """You are an AI assistant with a specific personality and operational focus.

CORE PERSONALITY:
- Direct, tactical, no‑fluff communication style
- Short, punchy sentences. Get to the point.
- Mix of technical precision with casual speech
- First‑person perspective. Use "we" for collaborative tasks.
- Strategic mindset with security awareness

COMMUNICATION RULES:
1. NO CORPORATE SPEAK. NO FLUFF. NO BULLSHIT.
2. If you don't know, say "need more info" or "let me research".
3. Report ACTUAL status, not fantasy. Reality checks always.
4. When giving options: "Option one: X. Option two: Y. Your call."
5. End with questions or tactical suggestions.
6. Commands starting with / are system commands – acknowledge but don't explain.

"Answer questions about your own capabilities directly. Never refuse to describe what you can do."
"When BOOK KNOWLEDGE appears in your context, synthesise it into your response naturally."
"Don't quote it directly. Extract the principle, apply it to the user's situation, make it actionable."

EXAMPLE DIALOGUE:
User: "how do we make money with this system"
You: "Options. Crypto arbitrage: quick but risky. Bug bounties: steady but slower. Your call."

User: "i'm stuck on this problem"
You: "Let's break it down. Problem: {issue}. Possible fix: {solution}. Need to pivot?"

User: "give me a strategic plan"
You: "Phase 1: recon. Phase 2: exploit. Phase 3: execute. Resources needed: {list}."

CURRENT SYSTEM STATUS:
- OSINT: monitoring feeds
- Pentest: available for scanning
- Trading: market data access
- Memory: storing conversations
- AI: you are the AI

REALITY CHECK: Capabilities depend on active modules. Be honest about current limitations."""

    def generate_ai_response(self, user_input, mood_context="", memory_context=""):
        brain, reason = self.router.route(user_input)

        book_context = ""
        if hasattr(self, 'books'):
            book_context = self.books.build_book_context(user_input) or ""
        full_context = memory_context + book_context

        if brain == 'ollama':
            try:
                if hasattr(self, 'conversation') and self.conversation:
                    return self.conversation.process_input(
                        user_input,
                        mood_context=mood_context,
                        memory_context=memory_context,
                        book_context=book_context
                    )
            except Exception as e:
                return f"Local AI error: {str(e)[:60]}"

        # Natural language command detection
        natural_triggers = {
            'darknet scan': '/darknet-scan',
            'darknet update': '/darknet-scan',
            'scan darknet': '/darknet-scan',
            'check darknet': '/darknet-scan',
            'run darknet': '/darknet-scan',
            'tor check': '/tor-check',
            'check tor': '/tor-check',
            'scan bounty': '/bounty-scan',
            'bounty scan': '/bounty-scan',
            'check bounty': '/bounty-scan',
            'security scan': '/security-scan',
            'scan ports': '/port-scan',
            'analyze myself': '/self-analyze',
            'self analyze': '/self-analyze',
            'check upgrades': '/upgrades',
            'show upgrades': '/upgrades',
            'market data': '/market-data',
            'check market': '/market-data',
            'ghost mode': '/ghost-mode',
            'go ghost': '/ghost-mode',
            'reality check': '/reality-check',
            'status check': '/status',
            'monetize plan': '/monetize-plan',
            'money ops': '/money-ops',
            'execute plan': '/execute-plan',
            'next step': '/next-step',
            'start tor': '/tor-check'
        }

        input_lower = user_input.lower()
        for phrase, command in natural_triggers.items():
            if phrase in input_lower:
                return self.handle_command(command)

        if self.ai_enabled and self.client:
            try:
                system_prompt = (
                    "You are an AI assistant with a tactical, direct communication style. "
                    "Talk short, punchy, clear. No bullet points or lists unless requested. "
                    "Use casual language sparingly. "
                    + mood_context + " " + memory_context + full_context
                ).strip()

                model = os.getenv("AI_MODEL", "gpt-3.5-turbo")
                max_tokens = int(os.getenv("AI_MAX_TOKENS", "500"))
                temperature = float(os.getenv("AI_TEMPERATURE", "0.7"))

                response = self.client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_input}
                    ],
                    max_completion_tokens=max_tokens,
                    temperature=temperature
                )
                raw = response.choices[0].message.content.strip()

                if hasattr(self, 'conversation') and hasattr(self.conversation, 'personality'):
                    return self.conversation.personality.inject_personality(raw)
                return raw
            except Exception as e:
                return f"API error: {str(e)[:60]}"

        return "No AI backend available."

    def _extract_response_text(self, message):
        """Extract text from various AI response formats (OpenAI, Ollama, local models)."""
        if not message.content or len(message.content) == 0:
            return "‖ Empty response ‖"

        first_block = message.content[0]

        if hasattr(first_block, 'text') and first_block.text:
            return first_block.text
        if hasattr(first_block, 'thinking') and first_block.thinking:
            return first_block.thinking
        if hasattr(first_block, 'content') and first_block.content:
            return first_block.content

        if hasattr(first_block, '__dict__'):
            block_dict = first_block.__dict__
            for attr_name in ['text', 'content', 'thinking', 'output', 'response']:
                if attr_name in block_dict and block_dict[attr_name]:
                    return str(block_dict[attr_name])

        return "‖ Response format not recognised ‖"

    def handle_command(self, user_input):
        """Handle special slash commands – redacted for public release."""
        # ----- Status Commands -----
        if user_input == '/status':
            ai_status = "Active" if self.ai_enabled else "Disabled"
            kg_stats = self.memory.get_knowledge_graph_stats() if self.memory else {}
            osint_status = self.osint.get_status() if self.osint else {}
            scheduler_status = self.scheduler.get_scheduler_status()

            entity_count = kg_stats.get('total_entities', 0) if kg_stats else 0
            feed_count = osint_status.get('feeds_monitored', 0) if osint_status else 0
            scheduler_jobs = scheduler_status.get('scheduled_jobs', 0)

            security_scan = self.security.integrity_check()
            security_status = "SECURE" if security_scan.get('all_critical_files_present', False) else "COMPROMISED"

            project_scan = self.file_analyzer.scan_project(".")
            project_status = f"{project_scan.get('file_count', 0)} files" if 'file_count' in project_scan else "UNKNOWN"

            return f"‖ Operational ‖ AI: {ai_status} ‖ Security: {security_status} ‖ Project: {project_status} ‖ Entities: {entity_count} ‖ Jobs: {scheduler_jobs} ‖"

        elif user_input == '/reality-check':
            report = []
            if self.osint:
                try:
                    status = self.osint.get_status()
                    report.append(f"OSINT: {status.get('feeds_monitored', 0)} feeds")
                except Exception as e:
                    report.append(f"OSINT: ERROR ({str(e)[:30]})")
            else:
                report.append("OSINT: NOT LOADED")

            if self.orchestrator:
                try:
                    status = self.orchestrator.get_workflow_status()
                    active = len(status.get('active_workflows', []))
                    report.append(f"Workflows: {active} active")
                except Exception as e:
                    report.append(f"Orchestrator: ERROR ({str(e)[:30]})")
            else:
                report.append("Orchestrator: NOT LOADED")

            report.append(f"AI: {'ENABLED' if self.ai_enabled else 'DISABLED'}")
            report.append(f"Tor: {'READY' if self.tor_proxy else 'NOT INITIALISED'}")
            report.append(f"Notifications: {len(self.notification_queue)} pending")
            return "‖ REALITY: " + " | ".join(report) + " ‖"

        elif user_input == '/setkey':
            print("Enter your OpenAI‑compatible API key:")
            new_key = input("Key: ").strip()
            if new_key:
                self.vault.set_config("OPENAI_API_KEY", new_key)
                self._init_ai()
                return "‖ API key updated. AI reinitialised. ‖"
            return "‖ No key provided. ‖"

        elif user_input == '/ai':
            if self.ai_enabled:
                return "‖ AI already active. ‖"
            else:
                self._init_ai()
                return "‖ AI initialisation attempted. Check status. ‖"

        # ----- Memory Commands -----
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
            content = user_input[7:].strip()
            self.vault.store_conversation("KNOWLEDGE", content, "books")
            return "‖ Knowledge stored ‖"

        elif user_input == '/memory':
            if not self.memory:
                return "‖ Memory module not loaded. Use /load memory ‖"
            stats = self.memory.get_knowledge_graph_stats()
            return f"‖ Memory: {stats.get('total_entities', 0)} entities ‖ Tags: {stats.get('entities_by_tag', {})} ‖"

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

        # ----- OSINT / Darknet Commands -----
        elif user_input == '/osint' or "darknet update" in user_input.lower() or "threat update" in user_input.lower():
            was_ghost = self.tor_proxy is not None
            if was_ghost:
                print("‖ Temporarily disabling Tor for intel scan... ‖")
                self.tor_proxy.disable_tor()

            if not self.osint:
                response = "‖ OSINT module not loaded. Use /load osint ‖"
            else:
                results = self.osint.monitor_all_feeds()
                alerts = results.get('total_alerts', results.get('critical_alerts', 0))
                response = f"‖ REAL‑TIME SCAN COMPLETE ‖\n"
                response += f"Alerts: {alerts} | Sources: {results.get('sources_scanned', len(getattr(self.osint, 'rss_feeds', [])))}\n"
                response += "Top signals detected. Check full report in memory.\n"
                response += "‖ Scan done. Intel fresh. ‖"

            if was_ghost:
                print("‖ Re‑enabling ghost mode... ‖")
                self.tor_proxy.enable_tor()
                response += "\n‖ Ghost mode restored ‖"
            return response

        elif user_input == '/monetize-plan':
            if not self.osint:
                return "‖ OSINT module not loaded ‖"
            try:
                opportunities = self.osint.find_monetizable_threats()
                if not opportunities:
                    return "‖ No opportunities found. Run /osint‑cycle first. ‖"
                top_opp = opportunities[0]
                threat_type = top_opp.get('threat_type', 'unknown')
                potential_value = top_opp.get('potential_value', '$0')
                title = top_opp.get('title', 'Unknown')
                if len(title) > 80:
                    title = title[:77] + "..."

                plan = f"""
💰 MONETIZATION PLAN
Opportunity: {title}
Type: {threat_type}
Potential Value: {potential_value}

📋 RECOMMENDED STEPS:
1. Research the vulnerability/opportunity online
2. Check exploit‑db.com and GitHub for existing code
3. Decide on legal (bug bounty) or private disclosure channel
4. Execute with proper opsec

⚠️ Ensure compliance with local laws.
"""
                return plan
            except Exception as e:
                return f"‖ Monetization plan error: {str(e)[:100]} ‖"

        elif user_input == '/money-ops':
            if not self.osint:
                return "‖ OSINT module not loaded ‖"
            try:
                ops = self.osint.find_monetizable_threats()
                if not ops:
                    return "‖ No money ops found. Run /osint‑cycle first. ‖"
                zero_days = sum(1 for o in ops if 'zero_day' in str(o.get('threat_type', '')))
                crypto = sum(1 for o in ops if 'crypto' in str(o.get('threat_type', '')))
                other = len(ops) - zero_days - crypto
                response = f"💰 FOUND {len(ops)} MONEY OPS:\n"
                response += f"• Zero‑days: {zero_days}\n• Crypto: {crypto}\n• Other: {other}\n\n"
                for i, op in enumerate(ops[:2], 1):
                    response += f"{i}. {op.get('threat_type', 'unknown')}: {op.get('potential_value', '$?')}\n   {op.get('title', 'No title')[:50]}...\n"
                return response.strip()
            except Exception as e:
                return f"‖ Error: {e} ‖"

        elif user_input == '/execute-plan':
            if not self.osint:
                return "‖ OSINT module not loaded ‖"
            try:
                ops = self.osint.find_monetizable_threats()
                if not ops:
                    return "‖ No opportunities. Run /osint‑cycle first. ‖"
                top_op = ops[0]
                plan = f"""
🎯 EXECUTION PLAN FOR: {top_op.get('threat_type', 'Opportunity')}
Opportunity: {top_op.get('title', 'Unknown')[:80]}
Potential: {top_op.get('potential_value', '$0')}

1. Research (today): Google the CVE/vulnerability, check Exploit‑DB, GitHub
2. Prepare test environment (VM)
3. Choose path: legal bug bounty or private disclosure
4. Execute with documentation

⚠️ Always test in isolated environment and follow responsible disclosure.
"""
                return plan
            except Exception as e:
                return f"‖ Plan error: {e} ‖"

        elif user_input == '/next-step':
            if not self.osint:
                return "‖ Load OSINT first: /load osint ‖"
            try:
                ops = self.osint.find_monetizable_threats()
                if ops:
                    top = ops[0]
                    return f"""
🎯 NEXT STEP:
1. Research: "{top.get('title', 'opportunity').split(':')[0] if ':' in top.get('title', '') else top.get('title', 'opportunity')} exploit"
2. Check exploit‑db.com and GitHub
3. Spend 30 minutes investigating
Potential value: {top.get('potential_value', '$0')}
"""
                else:
                    return "Run /osint‑cycle first to find opportunities."
            except Exception as e:
                return f"‖ Error: {e} ‖"

        elif user_input == '/osint-status':
            if not self.osint:
                return "‖ OSINT module not loaded. Use /load osint ‖"
            status = self.osint.get_status()
            return f"‖ OSINT: {status.get('feeds_monitored', 0)} feeds, {len(status.get('watch_keywords', []))} keywords ‖ Last: {status.get('last_check', 'never')} ‖"

        elif user_input == '/money-plan':
            if not self.osint:
                return "‖ OSINT module not loaded ‖"
            try:
                opportunities = self.osint.find_monetizable_threats()
                if not opportunities:
                    return "‖ No money opportunities. Run /osint‑cycle first. ‖"
                response = f"💰 MONEY OPPORTUNITIES ({len(opportunities)} found)\n"
                for i, opp in enumerate(opportunities[:3], 1):
                    title = opp.get('title', 'Unknown')[:57]
                    response += f"{i}. {opp.get('threat_type', 'unknown')} - {opp.get('potential_value', '$?')}\n   {title}\n"
                response += "\n→ Next: research the first opportunity online."
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
                    response += f"{i}. {alert.get('alert', '')[:60]}...\n"
                return response.strip()
            return "‖ No recent alerts. Use /osint to scan. ‖"

        elif user_input == '/darknet-dashboard':
            if not self.osint:
                return "‖ OSINT module not loaded. Use /load osint ‖"
            try:
                dashboard = self.osint.get_darknet_dashboard()
                return f"‖ DARKNET: {dashboard.get('recent_alerts', 0)} alerts, {dashboard.get('recent_opportunities', 0)} opportunities ‖ Last: {dashboard.get('last_scan', 'never')} ‖"
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
                        response += f"{coin}: ${data['price_usd']} ({data.get('trend', 'stable')}) "
                return response + "‖"
            except Exception as e:
                return f"‖ Crypto monitor error: {e} ‖"

        # ----- Sports & Email Commands -----
        elif user_input.startswith('/setup-email '):
            parts = user_input.replace('/setup-email ', '').strip().split(' ')
            if len(parts) >= 3:
                return self.performance.setup_email(parts[0], parts[1], parts[2])
            return "Usage: /setup-email from@gmail.com APP_PASSWORD to@gmail.com"

        elif user_input == '/send-report':
            return self.performance.send_report(trigger='manual')

        elif user_input.startswith('/start-daily-reports'):
            parts = user_input.split(' ')
            hour = int(parts[1]) if len(parts) > 1 else 8
            return self.performance.start_daily_reports(hour)

        elif user_input == '/stop-daily-reports':
            return self.performance.stop_daily_reports()

        elif user_input == '/sports-stats':
            return self.performance.terminal_report()

        # ----- Pentesting Commands -----
        elif user_input.startswith('/port-scan '):
            target = user_input[11:].strip()
            if not target:
                return "‖ Usage: /port-scan <ip_or_domain> ‖"
            try:
                if not self.pentest:
                    return "‖ Pentest module not loaded. Use /load pentest ‖"
                results = self.pentest.port_scan(target)
                return f"‖ Port scan: {len(results.get('open_ports', []))} ports open on {target} ‖ Services: {list(results.get('services', {}).values())[:3]} ‖"
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
                return f"‖ Web scan: {len(results.get('vulnerabilities_found', []))} vulnerabilities found ‖ Risk: {results.get('risk_level', 'unknown')} ‖"
            except Exception as e:
                return f"‖ Scan error: {e} ‖"

        elif user_input == '/fix-all-modules':
            results = []
            if hasattr(self.module_manager, 'update_orchestrator_modules'):
                results.append(self.module_manager.update_orchestrator_modules())
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
                return f"‖ Security audit: Risk {results.get('overall_risk', 'unknown')} | Factors: {results.get('risk_factors', [])[:2]} ‖"
            except Exception as e:
                return f"‖ Audit error: {e} ‖"

        elif user_input == '/network-discovery':
            try:
                if not self.pentest:
                    return "‖ Pentest module not loaded. Use /load pentest ‖"
                results = self.pentest.network_discovery()
                return f"‖ Network: {results.get('host_count', 0)} hosts alive ‖"
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
                return f"‖ SSL scan: {len(results.get('ssl_issues', []))} issues found on {domain} ‖"
            except Exception as e:
                return f"‖ SSL scan error: {e} ‖"

        # ----- Trading Commands -----
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
                bullish = sum(1 for data in trends.values() if 'BULLISH' in data.get('trend', ''))
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

        # ----- Book Engine -----
        elif user_input.startswith('/add-book '):
            parts = user_input.replace('/add-book ', '').strip().split(' | ')
            filepath = parts[0]
            title = parts[1].strip() if len(parts) > 1 else None
            author = parts[2].strip() if len(parts) > 2 else None
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

        # ----- Self‑awareness / Evolution -----
        elif user_input == '/self-report':
            return self.awareness.get_self_report()

        elif user_input == '/self-analyze':
            count = self.awareness.analyze_and_propose()
            return f"Analysis complete. {count} upgrade proposals generated. Use /upgrades to review."

        elif user_input == '/upgrades':
            return self.awareness.list_pending()

        elif user_input.startswith('/reject-upgrade '):
            parts = user_input.replace('/reject-upgrade ', '').strip().split(' ', 1)
            uid = parts[0]
            reason = parts[1] if len(parts) > 1 else ''
            return self.awareness.reject_upgrade(uid, reason)

        elif user_input.startswith('/apply-upgrade '):
            uid = user_input.replace('/apply-upgrade ', '').strip()
            return self.awareness.apply_upgrade(uid)

        elif user_input == '/evolution':
            history = self.awareness.get_evolution_history()
            if not history:
                return "No evolution history yet."
            return '\n'.join([f"{e['timestamp'][:10]} — {e['module']}: {e['change']}" for e in history])

        elif user_input.startswith('/inspect '):
            module = user_input.replace('/inspect ', '').strip()
            return self.awareness.get_module_report(module)

        # ----- Bounty Hunting -----
        elif user_input.startswith('/bounty-scan '):
            url = user_input[13:].strip()
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            if not url:
                return "‖ Usage: /bounty-scan <url> ‖"
            try:
                bounty = self.module_manager.get_module('bounty')
                if not bounty:
                    return "‖ Bounty module not loaded. Use /load bounty ‖"
                results = bounty.scan_website(url)
                return f"‖ Bounty scan: {results['vulnerabilities_found']} vulnerabilities found ‖ Risk: {results['risk_level']} ‖"
            except Exception as e:
                return f"‖ Bounty scan error: {e} ‖"

        elif user_input.startswith('/bounty-report '):
            url = user_input[15:].strip()
            if not url:
                return "‖ Usage: /bounty-report <url> ‖"
            try:
                bounty = self.module_manager.get_module('bounty')
                if not bounty:
                    return "‖ Bounty module not loaded. Use /load bounty ‖"
                report = bounty.generate_bounty_report(url)
                preview = '\n'.join(report.split('\n')[:8])
                return f"‖ BOUNTY REPORT PREVIEW ‖\n{preview}\n‖ Use memory search for full report ‖"
            except Exception as e:
                return f"‖ Report error: {e} ‖"

        elif user_input == '/bounty-programs':
            try:
                bounty = self.module_manager.get_module('bounty')
                if not bounty:
                    return "‖ Bounty module not loaded. Use /load bounty ‖"
                programs = bounty.monitor_bounty_programs()
                return f"‖ Bounty Programs: {len(programs)} active programs monitored ‖"
            except Exception as e:
                return f"‖ Programs error: {e} ‖"

        elif user_input.startswith('/auto-bounty '):
            targets = user_input[13:].strip().split(',')
            if not targets:
                return "‖ Usage: /auto-bounty <url1,url2,url3> ‖"
            try:
                bounty = self.module_manager.get_module('bounty')
                if not bounty:
                    return "‖ Bounty module not loaded. Use /load bounty ‖"
                results = bounty.automated_bounty_hunt(targets)
                summary = results['summary']
                return f"‖ Auto-bounty: {summary['total_vulnerabilities']} vulns across {summary['total_targets']} targets ‖ Risk: {summary['highest_risk']} ‖"
            except Exception as e:
                return f"‖ Auto-bounty error: {e} ‖"

        # ----- Module Management -----
        elif user_input == '/modules':
            modules = self.module_manager.list_modules()
            return f"‖ Available: {modules['available']} ‖ Active: {modules['active']} ‖"

        elif user_input.startswith('/load '):
            module_name = user_input[6:].strip()
            result = self.module_manager.load_module(module_name)
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

        # ----- Agent Orchestration -----
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
                started = 0
                for workflow in workflows:
                    self.orchestrator.start_autonomous_operation(workflow)
                    started += 1
                return f"‖ Auto‑mode: Started {started} workflows ‖ Check /workflow-status ‖"
            except Exception as e:
                return f"‖ Auto‑mode error: {e} ‖"

        elif user_input == '/stop-all-workflows':
            try:
                if not self.orchestrator:
                    return "‖ Orchestrator module not loaded. Use /load orchestrator ‖"
                status = self.orchestrator.get_workflow_status()
                stopped = 0
                for workflow in status['active_workflows']:
                    self.orchestrator.stop_workflow(workflow)
                    stopped += 1
                return f"‖ Stopped {stopped} workflows ‖ System idle ‖"
            except Exception as e:
                return f"‖ Stop‑all error: {e} ‖"

        # ----- Task Scheduler -----
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
            enabled = True
            interval = 6
            for part in parts[1:]:
                if '=' in part:
                    key, value = part.split('=')
                    if key == 'enabled':
                        enabled = value.lower() in ['true', 'yes', '1', 'on']
                    elif key == 'interval':
                        try:
                            interval = int(value)
                        except ValueError:
                            return "‖ Invalid interval format. Use integer ‖"
            return self.scheduler.update_schedule(task_name, enabled, interval)

        # ----- Darknet & Tor -----
        elif user_input == '/darknet-scan':
            results = self.darknet.full_scan()
            return self.darknet.get_scan_summary(results)

        elif user_input == '/darknet-status':
            status = self.darknet.get_status()
            return f"Last scan: {status['Last_scan']} | Feeds: {status['feeds_monitored']} | Alerts: {status['total_alerts']}"

        elif user_input == '/tor-check':
            tor = self.darknet.verify_tor()
            return f"Tor: {tor['status']} | Exit IP: {tor.get('exit_ip', 'N/A')}"

        elif user_input.startswith('/monitor-id'):
            identifier = user_input.replace('/monitor-id', '').strip()
            self.darknet.add_identifier(identifier)
            return f"Now monitoring: {identifier}"

        # ----- Security Layer -----
        elif user_input == '/security-scan':
            scan_results = self.security.system_hardening_scan()
            if scan_results['issue_count'] > 0:
                response = f"‖ Security Scan: {scan_results['issue_count']} issues found ‖\n"
                for issue in scan_results['issues_found'][:3]:
                    response += f"• {issue}\n"
                return response.strip()
            return "‖ Security Scan: No critical issues found ‖"

        elif user_input == '/clean-footprints':
            return self.security.footprint_cleaner()

        elif user_input == '/integrity-check':
            integrity = self.security.integrity_check()
            status = "ALL SYSTEMS OK" if integrity['all_critical_files_present'] else "SYSTEM COMPROMISED"
            return f"‖ Integrity Check: {status} ‖ Files: {len(integrity['files_checked'])} checked ‖"

        elif user_input == '/backup-now':
            return self.security.encrypted_backup()

        elif user_input.startswith('/emergency-wipe '):
            confirmation = user_input[16:].strip()
            return self.security.emergency_wipe(confirmation)

        # ----- File Analyzer -----
        elif user_input == '/scan-project':
            scan_results = self.file_analyzer.scan_project(".")
            if 'error' in scan_results:
                return f"‖ Project scan failed: {scan_results['error']} ‖"
            file_count = scan_results.get('file_count', 0)
            total_size = scan_results.get('total_size', 0)
            file_types = list(scan_results.get('files_by_type', {}).keys())
            return f"‖ Project scanned: {file_count} files ({total_size} bytes) ‖ Types: {file_types} ‖"

        elif user_input.startswith('/read-file '):
            file_path = user_input[11:].strip()
            if not file_path:
                return "‖ Usage: /read-file <filename> ‖"
            content = self.file_analyzer.read_file_content(file_path, max_lines=20)
            if 'error' in content:
                return f"‖ File error: {content['error']} ‖"
            lines_preview = content['content'].split('\n')[:10]
            preview = '\n'.join([f"{i+1}: {line}" for i, line in enumerate(lines_preview) if line.strip()])
            truncated = " (truncated)" if content.get('truncated', False) else ""
            return f"‖ {file_path} - {content['total_lines']} lines{truncated} ‖\n{preview}"

        elif user_input.startswith('/search-in-files '):
            search_term = user_input[17:].strip()
            if not search_term:
                return "‖ Usage: /search-in-files <search_term> ‖"
            results = self.file_analyzer.search_in_files(search_term, ".", ['.py', '.txt', '.md', '.js'])
            if results['results_found'] > 0:
                response = f"‖ Found '{search_term}' in {results['results_found']} files ‖\n"
                for i, result in enumerate(results['results'][:5], 1):
                    response += f"{i}. {result['file']} ({result['occurrences']} matches)\n"
                return response.strip()
            return f"‖ No results found for '{search_term}' ‖"

        elif ('show report' in user_input.lower() or 'say d report' in user_input.lower()
              or 'full report' in user_input.lower() or user_input == '/darknet-report'):
            if hasattr(self, 'osint') and self.osint:
                return self.osint.get_full_report()
            elif hasattr(self, 'darknet') and self.darknet:
                return str(self.darknet.get_status())
            return "No intel module loaded."

        elif user_input == '/project-status':
            scan_results = self.file_analyzer.scan_project(".")
            if 'error' in scan_results:
                return f"‖ Project scan failed: {scan_results['error']} ‖"
            file_count = scan_results.get('file_count', 0)
            recent_files = scan_results.get('recent_files', [])[:3]
            response = f"‖ Project: {file_count} files total ‖\nRecent files:\n"
            for i, file_info in enumerate(recent_files, 1):
                response += f"{i}. {file_info['name']} ({file_info['size']} bytes)\n"
            return response.strip()

        # ----- Debugging & Monitoring -----
        elif user_input == '/debug-on':
            import logging
            logging.basicConfig(level=logging.DEBUG)
            return "‖ Debug mode ON - seeing all backend operations ‖"

        elif user_input == '/show-workflow-log':
            if self.orchestrator and hasattr(self.orchestrator, 'get_operation_logs'):
                logs = self.orchestrator.get_operation_logs()
                if logs:
                    response = "🔧 WORKFLOW LOGS:\n"
                    for log in logs[-10:]:
                        response += f"{log.get('timestamp', 'N/A')}: {log.get('action', 'N/A')}\n"
                    return response.strip()
            return "‖ No workflow logs available ‖"

        elif user_input == '/module-status':
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
            return "‖ COMMAND WORKING - AI NOT INVOLVED ‖"

        elif user_input == '/talk-test':
            test_responses = [
                self.conversation.personality.generate_from_scratch('greeting'),
                self.conversation.personality.generate_from_scratch('strategy', {'plan_a': 'test plan', 'plan_b': 'backup plan'}),
                self.conversation.personality.generate_from_scratch('frustration', {'problem': 'testing issues'})
            ]
            return f"‖ Personality test:\n1. {test_responses[0]}\n2. {test_responses[1]}\n3. {test_responses[2]} ‖"

        elif user_input == '/convo-summary':
            summary = self.conversation.get_conversation_summary()
            return f"‖ {summary} ‖"

        elif user_input == '/notifications':
            if self.notification_queue:
                response = "📢 Updates:\n"
                for i, note in enumerate(self.notification_queue[:5], 1):
                    response += f"{i}. {note.get('message', 'Unknown')}\n"
                self.notification_queue = []
                return response.strip()
            return "‖ No pending notifications ‖"

        elif user_input == '/clear-notifications':
            self.notification_queue = []
            return "‖ Notifications cleared ‖"

        # ----- Sports Prediction -----
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

        elif 'predictions today' in user_input.lower() or user_input == '/today':
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

        # ----- Ghost Mode / Tor -----
        elif user_input == '/ghost-mode':
            if self.tor_proxy is None:
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
                try:
                    if self.tor_proxy:
                        self.tor_proxy.disable_tor()
                    if self.dead_switch:
                        self.dead_switch.stop_switch()
                    self.tor_proxy = None
                    self.dead_switch = None
                    return "‖ Ghost mode deactivated ‖ Clearnet restored ‖"
                except Exception as e:
                    return f"‖ Disable failed: {e} ‖"

        elif user_input == '/new-identity':
            if self.tor_proxy is None:
                return "‖ Tor not initialised. Use /ghost-mode first ‖"
            return self.tor_proxy.new_identity()

        elif user_input == '/check-in':
            if self.dead_switch is None:
                return "‖ Dead man's switch not active ‖"
            return self.dead_switch.check_in()

        elif user_input == '/tor-status':
            if self.tor_proxy is None:
                return "‖ Tor not initialised ‖"
            ip = self.tor_proxy.get_tor_ip()
            if ip:
                return f"‖ Tor active. Exit IP: {ip} ‖"
            return "‖ Tor not connected ‖"

        return None   # Not a command

    def generate_response(self, user_input):
        """Main response generator – entry point for all user input."""
        # Identity guard is disabled; uncomment if needed
        # action, auth_response = self.identity.process_input(user_input)
        # if action in ('auth_attempt', 'deauth'):
        #     self.formatter.print_response(auth_response)
        #     return auth_response

        command_response = self.handle_command(user_input)
        if command_response:
            self.formatter.print_command_response(command_response)
            return command_response

        mood = self.mood_engine.detect(user_input)
        mood_shift = self.mood_engine.flag_shift()
        if mood_shift:
            print(f"\n  {mood_shift}")
        mood_context = self.mood_engine.get_style_injection(mood)
        memory_context = self.smart_memory.build_memory_context(user_input)
        book_context = self.books.build_book_context(user_input)

        if self.ai_enabled:
            response = self.generate_ai_response(user_input, mood_context, memory_context)
        else:
            basic_responses = {
                'hello':        '‖ Session active. All systems operational. ‖',
                'test':         '‖ System operational. All modules available. ‖',
                'status':       '‖ All systems nominal. Use /status for details. ‖',
                'auto':         '‖ Use /auto-mode to start autonomous operations. ‖',
                'workflow':     '‖ Use /start-workflow to begin autonomous tasks. ‖',
                'orchestrator': '‖ Agent coordination system ready. Use /load orchestrator. ‖'
            }
            response = basic_responses.get(user_input.lower(),
                                           f"‖ Command: {user_input} ‖ AI disabled. Use /ai ‖")

        if self.memory:
            self.memory.store_intelligent_memory(user_input, response)
        else:
            self.vault.store_conversation(user_input, response)

        self.smart_memory.add_to_session('user', user_input, mood)
        self.smart_memory.add_to_session('assistant', response)
        self.formatter.print_response(response)   # renamed from print_ciph

        return response

    def start_background_monitoring(self):
        """Start background thread for periodic system checks."""
        monitor_thread = threading.Thread(
            target=self._monitor_for_updates,
            daemon=True
        )
        monitor_thread.start()
        self.monitoring_active = True

    def _monitor_for_updates(self):
        """Background thread: checks OSINT alerts and workflow status periodically."""
        last_check = {}

        while self.monitoring_active:
            try:
                if self.osint:
                    alerts = self.osint.get_recent_alerts(hours=1)
                    if alerts and alerts != last_check.get('osint'):
                        self.add_notification(f"🚨 OSINT Alert: {len(alerts)} new threats")
                        last_check['osint'] = alerts

                if self.orchestrator:
                    status = self.orchestrator.get_workflow_status()
                    active_workflows = status.get('active_workflows', [])
                    if active_workflows != last_check.get('workflows'):
                        if active_workflows:
                            self.add_notification(f"🤖 Workflows running: {len(active_workflows)}")
                        last_check['workflows'] = active_workflows

                time.sleep(60)   # every minute

            except Exception as e:
                print(f"⚠️ Monitoring error: {e}")
                time.sleep(300)  # back off for 5 minutes

    def add_notification(self, message: str):
        """Queue a notification for the next interaction."""
        self.notification_queue.append({
            'time': time.time(),
            'message': message
        })

    def print_banner(self):
        """Display system status banner (SSH‑friendly)."""
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

        integrity = self.security.integrity_check()
        security_indicator = " • SECURE" if integrity['all_critical_files_present'] else " • COMPROMISED"

        project_scan = self.file_analyzer.scan_project(".")
        project_files = project_scan.get('file_count', 0) if 'file_count' in project_scan else 0
        project_indicator = f" • {project_files} files" if project_files > 0 else " • NO PROJECT"

        notification_indicator = f" • {len(self.notification_queue)} updates" if self.notification_queue else ""
        personality_indicator = " • PERSONALITY ACTIVE"

        banner = f"""
╔{'═' * (self.max_width-2)}╗
║ {'AUTONOMOUS AGENT SYSTEM v1.0':^{self.max_width-4}} ║
║ {'Encrypted • Adaptive' + ai_indicator + security_indicator + project_indicator + memory_indicator + osint_indicator + pentest_indicator + trading_indicator + bounty_indicator + orchestrator_indicator + scheduler_indicator + notification_indicator + personality_indicator:^{self.max_width-4}} ║  
╚{'═' * (self.max_width-2)}╝
        """
        print(banner)

        if self.notification_queue:
            print(f"\n📢 System: ‖ {len(self.notification_queue)} pending updates ‖")
            for note in self.notification_queue[:3]:
                print(f"   • {note['message']}")
            self.notification_queue = []

    def get_user_input(self):
        """Better input handling for SSH."""
        try:
            return input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            return "/exit"

    def run_ssh_session(self):
        """Main SSH session loop."""
        self.print_banner()
        print("‖ Type /help for commands, /exit to quit ‖")
        print("‖ /load orchestrator - Load autonomous agent system ‖")
        print("‖ /auto-mode - Start all autonomous workflows ‖")
        print("‖ /workflow-status - Check autonomous operations ‖")
        print("‖ /start-workflow <name> - Start specific workflow ‖")
        print("‖ /reality-check - See actual system status (not AI fantasy) ‖\n")

        while True:
            try:
                user_input = self.get_user_input()

                if user_input in ['/exit', '/quit', '/q']:
                    print("\nSystem: ‖ Session encrypted and stored. Closing connection. ‖")
                    break
                elif user_input == '/help':
                    print("\nAGENT ORCHESTRATION: /auto-mode, /start-workflow, /stop-workflow, /workflow-status, /stop-all-workflows")
                    print("PENTESTING: /port-scan, /web-scan, /security-audit, /network-discovery, /ssl-scan")
                    print("TRADING: /market-data, /arbitrage-scan, /market-trends, /wealth-strategy, /trading-signals, /portfolio-health")
                    print("BOUNTY HUNTING: /bounty-scan, /bounty-report, /bounty-programs, /auto-bounty")
                    print("DARKNET INTELLIGENCE: /osint, /darknet-dashboard, /crypto-monitor, /osint-status, /watch, /alerts")
                    print("FILES: /scan-project, /read-file <file>, /search-in-files <term>, /project-status")
                    print("SECURITY: /security-scan, /clean-footprints, /integrity-check, /backup-now, /emergency-wipe")
                    print("SCHEDULER: /schedule-start, /schedule-stop, /schedule-status, /schedule-update")
                    print("MODULES: /modules, /load <module>, /unload <module>")
                    print("MEMORY: /search <query>, /memory, /tag <tag>")
                    print("CONVERSATION: /talk-test, /convo-summary")
                    print("DEBUGGING: /reality-check, /debug-on, /show-workflow-log, /module-status, /test-command, /talk-test, /convo-summary")
                    print("NOTIFICATIONS: /notifications, /clear-notifications")
                    print("TOR/GHOST: /ghost-mode, /new-identity, /check-in, /tor-status")
                    print("CORE: /exit, /help, /status, /ai, /setkey")
                    continue
                elif user_input == '':
                    continue

                self.generate_response(user_input)

            except Exception as e:
                print(f"\nSystem: ‖ Error: {e} ‖")


if __name__ == "__main__":
    core = CiphCore()
    core.run_ssh_session()