#!/usr/bin/env python3
# agent_orchestrator.py - AI Agent Coordination & Autonomous Operations
# UPDATED: Correct method names + Fixed function call syntax

import threading
import time
import json
import traceback
from collections import deque
from typing import Dict, List, Any
from cipher_vault import CipherVault

class AgentOrchestrator:
    """
    Coordinates your AI modules to work together autonomously
    UPDATED: Fixed method name mismatches for all modules
    """
    
    def __init__(self, vault: CipherVault, modules: Dict[str, Any]):
        self.vault = vault
        self.modules = modules
        self.active_workflows = []
        self.agent_threads = {}
        self.operation_logs = deque(maxlen=100)
        self.debug_mode = True
        
        # UPDATED: CORRECT workflow templates with actual method names
        self.workflow_templates = {
            'threat_intel_cycle': {
                'name': 'Threat Intelligence Cycle',
                'steps': ['osint_scan', 'analyze_threats', 'log_operation'],
                'trigger': 'schedule',
                'interval_hours': 6
            },
            'trading_intelligence': {
                'name': 'Trading Intelligence Fusion', 
                'steps': ['market_scan', 'analyze_trends', 'generate_signals'],
                'trigger': 'market_volatility',
                'conditions': ['volume_spike', 'price_swing']
            },
            'security_audit_cycle': {
                'name': 'Continuous Security Audit',
                'steps': ['network_scan', 'vulnerability_scan', 'generate_report'],
                'trigger': 'schedule', 
                'interval_hours': 24
            }
        }
    
    def start_autonomous_operation(self, workflow_name: str) -> str:
        """Start an autonomous workflow with debugging"""
        if workflow_name not in self.workflow_templates:
            return f"❌ Unknown workflow: {workflow_name}"
        
        if workflow_name in self.active_workflows:
            return f"✅ Workflow {workflow_name} already running"
        
        workflow = self.workflow_templates[workflow_name]
        thread = threading.Thread(target=self._run_workflow, args=(workflow,))
        thread.daemon = True
        thread.start()
        
        self.agent_threads[workflow_name] = thread
        self.active_workflows.append(workflow_name)
        
        self._log_operation(f"Started workflow: {workflow_name}")
        return f"✅ Started autonomous {workflow_name} workflow"
    
    def _run_workflow(self, workflow: Dict[str, Any]):
        """Run a workflow autonomously WITH COMPLETE DEBUGGING"""
        workflow_name = workflow['name']
        print(f"🤖 [DEBUG] ======== STARTING WORKFLOW: {workflow_name} ========")
        print(f"🤖 [DEBUG] Steps in workflow: {workflow['steps']}")
        
        self._log_operation(f"Workflow {workflow_name}: STARTED")
        
        try:
            while workflow_name in self.active_workflows:
                print(f"🔁 [DEBUG] Workflow {workflow_name}: New cycle starting")
                
                # Execute each step with error handling
                for step_index, step in enumerate(workflow['steps']):
                    if workflow_name not in self.active_workflows:
                        print(f"⚠️ [DEBUG] Workflow {workflow_name} was stopped, exiting")
                        break
                    
                    print(f"  🛠️ [DEBUG] Executing step {step_index+1}/{len(workflow['steps'])}: {step}")
                    step_success = self._execute_workflow_step(step, workflow)
                    
                    if not step_success:
                        print(f"  ❌ [DEBUG] Step {step} failed, continuing to next step")
                        self._log_operation(f"Workflow {workflow_name}: Step {step} FAILED")
                    else:
                        print(f"  ✅ [DEBUG] Step {step} completed successfully")
                        self._log_operation(f"Workflow {workflow_name}: Step {step} COMPLETED")
                    
                    time.sleep(1)  # Small pause between steps
                
                # Check if we should continue
                if workflow_name not in self.active_workflows:
                    break
                
                # Handle schedule/trigger
                if workflow['trigger'] == 'schedule':
                    wait_hours = workflow.get('interval_hours', 6)
                    print(f"⏰ [DEBUG] Workflow {workflow_name}: Sleeping for {wait_hours} hours")
                    
                    # DEBUG MODE: Only wait 30 seconds instead of hours
                    if self.debug_mode:
                        print(f"⏰ [DEBUG] DEBUG MODE: Sleeping 30 seconds instead of {wait_hours} hours")
                        time.sleep(30)
                    else:
                        time.sleep(wait_hours * 3600)
                else:
                    print(f"⚠️ [DEBUG] Workflow {workflow_name}: Non-scheduled, stopping")
                    break
                    
        except Exception as e:
            print(f"💥 [DEBUG] Workflow {workflow_name} CRASHED with exception:")
            traceback.print_exc()
            self._log_operation(f"Workflow {workflow_name}: CRASHED - {str(e)[:100]}")
        
        # Clean up when workflow stops
        if workflow_name in self.active_workflows:
            self.active_workflows.remove(workflow_name)
        
        if workflow_name in self.agent_threads:
            del self.agent_threads[workflow_name]
        
        print(f"🛑 [DEBUG] ======== WORKFLOW {workflow_name} STOPPED ========")
        self._log_operation(f"Workflow {workflow_name}: STOPPED")
    
    def _execute_workflow_step(self, step: str, workflow: Dict[str, Any]) -> bool:
        """Execute a single workflow step with full debugging"""
        print(f"    🔍 [DEBUG] Looking for handler for step: '{step}'")
        
        # UPDATED: CORRECT method mapping
        step_actions = {
            # OSINT steps
            'osint_scan': self._run_osint_scan,
            'analyze_threats': self._analyze_threat_patterns,
            
            # Trading steps
            'market_scan': self._run_market_scan,
            'analyze_trends': self._run_market_analysis,
            'generate_signals': self._generate_trading_signals,
            
            # Security steps
            'network_scan': self._run_network_scan,
            'vulnerability_scan': self._run_vulnerability_scan,
            'generate_report': self._generate_security_report,
            
            # General steps
            'log_operation': self._log_workflow_operation,
        }
        
        if step in step_actions:
            print(f"    ✅ [DEBUG] Found handler for '{step}'")
            try:
                result = step_actions[step](workflow)
                print(f"    ✅ [DEBUG] Step '{step}' executed, returning True")
                return True
            except Exception as e:
                print(f"    ❌ [DEBUG] Step '{step}' FAILED with error: {e}")
                print(f"    📋 [DEBUG] Full error traceback:")
                traceback.print_exc()
                return False
        else:
            print(f"    ⚠️ [DEBUG] No handler found for step: '{step}'")
            self._log_operation(f"Missing handler for step: {step}")
            return False
    
    def _run_osint_scan(self, workflow: Dict[str, Any]) -> bool:
        """Execute OSINT scan as part of workflow"""
        print(f"      🕵️ [DEBUG] Attempting OSINT scan...")
        
        if 'osint' in self.modules and self.modules['osint']:
            try:
                # UPDATED: Correct method call
                print(f"      🕵️ [DEBUG] OSINT module found, calling monitor_all_feeds()")
                results = self.modules['osint'].monitor_all_feeds()
                
                if results:
                    print(f"      ✅ [DEBUG] OSINT scan successful")
                    
                    # Store intelligence
                    self.vault.store_conversation(
                        f"AUTO_OSINT [{workflow['name']}]",
                        f"Scan completed at {time.ctime()}",
                        "auto_workflow"
                    )
                    return True
                else:
                    print(f"      ⚠️ [DEBUG] OSINT scan returned no results")
                    return True  # Still count as success, just no data
                    
            except Exception as e:
                print(f"      ❌ [DEBUG] OSINT scan FAILED: {e}")
                traceback.print_exc()
                return False
        else:
            print(f"      ❌ [DEBUG] OSINT module not available")
            return False
    
    def _run_market_scan(self, workflow: Dict[str, Any]) -> bool:
        """Execute market scan as part of workflow"""
        print(f"      📈 [DEBUG] Attempting market scan...")
        
        if 'trading' in self.modules and self.modules['trading']:
            try:
                # UPDATED: Correct method call
                print(f"      📈 [DEBUG] Trading module found, calling get_market_data()")
                market_data = self.modules['trading'].get_market_data('BTCUSDT')
                
                if market_data:
                    print(f"      ✅ [DEBUG] Market scan successful: ${market_data.get('price', 'N/A')}")
                    
                    # Store analysis
                    self.vault.store_conversation(
                        f"AUTO_TRADING [{workflow['name']}]",
                        f"Market scan completed at {time.ctime()} | BTC: ${market_data.get('price', 'N/A')}",
                        "auto_workflow"
                    )
                    return True
                else:
                    print(f"      ⚠️ [DEBUG] Market scan returned no data")
                    return True
                    
            except Exception as e:
                print(f"      ❌ [DEBUG] Market scan FAILED: {e}")
                traceback.print_exc()
                return False
        else:
            print(f"      ❌ [DEBUG] Trading module not available")
            return False
    
    def _run_market_analysis(self, workflow: Dict[str, Any]) -> bool:
        """Execute market analysis as part of workflow"""
        print(f"      📊 [DEBUG] Attempting market analysis...")
        
        if 'trading' in self.modules and self.modules['trading']:
            try:
                # UPDATED: Correct method call
                print(f"      📊 [DEBUG] Trading module found, calling analyze_market_trends()")
                trends = self.modules['trading'].analyze_market_trends()
                
                print(f"      ✅ [DEBUG] Analyzed trends for {len(trends)} assets")
                return True
            except Exception as e:
                print(f"      ❌ [DEBUG] Market analysis FAILED: {e}")
                traceback.print_exc()
                return False
        else:
            print(f"      ❌ [DEBUG] Trading module not available")
            return False
    
    def _generate_trading_signals(self, workflow: Dict[str, Any]) -> bool:
        """Generate trading signals based on analysis"""
        print(f"      🎯 [DEBUG] Generating trading signals...")
        
        if 'trading' in self.modules and self.modules['trading']:
            try:
                # UPDATED: Correct method call
                print(f"      🎯 [DEBUG] Trading module found, calling automated_trading_signal()")
                signals = self.modules['trading'].automated_trading_signal()
                
                print(f"      ✅ [DEBUG] Generated {signals.get('total_signals', 0)} signals")
                return True
            except Exception as e:
                print(f"      ❌ [DEBUG] Signal generation FAILED: {e}")
                return False
        else:
            print(f"      ❌ [DEBUG] Trading module not available")
            return False
    
    def _run_network_scan(self, workflow: Dict[str, Any]) -> bool:
        """Execute network scan as part of workflow"""
        print(f"      🌐 [DEBUG] Attempting network scan...")
        
        if 'pentest' in self.modules and self.modules['pentest']:
            try:
                # UPDATED: Correct method call
                print(f"      🌐 [DEBUG] Pentest module found, calling network_discovery()")
                results = self.modules['pentest'].network_discovery()
                
                print(f"      ✅ [DEBUG] Network scan found {results.get('host_count', 0)} hosts")
                return True
            except Exception as e:
                print(f"      ❌ [DEBUG] Network scan FAILED: {e}")
                return False
        else:
            print(f"      ❌ [DEBUG] Pentest module not available")
            return False
    
    def _run_vulnerability_scan(self, workflow: Dict[str, Any]) -> bool:
        """Execute vulnerability scan as part of workflow"""
        print(f"      🛡️ [DEBUG] Attempting vulnerability scan...")
        
        # UPDATED: Can use either pentest or bounty module
        if 'pentest' in self.modules and self.modules['pentest']:
            try:
                print(f"      🛡️ [DEBUG] Pentest module found, calling web_vulnerability_scan()")
                # Use test target
                results = self.modules['pentest'].web_vulnerability_scan('http://testphp.vulnweb.com')
                print(f"      ✅ [DEBUG] Vulnerability scan completed")
                return True
            except Exception as e:
                print(f"      ❌ [DEBUG] Vulnerability scan FAILED: {e}")
                return False
        elif 'bounty' in self.modules and self.modules['bounty']:
            try:
                print(f"      🛡️ [DEBUG] Bounty module found, calling scan_website()")
                results = self.modules['bounty'].scan_website('http://testphp.vulnweb.com')
                print(f"      ✅ [DEBUG] Bounty scan found {results.get('vulnerabilities_found', 0)} vulnerabilities")
                return True
            except Exception as e:
                print(f"      ❌ [DEBUG] Bounty scan FAILED: {e}")
                return False
        else:
            print(f"      ❌ [DEBUG] No vulnerability scanning module available")
            return False
    
    def _generate_security_report(self, workflow: Dict[str, Any]) -> bool:
        """Generate security report"""
        print(f"      📄 [DEBUG] Generating security report...")
        
        try:
            self.vault.store_conversation(
                f"SECURITY_REPORT [{workflow['name']}]",
                f"Security report generated at {time.ctime()}",
                "auto_workflow"
            )
            return True
        except Exception as e:
            print(f"      ❌ [DEBUG] Report generation FAILED: {e}")
            return False
    
    def _log_workflow_operation(self, workflow: Dict[str, Any]) -> bool:
        """Log workflow operation"""
        print(f"      📝 [DEBUG] Logging workflow operation...")
        self._log_operation(f"Workflow {workflow['name']} completed a cycle")
        return True
    
    def _analyze_threat_patterns(self, workflow: Dict[str, Any]) -> bool:
        """Analyze threat patterns from OSINT results"""
        print("      🔎 [DEBUG] Analyzing threat patterns...")
        if self.vault:
            recent_convs = self.vault.get_recent_conversations(limit=5, context_tag="auto_workflow")
            if recent_convs:
                self._log_operation(f"Workflow {workflow['name']}: Analyzed threat patterns across {len(recent_convs)} entries")
        return True

    def save_state(self):
        """Save workflow state to vault"""
        if self.vault:
            state = {
                'active_workflows': list(self.active_workflows),
                'operation_logs': list(self.operation_logs)
            }
            self.vault.set_config('orchestrator_state', json.dumps(state))

    def load_state(self):
        """Load workflow state from vault"""
        if self.vault:
            raw = self.vault.get_config('orchestrator_state')
            if raw:
                try:
                    state = json.loads(raw)
                    self.active_workflows = state.get('active_workflows', [])
                    saved_logs = state.get('operation_logs', [])
                    self.operation_logs = deque(saved_logs, maxlen=100)
                except Exception as e:
                    print(f"⚠️ [DEBUG] Failed to load orchestrator state: {e}")

    def _log_operation(self, message: str):
        """Log an operation for debugging"""
        log_entry = {
            'timestamp': time.time(),
            'action': message
        }
        self.operation_logs.append(log_entry)
    
    def get_operation_logs(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent operation logs for debugging"""
        return list(self.operation_logs)[-limit:] if self.operation_logs else []
    
    def stop_workflow(self, workflow_name: str) -> str:
        """Stop an autonomous workflow"""
        try:
            self.active_workflows.remove(workflow_name)
            self._log_operation(f"Manually stopped workflow: {workflow_name}")
            return f"✅ Stopped {workflow_name} workflow"
        except ValueError:
            return f"❌ Workflow {workflow_name} not active"
    
    def get_workflow_status(self) -> Dict[str, Any]:
        """Get status of all workflows"""
        return {
            'active_workflows': self.active_workflows.copy(),
            'available_workflows': list(self.workflow_templates.keys()),
            'total_agents': len(self.agent_threads),
            'system_status': 'OPERATIONAL' if self.active_workflows else 'IDLE',
            'debug_mode': self.debug_mode
        }
    
    def create_custom_workflow(self, name: str, steps: List[str], trigger: str = 'manual') -> str:
        """Create a custom workflow"""
        self.workflow_templates[name] = {
            'name': name,
            'steps': steps,
            'trigger': trigger
        }
        return f"✅ Created custom workflow: {name}"
    
    def stop_all_workflows(self) -> str:
        """Stop all running workflows"""
        count = len(self.active_workflows)
        self.active_workflows.clear()
        self.agent_threads.clear()
        self._log_operation(f"Stopped all {count} workflows")
        return f"✅ Stopped {count} workflows"