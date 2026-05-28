#!/usr/bin/env python3
# agent_orchestrator.py - AI Agent Coordination & Autonomous Operations
# Redacted for public release – no personal information present

import threading
import time
import traceback
from typing import Dict, List, Any
from cipher_vault import CipherVault

# Optional: externalize test target for vulnerability scans
DEFAULT_TEST_TARGET = "http://testphp.vulnweb.com"   # public test site (Acunetix)

class AgentOrchestrator:
    """
    Coordinates AI modules to work together autonomously.
    Supports predefined workflows and custom sequences.
    """
    
    def __init__(self, vault: CipherVault, modules: Dict[str, Any]):
        self.vault = vault
        self.modules = modules
        self.active_workflows = []
        self.agent_threads = {}
        self.operation_logs = []
        self.debug_mode = True   # use shorter sleep intervals for testing
        
        # Workflow templates – step names must match handler keys
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
        """Start an autonomous workflow in a background thread."""
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
        """Main loop for a workflow: executes steps, then waits or repeats."""
        workflow_name = workflow['name']
        print(f"🤖 [DEBUG] ======== STARTING WORKFLOW: {workflow_name} ========")
        self._log_operation(f"Workflow {workflow_name}: STARTED")
        
        try:
            while workflow_name in self.active_workflows:
                # Execute each step in sequence
                for step_index, step in enumerate(workflow['steps']):
                    if workflow_name not in self.active_workflows:
                        break
                    
                    success = self._execute_workflow_step(step, workflow)
                    if not success:
                        self._log_operation(f"Workflow {workflow_name}: Step {step} FAILED")
                    else:
                        self._log_operation(f"Workflow {workflow_name}: Step {step} COMPLETED")
                    time.sleep(1)  # brief pause between steps
                
                if workflow_name not in self.active_workflows:
                    break
                
                # Handle scheduling
                if workflow['trigger'] == 'schedule':
                    wait_hours = workflow.get('interval_hours', 6)
                    if self.debug_mode:
                        print(f"⏰ [DEBUG] Debug mode: sleeping 30 sec instead of {wait_hours} hours")
                        time.sleep(30)
                    else:
                        time.sleep(wait_hours * 3600)
                else:
                    # Non‑scheduled workflows run once and stop
                    break
                    
        except Exception as e:
            print(f"💥 [DEBUG] Workflow {workflow_name} crashed: {e}")
            traceback.print_exc()
            self._log_operation(f"Workflow {workflow_name}: CRASHED - {str(e)[:100]}")
        
        # Cleanup
        if workflow_name in self.active_workflows:
            self.active_workflows.remove(workflow_name)
        if workflow_name in self.agent_threads:
            del self.agent_threads[workflow_name]
        
        print(f"🛑 [DEBUG] ======== WORKFLOW {workflow_name} STOPPED ========")
        self._log_operation(f"Workflow {workflow_name}: STOPPED")
    
    def _execute_workflow_step(self, step: str, workflow: Dict[str, Any]) -> bool:
        """Map a step name to its implementation and execute it."""
        step_actions = {
            # OSINT
            'osint_scan': self._run_osint_scan,
            'analyze_threats': self._analyze_threat_patterns,
            
            # Trading
            'market_scan': self._run_market_scan,
            'analyze_trends': self._run_market_analysis,
            'generate_signals': self._generate_trading_signals,
            
            # Security / Pentest
            'network_scan': self._run_network_scan,
            'vulnerability_scan': self._run_vulnerability_scan,
            'generate_report': self._generate_security_report,
            
            # General
            'log_operation': self._log_workflow_operation,
        }
        
        if step not in step_actions:
            self._log_operation(f"Missing handler for step: {step}")
            return False
        
        try:
            return step_actions[step](workflow)
        except Exception as e:
            print(f"❌ Step '{step}' failed: {e}")
            traceback.print_exc()
            return False
    
    # ---------- Step implementations ----------
    
    def _run_osint_scan(self, workflow: Dict[str, Any]) -> bool:
        """Run OSINT feed scan."""
        osint = self.modules.get('osint')
        if not osint:
            return False
        try:
            results = osint.monitor_all_feeds()
            if results:
                self.vault.store_conversation(
                    f"AUTO_OSINT [{workflow['name']}]",
                    f"Scan completed at {time.ctime()}",
                    "auto_workflow"
                )
            return True
        except Exception as e:
            print(f"OSINT scan error: {e}")
            return False
    
    def _analyze_threat_patterns(self, workflow: Dict[str, Any]) -> bool:
        """Analyze threat patterns – placeholder."""
        # Extend with actual analysis logic
        self._log_operation("Threat pattern analysis executed (placeholder)")
        return True
    
    def _run_market_scan(self, workflow: Dict[str, Any]) -> bool:
        """Fetch market data for BTC."""
        trading = self.modules.get('trading')
        if not trading:
            return False
        try:
            market_data = trading.get_market_data('BTCUSDT')
            if market_data:
                self.vault.store_conversation(
                    f"AUTO_TRADING [{workflow['name']}]",
                    f"BTC: ${market_data.get('price', 'N/A')} at {time.ctime()}",
                    "auto_workflow"
                )
            return True
        except Exception as e:
            print(f"Market scan error: {e}")
            return False
    
    def _run_market_analysis(self, workflow: Dict[str, Any]) -> bool:
        """Analyze market trends."""
        trading = self.modules.get('trading')
        if not trading:
            return False
        try:
            trends = trading.analyze_market_trends()
            # trends is a dict – we don't need to store it here
            return True
        except Exception as e:
            print(f"Market analysis error: {e}")
            return False
    
    def _generate_trading_signals(self, workflow: Dict[str, Any]) -> bool:
        """Generate trading signals from market data."""
        trading = self.modules.get('trading')
        if not trading:
            return False
        try:
            signals = trading.automated_trading_signal()
            return signals is not None
        except Exception as e:
            print(f"Signal generation error: {e}")
            return False
    
    def _run_network_scan(self, workflow: Dict[str, Any]) -> bool:
        """Discover hosts on local network."""
        pentest = self.modules.get('pentest')
        if not pentest:
            return False
        try:
            results = pentest.network_discovery()
            return results.get('host_count', 0) >= 0
        except Exception as e:
            print(f"Network scan error: {e}")
            return False
    
    def _run_vulnerability_scan(self, workflow: Dict[str, Any]) -> bool:
        """Run web vulnerability scan on a test target (or configured target)."""
        # Use public test site by default – override via config if needed
        target = DEFAULT_TEST_TARGET
        # Prefer pentest module; fallback to bounty
        pentest = self.modules.get('pentest')
        if pentest:
            try:
                results = pentest.web_vulnerability_scan(target)
                return results is not None
            except Exception as e:
                print(f"Vulnerability scan (pentest) error: {e}")
        
        bounty = self.modules.get('bounty')
        if bounty:
            try:
                results = bounty.scan_website(target)
                return results.get('vulnerabilities_found', 0) >= 0
            except Exception as e:
                print(f"Vulnerability scan (bounty) error: {e}")
        
        return False
    
    def _generate_security_report(self, workflow: Dict[str, Any]) -> bool:
        """Store a security report in the vault."""
        try:
            self.vault.store_conversation(
                f"SECURITY_REPORT [{workflow['name']}]",
                f"Report generated at {time.ctime()}",
                "auto_workflow"
            )
            return True
        except Exception as e:
            print(f"Report generation error: {e}")
            return False
    
    def _log_workflow_operation(self, workflow: Dict[str, Any]) -> bool:
        """Generic logging step."""
        self._log_operation(f"Workflow {workflow['name']} completed a cycle")
        return True
    
    # ---------- Utility & debugging methods ----------
    
    def _log_operation(self, message: str):
        """Store an operation log entry."""
        self.operation_logs.append({
            'timestamp': time.time(),
            'action': message
        })
        if len(self.operation_logs) > 100:
            self.operation_logs = self.operation_logs[-100:]
    
    def get_operation_logs(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent operation logs."""
        return self.operation_logs[-limit:] if self.operation_logs else []
    
    def stop_workflow(self, workflow_name: str) -> str:
        """Stop a running workflow by name."""
        if workflow_name in self.active_workflows:
            self.active_workflows.remove(workflow_name)
            self._log_operation(f"Manually stopped workflow: {workflow_name}")
            return f"✅ Stopped {workflow_name} workflow"
        return f"❌ Workflow {workflow_name} not active"
    
    def get_workflow_status(self) -> Dict[str, Any]:
        """Return current status of all workflows."""
        return {
            'active_workflows': self.active_workflows.copy(),
            'available_workflows': list(self.workflow_templates.keys()),
            'total_agents': len(self.agent_threads),
            'system_status': 'OPERATIONAL' if self.active_workflows else 'IDLE',
            'debug_mode': self.debug_mode
        }
    
    def create_custom_workflow(self, name: str, steps: List[str], trigger: str = 'manual') -> str:
        """Dynamically create a new workflow template."""
        self.workflow_templates[name] = {
            'name': name,
            'steps': steps,
            'trigger': trigger
        }
        return f"✅ Created custom workflow: {name}"
    
    def stop_all_workflows(self) -> str:
        """Stop every active workflow."""
        count = len(self.active_workflows)
        self.active_workflows.clear()
        self.agent_threads.clear()
        self._log_operation(f"Stopped all {count} workflows")
        return f"✅ Stopped {count} workflows"