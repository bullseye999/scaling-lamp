#!/usr/bin/env python3
# ciph_kernel_v3.py - Production-grade agent core

import json
import re
import time
import uuid
from typing import Dict, Any, Optional, Tuple, Callable, List

class CiphKernelV3:
    def __init__(self, modules, darknet, trading, sports, pentest, bounty, orchestrator, state_manager=None):
        self.modules = modules
        self.darknet = darknet
        self.trading = trading
        self.sports = sports
        self.pentest = pentest
        self.bounty = bounty
        self.orchestrator = orchestrator
        self.state_manager = state_manager  # Optional, passed from ciph_core
        self.execution_log = []
        self.brain = None
        

    # ========== SNAPSHOT (Minimal frozen truth per turn) ==========
    def snapshot(self) -> Dict:
        """Return snapshot from state manager (single source of truth)."""
        if self.state_manager:
            return self.state_manager.get_snapshot()
        
        # Fallback if no state manager
        workflows_active = 0
        if self.orchestrator:
            try:
                workflows_active = len(self.orchestrator.active_workflows)
            except:
                pass
        return {
            "loaded": list(self.modules.active_modules.keys()),
            "tor": self.darknet is not None,
            "workflows": workflows_active,
        }

    def validate_params(self, action: str, params: Dict) -> bool:
        """Validate parameters before execution"""
        validations = {
            'load_module': {
                'required': ['name'],
                'valid_values': {'name': ['trading', 'pentest', 'bounty', 'orchestrator', 'memory', 'osint']}
            },
            'market_data': {
                'required': ['symbol']
            },
            'sports_predict': {
                'required': ['home', 'away']
            }
        }
        if action not in validations:
            return True
        rules = validations[action]
        for req in rules.get('required', []):
            if req not in params:
                return False
        for key, valid_values in rules.get('valid_values', {}).items():
            if key in params and params[key] not in valid_values:
                return False
        return True

    def compose_actions(self, actions: List[Tuple[str, Dict]]) -> List[Dict]:
        """Chain multiple actions together"""
        results = []
        for action, params in actions:
            if not self.validate_params(action, params):
                results.append({'action': action, 'params': params, 'result': 'Invalid params', 'success': False})
                break
            msg, success = self.execute(action, params)
            results.append({
                'action': action,
                'params': params,
                'result': msg,
                'success': success
            })
            if not success:
                break
        return results

    # ========== EXECUTION LOG (Single source of truth) ==========
    def log(self, action: str, params: Dict, result: Any, success: bool) -> str:
        """Record every state change. Returns log entry ID."""
        entry = {
            "id": str(uuid.uuid4())[:8],
            "time": time.time(),
            "action": action,
            "params": params,
            "result": str(result)[:200],
            "success": success
        }
        self.execution_log.append(entry)
        # Keep only last 100 entries
        self.execution_log = self.execution_log[-100:]
        return entry["id"]

    def last_result(self, action: str = None) -> Optional[Dict]:
        """Get most recent execution result for an action."""
        for entry in reversed(self.execution_log):
            if action is None or entry["action"] == action:
                return entry
        return None

    # ========== EXECUTOR (Only authority over reality) ==========
    def execute(self, action: str, params: Dict) -> Tuple[str, bool]:
        """
        Run action, log result, return (user_message, success).
        This is the ONLY place system state can change.
        """
        
        # ---------- DARKNET SCAN ----------
        if action == "darknet_scan":
            if not self.darknet:
                msg = "❌ Darknet module not loaded. Use /load darknet"
                self.log(action, params, msg, False)
                return msg, False
            
            try:
                result = self.darknet.full_scan()
                alert_count = result.get('total_alerts', 0)
                msg = f"🌑 Darknet scan complete: {alert_count} alerts found"
                self.log(action, params, msg, True)
                return msg, True
            except Exception as e:
                msg = f"❌ Darknet scan failed: {str(e)[:100]}"
                self.log(action, params, msg, False)
                return msg, False

        # ---------- LOAD MODULE ----------
        elif action == "load_module":
            name = params.get("name")
            if not name:
                msg = "❌ Missing module name"
                self.log(action, params, msg, False)
                return msg, False
            
            result = self.modules.load_module(name)
            success = "✅" in result
            self.log(action, {"name": name}, result, success)
            return result, success

        # ---------- REALITY CHECK ----------
        elif action == "reality_check":
            snap = self.snapshot()
            msg = f"Loaded: {snap['loaded']} | Tor: {snap['tor']} | Workflows: {snap['workflows']}"
            self.log(action, {}, msg, True)
            return msg, True

        # ---------- MARKET DATA ----------
        elif action == "market_data":
            if not self.trading:
                msg = "❌ Trading module not loaded"
                self.log(action, params, msg, False)
                return msg, False
            
            symbol = params.get("symbol", "BTCUSDT")
            try:
                data = self.trading.get_market_data(symbol)
                if data and 'price' in data:
                    msg = f"💰 {symbol}: ${data['price']} | 24h: {data.get('change_24h', 'N/A')}%"
                    self.log(action, {"symbol": symbol}, msg, True)
                    return msg, True
                else:
                    msg = f"❌ Failed to get {symbol} data"
                    self.log(action, {"symbol": symbol}, msg, False)
                    return msg, False
            except Exception as e:
                msg = f"❌ Market data error: {str(e)[:80]}"
                self.log(action, {"symbol": symbol}, msg, False)
                return msg, False

        # ---------- SPORTS PREDICTION ----------
        elif action == "sports_predict":
            if not self.sports:
                msg = "❌ Sports module not loaded"
                self.log(action, params, msg, False)
                return msg, False
            
            home = params.get("home", "")
            away = params.get("away", "")
            if not home or not away:
                msg = "❌ Missing home or away team"
                self.log(action, params, msg, False)
                return msg, False
            
            try:
                result = self.sports.predict_match(home, away)
                signal = result.get('signal', 'Prediction complete')
                self.log(action, {"home": home, "away": away}, signal, True)
                return signal, True
            except Exception as e:
                msg = f"❌ Prediction failed: {str(e)[:80]}"
                self.log(action, params, msg, False)
                return msg, False

        # ---------- UNKNOWN ACTION ----------
        else:
            msg = f"❌ Unknown action: {action}"
            self.log(action, params, msg, False)
            return msg, False

    # ========== INTENT PARSER (Flexible: JSON + retry) ==========
    def parse_intent(self, llm_response: str) -> Dict:
        """
        Extract intent from LLM response.
        Tries JSON first, then falls back to keyword detection.
        """
        # Try JSON extraction
        json_match = re.search(r'\{.*\}', llm_response, re.DOTALL)
        if json_match:
            try:
                intent = json.loads(json_match.group(0))
                # Handle both formats: {"action":...} and {"type":"action","action":...}
                if "action" in intent:
                    return {"type": "action", "action": intent["action"], "params": intent.get("params", {})}
                if "type" in intent:
                    return intent
                if "chat" in intent:
                    return {"type": "chat", "content": intent["chat"]}
            except:
                pass
        
        # Fallback: keyword detection
        text = llm_response.lower()
        
        # Darknet scan
        if any(phrase in text for phrase in ["darknet scan", "threat intel", "darknet-scan"]):
            return {"type": "action", "action": "darknet_scan", "params": {}}
        
        # Load module
        if "load module" in text:
            for mod in ["trading", "pentest", "bounty", "orchestrator", "memory", "osint"]:
                if mod in text:
                    return {"type": "action", "action": "load_module", "params": {"name": mod}}
        
        # Reality check
        if any(phrase in text for phrase in ["reality check", "system status", "what's loaded"]):
            return {"type": "action", "action": "reality_check", "params": {}}
        
        # Market data
        if any(phrase in text for phrase in ["btc price", "crypto price", "market data", "bitcoin price"]):
            return {"type": "action", "action": "market_data", "params": {"symbol": "BTCUSDT"}}
        
        # Sports prediction
        if "predict" in text and "vs" in text:
            import re as regex
            match = regex.search(r'(\w+)\s+vs\s+(\w+)', text, regex.IGNORECASE)
            if match:
                return {"type": "action", "action": "sports_predict", "params": {"home": match.group(1), "away": match.group(2)}}
        
        # Default: treat as chat
        return {"type": "chat", "content": llm_response}

    # ========== MAIN PROCESS ==========
    def process(self, user_input: str, llm_caller: Callable) -> str:
        """
        Main entry point.
        llm_caller: function(prompt, history, system_prompt, temperature) -> str
        """
        # 1. Build snapshot (frozen truth)
        snap = self.snapshot()
        
        # 2. Build system prompt (strict on facts, flexible on language)
        system_prompt = f"""You are Ciph, an execution agent. Current reality snapshot:
{json.dumps(snap, indent=2)}

RULES:
- NEVER claim something happened (e.g., "module loaded", "scan completed").
- You can REQUEST actions by outputting JSON: {{"action": "darknet_scan", "params": {{}}}}
- Or CHAT naturally: {{"chat": "your response"}}
- Or just speak naturally – I'll detect actions from your words.

Available actions:
- darknet_scan: Run darknet threat intelligence scan
- load_module: {{"name": "trading|pentest|bounty|orchestrator|memory|osint"}}
- reality_check: Show current system state
- market_data: {{"symbol": "BTCUSDT"}}
- sports_predict: {{"home": "team", "away": "team"}}

Be helpful, direct, and grounded in the reality snapshot above."""
        
        # 3. Get LLM response
        try:
            raw_response = llm_caller(user_input, [], system_prompt, temperature=0.3)
        except Exception as e:
            return f"❌ LLM error: {str(e)[:100]}"
        
        # 4. Parse intent
        intent = self.parse_intent(raw_response)
        
        # 5. Execute if action requested
        if intent.get("type") == "action":
            action = intent.get("action")
            params = intent.get("params", {})
            msg, _ = self.execute(action, params)
            return msg
        
        # 6. Otherwise return chat response
        return intent.get("content", raw_response)