#!/usr/bin/env python3
# ciph_kernel_v3.py - Production-grade agent core

import json
import re
import time
import uuid
from typing import Dict, Any, Optional, Tuple, Callable, List

class CiphKernelV3:
    def __init__(self, modules, darknet, trading, sports, pentest, bounty, orchestrator, state_manager=None, vault=None):
        self.modules = modules
        self.darknet = darknet
        self.trading = trading
        self.sports = sports
        self.pentest = pentest
        self.bounty = bounty
        self.orchestrator = orchestrator
        self.state_manager = state_manager  # Optional, passed from ciph_core
        self.vault = vault or getattr(modules, 'vault', None)
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

    # ─────────────────────────────────────────────────────────────
    # EPISTEMIC STATE MACHINE & TRANSITION CONTROLLER (PHASE 2)
    # ─────────────────────────────────────────────────────────────

    def resolve_hypothesis(
        self,
        claim_id: str,
        receipt_id: str,
        success: bool,
        reason: str = ""
    ) -> Tuple[str, str]:
        """
        Kernel-owned state transition for hypotheses.
        Only runtime execution receipts can trigger promotion or refutation.
        """
        if not self.vault:
            return "ERROR", "No vault connected to kernel."
            
        claim = self.vault.get_claim_with_evidence(claim_id)
        if not claim:
            return "ERROR", f"Claim {claim_id} not found."
            
        receipt = self.vault.get_evidence_receipt(receipt_id)
        if not receipt:
            return "ERROR", f"Receipt {receipt_id} not found."
            
        if success:
            # Observation confirmed -> promote to VERIFIED_REAL
            self.vault.update_claim_state(
                claim_id=claim_id,
                new_state="VERIFIED_REAL",
                verifying_receipt_id=receipt_id,
                calculated_confidence_tier="TIER_4_VERIFIED_RECEIPT"
            )
            # Record in win history
            domain_vector = f"{claim['subject']}:{claim['predicate']}"
            self.vault.record_win(
                claim_id=claim_id,
                domain_vector=domain_vector,
                verifying_receipt_id=receipt_id
            )
            msg = f"✓ Claim {claim_id} ({claim['subject']}) promoted to VERIFIED_REAL via receipt {receipt_id}."
            self.log("resolve_hypothesis", {"claim_id": claim_id, "receipt_id": receipt_id}, msg, True)
            return "VERIFIED_REAL", msg
        else:
            # Hypothesis refuted -> move to Graveyard
            self.vault.update_claim_state(
                claim_id=claim_id,
                new_state="REFUTED",
                retirement_reason="refuted_by_receipt"
            )
            self.vault.add_to_graveyard(
                subject=claim['subject'],
                predicate=claim['predicate'],
                refuting_receipt_id=receipt_id,
                condition=claim['condition']
            )
            msg = f"✗ Claim {claim_id} refuted by receipt {receipt_id} -> Tombstoned to Graveyard."
            self.log("resolve_hypothesis", {"claim_id": claim_id, "receipt_id": receipt_id}, msg, True)
            return "REFUTED", msg

    def resolve_contradiction(self, claim_a_id: str, claim_b_id: str) -> Dict[str, Any]:
        """
        Deterministically resolves conflicting observations between two claims.
        Evaluates source receipt weights, direct execution vs passive signals, and recency.
        """
        if not self.vault:
            return {"status": "ERROR", "message": "No vault connected"}
            
        claim_a = self.vault.get_claim_with_evidence(claim_a_id)
        claim_b = self.vault.get_claim_with_evidence(claim_b_id)
        if not claim_a or not claim_b:
            return {"status": "ERROR", "message": "One or both claims not found"}
            
        # Deterministic scoring based on evidence weight and recency
        score_a = sum(e.get('weight', 1.0) for e in claim_a.get('evidence', []))
        score_b = sum(e.get('weight', 1.0) for e in claim_b.get('evidence', []))
        
        # If weights equal, compare newest receipt timestamp
        time_a = max([e.get('observed_at', 0) for e in claim_a.get('evidence', [])] or [claim_a['created_at']])
        time_b = max([e.get('observed_at', 0) for e in claim_b.get('evidence', [])] or [claim_b['created_at']])
        
        if score_a > score_b:
            winner, loser = claim_a, claim_b
            winner_reason = f"Higher evidence weight ({score_a:.1f} vs {score_b:.1f})"
        elif score_b > score_a:
            winner, loser = claim_b, claim_a
            winner_reason = f"Higher evidence weight ({score_b:.1f} vs {score_a:.1f})"
        else:
            # Tie break on recency
            if time_a >= time_b:
                winner, loser = claim_a, claim_b
                winner_reason = f"More recent observation timestamp ({time_a} >= {time_b})"
            else:
                winner, loser = claim_b, claim_a
                winner_reason = f"More recent observation timestamp ({time_b} > {time_a})"
                
        # Winner remains/promotes to VERIFIED_REAL
        self.vault.update_claim_state(
            claim_id=winner['claim_id'],
            new_state="VERIFIED_REAL"
        )
        # Loser is marked SUPERSEDED
        self.vault.update_claim_state(
            claim_id=loser['claim_id'],
            new_state="SUPERSEDED",
            supersedes_claim_id=winner['claim_id'],
            retirement_reason="superseded"
        )
        
        report = {
            "status": "RESOLVED",
            "winning_claim_id": winner['claim_id'],
            "superseded_claim_id": loser['claim_id'],
            "reason": winner_reason,
            "resolved_at": time.time()
        }
        self.log("resolve_contradiction", {"claim_a": claim_a_id, "claim_b": claim_b_id}, str(report), True)
        return report

    def stage_epistemic_action(
        self,
        tool_command: str,
        action_source: str = "hypothesis_verifier",
        claim_id: Optional[str] = None
    ) -> str:
        """Stage an action in the vault queue."""
        if not self.vault:
            return ""
        return self.vault.stage_action(
            tool_command=tool_command,
            action_source=action_source,
            claim_id=claim_id
        )

    def execute_staged_action(
        self,
        action_id: str,
        executor_func: Callable[[], Tuple[str, bool, int, str]],
        tool_name: str = "generic_tool",
        target_identifier: str = "localhost",
        worker_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a staged action under an atomic CAS lock.
        Prevents double-firing on live targets and ensures receipt logging.
        executor_func: returns (summary_msg, success_bool, exit_code, raw_stdout)
        """
        if not self.vault:
            return {"status": "ERROR", "error": "No vault connected"}
            
        worker_id = worker_id or f"worker_{uuid.uuid4().hex[:6]}"
        
        # 1. Acquire Atomic CAS Lock
        lock_acquired = self.vault.acquire_action_cas_lock(action_id, worker_id)
        if not lock_acquired:
            return {
                "status": "LOCKED",
                "success": False,
                "error": "Action already acquired by another worker or not in STAGED state"
            }
            
        # 2. Execute physical tool
        try:
            summary_msg, success, exit_code, raw_stdout = executor_func()
        except Exception as e:
            self.vault.complete_staged_action(action_id, "FAILED")
            return {
                "status": "FAILED",
                "success": False,
                "error": f"Execution exception: {str(e)}"
            }
            
        # 3. Store Immutable Evidence Receipt
        receipt_id = self.vault.store_evidence_receipt(
            tool_name=tool_name,
            target_identifier=target_identifier,
            raw_output=raw_stdout or summary_msg,
            exit_code=exit_code
        )
        
        # 4. Resolve claim state if linked
        conn = self.vault._get_connection()
        claim_id = None
        try:
            c = conn.cursor()
            c.execute('SELECT claim_id FROM staged_actions WHERE action_id = ?', (action_id,))
            row = c.fetchone()
            if row:
                claim_id = row[0]
        finally:
            conn.close()
            
        resolution = None
        if claim_id:
            resolution = self.resolve_hypothesis(claim_id, receipt_id, success)
            
        # 5. Mark staged action completed
        self.vault.complete_staged_action(action_id, "COMPLETED" if success else "FAILED")
        
        return {
            "status": "COMPLETED",
            "success": success,
            "receipt_id": receipt_id,
            "claim_id": claim_id,
            "resolution": resolution,
            "summary": summary_msg
        }

    def evaluate_ttl_and_decay(self, default_ttl_seconds: float = 86400.0) -> Dict[str, List[str]]:
        """
        Scans active claims and applies temporal decay / eviction.
        VERIFIED_REAL claims -> STALE (ttl_expired)
        CORROBORATED claims -> EXPIRED (ttl_expired)
        """
        if not self.vault:
            return {"decayed": [], "expired": []}
            
        current_time = time.time()
        decayed = []
        expired = []
        
        # Check active VERIFIED_REAL claims
        real_claims = self.vault.get_claims_by_state(["VERIFIED_REAL"], limit=200)
        for c in real_claims:
            exp_time = c.get('expires_at') or (c['created_at'] + default_ttl_seconds)
            if current_time >= exp_time:
                self.vault.update_claim_state(
                    claim_id=c['claim_id'],
                    new_state="STALE",
                    retirement_reason="ttl_expired"
                )
                decayed.append(c['claim_id'])
                
        # Check CORROBORATED claims
        corroborated_claims = self.vault.get_claims_by_state(["CORROBORATED"], limit=200)
        for c in corroborated_claims:
            exp_time = c.get('expires_at') or (c['created_at'] + default_ttl_seconds)
            if current_time >= exp_time:
                self.vault.update_claim_state(
                    claim_id=c['claim_id'],
                    new_state="EXPIRED",
                    retirement_reason="ttl_expired"
                )
                expired.append(c['claim_id'])
                
        return {"decayed": decayed, "expired": expired}

    def get_epistemic_grounding(self) -> Dict[str, Any]:
        """Provides a grounded snapshot of verified reality, negative cache, and win stats."""
        if not self.vault:
            return {"real_facts": [], "graveyard": [], "wins_count": 0}
            
        real_facts = self.vault.get_active_real_claims(limit=20)
        graveyard = self.vault.get_recent_graveyard(limit=10)
        wins = self.vault.get_recent_wins(limit=10)
        
        return {
            "real_facts": real_facts,
            "graveyard": graveyard,
            "wins_count": len(wins),
            "recent_wins": wins
        }