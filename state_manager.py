#!/usr/bin/env python3
# state_manager.py - Clean separation of state types
# System State (truth), Background State (no LLM access), Runtime Snapshot (LLM sees)

import time
from typing import Dict, Any, List

class StateManager:
    """Three isolated state stores: System, Background, Snapshot."""

    def __init__(self):
        # System State - TRUTH (only executor can modify)
        self.system_state = {
            "loaded_modules": {"value": [], "timestamp": 0},
            "tor": {"value": False, "timestamp": 0},
            "active_workflows": {"value": 0, "timestamp": 0},
            "ai_enabled": {"value": False, "timestamp": 0},
            "orchestrator_ready": {"value": False, "timestamp": 0},
        }
        
        # Background State - NO LLM access (sports, OSINT polling, etc.)
        self.background_state = {
            "sports_predictions": {"value": 0, "timestamp": 0},
            "osint_feeds": {"value": 0, "timestamp": 0},
            "notifications": {"value": 0, "timestamp": 0},
        }
        
        # Runtime Snapshot - LLM sees ONLY this (filtered, clean)
        self.runtime_snapshot = self._build_snapshot()
        
        # Log of state changes (for debugging)
        self.change_log = []

    def _build_snapshot(self) -> Dict:
        """Build filtered view for LLM – no background state, no raw logs."""
        return {
            "loaded": self.system_state["loaded_modules"]["value"],
            "tor": self.system_state["tor"]["value"],
            "workflows": self.system_state["active_workflows"]["value"],
            "ai": self.system_state["ai_enabled"]["value"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def _refresh_snapshot(self):
        """Update runtime snapshot after system state changes."""
        self.runtime_snapshot = self._build_snapshot()

    def _log_change(self, category: str, key: str, old_value: Any, new_value: Any):
        """Record state change for debugging."""
        self.change_log.append({
            "time": time.time(),
            "category": category,
            "key": key,
            "old": old_value,
            "new": new_value
        })
        # Keep only last 100
        self.change_log = self.change_log[-100:]

    def update_orchestrator_ready(self, ready: bool):
        old = self.system_state.get("orchestrator_ready", {}).get("value", False)
        self.system_state["orchestrator_ready"] = {"value": ready, "timestamp": time.time()}
        self._log_change("system", "orchestrator_ready", old, ready)
        self._refresh_snapshot()

    def update_background_trading(self, loaded: bool):
        self.background_state["trading_loaded"] = {"value": loaded, "timestamp": time.time()}
        self._log_change("background", "trading_loaded", not loaded, loaded)

    def update_background_pentest(self, loaded: bool):
        self.background_state["pentest_loaded"] = {"value": loaded, "timestamp": time.time()}
        self._log_change("background", "pentest_loaded", not loaded, loaded)

    def update_background_bounty(self, loaded: bool):
        self.background_state["bounty_loaded"] = {"value": loaded, "timestamp": time.time()}
        self._log_change("background", "bounty_loaded", not loaded, loaded)

    def update_background_last_scan(self, last_scan: str):
        self.background_state["last_darknet_scan"] = {"value": last_scan, "timestamp": time.time()}
        self._log_change("background", "last_darknet_scan", None, last_scan)

    # ========== SYSTEM STATE MODIFIERS (Only executor calls these) ==========
    def update_loaded_modules(self, modules: List[str]):
        old = self.system_state["loaded_modules"]["value"]
        self.system_state["loaded_modules"] = {"value": modules, "timestamp": time.time()}
        self._log_change("system", "loaded_modules", old, modules)
        self._refresh_snapshot()

    def update_tor(self, active: bool):
        old = self.system_state["tor"]["value"]
        self.system_state["tor"] = {"value": active, "timestamp": time.time()}
        self._log_change("system", "tor", old, active)
        self._refresh_snapshot()

    def update_workflows(self, count: int):
        old = self.system_state["active_workflows"]["value"]
        self.system_state["active_workflows"] = {"value": count, "timestamp": time.time()}
        self._log_change("system", "active_workflows", old, count)
        self._refresh_snapshot()

    def update_ai_enabled(self, enabled: bool):
        old = self.system_state["ai_enabled"]["value"]
        self.system_state["ai_enabled"] = {"value": enabled, "timestamp": time.time()}
        self._log_change("system", "ai_enabled", old, enabled)
        self._refresh_snapshot()

    # ========== BACKGROUND STATE (No LLM access) ==========
    def update_background_sports(self, count: int):
        old = self.background_state["sports_predictions"]["value"]
        self.background_state["sports_predictions"] = {"value": count, "timestamp": time.time()}
        self._log_change("background", "sports_predictions", old, count)

    def update_background_osint(self, feeds: int):
        old = self.background_state["osint_feeds"]["value"]
        self.background_state["osint_feeds"] = {"value": feeds, "timestamp": time.time()}
        self._log_change("background", "osint_feeds", old, feeds)

    def update_background_notifications(self, count: int):
        old = self.background_state["notifications"]["value"]
        self.background_state["notifications"] = {"value": count, "timestamp": time.time()}
        self._log_change("background", "notifications", old, count)

    # ========== QUERIES ==========
    def get_snapshot(self) -> Dict:
        """LLM sees ONLY this – clean, minimal, filtered."""
        return self.runtime_snapshot

    def get_system_state_raw(self) -> Dict:
        """For /reality-check – bypasses LLM entirely. Returns full truth."""
        return {
            "loaded_modules": self.system_state["loaded_modules"]["value"],
            "tor": self.system_state["tor"]["value"],
            "active_workflows": self.system_state["active_workflows"]["value"],
            "ai_enabled": self.system_state["ai_enabled"]["value"],
            "orchestrator_ready": self.system_state["orchestrator_ready"]["value"],
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    def get_background_summary(self) -> Dict:
        return {
            "sports_predictions": self.background_state.get("sports_predictions", {}).get("value", 0),
            "osint_feeds": self.background_state.get("osint_feeds", {}).get("value", 0),
            "notifications": self.background_state.get("notifications", {}).get("value", 0),
            "trading_loaded": self.background_state.get("trading_loaded", {}).get("value", False),
            "pentest_loaded": self.background_state.get("pentest_loaded", {}).get("value", False),
            "bounty_loaded": self.background_state.get("bounty_loaded", {}).get("value", False),
            "last_darknet_scan": self.background_state.get("last_darknet_scan", {}).get("value", "Never"),
        }

    def get_change_log(self, limit: int = 20) -> List[Dict]:
        """Debugging: see recent state changes."""
        return self.change_log[-limit:]

    # ========== INITIALIZATION ==========
    def initialize_from_core(self, modules: List[str], tor_active: bool, workflows: int, ai_enabled: bool):
        """Called once at startup to sync with actual system."""
        self.update_loaded_modules(modules)
        self.update_tor(tor_active)
        self.update_workflows(workflows)
        self.update_ai_enabled(ai_enabled)