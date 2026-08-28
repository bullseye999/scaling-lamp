#!/usr/bin/env python3
# module_manager.py - Hot-swappable module system WITH PROPER ORCHESTRATOR SUPPORT
# UPDATED: Fixed module passing to orchestrator

import importlib
import sys
from typing import Dict, Any, Optional

class ModuleManager:
    """
    Dynamic module loader - can add/remove modules without restarting Ciph
    FIXED: Properly passes all loaded modules to orchestrator
    """
    
    def __init__(self, vault):
        self.vault = vault
        self.active_modules = {}
        self.available_modules = {
            'osint': 'osint_miner.OSINTMiner',
            'memory': 'memory_engine.MemoryEngine', 
            'pentest': 'pentest_engine.PentestEngine',
            'trading': 'trading_engine.TradingEngine',
            'bounty': 'bounty_hunter.BountyHunter',
            'orchestrator': 'agent_orchestrator.AgentOrchestrator'
        }
        
        # Auto-load core modules
        self.load_module('memory')
        self.load_module('osint')
    
    def load_module(self, module_name: str) -> str:
        """Dynamically load a module with PROPER orchestrator handling"""
        if module_name in self.available_modules:
            try:
                if module_name in self.active_modules:
                    return f"✅ Module {module_name} already loaded"
                
                module_path, class_name = self.available_modules[module_name].split('.')
                module = importlib.import_module(module_path)
                module_class = getattr(module, class_name)
                
                # CRITICAL FIX: Special handling for orchestrator
                if module_name == 'orchestrator':
                    # Pass ALL currently loaded modules (excluding orchestrator itself)
                    modules_for_orchestrator = {}
                    for name, mod in self.active_modules.items():
                        if name != 'orchestrator':  # Don't include self
                            modules_for_orchestrator[name] = mod
                    
                    # Initialize orchestrator with all loaded modules
                    self.active_modules[module_name] = module_class(self.vault, modules_for_orchestrator)
                else:
                    # Regular module initialization
                    self.active_modules[module_name] = module_class(self.vault)
                
                # If orchestrator is already loaded, update it with new module
                if module_name != 'orchestrator' and 'orchestrator' in self.active_modules:
                    print(f"🔧 Adding {module_name} to orchestrator's module list")
                    self.active_modules['orchestrator'].modules[module_name] = self.active_modules[module_name]
                
                return f"✅ Module {module_name} loaded successfully"
                
            except Exception as e:
                return f"❌ Failed to load {module_name}: {e}"
        return f"❌ Unknown module: {module_name}"
    
    def unload_module(self, module_name: str) -> str:
        """Unload a module and remove from orchestrator if needed"""
        if module_name in self.active_modules:
            # Remove from orchestrator if it exists
            if module_name != 'orchestrator' and 'orchestrator' in self.active_modules:
                if hasattr(self.active_modules['orchestrator'], 'modules'):
                    if module_name in self.active_modules['orchestrator'].modules:
                        del self.active_modules['orchestrator'].modules[module_name]
                        print(f"🔧 Removed {module_name} from orchestrator")
            
            del self.active_modules[module_name]
            return f"✅ Module {module_name} unloaded"
        return f"❌ Module {module_name} not active"
    
    def get_module(self, module_name: str) -> Optional[Any]:
        """Get a loaded module instance"""
        return self.active_modules.get(module_name)
    
    def list_modules(self) -> Dict[str, list]:
        """List all available and active modules"""
        orchestrator_module_count = 0
        if 'orchestrator' in self.active_modules and hasattr(self.active_modules['orchestrator'], 'modules'):
            orchestrator_module_count = len(self.active_modules['orchestrator'].modules)
        
        return {
            'available': list(self.available_modules.keys()),
            'active': list(self.active_modules.keys()),
            'orchestrator_has_modules': orchestrator_module_count
        }
    
    def reload_module(self, module_name: str) -> str:
        """Reload a module (for updates)"""
        unload_result = self.unload_module(module_name)
        load_result = self.load_module(module_name)
        return f"{unload_result} | {load_result}"

    def auto_load_orchestrator(self):
        """Load orchestrator with all currently loaded modules."""
        if 'orchestrator' not in self.active_modules:
            # Temporarily load orchestrator
            result = self.load_module('orchestrator')
            if '✅' in result:
                # Ensure orchestrator has all modules
                if hasattr(self.active_modules['orchestrator'], 'modules'):
                    # Modules already passed during load_module, but double-check
                    pass
                return True
        return False
    
    def update_orchestrator_modules(self):
        """Update orchestrator with all current modules"""
        if 'orchestrator' in self.active_modules:
            # Collect all modules except orchestrator
            modules_for_orchestrator = {}
            for name, mod in self.active_modules.items():
                if name != 'orchestrator':
                    modules_for_orchestrator[name] = mod
            
            # Update orchestrator
            if hasattr(self.active_modules['orchestrator'], 'modules'):
                self.active_modules['orchestrator'].modules = modules_for_orchestrator
                return f"✅ Updated orchestrator with {len(modules_for_orchestrator)} modules"
        return "❌ Orchestrator not loaded"

    def check_optional_dependencies(self) -> Dict[str, bool]:
        """Check availability of optional external dependencies"""
        deps = ['stem', 'pqcrypto', 'feedparser', 'requests', 'socks']
        status = {}
        for dep in deps:
            try:
                importlib.import_module(dep)
                status[dep] = True
            except ImportError:
                status[dep] = False
        return status

# Test the module manager
if __name__ == "__main__":
    from cipher_vault import CipherVault
    vault = CipherVault()
    manager = ModuleManager(vault)
    
    print("🧪 Testing Module Manager:")
    print(manager.list_modules())
    print(manager.load_module('trading'))
    print(manager.load_module('orchestrator'))
    print("Final status:", manager.list_modules())