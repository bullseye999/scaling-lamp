#!/usr/bin/env python3
# config_manager.py - Professional configuration system (generic version)

import os
import json
import yaml
from typing import Dict, Any, Optional

class ConfigManager:
    """
    Professional configuration management for the system.
    Supports JSON, YAML, and environment variables.
    """
    
    def __init__(self, vault, config_path: str = "system_config.yaml"):
        self.vault = vault
        self.config_path = config_path
        self.default_config = {
            'version': '0.7',
            'environment': 'development',
            'modules': {
                'memory': {'enabled': True, 'auto_cleanup_days': 30},
                'osint': {'enabled': True, 'scan_interval_hours': 6},
                'security': {'enabled': True, 'auto_backup_hours': 12},
                'scheduler': {'enabled': True, 'start_on_launch': True}
            },
            'ai': {
                'model': 'claude-3-sonnet-20240229',
                'temperature': 0.7,
                'max_tokens': 1000
            },
            'security': {
                'auto_wipe_timeout_hours': 24,
                'max_session_hours': 8,
                'backup_retention_days': 7
            }
        }
        self.current_config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                        return yaml.safe_load(f) or self.default_config
                    else:
                        return json.load(f) or self.default_config
            except Exception:
                pass
        
        env_config = self._load_from_env()
        if env_config:
            return {**self.default_config, **env_config}
        
        self._save_config(self.default_config)
        return self.default_config
    
    def _load_from_env(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_config = {}
        
        # Map environment variables to config structure (generic prefix)
        env_mappings = {
            'APP_ENVIRONMENT': ['environment'],
            'APP_AI_MODEL': ['ai', 'model'],
            'APP_AUTO_BACKUP_HOURS': ['security', 'auto_backup_hours']
        }
        
        for env_var, config_path in env_mappings.items():
            if env_var in os.environ:
                self._set_nested_value(env_config, config_path, os.environ[env_var])
        
        return env_config
    
    def _set_nested_value(self, config_dict: Dict, path: list, value: Any):
        """Set value in nested dictionary"""
        current = config_dict
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
    
    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                    yaml.dump(config, f, default_flow_style=False)
                else:
                    json.dump(config, f, indent=2)
        except Exception:
            pass  # Fail silently for now
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value by dot notation"""
        keys = key_path.split('.')
        current = self.current_config
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        
        return current
    
    def set(self, key_path: str, value: Any):
        """Set configuration value by dot notation"""
        keys = key_path.split('.')
        current = self.current_config
        
        for key in keys[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
        self._save_config(self.current_config)
        
        # Also store in vault for critical settings
        if key_path.startswith('ai.') or key_path.startswith('security.'):
            self.vault.set_config(f"config_{key_path}", str(value))
    
    def get_environment_config(self) -> Dict[str, Any]:
        """Get environment‑specific configuration"""
        environment = self.get('environment', 'development')
        
        env_configs = {
            'development': {
                'log_level': 'DEBUG',
                'enable_debug_commands': True,
                'auto_save_interval': 300  # 5 minutes
            },
            'production': {
                'log_level': 'WARNING',
                'enable_debug_commands': False,
                'auto_save_interval': 60  # 1 minute
            },
            'staging': {
                'log_level': 'INFO',
                'enable_debug_commands': False,
                'auto_save_interval': 120  # 2 minutes
            }
        }
        
        return env_configs.get(environment, env_configs['development'])
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate current configuration"""
        issues = []
        
        # Check required AI settings if AI is enabled
        if self.get('modules.ai.enabled', True):
            api_key = self.vault.get_config("AI_API_KEY")
            if not api_key:
                issues.append("AI API key not configured")
        
        # Check security settings
        auto_wipe = self.get('security.auto_wipe_timeout_hours')
        if auto_wipe and auto_wipe < 1:
            issues.append("Auto-wipe timeout too short (minimum 1 hour)")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'environment': self.get('environment'),
            'version': self.get('version')
        }


if __name__ == "__main__":
    from cipher_vault import CipherVault
    vault = CipherVault()
    config = ConfigManager(vault)
    
    print("🧪 Testing Config Manager:")
    print("Environment:", config.get('environment'))
    print("AI Model:", config.get('ai.model'))
    print("Validation:", config.validate_config())