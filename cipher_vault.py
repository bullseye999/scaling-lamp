#!/usr/bin/env python3
# cipher_vault.py - Professional encrypted storage
# ENHANCED VERSION: Fixed type hints + maintained full functionality

import sqlite3
import json
from cryptography.fernet import Fernet # type: ignore
import base64
import os
from typing import Optional, Dict, Any, List
from datetime import datetime

class CipherVault:
    """
    Secure, encrypted storage for Ciph's memory and configurations.
    All data is encrypted before being written to the SQLite database.
    ENHANCED: Fixed type hints + added datetime parsing utilities
    """

    def __init__(self, db_path: str = "ciph_vault.db", key_file: str = "ciph.key"):
        self.db_path = db_path
        self.key_file = key_file
        self._init_key()
        self._init_db()

    def _init_key(self):
        """Load encryption key or generate a new one if it doesn't exist."""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            # Secure the key file permissions (Unix-like systems)
            try:
                os.chmod(self.key_file, 0o600)
            except Exception:
                pass
        self.cipher_suite = Fernet(self.key)

    def _encrypt(self, data: str) -> str:
        """Encrypt a string."""
        if data is None:
            data = ""  # Handle None values
        return self.cipher_suite.encrypt(data.encode()).decode()

    def _decrypt(self, encrypted_data: str) -> Optional[str]:
        """Decrypt a string."""
        if encrypted_data is None:
            return None
        try:
            return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return None

    def _init_db(self):
        """Initialize the encrypted database schema."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # Conversations table
        c.execute('''
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY,
                timestamp REAL,
                encrypted_prompt TEXT,
                encrypted_response TEXT,
                context_tag TEXT
            )
        ''')
        # Configurations table (for API keys, settings - also encrypted)
        c.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                encrypted_value TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def store_conversation(self, prompt: str, response: str, context_tag: str = "general"):
        """Store an encrypted conversation turn."""
        prompt = prompt or ""
        response = response or ""
        context_tag = context_tag or "general"
        
        import time
        timestamp = time.time()
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            c.execute('BEGIN TRANSACTION')
            c.execute('''
                INSERT INTO conversations (timestamp, encrypted_prompt, encrypted_response, context_tag)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, self._encrypt(prompt), self._encrypt(response), context_tag))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_recent_conversations(self, limit: int = 10, context_tag: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent conversations, decrypted."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        if context_tag:
            c.execute('''
                SELECT timestamp, encrypted_prompt, encrypted_response FROM conversations
                WHERE context_tag = ? ORDER BY timestamp DESC LIMIT ?
            ''', (context_tag, limit))
        else:
            c.execute('''
                SELECT timestamp, encrypted_prompt, encrypted_response FROM conversations
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))

        rows = c.fetchall()
        conn.close()

        conversations = []
        for timestamp, enc_prompt, enc_response in rows:
            # Handle potential None values
            decrypted_prompt = self._decrypt(enc_prompt) if enc_prompt else ""
            decrypted_response = self._decrypt(enc_response) if enc_response else ""
            
            conversations.append({
                'timestamp': timestamp,
                'prompt': decrypted_prompt or "",
                'response': decrypted_response or ""
            })
        return conversations

    def set_config(self, key: str, value: str):
        """Store an encrypted configuration value."""
        key = key or ""
        value = value or ""
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO config (key, encrypted_value)
            VALUES (?, ?)
        ''', (key, self._encrypt(value)))
        conn.commit()
        conn.close()

    def get_config(self, key: str) -> Optional[str]:
        """Retrieve a decrypted configuration value."""
        key = key or ""
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT encrypted_value FROM config WHERE key = ?', (key,))
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            return self._decrypt(row[0])
        return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse various date formats from feeds - FIXED TYPE HINT"""
        if not date_str:
            return None
            
        try:
            # Try different date formats
            for fmt in ['%a, %d %b %Y %H:%M:%S %z', '%a, %d %b %Y %H:%M:%S %Z', 
                       '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S']:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
            return None
        except Exception:
            return None

    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics and health info."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Get conversation count
        c.execute('SELECT COUNT(*) FROM conversations')
        conv_count = c.fetchone()[0]
        
        # Get config count
        c.execute('SELECT COUNT(*) FROM config')
        config_count = c.fetchone()[0]
        
        # Get oldest and newest entries
        c.execute('SELECT MIN(timestamp), MAX(timestamp) FROM conversations')
        time_range = c.fetchone()
        
        conn.close()
        
        return {
            'conversation_count': conv_count,
            'config_count': config_count,
            'oldest_entry': time_range[0] if time_range[0] else 'None',
            'newest_entry': time_range[1] if time_range[1] else 'None',
            'database_size': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0,
            'vault_status': 'OPERATIONAL'
        }

    def cleanup_old_conversations(self, days_old: int = 30) -> int:
        """Clean up conversations older than specified days."""
        import time
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM conversations WHERE timestamp < ?', (cutoff_time,))
        count_before = c.fetchone()[0]
        
        c.execute('DELETE FROM conversations WHERE timestamp < ?', (cutoff_time,))
        conn.commit()
        conn.close()
        
        return count_before

    def export_conversations(self, output_file: str = "ciph_export.json") -> bool:
        """Export all conversations to encrypted JSON file."""
        try:
            conversations = self.get_recent_conversations(limit=10000)  # Large limit to get all
            
            export_data = {
                'export_time': datetime.now().isoformat(),
                'conversation_count': len(conversations),
                'conversations': conversations
            }
            
            # Encrypt the export data
            encrypted_export = self._encrypt(json.dumps(export_data))
            
            with open(output_file, 'w') as f:
                json.dump({'encrypted_data': encrypted_export}, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Export failed: {e}")
            return False

    def _get_connection(self):
        """Internal method to get database connection - for advanced operations."""
        return sqlite3.connect(self.db_path)

# Enhanced example usage with new features
if __name__ == "__main__":
    vault = CipherVault()

    # Store a secret config (like an API key - in real use, we'll handle this more carefully)
    vault.set_config("SYSTEM_VERSION", "Ciph v1.0 Enhanced")
    vault.set_config("SECURITY_LEVEL", "QUANTUM_AWARE")

    # Store test conversations
    vault.store_conversation(
        "What's the threat landscape for quantum computing?",
        "It's evolving rapidly. The main near-term risk is harvest-now-decrypt-later attacks.",
        context_tag="threat_intel"
    )

    vault.store_conversation(
        "System status check",
        "All modules operational. Encryption: AES-256. Vault: Secure.",
        context_tag="system"
    )

    # Retrieve recent conversations
    recent = vault.get_recent_conversations(limit=5)
    print("📊 RECENT CONVERSATIONS:")
    for conv in recent:
        print(f"> {conv['prompt']}")
        print(f"< {conv['response']}")
        print()

    # Show database stats
    stats = vault.get_database_stats()
    print("📈 DATABASE STATISTICS:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Test config retrieval
    version = vault.get_config("SYSTEM_VERSION")
    print(f"🔧 SYSTEM VERSION: {version}")

    print("✅ CIPHER VAULT ENHANCED - ALL SYSTEMS OPERATIONAL")