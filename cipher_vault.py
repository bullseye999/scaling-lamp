#!/usr/bin/env python3
# cipher_vault.py - Professional encrypted storage
# ENHANCED VERSION: Fixed type hints + maintained full functionality

import sqlite3
import json
from cryptography.fernet import Fernet, MultiFernet # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import Optional, Dict, Any, List
from datetime import datetime

class CipherVault:
    """
    Secure, encrypted storage for Ciph's memory and configurations.
    All data is encrypted before being written to the SQLite database.
    ENHANCED: PBKDF2 key derivation + MultiFernet backwards compatibility + strict WAL mode.
    """

    def __init__(self, db_path: str = "ciph_vault.db", key_file: str = "ciph.key", salt_file: str = "ciph.salt"):
        self.db_path = db_path
        self.key_file = key_file
        self.salt_file = salt_file
        self._init_key()
        self._init_db()

    def _init_key(self):
        """Derive encryption key using PBKDF2HMAC with random salt and passphrase, supporting legacy keys seamlessly."""
        # 1. Manage persistent salt
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            try:
                os.chmod(self.salt_file, 0o600)
            except Exception:
                pass

        # 2. Derive key from passphrase using PBKDF2HMAC (SHA256, 480,000 iterations)
        passphrase = os.getenv("CIPH_VAULT_PASSPHRASE", "REDACTED_LEGACY_VALUE").encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
            backend=default_backend()
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(passphrase))
        
        # 3. Setup MultiFernet for seamless backward compatibility with existing vaults
        fernet_instances = [Fernet(self.key)]
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'rb') as f:
                    legacy_key = f.read().strip()
                if legacy_key and legacy_key != self.key:
                    fernet_instances.append(Fernet(legacy_key))
            except Exception:
                pass
        
        self.cipher_suite = MultiFernet(fernet_instances)

    def _encrypt(self, data: str) -> str:
        """Encrypt a string."""
        if data is None:
            data = ""  # Handle None values
        return self.cipher_suite.encrypt(data.encode()).decode()

    def _decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt an encrypted string.
        Raises cryptography.fernet.InvalidToken or ValueError on invalid/corrupted payloads.
        """
        if not encrypted_data:
            return ""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection configured with WAL mode and busy timeout."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def _init_db(self):
        """Initialize the encrypted database schema."""
        conn = self._get_connection()
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
        # Narrative Timeline table (Episodic memory milestones)
        c.execute('''
            CREATE TABLE IF NOT EXISTS narrative_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                encrypted_summary TEXT,
                encrypted_targets TEXT,
                encrypted_decisions TEXT,
                context_tag TEXT
            )
        ''')
        # Bounty Scopes table
        c.execute('''
            CREATE TABLE IF NOT EXISTS bounty_scopes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                program_name TEXT,
                encrypted_scope_json TEXT,
                is_active INTEGER DEFAULT 1
            )
        ''')
        # Bounty Reports Index table
        c.execute('''
            CREATE TABLE IF NOT EXISTS bounty_reports_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                target TEXT,
                vuln_type TEXT,
                cvss_score REAL,
                severity TEXT,
                report_path TEXT,
                status TEXT DEFAULT 'DRAFT'
            )
        ''')
        # Historical Recon Snapshots table (for diffing & change detection)
        c.execute('''
            CREATE TABLE IF NOT EXISTS recon_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                target TEXT,
                encrypted_snapshot_json TEXT,
                asset_count INTEGER
            )
        ''')
        # Watchtower Events table (for passive sensor alerts)
        c.execute('''
            CREATE TABLE IF NOT EXISTS watchtower_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                target TEXT,
                event_type TEXT,
                details TEXT,
                severity TEXT DEFAULT 'INFO'
            )
        ''')
        # OPSEC Score History table (for tracking anonymity trends over time)
        c.execute('''
            CREATE TABLE IF NOT EXISTS opsec_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                score INTEGER,
                exit_ip TEXT,
                latency_ms REAL,
                status TEXT,
                details TEXT
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
        conn = self._get_connection()
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
        conn = self._get_connection()
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
        
        conn = self._get_connection()
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
        
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('SELECT encrypted_value FROM config WHERE key = ?', (key,))
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            try:
                return self._decrypt(row[0])
            except Exception:
                return None
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
        conn = self._get_connection()
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

    def store_narrative_milestone(self, summary: str, targets: str = "", decisions: str = "", tag: str = "strategic") -> int:
        """Store an episodic narrative milestone."""
        import time
        t = time.time()
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO narrative_timeline (timestamp, encrypted_summary, encrypted_targets, encrypted_decisions, context_tag)
            VALUES (?, ?, ?, ?, ?)
        ''', (t, self._encrypt(summary), self._encrypt(targets), self._encrypt(decisions), tag))
        row_id = c.lastrowid
        conn.commit()
        conn.close()
        return row_id

    def get_narrative_milestones(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve recent narrative milestones."""
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, timestamp, encrypted_summary, encrypted_targets, encrypted_decisions, context_tag
            FROM narrative_timeline
            ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        rows = c.fetchall()
        conn.close()
        milestones = []
        for r in rows:
            milestones.append({
                'id': r[0],
                'timestamp': r[1],
                'summary': self._decrypt(r[2]) or "",
                'targets': self._decrypt(r[3]) or "",
                'decisions': self._decrypt(r[4]) or "",
                'tag': r[5]
            })
        return milestones

    def store_bounty_scope(self, program_name: str, scope_dict: Dict[str, Any]) -> int:
        """Store an ingested bounty scope."""
        import time
        t = time.time()
        scope_json = json.dumps(scope_dict)
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO bounty_scopes (timestamp, program_name, encrypted_scope_json, is_active)
            VALUES (?, ?, ?, 1)
        ''', (t, program_name, self._encrypt(scope_json)))
        row_id = c.lastrowid
        conn.commit()
        conn.close()
        return row_id

    def get_active_bounty_scopes(self) -> List[Dict[str, Any]]:
        """Get all active bug bounty scopes."""
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, timestamp, program_name, encrypted_scope_json
            FROM bounty_scopes WHERE is_active = 1
            ORDER BY timestamp DESC
        ''')
        rows = c.fetchall()
        conn.close()
        scopes = []
        for r in rows:
            raw_json = self._decrypt(r[3]) or "{}"
            try:
                data = json.loads(raw_json)
            except Exception:
                data = {}
            scopes.append({
                'id': r[0],
                'timestamp': r[1],
                'program_name': r[2],
                'scope': data
            })
        return scopes

    def store_bounty_report_index(self, target: str, vuln_type: str, cvss_score: float, severity: str, report_path: str, status: str = "DRAFT") -> int:
        """Index a generated bounty report."""
        import time
        t = time.time()
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO bounty_reports_index (timestamp, target, vuln_type, cvss_score, severity, report_path, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (t, target, vuln_type, cvss_score, severity, report_path, status))
        row_id = c.lastrowid
        conn.commit()
        conn.close()
        return row_id

    def get_bounty_reports_index(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List all indexed bug bounty reports."""
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, timestamp, target, vuln_type, cvss_score, severity, report_path, status
            FROM bounty_reports_index
            ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        rows = c.fetchall()
        conn.close()
        reports = []
        for r in rows:
            reports.append({
                'id': r[0],
                'timestamp': r[1],
                'target': r[2],
                'vuln_type': r[3],
                'cvss_score': r[4],
                'severity': r[5],
                'report_path': r[6],
                'status': r[7]
            })
        return reports

    def store_recon_snapshot(self, target: str, snapshot_dict: Dict[str, Any]) -> int:
        """Store a recon snapshot for historical diffing."""
        import time
        t = time.time()
        snapshot_json = json.dumps(snapshot_dict)
        asset_count = len(snapshot_dict.get("subdomains", [])) + len(snapshot_dict.get("exposed_endpoints", [])) + len(snapshot_dict.get("js_endpoints", []))
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO recon_snapshots (timestamp, target, encrypted_snapshot_json, asset_count)
            VALUES (?, ?, ?, ?)
        ''', (t, target.lower(), self._encrypt(snapshot_json), asset_count))
        row_id = c.lastrowid
        conn.commit()
        conn.close()
        return row_id

    def get_recent_recon_snapshots(self, target: str, limit: int = 3) -> List[Dict[str, Any]]:
        """Retrieve recent recon snapshots for a target domain."""
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, timestamp, target, encrypted_snapshot_json, asset_count
            FROM recon_snapshots
            WHERE target = ?
            ORDER BY timestamp DESC LIMIT ?
        ''', (target.lower(), limit))
        rows = c.fetchall()
        conn.close()
        snapshots = []
        for r in rows:
            raw_json = self._decrypt(r[3]) or "{}"
            try:
                data = json.loads(raw_json)
            except Exception:
                data = {}
            snapshots.append({
                'id': r[0],
                'timestamp': r[1],
                'target': r[2],
                'snapshot': data,
                'asset_count': r[4]
            })
        return snapshots

    def store_watchtower_event(self, target: str, event_type: str, details: str, severity: str = "INFO") -> int:
        """Store a passive sensor alert or change detection event."""
        import time
        t = time.time()
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO watchtower_events (timestamp, target, event_type, details, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (t, target.lower(), event_type, details, severity))
        row_id = c.lastrowid
        conn.commit()
        conn.close()
        return row_id

    def get_recent_watchtower_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent watchtower events."""
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, timestamp, target, event_type, details, severity
            FROM watchtower_events
            ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        rows = c.fetchall()
        conn.close()
        events = []
        for r in rows:
            events.append({
                'id': r[0],
                'timestamp': r[1],
                'target': r[2],
                'event_type': r[3],
                'details': r[4],
                'severity': r[5]
            })
        return events

    def store_opsec_audit(self, score: int, exit_ip: str, latency_ms: float, status: str, details: str = "") -> int:
        """Store an OPSEC score snapshot in history."""
        import time
        t = time.time()
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO opsec_history (timestamp, score, exit_ip, latency_ms, status, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (t, score, exit_ip, latency_ms, status, details))
        row_id = c.lastrowid
        conn.commit()
        conn.close()
        return row_id

    def get_opsec_history(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Retrieve historical OPSEC audit snapshots."""
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, timestamp, score, exit_ip, latency_ms, status, details
            FROM opsec_history
            ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        rows = c.fetchall()
        conn.close()
        history = []
        for r in rows:
            history.append({
                'id': r[0],
                'timestamp': r[1],
                'score': r[2],
                'exit_ip': r[3],
                'latency_ms': r[4],
                'status': r[5],
                'details': r[6]
            })
        return history

    def get_global_assets_summary(self) -> Dict[str, Any]:
        """Aggregate all unique assets discovered across all targets."""
        conn = self._get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT target, encrypted_snapshot_json, timestamp
            FROM recon_snapshots
            ORDER BY timestamp DESC
        ''')
        rows = c.fetchall()
        conn.close()

        all_subdomains = set()
        all_endpoints = set()
        all_js_routes = set()
        targets_tracked = set()

        for target, enc_json, ts in rows:
            raw_json = self._decrypt(enc_json) or "{}"
            try:
                data = json.loads(raw_json)
                targets_tracked.add(target)
                for s in data.get("subdomains", []):
                    all_subdomains.add(s)
                for ep in data.get("exposed_endpoints", []):
                    all_endpoints.add(f"{target}{ep.get('path', '')}")
                for js_r in data.get("js_endpoints", []):
                    all_js_routes.add(js_r.get("endpoint", ""))
            except Exception:
                pass

        return {
            "targets_count": len(targets_tracked),
            "targets": sorted(list(targets_tracked)),
            "subdomains_count": len(all_subdomains),
            "subdomains": sorted(list(all_subdomains)),
            "exposed_endpoints_count": len(all_endpoints),
            "exposed_endpoints": sorted(list(all_endpoints)),
            "js_routes_count": len(all_js_routes),
            "js_routes": sorted(list(all_js_routes))
        }

    def cleanup_old_conversations(self, days_old: int = 30) -> int:
        """Clean up conversations older than specified days."""
        import time
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        
        conn = self._get_connection()
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

    # ─────────────────────────────────────────────
    # SESSION & TELEMETRY LIFECYCLE TRACKING
    # ─────────────────────────────────────────────

    def record_session_start(self) -> Dict[str, Any]:
        """
        Record session start timestamp and calculate elapsed time away since last session.
        """
        import time
        now = datetime.now()
        now_iso = now.isoformat()
        last_end_iso = self.get_config("SESSION_LAST_END")
        
        elapsed_seconds = 0.0
        elapsed_formatted = "First session today"
        is_first_session = True
        
        if last_end_iso:
            try:
                last_end_dt = datetime.fromisoformat(last_end_iso)
                elapsed_seconds = max(0.0, (now - last_end_dt).total_seconds())
                is_first_session = False
                
                hours = int(elapsed_seconds // 3600)
                minutes = int((elapsed_seconds % 3600) // 60)
                if hours > 24:
                    days = hours // 24
                    rem_hours = hours % 24
                    elapsed_formatted = f"{days}d {rem_hours}h {minutes}m"
                elif hours > 0:
                    elapsed_formatted = f"{hours}h {minutes}m"
                elif minutes > 0:
                    elapsed_formatted = f"{minutes} minutes"
                else:
                    elapsed_formatted = f"{int(elapsed_seconds)} seconds"
            except Exception:
                is_first_session = True
                elapsed_formatted = "Recent session"

        self.set_config("SESSION_CURRENT_START", now_iso)
        return {
            "is_first_session": is_first_session,
            "elapsed_seconds": elapsed_seconds,
            "elapsed_formatted": elapsed_formatted,
            "last_end_time": last_end_iso,
            "current_start_time": now_iso
        }

    def record_session_end(self):
        """Record session shutdown timestamp."""
        now_iso = datetime.now().isoformat()
        self.set_config("SESSION_LAST_END", now_iso)

    def save_telemetry_digest(self, digest: Dict[str, Any]):
        """Store the latest real-world & darknet telemetry digest in encrypted vault config."""
        self.set_config("LATEST_TELEMETRY_DIGEST", json.dumps(digest))

    def get_telemetry_digest(self) -> Optional[Dict[str, Any]]:
        """Retrieve the latest real-world & darknet telemetry digest from encrypted vault config."""
        raw = self.get_config("LATEST_TELEMETRY_DIGEST")
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                return None
        return None

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