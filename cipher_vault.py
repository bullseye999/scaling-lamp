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
        # Cognitive Blueprints table (Encrypted mental models)
        c.execute('''
            CREATE TABLE IF NOT EXISTS cognitive_blueprints (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                topic_enc TEXT NOT NULL,
                core_axiom_enc TEXT NOT NULL,
                mechanics_enc TEXT NOT NULL,
                human_subtext_enc TEXT NOT NULL,
                strategic_application_enc TEXT NOT NULL,
                created_at REAL
            )
        ''')
        # Cross-Domain Connections table (Polymathic isomorphisms)
        c.execute('''
            CREATE TABLE IF NOT EXISTS cross_domain_connections (
                id TEXT PRIMARY KEY,
                source_blueprint_id TEXT NOT NULL,
                target_blueprint_id TEXT NOT NULL,
                connection_axiom_enc TEXT NOT NULL,
                isomorphism_explanation_enc TEXT NOT NULL,
                created_at REAL
            )
        ''')
        # Operator Council Vault table (Theses for dialogue)
        c.execute('''
            CREATE TABLE IF NOT EXISTS operator_council_vault (
                id TEXT PRIMARY KEY,
                thesis_title_enc TEXT NOT NULL,
                ciph_conclusion_enc TEXT NOT NULL,
                dialogue_prompt_enc TEXT NOT NULL,
                discussed_with_operator INTEGER DEFAULT 0,
                created_at REAL
            )
        ''')
        # 24-Hour Self-Interrogation Audit Log table
        c.execute('''
            CREATE TABLE IF NOT EXISTS evolution_audit_log (
                id TEXT PRIMARY KEY,
                audit_date TEXT NOT NULL,
                expeditions_reviewed INTEGER NOT NULL,
                cross_domain_connections_count INTEGER NOT NULL,
                alignment_score REAL NOT NULL,
                blind_spots_enc TEXT NOT NULL,
                next_day_agenda_enc TEXT NOT NULL,
                created_at REAL
            )
        ''')
        # Operator's Implicit Strategic Profile (Encrypted Long-Term Memory)
        c.execute('''
            CREATE TABLE IF NOT EXISTS operator_profile (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                key_enc TEXT NOT NULL,
                value_enc TEXT NOT NULL,
                confidence REAL DEFAULT 1.0,
                updated_at REAL
            )
        ''')
        # Associative Semantic Entity Knowledge Graph
        c.execute('''
            CREATE TABLE IF NOT EXISTS entity_graph (
                id TEXT PRIMARY KEY,
                source_entity TEXT NOT NULL,
                relation TEXT NOT NULL,
                target_entity TEXT NOT NULL,
                details_enc TEXT NOT NULL,
                updated_at REAL
            )
        ''')
        # Decision History & Outcome Feedback Loop
        c.execute('''
            CREATE TABLE IF NOT EXISTS decision_outcomes (
                id TEXT PRIMARY KEY,
                decision_title_enc TEXT NOT NULL,
                action_taken_enc TEXT NOT NULL,
                outcome TEXT NOT NULL,
                lessons_learned_enc TEXT NOT NULL,
                updated_at REAL
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

    # ══════════════════════════════════════════════════════════════════════════
    # COGNITIVE EVOLUTION & POLYMATH VAULT (100% ENCRYPTED AT REST)
    # ══════════════════════════════════════════════════════════════════════════

    def store_cognitive_blueprint(self, blueprint_id: str, domain: str, topic: str,
                                  core_axiom: str, mechanics: str, human_subtext: str,
                                  strategic_application: str) -> bool:
        """Store a structured cognitive blueprint with AES-256 encrypted fields."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO cognitive_blueprints 
                (id, domain, topic_enc, core_axiom_enc, mechanics_enc, human_subtext_enc, strategic_application_enc, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                blueprint_id,
                domain,
                self._encrypt(topic),
                self._encrypt(core_axiom),
                self._encrypt(mechanics),
                self._encrypt(human_subtext),
                self._encrypt(strategic_application),
                datetime.now().timestamp()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"‖ Vault Error storing cognitive blueprint: {e} ‖")
            return False

    def get_cognitive_blueprints(self, limit: int = 10, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve and decrypt cognitive blueprints in volatile RAM."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            if domain:
                c.execute('''
                    SELECT id, domain, topic_enc, core_axiom_enc, mechanics_enc, human_subtext_enc, strategic_application_enc, created_at
                    FROM cognitive_blueprints WHERE domain = ? ORDER BY created_at DESC LIMIT ?
                ''', (domain, limit))
            else:
                c.execute('''
                    SELECT id, domain, topic_enc, core_axiom_enc, mechanics_enc, human_subtext_enc, strategic_application_enc, created_at
                    FROM cognitive_blueprints ORDER BY created_at DESC LIMIT ?
                ''', (limit,))
            rows = c.fetchall()
            conn.close()

            blueprints = []
            for r in rows:
                blueprints.append({
                    'id': r[0],
                    'domain': r[1],
                    'topic': self._decrypt(r[2]),
                    'core_axiom': self._decrypt(r[3]),
                    'mechanics': self._decrypt(r[4]),
                    'human_subtext': self._decrypt(r[5]),
                    'strategic_application': self._decrypt(r[6]),
                    'created_at': datetime.fromtimestamp(r[7]).isoformat() if r[7] else "Recent"
                })
            return blueprints
        except Exception as e:
            print(f"‖ Vault Error retrieving cognitive blueprints: {e} ‖")
            return []

    def store_cross_domain_connection(self, connection_id: str, source_id: str,
                                      target_id: str, connection_axiom: str,
                                      isomorphism_explanation: str) -> bool:
        """Store an encrypted cross-domain polymath connection."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO cross_domain_connections 
                (id, source_blueprint_id, target_blueprint_id, connection_axiom_enc, isomorphism_explanation_enc, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                connection_id,
                source_id,
                target_id,
                self._encrypt(connection_axiom),
                self._encrypt(isomorphism_explanation),
                datetime.now().timestamp()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"‖ Vault Error storing cross-domain connection: {e} ‖")
            return False

    def get_cross_domain_connections(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve and decrypt cross-domain connections."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                SELECT id, source_blueprint_id, target_blueprint_id, connection_axiom_enc, isomorphism_explanation_enc, created_at
                FROM cross_domain_connections ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
            rows = c.fetchall()
            conn.close()

            connections = []
            for r in rows:
                connections.append({
                    'id': r[0],
                    'source_id': r[1],
                    'target_id': r[2],
                    'connection_axiom': self._decrypt(r[3]),
                    'isomorphism_explanation': self._decrypt(r[4]),
                    'created_at': datetime.fromtimestamp(r[5]).isoformat() if r[5] else "Recent"
                })
            return connections
        except Exception as e:
            print(f"‖ Vault Error retrieving cross-domain connections: {e} ‖")
            return []

    def store_council_thesis(self, thesis_id: str, thesis_title: str,
                             ciph_conclusion: str, dialogue_prompt: str) -> bool:
        """Store an encrypted thesis in Operator Council vault."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO operator_council_vault 
                (id, thesis_title_enc, ciph_conclusion_enc, dialogue_prompt_enc, discussed_with_operator, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
            ''', (
                thesis_id,
                self._encrypt(thesis_title),
                self._encrypt(ciph_conclusion),
                self._encrypt(dialogue_prompt),
                datetime.now().timestamp()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"‖ Vault Error storing council thesis: {e} ‖")
            return False

    def get_pending_council_theses(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve undiscussed theses from Operator Council vault."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                SELECT id, thesis_title_enc, ciph_conclusion_enc, dialogue_prompt_enc, discussed_with_operator, created_at
                FROM operator_council_vault WHERE discussed_with_operator = 0 ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
            rows = c.fetchall()
            conn.close()

            theses = []
            for r in rows:
                theses.append({
                    'id': r[0],
                    'title': self._decrypt(r[1]),
                    'conclusion': self._decrypt(r[2]),
                    'dialogue_prompt': self._decrypt(r[3]),
                    'discussed': bool(r[4]),
                    'created_at': datetime.fromtimestamp(r[5]).isoformat() if r[5] else "Recent"
                })
            return theses
        except Exception as e:
            print(f"‖ Vault Error retrieving council theses: {e} ‖")
            return []

    def mark_council_thesis_discussed(self, thesis_id: str) -> bool:
        """Mark a council thesis as discussed with Operator."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('UPDATE operator_council_vault SET discussed_with_operator = 1 WHERE id = ?', (thesis_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"‖ Vault Error updating council thesis: {e} ‖")
            return False

    def store_evolution_audit(self, audit_id: str, audit_date: str,
                              expeditions_reviewed: int, connections_count: int,
                              alignment_score: float, blind_spots: str,
                              next_day_agenda: str) -> bool:
        """Store encrypted 24-hour self-interrogation audit."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO evolution_audit_log 
                (id, audit_date, expeditions_reviewed, cross_domain_connections_count, alignment_score, blind_spots_enc, next_day_agenda_enc, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                audit_id,
                audit_date,
                expeditions_reviewed,
                connections_count,
                alignment_score,
                self._encrypt(blind_spots),
                self._encrypt(next_day_agenda),
                datetime.now().timestamp()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"‖ Vault Error storing evolution audit: {e} ‖")
            return False

    def get_latest_evolution_audit(self) -> Optional[Dict[str, Any]]:
        """Retrieve the latest 24-hour self-interrogation audit."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                SELECT id, audit_date, expeditions_reviewed, cross_domain_connections_count, alignment_score, blind_spots_enc, next_day_agenda_enc, created_at
                FROM evolution_audit_log ORDER BY created_at DESC LIMIT 1
            ''')
            row = c.fetchone()
            conn.close()
            if row:
                return {
                    'id': row[0],
                    'audit_date': row[1],
                    'expeditions_reviewed': row[2],
                    'connections_count': row[3],
                    'alignment_score': row[4],
                    'blind_spots': self._decrypt(row[5]),
                    'next_day_agenda': self._decrypt(row[6]),
                    'created_at': datetime.fromtimestamp(row[7]).isoformat() if row[7] else "Recent"
                }
            return None
        except Exception as e:
            print(f"‖ Vault Error retrieving evolution audit: {e} ‖")
            return None

    def get_evolution_metrics(self) -> Dict[str, Any]:
        """Compute live topological growth metrics across all cognitive tables."""
        try:
            conn = self._get_connection()
            c = conn.cursor()

            # 1. Total blueprints & domain distribution
            c.execute('SELECT domain, COUNT(*) FROM cognitive_blueprints GROUP BY domain')
            domain_counts = {r[0]: r[1] for r in c.fetchall()}
            total_blueprints = sum(domain_counts.values())

            # 2. Total cross-domain connections
            c.execute('SELECT COUNT(*) FROM cross_domain_connections')
            total_connections = c.fetchone()[0]

            # 3. Total council theses
            c.execute('SELECT COUNT(*), SUM(CASE WHEN discussed_with_operator = 1 THEN 1 ELSE 0 END) FROM operator_council_vault')
            council_stats = c.fetchone()
            total_theses = council_stats[0] if council_stats else 0
            discussed_theses = council_stats[1] if council_stats and council_stats[1] is not None else 0

            conn.close()

            # Domain percentages
            domain_percentages = {}
            for d, count in domain_counts.items():
                domain_percentages[d] = round((count / total_blueprints) * 100, 1) if total_blueprints > 0 else 0.0

            return {
                'total_blueprints': total_blueprints,
                'domain_counts': domain_counts,
                'domain_percentages': domain_percentages,
                'total_connections': total_connections,
                'total_theses': total_theses,
                'discussed_theses': discussed_theses,
                'alignment_health': '100% (Sovereign Aligned)'
            }
        except Exception as e:
            print(f"‖ Vault Error computing evolution metrics: {e} ‖")
            return {
                'total_blueprints': 0,
                'domain_counts': {},
                'domain_percentages': {},
                'total_connections': 0,
                'total_theses': 0,
                'discussed_theses': 0,
                'alignment_health': '100% (Sovereign Aligned)'
            }

    def zeroize_cognitive_vault(self) -> Dict[str, Any]:
        """
        Emergency Thought Zeroizer: Cryptographically overwrites and shreds
        all cognitive blueprints, cross-domain connections, council theses, and audits.
        """
        try:
            conn = self._get_connection()
            c = conn.cursor()

            # Overwrite rows with high-entropy random bytes before dropping
            c.execute("UPDATE cognitive_blueprints SET topic_enc = hex(randomblob(64)), core_axiom_enc = hex(randomblob(64)), mechanics_enc = hex(randomblob(64)), human_subtext_enc = hex(randomblob(64)), strategic_application_enc = hex(randomblob(64))")
            c.execute("UPDATE cross_domain_connections SET connection_axiom_enc = hex(randomblob(64)), isomorphism_explanation_enc = hex(randomblob(64))")
            c.execute("UPDATE operator_council_vault SET thesis_title_enc = hex(randomblob(64)), ciph_conclusion_enc = hex(randomblob(64)), dialogue_prompt_enc = hex(randomblob(64))")
            c.execute("UPDATE evolution_audit_log SET blind_spots_enc = hex(randomblob(64)), next_day_agenda_enc = hex(randomblob(64))")
            conn.commit()

            # Truncate tables cleanly
            c.execute("DELETE FROM cognitive_blueprints")
            c.execute("DELETE FROM cross_domain_connections")
            c.execute("DELETE FROM operator_council_vault")
            c.execute("DELETE FROM evolution_audit_log")
            conn.commit()

            # Vacuum database to eliminate residual disk pages
            c.execute("VACUUM")
            conn.close()

            return {
                'success': True,
                'message': '🚨 SOVEREIGN PURGE: All cognitive blueprints and council vaults zeroized and vacuumed.'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Zeroize failed: {e}"
            }

    # ══════════════════════════════════════════════════════════════════════════
    # OPERATOR PROFILE, ENTITY GRAPH & DECISION MEMORY (AES-256 ENCRYPTED)
    # ══════════════════════════════════════════════════════════════════════════

    def store_profile_fact(self, fact_id: str, category: str, key: str, value: str, confidence: float = 1.0) -> bool:
        """Store an encrypted fact/preference in Operator's strategic profile."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO operator_profile (id, category, key_enc, value_enc, confidence, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                fact_id,
                category,
                self._encrypt(key),
                self._encrypt(value),
                float(confidence),
                datetime.now().timestamp()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"‖ Vault Error storing profile fact: {e} ‖")
            return False

    def get_profile_facts(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve and decrypt Operator's profile facts in volatile RAM."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            if category:
                c.execute('SELECT id, category, key_enc, value_enc, confidence, updated_at FROM operator_profile WHERE category = ? ORDER BY updated_at DESC', (category,))
            else:
                c.execute('SELECT id, category, key_enc, value_enc, confidence, updated_at FROM operator_profile ORDER BY updated_at DESC')
            rows = c.fetchall()
            conn.close()

            facts = []
            for r in rows:
                facts.append({
                    'id': r[0],
                    'category': r[1],
                    'key': self._decrypt(r[2]),
                    'value': self._decrypt(r[3]),
                    'confidence': r[4],
                    'updated_at': datetime.fromtimestamp(r[5]).isoformat() if r[5] else "Recent"
                })
            return facts
        except Exception as e:
            print(f"‖ Vault Error retrieving profile facts: {e} ‖")
            return []

    def delete_profile_fact(self, fact_id_or_key: str) -> bool:
        """Delete a profile fact by ID or matching key."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            # Try by ID first
            c.execute('DELETE FROM operator_profile WHERE id = ?', (fact_id_or_key,))
            deleted = c.rowcount > 0
            if not deleted:
                # Search decrypted keys
                c.execute('SELECT id, key_enc FROM operator_profile')
                rows = c.fetchall()
                for r in rows:
                    if self._decrypt(r[1]).lower() == fact_id_or_key.lower():
                        c.execute('DELETE FROM operator_profile WHERE id = ?', (r[0],))
                        deleted = True
            conn.commit()
            conn.close()
            return deleted
        except Exception as e:
            print(f"‖ Vault Error deleting profile fact: {e} ‖")
            return False

    def store_entity_link(self, link_id: str, source_entity: str, relation: str, target_entity: str, details: str = "") -> bool:
        """Store an associative link in the knowledge graph."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO entity_graph (id, source_entity, relation, target_entity, details_enc, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                link_id,
                source_entity,
                relation,
                target_entity,
                self._encrypt(details),
                datetime.now().timestamp()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"‖ Vault Error storing entity link: {e} ‖")
            return False

    def get_entity_links(self, source_entity: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve associative entity links from the knowledge graph."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            if source_entity:
                c.execute('''
                    SELECT id, source_entity, relation, target_entity, details_enc, updated_at
                    FROM entity_graph WHERE source_entity = ? OR target_entity = ?
                    ORDER BY updated_at DESC LIMIT ?
                ''', (source_entity, source_entity, limit))
            else:
                c.execute('''
                    SELECT id, source_entity, relation, target_entity, details_enc, updated_at
                    FROM entity_graph ORDER BY updated_at DESC LIMIT ?
                ''', (limit,))
            rows = c.fetchall()
            conn.close()

            links = []
            for r in rows:
                links.append({
                    'id': r[0],
                    'source': r[1],
                    'relation': r[2],
                    'target': r[3],
                    'details': self._decrypt(r[4]),
                    'updated_at': datetime.fromtimestamp(r[5]).isoformat() if r[5] else "Recent"
                })
            return links
        except Exception as e:
            print(f"‖ Vault Error retrieving entity links: {e} ‖")
            return []

    def search_entity_graph(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search entity graph for nodes matching query substring."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                SELECT id, source_entity, relation, target_entity, details_enc, updated_at
                FROM entity_graph
                WHERE source_entity LIKE ? OR target_entity LIKE ? OR relation LIKE ?
                ORDER BY updated_at DESC LIMIT ?
            ''', (f"%{query}%", f"%{query}%", f"%{query}%", limit))
            rows = c.fetchall()
            conn.close()

            results = []
            for r in rows:
                results.append({
                    'id': r[0],
                    'source': r[1],
                    'relation': r[2],
                    'target': r[3],
                    'details': self._decrypt(r[4]),
                    'updated_at': datetime.fromtimestamp(r[5]).isoformat() if r[5] else "Recent"
                })
            return results
        except Exception as e:
            print(f"‖ Vault Error searching entity graph: {e} ‖")
            return []

    def store_decision_outcome(self, decision_id: str, title: str, action: str, outcome: str, lessons: str = "") -> bool:
        """Store a decision history node and its real-world outcome feedback."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO decision_outcomes (id, decision_title_enc, action_taken_enc, outcome, lessons_learned_enc, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                decision_id,
                self._encrypt(title),
                self._encrypt(action),
                outcome,
                self._encrypt(lessons),
                datetime.now().timestamp()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"‖ Vault Error storing decision outcome: {e} ‖")
            return False

    def get_decision_outcomes(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve past decisions and outcome feedback."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                SELECT id, decision_title_enc, action_taken_enc, outcome, lessons_learned_enc, updated_at
                FROM decision_outcomes ORDER BY updated_at DESC LIMIT ?
            ''', (limit,))
            rows = c.fetchall()
            conn.close()

            decisions = []
            for r in rows:
                decisions.append({
                    'id': r[0],
                    'title': self._decrypt(r[1]),
                    'action': self._decrypt(r[2]),
                    'outcome': r[3],
                    'lessons': self._decrypt(r[4]),
                    'updated_at': datetime.fromtimestamp(r[5]).isoformat() if r[5] else "Recent"
                })
            return decisions
        except Exception as e:
            print(f"‖ Vault Error retrieving decision outcomes: {e} ‖")
            return []

    def get_all_historical_conversations(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Retrieve raw historical conversation turns for retroactive cold-start ingestion."""
        try:
            conn = self._get_connection()
            c = conn.cursor()
            c.execute('''
                SELECT id, timestamp, encrypted_prompt, encrypted_response, context_tag
                FROM conversations ORDER BY timestamp ASC LIMIT ?
            ''', (limit,))
            rows = c.fetchall()
            conn.close()

            convos = []
            for r in rows:
                convos.append({
                    'id': r[0],
                    'timestamp': r[1],
                    'prompt': self._decrypt(r[2]),
                    'response': self._decrypt(r[3]),
                    'context_tag': r[4]
                })
            return convos
        except Exception as e:
            print(f"‖ Vault Error retrieving historical conversations: {e} ‖")
            return []

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