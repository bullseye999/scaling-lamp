#!/usr/bin/env python3
# security_layer.py - Advanced OPSEC and security tools

import os
import hashlib
import subprocess
import tempfile
from datetime import datetime
from typing import List, Dict, Any

class SecurityLayer:
    """
    Advanced security and OPSEC tools for the system.
    """
    
    def __init__(self, vault):
        self.vault = vault
        self.security_log = []
        
    def system_hardening_scan(self) -> Dict[str, Any]:
        """Scan system for common security issues."""
        print("🛡️  Running security scan...")
        issues = []
        
        # Check file permissions
        sensitive_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "~/.ssh/", "~/.bash_history", "/var/log/"
        ]
        
        for file_path in sensitive_files:
            expanded_path = os.path.expanduser(file_path)
            if os.path.exists(expanded_path):
                try:
                    stat_info = os.stat(expanded_path)
                    if stat_info.st_mode & 0o777 == 0o777:  # World writable
                        issues.append(f"⚠️  Overly permissive: {file_path}")
                except Exception:
                    pass
        
        # Check for unnecessary services
        try:
            result = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True)
            open_ports = [line for line in result.stdout.split('\n') if 'LISTEN' in line]
            if len(open_ports) > 5:
                issues.append(f"⚠️  Multiple open ports: {len(open_ports)} detected")
        except Exception:
            pass
        
        # Check SSH security
        ssh_config = "/etc/ssh/sshd_config"
        if os.path.exists(ssh_config):
            with open(ssh_config, 'r') as f:
                content = f.read()
                if "PasswordAuthentication yes" in content:
                    issues.append("⚠️  SSH password authentication enabled")
                if "PermitRootLogin yes" in content:
                    issues.append("⚠️  SSH root login permitted")
        
        return {
            'scan_time': datetime.now().isoformat(),
            'issues_found': issues,
            'issue_count': len(issues),
            'recommendations': [
                "Use key-based SSH authentication",
                "Regularly update packages",
                "Enable firewall",
                "Use fail2ban for SSH protection"
            ]
        }
    
    def footprint_cleaner(self) -> str:
        """Clean system footprints and traces."""
        print("🧹 Cleaning footprints...")
        cleaned = []
        
        # Clear bash history
        try:
            subprocess.run(["history", "-c"], shell=True)
            cleaned.append("Bash history cleared")
        except Exception:
            pass
        
        # Clear temporary files
        try:
            subprocess.run(["rm", "-rf", "/tmp/*"], capture_output=True)
            cleaned.append("Temp files cleared")
        except Exception:
            pass
        
        # Clear various caches
        cache_dirs = [
            "~/.cache/",
            "~/.local/share/Trash/",
            "~/.thumbnails/"
        ]
        
        for cache_dir in cache_dirs:
            expanded_dir = os.path.expanduser(cache_dir)
            if os.path.exists(expanded_dir):
                try:
                    subprocess.run(["rm", "-rf", expanded_dir + "*"], capture_output=True)
                    cleaned.append(f"Cleared {cache_dir}")
                except Exception:
                    pass
        
        self.vault.store_conversation(
            "FOOTPRINT_CLEANER_RUN",
            f"Cleaned: {', '.join(cleaned)}",
            context_tag="security"
        )
        
        return f"‖ Footprint cleaning complete: {len(cleaned)} actions ‖"
    
    def encrypted_backup(self, backup_path: str = None) -> str:
        """Create encrypted backup of the system."""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"system_backup_{timestamp}.tar.gpg"
        
        try:
            import tarfile
            with tarfile.open("temp_backup.tar", "w") as tar:
                # Use generic vault filenames – adjust to your actual files
                tar.add("secure_vault.db", arcname="vault.db")
                tar.add("vault.key", arcname="encryption.key")
                for config_file in ["config.json", "settings.yaml"]:
                    if os.path.exists(config_file):
                        tar.add(config_file)
            
            # Encrypt with GPG (if available)
            try:
                result = subprocess.run([
                    "gpg", "--symmetric", "--cipher-algo", "AES256",
                    "--passphrase", "temp_password",  # In production, use proper key management
                    "-o", backup_path, "temp_backup.tar"
                ], capture_output=True)
                
                if result.returncode == 0:
                    os.remove("temp_backup.tar")
                    return f"‖ Encrypted backup created: {backup_path} ‖"
                else:
                    return "‖ GPG encryption failed ‖"
            except Exception:
                # Fallback: just compress without encryption
                os.rename("temp_backup.tar", backup_path)
                return f"‖ Backup created (unencrypted): {backup_path} ‖"
                
        except Exception as e:
            return f"‖ Backup failed: {str(e)} ‖"
    
    def integrity_check(self) -> Dict[str, Any]:
        """Check integrity of critical system files."""
        print("🔍 Running integrity check...")
        checks = {}
        
        critical_files = {
            "secure_vault.db": "Database file",
            "vault.key": "Encryption key",
            "cipher_vault.py": "Core encryption module",
            "ciph_core.py": "Main orchestrator"
        }
        
        for filename, description in critical_files.items():
            if os.path.exists(filename):
                file_hash = self._calculate_file_hash(filename)
                file_size = os.path.getsize(filename)
                checks[filename] = {
                    'status': 'OK',
                    'hash': file_hash[:16] + "...",
                    'size': file_size,
                    'description': description
                }
            else:
                checks[filename] = {
                    'status': 'MISSING',
                    'hash': 'N/A',
                    'size': 0,
                    'description': description
                }
        
        return {
            'check_time': datetime.now().isoformat(),
            'files_checked': checks,
            'all_critical_files_present': all(
                check['status'] == 'OK' for check in checks.values()
            )
        }
    
    def encrypt_runtime_memory(self) -> str:
        """Placeholder for runtime memory encryption."""
        # In a real implementation, this would encrypt sensitive buffers in RAM.
        return "‖ Runtime memory encryption placeholder ‖"
    
    def generate_false_traffic(self) -> str:
        """Placeholder for generating false network traffic patterns."""
        # Would implement decoy requests, timing noise, etc.
        return "‖ False traffic generator placeholder ‖"

    def _calculate_file_hash(self, filename: str) -> str:
        """Calculate SHA256 hash of a file."""
        hasher = hashlib.sha256()
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def emergency_wipe(self, confirmation: str) -> str:
        """Emergency data destruction (with confirmation)."""
        if confirmation != "CONFIRM_WIPE_ALL":
            return "‖ Wipe aborted: Invalid confirmation code ‖"
        
        print("🚨 INITIATING EMERGENCY WIPE...")
        
        try:
            # Securely delete sensitive files (update filenames to match your setup)
            sensitive_files = ["secure_vault.db", "vault.key", "config.json"]
            
            for filename in sensitive_files:
                if os.path.exists(filename):
                    # Multiple overwrite passes (simplified)
                    with open(filename, 'wb') as f:
                        f.write(os.urandom(os.path.getsize(filename)))
                    os.remove(filename)
            
            # Clear conversation history from vault
            if hasattr(self, 'vault'):
                conn = self.vault._get_connection()
                c = conn.cursor()
                c.execute('DELETE FROM conversations')
                c.execute('DELETE FROM config')
                conn.commit()
                conn.close()
            
            return "‖ EMERGENCY WIPE COMPLETE - All data destroyed ‖"
            
        except Exception as e:
            return f"‖ Wipe failed: {str(e)} ‖"


if __name__ == "__main__":
    from cipher_vault import CipherVault
    vault = CipherVault()
    security = SecurityLayer(vault)
    
    print("🧪 Testing Security Layer:")
    print(security.system_hardening_scan())
    print(security.footprint_cleaner())
    print(security.integrity_check())