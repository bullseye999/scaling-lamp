#!/usr/bin/env python3
# tor_proxy.py - Anonymous internet access with control port support

import requests
import socks
import socket
import time
import os
from typing import Optional

class TorProxy:
    """Route all traffic through Tor network with control port access."""
    
    def __init__(self):
        self.tor_port = 9050
        self.control_port = 9051
        self.current_ip = None
        self.cookie_path = "/run/tor/control.authcookie"
        self._original_socket = socket.socket   # store original for restoration
        
    def enable_tor(self) -> str:
        """Route all traffic through Tor."""
        try:
            # Set up SOCKS5 proxy for Tor
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            socket.socket = socks.socksocket
            
            # Test connection
            self.current_ip = self._get_tor_ip()
            if self.current_ip:
                control_status = self._check_control_port()
                return f"‖ Tor enabled. Exit IP: {self.current_ip} ‖ {control_status} ‖"
            return "‖ Tor connection failed ‖"
            
        except Exception as e:
            return f"‖ Tor setup failed: {str(e)[:80]} ‖"
    
    def _get_tor_ip(self) -> Optional[str]:
        """Get current Tor exit node IP."""
        try:
            # Save original socket temporarily
            orig_socket = socket.socket
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            socket.socket = socks.socksocket
            
            response = requests.get('https://api.ipify.org?format=json', timeout=10)
            
            # Restore original socket
            socket.socket = orig_socket
            
            if response.status_code == 200:
                ip_data = response.json()
                return ip_data.get('ip')
        except Exception:
            pass
        return None
    
    def _check_control_port(self) -> str:
        """Check if Tor control port is accessible."""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(("127.0.0.1", self.control_port))
            sock.send(b"PROTOCOLINFO\n")
            response = sock.recv(1024)
            sock.close()
            
            if b"250" in response:
                if os.path.exists(self.cookie_path):
                    try:
                        with open(self.cookie_path, 'rb') as f:
                            f.read(1)
                        return "ControlPort: READY"
                    except PermissionError:
                        return "ControlPort: NO_COOKIE_ACCESS"
                return "ControlPort: READY_NO_COOKIE"
            return "ControlPort: NO_RESPONSE"
        except Exception:
            return "ControlPort: UNREACHABLE"
    
    def new_identity(self) -> str:
        """Request a new Tor circuit (new exit IP)."""
        try:
            import stem
            from stem.control import Controller
            from stem import Signal
            
            with Controller.from_port(port=self.control_port) as controller:
                try:
                    controller.authenticate()
                except stem.connection.AuthenticationFailure:
                    # Try without authentication (some setups)
                    try:
                        controller.authenticate(None)
                    except Exception:
                        return "‖ Authentication failed. Check cookie permissions ‖"
                
                controller.signal(Signal.NEWNYM)
                time.sleep(3)   # allow circuit to rebuild
                
                new_ip = self._get_tor_ip()
                self.current_ip = new_ip
                
                if new_ip:
                    return f"‖ New Tor identity: {new_ip} ‖"
                return "‖ New identity created (IP refreshing) ‖"
                
        except ImportError:
            return "‖ Install stem: pip install stem ‖"
        except Exception as e:
            error_msg = str(e)
            if "Permission denied" in error_msg:
                return "‖ Permission denied. Try: sudo chmod 644 /run/tor/control.authcookie ‖"
            elif "Authentication failed" in error_msg:
                return "‖ Auth failed. Check /etc/tor/torrc has CookieAuthentication 1 ‖"
            return f"‖ Control port error: {error_msg[:80]} ‖"
    
    def get_tor_ip(self) -> Optional[str]:
        """Return cached Tor exit IP (refreshes if None)."""
        if not self.current_ip:
            self.current_ip = self._get_tor_ip()
        return self.current_ip

    def disable_tor(self) -> str:
        """Disable Tor proxy – restore normal clearnet routing."""
        try:
            # Restore original socket
            socket.socket = socket._original_socket if hasattr(socket, '_original_socket') else socket.socket
            # Clear proxy (using the correct method)
            socks.set_default_proxy()   # clears proxy
            self.current_ip = None
            return "‖ Tor disabled. Back on clearnet ‖"
        except Exception as e:
            return f"‖ Disable Tor failed: {e} ‖"
    
    def test_connection(self) -> str:
        """Test if Tor is working."""
        try:
            ip = self._get_tor_ip()
            if ip:
                return f"‖ Tor working. Your IP: {ip} ‖"
            return "‖ Tor not working - check Tor service ‖"
        except Exception as e:
            return f"‖ Test failed: {str(e)[:80]} ‖"
    
    def fix_cookie_permissions(self) -> str:
        """Fix cookie file permissions (requires sudo)."""
        try:
            import subprocess
            result = subprocess.run(
                ["sudo", "chmod", "644", self.cookie_path],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return "‖ Cookie permissions fixed ‖"
            return f"‖ Fix failed: {result.stderr[:80]} ‖"
        except Exception as e:
            return f"‖ Permission fix error: {str(e)[:80]} ‖"


if __name__ == "__main__":
    print("🧪 Testing Tor Proxy with Control Port...")
    
    proxy = TorProxy()
    print("1. Testing Tor connection...")
    print(proxy.test_connection())
    
    print("\n2. Checking control port...")
    print(proxy._check_control_port())
    
    print("\n3. Testing new identity...")
    print(proxy.new_identity())
    
    print("\n4. Final IP check...")
    print(f"Current IP: {proxy.get_tor_ip()}")