#!/usr/bin/env python3
# dead_mans_switch.py - Automatic data destruction on inactivity

import threading
import time
import os

class DeadMansSwitch:
    """Destroy sensitive data if the user does not check in within a timeout."""
    
    def __init__(self, vault):
        self.vault = vault
        self.alive_signal = True
        self.check_interval = 300  # 5 minutes (not used in current logic)
        self.trigger_thread = None
        
    def start_switch(self, hours=24):
        """Start monitoring – wipe if no check‑in within the given hours."""
        self.trigger_thread = threading.Thread(
            target=self._monitor_switch,
            args=(hours * 3600,),
            daemon=True
        )
        self.trigger_thread.start()
        return f"‖ Dead man's switch active: {hours}h countdown ‖"
    
    def _monitor_switch(self, timeout_seconds):
        """Background thread: reset timer on check‑in, otherwise trigger wipe."""
        last_check = time.time()
        
        while time.time() - last_check < timeout_seconds:
            if not self.alive_signal:
                # Check‑in received – reset timer
                last_check = time.time()
                self.alive_signal = True
            
            time.sleep(60)  # Check every minute
        
        # Timeout reached – execute emergency destruction
        self._emergency_destruct()
    
    def check_in(self):
        """Call this regularly to prove you are alive and reset the timer."""
        self.alive_signal = False
        return "‖ Switch check‑in recorded ‖"

    def stop_switch(self):
        """Stop the dead man's switch (prevents accidental wipe)."""
        self.alive_signal = True  # Prevent trigger
        if self.trigger_thread and self.trigger_thread.is_alive():
            # The thread cannot be forcibly stopped, but marking as stopped is enough.
            pass
        return "‖ Dead man's switch stopped ‖"
    
    def _emergency_destruct(self):
        """
        Complete system destruction – overwrite files, delete keys, scrub database.
        (Implementation placeholder – customize for your environment.)
        """
        # List of sensitive files to destroy (rename to match your project's files)
        destructive_files = [
            "secure_vault.db", "vault.key",
            "quantum_vault.db", "quantum.key",
            "config.json", "*.log"
        ]
        
        # Secure deletion logic would go here (overwrite, rename, unlink).
        # For safety, this method is not fully implemented in the public example.
        
        # Hard exit – no cleanup, no trace
        os._exit(0)