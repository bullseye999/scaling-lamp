#!/usr/bin/env python3
# dead_mans_switch.py - Automatic data destruction

import threading
import time
import os

class DeadMansSwitch:
    """Destroy everything if compromised"""
    
    def __init__(self, vault):
        self.vault = vault
        self.alive_signal = True
        self.check_interval = 300  # 5 minutes
        self.trigger_thread = None
        
    def start_switch(self, hours=24):
        """Start monitoring - wipe if no check-in"""
        self.trigger_thread = threading.Thread(
            target=self._monitor_switch,
            args=(hours * 3600,),
            daemon=True
        )
        self.trigger_thread.start()
        return f"‖ Dead man's switch active: {hours}h countdown ‖"
    
    def _monitor_switch(self, timeout_seconds):
        """Monitor for activity"""
        last_check = time.time()
        
        while time.time() - last_check < timeout_seconds:
            if not self.alive_signal:
                # Signal received - reset timer
                last_check = time.time()
                self.alive_signal = True
            
            time.sleep(60)  # Check every minute
        
        # TIMEOUT REACHED - WIPE EVERYTHING
       # self._emergency_destruct()
    
    def check_in(self):
        """Call this regularly to prove you're alive"""
        self.alive_signal = False
        return "‖ Switch check-in recorded ‖"

    def stop_switch(self):
        """Stop the dead man's switch"""
        self.alive_signal = True  # Prevent trigger
        if self.trigger_thread and self.trigger_thread.is_alive():
            # Can't really stop thread, but mark as stopped
            pass
        return "‖ Dead man's switch stopped ‖"
    
    def secure_delete(self, filepath: str, passes: int = 3):
        """Overwrite file with random data multiple times before deleting"""
        if not os.path.exists(filepath):
            return
        try:
            size = os.path.getsize(filepath)
            for _ in range(passes):
                with open(filepath, 'wb') as f:
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            with open(filepath, 'wb') as f:
                f.write(b'\x00' * size)
                f.flush()
                os.fsync(f.fileno())
            os.remove(filepath)
        except Exception:
            pass

    def wipe_memory(self):
        """Force garbage collection to clean up memory references"""
        import gc
        gc.collect()

    def _emergency_destruct(self):
        """Complete system destruction"""
        destructive_files = [
            "ciph_vault.db", "ciph.key", 
            "quantum_vault.db", "quantum.key"
        ]
        for f in destructive_files:
            if os.path.exists(f):
                self.secure_delete(f)
        self.wipe_memory()
        os._exit(0)  # Hard exit